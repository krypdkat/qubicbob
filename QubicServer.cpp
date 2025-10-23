#include <atomic>
#include <thread>
#include <vector>
#include <memory>
#include <mutex>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>

#include "Logger.h"
#include "connection.h"
#include "shim.h"
// Forward declaration from IOProcessor.cpp
void connReceiver(QCPtr& conn, const bool isTrustedNode, std::atomic_bool& stopFlag);

namespace {
    class QubicServer {
    public:
        static QubicServer& instance() {
            static QubicServer inst;
            return inst;
        }

        bool start(uint16_t port = 21842) {
            std::lock_guard<std::mutex> lk(m_);
            if (running_) return true;

            listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (listen_fd_ < 0) {
                Logger::get()->critical("QubicServer: socket() failed (errno={})", errno);
                return false;
            }

            int yes = 1;
            ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
            ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(port);

            if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
                Logger::get()->critical("QubicServer: bind() failed on port {} (errno={})", port, errno);
                ::close(listen_fd_);
                listen_fd_ = -1;
                return false;
            }

            if (::listen(listen_fd_, 128) < 0) {
                Logger::get()->critical("QubicServer: listen() failed (errno={})", errno);
                ::close(listen_fd_);
                listen_fd_ = -1;
                return false;
            }

            running_ = true;
            accept_thread_ = std::thread(&QubicServer::acceptLoop, this);
            Logger::get()->info("QubicServer: listening on port {}", port);
            return true;
        }

        void stop() {
            std::lock_guard<std::mutex> lk(m_);
            if (!running_) return;
            running_ = false;

            if (listen_fd_ >= 0) {
                ::shutdown(listen_fd_, SHUT_RDWR);
                ::close(listen_fd_);
                listen_fd_ = -1;
            }

            if (accept_thread_.joinable()) {
                accept_thread_.join();
            }

            // Stop all client handlers
            {
                std::lock_guard<std::mutex> lk2(clients_m_);
                for (auto& c : clients_) {
                    c->stopFlag.store(true, std::memory_order_relaxed);
                    if (c->conn) {
                        c->conn->disconnect();
                    }
                }
            }

            {
                std::lock_guard<std::mutex> lk2(clients_m_);
                for (auto& c : clients_) {
                    if (c->th.joinable()) c->th.join();
                }
                clients_.clear();
            }

            Logger::get()->info("QubicServer: stopped");
        }

    private:
        struct ClientCtx {
            std::atomic_bool stopFlag{false};
            QCPtr conn;
            std::thread th;
            int fd{-1};
        };

        QubicServer() = default;
        ~QubicServer() { stop(); }

        void acceptLoop() {
            while (running_) {
                sockaddr_in cli{};
                socklen_t len = sizeof(cli);
                int cfd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&cli), &len);
                if (cfd < 0) {
                    if (!running_) break;
                    // EAGAIN/EINTR acceptable during shutdown or transient
                    continue;
                }

                // Basic socket tuning
                int one = 1;
                ::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_KEEPALIVE
                ::setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#endif

                auto ctx = std::make_shared<ClientCtx>();
                ctx->fd = cfd;

                // Wrap the accepted socket into QCPtr (NON-reconnectable as per connection.h)
                ctx->conn = make_qc_by_socket(cfd);

                {
                    std::lock_guard<std::mutex> lk(clients_m_);
                    clients_.push_back(ctx);
                }

                // Non-trusted connections
                const bool isTrustedNode = false;

                // Launch per-connection receiver thread
                ctx->th = std::thread([this, ctx, isTrustedNode]() {
                    try {
                        ctx->conn->doHandshake();
                        connReceiver(ctx->conn, isTrustedNode, ctx->stopFlag);
                    } catch (...) {
                        Logger::get()->warn("QubicServer: connReceiver crashed for a client");
                    }

                    // Cleanup when receiver exits
                    if (ctx->conn) ctx->conn->disconnect();
                    if (ctx->fd >= 0) {
                        ::shutdown(ctx->fd, SHUT_RDWR);
                        ::close(ctx->fd);
                        ctx->fd = -1;
                    }

                    // IMPORTANT: Detach the thread before removing ctx to avoid destroying a joinable thread from within itself
                    if (ctx->th.joinable()) {
                        ctx->th.detach();
                    }

                    // Remove from list
                    std::lock_guard<std::mutex> lk(clients_m_);
                    auto it = std::remove_if(clients_.begin(), clients_.end(),
                                             [&](const std::shared_ptr<ClientCtx>& p){ return p.get() == ctx.get(); });
                    clients_.erase(it, clients_.end());
                });
            }
        }

    private:
        std::mutex m_;
        std::atomic_bool running_{false};
        int listen_fd_{-1};
        std::thread accept_thread_;

        std::mutex clients_m_;
        std::vector<std::shared_ptr<ClientCtx>> clients_;
    };
} // namespace

// Public helpers to control the server
bool StartQubicServer(uint16_t port = 21842) {
    return QubicServer::instance().start(port);
}

void StopQubicServer() {
    QubicServer::instance().stop();
}