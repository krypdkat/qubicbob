#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <random>
#include <algorithm>
#include "structs.h"

// Not thread safe
class QubicConnection
{
public:
    QubicConnection(const char* nodeIp, int nodePort);
    ~QubicConnection();
    int receiveData(uint8_t* buffer, int sz);
    int sendData(uint8_t* buffer, int sz);
    void receiveAFullPacket(RequestResponseHeader& header, std::vector<uint8_t>& buffer);
    bool reconnect();
    void disconnect();
    [[nodiscard]] bool isSocketValid() const{ return mSocket>=0;}
    char* getNodeIp() { return mNodeIp;}
    void updatePasscode(const uint64_t passcode[4]){ memcpy(mPasscode, passcode, 8*4); }
    void getPasscode(uint64_t* passcode){ memcpy(passcode, mPasscode, 8*4); }
    // Construct from an already-open socket; this connection is NON-reconnectable.
    QubicConnection(int existingSocket);
    // Expose whether this connection is allowed to reconnect.
    [[nodiscard]] bool isReconnectable() const { return mReconnectable; }

    // non-thread safe operation
    void getTickInfo(uint32_t& tick, uint16_t& epoch);
    void doHandshake();
    void getComputorList(const uint16_t epoch, Computors& compList);
    void sendEndPacket(uint32_t dejavu = 0xffffffff);
private:
    char mNodeIp[32];
    int mNodePort;
    int mSocket;
    uint8_t mBuffer[0xFFFFFF];
    uint64_t mPasscode[4]; // for loggingEvent
    bool mReconnectable;   // whether reconnect() is allowed
};
typedef std::shared_ptr<QubicConnection> QCPtr;
static QCPtr make_qc(const char* nodeIp, int nodePort)
{
    return std::make_shared<QubicConnection>(nodeIp, nodePort);
}
// Factory to build a NON-reconnectable connection from an existing socket.
static QCPtr make_qc_by_socket(int existingSocket)
{
    return std::make_shared<QubicConnection>(existingSocket);
}

// TODO: move to cpp later
class ConnectionPool {
public:
    ConnectionPool()
            : rng_(std::random_device{}()) {}

    void add(const QCPtr& c) {
        if (c) conns_.push_back(c);
    }

    void add(const std::vector<QCPtr>& cs) {
        for (const auto& c : cs) add(c);
    }

    std::size_t size() const { return conns_.size(); }
    QCPtr& get(int i) { return conns_[i];}
    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandom(uint8_t* buffer, int sz) {
        if (conns_.empty()) return -1;

        // Build an index list of currently valid connections
        std::vector<std::size_t> idx;
        idx.reserve(conns_.size());
        for (std::size_t i = 0; i < conns_.size(); ++i) {
            if (conns_[i] && conns_[i]->isSocketValid()) {
                idx.push_back(i);
            }
        }
        if (idx.empty()) return -1;

        std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
        auto chosen = idx[dist(rng_)];
        return conns_[chosen]->sendData(buffer, sz);
    }

    // Sends to 'howMany' distinct random valid connections (or fewer if not enough are valid).
    // Returns a vector of bytes-sent per selected connection, in the order of selection.
    std::vector<int> sendToMany(uint8_t* buffer, int sz, std::size_t howMany) {
        std::vector<int> results;
        if (conns_.empty() || howMany == 0) return results;

        // Collect indices of valid connections
        std::vector<std::size_t> idx;
        idx.reserve(conns_.size());
        for (std::size_t i = 0; i < conns_.size(); ++i) {
            if (conns_[i] && conns_[i]->isSocketValid()) {
                idx.push_back(i);
            }
        }
        if (idx.empty()) return results;

        // Shuffle and take first K
        std::shuffle(idx.begin(), idx.end(), rng_);
        if (howMany < idx.size()) {
            idx.resize(howMany);
        }

        results.reserve(idx.size());
        for (auto i : idx) {
            results.push_back(conns_[i]->sendData(buffer, sz));
        }
        return results;
    }

    int sendWithPasscodeToRandom(uint8_t* buffer, int passcodeOffset, int sz) {
        if (conns_.empty()) return -1;

        // Build an index list of currently valid connections
        std::vector<std::size_t> idx;
        idx.reserve(conns_.size());
        for (std::size_t i = 0; i < conns_.size(); ++i) {
            if (conns_[i] && conns_[i]->isSocketValid()) {
                idx.push_back(i);
            }
        }
        if (idx.empty()) return -1;

        std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
        auto chosen = idx[dist(rng_)];
        conns_[chosen]->getPasscode((uint64_t*)(buffer+passcodeOffset));
        return conns_[chosen]->sendData(buffer, sz);
    }

private:
    std::vector<QCPtr> conns_;
    std::mt19937 rng_;
};