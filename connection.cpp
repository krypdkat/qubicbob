#include "structs.h"
#include <stdexcept>
#include <algorithm> // For std::min

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>  // for errno
#include <fcntl.h>
#include <netinet/tcp.h>

#include "connection.h"
#include "Logger.h"
#include "GlobalVar.h"
#include "shim.h"
static int do_connect(const char* nodeIp, int nodePort)
{
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        Logger::get()->error("socket() failed: {} ({})", errno, strerror(errno));
        return -1;
    }

    // Close-on-exec for safety
    {
        int flags = fcntl(serverSocket, F_GETFD);
        if (flags >= 0) {
            (void)fcntl(serverSocket, F_SETFD, flags | FD_CLOEXEC);
        }
    }

    // Configure timeouts (best-effort)
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof tv) < 0) {
        Logger::get()->warn("setsockopt(SO_RCVTIMEO) failed: {} ({})", errno, strerror(errno));
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof tv) < 0) {
        Logger::get()->warn("setsockopt(SO_SNDTIMEO) failed: {} ({})", errno, strerror(errno));
    }

    // Improve latency and resilience (best-effort)
    {
        int on = 1;
        (void)setsockopt(serverSocket, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        (void)setsockopt(serverSocket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    }

    sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(nodePort));

    if (inet_pton(AF_INET, nodeIp, &addr.sin_addr) <= 0) {
        Logger::get()->error("Invalid IP address '{}'", nodeIp);
        close(serverSocket);
        return -1;
    }

    // Handle EINTR for blocking connect
    int rc;
    do {
        rc = connect(serverSocket, (const sockaddr*)&addr, sizeof(addr));
    } while (rc < 0 && errno == EINTR);

    if (rc < 0) {
        Logger::get()->error("Failed to connect {}:{} | errno {} ({})", nodeIp, nodePort, errno, strerror(errno));
        close(serverSocket);
        return -1;
    }

    return serverSocket;
}


QubicConnection::QubicConnection(const char* nodeIp, int nodePort)
{
    memset(mPasscode, 0xff, 8*4);
    strncpy(mNodeIp, nodeIp, sizeof(mNodeIp) - 1);
    mNodeIp[sizeof(mNodeIp) - 1] = '\0';
    mNodePort = nodePort;
    mSocket = -1;
    mSocket = do_connect(mNodeIp, mNodePort);
    mReconnectable = true;
}
QubicConnection::~QubicConnection()
{
	close(mSocket);
}

int QubicConnection::receiveData(uint8_t* buffer, int sz)
{
    int count = 0;
    double orgSize = sz;
    while (sz > 0)
    {
        auto ret = recv(mSocket, (char*)buffer + count, std::min(1024, sz), 0);
        if (ret < 0)
        {
            return ret;
        }
        if (ret == 0)
        {
            return count;
        }
        count += ret;
        sz -= ret;
    }
	return count;
}
void QubicConnection::receiveAFullPacket(RequestResponseHeader& header, std::vector<uint8_t>& buffer)
{
    // first receive the header
    int recvByte = receiveData((uint8_t*)&header, sizeof(RequestResponseHeader));
    if (recvByte < 0)
    {
        throw std::logic_error("Socket Error");
    }
    if (recvByte != sizeof(RequestResponseHeader)) throw std::logic_error("Failed to get header.");
    int packet_size = header.size();
    if (packet_size > RequestResponseHeader::max_size)
    {
        throw std::logic_error("Malformed header data.");
    }
    buffer.resize(header.size());
    memcpy(buffer.data(), &header, sizeof(RequestResponseHeader));
    // receive the rest
    int remaining_size = packet_size - sizeof(RequestResponseHeader);
    recvByte = receiveData(buffer.data() + sizeof(RequestResponseHeader), remaining_size);
    if (recvByte != remaining_size) throw std::logic_error("Not received enough data.");
}

void QubicConnection::sendEndPacket(uint32_t dejavu)
{
    RequestResponseHeader nop{};
    nop.setType(35);
    if (dejavu != 0xffffffff) nop.setDejavu(dejavu);
    else nop.randomizeDejavu();
    nop.setSize(sizeof(RequestResponseHeader));
    sendData((uint8_t *) &nop, sizeof(nop));
}

int QubicConnection::sendData(uint8_t* buffer, int sz)
{
    if (sz >= 8)
    {
        RequestResponseHeader header;
        memcpy((void*)&header, buffer, 8);
        uint32_t dejavu = header.getDejavu();
        if (dejavu)
        {
            requestMapperFrom.add(dejavu, buffer, sz, nullptr);
        }
    }
    int size = sz;
    while (size > 0 && mSocket != -1) {
        int numberOfBytes = send(mSocket, reinterpret_cast<char*>(buffer), size, MSG_NOSIGNAL);
        if (numberOfBytes < 0) {
            if (errno == EINTR) {
                // Interrupted by a signal, retry the send
                continue;
            }
            // Peer likely closed (EPIPE) or connection reset, mark socket invalid
            Logger::get()->debug("send() failed on socket {} with errno {}. Disconnecting.", mSocket, errno);
            disconnect();
            return (sz - size); // bytes successfully sent before failure
        }
        if (numberOfBytes == 0) {
            // Treat as closed
            Logger::get()->debug("send() returned 0 on socket {}. Disconnecting.", mSocket);
            disconnect();
            return (sz - size);
        }
        buffer += numberOfBytes;
        size   -= numberOfBytes;
    }
    return sz;
}

void QubicConnection::getComputorList(const uint16_t epoch, Computors& compList)
{
    RequestResponseHeader header{};
    std::vector<uint8_t> packet;
    int count = 0;
    while (1)
    {
        // trying to get until Computors packet arrive
        // resend each 20 packets
        if ( count++ % 20 == 0 )
        {
            header.setSize(sizeof(header));
            header.randomizeDejavu();
            header.setType(REQUEST_COMPUTOR_LIST);
            sendData((uint8_t*)&header, 8);
        }
        RequestResponseHeader header{};
        receiveAFullPacket(header, packet);
        if (!packet.empty())
        {
            memcpy((void*)&header, packet.data(), 8);
            if (header.type() == 2)
            {
                if (header.size() == 8 + sizeof(Computors))
                {
                    memcpy((void*)&compList, packet.data() + 8, sizeof(Computors));
                    break;
                }
            }
        }
    }
}

void QubicConnection::doHandshake()
{
    struct
    {
        RequestResponseHeader header;
        uint8_t ip[4][4];
    } payload;
    memset(&payload, 0, sizeof(payload));
    payload.header.randomizeDejavu();
    payload.header.setType(0);
    payload.header.setSize(sizeof(payload));
    sendData((uint8_t*)&payload, sizeof(payload));
}

void QubicConnection::getTickInfo(uint32_t& tick, uint16_t& epoch)
{
    RequestResponseHeader header{};
    std::vector<uint8_t> packet;
    int count = 0;
    while (1)
    {
        // trying to get until Computors packet arrive
        // resend each 20 packets
        if ( count++ % 20 == 0 )
        {
            header.setSize(sizeof(header));
            header.randomizeDejavu();
            header.setType(REQUEST_CURRENT_TICK_INFO);
            sendData((uint8_t*)&header, 8);
        }
        RequestResponseHeader header{};
        receiveAFullPacket(header, packet);
        if (!packet.empty())
        {
            memcpy((void*)&header, packet.data(), 8);
            if (header.type() == RESPOND_CURRENT_TICK_INFO)
            {
                if (header.size() == 8 + sizeof(CurrentTickInfo))
                {
                    CurrentTickInfo ctick{};
                    memcpy((void*)&ctick, packet.data()+8, sizeof(CurrentTickInfo));
                    tick = ctick.initialTick;
                    epoch = ctick.epoch;
                    break;
                }
            }
        }
    }
}

void QubicConnection::disconnect()
{
    if (mSocket >= 0) {
        close(mSocket);
        mSocket = -1;
    }
}

bool QubicConnection::reconnect()
{
    // Disallow reconnect if this connection was created from an external socket
    if (!mReconnectable) {
        Logger::get()->debug("reconnect() called on a non-reconnectable connection.");
        return false;
    }
    if (mSocket >= 0) {
        close(mSocket);
        mSocket = -1;
    }

    // Attempt to re-establish connection
    int newSocket = do_connect(mNodeIp, mNodePort);
    if (newSocket < 0) {
        Logger::get()->error("Failed to reconnect {}:{}", mNodeIp, mNodePort);
        return false;
    }

    mSocket = newSocket;
    return true;
}

QubicConnection::QubicConnection(int existingSocket)
{
    memset(mPasscode, 0xff, 8*4);
    mNodeIp[0] = '\0';
    mNodePort = 0;
    mSocket = existingSocket;
    mReconnectable = false;
}