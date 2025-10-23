#include <sstream>
#include <iomanip>
#include <cassert>
#include "db.h"
#include "GlobalVar.h"
#include "Logger.h"
#include "K12AndKeyUtil.h"
#include "shim.h"
const uint32_t max_packet_size = 0xffffff;

bool verifySignature(void* ptr, uint8_t* pubkey, int structSize) // structSize include sig 64 bytes
{
    uint8_t* p = (uint8_t*)ptr;
    uint8_t digest[32];
    KangarooTwelve(p, structSize - 64, digest, 32);
    if (verify(pubkey, digest, p + structSize - 64))
    {
        return true;
    }
    return false;
}
void processTickVote(uint8_t* ptr)
{
    auto* vote = reinterpret_cast<TickVote*>(ptr);
    uint8_t* compPubkey = computorsList.publicKeys[vote->computorIndex].m256i_u8;
    vote->computorIndex ^= 3;
    bool ok = verifySignature((void *) vote, compPubkey, sizeof(TickVote));
    vote->computorIndex ^= 3;
    if (ok)
    {
        db_insert_tick_vote(*vote);
    }
    else
    {
        Logger::get()->warn("Vote {}:{} has invalid signature", vote->tick, vote->computorIndex);
    }
}

void processTickData(uint8_t* ptr)
{
    auto* data = reinterpret_cast<TickData*>(ptr);
    uint8_t* compPubkey = computorsList.publicKeys[data->computorIndex].m256i_u8;
    data->computorIndex ^= 8;
    bool ok = verifySignature((void *) data, compPubkey, sizeof(TickData));
    data->computorIndex ^= 8;
    if (ok)
    {
        db_insert_tick_data(*data);
    }
    else
    {
        Logger::get()->warn("TickData {}:{} has invalid signature", data->tick, data->computorIndex);
    }

}

void processTransaction(const uint8_t* ptr)
{
    const auto* tx = reinterpret_cast<const Transaction*>(ptr);
    auto* pubkey = (uint8_t*)tx->sourcePublicKey;
    if (verifySignature((void *) tx, pubkey, sizeof(Transaction) + tx->inputSize + 64))
    {
        db_insert_transaction(tx);
    }
    else
    {
        char IDEN[64] = {0};
        getIdentityFromPublicKey(tx->sourcePublicKey, IDEN, false);
        Logger::get()->warn("Transaction {}:{} has invalid signature", tx->tick, IDEN);
    }

}

void processLogEvent(const uint8_t* _ptr, uint32_t chunkSize)
{
    uint32_t offset = 0;
    uint64_t maxLogId = 0;
    while (offset < chunkSize)
    {
        auto ptr = _ptr + offset;
        uint16_t epoch;
        uint32_t tick;
        uint32_t tmp;
        uint64_t logId;
        memcpy(&epoch, ptr, sizeof(epoch));
        memcpy(&tick, ptr + 2, sizeof(tick));
        memcpy(&tmp, ptr + 6, sizeof(tmp));
        memcpy(&logId, ptr + 10, sizeof(logId));
        uint32_t messageSize = tmp & 0x00FFFFFF;

        if (!db_insert_log(epoch, tick, logId, messageSize + LogEvent::PackedHeaderSize, ptr))
        {
            Logger::get()->warn("Failed to add log {}", logId);
        }

        offset += messageSize + LogEvent::PackedHeaderSize;
        maxLogId = std::max(maxLogId, logId);
    }
    db_update_latest_log_id(gCurrentProcessingEpoch, maxLogId);
}

void processLogRanges(RequestResponseHeader& header, const uint8_t* ptr)
{
    struct {
        RequestResponseHeader header;
        unsigned long long passcode[4];
        unsigned int tick;
    } packet;

    std::vector<uint8_t> request;
    requestMapperFrom.get(header.getDejavu(), request);
    if (request.size() == sizeof(packet))
    {
        memcpy(&packet, request.data(), sizeof(packet));
        int header_sz = header.size();
        int needed_sz = sizeof(RequestResponseHeader) + sizeof(ResponseAllLogIdRangesFromTick);
        if (header_sz == needed_sz)
        {
            const auto* logRange = reinterpret_cast<const ResponseAllLogIdRangesFromTick*>(ptr);
            db_insert_log_range(packet.tick, *logRange);
        }
    }
    else
    {
        Logger::get()->warn("Cannot find suitable tick to map the log range");
    }
}

void DataProcessorThread(std::atomic_bool& exitFlag)
{
    std::vector<uint8_t> buf;
    buf.resize(RequestResponseHeader::max_size, 0);
    uint8_t* ptr = buf.data();
    while (!exitFlag.load())
    {
        uint32_t packet_size = 0;
        MRB_Data.GetPacket(ptr, packet_size);
        if (packet_size == 0 || packet_size >= RequestResponseHeader::max_size)
        {
            Logger::get()->warn("Malformed packet_size: {}", packet_size);
            continue;
        }
        RequestResponseHeader header{};
        memcpy(&header, ptr, 8);
        auto type = header.type();
        ptr += 8;
        switch (type)
        {
            case BROADCAST_TICK_VOTE: // TickVote
                processTickVote(ptr);
                break;
            case TickData::type(): // TickData
                processTickData(ptr);
                break;
            case BROADCAST_TRANSACTION: // Transaction
                processTransaction(ptr);
                break;
            case RespondLog::type(): // log event
                processLogEvent(ptr, packet_size - 8);
                break;
            case ResponseAllLogIdRangesFromTick::type(): // logID ranges
                processLogRanges(header, ptr);
                break;
            default:
                break;
        }
    }
}

void replyTickData(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    uint32_t tick;
    memcpy(&tick, ptr, 4);
    FullTickStruct fts{};
    if (db_get_vtick(tick, fts))
    {
        struct
        {
            RequestResponseHeader header;
            TickData td;
        } resp;
        resp.td = fts.td;
        resp.header.setType(TickData::type());
        resp.header.setDejavu(dejavu);
        resp.header.setSize((sizeof(resp)));
        conn->sendData((uint8_t*)&resp, sizeof(resp));
    }
}

void replyTransaction(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    RequestedTickTransactions *request = (RequestedTickTransactions *)ptr;
    uint32_t tick = request->tick;
    FullTickStruct fts{};
    db_get_vtick(tick, fts);
    auto& td= fts.td;
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (td.transactionDigests[i] != m256i::zero())
        {
            if (!(request->transactionFlags[i >> 3] & (1 << (i & 7))))
            {
                char hash[64] = {0};
                getIdentityFromPublicKey(td.transactionDigests[i], hash, true);
                std::string strHash(hash);
                std::vector<uint8_t> txData;
                if (db_get_transaction(strHash, txData))
                {
                    RequestResponseHeader resp;
                    resp.setSize(8 + txData.size());
                    resp.setDejavu(dejavu);
                    resp.setType(BROADCAST_TRANSACTION);
                    conn->sendData((uint8_t *) &resp, sizeof(resp));
                    conn->sendData(txData.data(), txData.size());
                }
            }
        }
    }
    conn->sendEndPacket(dejavu);
    return;
}

void replyComputorList(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    if (computorsList.epoch != 0)
    {
        RequestResponseHeader resp{};
        resp.setSize(8 + sizeof(Computors));
        resp.setDejavu(dejavu);
        resp.setType(RESPOND_COMPUTOR_LIST);
        conn->sendData((uint8_t *) &resp, sizeof(resp));
        conn->sendData((uint8_t*)&computorsList, sizeof(computorsList));
        return;
    }
    conn->sendEndPacket(dejavu);
}

void replyTickVotes(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    auto *request = (RequestedQuorumTick *)ptr;
    uint32_t tick = request->tick;
    FullTickStruct fts{};
    db_get_vtick(tick, fts);
    for (int i = 0; i < NUMBER_OF_COMPUTORS; i++)
    {
        auto& tv = fts.tv[i];
        if (tv.epoch != 0)
        {
            if (!(request->voteFlags[i >> 3] & (1 << (i & 7))))
            {
                RequestResponseHeader resp{};
                resp.setSize(8 + sizeof(TickVote));
                resp.setDejavu(dejavu);
                resp.setType(BROADCAST_TICK_VOTE);
                conn->sendData((uint8_t *) &resp, sizeof(resp));
                conn->sendData((uint8_t*)&tv, sizeof(tv));
            }
        }
    }
    conn->sendEndPacket(dejavu);
    return;
}

void replyLogEvent(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    RequestLog* request = (RequestLog*)ptr;
    if (request->passcode[0] != 0 ||
            request->passcode[1] != 0 ||
            request->passcode[2] != 0 ||
            request->passcode[3] != 0)
    {
        conn->sendEndPacket();
        return;
    }
    if (request->toid - request->fromid + 1 >= 1000)
    {
        conn->sendEndPacket();
        return;
    }
    RequestResponseHeader header{};
    header.setDejavu(dejavu);
    header.setType(RespondLog::type());
    std::vector<uint8_t> resp;
    for (uint64_t i = request->fromid; i < request->toid; i++)
    {
        LogEvent le;
        if (db_get_log(gCurrentProcessingEpoch, i, le))
        {
            int currentSize = resp.size();
            resp.resize(currentSize + le.getLogSize() + LogEvent::PackedHeaderSize);
            memcpy(resp.data() + currentSize, le.getRawPtr(), le.getLogSize() + LogEvent::PackedHeaderSize);
        }
    }
    header.setSize(8 + resp.size());
    conn->sendData((uint8_t *) &header, sizeof(header));
    conn->sendData(resp.data(), resp.size());
}

void replyLogRange(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    RequestAllLogIdRangesFromTick* request = (RequestAllLogIdRangesFromTick*)ptr;
    if (request->passcode[0] != 0 ||
        request->passcode[1] != 0 ||
        request->passcode[2] != 0 ||
        request->passcode[3] != 0)
    {
        conn->sendEndPacket();
        return;
    }
    uint32_t tick = request->tick;
    ResponseAllLogIdRangesFromTick logRange;
    if (db_get_log_range_all_txs(tick, logRange)) {
        RequestResponseHeader resp{};
        resp.setSize(8 + sizeof(ResponseAllLogIdRangesFromTick));
        resp.setDejavu(dejavu);
        resp.setType(ResponseAllLogIdRangesFromTick::type());
        conn->sendData((uint8_t *) &resp, sizeof(resp));
        conn->sendData((uint8_t *) &logRange, sizeof(logRange));
        return;
    }
    conn->sendEndPacket(dejavu);
}

void RequestProcessorThread(std::atomic_bool& exitFlag)
{
    std::vector<uint8_t> buf;
    buf.resize(RequestResponseHeader::max_size, 0);
    uint8_t* ptr = buf.data();
    while (!exitFlag.load())
    {
        uint32_t packet_size = 0;
        MRB_Request.GetPacket(ptr, packet_size);
        if (packet_size == 0 || packet_size >= RequestResponseHeader::max_size)
        {
            Logger::get()->warn("Malformed packet_size: {}", packet_size);
            continue;
        }
        RequestResponseHeader header{};
        memcpy(&header, ptr, 8);
        auto type = header.type();
        ptr += 8;

        std::vector<uint8_t> ignore;
        QCPtr conn;
        requestMapperTo.get(header.getDejavu(), ignore, conn);
        if (conn == nullptr) continue;
        switch (type)
        {
            case REQUEST_COMPUTOR_LIST: // request computors list
                replyComputorList(conn, header.getDejavu(), ptr);
                break;
            case RequestedQuorumTick::type: // TickVote
                replyTickVotes(conn, header.getDejavu(), ptr);
                break;
            case RequestTickData::type: // TickData
                replyTickData(conn, header.getDejavu(), ptr);
                break;
            case REQUEST_TICK_TRANSACTIONS: // Transaction
                replyTransaction(conn, header.getDejavu(), ptr);
                break;
            case RequestLog::type():
                 replyLogEvent(conn, header.getDejavu(), ptr);
                break;
            case RequestAllLogIdRangesFromTick::type(): // logID ranges
                replyLogRange(conn, header.getDejavu(), ptr);
                break;
            default:
                break;
        }
    }
}