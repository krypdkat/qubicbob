#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <cstring>

#include "connection.h"
#include "structs.h"
#include "GlobalVar.h"
#include "Logger.h"
#include "db.h"
#include "K12AndKeyUtil.h"
#include "commonFunctions.h"
#include "Profiler.h"
#include "shim.h"
using namespace std::chrono_literals;

// verify if:
// - have tick data
// - have enough txs
// - quorum reach in tick votes
bool verifyQuorum(uint32_t tick, TickData& td, std::vector<TickVote>& votes)
{
    // check and fetch more votes
    int count = 0;
    for (int i = 0; i < 676; i++)
    {
        auto& vote = votes[i];
        if (vote.tick != tick)
        {
            db_get_tick_vote(tick, i, vote);
        }
        if (vote.tick == tick && vote.epoch == gCurrentProcessingEpoch) count++;
    }
    if (count < 225) {
        return false;
    }
    struct ConsensusData
    {
        unsigned int prevResourceTestingDigest;
        unsigned int prevTransactionBodyDigest;
        m256i prevSpectrumDigest;
        m256i prevUniverseDigest;
        m256i prevComputerDigest;
        m256i transactionDigest;

        bool operator<(const ConsensusData &other) const {
            if (prevResourceTestingDigest != other.prevResourceTestingDigest)
                return prevResourceTestingDigest < other.prevResourceTestingDigest;
            if (prevTransactionBodyDigest != other.prevTransactionBodyDigest)
                return prevTransactionBodyDigest < other.prevTransactionBodyDigest;
            if (memcmp(prevSpectrumDigest.m256i_u8, other.prevSpectrumDigest.m256i_u8, 32) != 0)
                return memcmp(prevSpectrumDigest.m256i_u8, other.prevSpectrumDigest.m256i_u8, 32) < 0;
            if (memcmp(prevUniverseDigest.m256i_u8, other.prevUniverseDigest.m256i_u8, 32) != 0)
                return memcmp(prevUniverseDigest.m256i_u8, other.prevUniverseDigest.m256i_u8, 32) < 0;
            if (memcmp(prevComputerDigest.m256i_u8, other.prevComputerDigest.m256i_u8, 32) != 0)
                return memcmp(prevComputerDigest.m256i_u8, other.prevComputerDigest.m256i_u8, 32) < 0;
            return memcmp(transactionDigest.m256i_u8, other.transactionDigest.m256i_u8, 32) < 0;
        }

    };
    std::map<ConsensusData, int> digestCount;
    for (const auto &vote: votes) {
        ConsensusData cd{};
        cd.prevResourceTestingDigest = vote.prevResourceTestingDigest;
        cd.prevTransactionBodyDigest = vote.prevTransactionBodyDigest;
        cd.prevSpectrumDigest = vote.prevSpectrumDigest;
        cd.prevUniverseDigest = vote.prevUniverseDigest;
        cd.prevComputerDigest = vote.prevComputerDigest;
        cd.transactionDigest = vote.transactionDigest;
        digestCount[cd]++;
    }

    int maxCount = 0;
    m256i maxDigest;
    for (const auto &pair: digestCount) {
        maxCount = std::max(maxCount, pair.second);
        if (maxCount == pair.second)
        {
            maxDigest = pair.first.transactionDigest;
        }
    }

    if (isArrayZero(maxDigest.m256i_u8, 32))
    {
        if (maxCount > 225)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else if (maxCount < 451) return false; // not yet collect enough data for non empty tick
    if (td.tick != tick || td.epoch != gCurrentProcessingEpoch)
    {
        if (!db_get_tick_data(tick, td))
        {
            return false;
        }
    }
    if (td.tick != tick || td.epoch != gCurrentProcessingEpoch)
    {
        return false;
    }
    for (int i= 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (!isArrayZero(td.transactionDigests[i], 32))
        {
            char qhash[64] = {0};
            getIdentityFromPublicKey(td.transactionDigests[i], qhash, true);
            std::string hash_str(qhash);
            if (!db_check_transaction_exist(hash_str))
            {
                return false;
            }
        }
    }

    uint8_t tdHash[32];
    KangarooTwelve((uint8_t*)&td, sizeof(TickData), tdHash, 32);
    if (memcmp(tdHash, maxDigest.m256i_u8, 32) != 0)
    {
        Logger::get()->critical("Consensus error: tickData {} is mismatched (there are potentially 2 tick data)", td.tick);
    }
    return true; // quorum reach
}

// Requester thread: periodically evaluates what to request next and sends requests over the connection.
// Placeholders (TODO) are included where the request conditions and payloads will be implemented.
void IORequestThread(ConnectionPool& conn_pool, std::atomic_bool& stopFlag, std::chrono::milliseconds requestCycle, uint32_t futureOffset)
{
    // Optional: pacing/tuning knobs
    const auto idleBackoff = 10ms;   // Backoff when there's nothing immediate to request
    const auto errorBackoff = 2000ms; // Backoff after an exception
    auto requestClock = std::chrono::high_resolution_clock::now() - requestCycle;
    while (!stopFlag.load(std::memory_order_relaxed)) {
        try {
            /* Don't need to fetch too far if not yet verifying*/
            while (gCurrentFetchingTick > gCurrentVerifyLoggingTick + 1000 && !stopFlag.load(std::memory_order_relaxed)) SLEEP(100);
            auto now = std::chrono::high_resolution_clock::now();
            if (now - requestClock >= requestCycle)
            {
                requestClock = now;
                for (uint32_t offset = 0; offset < futureOffset; offset++) {
                    bool have_next_td = false;
                    {
                        if (!db_has_tick_data(gCurrentFetchingTick + offset))
                        {
                            // request if this tick doesn't exist
                            struct {
                                RequestResponseHeader header;
                                unsigned int tick;
                            } pl{}; // type 16
                            pl.header.setSize(sizeof(pl));
                            pl.header.setType(16);
                            pl.header.randomizeDejavu();
                            pl.tick = gCurrentFetchingTick + offset;
                            conn_pool.sendToMany((uint8_t *) &pl, sizeof(pl), 1);
                        } else {
                            have_next_td = true;
                        }
                    }

                    {
                        // tick votes
                        struct {
                            RequestResponseHeader header;
                            unsigned int tick;
                            unsigned char voteFlags[(NUMBER_OF_COMPUTORS + 7) / 8];
                        } pl{}; // type 14
                        pl.header.setSize(sizeof(pl));
                        pl.header.setType(14);
                        pl.header.randomizeDejavu();
                        pl.tick = gCurrentFetchingTick + offset;
                        memset(pl.voteFlags, 0, sizeof(pl.voteFlags));
                        int count = 0;
                        auto tvs = db_get_tick_votes(gCurrentFetchingTick + offset);
                        for (auto& tv: tvs) {
                            int i = tv.computorIndex;
                            pl.voteFlags[i >> 3] |= (1 << (i & 7)); // turn on the flag if the vote exists
                            count++;
                        }
                        if (count < 676)
                        {
                            conn_pool.sendToMany((uint8_t *) &pl, sizeof(pl), 1);
                        }
                    }

                    {
                        // transactions: requires to have tickdata
                        if (have_next_td) {
                            TickData td{};
                            db_get_tick_data(gCurrentFetchingTick + offset, td);
                            struct {
                                RequestResponseHeader header;
                                unsigned int tick;
                                unsigned char flag[NUMBER_OF_TRANSACTIONS_PER_TICK / 8];
                            } pl{}; // type 29

                            pl.header.setSize(sizeof(pl));
                            pl.header.setType(29);
                            pl.header.randomizeDejavu();
                            pl.tick = gCurrentFetchingTick + offset;
                            memset(pl.flag, 0, sizeof(pl.flag));
                            int count = 0;
                            for (unsigned int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++) {
                                if (isArrayZero(td.transactionDigests[i], 32)) continue;
                                char qhash[64] = {0};
                                getIdentityFromPublicKey(td.transactionDigests[i], qhash, true);
                                std::string hash_str(qhash);
                                std::vector<uint8_t> tx_data;
                                if (db_check_transaction_exist(hash_str)) {
                                    pl.flag[i >> 3] |= (1 << (i & 7)); // turn on the flag if the tx exists
                                } else
                                {
                                    count++;
                                }
                            }
                            if (count) conn_pool.sendToMany((uint8_t *) &pl, sizeof(pl), 1);
                        }
                    }
                }
            }
        } catch (const std::exception& ex) {
            Logger::get()->warn("IORequestThread exception: {}", ex.what());
            std::this_thread::sleep_for(errorBackoff);
        } catch (...) {
            Logger::get()->warn("IORequestThread unknown exception.");
            std::this_thread::sleep_for(errorBackoff);
        }
    }
}

// Compress a verified tick: pack TickData + up to 676 TickVotes into FullTickStruct,
// store via db_insert_vtick, then delete raw TickData/TickVotes.
static void compressTick(uint32_t tick, TickData td, std::vector<TickVote> votes)
{
    bool haveTickData = td.tick == tick && td.epoch == gCurrentProcessingEpoch;
    // Load TickData
    // Prepare the aggregated struct
    FullTickStruct full{};
    std::memset((void*)&full, 0, sizeof(full));
    if (haveTickData) std::memcpy((void*)&full.td, &td, sizeof(TickData));

    for (const auto& v : votes)
    {
        if (v.computorIndex < 676 && v.epoch != 0)
        {
            std::memcpy((void*)&full.tv[v.computorIndex], &v, sizeof(TickVote));
        }
    }

    // Insert the compressed record
    if (!db_insert_vtick(tick, full))
    {
        Logger::get()->error("compressTick: Failed to insert vtick for tick {}", tick);
        return; // Do not delete raw data if insertion fails
    }

    // Delete raw TickData
    if (!db_delete_tick_data(tick))
    {
        Logger::get()->warn("compressTick: Failed to delete TickData for tick {}", tick);
    }

    // Delete all TickVotes for this tick (attempt all indices; API treats missing as success)
    for (uint16_t i = 0; i < 676; ++i)
    {
        if (!db_delete_tick_vote(tick, i))
        {
            Logger::get()->warn("compressTick: Failed to delete TickVote for tick {}, computor {}", tick, i);
        }
    }

    Logger::get()->trace("compressTick: Compressed and pruned raw data for tick {}", tick);
}

void IOVerifyThread(std::atomic_bool& stopFlag)
{
    const auto idleBackoff = 10ms;
    TickData td{};
    std::vector<TickVote> votes;
    votes.resize(676);
    memset(votes.data(), 0, votes.size() * sizeof(TickVote));
    while (!stopFlag.load())
    {
        if (!verifyQuorum(gCurrentFetchingTick, td, votes))
        {
            std::this_thread::sleep_for(idleBackoff);
        }
        else
        {
            auto current_tick = gCurrentFetchingTick.load();
            std::thread(compressTick, current_tick, td, votes).detach();
            db_update_latest_tick_and_epoch(gCurrentFetchingTick, gCurrentProcessingEpoch);
            Logger::get()->trace("Progress ticking from {} to {}", gCurrentFetchingTick.load(), gCurrentFetchingTick.load() + 1);
            uint32_t tmp_tick;
            uint16_t tmp_epoch;
            db_get_latest_tick_and_epoch(tmp_tick, tmp_epoch);
            if (current_tick == tmp_tick) gCurrentFetchingTick++;
        }
    }
}

// Receiver thread: continuously receives full packets and enqueues them into the global round buffer (MRB).
void connReceiver(QCPtr& conn, const bool isTrustedNode, std::atomic_bool& stopFlag)
{
    using namespace std::chrono_literals;

    const auto errorBackoff = 500ms;

    std::vector<uint8_t> packet;
    packet.reserve(64 * 1024); // Optional: initial capacity to minimize reallocations
    while (!stopFlag.load(std::memory_order_relaxed)) {
        try {
            // Blocking receive of a complete packet from the connection.
            RequestResponseHeader hdr{};
            conn->receiveAFullPacket(hdr, packet);

            if (packet.empty()) {
                // Defensive check; shouldn't happen if receiveAFullPacket succeeds.
                continue;
            }
            if (!isTrustedNode)
            {
                if (!checkAllowedTypeForNonTrusted(hdr.type()))
                {
                    continue; //drop
                }
            }
            // trusted conn allowed all packets
            if (isDataType(hdr.type()))
            {
                // Enqueue the packet into the global MutexRoundBuffer.
                bool ok = MRB_Data.EnqueuePacket(packet.data());
                if (!ok) {
                    Logger::get()->warn("connReceiver: failed to enqueue packet (size={}, type={}). Dropped.",
                                        packet.size(),
                                        static_cast<unsigned>(hdr.type()));
                }
            }

            if (isRequestType(hdr.type()))
            {
                if (!isTrustedNode)
                {
                    Logger::get()->info("Get a {} request", hdr.type());
                }
                bool ok = MRB_Request.EnqueuePacket(packet.data());
                if (!ok) {
                    Logger::get()->warn("connReceiver: failed to enqueue packet (size={}, type={}). Dropped.",
                                        packet.size(),
                                        static_cast<unsigned>(hdr.type()));
                }
                else
                {
                    requestMapperTo.add(hdr.getDejavu(), nullptr, 0, conn);
                }
            }

        } catch (const std::logic_error& ex) {
            if (!conn->isReconnectable()) return;
            Logger::get()->trace("connReceiver Too many error on : {}. Disconnecting", conn->getNodeIp());
            conn->disconnect();
            SLEEP(errorBackoff);
            conn->reconnect();
        } catch (...) {
            if (!conn->isReconnectable()) return;
            Logger::get()->trace("connReceiver unknown exception from ip {}", conn->getNodeIp());
            conn->disconnect();
            SLEEP(errorBackoff);
            conn->reconnect();
        }
    }
}