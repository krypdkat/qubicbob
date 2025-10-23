#include <atomic>
#include <chrono>
#include <thread>
#include "SpecialBufferStructs.h"
#include "structs.h"
#include "db.h"
#include "Logger.h"
#include "K12AndKeyUtil.h"
#include "GlobalVar.h"
#include "shim.h"
static bool matchesTransaction(const QuTransfer &transfer, const Transaction &tx) {
    return transfer.sourcePublicKey == tx.sourcePublicKey &&
            transfer.destinationPublicKey == tx.destinationPublicKey &&
           transfer.amount == tx.amount;
}

static std::string getTransactionHash(const unsigned char *digest) {
    char hash[65] = {0};
    getIdentityFromPublicKey(digest, hash, true);
    return std::string(hash);
}

static int getTransactionIndexFromLogId(const ResponseAllLogIdRangesFromTick &logrange, long long logId) {
    for (int i = 0; i < LOG_TX_PER_TICK; i++) {
        if (logId >= logrange.fromLogId[i] && logId < logrange.fromLogId[i] + logrange.length[i]) {
            return i;
        }
    }
    return -1;
}

// Index a single verified tick. Extend this to build/search indexes as needed.
static void indexTick(uint32_t tick, const TickData &td) {
    ResponseAllLogIdRangesFromTick logrange{};


    db_get_log_range_all_txs(tick, logrange);
    if (td.tick == tick)
    {
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++) {
            if (td.transactionDigests[i] == m256i::zero()) continue;
            std::string txHash = getTransactionHash(td.transactionDigests[i]);
            std::string key = "itx:" + txHash;

            LogEvent firstEvent;
            bool isExecuted = false;
            if (logrange.length[i] > 0) {
                db_get_log(td.epoch, logrange.fromLogId[i], firstEvent);
                if (firstEvent.getType() == QU_TRANSFER) { // QuTransfer type
                    auto transfer = (QuTransfer *) firstEvent.getLogBodyPtr();
                    std::vector<uint8_t> tx_data;
                    if (db_get_transaction(txHash, tx_data)) {
                        auto tx = (Transaction*)tx_data.data();
                        isExecuted = matchesTransaction(*transfer, *tx);
                    }
                }
            }
            db_set_indexed_tx(key.c_str(), i, logrange.fromLogId[i],
                              logrange.fromLogId[i] + logrange.length[i] - 1,
                              isExecuted);
        }
    }

    // handling 5 special events
    for (int i = SC_INITIALIZE_TX; i <= SC_END_EPOCH_TX; i++)
    {
        std::string key = "itx:" + std::to_string(tick) + "_" + std::to_string(i);
        db_set_indexed_tx(key.c_str(), i, logrange.fromLogId[i],
                          logrange.fromLogId[i] + logrange.length[i] - 1,
                          true);
    }

    // now handling all log events
    auto vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, tick, tick);
    uint32_t SC_index = 0;
    uint32_t logType = 0;
    m256i topic1, topic2, topic3;
    for (int i = 0; i < vle.size(); i++)
    {
        auto& le  = vle[i];
        auto type = le.getType();
        SC_index = 0xffffffff;
        switch(type)
        {
            case QU_TRANSFER:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<QuTransfer>();
                topic1 = e->sourcePublicKey;
                topic2 = e->destinationPublicKey;
                topic3 = m256i::zero();
                break;
            }
            case ASSET_ISSUANCE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetIssuance>();
                topic1 = e->issuerPublicKey;
                topic2 = m256i::zero();
                memcpy(topic2.m256i_u8, ((uint8_t*)e) + 32, 31);
                topic3 = m256i::zero();
                break;
            }
            case ASSET_OWNERSHIP_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetOwnershipChange>();
                topic1 = e->sourcePublicKey;
                topic2 = e->destinationPublicKey;
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->name, 7);
                KangarooTwelve(assetHash, 39, topic3.m256i_u8, 32);
                break;
            }
            case ASSET_POSSESSION_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetPossessionChange>();
                topic1 = e->sourcePublicKey;
                topic2 = e->destinationPublicKey;
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->name, 7);
                KangarooTwelve(assetHash, 39, topic3.m256i_u8, 32);
                break;
            }
            case ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetOwnershipManagingContractChange>();
                topic1 = e->ownershipPublicKey;
                topic2 = m256i::zero();
                topic3 = m256i::zero();
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->assetName, 7);
                KangarooTwelve(assetHash, 39, topic2.m256i_u8, 32);
                break;
            }
            case ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetPossessionManagingContractChange>();
                topic1 = e->ownershipPublicKey;
                topic2 = m256i::zero();
                topic3 = m256i::zero();
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->assetName, 7);
                KangarooTwelve(assetHash, 39, topic2.m256i_u8, 32);
                break;
            }
            case BURNING:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<Burning>();
                topic1 = e->sourcePublicKey;
                topic2 = m256i::zero();
                topic3 = m256i::zero();
                break;
            }

            case CONTRACT_ERROR_MESSAGE:
            case CONTRACT_WARNING_MESSAGE:
            case CONTRACT_INFORMATION_MESSAGE:
            case CONTRACT_DEBUG_MESSAGE:
            {
                auto ptr = le.getRawPtr();
                int le_sz = le.getLogSize();
                if (le_sz >= 8)
                {
                    memcpy(&SC_index, ptr, 4);
                    memcpy(&logType, ptr +4, 4);
                    if (logType >= 100000)
                    {
                        topic1 = m256i::zero();
                        topic2 = m256i::zero();
                        topic3 = m256i::zero();
                        if (le_sz - 8 > 0) memcpy(topic1.m256i_u8, ptr + 8, std::min(32, le_sz-8));
                        if (le_sz - 40 > 0) memcpy(topic2.m256i_u8, ptr + 40, std::min(32, le_sz-40));
                        if (le_sz - 72 > 0) memcpy(topic3.m256i_u8, ptr + 72, std::min(32, le_sz-72));
                    }
                    else
                    {
                        SC_index = 0xffffffff;
                    }
                }
            }
            case SPECTRUM_STATS:
                // nothing to do
                break;
            case DUST_BURNING:
                // TODO: simulate and implement this
                break;
            case CUSTOM_MESSAGE:
            {
                // no indexing
                break;
            }
            default:
                break;
        }
        if (SC_index != 0xffffffff)
        {
            std::string key;
            if (!(SC_index == 0 && logType == 0))
            {
                //bool db_add_indexer(const std::string &key, uint32_t tickNumber)
                if (SC_index != 0)
                {
                    key = "indexed:" + std::to_string(SC_index);
                    db_add_indexer(key, tick);
                }
                key = "indexed:" + std::to_string(SC_index) + ":" + std::to_string(logType);
                db_add_indexer(key, tick);
            }
            // populate all scenarios with topic1,2,3
            // 3 bits => 0=>7
            for (int bit = 0; bit < 8; bit++)
            {
                key = "indexed:" + std::to_string(SC_index) + ":" + std::to_string(logType) + ":";
                int isSet = 0;
                for (int j = 0; j < 3; j++)
                {
                    const m256i &topic = (j == 0) ? topic1 : ((j == 1) ? topic2 : topic3);
                    if (topic == m256i::zero()) {
                        key += std::string("ANY") + ((j == 2) ? "" : ":");
                    } else if ((bit >> j) & 1) {
                        char qhash[64] = {0};
                        getIdentityFromPublicKey(topic.m256i_u8, qhash, true);
                        std::string str_hash(qhash);
                        key += str_hash + ((j == 2) ? "" : ":");
                        isSet++;
                    } else {
                        key += std::string("ANY") + ((j == 2) ? "" : ":");
                    }
                }
                if (isSet) db_add_indexer(key, tick);
            }
        }
    }

    Logger::get()->trace("Indexed verified tick {}", tick);
}

bool tryGetTickData(uint32_t tick, TickData& data) {
    if (db_get_tick_data(tick, data)) {
        return true;
    }
    FullTickStruct full;
    if (db_get_vtick(tick, full)) {
        data = full.td;
        return true;
    }
    memset(&data, 0, sizeof(TickData));
    return true;
}

void indexVerifiedTicks(std::atomic_bool& stopFlag)
{
    using namespace std::chrono_literals;

    // Recover the last indexed tick; start from -1 if none is stored yet.
    long long lastIndexed = -1;
    lastIndexed = db_get_last_indexed_tick();
    if (lastIndexed == -1) lastIndexed = gInitialTick.load() - 1;
    gCurrentIndexingTick = lastIndexed;
    Logger::get()->info("QubicIndexer: starting at last_indexed_tick={}", lastIndexed);

    while (!stopFlag.load(std::memory_order_relaxed))
    {
        uint32_t nextTick = static_cast<uint32_t>(lastIndexed + 1);
        while (nextTick >= gCurrentVerifyLoggingTick && !stopFlag.load(std::memory_order_relaxed)) SLEEP(10);
        if (stopFlag.load(std::memory_order_relaxed)) break;

        // Only proceed when the verified-compressed record exists.
        TickData td;
        tryGetTickData(nextTick, td);
        indexTick(nextTick, td);

        // Persist progress.
        if (!db_update_last_indexed_tick(nextTick)) {
            Logger::get()->warn("QubicIndexer: failed to update last_indexed_tick to {}", nextTick);
            // Best-effort sleep to avoid hammering DB if there's a transient error.
            SLEEP(1000);
            continue;
        }

        lastIndexed = nextTick;
        gCurrentIndexingTick = lastIndexed;
    }

    Logger::get()->info("QubicIndexer: stopping gracefully at last_indexed_tick={}", lastIndexed);
}
