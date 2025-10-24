#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <cstring>
#include <algorithm>
#include "m256i.h"
#include "connection.h"
#include "structs.h"
#include "GlobalVar.h"
#include "Logger.h"
#include "db.h"
#include "K12AndKeyUtil.h"
#include "commonFunctions.h"
#include "Entity.h"
#include "Asset.h"
#include <string>
#include <filesystem>
#include <queue>
#include "Profiler.h"
#include "shim.h"
using namespace std::chrono_literals;
extern "C" {
    // declare for xkcp
int KT128(const unsigned char *input, size_t inputByteLen,
          unsigned char *output, size_t outputByteLen,
          const unsigned char *customization, size_t customByteLen);
}
// Constants (kept local to this translation unit)
static constexpr long long MAX_LOG_EVENT_PER_CALL = 100000;

static void KangarooTwelve64To32(void* input, void* output)
{
    KT128((uint8_t*)input, 64, (uint8_t*)output, 32, nullptr, 0);
}

void computeSpectrumDigest(const uint32_t tick)
{
    unsigned int digestIndex;
    if (tick != UINT32_MAX)
    {
        // pass
    }
    else
    {
        for (digestIndex = 0; digestIndex < SPECTRUM_CAPACITY; digestIndex++)
        {
            KangarooTwelve64To32(&spectrum[digestIndex], &spectrumDigests[digestIndex]);
            spectrumChangeFlags[digestIndex >> 6] |= (1ULL << (digestIndex & 63));
        }
    }

    unsigned int previousLevelBeginning = 0;
    unsigned int numberOfLeafs = SPECTRUM_CAPACITY;
    while (numberOfLeafs > 1)
    {
        for (unsigned int i = 0; i < numberOfLeafs; i += 2)
        {
            if (spectrumChangeFlags[i >> 6] & (3ULL << (i & 63)))
            {
                KangarooTwelve64To32(&spectrumDigests[previousLevelBeginning + i], &spectrumDigests[digestIndex]);
                spectrumChangeFlags[i >> 6] &= ~(3ULL << (i & 63));
                spectrumChangeFlags[i >> 7] |= (1ULL << ((i >> 1) & 63));
            }
            digestIndex++;
        }
        previousLevelBeginning += numberOfLeafs;
        numberOfLeafs >>= 1;
    }
    spectrumChangeFlags[0] = 0;
}

m256i getUniverseDigest(uint32_t tick)
{
    unsigned int digestIndex;
    if (tick != UINT32_MAX) {
        for (digestIndex = 0; digestIndex < ASSETS_CAPACITY; digestIndex++)
        {
            if (assetChangeFlags[digestIndex >> 6] & (1ULL << (digestIndex & 63)))
            {
                KangarooTwelve((uint8_t*)&assets[digestIndex], sizeof(AssetRecord), (uint8_t*)&assetDigests[digestIndex], 32);
            }
        }
    }
    else
    {
        for (digestIndex = 0; digestIndex < ASSETS_CAPACITY; digestIndex++)
        {
            KangarooTwelve((uint8_t*)&assets[digestIndex], sizeof(AssetRecord), (uint8_t*)&assetDigests[digestIndex], 32);
            assetChangeFlags[digestIndex >> 6] |= (1ULL << (digestIndex & 63));
        }
    }

    unsigned int previousLevelBeginning = 0;
    unsigned int numberOfLeafs = ASSETS_CAPACITY;
    while (numberOfLeafs > 1)
    {
        for (unsigned int i = 0; i < numberOfLeafs; i += 2)
        {
            if (assetChangeFlags[i >> 6] & (3ULL << (i & 63)))
            {
                KangarooTwelve64To32(&assetDigests[previousLevelBeginning + i], &assetDigests[digestIndex]);
                assetChangeFlags[i >> 6] &= ~(3ULL << (i & 63));
                assetChangeFlags[i >> 7] |= (1ULL << ((i >> 1) & 63));
            }
            digestIndex++;
        }
        previousLevelBeginning += numberOfLeafs;
        numberOfLeafs >>= 1;
    }
    assetChangeFlags[0] = 0;

    return assetDigests[(ASSETS_CAPACITY * 2 - 1) - 1];
}

void processQuTransfer(LogEvent& le)
{
    QuTransfer qt;
    memcpy((void*)&qt, le.getLogBodyPtr(), sizeof(QuTransfer));
    auto src_idx = spectrumIndex(qt.sourcePublicKey);
    if (src_idx != -1)
    {
        if (!decreaseEnergy(src_idx, qt.amount, le.getTick()))
        {
            Logger::get()->critical("QUs transfer: Failed to decrease energy");
        }
    }
    else
    {
        if (qt.sourcePublicKey != m256i::zero()) Logger::get()->critical("QUs transfer has invalid source index");
    }
    increaseEnergy(qt.destinationPublicKey, qt.amount, le.getTick());
}

bool processDistributeDividends(std::vector<LogEvent>& vle)
{
    if (vle.size() == 0) return true;
    // sanity check
    for (auto& le : vle)
    {
        if (le.getType() != QU_TRANSFER) return false;
    }
    QuTransfer qt;
    memcpy((void*)&qt, vle[0].getLogBodyPtr(), sizeof(QuTransfer));
    auto src_id = qt.sourcePublicKey;
    long long total = 0;
    for (auto& le : vle)
    {
        QuTransfer qt1;
        memcpy((void*)&qt1, le.getLogBodyPtr(), sizeof(QuTransfer));
        if (qt1.sourcePublicKey != qt.sourcePublicKey) return false;
        total += qt1.amount;
    }
    auto src_idx = spectrumIndex(qt.sourcePublicKey);
    if (src_idx == -1) return false;
    decreaseEnergy(src_idx, total, vle[0].getTick());
    for (auto& le : vle)
    {
        QuTransfer qt1;
        memcpy((void*)&qt1, le.getLogBodyPtr(), sizeof(QuTransfer));
        increaseEnergy(qt1.destinationPublicKey, qt1.amount, vle[0].getTick());
    }
    return true;
}

void processQuBurn(LogEvent& le)
{
    Burning b;
    memcpy((void*)&b, le.getLogBodyPtr(), sizeof(Burning));
    auto src_idx = spectrumIndex(b.sourcePublicKey);
    if (src_idx != -1) decreaseEnergy(src_idx, b.amount, le.getTick());
}

void processIssueAsset(LogEvent& le)
{
    AssetIssuance ai;
    memcpy((void*)&ai, le.getLogBodyPtr(), sizeof(AssetIssuance));
    int issuanceIndex, ownershipIndex, possessionIndex;
    issueAsset(ai.issuerPublicKey, ai.name, ai.numberOfDecimalPlaces, ai.unitOfMeasurement, ai.numberOfShares, ai.managingContractIndex,
               &issuanceIndex, &ownershipIndex, &possessionIndex);
}

// this is currently go with a pair Possession & Ownership
// need to update when the core changes ie: only transfer either Possession or Ownership
void processChangeOwnershipAndPossession(LogEvent& le0, LogEvent& le1)
{
    // sanity check
    bool valid = true;
    valid &= ((le0.getType() == ASSET_OWNERSHIP_CHANGE) && (le1.getType() == ASSET_POSSESSION_CHANGE)) || ((le1.getType() == ASSET_OWNERSHIP_CHANGE) && (le0.getType() == ASSET_POSSESSION_CHANGE));
    if (!valid)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    LogEvent ownership, possession;
    if (le0.getType() == ASSET_OWNERSHIP_CHANGE)
    {
        ownership = le0;
        possession = le1;
    }
    else
    {
        ownership = le1;
        possession = le0;
    }
    AssetOwnershipChange aoc{};
    AssetPossessionChange apc{};
    memcpy((void*)&aoc, ownership.getLogBodyPtr(), sizeof(AssetOwnershipChange));
    memcpy((void*)&apc, possession.getLogBodyPtr(), sizeof(AssetPossessionChange));
    if (memcmp(&aoc, &apc, sizeof(AssetOwnershipChange)) != 0)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    uint64_t assetName = 0;
    memcpy((void*)&assetName, aoc.name, 7);
    transferShareOwnershipAndPossession(assetName, aoc.issuerPublicKey, aoc.sourcePublicKey, aoc.sourcePublicKey, aoc.numberOfShares, aoc.managingContractIndex, aoc.destinationPublicKey);
}

// this is currently go with a pair Possession & Ownership
// need to update when the core changes ie: only transfer either Possession or Ownership
void processChangeManagingContract(LogEvent& le0, LogEvent& le1)
{
    // sanity check
    bool valid = true;
    valid &= ((le0.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE) && (le1.getType() == ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE))
            || ((le1.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE) && (le0.getType() == ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE));
    if (!valid)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    LogEvent ownership, possession;
    if (le0.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE)
    {
        ownership = le0;
        possession = le1;
    }
    else
    {
        ownership = le1;
        possession = le0;
    }
    AssetOwnershipManagingContractChange omcc{};
    AssetPossessionManagingContractChange pmcc{};
    memcpy((void*)&omcc, ownership.getLogBodyPtr(), sizeof(AssetOwnershipManagingContractChange));
    memcpy((void*)&pmcc, possession.getLogBodyPtr(), sizeof(AssetPossessionManagingContractChange));
    if (omcc.ownershipPublicKey != pmcc.ownershipPublicKey ||
            (memcmp(omcc.assetName, pmcc.assetName, 7) != 0) ||
            (omcc.numberOfShares != pmcc.numberOfShares) ||
            (omcc.sourceContractIndex != pmcc.sourceContractIndex) ||
            (omcc.destinationContractIndex != pmcc.destinationContractIndex)
        )
    {
        Logger::get()->error("Invalid pair Possession or Ownership in transfering management rights");
        exit(1);
    }
    uint64_t assetName = 0;
    memcpy((void*)&assetName, omcc.assetName, 7);
    long long nshare = omcc.numberOfShares;
    auto issuer = omcc.issuerPublicKey;
    auto owner = omcc.ownershipPublicKey;
    auto poss = pmcc.possessionPublicKey;
    auto src_id = omcc.sourceContractIndex;
    auto dst_id = omcc.destinationContractIndex;
    int issuanceIndex, ownershipIndex, possessionIndex;
    findIssuerIndex(issuer, assetName, &issuanceIndex);
    findOwnershipIndex(issuanceIndex, owner, src_id, &ownershipIndex);
    findPossessionIndex(ownershipIndex, poss, src_id, &possessionIndex);
    int destinationOwnershipIndexPtr, destinationPossessionIndexPtr;
    if (!transferShareManagementRights(ownershipIndex, possessionIndex, dst_id, dst_id, nshare,
                                  &destinationOwnershipIndexPtr, &destinationPossessionIndexPtr, false))
    {
        Logger::get()->error("Failed to transfer management rights");
        exit(1);
    }
}

// Small helper to load a fixed-size array from a binary file with uniform logging.
static bool loadFile(const std::string& path,
                     void* outBuffer,
                     size_t elementSize,
                     size_t elementCount,
                     const char* label)
{
    Logger::get()->info("Loading file {}", path);
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        Logger::get()->error("Failed to open {} file: {}", label, path);
        return false;
    }
    size_t readCount = fread(outBuffer, elementSize, elementCount, f);
    fclose(f);
    if (readCount != elementCount) {
        Logger::get()->error("Failed to read {} file. Expected {} records, got {}",
                             label, elementCount, readCount);
        return false;
    }
    return true;
}

#define SAVE_PERIOD 1000

// Compress a verified tick: pack TickData + up to 676 TickVotes into FullTickStruct,
// store via db_insert_vtick, then delete raw TickData/TickVotes.
void compressTick(uint32_t tick)
{
    // Load TickData
    bool haveTickData = true;
    TickData td{};
    if (!db_get_tick_data(tick, td))
    {
        // empty tick
        haveTickData = false;
    }

    // Prepare the aggregated struct
    FullTickStruct full{};
    std::memset((void*)&full, 0, sizeof(full));
    if (haveTickData) std::memcpy((void*)&full.td, &td, sizeof(TickData));

    // Fetch all votes for the tick (some may be missing)
    std::vector<TickVote> votes = db_get_tick_votes(tick);
    for (const auto& v : votes)
    {
        if (v.computorIndex < 676)
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

static std::queue<uint32_t> gCompressQueue;
static std::mutex gCompressMutex;
static std::condition_variable gCompressCv;
static std::vector<std::thread> gCompressWorkers;
static std::once_flag gCompressInitOnce;
static std::condition_variable gCompressDoneCv;
static std::atomic<unsigned int> gCompressPending{0};
static std::atomic<bool> gCompressStop{false}; // graceful shutdown flag

static void initCompressionWorkers()
{
    unsigned int hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 2; // conservative default
    // Choose worker count; cap a bit to avoid overloading DB
    const unsigned int workers = std::min<unsigned int>(hw, 16);

    for (unsigned int i = 0; i < workers; ++i)
    {
        gCompressWorkers.emplace_back([](){
            for (;;)
            {
                uint32_t tick;
                {
                    std::unique_lock<std::mutex> lk(gCompressMutex);
                    gCompressCv.wait(lk, [] { return gCompressStop.load() || !gCompressQueue.empty(); });
                    if (gCompressStop.load() && gCompressQueue.empty()) {
                        // Stop requested and no work left.
                        return;
                    }
                    tick = gCompressQueue.front();
                    gCompressQueue.pop();
                }
                // Run compression outside the lock
                compressTick(tick);

                // Notify when the queue drains and no work is pending.
                unsigned int remaining = --gCompressPending;
                if (remaining == 0) {
                    std::unique_lock<std::mutex> lk(gCompressMutex);
                    if (gCompressQueue.empty()) {
                        Logger::get()->info("Background compression finished.");
                        gCompressDoneCv.notify_all();
                    }
                }
            }
        });
        // no detach; we will join on shutdown
    }
}

static inline void enqueueCompression(uint32_t tick)
{
    std::call_once(gCompressInitOnce, initCompressionWorkers);
    {
        std::lock_guard<std::mutex> lk(gCompressMutex);
        gCompressPending++;
        gCompressQueue.push(tick);
    }
    gCompressCv.notify_one();
}

// Expose a shutdown function to stop and join workers.
void shutdownCompressionWorkers()
{
    {
        std::lock_guard<std::mutex> lk(gCompressMutex);
        gCompressStop.store(true);
    }
    gCompressCv.notify_all();

    for (auto &t : gCompressWorkers) {
        if (t.joinable()) t.join();
    }
    gCompressWorkers.clear();

    // Reset for potential re-init in future runs (optional).
    gCompressStop.store(false);
}


void saveStateAndCompressDB(uint32_t& lastVerifiedTick)
{
    Logger::get()->info("Saving verified universe/spectrum {} - Do not shutdown", gCurrentVerifyLoggingTick);
    std::string tickSpectrum = "spectrum." + std::to_string(gCurrentVerifyLoggingTick);
    std::string tickUniverse = "universe." + std::to_string(gCurrentVerifyLoggingTick);

    FILE *f = fopen(tickSpectrum.c_str(), "wb");
    if (!f) {
        Logger::get()->error("Failed to open spectrum file for writing: {}", tickSpectrum);
    } else {
        if (fwrite(spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, f) != SPECTRUM_CAPACITY) {
            Logger::get()->error("Failed to write spectrum file: {}", tickSpectrum);
        }
        fclose(f);
    }

    f = fopen(tickUniverse.c_str(), "wb");
    if (!f) {
        Logger::get()->error("Failed to open universe file for writing: {}", tickUniverse);
    } else {
        if (fwrite(assets, sizeof(AssetRecord), ASSETS_CAPACITY, f) != ASSETS_CAPACITY) {
            Logger::get()->error("Failed to write universe file: {}", tickUniverse);
        }
        fclose(f);
    }
    db_update_latest_verified_tick(gCurrentVerifyLoggingTick);
    tickSpectrum = "spectrum." + std::to_string(lastVerifiedTick);
    tickUniverse = "universe." + std::to_string(lastVerifiedTick);
    if (std::filesystem::exists(tickSpectrum) && std::filesystem::exists(tickUniverse)) {
        std::filesystem::remove(tickSpectrum);
        std::filesystem::remove(tickUniverse);
    }
    Logger::get()->info("Saved checkpoints. Deleted old verified universe/spectrum {}. "
                        "Data Compression will run in background. "
                        "Please wait for finish message before shutting down", lastVerifiedTick);
    for (uint32_t tick = lastVerifiedTick + 1; tick <= gCurrentVerifyLoggingTick; tick++)
    {
        //compressTick(tick);
        enqueueCompression(tick);
    }
    lastVerifiedTick = gCurrentVerifyLoggingTick;
}


void verifyLoggingEvent(std::atomic_bool& stopFlag)
{
    uint32_t lastVerifiedTick = db_get_latest_verified_tick();
    std::string spectrumFilePath;
    std::string assetFilePath;
    // Choose default files based on lastVerifiedTick; fallback to epoch files if any is missing.
    if (lastVerifiedTick != -1) {
        std::string tickSpectrum = "spectrum." + std::to_string(lastVerifiedTick);
        std::string tickUniverse = "universe." + std::to_string(lastVerifiedTick);
        if (std::filesystem::exists(tickSpectrum) && std::filesystem::exists(tickUniverse)) {
            spectrumFilePath = std::move(tickSpectrum);
            assetFilePath    = std::move(tickUniverse);
        } else {
            spectrumFilePath = "spectrum." + std::to_string(gCurrentProcessingEpoch);
            assetFilePath    = "universe." + std::to_string(gCurrentProcessingEpoch);
        }
    } else {
        spectrumFilePath = "spectrum." + std::to_string(gCurrentProcessingEpoch);
        assetFilePath    = "universe." + std::to_string(gCurrentProcessingEpoch);
        lastVerifiedTick =  gInitialTick - 1;
    }

    if (!loadFile(spectrumFilePath, spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, "spectrum")) {
        return;
    }

    if (!loadFile(assetFilePath, assets, sizeof(AssetRecord), ASSETS_CAPACITY, "universe")) {
        return;
    }
    gCurrentVerifyLoggingTick = lastVerifiedTick+1;
    computeSpectrumDigest(UINT32_MAX);
    getUniverseDigest(UINT32_MAX);
    while (gCurrentLoggingEventTick == gInitialTick) {
        if (stopFlag.load()) return;
        SLEEP(100);
    }
    while (!stopFlag.load())
    {
        while (gCurrentVerifyLoggingTick >= gCurrentLoggingEventTick && !stopFlag.load()) SLEEP(100);
        if (stopFlag.load()) return;
        std::vector<LogEvent> vle;
        {
            PROFILE_SCOPE("db_get_logs_by_tick_range");
            vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, gCurrentVerifyLoggingTick, gCurrentVerifyLoggingTick);
            // verify if we have enough logging
            long long fromId, length;
            db_get_log_range_for_tick(gCurrentVerifyLoggingTick, fromId, length);
            if (fromId != -1 && length != -1 && vle.size() != length)
            {
                refetchFromId = fromId;
                refetchToId = fromId + length -1;
                Logger::get()->info("Entering rescue mode to fetch missing data");
                while (!stopFlag.load())
                {
                    SLEEP(1000);
                    vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, gCurrentVerifyLoggingTick, gCurrentVerifyLoggingTick);
                    if (vle.size() == length)
                    {
                        Logger::get()->info("Successfully refetch data log {} => {}", refetchFromId, refetchToId);
                        break;
                    }
                    else
                    {
                        Logger::get()->info("Failed to get data log {} => {}", refetchFromId, refetchToId);
                    }
                }
                if (stopFlag.load()) return;
                refetchFromId = -1;
                refetchToId = -1;
            }
        }

        LogEvent* ple = nullptr; // to solve the case of transferring ownership & possession, they go with pair
        LogEvent* ple1 = nullptr; // to solve the case of transferring management rights, they go with pair
        {
            PROFILE_SCOPE("simulating");
            for (int i = 0; i < vle.size(); i++)
            {
                auto& le  = vle[i];

                // If self-check fails, skip this entry and reset any pairing state to avoid
                // dereferencing invalid bodies or headers.
                if (!le.selfCheck(gCurrentProcessingEpoch, gCurrentVerifyLoggingTick))
                {
                    Logger::get()->critical("Failed selfCheck in logging event");
                    ple = nullptr;
                    ple1 = nullptr;
                    exit(2);
                }

                auto type = le.getType();
                switch(type)
                {
                    case QU_TRANSFER:
                        processQuTransfer(le);
                        break;
                    case ASSET_ISSUANCE:
                        processIssueAsset(le);
                        break;
                    case ASSET_OWNERSHIP_CHANGE:
                    case ASSET_POSSESSION_CHANGE:
                        if (ple)
                        {
                            processChangeOwnershipAndPossession(*ple, le);
                            ple = nullptr;
                        }
                        else
                        {
                            ple = &le;
                        }
                        break;
                    case ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE:
                    case ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE:
                        if (ple1)
                        {
                            processChangeManagingContract(*ple1, le);
                            ple1 = nullptr;
                        }
                        else
                        {
                            ple1 = &le;
                        }
                        break;
                    case BURNING:
                        processQuBurn(le);
                        break;
                    case CONTRACT_ERROR_MESSAGE:
                    case CONTRACT_WARNING_MESSAGE:
                    case CONTRACT_INFORMATION_MESSAGE:
                    case CONTRACT_DEBUG_MESSAGE:
                    case SPECTRUM_STATS:
                        // nothing to do
                        break;
                    case DUST_BURNING:
                        // TODO: simulate and implement this
                        break;
                    case CUSTOM_MESSAGE:
                    {
                        uint64_t msg = le.getCustomMessage();
                        if (msg == CUSTOM_MESSAGE_OP_START_DISTRIBUTE_DIVIDENDS)
                        {
                            i += 1;
                            std::vector<LogEvent> dd;
                            while (msg != CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS && i < vle.size())
                            {
                                // Skip any malformed entries inside the dividend window as well.
                                if (!vle[i].selfCheck(gCurrentProcessingEpoch, gCurrentVerifyLoggingTick))
                                {
                                    Logger::get()->critical("Failed logEvent selfCheck in dividend window");
                                    i += 1;
                                    exit(2);
                                }

                                if (vle[i].getType() != 255)
                                {
                                    dd.push_back(vle[i]);
                                    i += 1;
                                }
                                else
                                {
                                    msg = vle[i].getCustomMessage();
                                    if (msg == CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS)
                                    {
                                        break;
                                    }
                                    else
                                    {
                                        Logger::get()->error("Expecting OP_END_DISTRIBUTE_DIVIDENDS, but received {}", msg);
                                    }
                                }
                            }
                            if (msg != CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS)
                            {
                                Logger::get()->critical("Missing OP END Distribute dividends");
                                exit(-1);
                            }
                            processDistributeDividends(dd);
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }
        m256i db_spectrumDigest, spectrumDigest,  db_universeDigest, universeDigest;
        {
            PROFILE_SCOPE("computeDigests");
            db_spectrumDigest = db_getSpectrumDigest(gCurrentVerifyLoggingTick);
            while (db_spectrumDigest == m256i::zero())
            {
                if (stopFlag.load()) return;
                SLEEP(1000);
                db_spectrumDigest = db_getSpectrumDigest(gCurrentVerifyLoggingTick);
            }
            computeSpectrumDigest(gCurrentVerifyLoggingTick);
            spectrumDigest = spectrumDigests[(SPECTRUM_CAPACITY * 2 - 1) - 1];
            if (spectrumDigest != db_spectrumDigest)
            {
                Logger::get()->warn("Failed spectrum digest at tick {}, please check!", gCurrentVerifyLoggingTick);
                exit(-1);
            }

            db_universeDigest = db_getUniverseDigest(gCurrentVerifyLoggingTick);
            while (db_universeDigest == m256i::zero())
            {
                if (stopFlag.load()) return;
                SLEEP(1000);
                db_universeDigest = db_getUniverseDigest(gCurrentVerifyLoggingTick);
            }
            universeDigest = getUniverseDigest(gCurrentVerifyLoggingTick);
        }

        if (universeDigest != db_universeDigest)
        {
            Logger::get()->warn("Failed universe digest at tick {}, please check!", gCurrentVerifyLoggingTick);
            exit(-1);
        }
        else
        {
            Logger::get()->trace("Verified logging event tick {}", gCurrentVerifyLoggingTick);
            if (gCurrentVerifyLoggingTick - lastVerifiedTick == SAVE_PERIOD)
            {
                saveStateAndCompressDB(lastVerifiedTick);
            }
            gCurrentVerifyLoggingTick++;
        }
    }
    Logger::get()->info("verifyLoggingEvent stopping gracefully.");
}

// The logging fetcher thread: uses its own connection, shares DB with other threads.
void LoggingEventRequestThread(ConnectionPool& conn, std::atomic_bool& stopFlag, std::chrono::milliseconds requestCycle, uint32_t futureOffset)
{
    auto idleBackoff = 50ms;         // Start at 50ms
    constexpr auto minBackoff = 5ms; // Lower bound
    constexpr auto maxBackoff = 500ms; // Upper bound

    while (!stopFlag.load(std::memory_order_relaxed)) {
        bool advancedTick = false; // "working" if we managed to advance the tick this loop

        try {
            while (refetchFromId != -1 && refetchToId != -1 && !stopFlag.load(std::memory_order_relaxed))
            {
                for (long long s = refetchFromId; s <= refetchToId; s += MAX_LOG_EVENT_PER_CALL) {
                    long long e = std::min(refetchToId, s + MAX_LOG_EVENT_PER_CALL - 1);
                    struct {
                        RequestResponseHeader header;
                        unsigned long long passcode[4];
                        unsigned long long fromid;
                        unsigned long long toid;
                    } packet;
                    memset(&packet, 0, sizeof(packet));
                    packet.header.setSize(sizeof(packet));
                    packet.header.randomizeDejavu();
                    packet.header.setType(RequestLog::type());
                    packet.fromid = s;
                    packet.toid = e;
                    conn.sendWithPasscodeToRandom((uint8_t *) &packet, 8, packet.header.size());
                }
                SLEEP(100);
            }
            while (gCurrentLoggingEventTick >= gCurrentProcessingTick && !stopFlag.load(std::memory_order_relaxed)) SLEEP(100);
            if (stopFlag.load(std::memory_order_relaxed)) break;
            if (!db_check_log_range(gCurrentLoggingEventTick))
            {
                struct {
                    RequestResponseHeader header;
                    unsigned long long passcode[4];
                    unsigned int tick;
                } packet;
                memset(&packet, 0, sizeof(packet));
                packet.header.setSize(sizeof(packet));
                packet.header.randomizeDejavu();
                packet.header.setType(RequestAllLogIdRangesFromTick::type());
                packet.tick = gCurrentLoggingEventTick;
                conn.sendWithPasscodeToRandom((uint8_t *) &packet, 8, packet.header.size());
            } else {
                long long fromId, length;
                db_get_log_range_for_tick(gCurrentLoggingEventTick, fromId, length);
                if (fromId == -1 || length == -1)
                {
                    Logger::get()->trace("Tick {} doesn't generate any log. Advancing logEvent tick", gCurrentLoggingEventTick);
                    gCurrentLoggingEventTick++;
                    idleBackoff = std::max(std::chrono::milliseconds(idleBackoff) - 5ms, minBackoff);
                    continue;
                }
                long long endId = fromId + length - 1; // inclusive
                while (db_log_exists(gCurrentProcessingEpoch, fromId) && fromId <= endId) fromId++;
                for (long long s = fromId; s <= endId; s += MAX_LOG_EVENT_PER_CALL) {
                    long long e = std::min(endId, s + MAX_LOG_EVENT_PER_CALL - 1);
                    struct {
                        RequestResponseHeader header;
                        unsigned long long passcode[4];
                        unsigned long long fromid;
                        unsigned long long toid;
                    } packet;
                    memset(&packet, 0, sizeof(packet));
                    packet.header.setSize(sizeof(packet));
                    packet.header.randomizeDejavu();
                    packet.header.setType(RequestLog::type());
                    packet.fromid = s;
                    packet.toid = e;
                    conn.sendWithPasscodeToRandom((uint8_t *) &packet, 8, packet.header.size());
                }
                if (fromId >= endId)
                {
                    Logger::get()->trace("Advancing logEvent tick {}", gCurrentLoggingEventTick);
                    gCurrentLoggingEventTick++;
                    db_update_latest_event_tick_and_epoch(gCurrentLoggingEventTick, gCurrentProcessingEpoch);
                    advancedTick = true; // progressed with enough data
                }
            }
            for (int i = 1; i < 5; i++)
            {
                if (!db_check_log_range(gCurrentLoggingEventTick + i))
                {
                    struct {
                        RequestResponseHeader header;
                        unsigned long long passcode[4];
                        unsigned int tick;
                    } packet;
                    memset(&packet, 0, sizeof(packet));
                    packet.header.setSize(sizeof(packet));
                    packet.header.randomizeDejavu();
                    packet.header.setType(RequestAllLogIdRangesFromTick::type());
                    packet.tick = gCurrentLoggingEventTick + i;
                    conn.sendWithPasscodeToRandom((uint8_t *) &packet, 8, packet.header.size());
                }
            }

            // Dynamic auto-scaling backoff: tighten when "working", relax when "idle"
            if (advancedTick) {
                // Progress made: reduce by 5ms down to minBackoff
                idleBackoff = std::max(std::chrono::milliseconds(idleBackoff) - 5ms, minBackoff);
            } else {
                // No progress: increase by 5ms up to maxBackoff
                idleBackoff = std::min(std::chrono::milliseconds(idleBackoff) + 5ms, maxBackoff);
            }

            SLEEP(idleBackoff);
        } catch (std::logic_error &ex) {

        }
    }

    Logger::get()->info("LoggingEventThread stopping gracefully.");
}