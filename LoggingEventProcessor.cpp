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
//    KT128((uint8_t*)input, 64, (uint8_t*)output, 32, nullptr, 0);
    KangarooTwelve((uint8_t*)input, 64, (uint8_t*)output, 32);
}

void computeSpectrumDigest(const uint32_t tickStart, const uint32_t tickEnd)
{
    unsigned int digestIndex;
    if (tickStart != UINT32_MAX)
    {
        for (digestIndex = 0; digestIndex < SPECTRUM_CAPACITY; digestIndex++)
        {
            if ( ((spectrum[digestIndex].latestIncomingTransferTick >= tickStart) && (spectrum[digestIndex].latestIncomingTransferTick <= tickEnd))
            || ((spectrum[digestIndex].latestOutgoingTransferTick >= tickStart) && (spectrum[digestIndex].latestOutgoingTransferTick <= tickEnd)))
            {
                KangarooTwelve64To32(&spectrum[digestIndex], &spectrumDigests[digestIndex]);
                spectrumChangeFlags[digestIndex >> 6] |= (1ULL << (digestIndex & 63));
            }
        }
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

m256i getUniverseDigest(const uint32_t tickStart, const uint32_t tickEnd)
{
    unsigned int digestIndex;
    if (tickStart != UINT32_MAX) {
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

void saveState(uint32_t& tracker, uint32_t lastVerified)
{
    Logger::get()->info("Saving verified universe/spectrum {} - Do not shutdown", lastVerified);
    std::string tickSpectrum = "spectrum." + std::to_string(lastVerified);
    std::string tickUniverse = "universe." + std::to_string(lastVerified);

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
    db_update_latest_verified_tick(lastVerified);
    tickSpectrum = "spectrum." + std::to_string(tracker);
    tickUniverse = "universe." + std::to_string(tracker);
    if (std::filesystem::exists(tickSpectrum) && std::filesystem::exists(tickUniverse)) {
        std::filesystem::remove(tickSpectrum);
        std::filesystem::remove(tickUniverse);
    }
    Logger::get()->info("Saved checkpoints. Deleted old verified universe/spectrum {}. ", tracker);
    tracker = lastVerified;
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
            Logger::get()->error("Cannot find snapshot files: {} and {}. bob will likely misalign and stuck", tickSpectrum, tickUniverse);
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
    computeSpectrumDigest(UINT32_MAX, UINT32_MAX);
    getUniverseDigest(UINT32_MAX, UINT32_MAX);
    while (gCurrentLoggingEventTick == gInitialTick) {
        if (stopFlag.load()) return;
        SLEEP(100);
    }
    while (!stopFlag.load())
    {
        while (gCurrentVerifyLoggingTick >= gCurrentLoggingEventTick && !stopFlag.load()) SLEEP(100);
        if (stopFlag.load()) return;
        uint32_t processFromTick = gCurrentVerifyLoggingTick;
        uint32_t processToTick = std::min(gCurrentVerifyLoggingTick + BATCH_VERIFICATION, gCurrentLoggingEventTick - 1);
        std::vector<LogEvent> vle;
        {
            PROFILE_SCOPE("db_get_logs_by_tick_range");
            vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, processFromTick, processToTick);
            // verify if we have enough logging
            long long fromId, length;
            db_get_combined_log_range_for_ticks(processFromTick, processToTick, fromId, length);

            if (fromId != -1 && length != -1 && vle.size() != length)
            {
                refetchFromId = fromId;
                refetchToId = fromId + length -1;
                Logger::get()->info("Entering rescue mode to fetch missing data");
                while (!stopFlag.load())
                {
                    SLEEP(1000);
                    vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, processFromTick, processToTick);
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
                if (!le.selfCheck(gCurrentProcessingEpoch))
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
                                if (!vle[i].selfCheck(gCurrentProcessingEpoch))
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
            db_spectrumDigest = db_getSpectrumDigest(processToTick);
            while (db_spectrumDigest == m256i::zero())
            {
                if (stopFlag.load()) return;
                SLEEP(1000);
                db_spectrumDigest = db_getSpectrumDigest(processToTick);
            }
            computeSpectrumDigest(processFromTick, processToTick);
            spectrumDigest = spectrumDigests[(SPECTRUM_CAPACITY * 2 - 1) - 1];
            if (spectrumDigest != db_spectrumDigest)
            {
                Logger::get()->warn("Failed spectrum digest at tick {} -> {}, please check!", processFromTick, processToTick);
                exit(-1);
            }

            db_universeDigest = db_getUniverseDigest(processToTick);
            while (db_universeDigest == m256i::zero())
            {
                if (stopFlag.load()) return;
                SLEEP(1000);
                db_universeDigest = db_getUniverseDigest(processToTick);
            }
            universeDigest = getUniverseDigest(processFromTick, processToTick);
        }

        if (universeDigest != db_universeDigest)
        {
            Logger::get()->warn("Failed universe digest at tick {} -> {}, please check!", processFromTick, processToTick);
            exit(-1);
        }
        else
        {
            Logger::get()->trace("Verified logging event tick {}->{}", processFromTick, processToTick);
            if (processToTick - lastVerifiedTick >= SAVE_PERIOD)
            {
                saveState(lastVerifiedTick, processToTick);
            }
            gCurrentVerifyLoggingTick = processToTick + 1;
        }
    }
    Logger::get()->info("verifyLoggingEvent stopping gracefully.");
}

// The logging fetcher thread: uses its own connection, shares DB with other threads.
void LoggingEventRequestThread(ConnectionPool& conn, std::atomic_bool& stopFlag, std::chrono::milliseconds requestCycle, uint32_t futureOffset)
{
    auto idleBackoff = 10ms;

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
            while (gCurrentLoggingEventTick >= gCurrentFetchingTick && !stopFlag.load(std::memory_order_relaxed)) SLEEP(100);
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
            SLEEP(idleBackoff);
        } catch (std::logic_error &ex) {

        }
    }

    Logger::get()->info("LoggingEventThread stopping gracefully.");
}