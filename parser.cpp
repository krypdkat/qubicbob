#include "parser.h"
#include <string>
#include <cstring>
#include "utils.h"
#include "Logger.h"
#include "K12AndKeyUtil.h"
#include <vector>
#include <algorithm>

// 0 is short form, 1 is more details, 2 is all details
int parseToStringDetailLevel = 1;

constexpr int QU_TRANSFER = 0;
constexpr int QU_TRANSFER_LOG_SIZE = 72;
constexpr int ASSET_ISSUANCE = 1;
constexpr int ASSET_ISSUANCE_LOG_SIZE = 55;
constexpr int ASSET_OWNERSHIP_CHANGE = 2;
constexpr int ASSET_OWNERSHIP_CHANGE_LOG_SIZE = 119;
constexpr int ASSET_POSSESSION_CHANGE = 3;
constexpr int ASSET_POSSESSION_CHANGE_LOG_SIZE = 119;
constexpr int CONTRACT_ERROR_MESSAGE = 4;
constexpr int CONTRACT_ERROR_MESSAGE_LOG_SIZE = 4;
constexpr int CONTRACT_WARNING_MESSAGE = 5;
constexpr int CONTRACT_INFORMATION_MESSAGE = 6;
constexpr int CONTRACT_DEBUG_MESSAGE = 7;
constexpr int BURNING = 8;
constexpr int BURNING_LOG_SIZE = 40;
constexpr int DUST_BURNING = 9;
constexpr int DUST_BURNING_MAX_LOG_SIZE = 2621442;
constexpr int SPECTRUM_STATS = 10;
constexpr int SPECTRUM_STATS_LOG_SIZE = 224;
constexpr int CUSTOM_MESSAGE = 255;

constexpr int LOG_HEADER_SIZE = 26; // 2 bytes epoch + 4 bytes tick + 4 bytes log size/types + 8 bytes log id + 8 bytes log digest

std::string logTypeToString(uint8_t type){
    switch(type){
        case QU_TRANSFER: return "QU transfer";
        case ASSET_ISSUANCE: return "Asset issuance";
        case ASSET_OWNERSHIP_CHANGE: return "Asset ownership change";
        case ASSET_POSSESSION_CHANGE: return "Asset possession change";
        case CONTRACT_ERROR_MESSAGE: return "Contract error";
        case CONTRACT_WARNING_MESSAGE: return "Contract warning";
        case CONTRACT_INFORMATION_MESSAGE: return "Contract info";
        case CONTRACT_DEBUG_MESSAGE: return "Contract debug";
        case BURNING: return "Burn";
        case DUST_BURNING: return "Dust burn";
        case SPECTRUM_STATS: return "Spectrum stats";
        case CUSTOM_MESSAGE: return "Custom msg";
    }
    return "Unknown msg";
}

std::string parseLogToString_type0(const uint8_t* ptr){
    char sourceIdentity[61] = {0};
    char destIdentity[61] = {0};
    uint64_t amount;
    const bool isLowerCase = false;
    getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
    getIdentityFromPublicKey(ptr+32, destIdentity, isLowerCase);
    memcpy(&amount, ptr+64, sizeof(amount));
    return "from " + std::string(sourceIdentity) + " to " + std::string(destIdentity) + " " + std::to_string(amount) + "QU.";
}

std::string parseLogToString_type1(const uint8_t* ptr){
    char sourceIdentity[61] = {0};
    char name[8] = {0};
    char numberOfDecimalPlaces = 0;
    uint8_t unit[8] = {0};
    long long numberOfShares = 0;

    const bool isLowerCase = false;
    getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
    memcpy(&numberOfShares, ptr+32, sizeof(numberOfShares));
    memcpy(name, ptr+32+8, 7);
    numberOfDecimalPlaces = ptr[32+8+7];
    memcpy(unit, ptr+32+8+7+1, 7);

    return std::string(sourceIdentity) + " issued " + std::to_string(numberOfShares) + " " + std::string(name)
           + ". Number of decimal: " + std::to_string(numberOfDecimalPlaces) + ". Unit of measurement: "
           + std::to_string(unit[0]) + "-" + std::to_string(unit[1]) + "-"
           + std::to_string(unit[2]) + "-" + std::to_string(unit[3]) + "-"
           + std::to_string(unit[4]) + "-" + std::to_string(unit[5]) + "-"
           + std::to_string(unit[6]);
}

std::string parseToStringBurningLog(const uint8_t* ptr)
{
    char sourceIdentity[61] = { 0 };
    uint64_t burnAmount;
    memcpy(&burnAmount, ptr + 32, sizeof(burnAmount));
    getIdentityFromPublicKey(ptr, sourceIdentity, false);
    return std::string(sourceIdentity) + " burned " + std::to_string(burnAmount) + " QU";
}

struct DustBurning
{
    unsigned short numberOfBurns;

    struct Entity
    {
        unsigned char publicKey[32];
        unsigned long long amount;
    };
    static_assert(sizeof(Entity) == 40, "Unexpected size");

    unsigned int messageSize() const
    {
        return 2 + numberOfBurns * sizeof(Entity);
    }

    Entity& entity(unsigned short i)
    {
        char* buf = reinterpret_cast<char*>(this);
        return *reinterpret_cast<Entity*>(buf + i * (sizeof(Entity)) + 2);
    }
};

std::string parseToStringDustBurningLog(uint8_t* ptr, uint32_t messageSize)
{
    DustBurning* db = (DustBurning*)ptr;
    if (messageSize < 2 || messageSize > DUST_BURNING_MAX_LOG_SIZE || db->messageSize() != messageSize)
        return "null";

    std::string retVal = "balances of " + std::to_string(db->numberOfBurns) + " entities burned as dust";
    if (parseToStringDetailLevel >= 1)
    {
        char identity[61] = { 0 };
        for (int i = 0; i < db->numberOfBurns; ++i)
        {
            const DustBurning::Entity& e = db->entity(i);
            getIdentityFromPublicKey(e.publicKey, identity, false);
            retVal += "\n\t" + std::to_string(i) + ": " + std::to_string(e.amount) + " QU of " + identity;

            if (parseToStringDetailLevel < 2 && i == 1 && db->numberOfBurns > 5)
            {
                retVal += "\n\t...";
                i = db->numberOfBurns - 2;
            }
        }
    }

    return retVal;
}

std::string parseToStringSpectrumStats(uint8_t* ptr)
{
    struct SpectrumStats
    {
        unsigned long long totalAmount;
        unsigned long long dustThresholdBurnAll;
        unsigned long long dustThresholdBurnHalf;
        unsigned int numberOfEntities;
        unsigned int entityCategoryPopulations[48];
    };
    SpectrumStats* s = (SpectrumStats*)ptr;
    
    std::string retVal = std::to_string(s->totalAmount) + " QU in " + std::to_string(s->numberOfEntities)
        + " entities, dust threshold " + std::to_string(s->dustThresholdBurnAll);
    if (s->dustThresholdBurnHalf != 0)
        retVal += " (burn all <=), " + std::to_string(s->dustThresholdBurnHalf) + " (burn half <=)";
    if (parseToStringDetailLevel >= 1)
    {
        for (int i = 0; i < 48; ++i)
        {
            if (s->entityCategoryPopulations[i])
            {
                unsigned long long lowerBound = (1llu << i), upperBound = (1llu << (i + 1)) - 1;
                const char* burnIndicator = "\n\t+ bin ";
                if (lowerBound <= s->dustThresholdBurnAll)
                    burnIndicator = "\n\t- bin ";
                else if (lowerBound <= s->dustThresholdBurnHalf)
                    burnIndicator = "\n\t* bin ";
                retVal += burnIndicator + std::to_string(i) + ": " + std::to_string(s->entityCategoryPopulations[i]) + " entities with balance between "
                    + std::to_string(lowerBound) + " and " + std::to_string(upperBound);
            }
        }
    }

    return retVal;
}

std::string parseLogToString_type2_type3(const uint8_t* ptr){
    char sourceIdentity[61] = {0};
    char dstIdentity[61] = {0};
    char issuerIdentity[61] = {0};
    char name[8] = {0};
    char numberOfDecimalPlaces = 0;
    char unit[8] = {0};
    long long numberOfShares = 0;
    const bool isLowerCase = false;
    getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
    getIdentityFromPublicKey(ptr+32, dstIdentity, isLowerCase);
    getIdentityFromPublicKey(ptr+64, issuerIdentity, isLowerCase);
    memcpy(&numberOfShares, ptr+96, sizeof(numberOfShares));
    memcpy(name, ptr+96+8, 7);
    numberOfDecimalPlaces = ptr[96+8+7];
    memcpy(unit, ptr+96+8+7+1, 7);
    return "from " + std::string(sourceIdentity) + " to " + std::string(dstIdentity) + " " + std::to_string(numberOfShares) + " " + std::string(name)
           + "(Issuer: " + std::string(issuerIdentity) + ")"
           + ". Number of decimal: " + std::to_string(numberOfDecimalPlaces) + ". Unit of measurement: "
           + std::to_string(unit[0]) + "-" + std::to_string(unit[1]) + "-"
           + std::to_string(unit[2]) + "-" + std::to_string(unit[3]) + "-"
           + std::to_string(unit[4]) + "-" + std::to_string(unit[5]) + "-"
           + std::to_string(unit[6]);
}

unsigned long long printQubicLog(uint8_t* logBuffer, int bufferSize, uint64_t fromId, uint64_t toId){
    if (bufferSize == 0){
        Logger::get()->info("Empty log\n");
        return -1;
    }
    if (bufferSize < LOG_HEADER_SIZE){
        Logger::get()->warn("Buffer size is too small (not enough to contain the header), expected %d | received %d\n", LOG_HEADER_SIZE, bufferSize);
        return -1;
    }
    const uint8_t* end = logBuffer + bufferSize;
    unsigned long long retLogId = 0;
    bool isBigChunk = (toId > fromId) && (toId - fromId > 3000);
    if (isBigChunk)
    {
        printf("[LARGE LOGGING BATCH => ONLY PRINT HEAD AND TAIL]\n");
    }
    while (logBuffer < end){
        if (logBuffer + LOG_HEADER_SIZE > end) {
            Logger::get()->warn("Error: Incomplete log header at end of buffer.\n");
            break;
        }
        // basic info
        uint16_t epoch;
        uint32_t tick;
        uint32_t tmp;
        uint64_t logId;
        uint64_t logDigest;

        memcpy(&epoch, logBuffer, sizeof(epoch));
        memcpy(&tick, logBuffer + 2, sizeof(tick));
        memcpy(&tmp, logBuffer + 6, sizeof(tmp));
        memcpy(&logId, logBuffer + 10, sizeof(logId));
        memcpy(&logDigest, logBuffer + 18, sizeof(logDigest));

        if (logId > retLogId) retLogId = logId;
        
        uint8_t messageType = tmp >> 24;
        std::string mt = logTypeToString(messageType);
        uint32_t messageSize = tmp & 0x00FFFFFF;

        if (logBuffer + LOG_HEADER_SIZE + messageSize > end)
        {
            Logger::get()->warn("Error: log buffer contains incomplete log message (log ID %llu)\n", logId);
            return retLogId;
        }

        uint64_t computedLogDigest = 0;
        KangarooTwelve(logBuffer + LOG_HEADER_SIZE, messageSize, (uint8_t*) &computedLogDigest, sizeof(computedLogDigest));
        if (logDigest != computedLogDigest)
        {
            Logger::get()->warn("------------------------------\n");
            Logger::get()->warn("WARNING: mismatched log digest\n");
            Logger::get()->warn("------------------------------\n");
            return retLogId;
        }

        logBuffer += LOG_HEADER_SIZE;
        std::string humanLog = "null";
        switch(messageType){
            case QU_TRANSFER:
                if (messageSize == QU_TRANSFER_LOG_SIZE){
                    humanLog = parseLogToString_type0(logBuffer);
                } else {
                    Logger::get()->warn("Malfunction buffer size for QU_TRANSFER log\n");
                }
                break;
            case ASSET_ISSUANCE:
                if (messageSize == ASSET_ISSUANCE_LOG_SIZE){
                    humanLog = parseLogToString_type1(logBuffer);
                } else {
                    Logger::get()->warn("Malfunction buffer size for ASSET_ISSUANCE log\n");
                }
                break;
            case ASSET_OWNERSHIP_CHANGE:
            case ASSET_POSSESSION_CHANGE:
                if (messageSize == ASSET_OWNERSHIP_CHANGE_LOG_SIZE){
                    humanLog = parseLogToString_type2_type3(logBuffer);
                } else {
                    Logger::get()->warn("Malfunction buffer size for ASSET_OWNERSHIP/POSSESSION_CHANGE log\n");
                }
                break;
            case BURNING:
                if (messageSize == BURNING_LOG_SIZE) {
                    humanLog = parseToStringBurningLog(logBuffer);
                } else {
                    Logger::get()->warn("Malfunction buffer size for BURNING log\n");
                }
                break;
            case DUST_BURNING:
                humanLog = parseToStringDustBurningLog(logBuffer, messageSize);
                if (humanLog == "null") {
                    Logger::get()->warn("Malfunction buffer size for DUST_BURNING log\n");
                }
                break;
            case SPECTRUM_STATS:
                if (messageSize == SPECTRUM_STATS_LOG_SIZE) {
                    humanLog = parseToStringSpectrumStats(logBuffer);
                } else {
                    Logger::get()->warn("Malfunction buffer size for SPECTRUM_STATS log\n");
                }
                break;
            case CONTRACT_INFORMATION_MESSAGE:
            case CONTRACT_ERROR_MESSAGE:
            case CONTRACT_WARNING_MESSAGE:
            case CONTRACT_DEBUG_MESSAGE:
            case CUSTOM_MESSAGE:
            {
                if (messageSize < sizeof(uint32_t)) {
                    humanLog = "Invalid contract message: too short";
                    break;
                }
                uint32_t contractId;
                memcpy(&contractId, logBuffer, sizeof(contractId));
                humanLog = "Contract ID #" + std::to_string(contractId) + " ";

                if (messageType == CONTRACT_INFORMATION_MESSAGE) humanLog += "INFO: ";
                else if (messageType == CONTRACT_ERROR_MESSAGE) humanLog += "ERROR: ";
                else if (messageType == CONTRACT_WARNING_MESSAGE) humanLog += "WARNING: ";
                else if (messageType == CONTRACT_DEBUG_MESSAGE) humanLog += "DEBUG: ";
                else if (messageType == CUSTOM_MESSAGE) humanLog += "CUSTOM: ";

                const uint32_t hexDataSize = messageSize - sizeof(uint32_t);
                std::vector<char> buff(hexDataSize * 2 + 1, 0);
                byteToHex(logBuffer + sizeof(uint32_t), buff.data(), hexDataSize);
                humanLog += std::string(buff.data());
                break;
            }
        }
        if (isBigChunk)
        {
            if ((logId < (fromId + 10) || (logId > toId - 10)))
            {
                Logger::get()->info("[%llu] %u.%03u %s: %s\n", logId, tick, epoch, mt.c_str(), humanLog.c_str());
            }
        }
        else
        {
            Logger::get()->info("[%llu] %u.%03u %s: %s\n", logId, tick, epoch, mt.c_str(), humanLog.c_str());
        }
        
        if (humanLog == "null"){
            const uint32_t max_bytes_to_print = 1024;
            uint32_t bytes_to_print = std::min(messageSize, max_bytes_to_print);
            std::vector<char> buff(bytes_to_print * 2 + 1, 0);
            byteToHex(logBuffer, buff.data(), bytes_to_print);
            Logger::get()->warn("NO parser for this message yet | Original message (%u bytes): %s%s\n", messageSize, buff.data(), (messageSize > max_bytes_to_print) ? "..." : "");
        }
        logBuffer+= messageSize;
    }
    return retLogId;
}