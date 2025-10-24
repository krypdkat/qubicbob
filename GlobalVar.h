#pragma once
#include <map>
#include <atomic>
#include "structs.h"
#include "SpecialBufferStructs.h"
#include "common_def.h"
#include <atomic>
#include <chrono>
#include <thread>

struct GlobalState {
    MutexRoundBuffer MRB_Data{512 * 1024u * 1024u};
    MutexRoundBuffer MRB_Request{128u * 1024u * 1024u};
    RequestMap requestMapperFrom;
    RequestMap requestMapperTo;

    std::atomic<uint32_t> gCurrentProcessingTick{0};
    std::atomic<uint16_t> gCurrentProcessingEpoch{0};
    std::atomic<uint32_t> gInitialTick{0};
    std::atomic<uint32_t> gCurrentLoggingEventTick{0};
    std::atomic<uint32_t> gCurrentVerifyLoggingTick{0};
    std::atomic<uint32_t> gCurrentIndexingTick{0};
    Computors computorsList{0};
    // Fixed-size global state buffers (no heap allocations)
    uint8_t spectrum[SPECTRUM_CAPACITY * 64]; // 64 is sizeof entity
    uint8_t assets[ASSETS_CAPACITY * 48];  // 48 is sizeof asset

    // Change flags bitsets
    unsigned long long assetChangeFlags[ASSETS_CAPACITY / (sizeof(unsigned long long) * 8)];
    unsigned long long spectrumChangeFlags[SPECTRUM_CAPACITY / (sizeof(unsigned long long) * 8)];

    // Pre-sized digest trees: full binary tree storage (2*N - 1) nodes
    m256i spectrumDigests[(SPECTRUM_CAPACITY * 2 - 1)];
    m256i assetDigests[(ASSETS_CAPACITY * 2 - 1)];

    // Rescue mode range
    long long refetchFromId{-1};
    long long refetchToId{-1};
};

// Safe, lazy singleton accessor avoids static init order issues.
GlobalState& GS();

#define SLEEP(x) std::this_thread::sleep_for(std::chrono::milliseconds(x))
#define BATCH_VERIFICATION 64
#define QU_TRANSFER 0
#define ASSET_ISSUANCE 1
#define ASSET_OWNERSHIP_CHANGE 2
#define ASSET_POSSESSION_CHANGE 3
#define CONTRACT_ERROR_MESSAGE 4
#define CONTRACT_WARNING_MESSAGE 5
#define CONTRACT_INFORMATION_MESSAGE 6
#define CONTRACT_DEBUG_MESSAGE 7
#define BURNING 8
#define DUST_BURNING 9
#define SPECTRUM_STATS 10
#define ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE 11
#define ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE 12
#define CUSTOM_MESSAGE 255
#define CUSTOM_MESSAGE_OP_START_DISTRIBUTE_DIVIDENDS 6217575821008262227ULL // STA_DDIV
#define CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS 6217575821008457285ULL //END_DDIV

static bool checkAllowedTypeForNonTrusted(int type)
{
    if (type == 45) return false;
    if (type == 51) return false;
    return true;
}

static bool isRequestType(int type)
{
    if (type == 11) return true; //request vote
    if (type == 14) return true; //request vote
    if (type == 16) return true; //request tickdata
    if (type == 29) return true; // request tx
    if (type == 44) return true; // request log
    if (type == 50) return true; // request log range
    return false;
}
static bool isDataType(int type)
{
    if (type == 3) return true; //vote
    if (type == 8) return true; //tickdata
    if (type == 24) return true; // tx
    if (type == 45) return true; // log
    if (type == 51) return true; //  logrange
    return false;
}