#include "ApiHelpers.h"
#include "K12AndKeyUtil.h"
#include "Entity.h"
#include "Asset.h"
#include "GlobalVar.h"
#include "database/db.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace ApiHelpers {

// ============================================================================
// Utility Functions
// ============================================================================

std::string bytesToHex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string getIdentityStr(const uint8_t* publicKey, bool lowercase) {
    return getIdentity(publicKey, lowercase);
}

// ============================================================================
// Balance Functions
// ============================================================================

BalanceInfo getBalanceInfo(const std::string& identity) {
    BalanceInfo info;

    if (identity.size() < 60) {
        info.error = "Wrong identity format";
        return info;
    }

    m256i pk{};
    getPublicKeyFromIdentity(identity.data(), pk.m256i_u8);
    int index = spectrumIndex(pk);

    if (index < 0) {
        info.error = "Identity not found in spectrum";
        return info;
    }

    const auto& e = spectrum[index];
    info.found = true;
    info.incomingAmount = e.incomingAmount;
    info.outgoingAmount = e.outgoingAmount;
    info.balance = e.incomingAmount - e.outgoingAmount;
    info.numberOfIncomingTransfers = e.numberOfIncomingTransfers;
    info.numberOfOutgoingTransfers = e.numberOfOutgoingTransfers;
    info.latestIncomingTransferTick = e.latestIncomingTransferTick;
    info.latestOutgoingTransferTick = e.latestOutgoingTransferTick;
    info.currentTick = gCurrentVerifyLoggingTick.load() - 1;

    // Check if entity is being processed
    if (e.numberOfIncomingTransfers > info.currentTick ||
        e.numberOfOutgoingTransfers > info.currentTick) {
        info.isBeingProcessed = true;
    }

    return info;
}

// ============================================================================
// Asset Functions
// ============================================================================

AssetBalanceInfo getAssetBalanceInfo(const std::string& identity,
                                      const std::string& assetIssuer,
                                      const std::string& assetName,
                                      uint32_t manageSCIndex) {
    AssetBalanceInfo info;

    if (identity.size() < 60 || assetIssuer.size() < 60) {
        info.error = "Invalid identity format";
        return info;
    }

    m256i pk, issuer;
    uint64_t asset_name = 0;

    getPublicKeyFromIdentity(identity.c_str(), pk.m256i_u8);
    getPublicKeyFromIdentity(assetIssuer.c_str(), issuer.m256i_u8);
    memcpy(&asset_name, assetName.data(), std::min(size_t(7), assetName.size()));

    long long ownershipBalance, possessionBalance;
    getAssetBalances(pk, issuer, asset_name, manageSCIndex, ownershipBalance, possessionBalance);

    info.found = true;
    info.ownershipBalance = ownershipBalance;
    info.possessionBalance = possessionBalance;

    return info;
}

// ============================================================================
// Transaction Functions
// ============================================================================

TransactionInfo getTransactionInfo(const std::string& txHash) {
    TransactionInfo info;

    if (txHash.empty()) {
        info.error = "Invalid transaction hash";
        return info;
    }

    std::vector<uint8_t> txData;
    if (!db_try_get_transaction(txHash.c_str(), txData)) {
        info.error = "Transaction not found";
        return info;
    }

    Transaction* tx = reinterpret_cast<Transaction*>(txData.data());
    if (!tx) {
        info.error = "Invalid transaction data";
        return info;
    }

    info.found = true;
    info.hash = txHash;
    info.from = getIdentity(tx->sourcePublicKey, false);
    info.to = getIdentity(tx->destinationPublicKey, false);
    info.amount = tx->amount;
    info.tick = tx->tick;
    info.inputSize = tx->inputSize;
    info.inputType = tx->inputType;

    // Encode input data as hex
    if (tx->inputSize > 0) {
        const uint8_t* input = txData.data() + sizeof(Transaction);
        info.inputData = bytesToHex(input, tx->inputSize);
    }

    // Try to get indexed information
    int tx_index;
    long long from_log_id, to_log_id;
    uint64_t timestamp;
    bool executed;

    if (db_get_indexed_tx(txHash.c_str(), tx_index, from_log_id, to_log_id, timestamp, executed)) {
        info.hasIndexedInfo = true;
        info.transactionIndex = tx_index;
        info.logIdFrom = from_log_id;
        info.logIdTo = to_log_id;
        info.timestamp = timestamp;
        info.executed = executed;
    }

    return info;
}

// ============================================================================
// Epoch Functions
// ============================================================================

EpochInfo getEpochInfo(uint16_t epoch) {
    EpochInfo info;
    info.epoch = epoch;

    std::string es = std::to_string(epoch);

    uint32_t initTick = 0;
    db_get_u32("init_tick:" + es, initTick);
    info.initialTick = initTick;

    uint32_t endTick = 0;
    db_get_u32("end_epoch_tick:" + es, endTick);
    info.endTick = endTick;

    long long start = -1, length = -1;
    db_get_end_epoch_log_range(epoch, start, length);
    info.endTickStartLogId = start;
    info.endTickEndLogId = start + length - 1;

    info.found = true;
    return info;
}

EpochInfo getCurrentEpochInfo() {
    uint16_t epoch = gCurrentProcessingEpoch.load();
    EpochInfo info = getEpochInfo(epoch);
    info.currentTick = gCurrentVerifyLoggingTick.load();
    return info;
}

// ============================================================================
// Sync Status Functions
// ============================================================================

SyncStatus getSyncStatus() {
    SyncStatus status;

    status.epoch = gCurrentProcessingEpoch.load();
    status.initialTick = gInitialTick.load();
    status.currentFetchingTick = gCurrentFetchingTick.load();
    status.currentFetchingLogTick = gCurrentFetchingLogTick.load();
    status.currentVerifyLoggingTick = gCurrentVerifyLoggingTick.load();
    status.currentIndexingTick = gCurrentIndexingTick.load();
    status.currentNetworkTick = gCurrentNetworkTick.load();

    // Determine sync status
    uint32_t verifyLoggingTick = status.currentVerifyLoggingTick;
    uint32_t fetchingTick = status.currentFetchingTick;
    uint32_t networkTick = status.currentNetworkTick;

    bool isSynced;
    if (networkTick > 0) {
        // If we know the network tick, use it for sync determination
        isSynced = (networkTick <= verifyLoggingTick + 10);
    } else {
        // Fallback: compare internal pipeline stages
        isSynced = (fetchingTick <= verifyLoggingTick + 10);
    }

    status.isSyncing = !isSynced;

    if (status.isSyncing) {
        uint32_t targetTick = (networkTick > 0) ? networkTick : fetchingTick;
        uint32_t initialTick = status.initialTick;
        if (verifyLoggingTick > initialTick && targetTick > initialTick) {
            status.progress = static_cast<double>(verifyLoggingTick - initialTick) /
                              static_cast<double>(targetTick - initialTick);
        }
    }

    return status;
}

} // namespace ApiHelpers
