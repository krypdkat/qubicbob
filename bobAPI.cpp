// interop for other program to interact with BOB
#include "bob.h"
#include "K12AndKeyUtil.h"
#include "shim.h"
#include "Entity.h"
#include "db.h"
#include <vector>
#include <sstream>
#include <iomanip>

std::string bobGetBalance(const char* identity)
{
    if (!identity) return "{\"error\": \"Wrong identity format\"}";
    std::string str(identity);
    if (str.size() < 60) return "{\"error\": \"Wrong identity format\"}";

    m256i pk{};
    getPublicKeyFromIdentity(str.data(), pk.m256i_u8);
    int index = spectrumIndex(pk);
    if (index < 0) return "{\"error\": \"Wrong identity format\"}";

    const auto& e = spectrum[index];
    return std::string("{") +
           "\"incomingAmount\":" + std::to_string(e.incomingAmount) +
            ",\"outgoingAmount\":" + std::to_string(e.outgoingAmount) +
            ",\"balance\":" + std::to_string(e.incomingAmount - e.outgoingAmount) +
           ",\"numberOfIncomingTransfers\":" + std::to_string(e.numberOfIncomingTransfers) +
           ",\"numberOfOutgoingTransfers\":" + std::to_string(e.numberOfOutgoingTransfers) +
           ",\"latestIncomingTransferTick\":" + std::to_string(e.latestIncomingTransferTick) +
           ",\"latestOutgoingTransferTick\":" + std::to_string(e.latestOutgoingTransferTick) +
           "}";
}

std::string bobGetAsset(const char* identity)
{
    return "NOT YET IMPLEMENTED";
}

std::string bobGetTransaction(const char* txHash)
{
    if (!txHash) return "{\"error\": \"Invalid transaction hash\"}";

    try {
        std::vector<uint8_t> txData;
        if (!db_get_transaction(txHash, txData)) {
            return "{\"error\": \"Transaction not found\"}";
        }
        Transaction *tx = reinterpret_cast<Transaction *>(txData.data());
        if (!tx) {
            return "{\"error\": \"Invalid transaction data\"}";
        }
        std::string inputData = "";
        if (tx->inputSize)
        {
            const uint8_t *input = txData.data() + sizeof(Transaction);
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (size_t i = 0; i < tx->inputSize; ++i) {
                ss << std::setw(2) << static_cast<int>(input[i]);
            }
            inputData = ss.str();
        }
        int tx_index;
        long long from_log_id;
        long long to_log_id;
        bool executed;
        if (!db_get_indexed_tx(txHash, tx_index, from_log_id, to_log_id, executed)) {
            return std::string("{") +
                   "\"hash\":\"" + txHash + "\"," +
                   "\"from\":\"" + getIdentity(tx->sourcePublicKey, false) + "\"," +
                   "\"to\":\"" + getIdentity(tx->destinationPublicKey, false) + "\"," +
                   "\"amount\":" + std::to_string(tx->amount) + "," +
                   "\"tick\":" + std::to_string(tx->tick) + "," +
                    "\"inputSize\":" + std::to_string(tx->inputSize) + "," +
                    "\"inputData\":\"" + inputData + "\"" +
                    "}";
        }

        return std::string("{") +
               "\"hash\":\"" + txHash + "\"," +
               "\"from\":\"" + getIdentity(tx->sourcePublicKey, false) + "\"," +
               "\"to\":\"" + getIdentity(tx->destinationPublicKey, false) + "\"," +
               "\"amount\":" + std::to_string(tx->amount) + "," +
               "\"tick\":" + std::to_string(tx->tick) + "," +
                "\"logIdFrom\":" + std::to_string(from_log_id) + "," +
                "\"logIdTo\":" + std::to_string(to_log_id) + "," +
                "\"transactionIndex\":" + std::to_string(tx_index) + "," +
                "\"executed\":" + (executed ? "true" : "false") + "," +
                "\"inputSize\":" + std::to_string(tx->inputSize) + "," +
                "\"inputData\":\"" + inputData + "\"" +
                "}";
    } catch (const std::exception &e) {
        return std::string("{\"error\": \"") + e.what() + "\"}";
    }
}

std::string bobGetLog(long long start, long long end)
{
    (void)start;
    (void)end;
    return "NOT YET IMPLEMENTED";
}

std::string bobGetTick(const uint32_t tick)
{
    (void)tick;
    return "NOT YET IMPLEMENTED";
}

std::string bobFindLog(uint32_t scIndex, uint32_t logType, const char* topic1, const char* topic2, const char* topic3)
{
    (void)scIndex;
    (void)logType;
    (void)topic1;
    (void)topic2;
    (void)topic3;
    return "NOT YET IMPLEMENTED";
}