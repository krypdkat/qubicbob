#include <gtest/gtest.h>
#include <sw/redis++/redis++.h>
#include "db.h"
#include "K12AndKeyUtil.h"
#include "Logger.h"

// ---- Test Configuration ----
const std::string REDIS_CONNECTION_STRING = "tcp://127.0.0.1:6379";
// ---- Helper Functions for Test Data ----

// Fills a buffer with a sequence of bytes
void fill_buffer(unsigned char* buf, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        buf[i] = static_cast<unsigned char>(i % 256);
    }
}

TickVote create_dummy_tick_vote(uint32_t tick, uint16_t computorIndex) {
    TickVote vote{};
    vote.tick = tick;
    vote.computorIndex = computorIndex;
    vote.epoch = 1;
    vote.year = 24;
    fill_buffer(vote.signature, SIGNATURE_SIZE);
    return vote;
}

TickData create_dummy_tick_data(uint32_t tick, uint16_t computorIndex) {
    TickData data{};
    data.tick = tick;
    data.computorIndex = computorIndex;
    data.epoch = 1;
    fill_buffer(data.timelock, 32);
    return data;
}

// Transaction is variable size, so we need to handle allocation
std::vector<uint8_t> create_dummy_transaction_buffer(uint32_t tick, uint16_t inputSize) {
    size_t total_size = sizeof(Transaction) + inputSize + SIGNATURE_SIZE;
    std::vector<uint8_t> buffer(total_size, 0);

    Transaction* tx = reinterpret_cast<Transaction*>(buffer.data());
    tx->tick = tick;
    tx->inputSize = inputSize;
    fill_buffer(tx->sourcePublicKey, 32);
    fill_buffer(buffer.data() + sizeof(Transaction) + inputSize, SIGNATURE_SIZE);

    return buffer;
}

// ---- Test Fixture ----

class DBTest : public ::testing::Test {
protected:
    std::unique_ptr<sw::redis::Redis> _redis_admin;

    void SetUp() override {
        try {
            _redis_admin = std::make_unique<sw::redis::Redis>(REDIS_CONNECTION_STRING);
            _redis_admin->flushdb();
        } catch (const sw::redis::Error& e) {
            FAIL() << "Cannot connect to Redis for test setup: " << e.what();
        }
        db_connect(REDIS_CONNECTION_STRING);
    }

    void TearDown() override {
        db_close();
        if (_redis_admin) {
            _redis_admin.reset();
        }
    }
};

// ---- Test Cases ----

// Step 3: Test connection management.
TEST(DBConnectionTest, ConnectAndClose) {
    Logger::init("none"); //call once
    ASSERT_NO_THROW(db_connect(REDIS_CONNECTION_STRING));
    ASSERT_NO_THROW(db_connect(REDIS_CONNECTION_STRING)); // Should be a no-op
    db_close();
    db_close(); // Should be a no-op
}

TEST(DBConnectionTest, InvalidConnection) {
    ASSERT_THROW(db_connect("tcp://invalid-host:1234"), std::runtime_error);
}

TEST_F(DBTest, OperationsFailWhenNotConnected) {
    db_close(); // Close the connection from SetUp
    TickVote vote = create_dummy_tick_vote(1, 1);
    ASSERT_FALSE(db_insert_tick_vote(vote));
    uint32_t tick;
    uint16_t epoch;
    ASSERT_FALSE(db_get_latest_tick_and_epoch(tick, epoch));
}

// Step 4: Test core functionality for TickVote.
TEST_F(DBTest, InsertAndGetTickVote) {
    TickVote vote_to_insert = create_dummy_tick_vote(100, 42);
    ASSERT_TRUE(db_insert_tick_vote(vote_to_insert));

    TickVote retrieved_vote{};
    ASSERT_TRUE(db_get_tick_vote(100, 42, retrieved_vote));
    ASSERT_EQ(0, memcmp(&vote_to_insert, &retrieved_vote, sizeof(TickVote)));
}

// Step 5: Test edge cases, such as retrieving non-existent data.
TEST_F(DBTest, GetNonExistentTickVote) {
    TickVote retrieved_vote{};
    ASSERT_FALSE(db_get_tick_vote(999, 99, retrieved_vote));
}

TEST_F(DBTest, GetTickVoteCountAndVotes) {
    ASSERT_EQ(0, db_get_tick_vote_count(200));

    TickVote vote1 = create_dummy_tick_vote(200, 1);
    TickVote vote2 = create_dummy_tick_vote(200, 2);
    ASSERT_TRUE(db_insert_tick_vote(vote1));
    ASSERT_TRUE(db_insert_tick_vote(vote2));

    ASSERT_EQ(2, db_get_tick_vote_count(200));
    ASSERT_EQ(0, db_get_tick_vote_count(201));

    std::vector<TickVote> votes = db_get_tick_votes(200);
    ASSERT_EQ(2, votes.size());
}

// Step 4: Test core functionality for TickData.
TEST_F(DBTest, InsertAndGetTickData) {
    TickData data_to_insert = create_dummy_tick_data(400, 55);
    ASSERT_TRUE(db_insert_tick_data(data_to_insert));

    TickData retrieved_data{};
    ASSERT_TRUE(db_get_tick_data(400, retrieved_data));
    ASSERT_EQ(0, memcmp(&data_to_insert, &retrieved_data, sizeof(TickData)));
}

// Step 5: Test edge case for inconsistent TickData.
TEST_F(DBTest, GetInconsistentTickData) {
    TickData data1 = create_dummy_tick_data(500, 1);
    TickData data2 = create_dummy_tick_data(500, 2);
    data2.timelock[0] = 0xFF; // Ensure hashes are different

    ASSERT_TRUE(db_insert_tick_data(data1));
    ASSERT_TRUE(db_insert_tick_data(data2));

    TickData retrieved_data{};
    ASSERT_FALSE(db_get_tick_data(500, retrieved_data));
}

// Step 4: Test core functionality for Transaction.
TEST_F(DBTest, InsertAndGetTransaction) {
    auto tx_buffer = create_dummy_transaction_buffer(600, 128);
    Transaction* tx_to_insert = reinterpret_cast<Transaction*>(tx_buffer.data());
    ASSERT_TRUE(db_insert_transaction(tx_to_insert));

    char hash[64] = {0};
    getQubicHash(tx_buffer.data(), tx_buffer.size(), hash);
    std::string hash_str(hash);

    std::vector<uint8_t> retrieved_tx_data;
    ASSERT_TRUE(db_get_transaction(hash_str, retrieved_tx_data));
    ASSERT_EQ(tx_buffer.size(), retrieved_tx_data.size());
    ASSERT_EQ(0, memcmp(tx_buffer.data(), retrieved_tx_data.data(), tx_buffer.size()));
}

TEST_F(DBTest, GetTickTransactionCount) {
    ASSERT_EQ(0, db_get_tick_transaction_count(700));

    auto tx1 = create_dummy_transaction_buffer(700, 32);
    auto tx2 = create_dummy_transaction_buffer(700, 64);
    ASSERT_TRUE(db_insert_transaction(reinterpret_cast<Transaction*>(tx1.data())));
    ASSERT_TRUE(db_insert_transaction(reinterpret_cast<Transaction*>(tx2.data())));

    ASSERT_EQ(2, db_get_tick_transaction_count(700));
    ASSERT_EQ(0, db_get_tick_transaction_count(701));
}

// Step 4: Test core functionality for Logs.
TEST_F(DBTest, InsertAndGetLogs) {
    std::string tx_hash = "a_sample_tx_hash_string_for_testing_123";
    uint8_t content1[] = "log content 1";
    uint8_t content2[] = "log content 2";

    ASSERT_TRUE(db_insert_log(1, 800, 1, sizeof(content1), 10, 100, 1000, tx_hash, content1));
    ASSERT_TRUE(db_insert_log(1, 801, 1, sizeof(content2), 20, 200, 2000, tx_hash, content2));

    std::vector<LogEvent> logs_by_hash = db_get_logs_by_tx_hash(tx_hash);
    ASSERT_EQ(2, logs_by_hash.size());

    std::vector<LogEvent> logs_by_range = db_get_logs_by_tick_range(800, 800);
    ASSERT_EQ(1, logs_by_range.size());
    ASSERT_EQ(800, logs_by_range[0].tick);
    ASSERT_EQ(sizeof(content1), logs_by_range[0].content.size());

    std::vector<LogEvent> logs_by_range_filtered = db_get_logs_by_tick_range(800, 805, 20);
    ASSERT_EQ(1, logs_by_range_filtered.size());
    ASSERT_EQ(801, logs_by_range_filtered[0].tick);
}

TEST_F(DBTest, InsertLogRange) {
    ResponseAllLogIdRangesFromTick logRange{};
    for (size_t i = 0; i < LOG_TX_PER_TICK; ++i) {
        logRange.fromLogId[i] = static_cast<long long>(1000 + i);
        logRange.length[i] = static_cast<long long>(i % 10);
    }

    ASSERT_TRUE(db_insert_log_range(900, logRange));

    // Verify a few representative indices
    std::vector<size_t> indices = {0, 1, LOG_TX_PER_TICK - 1};
    for (size_t idx : indices) {
        std::string key = "log_ranges:900:" + std::to_string(idx);
        std::unordered_map<std::string, std::string> fields;
        _redis_admin->hgetall(key, std::inserter(fields, fields.end()));

        ASSERT_EQ(2u, fields.size()) << "Unexpected field count at index " << idx;
        ASSERT_EQ(std::to_string(logRange.fromLogId[idx]), fields["fromLogId"]) << "fromLogId mismatch at index " << idx;
        ASSERT_EQ(std::to_string(logRange.length[idx]), fields["length"]) << "length mismatch at index " << idx;
    }
}

TEST_F(DBTest, UpdateAndGetLatestTickAndEpoch) {
    uint32_t tick = 0;
    uint16_t epoch = 0;

    ASSERT_TRUE(db_get_latest_tick_and_epoch(tick, epoch));
    ASSERT_EQ(0, tick);
    ASSERT_EQ(0, epoch);

    ASSERT_TRUE(db_update_latest_tick_and_epoch(1000, 5));
    ASSERT_TRUE(db_get_latest_tick_and_epoch(tick, epoch));
    ASSERT_EQ(1000, tick);
    ASSERT_EQ(5, epoch);

    ASSERT_TRUE(db_update_latest_tick_and_epoch(1001, 6));
    ASSERT_TRUE(db_get_latest_tick_and_epoch(tick, epoch));
    ASSERT_EQ(1001, tick);
    ASSERT_EQ(6, epoch);

    // Update with a lower tick should NOT change the values
    ASSERT_TRUE(db_update_latest_tick_and_epoch(999, 7));
    ASSERT_TRUE(db_get_latest_tick_and_epoch(tick, epoch));
    ASSERT_EQ(1001, tick);
    ASSERT_EQ(6, epoch);

    // Update with the same tick should NOT change the values
    ASSERT_TRUE(db_update_latest_tick_and_epoch(1001, 8));
    ASSERT_TRUE(db_get_latest_tick_and_epoch(tick, epoch));
    ASSERT_EQ(1001, tick);
    ASSERT_EQ(6, epoch);
}