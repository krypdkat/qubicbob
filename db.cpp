#include "db.h"
#include <sw/redis++/redis++.h>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <iomanip>
#include <future>
#include <zstd.h> // zstd compression/decompression
#include "Logger.h"
#include "K12AndKeyUtil.h"
#include <cstdlib> // std::exit

// Global Redis client handle
static std::unique_ptr<sw::redis::Redis> g_redis = nullptr;

// Helper to convert byte array to hex string
static std::string bytes_to_hex_string(const unsigned char* bytes, size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

void db_connect(const std::string& connectionString) {
    if (g_redis) {
        Logger::get()->info("Database connection already open.\n");
        return;
    }
    try {
        // Ensure a Redis connection pool with 16 connections is used.
        // redis++ supports configuring pool size via URI query parameter `pool_size`.
        std::string uri_with_pool = connectionString;
        if (uri_with_pool.find('?') == std::string::npos) {
            uri_with_pool += "?pool_size=32";
        } else {
            uri_with_pool += "&pool_size=32";
        }

        g_redis = std::make_unique<sw::redis::Redis>(uri_with_pool);
        g_redis->ping();

        // Verify RedisTimeSeries (TS.* commands) is available.
        // We probe with TS.INFO on a dummy key; if the module is missing, Redis returns "unknown command".
        try {
            g_redis->command<void>("TS.INFO", "bob_ts_probe_dummy_key");
        } catch (const sw::redis::ReplyError& e) {
            const std::string msg = e.what();
            if (msg.find("unknown command") != std::string::npos) {
                Logger::get()->critical("RedisTimeSeries module not loaded. Please load RedisTimeSeries (TS.*) before running.");
                std::exit(2);
            }
            // If it's a different error (e.g., key not found), that's fine — the module exists.
        }
    } catch (const sw::redis::Error& e) {
        g_redis.reset();
        throw std::runtime_error("Cannot connect to Redis: " + std::string(e.what()));
    }
    Logger::get()->trace("Connected to DB!");
}

void db_close() {
    g_redis.reset();
    Logger::get()->info("Closed redis DB connections");
}

bool db_insert_tick_vote(const TickVote& vote) {
    if (!g_redis) return false;
    try {
        sw::redis::StringView val(reinterpret_cast<const char*>(&vote), sizeof(vote));
        std::string key = "tick_vote:" + std::to_string(vote.tick) + ":" + std::to_string(vote.computorIndex);
        g_redis->set(key, val);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_tick_data(const TickData& data) {
    if (!g_redis) return false;
    try {
        sw::redis::StringView val(reinterpret_cast<const char*>(&data), sizeof(data));
        std::string key = "tick_data:" + std::to_string(data.tick);
        g_redis->set(key, val);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_transaction(const Transaction* tx) {
    if (!g_redis) return false;
    try {
        size_t tx_size = sizeof(Transaction) + tx->inputSize + SIGNATURE_SIZE;
        sw::redis::StringView val(reinterpret_cast<const char*>(tx), tx_size);
        char hash[64] = {0};
        getQubicHash(reinterpret_cast<const unsigned char*>(tx), tx_size, hash);
        std::string hash_str(hash);
        // Store by transaction hash only; tick is no longer part of the key.
        std::string key = "transaction:" + hash_str;
        g_redis->set(key, val);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_log(uint16_t epoch, uint32_t tick, uint64_t logId, int logSize, const uint8_t* content) {
    if (!g_redis) return false;
    try {
        std::string key = "log:" +
                std::to_string(epoch) + ":" +
                std::to_string(logId);
        std::unordered_map<std::string, std::string> fields;
        fields["content"] = std::string(reinterpret_cast<const char*>(content), logSize);
        g_redis->hmset(key, fields.begin(), fields.end());
        // Removed: stop tracking per-tick log index (log_index:<epoch>:<tick>)
        // std::string index_key = "log_index:" + std::to_string(epoch) + ":" + std::to_string(tick);
        // g_redis->sadd(index_key, key);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}



bool db_insert_log_range(uint32_t tick, const ResponseAllLogIdRangesFromTick& logRange) {
    if (!g_redis) return false;
    try {
        if (isArrayZero((uint8_t*)&logRange, sizeof(ResponseAllLogIdRangesFromTick)))
        {
            return false;
        }
        // Compute min/max and store under a per-tick summary key
        long long min_log_id = INTMAX_MAX;
        long long max_log_id = -1;
        for (size_t i = 0; i < LOG_TX_PER_TICK; ++i) {
            if (logRange.fromLogId[i] == -1 || logRange.length[i] == -1) continue;
            min_log_id = std::min(min_log_id, logRange.fromLogId[i]);
            max_log_id = std::max(max_log_id, logRange.fromLogId[i] + logRange.length[i]);
            if (logRange.fromLogId[i] < -1)
            {
//                Logger::get()->error("Log ranges have invalid value: tick {} logRange.fromLogId[i] {}", tick, logRange.fromLogId[i]);
                return false;
            }
            if (logRange.length[i] < -1)
            {
//                Logger::get()->error("Log ranges have invalid value: tick {} logRange.length[i] {}", tick, logRange.length[i]);
                return false;
            }
            //TODO: track END_EPOCH log range
        }

        if (min_log_id == INTMAX_MAX) {
            min_log_id = -1;
            max_log_id = -1;
        }

        // Store the whole struct for the tick
        sw::redis::StringView val(reinterpret_cast<const char*>(&logRange), sizeof(ResponseAllLogIdRangesFromTick));
        std::string key_struct = "log_ranges:" + std::to_string(tick);
        g_redis->set(key_struct, val);

        std::string key_summary = "tick_log_range:" + std::to_string(tick);
        std::unordered_map<std::string, std::string> fields;
        fields["fromLogId"] = std::to_string(min_log_id);
        fields["length"] = (min_log_id == -1) ? std::to_string(-1) : std::to_string(max_log_id - min_log_id);
        g_redis->hmset(key_summary, fields.begin(), fields.end());
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_insert_log_range: %s\n", e.what());
        return false;
    }
    return true;
}

bool db_check_log_range(uint32_t tick)
{
    if (!g_redis) return false;
    try {
        std::string key = "log_ranges:" + std::to_string(tick);
        return g_redis->exists(key);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in check_log_range: %s\n", e.what());
        return false;
    }
    return false;
}

bool db_log_exists(uint16_t epoch, uint64_t logId) {
    if (!g_redis) return false;
    try {
        std::string key = "log:" + std::to_string(epoch) + ":" + std::to_string(logId);
        return g_redis->exists(key);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_log_exists: %s\n", e.what());
        return false;
    }
    return false;
}

bool db_get_log_range_all_txs(uint32_t tick, ResponseAllLogIdRangesFromTick &logRange) {
    if (!g_redis) return false;
    try {
        // Default to -1s
        memset(&logRange, -1, sizeof(ResponseAllLogIdRangesFromTick));

        // Fetch the whole struct for the tick
        std::string key = "log_ranges:" + std::to_string(tick);
        auto val = g_redis->get(key);
        if (!val) {
            // Not an error; just means no ranges for this tick yet
            return true;
        }
        if (val->size() != sizeof(ResponseAllLogIdRangesFromTick)) {
            Logger::get()->warn("LogRange size mismatch for key %s: got %zu, expected %zu",
                                key.c_str(), val->size(), sizeof(ResponseAllLogIdRangesFromTick));
            return false;
        }
        memcpy((void*)&logRange, val->data(), sizeof(ResponseAllLogIdRangesFromTick));
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_log_range_all_txs: %s\n", e.what());
        return false;
    }
    return false;
}

bool db_get_log_range_for_tick(uint32_t tick, long long& fromLogId, long long& length) {
    fromLogId = -1;
    length = -1;
    if (!g_redis) return false;
    try {
        const std::string key = "tick_log_range:" + std::to_string(tick);
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget(key, {"fromLogId", "length"}, std::back_inserter(vals));
        if (vals.size() == 2 && vals[0] && vals[1]) {
            long long min_id = std::stoll(*vals[0]);
            long long len = std::stoll(*vals[1]);
            if (min_id == -1 || len == -1) {
                fromLogId = -1;
                length = -1;
                return true;
            }
            fromLogId = min_id;
            length = len; // length already stored as (max_log_id - min_log_id)
            return true;
        }
        return false;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_log_range_for_tick: %s\n", e.what());
        return false;
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error in db_get_log_range_for_tick: %s\n", e.what());
        return false;
    }
}

bool db_update_latest_tick_and_epoch(uint32_t tick, uint16_t epoch) {
    if (!g_redis) return false;
    try {
        const char* script = R"lua(
local new_tick = tonumber(ARGV[1])
local current_tick = tonumber(redis.call('hget', KEYS[1], 'latest_tick')) or 0
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'latest_tick', new_tick, 'latest_epoch', ARGV[2])
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick), std::to_string(epoch)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_get_latest_tick_and_epoch(uint32_t& tick, uint16_t& epoch)
{
    if (!g_redis) return false;
    try {
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget("db_status", {"latest_tick", "latest_epoch"}, std::back_inserter(vals));

        tick = 0;
        epoch = 0;

        if (vals.size() > 0 && vals[0]) {
            tick = std::stoul(*vals[0]);
        }
        if (vals.size() > 1 && vals[1]) {
            epoch = std::stoi(*vals[1]);
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    } catch (const std::logic_error& e) {
        Logger::get()->error("Parsing error while getting latest tick/epoch: %s\n", e.what());
        return false;
    }
    return true;
}

/*LOGGING EVENTS*/

bool db_update_latest_event_tick_and_epoch(uint32_t tick, uint16_t epoch) {
    if (!g_redis) return false;
    try {
        const char* script = R"lua(
local new_tick = tonumber(ARGV[1])
local current_tick = tonumber(redis.call('hget', KEYS[1], 'latest_event_tick')) or 0
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'latest_event_tick', new_tick, 'latest_event_epoch', ARGV[2])
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick), std::to_string(epoch)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_get_latest_event_tick_and_epoch(uint32_t& tick, uint16_t& epoch)
{
    if (!g_redis) return false;
    try {
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget("db_status", {"latest_event_tick", "latest_event_epoch"}, std::back_inserter(vals));

        tick = 0;
        epoch = 0;

        if (vals.size() > 0 && vals[0]) {
            tick = std::stoul(*vals[0]);
        }
        if (vals.size() > 1 && vals[1]) {
            epoch = std::stoi(*vals[1]);
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    } catch (const std::logic_error& e) {
        Logger::get()->error("Parsing error while getting latest event tick/epoch: %s\n", e.what());
        return false;
    }
    return true;
}

bool db_update_latest_log_id(uint64_t logId) {
    if (!g_redis) return false;
    try {
        const char *script = R"lua(
local new_id = tonumber(ARGV[1])
local current_id = tonumber(redis.call('hget', KEYS[1], 'latest_log_id')) or 0
if new_id > current_id then
    redis.call('hset', KEYS[1], 'latest_log_id', new_id)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(logId)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_update_latest_log_id(uint16_t epoch, long long logId) {
    if (!g_redis) return false;
    try {
        const std::string key = "db_status:epoch:" + std::to_string(epoch);
        const char *script = R"lua(
local current_id = tonumber(redis.call('hget', KEYS[1], 'latest_log_id')) or -1
local new_id = tonumber(ARGV[1]) or -1
if new_id > current_id then
    redis.call('hset', KEYS[1], 'latest_log_id', new_id)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {key};
        std::vector<std::string> args = {std::to_string(logId)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error in db_update_latest_log_id: %s\n", e.what());
        return false;
    }
    return true;
}

long long db_get_latest_log_id(uint16_t epoch) {
    if (!g_redis) return 0;
    try {
        const std::string key = "db_status:epoch:" + std::to_string(epoch);
        auto val = g_redis->hget(key, "latest_log_id");
        if (val) {
            return std::stoull(*val);
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error: {}\n", e.what());
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error while getting latest log ID: %s\n", e.what());
    }
    return -1;
}

bool db_update_latest_verified_tick(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const char *script = R"lua(
local current_tick = tonumber(redis.call('hget', KEYS[1], 'latest_verified_tick')) or -1
local new_tick = tonumber(ARGV[1])
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'latest_verified_tick', new_tick)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_update_latest_verified_tick: %s\n", e.what());
        return false;
    }
    return false;
}


long long db_get_latest_verified_tick() {
    if (!g_redis) return -1;
    try {
        auto val = g_redis->hget("db_status", "latest_verified_tick");
        if (val) {
            return std::stoll(*val);
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_latest_verified_tick: %s\n", e.what());
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error while getting latest verified tick: %s\n", e.what());
    }
    return -1;
}

static bool fill_log_from_key_and_fields(const std::string& key,
                                         const std::vector<sw::redis::Optional<std::string>>& vals,
                                         LogEvent& log) {

    try {
        if (!(vals.size() == 1 && vals[0])) {
            Logger::get()->warn("Could not retrieve content for log key {}", key.c_str());
            return false;
        }
        // Assemble packed buffer: header (26 bytes) + payload
        const std::string& payload = *vals[0];
        log.updateContent((uint8_t*)payload.data(),payload.size());

        return true;
    } catch(const std::logic_error& e) {
        Logger::get()->error("Failed to parse log fields for key {}: {}", key.c_str(), e.what());
    }

    return false;
}

bool db_get_log(uint16_t epoch, uint64_t logId, LogEvent &log)
{
    if (!g_redis) return false;
    try {
        std::string key = "log:" + std::to_string(epoch) + ":" + std::to_string(logId);
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget(key, {"content"}, std::back_inserter(vals));

        // Pass a dummy tick value since it's not used in this context
        return fill_log_from_key_and_fields(key, vals, log);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_log: %s\n", e.what());
        return false;
    }
    return false;
}

std::vector<LogEvent> db_get_logs_by_tick_range(uint16_t epoch, uint32_t start_tick, uint32_t end_tick) {
    std::vector<LogEvent> logs;
    if (!g_redis) return logs;

    try {
        constexpr int BATCH_SIZE = 128;
        static const std::array<std::string, 1> fields = {"content"};

        for (uint32_t tick = start_tick; tick <= end_tick; ++tick) {
            long long fromLogId = -1;
            long long length = -1;
            if (!db_get_log_range_for_tick(tick, fromLogId, length)) {
                // No range available or error — skip this tick
                continue;
            }
            if (fromLogId == -1 || length == -1 || length == 0) {
                // No logs for this tick
                continue;
            }

            const long long toLogId = fromLogId + length; // exclusive upper bound
            for (long long start = fromLogId; start < toLogId; start += BATCH_SIZE) {
                const long long stop = std::min(toLogId, start + static_cast<long long>(BATCH_SIZE));

                // Build keys for this slice: "log:<epoch>:<logId>"
                std::vector<std::string> keys;
                keys.reserve(static_cast<size_t>(stop - start));
                for (long long id = start; id < stop; ++id) {
                    keys.emplace_back("log:" + std::to_string(epoch) + ":" + std::to_string(id));
                }

                // Fetch contents via MGET in one round-trip
                std::vector<sw::redis::OptionalString> vals;
                vals.reserve(keys.size());
                g_redis->mget(keys.begin(), keys.end(), std::back_inserter(vals));

                // Extract and assemble LogEvent entries
                for (size_t i = 0; i < keys.size(); ++i) {
                    try {
                        const auto &opt = vals[i];
                        if (!opt) continue;

                        // Reuse existing helper by wrapping the single value
                        std::vector<sw::redis::OptionalString> singleField{opt};
                        LogEvent completed;
                        if (fill_log_from_key_and_fields(keys[i], singleField, completed)) {
                            logs.push_back(std::move(completed));
                        }
                    } catch (...) {
                        // Skip malformed/errored entries
                    }
                }
            }
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_logs_by_tick_range: %s\n", e.what());
    }

    return logs;
}

long long db_get_tick_vote_count(uint32_t tick) {
    if (!g_redis) return -1;
    try {
        // Deterministic bounded check: keys tick_vote:<tick>:0..675
        constexpr int MAX_COMPUTORS = 676;
        constexpr int BATCH_SIZE = 128; // smaller, short-lived operations

        long long count = 0;
        const std::string prefix = "tick_vote:" + std::to_string(tick) + ":";

        std::vector<std::string> keys;
        keys.reserve(BATCH_SIZE);

        for (int start = 0; start < MAX_COMPUTORS; start += BATCH_SIZE) {
            const int end = std::min(MAX_COMPUTORS, start + BATCH_SIZE);

            keys.clear();
            for (int i = start; i < end; ++i) {
                keys.emplace_back(prefix + std::to_string(i));
            }

            std::vector<sw::redis::OptionalString> vals;
            vals.reserve(keys.size());

            // MGET for a short chunk to avoid holding a connection too long.
            g_redis->mget(keys.begin(), keys.end(), std::back_inserter(vals));

            for (const auto &opt : vals) {
                if (opt) {
                    ++count;
                }
            }
        }
        return count;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return -1;
    }
}


bool db_get_tick_vote(uint32_t tick, uint16_t computorIndex, TickVote& vote) {
    if (!g_redis) return false;
    try {
        // Key is unique; fetch directly.
        const std::string key = "tick_vote:" + std::to_string(tick) + ":" + std::to_string(computorIndex);
        auto val = g_redis->get(key);
        if (val && val->size() == sizeof(TickVote)) {
            memcpy((void*)&vote, val->data(), sizeof(TickVote));
            return true;
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_tick_vote: %s\n", e.what());
    }
    return false;
}

std::vector<TickVote> db_get_tick_votes(uint32_t tick) {
    std::vector<TickVote> votes;
    if (!g_redis) return votes;
    try {
        // Deterministic bounded fetch: keys tick_vote:<tick>:0..675
        constexpr int MAX_COMPUTORS = 676;
        constexpr int BATCH_SIZE = 128; // small chunks to avoid long-lived ops

        votes.reserve(MAX_COMPUTORS);

        const std::string prefix = "tick_vote:" + std::to_string(tick) + ":";

        std::vector<std::string> keys;
        keys.reserve(BATCH_SIZE);

        for (int start = 0; start < MAX_COMPUTORS; start += BATCH_SIZE) {
            const int end = std::min(MAX_COMPUTORS, start + BATCH_SIZE);

            keys.clear();
            for (int i = start; i < end; ++i) {
                keys.emplace_back(prefix + std::to_string(i));
            }

            std::vector<sw::redis::OptionalString> vals;
            vals.reserve(keys.size());

            // MGET for a short chunk
            g_redis->mget(keys.begin(), keys.end(), std::back_inserter(vals));

            for (const auto &opt : vals) {
                if (!opt) continue;
                const auto &s = *opt;
                if (s.size() != sizeof(TickVote)) continue;

                TickVote vote{};
                std::memcpy((void*)&vote, s.data(), sizeof(TickVote));
                votes.push_back(vote);
            }
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_tick_votes: {}\n", e.what());
    }
    return votes;
}

bool db_get_tick_data(uint32_t tick, TickData& data) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_data:" + std::to_string(tick);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        if (val->size() != sizeof(TickData)) {
            Logger::get()->warn("TickData size mismatch for key %s: got %zu, expected %zu",
                                key.c_str(), val->size(), sizeof(TickData));
            return false;
        }
        memcpy((void*)&data, val->data(), sizeof(TickData));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_tick_data: %s\n", e.what());
    }
    return false;
}

bool db_get_transaction(const std::string& tx_hash, std::vector<uint8_t>& tx_data) {
    if (!g_redis) return false;
    try {
        // Tick is no longer used in the key; fetch by hash only.
        const std::string key = "transaction:" + tx_hash;
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        tx_data.assign(val->begin(), val->end());
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_transaction (by hash, tick ignored): %s\n", e.what());
    }
    return false;
}

bool db_check_transaction_exist(const std::string& tx_hash) {
    if (!g_redis) return false;
    try {
        const std::string key = "transaction:" + tx_hash;
        return g_redis->exists(key);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_check_transaction_exist: %s\n", e.what());
    }
    return false;
}


bool db_has_tick_data(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_data:" + std::to_string(tick);
        return g_redis->exists(key);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_has_tick_data: %s\n", e.what());
        return false;
    }
    return false;
}

struct VoteCluster {
    m256i prevSpectrumDigest;
    std::vector<TickVote> votes;
};

m256i db_getSpectrumDigest(uint32_t tick) {
    std::vector<TickVote> votes = db_get_tick_votes(tick + 1);
    if (votes.empty()) {
        return m256i{}; // Return zero digest if no votes
    }

    // Group votes by prevSpectrumDigest
    std::vector<VoteCluster> clusters;
    for (const auto &vote: votes) {
        bool found = false;
        for (auto &cluster: clusters) {
            if (memcmp(&cluster.prevSpectrumDigest, &vote.prevSpectrumDigest, sizeof(m256i)) == 0) {
                cluster.votes.push_back(vote);
                found = true;
                break;
            }
        }
        if (!found) {
            clusters.push_back({vote.prevSpectrumDigest, {vote}});
        }
    }

    // Find largest cluster
    size_t maxSize = 0;
    m256i result{};
    m256i td;
    for (const auto &cluster: clusters) {
        if (cluster.votes.size() > maxSize) {
            maxSize = cluster.votes.size();
            result = cluster.prevSpectrumDigest;
            td = cluster.votes[0].transactionDigest;
        }
    }

    int threshold = 226;
    if (td != m256i::zero())
    {
        threshold = 451;
    }
    return (maxSize >= threshold) ? result : m256i{};
}

m256i db_getUniverseDigest(uint32_t tick) {
    std::vector<TickVote> votes = db_get_tick_votes(tick + 1);
    if (votes.empty()) {
        return m256i{}; // Return zero digest if no votes
    }

    // Group votes by prevUniverseDigest
    struct UCluster {
        m256i prevUniverseDigest;
        std::vector<TickVote> votes;
    };

    std::vector<UCluster> clusters;
    for (const auto& vote : votes) {
        bool found = false;
        for (auto& cluster : clusters) {
            if (memcmp(&cluster.prevUniverseDigest, &vote.prevUniverseDigest, sizeof(m256i)) == 0) {
                cluster.votes.push_back(vote);
                found = true;
                break;
            }
        }
        if (!found) {
            UCluster nc;
            memcpy((void*)&nc.prevUniverseDigest, vote.prevUniverseDigest.m256i_u8, sizeof(m256i));
            nc.votes.push_back(vote);
            clusters.push_back(nc);
        }
    }

    // Find largest cluster
    size_t maxSize = 0;
    m256i result{};
    m256i td;
    for (const auto& cluster : clusters) {
        if (cluster.votes.size() > maxSize) {
            maxSize = cluster.votes.size();
            result = cluster.prevUniverseDigest;
            td = cluster.votes[0].transactionDigest;
        }
    }
    int threshold = 226;
    if (td != m256i::zero())
    {
        threshold = 451;
    }
    // Return result only if largest cluster has at least threshold votes
    return (maxSize >= threshold) ? result : m256i{};
}

// Store the whole Computors struct per epoch; key = "computor:<epoch>"
bool db_insert_computors(const Computors& comps) {
    if (!g_redis) return false;
    try {
        sw::redis::StringView val(reinterpret_cast<const char*>(&comps), sizeof(Computors));
        std::string key = "computor:" + std::to_string(comps.epoch);
        g_redis->set(key, val);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_insert_computors: %s\n", e.what());
        return false;
    }
    return true;
}

// Retrieve the whole Computors struct by epoch; key = "computor:<epoch>"
bool db_get_computors(uint16_t epoch, Computors& comps) {
    if (!g_redis) return false;
    try {
        const std::string key = "computor:" + std::to_string(epoch);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        if (val->size() != sizeof(Computors)) {
            Logger::get()->warn("Computors size mismatch for key %s: got %zu, expected %zu",
                                key.c_str(), val->size(), sizeof(Computors));
            return false;
        }
        std::memcpy((void*)&comps, val->data(), sizeof(Computors));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_computors: %s\n", e.what());
        return false;
    }
    return false;
}

bool db_delete_tick_data(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_data:" + std::to_string(tick);
        g_redis->del(key);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_delete_tick_data: %s\n", e.what());
        return false;
    }
}

bool db_delete_tick_vote(uint32_t tick, uint16_t computorIndex) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_vote:" + std::to_string(tick) + ":" + std::to_string(computorIndex);
        g_redis->del(key);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_delete_tick_vote: %s\n", e.what());
        return false;
    }
}


// Insert FullTickStruct compressed with zstd under key "vtick:<tick>"
bool db_insert_vtick(uint32_t tick, const FullTickStruct& fullTick)
{
    if (!g_redis) return false;
    try {
        const size_t srcSize = sizeof(FullTickStruct);
        const size_t maxCompressed = ZSTD_compressBound(srcSize);

        std::string compressed;
        compressed.resize(maxCompressed);

        size_t const cSize = ZSTD_compress(
                compressed.data(),
                compressed.size(),
                reinterpret_cast<const void*>(&fullTick),
                srcSize,
//                ZSTD_maxCLevel()
                ZSTD_defaultCLevel()
        );
//        Logger::get()->info("Compressed from {} to {}",  srcSize, cSize);

        if (ZSTD_isError(cSize)) {
            Logger::get()->error("ZSTD_compress error in db_insert_vtick: %s",
                                 ZSTD_getErrorName(cSize));
            return false;
        }

        // shrink to actual compressed size
        compressed.resize(cSize);

        const std::string key = "vtick:" + std::to_string(tick);
        sw::redis::StringView val(compressed.data(), compressed.size());
        g_redis->set(key, val);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_insert_vtick: %s\n", e.what());
        return false;
    }
}

// Get FullTickStruct stored under "vtick:<tick>", decompressing with zstd
bool db_get_vtick(uint32_t tick, FullTickStruct& outFullTick)
{
    if (!g_redis) return false;
    try {
        const std::string key = "vtick:" + std::to_string(tick);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }

        const size_t dstSize = sizeof(FullTickStruct);
        size_t const dSize = ZSTD_decompress(
                reinterpret_cast<void*>(&outFullTick),
                dstSize,
                val->data(),
                val->size()
        );

        if (ZSTD_isError(dSize)) {
            Logger::get()->error("ZSTD_decompress error in db_get_vtick: %s",
                                 ZSTD_getErrorName(dSize));
            return false;
        }

        if (dSize != dstSize) {
            Logger::get()->warn("Decompressed FullTickStruct size mismatch for key %s: got %zu, expected %zu",
                                key.c_str(), dSize, dstSize);
            return false;
        }
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_vtick: %s\n", e.what());
        return false;
    }
}

long long db_get_last_indexed_tick() {
    if (!g_redis) return -1;
    try {
        auto val = g_redis->hget("db_status", "last_indexed_tick");
        if (val) {
            return std::stoll(*val);
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_last_indexed_tick: %s\n", e.what());
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error while getting last_indexed_tick: %s\n", e.what());
    }
    return -1;
}

bool db_update_last_indexed_tick(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const char *script = R"lua(
local current_tick = tonumber(redis.call('hget', KEYS[1], 'last_indexed_tick')) or -1
local new_tick = tonumber(ARGV[1])
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'last_indexed_tick', new_tick)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_update_last_indexed_tick: %s\n", e.what());
        return false;
    }
}

bool db_add_indexer(const std::string &key, uint32_t tickNumber)
{
    if (!g_redis) return false;
    try {
        // Create TimeSeries if it doesn't exist
        const char *create_script = R"lua(
if not redis.call('EXISTS', KEYS[1]) then
    redis.call('TS.CREATE', KEYS[1], 'DUPLICATE_POLICY', 'FIRST')
    return 1
end
return 1
)lua";
        std::vector<std::string> keys = {key};
        std::vector<std::string> args = {std::to_string(tickNumber)};
        g_redis->eval<long long>(create_script, keys.begin(), keys.end(), args.begin(), args.end());

        // Add the record
        const char *add_script = R"lua(
local ret = redis.call('TS.ADD', KEYS[1], ARGV[1], '1', 'DUPLICATE_POLICY', 'FIRST')
return 1
)lua";

        g_redis->eval<long long>(add_script, keys.begin(), keys.end(), args.begin(), args.end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in addIndexer: {}\n", e.what());
        return false;
    }
}

// Store per-transaction index info for fast lookup by tx-hash.
// Key is expected to be "itx:<txHash>".
// Fields stored:
//   - tx_index     (int)       : index within the tick (0..NUMBER_OF_TRANSACTIONS_PER_TICK-1)
//   - from_log_id  (long long) : first logId for this tx in the tick, or -1 if none
//   - to_log_id    (long long) : last  logId for this tx in the tick, or -1 if none
//   - executed     (0/1)       : whether the tx was executed (best-effort heuristic)
struct IndexedTx {
    int tx_index;           // Index within tick (0..NUMBER_OF_TRANSACTIONS_PER_TICK-1)
    long long from_log_id;  // First logId for this tx in the tick, or -1 if none
    long long to_log_id;    // Last logId for this tx in the tick, or -1 if none
    bool executed;          // Whether the tx was executed (best-effort heuristic)
};

bool db_set_indexed_tx(const char *key,
                       int tx_index,
                       long long from_log_id,
                       long long to_log_id,
                       bool executed) {
    if (!g_redis) return false;
    try {
        // Normalize invalid ranges to (-1, -1)
        if (from_log_id < 0 || to_log_id < 0 || to_log_id < from_log_id) {
            from_log_id = -1;
            to_log_id = -1;
            executed = false; // if there's no logs, mark as not executed
        }

        std::unordered_map<std::string, std::string> fields;
        fields["tx_index"] = std::to_string(tx_index);
        fields["from_log_id"] = std::to_string(from_log_id);
        fields["to_log_id"] = std::to_string(to_log_id);
        fields["executed"] = executed ? "1" : "0";

        g_redis->hmset(key, fields.begin(), fields.end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_set_indexed_tx: %s\n", e.what());
        return false;
    }
}

bool db_get_indexed_tx(const char* tx_hash,
                       int& tx_index,
                       long long& from_log_id,
                       long long& to_log_id,
                       bool& executed) {
    if (!g_redis) return false;
    try {
        const std::string key = std::string("itx:") + tx_hash;
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget(key, {"tx_index", "from_log_id", "to_log_id", "executed"}, std::back_inserter(vals));

        if (vals.size() != 4 || !vals[0] || !vals[1] || !vals[2] || !vals[3]) {
            return false;
        }

        try {
            tx_index   = std::stoi(*vals[0]);
            from_log_id = std::stoll(*vals[1]);
            to_log_id   = std::stoll(*vals[2]);
            executed    = (*vals[3] == std::string("1"));
            return true;
        } catch (const std::logic_error& e) {
            Logger::get()->error("Parsing error in db_get_indexed_tx: %s\n", e.what());
            return false;
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_indexed_tx: %s\n", e.what());
        return false;
    }
}
