#include "LogSubscriptionManager.h"
#include "database/db.h"
#include "Logger.h"
#include "shim.h"

#include <json/json.h>
#include <sstream>
#include <iomanip>
#include <drogon/drogon.h>

LogSubscriptionManager& LogSubscriptionManager::instance() {
    static LogSubscriptionManager inst;
    return inst;
}

void LogSubscriptionManager::addClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    ClientState state;
    state.conn = conn;
    state.connectedAt = std::chrono::steady_clock::now();
    state.lastTick = 0;
    state.catchUpInProgress = false;

    clients_[conn] = std::move(state);

    Logger::get()->info("WebSocket client connected. Total clients: {}", clients_.size());
}

void LogSubscriptionManager::removeClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return;

    // Remove from all subscription indexes
    for (const auto& key : it->second.subscriptions) {
        auto subIt = subscriptionIndex_.find(key);
        if (subIt != subscriptionIndex_.end()) {
            subIt->second.erase(conn);
            if (subIt->second.empty()) {
                subscriptionIndex_.erase(subIt);
            }
        }
    }

    clients_.erase(it);

    Logger::get()->info("WebSocket client disconnected. Total clients: {}", clients_.size());
}

void LogSubscriptionManager::setClientLastTick(const drogon::WebSocketConnectionPtr& conn, uint32_t lastTick) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it != clients_.end()) {
        it->second.lastTick = lastTick;
        it->second.lastLogId = -1;  // Clear log ID when tick is set
    }
}

void LogSubscriptionManager::setClientLastLogId(const drogon::WebSocketConnectionPtr& conn, int64_t lastLogId) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it != clients_.end()) {
        it->second.lastLogId = lastLogId;
    }
}

bool LogSubscriptionManager::subscribe(const drogon::WebSocketConnectionPtr& conn, uint32_t scIndex, uint32_t logType) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return false;

    SubscriptionKey key{scIndex, logType};

    // Add to client's subscription set
    auto [_, inserted] = it->second.subscriptions.insert(key);
    if (!inserted) {
        // Already subscribed
        return true;
    }

    // Add to subscription index
    subscriptionIndex_[key].insert(conn);

    Logger::get()->debug("Client subscribed to scIndex={}, logType={}", scIndex, logType);
    return true;
}

bool LogSubscriptionManager::unsubscribe(const drogon::WebSocketConnectionPtr& conn, uint32_t scIndex, uint32_t logType) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return false;

    SubscriptionKey key{scIndex, logType};

    // Remove from client's subscription set
    if (it->second.subscriptions.erase(key) == 0) {
        // Was not subscribed
        return false;
    }

    // Remove from subscription index
    auto subIt = subscriptionIndex_.find(key);
    if (subIt != subscriptionIndex_.end()) {
        subIt->second.erase(conn);
        if (subIt->second.empty()) {
            subscriptionIndex_.erase(subIt);
        }
    }

    Logger::get()->debug("Client unsubscribed from scIndex={}, logType={}", scIndex, logType);
    return true;
}

void LogSubscriptionManager::unsubscribeAll(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return;

    // Remove from all subscription indexes
    for (const auto& key : it->second.subscriptions) {
        auto subIt = subscriptionIndex_.find(key);
        if (subIt != subscriptionIndex_.end()) {
            subIt->second.erase(conn);
            if (subIt->second.empty()) {
                subscriptionIndex_.erase(subIt);
            }
        }
    }

    it->second.subscriptions.clear();

    Logger::get()->debug("Client unsubscribed from all");
}

bool LogSubscriptionManager::extractSubscriptionKey(const LogEvent& log, SubscriptionKey& key) const {
    uint32_t type = log.getType();

    // Core events (SC_index = 0)
    switch (type) {
        case QU_TRANSFER:
        case ASSET_ISSUANCE:
        case ASSET_OWNERSHIP_CHANGE:
        case ASSET_POSSESSION_CHANGE:
        case BURNING:
        case ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE:
        case ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE:
            key.scIndex = 0;
            key.logType = type;
            return true;

        case CONTRACT_ERROR_MESSAGE:
        case CONTRACT_WARNING_MESSAGE:
        case CONTRACT_INFORMATION_MESSAGE:
        case CONTRACT_DEBUG_MESSAGE: {
            // Extract scIndex and logType from body
            auto ptr = log.getLogBodyPtr();
            int bodySize = log.getLogSize();
            if (bodySize >= 8) {
                memcpy(&key.scIndex, ptr, 4);
                memcpy(&key.logType, ptr + 4, 4);
                // Only include if logType >= 100000 (indexed custom events)
                if (key.logType >= 100000) {
                    return true;
                }
            }
            return false;
        }

        case SPECTRUM_STATS:
        case DUST_BURNING:
        case CUSTOM_MESSAGE:
        default:
            // Not indexed / not subscribable
            return false;
    }
}

void LogSubscriptionManager::pushVerifiedLogs(uint32_t tick, uint16_t epoch, const std::vector<LogEvent>& logs) {
    // Prepare messages under lock, then dispatch asynchronously
    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::string>> pendingSends;

    {
        std::shared_lock lock(mutex_);

        if (clients_.empty() || subscriptionIndex_.empty()) return;

        for (const auto& log : logs) {
            SubscriptionKey key;
            if (!extractSubscriptionKey(log, key)) continue;

            // Find subscribers for this key
            auto subIt = subscriptionIndex_.find(key);
            if (subIt == subscriptionIndex_.end() || subIt->second.empty()) continue;

            // Parse log to JSON using same format as REST API
            std::string parsedJson = const_cast<LogEvent&>(log).parseToJson();

            // Parse the JSON string to embed it in our message
            Json::Value parsedLog;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream(parsedJson);
            Json::parseFromStream(builder, stream, &parsedLog, &errors);

            // Build WebSocket message with parsed log as "message" field
            Json::Value msg;
            msg["type"] = "log";
            msg["scIndex"] = key.scIndex;
            msg["logType"] = key.logType;
            msg["isCatchUp"] = false;
            msg["message"] = parsedLog;

            Json::FastWriter writer;
            std::string jsonStr = writer.write(msg);

            // Collect subscribers to send to
            for (const auto& conn : subIt->second) {
                // Skip clients in catch-up to avoid duplicate/out-of-order messages
                auto clientIt = clients_.find(conn);
                if (clientIt != clients_.end() && clientIt->second.catchUpInProgress) {
                    continue;
                }
                pendingSends.emplace_back(conn, jsonStr);
            }
        }
    }

    // Dispatch sends asynchronously via Drogon's event loop
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([sends = std::move(pendingSends)]() {
                for (const auto& [conn, jsonStr] : sends) {
                    try {
                        if (conn->connected()) {
                            conn->send(jsonStr);
                        }
                    } catch (const std::exception& e) {
                        Logger::get()->warn("Failed to send WebSocket message: {}", e.what());
                    }
                }
            });
        }
    }
}

void LogSubscriptionManager::performCatchUp(const drogon::WebSocketConnectionPtr& conn, uint32_t toTick) {
    uint32_t fromTick;
    std::unordered_set<SubscriptionKey, SubscriptionKeyHash> subscriptions;

    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it == clients_.end()) return;

        if (it->second.subscriptions.empty()) {
            // No subscriptions, nothing to catch up
            Json::Value msg;
            msg["type"] = "catchUpComplete";
            msg["fromTick"] = 0;
            msg["toTick"] = toTick;
            msg["logsDelivered"] = 0;
            Json::FastWriter writer;
            sendJson(conn, writer.write(msg));
            return;
        }

        fromTick = it->second.lastTick + 1;
        subscriptions = it->second.subscriptions;
        it->second.catchUpInProgress = true;
    }

    // Ensure fromTick is not before the epoch's initial tick
    uint32_t initialTick = gInitialTick.load();
    if (fromTick < initialTick) {
        fromTick = initialTick;
    }

    if (fromTick > toTick) {
        // Already up to date
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastTick = toTick;
        }

        Json::Value msg;
        msg["type"] = "catchUpComplete";
        msg["fromTick"] = fromTick;
        msg["toTick"] = toTick;
        msg["logsDelivered"] = 0;
        Json::FastWriter writer;
        sendJson(conn, writer.write(msg));
        return;
    }

    uint16_t epoch = gCurrentProcessingEpoch.load();
    int logsDelivered = 0;

    // Process in batches to avoid blocking too long
    const uint32_t BATCH_SIZE = 100;

    for (uint32_t tick = fromTick; tick <= toTick; tick += BATCH_SIZE) {
        uint32_t batchEnd = std::min(tick + BATCH_SIZE - 1, toTick);

        bool success;
        auto logs = db_get_logs_by_tick_range(epoch, tick, batchEnd, success);

        if (!success) {
            Logger::get()->warn("Catch-up: failed to fetch logs for ticks {}-{}", tick, batchEnd);
            continue;
        }

        for (auto& log : logs) {
            SubscriptionKey key;
            if (!extractSubscriptionKey(log, key)) continue;

            // Check if client is subscribed to this key
            if (subscriptions.find(key) == subscriptions.end()) continue;

            // Parse log to JSON using same format as REST API
            std::string parsedJson = log.parseToJson();

            // Parse the JSON string to embed it in our message
            Json::Value parsedLog;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream(parsedJson);
            Json::parseFromStream(builder, stream, &parsedLog, &errors);

            // Build WebSocket message with parsed log as "message" field
            Json::Value msg;
            msg["type"] = "log";
            msg["scIndex"] = key.scIndex;
            msg["logType"] = key.logType;
            msg["isCatchUp"] = true;
            msg["message"] = parsedLog;

            Json::FastWriter writer;
            try {
                conn->send(writer.write(msg));
                logsDelivered++;
            } catch (const std::exception& e) {
                Logger::get()->warn("Catch-up send failed: {}", e.what());
                break;
            }
        }

        // Check if connection is still valid
        if (!conn->connected()) {
            Logger::get()->info("Catch-up aborted: connection closed");
            return;
        }
    }

    // Mark catch-up complete
    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastTick = toTick;
        }
    }

    // Send completion message
    Json::Value msg;
    msg["type"] = "catchUpComplete";
    msg["fromTick"] = fromTick;
    msg["toTick"] = toTick;
    msg["logsDelivered"] = logsDelivered;
    Json::FastWriter writer;
    sendJson(conn, writer.write(msg));

    Logger::get()->info("Catch-up complete: {} logs delivered (ticks {}-{})", logsDelivered, fromTick, toTick);
}

void LogSubscriptionManager::performCatchUpByLogId(const drogon::WebSocketConnectionPtr& conn, int64_t toLogId) {
    int64_t fromLogId;
    std::unordered_set<SubscriptionKey, SubscriptionKeyHash> subscriptions;

    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it == clients_.end()) return;

        if (it->second.subscriptions.empty()) {
            // No subscriptions, nothing to catch up
            Json::Value msg;
            msg["type"] = "catchUpComplete";
            msg["fromLogId"] = Json::Int64(0);
            msg["toLogId"] = Json::Int64(toLogId);
            msg["logsDelivered"] = 0;
            Json::FastWriter writer;
            sendJson(conn, writer.write(msg));
            return;
        }

        fromLogId = it->second.lastLogId + 1;
        subscriptions = it->second.subscriptions;
        it->second.catchUpInProgress = true;
    }

    if (fromLogId < 0) fromLogId = 0;

    if (fromLogId > toLogId) {
        // Already up to date
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastLogId = toLogId;
        }

        Json::Value msg;
        msg["type"] = "catchUpComplete";
        msg["fromLogId"] = Json::Int64(fromLogId);
        msg["toLogId"] = Json::Int64(toLogId);
        msg["logsDelivered"] = 0;
        Json::FastWriter writer;
        sendJson(conn, writer.write(msg));
        return;
    }

    uint16_t epoch = gCurrentProcessingEpoch.load();
    int logsDelivered = 0;

    // Process in batches to avoid blocking too long
    const int64_t BATCH_SIZE = 1000;

    for (int64_t id = fromLogId; id <= toLogId; id += BATCH_SIZE) {
        int64_t batchEnd = std::min(id + BATCH_SIZE - 1, toLogId);

        auto logs = db_try_get_logs(epoch, id, batchEnd);

        for (auto& log : logs) {
            SubscriptionKey key;
            if (!extractSubscriptionKey(log, key)) continue;

            // Check if client is subscribed to this key
            if (subscriptions.find(key) == subscriptions.end()) continue;

            // Parse log to JSON using same format as REST API
            std::string parsedJson = log.parseToJson();

            // Parse the JSON string to embed it in our message
            Json::Value parsedLog;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream(parsedJson);
            Json::parseFromStream(builder, stream, &parsedLog, &errors);

            // Build WebSocket message with parsed log as "message" field
            Json::Value msg;
            msg["type"] = "log";
            msg["scIndex"] = key.scIndex;
            msg["logType"] = key.logType;
            msg["isCatchUp"] = true;
            msg["message"] = parsedLog;

            Json::FastWriter writer;
            try {
                conn->send(writer.write(msg));
                logsDelivered++;
            } catch (const std::exception& e) {
                Logger::get()->warn("Catch-up send failed: {}", e.what());
                break;
            }
        }

        // Check if connection is still valid
        if (!conn->connected()) {
            Logger::get()->info("Catch-up aborted: connection closed");
            return;
        }
    }

    // Mark catch-up complete
    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastLogId = toLogId;
        }
    }

    // Send completion message
    Json::Value msg;
    msg["type"] = "catchUpComplete";
    msg["fromLogId"] = Json::Int64(fromLogId);
    msg["toLogId"] = Json::Int64(toLogId);
    msg["logsDelivered"] = logsDelivered;
    Json::FastWriter writer;
    sendJson(conn, writer.write(msg));

    Logger::get()->info("Catch-up by logId complete: {} logs delivered (logIds {}-{})", logsDelivered, fromLogId, toLogId);
}

size_t LogSubscriptionManager::getClientCount() const {
    std::shared_lock lock(mutex_);
    return clients_.size();
}

size_t LogSubscriptionManager::getTotalSubscriptionCount() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [conn, state] : clients_) {
        count += state.subscriptions.size();
    }
    return count;
}

void LogSubscriptionManager::sendJson(const drogon::WebSocketConnectionPtr& conn, const std::string& json) {
    try {
        conn->send(json);
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send WebSocket JSON: {}", e.what());
    }
}
