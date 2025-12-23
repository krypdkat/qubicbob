#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <atomic>
#include <optional>
#include "drogon/WebSocketConnection.h"
#include "LogEvent.h"
#include "structs.h"

// Subscription types for Qubic API
enum class QubicSubscriptionType {
    NewTicks,    // New tick notifications
    Logs,        // Log events matching filter
    Transfers    // QU transfer events (specialized log filter)
};

// Log filter for subscriptions
struct LogFilter {
    std::optional<uint32_t> fromTick;
    std::optional<uint32_t> toTick;
    std::vector<std::string> identities;  // Filter by source or destination identity
    std::vector<uint32_t> logTypes;       // Filter by log type
};

// Subscription entry
struct QubicSubscription {
    std::string id;
    QubicSubscriptionType type;
    LogFilter filter;
    drogon::WebSocketConnectionPtr conn;
};

class QubicSubscriptionManager {
public:
    static QubicSubscriptionManager& instance();

    // Client lifecycle
    void addClient(const drogon::WebSocketConnectionPtr& conn);
    void removeClient(const drogon::WebSocketConnectionPtr& conn);

    // Subscription management
    std::string subscribe(const drogon::WebSocketConnectionPtr& conn,
                          QubicSubscriptionType type,
                          const LogFilter& filter = {});
    bool unsubscribe(const drogon::WebSocketConnectionPtr& conn,
                     const std::string& subscriptionId);

    // Event distribution (called from LogSubscriptionManager)
    void onNewTick(uint32_t tick, const TickData& td);
    void onNewLogs(uint32_t tick, const std::vector<LogEvent>& logs, const TickData& td);

    // Get client count for monitoring
    size_t getClientCount() const;

private:
    QubicSubscriptionManager() = default;

    std::string generateSubscriptionId();
    bool matchesFilter(const LogEvent& log, const LogFilter& filter,
                       const std::string& sourceIdentity,
                       const std::string& destIdentity);
    void sendSubscriptionMessage(const drogon::WebSocketConnectionPtr& conn,
                                 const std::string& subscriptionId,
                                 const Json::Value& result);

    mutable std::shared_mutex mutex_;

    // Client -> subscriptions mapping
    std::unordered_map<drogon::WebSocketConnectionPtr,
                       std::unordered_set<std::string>> clientSubscriptions_;

    // Subscription ID -> subscription data
    std::unordered_map<std::string, QubicSubscription> subscriptions_;

    // Counter for generating subscription IDs
    std::atomic<uint64_t> subscriptionCounter_{0};
};
