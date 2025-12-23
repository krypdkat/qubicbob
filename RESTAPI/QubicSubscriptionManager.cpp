#include "QubicSubscriptionManager.h"
#include "QubicRpcMapper.h"
#include "Logger.h"
#include "GlobalVar.h"
#include "K12AndKeyUtil.h"
#include "database/db.h"
#include "drogon/drogon.h"
#include <sstream>
#include <iomanip>
#include <cstring>

QubicSubscriptionManager& QubicSubscriptionManager::instance() {
    static QubicSubscriptionManager instance;
    return instance;
}

void QubicSubscriptionManager::addClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);
    clientSubscriptions_[conn] = {};
}

void QubicSubscriptionManager::removeClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    // Remove all subscriptions for this client
    auto it = clientSubscriptions_.find(conn);
    if (it != clientSubscriptions_.end()) {
        for (const auto& subId : it->second) {
            subscriptions_.erase(subId);
        }
        clientSubscriptions_.erase(it);
    }
}

std::string QubicSubscriptionManager::generateSubscriptionId() {
    uint64_t id = subscriptionCounter_.fetch_add(1);
    std::stringstream ss;
    ss << "qubic_sub_" << std::hex << id;
    return ss.str();
}

std::string QubicSubscriptionManager::subscribe(
    const drogon::WebSocketConnectionPtr& conn,
    QubicSubscriptionType type,
    const LogFilter& filter)
{
    std::unique_lock lock(mutex_);

    // Check if client is registered
    auto clientIt = clientSubscriptions_.find(conn);
    if (clientIt == clientSubscriptions_.end()) {
        return "";
    }

    // Generate subscription ID
    std::string subId = generateSubscriptionId();

    // Create subscription
    QubicSubscription sub;
    sub.id = subId;
    sub.type = type;
    sub.filter = filter;
    sub.conn = conn;

    // Store subscription
    subscriptions_[subId] = sub;
    clientIt->second.insert(subId);

    Logger::get()->debug("Qubic subscription created: {} type={}", subId, static_cast<int>(type));

    return subId;
}

bool QubicSubscriptionManager::unsubscribe(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionId)
{
    std::unique_lock lock(mutex_);

    // Find subscription
    auto subIt = subscriptions_.find(subscriptionId);
    if (subIt == subscriptions_.end()) {
        return false;
    }

    // Verify ownership
    if (subIt->second.conn != conn) {
        return false;
    }

    // Remove from client's subscription set
    auto clientIt = clientSubscriptions_.find(conn);
    if (clientIt != clientSubscriptions_.end()) {
        clientIt->second.erase(subscriptionId);
    }

    // Remove subscription
    subscriptions_.erase(subIt);

    Logger::get()->debug("Qubic subscription removed: {}", subscriptionId);

    return true;
}

size_t QubicSubscriptionManager::getClientCount() const {
    std::shared_lock lock(mutex_);
    return clientSubscriptions_.size();
}

void QubicSubscriptionManager::onNewTick(uint32_t tick, const TickData& td) {
    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::pair<std::string, Json::Value>>> pendingSends;

    {
        std::shared_lock lock(mutex_);

        if (subscriptions_.empty()) return;

        // Build tick notification in Qubic format
        std::vector<m256i> txDigests;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
            if (td.transactionDigests[i] != m256i::zero()) {
                txDigests.push_back(td.transactionDigests[i]);
            }
        }

        Json::Value tickData = QubicRpc::tickDataToQubicTick(tick, td, txDigests, false);

        // Find all newTicks subscriptions
        for (const auto& [subId, sub] : subscriptions_) {
            if (sub.type == QubicSubscriptionType::NewTicks) {
                pendingSends.emplace_back(sub.conn, std::make_pair(subId, tickData));
            }
        }
    }

    // Send asynchronously
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([this, sends = std::move(pendingSends)]() {
                for (const auto& [conn, subIdAndResult] : sends) {
                    if (conn->connected()) {
                        sendSubscriptionMessage(conn, subIdAndResult.first, subIdAndResult.second);
                    }
                }
            });
        }
    }
}

void QubicSubscriptionManager::onNewLogs(uint32_t tick, const std::vector<LogEvent>& logs,
                                          const TickData& td) {
    if (logs.empty()) return;

    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::pair<std::string, Json::Value>>> pendingSends;

    {
        std::shared_lock lock(mutex_);

        if (subscriptions_.empty()) return;

        // Get log ranges for transaction index lookup
        LogRangesPerTxInTick lr{-1};
        db_try_get_log_ranges(tick, lr);

        uint64_t logIndexInTick = 0;

        for (const auto& log : logs) {
            // Find transaction index
            int txIndex = 0;
            uint64_t logId = log.getLogId();
            for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                if (lr.fromLogId[i] >= 0 && lr.length[i] > 0) {
                    if (static_cast<int64_t>(logId) >= lr.fromLogId[i] &&
                        static_cast<int64_t>(logId) < lr.fromLogId[i] + lr.length[i]) {
                        txIndex = i;
                        break;
                    }
                }
            }

            // Convert to Qubic log format
            Json::Value qubicLog = QubicRpc::logEventToQubicLog(log, td, txIndex, logIndexInTick++);

            // Get source/destination identities for filtering
            std::string sourceIdentity;
            std::string destIdentity;
            if (qubicLog.isMember("source")) {
                sourceIdentity = qubicLog["source"].asString();
            }
            if (qubicLog.isMember("destination")) {
                destIdentity = qubicLog["destination"].asString();
            }

            // Check all log and transfer subscriptions
            for (const auto& [subId, sub] : subscriptions_) {
                if (sub.type == QubicSubscriptionType::Logs ||
                    sub.type == QubicSubscriptionType::Transfers) {
                    if (matchesFilter(log, sub.filter, sourceIdentity, destIdentity)) {
                        pendingSends.emplace_back(sub.conn, std::make_pair(subId, qubicLog));
                    }
                }
            }
        }
    }

    // Send asynchronously
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([this, sends = std::move(pendingSends)]() {
                for (const auto& [conn, subIdAndResult] : sends) {
                    if (conn->connected()) {
                        sendSubscriptionMessage(conn, subIdAndResult.first, subIdAndResult.second);
                    }
                }
            });
        }
    }
}

bool QubicSubscriptionManager::matchesFilter(
    const LogEvent& log,
    const LogFilter& filter,
    const std::string& sourceIdentity,
    const std::string& destIdentity)
{
    // Check log type filter
    if (!filter.logTypes.empty()) {
        bool match = false;
        for (uint32_t lt : filter.logTypes) {
            if (log.getType() == lt) {
                match = true;
                break;
            }
        }
        if (!match) return false;
    }

    // Check identity filter
    if (!filter.identities.empty()) {
        bool match = false;
        for (const auto& id : filter.identities) {
            if (sourceIdentity == id || destIdentity == id) {
                match = true;
                break;
            }
        }
        if (!match) return false;
    }

    return true;
}

void QubicSubscriptionManager::sendSubscriptionMessage(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionId,
    const Json::Value& result)
{
    Json::Value msg(Json::objectValue);
    msg["jsonrpc"] = "2.0";
    msg["method"] = "qubic_subscription";
    msg["params"]["subscription"] = subscriptionId;
    msg["params"]["result"] = result;

    Json::FastWriter writer;
    try {
        conn->send(writer.write(msg));
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send Qubic subscription message: {}", e.what());
    }
}
