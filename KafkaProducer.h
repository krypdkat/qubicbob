#pragma once

#include <string>
#include <atomic>
#include "Config.h"

// Forward declarations to avoid including librdkafka headers in the header
typedef struct rd_kafka_s rd_kafka_t;
typedef struct rd_kafka_topic_s rd_kafka_topic_t;

class KafkaProducer {
public:
    static KafkaProducer& instance();

    // Initialize the Kafka producer with the given configuration
    // Returns true on success, false on failure
    bool init(const KafkaConfig& config);

    // Gracefully shutdown the producer, flushing any pending messages
    void shutdown();

    // Send a verified log event to Kafka (async, non-blocking)
    // parsedJson: the full JSON representation of the log event
    // txHash: transaction hash associated with this log
    // timestamp: unix timestamp in milliseconds
    void sendLog(const std::string& parsedJson, const std::string& txHash, uint64_t timestamp);

    // Send a verified transaction to Kafka (async, non-blocking)
    // txJson: JSON representation of the transaction with all fields
    void sendTransaction(const std::string& txJson);

    // Check if the Kafka producer is enabled and initialized
    bool isEnabled() const { return enabled_.load(); }

    // Poll for events (call periodically to handle callbacks)
    void poll(int timeout_ms = 0);

private:
    KafkaProducer() = default;
    ~KafkaProducer();
    KafkaProducer(const KafkaProducer&) = delete;
    KafkaProducer& operator=(const KafkaProducer&) = delete;

    rd_kafka_t* producer_ = nullptr;
    rd_kafka_topic_t* logsTopic_ = nullptr;
    rd_kafka_topic_t* txsTopic_ = nullptr;
    std::atomic<bool> enabled_{false};
    std::atomic<uint64_t> messagesSent_{0};
    std::atomic<uint64_t> messagesDelivered_{0};
    std::atomic<uint64_t> messagesFailed_{0};
};
