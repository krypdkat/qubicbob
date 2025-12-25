#include "KafkaProducer.h"
#include "Logger.h"
#include <librdkafka/rdkafka.h>
#include <cstring>

// Delivery report callback - called for each message sent
static void dr_msg_cb(rd_kafka_t* rk, const rd_kafka_message_t* rkmessage, void* opaque) {
    (void)rk;
    (void)opaque;
    if (rkmessage->err) {
        Logger::get()->warn("Kafka message delivery failed: {} [{}]",
                           rd_kafka_err2str(rkmessage->err),
                           rd_kafka_topic_name(rkmessage->rkt));
    }
}

// Error callback
static void error_cb(rd_kafka_t* rk, int err, const char* reason, void* opaque) {
    (void)rk;
    (void)opaque;
    Logger::get()->error("Kafka error: {} ({}): {}",
                        rd_kafka_err2name(static_cast<rd_kafka_resp_err_t>(err)),
                        err, reason);
}

// Log callback
static void log_cb(const rd_kafka_t* rk, int level, const char* fac, const char* buf) {
    (void)rk;
    switch (level) {
        case 0: // EMERG
        case 1: // ALERT
        case 2: // CRIT
            Logger::get()->critical("Kafka [{}]: {}", fac, buf);
            break;
        case 3: // ERR
            Logger::get()->error("Kafka [{}]: {}", fac, buf);
            break;
        case 4: // WARNING
            Logger::get()->warn("Kafka [{}]: {}", fac, buf);
            break;
        case 5: // NOTICE
        case 6: // INFO
            Logger::get()->info("Kafka [{}]: {}", fac, buf);
            break;
        default: // DEBUG
            Logger::get()->debug("Kafka [{}]: {}", fac, buf);
            break;
    }
}

KafkaProducer& KafkaProducer::instance() {
    static KafkaProducer inst;
    return inst;
}

KafkaProducer::~KafkaProducer() {
    shutdown();
}

bool KafkaProducer::init(const KafkaConfig& config) {
    if (!config.enabled) {
        Logger::get()->info("Kafka producer is disabled");
        return true;
    }

    char errstr[512];
    rd_kafka_conf_t* conf = rd_kafka_conf_new();

    // Set broker list
    if (rd_kafka_conf_set(conf, "bootstrap.servers", config.brokers.c_str(),
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        Logger::get()->error("Kafka config error (bootstrap.servers): {}", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    // Set compression
    if (rd_kafka_conf_set(conf, "compression.type", config.compression.c_str(),
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        Logger::get()->error("Kafka config error (compression.type): {}", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    // Set batching parameters
    std::string batch_size_str = std::to_string(config.batch_size);
    if (rd_kafka_conf_set(conf, "batch.num.messages", batch_size_str.c_str(),
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        Logger::get()->error("Kafka config error (batch.num.messages): {}", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    std::string linger_str = std::to_string(config.linger_ms);
    if (rd_kafka_conf_set(conf, "linger.ms", linger_str.c_str(),
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        Logger::get()->error("Kafka config error (linger.ms): {}", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    // Set callbacks
    rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
    rd_kafka_conf_set_error_cb(conf, error_cb);
    rd_kafka_conf_set_log_cb(conf, log_cb);
    rd_kafka_conf_set_opaque(conf, this);

    // Create producer instance
    producer_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!producer_) {
        Logger::get()->error("Failed to create Kafka producer: {}", errstr);
        // conf is already destroyed by rd_kafka_new on failure
        return false;
    }

    // Create topics
    logsTopic_ = rd_kafka_topic_new(producer_, config.logs_topic.c_str(), nullptr);
    if (!logsTopic_) {
        Logger::get()->error("Failed to create Kafka logs topic: {}",
                            rd_kafka_err2str(rd_kafka_last_error()));
        rd_kafka_destroy(producer_);
        producer_ = nullptr;
        return false;
    }

    txsTopic_ = rd_kafka_topic_new(producer_, config.txs_topic.c_str(), nullptr);
    if (!txsTopic_) {
        Logger::get()->error("Failed to create Kafka txs topic: {}",
                            rd_kafka_err2str(rd_kafka_last_error()));
        rd_kafka_topic_destroy(logsTopic_);
        logsTopic_ = nullptr;
        rd_kafka_destroy(producer_);
        producer_ = nullptr;
        return false;
    }

    enabled_ = true;
    Logger::get()->info("Kafka producer initialized: brokers={}, logs_topic={}, txs_topic={}",
                       config.brokers, config.logs_topic, config.txs_topic);
    return true;
}

void KafkaProducer::shutdown() {
    if (!enabled_.load()) return;

    enabled_ = false;

    if (producer_) {
        // Wait for outstanding messages to be delivered (up to 10 seconds)
        Logger::get()->info("Kafka producer flushing pending messages...");
        rd_kafka_flush(producer_, 10000);

        int outq = rd_kafka_outq_len(producer_);
        if (outq > 0) {
            Logger::get()->warn("Kafka producer shutdown with {} messages still in queue", outq);
        }
    }

    if (txsTopic_) {
        rd_kafka_topic_destroy(txsTopic_);
        txsTopic_ = nullptr;
    }

    if (logsTopic_) {
        rd_kafka_topic_destroy(logsTopic_);
        logsTopic_ = nullptr;
    }

    if (producer_) {
        rd_kafka_destroy(producer_);
        producer_ = nullptr;
    }

    Logger::get()->info("Kafka producer shutdown complete. Sent: {}, Delivered: {}, Failed: {}",
                       messagesSent_.load(), messagesDelivered_.load(), messagesFailed_.load());
}

void KafkaProducer::sendLog(const std::string& parsedJson, const std::string& logKey, uint64_t timestamp) {
    if (!enabled_.load() || !producer_ || !logsTopic_) return;
    (void)timestamp; // Reserved for future use

    // Use logKey (epoch:logId) as the message key for partitioning and deduplication
    int result = rd_kafka_produce(
        logsTopic_,
        RD_KAFKA_PARTITION_UA,  // Let librdkafka choose partition
        RD_KAFKA_MSG_F_COPY,    // Copy the payload
        const_cast<char*>(parsedJson.data()),
        parsedJson.size(),
        logKey.data(),          // Key
        logKey.size(),
        nullptr                 // Opaque (per-message)
    );

    if (result == -1) {
        rd_kafka_resp_err_t err = rd_kafka_last_error();
        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            // Queue is full, poll to make room and retry once
            rd_kafka_poll(producer_, 100);
            result = rd_kafka_produce(
                logsTopic_,
                RD_KAFKA_PARTITION_UA,
                RD_KAFKA_MSG_F_COPY,
                const_cast<char*>(parsedJson.data()),
                parsedJson.size(),
                logKey.data(),
                logKey.size(),
                nullptr
            );
        }

        if (result == -1) {
            messagesFailed_++;
            Logger::get()->warn("Failed to produce log message to Kafka: {}",
                               rd_kafka_err2str(rd_kafka_last_error()));
            return;
        }
    }

    messagesSent_++;
}

void KafkaProducer::sendTransaction(const std::string& txJson, const std::string& txHash) {
    if (!enabled_.load() || !producer_ || !txsTopic_) return;

    // Use txHash as the message key for partitioning and deduplication
    int result = rd_kafka_produce(
        txsTopic_,
        RD_KAFKA_PARTITION_UA,
        RD_KAFKA_MSG_F_COPY,
        const_cast<char*>(txJson.data()),
        txJson.size(),
        txHash.data(),
        txHash.size(),
        nullptr
    );

    if (result == -1) {
        rd_kafka_resp_err_t err = rd_kafka_last_error();
        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            rd_kafka_poll(producer_, 100);
            result = rd_kafka_produce(
                txsTopic_,
                RD_KAFKA_PARTITION_UA,
                RD_KAFKA_MSG_F_COPY,
                const_cast<char*>(txJson.data()),
                txJson.size(),
                txHash.data(),
                txHash.size(),
                nullptr
            );
        }

        if (result == -1) {
            messagesFailed_++;
            Logger::get()->warn("Failed to produce tx message to Kafka: {}",
                               rd_kafka_err2str(rd_kafka_last_error()));
            return;
        }
    }

    messagesSent_++;
}

void KafkaProducer::poll(int timeout_ms) {
    if (producer_) {
        rd_kafka_poll(producer_, timeout_ms);
    }
}
