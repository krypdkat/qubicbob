#include "Config.h"
#include "cxxopts.hpp"
#include "connection.h"
#include "parser.h"
#include "structs.h"
#include "Logger.h"
#include "GlobalVar.h"
#include "db.h"
#include "Profiler.h"
#include <chrono>
#include <cstring>   // memcpy
#include <cstdlib>   // strtoull
#include <limits>    // std::numeric_limits
#include <algorithm> // std::max
#include "K12AndKeyUtil.h"
#include <pthread.h> // thread naming on POSIX
#include "shim.h"
void IOVerifyThread(std::atomic_bool& stopFlag);
void IORequestThread(ConnectionPool& conn_pool, std::atomic_bool& stopFlag, std::chrono::milliseconds requestCycle, uint32_t futureOffset);
void LoggingEventRequestThread(ConnectionPool& conn, std::atomic_bool& stopFlag, std::chrono::milliseconds requestCycle, uint32_t futureOffset);
void connReceiver(QCPtr& conn, const bool isTrustedNode, std::atomic_bool& stopFlag);
void DataProcessorThread(std::atomic_bool& exitFlag);
void RequestProcessorThread(std::atomic_bool& exitFlag);
void verifyLoggingEvent(std::atomic_bool& stopFlag);
void indexVerifiedTicks(std::atomic_bool& stopFlag);
std::atomic_bool stopFlag{false};

// Public helpers from QubicServer.cpp
bool StartQubicServer(uint16_t port = 21842);
void StopQubicServer();

static inline void set_this_thread_name(const char* name_in) {
    // Linux allows up to 16 bytes including null terminator
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%s", name_in ? name_in : "");
    pthread_setname_np(pthread_self(), buf);
}

void requestToExitBob()
{
    stopFlag = true;
}

int runBob(int argc, char *argv[])
{
    // Ignore SIGPIPE so write/send on a closed socket doesn't terminate the process.
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, nullptr);
    // Load configuration from JSON
    const std::string config_path = (argc > 1) ? std::string(argv[1]) : std::string("bob.json");
    AppConfig cfg;
    std::string cfg_error;
    if (!LoadConfig(config_path, cfg, cfg_error)) {
        printf("Failed to load config '%s': %s\n", config_path.c_str(), cfg_error.c_str());
        return -1;
    }
    if (cfg.trusted_nodes.empty()) {
        printf("Config error: 'trusted-node' requires at least one endpoint in ip:port or ip:port:pass0-pass1-pass2-pass3 format.\n");
        return -1;
    }
    if (cfg.arbitrator_identity.empty()) {
        printf("Config error: 'arbitrator-identity' is required.\n");
        return -1;
    }

    // Defaults for new knobs are already in AppConfig
    unsigned int request_cycle_ms = cfg.request_cycle_ms;
    unsigned int future_offset = cfg.future_offset;

    // trace - debug - info - warn - error - fatal
    std::string log_level = cfg.log_level;
    const bool verify_log_event = cfg.verify_log_event;

    // Put redis_url in REDIS_CONNECTION_STRING
    std::string REDIS_CONNECTION_STRING = cfg.redis_url;
    Logger::init(log_level);

    // Read server flags
    const bool run_server = cfg.run_server;
    unsigned int server_port_u = cfg.server_port;
    if (run_server) {
        if (server_port_u == 0 || server_port_u > 65535) {
            Logger::get()->critical("Invalid server_port {}. Must be in 1..65535", server_port_u);
            return -1;
        }
        const uint16_t server_port = static_cast<uint16_t>(server_port_u);
        if (!StartQubicServer(server_port)) {
            Logger::get()->critical("Failed to start embedded server on port {}", server_port);
            return -1;
        }
        Logger::get()->info("Embedded server enabled on port {}", server_port);
    }

    {
        // initialize gCurrentProcessingTick with 1st connection
        db_connect(REDIS_CONNECTION_STRING);
        uint32_t tick;
        uint16_t epoch;
        db_get_latest_tick_and_epoch(tick, epoch);
        gCurrentFetchingTick = tick;
        gCurrentProcessingEpoch = epoch;
        uint16_t event_epoch;
        db_get_latest_event_tick_and_epoch(tick, event_epoch);
        gCurrentLoggingEventTick = tick;
        Logger::get()->info("Loaded DB. DATA: Tick: {} | epoch: {}", gCurrentFetchingTick.load(), gCurrentProcessingEpoch.load());
        Logger::get()->info("Loaded DB. EVENT: Tick: {} | epoch: {}", gCurrentLoggingEventTick.load(), event_epoch);
    }
    // Collect endpoints from config
    std::vector<std::string> endpoints = cfg.trusted_nodes;

    // Try endpoints in order, connect to the first that works
    ConnectionPool conn_pool;
    ConnectionPool conn_pool_logging; // conn pool with passcode
    for (const auto& endpoint : endpoints) {
        // Parse ip:port[:pass0-pass1-pass2-pass3]
        auto p1 = endpoint.find(':');
        if (p1 == std::string::npos || p1 == 0 || p1 == endpoint.size() - 1) {
            Logger::get()->warn("Skipping invalid endpoint '{}', expected ip:port or ip:port:pass0-pass1-pass2-pass3", endpoint);
            continue;
        }
        auto p2 = endpoint.find(':', p1 + 1);
        std::string ip = endpoint.substr(0, p1);
        std::string port_str;
        std::string passcode_str;

        if (p2 == std::string::npos) {
            port_str = endpoint.substr(p1 + 1);
        } else {
            if (p2 == endpoint.size() - 1) {
                Logger::get()->warn("Skipping endpoint '{}': missing passcode after second ':'", endpoint);
                continue;
            }
            port_str = endpoint.substr(p1 + 1, p2 - (p1 + 1));
            passcode_str = endpoint.substr(p2 + 1);
        }

        int port = 0;
        try {
            port = std::stoi(port_str);
            if (port <= 0 || port > 65535) {
                throw std::out_of_range("port out of range");
            }
        } catch (...) {
            Logger::get()->warn("Skipping endpoint '{}': invalid port '{}'", endpoint, port_str);
            continue;
        }

        // Optional passcode parsing
        bool has_passcode = false;
        uint64_t passcode_arr[4] = {0,0,0,0};
        if (!passcode_str.empty()) {
            // Split by '-'
            uint64_t parsed[4];
            size_t start = 0;
            int idx = 0;
            while (idx < 4 && start <= passcode_str.size()) {
                size_t dash = passcode_str.find('-', start);
                auto token = passcode_str.substr(start, (dash == std::string::npos) ? std::string::npos : (dash - start));
                if (token.empty()) break;
                try {
                    parsed[idx] = static_cast<uint64_t>(std::stoull(token, nullptr, 10));
                } catch (...) {
                    idx = -1; // mark error
                    break;
                }
                idx++;
                if (dash == std::string::npos) break;
                start = dash + 1;
            }
            if (idx == 4) {
                memcpy(passcode_arr, parsed, sizeof(parsed));
                has_passcode = true;
            } else {
                Logger::get()->warn("Skipping endpoint '{}': invalid passcode format, expected 4 uint64 separated by '-'", endpoint);
                continue;
            }
        }
        QCPtr conn = make_qc(ip.c_str(), port);
        if (has_passcode) {
            conn->updatePasscode(passcode_arr);
        }

        try {
            if (conn->isSocketValid())
            {
                uint32_t initTick = 0;
                uint16_t initEpoch = 0;
                conn->doHandshake();
                conn->getTickInfo(initTick, initEpoch);
                gInitialTick = initTick;
                if (initTick > gCurrentFetchingTick.load())
                {
                    Logger::get()->warn("Initial tick from node {} is greater than local leading tick: {} vs {}", ip, initTick, gCurrentFetchingTick.load());
                    gCurrentFetchingTick = initTick;
                }
                if (initTick > gCurrentLoggingEventTick.load())
                {
                    gCurrentLoggingEventTick = initTick;
                }

                if (initEpoch > gCurrentProcessingEpoch.load())
                {
                    Logger::get()->warn("Initial epoch from node {} is greater than local leading epoch: {} vs {}", ip, initEpoch, gCurrentProcessingEpoch.load());
                    gCurrentProcessingEpoch = initEpoch;
                }
                if (computorsList.epoch != gCurrentProcessingEpoch.load())
                {
                    if (!db_get_computors(gCurrentProcessingEpoch.load(),computorsList))
                    {
                        Logger::get()->warn("Computor list for epoch {} doesn't exist, trying to get one...", gCurrentProcessingEpoch.load());
                        conn->getComputorList(gCurrentProcessingEpoch.load(),computorsList);
                        uint8_t digest[32];
                        uint8_t arbitratorPublicKey[32];
                        getPublicKeyFromIdentity(cfg.arbitrator_identity.c_str(), arbitratorPublicKey);
                        KangarooTwelve((uint8_t*)&computorsList, sizeof(computorsList) - 64, digest, 32);
                        if (verify(arbitratorPublicKey, digest, computorsList.signature))
                        {
                            db_insert_computors(computorsList);
                        }
                        else
                        {
                            Logger::get()->critical("Invalid signature in computor list");
                        }
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            Logger::get()->warn("Failed to connect or handshake with endpoint '{}': {}."
                                "bob still added this node to connection pool for future use", endpoint, e.what());
        }
        conn_pool.add(conn);
        if (has_passcode) conn_pool_logging.add(conn);
    }
    stopFlag.store(false);
    auto request_thread = std::thread(
            [&](){
                set_this_thread_name("io-req");
                IORequestThread(
                        std::ref(conn_pool),
                        std::ref(stopFlag),
                        std::chrono::milliseconds(request_cycle_ms),
                        static_cast<uint32_t>(future_offset)
                );
            }
    );
    auto verify_thread = std::thread([&](){
        set_this_thread_name("verify");
        IOVerifyThread(std::ref(stopFlag));
    });
    auto log_request_thread = std::thread([&](){
        set_this_thread_name("log-req");
        LoggingEventRequestThread(std::ref(conn_pool_logging), std::ref(stopFlag),
                                  std::chrono::milliseconds(request_cycle_ms),
                                  static_cast<uint32_t>(future_offset));
    });
    auto indexer_thread = std::thread([&](){
        set_this_thread_name("indexer");
        indexVerifiedTicks(std::ref(stopFlag));
    });
    int pool_size = conn_pool.size();
    std::vector<std::thread> v_recv_thread;
    std::vector<std::thread> v_data_thread;
    Logger::get()->info("Starting {} data processor threads", pool_size);
    const bool isTrustedNode = true;
    for (int i = 0; i < pool_size; i++)
    {
        v_recv_thread.emplace_back([&, i](){
            char nm[16];
            std::snprintf(nm, sizeof(nm), "recv-%d", i);
            set_this_thread_name(nm);
            connReceiver(std::ref(conn_pool.get(i)), isTrustedNode, std::ref(stopFlag));
        });
    }
    for (int i = 0; i < std::max(16, pool_size); i++)
    {
        v_data_thread.emplace_back([&](){
            set_this_thread_name("data");
            DataProcessorThread(std::ref(stopFlag));
        });
        v_data_thread.emplace_back([&, i](){
            char nm[16];
            std::snprintf(nm, sizeof(nm), "reqp-%d", i);
            set_this_thread_name(nm);
            RequestProcessorThread(std::ref(stopFlag));
        });
    }
    std::thread log_event_verifier_thread;
    if (verify_log_event) {
        log_event_verifier_thread = std::thread([&](){
            set_this_thread_name("log-ver");
            verifyLoggingEvent(std::ref(stopFlag));
        });
    }
    uint32_t prevFetchingTickData = 0;
    uint32_t prevLoggingEventTick = 0;
    uint32_t prevVerifyEventTick = 0;
    uint32_t prevIndexingTick = 0;
    const long long sleep_time = 5;
    while (!stopFlag.load())
    {
        float fetching_td_speed = (prevFetchingTickData == 0) ? 0: float(gCurrentFetchingTick.load() - prevFetchingTickData) / sleep_time;
        float fetching_le_speed = (prevLoggingEventTick == 0) ? 0: float(gCurrentLoggingEventTick.load() - prevLoggingEventTick) / sleep_time;
        float verify_le_speed = (prevVerifyEventTick == 0) ? 0: float(gCurrentVerifyLoggingTick.load() - prevVerifyEventTick) / sleep_time;
        float indexing_speed = (prevIndexingTick == 0) ? 0: float(gCurrentIndexingTick.load() - prevIndexingTick) / sleep_time;
        prevFetchingTickData = gCurrentFetchingTick.load();
        prevLoggingEventTick = gCurrentLoggingEventTick.load();
        prevVerifyEventTick = gCurrentVerifyLoggingTick.load();
        prevIndexingTick = gCurrentIndexingTick.load();
        Logger::get()->info("Current state: TickData: {} ({}) | LogEvent: {} ({}) | Indexing: {} ({}) | Verifying: {} ({})",
                            gCurrentFetchingTick.load(), fetching_td_speed,
                            gCurrentLoggingEventTick.load(), fetching_le_speed,
                            gCurrentIndexingTick.load(), indexing_speed,
                            gCurrentVerifyLoggingTick.load(), verify_le_speed);
        requestMapperFrom.clean();
        int count = 0;
        while (count++ < sleep_time*10 && !stopFlag.load()) SLEEP(100);
    }
    // Signal stop, disconnect sockets first to break any blocking I/O.
    for (int i = 0; i < conn_pool.size(); i++) conn_pool.get(i)->disconnect();

    // Stop and join producer/request threads first so they cannot enqueue more work.
    verify_thread.join();
    Logger::get()->info("Exited Verifying thread");
    request_thread.join();
    Logger::get()->info("Exited TickDataRequest thread");
    log_request_thread.join();
    Logger::get()->info("Exited LogEventRequest thread");
    indexer_thread.join();
    Logger::get()->info("Exited indexer thread");
    if (log_event_verifier_thread.joinable())
    {
        Logger::get()->info("Exiting verifyLoggingEvent thread");
        log_event_verifier_thread.join();
        Logger::get()->info("Exited verifyLoggingEvent thread");
    }

    // Now the receivers can drain and exit.
    for (auto& thr : v_recv_thread) thr.join();
    Logger::get()->info("Exited recv threads");

    // Wake all data threads so none remain blocked on MRB.
    {
        RequestResponseHeader header;
        header.randomizeDejavu();
        header.setType(35); // NOP
        header.setSize(8);
        const size_t wake_count = v_data_thread.size() * 4; // ensure enough tokens
        for (size_t i = 0; i < wake_count; ++i) {
            MRB_Data.EnqueuePacket(reinterpret_cast<uint8_t*>(&header));
            MRB_Request.EnqueuePacket(reinterpret_cast<uint8_t*>(&header));
        }
    }

    for (auto& thr : v_data_thread) thr.join();
    Logger::get()->info("Exited data threads");
    db_close();

    // Stop embedded server (if it was started) before shutting down logger
    StopQubicServer();
    ProfilerRegistry::instance().printSummary();
    Logger::get()->info("Shutting down logger");
    spdlog::shutdown();
    return 0;
}