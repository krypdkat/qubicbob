#include "drogon/drogon.h"
#include "drogon/HttpAppFramework.h"
#include "drogon/HttpResponse.h"
#include "drogon/utils/Utilities.h"

// Include WebSocket controller to trigger auto-registration
#include "LogWebSocket.h"

#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <fstream>
#include <sstream>

#include "bob.h"
#include "Logger.h"
#include "shim.h"

// OpenAPI spec - embedded at compile time or loaded from file
static std::string g_openApiSpec;
static std::once_flag g_openApiLoadOnce;

namespace {
    std::once_flag g_startOnce;
    std::atomic<bool> g_started{false};

    drogon::HttpResponsePtr makeJsonResponse(const std::string& jsonStr, drogon::HttpStatusCode code = drogon::k200OK) {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(code);
        resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
        resp->setBody(jsonStr);
        return resp;
    }

    drogon::HttpResponsePtr makeError(const std::string& msg, drogon::HttpStatusCode code = drogon::k400BadRequest) {
        Json::Value err;
        err["ok"] = false;
        err["error"] = msg;
        auto resp = drogon::HttpResponse::newHttpJsonResponse(err);
        resp->setStatusCode(code);
        return resp;
    }

    void registerRoutes() {
        using namespace drogon;

        // Load OpenAPI spec once
        std::call_once(g_openApiLoadOnce, []() {
            // Try to load from file first (for development)
            std::ifstream file("RESTAPI/openapi.json");
            if (!file.is_open()) {
                file.open("openapi.json");
            }
            if (file.is_open()) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                g_openApiSpec = buffer.str();
            } else {
                // Minimal fallback spec
                g_openApiSpec = R"({"openapi":"3.0.3","info":{"title":"QubicBob API","version":"1.0.0"},"paths":{}})";
            }
        });

        // GET /swagger - Swagger UI
        app().registerHandler(
            "/swagger",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                const std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QubicBob API - Swagger UI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/openapi.json",
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout",
                deepLinking: true,
                showExtensions: true,
                showCommonExtensions: true
            });
        };
    </script>
</body>
</html>)";
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_TEXT_HTML);
                resp->setBody(html);
                callback(resp);
            },
            {Get}
        );

        // GET /openapi.json - OpenAPI specification
        app().registerHandler(
            "/openapi.json",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(g_openApiSpec);
                resp->addHeader("Access-Control-Allow-Origin", "*");
                callback(resp);
            },
            {Get}
        );

        // GET /balance/{identity}
        app().registerHandler(
            "/balance/{1}",
            [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& identity) {
                try {
                    std::string result = bobGetBalance(identity.c_str());
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("balance error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Get}
        );

        // GET /asset/{identity}/{issuer}/{asset_name}/{manageSCIndex}
        app().registerHandler(
                "/asset/{1}/{2}/{3}/{4}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &identity, const std::string &issuer, const std::string &assetName,
                   const std::string &manageSCIndexStr) {
                    try {
                        unsigned long long v = std::stoull(manageSCIndexStr);
                        if (v > std::numeric_limits<uint32_t>::max()) {
                            callback(makeError("manageSCIndex out of uint32 range"));
                            return;
                        }
                        uint32_t manageSCIndex = static_cast<uint32_t>(v);
                        std::string result = bobGetAsset(identity, assetName, issuer, manageSCIndex);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("manageSCIndex must be an integer"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("manageSCIndex out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("asset error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /epochinfo/{epoch}
        app().registerHandler(
                "/epochinfo/{1}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &epochStr) {
                    try {
                        uint16_t epoch = std::stoi(epochStr);
                        std::string result = bobGetEpochInfo(epoch);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("epoch must be an integer"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("epoch out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("epochinfo error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /tx/{tx_hash}
        app().registerHandler(
            "/tx/{1}",
            [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& txHash) {
                try {
                    std::string result = bobGetTransaction(txHash.c_str());
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("tx error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Get}
        );

        // GET /log/{epoch}/{from_id}/{to_id}
        app().registerHandler(
                "/log/{1}/{2}/{3}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &epochStr, const std::string &fromStr, const std::string &toStr) {
                    try {
                        // Parse as 64-bit integers
                        uint16_t epoch = std::stoll(epochStr);
                        int64_t fromId = std::stoll(fromStr);
                        int64_t toId = std::stoll(toStr);
                        if (toId < fromId) {
                            callback(makeError("to_id must be >= from_id"));
                            return;
                        }
                        std::string result = bobGetLog(epoch, fromId, toId);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("from_id/to_id must be integers"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("from_id/to_id out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("log error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /tick/{tick_number}
        app().registerHandler(
            "/tick/{1}",
            [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& tickStr) {
                try {
                    unsigned long long v = std::stoull(tickStr);
                    if (v > std::numeric_limits<uint32_t>::max()) {
                        callback(makeError("tick number out of uint32 range"));
                        return;
                    }
                    uint32_t tickNum = static_cast<uint32_t>(v);
                    std::string result = bobGetTick(tickNum);
                    callback(makeJsonResponse(result));
                } catch (const std::invalid_argument&) {
                    callback(makeError("tick_number must be an integer"));
                } catch (const std::out_of_range&) {
                    callback(makeError("tick_number out of range"));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("tick error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Get}
        );
        app().registerHandler(
                "/findLog",
                [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid or missing JSON body"));
                            return;
                        }
                        const auto& j = *jsonPtr;

                        auto getU32 = [&](const char* key, uint32_t& out) -> bool {
                            if (!j.isMember(key) || !(j[key].isUInt() || j[key].isUInt64())) return false;
                            unsigned long long v = j[key].asUInt64();
                            if (v > std::numeric_limits<uint32_t>::max()) return false;
                            out = static_cast<uint32_t>(v);
                            return true;
                        };

                        uint32_t fromTick, toTick, scIndex, logType;
                        if (!getU32("fromTick", fromTick) ||
                            !getU32("toTick", toTick) ||
                            !getU32("scIndex", scIndex) ||
                            !getU32("logType", logType)) {
                            callback(makeError("All numeric fields must be uint32: fromTick, toTick, scIndex, logType"));
                            return;
                        }

                        if (!j.isMember("topic1") || !j["topic1"].isString() ||
                            !j.isMember("topic2") || !j["topic2"].isString() ||
                            !j.isMember("topic3") || !j["topic3"].isString()) {
                            callback(makeError("topic1, topic2, topic3 (strings) are required"));
                            return;
                        }

                        if (fromTick > toTick) {
                            callback(makeError("fromTick must be <= toTick"));
                            return;
                        }

                        const std::string topic1 = j["topic1"].asString();
                        const std::string topic2 = j["topic2"].asString();
                        const std::string topic3 = j["topic3"].asString();

                        std::string result = bobFindLog(scIndex, logType, topic1, topic2, topic3, fromTick, toTick);
                        callback(makeJsonResponse(result));
                    } catch (const std::exception& ex) {
                        callback(makeError(std::string("findLog error: ") + ex.what(), drogon::k500InternalServerError));
                    }
                },
                {Post}
        );
        app().registerHandler(
                "/getlogcustom",
                [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid or missing JSON body"));
                            return;
                        }
                        const auto& j = *jsonPtr;

                        auto getU32 = [&](const char* key, uint32_t& out) -> bool {
                            if (!j.isMember(key) || !(j[key].isUInt() || j[key].isUInt64())) return false;
                            unsigned long long v = j[key].asUInt64();
                            if (v > std::numeric_limits<uint32_t>::max()) return false;
                            out = static_cast<uint32_t>(v);
                            return true;
                        };


                        uint32_t tick, startTick, endTick, scIndex, logType;
                        uint32_t epoch;
                        if (
                            !getU32("scIndex", scIndex) ||
                            !getU32("logType", logType) ||
                            !getU32("epoch", epoch)) {
                            callback(makeError("All numeric fields must be uint32: epoch, scIndex, logType"));
                            return;
                        }
                        if (getU32("tick", tick)) {
                            startTick = tick;
                            endTick = tick;
                        } else {
                            if (!getU32("startTick", startTick) ||
                                !getU32("endTick", endTick)) {
                                callback(makeError("Either tick (uint32) or both startTick and endTick (uint32) are required"));
                                return;
                            }
                        }

                        std::string topics[3] = {"", "", ""};
                        for (int i = 1; i <= 3; ++i) {
                            std::string key = "topic" + std::to_string(i);
                            if (!j.isMember(key) || !j[key].isString()) {
                                topics[i-1] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB";
                            } else {
                                topics[i-1] = j[key].asString();
                                // To uppercase
                                std::transform(topics[i-1].begin(), topics[i-1].end(), topics[i-1].begin(), ::toupper);
                            }
                        }

                        // Reuse the existing find API with a single-tick window
                        std::string result = getCustomLog(scIndex, logType, topics[0], topics[1], topics[2], epoch, startTick, endTick);
                        callback(makeJsonResponse(result));
                    } catch (const std::exception& ex) {
                        callback(makeError(std::string("getlogcustom error: ") + ex.what(), drogon::k500InternalServerError));
                    }
                },
                {Post}
        );

        // POST /getQuTransferForIdentity
        app().registerHandler(
            "/getQuTransfersForIdentity",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                try {
                    auto jsonPtr = req->getJsonObject();
                    if (!jsonPtr) {
                        callback(makeError("Invalid JSON body"));
                        return;
                    }
                    const auto& json = *jsonPtr;
                    
                    if (!json.isMember("fromTick") || !json.isMember("toTick") || !json.isMember("identity")) {
                        callback(makeError("Missing required fields: fromTick, toTick, identity"));
                        return;
                    }
                    
                    uint32_t fromTick = json["fromTick"].asUInt();
                    uint32_t toTick = json["toTick"].asUInt();
                    std::string identity = json["identity"].asString();
                    std::string result = getQuTransfersForIdentity(fromTick, toTick, identity);
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("getQuTransfersForIdentity error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Post}
        );

        // POST /getAssetTransferForIdentity
        app().registerHandler(
            "/getAssetTransfersForIdentity",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                try {
                    auto jsonPtr = req->getJsonObject();
                    if (!jsonPtr) {
                        callback(makeError("Invalid JSON body"));
                        return;
                    }
                    const auto& json = *jsonPtr;
                    
                    if (!json.isMember("fromTick") || !json.isMember("toTick") || !json.isMember("identity") ||
                        !json.isMember("assetIssuer") || !json.isMember("assetName")) {
                        callback(makeError("Missing required fields: fromTick, toTick, identity, assetIssuer, assetName"));
                        return;
                    }
                    
                    uint32_t fromTick = json["fromTick"].asUInt();
                    uint32_t toTick = json["toTick"].asUInt();
                    std::string identity = json["identity"].asString();
                    std::string assetIssuer = json["assetIssuer"].asString();
                    std::string assetName = json["assetName"].asString();
                    std::string result = getAssetTransfersForIdentity(fromTick, toTick, identity, assetIssuer,
                                                                      assetName);
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("getAssetTransfersForIdentity error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Post}
        );

        // POST /getAllAssetTransfer
        app().registerHandler(
            "/getAllAssetTransfers",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                try {
                    auto jsonPtr = req->getJsonObject();
                    if (!jsonPtr) {
                        callback(makeError("Invalid JSON body"));
                        return;
                    }
                    const auto& json = *jsonPtr;
                    
                    if (!json.isMember("fromTick") || !json.isMember("toTick") || 
                        !json.isMember("assetIssuer") || !json.isMember("assetName")) {
                        callback(makeError("Missing required fields: fromTick, toTick, assetIssuer, assetName"));
                        return;
                    }
                    
                    uint32_t fromTick = json["fromTick"].asUInt();
                    uint32_t toTick = json["toTick"].asUInt();
                    std::string assetIssuer = json["assetIssuer"].asString();
                    std::string assetName = json["assetName"].asString();
                    
                    std::string result = getAllAssetTransfers(fromTick, toTick, assetIssuer, assetName);
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("getAllAssetTransfers error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Post}
        );

        // GET /status - Returns node status information
        app().registerHandler(
                "/status",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        std::string result = bobGetStatus();
                        callback(makeJsonResponse(result));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("status error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // POST /querySmartContract
        app().registerHandler(
                "/querySmartContract",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    try {
        if (gNumBMConnection == 0)
        {
            callback(makeError("Bob has no connection to any BM"));
            return;
        }
        auto jsonPtr = req->getJsonObject();
        if (!jsonPtr) {
            callback(makeError("Invalid or missing JSON body"));
            return;
        }
        const auto &j = *jsonPtr;

        if (!j.isMember("nonce") || !j["nonce"].isUInt64()) {
            callback(makeError("nonce (uint32) is required"));
            return;
        }
        if (!j.isMember("scIndex") || !j["scIndex"].isUInt()) {
            callback(makeError("scIndex (uint32) is required"));
            return;
        }
        if (!j.isMember("funcNumber") || !j["funcNumber"].isUInt()) {
            callback(makeError("funcNumber (uint32) is required"));
            return;
        }
        if (!j.isMember("data") || !j["data"].isString()) {
            callback(makeError("data (hex string) is required"));
            return;
        }

        const uint32_t nonce = static_cast<uint32_t>(j["nonce"].asUInt64());
        const uint32_t scIndex = static_cast<uint32_t>(j["scIndex"].asUInt());
        const uint32_t funcNumber = static_cast<uint32_t>(j["funcNumber"].asUInt());
        std::string hex = j["data"].asString();

        // normalize hex
        if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
        if (hex.size() % 2 != 0) {
            callback(makeError("data hex length must be even"));
            return;
        }
        auto isHex = [](char c) {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        };
        for (char c : hex) {
            if (!isHex(c)) {
                callback(makeError("data must be a hex string"));
                return;
            }
        }
        std::vector<uint8_t> dataBytes;
        dataBytes.reserve(hex.length() / 2);
        for (size_t i = 0; i < hex.length(); i += 2) {
            uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
            dataBytes.push_back(byte);
        }

        // 1) Try immediate cache hit
        {
            std::vector<uint8_t> out;
            if (responseSCData.get(nonce, out)) {
                Json::Value root;
                root["nonce"] = nonce;
                // reuse helper from bobAPI.cpp if exposed, otherwise inline:
                {
                    std::stringstream ss;
                    ss << std::hex << std::setfill('0');
                    for (const auto& b : out) ss << std::setw(2) << static_cast<int>(b);
                    root["data"] = ss.str();
                }
                Json::FastWriter writer;
                callback(makeJsonResponse(writer.write(root)));
                return;
            }
        }

        // 2) Enqueue the request (non-blocking)
        enqueueSmartContractRequest(nonce, scIndex, funcNumber, dataBytes.data(), static_cast<uint32_t>(dataBytes.size()));

        // 3) Use Drogon's event loop timer instead of detached thread
        auto sharedCallback = std::make_shared<std::function<void(const HttpResponsePtr&)>>(std::move(callback));
        auto attemptCount = std::make_shared<int>(0);
        
        auto loop = drogon::app().getIOLoop(0);  // Get an event loop

        // Use a shared_ptr to the function for proper capture
        auto pollResultPtr = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> pollResultWeak = pollResultPtr;
        
        *pollResultPtr = [nonce, sharedCallback, attemptCount, loop, pollResultWeak]() {
            std::vector<uint8_t> out;
            if (responseSCData.get(nonce, out)) {
                Json::Value root;
                root["nonce"] = nonce;
                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for (const auto& b : out) ss << std::setw(2) << static_cast<int>(b);
                root["data"] = ss.str();
                Json::FastWriter writer;
                (*sharedCallback)(makeJsonResponse(writer.write(root)));
                return;
            }
            
            (*attemptCount)++;
            if (*attemptCount >= 20) {
                Json::Value root;
                root["error"] = "pending";
                root["message"] = "Query enqueued; try again with the same nonce";
                root["nonce"] = nonce;
                Json::FastWriter writer;
                auto resp = makeJsonResponse(writer.write(root), drogon::k202Accepted);
                resp->setCloseConnection(true);
                (*sharedCallback)(resp);
                return;
            }
            
            // Use weak_ptr to avoid circular reference
            if (auto pollFunc = pollResultWeak.lock()) {
                loop->runAfter(0.1, *pollFunc);
            }
        };
        
        // Start polling after 100ms
        loop->runAfter(0.1, *pollResultPtr);
        
    } catch (const std::exception &ex) {
        callback(makeError(std::string("querySmartContract error: ") + ex.what(), k500InternalServerError));
    }
});

        // POST /broadcastTransaction
        app().registerHandler(
                "/broadcastTransaction",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        if (gNumBMConnection == 0)
                        {
                            callback(makeError("Bob has no connection to any BM"));
                            return;
                        }
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid or missing JSON body"));
                            return;
                        }
                        const auto &j = *jsonPtr;

                        if (!j.isMember("data") || !j["data"].isString()) {
                            callback(makeError("data (hex string) is required"));
                            return;
                        }

                        std::string hex = j["data"].asString();
                        if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
                        if (hex.size() % 2 != 0) {
                            callback(makeError("data hex length must be even"));
                            return;
                        }

                        auto isHex = [](char c) {
                            return (c >= '0' && c <= '9') ||
                                   (c >= 'a' && c <= 'f') ||
                                   (c >= 'A' && c <= 'F');
                        };
                        for (char c: hex) {
                            if (!isHex(c)) {
                                callback(makeError("data must be a hex string"));
                                return;
                            }
                        }

                        std::vector<uint8_t> txData;
                        txData.resize(sizeof(RequestResponseHeader) + hex.length() / 2);
                        auto hdr = (RequestResponseHeader*)txData.data();
                        hdr->setType(BROADCAST_TRANSACTION);
                        hdr->zeroDejavu();
                        hdr->setSize(txData.size());
                        for (int i = 0, count = 0; i < hex.length(); i += 2, count++) {
                            uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
                            txData[count+8] = byte;
                        }

                        std::string result = broadcastTransaction(txData.data(), txData.size());
                        callback(makeJsonResponse(result));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("broadcast error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Post}
        );

    }

    void startServerIfNeeded() {
        std::call_once(g_startOnce, []() {
            if (g_started.exchange(true)) return;

            registerRoutes();

            // Configure and start Drogon
            drogon::app()
                .setLogLevel(trantor::Logger::kInfo)
                .addListener("0.0.0.0", 40420)  // listen at port 40420
                .setThreadNum(std::max(2, gMaxThreads))
                .setIdleConnectionTimeout(120)      // Increased for WebSocket connections
                .setKeepaliveRequestsNumber(200)
                .setMaxConnectionNum(676)          // Limit max concurrent connections
                .setMaxConnectionNumPerIP(100)      // Limit per-IP connections (prevents single client abuse)
                .disableSigtermHandling()
                .reusePort()                        // Enable SO_REUSEADDR to avoid "Address already in use" errors
                ;

            // Run Drogon in a background thread so it doesn't block the main program
            std::thread([]() {
                drogon::app().run();
            }).detach();
        });
    }
} // namespace

// Optional explicit control APIs (in case another part of the program wants to manage lifecycle)
void startRESTServer() {
    Logger::get()->info("Start REST API server");
    startServerIfNeeded();
}

void stopRESTServer() {
    // This will trigger a graceful shutdown; if the app isn't running, it's a no-op.
    drogon::app().quit();
    Logger::get()->info("Stop REST API server");
}