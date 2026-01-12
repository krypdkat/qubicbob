#include "QubicRpcWebSocket.h"
#include "QubicRpcMethods.h"
#include "QubicSubscriptionManager.h"
#include "QubicRpcMapper.h"
#include "Logger.h"
#include "shim.h"
#include <sstream>

void QubicRpcWebSocket::handleNewConnection(
    const drogon::HttpRequestPtr& req,
    const drogon::WebSocketConnectionPtr& wsConnPtr)
{
    // Reject connections until bootstrap is complete
    if (gCurrentVerifyLoggingTick.load() <= gInitialTick.load()) {
        Logger::get()->info("Qubic JSON-RPC WebSocket connection rejected (bootstrap in progress) from {}",
                            req->getPeerAddr().toIpPort());
        Json::Value error;
        error["jsonrpc"] = "2.0";
        error["error"]["code"] = -32000;
        error["error"]["message"] = "Server is starting up, please try again later";
        error["id"] = Json::Value::null;
        Json::FastWriter writer;
        wsConnPtr->send(writer.write(error));
        wsConnPtr->shutdown();
        return;
    }

    Logger::get()->info("Qubic JSON-RPC WebSocket connection from {}",
                        req->getPeerAddr().toIpPort());

    // Register with subscription manager
    QubicSubscriptionManager::instance().addClient(wsConnPtr);
}

void QubicRpcWebSocket::handleConnectionClosed(
    const drogon::WebSocketConnectionPtr& wsConnPtr)
{
    Logger::get()->info("Qubic JSON-RPC WebSocket connection closed");

    // Cleanup subscriptions
    QubicSubscriptionManager::instance().removeClient(wsConnPtr);
}

void QubicRpcWebSocket::handleNewMessage(
    const drogon::WebSocketConnectionPtr& wsConnPtr,
    std::string&& message,
    const drogon::WebSocketMessageType& type)
{
    // Ignore non-text messages
    if (type == drogon::WebSocketMessageType::Ping ||
        type == drogon::WebSocketMessageType::Pong ||
        type == drogon::WebSocketMessageType::Close) {
        return;
    }

    if (type != drogon::WebSocketMessageType::Text) {
        sendResponse(wsConnPtr, makeError(Json::Value::null,
                     QubicRpcError::INVALID_REQUEST, "Only text messages are supported"));
        return;
    }

    // Parse JSON
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(message);

    if (!Json::parseFromStream(builder, stream, &root, &errors)) {
        sendResponse(wsConnPtr, makeError(Json::Value::null,
                     QubicRpcError::PARSE_ERROR, "Parse error: " + errors));
        return;
    }

    // Handle batch requests (array of requests)
    if (root.isArray()) {
        if (root.empty()) {
            sendResponse(wsConnPtr, makeError(Json::Value::null,
                         QubicRpcError::INVALID_REQUEST, "Empty batch"));
            return;
        }

        Json::Value responses(Json::arrayValue);
        for (const auto& req : root) {
            Json::Value response = processRequest(wsConnPtr, req);
            if (!response.isNull()) {
                responses.append(response);
            }
        }

        if (!responses.empty()) {
            sendResponse(wsConnPtr, responses);
        }
        return;
    }

    // Single request
    Json::Value response = processRequest(wsConnPtr, root);
    if (!response.isNull()) {
        sendResponse(wsConnPtr, response);
    }
}

Json::Value QubicRpcWebSocket::processRequest(
    const drogon::WebSocketConnectionPtr& conn,
    const Json::Value& request)
{
    // Validate JSON-RPC 2.0 structure
    if (!request.isObject()) {
        return makeError(Json::Value::null, QubicRpcError::INVALID_REQUEST,
                        "Request must be an object");
    }

    // Check jsonrpc version
    if (!request.isMember("jsonrpc") || request["jsonrpc"].asString() != "2.0") {
        return makeError(request.get("id", Json::Value::null),
                        QubicRpcError::INVALID_REQUEST, "Invalid JSON-RPC version");
    }

    // Check method
    if (!request.isMember("method") || !request["method"].isString()) {
        return makeError(request.get("id", Json::Value::null),
                        QubicRpcError::INVALID_REQUEST, "Missing or invalid method");
    }

    std::string method = request["method"].asString();
    if (method.empty()) {
        return makeError(request.get("id", Json::Value::null),
                        QubicRpcError::INVALID_REQUEST, "Method cannot be empty");
    }
    Json::Value params = request.get("params", Json::Value(Json::arrayValue));
    Json::Value id = request.get("id", Json::Value::null);

    // If no id, this is a notification - no response required
    if (id.isNull() && !request.isMember("id")) {
        dispatchMethod(conn, id, method, params);
        return Json::Value::null;
    }

    return dispatchMethod(conn, id, method, params);
}

Json::Value QubicRpcWebSocket::dispatchMethod(
    const drogon::WebSocketConnectionPtr& conn,
    const Json::Value& id,
    const std::string& method,
    const Json::Value& params)
{
    try {
        // ====================================================================
        // Chain Info Methods
        // ====================================================================
        if (method == "qubic_chainId") {
            return makeResult(id, QubicRpcMethods::chainId());
        }
        if (method == "qubic_clientVersion") {
            return makeResult(id, QubicRpcMethods::clientVersion());
        }
        if (method == "qubic_syncing") {
            return makeResult(id, QubicRpcMethods::syncing());
        }
        if (method == "qubic_getCurrentEpoch") {
            return makeResult(id, QubicRpcMethods::getCurrentEpoch());
        }

        // ====================================================================
        // Tick Methods
        // ====================================================================
        if (method == "qubic_getTickNumber") {
            return makeResult(id, QubicRpcMethods::getTickNumber());
        }
        if (method == "qubic_getTickByNumber") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing tick number/tag parameter");
            }
            std::string tickTag = params[0].asString();
            bool includeTx = params.size() > 1 ? params[1].asBool() : false;
            return makeResult(id, QubicRpcMethods::getTickByNumber(tickTag, includeTx));
        }
        if (method == "qubic_getTickByHash") {
            // Disabled: inefficient implementation requiring full tick scan
            return makeError(id, QubicRpcError::METHOD_NOT_FOUND, "qubic_getTickByHash is not available");
        }

        // ====================================================================
        // Transaction Methods
        // ====================================================================
        if (method == "qubic_getTransactionByHash") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing transaction hash parameter");
            }
            return makeResult(id, QubicRpcMethods::getTransactionByHash(params[0].asString()));
        }
        if (method == "qubic_getTransactionReceipt") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing transaction hash parameter");
            }
            return makeResult(id, QubicRpcMethods::getTransactionReceipt(params[0].asString()));
        }
        if (method == "qubic_broadcastTransaction" || method == "qubic_sendRawTransaction") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing signed transaction parameter");
            }
            return makeResult(id, QubicRpcMethods::broadcastTransaction(params[0].asString()));
        }

        // ====================================================================
        // Balance & Transfer Methods
        // ====================================================================
        if (method == "qubic_getBalance") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing identity parameter");
            }
            if (!QubicRpcMethods::isValidIdentityInput(params[0].asString())) {
                return makeError(id, QubicRpcError::INVALID_PARAMS,
                    "Invalid identity format. Expected 60-char Qubic identity (A-Z) or 0x-prefixed hex public key");
            }
            return makeResult(id, QubicRpcMethods::getBalance(params[0].asString()));
        }
        if (method == "qubic_getTransfers") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing filter parameter");
            }
            // Accepts a filter object with optional fields:
            // identity, fromTick, toTick, scIndex, logType, topic1, topic2, topic3
            return makeResult(id, QubicRpcMethods::getTransfers(params[0]));
        }

        // ====================================================================
        // Asset Methods
        // ====================================================================
        if (method == "qubic_getAssetBalance") {
            if (!params.isArray() || params.size() < 3) {
                return makeError(id, QubicRpcError::INVALID_PARAMS,
                               "Missing parameters: [identity, issuer, assetName]");
            }
            if (!QubicRpcMethods::isValidIdentityInput(params[0].asString())) {
                return makeError(id, QubicRpcError::INVALID_PARAMS,
                    "Invalid identity format for parameter 1. Expected 60-char Qubic identity (A-Z) or 0x-prefixed hex public key");
            }
            if (!QubicRpcMethods::isValidIdentityInput(params[1].asString())) {
                return makeError(id, QubicRpcError::INVALID_PARAMS,
                    "Invalid identity format for parameter 2 (issuer). Expected 60-char Qubic identity (A-Z) or 0x-prefixed hex public key");
            }
            return makeResult(id, QubicRpcMethods::getAssetBalance(
                params[0].asString(), params[1].asString(), params[2].asString()));
        }
        if (method == "qubic_getAssets") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing identity parameter");
            }
            if (!QubicRpcMethods::isValidIdentityInput(params[0].asString())) {
                return makeError(id, QubicRpcError::INVALID_PARAMS,
                    "Invalid identity format. Expected 60-char Qubic identity (A-Z) or 0x-prefixed hex public key");
            }
            return makeResult(id, QubicRpcMethods::getAssets(params[0].asString()));
        }

        // ====================================================================
        // Log Methods
        // ====================================================================
        if (method == "qubic_getLogs") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing filter parameter");
            }
            return makeResult(id, QubicRpcMethods::getLogs(params[0]));
        }

        // ====================================================================
        // Subscription Methods (WebSocket only)
        // ====================================================================
        if (method == "qubic_subscribe") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing subscription type");
            }
            std::string subType = params[0].asString();
            Json::Value filterParams = params.size() > 1 ? params[1] : Json::Value();
            std::string subId = QubicRpcMethods::subscribe(conn, subType, filterParams);
            if (subId.empty()) {
                return makeError(id, QubicRpcError::INVALID_PARAMS,
                               "Invalid subscription type: " + subType +
                               ". Valid types: newTicks, logs, transfers, tickStream");
            }
            return makeResult(id, subId);
        }
        if (method == "qubic_unsubscribe") {
            if (!params.isArray() || params.size() < 1) {
                return makeError(id, QubicRpcError::INVALID_PARAMS, "Missing subscription ID");
            }
            bool success = QubicRpcMethods::unsubscribe(conn, params[0].asString());
            return makeResult(id, success);
        }

        // ====================================================================
        // Method Not Found
        // ====================================================================
        return makeError(id, QubicRpcError::METHOD_NOT_FOUND, "Method not found: " + method);

    } catch (const std::exception& e) {
        Logger::get()->error("Error in qubic_rpc method {}: {}", method, e.what());
        return makeError(id, QubicRpcError::INTERNAL_ERROR, e.what());
    }
}

Json::Value QubicRpcWebSocket::makeResult(const Json::Value& id, const Json::Value& result) {
    Json::Value response(Json::objectValue);
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["result"] = result;
    return response;
}

Json::Value QubicRpcWebSocket::makeError(const Json::Value& id, int code, const std::string& message) {
    Json::Value response(Json::objectValue);
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    return response;
}

void QubicRpcWebSocket::sendResponse(const drogon::WebSocketConnectionPtr& conn,
                                      const Json::Value& response) {
    Json::FastWriter writer;
    try {
        conn->send(writer.write(response));
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send Qubic RPC response: {}", e.what());
    }
}
