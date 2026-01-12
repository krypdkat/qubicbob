#include "QubicRpcHandler.h"
#include "QubicRpcMethods.h"
#include "QubicRpcMapper.h"
#include "Logger.h"

namespace QubicRpcHandler {

Json::Value makeResult(const Json::Value& id, const Json::Value& result) {
    Json::Value response(Json::objectValue);
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["result"] = result;
    return response;
}

Json::Value makeError(const Json::Value& id, int code, const std::string& message) {
    Json::Value response(Json::objectValue);
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["error"]["code"] = code;
    response["error"]["message"] = message;
    return response;
}

Json::Value processRequest(const Json::Value& request) {
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
        dispatchMethod(id, method, params);
        return Json::Value::null;
    }

    return dispatchMethod(id, method, params);
}

Json::Value processBatch(const Json::Value& requests) {
    if (!requests.isArray() || requests.empty()) {
        return makeError(Json::Value::null, QubicRpcError::INVALID_REQUEST, "Empty batch");
    }

    Json::Value responses(Json::arrayValue);
    for (const auto& req : requests) {
        Json::Value response = processRequest(req);
        if (!response.isNull()) {
            responses.append(response);
        }
    }

    return responses.empty() ? Json::Value::null : responses;
}

Json::Value dispatchMethod(const Json::Value& id,
                           const std::string& method,
                           const Json::Value& params) {
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
        // Subscription Methods - Not supported over HTTP
        // ====================================================================
        if (method == "qubic_subscribe") {
            return makeError(id, QubicRpcError::METHOD_NOT_FOUND,
                           "qubic_subscribe is only available over WebSocket. Use /ws/qubic endpoint.");
        }
        if (method == "qubic_unsubscribe") {
            return makeError(id, QubicRpcError::METHOD_NOT_FOUND,
                           "qubic_unsubscribe is only available over WebSocket. Use /ws/qubic endpoint.");
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

}  // namespace QubicRpcHandler
