#include "Config.h"
#include <rapidjson/reader.h>
#include <rapidjson/error/en.h>
#include <fstream>
#include <sstream>
#include <string>

namespace {

// A SAX handler that populates AppConfig directly.
struct ConfigSaxHandler : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, ConfigSaxHandler> {
    // References to output and error.
    AppConfig& out;
    std::string& error;

    // State
    std::string currentKey;
    bool inRootObject = false;
    bool inTrustedNode = false;
    bool seenTrustedNode = false;

    explicit ConfigSaxHandler(AppConfig& o, std::string& e) : out(o), error(e) {}

    // Object begin/end
    bool StartObject() {
        if (!inRootObject) {
            inRootObject = true;
        }
        return true;
    }
    bool EndObject(rapidjson::SizeType) {
        return true;
    }

    // Array begin/end
    bool StartArray() {
        if (currentKey == "trusted-node") {
            inTrustedNode = true;
            seenTrustedNode = true;
            out.trusted_nodes.clear();
        }
        return true;
    }
    bool EndArray(rapidjson::SizeType) {
        if (inTrustedNode) inTrustedNode = false;
        return true;
    }

    // Keys
    bool Key(const char* str, rapidjson::SizeType len, bool) {
        currentKey.assign(str, len);
        return true;
    }

    // Values
    bool String(const char* str, rapidjson::SizeType len, bool) {
        if (inTrustedNode) {
            out.trusted_nodes.emplace_back(std::string(str, len));
            return true;
        }
        if (currentKey == "log-level") {
            out.log_level.assign(str, len);
            return true;
        }
        if (currentKey == "redis-url") {
            out.redis_url.assign(str, len);
            return true;
        }
        if (currentKey == "arbitrator-identity") {
            out.arbitrator_identity.assign(str, len);
            return true;
        }
        // Unexpected string type for other keys -> error
        error = "Invalid type: string not allowed for key '" + currentKey + "'";
        return false;
    }

    bool Bool(bool b) {
        if (currentKey == "run-server") {
            out.run_server = b;
            return true;
        }
        if (currentKey == "verify-log-event") {
            out.verify_log_event = b;
            return true;
        }
        error = "Invalid type: boolean not allowed for key '" + currentKey + "'";
        return false;
    }

    bool Uint(unsigned u) {
        if (currentKey == "request-cycle-ms") {
            out.request_cycle_ms = u;
            return true;
        }
        if (currentKey == "future-offset") {
            out.future_offset = u;
            return true;
        }
        if (currentKey == "server-port") {
            out.server_port = u;
            return true;
        }
        error = "Invalid type: unsigned integer not allowed for key '" + currentKey + "'";
        return false;
    }

    // Accept also Int for robustness, but validate it's non-negative for fields expecting uint
    bool Int(int i) {
        if (i < 0) {
            error = "Negative integer is invalid for key '" + currentKey + "'";
            return false;
        }
        return Uint(static_cast<unsigned>(i));
    }

    // Other numeric types we don't expect
    bool Uint64(uint64_t) { return typeError("uint64"); }
    bool Int64(int64_t v) { return v >= 0 ? Uint(static_cast<unsigned>(v)) : typeError("int64"); }
    bool Double(double) { return typeError("double"); }
    bool Null() { return typeError("null"); }

    bool typeError(const char* t) {
        error = std::string("Invalid type: ") + t + " not allowed for key '" + currentKey + "'";
        return false;
    }
};

bool validateAfterParse(const ConfigSaxHandler& h, std::string& error) {
    if (!h.seenTrustedNode) {
        error = "'trusted-node' array is required";
        return false;
    }
    // All other fields are optional and already defaulted by caller.
    return true;
}

} // namespace

bool LoadConfig(const std::string& path, AppConfig& out, std::string& error) {
    std::ifstream ifs(path);
    if (!ifs) {
        error = "cannot open file";
        return false;
    }

    std::stringstream buffer;
    buffer << ifs.rdbuf();
    const std::string json = buffer.str();

    // Prepare SAX reader and handler
    rapidjson::Reader reader;
    rapidjson::StringStream ss(json.c_str());

    ConfigSaxHandler handler(out, error);

    // Parse
    if (!reader.Parse(ss, handler)) {
        const auto& parseErr = reader.GetParseErrorCode();
        size_t offset = reader.GetErrorOffset();
        error = std::string("invalid JSON: ") + rapidjson::GetParseError_En(parseErr) +
                " at offset " + std::to_string(offset);
        return false;
    }

    // Post-parse validation
    if (!validateAfterParse(handler, error)) {
        return false;
    }

    return true;
}