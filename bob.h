#pragma once
#include <cstdint>
#include <string>
//#ifdef __cplusplus
//extern "C" {
//#endif
int runBob(int argc, char *argv[]);
void requestToExitBob();

// other APIs:
// - human readable
// - easy for SC dev
std::string bobGetBalance(const char* identity);
std::string bobGetAsset(const char* identity);
std::string bobGetTransaction(const char* txHash);
std::string bobGetLog(int64_t start, int64_t end); // inclusive
std::string bobGetTick(const uint32_t tick); // return Data And Votes and LogRanges
std::string bobFindLog(uint32_t scIndex, uint32_t logType, const char* topic1, const char* topic2, const char* topic3);


// no one request for C ABI atm, add later if needed
//#ifdef __cplusplus
//}
//#endif