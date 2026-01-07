#include <drogon/HttpClient.h>
#include <vector>
#include <string>
#include <json/json.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdint>

std::vector<std::string> GetPeerFromDNS()
{
    std::vector<std::string> results;
    auto client = drogon::HttpClient::newHttpClient("https://api.qubic.global");
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/random-peers?service=bobNode&litePeers=2&bobPeers=4");

    auto [result, response] = client->sendRequest(req);

    if (result == drogon::ReqResult::Ok && response)
    {
        auto jsonPtr = response->getJsonObject();
        if (jsonPtr && jsonPtr->isMember("bobPeers"))
        {
            const auto& peers = (*jsonPtr)["bobPeers"];
            if (peers.isArray())
            {
                for (const auto& peer : peers)
                {
                    if (peer.isString())
                    {
                        std::string ip = peer.asString();
                        std::string peerString = "bob:" + ip + ":21842:0-0-0-0";
                        results.push_back(peerString);
                    }
                }
            }
        }
        if (jsonPtr && jsonPtr->isMember("litePeers"))
        {
            const auto& peers = (*jsonPtr)["litePeers"];
            if (peers.isArray())
            {
                for (const auto& peer : peers)
                {
                    if (peer.isString())
                    {
                        std::string ip = peer.asString();
                        std::string peerString = "BM:" + ip + ":21841:0-0-0-0";
                        results.push_back(peerString);
                    }
                }
            }
        }
    }

    return results;
}

bool DownloadStateFiles(uint16_t epoch)
{
    std::string url = "https://dl.qubic.global/ep" + std::to_string(epoch) + ".zip";
    std::string zipFile = "ep" + std::to_string(epoch) + ".zip";

    std::string wgetCmd = "wget -q --no-check-certificate -O " + zipFile + " \"" + url + "\"";
    int wgetResult = std::system(wgetCmd.c_str());

    if (wgetResult != 0)
    {
        return false;
    }

    std::string unzipCmd = "unzip -o -q " + zipFile;
    int unzipResult = std::system(unzipCmd.c_str());

    if (unzipResult != 0)
    {
        return false;
    }

    return true;
}

