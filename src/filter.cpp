#include <iostream>
#include <fstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <filesystem>

#include "filter.hpp"
#include "utils.hpp"

IPFilter::IPFilter() { RefreshRanges(); }

std::string IPFilter::FetchURL(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        auto callback = [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            static_cast<std::string*>(userdata)->append(ptr, size * nmemb);

            return size * nmemb;
        };

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        if (curl_easy_perform(curl) != CURLE_OK) return "";

        curl_easy_cleanup(curl);
    }

    return response;
}

void IPFilter::FetchAWSRanges() {
    std::cout << "[*] Fetching latest AWS IP ranges..." << std::endl;

    std::string data = FetchURL("https://ip-ranges.amazonaws.com/ip-ranges.json");

    if (data.empty()) return;

    try {
        auto jsonData = nlohmann::json::parse(data);

        for (const auto& item : jsonData["prefixes"]) {
            std::string cidr = item["ip_prefix"];
            size_t slash = cidr.find('/');

            if (slash != std::string::npos) {
                std::string ip = cidr.substr(0, slash);
                int prefix = std::stoi(cidr.substr(slash + 1));

                cloudRanges.push_back({Utils::IPToUint32(ip), prefix});
            }
        }
    } catch (...) { std::cerr << "[!] Failed to parse AWS JSON" << std::endl; }
}

void IPFilter::FetchCloudflareRanges() {
    std::cout << "[*] Fetching latest Cloudflare ranges..." << std::endl;

    std::string data = FetchURL("https://cloudflare.com/ips-v4");

    if (data.empty()) return;

    std::stringstream dataStream(data);
    std::string line;

    while (std::getline(dataStream, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t slash = line.find('/');

        if (slash != std::string::npos) {
            std::string ip = line.substr(0, slash);
            int prefix = std::stoi(line.substr(slash + 1));

            cloudRanges.push_back({Utils::IPToUint32(ip), prefix});
        }
    }
}

void IPFilter::RefreshRanges() {
    cloudRanges.clear();
    FetchAWSRanges();
    FetchCloudflareRanges();
    std::cout << "[+] Loaded " << cloudRanges.size() << " active cloud ranges." << std::endl;
}

bool IPFilter::IsCloudIPCIDR(const std::string& ipString) {
    uint32_t ip = Utils::IPToUint32(ipString);

    if (ip == 0) return false;

    for (const auto& range : cloudRanges) { if (Utils::IsIPInCIDR(ip, range.network, range.prefix)) return true; }

    return false;
}

bool IPFilter::ProbeHeaders(const std::string& ipString) {
    std::cout << "[*] Probing headers for known coud tags..." << std::endl;

    CURL* curl = curl_easy_init();

    if (!curl) return false;

    std::string url = "http://" + ipString;
    std::string headerData;
    bool isCloud = false;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);         // HEAD request only
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);        // Don't hang the tool
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Callback to capture headers
    auto headerCallback = [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        std::string* data = static_cast<std::string*>(userdata);

        data->append(ptr, size * nmemb);

        return size * nmemb;
    };

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, +headerCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerData);

    if (curl_easy_perform(curl) == CURLE_OK) {
        // Check for common Cloud signatures in headers
        if (headerData.find("server: cloudflare") != std::string::npos ||
            headerData.find("via: 1.1 cloudflare") != std::string::npos ||
            headerData.find("server: Amazon") != std::string::npos ||
            headerData.find("server: Akamai") != std::string::npos ||
            headerData.find("server: Fastly") != std::string::npos ||
            headerData.find("x-cache: hit from cloudfront") != std::string::npos ||
            headerData.find("via: varnish") != std::string::npos) {
            isCloud = true;
        }
    }

    curl_easy_cleanup(curl);

    return isCloud;
}
