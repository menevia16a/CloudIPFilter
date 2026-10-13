#include <iostream>
#include <curl/curl.h>

#include "filter.hpp"
#include "utils.hpp"

IPFilter::IPFilter() { LoadKnownCloudRanges(); }

void IPFilter::LoadKnownCloudRanges() {
    // Expanded static ranges for better baseline coverage
    cloudRanges.push_back({Utils::IPToUint32("173.245.48.0"), 20}); // Cloudflare
    cloudRanges.push_back({Utils::IPToUint32("103.21.244.0"), 22}); // Cloudflare
    cloudRanges.push_back({Utils::IPToUint32("104.16.0.0"), 12});   // Cloudflare
    cloudRanges.push_back({Utils::IPToUint32("13.32.0.0"), 12});    // AWS
}

bool IPFilter::IsCloudIPCIDR(const std::string& ipString) {
    uint32_t ip = Utils::IPToUint32(ipString);

    if (ip == 0) return false;

    for (const auto& range : cloudRanges) {
        if (Utils::IsIPInCIDR(ip, range.network, range.prefix)) return true;
    }

    return false;
}

bool IPFilter::ProbeHeaders(const std::string& ipString) {
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
