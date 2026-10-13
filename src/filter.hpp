#ifndef FILTER_HPP
#define FILTER_HPP

#include <string>
#include <vector>
#include <cstdint>

struct CIDRRange {
    uint32_t network;
    int prefix;
};

class IPFilter {
public:
    IPFilter();

    bool IsCloudIPCIDR(const std::string& ipString);
    bool ProbeHeaders(const std::string& ipString);

private:
    std::vector<CIDRRange> cloudRanges;

    void LoadKnownCloudRanges();
};

#endif // FILTER_HPP
