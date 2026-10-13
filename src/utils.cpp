#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <cmath>

#include "utils.hpp"

namespace Utils {
    uint32_t IPToUint32(const std::string& ip) {
        struct in_addr address;

        if (inet_pton(AF_INET, ip.c_str(), &address) != 1) return 0;

        return ntohl(address.s_addr);
    }

    bool IsIPInCIDR(uint32_t ip, uint32_t network, int prefix) {
        if (prefix == 0) return true;

        uint32_t mask = (0xFFFFFFFF << (32 - prefix));

        return (ip & mask) == (network & mask);
    }

    std::vector<std::string> ReadLinesFromFile(const std::string& filePath) {
        std::vector<std::string> lines;
        std::ifstream file(filePath);

        if (!file.is_open()) throw std::runtime_error("Could not open file: " + filePath);

        std::string line;

        while(std::getline(file, line)) {
            if (!line.empty()) lines.push_back(line);
        }

        return lines;
    }

    void PrintHelp(const char* programName) {
        std::cout << "CloudIPFilter - Advanced Cloud Infrastructure IP Filter\n"
                  << "Usage: " << programName << " -i <input_file> [-o <output_file>]\n\n"
                  << "Options:\n"
                  << "  -i/--input <input_file>         Path to a text file containing a list of IPs (one per line).\n"
                  << "  -o/--output <output_file>       Path to save the filtered results. If omitted, output is sent to stdout.\n"
                  << "  -h/--help                       Show this professional help menu.\n\n"
                  << "Description:\n"
                  << "  This tool identifies and removes IP addresses belonging to known cloud service \n"
                  << "  providers (Cloudflare, CloudFront, AWS, etc.) using CIDR matching and pattern analysis.\n";
    }

    void PrintVersion() { std::cout << "CloudIPFilter " << PROGRAM_VERSION << std::endl; }
} // namespace Utils
