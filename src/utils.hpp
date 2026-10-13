#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <netinet/in.h>

namespace Utils {
    const std::string PROGRAM_VERSION = "1.0";

    uint32_t IPToUint32(const std::string& ip);                                 // Converts a string to a uint32_t for efficient comparison
    bool IsIPInCIDR(uint32_t ip, uint32_t network, int prefix);                 // Checks if an IP is within a specific CIDR range
    std::vector<std::string> ReadLinesFromFile(const std::string& filePath);    // Read lines from a file into a vector of strings
    void PrintHelp(const char* programName);                                    // Prints the help menu
    void PrintVersion();                                                        // Prints the program's version
}

#endif // UTILS_HPP
