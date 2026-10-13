#include <iostream>
#include <fstream>
#include <algorithm>

#include "utils.hpp"
#include "filter.hpp"

void printUsageError(const std::string& message) { std::cerr << "Error: " << message << "\nUse --help for usage information." << std::endl; }

int main(int argc, char* argv[]) {
    if (argc < 2) {
        Utils::PrintHelp(argv[0]);

        return 1;
    }

    std::string inputFile = "";
    std::string outputFile = "";
    bool helpRequested = false;
    bool versionRequested = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") helpRequested = true;
        else if (arg == "-v" || arg == "--version") versionRequested = true;
        else if (arg == "-i" || arg == "--input") {
            if (i + 1 < argc) inputFile = argv[++i];
            else {
                printUsageError("Missing argument for the input flag.");

                return 1;
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) outputFile = argv[++i];
            else {
                printUsageError("Missing argument for the output flag.");

                return 1;
            }
        } else {
            // Unexpected argument
            printUsageError("Unknown argument: " + arg);

            return 1;
        }
    }

    if (helpRequested) {
        Utils::PrintHelp(argv[0]);

        return 0;
    } else if (versionRequested) {
        Utils::PrintVersion();

        return 0;
    }

    if (inputFile.empty()) {
        printUsageError("Input file must be specified using the -i flag.");

        return 1;
    }

    try {
        std::vector<std::string> ips = Utils::ReadLinesFromFile(inputFile);
        std::vector<std::string> filteredIPs;
        IPFilter filter;

        for (const auto& ip : ips) {
            // First check the passive layer (fast)
            if (!filter.IsCloudIPCIDR(ip)) {
                // If the passive layer passes, then perform active probing (slower but accurate)
                if (!filter.ProbeHeaders(ip)) filteredIPs.push_back(ip);
            }
        }

        if (!outputFile.empty()) {
            std::ofstream output(outputFile);

            if (!output.is_open()) throw std::runtime_error("Could not open the output file.");

            for (const auto& ip : filteredIPs) output << ip << "\n";

            std::cout << "Successfully filtered " << ips.size() << " IPs. "
                      << filteredIPs.size() << " remaining. Results saved to: " << outputFile << std::endl;
        } else { for (const auto& ip : filteredIPs) std::cout << ip << "\n"; }
    } catch (const std::exception& error) {
        printUsageError(error.what());

        return 1;
    }

    return 0;
}
