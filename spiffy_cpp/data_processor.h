#pragma once

#include <string>
#include <vector>
#include <map>

namespace spiffy {

/**
 * High-performance data processing utilities
 */
class DataProcessor {
public:
    DataProcessor();
    ~DataProcessor();

    /**
     * Parse MAC address and resolve vendor
     * @param mac MAC address (any format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
     * @param oui_db OUI database (map of prefix to vendor name)
     * @return Vendor name or "Unknown"
     */
    std::string resolve_mac_vendor(const std::string& mac, 
                                   const std::map<std::string, std::string>& oui_db);

    /**
     * Normalize MAC address to standard format
     * @param mac MAC address in any format
     * @return Normalized MAC (XX:XX:XX:XX:XX:XX)
     */
    std::string normalize_mac(const std::string& mac);

    /**
     * Generate IP range from subnet
     * @param subnet Subnet prefix (e.g., "192.168.1")
     * @param start Starting host number
     * @param end Ending host number
     * @return Vector of IP addresses
     */
    std::vector<std::string> generate_ip_range(const std::string& subnet, int start, int end);

    /**
     * Parse subnet from IP address
     * @param ip Full IP address
     * @return Subnet prefix (first 3 octets)
     */
    std::string extract_subnet(const std::string& ip);

    /**
     * Fast string search (Boyer-Moore algorithm)
     * @param text Text to search in
     * @param pattern Pattern to search for
     * @return Vector of positions where pattern is found
     */
    std::vector<size_t> fast_search(const std::string& text, const std::string& pattern);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace spiffy
