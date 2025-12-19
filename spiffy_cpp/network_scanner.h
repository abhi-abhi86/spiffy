#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace spiffy {

/**
 * High-performance network scanner using multi-threading and non-blocking I/O
 */
class NetworkScanner {
public:
    NetworkScanner(int max_threads = 100);
    ~NetworkScanner();

    /**
     * Scan a single port on a host
     * @param ip IP address to scan
     * @param port Port number to scan
     * @param timeout_ms Timeout in milliseconds
     * @return Port number if open, nullopt if closed
     */
    std::optional<int> scan_port(const std::string& ip, int port, int timeout_ms = 1500);

    /**
     * Scan multiple ports on a host
     * @param ip IP address to scan
     * @param ports Vector of port numbers to scan
     * @param timeout_ms Timeout in milliseconds
     * @return Vector of open port numbers
     */
    std::vector<int> scan_ports(const std::string& ip, const std::vector<int>& ports, int timeout_ms = 1500);

    /**
     * Perform ICMP ping to check if host is alive
     * @param ip IP address to ping
     * @param timeout_ms Timeout in milliseconds
     * @return true if host responds, false otherwise
     */
    bool ping_host(const std::string& ip, int timeout_ms = 1000);

    /**
     * Ping sweep across a subnet
     * @param subnet Subnet prefix (e.g., "192.168.1")
     * @param start_host Starting host number (default 1)
     * @param end_host Ending host number (default 254)
     * @return Vector of alive IP addresses
     */
    std::vector<std::string> ping_sweep(const std::string& subnet, int start_host = 1, int end_host = 254);

    /**
     * Grab service banner from a port
     * @param ip IP address
     * @param port Port number
     * @param timeout_ms Timeout in milliseconds
     * @return Banner string or empty if failed
     */
    std::string grab_banner(const std::string& ip, int port, int timeout_ms = 1500);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace spiffy
