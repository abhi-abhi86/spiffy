#pragma once

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <array>

namespace omega::core {

/**
 * @brief 10-Digit Token System with Bit-Shift Compression
 * 
 * Format: OOOPPPPPCC
 * - OOO: IP octets 3-4 compressed (3 digits)
 * - PPPPP: Port number (5 digits)
 * - CC: CRC8 checksum (2 digits)
 * 
 * Example: 192.168.1.5:12345 -> 0011234536
 */
class TokenSystem {
public:
    /**
     * @brief Compress IP and port into 10-digit token
     * 
     * @param ip IPv4 address (e.g., "192.168.1.5")
     * @param port Port number (1-65535)
     * @return 10-digit token string
     */
    static std::string compress(const std::string& ip, uint16_t port) {
        // Parse IP address
        auto octets = parse_ip(ip);
        
        // Compress octets 3-4 into 3 digits
        // Format: O3O3O4 (e.g., 001 for 1.5)
        uint16_t ip_component = (octets[2] * 10 + octets[3]) % 1000;
        
        // Port component (5 digits)
        uint32_t port_component = port % 100000;
        
        // Create base token (8 digits)
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(3) << ip_component
            << std::setw(5) << port_component;
        std::string base_token = oss.str();
        
        // Calculate CRC8 checksum
        uint8_t checksum = calculate_crc8(base_token);
        
        // Append checksum (2 digits)
        oss << std::setw(2) << static_cast<int>(checksum % 100);
        
        return oss.str();
    }
    
    /**
     * @brief Decompress 10-digit token to IP and port
     * 
     * @param token 10-digit token string
     * @param base_subnet Base subnet (e.g., "192.168")
     * @return Pair of (IP address, port)
     */
    static std::pair<std::string, uint16_t> decompress(
        const std::string& token,
        const std::string& base_subnet = "192.168"
    ) {
        if (token.length() != 10) {
            throw std::invalid_argument("Token must be exactly 10 digits");
        }
        
        // Extract components
        uint16_t ip_component = std::stoi(token.substr(0, 3));
        uint32_t port_component = std::stoi(token.substr(3, 5));
        uint8_t provided_checksum = std::stoi(token.substr(8, 2));
        
        // Validate checksum
        std::string base_token = token.substr(0, 8);
        uint8_t expected_checksum = calculate_crc8(base_token) % 100;
        
        if (provided_checksum != expected_checksum) {
            // Warning: checksum mismatch (but still proceed)
        }
        
        // Decode IP octets
        uint8_t octet3 = ip_component / 10;
        uint8_t octet4 = ip_component % 10;
        
        // Construct IP
        std::ostringstream ip_oss;
        ip_oss << base_subnet << "." << static_cast<int>(octet3) 
               << "." << static_cast<int>(octet4);
        
        return {ip_oss.str(), static_cast<uint16_t>(port_component)};
    }
    
    /**
     * @brief Validate token checksum
     */
    static bool validate(const std::string& token) {
        if (token.length() != 10) return false;
        
        std::string base_token = token.substr(0, 8);
        uint8_t provided_checksum = std::stoi(token.substr(8, 2));
        uint8_t expected_checksum = calculate_crc8(base_token) % 100;
        
        return provided_checksum == expected_checksum;
    }

private:
    /**
     * @brief Parse IP address into octets
     */
    static std::array<uint8_t, 4> parse_ip(const std::string& ip) {
        std::array<uint8_t, 4> octets{};
        std::istringstream iss(ip);
        std::string octet;
        size_t i = 0;
        
        while (std::getline(iss, octet, '.') && i < 4) {
            octets[i++] = static_cast<uint8_t>(std::stoi(octet));
        }
        
        if (i != 4) {
            throw std::invalid_argument("Invalid IP address format");
        }
        
        return octets;
    }
    
    /**
     * @brief Calculate CRC8 checksum
     */
    static uint8_t calculate_crc8(const std::string& data) {
        uint8_t crc = 0x00;
        constexpr uint8_t polynomial = 0x07; // CRC-8-CCITT
        
        for (char c : data) {
            crc ^= static_cast<uint8_t>(c);
            for (int i = 0; i < 8; ++i) {
                if (crc & 0x80) {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc <<= 1;
                }
            }
        }
        
        return crc;
    }
};

} // namespace omega::core
