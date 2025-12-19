#include "data_processor.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace spiffy {

class DataProcessor::Impl {
public:
    std::string resolve_mac_vendor(const std::string& mac,
                                   const std::map<std::string, std::string>& oui_db) {
        std::string normalized = normalize_mac(mac);
        if (normalized.empty()) return "Unknown";

        // Extract OUI (first 3 octets)
        std::string oui = normalized.substr(0, 8); // XX:XX:XX

        auto it = oui_db.find(oui);
        if (it != oui_db.end()) {
            return it->second;
        }

        return "Unknown Hardware";
    }

    std::string normalize_mac(const std::string& mac) {
        std::string result;
        std::string clean;

        // Remove all non-hex characters
        for (char c : mac) {
            if (std::isxdigit(c)) {
                clean += std::toupper(c);
            }
        }

        if (clean.length() != 12) {
            return ""; // Invalid MAC
        }

        // Format as XX:XX:XX:XX:XX:XX
        for (size_t i = 0; i < clean.length(); i += 2) {
            if (i > 0) result += ':';
            result += clean.substr(i, 2);
        }

        return result;
    }

    std::vector<std::string> generate_ip_range(const std::string& subnet, int start, int end) {
        std::vector<std::string> ips;
        ips.reserve(end - start + 1);

        for (int i = start; i <= end; ++i) {
            ips.push_back(subnet + "." + std::to_string(i));
        }

        return ips;
    }

    std::string extract_subnet(const std::string& ip) {
        size_t last_dot = ip.rfind('.');
        if (last_dot == std::string::npos) {
            return "";
        }
        return ip.substr(0, last_dot);
    }

    std::vector<size_t> fast_search(const std::string& text, const std::string& pattern) {
        std::vector<size_t> positions;
        
        if (pattern.empty() || text.empty() || pattern.length() > text.length()) {
            return positions;
        }

        // Boyer-Moore bad character heuristic
        const size_t pattern_len = pattern.length();
        const size_t text_len = text.length();
        
        // Build bad character table
        std::vector<int> bad_char(256, -1);
        for (size_t i = 0; i < pattern_len; ++i) {
            bad_char[static_cast<unsigned char>(pattern[i])] = i;
        }

        // Search
        size_t shift = 0;
        while (shift <= (text_len - pattern_len)) {
            int j = pattern_len - 1;

            while (j >= 0 && pattern[j] == text[shift + j]) {
                j--;
            }

            if (j < 0) {
                positions.push_back(shift);
                shift += (shift + pattern_len < text_len) ? 
                         pattern_len - bad_char[static_cast<unsigned char>(text[shift + pattern_len])] : 1;
            } else {
                shift += std::max(1, j - bad_char[static_cast<unsigned char>(text[shift + j])]);
            }
        }

        return positions;
    }
};

// Public interface
DataProcessor::DataProcessor() : pImpl(std::make_unique<Impl>()) {}
DataProcessor::~DataProcessor() = default;

std::string DataProcessor::resolve_mac_vendor(const std::string& mac,
                                              const std::map<std::string, std::string>& oui_db) {
    return pImpl->resolve_mac_vendor(mac, oui_db);
}

std::string DataProcessor::normalize_mac(const std::string& mac) {
    return pImpl->normalize_mac(mac);
}

std::vector<std::string> DataProcessor::generate_ip_range(const std::string& subnet, int start, int end) {
    return pImpl->generate_ip_range(subnet, start, end);
}

std::string DataProcessor::extract_subnet(const std::string& ip) {
    return pImpl->extract_subnet(ip);
}

std::vector<size_t> DataProcessor::fast_search(const std::string& text, const std::string& pattern) {
    return pImpl->fast_search(text, pattern);
}

} // namespace spiffy
