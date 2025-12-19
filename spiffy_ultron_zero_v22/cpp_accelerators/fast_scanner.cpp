/**
 * Omega Kernel - C++ Network Scanner Accelerator
 * High-performance port scanning for WIFI_RADAR module
 * Callable from Python via ctypes/pybind11
 */

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

extern "C" {

struct ScanResult {
    char ip[16];
    int port;
    bool is_open;
    int response_time_ms;
};

class FastScanner {
private:
    std::mutex results_mutex;
    std::vector<ScanResult> results;
    
public:
    /**
     * Fast TCP port scan with timeout
     * Returns: 1 if open, 0 if closed, -1 if error
     */
    int scan_port(const char* ip, int port, int timeout_ms) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return -1;
        
        // Set non-blocking
        fcntl(sock, F_SETFL, O_NONBLOCK);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Attempt connection
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        // Wait for connection with timeout
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        int result = select(sock + 1, nullptr, &fdset, nullptr, &tv);
        
        auto end = std::chrono::high_resolution_clock::now();
        int elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        close(sock);
        
        if (result > 0) {
            // Port is open
            return elapsed;
        }
        
        return 0; // Port closed or timeout
    }
    
    /**
     * Scan multiple ports on a single host (parallel)
     */
    void scan_host(const char* ip, const int* ports, int port_count, int timeout_ms) {
        std::vector<std::thread> threads;
        
        for (int i = 0; i < port_count; i++) {
            threads.emplace_back([this, ip, ports, i, timeout_ms]() {
                int response_time = scan_port(ip, ports[i], timeout_ms);
                
                if (response_time > 0) {
                    ScanResult result;
                    strncpy(result.ip, ip, 15);
                    result.ip[15] = '\0';
                    result.port = ports[i];
                    result.is_open = true;
                    result.response_time_ms = response_time;
                    
                    std::lock_guard<std::mutex> lock(results_mutex);
                    results.push_back(result);
                }
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
    }
    
    /**
     * Get scan results
     */
    int get_results(ScanResult* output, int max_results) {
        std::lock_guard<std::mutex> lock(results_mutex);
        int count = std::min((int)results.size(), max_results);
        
        for (int i = 0; i < count; i++) {
            output[i] = results[i];
        }
        
        return count;
    }
    
    void clear_results() {
        std::lock_guard<std::mutex> lock(results_mutex);
        results.clear();
    }
};

// Global scanner instance
static FastScanner* g_scanner = nullptr;

/**
 * C API for Python ctypes
 */
void* create_scanner() {
    return new FastScanner();
}

void destroy_scanner(void* scanner) {
    delete static_cast<FastScanner*>(scanner);
}

int scan_port_fast(void* scanner, const char* ip, int port, int timeout_ms) {
    return static_cast<FastScanner*>(scanner)->scan_port(ip, port, timeout_ms);
}

void scan_host_fast(void* scanner, const char* ip, const int* ports, int port_count, int timeout_ms) {
    static_cast<FastScanner*>(scanner)->scan_host(ip, ports, port_count, timeout_ms);
}

int get_scan_results(void* scanner, ScanResult* output, int max_results) {
    return static_cast<FastScanner*>(scanner)->get_results(output, max_results);
}

void clear_scan_results(void* scanner) {
    static_cast<FastScanner*>(scanner)->clear_results();
}

} // extern "C"
