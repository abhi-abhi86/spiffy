/**
 * Omega Kernel - C++ Network Scanner Accelerator v2.0
 * Modern C++17 with RAII, smart pointers, and connection pooling
 * Fixes: Memory leaks, segmentation faults, resource management
 */

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace omega {

// RAII Socket wrapper
class Socket {
private:
    int fd_;
    bool valid_;
    
public:
    Socket() : fd_(-1), valid_(false) {
        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        valid_ = (fd_ >= 0);
        
        if (valid_) {
            // Set non-blocking
            int flags = fcntl(fd_, F_GETFL, 0);
            fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
        }
    }
    
    ~Socket() {
        if (valid_ && fd_ >= 0) {
            close(fd_);
        }
    }
    
    // Delete copy constructor and assignment
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    
    // Move constructor and assignment
    Socket(Socket&& other) noexcept : fd_(other.fd_), valid_(other.valid_) {
        other.fd_ = -1;
        other.valid_ = false;
    }
    
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            if (valid_ && fd_ >= 0) {
                close(fd_);
            }
            fd_ = other.fd_;
            valid_ = other.valid_;
            other.fd_ = -1;
            other.valid_ = false;
        }
        return *this;
    }
    
    bool is_valid() const { return valid_; }
    int get_fd() const { return fd_; }
    
    bool connect_to(const std::string& ip, int port, int timeout_ms) {
        if (!valid_) return false;
        
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
            return false;
        }
        
        // Non-blocking connect
        connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        
        // Wait for connection with timeout
        fd_set fdset;
        struct timeval tv{};
        FD_ZERO(&fdset);
        FD_SET(fd_, &fdset);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        int result = select(fd_ + 1, nullptr, &fdset, nullptr, &tv);
        
        if (result > 0) {
            // Check if connection succeeded
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &len);
            return (error == 0);
        }
        
        return false;
    }
};

// Connection Pool with RAII
class ConnectionPool {
private:
    std::queue<std::unique_ptr<Socket>> available_;
    mutable std::mutex mutex_;  // mutable for const methods
    std::condition_variable cv_;
    size_t max_connections_;
    std::atomic<size_t> total_created_{0};
    
public:
    explicit ConnectionPool(size_t max_connections = 100) 
        : max_connections_(max_connections) {}
    
    ~ConnectionPool() {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!available_.empty()) {
            available_.pop();  // unique_ptr auto-deletes
        }
    }
    
    std::unique_ptr<Socket> acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (!available_.empty()) {
            auto socket = std::move(available_.front());
            available_.pop();
            return socket;
        }
        
        // Create new socket if under limit
        if (total_created_ < max_connections_) {
            total_created_++;
            return std::make_unique<Socket>();
        }
        
        // Wait for available socket
        cv_.wait(lock, [this] { return !available_.empty(); });
        auto socket = std::move(available_.front());
        available_.pop();
        return socket;
    }
    
    void release(std::unique_ptr<Socket> socket) {
        if (!socket || !socket->is_valid()) {
            return;  // Don't return invalid sockets
        }
        
        std::lock_guard<std::mutex> lock(mutex_);
        if (available_.size() < max_connections_ / 2) {
            available_.push(std::move(socket));
            cv_.notify_one();
        }
        // else: let socket go out of scope and be destroyed
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return available_.size();
    }
};

// Scan Result with value semantics
struct ScanResult {
    std::string ip;
    int port;
    bool is_open;
    int response_time_ms;
    
    ScanResult(std::string ip_, int port_, bool open_, int time_)
        : ip(std::move(ip_)), port(port_), is_open(open_), response_time_ms(time_) {}
};

// Main Scanner class
class FastScanner {
private:
    std::unique_ptr<ConnectionPool> pool_;
    std::vector<ScanResult> results_;
    mutable std::mutex results_mutex_;  // mutable for const methods
    std::atomic<bool> scanning_{false};
    
public:
    explicit FastScanner(size_t max_connections = 200) 
        : pool_(std::make_unique<ConnectionPool>(max_connections)) {}
    
    ~FastScanner() {
        // Wait for any ongoing scans
        while (scanning_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    // Delete copy
    FastScanner(const FastScanner&) = delete;
    FastScanner& operator=(const FastScanner&) = delete;
    
    int scan_port(const std::string& ip, int port, int timeout_ms = 1000) {
        auto socket = pool_->acquire();
        
        if (!socket || !socket->is_valid()) {
            return -1;
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        bool connected = socket->connect_to(ip, port, timeout_ms);
        auto end = std::chrono::high_resolution_clock::now();
        
        int elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        pool_->release(std::move(socket));
        
        return connected ? elapsed : 0;
    }
    
    std::vector<int> scan_ports(const std::string& ip, 
                                const std::vector<int>& ports,
                                int timeout_ms = 1000) {
        scanning_.store(true);
        std::vector<int> open_ports;
        std::mutex open_ports_mutex;
        
        std::vector<std::thread> threads;
        threads.reserve(ports.size());
        
        for (int port : ports) {
            threads.emplace_back([this, &ip, port, timeout_ms, &open_ports, &open_ports_mutex]() {
                try {
                    int response_time = scan_port(ip, port, timeout_ms);
                    
                    if (response_time > 0) {
                        std::lock_guard<std::mutex> lock(open_ports_mutex);
                        open_ports.push_back(port);
                        
                        // Also store in results
                        std::lock_guard<std::mutex> results_lock(results_mutex_);
                        results_.emplace_back(ip, port, true, response_time);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Scan error on port " << port << ": " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "Unknown scan error on port " << port << std::endl;
                }
            });
        }
        
        // Join all threads
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        scanning_.store(false);
        
        // Sort results
        std::sort(open_ports.begin(), open_ports.end());
        return open_ports;
    }
    
    std::vector<ScanResult> get_results() const {
        std::lock_guard<std::mutex> lock(results_mutex_);
        return results_;
    }
    
    void clear_results() {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results_.clear();
    }
    
    size_t pool_size() const {
        return pool_->size();
    }
};

} // namespace omega

// C API for Python bindings
extern "C" {

using namespace omega;

void* create_scanner(int max_connections) {
    try {
        return new FastScanner(max_connections);
    } catch (...) {
        return nullptr;
    }
}

void destroy_scanner(void* scanner) {
    if (scanner) {
        delete static_cast<FastScanner*>(scanner);
    }
}

int scan_port_fast(void* scanner, const char* ip, int port, int timeout_ms) {
    if (!scanner || !ip) return -1;
    
    try {
        return static_cast<FastScanner*>(scanner)->scan_port(ip, port, timeout_ms);
    } catch (...) {
        return -1;
    }
}

int scan_ports_fast(void* scanner, const char* ip, const int* ports, 
                    int port_count, int timeout_ms, int* output, int max_output) {
    if (!scanner || !ip || !ports || !output) return 0;
    
    try {
        std::vector<int> port_vec(ports, ports + port_count);
        auto open_ports = static_cast<FastScanner*>(scanner)->scan_ports(ip, port_vec, timeout_ms);
        
        int count = std::min(static_cast<int>(open_ports.size()), max_output);
        for (int i = 0; i < count; i++) {
            output[i] = open_ports[i];
        }
        
        return count;
    } catch (...) {
        return 0;
    }
}

void clear_results(void* scanner) {
    if (scanner) {
        try {
            static_cast<FastScanner*>(scanner)->clear_results();
        } catch (...) {}
    }
}

int get_pool_size(void* scanner) {
    if (!scanner) return 0;
    
    try {
        return static_cast<FastScanner*>(scanner)->pool_size();
    } catch (...) {
        return 0;
    }
}

} // extern "C"
