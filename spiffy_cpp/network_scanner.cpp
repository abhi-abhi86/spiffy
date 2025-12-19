#include "network_scanner.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <thread>
#include <future>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstring>

namespace spiffy {

// Thread pool implementation for concurrent scanning
class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    auto enqueue(F&& f) -> std::future<typename std::result_of<F()>::type> {
        using return_type = typename std::result_of<F()>::type;
        auto task = std::make_shared<std::packaged_task<return_type()>>(std::forward<F>(f));
        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop) throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace([task]() { (*task)(); });
        }
        condition.notify_one();
        return res;
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

// Implementation class
class NetworkScanner::Impl {
public:
    Impl(int max_threads) : thread_pool(max_threads) {}

    std::optional<int> scan_port(const std::string& ip, int port, int timeout_ms) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return std::nullopt;

        // Set non-blocking
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Attempt connection
        connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

        // Use poll to wait for connection with timeout
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLOUT;

        int result = poll(&pfd, 1, timeout_ms);
        close(sockfd);

        if (result > 0 && (pfd.revents & POLLOUT)) {
            return port;
        }
        return std::nullopt;
    }

    std::vector<int> scan_ports(const std::string& ip, const std::vector<int>& ports, int timeout_ms) {
        std::vector<std::future<std::optional<int>>> futures;
        
        for (int port : ports) {
            futures.push_back(thread_pool.enqueue([this, ip, port, timeout_ms]() {
                return scan_port(ip, port, timeout_ms);
            }));
        }

        std::vector<int> open_ports;
        for (auto& future : futures) {
            auto result = future.get();
            if (result.has_value()) {
                open_ports.push_back(result.value());
            }
        }

        return open_ports;
    }

    bool ping_host(const std::string& ip, int timeout_ms) {
        // Simple TCP connect to common ports as ping alternative
        // (ICMP requires root privileges)
        std::vector<int> common_ports = {80, 443, 22};
        for (int port : common_ports) {
            auto result = scan_port(ip, port, timeout_ms / 3);
            if (result.has_value()) return true;
        }
        return false;
    }

    std::vector<std::string> ping_sweep(const std::string& subnet, int start_host, int end_host) {
        std::vector<std::future<std::pair<std::string, bool>>> futures;

        for (int i = start_host; i <= end_host; ++i) {
            std::string ip = subnet + "." + std::to_string(i);
            futures.push_back(thread_pool.enqueue([this, ip]() {
                return std::make_pair(ip, ping_host(ip, 1000));
            }));
        }

        std::vector<std::string> alive_hosts;
        for (auto& future : futures) {
            auto result = future.get();
            if (result.second) {
                alive_hosts.push_back(result.first);
            }
        }

        return alive_hosts;
    }

    std::string grab_banner(const std::string& ip, int port, int timeout_ms) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return "";

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sockfd);
            return "";
        }

        // Send HTTP request for web ports
        if (port == 80 || port == 443) {
            const char* request = "HEAD / HTTP/1.0\r\n\r\n";
            send(sockfd, request, strlen(request), 0);
        }

        char buffer[1024] = {0};
        ssize_t bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        close(sockfd);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::string banner(buffer);
            // Return first line only
            size_t newline = banner.find('\n');
            if (newline != std::string::npos) {
                banner = banner.substr(0, newline);
            }
            if (banner.length() > 60) {
                banner = banner.substr(0, 60);
            }
            return banner;
        }

        return "";
    }

private:
    ThreadPool thread_pool;
};

// Public interface implementation
NetworkScanner::NetworkScanner(int max_threads) 
    : pImpl(std::make_unique<Impl>(max_threads)) {}

NetworkScanner::~NetworkScanner() = default;

std::optional<int> NetworkScanner::scan_port(const std::string& ip, int port, int timeout_ms) {
    return pImpl->scan_port(ip, port, timeout_ms);
}

std::vector<int> NetworkScanner::scan_ports(const std::string& ip, const std::vector<int>& ports, int timeout_ms) {
    return pImpl->scan_ports(ip, ports, timeout_ms);
}

bool NetworkScanner::ping_host(const std::string& ip, int timeout_ms) {
    return pImpl->ping_host(ip, timeout_ms);
}

std::vector<std::string> NetworkScanner::ping_sweep(const std::string& subnet, int start_host, int end_host) {
    return pImpl->ping_sweep(subnet, start_host, end_host);
}

std::string NetworkScanner::grab_banner(const std::string& ip, int port, int timeout_ms) {
    return pImpl->grab_banner(ip, port, timeout_ms);
}

} // namespace spiffy
