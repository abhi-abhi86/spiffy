#pragma once

#include <chrono>
#include <functional>
#include <future>
#include <stdexcept>
#include <atomic>

namespace omega::core {

/**
 * @brief Stark Watchdog - Enforces 0.8s timeout on all operations
 * 
 * Prevents network hangs by racing operations against a timer.
 * If operation exceeds 800ms, it's forcefully terminated.
 */
class StarkWatchdog {
public:
    static constexpr auto TIMEOUT = std::chrono::milliseconds(800);
    
    StarkWatchdog() : timeout_count_(0), total_operations_(0) {}
    
    /**
     * @brief Enforce timeout on a callable operation
     * 
     * @tparam Func Callable type
     * @tparam Args Argument types
     * @param func Function to execute
     * @param args Arguments to pass
     * @return Result of the function
     * @throws std::runtime_error if timeout occurs
     */
    template<typename Func, typename... Args>
    auto enforce(Func&& func, Args&&... args) -> decltype(auto) {
        total_operations_++;
        
        // Create async task
        auto future = std::async(
            std::launch::async,
            std::forward<Func>(func),
            std::forward<Args>(args)...
        );
        
        // Wait with timeout
        if (future.wait_for(TIMEOUT) == std::future_status::timeout) {
            timeout_count_++;
            throw std::runtime_error("Watchdog timeout: operation exceeded 800ms");
        }
        
        return future.get();
    }
    
    /**
     * @brief Get watchdog statistics
     */
    struct Stats {
        size_t total_operations;
        size_t timeout_count;
        size_t success_count;
        double success_rate;
    };
    
    Stats get_stats() const {
        size_t total = total_operations_.load();
        size_t timeouts = timeout_count_.load();
        size_t success = total - timeouts;
        double rate = total > 0 ? (success * 100.0 / total) : 100.0;
        
        return {total, timeouts, success, rate};
    }
    
    void reset_stats() {
        total_operations_ = 0;
        timeout_count_ = 0;
    }

private:
    std::atomic<size_t> timeout_count_;
    std::atomic<size_t> total_operations_;
};

} // namespace omega::core
