// include.h
#pragma once
// Central includes & small utilities shared across the anonymous chat backend.
// Header-only, minimal side-effects, C++17.

#include <array>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <memory>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <queue>
#include <sstream>
#include <iomanip>
#include <functional>
#include <algorithm>
#include <iostream>
#include <system_error>

// JSON library (used by other modules)
#include <nlohmann/json.hpp>

// Types used consistently across modules
namespace anon {
    using json = nlohmann::json;
    using bytes = std::vector<uint8_t>;
    using u8 = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;
    using time_point = std::chrono::system_clock::time_point;

    // Networking / deployment constants (mirrors your Python file)
    inline const std::array<std::string, 3> URL_IP = {
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com"
    };

    inline const std::string TEST_IP = "127.0.0.1";
    inline const std::string URL_BASE = "http://127.0.0.1:8000";
    inline const std::string URL_REGISTER = URL_BASE + "/register";
    inline const std::string URL_AUTHENTICATE = URL_BASE + "/authenticate";
    inline const std::string URL_GET_KEY = URL_BASE + "/get_key";
    inline const std::string URL_SET_PORT = URL_BASE + "/set_listening_port";
    inline const std::string URL_REQUEST_CONNECTION = URL_BASE + "/request_connection";
    inline const std::string URL_DISCOVER_ONLINE = URL_BASE + "/discover_online";

    // Sizes and timing (same semantics as Python constants)
    inline constexpr size_t MESSAGE_PADDING_SIZE = 256;
    inline constexpr size_t SESSION_ROTATION_HOURS = 24;
    inline constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;
    inline constexpr size_t HEARTBEAT_INTERVAL_SECONDS = 30;

    // Small helper: hex string generation from bytes (cryptographically-random bytes should come from crypto module)
    inline std::string to_hex(const bytes& b) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto v : b) oss << std::setw(2) << (static_cast<int>(v) & 0xff);
        return oss.str();
    }

    // Small helper: convert string to bytes
    inline bytes from_string(const std::string& s) {
        return bytes(s.begin(), s.end());
    }

    // Small helper: get current epoch seconds as double (used in message timestamping)
    inline double epoch_seconds_now_double() {
        using namespace std::chrono;
        auto now = system_clock::now();
        return duration_cast<duration<double>>(now.time_since_epoch()).count();
    }

    // Thread-safe simple queue (lightweight). If you already included a copy in another module,
    // prefer to keep one implementation — this one is intentionally minimal.
    template<typename T>
    class SimpleQueue {
    public:
        SimpleQueue() = default;
        SimpleQueue(const SimpleQueue&) = delete;
        SimpleQueue& operator=(const SimpleQueue&) = delete;

        void push(T item) {
            {
                std::lock_guard<std::mutex> lk(mutex_);
                q_.push(std::move(item));
            }
            cv_.notify_one();
        }

        // non-blocking pop; returns std::nullopt if empty
        std::optional<T> try_pop() {
            std::lock_guard<std::mutex> lk(mutex_);
            if (q_.empty()) return std::nullopt;
            T val = std::move(q_.front()); q_.pop();
            return val;
        }

        // blocking pop
        T wait_and_pop() {
            std::unique_lock<std::mutex> lk(mutex_);
            cv_.wait(lk, [this]{ return !q_.empty(); });
            T val = std::move(q_.front()); q_.pop();
            return val;
        }

        bool empty() const {
            std::lock_guard<std::mutex> lk(mutex_);
            return q_.empty();
        }

        size_t size() const {
            std::lock_guard<std::mutex> lk(mutex_);
            return q_.size();
        }

    private:
        mutable std::mutex mutex_;
        std::condition_variable cv_;
        std::queue<T> q_;
    };

} // namespace anon
