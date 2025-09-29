// traffic_manager.cpp
#include "traffic_manager.h"
#include "crypto.h" // for secure_random_bytes
#include <random>
#include <thread>
#include <cstring>

namespace anon {

namespace {
    // helper to seed a std RNG from secure random bytes
    std::uint64_t seed_from_secure_rng() {
        auto b = anon_crypto::secure_random_bytes(sizeof(std::uint64_t));
        std::uint64_t s = 0;
        for (size_t i = 0; i < sizeof(s) && i < b.size(); ++i) {
            s = (s << 8) | b[i];
        }
        return s;
    }
}

AnonymousTrafficManager::AnonymousTrafficManager()
: rng_(seed_from_secure_rng()) {
    // no heavy initialization here; crypto subsystem assumed initialized elsewhere
}

AnonymousTrafficManager::~AnonymousTrafficManager() {
    // best-effort stop
    stop_traffic_obfuscation(5.0);
}

void AnonymousTrafficManager::start_traffic_obfuscation() {
    bool expected = false;
    if (!is_active_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        // already active
        return;
    }

    std::lock_guard<std::mutex> lock(thread_mutex_);
    obfuscation_thread_ = std::thread(&AnonymousTrafficManager::obfuscation_loop, this);
}

bool AnonymousTrafficManager::stop_traffic_obfuscation(double timeout_seconds) {
    bool expected = true;
    if (!is_active_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        // was not active; nothing to do
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(thread_mutex_);
        if (!obfuscation_thread_.joinable()) return true;
        // we will wait for the thread to exit; obfuscation_loop checks is_active_ periodically
    }

    // politely wait for join up to timeout_seconds
    using clock = std::chrono::steady_clock;
    auto start = clock::now();
    while (clock::now() - start < std::chrono::duration<double>(timeout_seconds)) {
        {
            std::lock_guard<std::mutex> lock(thread_mutex_);
            if (obfuscation_thread_.joinable()) {
                // Try to join, but join can block — so use short sleeps until it exits.
                // join() will return immediately if thread already ended.
                // We'll attempt a non-blocking strategy: sleep small intervals and check joinable state.
            } else {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // If still joinable after timeout, detach to avoid blocking destructor (we already set is_active_ = false).
    {
        std::lock_guard<std::mutex> lock(thread_mutex_);
        if (obfuscation_thread_.joinable()) {
            try {
                obfuscation_thread_.detach();
            } catch(...) {
                // swallow exceptions; we cannot do much more
            }
        }
    }
    return false;
}

void AnonymousTrafficManager::obfuscation_loop() {
    // local distributions
    std::uniform_real_distribution<double> sleep_dist(min_sleep_seconds_, max_sleep_seconds_);
    std::uniform_int_distribution<uint32_t> size_dist(min_dummy_size_, max_dummy_size_);

    while (is_active_.load(std::memory_order_acquire)) {
        try {
            double s = sleep_dist(rng_);
            // sleep in smaller increments so stop can be more responsive
            auto sleep_ms_total = std::chrono::duration<double>(s);
            auto slept = std::chrono::duration<double>(0.0);
            const auto chunk = std::chrono::milliseconds(50);
            while (slept < sleep_ms_total && is_active_.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(chunk);
                slept += std::chrono::duration<double>(chunk);
            }
            if (!is_active_.load(std::memory_order_acquire)) break;

            uint32_t size = size_dist(rng_);
            // use cryptographically-secure bytes for the dummy payload
            bytes dummy = anon_crypto::secure_random_bytes(size);

            // Push into queue for transport layer to handle (no metadata attached)
            traffic_queue_.push(std::move(dummy));
        } catch (...) {
            // In production, we intentionally avoid logging sensitive internals.
            // If an error occurs, stop the loop to avoid noisy spinning.
            is_active_.store(false, std::memory_order_release);
            break;
        }
    }
    // thread exits naturally
}

} // namespace anon
