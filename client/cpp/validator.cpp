// validator.cpp
#include "validator.h"
#include <iostream>

namespace anon {

bool ConnectionValidator::validate_connection_integrity(const std::string& connection_id,
                                                        const std::string& public_key) {
    if (connection_id.empty() || public_key.empty()) {
        std::cerr << "[-] Validation error: Invalid inputs." << std::endl;
        return false;
    }

    try {
        std::lock_guard<std::mutex> lock(validation_mutex_);

        auto it = connection_metrics_.find(connection_id);
        if (it != connection_metrics_.end()) {
            const auto& stored_key = it->second.public_key;
            if (!stored_key.empty() && stored_key != public_key) {
                std::cerr << "[!] Security Alert: Key change detected for connection "
                          << connection_id << std::endl;
                return false;
            }
        }

        auto now = anon::epoch_seconds_now_double();
        uint64_t count = 1;
        if (it != connection_metrics_.end()) {
            count = it->second.validation_count + 1;
        }

        connection_metrics_[connection_id] = ConnectionMetrics{
            public_key,
            now,
            count
        };

        return true;
    } catch (const std::exception& e) {
        std::cerr << "[-] Validation error: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "[-] Validation error: Unknown exception" << std::endl;
        return false;
    }
}

std::optional<ConnectionMetrics> ConnectionValidator::get_metrics(
    const std::string& connection_id) const {
    std::lock_guard<std::mutex> lock(validation_mutex_);
    auto it = connection_metrics_.find(connection_id);
    if (it == connection_metrics_.end()) return std::nullopt;
    return it->second;
}

} // namespace anon
