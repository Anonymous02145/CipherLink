// validator.h
#pragma once
#include "include.h"

#include <unordered_map>
#include <mutex>

namespace anon {

struct ConnectionMetrics {
    std::string public_key;
    double last_validated;      // epoch seconds
    uint64_t validation_count;  // number of successful validations
};

class ConnectionValidator {
public:
    ConnectionValidator() = default;
    ~ConnectionValidator() = default;

    ConnectionValidator(const ConnectionValidator&) = delete;
    ConnectionValidator& operator=(const ConnectionValidator&) = delete;

    // Validate integrity of a connection. Returns true if valid, false otherwise.
    bool validate_connection_integrity(const std::string& connection_id,
                                       const std::string& public_key);

    // Optional: snapshot of metrics (thread-safe copy).
    std::optional<ConnectionMetrics> get_metrics(const std::string& connection_id) const;

private:
    mutable std::mutex validation_mutex_;
    std::unordered_map<std::string, ConnectionMetrics> connection_metrics_;
};

} // namespace anon
