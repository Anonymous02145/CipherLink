#pragma once
#include "include.h"
#include "encryption_engine.h"
#include "traffic_manager.h"

#include <unordered_set>
#include <mutex>

namespace anon {

class SecureMessageProtocol {
public:
    SecureMessageProtocol();
    ~SecureMessageProtocol() = default;

    SecureMessageProtocol(const SecureMessageProtocol&) = delete;
    SecureMessageProtocol& operator=(const SecureMessageProtocol&) = delete;

    // Encrypts a plaintext message with 32-byte key and optional associated data
    std::optional<bytes> encrypt_message(
        const std::string& plaintext,
        const bytes& key,
        const bytes& associated_data = {}
    );

    // Decrypts an encrypted message; returns content if valid and not a replay
    std::optional<std::string> decrypt_message(
        const bytes& encrypted_data,
        const bytes& key,
        const bytes& associated_data = {}
    );

private:
    E2EEncryptionEngine encryption_engine_;
    AnonymousTrafficManager traffic_manager_;

    // Static shared processed IDs to prevent replay attacks
    static std::unordered_set<std::string> processed_msg_ids_;
    static std::mutex processed_ids_mutex_;
    static constexpr size_t max_processed_ids = 1000;
    static constexpr size_t recent_keep_count = 500;

    // Generates a deterministic 16-byte message ID from plaintext + entropy + timestamp
    std::string generate_message_id(const std::string& plaintext);
};

} // namespace anon
