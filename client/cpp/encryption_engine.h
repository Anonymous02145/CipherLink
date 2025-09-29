// encryption_engine.h
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <cstdint>
#include <chrono>
#include <nlohmann/json.hpp>

#include "crypto.h" // anon_crypto::bytes

namespace anon {

// alias for binary blobs
using bytes = anon_crypto::bytes;
using json = nlohmann::json;

// Thread-safe queue for pending messages
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() = default;
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    void push(T item);
    // try pop without blocking; returns std::nullopt if empty
    std::optional<T> try_pop();
    // blocking pop
    T wait_and_pop();

private:
    std::queue<T> q_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

// Container returned by decrypt_message_advanced if successful
struct DecryptedMessage {
    std::string data;
    double timestamp;
    std::string msg_id;
    std::string version;
    // optional fields can be added if needed
    json raw_json;
};

class E2EEncryptionEngine {
public:
    E2EEncryptionEngine();
    ~E2EEncryptionEngine();

    // derive a session key from a raw X25519 shared secret and session id.
    // Returns std::nullopt on failure.
    std::optional<bytes> derive_session_key(const bytes& shared_secret, const std::string& session_id);

    // encrypt plaintext -> returns nonce || ciphertext_with_tag (same layout as Python)
    // returns std::nullopt on failure
    std::optional<bytes> encrypt_message_advanced(const std::string& plaintext,
                                                  const bytes& key,
                                                  const std::string& message_id);

    // decrypt; returns parsed DecryptedMessage on success, std::nullopt on failure
    std::optional<DecryptedMessage> decrypt_message_advanced(const bytes& encrypted_data,
                                                             const bytes& key);

    // Access to pending message queue (binary blobs: nonce + ciphertext)
    ThreadSafeQueue<bytes>& pending_queue() { return pending_messages_; }

    // (Optional) For production you may wish to expose/remove session keys via an interface
    // TODO: Add secure erase/rotation API and hook to KMS/HSM as needed.

private:
    // stored session data: key + salt (salt used during HKDF to allow deterministic derive)
    struct SessionData {
        bytes key;
        bytes salt;
        std::chrono::system_clock::time_point created;
    };

    std::mutex sessions_mtx_;
    std::unordered_map<std::string, SessionData> session_keys_;

    // message counter for local use (atomic not required if only used under mutex; keep simple)
    uint64_t message_counter_;

    ThreadSafeQueue<bytes> pending_messages_;

    // helpers
    static std::string base64_of_random(size_t num_bytes);
    static constexpr double MESSAGE_MAX_AGE_SECONDS = 300.0; // 5 minutes, matches Python
};

} // namespace anon
