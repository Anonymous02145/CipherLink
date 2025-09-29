// encryption_engine.cpp
#include "encryption_engine.h"
#include "crypto.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h> // for OPENSSL_cleanse if needed
#include <stdexcept>

namespace anon {

using namespace std::chrono;

/////////////////////
// ThreadSafeQueue //
/////////////////////
template<typename T>
void ThreadSafeQueue<T>::push(T item) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        q_.push(std::move(item));
    }
    cv_.notify_one();
}

template<typename T>
std::optional<T> ThreadSafeQueue<T>::try_pop() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (q_.empty()) return std::nullopt;
    T item = std::move(q_.front());
    q_.pop();
    return item;
}

template<typename T>
T ThreadSafeQueue<T>::wait_and_pop() {
    std::unique_lock<std::mutex> lk(mtx_);
    cv_.wait(lk, [this]{ return !q_.empty(); });
    T item = std::move(q_.front());
    q_.pop();
    return item;
}

// explicit instantiations used by this translation unit (so linker won't strip templates)
template class ThreadSafeQueue<bytes>;
template class ThreadSafeQueue<std::vector<uint8_t>>;

/////////////////////////////
// E2EEncryptionEngine impl //
/////////////////////////////

E2EEncryptionEngine::E2EEncryptionEngine()
: message_counter_(0)
{
    // Ensure crypto subsystem initialized (idempotent)
    anon_crypto::openssl_initialize();
}

E2EEncryptionEngine::~E2EEncryptionEngine() {
    // secure erase session keys
    std::lock_guard<std::mutex> lk(sessions_mtx_);
    for (auto &p : session_keys_) {
        anon_crypto::secure_zero(p.second.key);
        anon_crypto::secure_zero(p.second.salt);
    }
    session_keys_.clear();
}

// internal helper: base64-encoded random padding
std::string E2EEncryptionEngine::base64_of_random(size_t num_bytes) {
    auto r = anon_crypto::secure_random_bytes(num_bytes);
    return anon_crypto::base64_encode(r);
}

std::optional<bytes> E2EEncryptionEngine::derive_session_key(const bytes& shared_secret,
                                                             const std::string& session_id) {
    try {
        // Production note:
        // The Python implementation generated a random salt during derive but never stored it.
        // That makes reproducing the derived key impossible. In production we store salt with the session key
        // in memory (ephemeral) so later operations that need the same key can retrieve it.
        bytes salt = anon_crypto::secure_random_bytes(16);
        std::string info_label = "p2p_session_" + session_id;
        bytes info(info_label.begin(), info_label.end());

        bytes derived = anon_crypto::hkdf_sha256(shared_secret, std::optional<bytes>(salt), std::optional<bytes>(info), anon_crypto::AES_GCM_KEY_BYTES);

        SessionData sd;
        sd.key = derived;
        sd.salt = salt;
        sd.created = system_clock::now();

        {
            std::lock_guard<std::mutex> lk(sessions_mtx_);
            session_keys_[session_id] = std::move(sd);
        }

        return derived;
    } catch (...) {
        // Do not leak any error details (avoid logging internal errors)
        return std::nullopt;
    }
}

std::optional<bytes> E2EEncryptionEngine::encrypt_message_advanced(const std::string& plaintext,
                                                                   const bytes& key,
                                                                   const std::string& message_id) {
    try {
        // Build the JSON payload similar to Python's structure
        json message_data;
        message_data["data"] = plaintext;
        // timestamp as seconds.fraction since epoch
        auto now = system_clock::now();
        double ts = duration_cast<duration<double>>(now.time_since_epoch()).count();
        message_data["timestamp"] = ts;
        message_data["msg_id"] = message_id;
        message_data["version"] = "1.0";
        message_data["padding"] = base64_of_random(MESSAGE_PADDING_SIZE);

        // serialize compactly
        std::string serialized = message_data.dump(); // nlohmann::json::dump() uses compact separators by default

        // nonce generation
        bytes nonce = anon_crypto::secure_random_bytes(12);

        // encrypt: AES-GCM helper returns ciphertext with tag appended (as implemented earlier)
        bytes plaintext_bytes(serialized.begin(), serialized.end());
        bytes ciphertext = anon_crypto::aes_gcm_encrypt(key, nonce, plaintext_bytes, std::nullopt);

        // result = nonce || ciphertext
        bytes out;
        out.reserve(nonce.size() + ciphertext.size());
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());

        // push to pending queue for later send if desired
        pending_messages_.push(out);

        // increment counter (non-atomic ok under light contention; increment here for bookkeeping)
        ++message_counter_;

        return out;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<E2EEncryptionEngine::DecryptedMessage> E2EEncryptionEngine::decrypt_message_advanced(const bytes& encrypted_data,
                                                                                                 const bytes& key) {
    try {
        if (encrypted_data.size() < (12 + anon_crypto::AES_GCM_TAG_BYTES)) return std::nullopt;

        bytes nonce(encrypted_data.begin(), encrypted_data.begin() + 12);
        bytes ciphertext(encrypted_data.begin() + 12, encrypted_data.end());

        bytes decrypted = anon_crypto::aes_gcm_decrypt(key, nonce, ciphertext, std::nullopt);

        std::string s(decrypted.begin(), decrypted.end());
        json message_data = json::parse(s);

        // Validate required fields exist and types
        if (!message_data.contains("data") || !message_data.contains("timestamp") || !message_data.contains("msg_id"))
            return std::nullopt;

        double ts = message_data["timestamp"].get<double>();
        auto now = system_clock::now();
        double now_ts = duration_cast<duration<double>>(now.time_since_epoch()).count();

        if ((now_ts - ts) > MESSAGE_MAX_AGE_SECONDS) return std::nullopt;

        DecryptedMessage dm;
        dm.data = message_data["data"].get<std::string>();
        dm.timestamp = ts;
        dm.msg_id = message_data["msg_id"].get<std::string>();
        dm.version = message_data.value("version", std::string("1.0"));
        dm.raw_json = std::move(message_data);

        return dm;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace anon
