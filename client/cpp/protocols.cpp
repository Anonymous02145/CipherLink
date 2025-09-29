#include "secure_message_protocol.h"
#include "crypto.h"
#include <openssl/sha.h> // for SHA256
#include <sstream>
#include <iomanip>
#include <cmath>

namespace anon {

// Static members initialization
std::unordered_set<std::string> SecureMessageProtocol::processed_msg_ids_;
std::mutex SecureMessageProtocol::processed_ids_mutex_;

SecureMessageProtocol::SecureMessageProtocol()
: encryption_engine_(), traffic_manager_() {}

std::string SecureMessageProtocol::generate_message_id(const std::string& plaintext) {
    double now = epoch_seconds_now_double();
    bytes entropy = anon_crypto::secure_random_bytes(8);

    // Build SHA256(plaintext || entropy || timestamp)
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, plaintext.data(), plaintext.size());
    SHA256_Update(&ctx, entropy.data(), entropy.size());

    std::ostringstream ts_ss;
    ts_ss << std::fixed << std::setprecision(6) << now;
    std::string ts_str = ts_ss.str();
    SHA256_Update(&ctx, ts_str.data(), ts_str.size());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    // Return first 16 hex chars
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) { // 16 hex chars = 8 bytes
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::optional<bytes> SecureMessageProtocol::encrypt_message(
    const std::string& plaintext,
    const bytes& key,
    const bytes& associated_data
) {
    if (plaintext.empty() || key.size() != 32) {
        std::cerr << "[-] Encryption error: Invalid input (empty message or wrong key length).\n";
        return std::nullopt;
    }

    try {
        std::string message_id = generate_message_id(plaintext);

        // Build envelope
        json message_envelope = {
            {"content", plaintext},
            {"timestamp", epoch_seconds_now_double()},
            {"message_id", message_id},
            {"version", "secure_v1"}
        };

        std::string serialized = message_envelope.dump();

        // AES-GCM encryption
        bytes nonce = anon_crypto::secure_random_bytes(12);
        auto ciphertext = anon_crypto::aes_gcm_encrypt(
            key, nonce, bytes(serialized.begin(), serialized.end()), associated_data
        );

        // Return concatenated nonce + ciphertext
        bytes result;
        result.reserve(nonce.size() + ciphertext.size());
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        return result;

    } catch (const std::exception& e) {
        std::cerr << "[-] Unexpected encryption failure: " << e.what() << "\n";
        return std::nullopt;
    } catch (...) {
        std::cerr << "[-] Unknown encryption failure\n";
        return std::nullopt;
    }
}

std::optional<std::string> SecureMessageProtocol::decrypt_message(
    const bytes& encrypted_data,
    const bytes& key,
    const bytes& associated_data
) {
    if (encrypted_data.size() < 28 || key.size() != 32) {
        std::cerr << "[-] Decryption error: Invalid input (too short or wrong key length).\n";
        return std::nullopt;
    }

    try {
        bytes nonce(encrypted_data.begin(), encrypted_data.begin() + 12);
        bytes ciphertext(encrypted_data.begin() + 12, encrypted_data.end());

        bytes decrypted = anon_crypto::aes_gcm_decrypt(key, nonce, ciphertext, associated_data);

        json message_envelope = json::parse(decrypted);

        if (!message_envelope.contains("content") ||
            !message_envelope.contains("timestamp") ||
            !message_envelope.contains("message_id")) {
            std::cerr << "[-] Decryption error: Missing required fields in envelope.\n";
            return std::nullopt;
        }

        std::string msg_id = message_envelope["message_id"].get<std::string>();

        // Replay attack check
        {
            std::lock_guard<std::mutex> lock(processed_ids_mutex_);
            if (processed_msg_ids_.size() > max_processed_ids) {
                // Keep only recent IDs
                std::unordered_set<std::string> recent;
                size_t count = 0;
                for (const auto& id : processed_msg_ids_) {
                    if (count++ >= recent_keep_count) break;
                    recent.insert(id);
                }
                processed_msg_ids_ = std::move(recent);
            }

            if (processed_msg_ids_.count(msg_id)) {
                std::cerr << "[-] Decryption warning: Possible replay attack (duplicate ID).\n";
                return std::nullopt;
            }
            processed_msg_ids_.insert(msg_id);
        }

        double timestamp = message_envelope["timestamp"].get<double>();
        if (std::abs(epoch_seconds_now_double() - timestamp) > 600.0) {
            std::cerr << "[-] Decryption error: Message timestamp invalid (clock skew or expired).\n";
            return std::nullopt;
        }

        return message_envelope["content"].get<std::string>();

    } catch (const json::exception& e) {
        std::cerr << "[-] Decryption error: Invalid JSON in envelope: " << e.what() << "\n";
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "[-] Decryption error: " << e.what() << "\n";
        return std::nullopt;
    } catch (...) {
        std::cerr << "[-] Unknown decryption failure\n";
        return std::nullopt;
    }
}

} // namespace anon
