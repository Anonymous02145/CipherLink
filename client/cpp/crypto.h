// crypto.h
#pragma once
#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <optional>

namespace anon_crypto {

// Configuration constants (from your Python snippet)
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

inline constexpr size_t MESSAGE_PADDING_SIZE = 256;
inline constexpr size_t SESSION_ROTATION_HOURS = 24;
inline constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;
inline constexpr size_t HEARTBEAT_INTERVAL = 30;

// sizes
inline constexpr size_t X25519_PUBLIC_KEY_BYTES = 32;
inline constexpr size_t X25519_PRIVATE_KEY_BYTES = 32;
inline constexpr size_t SHARED_SECRET_BYTES = 32;
inline constexpr size_t AES_GCM_KEY_BYTES = 32; // AES-256-GCM
inline constexpr size_t AES_GCM_NONCE_BYTES = 12;
inline constexpr size_t AES_GCM_TAG_BYTES = 16;

// Basic binary types
using bytes = std::vector<uint8_t>;

// RAII: initialize OpenSSL for this process
void openssl_initialize();

// Keypair (x25519)
struct KeyPair {
    bytes private_key; // 32 bytes
    bytes public_key;  // 32 bytes

    KeyPair();
    KeyPair(bytes&& priv, bytes&& pub);
};

// Generate an X25519 keypair (secure random)
KeyPair generate_x25519_keypair();

// Compute x25519 shared secret: local_priv + remote_pub -> shared (32 bytes)
bytes x25519_shared_secret(const bytes& local_priv, const bytes& remote_pub);

// HKDF-SHA256: derive bytes of desired length from input key material + optional salt + info
bytes hkdf_sha256(const bytes& ikm,
                  const std::optional<bytes>& salt,
                  const std::optional<bytes>& info,
                  size_t out_len);

// AES-256-GCM encrypt/decrypt helpers
// - key: 32 bytes
// - nonce: 12 bytes
// returns ciphertext (ciphertext length = plaintext length + TAG_BYTES appended at the end)
bytes aes_gcm_encrypt(const bytes& key, const bytes& nonce,
                      const bytes& plaintext,
                      const std::optional<bytes>& aad = std::nullopt);

bytes aes_gcm_decrypt(const bytes& key, const bytes& nonce,
                      const bytes& ciphertext_with_tag,
                      const std::optional<bytes>& aad = std::nullopt);

// base64 helpers
std::string base64_encode(const bytes& data);
bytes base64_decode(const std::string& b64);

// secure memory zeroing
void secure_zero(bytes& b);

// utility: generate cryptographically secure random bytes
bytes secure_random_bytes(size_t n);

// Convenience: derive AES key+nonce from shared secret using HKDF labels
struct AesKeyAndNonce {
    bytes key;   // 32 bytes
    bytes nonce; // 12 bytes
};
AesKeyAndNonce derive_aes_key_and_nonce_from_shared(const bytes& shared_secret,
                                                    const std::optional<bytes>& salt = std::nullopt,
                                                    const std::optional<bytes>& info = std::nullopt);

} // namespace anon_crypto
