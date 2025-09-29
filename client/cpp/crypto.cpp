// crypto.cpp
#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace anon_crypto {

namespace {

void throw_openssl_last_error(const std::string& context) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    throw std::runtime_error(context + (buf[0] ? (": " + std::string(buf)) : ""));
}

} // anonymous

void openssl_initialize() {
    // OpenSSL 1.1.0+ does initialization automatically for most parts.
    // Still, load error strings for diagnostics (safe — not revealing secrets).
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(0, nullptr);
}

// KeyPair implementation
KeyPair::KeyPair() : private_key(), public_key() {}
KeyPair::KeyPair(bytes&& priv, bytes&& pub)
: private_key(std::move(priv)), public_key(std::move(pub)) {}

// generate_x25519_keypair
KeyPair generate_x25519_keypair() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw_openssl_last_error("EVP_PKEY_keygen_init");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw_openssl_last_error("EVP_PKEY_keygen");
    }
    EVP_PKEY_CTX_free(pctx);

    // extract raw private and public keys
    size_t priv_len = X25519_PRIVATE_KEY_BYTES;
    bytes priv(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw_openssl_last_error("EVP_PKEY_get_raw_private_key");
    }

    size_t pub_len = X25519_PUBLIC_KEY_BYTES;
    bytes pub(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw_openssl_last_error("EVP_PKEY_get_raw_public_key");
    }

    EVP_PKEY_free(pkey);
    return KeyPair(std::move(priv), std::move(pub));
}

// x25519_shared_secret
bytes x25519_shared_secret(const bytes& local_priv, const bytes& remote_pub) {
    if (local_priv.size() != X25519_PRIVATE_KEY_BYTES || remote_pub.size() != X25519_PUBLIC_KEY_BYTES)
        throw std::runtime_error("x25519_shared_secret: invalid key sizes");

    EVP_PKEY* priv = nullptr;
    EVP_PKEY* peer = nullptr;

    // create EVP_PKEY from raw private
    priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, local_priv.data(), local_priv.size());
    if (!priv) throw_openssl_last_error("EVP_PKEY_new_raw_private_key");

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, remote_pub.data(), remote_pub.size());
    if (!peer) {
        EVP_PKEY_free(priv);
        throw_openssl_last_error("EVP_PKEY_new_raw_public_key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        throw_openssl_last_error("EVP_PKEY_CTX_new");
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        EVP_PKEY_CTX_free(ctx);
        throw_openssl_last_error("EVP_PKEY_derive_init");
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        EVP_PKEY_CTX_free(ctx);
        throw_openssl_last_error("EVP_PKEY_derive_set_peer");
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        EVP_PKEY_CTX_free(ctx);
        throw_openssl_last_error("EVP_PKEY_derive (len)");
    }
    bytes secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        EVP_PKEY_CTX_free(ctx);
        throw_openssl_last_error("EVP_PKEY_derive (data)");
    }

    // clean up
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);

    // If library returns larger secret, resize (but X25519 produces 32)
    if (secret.size() != SHARED_SECRET_BYTES) secret.resize(SHARED_SECRET_BYTES);

    return secret;
}

// HKDF-SHA256 using OpenSSL HKDF APIs
bytes hkdf_sha256(const bytes& ikm,
                  const std::optional<bytes>& salt,
                  const std::optional<bytes>& info,
                  size_t out_len) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw_openssl_last_error("EVP_PKEY_CTX_new_id HKDF");

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw_openssl_last_error("EVP_PKEY_derive_init HKDF");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw_openssl_last_error("EVP_PKEY_CTX_set_hkdf_md");
    }
    // salt
    if (salt.has_value()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt->data(), salt->size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw_openssl_last_error("EVP_PKEY_CTX_set1_hkdf_salt");
        }
    } else {
        // explicit empty salt is allowed; do not set means OpenSSL treats as NULL which is fine
    }
    // IKM (input key material)
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw_openssl_last_error("EVP_PKEY_CTX_set1_hkdf_key");
    }
    // info
    if (info.has_value()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info->data(), info->size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw_openssl_last_error("EVP_PKEY_CTX_add1_hkdf_info");
        }
    }

    bytes out(out_len);
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw_openssl_last_error("EVP_PKEY_derive HKDF");
    }
    EVP_PKEY_CTX_free(pctx);
    if (len != out_len) out.resize(len);
    return out;
}

// AES-GCM encrypt/decrypt
bytes aes_gcm_encrypt(const bytes& key, const bytes& nonce,
                      const bytes& plaintext, const std::optional<bytes>& aad) {
    if (key.size() != AES_GCM_KEY_BYTES) throw std::runtime_error("aes_gcm_encrypt: invalid key size");
    if (nonce.size() != AES_GCM_NONCE_BYTES) throw std::runtime_error("aes_gcm_encrypt: invalid nonce size");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw_openssl_last_error("EVP_CIPHER_CTX_new");

    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_EncryptInit_ex");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_CIPHER_CTX_ctrl set iv len");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_EncryptInit_ex set key/iv");
    }

    int outlen = 0;
    if (aad.has_value() && !aad->empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &outlen, aad->data(), static_cast<int>(aad->size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw_openssl_last_error("EVP_EncryptUpdate AAD");
        }
    }

    bytes ciphertext(plaintext.size());
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw_openssl_last_error("EVP_EncryptUpdate");
        }
    }
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_EncryptFinal_ex");
    }
    outlen += tmplen;
    ciphertext.resize(outlen);

    // get tag
    bytes tag(AES_GCM_TAG_BYTES);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_BYTES, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_CIPHER_CTX_ctrl get tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    // append tag to ciphertext for transport convenience
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

bytes aes_gcm_decrypt(const bytes& key, const bytes& nonce,
                      const bytes& ciphertext_with_tag, const std::optional<bytes>& aad) {
    if (key.size() != AES_GCM_KEY_BYTES) throw std::runtime_error("aes_gcm_decrypt: invalid key size");
    if (nonce.size() != AES_GCM_NONCE_BYTES) throw std::runtime_error("aes_gcm_decrypt: invalid nonce size");
    if (ciphertext_with_tag.size() < AES_GCM_TAG_BYTES) throw std::runtime_error("ciphertext too short");

    size_t ciphertext_len = ciphertext_with_tag.size() - AES_GCM_TAG_BYTES;
    const uint8_t* ct_ptr = ciphertext_with_tag.data();
    const uint8_t* tag_ptr = ct_ptr + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw_openssl_last_error("EVP_CIPHER_CTX_new decrypt");

    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_DecryptInit_ex");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_CIPHER_CTX_ctrl set iv len decrypt");
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_DecryptInit_ex set key iv decrypt");
    }
    int outlen = 0;
    if (aad.has_value() && !aad->empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &outlen, aad->data(), static_cast<int>(aad->size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw_openssl_last_error("EVP_DecryptUpdate AAD decrypt");
        }
    }
    bytes plaintext(ciphertext_len);
    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ct_ptr, static_cast<int>(ciphertext_len)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw_openssl_last_error("EVP_DecryptUpdate decrypt");
        }
    }
    int tmplen = 0;
    // set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_BYTES, const_cast<uint8_t*>(tag_ptr)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw_openssl_last_error("EVP_CIPHER_CTX_ctrl set tag");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        // Authentication failed (tag mismatch) — do not reveal details
        throw std::runtime_error("aes_gcm_decrypt: authentication failed");
    }
    outlen += tmplen;
    plaintext.resize(outlen);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// base64 encode/decode using BIO
std::string base64_encode(const bytes& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    // no newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64, mem);
    if (!bio) throw std::runtime_error("base64_encode: BIO_new failed");

    if (BIO_write(bio, data.data(), static_cast<int>(data.size())) <= 0) {
        BIO_free_all(bio);
        throw_openssl_last_error("BIO_write base64");
    }
    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        throw_openssl_last_error("BIO_flush base64");
    }
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string out;
    out.assign(bptr->data, bptr->length);
    BIO_free_all(bio);
    return out;
}

bytes base64_decode(const std::string& b64) {
    BIO* b64f = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    BIO_set_flags(b64f, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64f, mem);
    if (!bio) throw std::runtime_error("base64_decode: BIO_new failed");

    // decode size is <= input length
    bytes out(b64.size());
    int len = BIO_read(bio, out.data(), static_cast<int>(out.size()));
    BIO_free_all(bio);
    if (len < 0) throw_openssl_last_error("BIO_read base64");
    out.resize(static_cast<size_t>(len));
    return out;
}

void secure_zero(bytes& b) {
    if (!b.empty()) {
        OPENSSL_cleanse(b.data(), b.size());
    }
}

bytes secure_random_bytes(size_t n) {
    bytes out(n);
    if (n > 0) {
        if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
            throw_openssl_last_error("RAND_bytes");
        }
    }
    return out;
}

AesKeyAndNonce derive_aes_key_and_nonce_from_shared(const bytes& shared_secret,
                                                    const std::optional<bytes>& salt,
                                                    const std::optional<bytes>& info) {
    // Use HKDF to derive key then nonce
    // info labels to keep derivation domain-separated
    bytes key = hkdf_sha256(shared_secret, salt, std::optional<bytes>(bytes({'k','e','y'})), AES_GCM_KEY_BYTES);
    bytes nonce = hkdf_sha256(shared_secret, salt, std::optional<bytes>(bytes({'n','o','n','c','e'})), AES_GCM_NONCE_BYTES);
    return AesKeyAndNonce{std::move(key), std::move(nonce)};
}

} // namespace anon_crypto
