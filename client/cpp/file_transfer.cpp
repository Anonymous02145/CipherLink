// file_transfer.cpp
#include "file_transfer.h"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

namespace anon {

FileTransferProtocol::FileTransferProtocol()
: chunk_size_(8192) {}

FileTransferProtocol::~FileTransferProtocol() {
    // Wipe paths from memory
    for (auto &p : transfers_) {
        // Not strictly secret, but avoid leaving sensitive metadata
        p.second.file_path.assign(p.second.file_path.size(), '\0');
        p.second.file_name.assign(p.second.file_name.size(), '\0');
        p.second.file_hash.assign(p.second.file_hash.size(), '\0');
    }
    transfers_.clear();
}

std::optional<json> FileTransferProtocol::prepare_file_transfer(const std::string& file_path) {
    try {
        namespace fs = std::filesystem;
        if (!fs::exists(file_path)) return std::nullopt;

        uint64_t file_size = fs::file_size(file_path);
        std::string file_name = fs::path(file_path).filename().string();
        std::string file_hash = calculate_file_hash(file_path);

        // generate random transfer id (32 hex chars)
        bytes rnd = anon_crypto::secure_random_bytes(16);
        std::ostringstream oss;
        for (auto b : rnd) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::string transfer_id = oss.str();

        FileTransferMeta meta;
        meta.file_path = file_path;
        meta.file_name = file_name;
        meta.file_hash = file_hash;
        meta.file_size = file_size;
        meta.total_chunks = (file_size + chunk_size_ - 1) / chunk_size_;
        meta.chunks_sent = 0;
        meta.status = "ready";

        transfers_[transfer_id] = meta;

        json out;
        out["transfer_id"]  = transfer_id;
        out["file_name"]    = file_name;
        out["file_size"]    = file_size;
        out["file_hash"]    = file_hash;
        out["total_chunks"] = meta.total_chunks;
        return out;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<bytes> FileTransferProtocol::encrypt_file_chunk(const std::string& transfer_id,
                                                              uint64_t chunk_index,
                                                              const bytes& key) {
    try {
        if (!transfers_.count(transfer_id)) return std::nullopt;
        auto& meta = transfers_[transfer_id];

        std::ifstream f(meta.file_path, std::ios::binary);
        if (!f) return std::nullopt;

        uint64_t offset = chunk_index * chunk_size_;
        f.seekg(offset);
        std::vector<uint8_t> chunk_data(chunk_size_);
        f.read(reinterpret_cast<char*>(chunk_data.data()), chunk_size_);
        size_t read_bytes = f.gcount();
        chunk_data.resize(read_bytes);

        if (chunk_data.empty()) return std::nullopt;

        // build envelope
        json envelope;
        envelope["transfer_id"]  = transfer_id;
        envelope["chunk_index"]  = chunk_index;
        envelope["total_chunks"] = meta.total_chunks;
        envelope["data"]         = anon_crypto::base64_encode(chunk_data);
        double ts = std::chrono::duration_cast<std::chrono::duration<double>>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
        envelope["timestamp"] = ts;

        std::string serialized = envelope.dump();

        bytes nonce = anon_crypto::secure_random_bytes(12);
        bytes plaintext(serialized.begin(), serialized.end());
        bytes ciphertext = anon_crypto::aes_gcm_encrypt(key, nonce, plaintext, std::nullopt);

        bytes out;
        out.reserve(nonce.size() + ciphertext.size());
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());

        meta.chunks_sent++;
        return out;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<json> FileTransferProtocol::decrypt_file_chunk(const bytes& encrypted_chunk,
                                                             const bytes& key) {
    try {
        if (encrypted_chunk.size() < 12 + anon_crypto::AES_GCM_TAG_BYTES) return std::nullopt;

        bytes nonce(encrypted_chunk.begin(), encrypted_chunk.begin() + 12);
        bytes ciphertext(encrypted_chunk.begin() + 12, encrypted_chunk.end());

        bytes decrypted = anon_crypto::aes_gcm_decrypt(key, nonce, ciphertext, std::nullopt);
        std::string s(decrypted.begin(), decrypted.end());

        json envelope = json::parse(s);

        // required fields check
        for (auto& field : {"transfer_id", "chunk_index", "total_chunks", "data"}) {
            if (!envelope.contains(field)) return std::nullopt;
        }

        return envelope;
    } catch (...) {
        return std::nullopt;
    }
}

std::string FileTransferProtocol::calculate_file_hash(const std::string& file_path) {
    std::ifstream f(file_path, std::ios::binary);
    if (!f) return {};

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    char buf[4096];
    while (f.read(buf, sizeof(buf)) || f.gcount()) {
        SHA256_Update(&ctx, buf, f.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return oss.str();
}

} // namespace anon
