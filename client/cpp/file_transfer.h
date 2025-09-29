// file_transfer.h
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "crypto.h"  // anon_crypto::bytes

namespace anon {

using bytes = anon_crypto::bytes;
using json  = nlohmann::json;

struct FileTransferMeta {
    std::string file_path;
    std::string file_name;
    std::string file_hash;
    uint64_t file_size;
    uint64_t total_chunks;
    uint64_t chunks_sent;
    std::string status;
};

class FileTransferProtocol {
public:
    FileTransferProtocol();
    ~FileTransferProtocol();

    // Prepare metadata and register transfer
    std::optional<json> prepare_file_transfer(const std::string& file_path);

    // Encrypt one file chunk (returns nonce||ciphertext)
    std::optional<bytes> encrypt_file_chunk(const std::string& transfer_id,
                                            uint64_t chunk_index,
                                            const bytes& key);

    // Decrypt one encrypted chunk (returns parsed JSON)
    std::optional<json> decrypt_file_chunk(const bytes& encrypted_chunk,
                                           const bytes& key);

private:
    uint64_t chunk_size_;
    std::unordered_map<std::string, FileTransferMeta> transfers_;

    static std::string calculate_file_hash(const std::string& file_path);
};

} // namespace anon
