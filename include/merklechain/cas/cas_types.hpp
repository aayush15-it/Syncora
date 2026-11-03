#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace mc::cas {

namespace fs = std::filesystem;

// 64-character lowercase hexadecimal SHA-256 chunk identifier
using ChunkHash = std::string;

// Canonical empty SHA-256 digest
inline constexpr const char* kEmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Represents a chunk reference within a file
struct ChunkInfo {
    std::uint64_t offset{0};
    std::uint64_t size{0};
    ChunkHash hash;

    bool operator==(const ChunkInfo& other) const {
        return offset == other.offset && size == other.size && hash == other.hash;
    }
    bool operator!=(const ChunkInfo& other) const {
        return !(*this == other);
    }
};

enum class PutResultStatus {
    StoredNew,       // Chunk did not exist; written and verified
    AlreadyExists,   // Chunk already present in object store; deduplicated
    HashMismatch,    // Provided hash did not match written content
    IoError          // Filesystem or write error
};

struct PutResult {
    PutResultStatus status{PutResultStatus::IoError};
    ChunkHash hash;
    std::uint64_t size{0};
    std::string error_message;

    bool is_ok() const {
        return status == PutResultStatus::StoredNew || status == PutResultStatus::AlreadyExists;
    }
};

} // namespace mc::cas

