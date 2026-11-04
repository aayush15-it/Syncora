#pragma once

#include "merklechain/peer/peer_protocol.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/chunker.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace mc::peer {

// FastCDC Canonical Parameters for Peer Synchronization
inline constexpr std::uint32_t kPeerFastCdcMinSize = 4096;   // 4 KB minimum chunk size
inline constexpr std::uint32_t kPeerFastCdcAvgSize = 8192;   // 8 KB average target chunk size
inline constexpr std::uint32_t kPeerFastCdcMaxSize = 16384;  // 16 KB maximum chunk size
inline constexpr std::uint32_t kMaxPeerManifestChunks = 50000; // ~800 MB file limit per manifest

// Returns canonical ChunkerConfig for peer CAS delta sync: 4KB / 8KB / 16KB
mc::cas::ChunkerConfig get_peer_chunker_config();

// Validates a relative path for peer transmission.
// Rejects: empty, leading slashes ('/', '\'), directory traversal (".."),
// drive letters ('C:'), null bytes, and non-printable control characters.
bool validate_peer_path(const std::string& path, std::string& err);

// Validates a FileManifest for peer transmission according to FastCDC rules:
// - Non-empty files: non-final chunks 4096..16384, final chunk 1..16384
// - Empty files: total_size == 0, chunk count == 0, file_sha256 == kEmptySha256
// - Offsets contiguous, sum of sizes == total_size, valid 64-hex SHA-256
bool validate_peer_manifest(const mc::cas::FileManifest& manifest, std::string& err);

// Serializes a FileManifest to binary bytes for ChunkManifestMessage
std::vector<std::uint8_t> serialize_peer_manifest(const mc::cas::FileManifest& manifest);

// Deserializes and validates a binary FileManifest from ChunkManifestMessage payload
bool deserialize_peer_manifest(
    const std::uint8_t* data,
    std::size_t size,
    mc::cas::FileManifest& out_manifest,
    std::string& err);

inline bool deserialize_peer_manifest(
    const std::vector<std::uint8_t>& data,
    mc::cas::FileManifest& out_manifest,
    std::string& err) {
    return deserialize_peer_manifest(data.data(), data.size(), out_manifest, err);
}

// Session chunk authorization whitelist to prevent unauthorized CAS object probing.
class SessionChunkAuthorizer {
public:
    SessionChunkAuthorizer() = default;

    // Authorize all chunk hashes present in a FileManifest
    void authorize_manifest(const mc::cas::FileManifest& manifest);

    // Authorize a single chunk hash (must be valid 64-hex)
    bool authorize_hash(const std::string& chunk_hash);

    // Check if a chunk hash is authorized in the current session
    bool is_authorized(const std::string& chunk_hash) const noexcept;

    // Validates an incoming ChunkRequestMessage:
    // - Path is valid relative path
    // - Requested hashes is non-empty and <= 4096
    // - Every hash is valid 64-hex SHA-256
    // - Every hash was authorized via authorize_manifest or authorize_hash
    bool validate_chunk_request(const ChunkRequestMessage& request, std::string& err) const;

    std::size_t authorized_count() const noexcept { return authorized_hashes_.size(); }
    void clear() noexcept { authorized_hashes_.clear(); }

private:
    std::unordered_set<std::string> authorized_hashes_;
};

// Computes which chunks in the manifest are missing from the receiver's local ObjectStore.
// Returns unique missing chunk hashes in manifest order.
// If all chunks exist in local CAS, returns an empty vector (zero-chunk transfer).
std::vector<std::string> compute_missing_chunks(
    const mc::cas::FileManifest& manifest,
    const mc::cas::ObjectStore& object_store);

// Splits missing chunk hashes into bounded ChunkRequestMessage frames (<= max_chunks_per_request).
std::vector<ChunkRequestMessage> build_chunk_requests(
    const std::string& relative_path,
    const std::vector<std::string>& missing_hashes,
    std::size_t max_chunks_per_request = kMaxRequestedChunksPerRequest);

// Chunks a local file using canonical FastCDC peer configuration (4KB/8KB/16KB)
// and produces a valid mc::cas::FileManifest.
bool chunk_file_for_peer(
    const std::string& file_path,
    mc::cas::FileManifest& out_manifest,
    std::string& err);

// Chunks an in-memory buffer using canonical FastCDC peer configuration (4KB/8KB/16KB)
// and produces a valid mc::cas::FileManifest.
bool chunk_buffer_for_peer(
    const void* data,
    std::size_t size,
    mc::cas::FileManifest& out_manifest,
    std::string& err);

// Cryptographically verifies that received chunk data matches claimed SHA-256 hash
// and is within the valid FastCDC size limit (1 byte to 16384 bytes).
bool verify_chunk_payload(
    const std::string& claimed_hash,
    const void* data,
    std::size_t size,
    std::string& err);

} // namespace mc::peer
