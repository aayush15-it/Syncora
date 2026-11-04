#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mc::peer {

inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::size_t kFrameHeaderSize = 12;
inline constexpr std::uint32_t kMaximumFramePayload = 1024U * 1024U;

// Milestone 3.4 Wire Limits & Capability Constants
inline constexpr std::size_t kMaxChunkHashHexSize = 64;
inline constexpr std::uint32_t kMaxRequestedChunksPerRequest = 4096;
inline constexpr std::size_t kMaxChunkDataPayloadSize = 16384; // 16 KB FastCDC maximum chunk
inline constexpr const char* kCapCasDeltaV1 = "cas_delta_v1";
inline constexpr const char* kCapWholeFile = "whole_file";

enum class MessageType : std::uint16_t {
    Hello = 1,
    ManifestRequest = 2,
    Manifest = 3,
    FileRequest = 4,
    FileData = 5,
    FileEnd = 6,
    Approval = 7,
    SyncResult = 8,
    Error = 9,

    // Milestone 3.4 CAS Delta Extensions
    ChunkManifestRequest = 10, // Request chunk manifest for relative path
    ChunkManifest = 11,        // Binary serialized mc::cas::FileManifest
    ChunkRequest = 12,         // List of missing chunk hashes requested by receiver
    ChunkData = 13             // Content-addressed chunk payload
};

struct Frame {
    std::uint16_t version{kProtocolVersion};
    MessageType type{MessageType::Error};
    std::string payload;
};

// Wire format: ASCII "MCRP", uint16 version, uint16 type, uint32 payload
// length; all integers are unsigned big-endian. Payload is opaque bytes.
std::vector<std::uint8_t> encode_frame(const Frame& frame);

// Incremental bounded decoder. feed() supports arbitrary TLS read boundaries
// and multiple frames in one read; finish() rejects a truncated trailing frame.
class FrameDecoder {
public:
    std::vector<Frame> feed(const std::uint8_t* data, std::size_t size);
    std::vector<Frame> feed(const std::vector<std::uint8_t>& data) {
        return feed(data.data(), data.size());
    }
    void finish() const;
    void reset() noexcept;

private:
    std::vector<std::uint8_t> pending_;
    std::uint32_t expected_payload_{};
    bool header_validated_{false};
    std::uint16_t version_{};
    MessageType type_{MessageType::Error};
};

bool valid_message_type(std::uint16_t type) noexcept;
bool is_valid_hex_sha256(const std::string& hash) noexcept;

// Capability negotiation representation
struct PeerCapabilities {
    std::string identity;
    std::string version{"1.0"};
    std::vector<std::string> capabilities;

    bool has_capability(const std::string& cap) const noexcept;
    bool supports_cas_delta() const noexcept;
};

std::string encode_hello_payload(const PeerCapabilities& caps);
PeerCapabilities decode_hello_payload(const std::string& payload);

// MessageType::ChunkManifestRequest (10)
struct ChunkManifestRequestMessage {
    std::string relative_path;

    bool operator==(const ChunkManifestRequestMessage& o) const noexcept {
        return relative_path == o.relative_path;
    }
};
std::string encode_chunk_manifest_request(const ChunkManifestRequestMessage& msg);
ChunkManifestRequestMessage decode_chunk_manifest_request(const std::string& payload);

// MessageType::ChunkManifest (11)
struct ChunkManifestMessage {
    std::string relative_path;
    std::vector<std::uint8_t> serialized_manifest;

    bool operator==(const ChunkManifestMessage& o) const noexcept {
        return relative_path == o.relative_path && serialized_manifest == o.serialized_manifest;
    }
};
std::string encode_chunk_manifest_message(const ChunkManifestMessage& msg);
ChunkManifestMessage decode_chunk_manifest_message(const std::string& payload);

// MessageType::ChunkRequest (12)
struct ChunkRequestMessage {
    std::string relative_path;
    std::vector<std::string> requested_hashes;

    bool operator==(const ChunkRequestMessage& o) const noexcept {
        return relative_path == o.relative_path && requested_hashes == o.requested_hashes;
    }
};
std::string encode_chunk_request(const ChunkRequestMessage& msg);
ChunkRequestMessage decode_chunk_request(const std::string& payload);

// MessageType::ChunkData (13)
struct ChunkDataMessage {
    std::string chunk_hash;
    std::vector<std::uint8_t> data;

    bool operator==(const ChunkDataMessage& o) const noexcept {
        return chunk_hash == o.chunk_hash && data == o.data;
    }
};
std::string encode_chunk_data(const ChunkDataMessage& msg);
ChunkDataMessage decode_chunk_data(const std::string& payload);

} // namespace mc::peer
