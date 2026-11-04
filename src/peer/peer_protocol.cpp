#include "merklechain/peer/peer_protocol.hpp"

#include <algorithm>
#include <stdexcept>

namespace mc::peer {
namespace {
constexpr std::uint8_t kMagic[] = {'M', 'C', 'R', 'P'};

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}
void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}
void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int i = 56; i >= 0; i -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(i)) & 0xffU));
    }
}
std::uint16_t read_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) |
                                      static_cast<std::uint16_t>(p[1]));
}
std::uint32_t read_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24U) |
           (static_cast<std::uint32_t>(p[1]) << 16U) |
           (static_cast<std::uint32_t>(p[2]) << 8U) |
           static_cast<std::uint32_t>(p[3]);
}
std::uint64_t read_u64(const std::uint8_t* p) {
    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8U) | static_cast<std::uint64_t>(p[i]);
    }
    return val;
}
void validate_header(const std::vector<std::uint8_t>& header,
                     std::uint16_t& version, MessageType& type,
                     std::uint32_t& payload_size) {
    if (header.size() != kFrameHeaderSize ||
        !std::equal(std::begin(kMagic), std::end(kMagic), header.begin()))
        throw std::runtime_error("invalid peer frame magic");
    version = read_u16(header.data() + 4);
    if (version != kProtocolVersion)
        throw std::runtime_error("unsupported peer protocol version");
    const auto raw_type = read_u16(header.data() + 6);
    if (!valid_message_type(raw_type))
        throw std::runtime_error("invalid peer message type");
    type = static_cast<MessageType>(raw_type);
    payload_size = read_u32(header.data() + 8);
    if (payload_size > kMaximumFramePayload)
        throw std::runtime_error("peer frame exceeds the payload limit");
}
} // namespace

bool valid_message_type(std::uint16_t type) noexcept {
    return type >= static_cast<std::uint16_t>(MessageType::Hello) &&
           type <= static_cast<std::uint16_t>(MessageType::ChunkManifestPage);
}

bool is_valid_hex_sha256(const std::string& hash) noexcept {
    if (hash.size() != kMaxChunkHashHexSize) return false;
    for (char c : hash) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool PeerCapabilities::has_capability(const std::string& cap) const noexcept {
    for (const auto& c : capabilities) {
        if (c == cap) return true;
    }
    return false;
}

bool PeerCapabilities::supports_cas_delta() const noexcept {
    return has_capability(kCapCasDeltaV1);
}

std::string encode_hello_payload(const PeerCapabilities& caps) {
    if (caps.identity.empty()) {
        throw std::runtime_error("cannot encode hello payload with empty identity");
    }
    std::string out = "identity=" + caps.identity;
    if (!caps.version.empty()) {
        out += ";version=" + caps.version;
    }
    if (!caps.capabilities.empty()) {
        out += ";caps=";
        for (std::size_t i = 0; i < caps.capabilities.size(); ++i) {
            if (i > 0) out += ",";
            out += caps.capabilities[i];
        }
    }
    return out;
}

PeerCapabilities decode_hello_payload(const std::string& payload) {
    if (payload.empty()) {
        throw std::runtime_error("empty hello payload");
    }
    // If no '=' and no ';' and no ':', treat entire payload as plain identity (legacy mode)
    if (payload.find('=') == std::string::npos &&
        payload.find(';') == std::string::npos &&
        payload.find(':') == std::string::npos) {
        PeerCapabilities caps;
        caps.identity = payload;
        caps.version = "1.0";
        return caps;
    }

    PeerCapabilities caps;
    caps.version = "1.0";
    std::size_t start = 0;
    while (start < payload.size()) {
        auto end = payload.find(';', start);
        if (end == std::string::npos) end = payload.size();
        std::string token = payload.substr(start, end - start);
        start = end + 1;

        auto trim_start = token.find_first_not_of(" \t\r\n");
        if (trim_start == std::string::npos) continue;
        auto trim_end = token.find_last_not_of(" \t\r\n");
        token = token.substr(trim_start, trim_end - trim_start + 1);

        auto eq_pos = token.find('=');
        if (eq_pos == std::string::npos) {
            eq_pos = token.find(':');
        }
        if (eq_pos == std::string::npos) {
            if (caps.identity.empty()) {
                caps.identity = token;
            }
            continue;
        }

        std::string key = token.substr(0, eq_pos);
        std::string val = token.substr(eq_pos + 1);

        auto k_start = key.find_first_not_of(" \t\r\n");
        if (k_start != std::string::npos) {
            auto k_end = key.find_last_not_of(" \t\r\n");
            key = key.substr(k_start, k_end - k_start + 1);
        }
        auto v_start = val.find_first_not_of(" \t\r\n");
        if (v_start != std::string::npos) {
            auto v_end = val.find_last_not_of(" \t\r\n");
            val = val.substr(v_start, v_end - v_start + 1);
        } else {
            val.clear();
        }

        if (key == "identity") {
            caps.identity = val;
        } else if (key == "version") {
            caps.version = val;
        } else if (key == "caps" || key == "capabilities") {
            std::size_t c_start = 0;
            while (c_start < val.size()) {
                auto c_end = val.find(',', c_start);
                if (c_end == std::string::npos) c_end = val.size();
                std::string cap = val.substr(c_start, c_end - c_start);
                c_start = c_end + 1;
                auto cap_s = cap.find_first_not_of(" \t\r\n");
                if (cap_s != std::string::npos) {
                    auto cap_e = cap.find_last_not_of(" \t\r\n");
                    cap = cap.substr(cap_s, cap_e - cap_s + 1);
                    if (!cap.empty()) {
                        caps.capabilities.push_back(cap);
                    }
                }
            }
        }
    }

    if (caps.identity.empty()) {
        throw std::runtime_error("empty identity in hello payload");
    }
    return caps;
}

std::string encode_chunk_manifest_request(const ChunkManifestRequestMessage& msg) {
    if (msg.relative_path.size() > 65535U) {
        throw std::runtime_error("relative_path exceeds 65535 bytes");
    }
    std::vector<std::uint8_t> out;
    out.reserve(2U + msg.relative_path.size());
    append_u16(out, static_cast<std::uint16_t>(msg.relative_path.size()));
    out.insert(out.end(), msg.relative_path.begin(), msg.relative_path.end());
    return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

ChunkManifestRequestMessage decode_chunk_manifest_request(const std::string& payload) {
    if (payload.size() < 2U) {
        throw std::runtime_error("truncated ChunkManifestRequest frame");
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(payload.data());
    const std::uint16_t path_len = read_u16(p);
    if (payload.size() != 2U + static_cast<std::size_t>(path_len)) {
        throw std::runtime_error("ChunkManifestRequest payload length mismatch");
    }
    ChunkManifestRequestMessage msg;
    msg.relative_path = payload.substr(2, path_len);
    return msg;
}

std::string encode_chunk_manifest_message(const ChunkManifestMessage& msg) {
    if (msg.relative_path.size() > 65535U) {
        throw std::runtime_error("relative_path exceeds 65535 bytes");
    }
    const std::size_t total_size = 2U + msg.relative_path.size() + msg.serialized_manifest.size();
    if (total_size > kMaximumFramePayload) {
        throw std::runtime_error("ChunkManifest message exceeds maximum frame payload");
    }
    std::vector<std::uint8_t> out;
    out.reserve(total_size);
    append_u16(out, static_cast<std::uint16_t>(msg.relative_path.size()));
    out.insert(out.end(), msg.relative_path.begin(), msg.relative_path.end());
    out.insert(out.end(), msg.serialized_manifest.begin(), msg.serialized_manifest.end());
    return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

ChunkManifestMessage decode_chunk_manifest_message(const std::string& payload) {
    if (payload.size() < 2U) {
        throw std::runtime_error("truncated ChunkManifest frame");
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(payload.data());
    const std::uint16_t path_len = read_u16(p);
    if (payload.size() < 2U + static_cast<std::size_t>(path_len)) {
        throw std::runtime_error("truncated ChunkManifest path");
    }
    ChunkManifestMessage msg;
    msg.relative_path = payload.substr(2, path_len);
    const std::size_t manifest_start = 2U + static_cast<std::size_t>(path_len);
    msg.serialized_manifest.assign(payload.begin() + static_cast<std::ptrdiff_t>(manifest_start), payload.end());
    return msg;
}

std::string encode_chunk_request(const ChunkRequestMessage& msg) {
    if (msg.relative_path.size() > 65535U) {
        throw std::runtime_error("relative_path exceeds 65535 bytes");
    }
    if (msg.requested_hashes.size() > kMaxRequestedChunksPerRequest) {
        throw std::runtime_error("chunk request exceeds maximum of 4096 chunk hashes");
    }
    const std::size_t total_size = 2U + msg.relative_path.size() + 4U +
                                   msg.requested_hashes.size() * kMaxChunkHashHexSize;
    if (total_size > kMaximumFramePayload) {
        throw std::runtime_error("ChunkRequest message exceeds maximum frame payload");
    }
    std::vector<std::uint8_t> out;
    out.reserve(total_size);
    append_u16(out, static_cast<std::uint16_t>(msg.relative_path.size()));
    out.insert(out.end(), msg.relative_path.begin(), msg.relative_path.end());
    append_u32(out, static_cast<std::uint32_t>(msg.requested_hashes.size()));
    for (const auto& h : msg.requested_hashes) {
        if (!is_valid_hex_sha256(h)) {
            throw std::runtime_error("invalid hex SHA-256 hash in chunk request: " + h);
        }
        out.insert(out.end(), h.begin(), h.end());
    }
    return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

ChunkRequestMessage decode_chunk_request(const std::string& payload) {
    if (payload.size() < 6U) {
        throw std::runtime_error("truncated ChunkRequest header");
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(payload.data());
    const std::uint16_t path_len = read_u16(p);
    if (payload.size() < 2U + static_cast<std::size_t>(path_len) + 4U) {
        throw std::runtime_error("truncated ChunkRequest path or count");
    }
    const std::uint32_t chunk_count = read_u32(p + 2 + path_len);
    if (chunk_count > kMaxRequestedChunksPerRequest) {
        throw std::runtime_error("chunk request count exceeds maximum 4096");
    }
    const std::size_t expected_size = 2U + static_cast<std::size_t>(path_len) + 4U +
                                      static_cast<std::size_t>(chunk_count) * kMaxChunkHashHexSize;
    if (payload.size() != expected_size) {
        throw std::runtime_error("ChunkRequest payload size mismatch");
    }
    ChunkRequestMessage msg;
    msg.relative_path = payload.substr(2, path_len);
    msg.requested_hashes.reserve(chunk_count);
    std::size_t offset = 2U + static_cast<std::size_t>(path_len) + 4U;
    for (std::uint32_t i = 0; i < chunk_count; ++i) {
        std::string h = payload.substr(offset, kMaxChunkHashHexSize);
        if (!is_valid_hex_sha256(h)) {
            throw std::runtime_error("invalid hex hash in chunk request payload: " + h);
        }
        msg.requested_hashes.push_back(std::move(h));
        offset += kMaxChunkHashHexSize;
    }
    return msg;
}

std::string encode_chunk_data(const ChunkDataMessage& msg) {
    if (!is_valid_hex_sha256(msg.chunk_hash)) {
        throw std::runtime_error("invalid hex SHA-256 chunk hash in ChunkData: " + msg.chunk_hash);
    }
    const std::size_t total_size = kMaxChunkHashHexSize + msg.data.size();
    if (total_size > kMaximumFramePayload) {
        throw std::runtime_error("ChunkData message exceeds maximum frame payload");
    }
    std::vector<std::uint8_t> out;
    out.reserve(total_size);
    out.insert(out.end(), msg.chunk_hash.begin(), msg.chunk_hash.end());
    out.insert(out.end(), msg.data.begin(), msg.data.end());
    return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

ChunkDataMessage decode_chunk_data(const std::string& payload) {
    if (payload.size() < kMaxChunkHashHexSize) {
        throw std::runtime_error("truncated ChunkData message: smaller than 64-byte hash");
    }
    std::string chunk_hash = payload.substr(0, kMaxChunkHashHexSize);
    if (!is_valid_hex_sha256(chunk_hash)) {
        throw std::runtime_error("invalid hex chunk hash in ChunkData: " + chunk_hash);
    }
    const std::size_t data_len = payload.size() - kMaxChunkHashHexSize;
    if (data_len > kMaxChunkDataPayloadSize) {
        throw std::runtime_error("ChunkData payload exceeds maximum FastCDC chunk size (" +
                                 std::to_string(kMaxChunkDataPayloadSize) + " bytes)");
    }
    ChunkDataMessage msg;
    msg.chunk_hash = std::move(chunk_hash);
    msg.data.assign(payload.begin() + static_cast<std::ptrdiff_t>(kMaxChunkHashHexSize), payload.end());
    return msg;
}

std::string encode_chunk_manifest_page(const ChunkManifestPageMessage& msg) {
    if (msg.relative_path.size() > 65535U) {
        throw std::runtime_error("relative_path exceeds 65535 bytes");
    }
    if (msg.file_sha256.size() != 64) {
        throw std::runtime_error("file_sha256 must be 64 characters");
    }
    const std::size_t total_size = 2U + msg.relative_path.size() +
                                   2U + 64U +
                                   8U + 4U + 4U + 4U + 4U + 4U +
                                   msg.page_payload.size();
    if (total_size > kMaximumFramePayload) {
        throw std::runtime_error("ChunkManifestPage exceeds maximum frame payload");
    }
    std::vector<std::uint8_t> out;
    out.reserve(total_size);
    append_u16(out, static_cast<std::uint16_t>(msg.relative_path.size()));
    out.insert(out.end(), msg.relative_path.begin(), msg.relative_path.end());
    append_u16(out, 64U);
    out.insert(out.end(), msg.file_sha256.begin(), msg.file_sha256.end());
    append_u64(out, msg.total_size);
    append_u32(out, msg.page_index);
    append_u32(out, msg.total_pages);
    append_u32(out, msg.chunks_in_page);
    append_u32(out, msg.total_chunks);
    append_u32(out, static_cast<std::uint32_t>(msg.page_payload.size()));
    out.insert(out.end(), msg.page_payload.begin(), msg.page_payload.end());
    return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

ChunkManifestPageMessage decode_chunk_manifest_page(const std::string& payload) {
    if (payload.size() < 2U + 2U + 64U + 8U + 4U + 4U + 4U + 4U + 4U) {
        throw std::runtime_error("truncated ChunkManifestPage frame");
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(payload.data());
    std::size_t offset = 0;
    const std::uint16_t path_len = read_u16(p + offset);
    offset += 2;
    if (payload.size() < offset + path_len + 2 + 64 + 28) {
        throw std::runtime_error("truncated path in ChunkManifestPage frame");
    }
    ChunkManifestPageMessage msg;
    msg.relative_path = payload.substr(offset, path_len);
    offset += path_len;
    const std::uint16_t sha_len = read_u16(p + offset);
    offset += 2;
    if (sha_len != 64 || payload.size() < offset + 64 + 28) {
        throw std::runtime_error("invalid sha256 in ChunkManifestPage frame");
    }
    msg.file_sha256 = payload.substr(offset, 64);
    offset += 64;
    msg.total_size = read_u64(p + offset);
    offset += 8;
    msg.page_index = read_u32(p + offset);
    offset += 4;
    msg.total_pages = read_u32(p + offset);
    offset += 4;
    msg.chunks_in_page = read_u32(p + offset);
    offset += 4;
    msg.total_chunks = read_u32(p + offset);
    offset += 4;
    const std::uint32_t payload_len = read_u32(p + offset);
    offset += 4;
    if (payload.size() != offset + payload_len) {
        throw std::runtime_error("ChunkManifestPage payload size mismatch");
    }
    msg.page_payload.assign(p + offset, p + offset + payload_len);
    return msg;
}

std::vector<std::uint8_t> encode_frame(const Frame& frame) {
    const auto raw_type = static_cast<std::uint16_t>(frame.type);
    if (frame.version != kProtocolVersion)
        throw std::runtime_error("cannot encode unsupported peer protocol version");
    if (!valid_message_type(raw_type))
        throw std::runtime_error("cannot encode invalid peer message type");
    if (frame.payload.size() > kMaximumFramePayload)
        throw std::runtime_error("peer frame exceeds the payload limit");
    std::vector<std::uint8_t> result;
    result.reserve(kFrameHeaderSize + frame.payload.size());
    result.insert(result.end(), std::begin(kMagic), std::end(kMagic));
    append_u16(result, frame.version);
    append_u16(result, raw_type);
    append_u32(result, static_cast<std::uint32_t>(frame.payload.size()));
    result.insert(result.end(), frame.payload.begin(), frame.payload.end());
    return result;
}

std::vector<Frame> FrameDecoder::feed(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) throw std::runtime_error("null peer frame input");
    std::vector<Frame> frames;
    std::size_t offset = 0;
    while (offset < size) {
        std::size_t wanted = 0;
        if (!header_validated_) {
            wanted = kFrameHeaderSize - pending_.size();
        } else {
            const auto current_payload = pending_.size() - kFrameHeaderSize;
            wanted = static_cast<std::size_t>(expected_payload_) - current_payload;
        }
        const auto count = std::min(wanted, size - offset);
        pending_.insert(pending_.end(), data + offset, data + offset + count);
        offset += count;

        if (!header_validated_ && pending_.size() == kFrameHeaderSize) {
            validate_header(pending_, version_, type_, expected_payload_);
            header_validated_ = true;
            if (expected_payload_ == 0) {
                frames.push_back(Frame{version_, type_, {}});
                reset();
            }
        } else if (header_validated_ &&
                   pending_.size() == kFrameHeaderSize + expected_payload_) {
            std::string payload(reinterpret_cast<const char*>(pending_.data() + kFrameHeaderSize),
                                static_cast<std::size_t>(expected_payload_));
            frames.push_back(Frame{version_, type_, std::move(payload)});
            reset();
        }
    }
    return frames;
}

void FrameDecoder::finish() const {
    if (!pending_.empty()) throw std::runtime_error("truncated peer frame");
}

void FrameDecoder::reset() noexcept {
    pending_.clear();
    expected_payload_ = 0;
    header_validated_ = false;
    version_ = 0;
    type_ = MessageType::Error;
}

} // namespace mc::peer
