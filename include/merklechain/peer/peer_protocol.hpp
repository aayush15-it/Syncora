#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mc::peer {

inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::size_t kFrameHeaderSize = 12;
inline constexpr std::uint32_t kMaximumFramePayload = 1024U * 1024U;

enum class MessageType : std::uint16_t {
    Hello = 1,
    ManifestRequest = 2,
    Manifest = 3,
    FileRequest = 4,
    FileData = 5,
    FileEnd = 6,
    Approval = 7,
    SyncResult = 8,
    Error = 9
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

} // namespace mc::peer
