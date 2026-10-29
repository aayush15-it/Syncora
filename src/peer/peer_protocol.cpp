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
           type <= static_cast<std::uint16_t>(MessageType::Error);
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
