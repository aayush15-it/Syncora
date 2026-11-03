#include "merklechain/cas/chunker.hpp"
#include "merklechain/hash.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace mc::cas {

namespace {

// Deterministically generated 256-entry 64-bit Gear matrix for rolling hash
// Generated via splitmix64 PRNG with fixed seed 0x46617374434443ULL ("FastCDC")
constexpr std::array<std::uint64_t, 256> generate_gear_matrix() {
    std::array<std::uint64_t, 256> matrix{};
    std::uint64_t state = 0x46617374434443ULL;
    for (std::size_t i = 0; i < 256; ++i) {
        state += 0x9e3779b97f4a7c15ULL;
        std::uint64_t z = state;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        matrix[i] = z ^ (z >> 31);
    }
    return matrix;
}

constexpr auto kGearMatrix = generate_gear_matrix();

} // namespace

FastCDCChunker::FastCDCChunker(ChunkerConfig config) : config_(config) {
    std::string err;
    if (!config_.validate(err)) {
        throw std::invalid_argument("Invalid ChunkerConfig: " + err);
    }
    init_masks();
}

void FastCDCChunker::init_masks() {
    std::uint32_t n = 0;
    std::uint32_t val = config_.avg_size;
    while (val > 1) {
        val >>= 1;
        ++n;
    }
    if ((config_.avg_size & (config_.avg_size - 1)) != 0) {
        if ((1U << n) * 3 / 2 <= config_.avg_size) {
            ++n;
        }
    }
    if (n < 4) n = 4;
    if (n > 30) n = 30;

    const std::uint32_t norm = config_.normalization_level;
    const std::uint32_t bits_s = (n + norm < 60) ? (n + norm) : 60;
    const std::uint32_t bits_l = (n >= norm + 1) ? (n - norm) : 1;

    mask_s_ = (1ULL << bits_s) - 1ULL;
    mask_l_ = (1ULL << bits_l) - 1ULL;
}

std::size_t FastCDCChunker::cut_point(const std::uint8_t* data, std::size_t length) const {
    if (length <= config_.min_size) {
        return length;
    }

    const std::size_t limit = std::min(length, static_cast<std::size_t>(config_.max_size));
    const std::size_t avg_limit = std::min(length, static_cast<std::size_t>(config_.avg_size));

    std::uint64_t fp = 0;

    // Sub-minimum skipping: bytes [0, min_size - 1) are bypassed without checking boundaries
    // Region 1: [min_size - 1, avg_size) - strict mask to avoid undersized chunks
    const std::size_t start_idx = (config_.min_size > 0) ? (config_.min_size - 1) : 0;
    for (std::size_t i = start_idx; i < avg_limit; ++i) {
        fp = (fp << 1) + kGearMatrix[data[i]];
        if ((fp & mask_s_) == 0) {
            return i + 1;
        }
    }

    // Region 2: [avg_size, max_size) - loose mask to cut before reaching maximum
    for (std::size_t i = avg_limit; i < limit; ++i) {
        fp = (fp << 1) + kGearMatrix[data[i]];
        if ((fp & mask_l_) == 0) {
            return i + 1;
        }
    }

    return limit;
}

std::vector<ChunkInfo> FastCDCChunker::chunk_buffer(const void* data, std::size_t size) const {
    std::vector<ChunkInfo> chunks;
    if (size == 0 || data == nullptr) {
        return chunks;
    }

    const auto* byte_ptr = static_cast<const std::uint8_t*>(data);
    std::size_t offset = 0;

    while (offset < size) {
        const std::size_t remaining = size - offset;
        const std::size_t chunk_len = cut_point(byte_ptr + offset, remaining);
        const std::string hash = mc::sha256_data(byte_ptr + offset, chunk_len);

        chunks.push_back(ChunkInfo{
            static_cast<std::uint64_t>(offset),
            static_cast<std::uint64_t>(chunk_len),
            hash
        });

        offset += chunk_len;
    }

    return chunks;
}

std::vector<ChunkInfo> FastCDCChunker::chunk_file(const fs::path& path) const {
    std::vector<ChunkInfo> chunks;
    chunk_file_stream(path, [&chunks](const ChunkInfo& info, const std::uint8_t* /*data*/) {
        chunks.push_back(info);
    });
    return chunks;
}

std::vector<ChunkInfo> FastCDCChunker::chunk_stream(std::istream& stream) const {
    std::vector<ChunkInfo> chunks;
    if (!stream || stream.rdbuf() == nullptr) {
        return chunks;
    }

    const std::size_t window_size = std::max(static_cast<std::size_t>(config_.max_size) * 2, static_cast<std::size_t>(128 * 1024));
    std::vector<std::uint8_t> buffer(window_size);

    std::size_t buffer_valid = 0;
    std::uint64_t total_offset = 0;

    while (true) {
        // Refill buffer until at least max_size bytes are present, or EOF is reached
        while (buffer_valid < config_.max_size) {
            const auto to_read = static_cast<std::streamsize>(window_size - buffer_valid);
            const auto n = stream.rdbuf()->sgetn(reinterpret_cast<char*>(buffer.data() + buffer_valid), to_read);
            if (n <= 0) break;
            buffer_valid += static_cast<std::size_t>(n);
        }

        if (buffer_valid == 0) {
            break;
        }

        const std::size_t chunk_len = cut_point(buffer.data(), buffer_valid);
        const std::string hash = mc::sha256_data(buffer.data(), chunk_len);
        chunks.push_back(ChunkInfo{total_offset, static_cast<std::uint64_t>(chunk_len), hash});

        total_offset += chunk_len;
        const std::size_t remaining = buffer_valid - chunk_len;
        if (remaining > 0) {
            std::memmove(buffer.data(), buffer.data() + chunk_len, remaining);
        }
        buffer_valid = remaining;
    }

    return chunks;
}

void FastCDCChunker::chunk_file_stream(const fs::path& path, const ChunkCallback& callback) const {
    std::ifstream in(path, std::ios::binary);
    if (!in || in.rdbuf() == nullptr) {
        throw std::runtime_error("Cannot open file for chunking: " + path.string());
    }

    // Sliding window buffer: 2 * max_size to ensure smooth stream chunking
    const std::size_t window_size = std::max(static_cast<std::size_t>(config_.max_size) * 2, static_cast<std::size_t>(128 * 1024));
    std::vector<std::uint8_t> buffer(window_size);

    std::size_t buffer_valid = 0;
    std::uint64_t total_offset = 0;

    while (true) {
        // Refill buffer until at least max_size bytes are present, or EOF is reached
        while (buffer_valid < config_.max_size) {
            const auto to_read = static_cast<std::streamsize>(window_size - buffer_valid);
            const auto n = in.rdbuf()->sgetn(reinterpret_cast<char*>(buffer.data() + buffer_valid), to_read);
            if (n <= 0) break;
            buffer_valid += static_cast<std::size_t>(n);
        }

        if (buffer_valid == 0) {
            break;
        }

        const std::size_t chunk_len = cut_point(buffer.data(), buffer_valid);
        const std::string hash = mc::sha256_data(buffer.data(), chunk_len);
        ChunkInfo info{total_offset, static_cast<std::uint64_t>(chunk_len), hash};
        callback(info, buffer.data());

        total_offset += chunk_len;
        const std::size_t remaining = buffer_valid - chunk_len;
        if (remaining > 0) {
            std::memmove(buffer.data(), buffer.data() + chunk_len, remaining);
        }
        buffer_valid = remaining;
    }
}

FixedChunker::FixedChunker(std::uint32_t chunk_size) : chunk_size_(chunk_size) {
    if (chunk_size_ == 0) {
        throw std::invalid_argument("chunk_size must be > 0");
    }
}

std::vector<ChunkInfo> FixedChunker::chunk_buffer(const void* data, std::size_t size) const {
    std::vector<ChunkInfo> chunks;
    if (size == 0 || data == nullptr) {
        return chunks;
    }

    const auto* byte_ptr = static_cast<const std::uint8_t*>(data);
    std::size_t offset = 0;

    while (offset < size) {
        const std::size_t remaining = size - offset;
        const std::size_t chunk_len = std::min(static_cast<std::size_t>(chunk_size_), remaining);
        const std::string hash = mc::sha256_data(byte_ptr + offset, chunk_len);

        chunks.push_back(ChunkInfo{
            static_cast<std::uint64_t>(offset),
            static_cast<std::uint64_t>(chunk_len),
            hash
        });

        offset += chunk_len;
    }

    return chunks;
}

std::vector<ChunkInfo> FixedChunker::chunk_file(const fs::path& path) const {
    std::vector<ChunkInfo> chunks;
    chunk_file_stream(path, [&chunks](const ChunkInfo& info, const std::uint8_t* /*data*/) {
        chunks.push_back(info);
    });
    return chunks;
}

std::vector<ChunkInfo> FixedChunker::chunk_stream(std::istream& stream) const {
    std::vector<std::uint8_t> buffer(std::istreambuf_iterator<char>(stream), {});
    return chunk_buffer(buffer.data(), buffer.size());
}

void FixedChunker::chunk_file_stream(const fs::path& path, const ChunkCallback& callback) const {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot open file for fixed chunking: " + path.string());
    }

    std::vector<std::uint8_t> buffer(chunk_size_);
    std::uint64_t total_offset = 0;

    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = static_cast<std::size_t>(in.gcount());
        if (count == 0) break;

        const std::string hash = mc::sha256_data(buffer.data(), count);
        ChunkInfo info{total_offset, static_cast<std::uint64_t>(count), hash};
        callback(info, buffer.data());

        total_offset += count;
    }
}

} // namespace mc::cas
