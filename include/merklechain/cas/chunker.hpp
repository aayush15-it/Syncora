#pragma once

#include "merklechain/cas/cas_types.hpp"
#include <functional>
#include <istream>
#include <memory>
#include <string>
#include <vector>

namespace mc::cas {

struct ChunkerConfig {
    std::uint32_t min_size{4096};         // 4 KB minimum chunk size
    std::uint32_t avg_size{16384};        // 16 KB average target chunk size
    std::uint32_t max_size{65536};        // 64 KB maximum chunk size
    std::uint32_t normalization_level{1}; // 1 or 2 (FastCDC dual-mask normalization)

    bool validate(std::string& err) const {
        if (min_size == 0) {
            err = "min_size must be > 0";
            return false;
        }
        if (min_size > avg_size) {
            err = "min_size must be <= avg_size";
            return false;
        }
        if (avg_size > max_size) {
            err = "avg_size must be <= max_size";
            return false;
        }
        if (normalization_level == 0 || normalization_level > 3) {
            err = "normalization_level must be 1, 2, or 3";
            return false;
        }
        return true;
    }
};

using ChunkCallback = std::function<void(const ChunkInfo& info, const std::uint8_t* data)>;

class IChunker {
public:
    virtual ~IChunker() = default;

    virtual std::vector<ChunkInfo> chunk_buffer(const void* data, std::size_t size) const = 0;
    virtual std::vector<ChunkInfo> chunk_file(const fs::path& path) const = 0;
    virtual std::vector<ChunkInfo> chunk_stream(std::istream& stream) const = 0;

    // Streaming chunking with zero-copy/low-memory callback
    virtual void chunk_file_stream(const fs::path& path, const ChunkCallback& callback) const = 0;
};

class FastCDCChunker : public IChunker {
public:
    explicit FastCDCChunker(ChunkerConfig config = ChunkerConfig{});

    const ChunkerConfig& config() const { return config_; }

    std::vector<ChunkInfo> chunk_buffer(const void* data, std::size_t size) const override;
    std::vector<ChunkInfo> chunk_file(const fs::path& path) const override;
    std::vector<ChunkInfo> chunk_stream(std::istream& stream) const override;
    void chunk_file_stream(const fs::path& path, const ChunkCallback& callback) const override;

    // Cut-point determination for a data slice starting at index 0.
    // Returns chunk length in bytes (between min_size and min(max_size, length)).
    std::size_t cut_point(const std::uint8_t* data, std::size_t length) const;

private:
    ChunkerConfig config_;
    std::uint64_t mask_s_{0}; // strict mask for [min, avg)
    std::uint64_t mask_l_{0}; // loose mask for [avg, max)

    void init_masks();
};

class FixedChunker : public IChunker {
public:
    explicit FixedChunker(std::uint32_t chunk_size = 16384);

    std::uint32_t chunk_size() const { return chunk_size_; }

    std::vector<ChunkInfo> chunk_buffer(const void* data, std::size_t size) const override;
    std::vector<ChunkInfo> chunk_file(const fs::path& path) const override;
    std::vector<ChunkInfo> chunk_stream(std::istream& stream) const override;
    void chunk_file_stream(const fs::path& path, const ChunkCallback& callback) const override;

private:
    std::uint32_t chunk_size_{16384};
};

} // namespace mc::cas

