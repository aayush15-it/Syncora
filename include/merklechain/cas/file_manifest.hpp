#pragma once

#include "merklechain/cas/cas_types.hpp"
#include <string>
#include <vector>

namespace mc::cas {

class FileManifest {
public:
    static constexpr std::uint32_t kCurrentVersion = 1;

    FileManifest() = default;
    FileManifest(std::uint64_t total_size, std::string file_sha256, std::vector<ChunkInfo> chunks)
        : version_(kCurrentVersion), total_size_(total_size), file_sha256_(std::move(file_sha256)), chunks_(std::move(chunks)) {}

    std::uint32_t version() const { return version_; }
    void set_version(std::uint32_t v) { version_ = v; }

    std::uint64_t total_size() const { return total_size_; }
    void set_total_size(std::uint64_t s) { total_size_ = s; }

    const std::string& file_sha256() const { return file_sha256_; }
    void set_file_sha256(std::string hash) { file_sha256_ = std::move(hash); }

    const std::vector<ChunkInfo>& chunks() const { return chunks_; }
    std::vector<ChunkInfo>& chunks() { return chunks_; }
    void set_chunks(std::vector<ChunkInfo> chunks) {
        chunks_ = std::move(chunks);
        total_size_ = 0;
        for (const auto& c : chunks_) {
            total_size_ += c.size;
        }
    }

    std::size_t chunk_count() const { return chunks_.size(); }
    bool is_empty() const { return total_size_ == 0 && chunks_.empty(); }

    void add_chunk(ChunkInfo chunk) {
        total_size_ += chunk.size;
        chunks_.push_back(std::move(chunk));
    }

    void clear() {
        total_size_ = 0;
        file_sha256_ = kEmptySha256;
        chunks_.clear();
    }

    bool validate(std::string& err) const;

    bool operator==(const FileManifest& other) const {
        return version_ == other.version_ &&
               total_size_ == other.total_size_ &&
               file_sha256_ == other.file_sha256_ &&
               chunks_ == other.chunks_;
    }

    bool operator!=(const FileManifest& other) const {
        return !(*this == other);
    }

private:
    std::uint32_t version_{kCurrentVersion};
    std::uint64_t total_size_{0};
    std::string file_sha256_{kEmptySha256};
    std::vector<ChunkInfo> chunks_;
};

} // namespace mc::cas

