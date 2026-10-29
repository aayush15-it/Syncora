#pragma once

#include "merklechain/types.hpp"
#include <cstddef>
#include <memory>

namespace mc {

// Owns a newly-created sibling staging file. On Windows the entry is created
// atomically with CREATE_NEW, retained open without write/delete sharing, and
// renamed or deleted through that same handle.
class StagingFile {
public:
    explicit StagingFile(fs::path path);
    ~StagingFile();
    StagingFile(const StagingFile&) = delete;
    StagingFile& operator=(const StagingFile&) = delete;
    StagingFile(StagingFile&&) noexcept;
    StagingFile& operator=(StagingFile&&) noexcept;

    const fs::path& path() const noexcept;
    void reset();
    void write(const void* data, std::size_t size);
    void flush();
    std::uintmax_t size() const;
    std::uintmax_t bytes_written() const noexcept;
    std::string sha256();
    std::string sha256_range(std::uintmax_t offset, std::uintmax_t length);
    void commit_to(const fs::path& target, const std::string& expected_sha256);
    void move_failed_commit_to(const fs::path& quarantine);
    void keep() noexcept;
    bool discard() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

void copy_file_to_staging(const fs::path& source, StagingFile& staging,
                          const std::string& expected_sha256,
                          std::uintmax_t* source_bytes_read=nullptr);

} // namespace mc
