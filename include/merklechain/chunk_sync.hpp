#pragma once

#include "merklechain/types.hpp"
#include "merklechain/staging_file.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace mc {

inline constexpr std::uint32_t kChunkManifestVersion = 1;
inline constexpr std::uintmax_t kDefaultChunkSize = 1024U * 1024U;

struct ChunkDescriptor {
    std::uintmax_t offset{};
    std::uintmax_t size{};
    std::string sha256;
};

// Ephemeral local manifest. It is regenerated from disk and is not persisted.
struct ChunkManifest {
    std::uint32_t format_version{kChunkManifestVersion};
    std::uintmax_t chunk_size{kDefaultChunkSize};
    std::uintmax_t file_size{};
    std::string file_sha256;
    std::vector<ChunkDescriptor> chunks;
};

struct ChunkTransferResult {
    bool used_chunks{false};
    std::uintmax_t bytes_transferred{};
    std::uintmax_t source_bytes_processed{};
    std::uintmax_t reused_bytes{};
    std::uintmax_t bytes_written{};
    std::size_t chunk_count{};
    std::size_t reused_chunks{};
    std::string fallback_reason;
};

ChunkManifest build_chunk_manifest(const fs::path& file,
                                   std::uintmax_t chunk_size=kDefaultChunkSize,
                                   std::uintmax_t* source_bytes_processed=nullptr);

// Produces a complete staged file. Equal verified chunks may be read from the
// destination; all other bytes come from source. Any unusable chunk metadata or
// reconstruction failure retries through a whole-file copy and full SHA-256.
ChunkTransferResult copy_file_chunked_or_fallback(
    const fs::path& source, const fs::path& current_destination,
    StagingFile& staging, const std::string& expected_source_sha256,
    const std::string& expected_destination_sha256,
    std::uintmax_t chunk_size=kDefaultChunkSize);

#ifdef MERKLECHAIN_TESTING
enum class ChunkFaultPointForTesting {
    None,
    CorruptFirstChunk,
    TruncateFirstChunk,
    ChangeSourceAfterFirstChunk,
    MissingSourceManifest,
    IncompatibleSourceManifest,
    MissingChunkDescriptor,
    OverlappingChunkRange,
    IncorrectFinalChunkLength,
    InvalidChunkHash
};
void set_chunk_fault_point_for_testing(ChunkFaultPointForTesting point);
#endif

} // namespace mc
