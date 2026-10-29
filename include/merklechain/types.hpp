#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace mc {
namespace fs = std::filesystem;
enum class Operation { Add, Modify, Delete, Unchanged, Preserve };
enum class JobState { Planned, PendingApproval, InProgress, SucceededVerified, Failed, Cancelled, Interrupted, Skipped };
struct FileMetadata {
    std::string relative_path;
    std::uintmax_t size{};
    std::int64_t modified_ticks{};
    std::string sha256;
};
struct FileManifest {
    std::vector<FileMetadata> files;
    std::string merkle_root;
    std::vector<std::string> warnings;
    bool complete{true};
};
struct SyncJob {
    std::string id;
    Operation operation{};
    fs::path source;
    fs::path destination;
    std::string relative_path;
    std::string content_hash;
    std::string expected_destination_hash;
    int priority{};
    std::chrono::system_clock::time_point enqueued_at{std::chrono::system_clock::now()};
    JobState state{JobState::Planned};
    std::string error;
    bool verified{false};
    std::int64_t started_at_ms{};
    std::int64_t completed_at_ms{};
    std::uintmax_t bytes_transferred{};
    std::uintmax_t source_bytes_processed{};
    std::uintmax_t bytes_reused{};
    std::uintmax_t bytes_written{};
    std::uintmax_t chunk_size_bytes{};
    std::size_t chunks_total{};
    std::size_t chunks_reused{};
    bool chunked_transfer{false};
    std::string transfer_fallback_reason;
};
struct VersionRecord {
    std::string id;
    std::string parent_id;
    std::string snapshot_reference;
    std::int64_t timestamp{};
    std::vector<std::string> changed_files;
    std::string integrity_hash;
};
struct PeerRecord {
    std::string device_id;
    std::string display_name;
    std::string role;
    bool paired{false};
    std::vector<std::string> authorized_folders;
};
struct FileActivityRecord {
    std::string job_id, relative_path, source, destination, operation, content_hash;
    std::uintmax_t bytes{};
    std::int64_t started{}, completed{};
    std::string result, error;
};
} // namespace mc
