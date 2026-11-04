#pragma once

#include "merklechain/cas/cas_types.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace mc::cas {

namespace fs = std::filesystem;

enum class CasFaultPointForTesting {
    None,
    CrashDuringTempWrite,
    CrashBeforePromotion,
    CrashAfterPromotion
};

void set_cas_fault_point_for_testing(CasFaultPointForTesting point);
CasFaultPointForTesting get_cas_fault_point_for_testing();

enum class ObjectAvailability {
    AvailableValid,
    Missing,
    Corrupt,
    InvalidHash,
    IoError
};

struct ObjectStatus {
    ObjectAvailability availability{ObjectAvailability::Missing};
    std::uintmax_t size{0};
    std::string actual_hash;
    std::string error;

    bool is_available_and_valid() const noexcept {
        return availability == ObjectAvailability::AvailableValid;
    }
};

struct ObjectStoreConfig {
    fs::path root_path;
    bool verify_on_write{true};
    bool verify_on_read{true};
    std::uint32_t shard_prefix_len{2}; // 2 hex chars prefix directory, e.g. objects/ab/<64-char-hash>
};

struct StoreStats {
    std::uint64_t total_objects{0};
    std::uint64_t total_bytes{0};
    std::uint64_t deduplicated_puts{0};
    std::uint64_t new_puts{0};
};

class ObjectStore {
public:
    explicit ObjectStore(ObjectStoreConfig config);
    ~ObjectStore() = default;

    // Disallow copy; allow move
    ObjectStore(const ObjectStore&) = delete;
    ObjectStore& operator=(const ObjectStore&) = delete;
    ObjectStore(ObjectStore&&) noexcept = default;
    ObjectStore& operator=(ObjectStore&&) noexcept = default;

    const ObjectStoreConfig& config() const { return config_; }
    const fs::path& root_path() const { return config_.root_path; }
    const fs::path& objects_dir() const { return objects_dir_; }
    const fs::path& tmp_dir() const { return tmp_dir_; }

    // Initialize directory structure and clean stale temp files
    bool initialize(std::string& err);

    // Write chunk data into CAS store. Deduplicates if object already exists.
    PutResult put_object(const void* data, std::size_t size, const std::string& expected_hash = "");

    // Check if an object exists in store and is a valid regular file
    bool has_object(const ChunkHash& hash) const;

    // Cryptographically verifies stored object integrity and returns 5-state ObjectStatus.
    // If expected_size > 0, checks file size first before hashing.
    ObjectStatus verify_object(const ChunkHash& hash, std::uintmax_t expected_size = 0) const;

    // Repairs or stores an object atomically without any deletion gap.
    // Writes to a unique temp file, verifies integrity, and atomically moves/replaces destination.
    PutResult repair_object(const void* data, std::size_t size, const std::string& expected_hash = "");

    // Retrieve object bytes. If verify_on_read is set, validates SHA-256 before returning.
    bool get_object(const ChunkHash& hash, std::vector<std::uint8_t>& out_data) const;

    // Get size of stored object
    std::uintmax_t object_size(const ChunkHash& hash) const;

    // Get filesystem path for an object: objects/<prefix>/<hash>
    fs::path object_path(const ChunkHash& hash) const;

    // Reconstruct whole file from manifest.
    // MANDATORY GUARANTEE: Working copy is never hardlinked to CAS objects!
    // Writes chunk-by-chunk through a staging file and verifies whole-file SHA-256.
    bool reconstruct_file(const FileManifest& manifest, const fs::path& destination_path, std::string& err, bool verify_whole_file = true) const;

    // Clean up abandoned temp files (e.g. from interrupted operations/crashes).
    // Protects in-flight files registered in active_temp_paths_ and files younger than max_age_ms.
    std::size_t clean_temp_directory(std::uint64_t max_age_ms = 0, std::string* err = nullptr);
    std::size_t clean_temp_directory(std::string* err);

    // Temp file ownership registration (thread-safe)
    void register_active_temp(const fs::path& p);
    void unregister_active_temp(const fs::path& p);
    bool is_active_temp(const fs::path& p) const;

    // Remove a single object physically from CAS store
    bool remove_object(const ChunkHash& hash, std::string& err);

    // List all chunk hashes stored physically in CAS store
    std::vector<ChunkHash> list_all_objects(std::string* err = nullptr) const;

    // Process liveness checker helper
    static bool is_process_alive(unsigned long pid);

    // Process liveness and PID reuse checker helper
    static bool is_process_alive_for_file(unsigned long pid, std::int64_t file_ts_ms, bool& out_pid_reused);

    // File lock detection: returns true if the file is held open by a live writer/process
    static bool is_file_locked_by_writer(const fs::path& p);

    // Compute live stats by scanning objects directory
    StoreStats compute_stats() const;

    // Check whether a string is a valid lowercase 64-hex SHA-256
    static bool is_valid_hex_hash(const std::string& hash);

private:
    ObjectStoreConfig config_;
    fs::path objects_dir_;
    fs::path tmp_dir_;

    mutable std::mutex stats_mutex_;
    std::uint64_t deduplicated_puts_{0};
    std::uint64_t new_puts_{0};

    mutable std::mutex temp_registry_mutex_;
    std::unordered_set<std::string> active_temp_paths_;

    fs::path generate_temp_path();
};

} // namespace mc::cas

