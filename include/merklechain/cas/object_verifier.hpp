#pragma once

#include "merklechain/cas/cas_types.hpp"
#include "merklechain/cas/object_store.hpp"
#include <string>
#include <vector>

namespace mc::cas {

struct ObjectVerificationResult {
    ChunkHash hash;
    fs::path path;
    bool valid{false};
    std::uintmax_t expected_size{0};
    std::uintmax_t actual_size{0};
    std::string actual_hash;
    std::string error;
};

struct StoreVerificationReport {
    std::uint64_t total_objects{0};
    std::uint64_t valid_objects{0};
    std::uint64_t corrupt_objects{0};
    std::uint64_t orphaned_temp_files{0};
    std::uint64_t total_bytes{0};
    std::vector<ObjectVerificationResult> failures;

    bool is_healthy() const {
        return corrupt_objects == 0 && failures.empty();
    }
};

class ObjectVerifier {
public:
    // Verify a single object on disk against its expected hash and optional expected size
    static ObjectVerificationResult verify_object(const fs::path& object_path, const ChunkHash& expected_hash, std::uintmax_t expected_size = 0);

    // Audit the entire object store, verifying every stored object matches its content SHA-256
    static StoreVerificationReport verify_store(const ObjectStore& store);

    // Verify all chunks referenced in a file manifest exist in the store and are intact
    static bool verify_file_chunks(const ObjectStore& store, const FileManifest& manifest, std::string& err);
};

} // namespace mc::cas

