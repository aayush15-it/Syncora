#include "merklechain/cas/object_verifier.hpp"
#include "merklechain/hash.hpp"

namespace mc::cas {

ObjectVerificationResult ObjectVerifier::verify_object(const fs::path& object_path, const ChunkHash& expected_hash, std::uintmax_t expected_size) {
    ObjectVerificationResult res;
    res.hash = expected_hash;
    res.path = object_path;
    res.expected_size = expected_size;

    std::error_code ec;
    if (!fs::exists(object_path, ec) || !fs::is_regular_file(object_path, ec)) {
        res.valid = false;
        res.error = "Object file does not exist or is not a regular file";
        return res;
    }

    res.actual_size = fs::file_size(object_path, ec);
    if (ec) {
        res.valid = false;
        res.error = "Failed to query object file size: " + ec.message();
        return res;
    }

    if (expected_size > 0 && res.actual_size != expected_size) {
        res.valid = false;
        res.error = "Size mismatch: expected " + std::to_string(expected_size) + ", got " + std::to_string(res.actual_size);
        return res;
    }

    try {
        std::uintmax_t bytes_read = 0;
        res.actual_hash = mc::sha256_file(object_path, &bytes_read);
        if (res.actual_hash != expected_hash) {
            res.valid = false;
            res.error = "Hash mismatch: expected " + expected_hash + ", got " + res.actual_hash;
            return res;
        }
        res.valid = true;
    } catch (const std::exception& e) {
        res.valid = false;
        res.error = std::string("Hashing exception: ") + e.what();
    }

    return res;
}

StoreVerificationReport ObjectVerifier::verify_store(const ObjectStore& store) {
    StoreVerificationReport report;
    std::error_code ec;

    const fs::path obj_dir = store.objects_dir();
    if (!fs::exists(obj_dir, ec)) {
        return report;
    }

    for (const auto& shard : fs::directory_iterator(obj_dir, ec)) {
        if (shard.is_directory(ec)) {
            for (const auto& obj : fs::directory_iterator(shard.path(), ec)) {
                if (obj.is_regular_file(ec)) {
                    ++report.total_objects;
                    const auto fsize = fs::file_size(obj.path(), ec);
                    report.total_bytes += fsize;

                    const std::string expected_hash = obj.path().filename().string();
                    auto vres = verify_object(obj.path(), expected_hash, fsize);
                    if (vres.valid) {
                        ++report.valid_objects;
                    } else {
                        ++report.corrupt_objects;
                        report.failures.push_back(vres);
                    }
                }
            }
        }
    }

    // Check temp directory for orphans
    const fs::path tmp_dir = store.tmp_dir();
    if (fs::exists(tmp_dir, ec)) {
        for (const auto& tmp_entry : fs::directory_iterator(tmp_dir, ec)) {
            if (tmp_entry.is_regular_file(ec)) {
                ++report.orphaned_temp_files;
            }
        }
    }

    return report;
}

bool ObjectVerifier::verify_file_chunks(const ObjectStore& store, const FileManifest& manifest, std::string& err) {
    for (std::size_t i = 0; i < manifest.chunks().size(); ++i) {
        const auto& c = manifest.chunks()[i];
        if (!store.has_object(c.hash)) {
            err = "Chunk " + std::to_string(i) + " (" + c.hash + ") missing from store";
            return false;
        }
        const fs::path opath = store.object_path(c.hash);
        auto res = verify_object(opath, c.hash, c.size);
        if (!res.valid) {
            err = "Chunk " + std::to_string(i) + " (" + c.hash + ") failed verification: " + res.error;
            return false;
        }
    }
    return true;
}

} // namespace mc::cas

