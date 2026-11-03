#include "merklechain/cas/object_store.hpp"
#include "merklechain/hash.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <atomic>
#include <chrono>
#include <fstream>
#include <random>
#include <array>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace mc::cas {

namespace {
std::atomic<CasFaultPointForTesting> g_cas_fault_point{CasFaultPointForTesting::None};

bool atomic_replace_file(const fs::path& src, const fs::path& dst, std::string& err) {
#ifdef _WIN32
    if (!MoveFileExW(src.wstring().c_str(), dst.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD gle = GetLastError();
        err = "MoveFileExW error: " + std::to_string(gle);
        return false;
    }
    return true;
#else
    if (::rename(src.c_str(), dst.c_str()) != 0) {
        err = "rename error: " + std::to_string(errno);
        return false;
    }
    return true;
#endif
}
}

void set_cas_fault_point_for_testing(CasFaultPointForTesting point) {
    g_cas_fault_point.store(point);
}

CasFaultPointForTesting get_cas_fault_point_for_testing() {
    return g_cas_fault_point.load();
}

ObjectStore::ObjectStore(ObjectStoreConfig config) : config_(std::move(config)) {
    objects_dir_ = config_.root_path / "objects";
    tmp_dir_ = config_.root_path / ".tmp";
}

bool ObjectStore::is_valid_hex_hash(const std::string& hash) {
    if (hash.size() != 64) return false;
    for (char c : hash) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool ObjectStore::initialize(std::string& err) {
    std::error_code ec;
    fs::create_directories(objects_dir_, ec);
    if (ec) {
        err = "Failed to create CAS objects directory: " + ec.message();
        return false;
    }

    fs::create_directories(tmp_dir_, ec);
    if (ec) {
        err = "Failed to create CAS temp directory: " + ec.message();
        return false;
    }

    // Clean any lingering temp files from previous process runs or crashes
    clean_temp_directory(&err);
    return true;
}

fs::path ObjectStore::object_path(const ChunkHash& hash) const {
    if (!is_valid_hex_hash(hash)) {
        throw std::invalid_argument("Invalid chunk hash (malformed or path traversal attempt): " + hash);
    }
    const std::uint32_t prefix_len = std::min(config_.shard_prefix_len, static_cast<std::uint32_t>(hash.size()));
    const std::string prefix = hash.substr(0, prefix_len);
    return objects_dir_ / prefix / hash;
}

fs::path ObjectStore::generate_temp_path() const {
#ifdef _WIN32
    const unsigned long pid = ::GetCurrentProcessId();
#else
    const auto pid = ::getpid();
#endif
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::array<unsigned char, 8> rand_bytes{};
    if (RAND_bytes(rand_bytes.data(), static_cast<int>(rand_bytes.size())) != 1) {
        // Fallback to random device
        std::random_device rd;
        for (auto& b : rand_bytes) b = static_cast<unsigned char>(rd() & 0xFF);
    }
    return tmp_dir_ / ("obj_tmp_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + mc::to_hex(rand_bytes.data(), rand_bytes.size()) + ".tmp");
}

bool ObjectStore::has_object(const ChunkHash& hash) const {
    if (!is_valid_hex_hash(hash)) return false;
    const fs::path p = object_path(hash);
    std::error_code ec;
    return fs::exists(p, ec) && fs::is_regular_file(p, ec);
}

std::uintmax_t ObjectStore::object_size(const ChunkHash& hash) const {
    if (!is_valid_hex_hash(hash)) return 0;
    const fs::path p = object_path(hash);
    std::error_code ec;
    return fs::file_size(p, ec);
}

PutResult ObjectStore::put_object(const void* data, std::size_t size, const std::string& expected_hash) {
    if (data == nullptr && size > 0) {
        return {PutResultStatus::IoError, "", 0, "Null data buffer with non-zero size"};
    }

    // Determine and verify hash
    std::string actual_hash = mc::sha256_data(data, size);
    if (!expected_hash.empty() && expected_hash != actual_hash) {
        return {PutResultStatus::HashMismatch, actual_hash, size,
                "Provided expected hash " + expected_hash + " did not match content hash " + actual_hash};
    }

    // Deduplication check: if object is already stored, return immediately
    const fs::path dest_path = object_path(actual_hash);
    std::error_code ec;

    auto verify_existing_dest = [&](const fs::path& target, bool& out_confirmed_corrupt) -> bool {
        out_confirmed_corrupt = false;
        std::error_code check_ec;
        if (!fs::exists(target, check_ec) || !fs::is_regular_file(target, check_ec)) {
            return false;
        }
        const auto fsz = fs::file_size(target, check_ec);
        if (check_ec) {
            return false;
        }
        if (fsz != size) {
            out_confirmed_corrupt = true;
            return false;
        }
        if (!config_.verify_on_read) {
            return true;
        }
        for (int attempt = 0; attempt < 5; ++attempt) {
            try {
                std::uintmax_t existing_bytes = 0;
                const std::string existing_hash = mc::sha256_file(target, &existing_bytes);
                if (existing_hash == actual_hash && existing_bytes == size) {
                    return true;
                } else {
                    out_confirmed_corrupt = true;
                    return false;
                }
            } catch (const std::exception&) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
        return true;
    };

    bool is_corrupt = false;
    if (verify_existing_dest(dest_path, is_corrupt)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++deduplicated_puts_;
        return {PutResultStatus::AlreadyExists, actual_hash, size, ""};
    }
    if (is_corrupt) {
        fs::remove(dest_path, ec);
    }

    // Write object through a unique temporary file on the same filesystem
    const fs::path tmp_path = generate_temp_path();
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return {PutResultStatus::IoError, actual_hash, size, "Failed to create temp file: " + tmp_path.string()};
        }
        if (size > 0) {
            if (g_cas_fault_point.load() == CasFaultPointForTesting::CrashDuringTempWrite) {
                const std::size_t partial = size / 2;
                if (partial > 0) {
                    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(partial));
                    out.flush();
                }
#ifdef MERKLECHAIN_TESTING
                std::_Exit(91);
#else
                return {PutResultStatus::IoError, actual_hash, size, "Injected fault: CrashDuringTempWrite"};
#endif
            }
            out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
            out.flush();
            if (!out) {
                fs::remove(tmp_path, ec);
                return {PutResultStatus::IoError, actual_hash, size, "Failed to write object data to temp file"};
            }
        }
    }

    // Verify written data before promoting
    if (config_.verify_on_write) {
        std::uintmax_t read_bytes = 0;
        try {
            const std::string written_hash = mc::sha256_file(tmp_path, &read_bytes);
            if (written_hash != actual_hash || read_bytes != size) {
                fs::remove(tmp_path, ec);
                return {PutResultStatus::HashMismatch, actual_hash, size, "Verification on write failed for temp object"};
            }
        } catch (const std::exception& e) {
            fs::remove(tmp_path, ec);
            return {PutResultStatus::IoError, actual_hash, size, "Verification on write failed: " + std::string(e.what())};
        }
    }

    if (g_cas_fault_point.load() == CasFaultPointForTesting::CrashBeforePromotion) {
#ifdef MERKLECHAIN_TESTING
        std::_Exit(92);
#else
        return {PutResultStatus::IoError, actual_hash, size, "Injected fault: CrashBeforePromotion"};
#endif
    }

    // Ensure parent shard directory exists
    fs::create_directories(dest_path.parent_path(), ec);
    if (ec) {
        fs::remove(tmp_path, ec);
        return {PutResultStatus::IoError, actual_hash, size, "Failed to create shard directory: " + ec.message()};
    }

    // Atomic move to final object location
    fs::rename(tmp_path, dest_path, ec);
    if (ec) {
        // If rename failed because another concurrent process/thread created it in the meantime, handle cleanly
        bool rename_corrupt = false;
        if (verify_existing_dest(dest_path, rename_corrupt)) {
            fs::remove(tmp_path, ec);
            std::lock_guard<std::mutex> lock(stats_mutex_);
            ++deduplicated_puts_;
            return {PutResultStatus::AlreadyExists, actual_hash, size, ""};
        } else if (rename_corrupt) {
            // If the object at dest_path was corrupt, heal it by atomic replacement without deletion gap
            std::string repl_err;
            bool replaced = false;
            for (int attempt = 0; attempt < 3; ++attempt) {
                if (atomic_replace_file(tmp_path, dest_path, repl_err)) {
                    replaced = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            if (replaced) {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                ++new_puts_;
                return {PutResultStatus::StoredNew, actual_hash, size, ""};
            }
            // Check if another concurrent worker healed it in the meantime
            if (verify_existing_dest(dest_path, rename_corrupt)) {
                fs::remove(tmp_path, ec);
                std::lock_guard<std::mutex> lock(stats_mutex_);
                ++deduplicated_puts_;
                return {PutResultStatus::AlreadyExists, actual_hash, size, ""};
            }
        }
        fs::remove(tmp_path, ec);
        return {PutResultStatus::IoError, actual_hash, size, "Failed to move temp object to CAS store: " + ec.message()};
    }

    if (g_cas_fault_point.load() == CasFaultPointForTesting::CrashAfterPromotion) {
#ifdef MERKLECHAIN_TESTING
        std::_Exit(93);
#else
        return {PutResultStatus::StoredNew, actual_hash, size, "Injected fault: CrashAfterPromotion"};
#endif
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++new_puts_;
    }

    return {PutResultStatus::StoredNew, actual_hash, size, ""};
}

bool ObjectStore::get_object(const ChunkHash& hash, std::vector<std::uint8_t>& out_data) const {
    out_data.clear();
    if (!is_valid_hex_hash(hash)) return false;

    const fs::path p = object_path(hash);
    std::error_code ec;
    if (!fs::exists(p, ec) || !fs::is_regular_file(p, ec)) {
        return false;
    }

    const auto fsize = fs::file_size(p, ec);
    if (ec) return false;

    std::ifstream in(p, std::ios::binary);
    if (!in) return false;

    out_data.resize(static_cast<std::size_t>(fsize));
    if (fsize > 0) {
        in.read(reinterpret_cast<char*>(out_data.data()), static_cast<std::streamsize>(fsize));
        if (static_cast<std::size_t>(in.gcount()) != fsize) {
            out_data.clear();
            return false;
        }
    }

    if (config_.verify_on_read) {
        const std::string read_hash = mc::sha256_data(out_data.data(), out_data.size());
        if (read_hash != hash) {
            out_data.clear();
            return false;
        }
    }

    return true;
}

bool ObjectStore::reconstruct_file(const FileManifest& manifest, const fs::path& destination_path, std::string& err, bool verify_whole_file) const {
    if (!manifest.validate(err)) {
        return false;
    }

    std::error_code ec;
    fs::create_directories(destination_path.parent_path(), ec);
    if (ec) {
        err = "Failed to create destination directory: " + ec.message();
        return false;
    }

    // MANDATORY REQUIREMENT: Working-copy files must never be hard-linked to immutable CAS objects!
    // We write chunk data through an atomic local staging file.
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path staging_path = destination_path.parent_path() / ("." + destination_path.filename().string() + ".reconstruct." + std::to_string(now_ns) + ".tmp");

    std::ofstream out(staging_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "Failed to create staging file for reconstruction: " + staging_path.string();
        return false;
    }

    // Initialize whole-file SHA-256 context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        out.close();
        fs::remove(staging_path, ec);
        err = "Failed to allocate OpenSSL digest context";
        return false;
    }
    struct EvpGuard { EVP_MD_CTX* p; ~EvpGuard(){ EVP_MD_CTX_free(p); } } guard{ctx};
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        out.close();
        fs::remove(staging_path, ec);
        err = "Failed to initialize OpenSSL SHA-256";
        return false;
    }

    std::vector<std::uint8_t> chunk_buffer;
    for (std::size_t i = 0; i < manifest.chunks().size(); ++i) {
        const auto& c = manifest.chunks()[i];
        if (!get_object(c.hash, chunk_buffer)) {
            out.close();
            fs::remove(staging_path, ec);
            err = "Missing or corrupted chunk in CAS store at index " + std::to_string(i) + " (" + c.hash + ")";
            return false;
        }
        if (chunk_buffer.size() != c.size) {
            out.close();
            fs::remove(staging_path, ec);
            err = "Chunk size mismatch for " + c.hash + ": expected " + std::to_string(c.size) + ", read " + std::to_string(chunk_buffer.size());
            return false;
        }

        if (c.size > 0) {
            out.write(reinterpret_cast<const char*>(chunk_buffer.data()), static_cast<std::streamsize>(c.size));
            if (!out) {
                out.close();
                fs::remove(staging_path, ec);
                err = "Failed writing chunk data to staging file";
                return false;
            }
            if (EVP_DigestUpdate(ctx, chunk_buffer.data(), chunk_buffer.size()) != 1) {
                out.close();
                fs::remove(staging_path, ec);
                err = "EVP_DigestUpdate failed during file reconstruction";
                return false;
            }
        }
    }

    out.flush();
    out.close();

    // Finalize whole-file digest
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
        fs::remove(staging_path, ec);
        err = "EVP_DigestFinal_ex failed during file reconstruction";
        return false;
    }
    const std::string reconstructed_sha256 = mc::to_hex(digest.data(), digest_len);

    if (verify_whole_file && reconstructed_sha256 != manifest.file_sha256()) {
        fs::remove(staging_path, ec);
        err = "Reconstructed whole-file SHA-256 (" + reconstructed_sha256 + ") does not match manifest (" + manifest.file_sha256() + ")";
        return false;
    }

    // Atomically promote staging file to final destination
    std::string move_err;
    if (!atomic_replace_file(staging_path, destination_path, move_err)) {
        bool promoted = false;
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            if (atomic_replace_file(staging_path, destination_path, move_err)) {
                promoted = true;
                break;
            }
        }
        if (!promoted) {
            fs::remove(staging_path, ec);
            err = "Failed promoting staging file to destination: " + move_err;
            return false;
        }
    }

    return true;
}

std::size_t ObjectStore::clean_temp_directory(std::string* err) {
    std::error_code ec;
    std::size_t cleaned_count = 0;
    if (!fs::exists(tmp_dir_, ec)) return 0;

    for (const auto& entry : fs::directory_iterator(tmp_dir_, ec)) {
        if (entry.is_regular_file(ec)) {
            if (fs::remove(entry.path(), ec)) {
                ++cleaned_count;
            } else if (err && err->empty()) {
                *err = "Failed to remove temp file: " + entry.path().string() + " (" + ec.message() + ")";
            }
        }
    }
    return cleaned_count;
}

StoreStats ObjectStore::compute_stats() const {
    StoreStats stats;
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats.deduplicated_puts = deduplicated_puts_;
        stats.new_puts = new_puts_;
    }

    std::error_code ec;
    if (!fs::exists(objects_dir_, ec)) return stats;

    for (const auto& shard : fs::directory_iterator(objects_dir_, ec)) {
        if (shard.is_directory(ec)) {
            for (const auto& obj : fs::directory_iterator(shard.path(), ec)) {
                if (obj.is_regular_file(ec)) {
                    ++stats.total_objects;
                    stats.total_bytes += fs::file_size(obj.path(), ec);
                }
            }
        }
    }

    return stats;
}

} // namespace mc::cas
