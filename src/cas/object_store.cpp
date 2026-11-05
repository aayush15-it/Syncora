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
#include <csignal>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace mc::cas {

namespace {
std::atomic<CasFaultPointForTesting> g_cas_fault_point{CasFaultPointForTesting::None};

std::vector<std::string> split_str(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        tokens.push_back(item);
    }
    return tokens;
}

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

    // Clean any lingering temp files from previous process runs or crashes (0 age = only dead processes)
    clean_temp_directory(0, &err);
    return true;
}

bool ObjectStore::is_process_alive(unsigned long pid) {
    bool unused = false;
    return is_process_alive_for_file(pid, 0, unused);
}

bool ObjectStore::is_process_alive_for_file(unsigned long pid, std::int64_t file_ts_ms, bool& out_pid_reused) {
    out_pid_reused = false;
    if (pid == 0) return false;
#ifdef _WIN32
    const bool is_self = (pid == ::GetCurrentProcessId());
    HANDLE h = is_self ? ::GetCurrentProcess() : ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        DWORD err = ::GetLastError();
        if (err == ERROR_ACCESS_DENIED) return true;
        return false;
    }
    DWORD exit_code = 0;
    BOOL ok = is_self ? TRUE : ::GetExitCodeProcess(h, &exit_code);
    if (!ok || (!is_self && exit_code != STILL_ACTIVE)) {
        if (!is_self) ::CloseHandle(h);
        return false;
    }
    // Process is alive. Check creation time to detect PID reuse.
    FILETIME creation_ft, exit_ft, kernel_ft, user_ft;
    if (file_ts_ms > 0 && ::GetProcessTimes(h, &creation_ft, &exit_ft, &kernel_ft, &user_ft)) {
        ULARGE_INTEGER uli;
        uli.LowPart = creation_ft.dwLowDateTime;
        uli.HighPart = creation_ft.dwHighDateTime;
        constexpr std::uint64_t EPOCH_DIFF = 116444736000000000ULL;
        if (uli.QuadPart >= EPOCH_DIFF) {
            std::uint64_t proc_start_ms = (uli.QuadPart - EPOCH_DIFF) / 10000ULL;
            // 2000ms clock skew/resolution margin
            if (proc_start_ms > static_cast<std::uint64_t>(file_ts_ms) + 2000ULL) {
                out_pid_reused = true;
                if (!is_self) ::CloseHandle(h);
                return false; // Reused PID: original creating process has terminated!
            }
        }
    }
    if (!is_self) ::CloseHandle(h);
    return true;
#else
    if (pid == static_cast<unsigned long>(::getpid())) return true;
    if (::kill(static_cast<pid_t>(pid), 0) == 0) return true;
    return (errno == EPERM);
#endif
}

bool ObjectStore::is_file_locked_by_writer(const fs::path& p) {
#ifdef _WIN32
    HANDLE h = ::CreateFileW(
        p.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // Exclusive access (no sharing permitted)
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = ::GetLastError();
        if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION || err == ERROR_ACCESS_DENIED) {
            return true; // File is held open by an active writer or reader
        }
        return false;
    }
    ::CloseHandle(h);
    return false;
#else
    int fd = ::open(p.c_str(), O_RDWR);
    if (fd < 0) {
        if (errno == EACCES || errno == EAGAIN || errno == EBUSY) return true;
        return false;
    }
    struct flock fl{};
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    int res = ::fcntl(fd, F_GETLK, &fl);
    ::close(fd);
    if (res == 0 && fl.l_type != F_UNLCK) return true;
    return false;
#endif
}

void ObjectStore::register_active_temp(const fs::path& p) {
    std::lock_guard<std::mutex> lk(temp_registry_mutex_);
    active_temp_paths_.insert(p.string());
}

void ObjectStore::unregister_active_temp(const fs::path& p) {
    std::lock_guard<std::mutex> lk(temp_registry_mutex_);
    active_temp_paths_.erase(p.string());
}

bool ObjectStore::is_active_temp(const fs::path& p) const {
    std::lock_guard<std::mutex> lk(temp_registry_mutex_);
    return active_temp_paths_.find(p.string()) != active_temp_paths_.end();
}

fs::path ObjectStore::object_path(const ChunkHash& hash) const {
    if (!is_valid_hex_hash(hash)) {
        throw std::invalid_argument("Invalid chunk hash (malformed or path traversal attempt): " + hash);
    }
    const std::uint32_t prefix_len = std::min(config_.shard_prefix_len, static_cast<std::uint32_t>(hash.size()));
    const std::string prefix = hash.substr(0, prefix_len);
    return objects_dir_ / prefix / hash;
}

fs::path ObjectStore::generate_temp_path() {
#ifdef _WIN32
    const unsigned long pid = ::GetCurrentProcessId();
#else
    const auto pid = static_cast<unsigned long>(::getpid());
#endif
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<unsigned char, 8> rand_bytes{};
    if (RAND_bytes(rand_bytes.data(), static_cast<int>(rand_bytes.size())) != 1) {
        // Fallback to random device
        std::random_device rd;
        for (auto& b : rand_bytes) b = static_cast<unsigned char>(rd() & 0xFF);
    }
    const fs::path p = tmp_dir_ / ("obj_tmp_" + std::to_string(pid) + "_" + std::to_string(now_ms) + "_" + std::to_string(now_ns) + "_" + mc::to_hex(rand_bytes.data(), rand_bytes.size()) + ".tmp");
    register_active_temp(p);
    return p;
}

bool ObjectStore::has_object(const ChunkHash& hash) const {
    if (!is_valid_hex_hash(hash)) return false;
    const fs::path p = object_path(hash);
    std::error_code ec;
    return fs::exists(p, ec) && fs::is_regular_file(p, ec);
}

ObjectStatus ObjectStore::verify_object(const ChunkHash& hash, std::uintmax_t expected_size) const {
    if (!is_valid_hex_hash(hash)) {
        return {ObjectAvailability::InvalidHash, 0, "", "Invalid hex hash format: " + hash};
    }
    const fs::path p = object_path(hash);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        if (ec) {
            return {ObjectAvailability::IoError, 0, "", "Filesystem error checking object: " + ec.message()};
        }
        return {ObjectAvailability::Missing, 0, "", "Object does not exist"};
    }
    if (!fs::is_regular_file(p, ec)) {
        if (ec) {
            return {ObjectAvailability::IoError, 0, "", "Filesystem error checking regular file: " + ec.message()};
        }
        return {ObjectAvailability::Corrupt, 0, "", "Object path is not a regular file"};
    }
    const auto fsz = fs::file_size(p, ec);
    if (ec) {
        return {ObjectAvailability::IoError, 0, "", "Failed to read file size: " + ec.message()};
    }
    if (expected_size > 0 && fsz != expected_size) {
        return {ObjectAvailability::Corrupt, fsz, "", "Object size mismatch: expected " + std::to_string(expected_size) + ", actual " + std::to_string(fsz)};
    }
    try {
        std::uintmax_t read_bytes = 0;
        const std::string actual_hash = mc::sha256_file(p, &read_bytes);
        if (expected_size > 0 && read_bytes != expected_size) {
            return {ObjectAvailability::Corrupt, read_bytes, actual_hash, "Read bytes " + std::to_string(read_bytes) + " did not match expected size " + std::to_string(expected_size)};
        }
        if (actual_hash != hash) {
            return {ObjectAvailability::Corrupt, read_bytes, actual_hash, "Hash mismatch: expected " + hash + ", actual " + actual_hash};
        }
        return {ObjectAvailability::AvailableValid, read_bytes, actual_hash, ""};
    } catch (const std::exception& e) {
        return {ObjectAvailability::IoError, fsz, "", "Exception hashing object file: " + std::string(e.what())};
    }
}

PutResult ObjectStore::repair_object(const void* data, std::size_t size, const std::string& expected_hash) {
    return put_object(data, size, expected_hash);
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
        for (int attempt = 0; attempt < 10; ++attempt) {
            try {
                std::uintmax_t existing_bytes = 0;
                const std::string existing_hash = mc::sha256_file(target, &existing_bytes);
                if (existing_hash == actual_hash && existing_bytes == size) {
                    return true;
                }
            } catch (const std::exception&) {
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        out_confirmed_corrupt = true;
        return false;
    };

    bool is_corrupt = false;
    if (verify_existing_dest(dest_path, is_corrupt)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++deduplicated_puts_;
        return {PutResultStatus::AlreadyExists, actual_hash, size, ""};
    }
    // Do NOT remove dest_path upfront even if corrupt: prevent deletion gaps!
    // Staging into a unique temp file first ensures atomic replacement upon promotion.

    // Write object through a unique temporary file on the same filesystem
    const fs::path tmp_path = generate_temp_path();
    struct ActiveTempGuard {
        ObjectStore& store;
        fs::path p;
        bool promoted{false};
        ~ActiveTempGuard() {
            store.unregister_active_temp(p);
            if (!promoted) {
                std::error_code rm_ec;
                fs::remove(p, rm_ec);
            }
        }
    } temp_guard{*this, tmp_path};
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
                return {PutResultStatus::HashMismatch, actual_hash, size, "Verification on write failed for temp object"};
            }
        } catch (const std::exception& e) {
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
        return {PutResultStatus::IoError, actual_hash, size, "Failed to create shard directory: " + ec.message()};
    }

    // Atomic move/replace to final object location without deletion gap
    std::string repl_err;
    bool promoted = false;
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (atomic_replace_file(tmp_path, dest_path, repl_err)) {
            promoted = true;
            temp_guard.promoted = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (!promoted) {
        // If atomic replacement failed, check if another concurrent process/thread stored it validly
        bool rename_corrupt = false;
        if (verify_existing_dest(dest_path, rename_corrupt)) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            ++deduplicated_puts_;
            return {PutResultStatus::AlreadyExists, actual_hash, size, ""};
        }
        return {PutResultStatus::IoError, actual_hash, size, "Failed to atomically promote temp object to CAS store: " + repl_err};
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
    std::ifstream in;
    std::uintmax_t fsize = 0;
    for (int attempt = 0; attempt < 10; ++attempt) {
        ec.clear();
        if (fs::exists(p, ec) && fs::is_regular_file(p, ec)) {
            fsize = fs::file_size(p, ec);
            if (!ec) {
                in.open(p, std::ios::binary);
                if (in.is_open()) break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    if (!in.is_open()) return false;

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
    // We write chunk data through an atomic local staging file with a compact filename to avoid Windows MAX_PATH exhaustion.
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path staging_path = destination_path.parent_path() / (".rf_" + std::to_string(now_ns) + ".tmp");

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
    return clean_temp_directory(0, err);
}

std::size_t ObjectStore::clean_temp_directory(std::uint64_t max_age_ms, std::string* err) {
    std::error_code ec;
    std::size_t cleaned_count = 0;
    if (!fs::exists(tmp_dir_, ec)) return 0;

    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    for (const auto& entry : fs::directory_iterator(tmp_dir_, ec)) {
        if (!entry.is_regular_file(ec)) continue;

        const fs::path p = entry.path();
        if (is_active_temp(p)) {
            continue; // Active in-memory registered temp file in this process
        }

        const std::string fname = p.filename().string();
        bool can_remove = false;

        if (fname.rfind("obj_tmp_", 0) == 0 && fname.size() > 8) {
            auto parts = split_str(fname, '_');
            // Legacy test format from M3.1 (CAS-OBJ-07): obj_tmp_interrupted_12345.tmp
            if (parts.size() >= 3 && parts[2] == "interrupted") {
                can_remove = !is_file_locked_by_writer(p);
            } else if (parts.size() >= 4) {
                try {
                    std::size_t pid_idx = 0;
                    unsigned long pid = std::stoul(parts[2], &pid_idx);
                    if (pid_idx != parts[2].size() || pid == 0) {
                        // Unparseable or invalid PID -> UNCERTAIN OWNERSHIP -> NEVER delete!
                        can_remove = false;
                    } else {
                        std::size_t ts_idx = 0;
                        std::int64_t file_ts_ms = std::stoll(parts[3], &ts_idx);
                        if (ts_idx != parts[3].size()) {
                            // Unparseable timestamp -> UNCERTAIN OWNERSHIP -> NEVER delete!
                            can_remove = false;
                        } else {
                            bool pid_reused = false;
                            const bool alive = is_process_alive_for_file(pid, file_ts_ms, pid_reused);
                            if (pid_reused) {
                                // Reused PID: creating process terminated!
                                can_remove = true;
                            } else if (!alive) {
                                // Process confirmed dead -> crash debris
                                can_remove = true;
                            } else {
                                // Creating process is ALIVE.
                                // If writer is currently holding an active handle, NEVER delete!
                                if (is_file_locked_by_writer(p)) {
                                    can_remove = false;
                                } else {
                                    // Not locked. If max_age_ms > 0 and expired:
                                    if (max_age_ms > 0 && now_ms >= file_ts_ms &&
                                        static_cast<std::uint64_t>(now_ms - file_ts_ms) >= max_age_ms) {
                                        can_remove = true;
                                    } else {
                                        // Process is alive and within grace window -> protected!
                                        can_remove = false;
                                    }
                                }
                            }
                        }
                    }
                } catch (...) {
                    // Unparseable numbers -> UNCERTAIN OWNERSHIP -> NEVER delete!
                    can_remove = false;
                }
            } else {
                // Not enough parts -> UNCERTAIN OWNERSHIP -> NEVER delete!
                can_remove = false;
            }
        } else {
            // Does not match obj_tmp_
            // If file is older than 1 hour (e.g. GC-TEST-08 active_worker_test.tmp aged 24h)
            auto ftime = fs::last_write_time(p, ec);
            if (!ec) {
                auto sftime = std::chrono::time_point_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now() + (ftime - fs::file_time_type::clock::now()));
                auto file_age = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now() - sftime).count();
                if (file_age >= 3600000 && !is_file_locked_by_writer(p)) {
                    can_remove = true;
                } else {
                    // Recent file with unknown name -> UNCERTAIN OWNERSHIP -> NEVER delete!
                    can_remove = false;
                }
            }
        }

        if (can_remove) {
            if (fs::remove(p, ec)) {
                ++cleaned_count;
            } else {
                // If another thread or process unlinked it concurrently, check if file is now gone
                std::error_code exists_ec;
                bool still_there = fs::exists(p, exists_ec);
                if (still_there) {
                    for (int retry = 0; retry < 3 && still_there; ++retry) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        still_there = fs::exists(p, exists_ec);
                    }
                }
                if (still_there && err && err->empty()) {
                    *err = "Failed to remove temp file: " + p.string() + " (" + ec.message() + ")";
                }
            }
        }
    }
    return cleaned_count;
}

bool ObjectStore::remove_object(const ChunkHash& hash, std::string& err) {
    if (!is_valid_hex_hash(hash)) {
        err = "Invalid chunk hash: " + hash;
        return false;
    }
    const fs::path p = object_path(hash);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        return true; // Idempotent: already absent
    }
    if (!fs::remove(p, ec)) {
        err = "Failed to remove CAS object file " + p.string() + ": " + ec.message();
        return false;
    }
    return true;
}

std::vector<ChunkHash> ObjectStore::list_all_objects(std::string* err) const {
    std::vector<ChunkHash> objects;
    std::error_code ec;
    if (!fs::exists(objects_dir_, ec)) return objects;

    for (const auto& shard : fs::directory_iterator(objects_dir_, ec)) {
        if (!shard.is_directory(ec)) continue;
        for (const auto& entry : fs::directory_iterator(shard.path(), ec)) {
            if (entry.is_regular_file(ec)) {
                const std::string h = entry.path().filename().string();
                if (is_valid_hex_hash(h)) {
                    objects.push_back(h);
                }
            }
        }
    }
    if (ec && err && err->empty()) {
        *err = "Directory iteration error: " + ec.message();
    }
    return objects;
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
