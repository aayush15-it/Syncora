#include "merklechain/peer/peer_sync.hpp"

#include "merklechain/hash.hpp"
#include "merklechain/peer/peer_protocol.hpp"
#include "merklechain/scanner.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>

namespace mc::peer {
namespace {
using FilesByKey = std::map<std::string, FileMetadata>;

void db_exec(sqlite3* db, const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        const std::string message = error ? error : sqlite3_errmsg(db);
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool valid_identity(const std::string& value) {
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_';
        });
}

bool valid_digest(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

bool valid_utf8(const std::string& value) {
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = static_cast<unsigned char>(value[index]);
        if (first <= 0x7fU) { ++index; continue; }
        std::size_t continuation_count = 0;
        std::uint32_t codepoint = 0;
        if (first >= 0xc2U && first <= 0xdfU) {
            continuation_count = 1U; codepoint = first & 0x1fU;
        } else if (first >= 0xe0U && first <= 0xefU) {
            continuation_count = 2U; codepoint = first & 0x0fU;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            continuation_count = 3U; codepoint = first & 0x07U;
        } else return false;
        if (value.size() - index - 1U < continuation_count) return false;
        for (std::size_t part = 1U; part <= continuation_count; ++part) {
            const auto next = static_cast<unsigned char>(value[index + part]);
            if ((next & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((continuation_count == 1U && codepoint < 0x80U) ||
            (continuation_count == 2U && codepoint < 0x800U) ||
            (continuation_count == 3U && codepoint < 0x10000U) ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU)
            return false;
        index += continuation_count + 1U;
    }
    return true;
}

std::string normalize_path(const std::string& input) {
    if (input.empty() || input.size() > 4096 || !valid_utf8(input) ||
        !safe_relative_path(input))
        throw std::runtime_error("peer manifest contains an unsafe or overlong relative path");
    auto path = input;
    std::replace(path.begin(), path.end(), '\\', '/');
    if (path != input || path.empty() || path.front() == '/' || path.back() == '/' ||
        path.find("//") != std::string::npos)
        throw std::runtime_error("peer manifest contains a non-canonical relative path");
    return path;
}

std::string path_key(std::string path) {
    std::transform(path.begin(), path.end(), path.begin(), [](unsigned char c) {
        return static_cast<char>(c < 0x80U ? std::tolower(c) : c);
    });
    return path;
}

FilesByKey validate_files(const std::vector<FileMetadata>& files) {
    if (files.size() > 1000000U) throw std::runtime_error("peer manifest exceeds one million files");
    FilesByKey result;
    for (const auto& input : files) {
        auto file = input;
        file.relative_path = normalize_path(file.relative_path);
        if (file.size > static_cast<std::uintmax_t>(std::numeric_limits<sqlite3_int64>::max()))
            throw std::runtime_error("peer manifest file exceeds SQLite's signed size range");
        if (!valid_digest(file.sha256)) throw std::runtime_error("peer manifest contains a malformed SHA-256 digest");
        if (std::any_of(file.sha256.begin(), file.sha256.end(), [](unsigned char c) {
                return c >= 'A' && c <= 'F';
            })) throw std::runtime_error("peer manifest SHA-256 digests must use canonical lowercase hexadecimal");
        std::transform(file.sha256.begin(), file.sha256.end(), file.sha256.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (!result.emplace(path_key(file.relative_path), std::move(file)).second)
            throw std::runtime_error("peer manifest contains duplicate paths under case-insensitive comparison");
    }
    return result;
}

FilesByKey validate_manifest(const FileManifest& manifest) {
    if (!manifest.complete) throw std::runtime_error("peer planning requires complete local and remote scans");
    auto files = validate_files(manifest.files);
    if (!valid_digest(manifest.merkle_root) ||
        std::any_of(manifest.merkle_root.begin(), manifest.merkle_root.end(), [](unsigned char c) {
            return c >= 'A' && c <= 'F';
        }))
        throw std::runtime_error("peer manifest Merkle root is malformed or not canonical lowercase hexadecimal");
    std::vector<FileMetadata> canonical;
    canonical.reserve(files.size());
    for (const auto& [key, file] : files) {
        (void)key;
        canonical.push_back(file);
    }
    std::sort(canonical.begin(), canonical.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    if (merkle_root(canonical) != manifest.merkle_root)
        throw std::runtime_error("peer manifest Merkle root is missing or does not match its file list");
    return files;
}

std::optional<FileMetadata> lookup(const FilesByKey& files, const std::string& key) {
    const auto found = files.find(key);
    if (found == files.end()) return std::nullopt;
    return found->second;
}

bool same_content(const FileMetadata* left, const FileMetadata* right) {
    return left != nullptr && right != nullptr && left->sha256 == right->sha256;
}

void validate_consistent_sizes(const FilesByKey& base, const FilesByKey& local,
                               const FilesByKey& remote) {
    std::map<std::string, std::uintmax_t> sizes;
    const auto collect = [&](const FilesByKey& files) {
        for (const auto& [key, file] : files) {
            (void)key;
            const auto inserted = sizes.emplace(file.sha256, file.size);
            if (!inserted.second && inserted.first->second != file.size)
                throw std::runtime_error("the same SHA-256 was reported with inconsistent file sizes");
        }
    };
    collect(base);
    collect(local);
    collect(remote);
}

void append_u64(std::string& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<char>((value >> static_cast<unsigned int>(shift)) & 0xffU));
}

void append_string(std::string& out, const std::string& value) {
    append_u64(out, static_cast<std::uint64_t>(value.size()));
    out.append(value);
}

void append_u16(std::string& out, std::uint16_t value) {
    out.push_back(static_cast<char>((value >> 8U) & 0xffU));
    out.push_back(static_cast<char>(value & 0xffU));
}

void append_u32(std::string& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<char>((value >> static_cast<unsigned int>(shift)) & 0xffU));
}

std::uint64_t read_u64(const std::string& input, std::size_t& offset) {
    if (offset > input.size() || input.size() - offset < 8U)
        throw std::runtime_error("truncated peer manifest integer");
    std::uint64_t value = 0;
    for (unsigned int index = 0; index < 8U; ++index)
        value = (value << 8U) | static_cast<unsigned char>(input[offset++]);
    return value;
}

std::uint32_t read_u32(const std::string& input, std::size_t& offset) {
    if (offset > input.size() || input.size() - offset < 4U)
        throw std::runtime_error("truncated peer manifest count");
    std::uint32_t value = 0;
    for (unsigned int index = 0; index < 4U; ++index)
        value = (value << 8U) | static_cast<unsigned char>(input[offset++]);
    return value;
}

std::uint16_t read_u16(const std::string& input, std::size_t& offset) {
    if (offset > input.size() || input.size() - offset < 2U)
        throw std::runtime_error("truncated peer manifest path length");
    const auto high = static_cast<unsigned char>(input[offset++]);
    const auto low = static_cast<unsigned char>(input[offset++]);
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(high) << 8U) | low);
}

std::string digest_to_bytes(const std::string& hex) {
    if (!valid_digest(hex)) throw std::runtime_error("peer manifest contains a malformed digest");
    std::string bytes;
    bytes.reserve(32U);
    for (std::size_t index = 0; index < hex.size(); index += 2U) {
        const auto nibble = [](unsigned char value) -> unsigned char {
            if (value >= '0' && value <= '9') return static_cast<unsigned char>(value - '0');
            if (value >= 'a' && value <= 'f') return static_cast<unsigned char>(value - 'a' + 10U);
            if (value >= 'A' && value <= 'F') return static_cast<unsigned char>(value - 'A' + 10U);
            throw std::runtime_error("peer manifest contains a malformed digest");
        };
        bytes.push_back(static_cast<char>((nibble(static_cast<unsigned char>(hex[index])) << 4U) |
                                           nibble(static_cast<unsigned char>(hex[index + 1U]))));
    }
    return bytes;
}

std::string digest_to_hex(const std::string& bytes) {
    if (bytes.size() != 32U) throw std::runtime_error("peer manifest digest has an invalid length");
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64U);
    for (const auto byte : bytes) {
        const auto value = static_cast<unsigned char>(byte);
        hex.push_back(digits[value >> 4U]);
        hex.push_back(digits[value & 0x0fU]);
    }
    return hex;
}

void append_optional_file(std::string& out, const std::optional<FileMetadata>& file) {
    out.push_back(file ? '\1' : '\0');
    if (!file) return;
    append_string(out, file->relative_path);
    append_u64(out, static_cast<std::uint64_t>(file->size));
    append_string(out, file->sha256);
}

std::string calculate_plan_hash(const PeerSyncPlan& plan) {
    std::string canonical("MERKLECHAIN-PEER-PLAN-v1", 24);
    append_string(canonical, plan.peer_id);
    append_string(canonical, plan.folder_pair_id);
    canonical.push_back(plan.baseline_root.empty() ? '\0' : '\1');
    append_string(canonical, plan.baseline_root);
    append_string(canonical, plan.local_root);
    append_string(canonical, plan.remote_root);
    canonical.push_back(plan.requires_approval ? '\1' : '\0');
    canonical.push_back(plan.requires_deletion_confirmation ? '\1' : '\0');
    canonical.push_back(plan.has_unresolved_conflicts ? '\1' : '\0');
    append_u64(canonical, static_cast<std::uint64_t>(plan.entries.size()));
    for (const auto& entry : plan.entries) {
        append_string(canonical, entry.relative_path);
        canonical.push_back(static_cast<char>(entry.action));
        canonical.push_back(static_cast<char>(entry.conflict));
        canonical.push_back(static_cast<char>(entry.resolution));
        canonical.push_back(entry.approval_required ? '\1' : '\0');
        canonical.push_back(entry.deletion_confirmation_required ? '\1' : '\0');
        canonical.push_back(entry.resolution_required ? '\1' : '\0');
        append_optional_file(canonical, entry.baseline);
        append_optional_file(canonical, entry.local);
        append_optional_file(canonical, entry.remote);
    }
    return sha256_data(canonical.data(), canonical.size());
}

void bind_text(sqlite3_stmt* statement, int index, const std::string& value) {
    if (sqlite3_bind_text(statement, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
        throw std::runtime_error("cannot bind peer baseline text: " + std::string(sqlite3_errstr(sqlite3_errcode(sqlite3_db_handle(statement)))));
}

void bind_i64(sqlite3* db, sqlite3_stmt* statement, int index, sqlite3_int64 value) {
    const int status = sqlite3_bind_int64(statement, index, value);
    if (status != SQLITE_OK)
        throw std::runtime_error(std::string("cannot bind peer baseline integer: ") + sqlite3_errmsg(db));
}

void reject_symlink(const fs::path& path) {
    std::error_code error;
    const auto status = fs::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) return;
    if (error) throw std::runtime_error("cannot inspect peer baseline path: " + error.message());
    if (fs::is_symlink(status)) throw std::runtime_error("peer baseline path cannot be a symbolic link: " + path.string());
}

void require_db(sqlite3* db, int status, const char* action) {
    if (status != SQLITE_OK && status != SQLITE_DONE && status != SQLITE_ROW)
        throw std::runtime_error(std::string(action) + ": " + sqlite3_errmsg(db));
}

void validate_baseline(const PeerBaseline& baseline) {
    if (!baseline.exists) {
        if (!baseline.files.empty() || !baseline.merkle_root.empty())
            throw std::runtime_error("absent peer baseline contains unexpected data");
        return;
    }
    auto files = validate_files(baseline.files);
    std::vector<FileMetadata> normalized;
    normalized.reserve(files.size());
    for (const auto& [key, file] : files) {
        (void)key;
        normalized.push_back(file);
    }
    if (!valid_digest(baseline.merkle_root) || merkle_root(normalized) != baseline.merkle_root)
        throw std::runtime_error("stored peer baseline Merkle root is corrupt");
}

void schedule(PeerSyncPlan& plan, PeerPlanEntry& entry, PeerPlanAction action) {
    entry.action = action;
    entry.approval_required = action != PeerPlanAction::NoChange;
    entry.deletion_confirmation_required = action == PeerPlanAction::DeleteLocal ||
                                            action == PeerPlanAction::DeleteRemote;
    plan.requires_approval = plan.requires_approval || entry.approval_required;
    plan.requires_deletion_confirmation = plan.requires_deletion_confirmation ||
                                          entry.deletion_confirmation_required;
}

} // namespace

struct PeerBaselineStore::Impl { sqlite3* db{}; };

PeerBaselineStore::PeerBaselineStore(const fs::path& database_file) : impl_(new Impl) {
    try {
        if (!database_file.parent_path().empty()) {
            reject_symlink(database_file.parent_path());
            fs::create_directories(database_file.parent_path());
            reject_symlink(database_file.parent_path());
        }
        reject_symlink(database_file);
        if (sqlite3_open_v2(database_file.string().c_str(), &impl_->db,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                            nullptr) != SQLITE_OK)
            throw std::runtime_error(std::string("cannot open peer baseline database: ") +
                                     (impl_->db ? sqlite3_errmsg(impl_->db) : "SQLite allocation failure"));
        sqlite3_busy_timeout(impl_->db, 5000);
        db_exec(impl_->db, "PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;");
        db_exec(impl_->db,
            "CREATE TABLE IF NOT EXISTS peer_sync_baselines("
            "peer_id TEXT NOT NULL,folder_pair_id TEXT NOT NULL,merkle_root TEXT NOT NULL,"
            "committed_at_ms INTEGER NOT NULL,PRIMARY KEY(peer_id,folder_pair_id));"
            "CREATE TABLE IF NOT EXISTS peer_sync_baseline_files("
            "peer_id TEXT NOT NULL,folder_pair_id TEXT NOT NULL,path_key TEXT NOT NULL,"
            "relative_path TEXT NOT NULL,size INTEGER NOT NULL,modified_ticks INTEGER NOT NULL,sha256 TEXT NOT NULL,"
            "PRIMARY KEY(peer_id,folder_pair_id,path_key),"
            "FOREIGN KEY(peer_id,folder_pair_id) REFERENCES peer_sync_baselines(peer_id,folder_pair_id) ON DELETE CASCADE);");
        db_exec(impl_->db, "COMMIT;");
    } catch (...) {
        if (impl_->db) {
            try { db_exec(impl_->db, "ROLLBACK;"); } catch (...) {}
            sqlite3_close(impl_->db);
        }
        delete impl_;
        impl_ = nullptr;
        throw;
    }
}

PeerBaselineStore::~PeerBaselineStore() {
    if (impl_) {
        if (impl_->db) sqlite3_close(impl_->db);
        delete impl_;
    }
}

PeerBaseline PeerBaselineStore::load(const std::string& peer_id,
                                     const std::string& folder_pair_id) const {
    if (!valid_identity(peer_id) || !valid_identity(folder_pair_id))
        throw std::runtime_error("peer and folder-pair IDs must contain 1-128 ASCII letters, digits, '_' or '-'");
    PeerBaseline result;
    result.peer_id = peer_id;
    result.folder_pair_id = folder_pair_id;
    sqlite3_stmt* statement = nullptr;
    require_db(impl_->db, sqlite3_prepare_v2(impl_->db,
        "SELECT merkle_root,committed_at_ms FROM peer_sync_baselines WHERE peer_id=? AND folder_pair_id=?",
        -1, &statement, nullptr), "prepare peer baseline read");
    try {
        bind_text(statement, 1, peer_id);
        bind_text(statement, 2, folder_pair_id);
        const int row = sqlite3_step(statement);
        if (row == SQLITE_ROW) {
            result.exists = true;
            const auto* root = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
            if (!root) throw std::runtime_error("peer baseline root is NULL");
            result.merkle_root = root;
            result.committed_at_ms = sqlite3_column_int64(statement, 1);
        } else if (row != SQLITE_DONE) require_db(impl_->db, row, "read peer baseline");
        sqlite3_finalize(statement);
        statement = nullptr;
        if (result.exists) {
            require_db(impl_->db, sqlite3_prepare_v2(impl_->db,
                "SELECT relative_path,size,modified_ticks,sha256 FROM peer_sync_baseline_files "
                "WHERE peer_id=? AND folder_pair_id=? ORDER BY path_key",
                -1, &statement, nullptr), "prepare peer baseline files read");
            bind_text(statement, 1, peer_id);
            bind_text(statement, 2, folder_pair_id);
            int file_row = SQLITE_ROW;
            while ((file_row = sqlite3_step(statement)) == SQLITE_ROW) {
                const auto* path = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
                const auto* hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 3));
                if (!path || !hash) throw std::runtime_error("peer baseline file contains NULL metadata");
                FileMetadata file;
                file.relative_path = path;
                const auto size = sqlite3_column_int64(statement, 1);
                if (size < 0) throw std::runtime_error("peer baseline contains a negative file size");
                file.size = static_cast<std::uintmax_t>(size);
                file.modified_ticks = sqlite3_column_int64(statement, 2);
                file.sha256 = hash;
                result.files.push_back(std::move(file));
            }
            if (file_row != SQLITE_DONE) require_db(impl_->db, file_row, "read peer baseline files");
        }
        if (statement) sqlite3_finalize(statement);
    } catch (...) {
        if (statement) sqlite3_finalize(statement);
        throw;
    }
    validate_baseline(result);
    return result;
}

void PeerBaselineStore::commit_reconciled_manifest(const std::string& peer_id,
                                                   const std::string& folder_pair_id,
                                                   const FileManifest& manifest) {
    if (!valid_identity(peer_id) || !valid_identity(folder_pair_id))
        throw std::runtime_error("peer and folder-pair IDs must contain 1-128 ASCII letters, digits, '_' or '-'");
    if (!manifest.complete) throw std::runtime_error("cannot advance peer baseline from an incomplete scan");
    const auto files = validate_files(manifest.files);
        if (!valid_digest(manifest.merkle_root) ||
            std::any_of(manifest.merkle_root.begin(), manifest.merkle_root.end(), [](unsigned char c) {
                return c >= 'A' && c <= 'F';
            }) || merkle_root(manifest.files) != manifest.merkle_root)
        throw std::runtime_error("cannot advance peer baseline from a manifest with an invalid Merkle root");

    db_exec(impl_->db, "BEGIN IMMEDIATE;");
    sqlite3_stmt* baseline = nullptr;
    sqlite3_stmt* erase = nullptr;
    sqlite3_stmt* insert = nullptr;
    try {
        require_db(impl_->db, sqlite3_prepare_v2(impl_->db,
            "INSERT INTO peer_sync_baselines(peer_id,folder_pair_id,merkle_root,committed_at_ms) VALUES(?,?,?,?) "
            "ON CONFLICT(peer_id,folder_pair_id) DO UPDATE SET merkle_root=excluded.merkle_root,committed_at_ms=excluded.committed_at_ms",
            -1, &baseline, nullptr), "prepare peer baseline upsert");
        bind_text(baseline, 1, peer_id);
        bind_text(baseline, 2, folder_pair_id);
        bind_text(baseline, 3, manifest.merkle_root);
        bind_i64(impl_->db, baseline, 4, now_ms());
        require_db(impl_->db, sqlite3_step(baseline), "upsert peer baseline");
        sqlite3_finalize(baseline);
        baseline = nullptr;

        require_db(impl_->db, sqlite3_prepare_v2(impl_->db,
            "DELETE FROM peer_sync_baseline_files WHERE peer_id=? AND folder_pair_id=?",
            -1, &erase, nullptr), "prepare peer baseline file replacement");
        bind_text(erase, 1, peer_id);
        bind_text(erase, 2, folder_pair_id);
        require_db(impl_->db, sqlite3_step(erase), "delete previous peer baseline files");
        sqlite3_finalize(erase);
        erase = nullptr;

        require_db(impl_->db, sqlite3_prepare_v2(impl_->db,
            "INSERT INTO peer_sync_baseline_files(peer_id,folder_pair_id,path_key,relative_path,size,modified_ticks,sha256) VALUES(?,?,?,?,?,?,?)",
            -1, &insert, nullptr), "prepare peer baseline file insert");
        for (const auto& [key, file] : files) {
            bind_text(insert, 1, peer_id);
            bind_text(insert, 2, folder_pair_id);
            bind_text(insert, 3, key);
            bind_text(insert, 4, file.relative_path);
            if (file.size > static_cast<std::uintmax_t>(std::numeric_limits<sqlite3_int64>::max()))
                throw std::runtime_error("peer baseline file exceeds SQLite's signed size range");
            bind_i64(impl_->db, insert, 5, static_cast<sqlite3_int64>(file.size));
            bind_i64(impl_->db, insert, 6, file.modified_ticks);
            bind_text(insert, 7, file.sha256);
            require_db(impl_->db, sqlite3_step(insert), "insert peer baseline file");
            sqlite3_reset(insert);
            sqlite3_clear_bindings(insert);
        }
        sqlite3_finalize(insert);
        insert = nullptr;
        db_exec(impl_->db, "COMMIT;");
    } catch (...) {
        if (baseline) sqlite3_finalize(baseline);
        if (erase) sqlite3_finalize(erase);
        if (insert) sqlite3_finalize(insert);
        try { db_exec(impl_->db, "ROLLBACK;"); } catch (...) {}
        throw;
    }
}

std::string encode_peer_manifest(const FileManifest& manifest,
                                 std::uint32_t max_files,
                                 std::uint64_t max_file_size_bytes) {
    if (max_files == 0U || manifest.files.size() > max_files)
        throw std::runtime_error("peer manifest exceeds the configured file-count limit");
    (void)validate_manifest(manifest);
    std::string output("MCMF", 4U);
    append_u16(output, 1U);
    append_u32(output, static_cast<std::uint32_t>(manifest.files.size()));
    output += digest_to_bytes(manifest.merkle_root);
    auto files = manifest.files;
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    for (const auto& file : files) {
        if (file.relative_path.size() > 4096U ||
            file.relative_path.size() > std::numeric_limits<std::uint16_t>::max())
            throw std::runtime_error("peer manifest path exceeds the protocol path limit");
        if (file.size > max_file_size_bytes)
            throw std::runtime_error("peer manifest file exceeds the configured size limit");
        append_u16(output, static_cast<std::uint16_t>(file.relative_path.size()));
        output.append(file.relative_path);
        append_u64(output, static_cast<std::uint64_t>(file.size));
        std::uint64_t timestamp_bits = 0;
        static_assert(sizeof(timestamp_bits) == sizeof(file.modified_ticks), "timestamp width mismatch");
        std::memcpy(&timestamp_bits, &file.modified_ticks, sizeof(timestamp_bits));
        append_u64(output, timestamp_bits);
        output += digest_to_bytes(file.sha256);
        if (output.size() > kMaximumFramePayload)
            throw std::runtime_error("peer manifest exceeds the single-frame protocol limit");
    }
    return output;
}

FileManifest decode_peer_manifest(const std::string& payload,
                                  std::uint32_t max_files,
                                  std::uint64_t max_file_size_bytes) {
    if (payload.size() > kMaximumFramePayload)
        throw std::runtime_error("peer manifest exceeds the protocol payload limit");
    if (payload.size() < 42U || payload.compare(0, 4U, "MCMF") != 0)
        throw std::runtime_error("peer manifest has invalid magic or is truncated");
    std::size_t offset = 4U;
    if (read_u16(payload, offset) != 1U)
        throw std::runtime_error("peer manifest version is unsupported");
    const auto count = read_u32(payload, offset);
    if (count > max_files || count > 1000000U)
        throw std::runtime_error("peer manifest exceeds the configured file-count limit");
    FileManifest manifest;
    manifest.complete = true;
    manifest.merkle_root = digest_to_hex(payload.substr(offset, 32U));
    offset += 32U;
    manifest.files.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto path_size = read_u16(payload, offset);
        if (path_size == 0U || path_size > 4096U ||
            offset > payload.size() || payload.size() - offset < path_size)
            throw std::runtime_error("peer manifest contains a truncated or invalid path");
        FileMetadata file;
        file.relative_path.assign(payload.data() + offset, path_size);
        offset += path_size;
        const auto raw_size = read_u64(payload, offset);
        if (raw_size > max_file_size_bytes ||
            raw_size > static_cast<std::uint64_t>(std::numeric_limits<sqlite3_int64>::max()))
            throw std::runtime_error("peer manifest file exceeds the configured size limit");
        file.size = static_cast<std::uintmax_t>(raw_size);
        const auto timestamp_bits = read_u64(payload, offset);
        std::memcpy(&file.modified_ticks, &timestamp_bits, sizeof(timestamp_bits));
        if (offset > payload.size() || payload.size() - offset < 32U)
            throw std::runtime_error("peer manifest contains a truncated file digest");
        file.sha256 = digest_to_hex(payload.substr(offset, 32U));
        offset += 32U;
        manifest.files.push_back(std::move(file));
    }
    if (offset != payload.size()) throw std::runtime_error("peer manifest contains trailing data");
    (void)validate_manifest(manifest);
    return manifest;
}

PeerSyncPlan plan_bidirectional(const std::string& peer_id,
                                const std::string& folder_pair_id,
                                const PeerBaseline& baseline,
                                const FileManifest& local,
                                const FileManifest& remote) {
    PeerSyncPlan plan;
    plan.peer_id = peer_id;
    plan.folder_pair_id = folder_pair_id;
    try {
        if (!valid_identity(peer_id) || !valid_identity(folder_pair_id))
            throw std::runtime_error("peer and folder-pair IDs must contain 1-128 ASCII letters, digits, '_' or '-'");
        if (!local.complete || !remote.complete)
            throw std::runtime_error("peer planning refused because at least one scan is incomplete");
        const auto local_files = validate_manifest(local);
        const auto remote_files = validate_manifest(remote);
        validate_baseline(baseline);
        if (baseline.exists &&
            ((baseline.peer_id != peer_id && !baseline.peer_id.empty()) ||
             (baseline.folder_pair_id != folder_pair_id && !baseline.folder_pair_id.empty())))
            throw std::runtime_error("peer baseline belongs to a different peer or folder pair");

        FilesByKey base_files;
        if (baseline.exists) base_files = validate_files(baseline.files);
        validate_consistent_sizes(base_files, local_files, remote_files);
        plan.valid = true;
        plan.baseline_root = baseline.exists ? baseline.merkle_root : std::string{};
        plan.local_root = local.merkle_root;
        plan.remote_root = remote.merkle_root;

        std::map<std::string, std::string> all_paths;
        for (const auto& [key, file] : base_files) all_paths.emplace(key, file.relative_path);
        for (const auto& [key, file] : local_files) all_paths.emplace(key, file.relative_path);
        for (const auto& [key, file] : remote_files) all_paths.emplace(key, file.relative_path);

        for (const auto& [key, fallback_path] : all_paths) {
            PeerPlanEntry entry;
            entry.baseline = lookup(base_files, key);
            entry.local = lookup(local_files, key);
            entry.remote = lookup(remote_files, key);
            entry.relative_path = entry.baseline ? entry.baseline->relative_path :
                                  (entry.local ? entry.local->relative_path :
                                                 (entry.remote ? entry.remote->relative_path : fallback_path));
            const auto* base = entry.baseline ? &entry.baseline.value() : nullptr;
            const auto* left = entry.local ? &entry.local.value() : nullptr;
            const auto* right = entry.remote ? &entry.remote.value() : nullptr;
            if (!base) {
                if (left && right) {
                    if (!same_content(left, right)) {
                        entry.action = PeerPlanAction::Conflict;
                        entry.conflict = baseline.exists ? PeerConflictKind::ConcurrentAddition :
                                                           PeerConflictKind::InitialDivergence;
                    }
                } else if (left) schedule(plan, entry, PeerPlanAction::AddRemote);
                else if (right) schedule(plan, entry, PeerPlanAction::AddLocal);
            } else if (!left && !right) {
                // Both peers independently reached the same deleted state.
            } else if (left && right) {
                if (same_content(left, right)) {
                    // Equal current content is converged even if both differ from base.
                } else if (left->sha256 == base->sha256) {
                    schedule(plan, entry, PeerPlanAction::UpdateLocal);
                } else if (right->sha256 == base->sha256) {
                    schedule(plan, entry, PeerPlanAction::UpdateRemote);
                } else {
                    entry.action = PeerPlanAction::Conflict;
                    entry.conflict = PeerConflictKind::ConcurrentModification;
                }
            } else if (!left && right) {
                if (right->sha256 == base->sha256)
                    schedule(plan, entry, PeerPlanAction::DeleteRemote);
                else {
                    entry.action = PeerPlanAction::Conflict;
                    entry.conflict = PeerConflictKind::LocalDeletionRemoteModification;
                }
            } else if (left && !right) {
                if (left->sha256 == base->sha256)
                    schedule(plan, entry, PeerPlanAction::DeleteLocal);
                else {
                    entry.action = PeerPlanAction::Conflict;
                    entry.conflict = PeerConflictKind::RemoteDeletionLocalModification;
                }
            }
            if (entry.action == PeerPlanAction::Conflict) {
                entry.approval_required = true;
                entry.resolution_required = true;
                plan.requires_approval = true;
                plan.has_unresolved_conflicts = true;
            }
            plan.entries.push_back(std::move(entry));
        }
        plan.plan_hash = calculate_plan_hash(plan);
    } catch (const std::exception& error) {
        plan.valid = false;
        plan.error = error.what();
        plan.entries.clear();
        plan.plan_hash.clear();
    }
    return plan;
}

bool resolve_peer_conflict(PeerSyncPlan& plan, const std::string& relative_path,
                           PeerConflictResolution resolution) {
    if (!plan.valid || resolution == PeerConflictResolution::Unresolved) return false;
    std::string key;
    try { key = path_key(normalize_path(relative_path)); }
    catch (...) { return false; }
    const auto found = std::find_if(plan.entries.begin(), plan.entries.end(), [&](const auto& entry) {
        return path_key(entry.relative_path) == key;
    });
    if (found == plan.entries.end() || found->action != PeerPlanAction::Conflict ||
        !found->resolution_required) return false;
    found->resolution = resolution;
    found->resolution_required = false;
    switch (resolution) {
        case PeerConflictResolution::KeepLocal:
            if (found->local)
                schedule(plan, *found, found->remote ? PeerPlanAction::UpdateRemote : PeerPlanAction::AddRemote);
            else schedule(plan, *found, PeerPlanAction::DeleteRemote);
            break;
        case PeerConflictResolution::KeepRemote:
            if (found->remote)
                schedule(plan, *found, found->local ? PeerPlanAction::UpdateLocal : PeerPlanAction::AddLocal);
            else schedule(plan, *found, PeerPlanAction::DeleteLocal);
            break;
        case PeerConflictResolution::PreserveBoth:
            found->action = PeerPlanAction::PreserveBoth;
            found->approval_required = true;
            found->deletion_confirmation_required = false;
            plan.requires_approval = true;
            break;
        case PeerConflictResolution::Unresolved:
            return false;
    }
    plan.has_unresolved_conflicts = std::any_of(plan.entries.begin(), plan.entries.end(), [](const auto& entry) {
        return entry.resolution_required;
    });
    plan.requires_deletion_confirmation = std::any_of(plan.entries.begin(), plan.entries.end(), [](const auto& entry) {
        return entry.deletion_confirmation_required;
    });
    plan.requires_approval = std::any_of(plan.entries.begin(), plan.entries.end(), [](const auto& entry) {
        return entry.approval_required;
    });
    plan.plan_hash = calculate_plan_hash(plan);
    return true;
}

bool peer_plan_is_authorized(const PeerSyncPlan& plan,
                             const std::string& approved_plan_hash,
                             bool approved,
                             bool deletion_confirmed) {
    if (!plan.valid || plan.plan_hash.empty() || plan.has_unresolved_conflicts ||
        approved_plan_hash != plan.plan_hash)
        return false;
    try {
        if (calculate_plan_hash(plan) != plan.plan_hash) return false;
    } catch (...) { return false; }
    if (plan.requires_approval && !approved) return false;
    if (plan.requires_deletion_confirmation && !deletion_confirmed) return false;
    return true;
}

const char* peer_plan_action_name(PeerPlanAction action) noexcept {
    switch (action) {
        case PeerPlanAction::NoChange: return "NO_CHANGE";
        case PeerPlanAction::AddLocal: return "ADD_LOCAL";
        case PeerPlanAction::UpdateLocal: return "UPDATE_LOCAL";
        case PeerPlanAction::DeleteLocal: return "DELETE_LOCAL";
        case PeerPlanAction::AddRemote: return "ADD_REMOTE";
        case PeerPlanAction::UpdateRemote: return "UPDATE_REMOTE";
        case PeerPlanAction::DeleteRemote: return "DELETE_REMOTE";
        case PeerPlanAction::PreserveBoth: return "PRESERVE_BOTH";
        case PeerPlanAction::Conflict: return "CONFLICT";
    }
    return "UNKNOWN";
}

const char* peer_conflict_name(PeerConflictKind conflict) noexcept {
    switch (conflict) {
        case PeerConflictKind::None: return "NONE";
        case PeerConflictKind::InitialDivergence: return "INITIAL_DIVERGENCE";
        case PeerConflictKind::ConcurrentAddition: return "CONCURRENT_ADDITION";
        case PeerConflictKind::ConcurrentModification: return "CONCURRENT_MODIFICATION";
        case PeerConflictKind::LocalDeletionRemoteModification: return "LOCAL_DELETE_REMOTE_MODIFY";
        case PeerConflictKind::RemoteDeletionLocalModification: return "REMOTE_DELETE_LOCAL_MODIFY";
    }
    return "UNKNOWN";
}

} // namespace mc::peer
