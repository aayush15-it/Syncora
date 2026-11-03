#include "merklechain/collab_store.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/staging_file.hpp"
#include "merklechain/sync.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <atomic>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace mc {

namespace {

std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.size() % 2 != 0) return bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte = 0;
        std::istringstream iss(hex.substr(i, 2));
        if (iss >> std::hex >> byte) {
            bytes.push_back(static_cast<unsigned char>(byte));
        } else {
            return {};
        }
    }
    return bytes;
}

std::string join_strings(const std::vector<std::string>& list, char delimiter = ',') {
    std::string res;
    for (std::size_t i = 0; i < list.size(); ++i) {
        if (i) res += delimiter;
        res += list[i];
    }
    return res;
}

std::vector<std::string> split_strings(const std::string& str, char delimiter = ',') {
    std::vector<std::string> items;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) items.push_back(item);
    }
    return items;
}

} // namespace

void copy_directory_recursive(const fs::path& source, const fs::path& target) {
    fs::create_directories(target);
    for (const auto& entry : fs::recursive_directory_iterator(source)) {
        const auto rel = fs::relative(entry.path(), source);
        const auto dest = target / rel;
        if (entry.is_directory()) {
            fs::create_directories(dest);
        } else if (entry.is_regular_file()) {
            fs::create_directories(dest.parent_path());
            fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing);
        }
    }
}

namespace {

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

std::string generate_unified_diff(const std::string& path,
                                  const std::string& old_text,
                                  const std::string& new_text) {
    const auto old_lines = split_lines(old_text);
    const auto new_lines = split_lines(new_text);
    std::ostringstream diff;
    diff << "--- a/" << path << "\n";
    diff << "+++ b/" << path << "\n";

    // Simple line diff algorithm
    std::size_t i = 0, j = 0;
    while (i < old_lines.size() || j < new_lines.size()) {
        if (i < old_lines.size() && j < new_lines.size() && old_lines[i] == new_lines[j]) {
            diff << "  " << old_lines[i] << "\n";
            ++i; ++j;
        } else if (i < old_lines.size() && (j >= new_lines.size() || old_lines[i] != new_lines[j])) {
            // Check if deleted
            diff << "- " << old_lines[i] << "\n";
            ++i;
            if (j < new_lines.size() && (i >= old_lines.size() || old_lines[i] != new_lines[j])) {
                diff << "+ " << new_lines[j] << "\n";
                ++j;
            }
        } else if (j < new_lines.size()) {
            diff << "+ " << new_lines[j] << "\n";
            ++j;
        }
    }
    return diff.str();
}

std::int64_t file_ticks_to_millis(std::int64_t ticks) {
    using FileClock = fs::file_time_type::clock;
    const auto file_time = fs::file_time_type(FileClock::duration(ticks));
    const auto system_time = std::chrono::system_clock::now() +
        std::chrono::duration_cast<std::chrono::system_clock::duration>(file_time - FileClock::now());
    return std::chrono::duration_cast<std::chrono::milliseconds>(system_time.time_since_epoch()).count();
}

} // namespace


// ---------------------------------------------------------------------------
// Controlled failpoints for testing crash recovery
// ---------------------------------------------------------------------------
namespace {
std::atomic<CollabFaultPoint> g_collab_fault_point{CollabFaultPoint::None};
std::atomic<bool> g_collab_process_exit_on_fault{false};
}

void set_collab_fault_point_for_testing(CollabFaultPoint fp) {
    g_collab_fault_point.store(fp);
}

CollabFaultPoint get_collab_fault_point_for_testing() {
    return g_collab_fault_point.load();
}

void set_collab_process_exit_on_fault_for_testing(bool enable) {
    g_collab_process_exit_on_fault.store(enable);
}

bool get_collab_process_exit_on_fault_for_testing() {
    return g_collab_process_exit_on_fault.load();
}

static void trigger_collab_fault_point(CollabFaultPoint target, const char* name) {
    const auto active = g_collab_fault_point.load();
    if (active == target ||
        (target == CollabFaultPoint::FailAfterBaselineBackup && active == CollabFaultPoint::FailAfterBackup)) {
#ifdef MERKLECHAIN_TESTING
        if (g_collab_process_exit_on_fault.load()) {
            std::_Exit(95);
        }
#endif
        throw CollabFaultPointInjected(name);
    }
}

#ifdef _WIN32
static bool create_sentinel_exclusive(const fs::path& sentinel_path, const std::string& content) {
    HANDLE hFile = CreateFileW(
        sentinel_path.wstring().c_str(),
        GENERIC_WRITE,
        0, // exclusive
        nullptr,
        CREATE_NEW, // fail if exists
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
            return false;
        }
        throw std::runtime_error("failed to create sentinel file: " + sentinel_path.string() + " (error: " + std::to_string(err) + ")");
    }
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
    CloseHandle(hFile);
    if (!ok || written != content.size()) {
        throw std::runtime_error("failed to write sentinel content to " + sentinel_path.string());
    }
    return true;
}
#else
static bool create_sentinel_exclusive(const fs::path& sentinel_path, const std::string& content) {
    int fd = open(sentinel_path.string().c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            return false;
        }
        throw std::runtime_error("failed to create sentinel file: " + sentinel_path.string() + " (errno: " + std::to_string(errno) + ")");
    }
    ssize_t written = write(fd, content.data(), content.size());
    close(fd);
    if (written < 0 || static_cast<std::size_t>(written) != content.size()) {
        throw std::runtime_error("failed to write sentinel content to " + sentinel_path.string());
    }
    return true;
}
#endif

CollabStore::CollabStore(const fs::path& db_path, const fs::path& base_storage_dir)
    : db_path_(db_path), base_storage_dir_(base_storage_dir) {
    fs::create_directories(db_path_.parent_path());
    fs::create_directories(base_storage_dir_);

    const int rc = sqlite3_open(db_path_.u8string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "failed to open database";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("CollabStore database error: " + err);
    }

    // Enable WAL and foreign keys.
    // db_mutex_ not required here: single-threaded construction phase.
    execute_sql("PRAGMA journal_mode = WAL;");
    execute_sql("PRAGMA foreign_keys = ON;");

    // Initialize Content-Addressed Storage (CAS)
    cas::ObjectStoreConfig cas_cfg{cas_root_dir()};
    cas_cfg.verify_on_read = true;
    cas_cfg.verify_on_write = true;
    cas_store_ = std::make_unique<cas::ObjectStore>(std::move(cas_cfg));
    std::string cas_err;
    if (!cas_store_->initialize(cas_err)) {
        throw std::runtime_error("Failed to initialize CAS store: " + cas_err);
    }

    init_schema();
    seed_default_accounts_if_empty();
    recover_incomplete_operations();
}

CollabStore::~CollabStore() {
    const auto result = finalize_and_close(); // noexcept
    if (result == FinalizeResult::CLOSE_FAILED) {
        // sqlite3_close_v2 defers resource release until all remaining
        // statements are finalized. Always succeeds from caller perspective.
        // Used only here as last-resort fallback to prevent a hard leak.
        if (db_) {
            sqlite3_close_v2(db_);
            db_ = nullptr;
            std::cerr << "[ERROR] CollabStore destructor: sqlite3_close returned BUSY. "
                         "Used sqlite3_close_v2 to defer cleanup. "
                         "Investigate unregistered prepared statements." << std::endl;
        }
    }
}

FinalizeResult CollabStore::finalize_and_close() noexcept {
    // Phase 0: Signal shutdown and drain all in-flight operations.
    {
        std::unique_lock<std::mutex> life_lock(lifecycle_mutex_);
        if (finalized_) return FinalizeResult::ALREADY_FINALIZED;
        shutting_down_ = true;
        drain_cv_.wait(life_lock, [this]() { return active_ops_ == 0; });
        // active_ops_ == 0; no new OperationGuard can be admitted.
    }

    std::lock_guard<std::mutex> db_lock(db_mutex_);

    if (!db_) {
        std::lock_guard<std::mutex> lk(lifecycle_mutex_);
        finalized_ = true;
        return FinalizeResult::ALREADY_FINALIZED;
    }

    // Phase 1: Force-finalize any remaining live statements before close.
    const std::size_t leaked = stmt_registry_.finalize_all();
    if (leaked > 0) {
        std::cerr << "[WARN] CollabStore::finalize_and_close: force-finalized "
                  << leaked << " leaked prepared statement(s). "
                  << "Check all sqlite3_prepare_v2 call sites use stmt_registry_."
                  << std::endl;
    }

    // Phase 2: WAL checkpoint (best-effort; non-fatal on failure).
    bool checkpoint_ok = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        const int cp_rc = sqlite3_wal_checkpoint_v2(
            db_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
        if (cp_rc == SQLITE_OK) { checkpoint_ok = true; break; }
        if (cp_rc == SQLITE_BUSY || cp_rc == SQLITE_LOCKED) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20 << attempt));
            continue;
        }
        std::cerr << "[WARN] CollabStore::finalize_and_close: WAL checkpoint failed (rc="
                  << cp_rc << "): " << sqlite3_errmsg(db_) << std::endl;
        break;
    }

    // Phase 3: Close the connection.
    const int close_rc = sqlite3_close(db_);
    if (close_rc != SQLITE_OK) {
        std::cerr << "[ERROR] CollabStore::finalize_and_close: sqlite3_close failed (rc="
                  << close_rc << "): " << sqlite3_errmsg(db_)
                  << ". Database handle retained for retry." << std::endl;
        return FinalizeResult::CLOSE_FAILED;
    }

    db_ = nullptr;
    {
        std::lock_guard<std::mutex> lk(lifecycle_mutex_);
        finalized_ = true;
    }
    return checkpoint_ok ? FinalizeResult::OK : FinalizeResult::CHECKPOINT_FAILED;
}

std::unique_lock<std::mutex> CollabStore::get_workspace_lock(const std::string& ws_id) const {
    std::shared_ptr<std::mutex> ws_mutex;
    {
        std::lock_guard<std::mutex> reg_lock(ws_registry_mutex_);
        auto it = ws_mutexes_.find(ws_id);
        if (it == ws_mutexes_.end()) {
            ws_mutex = std::make_shared<std::mutex>();
            ws_mutexes_[ws_id] = ws_mutex;
        } else {
            ws_mutex = it->second;
        }
    }
    return std::unique_lock<std::mutex>(*ws_mutex);
}

std::int64_t CollabStore::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void CollabStore::execute_sql(const std::string& sql) {
    // Precondition: caller must hold db_mutex_.
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        throw std::runtime_error("SQL execution failed: " + err + " (Query: " + sql + ")");
    }
}

std::string CollabStore::generate_random_token(std::size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1) {
        throw std::runtime_error("failed to generate cryptographically secure random bytes");
    }
    return to_hex(buf.data(), bytes);
}

std::string CollabStore::hash_password(const std::string& password) {
    constexpr int iterations = 100000;
    constexpr int salt_len = 16;
    constexpr int key_len = 32;

    std::vector<unsigned char> salt(salt_len);
    if (RAND_bytes(salt.data(), salt_len) != 1) {
        throw std::runtime_error("failed to generate password salt");
    }

    std::vector<unsigned char> key(key_len);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                          salt.data(), salt_len, iterations,
                          EVP_sha256(), key_len, key.data()) != 1) {
        throw std::runtime_error("PBKDF2 password hashing failed");
    }

    std::ostringstream ss;
    ss << "$pbkdf2-sha256$" << iterations << "$" << to_hex(salt.data(), salt_len) << "$" << to_hex(key.data(), key_len);
    return ss.str();
}

bool CollabStore::verify_password(const std::string& password, const std::string& stored_hash) {
    // Expected format: $pbkdf2-sha256$iterations$salt$hash
    if (stored_hash.rfind("$pbkdf2-sha256$", 0) != 0) return false;
    const auto parts = split_strings(stored_hash, '$');
    if (parts.size() < 4) return false;

    int iterations = 0;
    try {
        iterations = std::stoi(parts[1]);
    } catch (...) {
        return false;
    }

    const auto salt = from_hex(parts[2]);
    const auto expected_key = from_hex(parts[3]);
    if (salt.empty() || expected_key.empty()) return false;

    std::vector<unsigned char> computed_key(expected_key.size());
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                          salt.data(), static_cast<int>(salt.size()), iterations,
                          EVP_sha256(), static_cast<int>(computed_key.size()), computed_key.data()) != 1) {
        return false;
    }

    return CRYPTO_memcmp(computed_key.data(), expected_key.data(), expected_key.size()) == 0;
}

void CollabStore::init_schema() {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            permissions TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            last_login_ms INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS workspaces (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            root_path TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS workspace_members (
            workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (workspace_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES users(id),
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            file_count INTEGER NOT NULL,
            total_size INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            status TEXT NOT NULL,
            review_notes TEXT,
            submitted_at_ms INTEGER NOT NULL,
            reviewed_at_ms INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS published_versions (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            parent_version_id TEXT,
            title TEXT NOT NULL,
            release_notes TEXT,
            merkle_root TEXT NOT NULL,
            file_count INTEGER NOT NULL,
            total_size INTEGER NOT NULL,
            published_by_id TEXT NOT NULL REFERENCES users(id),
            published_at_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS client_updates (
            id TEXT PRIMARY KEY,
            version_id TEXT NOT NULL REFERENCES published_versions(id) ON DELETE CASCADE,
            client_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            accepted_at_ms INTEGER NOT NULL DEFAULT 0,
            applied_at_ms INTEGER NOT NULL DEFAULT 0,
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id TEXT,
            actor_username TEXT,
            action TEXT NOT NULL,
            resource TEXT,
            outcome TEXT NOT NULL,
            detail TEXT,
            timestamp_ms INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_submissions_client ON submissions(client_id);
        CREATE INDEX IF NOT EXISTS idx_submissions_ws ON submissions(workspace_id);
        CREATE INDEX IF NOT EXISTS idx_versions_ws ON published_versions(workspace_id);
        CREATE INDEX IF NOT EXISTS idx_updates_client ON client_updates(client_id);

        CREATE TABLE IF NOT EXISTS workspace_operations (
            op_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id),
            operation_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            state TEXT NOT NULL,
            intent_step TEXT NOT NULL,
            expected_base_hash TEXT NOT NULL,
            expected_work_hash TEXT NOT NULL,
            replacement_hash TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_workspace_ops_ws ON workspace_operations(workspace_id);
        CREATE INDEX IF NOT EXISTS idx_workspace_ops_state ON workspace_operations(state);
        CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp_ms);

        -- Milestone 3.2: Content-Addressed Storage (CAS) Metadata
        CREATE TABLE IF NOT EXISTS cas_chunks (
            chunk_hash TEXT PRIMARY KEY,
            chunk_size INTEGER NOT NULL,
            reference_count INTEGER NOT NULL DEFAULT 0 CHECK(reference_count >= 0),
            created_at_ms INTEGER NOT NULL,
            verified_at_ms INTEGER NOT NULL,
            storage_state TEXT NOT NULL DEFAULT 'COMMITTED'
        );
        CREATE INDEX IF NOT EXISTS idx_cas_chunks_ref ON cas_chunks(reference_count);
        CREATE INDEX IF NOT EXISTS idx_cas_chunks_state ON cas_chunks(storage_state);

        CREATE TABLE IF NOT EXISTS version_manifests (
            manifest_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            version_id TEXT NOT NULL REFERENCES published_versions(id) ON DELETE CASCADE,
            relative_path TEXT NOT NULL,
            whole_file_sha256 TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            chunk_count INTEGER NOT NULL,
            manifest_blob BLOB,
            created_at_ms INTEGER NOT NULL,
            UNIQUE(version_id, relative_path)
        );
        CREATE INDEX IF NOT EXISTS idx_version_manifests_ver ON version_manifests(version_id);
        CREATE INDEX IF NOT EXISTS idx_version_manifests_ws ON version_manifests(workspace_id);
        CREATE INDEX IF NOT EXISTS idx_version_manifests_hash ON version_manifests(whole_file_sha256);

        CREATE TABLE IF NOT EXISTS version_manifest_chunks (
            manifest_id TEXT NOT NULL REFERENCES version_manifests(manifest_id) ON DELETE CASCADE,
            chunk_index INTEGER NOT NULL,
            chunk_hash TEXT NOT NULL REFERENCES cas_chunks(chunk_hash),
            chunk_size INTEGER NOT NULL,
            PRIMARY KEY (manifest_id, chunk_index)
        );
        CREATE INDEX IF NOT EXISTS idx_manifest_chunks_hash ON version_manifest_chunks(chunk_hash);
        CREATE INDEX IF NOT EXISTS idx_manifest_chunks_man ON version_manifest_chunks(manifest_id);
    )";
    execute_sql(schema);
}

void CollabStore::seed_default_accounts_if_empty() {
    OperationGuard op_guard(*this);
    sqlite3_stmt* stmt = nullptr;
    int count = 0;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        stmt = stmt_registry_.prepare(db_, "SELECT COUNT(*) FROM users"); if (!stmt) return;
        if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
        stmt_registry_.finalize(stmt);
    }

    if (count == 0) {
        // Seed default host account: host / MerkleHost2026!
        const auto host_user = create_user("host", "MerkleHost2026!", "host",
            {"submit", "view_versions", "download_updates", "accept_updates", "admin"});
        record_event(host_user.id, "system", "ACCOUNT_SEEDED", "user:host", "success", "Default host account provisioned");

        // Seed default client account: client_alice / AliceClient2026!
        const auto client_user = create_user("client_alice", "AliceClient2026!", "client",
            {"submit", "view_versions", "download_updates", "accept_updates"});
        record_event(client_user.id, "system", "ACCOUNT_SEEDED", "user:client_alice", "success", "Default client account provisioned");

        // Seed default workspace: Default-Workspace
        const auto ws = create_workspace("Default-Workspace", "Primary collaboration workspace for synchronized files", "ws-default");
        assign_user_to_workspace(ws.id, host_user.id);
        assign_user_to_workspace(ws.id, client_user.id);
        record_event(host_user.id, "system", "WORKSPACE_SEEDED", "workspace:" + ws.id, "success", "Default workspace configured");
    }
}

CollabUser CollabStore::create_user(const std::string& username,
                                     const std::string& password,
                                     const std::string& role,
                                     const std::vector<std::string>& permissions) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    if (username.empty()) throw std::runtime_error("username cannot be empty");
    if (password.length() < 8) throw std::runtime_error("password must be at least 8 characters");
    if (role != "host" && role != "client") throw std::runtime_error("role must be 'host' or 'client'");

    CollabUser user;
    user.id = "usr_" + generate_random_token(12);
    user.username = username;
    user.password_hash = hash_password(password);
    user.role = role;
    user.status = "active";
    user.permissions = permissions;
    user.created_at_ms = now_ms();
    user.last_login_ms = 0;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO users (id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) {
        throw std::runtime_error("failed to prepare user insert statement");
    }

    const auto perms_str = join_strings(user.permissions);
    sqlite3_bind_text(stmt, 1, user.id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user.username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user.password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, user.role.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, user.status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, perms_str.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, user.created_at_ms);
    sqlite3_bind_int64(stmt, 8, user.last_login_ms);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db_);
        stmt_registry_.finalize(stmt);
        throw std::runtime_error("failed to create user: " + err);
    }
    stmt_registry_.finalize(stmt);

    return user;
}

// Precondition: caller must hold db_mutex_.
std::optional<CollabUser> CollabStore::find_user_by_id_nolock(const std::string& user_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms FROM users WHERE id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabUser u;
        u.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        u.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        u.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        u.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        u.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        u.permissions = split_strings(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)));
        u.created_at_ms = sqlite3_column_int64(stmt, 6);
        u.last_login_ms = sqlite3_column_int64(stmt, 7);
        stmt_registry_.finalize(stmt);
        return u;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

std::optional<CollabUser> CollabStore::find_user_by_id(const std::string& user_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    return find_user_by_id_nolock(user_id);
}

// Precondition: caller must hold db_mutex_.
std::optional<CollabUser> CollabStore::find_user_by_username_nolock(const std::string& username) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms FROM users WHERE username = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabUser u;
        u.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        u.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        u.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        u.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        u.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        u.permissions = split_strings(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)));
        u.created_at_ms = sqlite3_column_int64(stmt, 6);
        u.last_login_ms = sqlite3_column_int64(stmt, 7);
        stmt_registry_.finalize(stmt);
        return u;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

std::optional<CollabUser> CollabStore::find_user_by_username(const std::string& username) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    return find_user_by_username_nolock(username);
}

std::vector<CollabUser> CollabStore::list_clients() {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::vector<CollabUser> users;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms FROM users ORDER BY created_at_ms DESC";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return users;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabUser u;
        u.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        u.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        u.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        u.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        u.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        u.permissions = split_strings(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)));
        u.created_at_ms = sqlite3_column_int64(stmt, 6);
        u.last_login_ms = sqlite3_column_int64(stmt, 7);
        users.push_back(u);
    }
    stmt_registry_.finalize(stmt);
    return users;
}

bool CollabStore::set_user_status(const std::string& user_id, const std::string& status) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE users SET status = ? WHERE id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return false;
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    stmt_registry_.finalize(stmt);

    if (ok && status == "suspended") {
        revoke_all_user_sessions_nolock(user_id);
    }
    return ok;
}

bool CollabStore::reset_user_password(const std::string& user_id, const std::string& new_password) {
    if (new_password.length() < 8) throw std::runtime_error("password must be at least 8 characters");
    const auto hash = hash_password(new_password);

    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE users SET password_hash = ? WHERE id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return false;
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    stmt_registry_.finalize(stmt);

    if (ok) {
        revoke_all_user_sessions_nolock(user_id);
    }
    return ok;
}

bool CollabStore::update_user_permissions(const std::string& user_id, const std::vector<std::string>& permissions) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    const auto perms_str = join_strings(permissions);
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE users SET permissions = ? WHERE id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return false;
    sqlite3_bind_text(stmt, 1, perms_str.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    stmt_registry_.finalize(stmt);
    return ok;
}

std::optional<CollabSession> CollabStore::authenticate(const std::string& username,
                                                        const std::string& password,
                                                        std::string& error_out) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    const auto user_opt = find_user_by_username_nolock(username);
    if (!user_opt) {
        error_out = "Invalid username or password";
        return std::nullopt;
    }
    const auto& user = *user_opt;
    if (user.status == "suspended") {
        error_out = "Account is suspended. Please contact administrator.";
        return std::nullopt;
    }
    if (!verify_password(password, user.password_hash)) {
        error_out = "Invalid username or password";
        return std::nullopt;
    }

    // Update last login
    const auto current_time = now_ms();
    {
        sqlite3_stmt* stmt = nullptr;
        stmt = stmt_registry_.prepare(db_, "UPDATE users SET last_login_ms = ? WHERE id = ?"); if (stmt) {
            sqlite3_bind_int64(stmt, 1, current_time);
            sqlite3_bind_text(stmt, 2, user.id.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            stmt_registry_.finalize(stmt);
        }
    }

    // Create session (24h validity)
    CollabSession session;
    session.token = "ses_" + generate_random_token(24);
    session.user_id = user.id;
    session.username = user.username;
    session.role = user.role;
    session.created_at_ms = current_time;
    session.expires_at_ms = current_time + (24LL * 60LL * 60LL * 1000LL);
    session.active = true;

    {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "INSERT INTO sessions (token, user_id, created_at_ms, expires_at_ms, active) VALUES (?, ?, ?, ?, 1)";
        stmt = stmt_registry_.prepare(db_, sql); if (stmt) {
            sqlite3_bind_text(stmt, 1, session.token.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, session.user_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 3, session.created_at_ms);
            sqlite3_bind_int64(stmt, 4, session.expires_at_ms);
            sqlite3_step(stmt);
            stmt_registry_.finalize(stmt);
        }
    }

    return session;
}

// Precondition: caller must hold db_mutex_.
void CollabStore::revoke_session_nolock(const std::string& token) {
    sqlite3_stmt* stmt = nullptr;
    stmt = stmt_registry_.prepare(db_, "UPDATE sessions SET active = 0 WHERE token = ?"); if (stmt) {
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        stmt_registry_.finalize(stmt);
    }
}

void CollabStore::revoke_session(const std::string& token) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    revoke_session_nolock(token);
}

// Precondition: caller must hold db_mutex_.
void CollabStore::revoke_all_user_sessions_nolock(const std::string& user_id) {
    sqlite3_stmt* stmt = nullptr;
    stmt = stmt_registry_.prepare(db_, "UPDATE sessions SET active = 0 WHERE user_id = ?"); if (stmt) {
        sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        stmt_registry_.finalize(stmt);
    }
}

void CollabStore::revoke_all_user_sessions(const std::string& user_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    revoke_all_user_sessions_nolock(user_id);
}

std::optional<CollabSession> CollabStore::validate_session(const std::string& token) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    if (token.empty()) return std::nullopt;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT s.token, s.user_id, u.username, u.role, s.created_at_ms, s.expires_at_ms, s.active, u.status
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.active = 1
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabSession s;
        s.token = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        s.user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        s.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        s.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        s.created_at_ms = sqlite3_column_int64(stmt, 4);
        s.expires_at_ms = sqlite3_column_int64(stmt, 5);
        s.active = sqlite3_column_int(stmt, 6) != 0;
        const std::string user_status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        stmt_registry_.finalize(stmt);

        if (user_status != "active" || now_ms() > s.expires_at_ms) {
            revoke_session_nolock(token);
            return std::nullopt;
        }
        return s;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

CollabWorkspace CollabStore::create_workspace(const std::string& name, const std::string& description, const std::string& custom_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    CollabWorkspace ws;
    ws.id = custom_id.empty() ? ("ws_" + generate_random_token(8)) : custom_id;
    ws.name = name;
    ws.description = description;
    ws.root_path = base_storage_dir_ / "workspaces" / ws.id;
    ws.created_at_ms = now_ms();

    fs::create_directories(ws.root_path);
    fs::create_directories(workspace_submissions_dir(ws.id));
    fs::create_directories(workspace_baseline_dir(ws.id));
    fs::create_directories(workspace_working_copy_dir(ws.id));
    fs::create_directories(workspace_versions_dir(ws.id));

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO workspaces (id, name, description, root_path, created_at_ms) VALUES (?, ?, ?, ?, ?)";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) {
        throw std::runtime_error("failed to prepare workspace insert");
    }

    const auto root_str = ws.root_path.u8string();
    sqlite3_bind_text(stmt, 1, ws.id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ws.name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, ws.description.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, root_str.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, ws.created_at_ms);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db_);
        stmt_registry_.finalize(stmt);
        throw std::runtime_error("failed to create workspace: " + err);
    }
    stmt_registry_.finalize(stmt);

    return ws;
}

// Precondition: caller must hold db_mutex_.
std::vector<CollabWorkspace> CollabStore::list_workspaces_nolock() {
    std::vector<CollabWorkspace> workspaces;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, name, description, root_path, created_at_ms FROM workspaces ORDER BY created_at_ms ASC";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return workspaces;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabWorkspace ws;
        ws.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ws.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* desc = sqlite3_column_text(stmt, 2);
        ws.description = desc ? reinterpret_cast<const char*>(desc) : "";
        ws.root_path = fs::u8path(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
        ws.created_at_ms = sqlite3_column_int64(stmt, 4);
        workspaces.push_back(ws);
    }
    stmt_registry_.finalize(stmt);
    return workspaces;
}

std::vector<CollabWorkspace> CollabStore::list_workspaces() {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    return list_workspaces_nolock();
}

// Precondition: caller must hold db_mutex_.
std::optional<CollabWorkspace> CollabStore::find_workspace_by_id_nolock(const std::string& ws_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, name, description, root_path, created_at_ms FROM workspaces WHERE id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, ws_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabWorkspace ws;
        ws.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ws.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* desc = sqlite3_column_text(stmt, 2);
        ws.description = desc ? reinterpret_cast<const char*>(desc) : "";
        ws.root_path = fs::u8path(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
        ws.created_at_ms = sqlite3_column_int64(stmt, 4);
        stmt_registry_.finalize(stmt);
        return ws;
    }
    stmt_registry_.finalize(stmt);

    if (ws_id == "ws-default") {
        auto list = list_workspaces_nolock();
        for (const auto& w : list) {
            if (w.name == "Default-Workspace") return w;
        }
        if (!list.empty()) return list.front();
    }
    return std::nullopt;
}

std::optional<CollabWorkspace> CollabStore::find_workspace_by_id(const std::string& ws_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    return find_workspace_by_id_nolock(ws_id);
}

std::vector<CollabWorkspace> CollabStore::list_workspaces_for_user(const std::string& user_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::vector<CollabWorkspace> workspaces;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT w.id, w.name, w.description, w.root_path, w.created_at_ms
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE wm.user_id = ?
        ORDER BY w.created_at_ms ASC
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return workspaces;
    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabWorkspace ws;
        ws.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ws.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* desc = sqlite3_column_text(stmt, 2);
        ws.description = desc ? reinterpret_cast<const char*>(desc) : "";
        ws.root_path = fs::u8path(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
        ws.created_at_ms = sqlite3_column_int64(stmt, 4);
        workspaces.push_back(ws);
    }
    stmt_registry_.finalize(stmt);
    return workspaces;
}

void CollabStore::assign_user_to_workspace(const std::string& workspace_id, const std::string& user_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::string actual_id = workspace_id;
    const auto ws_resolved = find_workspace_by_id_nolock(workspace_id);
    if (ws_resolved) actual_id = ws_resolved->id;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR IGNORE INTO workspace_members (workspace_id, user_id) VALUES (?, ?)";
    stmt = stmt_registry_.prepare(db_, sql); if (stmt) {
        sqlite3_bind_text(stmt, 1, actual_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        stmt_registry_.finalize(stmt);
    }
}

bool CollabStore::is_user_in_workspace(const std::string& workspace_id, const std::string& user_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::string actual_id = workspace_id;
    const auto ws_resolved = find_workspace_by_id_nolock(workspace_id);
    if (ws_resolved) actual_id = ws_resolved->id;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return false;
    sqlite3_bind_text(stmt, 1, actual_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    stmt_registry_.finalize(stmt);
    return found;
}

fs::path CollabStore::workspace_root(const std::string& ws_id) const {
    // Path helpers use ws_id directly. Alias resolution ("ws-default") is
    // performed at the API boundary by find_workspace_by_id() before any
    // path helper is called -- not here, to avoid re-entrant db_mutex_ acquisition.
    return base_storage_dir_ / "workspaces" / ws_id;
}
fs::path CollabStore::workspace_submissions_dir(const std::string& ws_id) const {
    return workspace_root(ws_id) / "submissions";
}
fs::path CollabStore::workspace_baseline_dir(const std::string& ws_id) const {
    return workspace_root(ws_id) / "baseline";
}
fs::path CollabStore::workspace_working_copy_dir(const std::string& ws_id) const {
    return workspace_root(ws_id) / "working_copy";
}
fs::path CollabStore::workspace_versions_dir(const std::string& ws_id) const {
    return workspace_root(ws_id) / "versions";
}

CollabSubmission CollabStore::create_submission(const std::string& client_id,
                                                const std::string& workspace_id,
                                                const fs::path& source_folder) {
    OperationGuard op_guard(*this);

    if (!fs::is_directory(source_folder)) {
        throw std::runtime_error("submission source folder is not an accessible directory");
    }

    // Resolve workspace ID under db_mutex_
    std::string actual_ws_id = workspace_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        auto ws = find_workspace_by_id_nolock(workspace_id);
        if (ws) actual_ws_id = ws->id;
    }

    // Acquire workspace lock across the entire logical operation
    auto ws_lock = get_workspace_lock(actual_ws_id);

    const auto manifest = scan_folder(source_folder);
    if (!manifest.complete) {
        throw std::runtime_error("cannot scan submission source folder; manifest incomplete");
    }

    CollabSubmission sub;
    sub.id = "sub_" + generate_random_token(10);
    sub.client_id = client_id;
    sub.workspace_id = actual_ws_id;
    sub.file_count = manifest.files.size();
    sub.total_size = 0;
    for (const auto& f : manifest.files) sub.total_size += f.size;
    sub.merkle_root = manifest.merkle_root;
    sub.status = "pending";
    sub.review_notes = "";
    sub.submitted_at_ms = now_ms();
    sub.reviewed_at_ms = 0;

    // Stage files in workspace submissions directory under ws_lock
    const auto target_dir = workspace_submissions_dir(actual_ws_id) / sub.id;
    copy_directory_recursive(source_folder, target_dir);

    // Verify staged folder matches expected Merkle root
    const auto staged_manifest = scan_folder(target_dir);
    if (!staged_manifest.complete || staged_manifest.merkle_root != sub.merkle_root) {
        fs::remove_all(target_dir);
        throw std::runtime_error("submission integrity verification failed upon staging");
    }

    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        sqlite3_stmt* stmt = nullptr;
        const char* sql = R"(
            INSERT INTO submissions (id, client_id, workspace_id, file_count, total_size, merkle_root, status, review_notes, submitted_at_ms, reviewed_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";
        stmt = stmt_registry_.prepare(db_, sql); if (!stmt) {
            throw std::runtime_error("failed to prepare submission record insert");
        }

        sqlite3_bind_text(stmt, 1, sub.id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, sub.client_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, sub.workspace_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(sub.file_count));
        sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(sub.total_size));
        sqlite3_bind_text(stmt, 6, sub.merkle_root.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, sub.status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, sub.review_notes.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 9, sub.submitted_at_ms);
        sqlite3_bind_int64(stmt, 10, sub.reviewed_at_ms);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::string err = sqlite3_errmsg(db_);
            stmt_registry_.finalize(stmt);
            throw std::runtime_error("failed to record submission: " + err);
        }
        stmt_registry_.finalize(stmt);
    }

    const auto user = find_user_by_id(client_id);
    record_event(client_id, user ? user->username : "unknown", "SUBMISSION_CREATED",
                 "submission:" + sub.id, "success",
                 "Submitted " + std::to_string(sub.file_count) + " files (root: " + sub.merkle_root.substr(0, 12) + "...)");

    return sub;
}

// Precondition: caller must hold db_mutex_.
std::optional<CollabSubmission> CollabStore::find_submission_by_id_nolock(const std::string& sub_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
        FROM submissions s
        JOIN users u ON s.client_id = u.id
        WHERE s.id = ?
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, sub_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabSubmission s;
        s.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        s.client_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        s.client_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        s.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        s.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 4));
        s.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 5));
        s.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        s.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        const auto* notes = sqlite3_column_text(stmt, 8);
        s.review_notes = notes ? reinterpret_cast<const char*>(notes) : "";
        s.submitted_at_ms = sqlite3_column_int64(stmt, 9);
        s.reviewed_at_ms = sqlite3_column_int64(stmt, 10);
        stmt_registry_.finalize(stmt);
        return s;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

std::optional<CollabSubmission> CollabStore::find_submission_by_id(const std::string& sub_id) {
    OperationGuard op_guard(*this);

    // 1. Retrieve workspace ID under db_mutex_
    std::string ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto sub_pre = find_submission_by_id_nolock(sub_id);
        if (!sub_pre) return std::nullopt;
        ws_id = sub_pre->workspace_id;
    }

    // 2. Acquire workspace lock
    auto ws_lock = get_workspace_lock(ws_id);

    // 3. Re-read and validate under db_mutex_
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    const auto sub = find_submission_by_id_nolock(sub_id);
    if (!sub || sub->workspace_id != ws_id) return std::nullopt;

    return sub;
}

std::vector<CollabSubmission> CollabStore::list_submissions(const std::string& workspace_id) {
    OperationGuard op_guard(*this);

    if (workspace_id.empty()) {
        // Global administrative reader: database-only
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        std::vector<CollabSubmission> list;
        sqlite3_stmt* stmt = nullptr;
        const char* sql = R"(
            SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
            FROM submissions s
            JOIN users u ON s.client_id = u.id
            ORDER BY s.submitted_at_ms DESC
        )";
        stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return list;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            CollabSubmission s;
            s.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            s.client_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            s.client_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            s.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            s.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 4));
            s.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 5));
            s.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            s.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const auto* notes = sqlite3_column_text(stmt, 8);
            s.review_notes = notes ? reinterpret_cast<const char*>(notes) : "";
            s.submitted_at_ms = sqlite3_column_int64(stmt, 9);
            s.reviewed_at_ms = sqlite3_column_int64(stmt, 10);
            list.push_back(s);
        }
        stmt_registry_.finalize(stmt);
        return list;
    }

    // Workspace-correlated reader: resolve workspace ID under db_mutex_
    std::string actual_ws_id = workspace_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(workspace_id);
        if (ws) actual_ws_id = ws->id;
    }

    // Acquire workspace lock
    auto ws_lock = get_workspace_lock(actual_ws_id);

    std::vector<CollabSubmission> list;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        sqlite3_stmt* stmt = nullptr;
        const char* sql = R"(
            SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
            FROM submissions s
            JOIN users u ON s.client_id = u.id
            WHERE s.workspace_id = ?
            ORDER BY s.submitted_at_ms DESC
        )";
        stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return list;
        sqlite3_bind_text(stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            CollabSubmission s;
            s.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            s.client_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            s.client_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            s.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            s.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 4));
            s.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 5));
            s.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            s.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            const auto* notes = sqlite3_column_text(stmt, 8);
            s.review_notes = notes ? reinterpret_cast<const char*>(notes) : "";
            s.submitted_at_ms = sqlite3_column_int64(stmt, 9);
            s.reviewed_at_ms = sqlite3_column_int64(stmt, 10);
            list.push_back(s);
        }
        stmt_registry_.finalize(stmt);
    }
    return list;
}

std::vector<CollabSubmission> CollabStore::list_submissions_for_client(const std::string& client_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::vector<CollabSubmission> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
        FROM submissions s
        JOIN users u ON s.client_id = u.id
        WHERE s.client_id = ?
        ORDER BY s.submitted_at_ms DESC
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return list;
    sqlite3_bind_text(stmt, 1, client_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabSubmission s;
        s.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        s.client_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        s.client_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        s.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        s.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 4));
        s.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 5));
        s.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        s.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        const auto* notes = sqlite3_column_text(stmt, 8);
        s.review_notes = notes ? reinterpret_cast<const char*>(notes) : "";
        s.submitted_at_ms = sqlite3_column_int64(stmt, 9);
        s.reviewed_at_ms = sqlite3_column_int64(stmt, 10);
        list.push_back(s);
    }
    stmt_registry_.finalize(stmt);
    return list;
}


bool CollabStore::create_sentinel_file(const fs::path& dir_path,
                                       const std::string& op_id,
                                       const std::string& ws_id,
                                       const std::string& op_type,
                                       const std::string& dir_role) {
    if (is_reparse_point_or_symlink(dir_path)) {
        throw std::runtime_error("reparse point detected at " + dir_path.string() + " -- refusing sentinel creation");
    }
    const auto sentinel_path = dir_path / ".syncora_op_sentinel";
    std::string content = "op_id=" + op_id + "\n" +
                          "workspace_id=" + ws_id + "\n" +
                          "op_type=" + op_type + "\n" +
                          "dir_role=" + dir_role + "\n" +
                          "created_at_ms=" + std::to_string(now_ms()) + "\n";
    return create_sentinel_exclusive(sentinel_path, content);
}

SentinelValidationResult CollabStore::validate_sentinel_file(const fs::path& dir_path,
                                                            const std::string& expected_op_id,
                                                            const std::string& expected_ws_id,
                                                            const std::string& expected_role) const {
    SentinelValidationResult res;
    if (is_reparse_point_or_symlink(dir_path)) {
        res.error = "directory is a reparse point or symlink";
        return res;
    }
    const auto sentinel_path = dir_path / ".syncora_op_sentinel";
    if (!fs::exists(sentinel_path) || !fs::is_regular_file(sentinel_path)) {
        res.error = "sentinel file missing or not regular file";
        return res;
    }
    std::ifstream f(sentinel_path, std::ios::binary);
    if (!f.is_open()) {
        res.error = "cannot open sentinel file";
        return res;
    }
    std::string line;
    std::unordered_map<std::string, std::string> kv;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto eq = line.find('=');
        if (eq != std::string::npos) {
            kv[line.substr(0, eq)] = line.substr(eq + 1);
        }
    }
    res.op_id = kv["op_id"];
    res.workspace_id = kv["workspace_id"];
    res.op_type = kv["op_type"];
    res.dir_role = kv["dir_role"];
    try {
        if (!kv["created_at_ms"].empty()) {
            res.created_at_ms = std::stoll(kv["created_at_ms"]);
        }
    } catch (...) {
        res.error = "invalid created_at_ms in sentinel";
        return res;
    }

    if (res.op_id.empty() || res.workspace_id.empty() || res.op_type.empty() || res.dir_role.empty() || res.created_at_ms <= 0) {
        res.error = "missing required fields in sentinel";
        return res;
    }

    const std::string dirname = dir_path.filename().string();
    if (dirname.rfind(".staging_", 0) == 0 || dirname.rfind(".backup_", 0) == 0) {
        std::string embedded_op_id;
        const auto op_pos = dirname.find("_op_");
        if (op_pos != std::string::npos) {
            embedded_op_id = dirname.substr(op_pos + 1);
        } else if (dirname.rfind(".staging_base_", 0) == 0 || dirname.rfind(".staging_work_", 0) == 0) {
            embedded_op_id = dirname.substr(14);
        } else if (dirname.rfind(".staging_ver_", 0) == 0 || dirname.rfind(".backup_base_", 0) == 0 || dirname.rfind(".backup_work_", 0) == 0) {
            embedded_op_id = dirname.substr(13);
        }
        if (!embedded_op_id.empty() && res.op_id != embedded_op_id) {
            res.error = "op_id in sentinel (" + res.op_id + ") does not match directory name suffix (" + embedded_op_id + ")";
            return res;
        }
    }
    if (!expected_op_id.empty() && res.op_id != expected_op_id) {
        res.error = "mismatched op_id (expected " + expected_op_id + ", got " + res.op_id + ")";
        return res;
    }
    if (!expected_ws_id.empty() && res.workspace_id != expected_ws_id) {
        res.error = "mismatched workspace_id (expected " + expected_ws_id + ", got " + res.workspace_id + ")";
        return res;
    }
    if (!expected_role.empty() && res.dir_role != expected_role) {
        res.error = "mismatched dir_role (expected " + expected_role + ", got " + res.dir_role + ")";
        return res;
    }
    res.valid = true;
    return res;
}

void CollabStore::quarantine_directory(const fs::path& suspect_dir,
                                       const std::string& ws_id,
                                       const std::string& reason) {
    if (!fs::exists(suspect_dir)) return;
    const auto q_base = workspace_root(ws_id) / ".quarantine";
    std::error_code ec;
    fs::create_directories(q_base, ec);
    const auto dest = q_base / (suspect_dir.filename().string() + "_" + std::to_string(now_ms()));
    fs::rename(suspect_dir, dest, ec);
    if (!ec) {
        record_event("SYSTEM", "recovery", "QUARANTINE_DIRECTORY",
                     "workspace:" + ws_id, "WARNING",
                     "Quarantined directory: " + suspect_dir.string() + " reason: " + reason);
    }
}

void CollabStore::assert_path_absent(const fs::path& p) const {
    if (fs::exists(p) || is_reparse_point_or_symlink(p)) {
        throw std::runtime_error("path already exists or is a reparse point: " + p.string());
    }
}

void CollabStore::insert_operation_intent_nolock(const WorkspaceOperationRecord& rec) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        INSERT INTO workspace_operations
        (op_id, workspace_id, operation_type, target_id, state, intent_step,
         expected_base_hash, expected_work_hash, replacement_hash, created_at_ms, updated_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    stmt = stmt_registry_.prepare(db_, sql);
    if (!stmt) throw std::runtime_error("failed to prepare workspace operation intent insert");
    sqlite3_bind_text(stmt, 1, rec.op_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, rec.workspace_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, rec.operation_type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, rec.target_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, rec.state.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, rec.intent_step.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, rec.expected_base_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, rec.expected_work_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, rec.replacement_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 10, rec.created_at_ms);
    sqlite3_bind_int64(stmt, 11, rec.updated_at_ms);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db_);
        stmt_registry_.finalize(stmt);
        throw std::runtime_error("failed to insert workspace operation intent: " + err);
    }
    stmt_registry_.finalize(stmt);
}

void CollabStore::update_operation_intent_nolock(const std::string& op_id,
                                                const std::string& state,
                                                const std::string& intent_step) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE workspace_operations SET state = ?, intent_step = ?, updated_at_ms = ? WHERE op_id = ?";
    stmt = stmt_registry_.prepare(db_, sql);
    if (!stmt) throw std::runtime_error("failed to prepare workspace operation intent update");
    sqlite3_bind_text(stmt, 1, state.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, intent_step.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now_ms());
    sqlite3_bind_text(stmt, 4, op_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    stmt_registry_.finalize(stmt);
}

std::optional<WorkspaceOperationRecord> CollabStore::find_workspace_operation_nolock(const std::string& op_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT op_id, workspace_id, operation_type, target_id, state, intent_step,
               expected_base_hash, expected_work_hash, replacement_hash, created_at_ms, updated_at_ms
        FROM workspace_operations WHERE op_id = ?
    )";
    stmt = stmt_registry_.prepare(db_, sql);
    if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, op_id.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        WorkspaceOperationRecord r;
        r.op_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        r.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.operation_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.target_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        r.state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        r.intent_step = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        r.expected_base_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        r.expected_work_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        r.replacement_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        r.created_at_ms = sqlite3_column_int64(stmt, 9);
        r.updated_at_ms = sqlite3_column_int64(stmt, 10);
        stmt_registry_.finalize(stmt);
        return r;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

std::vector<WorkspaceOperationRecord> CollabStore::list_incomplete_operations_nolock() {
    std::vector<WorkspaceOperationRecord> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT op_id, workspace_id, operation_type, target_id, state, intent_step,
               expected_base_hash, expected_work_hash, replacement_hash, created_at_ms, updated_at_ms
        FROM workspace_operations WHERE state NOT IN ('COMMITTED', 'FAILED') ORDER BY created_at_ms ASC
    )";
    stmt = stmt_registry_.prepare(db_, sql);
    if (!stmt) return list;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WorkspaceOperationRecord r;
        r.op_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        r.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.operation_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.target_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        r.state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        r.intent_step = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        r.expected_base_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        r.expected_work_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        r.replacement_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        r.created_at_ms = sqlite3_column_int64(stmt, 9);
        r.updated_at_ms = sqlite3_column_int64(stmt, 10);
        list.push_back(r);
    }
    stmt_registry_.finalize(stmt);
    return list;
}

std::vector<WorkspaceOperationRecord> CollabStore::list_workspace_operations(const std::string& workspace_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    std::vector<WorkspaceOperationRecord> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT op_id, workspace_id, operation_type, target_id, state, intent_step,
               expected_base_hash, expected_work_hash, replacement_hash, created_at_ms, updated_at_ms
        FROM workspace_operations WHERE workspace_id = ? ORDER BY created_at_ms DESC
    )";
    stmt = stmt_registry_.prepare(db_, sql);
    if (!stmt) return list;
    sqlite3_bind_text(stmt, 1, workspace_id.c_str(), -1, SQLITE_STATIC);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WorkspaceOperationRecord r;
        r.op_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        r.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.operation_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.target_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        r.state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        r.intent_step = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        r.expected_base_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        r.expected_work_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        r.replacement_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        r.created_at_ms = sqlite3_column_int64(stmt, 9);
        r.updated_at_ms = sqlite3_column_int64(stmt, 10);
        list.push_back(r);
    }
    stmt_registry_.finalize(stmt);
    return list;
}

std::optional<WorkspaceOperationRecord> CollabStore::find_workspace_operation(const std::string& op_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    return find_workspace_operation_nolock(op_id);
}

void CollabStore::recover_accept_submission_op(const WorkspaceOperationRecord& op) {
    const auto ws_root_dir = workspace_root(op.workspace_id);
    const auto base_dir = workspace_baseline_dir(op.workspace_id);
    const auto work_dir = workspace_working_copy_dir(op.workspace_id);
    const auto staging_base = ws_root_dir / (".staging_base_" + op.op_id);
    const auto staging_work = ws_root_dir / (".staging_work_" + op.op_id);
    const auto backup_base  = ws_root_dir / (".backup_base_" + op.op_id);
    const auto backup_work  = ws_root_dir / (".backup_work_" + op.op_id);

    bool is_committed = false;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        auto cur = find_workspace_operation_nolock(op.op_id);
        if (cur && cur->state == "COMMITTED") is_committed = true;
    }

    if (is_committed) {
        if (fs::exists(backup_base)) {
            auto sres = validate_sentinel_file(backup_base, op.op_id, op.workspace_id, "backup_base");
            if (sres.valid) fs::remove_all(backup_base);
            else quarantine_directory(backup_base, op.workspace_id, "corrupt backup_base sentinel");
        }
        if (fs::exists(backup_work)) {
            auto sres = validate_sentinel_file(backup_work, op.op_id, op.workspace_id, "backup_work");
            if (sres.valid) fs::remove_all(backup_work);
            else quarantine_directory(backup_work, op.workspace_id, "corrupt backup_work sentinel");
        }
        if (fs::exists(staging_base)) fs::remove_all(staging_base);
        if (fs::exists(staging_work)) fs::remove_all(staging_work);

        std::lock_guard<std::mutex> db_lock(db_mutex_);
        update_operation_intent_nolock(op.op_id, "COMMITTED", "COMPLETED");
        record_event_nolock("SYSTEM", "recovery", "RECOVERY_FORWARD_COMPLETED", "workspace:" + op.workspace_id, "success", "Cleaned up backups for committed op " + op.op_id);
        return;
    }

    // Rollback uncommitted operation
    if (fs::exists(backup_base)) {
        auto sres = validate_sentinel_file(backup_base, op.op_id, op.workspace_id, "backup_base");
        if (sres.valid) {
            bool hash_ok = true;
            fs::remove(backup_base / ".syncora_op_sentinel");
            if (op.expected_base_hash != "EMPTY" && op.expected_base_hash != "INITIAL") {
                auto m_clean = scan_folder(backup_base);
                if (m_clean.merkle_root != op.expected_base_hash) hash_ok = false;
            }
            if (hash_ok) {
                fs::remove_all(base_dir);
                fs::rename(backup_base, base_dir);
            } else {
                quarantine_directory(backup_base, op.workspace_id, "hash mismatch on restored backup_base");
            }
        } else {
            quarantine_directory(backup_base, op.workspace_id, sres.error);
        }
    }

    if (fs::exists(backup_work)) {
        auto sres = validate_sentinel_file(backup_work, op.op_id, op.workspace_id, "backup_work");
        if (sres.valid) {
            fs::remove(backup_work / ".syncora_op_sentinel");
            fs::remove_all(work_dir);
            fs::rename(backup_work, work_dir);
        } else {
            quarantine_directory(backup_work, op.workspace_id, sres.error);
        }
    }

    if (fs::exists(staging_base)) {
        auto sres = validate_sentinel_file(staging_base, op.op_id, op.workspace_id, "staging_base");
        if (sres.valid) fs::remove_all(staging_base);
        else quarantine_directory(staging_base, op.workspace_id, sres.error);
    }
    if (fs::exists(staging_work)) {
        auto sres = validate_sentinel_file(staging_work, op.op_id, op.workspace_id, "staging_work");
        if (sres.valid) fs::remove_all(staging_work);
        else quarantine_directory(staging_work, op.workspace_id, sres.error);
    }

    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        update_operation_intent_nolock(op.op_id, "FAILED", "ROLLED_BACK");
        record_event_nolock("SYSTEM", "recovery", "RECOVERY_ROLLBACK_COMPLETED", "workspace:" + op.workspace_id, "success", "Rolled back uncommitted op " + op.op_id);
    }
}

void CollabStore::recover_publish_version_op(const WorkspaceOperationRecord& op) {
    const auto ws_root_dir = workspace_root(op.workspace_id);
    const auto base_dir = workspace_baseline_dir(op.workspace_id);
    const auto versions_dir = workspace_versions_dir(op.workspace_id);
    const auto staging_ver = versions_dir / (".staging_ver_" + op.op_id);
    const auto final_ver = versions_dir / op.target_id;
    const auto staging_base = ws_root_dir / (".staging_base_" + op.op_id);
    const auto backup_base = ws_root_dir / (".backup_base_" + op.op_id);

    bool is_committed = false;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        auto cur = find_workspace_operation_nolock(op.op_id);
        if (cur && cur->state == "COMMITTED") is_committed = true;
    }

    if (is_committed) {
        if (fs::exists(backup_base)) {
            auto sres = validate_sentinel_file(backup_base, op.op_id, op.workspace_id, "backup_base");
            if (sres.valid) fs::remove_all(backup_base);
            else quarantine_directory(backup_base, op.workspace_id, "corrupt backup_base sentinel");
        }
        if (fs::exists(staging_base)) fs::remove_all(staging_base);
        if (fs::exists(staging_ver)) fs::remove_all(staging_ver);
        fs::remove(final_ver / ".syncora_op_sentinel");

        std::lock_guard<std::mutex> db_lock(db_mutex_);
        update_operation_intent_nolock(op.op_id, "COMMITTED", "COMPLETED");
        record_event_nolock("SYSTEM", "recovery", "PUBLICATION_RECOVERY_FORWARD_COMPLETED", "workspace:" + op.workspace_id, "success", "Cleaned up for committed publish op " + op.op_id);
        return;
    }

    // Rollback uncommitted publish
    if (fs::exists(final_ver)) {
        auto sres = validate_sentinel_file(final_ver, op.op_id, op.workspace_id, "version_snapshot");
        if (sres.valid) {
            fs::remove_all(final_ver);
        } else {
            bool published_in_db = false;
            {
                std::lock_guard<std::mutex> db_lock(db_mutex_);
                auto ver = find_version_by_id_nolock(op.target_id);
                if (ver) published_in_db = true;
            }
            if (!published_in_db) {
                quarantine_directory(final_ver, op.workspace_id, "uncommitted version snapshot without valid sentinel");
            }
        }
    }

    trigger_collab_fault_point(CollabFaultPoint::FailDuringRecovery, "FailDuringRecovery");

    if (fs::exists(backup_base)) {
        auto sres = validate_sentinel_file(backup_base, op.op_id, op.workspace_id, "backup_base");
        if (sres.valid) {
            bool hash_ok = true;
            fs::remove(backup_base / ".syncora_op_sentinel");
            if (op.expected_base_hash != "INITIAL" && op.expected_base_hash != "EMPTY") {
                auto m = scan_folder(backup_base);
                if (m.merkle_root != op.expected_base_hash) hash_ok = false;
            }
            if (hash_ok) {
                fs::remove_all(base_dir);
                fs::rename(backup_base, base_dir);
            } else {
                quarantine_directory(backup_base, op.workspace_id, "hash mismatch on restored publication backup_base");
            }
        } else {
            quarantine_directory(backup_base, op.workspace_id, sres.error);
        }
    }

    if (fs::exists(staging_base)) {
        auto sres = validate_sentinel_file(staging_base, op.op_id, op.workspace_id, "staging_base");
        if (sres.valid) fs::remove_all(staging_base);
        else quarantine_directory(staging_base, op.workspace_id, sres.error);
    }
    if (fs::exists(staging_ver)) {
        auto sres = validate_sentinel_file(staging_ver, op.op_id, op.workspace_id, "version_snapshot");
        if (sres.valid) fs::remove_all(staging_ver);
        else quarantine_directory(staging_ver, op.workspace_id, sres.error);
    }

    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        update_operation_intent_nolock(op.op_id, "FAILED", "ROLLED_BACK");
        record_event_nolock("SYSTEM", "recovery", "PUBLICATION_RECOVERY_ROLLBACK_COMPLETED", "workspace:" + op.workspace_id, "success", "Rolled back uncommitted publish op " + op.op_id);
    }
}

void CollabStore::scan_and_reconcile_orphaned_directories(const std::string& ws_id) {
    const auto ws_root_dir = workspace_root(ws_id);
    if (!fs::exists(ws_root_dir)) return;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(ws_root_dir, ec)) {
        if (!entry.is_directory()) continue;
        const std::string name = entry.path().filename().string();
        if (name.rfind(".staging_", 0) == 0 || name.rfind(".backup_", 0) == 0) {
            auto sres = validate_sentinel_file(entry.path(), "", ws_id, "");
            if (!sres.valid) {
                quarantine_directory(entry.path(), ws_id, "orphaned directory with invalid or missing sentinel: " + sres.error);
            } else {
                std::optional<WorkspaceOperationRecord> op;
                {
                    std::lock_guard<std::mutex> db_lock(db_mutex_);
                    op = find_workspace_operation_nolock(sres.op_id);
                }
                if (!op || op->state == "COMMITTED" || op->state == "FAILED") {
                    fs::remove_all(entry.path(), ec);
                }
            }
        }
    }
}

void CollabStore::recover_incomplete_operations() {
    std::vector<WorkspaceOperationRecord> ops;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        ops = list_incomplete_operations_nolock();
    }

    for (const auto& op : ops) {
        auto ws_lock = get_workspace_lock(op.workspace_id);
        if (op.operation_type == "ACCEPT_SUBMISSION") {
            recover_accept_submission_op(op);
        } else if (op.operation_type == "PUBLISH_VERSION") {
            recover_publish_version_op(op);
        }
    }

    std::vector<CollabWorkspace> ws_list;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        ws_list = list_workspaces_nolock();
    }
    for (const auto& ws : ws_list) {
        auto ws_lock = get_workspace_lock(ws.id);
        scan_and_reconcile_orphaned_directories(ws.id);
    }
}


bool CollabStore::accept_submission(const std::string& sub_id, const std::string& reviewer_id, const std::string& notes) {
    OperationGuard op_guard(*this);

    // 1. Retrieve workspace ID under db_mutex_
    std::string ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto sub_init = find_submission_by_id_nolock(sub_id);
        if (!sub_init || sub_init->status != "pending") return false;
        ws_id = sub_init->workspace_id;
    }

    // 2. Acquire workspace lock across the entire logical operation
    auto ws_lock = get_workspace_lock(ws_id);

    // 3. Re-read and validate submission under db_mutex_
    CollabSubmission sub;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto sub_check = find_submission_by_id_nolock(sub_id);
        if (!sub_check || sub_check->status != "pending" || sub_check->workspace_id != ws_id) return false;
        sub = *sub_check;
    }

    const auto sub_path = workspace_submissions_dir(ws_id) / sub.id;
    if (!fs::exists(sub_path)) return false;
    const auto sub_manifest = scan_folder(sub_path);
    if (!sub_manifest.complete || sub_manifest.merkle_root != sub.merkle_root) return false;

    const auto base_dir = workspace_baseline_dir(ws_id);
    const auto work_dir = workspace_working_copy_dir(ws_id);
    const auto ws_root_dir = workspace_root(ws_id);

    std::string expected_base_hash = "EMPTY";
    if (fs::exists(base_dir)) {
        const auto bm = scan_folder(base_dir);
        if (bm.complete && !bm.files.empty()) {
            expected_base_hash = bm.merkle_root;
        }
    }

    std::string expected_work_hash = "EMPTY";
    if (fs::exists(work_dir)) {
        const auto wm = scan_folder(work_dir);
        if (wm.complete && !wm.files.empty()) {
            expected_work_hash = wm.merkle_root;
        }
    }

    const std::string op_id = "op_acc_" + generate_random_token(10);
    const auto staging_base = ws_root_dir / (".staging_base_" + op_id);
    const auto staging_work = ws_root_dir / (".staging_work_" + op_id);
    const auto backup_base  = ws_root_dir / (".backup_base_" + op_id);
    const auto backup_work  = ws_root_dir / (".backup_work_" + op_id);

    // Verify paths do not exist
    assert_path_absent(staging_base);
    assert_path_absent(staging_work);
    assert_path_absent(backup_base);
    assert_path_absent(backup_work);

    // 4. Register intent in journal under db_mutex_
    WorkspaceOperationRecord op_rec;
    op_rec.op_id = op_id;
    op_rec.workspace_id = ws_id;
    op_rec.operation_type = "ACCEPT_SUBMISSION";
    op_rec.target_id = sub.id;
    op_rec.state = "PENDING";
    op_rec.intent_step = "STAGE_DIRECTORIES";
    op_rec.expected_base_hash = expected_base_hash;
    op_rec.expected_work_hash = expected_work_hash;
    op_rec.replacement_hash = sub.merkle_root;
    op_rec.created_at_ms = now_ms();
    op_rec.updated_at_ms = op_rec.created_at_ms;

    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        insert_operation_intent_nolock(op_rec);
    }

    try {
        trigger_collab_fault_point(CollabFaultPoint::FailAfterIntent, "FailAfterIntent");

        // 5. Create staging directories and write exclusive sentinels
        fs::create_directories(staging_base);
        if (is_reparse_point_or_symlink(staging_base)) {
            throw std::runtime_error("reparse point detected at staging_base");
        }
        if (!create_sentinel_file(staging_base, op_id, ws_id, "ACCEPT_SUBMISSION", "staging_base")) {
            throw std::runtime_error("staging_base sentinel already exists");
        }

        fs::create_directories(staging_work);
        if (is_reparse_point_or_symlink(staging_work)) {
            throw std::runtime_error("reparse point detected at staging_work");
        }
        if (!create_sentinel_file(staging_work, op_id, ws_id, "ACCEPT_SUBMISSION", "staging_work")) {
            throw std::runtime_error("staging_work sentinel already exists");
        }

        // Milestone 3.2: FastCDC chunking, CAS insertion, and verified reconstruction
        cas::FastCDCChunker chunker;
        for (const auto& sf : sub_manifest.files) {
            const auto src_file = sub_path / sf.relative_path;
            std::vector<std::uint8_t> fbuf(sf.size);
            if (sf.size > 0) {
                std::ifstream fin(src_file, std::ios::binary);
                if (!fin) throw std::runtime_error("failed to read submission file: " + sf.relative_path);
                fin.read(reinterpret_cast<char*>(fbuf.data()), static_cast<std::streamsize>(sf.size));
                if (static_cast<std::uintmax_t>(fin.gcount()) != sf.size) {
                    throw std::runtime_error("short read on submission file: " + sf.relative_path);
                }
            }
            const std::string computed_hash = sha256_data(fbuf.data(), fbuf.size());
            if (computed_hash != sf.sha256) {
                throw std::runtime_error("content hash mismatch on submission file: " + sf.relative_path);
            }

            auto chunks = chunker.chunk_buffer(fbuf.data(), fbuf.size());
            for (const auto& c : chunks) {
                auto pres = cas_store_->put_object(fbuf.data() + c.offset, static_cast<std::size_t>(c.size), c.hash);
                if (pres.status != cas::PutResultStatus::StoredNew && pres.status != cas::PutResultStatus::AlreadyExists) {
                    throw std::runtime_error("CAS put_object failed for " + c.hash + ": " + pres.error_message);
                }
            }

            cas::FileManifest fman(sf.size, sf.sha256, chunks);
            std::string recon_err;
            const auto dest_base = staging_base / sf.relative_path;
            const auto dest_work = staging_work / sf.relative_path;
            if (!cas_store_->reconstruct_file(fman, dest_base, recon_err, true)) {
                throw std::runtime_error("CAS reconstruction failed for staging_base " + sf.relative_path + ": " + recon_err);
            }
            if (!cas_store_->reconstruct_file(fman, dest_work, recon_err, true)) {
                throw std::runtime_error("CAS reconstruction failed for staging_work " + sf.relative_path + ": " + recon_err);
            }
        }

        trigger_collab_fault_point(CollabFaultPoint::FailAfterStaging, "FailAfterStaging");

        // 6. Update journal: state=STAGED, intent_step=BACKUP_DIRECTORIES
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "STAGED", "BACKUP_DIRECTORIES");
        }

        // 7. Backup baseline and working copy
        if (fs::exists(base_dir)) {
            fs::rename(base_dir, backup_base);
            if (!create_sentinel_file(backup_base, op_id, ws_id, "ACCEPT_SUBMISSION", "backup_base")) {
                throw std::runtime_error("backup_base sentinel already exists");
            }
        } else {
            fs::create_directories(backup_base);
            create_sentinel_file(backup_base, op_id, ws_id, "ACCEPT_SUBMISSION", "backup_base");
        }

        if (fs::exists(work_dir)) {
            fs::rename(work_dir, backup_work);
            if (!create_sentinel_file(backup_work, op_id, ws_id, "ACCEPT_SUBMISSION", "backup_work")) {
                throw std::runtime_error("backup_work sentinel already exists");
            }
        } else {
            fs::create_directories(backup_work);
            create_sentinel_file(backup_work, op_id, ws_id, "ACCEPT_SUBMISSION", "backup_work");
        }

        trigger_collab_fault_point(CollabFaultPoint::FailAfterBackup, "FailAfterBackup");

        // 8. Update journal: state=PROMOTING, intent_step=PROMOTE_BASELINE
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "PROMOTING", "PROMOTE_BASELINE");
        }

        // Remove temporary sentinel from staging before promotion
        fs::remove(staging_base / ".syncora_op_sentinel");
        fs::rename(staging_base, base_dir);

        trigger_collab_fault_point(CollabFaultPoint::FailAfterBaselinePromotion, "FailAfterBaselinePromotion");

        // Update journal: intent_step=PROMOTE_WORKING_COPY
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "PROMOTING", "PROMOTE_WORKING_COPY");
        }

        fs::remove(staging_work / ".syncora_op_sentinel");
        fs::rename(staging_work, work_dir);

        trigger_collab_fault_point(CollabFaultPoint::FailAfterWorkingCopyPromotion, "FailAfterWorkingCopyPromotion");

        // 9. Update journal: intent_step=COMMIT_DB
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "PROMOTING", "COMMIT_DB");
        }

        // 10. Commit SQLite transaction under db_mutex_
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            execute_sql("BEGIN IMMEDIATE;");
            try {
                sqlite3_stmt* stmt = nullptr;
                const char* sql = "UPDATE submissions SET status = 'accepted', review_notes = ?, reviewed_at_ms = ? WHERE id = ?";
                stmt = stmt_registry_.prepare(db_, sql);
                if (!stmt) throw std::runtime_error("failed to prepare submission accept update");
                sqlite3_bind_text(stmt, 1, notes.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int64(stmt, 2, now_ms());
                sqlite3_bind_text(stmt, 3, sub.id.c_str(), -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    stmt_registry_.finalize(stmt);
                    throw std::runtime_error("failed to update submission status");
                }
                stmt_registry_.finalize(stmt);

                update_operation_intent_nolock(op_id, "COMMITTED", "CLEANUP");

                const auto reviewer = find_user_by_id_nolock(reviewer_id);
                record_event_nolock(reviewer_id, reviewer ? reviewer->username : "host", "SUBMISSION_ACCEPTED",
                                    "submission:" + sub_id, "success", "Accepted baseline created in workspace: " + ws_id);

                execute_sql("COMMIT;");
            } catch (...) {
                execute_sql("ROLLBACK;");
                throw;
            }
        }

        trigger_collab_fault_point(CollabFaultPoint::FailAfterCommit, "FailAfterCommit");

        // 11. Cleanup verified backups after successful commit
        if (fs::exists(backup_base)) {
            const auto sres = validate_sentinel_file(backup_base, op_id, ws_id, "backup_base");
            if (sres.valid) fs::remove_all(backup_base);
            else quarantine_directory(backup_base, ws_id, "invalid backup_base sentinel at cleanup");
        }
        if (fs::exists(backup_work)) {
            const auto sres = validate_sentinel_file(backup_work, op_id, ws_id, "backup_work");
            if (sres.valid) fs::remove_all(backup_work);
            else quarantine_directory(backup_work, ws_id, "invalid backup_work sentinel at cleanup");
        }

        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "COMMITTED", "COMPLETED");
        }

        return true;
    } catch (...) {
        recover_accept_submission_op(op_rec);
        return false;
    }
}

bool CollabStore::reject_submission(const std::string& sub_id, const std::string& reviewer_id, const std::string& notes) {
    OperationGuard op_guard(*this);

    // 1. Retrieve workspace ID under db_mutex_
    std::string ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto sub_init = find_submission_by_id_nolock(sub_id);
        if (!sub_init || sub_init->status != "pending") return false;
        ws_id = sub_init->workspace_id;
    }

    // 2. Acquire workspace lock
    auto ws_lock = get_workspace_lock(ws_id);

    // 3. Re-read and validate record under db_mutex_
    bool ok = false;
    const auto t = now_ms();
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto sub = find_submission_by_id_nolock(sub_id);
        if (!sub || sub->status != "pending" || sub->workspace_id != ws_id) return false;

        sqlite3_stmt* stmt = nullptr;
        const char* sql = "UPDATE submissions SET status = 'rejected', review_notes = ?, reviewed_at_ms = ? WHERE id = ?";
        stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return false;
        sqlite3_bind_text(stmt, 1, notes.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, t);
        sqlite3_bind_text(stmt, 3, sub_id.c_str(), -1, SQLITE_STATIC);
        ok = (sqlite3_step(stmt) == SQLITE_DONE);
        stmt_registry_.finalize(stmt);
    }

    const auto reviewer = find_user_by_id(reviewer_id);
    record_event(reviewer_id, reviewer ? reviewer->username : "host", "SUBMISSION_REJECTED",
                 "submission:" + sub_id, "success", "Notes: " + notes);

    return ok;
}

std::vector<FileMetadata> CollabStore::list_working_copy_files(const std::string& ws_id) {
    OperationGuard op_guard(*this);
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    auto ws_lock = get_workspace_lock(actual_ws_id);
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    if (!fs::exists(work_dir)) return {};
    const auto manifest = scan_folder(work_dir);
    return manifest.files;
}

std::string CollabStore::read_working_copy_file_content(const std::string& ws_id, const std::string& rel_path) {
    OperationGuard op_guard(*this);
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    auto ws_lock = get_workspace_lock(actual_ws_id);
    if (!safe_relative_path(rel_path)) {
        throw std::runtime_error("invalid or unsafe relative path: " + rel_path);
    }
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    reject_symlink_path(work_dir, rel_path);
    const auto file_path = work_dir / rel_path;
    if (!fs::is_regular_file(file_path)) {
        throw std::runtime_error("file not found in working copy: " + rel_path);
    }
    const auto size = fs::file_size(file_path);
    if (size > 5 * 1024 * 1024) {
        throw std::runtime_error("file exceeds text editor size limit (5MB)");
    }
    std::ifstream in(file_path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return content;
}

void CollabStore::write_working_copy_file_content(const std::string& ws_id,
                                                  const std::string& rel_path,
                                                  const std::string& content) {
    OperationGuard op_guard(*this);
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    auto ws_lock = get_workspace_lock(actual_ws_id);
    if (!safe_relative_path(rel_path)) {
        throw std::runtime_error("invalid or unsafe relative path: " + rel_path);
    }
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    reject_symlink_path(work_dir, rel_path);
    fs::create_directories(work_dir);
    const auto target_path = work_dir / rel_path;
    fs::create_directories(target_path.parent_path());

    // Write file cleanly
    std::ofstream out(target_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("could not open file for writing: " + rel_path);
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) {
        throw std::runtime_error("failed writing content to file: " + rel_path);
    }
}

void CollabStore::delete_working_copy_file(const std::string& ws_id, const std::string& rel_path) {
    OperationGuard op_guard(*this);
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    auto ws_lock = get_workspace_lock(actual_ws_id);
    if (!safe_relative_path(rel_path)) {
        throw std::runtime_error("invalid or unsafe relative path: " + rel_path);
    }
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    reject_symlink_path(work_dir, rel_path);
    const auto target_path = work_dir / rel_path;
    if (fs::exists(target_path)) {
        fs::remove(target_path);
    }
}

std::vector<CollabFileDiff> CollabStore::compute_working_copy_diff(const std::string& ws_id) {
    OperationGuard op_guard(*this);
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    auto ws_lock = get_workspace_lock(actual_ws_id);
    std::vector<CollabFileDiff> diffs;
    const auto base_dir = workspace_baseline_dir(actual_ws_id);
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);

    const auto base_manifest = fs::exists(base_dir) ? scan_folder(base_dir) : FileManifest{};
    const auto work_manifest = fs::exists(work_dir) ? scan_folder(work_dir) : FileManifest{};

    std::unordered_map<std::string, FileMetadata> base_map;
    for (const auto& f : base_manifest.files) base_map[f.relative_path] = f;

    std::unordered_set<std::string> seen;

    for (const auto& wf : work_manifest.files) {
        seen.insert(wf.relative_path);
        CollabFileDiff d;
        d.relative_path = wf.relative_path;
        d.current_hash = wf.sha256;
        d.current_size = wf.size;
        d.current_modified_ms = file_ticks_to_millis(wf.modified_ticks);

        const auto it = base_map.find(wf.relative_path);
        if (it == base_map.end()) {
            d.change_type = "ADDED";
            d.baseline_hash = "";
            d.baseline_size = 0;
            d.baseline_modified_ms = 0;
        } else if (it->second.sha256 != wf.sha256) {
            d.change_type = "MODIFIED";
            d.baseline_hash = it->second.sha256;
            d.baseline_size = it->second.size;
            d.baseline_modified_ms = file_ticks_to_millis(it->second.modified_ticks);
        } else {
            d.change_type = "UNCHANGED";
            d.baseline_hash = it->second.sha256;
            d.baseline_size = it->second.size;
            d.baseline_modified_ms = file_ticks_to_millis(it->second.modified_ticks);
        }
        diffs.push_back(d);
    }

    // Check deleted files
    for (const auto& bf : base_manifest.files) {
        if (seen.find(bf.relative_path) == seen.end()) {
            CollabFileDiff d;
            d.relative_path = bf.relative_path;
            d.change_type = "DELETED";
            d.baseline_hash = bf.sha256;
            d.baseline_size = bf.size;
            d.baseline_modified_ms = file_ticks_to_millis(bf.modified_ticks);
            d.current_hash = "";
            d.current_size = 0;
            d.current_modified_ms = 0;
            diffs.push_back(d);
        }
    }

    std::sort(diffs.begin(), diffs.end(), [](const auto& a, const auto& b) {
        return a.relative_path < b.relative_path;
    });

    return diffs;
}

CollabFileDiff CollabStore::compute_file_diff(const std::string& ws_id, const std::string& rel_path) {
    OperationGuard op_guard(*this);
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    auto ws_lock = get_workspace_lock(actual_ws_id);
    if (!safe_relative_path(rel_path)) {
        throw std::runtime_error("invalid or unsafe relative path: " + rel_path);
    }
    const auto base_dir = workspace_baseline_dir(actual_ws_id);
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    reject_symlink_path(base_dir, rel_path);
    reject_symlink_path(work_dir, rel_path);

    CollabFileDiff diff;
    diff.relative_path = rel_path;

    const auto base_file = base_dir / rel_path;
    const auto work_file = work_dir / rel_path;

    const bool base_exists = fs::is_regular_file(base_file);
    const bool work_exists = fs::is_regular_file(work_file);

    std::string base_content;
    std::string work_content;

    if (base_exists) {
        diff.baseline_hash = sha256_file(base_file);
        diff.baseline_size = fs::file_size(base_file);
        if (diff.baseline_size < 2 * 1024 * 1024) {
            std::ifstream in(base_file, std::ios::binary);
            base_content.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        } else {
            diff.is_binary = true;
        }
    }

    if (work_exists) {
        diff.current_hash = sha256_file(work_file);
        diff.current_size = fs::file_size(work_file);
        if (diff.current_size < 2 * 1024 * 1024) {
            std::ifstream in(work_file, std::ios::binary);
            work_content.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        } else {
            diff.is_binary = true;
        }
    }

    if (!base_exists && work_exists) diff.change_type = "ADDED";
    else if (base_exists && !work_exists) diff.change_type = "DELETED";
    else if (diff.baseline_hash != diff.current_hash) diff.change_type = "MODIFIED";
    else diff.change_type = "UNCHANGED";

    // Detect binary content
    auto is_bin_str = [](const std::string& s) {
        for (unsigned char c : s) {
            if (c == 0) return true;
        }
        return false;
    };

    if (is_bin_str(base_content) || is_bin_str(work_content)) {
        diff.is_binary = true;
        diff.diff_text = "Binary files differ (SHA-256 baseline: " + diff.baseline_hash.substr(0, 16) +
                         "..., working copy: " + diff.current_hash.substr(0, 16) + "...)";
    } else {
        diff.diff_text = generate_unified_diff(rel_path, base_content, work_content);
    }

    return diff;
}

CollabPublishedVersion CollabStore::publish_version(const std::string& workspace_id,
                                                   const std::string& published_by_id,
                                                   const std::string& title,
                                                   const std::string& release_notes) {
    OperationGuard op_guard(*this);

    // 1. Resolve workspace ID under db_mutex_
    std::string actual_ws_id = workspace_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(workspace_id);
        if (ws) actual_ws_id = ws->id;
    }

    // 2. Acquire workspace lock across the entire publishing operation
    auto ws_lock = get_workspace_lock(actual_ws_id);

    const auto ws_root_dir = workspace_root(actual_ws_id);
    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    const auto base_dir = workspace_baseline_dir(actual_ws_id);
    const auto versions_dir = workspace_versions_dir(actual_ws_id);

    if (!fs::exists(work_dir)) {
        throw std::runtime_error("cannot publish: working copy does not exist");
    }
    const auto manifest = scan_folder(work_dir);
    if (!manifest.complete) {
        throw std::runtime_error("cannot publish: working copy scan incomplete");
    }

    // Determine parent version under db_mutex_
    std::string parent_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT id FROM published_versions WHERE workspace_id = ? ORDER BY published_at_ms DESC LIMIT 1";
        stmt = stmt_registry_.prepare(db_, sql);
        if (stmt) {
            sqlite3_bind_text(stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                parent_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            }
            stmt_registry_.finalize(stmt);
        }
    }

    std::string expected_base_hash = "INITIAL";
    if (fs::exists(base_dir)) {
        const auto bm = scan_folder(base_dir);
        if (bm.complete && !bm.files.empty()) {
            expected_base_hash = bm.merkle_root;
        }
    }

    const std::string op_id = "op_pub_" + generate_random_token(10);
    const std::string ver_id = "ver_" + generate_random_token(10);

    const auto staging_ver  = versions_dir / (".staging_ver_" + op_id);
    const auto final_ver    = versions_dir / ver_id;
    const auto staging_base = ws_root_dir / (".staging_base_" + op_id);
    const auto backup_base  = ws_root_dir / (".backup_base_" + op_id);

    assert_path_absent(staging_ver);
    assert_path_absent(final_ver);
    assert_path_absent(staging_base);
    assert_path_absent(backup_base);

    CollabPublishedVersion ver;
    ver.id = ver_id;
    ver.workspace_id = actual_ws_id;
    ver.parent_version_id = parent_id;
    ver.title = title.empty() ? ("Release " + ver.id.substr(4, 6)) : title;
    ver.release_notes = release_notes;
    ver.merkle_root = manifest.merkle_root;
    ver.file_count = manifest.files.size();
    ver.total_size = 0;
    for (const auto& f : manifest.files) ver.total_size += f.size;
    ver.published_by_id = published_by_id;
    ver.published_at_ms = now_ms();

    // 3. Register intent in journal under db_mutex_
    WorkspaceOperationRecord op_rec;
    op_rec.op_id = op_id;
    op_rec.workspace_id = actual_ws_id;
    op_rec.operation_type = "PUBLISH_VERSION";
    op_rec.target_id = ver_id;
    op_rec.state = "PENDING";
    op_rec.intent_step = "STAGE_SNAPSHOT";
    op_rec.expected_base_hash = expected_base_hash;
    op_rec.expected_work_hash = manifest.merkle_root;
    op_rec.replacement_hash = manifest.merkle_root;
    op_rec.created_at_ms = now_ms();
    op_rec.updated_at_ms = op_rec.created_at_ms;

    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        insert_operation_intent_nolock(op_rec);
    }

    try {
        trigger_collab_fault_point(CollabFaultPoint::FailAfterIntent, "FailAfterIntent");

        // 4. Create staging version snapshot and promote to final_ver
        fs::create_directories(staging_ver);
        if (is_reparse_point_or_symlink(staging_ver)) throw std::runtime_error("reparse point at staging_ver");
        if (!create_sentinel_file(staging_ver, op_id, actual_ws_id, "PUBLISH_VERSION", "version_snapshot")) {
            throw std::runtime_error("staging_ver sentinel already exists");
        }

        // Milestone 3.2: Chunk working copy files, store into CAS, and serialize manifests
        struct StagedManifestItem {
            std::string rel_path;
            std::string whole_file_sha256;
            std::uintmax_t file_size{0};
            cas::FileManifest file_man;
            std::vector<std::uint8_t> binary_blob;
        };
        std::vector<StagedManifestItem> staged_manifests;
        cas::FastCDCChunker chunker;
        for (const auto& wf : manifest.files) {
            const auto src_file = work_dir / wf.relative_path;
            std::vector<std::uint8_t> fbuf(wf.size);
            if (wf.size > 0) {
                std::ifstream fin(src_file, std::ios::binary);
                if (!fin) throw std::runtime_error("failed to read working copy file: " + wf.relative_path);
                fin.read(reinterpret_cast<char*>(fbuf.data()), static_cast<std::streamsize>(wf.size));
                if (static_cast<std::uintmax_t>(fin.gcount()) != wf.size) {
                    throw std::runtime_error("short read on working copy file: " + wf.relative_path);
                }
            }
            const std::string computed_hash = sha256_data(fbuf.data(), fbuf.size());
            if (computed_hash != wf.sha256) {
                throw std::runtime_error("content hash mismatch on working copy file: " + wf.relative_path);
            }

            auto chunks = chunker.chunk_buffer(fbuf.data(), fbuf.size());
            for (const auto& c : chunks) {
                auto pres = cas_store_->put_object(fbuf.data() + c.offset, static_cast<std::size_t>(c.size), c.hash);
                if (pres.status != cas::PutResultStatus::StoredNew && pres.status != cas::PutResultStatus::AlreadyExists) {
                    throw std::runtime_error("CAS put_object failed for " + c.hash + ": " + pres.error_message);
                }
            }

            cas::FileManifest fman(wf.size, wf.sha256, chunks);
            auto bin_blob = cas::ManifestSerializer::serialize_binary(fman);
            staged_manifests.push_back({wf.relative_path, wf.sha256, wf.size, std::move(fman), std::move(bin_blob)});
        }

        copy_directory_recursive(work_dir, staging_ver);
        const auto staged_ver_manifest = scan_folder(staging_ver);
        if (!staged_ver_manifest.complete || staged_ver_manifest.merkle_root != ver.merkle_root) {
            throw std::runtime_error("staged version root mismatch");
        }

        fs::rename(staging_ver, final_ver);
        create_sentinel_file(final_ver, op_id, actual_ws_id, "PUBLISH_VERSION", "version_snapshot");

        trigger_collab_fault_point(CollabFaultPoint::FailAfterSnapshotPromotion, "FailAfterSnapshotPromotion");

        // 5. Update journal: state=STAGED, intent_step=STAGE_BASELINE
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "STAGED", "STAGE_BASELINE");
        }

        fs::create_directories(staging_base);
        if (is_reparse_point_or_symlink(staging_base)) throw std::runtime_error("reparse point at staging_base");
        if (!create_sentinel_file(staging_base, op_id, actual_ws_id, "PUBLISH_VERSION", "staging_base")) {
            throw std::runtime_error("staging_base sentinel already exists");
        }
        copy_directory_recursive(work_dir, staging_base);

        trigger_collab_fault_point(CollabFaultPoint::FailAfterStagingBaseline, "FailAfterStagingBaseline");

        // 6. Update journal: intent_step=BACKUP_BASELINE
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "STAGED", "BACKUP_BASELINE");
        }

        if (fs::exists(base_dir)) {
            fs::rename(base_dir, backup_base);
            if (!create_sentinel_file(backup_base, op_id, actual_ws_id, "PUBLISH_VERSION", "backup_base")) {
                throw std::runtime_error("backup_base sentinel already exists");
            }
        } else {
            fs::create_directories(backup_base);
            create_sentinel_file(backup_base, op_id, actual_ws_id, "PUBLISH_VERSION", "backup_base");
        }

        trigger_collab_fault_point(CollabFaultPoint::FailAfterBaselineBackup, "FailAfterBaselineBackup");

        // 7. Update journal: state=PROMOTING, intent_step=PROMOTE_BASELINE
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "PROMOTING", "PROMOTE_BASELINE");
        }

        fs::remove(staging_base / ".syncora_op_sentinel");
        fs::rename(staging_base, base_dir);

        trigger_collab_fault_point(CollabFaultPoint::FailAfterBaselinePromotion, "FailAfterBaselinePromotion");

        // 8. Update journal: intent_step=COMMIT_DB
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "PROMOTING", "COMMIT_DB");
        }

        // 9. Commit SQLite transaction under db_mutex_
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            execute_sql("BEGIN IMMEDIATE;");
            try {
                sqlite3_stmt* stmt = nullptr;
                const char* sql = R"(
                    INSERT INTO published_versions (id, workspace_id, parent_version_id, title, release_notes, merkle_root, file_count, total_size, published_by_id, published_at_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                )";
                stmt = stmt_registry_.prepare(db_, sql);
                if (!stmt) throw std::runtime_error("failed to prepare version insert");
                sqlite3_bind_text(stmt, 1, ver.id.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, ver.workspace_id.c_str(), -1, SQLITE_STATIC);
                if (ver.parent_version_id.empty()) sqlite3_bind_null(stmt, 3);
                else sqlite3_bind_text(stmt, 3, ver.parent_version_id.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 4, ver.title.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 5, ver.release_notes.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 6, ver.merkle_root.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(ver.file_count));
                sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(ver.total_size));
                sqlite3_bind_text(stmt, 9, ver.published_by_id.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int64(stmt, 10, ver.published_at_ms);

                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    std::string err = sqlite3_errmsg(db_);
                    stmt_registry_.finalize(stmt);
                    throw std::runtime_error("failed to insert published version: " + err);
                }
                stmt_registry_.finalize(stmt);

                // Milestone 3.2: Record version manifests and update chunk reference counts
                const auto now_ts = now_ms();
                for (const auto& m : staged_manifests) {
                    const std::string man_id = "man_" + generate_random_token(10);
                    sqlite3_stmt* man_stmt = nullptr;
                    const char* man_sql = R"(
                        INSERT INTO version_manifests (manifest_id, workspace_id, version_id, relative_path, whole_file_sha256, file_size, chunk_count, manifest_blob, created_at_ms)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    )";
                    man_stmt = stmt_registry_.prepare(db_, man_sql);
                    if (!man_stmt) throw std::runtime_error("failed to prepare version_manifests insert");
                    sqlite3_bind_text(man_stmt, 1, man_id.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(man_stmt, 2, actual_ws_id.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(man_stmt, 3, ver.id.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(man_stmt, 4, m.rel_path.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(man_stmt, 5, m.whole_file_sha256.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_int64(man_stmt, 6, static_cast<sqlite3_int64>(m.file_size));
                    sqlite3_bind_int64(man_stmt, 7, static_cast<sqlite3_int64>(m.file_man.chunk_count()));
                    sqlite3_bind_blob(man_stmt, 8, m.binary_blob.data(), static_cast<int>(m.binary_blob.size()), SQLITE_STATIC);
                    sqlite3_bind_int64(man_stmt, 9, now_ts);
                    if (sqlite3_step(man_stmt) != SQLITE_DONE) {
                        std::string err = sqlite3_errmsg(db_);
                        stmt_registry_.finalize(man_stmt);
                        throw std::runtime_error("failed to insert version manifest: " + err);
                    }
                    stmt_registry_.finalize(man_stmt);

                    // Upsert cas_chunks first (so FK reference in version_manifest_chunks succeeds)
                    for (std::size_t ci = 0; ci < m.file_man.chunks().size(); ++ci) {
                        const auto& chunk = m.file_man.chunks()[ci];

                        // 1. Upsert cas_chunks reference count
                        sqlite3_stmt* ref_stmt = nullptr;
                        const char* ref_sql = R"(
                            INSERT INTO cas_chunks (chunk_hash, chunk_size, reference_count, created_at_ms, verified_at_ms, storage_state)
                            VALUES (?, ?, 1, ?, ?, 'COMMITTED')
                            ON CONFLICT(chunk_hash) DO UPDATE SET reference_count = reference_count + 1, verified_at_ms = ?
                        )";
                        ref_stmt = stmt_registry_.prepare(db_, ref_sql);
                        if (!ref_stmt) throw std::runtime_error("failed to prepare cas_chunks upsert");
                        sqlite3_bind_text(ref_stmt, 1, chunk.hash.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_int64(ref_stmt, 2, static_cast<sqlite3_int64>(chunk.size));
                        sqlite3_bind_int64(ref_stmt, 3, now_ts);
                        sqlite3_bind_int64(ref_stmt, 4, now_ts);
                        sqlite3_bind_int64(ref_stmt, 5, now_ts);
                        if (sqlite3_step(ref_stmt) != SQLITE_DONE) {
                            std::string err = sqlite3_errmsg(db_);
                            stmt_registry_.finalize(ref_stmt);
                            throw std::runtime_error("failed to update cas_chunk ref count: " + err);
                        }
                        stmt_registry_.finalize(ref_stmt);

                        // 2. Insert into version_manifest_chunks
                        sqlite3_stmt* chunk_stmt = nullptr;
                        const char* chunk_sql = R"(
                            INSERT INTO version_manifest_chunks (manifest_id, chunk_index, chunk_hash, chunk_size)
                            VALUES (?, ?, ?, ?)
                        )";
                        chunk_stmt = stmt_registry_.prepare(db_, chunk_sql);
                        if (!chunk_stmt) throw std::runtime_error("failed to prepare version_manifest_chunks insert");
                        sqlite3_bind_text(chunk_stmt, 1, man_id.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_int64(chunk_stmt, 2, static_cast<sqlite3_int64>(ci));
                        sqlite3_bind_text(chunk_stmt, 3, chunk.hash.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_int64(chunk_stmt, 4, static_cast<sqlite3_int64>(chunk.size));
                        if (sqlite3_step(chunk_stmt) != SQLITE_DONE) {
                            std::string err = sqlite3_errmsg(db_);
                            stmt_registry_.finalize(chunk_stmt);
                            throw std::runtime_error("failed to insert version_manifest_chunk: " + err);
                        }
                        stmt_registry_.finalize(chunk_stmt);
                    }
                }

                // Notify/create client update records for active clients
                std::vector<std::string> client_ids;
                {
                    sqlite3_stmt* mem_stmt = nullptr;
                    const char* mem_sql = R"(
                        SELECT wm.user_id FROM workspace_members wm
                        JOIN users u ON wm.user_id = u.id
                        WHERE wm.workspace_id = ? AND u.role = 'client' AND u.status = 'active'
                    )";
                    mem_stmt = stmt_registry_.prepare(db_, mem_sql);
                    if (mem_stmt) {
                        sqlite3_bind_text(mem_stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);
                        while (sqlite3_step(mem_stmt) == SQLITE_ROW) {
                            client_ids.push_back(reinterpret_cast<const char*>(sqlite3_column_text(mem_stmt, 0)));
                        }
                        stmt_registry_.finalize(mem_stmt);
                    }
                }

                for (const auto& cid : client_ids) {
                    const std::string upd_id = "upd_" + generate_random_token(10);
                    sqlite3_stmt* upd_stmt = nullptr;
                    const char* upd_sql = R"(
                        INSERT INTO client_updates (id, version_id, client_id, workspace_id, status)
                        VALUES (?, ?, ?, ?, 'available')
                    )";
                    upd_stmt = stmt_registry_.prepare(db_, upd_sql);
                    if (upd_stmt) {
                        sqlite3_bind_text(upd_stmt, 1, upd_id.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(upd_stmt, 2, ver.id.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(upd_stmt, 3, cid.c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(upd_stmt, 4, actual_ws_id.c_str(), -1, SQLITE_STATIC);
                        sqlite3_step(upd_stmt);
                        stmt_registry_.finalize(upd_stmt);
                    }
                }

                // Clean sentinel from committed final_ver
                fs::remove(final_ver / ".syncora_op_sentinel");

                update_operation_intent_nolock(op_id, "COMMITTED", "CLEANUP");

                const auto publisher = find_user_by_id_nolock(published_by_id);
                record_event_nolock(published_by_id, publisher ? publisher->username : "host", "VERSION_PUBLISHED",
                                    "version:" + ver.id, "success", "Published immutable version " + ver.title + " in workspace: " + actual_ws_id);

                execute_sql("COMMIT;");
            } catch (...) {
                execute_sql("ROLLBACK;");
                throw;
            }
        }

        trigger_collab_fault_point(CollabFaultPoint::FailAfterCommit, "FailAfterCommit");

        // 10. Clean up backup_base
        if (fs::exists(backup_base)) {
            auto sres = validate_sentinel_file(backup_base, op_id, actual_ws_id, "backup_base");
            if (sres.valid) fs::remove_all(backup_base);
            else quarantine_directory(backup_base, actual_ws_id, "invalid backup_base sentinel");
        }

        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            update_operation_intent_nolock(op_id, "COMMITTED", "COMPLETED");
        }

        return ver;
    } catch (...) {
        recover_publish_version_op(op_rec);
        throw;
    }
}

std::vector<CollabPublishedVersion> CollabStore::list_published_versions(const std::string& ws_id) {
    OperationGuard op_guard(*this);

    if (ws_id.empty()) {
        // Global administrative reader: database-only
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        return list_published_versions_nolock(ws_id);
    }

    // Workspace-correlated reader: resolve workspace ID under db_mutex_
    std::string actual_ws_id = ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ws = find_workspace_by_id_nolock(ws_id);
        if (ws) actual_ws_id = ws->id;
    }

    // Acquire workspace lock
    auto ws_lock = get_workspace_lock(actual_ws_id);

    std::lock_guard<std::mutex> db_lock(db_mutex_);
    return list_published_versions_nolock(actual_ws_id);
}

// Precondition: caller must hold db_mutex_.
// Precondition: caller must hold db_mutex_.
std::vector<CollabPublishedVersion> CollabStore::list_published_versions_nolock(const std::string& ws_id) {
    std::vector<CollabPublishedVersion> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = nullptr;
    if (ws_id.empty()) {
        sql = R"(
            SELECT v.id, v.workspace_id, v.parent_version_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, v.published_by_id, u.username, v.published_at_ms
            FROM published_versions v
            JOIN users u ON v.published_by_id = u.id
            ORDER BY v.published_at_ms DESC
        )";
        stmt = stmt_registry_.prepare(db_, sql);
        if (!stmt) return list;
    } else {
        sql = R"(
            SELECT v.id, v.workspace_id, v.parent_version_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, v.published_by_id, u.username, v.published_at_ms
            FROM published_versions v
            JOIN users u ON v.published_by_id = u.id
            WHERE v.workspace_id = ?
            ORDER BY v.published_at_ms DESC
        )";
        stmt = stmt_registry_.prepare(db_, sql);
        if (!stmt) return list;
        sqlite3_bind_text(stmt, 1, ws_id.c_str(), -1, SQLITE_STATIC);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabPublishedVersion v;
        v.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        v.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* parent = sqlite3_column_text(stmt, 2);
        v.parent_version_id = parent ? reinterpret_cast<const char*>(parent) : "";
        v.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        const auto* notes = sqlite3_column_text(stmt, 4);
        v.release_notes = notes ? reinterpret_cast<const char*>(notes) : "";
        v.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        v.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 6));
        v.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 7));
        v.published_by_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        const auto* uname = sqlite3_column_text(stmt, 9);
        v.published_by_username = uname ? reinterpret_cast<const char*>(uname) : "";
        v.published_at_ms = sqlite3_column_int64(stmt, 10);
        list.push_back(v);
    }
    stmt_registry_.finalize(stmt);
    return list;
}

std::optional<CollabPublishedVersion> CollabStore::find_version_by_id_nolock(const std::string& version_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT v.id, v.workspace_id, v.parent_version_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, v.published_by_id, u.username, v.published_at_ms
        FROM published_versions v
        JOIN users u ON v.published_by_id = u.id
        WHERE v.id = ?
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, version_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabPublishedVersion v;
        v.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        v.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* parent = sqlite3_column_text(stmt, 2);
        v.parent_version_id = parent ? reinterpret_cast<const char*>(parent) : "";
        v.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        const auto* notes = sqlite3_column_text(stmt, 4);
        v.release_notes = notes ? reinterpret_cast<const char*>(notes) : "";
        v.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        v.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 6));
        v.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 7));
        v.published_by_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        v.published_by_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        v.published_at_ms = sqlite3_column_int64(stmt, 10);
        stmt_registry_.finalize(stmt);
        return v;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

std::optional<CollabPublishedVersion> CollabStore::find_version_by_id(const std::string& version_id) {
    OperationGuard op_guard(*this);

    // 1. Retrieve workspace ID under db_mutex_
    std::string ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto ver_pre = find_version_by_id_nolock(version_id);
        if (!ver_pre) return std::nullopt;
        ws_id = ver_pre->workspace_id;
    }

    // 2. Acquire workspace lock
    auto ws_lock = get_workspace_lock(ws_id);

    // 3. Re-read and validate under db_mutex_
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    const auto ver = find_version_by_id_nolock(version_id);
    if (!ver || ver->workspace_id != ws_id) return std::nullopt;

    return ver;
}

std::vector<CollabClientUpdate> CollabStore::list_updates_for_client(const std::string& client_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::vector<CollabClientUpdate> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT u.id, u.version_id, u.client_id, u.workspace_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, u.status, u.accepted_at_ms, u.applied_at_ms, u.error_message
        FROM client_updates u
        JOIN published_versions v ON u.version_id = v.id
        WHERE u.client_id = ?
        ORDER BY v.published_at_ms DESC
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return list;
    sqlite3_bind_text(stmt, 1, client_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabClientUpdate upd;
        upd.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        upd.version_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        upd.client_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        upd.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        upd.version_title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        const auto* notes = sqlite3_column_text(stmt, 5);
        upd.release_notes = notes ? reinterpret_cast<const char*>(notes) : "";
        upd.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        upd.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 7));
        upd.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 8));
        upd.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        upd.accepted_at_ms = sqlite3_column_int64(stmt, 10);
        upd.applied_at_ms = sqlite3_column_int64(stmt, 11);
        const auto* err = sqlite3_column_text(stmt, 12);
        upd.error_message = err ? reinterpret_cast<const char*>(err) : "";
        list.push_back(upd);
    }
    stmt_registry_.finalize(stmt);
    return list;
}

// Precondition: caller must hold db_mutex_.
std::optional<CollabClientUpdate> CollabStore::find_update_by_id_nolock(const std::string& update_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT u.id, u.version_id, u.client_id, u.workspace_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, u.status, u.accepted_at_ms, u.applied_at_ms, u.error_message
        FROM client_updates u
        JOIN published_versions v ON u.version_id = v.id
        WHERE u.id = ?
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return std::nullopt;
    sqlite3_bind_text(stmt, 1, update_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabClientUpdate upd;
        upd.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        upd.version_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        upd.client_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        upd.workspace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        upd.version_title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        const auto* notes = sqlite3_column_text(stmt, 5);
        upd.release_notes = notes ? reinterpret_cast<const char*>(notes) : "";
        upd.merkle_root = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        upd.file_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 7));
        upd.total_size = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 8));
        upd.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        upd.accepted_at_ms = sqlite3_column_int64(stmt, 10);
        upd.applied_at_ms = sqlite3_column_int64(stmt, 11);
        const auto* err = sqlite3_column_text(stmt, 12);
        upd.error_message = err ? reinterpret_cast<const char*>(err) : "";
        stmt_registry_.finalize(stmt);
        return upd;
    }
    stmt_registry_.finalize(stmt);
    return std::nullopt;
}

std::optional<CollabClientUpdate> CollabStore::find_update_by_id(const std::string& update_id) {
    OperationGuard op_guard(*this);

    // 1. Retrieve workspace ID under db_mutex_
    std::string ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto upd_pre = find_update_by_id_nolock(update_id);
        if (!upd_pre) return std::nullopt;
        ws_id = upd_pre->workspace_id;
    }

    // 2. Acquire workspace lock
    auto ws_lock = get_workspace_lock(ws_id);

    // 3. Re-read and validate under db_mutex_
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    const auto upd = find_update_by_id_nolock(update_id);
    if (!upd || upd->workspace_id != ws_id) return std::nullopt;

    return upd;
}

bool CollabStore::accept_update(const std::string& update_id, const std::string& client_id) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    const auto upd = find_update_by_id_nolock(update_id);
    if (!upd || upd->client_id != client_id) return false;

    const auto t = now_ms();
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE client_updates SET status = 'accepted', accepted_at_ms = ? WHERE id = ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return false;
    sqlite3_bind_int64(stmt, 1, t);
    sqlite3_bind_text(stmt, 2, update_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    stmt_registry_.finalize(stmt);

    const auto user = find_user_by_id_nolock(client_id);
    record_event_nolock(client_id, user ? user->username : "client", "UPDATE_ACCEPTED",
                        "update:" + update_id, "success", "Accepted version update: " + upd->version_title);

    return ok;
}

bool CollabStore::apply_update(const std::string& update_id,
                               const std::string& client_id,
                               const fs::path& target_local_folder,
                               std::string& error_out) {
    OperationGuard op_guard(*this);

    // 1. Retrieve workspace ID under db_mutex_
    std::string ws_id;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto upd_init = find_update_by_id_nolock(update_id);
        if (!upd_init || upd_init->client_id != client_id) {
            error_out = "Update not found or unauthorized";
            return false;
        }
        ws_id = upd_init->workspace_id;
    }

    // 2. Acquire workspace lock
    auto ws_lock = get_workspace_lock(ws_id);

    // 3. Re-read and validate record under db_mutex_
    CollabClientUpdate upd;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        const auto upd_check = find_update_by_id_nolock(update_id);
        if (!upd_check || upd_check->client_id != client_id || upd_check->workspace_id != ws_id) {
            error_out = "Update not found or unauthorized";
            return false;
        }
        upd = *upd_check;
    }

    if (!fs::is_directory(target_local_folder)) {
        error_out = "Target local folder is not a valid directory";
        return false;
    }

    const auto version_dir = workspace_versions_dir(ws_id) / upd.version_id;
    if (!fs::exists(version_dir)) {
        error_out = "Published version directory missing from server";
        return false;
    }

    // Scan target directory and version directory
    const auto ver_manifest = scan_folder(version_dir);
    if (!ver_manifest.complete || ver_manifest.merkle_root != upd.merkle_root) {
        error_out = "Published version failed integrity verification";
        return false;
    }

    // Stage update in temporary directory inside target
    const auto staging_dir = target_local_folder / ".merklechain" / "staging" / upd.id;
    const auto recovery_dir = target_local_folder / ".merklechain" / "recovery" / upd.id;
    fs::create_directories(staging_dir);
    fs::create_directories(recovery_dir);

    try {
        // Copy files to staging and verify hashes
        copy_directory_recursive(version_dir, staging_dir);
        const auto staged_manifest = scan_folder(staging_dir);
        if (!staged_manifest.complete || staged_manifest.merkle_root != upd.merkle_root) {
            fs::remove_all(staging_dir);
            error_out = "Staged update content hash mismatch; aborted";
            return false;
        }

        // Apply from staging to target folder, preserving backups
        for (const auto& sf : staged_manifest.files) {
            const auto src_file = staging_dir / sf.relative_path;
            const auto dst_file = target_local_folder / sf.relative_path;

            if (fs::exists(dst_file)) {
                // Back up replaced file
                const auto rec_file = recovery_dir / sf.relative_path;
                fs::create_directories(rec_file.parent_path());
                fs::copy_file(dst_file, rec_file, fs::copy_options::overwrite_existing);
            }
            fs::create_directories(dst_file.parent_path());
            fs::copy_file(src_file, dst_file, fs::copy_options::overwrite_existing);
        }

        // Clean staging
        fs::remove_all(staging_dir);

        // Verify final root
        const auto final_manifest = scan_folder(target_local_folder);
        if (!final_manifest.complete) {
            error_out = "Post-update scan failed";
            return false;
        }

        // Mark applied under db_mutex_
        const auto t = now_ms();
        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            sqlite3_stmt* stmt = nullptr;
            const char* sql = "UPDATE client_updates SET status = 'applied', applied_at_ms = ? WHERE id = ?";
            stmt = stmt_registry_.prepare(db_, sql); if (stmt) {
                sqlite3_bind_int64(stmt, 1, t);
                sqlite3_bind_text(stmt, 2, update_id.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                stmt_registry_.finalize(stmt);
            }
        }

        const auto user = find_user_by_id(client_id);
        record_event(client_id, user ? user->username : "client", "UPDATE_APPLIED",
                     "update:" + update_id, "success",
                     "Applied version '" + upd.version_title + "' (final local root: " + final_manifest.merkle_root.substr(0, 12) + "...)");

        return true;
    } catch (const std::exception& ex) {
        fs::remove_all(staging_dir);
        error_out = std::string("Error during update application: ") + ex.what();

        {
            std::lock_guard<std::mutex> db_lock(db_mutex_);
            sqlite3_stmt* stmt = nullptr;
            const char* sql = "UPDATE client_updates SET status = 'failed', error_message = ? WHERE id = ?";
            stmt = stmt_registry_.prepare(db_, sql); if (stmt) {
                sqlite3_bind_text(stmt, 1, error_out.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, update_id.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                stmt_registry_.finalize(stmt);
            }
        }

        const auto user = find_user_by_id(client_id);
        record_event(client_id, user ? user->username : "client", "UPDATE_FAILED",
                     "update:" + update_id, "failure", error_out);

        return false;
    }
}

// Precondition: caller must hold db_mutex_.
void CollabStore::record_event_nolock(const std::string& actor_id,
                                      const std::string& actor_username,
                                      const std::string& action,
                                      const std::string& resource,
                                      const std::string& outcome,
                                      const std::string& detail) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        INSERT INTO security_events (actor_id, actor_username, action, resource, outcome, detail, timestamp_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";
    stmt = stmt_registry_.prepare(db_, sql); if (stmt) {
        sqlite3_bind_text(stmt, 1, actor_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, actor_username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, resource.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, outcome.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, detail.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 7, now_ms());
        sqlite3_step(stmt);
        stmt_registry_.finalize(stmt);
    }
}

void CollabStore::record_event(const std::string& actor_id,
                               const std::string& actor_username,
                               const std::string& action,
                               const std::string& resource,
                               const std::string& outcome,
                               const std::string& detail) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    record_event_nolock(actor_id, actor_username, action, resource, outcome, detail);
}

std::vector<CollabSecurityEvent> CollabStore::list_events(std::size_t limit) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::vector<CollabSecurityEvent> events;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, actor_id, actor_username, action, resource, outcome, detail, timestamp_ms FROM security_events ORDER BY id DESC LIMIT ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return events;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(limit));

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabSecurityEvent e;
        e.id = sqlite3_column_int64(stmt, 0);
        const auto* actor = sqlite3_column_text(stmt, 1);
        e.actor_id = actor ? reinterpret_cast<const char*>(actor) : "";
        const auto* uname = sqlite3_column_text(stmt, 2);
        e.actor_username = uname ? reinterpret_cast<const char*>(uname) : "";
        e.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        const auto* res = sqlite3_column_text(stmt, 4);
        e.resource = res ? reinterpret_cast<const char*>(res) : "";
        e.outcome = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        const auto* det = sqlite3_column_text(stmt, 6);
        e.detail = det ? reinterpret_cast<const char*>(det) : "";
        e.timestamp_ms = sqlite3_column_int64(stmt, 7);
        events.push_back(e);
    }
    stmt_registry_.finalize(stmt);
    return events;
}

std::vector<CollabSecurityEvent> CollabStore::list_events_for_actor(const std::string& actor_id, std::size_t limit) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    std::vector<CollabSecurityEvent> events;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, actor_id, actor_username, action, resource, outcome, detail, timestamp_ms FROM security_events WHERE actor_id = ? ORDER BY id DESC LIMIT ?";
    stmt = stmt_registry_.prepare(db_, sql); if (!stmt) return events;
    sqlite3_bind_text(stmt, 1, actor_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(limit));

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabSecurityEvent e;
        e.id = sqlite3_column_int64(stmt, 0);
        const auto* actor = sqlite3_column_text(stmt, 1);
        e.actor_id = actor ? reinterpret_cast<const char*>(actor) : "";
        const auto* uname = sqlite3_column_text(stmt, 2);
        e.actor_username = uname ? reinterpret_cast<const char*>(uname) : "";
        e.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        const auto* res = sqlite3_column_text(stmt, 4);
        e.resource = res ? reinterpret_cast<const char*>(res) : "";
        e.outcome = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        const auto* det = sqlite3_column_text(stmt, 6);
        e.detail = det ? reinterpret_cast<const char*>(det) : "";
        e.timestamp_ms = sqlite3_column_int64(stmt, 7);
        events.push_back(e);
    }
    stmt_registry_.finalize(stmt);
    return events;
}

std::int64_t file_ticks_to_millis(std::int64_t ticks) {
    using FileClock = fs::file_time_type::clock;
    const auto file_time = fs::file_time_type(FileClock::duration(ticks));
    const auto system_time = std::chrono::system_clock::now() +
        std::chrono::duration_cast<std::chrono::system_clock::duration>(file_time - FileClock::now());
    return std::chrono::duration_cast<std::chrono::milliseconds>(system_time.time_since_epoch()).count();
}


bool CollabStore::reconstruct_version(const std::string& version_id,
                                      const fs::path& destination_dir,
                                      std::string& error_out) {
    OperationGuard op_guard(*this);

    std::string expected_merkle_root;
    std::string ws_id;
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> manifest_blobs;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        auto ver = find_version_by_id_nolock(version_id);
        if (!ver) {
            error_out = "Version not found: " + version_id;
            return false;
        }
        expected_merkle_root = ver->merkle_root;
        ws_id = ver->workspace_id;

        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT relative_path, manifest_blob FROM version_manifests WHERE version_id = ? ORDER BY relative_path ASC";
        stmt = stmt_registry_.prepare(db_, sql);
        if (stmt) {
            sqlite3_bind_text(stmt, 1, version_id.c_str(), -1, SQLITE_STATIC);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string rel = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                const void* data = sqlite3_column_blob(stmt, 1);
                int bytes = sqlite3_column_bytes(stmt, 1);
                std::vector<std::uint8_t> blob;
                if (data && bytes > 0) {
                    const auto* p = reinterpret_cast<const std::uint8_t*>(data);
                    blob.assign(p, p + bytes);
                }
                manifest_blobs.emplace_back(std::move(rel), std::move(blob));
            }
            stmt_registry_.finalize(stmt);
        }
    }

    // Legacy fallback: if no manifests exist, check legacy snapshot or empty version
    if (manifest_blobs.empty()) {
        const auto legacy_dir = workspace_versions_dir(ws_id) / version_id;
        if (fs::exists(legacy_dir)) {
            const auto lm = scan_folder(legacy_dir);
            if (lm.complete && lm.merkle_root == expected_merkle_root) {
                std::error_code ec;
                fs::create_directories(destination_dir, ec);
                copy_directory_recursive(legacy_dir, destination_dir);
                return true;
            }
        }
        // If version has 0 files and empty merkle root, reconstruct as empty directory
        if (expected_merkle_root == sha256_data("MERKLECHAIN-EMPTY-v1", 20)) {
            std::error_code ec;
            fs::create_directories(destination_dir, ec);
            return true;
        }
        error_out = "No manifests found for version " + version_id + " and legacy snapshot unavailable";
        return false;
    }

    // Reconstruct via temporary staging directory (WITHOUT holding db_mutex_)
    const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto staging_parent = destination_dir.has_parent_path() ? destination_dir.parent_path() : fs::current_path();
    const fs::path staging_dir = staging_parent / (".reconstruct_" + version_id + "_" + std::to_string(now_ns) + "_" + generate_random_token(6) + ".tmp");

    std::error_code ec;
    fs::create_directories(staging_dir, ec);
    if (ec) {
        error_out = "Failed to create staging directory for version reconstruction: " + ec.message();
        return false;
    }

    for (const auto& [rel_path, blob] : manifest_blobs) {
        // Path safety validation
        if (rel_path.empty() || !safe_relative_path(rel_path)) {
            fs::remove_all(staging_dir, ec);
            error_out = "Unsafe relative path in manifest: " + rel_path;
            return false;
        }

        cas::FileManifest man;
        std::string parse_err;
        if (!cas::ManifestSerializer::deserialize_binary(blob.data(), blob.size(), man, parse_err)) {
            fs::remove_all(staging_dir, ec);
            error_out = "Corrupted manifest for " + rel_path + ": " + parse_err;
            return false;
        }

        const fs::path target_file = staging_dir / rel_path;
        std::string recon_err;
        if (!cas_store_->reconstruct_file(man, target_file, recon_err, true)) {
            fs::remove_all(staging_dir, ec);
            error_out = "Failed reconstructing " + rel_path + " from CAS: " + recon_err;
            return false;
        }
    }

    // Verify overall directory Merkle root matches published version
    const auto recon_manifest = scan_folder(staging_dir);
    if (!recon_manifest.complete || recon_manifest.merkle_root != expected_merkle_root) {
        fs::remove_all(staging_dir, ec);
        error_out = "Reconstructed version Merkle root mismatch: expected " + expected_merkle_root + ", got " + recon_manifest.merkle_root;
        return false;
    }

    // Atomically promote staging directory to destination_dir
    if (fs::exists(destination_dir)) {
        fs::remove_all(destination_dir, ec);
    }
    fs::create_directories(destination_dir.parent_path(), ec);
    fs::rename(staging_dir, destination_dir, ec);
    if (ec) {
        copy_directory_recursive(staging_dir, destination_dir);
        fs::remove_all(staging_dir, ec);
    }

    return true;
}

std::vector<cas::FileManifest> CollabStore::get_version_manifests(const std::string& version_id,
                                                                 std::string& error_out) {
    OperationGuard op_guard(*this);
    std::vector<std::vector<std::uint8_t>> blobs;
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT manifest_blob FROM version_manifests WHERE version_id = ? ORDER BY relative_path ASC";
        stmt = stmt_registry_.prepare(db_, sql);
        if (!stmt) {
            error_out = "Failed to prepare manifest query";
            return {};
        }
        sqlite3_bind_text(stmt, 1, version_id.c_str(), -1, SQLITE_STATIC);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* data = sqlite3_column_blob(stmt, 0);
            int bytes = sqlite3_column_bytes(stmt, 0);
            if (data && bytes > 0) {
                const auto* p = reinterpret_cast<const std::uint8_t*>(data);
                blobs.emplace_back(p, p + bytes);
            }
        }
        stmt_registry_.finalize(stmt);
    }

    std::vector<cas::FileManifest> manifests;
    manifests.reserve(blobs.size());
    for (const auto& b : blobs) {
        cas::FileManifest man;
        std::string err;
        if (!cas::ManifestSerializer::deserialize_binary(b.data(), b.size(), man, err)) {
            error_out = "Failed deserializing manifest: " + err;
            return {};
        }
        manifests.push_back(std::move(man));
    }
    return manifests;
}

std::size_t CollabStore::get_chunk_reference_count(const std::string& chunk_hash) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT reference_count FROM cas_chunks WHERE chunk_hash = ?";
    stmt = stmt_registry_.prepare(db_, sql);
    if (!stmt) return 0;
    sqlite3_bind_text(stmt, 1, chunk_hash.c_str(), -1, SQLITE_STATIC);
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    }
    stmt_registry_.finalize(stmt);
    return count;
}

bool CollabStore::audit_cas_reference_integrity(std::string& error_out) {
    OperationGuard op_guard(*this);
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    // Check for negative reference counts
    sqlite3_stmt* stmt = nullptr;
    const char* sql_neg = "SELECT chunk_hash, reference_count FROM cas_chunks WHERE reference_count < 0";
    stmt = stmt_registry_.prepare(db_, sql_neg);
    if (stmt) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int rc = sqlite3_column_int(stmt, 1);
            stmt_registry_.finalize(stmt);
            error_out = "Negative reference count detected for chunk " + h + ": " + std::to_string(rc);
            return false;
        }
        stmt_registry_.finalize(stmt);
    }

    // Check drift between cas_chunks.reference_count and COUNT(version_manifest_chunks)
    const char* sql_drift = R"(
        SELECT c.chunk_hash, c.reference_count, COUNT(vmc.chunk_hash)
        FROM cas_chunks c
        LEFT JOIN version_manifest_chunks vmc ON c.chunk_hash = vmc.chunk_hash
        GROUP BY c.chunk_hash
        HAVING c.reference_count != COUNT(vmc.chunk_hash)
    )";
    stmt = stmt_registry_.prepare(db_, sql_drift);
    if (stmt) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int expected = sqlite3_column_int(stmt, 1);
            int actual = sqlite3_column_int(stmt, 2);
            stmt_registry_.finalize(stmt);
            error_out = "Reference count drift for " + h + ": recorded " + std::to_string(expected) + ", actual manifest count " + std::to_string(actual);
            return false;
        }
        stmt_registry_.finalize(stmt);
    }

    // Check for dangling manifest chunk references lacking a cas_chunks catalog entry
    const char* sql_orphan = R"(
        SELECT vmc.chunk_hash
        FROM version_manifest_chunks vmc
        LEFT JOIN cas_chunks c ON vmc.chunk_hash = c.chunk_hash
        WHERE c.chunk_hash IS NULL
        LIMIT 1
    )";
    stmt = stmt_registry_.prepare(db_, sql_orphan);
    if (stmt) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            stmt_registry_.finalize(stmt);
            error_out = "Dangling manifest chunk reference without cas_chunks record: " + h;
            return false;
        }
        stmt_registry_.finalize(stmt);
    }

    // Verify physical CAS existence and size match for all active referenced chunks
    std::vector<std::pair<std::string, std::uintmax_t>> chunks_to_verify;
    const char* sql_phys = "SELECT chunk_hash, chunk_size FROM cas_chunks WHERE reference_count > 0";
    stmt = stmt_registry_.prepare(db_, sql_phys);
    if (stmt) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string h = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            auto sz = static_cast<std::uintmax_t>(sqlite3_column_int64(stmt, 1));
            chunks_to_verify.emplace_back(std::move(h), sz);
        }
        stmt_registry_.finalize(stmt);
    }

    for (const auto& [h, expected_sz] : chunks_to_verify) {
        if (!cas_store_->has_object(h)) {
            error_out = "Referenced chunk missing from physical CAS storage: " + h;
            return false;
        }
        if (cas_store_->object_size(h) != expected_sz) {
            error_out = "Referenced chunk size mismatch in physical CAS storage for " + h + ": expected " + std::to_string(expected_sz) + ", found " + std::to_string(cas_store_->object_size(h));
            return false;
        }
        auto vres = cas::ObjectVerifier::verify_object(cas_store_->object_path(h), h, expected_sz);
        if (!vres.valid) {
            error_out = "Referenced chunk cryptographic hash corruption for " + h + ": " + vres.error;
            return false;
        }
    }

    return true;
}

} // namespace mc
