#include "merklechain/collab_store.hpp"
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
#include <unordered_set>

namespace mc {

namespace {

std::string to_hex(const unsigned char* data, std::size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return ss.str();
}

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

void sanitize_and_validate_relative_path(const std::string& rel_path) {
    if (rel_path.empty()) throw std::runtime_error("relative path cannot be empty");
    if (rel_path.find('\\') != std::string::npos && rel_path.find('/') != std::string::npos) {
        // Normalize internally to forward slashes for checking
    }
    std::string norm = rel_path;
    std::replace(norm.begin(), norm.end(), '\\', '/');
    if (norm.front() == '/' || norm.find(':') != std::string::npos) {
        throw std::runtime_error("absolute or drive paths are forbidden: " + rel_path);
    }
    std::stringstream ss(norm);
    std::string segment;
    while (std::getline(ss, segment, '/')) {
        if (segment == "..") {
            throw std::runtime_error("directory traversal detected in path: " + rel_path);
        }
    }
}

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

    // Enable WAL and foreign keys
    execute_sql("PRAGMA journal_mode = WAL;");
    execute_sql("PRAGMA foreign_keys = ON;");

    init_schema();
    seed_default_accounts_if_empty();
}

CollabStore::~CollabStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

std::int64_t CollabStore::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void CollabStore::execute_sql(const std::string& sql) {
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
        CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp_ms);
    )";
    execute_sql(schema);
}

void CollabStore::seed_default_accounts_if_empty() {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM users", -1, &stmt, nullptr) != SQLITE_OK) return;
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

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
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
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
        sqlite3_finalize(stmt);
        throw std::runtime_error("failed to create user: " + err);
    }
    sqlite3_finalize(stmt);

    return user;
}

std::optional<CollabUser> CollabStore::find_user_by_id(const std::string& user_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms FROM users WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
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
        sqlite3_finalize(stmt);
        return u;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::optional<CollabUser> CollabStore::find_user_by_username(const std::string& username) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms FROM users WHERE username = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
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
        sqlite3_finalize(stmt);
        return u;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<CollabUser> CollabStore::list_clients() {
    std::vector<CollabUser> users;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, username, password_hash, role, status, permissions, created_at_ms, last_login_ms FROM users ORDER BY created_at_ms DESC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return users;

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
    sqlite3_finalize(stmt);
    return users;
}

bool CollabStore::set_user_status(const std::string& user_id, const std::string& status) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE users SET status = ? WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    if (ok && status == "suspended") {
        revoke_all_user_sessions(user_id);
    }
    return ok;
}

bool CollabStore::reset_user_password(const std::string& user_id, const std::string& new_password) {
    if (new_password.length() < 8) throw std::runtime_error("password must be at least 8 characters");
    const auto hash = hash_password(new_password);
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE users SET password_hash = ? WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    if (ok) {
        revoke_all_user_sessions(user_id);
    }
    return ok;
}

bool CollabStore::update_user_permissions(const std::string& user_id, const std::vector<std::string>& permissions) {
    const auto perms_str = join_strings(permissions);
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE users SET permissions = ? WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, perms_str.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

std::optional<CollabSession> CollabStore::authenticate(const std::string& username,
                                                        const std::string& password,
                                                        std::string& error_out) {
    const auto user_opt = find_user_by_username(username);
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
        if (sqlite3_prepare_v2(db_, "UPDATE users SET last_login_ms = ? WHERE id = ?", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, current_time);
            sqlite3_bind_text(stmt, 2, user.id.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
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
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, session.token.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, session.user_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 3, session.created_at_ms);
            sqlite3_bind_int64(stmt, 4, session.expires_at_ms);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    return session;
}

std::optional<CollabSession> CollabStore::validate_session(const std::string& token) {
    if (token.empty()) return std::nullopt;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT s.token, s.user_id, u.username, u.role, s.created_at_ms, s.expires_at_ms, s.active, u.status
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.active = 1
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
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
        sqlite3_finalize(stmt);

        if (user_status != "active" || now_ms() > s.expires_at_ms) {
            revoke_session(token);
            return std::nullopt;
        }
        return s;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

void CollabStore::revoke_session(const std::string& token) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE sessions SET active = 0 WHERE token = ?", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void CollabStore::revoke_all_user_sessions(const std::string& user_id) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE sessions SET active = 0 WHERE user_id = ?", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

CollabWorkspace CollabStore::create_workspace(const std::string& name, const std::string& description, const std::string& custom_id) {
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
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
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
        sqlite3_finalize(stmt);
        throw std::runtime_error("failed to create workspace: " + err);
    }
    sqlite3_finalize(stmt);

    return ws;
}

std::optional<CollabWorkspace> CollabStore::find_workspace_by_id(const std::string& ws_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, name, description, root_path, created_at_ms FROM workspaces WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_text(stmt, 1, ws_id.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CollabWorkspace ws;
        ws.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ws.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* desc = sqlite3_column_text(stmt, 2);
        ws.description = desc ? reinterpret_cast<const char*>(desc) : "";
        ws.root_path = fs::u8path(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
        ws.created_at_ms = sqlite3_column_int64(stmt, 4);
        sqlite3_finalize(stmt);
        return ws;
    }
    sqlite3_finalize(stmt);

    if (ws_id == "ws-default") {
        auto list = list_workspaces();
        for (const auto& w : list) {
            if (w.name == "Default-Workspace") return w;
        }
        if (!list.empty()) return list.front();
    }
    return std::nullopt;
}

std::vector<CollabWorkspace> CollabStore::list_workspaces() {
    std::vector<CollabWorkspace> workspaces;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, name, description, root_path, created_at_ms FROM workspaces ORDER BY created_at_ms ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return workspaces;

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
    sqlite3_finalize(stmt);
    return workspaces;
}

std::vector<CollabWorkspace> CollabStore::list_workspaces_for_user(const std::string& user_id) {
    std::vector<CollabWorkspace> workspaces;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT w.id, w.name, w.description, w.root_path, w.created_at_ms
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE wm.user_id = ?
        ORDER BY w.created_at_ms ASC
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return workspaces;
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
    sqlite3_finalize(stmt);
    return workspaces;
}

void CollabStore::assign_user_to_workspace(const std::string& workspace_id, const std::string& user_id) {
    std::string actual_id = workspace_id;
    auto ws = find_workspace_by_id(workspace_id);
    if (ws) actual_id = ws->id;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR IGNORE INTO workspace_members (workspace_id, user_id) VALUES (?, ?)";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, actual_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

bool CollabStore::is_user_in_workspace(const std::string& workspace_id, const std::string& user_id) {
    std::string actual_id = workspace_id;
    auto ws = find_workspace_by_id(workspace_id);
    if (ws) actual_id = ws->id;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, actual_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_STATIC);
    const bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

fs::path CollabStore::workspace_root(const std::string& ws_id) const {
    std::string actual_id = ws_id;
    auto ws = const_cast<CollabStore*>(this)->find_workspace_by_id(ws_id);
    if (ws) actual_id = ws->id;
    return base_storage_dir_ / "workspaces" / actual_id;
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
    if (!fs::is_directory(source_folder)) {
        throw std::runtime_error("submission source folder is not an accessible directory");
    }

    std::string actual_ws_id = workspace_id;
    auto ws = find_workspace_by_id(workspace_id);
    if (ws) actual_ws_id = ws->id;

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

    // Stage files in workspace submissions directory
    const auto target_dir = workspace_submissions_dir(actual_ws_id) / sub.id;
    copy_directory_recursive(source_folder, target_dir);

    // Verify staged folder matches expected Merkle root
    const auto staged_manifest = scan_folder(target_dir);
    if (!staged_manifest.complete || staged_manifest.merkle_root != sub.merkle_root) {
        fs::remove_all(target_dir);
        throw std::runtime_error("submission integrity verification failed upon staging");
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        INSERT INTO submissions (id, client_id, workspace_id, file_count, total_size, merkle_root, status, review_notes, submitted_at_ms, reviewed_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
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
        sqlite3_finalize(stmt);
        throw std::runtime_error("failed to record submission: " + err);
    }
    sqlite3_finalize(stmt);

    const auto user = find_user_by_id(client_id);
    record_event(client_id, user ? user->username : "unknown", "SUBMISSION_CREATED",
                 "submission:" + sub.id, "success",
                 "Submitted " + std::to_string(sub.file_count) + " files (root: " + sub.merkle_root.substr(0, 12) + "...)");

    return sub;
}

std::optional<CollabSubmission> CollabStore::find_submission_by_id(const std::string& sub_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
        FROM submissions s
        JOIN users u ON s.client_id = u.id
        WHERE s.id = ?
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
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
        sqlite3_finalize(stmt);
        return s;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<CollabSubmission> CollabStore::list_submissions(const std::string& workspace_id) {
    std::string actual_ws_id = workspace_id;
    if (!workspace_id.empty()) {
        auto ws = find_workspace_by_id(workspace_id);
        if (ws) actual_ws_id = ws->id;
    }
    std::vector<CollabSubmission> list;
    sqlite3_stmt* stmt = nullptr;
    std::string sql = R"(
        SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
        FROM submissions s
        JOIN users u ON s.client_id = u.id
    )";
    if (!workspace_id.empty()) {
        sql += " WHERE s.workspace_id = ?";
    }
    sql += " ORDER BY s.submitted_at_ms DESC";

    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return list;
    if (!workspace_id.empty()) {
        sqlite3_bind_text(stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);
    }

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
    sqlite3_finalize(stmt);
    return list;
}

std::vector<CollabSubmission> CollabStore::list_submissions_for_client(const std::string& client_id) {
    std::vector<CollabSubmission> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT s.id, s.client_id, u.username, s.workspace_id, s.file_count, s.total_size, s.merkle_root, s.status, s.review_notes, s.submitted_at_ms, s.reviewed_at_ms
        FROM submissions s
        JOIN users u ON s.client_id = u.id
        WHERE s.client_id = ?
        ORDER BY s.submitted_at_ms DESC
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return list;
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
    sqlite3_finalize(stmt);
    return list;
}

bool CollabStore::accept_submission(const std::string& sub_id, const std::string& reviewer_id, const std::string& notes) {
    const auto sub = find_submission_by_id(sub_id);
    if (!sub || sub->status != "pending") return false;

    const auto sub_path = workspace_submissions_dir(sub->workspace_id) / sub->id;
    const auto base_path = workspace_baseline_dir(sub->workspace_id);
    const auto work_path = workspace_working_copy_dir(sub->workspace_id);

    // Copy to baseline (immutable base) and working copy
    fs::remove_all(base_path);
    fs::remove_all(work_path);
    copy_directory_recursive(sub_path, base_path);
    copy_directory_recursive(sub_path, work_path);

    const auto t = now_ms();
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE submissions SET status = 'accepted', review_notes = ?, reviewed_at_ms = ? WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, notes.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, t);
    sqlite3_bind_text(stmt, 3, sub_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    const auto reviewer = find_user_by_id(reviewer_id);
    record_event(reviewer_id, reviewer ? reviewer->username : "host", "SUBMISSION_ACCEPTED",
                 "submission:" + sub_id, "success", "Accepted baseline created in workspace: " + sub->workspace_id);

    return ok;
}

bool CollabStore::reject_submission(const std::string& sub_id, const std::string& reviewer_id, const std::string& notes) {
    const auto sub = find_submission_by_id(sub_id);
    if (!sub || sub->status != "pending") return false;

    const auto t = now_ms();
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE submissions SET status = 'rejected', review_notes = ?, reviewed_at_ms = ? WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, notes.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, t);
    sqlite3_bind_text(stmt, 3, sub_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    const auto reviewer = find_user_by_id(reviewer_id);
    record_event(reviewer_id, reviewer ? reviewer->username : "host", "SUBMISSION_REJECTED",
                 "submission:" + sub_id, "success", "Notes: " + notes);

    return ok;
}

std::vector<FileMetadata> CollabStore::list_working_copy_files(const std::string& ws_id) {
    const auto work_dir = workspace_working_copy_dir(ws_id);
    if (!fs::exists(work_dir)) return {};
    const auto manifest = scan_folder(work_dir);
    return manifest.files;
}

std::string CollabStore::read_working_copy_file_content(const std::string& ws_id, const std::string& rel_path) {
    sanitize_and_validate_relative_path(rel_path);
    const auto file_path = workspace_working_copy_dir(ws_id) / rel_path;
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
    sanitize_and_validate_relative_path(rel_path);
    const auto work_dir = workspace_working_copy_dir(ws_id);
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
    sanitize_and_validate_relative_path(rel_path);
    const auto target_path = workspace_working_copy_dir(ws_id) / rel_path;
    if (fs::exists(target_path)) {
        fs::remove(target_path);
    }
}

std::vector<CollabFileDiff> CollabStore::compute_working_copy_diff(const std::string& ws_id) {
    std::vector<CollabFileDiff> diffs;
    const auto base_dir = workspace_baseline_dir(ws_id);
    const auto work_dir = workspace_working_copy_dir(ws_id);

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
    sanitize_and_validate_relative_path(rel_path);
    CollabFileDiff diff;
    diff.relative_path = rel_path;

    const auto base_file = workspace_baseline_dir(ws_id) / rel_path;
    const auto work_file = workspace_working_copy_dir(ws_id) / rel_path;

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

CollabPublishedVersion CollabStore::publish_version(const std::string& ws_id,
                                                    const std::string& published_by_id,
                                                    const std::string& title,
                                                    const std::string& release_notes) {
    std::string actual_ws_id = ws_id;
    auto ws = find_workspace_by_id(ws_id);
    if (ws) actual_ws_id = ws->id;

    const auto work_dir = workspace_working_copy_dir(actual_ws_id);
    if (!fs::exists(work_dir)) {
        throw std::runtime_error("cannot publish: working copy does not exist");
    }
    const auto manifest = scan_folder(work_dir);
    if (!manifest.complete) {
        throw std::runtime_error("cannot publish: working copy scan incomplete");
    }

    // Determine parent version
    std::string parent_id;
    {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT id FROM published_versions WHERE workspace_id = ? ORDER BY published_at_ms DESC LIMIT 1";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                parent_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            }
            sqlite3_finalize(stmt);
        }
    }

    CollabPublishedVersion ver;
    ver.id = "ver_" + generate_random_token(10);
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

    // Store immutable copy of version in workspace versions directory
    const auto ver_storage = workspace_versions_dir(actual_ws_id) / ver.id;
    copy_directory_recursive(work_dir, ver_storage);

    // Also update baseline to match published version
    const auto base_dir = workspace_baseline_dir(actual_ws_id);
    fs::remove_all(base_dir);
    copy_directory_recursive(work_dir, base_dir);

    // Save record to database in a transaction
    execute_sql("BEGIN TRANSACTION;");
    try {
        sqlite3_stmt* stmt = nullptr;
        const char* sql = R"(
            INSERT INTO published_versions (id, workspace_id, parent_version_id, title, release_notes, merkle_root, file_count, total_size, published_by_id, published_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("failed to prepare version insert");
        }
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
            sqlite3_finalize(stmt);
            throw std::runtime_error("failed to insert published version: " + err);
        }
        sqlite3_finalize(stmt);

        // Notify/create client update records for all clients assigned to workspace
        std::vector<std::string> client_ids;
        {
            sqlite3_stmt* mem_stmt = nullptr;
            const char* mem_sql = R"(
                SELECT wm.user_id FROM workspace_members wm
                JOIN users u ON wm.user_id = u.id
                WHERE wm.workspace_id = ? AND u.role = 'client' AND u.status = 'active'
            )";
            if (sqlite3_prepare_v2(db_, mem_sql, -1, &mem_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(mem_stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);
                while (sqlite3_step(mem_stmt) == SQLITE_ROW) {
                    client_ids.push_back(reinterpret_cast<const char*>(sqlite3_column_text(mem_stmt, 0)));
                }
                sqlite3_finalize(mem_stmt);
            }
        }

        for (const auto& cid : client_ids) {
            const std::string update_id = "upd_" + generate_random_token(10);
            sqlite3_stmt* upd_stmt = nullptr;
            const char* upd_sql = "INSERT INTO client_updates (id, version_id, client_id, workspace_id, status) VALUES (?, ?, ?, ?, 'available')";
            if (sqlite3_prepare_v2(db_, upd_sql, -1, &upd_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(upd_stmt, 1, update_id.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(upd_stmt, 2, ver.id.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(upd_stmt, 3, cid.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(upd_stmt, 4, actual_ws_id.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(upd_stmt);
                sqlite3_finalize(upd_stmt);
            }
        }

        execute_sql("COMMIT;");
    } catch (...) {
        execute_sql("ROLLBACK;");
        fs::remove_all(ver_storage);
        throw;
    }

    const auto publisher = find_user_by_id(published_by_id);
    record_event(published_by_id, publisher ? publisher->username : "host", "VERSION_PUBLISHED",
                 "version:" + ver.id, "success",
                 "Published version '" + ver.title + "' (root: " + ver.merkle_root.substr(0, 12) + "...)");

    return ver;
}

std::vector<CollabPublishedVersion> CollabStore::list_published_versions(const std::string& ws_id) {
    std::string actual_ws_id = ws_id;
    if (!ws_id.empty()) {
        auto ws = find_workspace_by_id(ws_id);
        if (ws) actual_ws_id = ws->id;
    }
    std::vector<CollabPublishedVersion> list;
    sqlite3_stmt* stmt = nullptr;
    std::string sql = R"(
        SELECT v.id, v.workspace_id, v.parent_version_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, v.published_by_id, u.username, v.published_at_ms
        FROM published_versions v
        JOIN users u ON v.published_by_id = u.id
    )";
    if (!ws_id.empty()) {
        sql += " WHERE v.workspace_id = ?";
    }
    sql += " ORDER BY v.published_at_ms DESC";

    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return list;
    if (!ws_id.empty()) {
        sqlite3_bind_text(stmt, 1, actual_ws_id.c_str(), -1, SQLITE_STATIC);
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
        v.published_by_username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        v.published_at_ms = sqlite3_column_int64(stmt, 10);
        list.push_back(v);
    }
    sqlite3_finalize(stmt);
    return list;
}

std::optional<CollabPublishedVersion> CollabStore::find_version_by_id(const std::string& version_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT v.id, v.workspace_id, v.parent_version_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, v.published_by_id, u.username, v.published_at_ms
        FROM published_versions v
        JOIN users u ON v.published_by_id = u.id
        WHERE v.id = ?
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
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
        sqlite3_finalize(stmt);
        return v;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<CollabClientUpdate> CollabStore::list_updates_for_client(const std::string& client_id) {
    std::vector<CollabClientUpdate> list;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT u.id, u.version_id, u.client_id, u.workspace_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, u.status, u.accepted_at_ms, u.applied_at_ms, u.error_message
        FROM client_updates u
        JOIN published_versions v ON u.version_id = v.id
        WHERE u.client_id = ?
        ORDER BY v.published_at_ms DESC
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return list;
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
    sqlite3_finalize(stmt);
    return list;
}

std::optional<CollabClientUpdate> CollabStore::find_update_by_id(const std::string& update_id) {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        SELECT u.id, u.version_id, u.client_id, u.workspace_id, v.title, v.release_notes, v.merkle_root, v.file_count, v.total_size, u.status, u.accepted_at_ms, u.applied_at_ms, u.error_message
        FROM client_updates u
        JOIN published_versions v ON u.version_id = v.id
        WHERE u.id = ?
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
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
        sqlite3_finalize(stmt);
        return upd;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

bool CollabStore::accept_update(const std::string& update_id, const std::string& client_id) {
    const auto upd = find_update_by_id(update_id);
    if (!upd || upd->client_id != client_id) return false;

    const auto t = now_ms();
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE client_updates SET status = 'accepted', accepted_at_ms = ? WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int64(stmt, 1, t);
    sqlite3_bind_text(stmt, 2, update_id.c_str(), -1, SQLITE_STATIC);
    const bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    const auto user = find_user_by_id(client_id);
    record_event(client_id, user ? user->username : "client", "UPDATE_ACCEPTED",
                 "update:" + update_id, "success", "Accepted version update: " + upd->version_title);

    return ok;
}

bool CollabStore::apply_update(const std::string& update_id,
                               const std::string& client_id,
                               const fs::path& target_local_folder,
                               std::string& error_out) {
    const auto upd = find_update_by_id(update_id);
    if (!upd || upd->client_id != client_id) {
        error_out = "Update not found or unauthorized";
        return false;
    }

    if (!fs::is_directory(target_local_folder)) {
        error_out = "Target local folder is not a valid directory";
        return false;
    }

    const auto version_dir = workspace_versions_dir(upd->workspace_id) / upd->version_id;
    if (!fs::exists(version_dir)) {
        error_out = "Published version directory missing from server";
        return false;
    }

    // Scan target directory and version directory
    const auto ver_manifest = scan_folder(version_dir);
    if (!ver_manifest.complete || ver_manifest.merkle_root != upd->merkle_root) {
        error_out = "Published version failed integrity verification";
        return false;
    }

    // Stage update in temporary directory inside target
    const auto staging_dir = target_local_folder / ".merklechain" / "staging" / upd->id;
    const auto recovery_dir = target_local_folder / ".merklechain" / "recovery" / upd->id;
    fs::create_directories(staging_dir);
    fs::create_directories(recovery_dir);

    try {
        // Copy files to staging and verify hashes
        copy_directory_recursive(version_dir, staging_dir);
        const auto staged_manifest = scan_folder(staging_dir);
        if (!staged_manifest.complete || staged_manifest.merkle_root != upd->merkle_root) {
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

        // Mark applied
        const auto t = now_ms();
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "UPDATE client_updates SET status = 'applied', applied_at_ms = ? WHERE id = ?";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, t);
            sqlite3_bind_text(stmt, 2, update_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        const auto user = find_user_by_id(client_id);
        record_event(client_id, user ? user->username : "client", "UPDATE_APPLIED",
                     "update:" + update_id, "success",
                     "Applied version '" + upd->version_title + "' (final local root: " + final_manifest.merkle_root.substr(0, 12) + "...)");

        return true;
    } catch (const std::exception& ex) {
        fs::remove_all(staging_dir);
        error_out = std::string("Error during update application: ") + ex.what();

        sqlite3_stmt* stmt = nullptr;
        const char* sql = "UPDATE client_updates SET status = 'failed', error_message = ? WHERE id = ?";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, error_out.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, update_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        const auto user = find_user_by_id(client_id);
        record_event(client_id, user ? user->username : "client", "UPDATE_FAILED",
                     "update:" + update_id, "failure", error_out);

        return false;
    }
}

void CollabStore::record_event(const std::string& actor_id,
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
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, actor_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, actor_username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, resource.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, outcome.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, detail.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 7, now_ms());
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

std::vector<CollabSecurityEvent> CollabStore::list_events(std::size_t limit) {
    std::vector<CollabSecurityEvent> events;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, actor_id, actor_username, action, resource, outcome, detail, timestamp_ms FROM security_events ORDER BY id DESC LIMIT ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return events;
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
    sqlite3_finalize(stmt);
    return events;
}

std::vector<CollabSecurityEvent> CollabStore::list_events_for_actor(const std::string& actor_id, std::size_t limit) {
    std::vector<CollabSecurityEvent> events;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, actor_id, actor_username, action, resource, outcome, detail, timestamp_ms FROM security_events WHERE actor_id = ? ORDER BY id DESC LIMIT ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return events;
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
    sqlite3_finalize(stmt);
    return events;
}

std::int64_t file_ticks_to_millis(std::int64_t ticks) {
    using FileClock = fs::file_time_type::clock;
    const auto file_time = fs::file_time_type(FileClock::duration(ticks));
    const auto system_time = std::chrono::system_clock::now() +
        std::chrono::duration_cast<std::chrono::system_clock::duration>(file_time - FileClock::now());
    return std::chrono::duration_cast<std::chrono::milliseconds>(system_time.time_since_epoch()).count();
}

} // namespace mc
