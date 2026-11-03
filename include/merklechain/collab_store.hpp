#pragma once

#include "merklechain/types.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"

#include <sqlite3.h>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mc {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// MANIFEST SEMANTICS NOTE:
// The Merkle root is computed from (relative_path, sha256_content) pairs only.
// File modification timestamps (modified_ticks) are captured as synchronization
// metadata for UI display but are NOT part of the Merkle root.
// Modification times are NOT preserved through staging copies; the copy receives
// the system time at the point of copy_directory_recursive() execution.
// Two directories with identical content but different modification times
// produce identical Merkle roots.
//
// DURABILITY LIMITATION: Operations use filesystem rename-based staging for
// process-crash safety. Power-loss atomicity is NOT guaranteed on Windows
// without explicit FlushFileBuffers/WriteThrough configuration. Staging
// directories remaining after a power loss are reconciled on next startup,
// but the intermediate state of NTFS metadata may not reflect completed renames.
// ---------------------------------------------------------------------------

struct CollabUser {
    std::string id;
    std::string username;
    std::string password_hash;
    std::string role;             // "host" or "client"
    std::string status;           // "active" or "suspended"
    std::vector<std::string> permissions; // "submit", "view_versions", "download_updates", "accept_updates"
    std::int64_t created_at_ms{0};
    std::int64_t last_login_ms{0};
};

struct CollabSession {
    std::string token;
    std::string user_id;
    std::string username;
    std::string role;
    std::int64_t created_at_ms{0};
    std::int64_t expires_at_ms{0};
    bool active{true};
};

struct CollabWorkspace {
    std::string id;
    std::string name;
    std::string description;
    fs::path root_path;
    std::int64_t created_at_ms{0};
};

struct CollabSubmission {
    std::string id;
    std::string client_id;
    std::string client_username;
    std::string workspace_id;
    std::size_t file_count{0};
    std::uintmax_t total_size{0};
    std::string merkle_root;
    std::string status;           // "pending", "accepted", "rejected"
    std::string review_notes;
    std::int64_t submitted_at_ms{0};
    std::int64_t reviewed_at_ms{0};
};

struct CollabPublishedVersion {
    std::string id;
    std::string workspace_id;
    std::string parent_version_id;
    std::string title;
    std::string release_notes;
    std::string merkle_root;
    std::size_t file_count{0};
    std::uintmax_t total_size{0};
    std::string published_by_id;
    std::string published_by_username;
    std::int64_t published_at_ms{0};
};

struct CollabClientUpdate {
    std::string id;
    std::string version_id;
    std::string client_id;
    std::string workspace_id;
    std::string version_title;
    std::string release_notes;
    std::string merkle_root;
    std::size_t file_count{0};
    std::uintmax_t total_size{0};
    std::string status;           // "available", "accepted", "applied", "failed"
    std::int64_t accepted_at_ms{0};
    std::int64_t applied_at_ms{0};
    std::string error_message;
};

struct CollabSecurityEvent {
    std::int64_t id{0};
    std::string actor_id;
    std::string actor_username;
    std::string action;
    std::string resource;
    std::string outcome;          // "success", "failure", "denied"
    std::string detail;
    std::int64_t timestamp_ms{0};
};

struct CollabFileDiff {
    std::string relative_path;
    std::string change_type;      // "ADDED", "MODIFIED", "DELETED", "UNCHANGED"
    std::string baseline_hash;
    std::string current_hash;
    std::uintmax_t baseline_size{0};
    std::uintmax_t current_size{0};
    std::int64_t baseline_modified_ms{0};
    std::int64_t current_modified_ms{0};
    bool is_binary{false};
    std::string diff_text;
};

// ---------------------------------------------------------------------------
// CollabFaultPoint: Controlled failpoints for testing crash recovery
// ---------------------------------------------------------------------------
enum class CollabFaultPoint {
    None,
    FailAfterIntent,
    FailAfterStaging,
    FailAfterBackup,
    FailAfterBaselinePromotion,
    FailAfterWorkingCopyPromotion,
    FailAfterCommit,
    FailAfterSnapshotPromotion,
    FailAfterStagingBaseline,
    FailAfterBaselineBackup
};

void set_collab_fault_point_for_testing(CollabFaultPoint fp);
CollabFaultPoint get_collab_fault_point_for_testing();

class CollabFaultPointInjected : public std::runtime_error {
public:
    explicit CollabFaultPointInjected(const std::string& msg)
        : std::runtime_error("INJECTED_FAULT_POINT: " + msg) {}
};

void copy_directory_recursive(const fs::path& source, const fs::path& target);

// ---------------------------------------------------------------------------
// WorkspaceOperationRecord: Durable intent journal record for crash recovery
// ---------------------------------------------------------------------------
struct WorkspaceOperationRecord {
    std::string op_id;
    std::string workspace_id;
    std::string operation_type; // "ACCEPT_SUBMISSION", "PUBLISH_VERSION"
    std::string target_id;
    std::string state;           // "PENDING", "STAGED", "PROMOTING", "COMMITTED", "FAILED"
    std::string intent_step;
    std::string expected_base_hash;
    std::string expected_work_hash;
    std::string replacement_hash;
    std::int64_t created_at_ms{0};
    std::int64_t updated_at_ms{0};
};

struct SentinelValidationResult {
    bool valid{false};
    std::string op_id;
    std::string workspace_id;
    std::string op_type;
    std::string dir_role;
    std::int64_t created_at_ms{0};
    std::string error;
};

// ---------------------------------------------------------------------------
// FinalizeResult: returned by finalize_and_close() to communicate shutdown
// outcome to explicit callers without throwing from a noexcept context.
// ---------------------------------------------------------------------------
enum class FinalizeResult {
    OK,                  // db_ closed cleanly; finalized_ = true
    CHECKPOINT_FAILED,   // WAL checkpoint timed out; db_ still closed; finalized_ = true
    CLOSE_FAILED,        // sqlite3_close returned error; db_ retained; finalized_ = false
    ALREADY_FINALIZED,   // no-op; store already shut down
};

// ---------------------------------------------------------------------------
// PreparedStatementRegistry
// Tracks every sqlite3_stmt* allocated against a CollabStore connection.
// All statement preparation and finalization must go through this registry so
// that finalize_and_close() can force-finalize any leaked statements before
// calling sqlite3_close(), preventing SQLITE_BUSY.
// ---------------------------------------------------------------------------
class PreparedStatementRegistry {
public:
    PreparedStatementRegistry() = default;
    PreparedStatementRegistry(const PreparedStatementRegistry&) = delete;
    PreparedStatementRegistry& operator=(const PreparedStatementRegistry&) = delete;

    // Prepare a statement and register it. Returns null and does NOT register
    // on prepare failure (caller must handle the null / error).
    sqlite3_stmt* prepare(sqlite3* db, const char* sql) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return nullptr;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        live_.insert(stmt);
        return stmt;
    }

    // Finalize a single statement and remove it from the registry. No-op for null or already-finalized.
    void finalize(sqlite3_stmt* stmt) {
        if (!stmt) return;
        bool was_registered = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            was_registered = (live_.erase(stmt) > 0);
        }
        if (was_registered) {
            sqlite3_finalize(stmt);
        }
    }

    // Returns the number of currently live statements.
    std::size_t live_count() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return live_.size();
    }

    // Force-finalize all remaining live statements. Returns the count finalized.
    // Called during shutdown, before sqlite3_close().
    std::size_t finalize_all() {
        std::unordered_set<sqlite3_stmt*> to_close;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            to_close.swap(live_);
        }
        for (auto* s : to_close) {
            sqlite3_finalize(s);
        }
        return to_close.size();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_set<sqlite3_stmt*> live_;
};

// ---------------------------------------------------------------------------
// CollabStore
// ---------------------------------------------------------------------------
class CollabStore {
public:
    explicit CollabStore(const fs::path& db_path, const fs::path& base_storage_dir);
    ~CollabStore();

    CollabStore(const CollabStore&) = delete;
    CollabStore& operator=(const CollabStore&) = delete;

    // Lifecycle: explicit shutdown and connection closure.
    // noexcept -- errors are communicated via FinalizeResult and stderr.
    FinalizeResult finalize_and_close() noexcept;

    // Cryptographic & Password Helpers
    static std::string hash_password(const std::string& password);
    static bool verify_password(const std::string& password, const std::string& stored_hash);
    static std::string generate_random_token(std::size_t bytes = 32);

    // Initialization & Seeding
    void init_schema();
    void seed_default_accounts_if_empty();

    // User & Account Management
    CollabUser create_user(const std::string& username,
                           const std::string& password,
                           const std::string& role,
                           const std::vector<std::string>& permissions);
    std::optional<CollabUser> find_user_by_id(const std::string& user_id);
    std::optional<CollabUser> find_user_by_username(const std::string& username);
    std::vector<CollabUser> list_clients();
    bool set_user_status(const std::string& user_id, const std::string& status);
    bool reset_user_password(const std::string& user_id, const std::string& new_password);
    bool update_user_permissions(const std::string& user_id, const std::vector<std::string>& permissions);

    // Session Management
    std::optional<CollabSession> authenticate(const std::string& username,
                                              const std::string& password,
                                              std::string& error_out);
    std::optional<CollabSession> validate_session(const std::string& token);
    void revoke_session(const std::string& token);
    void revoke_all_user_sessions(const std::string& user_id);

    // Workspaces
    CollabWorkspace create_workspace(const std::string& name, const std::string& description, const std::string& custom_id = "");
    std::optional<CollabWorkspace> find_workspace_by_id(const std::string& ws_id);
    std::vector<CollabWorkspace> list_workspaces();
    std::vector<CollabWorkspace> list_workspaces_for_user(const std::string& user_id);
    void assign_user_to_workspace(const std::string& workspace_id, const std::string& user_id);
    bool is_user_in_workspace(const std::string& workspace_id, const std::string& user_id);

    // Filesystem Path Resolution within Workspace
    fs::path workspace_root(const std::string& ws_id) const;
    fs::path workspace_submissions_dir(const std::string& ws_id) const;
    fs::path workspace_baseline_dir(const std::string& ws_id) const;
    fs::path workspace_working_copy_dir(const std::string& ws_id) const;
    fs::path workspace_versions_dir(const std::string& ws_id) const;

    // Submissions
    CollabSubmission create_submission(const std::string& client_id,
                                       const std::string& workspace_id,
                                       const fs::path& source_folder);
    std::optional<CollabSubmission> find_submission_by_id(const std::string& sub_id);
    std::vector<CollabSubmission> list_submissions(const std::string& workspace_id = "");
    std::vector<CollabSubmission> list_submissions_for_client(const std::string& client_id);
    bool accept_submission(const std::string& sub_id, const std::string& reviewer_id, const std::string& notes);
    bool reject_submission(const std::string& sub_id, const std::string& reviewer_id, const std::string& notes);

    // Host Workspace File Operations
    std::vector<FileMetadata> list_working_copy_files(const std::string& ws_id);
    std::string read_working_copy_file_content(const std::string& ws_id, const std::string& rel_path);
    void write_working_copy_file_content(const std::string& ws_id, const std::string& rel_path, const std::string& content);
    void delete_working_copy_file(const std::string& ws_id, const std::string& rel_path);

    // Change Review & Diff
    std::vector<CollabFileDiff> compute_working_copy_diff(const std::string& ws_id);
    CollabFileDiff compute_file_diff(const std::string& ws_id, const std::string& rel_path);

    // Publishing
    CollabPublishedVersion publish_version(const std::string& ws_id,
                                           const std::string& published_by_id,
                                           const std::string& title,
                                           const std::string& release_notes);
    std::vector<CollabPublishedVersion> list_published_versions(const std::string& ws_id);
    std::optional<CollabPublishedVersion> find_version_by_id(const std::string& version_id);

    // Client Updates
    std::vector<CollabClientUpdate> list_updates_for_client(const std::string& client_id);
    std::optional<CollabClientUpdate> find_update_by_id(const std::string& update_id);
    bool accept_update(const std::string& update_id, const std::string& client_id);
    bool apply_update(const std::string& update_id,
                      const std::string& client_id,
                      const fs::path& target_local_folder,
                      std::string& error_out);

    // Activity & Audit Logging
    void record_event(const std::string& actor_id,
                      const std::string& actor_username,
                      const std::string& action,
                      const std::string& resource,
                      const std::string& outcome,
                      const std::string& detail = "");
    std::vector<CollabSecurityEvent> list_events(std::size_t limit = 100);
    std::vector<CollabSecurityEvent> list_events_for_actor(const std::string& actor_id, std::size_t limit = 100);

    // Crash Recovery & Operation Journal
    void recover_incomplete_operations();
    std::vector<WorkspaceOperationRecord> list_workspace_operations(const std::string& workspace_id);
    std::optional<WorkspaceOperationRecord> find_workspace_operation(const std::string& op_id);
    const fs::path& storage_root() const { return base_storage_dir_; }
    const fs::path& database_path() const { return db_path_; }

    // ---------------------------------------------------------------------------
    // Infrastructure accessors for testing only
    // ---------------------------------------------------------------------------
    std::size_t live_statement_count() const { return stmt_registry_.live_count(); }
    bool is_finalized() const {
        std::lock_guard<std::mutex> lk(lifecycle_mutex_);
        return finalized_;
    }
    bool is_shutting_down() const {
        std::lock_guard<std::mutex> lk(lifecycle_mutex_);
        return shutting_down_;
    }
    std::size_t active_operations_count() const {
        std::lock_guard<std::mutex> lk(lifecycle_mutex_);
        return active_ops_;
    }

    bool test_create_sentinel_file(const fs::path& dir_path,
                                   const std::string& op_id,
                                   const std::string& ws_id,
                                   const std::string& op_type,
                                   const std::string& dir_role) {
        return create_sentinel_file(dir_path, op_id, ws_id, op_type, dir_role);
    }
    SentinelValidationResult test_validate_sentinel_file(const fs::path& dir_path,
                                                         const std::string& expected_op_id,
                                                         const std::string& expected_ws_id,
                                                         const std::string& expected_role) const {
        return validate_sentinel_file(dir_path, expected_op_id, expected_ws_id, expected_role);
    }

    template <typename F>
    auto execute_with_operation_guard(F&& f) -> decltype(f());

    template <typename F>
    auto execute_with_workspace_lock(const std::string& ws_id, F&& f) -> decltype(f());

private:
    // -----------------------------------------------------------------------
    // Storage paths and raw SQLite handle
    // -----------------------------------------------------------------------
    fs::path db_path_;
    fs::path base_storage_dir_;
    sqlite3* db_{nullptr};

    // -----------------------------------------------------------------------
    // Prepared statement registry
    // Owns the lifetime tracking of every sqlite3_stmt* against db_.
    // -----------------------------------------------------------------------
    mutable PreparedStatementRegistry stmt_registry_;

    // -----------------------------------------------------------------------
    // Database serialization mutex
    // Must be held for the duration of every sqlite3_prepare/step/finalize
    // sequence and every execute_sql() call.
    // Must NOT be held across filesystem operations.
    // Must NOT be acquired while lifecycle_mutex_ is held (lock ordering:
    //   lifecycle_mutex_ -> db_mutex_ -> stmt_registry_.mutex_).
    // -----------------------------------------------------------------------
    mutable std::mutex db_mutex_;

    // -----------------------------------------------------------------------
    // Lifecycle admission and drain
    // lock ordering: lifecycle_mutex_ must be acquired before db_mutex_.
    // -----------------------------------------------------------------------
    mutable std::mutex lifecycle_mutex_;
    std::condition_variable drain_cv_;
    bool shutting_down_{false};
    bool finalized_{false};
    int active_ops_{0};

    // -----------------------------------------------------------------------
    // Per-workspace serialization
    // Serializes compound operations (accept_submission, publish_version)
    // that modify a single workspace's filesystem and database state.
    // Acquired AFTER lifecycle_mutex_ is released by OperationGuard,
    // BEFORE db_mutex_.
    // -----------------------------------------------------------------------
    mutable std::mutex ws_registry_mutex_;
    mutable std::unordered_map<std::string, std::shared_ptr<std::mutex>> ws_mutexes_;



    // -----------------------------------------------------------------------
    // OperationGuard: RAII admission control for public methods.
    // Acquires a counted slot under lifecycle_mutex_. Throws if the store
    // is shutting down or finalized. Releases the slot on destruction and
    // notifies drain_cv_ if active_ops_ reaches zero.
    // -----------------------------------------------------------------------
    struct OperationGuard {
        CollabStore& store;
        bool admitted{false};
        bool nested_{false};

        static inline thread_local const CollabStore* active_store_{nullptr};

        explicit OperationGuard(CollabStore& s) : store(s) {
            if (active_store_ == &s) {
                nested_ = true;
                admitted = true;
                return;
            }
            std::lock_guard<std::mutex> lk(s.lifecycle_mutex_);
            if (s.shutting_down_ || s.finalized_) {
                throw std::runtime_error(
                    "CollabStore operation rejected: store is shutting down or finalized");
            }
            ++s.active_ops_;
            admitted = true;
            active_store_ = &s;
        }

        ~OperationGuard() {
            if (!admitted) return;
            if (nested_) return;
            active_store_ = nullptr;
            std::lock_guard<std::mutex> lk(store.lifecycle_mutex_);
            --store.active_ops_;
            if (store.active_ops_ == 0 && store.shutting_down_) {
                store.drain_cv_.notify_all();
            }
        }

        // Non-copyable, non-movable
        OperationGuard(const OperationGuard&) = delete;
        OperationGuard& operator=(const OperationGuard&) = delete;
    };

    // -----------------------------------------------------------------------
    // Per-workspace lock acquisition.
    // Returns a locked unique_lock on the workspace's dedicated mutex.
    // Creates the mutex on first use.
    // -----------------------------------------------------------------------
    std::unique_lock<std::mutex> get_workspace_lock(const std::string& ws_id) const;

    // -----------------------------------------------------------------------
    // Internal helpers -- require db_mutex_ to be held by the caller.
    // -----------------------------------------------------------------------
    void execute_sql(const std::string& sql);
    static std::int64_t now_ms();

    // -----------------------------------------------------------------------
    // Internal unlocked helpers -- Precondition: caller must hold db_mutex_.
    // These methods NEVER acquire OperationGuard or db_mutex_ directly.
    // -----------------------------------------------------------------------
    std::optional<CollabUser> find_user_by_id_nolock(const std::string& user_id);
    std::optional<CollabUser> find_user_by_username_nolock(const std::string& username);
    std::optional<CollabWorkspace> find_workspace_by_id_nolock(const std::string& ws_id);
    std::vector<CollabWorkspace> list_workspaces_nolock();
    std::optional<CollabSubmission> find_submission_by_id_nolock(const std::string& sub_id);
    std::optional<CollabPublishedVersion> find_version_by_id_nolock(const std::string& version_id);
    std::vector<CollabPublishedVersion> list_published_versions_nolock(const std::string& ws_id);
    std::optional<CollabClientUpdate> find_update_by_id_nolock(const std::string& update_id);
    void revoke_session_nolock(const std::string& token);

    // Sentinel & Ownership Helpers
    bool create_sentinel_file(const fs::path& dir_path,
                              const std::string& op_id,
                              const std::string& ws_id,
                              const std::string& op_type,
                              const std::string& dir_role);
    SentinelValidationResult validate_sentinel_file(const fs::path& dir_path,
                                                   const std::string& expected_op_id,
                                                   const std::string& expected_ws_id,
                                                   const std::string& expected_role) const;
    void quarantine_directory(const fs::path& suspect_dir,
                              const std::string& ws_id,
                              const std::string& reason);
    void assert_path_absent(const fs::path& p) const;

    // Operation Journal Helpers -- Precondition: caller must hold db_mutex_
    void insert_operation_intent_nolock(const WorkspaceOperationRecord& rec);
    void update_operation_intent_nolock(const std::string& op_id,
                                        const std::string& state,
                                        const std::string& intent_step);
    std::optional<WorkspaceOperationRecord> find_workspace_operation_nolock(const std::string& op_id);
    std::vector<WorkspaceOperationRecord> list_incomplete_operations_nolock();

    // Recovery Subroutines -- Precondition: caller must hold workspace lock for ws_id
    void recover_accept_submission_op(const WorkspaceOperationRecord& op);
    void recover_publish_version_op(const WorkspaceOperationRecord& op);
    void scan_and_reconcile_orphaned_directories(const std::string& ws_id);
    void revoke_all_user_sessions_nolock(const std::string& user_id);
    void record_event_nolock(const std::string& actor_id,
                             const std::string& actor_username,
                             const std::string& action,
                             const std::string& resource,
                             const std::string& outcome,
                             const std::string& detail = "");
};

template <typename F>
auto CollabStore::execute_with_operation_guard(F&& f) -> decltype(f()) {
    OperationGuard op_guard(*this);
    return f();
}

template <typename F>
auto CollabStore::execute_with_workspace_lock(const std::string& ws_id, F&& f) -> decltype(f()) {
    OperationGuard op_guard(*this);
    auto ws_lock = get_workspace_lock(ws_id);
    return f();
}

} // namespace mc
