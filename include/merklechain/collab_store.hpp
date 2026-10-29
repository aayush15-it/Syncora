#pragma once

#include "merklechain/types.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"

#include <sqlite3.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace mc {

namespace fs = std::filesystem;

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

class CollabStore {
public:
    explicit CollabStore(const fs::path& db_path, const fs::path& base_storage_dir);
    ~CollabStore();

    CollabStore(const CollabStore&) = delete;
    CollabStore& operator=(const CollabStore&) = delete;

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

private:
    fs::path db_path_;
    fs::path base_storage_dir_;
    sqlite3* db_{nullptr};

    void execute_sql(const std::string& sql);
    static std::int64_t now_ms();
};

} // namespace mc

