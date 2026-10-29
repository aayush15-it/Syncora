#pragma once

#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mc {
class VersionStore;
class ActivityStore;
class StagingFile;
}

namespace mc::peer {

enum class PeerSessionState {
    Created = 0,
    Authenticated = 1,
    ManifestsValidated = 2,
    PlanAgreed = 3,
    ApprovalPending = 4,
    Prepared = 5,
    CommitPending = 6,
    Committed = 7,
    Aborted = 8,
    RecoveryRequired = 9
};

enum class PeerObservedState { NotFound, Created, Prepared, CommitPending, Committed, Aborted, Unknown };
enum class PeerRecoveryAction { WaitForPeer, PrepareLocal, ResumeCommit, CompleteCommit, AbortUncommitted, ManualRecovery };

enum class PeerOperationState {
    Planned = 0,
    Staged = 1,
    RecoveryPrepared = 2,
    Prepared = 3,
    Committed = 4,
    Finalized = 5,
    RolledBack = 6,
    Failed = 7
};

const char* peer_operation_state_name(PeerOperationState state) noexcept;

struct PeerOperationRecord {
    std::string transaction_id;
    std::string operation_id;
    std::string session_id;
    std::string plan_hash;
    std::string relative_path;
    PeerPlanAction action{PeerPlanAction::NoChange};
    std::string prior_content_hash;
    std::string expected_new_hash;
    std::string staging_artifact;
    std::string recovery_artifact;
    PeerOperationState state{PeerOperationState::Planned};
    std::string error;
    std::int64_t created_at_ms{};
    std::int64_t updated_at_ms{};
};

std::string make_deterministic_operation_id(const std::string& session_id,
                                           const std::string& relative_path,
                                           PeerPlanAction action,
                                           const std::string& expected_new_hash);

struct PeerSessionRecord {
    std::string session_id;
    std::string local_peer;
    std::string remote_peer;
    PeerSessionState state{PeerSessionState::Created};
    std::string local_manifest_root;
    std::string remote_manifest_root;
    std::string baseline_root;
    std::string plan_hash;
    std::string expected_final_root;
    std::string recovery_diagnostic;
    bool plan_requires_approval{false};
    bool plan_requires_deletion_confirmation{false};
    bool approval_recorded{false};
    bool approved{false};
    bool deletion_confirmed{false};
    bool local_prepared{false};
    bool peer_prepared{false};
    bool local_commit_verified{false};
    bool peer_commit_verified{false};
    bool local_rollback_verified{false};
    bool peer_abort_acknowledged{false};
    bool recovery_material_retained{true};
    std::int64_t created_at_ms{};
    std::int64_t updated_at_ms{};
};

struct PeerSessionObservation {
    std::string session_id;
    std::string peer_id;
    PeerObservedState state{PeerObservedState::Unknown};
    std::string plan_hash;
    std::string final_root;
};

// Pure, deterministic recovery advice. It never mutates session state or files.
PeerRecoveryAction evaluate_peer_recovery(const PeerSessionRecord& local,
                                         const PeerSessionObservation& remote);
const char* peer_session_state_name(PeerSessionState state) noexcept;

// Durable local participant journal. Every transition is committed atomically
// in this device's SQLite database. It does not make two devices atomic.
class PeerSessionJournal {
public:
    explicit PeerSessionJournal(const std::string& database_path);
    ~PeerSessionJournal();
    PeerSessionJournal(const PeerSessionJournal&) = delete;
    PeerSessionJournal& operator=(const PeerSessionJournal&) = delete;

    std::string create(const std::string& local_peer, const std::string& remote_peer,
                       const std::string& existing_session_id = "");
    PeerSessionRecord load(const std::string& session_id) const;
    void mark_authenticated(const std::string& session_id,
                            const std::string& authenticated_peer_id);
    void record_manifests(const std::string& session_id,
                          const std::string& local_root,
                          const std::string& remote_root,
                          const std::string& baseline_root);
    void agree_plan(const std::string& session_id,
                    const std::string& local_plan_hash,
                    const std::string& remote_plan_hash,
                    const std::string& expected_final_root,
                    bool approval_required,
                    bool deletion_confirmation_required);
    void begin_approval(const std::string& session_id);
    void record_approval(const std::string& session_id,
                         const std::string& bound_plan_hash,
                         bool approved,
                         bool deletion_confirmed);
    void mark_local_prepared(const std::string& session_id,
                             const std::string& bound_plan_hash);
    void acknowledge_peer_prepared(const std::string& session_id,
                                   const std::string& peer_id,
                                   const std::string& bound_plan_hash);
    void begin_commit(const std::string& session_id,
                      const std::string& bound_plan_hash);
    void mark_local_commit_verified(const std::string& session_id,
                                    const std::string& bound_plan_hash,
                                    const std::string& final_root);
    void acknowledge_peer_commit(const std::string& session_id,
                                 const std::string& peer_id,
                                 const std::string& bound_plan_hash,
                                 const std::string& final_root);
    void mark_recovery_required(const std::string& session_id,
                                const std::string& diagnostic);
    void mark_local_rollback_verified(const std::string& session_id,
                                      const std::string& bound_plan_hash);
    void acknowledge_peer_abort(const std::string& session_id,
                                const std::string& peer_id,
                                const std::string& bound_plan_hash);
    void release_recovery_material(const std::string& session_id);
    std::vector<PeerSessionRecord> list_unfinished_sessions() const;

    // Operation-level transaction journal methods
    void record_operation(const PeerOperationRecord& record);
    std::vector<PeerOperationRecord> load_operations(const std::string& session_id) const;
    PeerOperationRecord load_operation(const std::string& operation_id) const;
    void update_operation(const PeerOperationRecord& record);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct PeerExecutorOptions {
    bool simulate_crash_before_commit{false};
    bool simulate_crash_during_replacement{false};
    bool simulate_crash_after_file_commit{false};
    bool simulate_history_write_failure{false};
    bool simulate_baseline_write_failure{false};
    bool simulate_rollback_failure{false};
    std::string custom_fault_path;
};

struct PeerExecutionResult {
    bool success{false};
    std::string error;
    std::string session_id;
    std::string final_merkle_root;
    std::size_t operations_prepared{0};
    std::size_t operations_committed{0};
    std::size_t operations_rolled_back{0};
    bool baseline_advanced{false};
    bool recovery_material_retained{true};
};

struct PeerReconciliationReport {
    std::string session_id;
    bool reconciled{false};
    bool manual_recovery_required{false};
    std::string diagnostic;
    std::size_t files_restored_from_retiring{0};
    std::size_t files_restored_from_recovery{0};
    std::size_t files_committed_from_staging{0};
    std::size_t lingering_retiring_cleaned{0};
    std::size_t orphaned_staging_cleaned{0};
};

// Integrates bilateral session journal with staging artifacts, verified file commits,
// rollback/recovery artifacts, VersionStore, ActivityStore, and PeerBaselineStore.
class PeerTransactionCoordinator {
public:
    PeerTransactionCoordinator(PeerSessionJournal& journal,
                               const fs::path& sync_root,
                               const fs::path& recovery_root,
                               PeerBaselineStore* baseline_store = nullptr,
                               VersionStore* version_store = nullptr,
                               ActivityStore* activity_store = nullptr);

    std::vector<PeerOperationRecord> plan_operations(const std::string& session_id,
                                                     const PeerSyncPlan& plan,
                                                     bool as_remote_peer = false);

    bool prepare_operations(const std::string& session_id,
                            const std::string& bound_plan_hash,
                            const std::function<void(const PeerOperationRecord&, StagingFile&)>& staging_writer,
                            const PeerExecutorOptions& options = {});

    PeerExecutionResult commit_local(const std::string& session_id,
                                     const std::string& bound_plan_hash,
                                     const PeerExecutorOptions& options = {});

    bool finalize_bilateral_commit(const std::string& session_id,
                                   const std::string& remote_peer,
                                   const std::string& folder_pair_id,
                                   const FileManifest& final_manifest,
                                   const PeerExecutorOptions& options = {});

    bool rollback_operations(const std::string& session_id,
                             const std::string& bound_plan_hash,
                             const PeerExecutorOptions& options = {});

    PeerRecoveryAction reconcile_and_recover(const std::string& session_id,
                                            const PeerSessionObservation& remote,
                                            const PeerExecutorOptions& options = {});

    PeerReconciliationReport reconcile_interrupted_session(const std::string& session_id,
                                                           bool resume_commit = false,
                                                           const PeerExecutorOptions& options = {});

    bool verify_recovery_artifacts(const std::string& session_id) const;

private:
    PeerSessionJournal& journal_;
    fs::path sync_root_;
    fs::path recovery_root_;
    PeerBaselineStore* baseline_store_;
    VersionStore* version_store_;
    ActivityStore* activity_store_;
};

} // namespace mc::peer
