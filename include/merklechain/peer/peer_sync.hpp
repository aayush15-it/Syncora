#pragma once

#include "merklechain/types.hpp"

#include <optional>
#include <string>
#include <vector>

namespace mc::peer {

enum class PeerPlanAction {
    NoChange,
    AddLocal,
    UpdateLocal,
    DeleteLocal,
    AddRemote,
    UpdateRemote,
    DeleteRemote,
    PreserveBoth,
    Conflict
};

enum class PeerConflictKind {
    None,
    InitialDivergence,
    ConcurrentAddition,
    ConcurrentModification,
    LocalDeletionRemoteModification,
    RemoteDeletionLocalModification
};

enum class PeerConflictResolution { Unresolved, KeepLocal, KeepRemote, PreserveBoth };

struct PeerBaseline {
    bool exists{false};
    std::string peer_id;
    std::string folder_pair_id;
    std::string merkle_root;
    std::int64_t committed_at_ms{};
    std::vector<FileMetadata> files;
};

struct PeerPlanEntry {
    std::string relative_path;
    PeerPlanAction action{PeerPlanAction::NoChange};
    PeerConflictKind conflict{PeerConflictKind::None};
    PeerConflictResolution resolution{PeerConflictResolution::Unresolved};
    std::optional<FileMetadata> baseline;
    std::optional<FileMetadata> local;
    std::optional<FileMetadata> remote;
    bool approval_required{false};
    bool deletion_confirmation_required{false};
    bool resolution_required{false};
};

struct PeerSyncPlan {
    bool valid{false};
    std::string error;
    std::string peer_id;
    std::string folder_pair_id;
    std::string baseline_root;
    std::string local_root;
    std::string remote_root;
    std::string plan_hash;
    bool requires_approval{false};
    bool requires_deletion_confirmation{false};
    bool has_unresolved_conflicts{false};
    std::vector<PeerPlanEntry> entries;
};

// The store advances only when the caller explicitly commits a fully
// reconciled manifest after all transfer/verification work has succeeded.
// Planning never writes or deletes files and never advances this baseline.
class PeerBaselineStore {
public:
    explicit PeerBaselineStore(const fs::path& database_file);
    ~PeerBaselineStore();
    PeerBaselineStore(const PeerBaselineStore&) = delete;
    PeerBaselineStore& operator=(const PeerBaselineStore&) = delete;

    PeerBaseline load(const std::string& peer_id,
                      const std::string& folder_pair_id) const;
    void commit_reconciled_manifest(const std::string& peer_id,
                                    const std::string& folder_pair_id,
                                    const FileManifest& manifest);

private:
    struct Impl;
    Impl* impl_{};
};

PeerSyncPlan plan_bidirectional(const std::string& peer_id,
                                const std::string& folder_pair_id,
                                const PeerBaseline& baseline,
                                const FileManifest& local,
                                const FileManifest& remote);

// Bounded binary manifest wire codec. The encoded value must fit one protocol
// frame; larger manifests fail closed until paged manifest exchange is added.
std::string encode_peer_manifest(const FileManifest& manifest,
                                 std::uint32_t max_files,
                                 std::uint64_t max_file_size_bytes);
FileManifest decode_peer_manifest(const std::string& payload,
                                  std::uint32_t max_files,
                                  std::uint64_t max_file_size_bytes);

// Approvals bind to the entire deterministic plan digest. Conflicts block
// authorization until resolve_peer_conflict explicitly resolves each entry.
bool resolve_peer_conflict(PeerSyncPlan& plan, const std::string& relative_path,
                           PeerConflictResolution resolution);
bool peer_plan_is_authorized(const PeerSyncPlan& plan,
                            const std::string& approved_plan_hash,
                            bool approved,
                            bool deletion_confirmed);

const char* peer_plan_action_name(PeerPlanAction action) noexcept;
const char* peer_conflict_name(PeerConflictKind conflict) noexcept;

} // namespace mc::peer
