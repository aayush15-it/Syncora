#include "merklechain/peer/peer_sync.hpp"

#include "merklechain/hash.hpp"

#include <algorithm>
#include <fstream>
#include <initializer_list>
#include <limits>

namespace {
using NamedContent = std::pair<std::string, std::string>;

mc::FileManifest manifest(std::initializer_list<NamedContent> entries) {
    mc::FileManifest result;
    for (const auto& [path, content] : entries) {
        mc::FileMetadata file;
        file.relative_path = path;
        file.size = content.size();
        file.modified_ticks = 123456;
        file.sha256 = mc::sha256_data(content.data(), content.size());
        result.files.push_back(std::move(file));
    }
    std::sort(result.files.begin(), result.files.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    result.merkle_root = mc::merkle_root(result.files);
    return result;
}

const mc::peer::PeerPlanEntry* entry(const mc::peer::PeerSyncPlan& plan,
                                     const std::string& path) {
    const auto found = std::find_if(plan.entries.begin(), plan.entries.end(), [&](const auto& item) {
        return item.relative_path == path;
    });
    return found == plan.entries.end() ? nullptr : &*found;
}

} // namespace

void run_peer_sync_tests(const mc::fs::path& fixture_root,
                         void (*check)(bool, const char*)) {
    using namespace mc::peer;
    const auto directory = fixture_root / "peer-plan";
    mc::fs::create_directories(directory);
    const auto sentinel = directory / "untouched.txt";
    { std::ofstream file(sentinel, std::ios::binary); file << "planner does not mutate"; }

    const auto first_local = manifest({{"local-new.txt", "from local"}});
    const auto first_remote = manifest({{"remote-new.txt", "from remote"}});
    const auto no_baseline = PeerBaseline{};
    auto wire_manifest = first_local;
    wire_manifest.files.front().modified_ticks = std::numeric_limits<std::int64_t>::min();
    const auto encoded_manifest = encode_peer_manifest(wire_manifest, 100U, 1024U * 1024U);
    const auto decoded_manifest = decode_peer_manifest(encoded_manifest, 100U, 1024U * 1024U);
    check(decoded_manifest.complete && decoded_manifest.merkle_root == wire_manifest.merkle_root &&
          decoded_manifest.files.size() == 1U &&
          decoded_manifest.files.front().relative_path == wire_manifest.files.front().relative_path &&
          decoded_manifest.files.front().sha256 == wire_manifest.files.front().sha256 &&
          decoded_manifest.files.front().modified_ticks == wire_manifest.files.front().modified_ticks,
          "bounded peer manifest codec round-trips content, root, and signed timestamp bits");
    auto truncated_manifest = encoded_manifest;
    truncated_manifest.pop_back();
    auto trailing_manifest = encoded_manifest;
    trailing_manifest.push_back('\0');
    bool malformed_rejected = false;
    try { (void)decode_peer_manifest(truncated_manifest, 100U, 1024U * 1024U); }
    catch (...) { malformed_rejected = true; }
    bool trailing_rejected = false;
    try { (void)decode_peer_manifest(trailing_manifest, 100U, 1024U * 1024U); }
    catch (...) { trailing_rejected = true; }
    check(malformed_rejected && trailing_rejected,
          "peer manifest codec rejects truncated and trailing wire data");
    auto escaped_manifest = encoded_manifest;
    escaped_manifest[44] = '.';
    escaped_manifest[45] = '.';
    escaped_manifest[46] = '/';
    bool escape_rejected = false;
    try { (void)decode_peer_manifest(escaped_manifest, 100U, 1024U * 1024U); }
    catch (...) { escape_rejected = true; }
    bool size_limit_rejected = false;
    try { (void)encode_peer_manifest(first_local, 100U, 1U); }
    catch (...) { size_limit_rejected = true; }
    auto invalid_utf8_manifest = encoded_manifest;
    invalid_utf8_manifest[44] = static_cast<char>(0xffU);
    bool invalid_utf8_rejected = false;
    try { (void)decode_peer_manifest(invalid_utf8_manifest, 100U, 1024U * 1024U); }
    catch (...) { invalid_utf8_rejected = true; }
    auto trailing_separator_manifest = encoded_manifest;
    trailing_separator_manifest[43U + wire_manifest.files.front().relative_path.size()] = '/';
    bool trailing_separator_rejected = false;
    try { (void)decode_peer_manifest(trailing_separator_manifest, 100U, 1024U * 1024U); }
    catch (...) { trailing_separator_rejected = true; }
    check(escape_rejected && size_limit_rejected && invalid_utf8_rejected && trailing_separator_rejected,
          "peer manifest codec rejects traversal, invalid UTF-8, non-file paths, and configured size excess");
    const auto first_plan = plan_bidirectional("device-a", "folders-1", no_baseline,
                                               first_local, first_remote);
    const auto* local_add = entry(first_plan, "local-new.txt");
    const auto* remote_add = entry(first_plan, "remote-new.txt");
    check(first_plan.valid && local_add && local_add->action == PeerPlanAction::AddRemote &&
          remote_add && remote_add->action == PeerPlanAction::AddLocal &&
          !first_plan.has_unresolved_conflicts,
          "first peer scan plans additions in both directions without inferring deletions");

    const auto base_manifest = manifest({
        {"edit-local.txt", "base"}, {"edit-remote.txt", "base"},
        {"delete-local.txt", "base"}, {"delete-remote.txt", "base"},
        {"concurrent.txt", "base"}, {"local-delete-remote-edit.txt", "base"},
        {"remote-delete-local-edit.txt", "base"}, {"independent-local.txt", "base"},
        {"independent-remote.txt", "base"}});
    PeerBaseline baseline;
    baseline.exists = true;
    baseline.peer_id = "device-a";
    baseline.folder_pair_id = "folders-1";
    baseline.merkle_root = base_manifest.merkle_root;
    baseline.files = base_manifest.files;
    const auto local_now = manifest({
        {"edit-local.txt", "local edit"}, {"edit-remote.txt", "base"},
        {"delete-remote.txt", "base"}, {"concurrent.txt", "local concurrent"},
        {"remote-delete-local-edit.txt", "local edit"},
        {"independent-local.txt", "local independent"}, {"independent-remote.txt", "base"}});
    const auto remote_now = manifest({
        {"edit-local.txt", "base"}, {"edit-remote.txt", "remote edit"},
        {"delete-local.txt", "base"}, {"concurrent.txt", "remote concurrent"},
        {"local-delete-remote-edit.txt", "remote edit"},
        {"independent-local.txt", "base"}, {"independent-remote.txt", "remote independent"}});
    auto plan = plan_bidirectional("device-a", "folders-1", baseline, local_now, remote_now);
    const auto* edited_from_local = entry(plan, "edit-local.txt");
    const auto* edited_from_remote = entry(plan, "edit-remote.txt");
    const auto* deleted_local = entry(plan, "delete-local.txt");
    const auto* deleted_remote = entry(plan, "delete-remote.txt");
    const auto* concurrent = entry(plan, "concurrent.txt");
    const auto* local_delete_conflict = entry(plan, "local-delete-remote-edit.txt");
    const auto* remote_delete_conflict = entry(plan, "remote-delete-local-edit.txt");
    const auto* independent_local = entry(plan, "independent-local.txt");
    const auto* independent_remote = entry(plan, "independent-remote.txt");
    check(plan.valid && edited_from_local && edited_from_local->action == PeerPlanAction::UpdateRemote &&
          edited_from_remote && edited_from_remote->action == PeerPlanAction::UpdateLocal &&
          independent_local && independent_local->action == PeerPlanAction::UpdateRemote &&
          independent_remote && independent_remote->action == PeerPlanAction::UpdateLocal,
          "baseline comparison propagates local, remote, and independent edits in both directions");
    check(deleted_local && deleted_local->action == PeerPlanAction::DeleteRemote &&
          deleted_remote && deleted_remote->action == PeerPlanAction::DeleteLocal &&
          deleted_local->deletion_confirmation_required && deleted_remote->deletion_confirmation_required,
          "baseline comparison detects deletions only when the opposite side still matches baseline");
    check(concurrent && concurrent->action == PeerPlanAction::Conflict &&
          concurrent->conflict == PeerConflictKind::ConcurrentModification &&
          local_delete_conflict && local_delete_conflict->conflict == PeerConflictKind::LocalDeletionRemoteModification &&
          remote_delete_conflict && remote_delete_conflict->conflict == PeerConflictKind::RemoteDeletionLocalModification &&
          plan.has_unresolved_conflicts,
          "planner detects concurrent edits and both delete-versus-modify conflict directions");
    check(plan_bidirectional("device-a", "folders-1", baseline, local_now, remote_now).plan_hash == plan.plan_hash,
          "peer plan ordering and SHA-256 digest are deterministic for identical inputs");

    auto incomplete = remote_now;
    incomplete.complete = false;
    const auto blocked = plan_bidirectional("device-a", "folders-1", baseline, local_now, incomplete);
    check(!blocked.valid && blocked.entries.empty() && blocked.plan_hash.empty(),
          "incomplete local or remote scans cannot produce deletion-capable plans");

    const auto divergent_local = manifest({{"same-name.txt", "A version"}});
    const auto divergent_remote = manifest({{"same-name.txt", "B version"}});
    const auto first_conflict = plan_bidirectional("device-a", "folders-1", no_baseline,
                                                   divergent_local, divergent_remote);
    const auto* initial_divergence = entry(first_conflict, "same-name.txt");
    check(initial_divergence && initial_divergence->action == PeerPlanAction::Conflict &&
          initial_divergence->conflict == PeerConflictKind::InitialDivergence &&
          !peer_plan_is_authorized(first_conflict, first_conflict.plan_hash, true, true),
          "different same-path contents on first sync remain intact and require explicit conflict resolution");

    const auto resolution_base_manifest = manifest({{"conflict.txt", "shared base"}});
    PeerBaseline resolution_base{true, "device-a", "folders-1", resolution_base_manifest.merkle_root,
                                 1, resolution_base_manifest.files};
    auto resolution_plan = plan_bidirectional("device-a", "folders-1", resolution_base,
        manifest({{"conflict.txt", "local version"}}),
        manifest({{"conflict.txt", "remote version"}}));
    const auto pre_resolution_hash = resolution_plan.plan_hash;
    const bool selected = resolve_peer_conflict(resolution_plan, "conflict.txt",
                                                PeerConflictResolution::KeepLocal);
    check(selected && !resolution_plan.has_unresolved_conflicts &&
          entry(resolution_plan, "conflict.txt")->action == PeerPlanAction::UpdateRemote &&
          resolution_plan.plan_hash != pre_resolution_hash &&
          !peer_plan_is_authorized(resolution_plan, pre_resolution_hash, true, true) &&
          !peer_plan_is_authorized(resolution_plan, resolution_plan.plan_hash, false, true) &&
          peer_plan_is_authorized(resolution_plan, resolution_plan.plan_hash, true, true),
          "explicit conflict resolution changes the plan digest and requires approval bound to the revised plan");

    const auto delete_base_manifest = manifest({{"remove.txt", "baseline"}});
    PeerBaseline delete_base{true, "device-a", "folders-1", delete_base_manifest.merkle_root,
                             2, delete_base_manifest.files};
    const auto deletion_plan = plan_bidirectional("device-a", "folders-1", delete_base,
        manifest({}), delete_base_manifest);
    check(deletion_plan.valid && deletion_plan.requires_approval &&
          deletion_plan.requires_deletion_confirmation &&
          !peer_plan_is_authorized(deletion_plan, deletion_plan.plan_hash, true, false) &&
          peer_plan_is_authorized(deletion_plan, deletion_plan.plan_hash, true, true),
          "deletion authorization requires change approval and separate deletion confirmation");

    auto tampered = first_plan;
    const auto original_hash = tampered.plan_hash;
    tampered.entries.front().relative_path += ".tampered";
    check(!peer_plan_is_authorized(tampered, original_hash, true, true),
          "approval validation recomputes the plan digest and rejects modified plan contents");
    auto tampered_approval = first_plan;
    tampered_approval.requires_approval = false;
    auto tampered_delete_gate = deletion_plan;
    tampered_delete_gate.requires_deletion_confirmation = false;
    auto tampered_conflict_gate = first_conflict;
    tampered_conflict_gate.has_unresolved_conflicts = false;
    check(!peer_plan_is_authorized(tampered_approval, first_plan.plan_hash, false, true) &&
          !peer_plan_is_authorized(tampered_delete_gate, deletion_plan.plan_hash, true, false) &&
          !peer_plan_is_authorized(tampered_conflict_gate, first_conflict.plan_hash, true, true),
          "approval digest binds aggregate approval, deletion, and unresolved-conflict gates");

    auto duplicate_case = manifest({{"Case.txt", "one"}, {"case.txt", "two"}});
    const auto duplicate_plan = plan_bidirectional("device-a", "folders-1", no_baseline,
                                                  duplicate_case, manifest({}));
    check(!duplicate_plan.valid, "manifest rejects case-insensitive duplicate paths before planning");
    check(mc::fs::exists(sentinel) && mc::sha256_file(sentinel) == mc::sha256_data("planner does not mutate", 23),
          "bidirectional planning leaves disposable filesystem contents unchanged");

    const auto baseline_db = directory / "peer-baselines.sqlite3";
    {
        PeerBaselineStore store(baseline_db);
        store.commit_reconciled_manifest("device-a", "folders-1", base_manifest);
        bool incomplete_rejected = false;
        auto incomplete_manifest = base_manifest;
        incomplete_manifest.complete = false;
        try { store.commit_reconciled_manifest("device-a", "folders-2", incomplete_manifest); }
        catch (...) { incomplete_rejected = true; }
        check(incomplete_rejected, "incomplete reconciliation cannot advance the persistent peer baseline");
    }
    {
        PeerBaselineStore reopened(baseline_db);
        const auto loaded = reopened.load("device-a", "folders-1");
        const auto isolated = reopened.load("device-a", "folders-2");
        check(loaded.exists && loaded.merkle_root == base_manifest.merkle_root &&
              loaded.files.size() == base_manifest.files.size() && !isolated.exists,
              "SQLite peer baseline survives close/reopen and is isolated by peer and folder pair");
    }
}
