#include "merklechain/peer/peer_session.hpp"
#include "merklechain/peer/peer_sync.hpp"
#include "merklechain/staging_file.hpp"
#include "merklechain/storage.hpp"
#include "merklechain/versioning.hpp"
#include "merklechain/scanner.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/types.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <stdexcept>

namespace {
using namespace mc::peer;
constexpr const char* local_root = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr const char* remote_root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr const char* plan_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr const char* result_root = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
constexpr const char* base_root = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

template<class Function>
bool throws(Function function) {
    try { function(); }
    catch (...) { return true; }
    return false;
}

std::string prepare_for_approval(PeerSessionJournal& journal, bool deletion_confirmation_required = false) {
    const auto id = journal.create("laptop_a", "laptop_b");
    journal.mark_authenticated(id, "laptop_b");
    journal.record_manifests(id, local_root, remote_root, base_root);
    journal.agree_plan(id, plan_hash, plan_hash, result_root, true, deletion_confirmation_required);
    journal.begin_approval(id);
    return id;
}

std::string prepare_for_commit(PeerSessionJournal& journal) {
    const auto id = prepare_for_approval(journal);
    journal.record_approval(id, plan_hash, true, false);
    journal.mark_local_prepared(id, plan_hash);
    journal.acknowledge_peer_prepared(id, "laptop_b", plan_hash);
    journal.begin_commit(id, plan_hash);
    return id;
}
} // namespace

void run_peer_session_tests(const mc::fs::path& fixture_root,
                            void (*check)(bool, const char*)) {
    const auto directory = fixture_root / "peer-session";
    mc::fs::create_directories(directory);
    const auto database = directory / "sessions.sqlite3";
    std::string lost_ack_id;
    std::string partial_prepare_id;
    std::string abort_id;
    {
        PeerSessionJournal journal(database.string());
        const auto id = prepare_for_approval(journal);
        auto created = journal.load(id);
        check(id.size() == 32U && created.state == PeerSessionState::ApprovalPending &&
              created.recovery_material_retained,
              "peer session gets a durable unique ID and retains recovery material from creation");
        PeerSessionObservation peer_prepared_without_approval{id, "laptop_b", PeerObservedState::Prepared,
                                                              plan_hash, result_root};
        check(throws([&] { journal.begin_commit(id, plan_hash); }) &&
              throws([&] { journal.mark_authenticated(id, "impostor"); }) &&
              throws([&] { journal.record_approval(id, std::string(64, 'f'), true, false); }) &&
              evaluate_peer_recovery(created, peer_prepared_without_approval) == PeerRecoveryAction::ManualRecovery,
              "peer journal rejects out-of-order, wrong-identity, and stale-plan messages");
        check(throws([&] { journal.agree_plan(id, plan_hash, std::string(64, 'f'), result_root, true, false); }) &&
              journal.load(id).state == PeerSessionState::ApprovalPending,
              "plan disagreement is rejected without advancing the session");
        journal.record_approval(id, plan_hash, true, false);
        journal.record_approval(id, plan_hash, true, false);
        journal.mark_local_prepared(id, plan_hash);
        journal.mark_local_prepared(id, plan_hash);
        journal.acknowledge_peer_prepared(id, "laptop_b", plan_hash);
        journal.acknowledge_peer_prepared(id, "laptop_b", plan_hash);
        check(journal.load(id).state == PeerSessionState::Prepared,
              "duplicate approval and prepare messages are idempotent and both prepare acknowledgments are required");
        journal.begin_commit(id, plan_hash);
        journal.begin_commit(id, plan_hash);
        check(throws([&] { journal.release_recovery_material(id); }),
              "recovery material cannot be released before a terminal bilateral state");
        check(throws([&] { journal.mark_local_commit_verified(id, plan_hash, local_root); }) &&
              journal.load(id).state == PeerSessionState::CommitPending,
              "failed final-root verification leaves commit pending and uncommitted");
        journal.mark_local_commit_verified(id, plan_hash, result_root);
        check(journal.load(id).state == PeerSessionState::CommitPending,
              "one local commit does not mark the bilateral session committed");
        lost_ack_id = id;

        const auto delete_id = prepare_for_approval(journal, true);
        bool deletion_confirmation_required = throws([&] {
            journal.record_approval(delete_id, plan_hash, true, false);
        });
        check(deletion_confirmation_required && journal.load(delete_id).state == PeerSessionState::ApprovalPending,
              "deletion preparation requires explicit confirmation bound to the agreed plan");

        const auto rejected_id = prepare_for_approval(journal);
        journal.record_approval(rejected_id, plan_hash, false, false);
        journal.record_approval(rejected_id, plan_hash, false, false);
        const auto rejected = journal.load(rejected_id);
        PeerSessionObservation unexpected_prepared{rejected_id, "laptop_b", PeerObservedState::Prepared,
                                                     plan_hash, result_root};
        PeerSessionObservation contradictory_abort{rejected_id, "laptop_b", PeerObservedState::Aborted,
                                                     std::string(64, 'f'), {}};
        check(rejected.state == PeerSessionState::Aborted && !rejected.local_prepared &&
              evaluate_peer_recovery(rejected, unexpected_prepared) == PeerRecoveryAction::ManualRecovery &&
              evaluate_peer_recovery(rejected, contradictory_abort) == PeerRecoveryAction::ManualRecovery,
              "rejected approval is an idempotent safe abort before mutation");

        partial_prepare_id = prepare_for_approval(journal);
        journal.record_approval(partial_prepare_id, plan_hash, true, false);
        journal.mark_local_prepared(partial_prepare_id, plan_hash);
        auto partial = journal.load(partial_prepare_id);
        PeerSessionObservation remote_created{partial_prepare_id, "laptop_b", PeerObservedState::Created, plan_hash, {}};
        PeerSessionObservation remote_prepared{partial_prepare_id, "laptop_b", PeerObservedState::Prepared,
                                                plan_hash, result_root};
        check(evaluate_peer_recovery(partial, remote_created) == PeerRecoveryAction::WaitForPeer &&
              evaluate_peer_recovery(partial, remote_prepared) == PeerRecoveryAction::ResumeCommit,
              "partial preparation has deterministic wait or resume advice without claiming synchronization");
        journal.mark_recovery_required(partial_prepare_id, "interrupted after local prepare");

        abort_id = prepare_for_commit(journal);
        journal.mark_recovery_required(abort_id, "both peers prepared; commit was not started");
        auto abort_record = journal.load(abort_id);
        PeerSessionObservation remote_aborted{abort_id, "laptop_b", PeerObservedState::Aborted, plan_hash, {}};
        check(evaluate_peer_recovery(abort_record, remote_aborted) == PeerRecoveryAction::AbortUncommitted,
              "uncommitted transaction reconciles toward rollback only after peer abort status");
    }

    {
        PeerSessionJournal restarted(database.string());
        auto partial = restarted.load(partial_prepare_id);
        check(partial.state == PeerSessionState::RecoveryRequired && partial.local_prepared &&
              partial.recovery_material_retained &&
              partial.recovery_diagnostic == "interrupted after local prepare",
              "session restart reloads partial preparation and preserves its recovery diagnostic");
        PeerSessionObservation stale{partial_prepare_id, "laptop_b", PeerObservedState::Prepared,
                                     std::string(64, 'f'), result_root};
        PeerSessionObservation missing{partial_prepare_id, "laptop_b", PeerObservedState::Unknown, {}, {}};
        check(evaluate_peer_recovery(partial, stale) == PeerRecoveryAction::ManualRecovery &&
              evaluate_peer_recovery(partial, missing) == PeerRecoveryAction::WaitForPeer,
              "recovery rejects a stale peer plan and waits rather than inferring from disconnect");
        restarted.acknowledge_peer_prepared(partial_prepare_id, "laptop_b", plan_hash);
        restarted.begin_commit(partial_prepare_id, plan_hash);
        restarted.mark_local_commit_verified(partial_prepare_id, plan_hash, result_root);

        const auto lost = restarted.load(lost_ack_id);
        PeerSessionObservation remote_pending{lost_ack_id, "laptop_b", PeerObservedState::CommitPending,
                                              plan_hash, result_root};
        PeerSessionObservation remote_missing{lost_ack_id, "laptop_b", PeerObservedState::Unknown, {}, {}};
        PeerSessionObservation remote_wrong_root{lost_ack_id, "laptop_b", PeerObservedState::Committed,
                                                 plan_hash, local_root};
        check(evaluate_peer_recovery(lost, remote_pending) == PeerRecoveryAction::ResumeCommit &&
              evaluate_peer_recovery(lost, remote_missing) == PeerRecoveryAction::WaitForPeer &&
              evaluate_peer_recovery(lost, remote_wrong_root) == PeerRecoveryAction::ManualRecovery,
              "lost commit acknowledgment resumes or waits, while contradictory roots require manual recovery");
        restarted.acknowledge_peer_commit(lost_ack_id, "laptop_b", plan_hash, result_root);
        restarted.acknowledge_peer_commit(lost_ack_id, "laptop_b", plan_hash, result_root);
        check(restarted.load(lost_ack_id).state == PeerSessionState::Committed,
              "matching peer commit acknowledgment makes the recovered session terminal idempotently");
        restarted.release_recovery_material(lost_ack_id);
        restarted.release_recovery_material(lost_ack_id);
        check(!restarted.load(lost_ack_id).recovery_material_retained,
              "recovery material is released only after both verified commits");

        restarted.mark_local_rollback_verified(abort_id, plan_hash);
        restarted.acknowledge_peer_abort(abort_id, "laptop_b", plan_hash);
        restarted.acknowledge_peer_abort(abort_id, "laptop_b", plan_hash);
        check(restarted.load(abort_id).state == PeerSessionState::Aborted,
              "rollback becomes aborted only after verified local rollback and peer abort acknowledgment");
        restarted.release_recovery_material(abort_id);

        auto contradictory = restarted.load(partial_prepare_id);
        PeerSessionObservation abort_after_commit{partial_prepare_id, "laptop_b", PeerObservedState::Aborted,
                                                   plan_hash, {}};
        check(evaluate_peer_recovery(contradictory, abort_after_commit) == PeerRecoveryAction::ManualRecovery &&
              throws([&] { restarted.mark_local_rollback_verified(partial_prepare_id, plan_hash); }),
              "one-sided commit cannot be rolled back based on a contradictory peer abort");
    }

    bool stale_conflict_rejected = false;
    {
        PeerSessionJournal reopened(database.string());
        stale_conflict_rejected = throws([&] {
            reopened.acknowledge_peer_commit(lost_ack_id, "laptop_b", std::string(64, 'f'), result_root);
        });
    }
    check(stale_conflict_rejected,
          "database reopen preserves the committed plan binding against stale acknowledgment replay");

    // Stage 5 Coordinator tests
    const auto coord_root = fixture_root / "peer-coordinator";
    mc::fs::remove_all(coord_root);
    mc::fs::create_directories(coord_root);

    const auto write_file = [](const mc::fs::path& p, const std::string& s) {
        mc::fs::create_directories(p.parent_path());
        std::ofstream f(p, std::ios::binary);
        f << s;
    };

    const auto read_file = [](const mc::fs::path& p) {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };

    const auto make_manifest = [](std::initializer_list<std::pair<std::string, std::string>> entries) {
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
    };

    // --- Scenario A: End-to-end plan, prepare, existing-preservation, commit, post-hash verify, idempotent retry, and baseline advancement ---
    const auto case_a = coord_root / "case_a";
    const auto sync_a = case_a / "sync";
    const auto recovery_a = case_a / "recovery";
    const auto state_a = case_a / ".merklechain";
    const auto db_a = case_a / "session.sqlite3";
    const auto baseline_db_a = case_a / "baseline.sqlite3";
    const auto activity_db_a = case_a / "activity.sqlite3";

    mc::fs::create_directories(sync_a);
    mc::fs::create_directories(recovery_a);
    mc::fs::create_directories(state_a);

    write_file(sync_a / "keep.txt", "keep content v1");
    write_file(sync_a / "update_me.txt", "old content v1");
    write_file(sync_a / "delete_me.txt", "to be deleted v1");

    auto local_manifest_a = make_manifest({
        {"delete_me.txt", "to be deleted v1"},
        {"keep.txt", "keep content v1"},
        {"update_me.txt", "old content v1"}
    });

    PeerBaseline baseline_a;
    baseline_a.exists = true;
    baseline_a.peer_id = "laptop_b";
    baseline_a.folder_pair_id = "pair-1";
    baseline_a.merkle_root = local_manifest_a.merkle_root;
    baseline_a.files = local_manifest_a.files;

    auto remote_manifest_a = make_manifest({
        {"add_me.txt", "newly added content v1"},
        {"keep.txt", "keep content v1"},
        {"update_me.txt", "updated content v2"}
    });

    auto expected_final_manifest_a = remote_manifest_a;

    auto plan_a = plan_bidirectional("laptop_b", "pair-1", baseline_a, local_manifest_a, remote_manifest_a);
    check(plan_a.valid && !plan_a.has_unresolved_conflicts && plan_a.entries.size() == 4,
          "coordinator planning produces valid plan for mixed Add/Update/Delete/Preserve");

    std::string session_a;
    {
        PeerSessionJournal journal(db_a.string());
        session_a = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_a, "laptop_b");
        journal.record_manifests(session_a, local_manifest_a.merkle_root, remote_manifest_a.merkle_root, baseline_a.merkle_root);
        journal.agree_plan(session_a, plan_a.plan_hash, plan_a.plan_hash, expected_final_manifest_a.merkle_root, true, true);
        journal.begin_approval(session_a);
        journal.record_approval(session_a, plan_a.plan_hash, true, true);

        PeerBaselineStore baseline_store(baseline_db_a);
        mc::VersionStore version_store(activity_db_a, state_a);
        mc::ActivityStore activity_store(activity_db_a);
        PeerTransactionCoordinator coordinator(journal, sync_a, recovery_a, &baseline_store, &version_store, &activity_store);

        auto ops = coordinator.plan_operations(session_a, plan_a);
        check(ops.size() == 3, "coordinator plans only local mutations (AddLocal, UpdateLocal, DeleteLocal)");

        bool deterministic_ids = true;
        for (const auto& op : ops) {
            auto expected_id = make_deterministic_operation_id(session_a, op.relative_path, op.action, op.expected_new_hash);
            if (op.operation_id != expected_id || op.state != PeerOperationState::Planned) {
                deterministic_ids = false;
            }
        }
        check(deterministic_ids, "operation records have deterministic IDs and initial Planned state");

        check(mc::sha256_file(sync_a / "keep.txt") == mc::sha256_data("keep content v1", 15) &&
              mc::sha256_file(sync_a / "update_me.txt") == mc::sha256_data("old content v1", 14) &&
              mc::sha256_file(sync_a / "delete_me.txt") == mc::sha256_data("to be deleted v1", 16),
              "existing destinations remain intact on disk during planning");

        auto writer = [](const PeerOperationRecord& op, mc::StagingFile& staging) {
            if (op.relative_path == "add_me.txt") staging.write("newly added content v1", 22);
            else if (op.relative_path == "update_me.txt") staging.write("updated content v2", 18);
        };

        bool prep_ok = coordinator.prepare_operations(session_a, plan_a.plan_hash, writer);
        check(prep_ok && coordinator.verify_recovery_artifacts(session_a),
              "preparation creates kept staging files and verified recovery artifacts before mutation");

        check(mc::sha256_file(sync_a / "update_me.txt") == mc::sha256_data("old content v1", 14) &&
              mc::sha256_file(sync_a / "delete_me.txt") == mc::sha256_data("to be deleted v1", 16),
              "existing destination files remain unmodified prior to commit boundary");

        check(!coordinator.commit_local(session_a, plan_a.plan_hash).success,
              "commit is blocked before bilateral preparation is acknowledged");

        journal.acknowledge_peer_prepared(session_a, "laptop_b", plan_a.plan_hash);
        journal.begin_commit(session_a, plan_a.plan_hash);

        check(!coordinator.finalize_bilateral_commit(session_a, "laptop_b", "pair-1", expected_final_manifest_a),
              "baseline cannot advance while operations are uncommitted or unfinalized");

        auto commit_res = coordinator.commit_local(session_a, plan_a.plan_hash);
        check(commit_res.success && commit_res.operations_committed == 3,
              "commit replaces destinations atomically and verifies all post-commit content hashes");

        auto actual_manifest = mc::scan_folder(sync_a);
        check(actual_manifest.merkle_root == expected_final_manifest_a.merkle_root &&
              mc::fs::exists(sync_a / "keep.txt") &&
              !mc::fs::exists(sync_a / "delete_me.txt") &&
              mc::sha256_file(sync_a / "add_me.txt") == mc::sha256_data("newly added content v1", 22) &&
              mc::sha256_file(sync_a / "update_me.txt") == mc::sha256_data("updated content v2", 18),
              "post-commit destination directory matches expected final Merkle root and preserves untouched files");

        auto dup_commit = coordinator.commit_local(session_a, plan_a.plan_hash);
        check(dup_commit.success, "duplicate commit request is idempotent and succeeds without re-mutation");

        check(!coordinator.finalize_bilateral_commit(session_a, "laptop_b", "pair-1", expected_final_manifest_a),
              "baseline store does not advance while peer commit acknowledgment is pending");

        journal.acknowledge_peer_commit(session_a, "laptop_b", plan_a.plan_hash, expected_final_manifest_a.merkle_root);
        PeerExecutorOptions baseline_fail_opts;
        baseline_fail_opts.simulate_baseline_write_failure = true;
        check(throws([&] { coordinator.finalize_bilateral_commit(session_a, "laptop_b", "pair-1", expected_final_manifest_a, baseline_fail_opts); }),
              "simulated baseline store write failure prevents premature finalization");

        bool final_ok = coordinator.finalize_bilateral_commit(session_a, "laptop_b", "pair-1", expected_final_manifest_a);
        auto loaded_baseline = baseline_store.load("laptop_b", "pair-1");
        check(final_ok && loaded_baseline.exists && loaded_baseline.merkle_root == expected_final_manifest_a.merkle_root &&
              !journal.load(session_a).recovery_material_retained,
              "successful bilateral finalization advances peer baseline store and safely releases recovery material");
    }

    // --- Scenario B: Crash/restart before commit and resume prepare ---
    const auto case_b = coord_root / "case_b";
    const auto sync_b = case_b / "sync";
    const auto recovery_b = case_b / "recovery";
    const auto db_b = case_b / "session.sqlite3";
    write_file(sync_b / "target.txt", "target v1");

    auto local_b = make_manifest({{"target.txt", "target v1"}});
    PeerBaseline baseline_b;
    baseline_b.exists = true;
    baseline_b.peer_id = "laptop_b";
    baseline_b.folder_pair_id = "pair-b";
    baseline_b.merkle_root = local_b.merkle_root;
    baseline_b.files = local_b.files;
    auto remote_b = make_manifest({{"target.txt", "target v2"}});
    auto plan_b = plan_bidirectional("laptop_b", "pair-b", baseline_b, local_b, remote_b);

    std::string session_b;
    {
        PeerSessionJournal journal(db_b.string());
        session_b = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_b, "laptop_b");
        journal.record_manifests(session_b, local_b.merkle_root, remote_b.merkle_root, baseline_b.merkle_root);
        journal.agree_plan(session_b, plan_b.plan_hash, plan_b.plan_hash, remote_b.merkle_root, true, false);
        journal.begin_approval(session_b);
        journal.record_approval(session_b, plan_b.plan_hash, true, false);

        PeerTransactionCoordinator coordinator(journal, sync_b, recovery_b);
        coordinator.plan_operations(session_b, plan_b);

        PeerExecutorOptions crash_prep_opts;
        crash_prep_opts.simulate_crash_before_commit = true;
        auto writer_b = [](const PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("target v2", 9);
        };
        check(throws([&] { coordinator.prepare_operations(session_b, plan_b.plan_hash, writer_b, crash_prep_opts); }),
              "simulated crash during preparation stops before commit");
        check(journal.load(session_b).state == PeerSessionState::RecoveryRequired,
              "interrupted preparation records RecoveryRequired in journal");
    }
    {
        PeerSessionJournal restarted_journal(db_b.string());
        PeerTransactionCoordinator restarted_coordinator(restarted_journal, sync_b, recovery_b);
        auto writer_b = [](const PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("target v2", 9);
        };
        bool resumed_prep = restarted_coordinator.prepare_operations(session_b, plan_b.plan_hash, writer_b);
        check(resumed_prep && restarted_journal.load(session_b).local_prepared,
              "resuming preparation after restart successfully prepares operations and marks local_prepared");
    }

    // --- Scenario C: Interrupted replacement and rollback recovery ---
    const auto case_c = coord_root / "case_c";
    const auto sync_c = case_c / "sync";
    const auto recovery_c = case_c / "recovery";
    const auto db_c = case_c / "session.sqlite3";
    write_file(sync_c / "file.txt", "precious data");

    auto local_c = make_manifest({{"file.txt", "precious data"}});
    PeerBaseline baseline_c;
    baseline_c.exists = true;
    baseline_c.peer_id = "laptop_b";
    baseline_c.folder_pair_id = "pair-c";
    baseline_c.merkle_root = local_c.merkle_root;
    baseline_c.files = local_c.files;
    auto remote_c = make_manifest({{"file.txt", "new bad data"}});
    auto plan_c = plan_bidirectional("laptop_b", "pair-c", baseline_c, local_c, remote_c);

    std::string session_c;
    {
        PeerSessionJournal journal(db_c.string());
        session_c = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_c, "laptop_b");
        journal.record_manifests(session_c, local_c.merkle_root, remote_c.merkle_root, baseline_c.merkle_root);
        journal.agree_plan(session_c, plan_c.plan_hash, plan_c.plan_hash, remote_c.merkle_root, true, false);
        journal.begin_approval(session_c);
        journal.record_approval(session_c, plan_c.plan_hash, true, false);

        PeerTransactionCoordinator coordinator(journal, sync_c, recovery_c);
        coordinator.plan_operations(session_c, plan_c);
        auto writer_c = [](const PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("new bad data", 12);
        };
        coordinator.prepare_operations(session_c, plan_c.plan_hash, writer_c);
        journal.acknowledge_peer_prepared(session_c, "laptop_b", plan_c.plan_hash);
        journal.begin_commit(session_c, plan_c.plan_hash);

        PeerExecutorOptions crash_replace_opts;
        crash_replace_opts.simulate_crash_during_replacement = true;
        check(throws([&] { coordinator.commit_local(session_c, plan_c.plan_hash, crash_replace_opts); }),
              "simulated crash during file replacement throws and marks recovery required");
        check(journal.load(session_c).state == PeerSessionState::RecoveryRequired,
              "crash during replacement sets journal state to RecoveryRequired");

        PeerSessionObservation obs{session_c, "laptop_b", PeerObservedState::Aborted, plan_c.plan_hash, {}};
        auto advice = coordinator.reconcile_and_recover(session_c, obs);
        check(advice == PeerRecoveryAction::AbortUncommitted,
              "reconciliation advises AbortUncommitted when peer aborted and replacement was interrupted");

        bool rollback_ok = coordinator.rollback_operations(session_c, plan_c.plan_hash);
        check(rollback_ok && mc::sha256_file(sync_c / "file.txt") == mc::sha256_data("precious data", 13) &&
              journal.load(session_c).local_rollback_verified,
              "rollback restores previous destination from verified recovery artifact and marks local rollback verified");
    }

    // --- Scenario D: Rollback failure handling ---
    const auto case_d = coord_root / "case_d";
    const auto sync_d = case_d / "sync";
    const auto recovery_d = case_d / "recovery";
    const auto db_d = case_d / "session.sqlite3";
    write_file(sync_d / "orig.txt", "orig");

    auto local_d = make_manifest({{"orig.txt", "orig"}});
    PeerBaseline baseline_d;
    baseline_d.exists = true;
    baseline_d.peer_id = "laptop_b";
    baseline_d.folder_pair_id = "pair-d";
    baseline_d.merkle_root = local_d.merkle_root;
    baseline_d.files = local_d.files;
    auto remote_d = make_manifest({{"orig.txt", "mod"}});
    auto plan_d = plan_bidirectional("laptop_b", "pair-d", baseline_d, local_d, remote_d);

    std::string session_d;
    {
        PeerSessionJournal journal(db_d.string());
        session_d = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_d, "laptop_b");
        journal.record_manifests(session_d, local_d.merkle_root, remote_d.merkle_root, baseline_d.merkle_root);
        journal.agree_plan(session_d, plan_d.plan_hash, plan_d.plan_hash, remote_d.merkle_root, true, false);
        journal.begin_approval(session_d);
        journal.record_approval(session_d, plan_d.plan_hash, true, false);

        PeerTransactionCoordinator coordinator(journal, sync_d, recovery_d);
        coordinator.plan_operations(session_d, plan_d);
        auto writer_d = [](const PeerOperationRecord&, mc::StagingFile& staging) { staging.write("mod", 3); };
        coordinator.prepare_operations(session_d, plan_d.plan_hash, writer_d);

        PeerExecutorOptions rollback_fail_opts;
        rollback_fail_opts.simulate_rollback_failure = true;
        check(throws([&] { coordinator.rollback_operations(session_d, plan_d.plan_hash, rollback_fail_opts); }),
              "simulated rollback failure throws exception");
        auto record_d = journal.load(session_d);
        check(record_d.state == PeerSessionState::RecoveryRequired &&
              record_d.recovery_material_retained &&
              record_d.recovery_diagnostic.find("rollback failed") != std::string::npos,
              "failed rollback preserves recovery artifacts and records explicit diagnostic for manual reconciliation");
    }

    // --- Scenario E: History write failure handling ---
    const auto case_e = coord_root / "case_e";
    const auto sync_e = case_e / "sync";
    const auto recovery_e = case_e / "recovery";
    const auto state_e = case_e / ".merklechain";
    const auto db_e = case_e / "session.sqlite3";
    const auto activity_db_e = case_e / "activity.sqlite3";
    write_file(sync_e / "hist.txt", "hist v1");

    auto local_e = make_manifest({{"hist.txt", "hist v1"}});
    PeerBaseline baseline_e;
    baseline_e.exists = true;
    baseline_e.peer_id = "laptop_b";
    baseline_e.folder_pair_id = "pair-e";
    baseline_e.merkle_root = local_e.merkle_root;
    baseline_e.files = local_e.files;
    auto remote_e = make_manifest({{"hist.txt", "hist v2"}});
    auto plan_e = plan_bidirectional("laptop_b", "pair-e", baseline_e, local_e, remote_e);

    std::string session_e;
    {
        PeerSessionJournal journal(db_e.string());
        session_e = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_e, "laptop_b");
        journal.record_manifests(session_e, local_e.merkle_root, remote_e.merkle_root, baseline_e.merkle_root);
        journal.agree_plan(session_e, plan_e.plan_hash, plan_e.plan_hash, remote_e.merkle_root, true, false);
        journal.begin_approval(session_e);
        journal.record_approval(session_e, plan_e.plan_hash, true, false);

        mc::VersionStore version_store(activity_db_e, state_e);
        mc::ActivityStore activity_store(activity_db_e);
        PeerTransactionCoordinator coordinator(journal, sync_e, recovery_e, nullptr, &version_store, &activity_store);
        coordinator.plan_operations(session_e, plan_e);
        auto writer_e = [](const PeerOperationRecord&, mc::StagingFile& staging) { staging.write("hist v2", 7); };
        coordinator.prepare_operations(session_e, plan_e.plan_hash, writer_e);

        journal.acknowledge_peer_prepared(session_e, "laptop_b", plan_e.plan_hash);
        journal.begin_commit(session_e, plan_e.plan_hash);

        PeerExecutorOptions hist_fail_opts;
        hist_fail_opts.simulate_history_write_failure = true;
        check(throws([&] { coordinator.commit_local(session_e, plan_e.plan_hash, hist_fail_opts); }),
              "simulated history write failure throws exception after file commit");
        check(mc::sha256_file(sync_e / "hist.txt") == mc::sha256_data("hist v2", 7) &&
              journal.load(session_e).state == PeerSessionState::RecoveryRequired,
              "verified destination file remains committed on disk while session marks history write failure");

        auto retry_res = coordinator.commit_local(session_e, plan_e.plan_hash);
        check(retry_res.success, "retrying commit after history write failure completes successfully and idempotently");
    }

    // --- Scenario F: Stale plan and changed destination hash detection ---
    const auto case_f = coord_root / "case_f";
    const auto sync_f = case_f / "sync";
    const auto recovery_f = case_f / "recovery";
    const auto db_f = case_f / "session.sqlite3";
    write_file(sync_f / "stale.txt", "unmodified content");

    auto local_f = make_manifest({{"stale.txt", "unmodified content"}});
    PeerBaseline baseline_f;
    baseline_f.exists = true;
    baseline_f.peer_id = "laptop_b";
    baseline_f.folder_pair_id = "pair-f";
    baseline_f.merkle_root = local_f.merkle_root;
    baseline_f.files = local_f.files;
    auto remote_f = make_manifest({{"stale.txt", "new remote content"}});
    auto plan_f = plan_bidirectional("laptop_b", "pair-f", baseline_f, local_f, remote_f);

    std::string session_f;
    {
        PeerSessionJournal journal(db_f.string());
        session_f = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_f, "laptop_b");
        journal.record_manifests(session_f, local_f.merkle_root, remote_f.merkle_root, baseline_f.merkle_root);
        journal.agree_plan(session_f, plan_f.plan_hash, plan_f.plan_hash, remote_f.merkle_root, true, false);
        journal.begin_approval(session_f);
        journal.record_approval(session_f, plan_f.plan_hash, true, false);

        PeerTransactionCoordinator coordinator(journal, sync_f, recovery_f);
        coordinator.plan_operations(session_f, plan_f);

        write_file(sync_f / "stale.txt", "concurrent local modification");

        auto writer_f = [](const PeerOperationRecord&, mc::StagingFile& staging) { staging.write("new remote content", 18); };
        check(throws([&] { coordinator.prepare_operations(session_f, plan_f.plan_hash, writer_f); }),
              "coordinator rejects preparation if destination content hash changed after planning");
        check(mc::sha256_file(sync_f / "stale.txt") == mc::sha256_data("concurrent local modification", 29),
              "tampered destination file is preserved and not clobbered");
    }

    // --- Scenario G: Idempotent recovery across repeated journal reopen ---
    {
        PeerSessionJournal reopened1(db_a.string());
        auto ops1 = reopened1.load_operations(session_a);
        PeerSessionJournal reopened2(db_a.string());
        auto ops2 = reopened2.load_operations(session_a);
        check(ops1.size() == 3 && ops2.size() == 3 &&
              ops1.front().state == PeerOperationState::Finalized &&
              ops2.front().state == PeerOperationState::Finalized,
              "repeated database close and reopen durably preserves finalized operation records");
    }

    // --- Scenario H: Pre-commit stale destination detection (Audit Gap) ---
    const auto case_h = coord_root / "case_h";
    const auto sync_h = case_h / "sync";
    const auto recovery_h = case_h / "recovery";
    const auto db_h = case_h / "session.sqlite3";
    write_file(sync_h / "update_stale.txt", "v1 original content");
    write_file(sync_h / "delete_stale.txt", "v1 to be deleted");

    auto local_h = make_manifest({
        {"delete_stale.txt", "v1 to be deleted"},
        {"update_stale.txt", "v1 original content"}
    });
    PeerBaseline baseline_h;
    baseline_h.exists = true;
    baseline_h.peer_id = "laptop_b";
    baseline_h.folder_pair_id = "pair-h";
    baseline_h.merkle_root = local_h.merkle_root;
    baseline_h.files = local_h.files;
    auto remote_h = make_manifest({
        {"update_stale.txt", "v2 remote content"}
    });
    auto plan_h = plan_bidirectional("laptop_b", "pair-h", baseline_h, local_h, remote_h);

    std::string session_h;
    {
        PeerSessionJournal journal(db_h.string());
        session_h = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_h, "laptop_b");
        journal.record_manifests(session_h, local_h.merkle_root, remote_h.merkle_root, baseline_h.merkle_root);
        journal.agree_plan(session_h, plan_h.plan_hash, plan_h.plan_hash, remote_h.merkle_root, true, true);
        journal.begin_approval(session_h);
        journal.record_approval(session_h, plan_h.plan_hash, true, true);

        PeerTransactionCoordinator coordinator(journal, sync_h, recovery_h);
        coordinator.plan_operations(session_h, plan_h);

        auto writer_h = [](const PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("v2 remote content", 17);
        };
        check(coordinator.prepare_operations(session_h, plan_h.plan_hash, writer_h),
              "operations prepare successfully before tamper");

        // Now tamper with the destination files AFTER prepare, immediately before commit
        write_file(sync_h / "update_stale.txt", "locally modified after prepare!");

        // Attempt commit: must detect stale destination contents immediately before mutation
        journal.acknowledge_peer_prepared(session_h, "laptop_b", plan_h.plan_hash);
        const auto commit_res = coordinator.commit_local(session_h, plan_h.plan_hash);
        check(!commit_res.success, "commit_local rejects mutation when destination contents changed after prepare");
        check(commit_res.error.find("stale destination") != std::string::npos,
              "commit_local error specifically diagnoses stale destination contents");
        check(read_file(sync_h / "update_stale.txt") == "locally modified after prepare!",
              "tampered file was not overwritten by stale commit");

        const auto session_rec = journal.load(session_h);
        check(session_rec.state == PeerSessionState::RecoveryRequired,
              "session marked as RecoveryRequired after detecting stale destination");
    }

    // --- Scenario I: Durable recovery reconciliation for interrupted operations ---
    const auto case_i = coord_root / "case_i";
    const auto sync_i = case_i / "sync";
    const auto recovery_i = case_i / "recovery";
    const auto db_i = case_i / "session.sqlite3";
    write_file(sync_i / "doc.txt", "v1 original doc");

    auto local_i = make_manifest({{"doc.txt", "v1 original doc"}});
    PeerBaseline baseline_i;
    baseline_i.exists = true;
    baseline_i.peer_id = "laptop_b";
    baseline_i.folder_pair_id = "pair-i";
    baseline_i.merkle_root = local_i.merkle_root;
    baseline_i.files = local_i.files;
    auto remote_i = make_manifest({{"doc.txt", "v2 updated doc"}});
    auto plan_i = plan_bidirectional("laptop_b", "pair-i", baseline_i, local_i, remote_i);

    // I.1: Crash mid-replacement: retiring file exists, destination missing
    std::string session_i1;
    {
        PeerSessionJournal journal(db_i.string());
        session_i1 = journal.create("laptop_a", "laptop_b");
        journal.mark_authenticated(session_i1, "laptop_b");
        journal.record_manifests(session_i1, local_i.merkle_root, remote_i.merkle_root, baseline_i.merkle_root);
        journal.agree_plan(session_i1, plan_i.plan_hash, plan_i.plan_hash, remote_i.merkle_root, true, false);
        journal.begin_approval(session_i1);
        journal.record_approval(session_i1, plan_i.plan_hash, true, false);

        PeerTransactionCoordinator coordinator(journal, sync_i, recovery_i);
        coordinator.plan_operations(session_i1, plan_i);

        auto writer_i = [](const PeerOperationRecord&, mc::StagingFile& staging) {
            staging.write("v2 updated doc", 14);
        };
        coordinator.prepare_operations(session_i1, plan_i.plan_hash, writer_i);
        journal.acknowledge_peer_prepared(session_i1, "laptop_b", plan_i.plan_hash);

        PeerExecutorOptions crash_opt;
        crash_opt.simulate_crash_during_replacement = true;
        check(throws([&] { coordinator.commit_local(session_i1, plan_i.plan_hash, crash_opt); }),
              "simulated crash during replacement throws");

        // Verify filesystem state right after crash: target does not exist, .mc-retiring exists
        check(!mc::fs::exists(sync_i / "doc.txt"), "target absent mid-replacement after crash");
        const auto ops = journal.load_operations(session_i1);
        const auto retiring = sync_i / ("doc.txt.mc-retiring-" + ops.front().operation_id.substr(0, 16));
        check(mc::fs::exists(retiring), "retiring file present after simulated crash");

        // Reconcile startup without resume (rollback to original v1)
        const auto rep = coordinator.reconcile_interrupted_session(session_i1, false);
        check(rep.reconciled && rep.files_restored_from_retiring == 1,
              "startup reconciliation restores target from retiring file");
        check(mc::fs::exists(sync_i / "doc.txt") &&
              read_file(sync_i / "doc.txt") == "v1 original doc",
              "restored file verified against prior content hash");
        check(!mc::fs::exists(retiring), "lingering retiring file cleaned up after reconciliation");
    }

    // I.2: Missing/corrupt recovery artifact triggers manual recovery
    {
        PeerSessionJournal journal(db_i.string());
        const auto ops = journal.load_operations(session_i1);
        // Overwrite backup artifact with corrupted bytes
        write_file(mc::fs::u8path(ops.front().recovery_artifact), "corrupted backup bytes");
        // Tamper destination
        write_file(sync_i / "doc.txt", "tampered content");

        PeerTransactionCoordinator coordinator(journal, sync_i, recovery_i);
        const auto rep = coordinator.reconcile_interrupted_session(session_i1, false);
        check(rep.manual_recovery_required,
              "reconciliation detects corrupt recovery artifact and requires manual recovery");
    }

    // --- Scenario J: list_unfinished_sessions ---
    {
        PeerSessionJournal journal(db_i.string());
        const auto unfinished = journal.list_unfinished_sessions();
        check(!unfinished.empty(), "list_unfinished_sessions returns incomplete sessions requiring recovery");
        const bool found_i1 = std::any_of(unfinished.begin(), unfinished.end(), [&](const auto& s) {
            return s.session_id == session_i1;
        });
        check(found_i1, "unfinalized session discovered in unfinished list");
    }
}
