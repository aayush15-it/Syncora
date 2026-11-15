#include "merklechain/collab_store.hpp"
#include "merklechain/scanner.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <future>
#include <vector>
#include <chrono>
#include <cassert>

namespace mc {

void run_branching_tests(const fs::path& fixture_root,
                         void (*check)(bool, const char*)) {
    const auto test_root = fixture_root / "branching_test_suite";
    std::error_code ec;
    fs::remove_all(test_root, ec);
    fs::create_directories(test_root, ec);

    // =========================================================================
    // 1. Schema & Migration Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "migration_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "migration.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        {
            CollabStore store(db_path, storage_dir);
            const auto host = store.find_user_by_username("host");
            check(host.has_value(), "Migration test: default host user exists");

            // Create workspace 1: No versions published yet
            const auto ws1 = store.create_workspace("Repo-Alpha", "Workspace with no versions");
            check(!ws1.id.empty(), "Workspace 1 created successfully");

            // Verify default main branch was created automatically
            const auto branches1 = store.list_branches(ws1.id);
            check(branches1.size() == 1, "New workspace automatically receives exactly one default branch");
            if (!branches1.empty()) {
                const auto& main_b = branches1[0];
                check(main_b.name == "main", "Default branch name is 'main'");
                check(main_b.is_default, "Default branch flag is true");
                check(main_b.is_active, "Default branch is marked active");
                check(main_b.head_version_id.empty(), "Default branch has empty head_version_id when no versions published");
                check(ws1.active_branch_id == main_b.id, "Workspace active_branch_id matches main branch ID");
            }

            // Verify active branch lookup helper
            const auto active_b = store.get_active_branch(ws1.id);
            check(active_b.has_value() && active_b->name == "main", "get_active_branch returns main branch");

            // Create workspace 2: Publish a version, then simulate legacy database migration
            const auto ws2 = store.create_workspace("Repo-Beta", "Workspace with version");
            const auto client = store.find_user_by_username("client_alice");
            store.assign_user_to_workspace(ws2.id, client->id);

            // Populate working copy and publish v1
            store.write_working_copy_file_content(ws2.id, "file1.txt", "Version 1 file content\n");
            const auto v1 = store.publish_version(ws2.id, host->id, "v1.0", "Initial commit");
            check(!v1.id.empty(), "Version 1 published on Repo-Beta");

            // Verify main branch head_version_id was updated to v1
            const auto main_ws2 = store.get_active_branch(ws2.id);
            check(main_ws2.has_value() && main_ws2->head_version_id == v1.id,
                  "publish_version automatically advances active branch head_version_id");
        }

        // Test Migration Idempotency: Reopen CollabStore multiple times
        {
            CollabStore store(db_path, storage_dir);
            const auto workspaces = store.list_workspaces();
            check(workspaces.size() >= 2, "Reopened store lists all existing workspaces");

            for (const auto& ws : workspaces) {
                const auto branches = store.list_branches(ws.id);
                check(branches.size() == 1, "Migration idempotency: branch count remains exactly 1 on reopen");
                check(!ws.active_branch_id.empty(), "Migration idempotency: active_branch_id preserved");
            }
        }
    }

    // =========================================================================
    // 2. Branch Creation & Validation Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "creation_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "creation.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Validation-Repo", "Testing branch names and constraints");

        // Valid branch names
        const std::vector<std::string> valid_names = {
            "feature/auth-provider",
            "fix-bug_123",
            "release/v1.0.0",
            "user/alice/experiment",
            "deep/nested/path/branch-name",
            "patch.1"
        };

        for (const auto& name : valid_names) {
            try {
                const auto b = store.create_branch(ws.id, name, "", host->id);
                check(b.name == name && b.workspace_id == ws.id, ("Valid branch name created: " + name).c_str());
            } catch (const std::exception& e) {
                check(false, ("Unexpected failure creating valid branch: " + name + " (" + e.what() + ")").c_str());
            }
        }

        // Duplicate branch name rejection
        bool duplicate_rejected = false;
        try {
            store.create_branch(ws.id, "feature/auth-provider", "", host->id);
        } catch (const std::exception&) {
            duplicate_rejected = true;
        }
        check(duplicate_rejected, "Duplicate branch name on same workspace is rejected");

        // Invalid branch names
        const std::vector<std::string> invalid_names = {
            "",                     // empty
            "   ",                  // whitespace only
            "/leading-slash",       // starts with slash
            "trailing-slash/",      // ends with slash
            "feature//double-slash",// consecutive slashes
            "has space",            // contains space
            "feature:colon",        // contains colon
            "feature~tilde",        // contains tilde
            "feature^caret",        // contains caret
            "feature?question",     // contains question
            "feature*asterisk",     // contains asterisk
            "feature[bracket",      // contains bracket
            "feature\\backslash",   // contains backslash
            "feature/../traversal", // dot-dot traversal
            "feature/./current",    // dot component
            std::string(129, 'a')   // exceeds 128 characters
        };

        for (const auto& inv : invalid_names) {
            bool rejected = false;
            try {
                store.create_branch(ws.id, inv, "", host->id);
            } catch (const std::exception&) {
                rejected = true;
            }
            check(rejected, ("Invalid branch name rejected: '" + inv + "'").c_str());
        }

        // Branch pointing to foreign / non-existent version rejection
        bool non_existent_ver_rejected = false;
        try {
            store.create_branch(ws.id, "invalid-head-branch", "non_existent_ver_id_12345", host->id);
        } catch (const std::exception&) {
            non_existent_ver_rejected = true;
        }
        check(non_existent_ver_rejected, "Branch creation pointing to non-existent version is rejected");

        // Create second workspace to test foreign version isolation
        const auto ws2 = store.create_workspace("Other-Repo", "Workspace 2");
        store.write_working_copy_file_content(ws2.id, "test.txt", "data");
        const auto v_ws2 = store.publish_version(ws2.id, host->id, "v1", "release");

        bool foreign_ver_rejected = false;
        try {
            store.create_branch(ws.id, "foreign-head-branch", v_ws2.id, host->id);
        } catch (const std::exception&) {
            foreign_ver_rejected = true;
        }
        check(foreign_ver_rejected, "Branch creation pointing to version from different workspace is rejected");

        // Zero-copy CAS check: creating a branch must not change CAS chunk counts
        const auto chunk_count_before = store.cas_store().list_all_objects().size();
        const auto branch_zero_copy = store.create_branch(ws2.id, "zero-copy-branch", v_ws2.id, host->id);
        const auto chunk_count_after = store.cas_store().list_all_objects().size();
        check(chunk_count_before == chunk_count_after, "Branch creation is O(1) zero-copy: CAS chunk count unchanged");
        check(branch_zero_copy.head_version_id == v_ws2.id, "Zero-copy branch points to target version ID");
    }

    // =========================================================================
    // 3. Branch Switching Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "switching_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "switching.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Switching-Repo", "Workspace for branch switching");

        // Step 1: Create Version 1 on main branch
        store.write_working_copy_file_content(ws.id, "common.txt", "Common file v1\n");
        store.write_working_copy_file_content(ws.id, "main_only.txt", "Main only v1\n");
        const auto v1 = store.publish_version(ws.id, host->id, "v1.0", "Main branch baseline");
        const auto v1_root = v1.merkle_root;

        const auto main_branch = store.get_active_branch(ws.id);
        check(main_branch.has_value() && main_branch->name == "main", "Initially on main branch");
        check(main_branch->head_version_id == v1.id, "main branch head is v1");

        // Step 2: Create feature-alpha branch pointing to v1
        const auto alpha_branch = store.create_branch(ws.id, "feature/alpha", v1.id, host->id);
        check(alpha_branch.head_version_id == v1.id, "feature/alpha branch points to v1");

        // Step 3: Switch to feature-alpha
        check(store.switch_branch(ws.id, alpha_branch.id), "Switch to feature/alpha succeeded");
        const auto active_after_alpha = store.get_active_branch(ws.id);
        check(active_after_alpha.has_value() && active_after_alpha->name == "feature/alpha",
              "Active branch is now feature/alpha");

        // Step 4: Make modifications on feature-alpha and publish v2
        store.write_working_copy_file_content(ws.id, "common.txt", "Common file modified in feature alpha\n");
        store.write_working_copy_file_content(ws.id, "alpha_feature.txt", "Alpha specific feature file\n");
        store.delete_working_copy_file(ws.id, "main_only.txt");
        const auto v2 = store.publish_version(ws.id, host->id, "v2.0-alpha", "Alpha modifications");
        const auto v2_root = v2.merkle_root;

        // Verify heads: feature/alpha is v2, main remains v1
        const auto alpha_head = store.find_branch_by_id(alpha_branch.id);
        const auto main_head = store.find_branch_by_id(main_branch->id);
        check(alpha_head.has_value() && alpha_head->head_version_id == v2.id, "feature/alpha head advanced to v2");
        check(main_head.has_value() && main_head->head_version_id == v1.id, "main branch head remained at v1");

        // Step 5: Switch back to main
        check(store.switch_branch(ws.id, main_branch->id), "Switch back to main succeeded");
        const auto active_main_again = store.get_active_branch(ws.id);
        check(active_main_again.has_value() && active_main_again->name == "main", "Active branch is main again");

        // Step 6: Verify working copy matches v1 exactly
        const auto main_manifest = scan_folder(storage_dir / "workspaces" / ws.id / "working_copy");
        check(main_manifest.merkle_root == v1_root, "Working copy restored to exact v1 Merkle root");
        const auto main_files = store.list_working_copy_files(ws.id);
        check(main_files.size() == 2, "Main working copy has 2 files");
        check(store.read_working_copy_file_content(ws.id, "common.txt") == "Common file v1\n",
              "common.txt content matches v1");
        check(store.read_working_copy_file_content(ws.id, "main_only.txt") == "Main only v1\n",
              "main_only.txt content matches v1");

        // Step 7: Switch back to feature/alpha
        check(store.switch_branch(ws.id, alpha_branch.id), "Switch back to feature/alpha succeeded");
        const auto alpha_manifest = scan_folder(storage_dir / "workspaces" / ws.id / "working_copy");
        check(alpha_manifest.merkle_root == v2_root, "Working copy restored to exact v2 Merkle root");
        check(store.read_working_copy_file_content(ws.id, "common.txt") == "Common file modified in feature alpha\n",
              "common.txt has alpha modifications");
        check(store.read_working_copy_file_content(ws.id, "alpha_feature.txt") == "Alpha specific feature file\n",
              "alpha_feature.txt exists");

        // Verify switching to current active branch is an idempotent no-op
        check(store.switch_branch(ws.id, alpha_branch.id), "Switching to already active branch succeeds immediately");

        // Step 8: Reject switching to non-existent branch or branch from another workspace
        bool invalid_switch_rejected = false;
        try {
            store.switch_branch(ws.id, "non_existent_branch_id_9999");
        } catch (const std::exception&) {
            invalid_switch_rejected = true;
        }
        check(invalid_switch_rejected, "Switching to non-existent branch ID is rejected");

        const auto ws_foreign = store.create_workspace("Foreign-Ws", "Another ws");
        const auto foreign_branch = store.get_active_branch(ws_foreign.id);
        bool cross_ws_switch_rejected = false;
        try {
            store.switch_branch(ws.id, foreign_branch->id);
        } catch (const std::exception&) {
            cross_ws_switch_rejected = true;
        }
        check(cross_ws_switch_rejected, "Switching to branch belonging to a different workspace is rejected");
    }

    // =========================================================================
    // 4. Branch Deletion & Immutability Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "deletion_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "deletion.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Deletion-Repo", "Workspace for testing branch deletion");

        store.write_working_copy_file_content(ws.id, "base.txt", "Baseline content");
        const auto v1 = store.publish_version(ws.id, host->id, "v1", "Initial");
        const auto main_branch = store.get_active_branch(ws.id);

        // Rule 1: Cannot delete default branch
        bool default_del_rejected = false;
        try {
            store.delete_branch(ws.id, main_branch->id);
        } catch (const std::exception&) {
            default_del_rejected = true;
        }
        check(default_del_rejected, "Deleting default branch ('main') is strictly rejected");

        // Create feature branch and switch to it
        const auto feat = store.create_branch(ws.id, "feature/temp", v1.id, host->id);
        store.switch_branch(ws.id, feat.id);

        // Rule 2: Cannot delete currently active branch
        bool active_del_rejected = false;
        try {
            store.delete_branch(ws.id, feat.id);
        } catch (const std::exception&) {
            active_del_rejected = true;
        }
        check(active_del_rejected, "Deleting currently active branch is strictly rejected");

        // Publish version on feature/temp so it has a version associated
        store.write_working_copy_file_content(ws.id, "temp.txt", "Temporary content");
        const auto v_temp = store.publish_version(ws.id, host->id, "v-temp", "Temp version");

        // Switch back to main branch
        store.switch_branch(ws.id, main_branch->id);

        // Delete inactive feature branch
        const auto cas_objects_before = store.cas_store().list_all_objects().size();
        const bool deleted = store.delete_branch(ws.id, feat.id);
        check(deleted, "Deleting inactive non-default branch succeeds");

        // Verify branch is gone from list and lookups
        const auto branch_lookup = store.find_branch_by_id(feat.id);
        check(!branch_lookup.has_value(), "Deleted branch cannot be found by ID");
        const auto branch_lookup_name = store.find_branch_by_name(ws.id, "feature/temp");
        check(!branch_lookup_name.has_value(), "Deleted branch cannot be found by name");

        // Rule 3: Versions and CAS chunks are immutable and preserved
        const auto versions = store.list_published_versions(ws.id);
        bool v_temp_found = false;
        for (const auto& v : versions) {
            if (v.id == v_temp.id) v_temp_found = true;
        }
        check(v_temp_found, "Published version v-temp remains intact after branch deletion");

        const auto cas_objects_after = store.cas_store().list_all_objects().size();
        check(cas_objects_before == cas_objects_after, "CAS chunks remain intact after branch deletion");
    }

    // =========================================================================
    // 5. Crash Recovery & Fault Injection Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "recovery_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "recovery.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        std::string ws_id;
        std::string v1_id, v2_id;
        std::string v1_root, v2_root;
        std::string main_b_id, branch_b_id;

        // Setup workspace with two branches at different versions
        {
            CollabStore store(db_path, storage_dir);
            const auto host = store.find_user_by_username("host");
            const auto ws = store.create_workspace("Recovery-Ws", "Crash recovery testing");
            ws_id = ws.id;

            // v1 on main
            store.write_working_copy_file_content(ws_id, "doc.txt", "Main Version 1\n");
            const auto v1 = store.publish_version(ws_id, host->id, "v1", "Commit 1");
            v1_id = v1.id;
            v1_root = v1.merkle_root;
            main_b_id = store.get_active_branch(ws_id)->id;

            // branch B with v2
            const auto b = store.create_branch(ws_id, "branch-b", v1_id, host->id);
            branch_b_id = b.id;
            store.switch_branch(ws_id, branch_b_id);

            store.write_working_copy_file_content(ws_id, "doc.txt", "Branch B Version 2\n");
            store.write_working_copy_file_content(ws_id, "extra.txt", "Extra branch B file\n");
            const auto v2 = store.publish_version(ws_id, host->id, "v2", "Commit 2");
            v2_id = v2.id;
            v2_root = v2.merkle_root;

            // Switch back to main
            store.switch_branch(ws_id, main_b_id);
            check(store.get_active_branch(ws_id)->name == "main", "Setup complete: active branch is main");
        }

        // Test 5.1: Fault Injection at FailAfterBranchSwitchStaging
        {
            CollabStore store(db_path, storage_dir);
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBranchSwitchStaging);

            bool injected = false;
            try {
                store.switch_branch(ws_id, branch_b_id);
            } catch (const CollabFaultPointInjected&) {
                injected = true;
            }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(injected, "Fault point FailAfterBranchSwitchStaging triggered");
        }

        // Reopen store: recover_incomplete_operations cleans up staging directory
        {
            CollabStore store(db_path, storage_dir);
            const auto active = store.get_active_branch(ws_id);
            check(active.has_value() && active->id == main_b_id,
                  "Recovery from staging fault: active branch remains main");
            const auto cur_root = scan_folder(storage_dir / "workspaces" / ws_id / "working_copy").merkle_root;
            check(cur_root == v1_root, "Working copy intact after staging fault recovery");
        }

        // Test 5.2: Fault Injection at FailAfterBranchSwitchBackup
        {
            CollabStore store(db_path, storage_dir);
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBranchSwitchBackup);

            bool injected = false;
            try {
                store.switch_branch(ws_id, branch_b_id);
            } catch (const CollabFaultPointInjected&) {
                injected = true;
            }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(injected, "Fault point FailAfterBranchSwitchBackup triggered");
        }

        // Reopen store: recovery cleans up backups and staging
        {
            CollabStore store(db_path, storage_dir);
            const auto active = store.get_active_branch(ws_id);
            check(active.has_value() && active->id == main_b_id,
                  "Recovery from backup fault: active branch remains main");
            const auto cur_root = scan_folder(storage_dir / "workspaces" / ws_id / "working_copy").merkle_root;
            check(cur_root == v1_root, "Working copy intact after backup fault recovery");
        }

        // Test 5.3: Fault Injection at FailAfterBranchSwitchPromotion
        {
            CollabStore store(db_path, storage_dir);
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBranchSwitchPromotion);

            bool injected = false;
            try {
                store.switch_branch(ws_id, branch_b_id);
            } catch (const CollabFaultPointInjected&) {
                injected = true;
            }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(injected, "Fault point FailAfterBranchSwitchPromotion triggered");
        }

        // Reopen store: uncommitted promotion is rolled back from backup_work and backup_base
        {
            CollabStore store(db_path, storage_dir);
            const auto active = store.get_active_branch(ws_id);
            check(active.has_value() && active->id == main_b_id,
                  "Recovery from uncommitted promotion: active branch remains main");
            const auto cur_root = scan_folder(storage_dir / "workspaces" / ws_id / "working_copy").merkle_root;
            check(cur_root == v1_root,
                  "Working copy restored from backup after uncommitted promotion crash");
        }
    }

    // =========================================================================
    // 6. Concurrency & Workspace Locking Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "concurrency_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "concurrency.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Concurrent-Ws", "Testing concurrent branch operations");

        store.write_working_copy_file_content(ws.id, "file.txt", "Initial");
        const auto v1 = store.publish_version(ws.id, host->id, "v1", "Commit 1");
        const auto main_b = store.get_active_branch(ws.id);

        // Create 5 branches concurrently
        std::vector<std::future<CollabBranch>> futures;
        for (int i = 0; i < 5; ++i) {
            const std::string bname = "feature/worker-" + std::to_string(i);
            futures.push_back(std::async(std::launch::async, [&store, ws_id = ws.id, bname, host_id = host->id, v1_id = v1.id]() {
                return store.create_branch(ws_id, bname, v1_id, host_id);
            }));
        }

        std::vector<CollabBranch> created_branches;
        for (auto& f : futures) {
            created_branches.push_back(f.get());
        }
        check(created_branches.size() == 5, "5 branches created concurrently without deadlock or corruption");

        const auto all_branches = store.list_branches(ws.id);
        check(all_branches.size() == 6, "Total branches is 6 (1 main + 5 concurrent features)");

        // Concurrent reads while switching branch
        std::atomic<bool> stop_readers{false};
        std::atomic<int> read_count{0};
        auto reader_thread = std::thread([&store, ws_id = ws.id, &stop_readers, &read_count]() {
            while (!stop_readers.load()) {
                const auto b_list = store.list_branches(ws_id);
                const auto act = store.get_active_branch(ws_id);
                if (!b_list.empty() && act.has_value()) {
                    read_count.fetch_add(1);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });

        // Switch back and forth multiple times
        for (int i = 0; i < 3; ++i) {
            store.switch_branch(ws.id, created_branches[i].id);
            store.switch_branch(ws.id, main_b->id);
        }

        stop_readers.store(true);
        reader_thread.join();
        check(read_count.load() > 0, "Concurrent branch queries succeeded while switches occurred");
        check(store.get_active_branch(ws.id)->id == main_b->id, "Final active branch is main");
    }

    // =========================================================================
    // 7. Dirty Working Copy Branch Switch & Force Override Tests
    // =========================================================================
    {
        const auto suite_dir = test_root / "dirty_switch_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "collab.sqlite3";
        const auto storage_dir = suite_dir / "storage";

        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Dirty-Test-WS", "Workspace for dirty switch tests");

        // Create initial file and publish version 1 on main
        store.write_working_copy_file_content(ws.id, "file1.txt", "Original Version 1 Content");
        const auto v1 = store.publish_version(ws.id, host->id, "v1.0", "Release 1");

        // Create feature branch
        const auto feat_b = store.create_branch(ws.id, "feature/dirty-test", v1.id, host->id);

        // Verify clean working copy
        check(!store.has_uncommitted_changes(ws.id), "Initially working copy has no uncommitted changes");

        // Mutate working copy (add uncommitted change)
        store.write_working_copy_file_content(ws.id, "file1.txt", "Uncommitted modification to file1");
        check(store.has_uncommitted_changes(ws.id), "Uncommitted changes detected after modifying file1.txt");

        // Attempting to switch branch without force must fail and throw runtime_error
        bool dirty_switch_threw = false;
        try {
            store.switch_branch(ws.id, feat_b.name, host->id, false);
        } catch (const std::exception& e) {
            dirty_switch_threw = true;
            std::string msg = e.what();
            check(msg.find("uncommitted changes") != std::string::npos, "Exception explicitly mentions uncommitted changes");
        }
        check(dirty_switch_threw, "switch_branch rejected dirty switch without force");

        // Active branch remains unchanged
        const auto act_b = store.get_active_branch(ws.id);
        check(act_b.has_value() && act_b->name == "main", "Active branch remains main after rejected switch");

        // Uncommitted edits are intact
        const auto cur_content = store.read_working_copy_file_content(ws.id, "file1.txt");
        check(cur_content == "Uncommitted modification to file1", "Uncommitted changes preserved after rejected switch");

        // Now perform switch with force = true
        bool force_switch_ok = false;
        try {
            force_switch_ok = store.switch_branch(ws.id, feat_b.name, host->id, true);
        } catch (...) {
            force_switch_ok = false;
        }
        check(force_switch_ok, "switch_branch with force=true successfully switched branch");

        // Active branch is now feature/dirty-test
        const auto act_b2 = store.get_active_branch(ws.id);
        check(act_b2.has_value() && act_b2->name == feat_b.name, "Active branch is now feature/dirty-test");

        // Working copy was restored to feature branch head version (v1)
        const auto feat_content = store.read_working_copy_file_content(ws.id, "file1.txt");
        check(feat_content == "Original Version 1 Content", "Working copy materialized from target branch head after forced switch");
        check(!store.has_uncommitted_changes(ws.id), "Working copy is clean after branch switch");
    }
}

} // namespace mc

