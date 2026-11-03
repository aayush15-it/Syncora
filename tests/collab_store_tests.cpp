#include <chrono>
#include <vector>
#include <future>
#include "merklechain/collab_store.hpp"
#include <atomic>
#include <thread>
#include "merklechain/scanner.hpp"
#include <iostream>
#include <cassert>
#include <fstream>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace mc {

void run_collab_store_tests(const fs::path& fixture_root,
                            void (*check)(bool, const char*)) {
    const auto test_dir = fixture_root / "collab_test_suite";
    fs::remove_all(test_dir);
    fs::create_directories(test_dir);

    const auto db_path = test_dir / "collab.sqlite3";
    const auto storage_dir = test_dir / "storage";

    // 1. Password hashing and verification
    const std::string pass = "SecurePassword123!";
    const std::string hash = CollabStore::hash_password(pass);
    check(!hash.empty() && hash.rfind("$pbkdf2-sha256$", 0) == 0, "PBKDF2 password hashing produces valid format");
    check(CollabStore::verify_password(pass, hash), "PBKDF2 password verification succeeds with correct password");
    check(!CollabStore::verify_password("WrongPassword!", hash), "PBKDF2 password verification rejects wrong password");

    // 2. Initialize CollabStore in an isolated scope so database is closed before cleanup
    {
        CollabStore store(db_path, storage_dir);

        // 3. Verify seeding
        const auto seeded_host = store.find_user_by_username("host");
        check(seeded_host.has_value() && seeded_host->role == "host", "Default host account seeded successfully");
        const auto seeded_client = store.find_user_by_username("client_alice");
        check(seeded_client.has_value() && seeded_client->role == "client", "Default client account seeded successfully");

        // 4. Client creation and lookup
        const auto client_bob = store.create_user("client_bob", "BobPassword123!", "client", {"submit", "download_updates"});
        check(client_bob.username == "client_bob" && client_bob.role == "client", "Host can create new client account");
        const auto bob_lookup = store.find_user_by_id(client_bob.id);
        check(bob_lookup.has_value() && bob_lookup->username == "client_bob", "Client lookup by ID succeeds");

        // 5. Authentication
        std::string auth_err;
        const auto bob_session = store.authenticate("client_bob", "BobPassword123!", auth_err);
        check(bob_session.has_value() && !bob_session->token.empty(), "Client authenticates with valid credentials");

        const auto invalid_auth = store.authenticate("client_bob", "BadPassword!", auth_err);
        check(!invalid_auth.has_value(), "Client authentication fails with incorrect password");

        // 6. Session validation
        const auto validated_session = store.validate_session(bob_session->token);
        check(validated_session.has_value() && validated_session->username == "client_bob", "Session token validates correctly");

        // 7. Suspension blocks authentication
        store.set_user_status(client_bob.id, "suspended");
        const auto suspended_session = store.validate_session(bob_session->token);
        check(!suspended_session.has_value(), "Suspension revokes active sessions");
        const auto suspended_auth = store.authenticate("client_bob", "BobPassword123!", auth_err);
        check(!suspended_auth.has_value(), "Suspended client cannot authenticate");

        // Reactivate for further tests
        store.set_user_status(client_bob.id, "active");

        // 8. Workspaces
        const auto ws = store.create_workspace("Engineering-Docs", "Workspace for engineering specs");
        check(!ws.id.empty() && ws.name == "Engineering-Docs", "Workspace created successfully");
        store.assign_user_to_workspace(ws.id, client_bob.id);
        check(store.is_user_in_workspace(ws.id, client_bob.id), "User assigned to workspace verified");

        // 9. Folder submission
        const auto client_folder = test_dir / "client_local_source";
        fs::create_directories(client_folder);
        {
            std::ofstream f1(client_folder / "file_a.txt");
            f1 << "Initial content of File A\nLine 2 of File A\n";
            std::ofstream f2(client_folder / "file_b.txt");
            f2 << "Content of File B\n";
        }

        const auto sub = store.create_submission(client_bob.id, ws.id, client_folder);
        check(sub.file_count == 2 && sub.status == "pending", "Client submits folder; submission staged and pending");

        // 10. Host accepts submission
        const bool accepted = store.accept_submission(sub.id, seeded_host->id, "Looks good, approved as v1 baseline");
        check(accepted, "Host successfully accepts client submission");

        const auto working_files = store.list_working_copy_files(ws.id);
        check(working_files.size() == 2, "Accepted submission becomes baseline and working copy (2 files)");

        // 11. Host edits working copy
        const std::string edited_a = "Initial content of File A\nModified Line 2 of File A\nAdded Line 3\n";
        store.write_working_copy_file_content(ws.id, "file_a.txt", edited_a);
        store.write_working_copy_file_content(ws.id, "file_c.txt", "Brand new file C created by Host\n");
        store.delete_working_copy_file(ws.id, "file_b.txt");

        // 12. Change review & diff calculation
        const auto diffs = store.compute_working_copy_diff(ws.id);
        bool has_mod_a = false, has_del_b = false, has_add_c = false;
        for (const auto& d : diffs) {
            if (d.relative_path == "file_a.txt" && d.change_type == "MODIFIED") has_mod_a = true;
            if (d.relative_path == "file_b.txt" && d.change_type == "DELETED") has_del_b = true;
            if (d.relative_path == "file_c.txt" && d.change_type == "ADDED") has_add_c = true;
        }
        check(has_mod_a && has_del_b && has_add_c, "Change review accurately identifies MODIFIED, DELETED, and ADDED files");

        const auto diff_a = store.compute_file_diff(ws.id, "file_a.txt");
        check(diff_a.diff_text.find("+ Added Line 3") != std::string::npos, "Line-by-line unified diff correctly identifies added line");
        check(diff_a.diff_text.find("- Line 2 of File A") != std::string::npos, "Line-by-line unified diff correctly identifies removed line");

        // 13. Publish version
        const auto pub_ver = store.publish_version(ws.id, seeded_host->id, "Version 1.1", "Updated spec and added file C");
        check(!pub_ver.id.empty() && pub_ver.file_count == 2, "Host publishes immutable version (2 files remaining)");

        // 14. Client updates generated
        const auto bob_updates = store.list_updates_for_client(client_bob.id);
        check(!bob_updates.empty() && bob_updates[0].status == "available", "Client receives notification of available published update");

        // 15. Client accepts update
        const bool upd_accepted = store.accept_update(bob_updates[0].id, client_bob.id);
        check(upd_accepted, "Client explicitly accepts published update");

        // 16. Client applies update
        const auto client_dest = test_dir / "client_synced_folder";
        fs::create_directories(client_dest);
        // Pre-populate with old content
        {
            std::ofstream f(client_dest / "file_a.txt");
            f << "Old client content\n";
        }

        std::string apply_err;
        const bool applied = store.apply_update(bob_updates[0].id, client_bob.id, client_dest, apply_err);
        check(applied && apply_err.empty(), "Client applies staged update with hash & Merkle verification");

        // Verify content applied matches published version
        const auto applied_manifest = scan_folder(client_dest);
        check(applied_manifest.merkle_root == pub_ver.merkle_root, "Client folder Merkle root matches published version root exactly");

        // 17. Security traversal rejection (preserved)
        bool caught_traversal = false;
        try {
            store.read_working_copy_file_content(ws.id, "../../../Windows/win.ini");
        } catch (...) {
            caught_traversal = true;
        }
        check(caught_traversal, "Path traversal attempt is strictly rejected by working copy reader");

        // 17b. Comprehensive relative path security validation across all four CollabStore methods
        const std::vector<std::string> unsafe_test_paths = {
            // Windows reserved names (mixed case & extensions)
            "aux.txt", "con", "com1.log", "AUX.txt", "NUL", "LPT1",
            // Directory traversal
            "../../../Windows/win.ini", "folder/../file.txt",
            // Absolute paths & drive prefixes
            "/Windows/file.txt", "C:/Windows/file.txt", "C:\\Windows\\file.txt",
            // Invalid path components & trailing dots/spaces
            "folder/file.txt.", "folder/file.txt ", "folder/./file.txt", "folder/<bad>.txt"
        };

        bool all_read_rejected = true;
        bool all_write_rejected = true;
        bool all_delete_rejected = true;
        bool all_diff_rejected = true;

        for (const auto& unsafe_path : unsafe_test_paths) {
            try {
                store.read_working_copy_file_content(ws.id, unsafe_path);
                all_read_rejected = false;
            } catch (const std::runtime_error&) {}

            try {
                store.write_working_copy_file_content(ws.id, unsafe_path, "payload");
                all_write_rejected = false;
            } catch (const std::runtime_error&) {}

            try {
                store.delete_working_copy_file(ws.id, unsafe_path);
                all_delete_rejected = false;
            } catch (const std::runtime_error&) {}

            try {
                store.compute_file_diff(ws.id, unsafe_path);
                all_diff_rejected = false;
            } catch (const std::runtime_error&) {}
        }

        check(all_read_rejected, "All unsafe paths rejected by read_working_copy_file_content");
        check(all_write_rejected, "All unsafe paths rejected by write_working_copy_file_content");
        check(all_delete_rejected, "All unsafe paths rejected by delete_working_copy_file");
        check(all_diff_rejected, "All unsafe paths rejected by compute_file_diff");

        // Repeated separator path (folder//file.txt) handling verification
        bool repeated_separator_handled = false;
        try {
            store.read_working_copy_file_content(ws.id, "folder//file.txt");
        } catch (const std::runtime_error&) {
            repeated_separator_handled = true;
        }
        check(repeated_separator_handled, "Repeated separator path handled safely without escaping workspace root");

        // 17c. Valid paths verification across all four methods
        const std::vector<std::string> valid_test_paths = {
            "document.txt",
            "src/main.cpp",
            "docs/readme.md",
            "src/utils/helper.cpp"
        };

        bool all_valid_worked = true;
        for (const auto& valid_path : valid_test_paths) {
            try {
                const std::string test_data = "Valid content for " + valid_path;
                store.write_working_copy_file_content(ws.id, valid_path, test_data);
                const std::string read_back = store.read_working_copy_file_content(ws.id, valid_path);
                if (read_back != test_data) all_valid_worked = false;
                const auto d = store.compute_file_diff(ws.id, valid_path);
                if (d.relative_path != valid_path) all_valid_worked = false;
                store.delete_working_copy_file(ws.id, valid_path);
            } catch (...) {
                all_valid_worked = false;
            }
        }
        check(all_valid_worked, "Valid relative paths work correctly across all CollabStore working copy methods");

        // 17d. Windows Directory Junction & Reparse-Point Security Tests
#ifdef _WIN32
        const auto temp_outside = fs::temp_directory_path() / "syncora_collab_junc_test";
        fs::remove_all(temp_outside);
        fs::create_directories(temp_outside);
        {
            std::ofstream out((temp_outside / "classified.txt").string());
            out << "top secret external data";
        }

        const auto work_dir = storage_dir / "workspaces" / ws.id / "working_copy";
        fs::create_directories(work_dir);
        const auto junc_path = work_dir / "external_junction";
        std::string mk_cmd = "cmd.exe /c mklink /J \"" + junc_path.string() + "\" \"" + temp_outside.string() + "\" >nul 2>nul";
        int mk_res = system(mk_cmd.c_str());

        if (mk_res == 0 && fs::exists(junc_path)) {
            // Read through junction must fail
            bool read_junc_threw = false;
            try {
                store.read_working_copy_file_content(ws.id, "external_junction/classified.txt");
            } catch (const std::runtime_error&) {
                read_junc_threw = true;
            }
            check(read_junc_threw, "CollabStore read_working_copy_file_content rejects directory junction traversal");

            // Write through junction must fail
            bool write_junc_threw = false;
            try {
                store.write_working_copy_file_content(ws.id, "external_junction/pwned.txt", "malicious payload");
            } catch (const std::runtime_error&) {
                write_junc_threw = true;
            }
            check(write_junc_threw, "CollabStore write_working_copy_file_content rejects directory junction traversal");
            check(!fs::exists(temp_outside / "pwned.txt"), "Target directory outside workspace remains unaffected by blocked write");

            // Delete through junction must fail
            bool delete_junc_threw = false;
            try {
                store.delete_working_copy_file(ws.id, "external_junction/classified.txt");
            } catch (const std::runtime_error&) {
                delete_junc_threw = true;
            }
            check(delete_junc_threw, "CollabStore delete_working_copy_file rejects directory junction traversal");
            check(fs::exists(temp_outside / "classified.txt"), "Target file outside workspace remains untouched by blocked deletion");

            // Diff through junction must fail
            bool diff_junc_threw = false;
            try {
                store.compute_file_diff(ws.id, "external_junction/classified.txt");
            } catch (const std::runtime_error&) {
                diff_junc_threw = true;
            }
            check(diff_junc_threw, "CollabStore compute_file_diff rejects directory junction traversal");

            // Safely unlink the junction without deleting target
            RemoveDirectoryW(junc_path.wstring().c_str());
            check(fs::exists(temp_outside / "classified.txt"), "Junction teardown unlinks junction without deleting target");
        }
        fs::remove_all(temp_outside);
#endif

        // 17e. Boundary containment and prefix-collision tests
        check(is_path_within_boundary(storage_dir, storage_dir / "workspaces" / ws.id / "working_copy" / "doc.txt"),
              "Canonical containment accepts legitimate sub-paths within boundary");
        check(!is_path_within_boundary(storage_dir, fs::path(storage_dir.string() + "_attack") / "doc.txt"),
              "Canonical containment strictly rejects boundary prefix-collision attacks");
        check(!is_path_within_boundary(storage_dir, storage_dir / ".." / "outside.txt"),
              "Canonical containment rejects directory traversal outside boundary");

        // 18. Audit log recording
        const auto events = store.list_events(50);
        check(!events.empty(), "Security audit events are properly recorded and retrieved");
    }

    // Clean up test directory safely after store is closed
    std::error_code ec;
    fs::remove_all(test_dir, ec);
}

void run_collab_store_lifecycle_tests(const fs::path& fixture_root,
                                      void (*check)(bool, const char*)) {
    const auto test_dir = fixture_root / "lifecycle_test_suite";
    fs::remove_all(test_dir);
    fs::create_directories(test_dir);
    const auto db_path   = test_dir / "lifecycle.sqlite3";
    const auto store_dir = test_dir / "storage";

    // CP1-T1: OperationGuard rejects operations after finalize_and_close()
    {
        CollabStore store(db_path, store_dir);
        // Seed and do one successful operation to confirm normal state.
        const auto host = store.find_user_by_username("host");
        check(host.has_value(), "CP1-T1: normal op succeeds before shutdown");

        const auto result = store.finalize_and_close();
        check(result == FinalizeResult::OK || result == FinalizeResult::CHECKPOINT_FAILED,
              "CP1-T1: finalize_and_close() returns OK or CHECKPOINT_FAILED");

        bool threw = false;
        try {
            store.find_user_by_username("host");
        } catch (const std::runtime_error&) {
            threw = true;
        }
        check(threw, "CP1-T1: OperationGuard rejects operation after finalize_and_close()");
    }

    // CP1-T2: finalize_and_close() is idempotent
    {
        fs::remove_all(test_dir / "idem");
        fs::create_directories(test_dir / "idem");
        CollabStore store2(test_dir / "idem" / "idem.sqlite3", test_dir / "idem" / "storage");
        store2.finalize_and_close();
        const auto result2 = store2.finalize_and_close();
        check(result2 == FinalizeResult::ALREADY_FINALIZED,
              "CP1-T2: second finalize_and_close() returns ALREADY_FINALIZED");
    }

    // CP1-T3: is_finalized() reflects shutdown state
    {
        fs::remove_all(test_dir / "isfin");
        fs::create_directories(test_dir / "isfin");
        CollabStore store3(test_dir / "isfin" / "fin.sqlite3", test_dir / "isfin" / "storage");
        check(!store3.is_finalized(), "CP1-T3: is_finalized() is false before shutdown");
        check(!store3.is_shutting_down(), "CP1-T3: is_shutting_down() is false before shutdown");
        store3.finalize_and_close();
        check(store3.is_finalized(), "CP1-T3: is_finalized() is true after finalize_and_close()");
    }

    // CP1-T4: live_statement_count() is 0 after normal operation completes
    {
        fs::remove_all(test_dir / "stmtcnt");
        fs::create_directories(test_dir / "stmtcnt");
        CollabStore store4(test_dir / "stmtcnt" / "cnt.sqlite3", test_dir / "stmtcnt" / "storage");
        // Perform several read operations
        store4.find_user_by_username("host");
        store4.list_clients();
        store4.list_workspaces();
        store4.list_events(10);
        check(store4.live_statement_count() == 0,
              "CP1-T4: live_statement_count() is 0 after operations complete (no leaked statements)");
        store4.finalize_and_close();
    }

    // CP1-T5: Destructor safely closes a live store without explicit finalize_and_close()
    {
        fs::remove_all(test_dir / "dtor");
        fs::create_directories(test_dir / "dtor");
        bool dtor_ok = false;
        try {
            CollabStore store5(test_dir / "dtor" / "dtor.sqlite3", test_dir / "dtor" / "storage");
            store5.find_user_by_username("host");
            // store5 goes out of scope here -- destructor must close cleanly
            dtor_ok = true;
        } catch (...) {
            dtor_ok = false;
        }
        check(dtor_ok, "CP1-T5: CollabStore destructor closes store cleanly without explicit finalize_and_close()");
        // Verify database file exists (was not corrupted by destructor)
        check(fs::exists(test_dir / "dtor" / "dtor.sqlite3"),
              "CP1-T5: Database file is intact after destructor");
    }

    // CP1-T6: Concurrent read operations do not deadlock (basic smoke test)
    {
fs::remove_all(test_dir / "concurrent");
        fs::create_directories(test_dir / "concurrent");
        CollabStore store6(test_dir / "concurrent" / "c.sqlite3",
                           test_dir / "concurrent" / "storage");
        const auto ws = store6.create_workspace("ThreadTestWS", "concurrent test");

        std::atomic<int> success_count{0};
        std::atomic<bool> failed{false};

        auto reader = [&]() {
            try {
                for (int i = 0; i < 20; ++i) {
                    store6.list_workspaces();
                    store6.list_clients();
                    store6.list_events(5);
                }
                ++success_count;
            } catch (...) {
                failed = true;
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(4);
        for (int i = 0; i < 4; ++i) threads.emplace_back(reader);
        for (auto& t : threads) t.join();

        check(!failed.load(), "CP1-T6: Concurrent read threads complete without exception");
        check(success_count.load() == 4, "CP1-T6: All 4 concurrent reader threads succeeded");
        check(store6.live_statement_count() == 0,
              "CP1-T6: No leaked statements after concurrent reads");
        store6.finalize_and_close();
    }


    // CP1-T7: Shutdown During an Active Operation
    {
        fs::remove_all(test_dir / "t7");
        fs::create_directories(test_dir / "t7");
        CollabStore store7(test_dir / "t7" / "t7.sqlite3", test_dir / "t7" / "storage");
        const auto ws = store7.create_workspace("T7_WS", "shutdown barrier test");

        std::promise<void> worker_admitted_promise;
        auto worker_admitted_future = worker_admitted_promise.get_future();

        std::promise<void> release_worker_promise;
        auto release_worker_future = release_worker_promise.get_future().share();

        std::promise<void> shutdown_initiated_promise;
        auto shutdown_initiated_future = shutdown_initiated_promise.get_future();

        std::atomic<bool> worker_completed{false};
        std::atomic<bool> worker_success{false};

        // Worker thread starts an operation and pauses inside OperationGuard
        std::thread worker([&]() {
            try {
                store7.execute_with_operation_guard([&]() {
                    // Signal barrier that worker is admitted inside OperationGuard
                    worker_admitted_promise.set_value();

                    // Pause inside the operation until release signal
                    release_worker_future.wait();

                    // Perform a nested operation while admitted
                    const auto u = store7.find_user_by_username("host");
                    if (u.has_value()) {
                        worker_success = true;
                    }
                });
                worker_completed = true;
            } catch (...) {
                worker_completed = false;
            }
        });

        // Main thread waits deterministically for worker to be admitted
        worker_admitted_future.wait();
        check(store7.active_operations_count() == 1,
              "CP1-T7: active_ops_ is 1 while worker is paused inside OperationGuard");

        // Shutdown thread initiates finalize_and_close()
        FinalizeResult close_result = FinalizeResult::ALREADY_FINALIZED;
        std::atomic<bool> close_completed{false};

        std::thread shutdown_thread([&]() {
            shutdown_initiated_promise.set_value();
            close_result = store7.finalize_and_close();
            close_completed = true;
        });

        // Wait until finalize_and_close() thread has been started
        shutdown_initiated_future.wait();

        // Wait until shutting_down_ flag is set (store has entered shutdown drain phase)
        while (!store7.is_shutting_down()) {
            std::this_thread::yield();
        }

        check(store7.is_shutting_down(), "CP1-T7: store is marked shutting_down");
        check(!close_completed.load(),
              "CP1-T7: finalize_and_close() is blocked waiting for active operation to drain");
        check(store7.active_operations_count() == 1,
              "CP1-T7: active_ops_ remains 1 while worker is in-flight");

        // Confirm new operations are rejected during shutdown drain
        bool new_db_op_rejected = false;
        try {
            store7.find_user_by_username("host");
        } catch (const std::runtime_error&) {
            new_db_op_rejected = true;
        }
        check(new_db_op_rejected,
              "CP1-T7: new database operation is rejected while drain is in progress");

        bool new_fs_op_rejected = false;
        try {
            store7.list_working_copy_files(ws.id);
        } catch (const std::runtime_error&) {
            new_fs_op_rejected = true;
        }
        check(new_fs_op_rejected,
              "CP1-T7: new filesystem operation is rejected while drain is in progress");

        // Release the worker to let it finish
        release_worker_promise.set_value();

        // Worker must complete successfully
        worker.join();
        check(worker_completed.load(), "CP1-T7: worker thread finished without exception");
        check(worker_success.load(), "CP1-T7: worker successfully completed its operation");

        // Shutdown thread must now unblock and complete
        shutdown_thread.join();
        check(close_completed.load(), "CP1-T7: finalize_and_close() completed after worker drained");
        check(close_result == FinalizeResult::OK || close_result == FinalizeResult::CHECKPOINT_FAILED,
              "CP1-T7: finalize_and_close() succeeded");
        check(store7.is_finalized(), "CP1-T7: store is marked finalized");
        check(store7.active_operations_count() == 0, "CP1-T7: active_ops_ is 0 after finalize");

        // Confirm all 6 public filesystem operations are rejected after finalization
        bool all_fs_rejected = true;
        try { store7.list_working_copy_files(ws.id); all_fs_rejected = false; } catch (const std::runtime_error&) {}
        try { store7.read_working_copy_file_content(ws.id, "file.txt"); all_fs_rejected = false; } catch (const std::runtime_error&) {}
        try { store7.write_working_copy_file_content(ws.id, "file.txt", "data"); all_fs_rejected = false; } catch (const std::runtime_error&) {}
        try { store7.delete_working_copy_file(ws.id, "file.txt"); all_fs_rejected = false; } catch (const std::runtime_error&) {}
        try { store7.compute_working_copy_diff(ws.id); all_fs_rejected = false; } catch (const std::runtime_error&) {}
        try { store7.compute_file_diff(ws.id, "file.txt"); all_fs_rejected = false; } catch (const std::runtime_error&) {}

        check(all_fs_rejected,
              "CP1-T7: all 6 public filesystem operations rejected after finalization");
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(test_dir, ec);
}



void run_collab_store_workspace_locking_tests(const fs::path& fixture_root,
                                             void (*check)(bool, const char*)) {
    const auto test_dir = fixture_root / "collab_ws_locking_suite";
    std::error_code ec;
    fs::remove_all(test_dir, ec);
    fs::create_directories(test_dir, ec);

    // CP2-T1: Serialization of same-workspace operations
    {
        const auto suite_dir = test_dir / "t1";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t1.sqlite3", suite_dir / "storage");
        const auto ws = store.create_workspace("WS_CP2_T1", "serialization test");

        std::promise<void> t1_holding_lock_promise;
        auto t1_holding_lock_future = t1_holding_lock_promise.get_future();

        std::promise<void> t1_release_promise;
        auto t1_release_future = t1_release_promise.get_future().share();

        std::atomic<bool> t1_in_critical{false};
        std::atomic<bool> t2_entered_while_t1_active{false};
        std::atomic<bool> t1_completed{false};
        std::atomic<bool> t2_completed{false};

        // Thread 1 acquires ws lock via execute_with_workspace_lock and holds it
        std::thread t1([&]() {
            store.execute_with_workspace_lock(ws.id, [&]() {
                t1_in_critical.store(true);
                t1_holding_lock_promise.set_value();
                t1_release_future.wait();
                if (t2_entered_while_t1_active.load()) {
                    // Violation
                }
                t1_in_critical.store(false);
            });
            t1_completed.store(true);
        });

        t1_holding_lock_future.wait();
        check(t1_in_critical.load(), "CP2-T1: Thread 1 has acquired workspace lock");

        // Thread 2 attempts to write to the same workspace working copy
        std::thread t2([&]() {
            if (t1_in_critical.load()) {
                // If t2 somehow executed inside before acquiring lock, flag it
            }
            // write_working_copy_file_content must acquire the same workspace lock
            store.write_working_copy_file_content(ws.id, "serialized.txt", "thread2_content");
            if (t1_in_critical.load()) {
                t2_entered_while_t1_active.store(true);
            }
            t2_completed.store(true);
        });

        // Sleep briefly to give Thread 2 time to block on the workspace mutex
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        check(!t2_completed.load(), "CP2-T1: Thread 2 is blocked waiting for workspace lock held by Thread 1");
        check(!t2_entered_while_t1_active.load(), "CP2-T1: Thread 2 did not enter critical section while Thread 1 held lock");

        // Now release Thread 1
        t1_release_promise.set_value();
        t1.join();
        t2.join();

        check(t1_completed.load(), "CP2-T1: Thread 1 completed successfully");
        check(t2_completed.load(), "CP2-T1: Thread 2 completed after Thread 1 released workspace lock");
        check(store.read_working_copy_file_content(ws.id, "serialized.txt") == "thread2_content",
              "CP2-T1: Thread 2 wrote content successfully after lock transfer");

        store.finalize_and_close();
    }

    // CP2-T2: Concurrency across different workspaces
    {
        const auto suite_dir = test_dir / "t2";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t2.sqlite3", suite_dir / "storage");
        const auto wsA = store.create_workspace("WS_CP2_T2_A", "concurrency test A");
        const auto wsB = store.create_workspace("WS_CP2_T2_B", "concurrency test B");

        std::promise<void> tA_holding_promise;
        auto tA_holding_future = tA_holding_promise.get_future();

        std::promise<void> tB_holding_promise;
        auto tB_holding_future = tB_holding_promise.get_future();

        std::promise<void> release_both_promise;
        auto release_both_future = release_both_promise.get_future().share();

        std::atomic<bool> tA_in_critical{false};
        std::atomic<bool> tB_in_critical{false};
        std::atomic<bool> both_held_concurrently{false};

        std::thread tA([&]() {
            store.execute_with_workspace_lock(wsA.id, [&]() {
                tA_in_critical.store(true);
                tA_holding_promise.set_value();
                release_both_future.wait();
                tA_in_critical.store(false);
            });
        });

        // Wait for Thread A to hold wsA lock
        tA_holding_future.wait();
        check(tA_in_critical.load(), "CP2-T2: Thread A holds workspace lock for Workspace A");

        // Thread B acquires wsB lock while Thread A is STILL holding wsA lock
        std::thread tB([&]() {
            store.execute_with_workspace_lock(wsB.id, [&]() {
                tB_in_critical.store(true);
                if (tA_in_critical.load()) {
                    both_held_concurrently.store(true);
                }
                tB_holding_promise.set_value();
                release_both_future.wait();
                tB_in_critical.store(false);
            });
        });

        // Wait for Thread B to acquire wsB lock (should not block on Thread A)
        auto status = tB_holding_future.wait_for(std::chrono::seconds(2));
        check(status == std::future_status::ready, "CP2-T2: Thread B acquired lock for Workspace B without blocking on A");
        check(both_held_concurrently.load(), "CP2-T2: Operations on different workspaces run concurrently");

        release_both_promise.set_value();
        tA.join();
        tB.join();

        store.finalize_and_close();
    }

    // CP2-T3: Reader consistency during compound operation
    {
        const auto suite_dir = test_dir / "t3";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t3.sqlite3", suite_dir / "storage");
        const auto ws = store.create_workspace("WS_CP2_T3", "reader consistency test");
        store.write_working_copy_file_content(ws.id, "data.txt", "v1_content");

        std::promise<void> writer_holding_promise;
        auto writer_holding_future = writer_holding_promise.get_future();

        std::promise<void> release_writer_promise;
        auto release_writer_future = release_writer_promise.get_future().share();

        std::atomic<bool> writer_active{false};
        std::atomic<bool> reader_finished{false};
        std::string reader_observed_content;

        // Thread 1 simulates compound mutation holding the workspace lock
        std::thread writer([&]() {
            store.execute_with_workspace_lock(ws.id, [&]() {
                writer_active.store(true);
                writer_holding_promise.set_value();
                release_writer_future.wait();
                // Perform FS update directly inside the lock
                const auto wc_path = suite_dir / "storage" / "workspaces" / ws.id / "working_copy" / "data.txt";
                std::ofstream f(wc_path, std::ios::binary | std::ios::trunc);
                f << "v2_committed_content";
                f.close();
                writer_active.store(false);
            });
        });

        writer_holding_future.wait();
        check(writer_active.load(), "CP2-T3: Compound operation holds workspace lock");

        // Thread 2 performs reader operation (read_working_copy_file_content)
        // Under CP2 reader consistency, it must acquire ws_lock and will block until writer completes
        std::thread reader([&]() {
            reader_observed_content = store.read_working_copy_file_content(ws.id, "data.txt");
            reader_finished.store(true);
        });

        // Give reader thread time to attempt acquisition
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        check(!reader_finished.load(), "CP2-T3: Reader is blocked while compound operation holds workspace lock");

        // Release writer
        release_writer_promise.set_value();
        writer.join();
        reader.join();

        check(reader_finished.load(), "CP2-T3: Reader unblocked after compound operation completed");
        check(reader_observed_content == "v2_committed_content",
              "CP2-T3: Reader observed consistent committed state (no torn/stale read)");

        // Also test list_submissions reader consistency
        const auto subs = store.list_submissions(ws.id);
        check(subs.empty(), "CP2-T3: list_submissions completes consistently under workspace lock");

        store.finalize_and_close();
    }

    // CP2-T4: Concurrent read/write data integrity on working copy
    {
        const auto suite_dir = test_dir / "t4";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t4.sqlite3", suite_dir / "storage");
        const auto ws = store.create_workspace("WS_CP2_T4", "data integrity test");

        std::atomic<bool> stop_flag{false};
        std::atomic<bool> corruption_detected{false};
        std::atomic<int> writes_completed{0};
        std::atomic<int> reads_completed{0};

        // Writer thread 1: writes to fileA.txt
        std::thread writer1([&]() {
            for (int i = 0; i < 50; ++i) {
                std::string payload = "HEADER_A_" + std::to_string(i) + "_TRAILER_AAAAAAAAAA";
                store.write_working_copy_file_content(ws.id, "fileA.txt", payload);
                writes_completed.fetch_add(1);
            }
        });

        // Writer thread 2: writes to fileB.txt
        std::thread writer2([&]() {
            for (int i = 0; i < 50; ++i) {
                std::string payload = "HEADER_B_" + std::to_string(i) + "_TRAILER_BBBBBBBBBB";
                store.write_working_copy_file_content(ws.id, "fileB.txt", payload);
                writes_completed.fetch_add(1);
            }
        });

        // Reader thread: reads fileA.txt and validates integrity
        std::thread reader1([&]() {
            while (!stop_flag.load()) {
                try {
                    const auto content = store.read_working_copy_file_content(ws.id, "fileA.txt");
                    if (!content.empty()) {
                        if (content.rfind("HEADER_A_", 0) != 0 || content.find("_TRAILER_AAAAAAAAAA") == std::string::npos) {
                            corruption_detected.store(true);
                        }
                    }
                    reads_completed.fetch_add(1);
                } catch (...) {
                    corruption_detected.store(true);
                }
                std::this_thread::yield();
            }
        });

        // Reader thread 2: performs diffs and file listings
        std::thread reader2([&]() {
            while (!stop_flag.load()) {
                try {
                    store.list_working_copy_files(ws.id);
                    store.compute_working_copy_diff(ws.id);
                    reads_completed.fetch_add(1);
                } catch (...) {
                    corruption_detected.store(true);
                }
                std::this_thread::yield();
            }
        });

        writer1.join();
        writer2.join();
        stop_flag.store(true);
        reader1.join();
        reader2.join();

        check(!corruption_detected.load(), "CP2-T4: Concurrent reads and writes produced no corruption or torn reads");
        check(writes_completed.load() == 100, "CP2-T4: All 100 writes completed successfully");
        check(reads_completed.load() > 0, "CP2-T4: Concurrent reader executed without deadlock");

        store.finalize_and_close();
    }

    // CP2-T5: Shutdown drain waiting on workspace locks
    {
        const auto suite_dir = test_dir / "t5";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t5.sqlite3", suite_dir / "storage");
        const auto ws = store.create_workspace("WS_CP2_T5", "shutdown drain ws test");

        std::promise<void> op_entered_promise;
        auto op_entered_future = op_entered_promise.get_future();

        std::promise<void> release_op_promise;
        auto release_op_future = release_op_promise.get_future().share();

        std::atomic<bool> op_active{false};
        std::atomic<bool> finalize_done{false};
        FinalizeResult fin_res = FinalizeResult::CHECKPOINT_FAILED;

        std::thread worker([&]() {
            store.execute_with_workspace_lock(ws.id, [&]() {
                op_active.store(true);
                op_entered_promise.set_value();
                release_op_future.wait();
                op_active.store(false);
            });
        });

        op_entered_future.wait();
        check(op_active.load(), "CP2-T5: Operation holding workspace lock is active");

        std::thread shutdown_thread([&]() {
            fin_res = store.finalize_and_close();
            finalize_done.store(true);
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        check(store.is_shutting_down(), "CP2-T5: Store is shutting_down");
        check(!finalize_done.load(), "CP2-T5: finalize_and_close() is blocked waiting for workspace operation to drain");
        check(store.active_operations_count() == 1, "CP2-T5: active_ops_ is 1 during workspace lock execution");

        // Release worker
        release_op_promise.set_value();
        worker.join();
        shutdown_thread.join();

        check(finalize_done.load(), "CP2-T5: finalize_and_close() completed after workspace operation finished");
        check(fin_res == FinalizeResult::OK || fin_res == FinalizeResult::CHECKPOINT_FAILED,
              "CP2-T5: finalize_and_close() returned success");
        check(store.is_finalized(), "CP2-T5: Store is marked finalized");
    }

    // CP2-T6: Multi-workspace concurrent stress test (zero deadlocks, zero statement leaks)
    {
        const auto suite_dir = test_dir / "t6";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t6.sqlite3", suite_dir / "storage");

        std::vector<CollabWorkspace> workspaces;
        for (int i = 0; i < 4; ++i) {
            workspaces.push_back(store.create_workspace("StressWS_" + std::to_string(i), "stress test ws"));
            store.write_working_copy_file_content(workspaces.back().id, "init.txt", "initial content");
        }

        std::atomic<bool> stress_failed{false};
        std::atomic<int> stress_ops_completed{0};
        const int num_threads = 8;
        const int iters_per_thread = 25;

        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        for (int tid = 0; tid < num_threads; ++tid) {
            threads.emplace_back([&, tid]() {
                try {
                    for (int iter = 0; iter < iters_per_thread; ++iter) {
                        const auto& ws = workspaces[static_cast<size_t>((tid + iter) % 4)];
                        const std::string filename = "file_" + std::to_string(tid) + ".txt";
                        const std::string payload = "tid_" + std::to_string(tid) + "_iter_" + std::to_string(iter);

                        // Filesystem write
                        store.write_working_copy_file_content(ws.id, filename, payload);

                        // Filesystem read
                        const auto read_back = store.read_working_copy_file_content(ws.id, filename);
                        if (read_back != payload) {
                            stress_failed.store(true);
                        }

                        // Filesystem diff & listing
                        store.list_working_copy_files(ws.id);
                        store.compute_working_copy_diff(ws.id);

                        // Reader consistency methods
                        store.list_submissions(ws.id);
                        store.list_published_versions(ws.id);

                        stress_ops_completed.fetch_add(5);
                    }
                } catch (...) {
                    stress_failed.store(true);
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        check(!stress_failed.load(), "CP2-T6: Multi-workspace concurrent stress test completed without exceptions");
        check(stress_ops_completed.load() == num_threads * iters_per_thread * 5,
              "CP2-T6: All stress test operations completed successfully");
        check(store.live_statement_count() == 0,
              "CP2-T6: live_statement_count() is 0 after stress test (no leaked statements)");

        const auto fin = store.finalize_and_close();
        check(fin == FinalizeResult::OK || fin == FinalizeResult::CHECKPOINT_FAILED,
              "CP2-T6: finalize_and_close() succeeded cleanly after stress test");
    }

    // Cleanup
    fs::remove_all(test_dir, ec);
}


// =============================================================================
// Phase 2: Transaction Journaling, Exclusive Sentinels & Crash Recovery Tests
// =============================================================================
void run_collab_store_phase2_recovery_tests(const fs::path& fixture_root,
                                            void (*check)(bool, const char*)) {
    const auto test_dir = fixture_root / "collab_phase2_recovery_suite";
    std::error_code ec;
    fs::remove_all(test_dir, ec);
    fs::create_directories(test_dir, ec);

    // =========================================================================
    // CP2-T7: Production Compound Operation with Concurrent Reader
    // =========================================================================
    {
        const auto suite_dir = test_dir / "cp2_t7";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "t7.sqlite3", suite_dir / "storage");
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("client_t7", "Pass123!", "client", {"submit"});
        const auto ws = store.create_workspace("WS_CP2_T7", "compound concurrent reader test");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto client_src = suite_dir / "client_src";
        fs::create_directories(client_src, ec);
        {
            std::ofstream(client_src / "doc1.txt") << "content 1";
            std::ofstream(client_src / "doc2.txt") << "content 2";
            std::ofstream(client_src / "doc3.txt") << "content 3";
        }
        const auto sub = store.create_submission(client.id, ws.id, client_src);

        std::atomic<bool> reader_running{true};
        std::atomic<bool> torn_observed{false};
        std::atomic<int> reader_iterations{0};

        std::thread reader_thread([&]() {
            while (reader_running.load()) {
                try {
                    const auto subs = store.list_submissions(ws.id);
                    const auto files = store.list_working_copy_files(ws.id);
                    if (!subs.empty() && subs[0].status == "accepted") {
                        // Invariant: once accepted, working copy must be complete (3 files) and match
                        if (files.size() != 3) {
                            torn_observed.store(true);
                        }
                        const auto c1 = store.read_working_copy_file_content(ws.id, "doc1.txt");
                        if (c1 != "content 1") {
                            torn_observed.store(true);
                        }
                    }
                    reader_iterations.fetch_add(1);
                    std::this_thread::yield();
                } catch (...) {
                }
            }
        });

        // Main thread executes compound accept_submission
        const bool accept_ok = store.accept_submission(sub.id, host->id, "Accepted in CP2-T7");
        reader_running.store(false);
        reader_thread.join();

        check(accept_ok, "CP2-T7: accept_submission succeeded under concurrent reader");
        check(!torn_observed.load(), "CP2-T7: Concurrent reader never observed torn state");
        check(reader_iterations.load() > 0, "CP2-T7: Reader executed concurrent iterations successfully");

        const auto fin = store.finalize_and_close();
        check(fin == FinalizeResult::OK || fin == FinalizeResult::CHECKPOINT_FAILED,
              "CP2-T7: finalize_and_close() succeeded cleanly");
    }

    // =========================================================================
    // OWN-T1..T5: Ownership Verification & Sentinel Checks
    // =========================================================================
    {
        const auto suite_dir = test_dir / "own_suite";
        fs::create_directories(suite_dir, ec);
        CollabStore store(suite_dir / "own.sqlite3", suite_dir / "storage");
        const auto ws = store.create_workspace("WS_OWN", "ownership test");
        const auto ws_dir = suite_dir / "storage" / "workspaces" / ws.id;

        // OWN-T1: Pre-existing sentinel prevents creation
        const auto test_preexist_dir = suite_dir / "preexist_dir";
        fs::create_directories(test_preexist_dir, ec);
        {
            std::ofstream(test_preexist_dir / ".syncora_op_sentinel") << "dummy sentinel";
        }
        const bool own_t1_created = store.test_create_sentinel_file(
            test_preexist_dir, "op_test", ws.id, "ACCEPT_SUBMISSION", "staging_base");
        check(!own_t1_created, "OWN-T1: Exclusive sentinel creation fails if sentinel already exists");

        // OWN-T2: Mismatched op_id in sentinel causes quarantine during recovery
        const auto suspect_dir_t2 = ws_dir / ".backup_base_op_t2_1111";
        fs::create_directories(suspect_dir_t2, ec);
        {
            std::ofstream f(suspect_dir_t2 / ".syncora_op_sentinel");
            f << "op_id=WRONG_OP_ID\n";
            f << "workspace_id=" << ws.id << "\n";
            f << "op_type=PUBLISH_VERSION\n";
            f << "dir_role=backup_base\n";
            f << "created_at_ms=1000\n";
        }
        store.recover_incomplete_operations();
        check(!fs::exists(suspect_dir_t2), "OWN-T2: Suspect directory removed from active path");
        check(fs::exists(ws_dir / ".quarantine"), "OWN-T2: Suspect directory moved to .quarantine");

        // OWN-T3: Mismatched workspace_id in sentinel causes quarantine
        const auto suspect_dir_t3 = ws_dir / ".staging_base_op_t3_2222";
        fs::create_directories(suspect_dir_t3, ec);
        {
            std::ofstream f(suspect_dir_t3 / ".syncora_op_sentinel");
            f << "op_id=op_t3_2222\n";
            f << "workspace_id=FOREIGN_WS_ID\n";
            f << "op_type=ACCEPT_SUBMISSION\n";
            f << "dir_role=staging_base\n";
            f << "created_at_ms=2000\n";
        }
        store.recover_incomplete_operations();
        check(!fs::exists(suspect_dir_t3), "OWN-T3: Suspect directory removed from active path");
        check(fs::exists(ws_dir / ".quarantine"), "OWN-T3: Foreign workspace sentinel quarantined");

        // OWN-T4: Mismatched dir_role in sentinel causes quarantine
        const auto suspect_dir_t4 = ws_dir / ".backup_work_op_t4_3333";
        fs::create_directories(suspect_dir_t4, ec);
        {
            std::ofstream f(suspect_dir_t4 / ".syncora_op_sentinel");
            f << "op_id=op_t4_3333\n";
            f << "workspace_id=" << ws.id << "\n";
            f << "op_type=ACCEPT_SUBMISSION\n";
            f << "dir_role=WRONG_ROLE\n";
            f << "created_at_ms=3000\n";
        }
        store.recover_incomplete_operations();
        check(!fs::exists(suspect_dir_t4), "OWN-T4: Suspect directory removed from active path");
        check(fs::exists(ws_dir / ".quarantine"), "OWN-T4: Invalid dir_role sentinel quarantined");

        // OWN-T5: Reparse-point / junction detection
        check(!is_reparse_point_or_symlink(ws_dir), "OWN-T5: Normal workspace directory is not a reparse point");
        check(!is_reparse_point_or_symlink(suite_dir / "non_existent_path"),
              "OWN-T5: Non-existent path returns false for reparse point check");

        store.finalize_and_close();
    }

    // =========================================================================
    // INIT-T1..T4: Initial Publication Recovery
    // =========================================================================
    {
        const auto suite_dir = test_dir / "init_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "init.sqlite3";
        const auto store_dir = suite_dir / "storage";

        std::string ws_id;
        // INIT-T1 & INIT-T2: Crash at FailAfterSnapshotPromotion (PUB-02)
        {
            CollabStore store(db_path, store_dir);
            const auto host = store.find_user_by_username("host");
            const auto ws = store.create_workspace("WS_INIT_TEST", "Initial publication recovery");
            ws_id = ws.id;

            store.write_working_copy_file_content(ws.id, "init_file.txt", "Initial file data");
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterSnapshotPromotion);

            bool injected_thrown = false;
            try {
                store.publish_version(ws.id, host->id, "Initial v1", "First commit notes");
            } catch (const CollabFaultPointInjected&) {
                injected_thrown = true;
            }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(injected_thrown, "INIT-T1: Fault point triggered during initial publication");

            const auto ops = store.list_workspace_operations(ws.id);
            check(!ops.empty(), "INIT-T1: Journal record exists for interrupted publication");
            check(ops[0].expected_base_hash == "INITIAL",
                  "INIT-T1: Initial publication records INITIAL expected_base_hash");
            check(ops[0].state == "FAILED" || ops[0].state == "PENDING" || ops[0].state == "STAGED",
                  "INIT-T1: Interrupted operation state is recorded in journal");
        }

        // INIT-T2: Reopen store triggers recovery
        {
            CollabStore store(db_path, store_dir);
            const auto ops = store.list_workspace_operations(ws_id);
            check(!ops.empty(), "INIT-T2: Operation history preserved after recovery");
            check(ops[0].state == "FAILED", "INIT-T2: Incomplete initial publish marked FAILED");

            const auto vers = store.list_published_versions(ws_id);
            check(vers.empty(), "INIT-T2: No version record exists for failed initial publish");

            const auto base_manifest = scan_folder(store_dir / "workspaces" / ws_id / "baseline");
            check(base_manifest.files.empty(), "INIT-T2: Baseline remains empty after failed initial publish");

            const auto work_content = store.read_working_copy_file_content(ws_id, "init_file.txt");
            check(work_content == "Initial file data", "INIT-T2: Working copy remains intact");
        }

        // INIT-T3: Crash at FailAfterBaselinePromotion (PUB-06)
        {
            CollabStore store(db_path, store_dir);
            const auto host = store.find_user_by_username("host");
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBaselinePromotion);

            bool injected_thrown = false;
            try {
                store.publish_version(ws_id, host->id, "Initial v1 retry", "Retry notes");
            } catch (const CollabFaultPointInjected&) {
                injected_thrown = true;
            }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(injected_thrown, "INIT-T3: Fault point triggered after baseline promotion");
        }

        // Reopen store to trigger recovery after baseline promotion crash
        {
            CollabStore store(db_path, store_dir);
            const auto vers = store.list_published_versions(ws_id);
            check(vers.empty(), "INIT-T3: Uncommitted version is not published");

            const auto base_manifest = scan_folder(store_dir / "workspaces" / ws_id / "baseline");
            check(base_manifest.files.empty(),
                  "INIT-T3: Baseline restored to empty initial state from INITIAL backup");

            const auto work_content = store.read_working_copy_file_content(ws_id, "init_file.txt");
            check(work_content == "Initial file data", "INIT-T3: Working copy untouched");
        }

        // INIT-T4: Happy path initial publish
        {
            CollabStore store(db_path, store_dir);
            const auto host = store.find_user_by_username("host");
            const auto v1 = store.publish_version(ws_id, host->id, "Release 1.0", "Clean publication");
            check(!v1.id.empty(), "INIT-T4: Initial version published successfully");
            check(v1.file_count == 1, "INIT-T4: Version contains 1 file");

            const auto ops = store.list_workspace_operations(ws_id);
            check(!ops.empty() && ops.front().state == "COMMITTED",
                  "INIT-T4: Publication operation marked COMMITTED");

            const auto base_manifest = scan_folder(store_dir / "workspaces" / ws_id / "baseline");
            check(base_manifest.files.size() == 1, "INIT-T4: Baseline contains published file");

            store.finalize_and_close();
        }
    }

    // =========================================================================
    // SUB-T1..T4: accept_submission() Crash Failpoints & Recovery
    // =========================================================================
    {
        const auto suite_dir = test_dir / "sub_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "sub.sqlite3";
        const auto store_dir = suite_dir / "storage";

        std::string ws_id;
        std::string sub1_id, sub2_id, sub3_id, sub4_id;

        // Setup base workspace and initial accepted submission
        {
            CollabStore store(db_path, store_dir);
            const auto host = store.find_user_by_username("host");
            const auto client = store.create_user("client_sub", "Pass123!", "client", {"submit"});
            const auto ws = store.create_workspace("WS_SUB_TEST", "submission crash recovery test");
            ws_id = ws.id;
            store.assign_user_to_workspace(ws.id, client.id);

            const auto src_initial = suite_dir / "src_initial";
            fs::create_directories(src_initial, ec);
            std::ofstream(src_initial / "base.txt") << "base version 0";
            const auto sub0 = store.create_submission(client.id, ws.id, src_initial);
            store.accept_submission(sub0.id, host->id, "Accept sub0");

            // SUB-T1: FailAfterStaging
            const auto src_sub1 = suite_dir / "src_sub1";
            fs::create_directories(src_sub1, ec);
            std::ofstream(src_sub1 / "sub1.txt") << "sub1 data";
            const auto sub1 = store.create_submission(client.id, ws.id, src_sub1);
            sub1_id = sub1.id;

            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterStaging);
            const bool ok1 = store.accept_submission(sub1.id, host->id, "Accept sub1 fail staging");
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(!ok1, "SUB-T1: Fault point triggered after staging (accept_submission returned false)");
        }

        // Reopen store to recover from SUB-T1
        {
            CollabStore store(db_path, store_dir);
            const auto sub1_rec = store.find_submission_by_id(sub1_id);
            check(sub1_rec.has_value() && sub1_rec->status == "pending",
                  "SUB-T1: Submission remains pending after staging crash recovery");
            check(store.read_working_copy_file_content(ws_id, "base.txt") == "base version 0",
                  "SUB-T1: Baseline and working copy untouched after staging crash");

            // SUB-T2: FailAfterBackup
            const auto host = store.find_user_by_username("host");
            const auto client = store.find_user_by_username("client_sub");
            const auto src_sub2 = suite_dir / "src_sub2";
            fs::create_directories(src_sub2, ec);
            std::ofstream(src_sub2 / "sub2.txt") << "sub2 data";
            const auto sub2 = store.create_submission(client->id, ws_id, src_sub2);
            sub2_id = sub2.id;

            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBackup);
            const bool ok2 = store.accept_submission(sub2.id, host->id, "Accept sub2 fail backup");
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(!ok2, "SUB-T2: Fault point triggered after backup (accept_submission returned false)");
        }

        // Reopen store to recover from SUB-T2
        {
            CollabStore store(db_path, store_dir);
            const auto sub2_rec = store.find_submission_by_id(sub2_id);
            check(sub2_rec.has_value() && sub2_rec->status == "pending",
                  "SUB-T2: Submission remains pending after backup crash recovery");
            check(store.read_working_copy_file_content(ws_id, "base.txt") == "base version 0",
                  "SUB-T2: Working copy restored from verified backup");

            // SUB-T3: FailAfterBaselinePromotion
            const auto host = store.find_user_by_username("host");
            const auto client = store.find_user_by_username("client_sub");
            const auto src_sub3 = suite_dir / "src_sub3";
            fs::create_directories(src_sub3, ec);
            std::ofstream(src_sub3 / "sub3.txt") << "sub3 data";
            const auto sub3 = store.create_submission(client->id, ws_id, src_sub3);
            sub3_id = sub3.id;

            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBaselinePromotion);
            const bool ok3 = store.accept_submission(sub3.id, host->id, "Accept sub3 fail baseline promo");
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(!ok3, "SUB-T3: Fault point triggered after baseline promotion (accept_submission returned false)");
        }

        // Reopen store to recover from SUB-T3
        {
            CollabStore store(db_path, store_dir);
            const auto sub3_rec = store.find_submission_by_id(sub3_id);
            check(sub3_rec.has_value() && sub3_rec->status == "pending",
                  "SUB-T3: Submission remains pending after baseline promotion crash recovery");
            check(store.read_working_copy_file_content(ws_id, "base.txt") == "base version 0",
                  "SUB-T3: Baseline restored from backup after uncommitted baseline promotion");

            // SUB-T4: FailAfterCommit
            const auto host = store.find_user_by_username("host");
            const auto client = store.find_user_by_username("client_sub");
            const auto src_sub4 = suite_dir / "src_sub4";
            fs::create_directories(src_sub4, ec);
            std::ofstream(src_sub4 / "sub4.txt") << "sub4 data";
            const auto sub4 = store.create_submission(client->id, ws_id, src_sub4);
            sub4_id = sub4.id;

            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterCommit);
            const bool ok4 = store.accept_submission(sub4.id, host->id, "Accept sub4 fail after commit");
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(!ok4, "SUB-T4: Fault point triggered after commit (accept_submission returned false)");
        }

        // Reopen store to recover from SUB-T4
        {
            CollabStore store(db_path, store_dir);
            const auto sub4_rec = store.find_submission_by_id(sub4_id);
            check(sub4_rec.has_value() && sub4_rec->status == "accepted",
                  "SUB-T4: Committed submission preserved during post-commit recovery");
            check(store.read_working_copy_file_content(ws_id, "sub4.txt") == "sub4 data",
                  "SUB-T4: Accepted content active in working copy");

            store.finalize_and_close();
        }
    }

    // =========================================================================
    // PUB-T1..T4: Subsequent Publication Crash Failpoints & Recovery
    // =========================================================================
    {
        const auto suite_dir = test_dir / "pub_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "pub.sqlite3";
        const auto store_dir = suite_dir / "storage";

        std::string ws_id;
        std::string v1_root;

        // Setup workspace and publish version 1
        {
            CollabStore store(db_path, store_dir);
            const auto host = store.find_user_by_username("host");
            const auto ws = store.create_workspace("WS_PUB_TEST", "subsequent publication test");
            ws_id = ws.id;

            store.write_working_copy_file_content(ws.id, "main.cpp", "int main() { return 0; }");
            const auto v1 = store.publish_version(ws.id, host->id, "v1.0", "First version");
            v1_root = v1.merkle_root;

            // PUB-T1: FailAfterSnapshotPromotion
            store.write_working_copy_file_content(ws.id, "main.cpp", "int main() { return 1; }");
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterSnapshotPromotion);

            bool inj1 = false;
            try {
                store.publish_version(ws.id, host->id, "v2.0-fail-snap", "Fail at snapshot promo");
            } catch (const CollabFaultPointInjected&) { inj1 = true; }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(inj1, "PUB-T1: Fault point triggered after snapshot promotion");
        }

        // Reopen store to recover from PUB-T1
        {
            CollabStore store(db_path, store_dir);
            const auto vers = store.list_published_versions(ws_id);
            check(vers.size() == 1, "PUB-T1: Only v1 published; uncommitted snapshot cleaned up");
            const auto base_manifest = scan_folder(store_dir / "workspaces" / ws_id / "baseline");
            check(base_manifest.merkle_root == v1_root, "PUB-T1: Baseline matches v1 root");

            // PUB-T2: FailAfterBackup
            const auto host = store.find_user_by_username("host");
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBackup);

            bool inj2 = false;
            try {
                store.publish_version(ws_id, host->id, "v2.0-fail-backup", "Fail at backup");
            } catch (const CollabFaultPointInjected&) { inj2 = true; }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(inj2, "PUB-T2: Fault point triggered after backup");
        }

        // Reopen store to recover from PUB-T2
        {
            CollabStore store(db_path, store_dir);
            const auto vers = store.list_published_versions(ws_id);
            check(vers.size() == 1, "PUB-T2: Only v1 published; failed backup rolled back");
            const auto base_manifest = scan_folder(store_dir / "workspaces" / ws_id / "baseline");
            check(base_manifest.merkle_root == v1_root, "PUB-T2: Baseline restored to v1 root from backup");

            // PUB-T3: FailAfterBaselinePromotion
            const auto host = store.find_user_by_username("host");
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBaselinePromotion);

            bool inj3 = false;
            try {
                store.publish_version(ws_id, host->id, "v2.0-fail-base-promo", "Fail at base promo");
            } catch (const CollabFaultPointInjected&) { inj3 = true; }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(inj3, "PUB-T3: Fault point triggered after baseline promotion");
        }

        // Reopen store to recover from PUB-T3
        {
            CollabStore store(db_path, store_dir);
            const auto vers = store.list_published_versions(ws_id);
            check(vers.size() == 1, "PUB-T3: Only v1 published; uncommitted baseline promo rolled back");
            const auto base_manifest = scan_folder(store_dir / "workspaces" / ws_id / "baseline");
            check(base_manifest.merkle_root == v1_root, "PUB-T3: Baseline restored to v1 root");

            // PUB-T4: FailAfterCommit
            const auto host = store.find_user_by_username("host");
            set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterCommit);

            bool inj4 = false;
            try {
                store.publish_version(ws_id, host->id, "v2.0-clean", "Committed release");
            } catch (const CollabFaultPointInjected&) { inj4 = true; }
            set_collab_fault_point_for_testing(CollabFaultPoint::None);
            check(inj4, "PUB-T4: Fault point triggered after commit");
        }

        // Reopen store to recover from PUB-T4
        {
            CollabStore store(db_path, store_dir);
            const auto vers = store.list_published_versions(ws_id);
            check(vers.size() == 2, "PUB-T4: Committed v2 is retained in published versions");
            const auto ops = store.list_workspace_operations(ws_id);
            check(!ops.empty() && ops.front().state == "COMMITTED",
                  "PUB-T4: Operation state is COMMITTED");

            store.finalize_and_close();
        }
    }

    // =========================================================================
    // MAN-T1..T3: Manifest and Merkle Reconciliation
    // =========================================================================
    {
        const auto suite_dir = test_dir / "man_suite";
        fs::create_directories(suite_dir, ec);

        // MAN-T1: File mtime modification does not change Merkle root
        const auto dir_t1 = suite_dir / "t1_mtime";
        fs::create_directories(dir_t1, ec);
        {
            std::ofstream(dir_t1 / "file1.txt") << "Content of file 1";
            std::ofstream(dir_t1 / "file2.txt") << "Content of file 2";
        }

        const auto manifest_before = scan_folder(dir_t1);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        // Touch last_write_time
        fs::last_write_time(dir_t1 / "file1.txt", fs::file_time_type::clock::now());
        const auto manifest_after = scan_folder(dir_t1);

        check(manifest_before.merkle_root == manifest_after.merkle_root,
              "MAN-T1: Modification time changes do not alter content Merkle root");

        // MAN-T2: Staged copy preserves exact Merkle root
        const auto dir_src = suite_dir / "t2_src";
        const auto dir_staging = suite_dir / "t2_staging";
        fs::create_directories(dir_src / "sub", ec);
        {
            std::ofstream(dir_src / "root.txt") << "root content";
            std::ofstream(dir_src / "sub" / "nested.txt") << "nested content";
        }

        copy_directory_recursive(dir_src, dir_staging);
        check(scan_folder(dir_src).merkle_root == scan_folder(dir_staging).merkle_root,
              "MAN-T2: Staged copy preserves identical Merkle root");

        // MAN-T3: Empty directory has deterministic Merkle root
        const auto dir_empty = suite_dir / "t3_empty";
        fs::create_directories(dir_empty, ec);
        const auto empty_manifest = scan_folder(dir_empty);
        check(empty_manifest.merkle_root == merkle_root({}) && empty_manifest.files.empty(),
              "MAN-T3: Empty directory produces canonical empty Merkle root");
    }

    // =========================================================================
    // FIN-T1..T3: Prepared Statement Registry & Shutdown
    // =========================================================================
    {
        const auto suite_dir = test_dir / "fin_suite";
        fs::create_directories(suite_dir, ec);
        const auto db_path = suite_dir / "fin.sqlite3";
        const auto store_dir = suite_dir / "storage";

        // FIN-T1: Statement registry live_statement_count() == 0 after operations
        {
            CollabStore store(db_path, store_dir);
            const auto ws = store.create_workspace("WS_FIN", "finalize test");
            store.list_workspace_operations(ws.id);
            store.list_submissions(ws.id);
            store.list_published_versions(ws.id);
            check(store.live_statement_count() == 0,
                  "FIN-T1: Statement registry live_statement_count() is 0 after operations");

            // FIN-T2: finalize_and_close() cleans up statements
            const auto fin = store.finalize_and_close();
            check(fin == FinalizeResult::OK || fin == FinalizeResult::CHECKPOINT_FAILED,
                  "FIN-T2: finalize_and_close() returned OK or CHECKPOINT_FAILED");
            check(store.live_statement_count() == 0,
                  "FIN-T2: live_statement_count() is 0 after finalize_and_close()");
        }

        // FIN-T3: Destructor fallback when finalize_and_close() is not explicitly called
        {
            {
                CollabStore store_inner(db_path, store_dir);
                const auto ws = store_inner.create_workspace("WS_INNER", "inner scope test");
                store_inner.write_working_copy_file_content(ws.id, "test.txt", "data");
                // store_inner destructs here without finalize_and_close()
            }
            // Reopen and verify database integrity
            CollabStore store_outer(db_path, store_dir);
            const auto ws_list = store_outer.list_workspaces();
            bool found_inner = false;
            for (const auto& w : ws_list) {
                if (w.name == "WS_INNER") found_inner = true;
            }
            check(found_inner, "FIN-T3: Destructor close fallback preserved database consistency");
            store_outer.finalize_and_close();
        }
    }

    fs::remove_all(test_dir, ec);
}

} // namespace mc
