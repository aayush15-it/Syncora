#include "merklechain/collab_store.hpp"
#include <iostream>
#include <cassert>
#include <fstream>

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

        // 17. Security traversal rejection
        bool caught_traversal = false;
        try {
            store.read_working_copy_file_content(ws.id, "../../../Windows/win.ini");
        } catch (...) {
            caught_traversal = true;
        }
        check(caught_traversal, "Path traversal attempt is strictly rejected by working copy reader");

        // 18. Audit log recording
        const auto events = store.list_events(50);
        check(!events.empty(), "Security audit events are properly recorded and retrieved");
    }

    // Clean up test directory safely after store is closed
    std::error_code ec;
    fs::remove_all(test_dir, ec);
}

} // namespace mc
