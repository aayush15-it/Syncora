#include "cas_tests.hpp"
#include "merklechain/collab_store.hpp"
#include "merklechain/cas/chunker.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/object_verifier.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <random>
#include <sqlite3.h>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace mc::cas {

namespace {

std::uint32_t get_hard_link_count(const mc::fs::path& p) {
#ifdef _WIN32
    HANDLE h = CreateFileW(p.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BY_HANDLE_FILE_INFORMATION info{};
    BOOL ok = GetFileInformationByHandle(h, &info);
    CloseHandle(h);
    return ok ? static_cast<std::uint32_t>(info.nNumberOfLinks) : 0;
#else
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0) return 0;
    return static_cast<std::uint32_t>(st.st_nlink);
#endif
}

std::vector<std::uint8_t> generate_test_data(std::size_t size, std::uint32_t seed) {
    std::vector<std::uint8_t> data(size);
    std::mt19937 rng(seed);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::uint8_t>(rng() & 0xFF);
    }
    return data;
}

void write_test_file(const mc::fs::path& p, const void* data, std::size_t size) {
    mc::fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (size > 0 && data != nullptr) {
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
}

#ifdef _WIN32
DWORD run_collab_child_process(const std::wstring& arguments) {
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size()) return static_cast<DWORD>(-1);
    executable.resize(length);

    std::wstring command = L"\"" + executable + L"\" " + arguments;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        return static_cast<DWORD>(-1);
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = static_cast<DWORD>(-1);
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}
#endif

} // namespace

void run_cas_collab_integration_tests(const mc::fs::path& fixture_root, void (*check)(bool, const char*)) {
    const auto test_dir = fixture_root / "cas_collab_integration_suite";
    std::error_code ec;
    mc::fs::remove_all(test_dir, ec);
    mc::fs::create_directories(test_dir);

    const auto db_path = test_dir / "collab.sqlite3";
    const auto storage_dir = test_dir / "storage";

    std::string ws1_id;
    std::string v1_id;
    std::string v2_id;

    // CAS-INT-01: Submission Acceptance with FastCDC Chunking & Verified Reconstruction
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        check(host.has_value(), "CAS-INT-01: Host account seeded");

        const auto client = store.create_user("cas_client1", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Workspace 1", "Workspace for CAS integration tests");
        ws1_id = ws.id;
        store.assign_user_to_workspace(ws.id, client.id);

        // Prepare client source files
        const auto client_src = test_dir / "client_src_1";
        mc::fs::create_directories(client_src);

        // 1. Text file
        const std::string text_content = "Small text file for testing CAS integration\nSecond line of content\n";
        write_test_file(client_src / "text.txt", text_content.data(), text_content.size());

        // 2. Multi-chunk binary file (~32KB)
        auto bin_data = generate_test_data(32768, 12345);
        write_test_file(client_src / "pattern.bin", bin_data.data(), bin_data.size());

        // 3. Empty file
        write_test_file(client_src / "empty.txt", nullptr, 0);

        const auto sub = store.create_submission(client.id, ws.id, client_src);
        check(sub.file_count == 3 && sub.status == "pending", "CAS-INT-01: Submission created with 3 files");

        const bool accepted = store.accept_submission(sub.id, host->id, "Approved for CAS baseline");
        check(accepted, "CAS-INT-01: accept_submission succeeded via FastCDC chunking and CAS reconstruction");

        const auto working_files = store.list_working_copy_files(ws.id);
        check(working_files.size() == 3, "CAS-INT-01: Working copy contains exactly 3 accepted files");

        // Verify working copy file contents and hard link count
        const auto work_dir = storage_dir / "workspaces" / ws.id / "working_copy";
        check(mc::fs::exists(work_dir / "text.txt"), "CAS-INT-01: text.txt exists in working copy");
        check(mc::fs::exists(work_dir / "pattern.bin"), "CAS-INT-01: pattern.bin exists in working copy");
        check(mc::fs::exists(work_dir / "empty.txt"), "CAS-INT-01: empty.txt exists in working copy");

        check(mc::sha256_file(work_dir / "pattern.bin") == mc::sha256_data(bin_data.data(), bin_data.size()),
              "CAS-INT-01: Reconstructed working copy pattern.bin matches source SHA-256 byte-for-byte");

        check(get_hard_link_count(work_dir / "text.txt") == 1,
              "CAS-INT-01: Reconstructed text.txt is an independent regular file (hard_link_count == 1)");
        check(get_hard_link_count(work_dir / "pattern.bin") == 1,
              "CAS-INT-01: Reconstructed pattern.bin is an independent regular file (hard_link_count == 1)");
    }

    // CAS-INT-02: Version Publication with Manifest Creation and Reference Counting
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        check(host.has_value() && !ws1_id.empty(), "CAS-INT-02: Found existing workspace ws1");

        auto v1 = store.publish_version(ws1_id, host->id, "Release 1.0", "First CAS release");
        v1_id = v1.id;
        check(!v1.id.empty() && v1.file_count == 3, "CAS-INT-02: publish_version succeeded for 3 files");

        std::string err;
        auto manifests = store.get_version_manifests(v1.id, err);
        check(err.empty() && manifests.size() == 3, "CAS-INT-02: get_version_manifests returned 3 deserialized manifests");

        // Verify each chunk has reference_count >= 1 in cas_chunks table
        bool all_chunks_refcounted = true;
        for (const auto& m : manifests) {
            for (const auto& c : m.chunks()) {
                if (store.get_chunk_reference_count(c.hash) == 0) {
                    all_chunks_refcounted = false;
                }
            }
        }
        check(all_chunks_refcounted, "CAS-INT-02: Every manifest chunk is recorded in cas_chunks with reference_count >= 1");

        std::string audit_err;
        const bool audit_ok = store.audit_cas_reference_integrity(audit_err);
        check(audit_ok && audit_err.empty(), "CAS-INT-02: audit_cas_reference_integrity reports zero drift");
    }

    // CAS-INT-03: Multi-Version Deduplication & Incremental Reference Counting
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");

        // Modify working copy: append to text.txt, add new_file.txt, keep pattern.bin and empty.txt unchanged
        const std::string text_v2 = "Small text file for testing CAS integration\nSecond line of content\nThird line added in v2!\n";
        store.write_working_copy_file_content(ws1_id, "text.txt", text_v2);
        store.write_working_copy_file_content(ws1_id, "new_file.txt", "Brand new file in v2");

        auto v2 = store.publish_version(ws1_id, host->id, "Release 2.0", "Incremental release");
        v2_id = v2.id;
        check(!v2.id.empty() && v2.file_count == 4, "CAS-INT-03: publish_version v2 succeeded for 4 files");

        std::string err;
        auto v1_manifests = store.get_version_manifests(v1_id, err);
        auto v2_manifests = store.get_version_manifests(v2_id, err);
        check(v1_manifests.size() == 3 && v2_manifests.size() == 4, "CAS-INT-03: Manifest counts reflect additions");

        // Unmodified chunks from pattern.bin should now have reference_count == 2
        bool dedup_verified = false;
        for (const auto& m : v2_manifests) {
            if (m.total_size() == 32768) {
                if (!m.chunks().empty()) {
                    auto rc = store.get_chunk_reference_count(m.chunks().front().hash);
                    dedup_verified = (rc == 2);
                }
            }
        }
        check(dedup_verified, "CAS-INT-03: Unmodified chunks across v1 and v2 have reference_count == 2");

        std::string audit_err;
        const bool audit_ok = store.audit_cas_reference_integrity(audit_err);
        check(audit_ok && audit_err.empty(), "CAS-INT-03: audit_cas_reference_integrity reports zero drift after v2");
    }

    // CAS-INT-04: Version Reconstruction via reconstruct_version()
    {
        CollabStore store(db_path, storage_dir);

        const auto recon_v1_dir = test_dir / "reconstructed_v1";
        std::string err1;
        const bool ok1 = store.reconstruct_version(v1_id, recon_v1_dir, err1);
        check(ok1 && err1.empty(), "CAS-INT-04: reconstruct_version v1 succeeded");

        auto ver1 = store.find_version_by_id(v1_id);
        check(ver1.has_value(), "CAS-INT-04: Found version 1 metadata");
        const auto scan_v1 = mc::scan_folder(recon_v1_dir);
        check(scan_v1.complete && scan_v1.merkle_root == ver1->merkle_root,
              "CAS-INT-04: Reconstructed v1 folder Merkle root matches published version 1 root");
        check(get_hard_link_count(recon_v1_dir / "text.txt") == 1,
              "CAS-INT-04: Reconstructed v1 file has hard_link_count == 1");

        const auto recon_v2_dir = test_dir / "reconstructed_v2";
        std::string err2;
        const bool ok2 = store.reconstruct_version(v2_id, recon_v2_dir, err2);
        check(ok2 && err2.empty(), "CAS-INT-04: reconstruct_version v2 succeeded");

        auto ver2 = store.find_version_by_id(v2_id);
        check(ver2.has_value(), "CAS-INT-04: Found version 2 metadata");
        const auto scan_v2 = mc::scan_folder(recon_v2_dir);
        check(scan_v2.complete && scan_v2.merkle_root == ver2->merkle_root,
              "CAS-INT-04: Reconstructed v2 folder Merkle root matches published version 2 root");

        // Mutating reconstructed file does NOT affect CAS store or working copy
        {
            std::ofstream mut(recon_v1_dir / "text.txt", std::ios::binary | std::ios::app);
            mut << "CORRUPTED CONTENT APPENDED";
        }
        auto rep = ObjectVerifier::verify_store(store.cas_store());
        check(rep.is_healthy(), "CAS-INT-04: Mutating reconstructed file leaves CAS objects completely unaffected");

        const auto work_text = store.read_working_copy_file_content(ws1_id, "text.txt");
        check(work_text.find("CORRUPTED") == std::string::npos,
              "CAS-INT-04: Mutating reconstructed file leaves workspace working copy completely unaffected");
    }

    // CAS-INT-05: Edge Cases: 0-byte file, 1-byte file, 2MB multi-boundary file, nested directories
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_edge_client", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Edge WS", "Edge cases workspace");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto edge_src = test_dir / "edge_client_src";
        mc::fs::create_directories(edge_src);

        // 1. 0-byte file
        write_test_file(edge_src / "zero.bin", nullptr, 0);

        // 2. 1-byte file
        const std::uint8_t one_byte = 0x7F;
        write_test_file(edge_src / "one.bin", &one_byte, 1);

        // 3. 2MB file in deep nested directory
        auto large_data = generate_test_data(2 * 1024 * 1024, 99999);
        const auto large_hash = mc::sha256_data(large_data.data(), large_data.size());
        write_test_file(edge_src / "nested" / "sub" / "folder" / "large.dat", large_data.data(), large_data.size());

        const auto sub = store.create_submission(client.id, ws.id, edge_src);
        const bool accepted = store.accept_submission(sub.id, host->id, "Accept edge submission");
        check(accepted, "CAS-INT-05: accept_submission succeeded for 0-byte, 1-byte, and 2MB nested files");

        auto v_edge = store.publish_version(ws.id, host->id, "Edge Release", "Edge case files");
        check(!v_edge.id.empty(), "CAS-INT-05: publish_version succeeded for edge files");

        const auto recon_edge = test_dir / "reconstructed_edge";
        std::string recon_err;
        const bool recon_ok = store.reconstruct_version(v_edge.id, recon_edge, recon_err);
        check(recon_ok && recon_err.empty(), "CAS-INT-05: reconstruct_version succeeded for edge files");

        const auto scan_edge = mc::scan_folder(recon_edge);
        check(scan_edge.complete && scan_edge.merkle_root == v_edge.merkle_root,
              "CAS-INT-05: Reconstructed edge folder Merkle root matches published root exactly");

        // Verify individual edge file properties
        check(mc::fs::file_size(recon_edge / "zero.bin") == 0, "CAS-INT-05: zero.bin is exactly 0 bytes");
        check(mc::fs::file_size(recon_edge / "one.bin") == 1, "CAS-INT-05: one.bin is exactly 1 byte");
        check(mc::sha256_file(recon_edge / "nested" / "sub" / "folder" / "large.dat") == large_hash,
              "CAS-INT-05: 2MB nested file reconstructed with exact byte-for-byte SHA-256 match");

        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-INT-05: audit_cas_reference_integrity confirmed zero drift after edge release");
    }

    // CAS-INT-06: Backward Compatibility: Fallback for Legacy Phase 2 Versions
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Legacy WS", "Legacy backward compat testing");

        // Create legacy directory snapshot on disk without any CAS manifests
        const std::string legacy_ver_id = "ver_legacy_phase2_001";
        const auto legacy_dir = storage_dir / "workspaces" / ws.id / "versions" / legacy_ver_id;
        mc::fs::create_directories(legacy_dir);
        const std::string legacy_content = "Legacy file content produced prior to Phase 3 CAS";
        write_test_file(legacy_dir / "legacy_file.txt", legacy_content.data(), legacy_content.size());

        const auto legacy_scan = mc::scan_folder(legacy_dir);

        // Manually insert row into published_versions without creating version_manifests rows
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            const char* sql = R"(
                INSERT INTO published_versions (id, workspace_id, parent_version_id, title, release_notes, merkle_root, file_count, total_size, published_by_id, published_at_ms)
                VALUES (?, ?, NULL, 'Legacy Version', 'Phase 2 legacy snapshot', ?, 1, ?, ?, 1000)
            )";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, legacy_ver_id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, ws.id.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, legacy_scan.merkle_root.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(legacy_content.size()));
            sqlite3_bind_text(stmt, 5, host->id.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }

        const auto recon_legacy = test_dir / "reconstructed_legacy";
        std::string err;
        const bool recon_legacy_ok = store.reconstruct_version(legacy_ver_id, recon_legacy, err);
        check(recon_legacy_ok && err.empty(),
              "CAS-INT-06: reconstruct_version falls back to legacy directory snapshot when manifests absent");

        const auto scan_recon_legacy = mc::scan_folder(recon_legacy);
        check(scan_recon_legacy.complete && scan_recon_legacy.merkle_root == legacy_scan.merkle_root,
              "CAS-INT-06: Reconstructed legacy version matches original legacy Merkle root");
        check(mc::fs::exists(recon_legacy / "legacy_file.txt"),
              "CAS-INT-06: legacy_file.txt successfully restored from legacy directory");
    }

    // CAS-INT-07: Rollback and Consistency on Interrupted Publication
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Rollback WS", "Rollback fault injection testing");

        store.write_working_copy_file_content(ws.id, "important.txt", "Important data before crash");

        // Inject fault before SQLite transaction commit
        set_collab_fault_point_for_testing(CollabFaultPoint::FailAfterBaselineBackup);

        bool exception_thrown = false;
        try {
            (void)store.publish_version(ws.id, host->id, "Failed Release", "Should fail and roll back");
        } catch (const std::runtime_error&) {
            exception_thrown = true;
        }
        check(exception_thrown, "CAS-INT-07: Injected fault triggered exception during publish_version");

        // Clear fault point
        set_collab_fault_point_for_testing(CollabFaultPoint::None);

        // Verify published_versions has no uncommitted version
        const auto vers_after_fail = store.list_published_versions(ws.id);
        check(vers_after_fail.empty(), "CAS-INT-07: No published version recorded in SQLite after rollback");

        // Verify zero reference count drift in CAS metadata
        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-INT-07: audit_cas_reference_integrity confirms zero drift after publication rollback");

        // Retry publish_version after fault cleared
        auto v_retry = store.publish_version(ws.id, host->id, "Retried Release", "Clean retry");
        check(!v_retry.id.empty(), "CAS-INT-07: Retrying publish_version succeeds cleanly after rollback");

        const auto vers_after_retry = store.list_published_versions(ws.id);
        check(vers_after_retry.size() == 1, "CAS-INT-07: Exactly 1 version recorded after clean retry");
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-INT-07: audit_cas_reference_integrity confirms 100% integrity after retried publication");
    }

    // CAS-INT-08: ObjectVerifier Deep Audit on Integrated Store
    {
        CollabStore store(db_path, storage_dir);
        auto report = ObjectVerifier::verify_store(store.cas_store());
        check(report.is_healthy(), "CAS-INT-08: ObjectVerifier confirms integrated CAS store is 100% healthy");
        check(report.corrupt_objects == 0, "CAS-INT-08: Zero corrupt objects in store");
        check(report.orphaned_temp_files == 0, "CAS-INT-08: Zero orphaned temp files in store");
        check(report.valid_objects > 0, "CAS-INT-08: Total valid chunk count is positive across all test versions");
        check(mc::fs::exists(store.cas_root_dir() / "objects"), "CAS-INT-08: CAS objects root exists");
    }

    // CAS-AUDIT-01: Single File Repeated Chunks Reference Counting
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_audit_client1", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Audit WS 1", "Repeated chunk workspace");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto audit_src = test_dir / "audit_src_1";
        mc::fs::create_directories(audit_src);

        // Build a deterministic repeating pattern: 4 identical 16KB blocks = 64KB
        auto block_data = generate_test_data(16384, 44444);
        std::vector<std::uint8_t> repeated_data;
        repeated_data.reserve(block_data.size() * 4);
        for (int i = 0; i < 4; ++i) {
            repeated_data.insert(repeated_data.end(), block_data.begin(), block_data.end());
        }
        write_test_file(audit_src / "repeated.bin", repeated_data.data(), repeated_data.size());

        const auto sub = store.create_submission(client.id, ws.id, audit_src);
        check(store.accept_submission(sub.id, host->id, "Accept repeated chunks"),
              "CAS-AUDIT-01: accept_submission succeeded for file with repeated chunks");

        auto v_rep = store.publish_version(ws.id, host->id, "Repeat Release", "Repeated chunks");
        check(!v_rep.id.empty(), "CAS-AUDIT-01: publish_version succeeded");

        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-AUDIT-01: audit_cas_reference_integrity confirms exact match with repeated chunk increments");

        // Verify that in cas_chunks, chunks have correct reference_count >= 4 for repeated blocks
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db,
                "SELECT c.chunk_hash, c.reference_count, COUNT(vmc.chunk_index) "
                "FROM cas_chunks c "
                "JOIN version_manifest_chunks vmc ON c.chunk_hash = vmc.chunk_hash "
                "JOIN version_manifests vm ON vmc.manifest_id = vm.manifest_id "
                "WHERE vm.version_id = ? "
                "GROUP BY c.chunk_hash", -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, v_rep.id.c_str(), -1, SQLITE_TRANSIENT);
            bool checked_any = false;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                checked_any = true;
                std::int64_t ref_count = sqlite3_column_int64(stmt, 1);
                std::int64_t vmc_count = sqlite3_column_int64(stmt, 2);
                check(ref_count >= vmc_count && vmc_count >= 1,
                      "CAS-AUDIT-01: cas_chunks reference_count accounts for every repeated occurrence");
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            check(checked_any, "CAS-AUDIT-01: Chunks verified in DB");
        }

        // Reconstruct and verify byte-for-byte fidelity
        const auto recon_rep = test_dir / "reconstructed_repeat";
        std::string recon_err;
        check(store.reconstruct_version(v_rep.id, recon_rep, recon_err),
              "CAS-AUDIT-01: reconstruct_version succeeded for repeated chunk file");
        check(mc::sha256_file(recon_rep / "repeated.bin") == mc::sha256_data(repeated_data.data(), repeated_data.size()),
              "CAS-AUDIT-01: Reconstructed file matches 64KB repeated data byte-for-byte");
    }

    // CAS-AUDIT-02: Multi-File Cross-File Chunk Sharing in Single Version
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_audit_client2", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Audit WS 2", "Cross-file chunk sharing");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto audit_src = test_dir / "audit_src_2";
        mc::fs::create_directories(audit_src);

        auto common_chunk = generate_test_data(16384, 55555);
        auto prefix = generate_test_data(8192, 11111);
        auto suffix = generate_test_data(8192, 22222);

        // File A: common + suffix
        std::vector<std::uint8_t> file_a_data = common_chunk;
        file_a_data.insert(file_a_data.end(), suffix.begin(), suffix.end());
        write_test_file(audit_src / "file_a.bin", file_a_data.data(), file_a_data.size());

        // File B: prefix + common
        std::vector<std::uint8_t> file_b_data = prefix;
        file_b_data.insert(file_b_data.end(), common_chunk.begin(), common_chunk.end());
        write_test_file(audit_src / "file_b.bin", file_b_data.data(), file_b_data.size());

        const auto sub = store.create_submission(client.id, ws.id, audit_src);
        check(store.accept_submission(sub.id, host->id, "Accept cross-file sharing"),
              "CAS-AUDIT-02: accept_submission succeeded for files sharing chunks");

        auto v_shared = store.publish_version(ws.id, host->id, "Cross-File Release", "Shared chunks");
        check(!v_shared.id.empty(), "CAS-AUDIT-02: publish_version succeeded");

        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-AUDIT-02: audit_cas_reference_integrity confirms cross-file deduplication consistency");

        const auto recon_dir = test_dir / "reconstructed_shared";
        std::string recon_err;
        check(store.reconstruct_version(v_shared.id, recon_dir, recon_err),
              "CAS-AUDIT-02: reconstruct_version succeeded for cross-file shared chunks");
        check(mc::sha256_file(recon_dir / "file_a.bin") == mc::sha256_data(file_a_data.data(), file_a_data.size()),
              "CAS-AUDIT-02: Reconstructed file_a matches byte-for-byte");
        check(mc::sha256_file(recon_dir / "file_b.bin") == mc::sha256_data(file_b_data.data(), file_b_data.size()),
              "CAS-AUDIT-02: Reconstructed file_b matches byte-for-byte");
    }

    // CAS-AUDIT-03: Corrupted/Missing Physical Chunk Detection and Atomic Reconstruction Abort
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_audit_client3", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Audit WS 3", "Integrity audit workspace");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto audit_src = test_dir / "audit_src_3";
        mc::fs::create_directories(audit_src);
        auto test_data = generate_test_data(16384, 77777);
        write_test_file(audit_src / "target.bin", test_data.data(), test_data.size());

        const auto sub = store.create_submission(client.id, ws.id, audit_src);
        check(store.accept_submission(sub.id, host->id, "Accept for audit"), "CAS-AUDIT-03: accept_submission succeeded");

        auto v_audit = store.publish_version(ws.id, host->id, "Audit Release", "Integrity check");
        check(!v_audit.id.empty(), "CAS-AUDIT-03: publish_version succeeded");

        // Find a chunk hash used by this version
        std::string target_chunk_hash;
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db,
                "SELECT vmc.chunk_hash "
                "FROM version_manifest_chunks vmc "
                "JOIN version_manifests vm ON vmc.manifest_id = vm.manifest_id "
                "WHERE vm.version_id = ? LIMIT 1", -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, v_audit.id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                target_chunk_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }
        check(!target_chunk_hash.empty(), "CAS-AUDIT-03: Found target chunk hash in DB");

        // Locate physical CAS object
        const auto chunk_file = store.cas_store().object_path(target_chunk_hash);
        check(mc::fs::exists(chunk_file), "CAS-AUDIT-03: Physical chunk file exists before injection");

        // Temporarily move physical chunk file to simulate missing object
        const auto backup_chunk = test_dir / "chunk_backup.tmp";
        mc::fs::rename(chunk_file, backup_chunk);

        // 1. audit_cas_reference_integrity must detect the missing physical chunk!
        std::string audit_err;
        bool audit_result = store.audit_cas_reference_integrity(audit_err);
        check(!audit_result, "CAS-AUDIT-03: audit_cas_reference_integrity detected missing physical chunk");
        check(audit_err.find(target_chunk_hash) != std::string::npos,
              "CAS-AUDIT-03: Audit error specifies missing chunk hash");

        // 2. reconstruct_version must fail and must NOT leave corrupted or partial files at target destination
        const auto recon_target = test_dir / "recon_should_not_exist";
        std::string recon_err;
        bool recon_result = store.reconstruct_version(v_audit.id, recon_target, recon_err);
        check(!recon_result, "CAS-AUDIT-03: reconstruct_version fails when physical chunk is missing");
        check(!mc::fs::exists(recon_target) || mc::fs::is_empty(recon_target),
              "CAS-AUDIT-03: Destination directory is not contaminated with corrupted partial state");

        // Restore chunk file
        mc::fs::rename(backup_chunk, chunk_file);

        // Verify store returns to 100% health
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-AUDIT-03: Store returns to 100% integrity after physical chunk restoration");
        check(store.reconstruct_version(v_audit.id, recon_target, recon_err),
              "CAS-AUDIT-03: reconstruct_version succeeds cleanly after chunk restoration");
    }

    // CAS-AUDIT-04: Path Traversal and Illegal Names Protection in Reconstruct Version
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_audit_client4", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Audit WS 4", "Traversal rejection workspace");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto audit_src = test_dir / "audit_src_4";
        mc::fs::create_directories(audit_src);
        write_test_file(audit_src / "legit.txt", "safe", 4);

        const auto sub = store.create_submission(client.id, ws.id, audit_src);
        store.accept_submission(sub.id, host->id, "Accept safe file");
        auto v_trav = store.publish_version(ws.id, host->id, "Traversal Test", "Testing security checks");

        // Inject malicious path entry into SQLite version_manifests for this version
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db,
                "INSERT INTO version_manifests(manifest_id, workspace_id, version_id, relative_path, whole_file_sha256, file_size, chunk_count, manifest_blob, created_at_ms) "
                "VALUES('man_malicious', ?, ?, '../escaped.txt', 'dummyhash', 4, 1, X'CA510001000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 1)",
                -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, ws.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, v_trav.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }

        const auto safe_recon_dir = test_dir / "safe_recon";
        std::string recon_err;
        bool ok = store.reconstruct_version(v_trav.id, safe_recon_dir, recon_err);
        check(!ok, "CAS-AUDIT-04: reconstruct_version strictly rejects traversal path '../escaped.txt'");
        check(!mc::fs::exists(test_dir / "escaped.txt"),
              "CAS-AUDIT-04: Escaped file was NOT created outside destination directory");

        // Clean up malicious test entry
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            sqlite3_exec(db, "DELETE FROM version_manifests WHERE relative_path LIKE '%escaped%'", nullptr, nullptr, nullptr);
            sqlite3_close(db);
        }
    }

    // CAS-AUDIT-05: Empty Version (0 Files) Reconstruction
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Empty WS", "Empty version workspace");

        auto v_empty = store.publish_version(ws.id, host->id, "Empty Release", "Empty workspace snapshot");
        check(!v_empty.id.empty() && v_empty.file_count == 0,
              "CAS-AUDIT-05: publish_version succeeded for empty workspace");

        const auto recon_empty_dir = test_dir / "reconstructed_empty";
        std::string recon_err;
        bool ok = store.reconstruct_version(v_empty.id, recon_empty_dir, recon_err);
        check(ok && recon_err.empty(), "CAS-AUDIT-05: reconstruct_version succeeded for 0-file version");
        check(mc::fs::exists(recon_empty_dir) && mc::fs::is_empty(recon_empty_dir),
              "CAS-AUDIT-05: Destination folder exists and is empty");
        const auto scan_empty = mc::scan_folder(recon_empty_dir);
        check(scan_empty.complete && scan_empty.merkle_root == v_empty.merkle_root,
              "CAS-AUDIT-05: Merkle root of reconstructed empty directory matches published version root");
    }

    // CAS-AUDIT-06: Database Close & Reopen Reference Consistency
    {
        // Close previous store handles and construct fresh CollabStore instance
        CollabStore store_reopened(db_path, storage_dir);
        std::string audit_err;
        check(store_reopened.audit_cas_reference_integrity(audit_err),
              "CAS-AUDIT-06: audit_cas_reference_integrity passes with zero drift on fresh store instance");

        auto vers = store_reopened.list_published_versions(ws1_id);
        check(!vers.empty(), "CAS-AUDIT-06: Published versions enumerated correctly after reopen");
        auto ver1 = store_reopened.find_version_by_id(v1_id);
        check(ver1.has_value(), "CAS-AUDIT-06: Found version 1 metadata after reopen");

        const auto fresh_recon = test_dir / "reopened_v1_recon";
        std::string fresh_err;
        check(store_reopened.reconstruct_version(v1_id, fresh_recon, fresh_err),
              "CAS-AUDIT-06: reconstruct_version succeeds after reopen");
        check(mc::scan_folder(fresh_recon).merkle_root == ver1->merkle_root,
              "CAS-AUDIT-06: Reconstructed Merkle root matches published root after reopen");
    }

    // CAS-AUDIT-07: Multi-Workspace Concurrent Publication Sharing Identical Chunks
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.find_user_by_username("cas_client1");

        const auto ws_a = store.create_workspace("Concurrent WS A", "Concurrency testing A");
        const auto ws_b = store.create_workspace("Concurrent WS B", "Concurrency testing B");
        store.assign_user_to_workspace(ws_a.id, client->id);
        store.assign_user_to_workspace(ws_b.id, client->id);

        const auto shared_data = generate_test_data(32768, 88888);
        const auto src_a = test_dir / "conc_src_a";
        const auto src_b = test_dir / "conc_src_b";
        mc::fs::create_directories(src_a);
        mc::fs::create_directories(src_b);
        write_test_file(src_a / "shared.bin", shared_data.data(), shared_data.size());
        write_test_file(src_b / "shared.bin", shared_data.data(), shared_data.size());

        const auto sub_a = store.create_submission(client->id, ws_a.id, src_a);
        const auto sub_b = store.create_submission(client->id, ws_b.id, src_b);
        check(store.accept_submission(sub_a.id, host->id, "Accept A"), "CAS-AUDIT-07: Accept submission A");
        check(store.accept_submission(sub_b.id, host->id, "Accept B"), "CAS-AUDIT-07: Accept submission B");

        // Concurrently publish versions from two threads
        mc::CollabPublishedVersion ver_a, ver_b;
        std::thread t1([&]() {
            ver_a = store.publish_version(ws_a.id, host->id, "Conc Pub A", "Notes A");
        });
        std::thread t2([&]() {
            ver_b = store.publish_version(ws_b.id, host->id, "Conc Pub B", "Notes B");
        });
        t1.join();
        t2.join();

        check(!ver_a.id.empty() && !ver_b.id.empty(),
              "CAS-AUDIT-07: Concurrent publish_version succeeded on both workspaces");
        check(ver_a.merkle_root == ver_b.merkle_root,
              "CAS-AUDIT-07: Both workspaces published identical content roots");

        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-AUDIT-07: audit_cas_reference_integrity reports zero drift after concurrent multi-workspace publication");

        // Verify shared chunks have reference_count >= 2
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db,
                "SELECT c.reference_count FROM cas_chunks c "
                "JOIN version_manifest_chunks vmc ON c.chunk_hash = vmc.chunk_hash "
                "JOIN version_manifests vm ON vmc.manifest_id = vm.manifest_id "
                "WHERE vm.version_id = ? LIMIT 1", -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, ver_a.id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                std::int64_t ref_count = sqlite3_column_int64(stmt, 0);
                check(ref_count >= 2,
                      "CAS-AUDIT-07: Shared chunk has reference_count >= 2 across concurrent workspaces");
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }
    }

    // CAS-AUDIT-08: Cryptographic Same-Size Physical Chunk Corruption Detection & Safe Reconstruction Abort
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_audit_client8", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("CAS Audit WS 8", "Cryptographic corruption test");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto audit_src = test_dir / "audit_src_8";
        mc::fs::create_directories(audit_src);
        auto test_data = generate_test_data(16384, 88811);
        write_test_file(audit_src / "crypto_target.bin", test_data.data(), test_data.size());

        const auto sub = store.create_submission(client.id, ws.id, audit_src);
        check(store.accept_submission(sub.id, host->id, "Accept for crypto corruption audit"),
              "CAS-AUDIT-08: accept_submission succeeded");

        auto v_pub = store.publish_version(ws.id, host->id, "Crypto Audit Release", "Cryptographic check");
        check(!v_pub.id.empty(), "CAS-AUDIT-08: publish_version succeeded");

        // Find referenced chunk hash
        std::string chunk_hash;
        {
            sqlite3* db = nullptr;
            sqlite3_open(db_path.string().c_str(), &db);
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db,
                "SELECT vmc.chunk_hash FROM version_manifest_chunks vmc "
                "JOIN version_manifests vm ON vmc.manifest_id = vm.manifest_id "
                "WHERE vm.version_id = ? LIMIT 1", -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, v_pub.id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                chunk_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }
        check(!chunk_hash.empty(), "CAS-AUDIT-08: Found target chunk hash");

        const auto chunk_path = store.cas_store().object_path(chunk_hash);
        check(mc::fs::exists(chunk_path), "CAS-AUDIT-08: Target chunk file exists");
        const auto orig_size = mc::fs::file_size(chunk_path);

        // Read chunk bytes
        std::vector<std::uint8_t> orig_bytes(orig_size);
        {
            std::ifstream in(chunk_path, std::ios::binary);
            in.read(reinterpret_cast<char*>(orig_bytes.data()), static_cast<std::streamsize>(orig_size));
        }

        // Mutate single byte in place (preserving EXACT SAME file size!)
        std::vector<std::uint8_t> corrupt_bytes = orig_bytes;
        corrupt_bytes[0] ^= 0xFF; // flip bits
        write_test_file(chunk_path, corrupt_bytes.data(), corrupt_bytes.size());
        check(mc::fs::file_size(chunk_path) == orig_size, "CAS-AUDIT-08: File size remains identical after bit flip");

        // 1. audit_cas_reference_integrity MUST catch the same-size cryptographic corruption!
        std::string audit_err;
        bool audit_ok = store.audit_cas_reference_integrity(audit_err);
        check(!audit_ok, "CAS-AUDIT-08: audit_cas_reference_integrity detected same-size corrupted chunk");
        check(audit_err.find("cryptographic hash corruption") != std::string::npos ||
              audit_err.find("Hash mismatch") != std::string::npos,
              "CAS-AUDIT-08: Error message explicitly reports cryptographic hash corruption");

        // 2. reconstruct_version MUST fail safely
        const auto recon_target = test_dir / "crypto_recon_dst";
        std::string recon_err;
        bool recon_ok = store.reconstruct_version(v_pub.id, recon_target, recon_err);
        check(!recon_ok, "CAS-AUDIT-08: reconstruct_version fails when chunk is corrupted in place");
        check(!mc::fs::exists(recon_target) || mc::fs::is_empty(recon_target),
              "CAS-AUDIT-08: Incomplete destination directory was not exposed");

        // 3. Original published version directory and SQLite records are untouched
        auto ver_meta = store.find_version_by_id(v_pub.id);
        check(ver_meta.has_value() && ver_meta->merkle_root == v_pub.merkle_root,
              "CAS-AUDIT-08: Original published version metadata in SQLite is intact and untouched");

        // 4. Heal the chunk: restore original bytes
        write_test_file(chunk_path, orig_bytes.data(), orig_bytes.size());
        check(store.audit_cas_reference_integrity(audit_err),
              "CAS-AUDIT-08: Store returns to 100% integrity after chunk restoration");
        check(store.reconstruct_version(v_pub.id, recon_target, recon_err),
              "CAS-AUDIT-08: reconstruct_version succeeds cleanly after chunk restoration");
        check(mc::scan_folder(recon_target).merkle_root == v_pub.merkle_root,
              "CAS-AUDIT-08: Reconstructed Merkle root matches published root exactly after heal");
    }

    // CAS-AUDIT-09: Process Crash — CAS Object Stored Before SQLite Metadata Commit
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.create_user("cas_crash_client1", "Password123!", "client", {"submit"});
        const auto ws = store.create_workspace("Crash WS 1", "Crash test 1");
        store.assign_user_to_workspace(ws.id, client.id);

        const auto src = test_dir / "crash_src_1";
        mc::fs::create_directories(src);
        auto data1 = generate_test_data(32768, 10101);
        write_test_file(src / "file1.bin", data1.data(), data1.size());

        const auto sub = store.create_submission(client.id, ws.id, src);
        check(store.accept_submission(sub.id, host->id, "Accept"), "CAS-AUDIT-09: accept_submission succeeded");

        // Spawn child worker that crashes at after-snapshot-promotion (exit code 95)
        std::wstring args = L"--collab-crash-worker \"" + db_path.wstring() + L"\" \"" +
                            storage_dir.wstring() + L"\" " + mc::fs::u8path(ws.id).wstring() +
                            L" " + mc::fs::u8path(host->id).wstring() + L" after-snapshot-promotion";
        DWORD exit_code = run_collab_child_process(args);
        check(exit_code == 95, "CAS-AUDIT-09: Worker terminated at after-snapshot-promotion with code 95");

        // Reopen database and storage engine: constructor executes recover_incomplete_operations()
        {
            CollabStore store_reopened(db_path, storage_dir);
            // Execute recovery a second time to verify idempotency
            store_reopened.recover_incomplete_operations();

            // Verify no published version recorded in SQLite
            auto vers = store_reopened.list_published_versions(ws.id);
            check(vers.empty(), "CAS-AUDIT-09: No uncommitted version recorded in SQLite");

            // Verify zero drift in CAS reference counts
            std::string audit_err;
            check(store_reopened.audit_cas_reference_integrity(audit_err),
                  "CAS-AUDIT-09: audit_cas_reference_integrity confirms zero reference drift after crash");

            // Verify working copy files remain completely intact
            auto wc_files = store_reopened.list_working_copy_files(ws.id);
            check(!wc_files.empty(), "CAS-AUDIT-09: Working copy files remain intact after recovery");

            // Subsequent clean publish succeeds
            auto v_retry = store_reopened.publish_version(ws.id, host->id, "Clean Publish", "Post-crash recovery");
            check(!v_retry.id.empty(), "CAS-AUDIT-09: Clean publish_version succeeds after crash recovery");
            check(store_reopened.audit_cas_reference_integrity(audit_err),
                  "CAS-AUDIT-09: Zero reference drift after retried publication");
        }
#else
        check(true, "CAS-AUDIT-09: Process crash test skipped on non-Windows");
#endif
    }

    // CAS-AUDIT-10: Process Crash — Manifest Staged Before Database Commit
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.find_user_by_username("cas_crash_client1");
        const auto ws = store.create_workspace("Crash WS 2", "Crash test 2");
        store.assign_user_to_workspace(ws.id, client->id);

        const auto src = test_dir / "crash_src_2";
        mc::fs::create_directories(src);
        auto data2 = generate_test_data(16384, 20202);
        write_test_file(src / "file2.bin", data2.data(), data2.size());

        const auto sub = store.create_submission(client->id, ws.id, src);
        check(store.accept_submission(sub.id, host->id, "Accept"), "CAS-AUDIT-10: accept_submission succeeded");

        // Spawn child worker that crashes at after-staging-baseline (exit code 95)
        std::wstring args = L"--collab-crash-worker \"" + db_path.wstring() + L"\" \"" +
                            storage_dir.wstring() + L"\" " + mc::fs::u8path(ws.id).wstring() +
                            L" " + mc::fs::u8path(host->id).wstring() + L" after-staging-baseline";
        DWORD exit_code = run_collab_child_process(args);
        check(exit_code == 95, "CAS-AUDIT-10: Worker terminated at after-staging-baseline with code 95");

        {
            CollabStore store_reopened(db_path, storage_dir);
            store_reopened.recover_incomplete_operations(); // second recovery (idempotent)

            auto vers = store_reopened.list_published_versions(ws.id);
            check(vers.empty(), "CAS-AUDIT-10: No published versions recorded");

            std::string audit_err;
            check(store_reopened.audit_cas_reference_integrity(audit_err),
                  "CAS-AUDIT-10: audit_cas_reference_integrity reports zero drift");

            auto v_clean = store_reopened.publish_version(ws.id, host->id, "Clean Publish 2", "Recovered");
            check(!v_clean.id.empty(), "CAS-AUDIT-10: Clean publish succeeds");
        }
#else
        check(true, "CAS-AUDIT-10: Process crash test skipped on non-Windows");
#endif
    }

    // CAS-AUDIT-11: Process Crash — Filesystem Promotion Completed Before SQLite Commit
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.find_user_by_username("cas_crash_client1");
        const auto ws = store.create_workspace("Crash WS 3", "Crash test 3");
        store.assign_user_to_workspace(ws.id, client->id);

        const auto src = test_dir / "crash_src_3";
        mc::fs::create_directories(src);
        auto data3 = generate_test_data(16384, 30303);
        write_test_file(src / "file3.bin", data3.data(), data3.size());

        const auto sub = store.create_submission(client->id, ws.id, src);
        check(store.accept_submission(sub.id, host->id, "Accept"), "CAS-AUDIT-11: accept_submission succeeded");

        // Spawn child worker that crashes at after-baseline-promotion (exit code 95)
        std::wstring args = L"--collab-crash-worker \"" + db_path.wstring() + L"\" \"" +
                            storage_dir.wstring() + L"\" " + mc::fs::u8path(ws.id).wstring() +
                            L" " + mc::fs::u8path(host->id).wstring() + L" after-baseline-promotion";
        DWORD exit_code = run_collab_child_process(args);
        check(exit_code == 95, "CAS-AUDIT-11: Worker terminated at after-baseline-promotion with code 95");

        {
            CollabStore store_reopened(db_path, storage_dir);
            store_reopened.recover_incomplete_operations(); // idempotent second recovery

            auto vers = store_reopened.list_published_versions(ws.id);
            check(vers.empty(), "CAS-AUDIT-11: No uncommitted version in DB");

            std::string audit_err;
            check(store_reopened.audit_cas_reference_integrity(audit_err),
                  "CAS-AUDIT-11: Zero reference count drift after promotion rollback");

            auto v_clean = store_reopened.publish_version(ws.id, host->id, "Clean Publish 3", "Recovered baseline");
            check(!v_clean.id.empty(), "CAS-AUDIT-11: Clean publish succeeds after promotion rollback");
        }
#else
        check(true, "CAS-AUDIT-11: Process crash test skipped on non-Windows");
#endif
    }

    // CAS-AUDIT-12: Process Crash — SQLite Commit Completed Before Backup Cleanup
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.find_user_by_username("cas_crash_client1");
        const auto ws = store.create_workspace("Crash WS 4", "Crash test 4");
        store.assign_user_to_workspace(ws.id, client->id);

        const auto src = test_dir / "crash_src_4";
        mc::fs::create_directories(src);
        auto data4 = generate_test_data(16384, 40404);
        write_test_file(src / "file4.bin", data4.data(), data4.size());

        const auto sub = store.create_submission(client->id, ws.id, src);
        check(store.accept_submission(sub.id, host->id, "Accept"), "CAS-AUDIT-12: accept_submission succeeded");

        // Spawn child worker that crashes at after-commit (exit code 95)
        std::wstring args = L"--collab-crash-worker \"" + db_path.wstring() + L"\" \"" +
                            storage_dir.wstring() + L"\" " + mc::fs::u8path(ws.id).wstring() +
                            L" " + mc::fs::u8path(host->id).wstring() + L" after-commit";
        DWORD exit_code = run_collab_child_process(args);
        check(exit_code == 95, "CAS-AUDIT-12: Worker terminated at after-commit with code 95");

        {
            CollabStore store_reopened(db_path, storage_dir);
            store_reopened.recover_incomplete_operations(); // idempotent second recovery

            // Because commit succeeded, recovery rolled FORWARD!
            auto vers = store_reopened.list_published_versions(ws.id);
            check(vers.size() == 1, "CAS-AUDIT-12: Committed version preserved after roll-forward recovery");

            std::string audit_err;
            check(store_reopened.audit_cas_reference_integrity(audit_err),
                  "CAS-AUDIT-12: audit_cas_reference_integrity confirms 100% integrity on committed version");

            const auto recon_dir = test_dir / "reconstructed_post_commit_crash";
            std::string recon_err;
            check(store_reopened.reconstruct_version(vers.front().id, recon_dir, recon_err),
                  "CAS-AUDIT-12: Reconstruct committed version succeeds after roll-forward cleanup");
            check(mc::scan_folder(recon_dir).merkle_root == vers.front().merkle_root,
                  "CAS-AUDIT-12: Reconstructed root matches committed version root");
        }
#else
        check(true, "CAS-AUDIT-12: Process crash test skipped on non-Windows");
#endif
    }

    // CAS-AUDIT-13: Process Crash — Recovery Interrupted and Re-executed
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto client = store.find_user_by_username("cas_crash_client1");
        const auto ws = store.create_workspace("Crash WS 5", "Crash test 5");
        store.assign_user_to_workspace(ws.id, client->id);

        const auto src = test_dir / "crash_src_5";
        mc::fs::create_directories(src);
        auto data5 = generate_test_data(16384, 50505);
        write_test_file(src / "file5.bin", data5.data(), data5.size());

        const auto sub = store.create_submission(client->id, ws.id, src);
        check(store.accept_submission(sub.id, host->id, "Accept"), "CAS-AUDIT-13: accept_submission succeeded");

        // First crash a worker during publish
        std::wstring args1 = L"--collab-crash-worker \"" + db_path.wstring() + L"\" \"" +
                             storage_dir.wstring() + L"\" " + mc::fs::u8path(ws.id).wstring() +
                             L" " + mc::fs::u8path(host->id).wstring() + L" after-snapshot-promotion";
        DWORD ec1 = run_collab_child_process(args1);
        check(ec1 == 95, "CAS-AUDIT-13: Worker 1 created incomplete operation and crashed");

        // Now run a recovery worker that crashes mid-recovery (during-recovery)
        std::wstring args2 = L"--collab-crash-worker \"" + db_path.wstring() + L"\" \"" +
                             storage_dir.wstring() + L"\" " + mc::fs::u8path(ws.id).wstring() +
                             L" " + mc::fs::u8path(host->id).wstring() + L" during-recovery";
        DWORD ec2 = run_collab_child_process(args2);
        check(ec2 == 95, "CAS-AUDIT-13: Recovery worker crashed mid-recovery with code 95");

        // Finally reopen store in parent: recovery runs to completion
        {
            CollabStore store_reopened(db_path, storage_dir);
            // Run recovery once more to verify complete idempotency
            store_reopened.recover_incomplete_operations();

            auto vers = store_reopened.list_published_versions(ws.id);
            check(vers.empty(), "CAS-AUDIT-13: No uncommitted version recorded in DB after interrupted recovery");

            std::string audit_err;
            check(store_reopened.audit_cas_reference_integrity(audit_err),
                  "CAS-AUDIT-13: Reference counts consistent after interrupted and resumed recovery");

            auto v_ok = store_reopened.publish_version(ws.id, host->id, "Clean Publish 5", "Fully recovered");
            check(!v_ok.id.empty(), "CAS-AUDIT-13: Subsequent publish succeeds after interrupted recovery");
        }
#else
        check(true, "CAS-AUDIT-13: Process crash test skipped on non-Windows");
#endif
    }
}

} // namespace mc::cas
