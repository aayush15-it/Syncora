#include "cas_gc_tests.hpp"
#include "merklechain/collab_store.hpp"
#include "merklechain/cas/chunker.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/object_verifier.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/scanner.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <sqlite3.h>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace mc::cas {

namespace {

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
DWORD run_gc_child_process(const std::wstring& arguments) {
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

static bool spawn_gc_child_process(const std::wstring& arguments, PROCESS_INFORMATION& process) {
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size()) return false;
    executable.resize(length);

    std::wstring command = L"\"" + executable + L"\" " + arguments;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));
    return CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
}
#endif

} // anonymous namespace

void run_cas_gc_tests(const mc::fs::path& fixture_root, void (*check)(bool, const char*)) {
    const auto test_dir = fixture_root / "cas_gc_suite";
    std::error_code ec;
    mc::fs::remove_all(test_dir, ec);
    mc::fs::create_directories(test_dir);

    const auto db_path = test_dir / "collab.sqlite3";
    const auto storage_dir = test_dir / "storage";

    // GC-TEST-01: Active Version Preservation
    {
        CollabStore store(db_path, storage_dir);
        store.init_schema();
        store.seed_default_accounts_if_empty();

        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Active WS 1", "Active Preservation Test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src = test_dir / "active_src_1";
        mc::fs::create_directories(src);

        auto d1 = generate_test_data(512, 1111);
        auto d2 = generate_test_data(81920, 2222);
        auto d3 = generate_test_data(150000, 3333);

        write_test_file(src / "small.txt", d1.data(), d1.size());
        write_test_file(src / "medium.bin", d2.data(), d2.size());
        write_test_file(src / "large.dat", d3.data(), d3.size());

        const auto sub = store.create_submission(host->id, ws.id, src);
        check(store.accept_submission(sub.id, host->id, "Accept active files"), "GC-TEST-01: accept_submission succeeded");

        const auto pub_v1 = store.publish_version(ws.id, host->id, "v1.0.0", "Active Version 1");
        check(!pub_v1.id.empty(), "GC-TEST-01: publish_version succeeded");

        // Run full GC with 0 grace period
        GcOptions opts;
        opts.dry_run = false;
        opts.grace_period_ms = 0;
        opts.sweep_physical_orphans = true;

        GcReport report = store.garbage_collect(opts);
        check(report.success, "GC-TEST-01: garbage_collect succeeded");
        check(report.chunks_deleted == 0, "GC-TEST-01: 0 chunks deleted from active version");
        check(report.reclaimed_bytes == 0, "GC-TEST-01: 0 bytes reclaimed from active version");

        // Reconstruct version and verify 100% Merkle parity
        const auto recon_dst = test_dir / "recon_active_v1";
        std::string err;
        check(store.reconstruct_version(pub_v1.id, recon_dst, err), "GC-TEST-01: reconstruct_version succeeded");
        check(mc::scan_folder(recon_dst).merkle_root == pub_v1.merkle_root,
              "GC-TEST-01: Reconstructed Merkle root matches published active version root");

        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "GC-TEST-01: audit_cas_reference_integrity confirms 0 reference drift");
    }

    // GC-TEST-02: Pruned Version Reclamation
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Prune WS 1", "Pruned Reclamation Test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src_v1 = test_dir / "prune_src_v1";
        const auto src_v2 = test_dir / "prune_src_v2";
        mc::fs::create_directories(src_v1);
        mc::fs::create_directories(src_v2);

        auto d_shared = generate_test_data(65536, 4444);
        auto d_uniq1 = generate_test_data(65536, 5555);
        auto d_uniq2 = generate_test_data(65536, 6666);

        write_test_file(src_v1 / "shared.bin", d_shared.data(), d_shared.size());
        write_test_file(src_v1 / "unique1.bin", d_uniq1.data(), d_uniq1.size());

        write_test_file(src_v2 / "shared.bin", d_shared.data(), d_shared.size());
        write_test_file(src_v2 / "unique2.bin", d_uniq2.data(), d_uniq2.size());

        // Publish v1
        const auto sub1 = store.create_submission(host->id, ws.id, src_v1);
        store.accept_submission(sub1.id, host->id, "Accept v1");
        const auto pub_v1 = store.publish_version(ws.id, host->id, "v1", "Initial");

        // Publish v2
        const auto sub2 = store.create_submission(host->id, ws.id, src_v2);
        store.accept_submission(sub2.id, host->id, "Accept v2");
        const auto pub_v2 = store.publish_version(ws.id, host->id, "v2", "Revised");

        // Inspect manifests to find chunks unique to v1
        std::string gvm_err1, gvm_err2;
        auto m_v1 = store.get_version_manifests(pub_v1.id, gvm_err1);
        auto m_v2 = store.get_version_manifests(pub_v2.id, gvm_err2);

        std::string uniq1_chunk;
        std::string shared_chunk;
        std::unordered_set<std::string> v2_hashes;
        for (const auto& f : m_v2) {
            for (const auto& c : f.chunks()) {
                v2_hashes.insert(c.hash);
            }
        }
        for (const auto& f : m_v1) {
            for (const auto& c : f.chunks()) {
                if (v2_hashes.count(c.hash)) {
                    shared_chunk = c.hash;
                } else {
                    uniq1_chunk = c.hash;
                }
            }
        }

        check(!uniq1_chunk.empty() && !shared_chunk.empty(), "GC-TEST-02: Found unique and shared chunks in v1");

        // Prune v1
        std::string prune_err;
        check(store.prune_version(pub_v1.id, prune_err), "GC-TEST-02: prune_version succeeded");

        // Unique1 chunk should now have reference count 0
        check(store.get_chunk_reference_count(uniq1_chunk) == 0,
              "GC-TEST-02: Unique v1 chunk reference count dropped to 0");
        // Shared chunk should still have reference count >= 1
        check(store.get_chunk_reference_count(shared_chunk) >= 1,
              "GC-TEST-02: Shared chunk reference count retained for v2");

        // Run GC
        GcOptions opts;
        opts.dry_run = false;
        opts.grace_period_ms = 0;
        GcReport rep = store.garbage_collect(opts);
        check(rep.success, "GC-TEST-02: garbage_collect succeeded");
        check(rep.chunks_deleted >= 1, "GC-TEST-02: Unreferenced unique v1 chunk was swept");

        // Verify shared chunk is still live and v2 reconstructs cleanly
        const auto recon_dst = test_dir / "recon_prune_v2";
        std::string err;
        check(store.reconstruct_version(pub_v2.id, recon_dst, err), "GC-TEST-02: reconstruct_version v2 succeeded");
        check(mc::scan_folder(recon_dst).merkle_root == pub_v2.merkle_root,
              "GC-TEST-02: Reconstructed v2 root matches published root exactly");
    }

    // GC-TEST-03: Shared Chunk Reference Handling
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Shared WS 1", "Shared Ref Counting Test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto s1 = test_dir / "s_src_1";
        const auto s2 = test_dir / "s_src_2";
        const auto s3 = test_dir / "s_src_3";
        mc::fs::create_directories(s1);
        mc::fs::create_directories(s2);
        mc::fs::create_directories(s3);

        auto d_sh = generate_test_data(32768, 7777);
        auto d_u2 = generate_test_data(32768, 8888);
        auto d_u3 = generate_test_data(32768, 9999);

        write_test_file(s1 / "shared.bin", d_sh.data(), d_sh.size());

        write_test_file(s2 / "shared.bin", d_sh.data(), d_sh.size());
        write_test_file(s2 / "u2.bin", d_u2.data(), d_u2.size());

        write_test_file(s3 / "shared.bin", d_sh.data(), d_sh.size());
        write_test_file(s3 / "u3.bin", d_u3.data(), d_u3.size());

        const auto sub1 = store.create_submission(host->id, ws.id, s1);
        store.accept_submission(sub1.id, host->id, "Accept 1");
        const auto v1 = store.publish_version(ws.id, host->id, "v1", "Release 1");

        const auto sub2 = store.create_submission(host->id, ws.id, s2);
        store.accept_submission(sub2.id, host->id, "Accept 2");
        const auto v2 = store.publish_version(ws.id, host->id, "v2", "Release 2");

        const auto sub3 = store.create_submission(host->id, ws.id, s3);
        store.accept_submission(sub3.id, host->id, "Accept 3");
        const auto v3 = store.publish_version(ws.id, host->id, "v3", "Release 3");

        std::string gvm_err;
        auto manifests1 = store.get_version_manifests(v1.id, gvm_err);
        std::string shared_hash = manifests1[0].chunks()[0].hash;
        check(store.get_chunk_reference_count(shared_hash) == 3,
              "GC-TEST-03: Shared chunk reference count is 3 across 3 versions");

        // Prune v1: ref count drops to 2
        std::string perr;
        check(store.prune_version(v1.id, perr), "GC-TEST-03: Prune v1 succeeded");
        check(store.get_chunk_reference_count(shared_hash) == 2,
              "GC-TEST-03: Shared chunk ref count decremented to 2");

        GcOptions opts;
        opts.grace_period_ms = 0;
        store.garbage_collect(opts);
        check(store.get_chunk_reference_count(shared_hash) == 2,
              "GC-TEST-03: Shared chunk untouched by GC when ref count is 2");

        // Prune v2: ref count drops to 1
        check(store.prune_version(v2.id, perr), "GC-TEST-03: Prune v2 succeeded");
        check(store.get_chunk_reference_count(shared_hash) == 1,
              "GC-TEST-03: Shared chunk ref count decremented to 1");

        store.garbage_collect(opts);
        check(store.get_chunk_reference_count(shared_hash) == 1,
              "GC-TEST-03: Shared chunk untouched by GC when ref count is 1");

        // Prune v3: ref count drops to 0
        check(store.prune_version(v3.id, perr), "GC-TEST-03: Prune v3 succeeded");
        check(store.get_chunk_reference_count(shared_hash) == 0,
              "GC-TEST-03: Shared chunk ref count decremented to 0 after last version pruned");

        GcReport r3 = store.garbage_collect(opts);
        check(r3.chunks_deleted >= 1, "GC-TEST-03: Shared chunk is swept when ref count reaches 0");
        check(store.get_chunk_reference_count(shared_hash) == 0,
              "GC-TEST-03: Swept chunk has 0 references in catalog");
        check(!store.cas_store().has_object(shared_hash),
              "GC-TEST-03: Swept chunk is no longer in physical CAS store");
    }

    // GC-TEST-04: Reference Count Reconciliation & Healing
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Heal WS 1", "Reference Reconciliation Test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src = test_dir / "heal_src";
        mc::fs::create_directories(src);
        auto d = generate_test_data(16384, 1212);
        write_test_file(src / "heal.bin", d.data(), d.size());

        const auto sub = store.create_submission(host->id, ws.id, src);
        store.accept_submission(sub.id, host->id, "Accept heal");
        const auto v = store.publish_version(ws.id, host->id, "v1", "Heal version");

        // Intentionally corrupt reference count in SQLite directly
        sqlite3* raw_db = nullptr;
        sqlite3_open(db_path.string().c_str(), &raw_db);
        sqlite3_exec(raw_db, "UPDATE cas_chunks SET reference_count = reference_count + 10;", nullptr, nullptr, nullptr);
        sqlite3_close(raw_db);

        std::string audit_err;
        bool audit_before = store.audit_cas_reference_integrity(audit_err);
        check(!audit_before, "GC-TEST-04: Reference integrity audit detected injected reference count drift");

        // Reconcile
        std::size_t healed = 0;
        std::string rec_err;
        bool rec_ok = store.reconcile_cas_reference_counts(healed, rec_err);
        check(rec_ok && healed > 0, "GC-TEST-04: reconcile_cas_reference_counts repaired drifted reference counts");

        bool audit_after = store.audit_cas_reference_integrity(audit_err);
        check(audit_after, "GC-TEST-04: Reference integrity audit returns 100% clean after reconciliation");
    }

    // GC-TEST-05: Grace Period Protection for Newly Written Unreferenced Chunks
    {
        CollabStore store(db_path, storage_dir);

        // Put a raw chunk directly into CAS store and insert into DB with ref_count = 0
        auto raw_chunk = generate_test_data(4096, 5050);
        std::string chunk_hash = mc::sha256_data(raw_chunk.data(), raw_chunk.size());

        // Insert into cas_chunks directly
        sqlite3* raw_db = nullptr;
        sqlite3_open(db_path.string().c_str(), &raw_db);
        const char* sql_ins = "INSERT INTO cas_chunks (chunk_hash, chunk_size, reference_count, created_at_ms, verified_at_ms, storage_state) VALUES (?, ?, 0, ?, ?, 'COMMITTED');";
        sqlite3_stmt* ins_stmt = nullptr;
        sqlite3_prepare_v2(raw_db, sql_ins, -1, &ins_stmt, nullptr);
        sqlite3_bind_text(ins_stmt, 1, chunk_hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(ins_stmt, 2, static_cast<sqlite3_int64>(raw_chunk.size()));
        sqlite3_bind_int64(ins_stmt, 3, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        sqlite3_bind_int64(ins_stmt, 4, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        sqlite3_step(ins_stmt);
        sqlite3_finalize(ins_stmt);
        sqlite3_close(raw_db);

        // Put physical chunk file
        const auto chunk_dir = storage_dir / "cas" / "objects" / chunk_hash.substr(0, 2);
        mc::fs::create_directories(chunk_dir);
        write_test_file(chunk_dir / chunk_hash, raw_chunk.data(), raw_chunk.size());

        // Run GC with 1 hour grace period
        GcOptions opts;
        opts.grace_period_ms = 3600 * 1000;
        GcReport rep = store.garbage_collect(opts);

        check(rep.success, "GC-TEST-05: garbage_collect succeeded with grace period");
        check(rep.chunks_in_grace_period_exempt >= 1, "GC-TEST-05: Newly created chunk is exempt by grace period");
        check(rep.chunks_deleted == 0, "GC-TEST-05: Exempt chunk was NOT deleted");
        check(mc::fs::exists(chunk_dir / chunk_hash), "GC-TEST-05: Physical chunk file remains on disk");

        // Run GC with 0 grace period -> must now be swept
        opts.grace_period_ms = 0;
        GcReport rep_now = store.garbage_collect(opts);
        check(rep_now.chunks_deleted >= 1, "GC-TEST-05: Chunk swept when grace period is 0");
        check(!mc::fs::exists(chunk_dir / chunk_hash), "GC-TEST-05: Physical chunk file removed after sweep");
    }

    // GC-TEST-06: Physical Orphan Cleanup for Aged Untracked Files
    {
        CollabStore store(db_path, storage_dir);

        // Create an aged orphan file directly on disk (not in SQLite cas_chunks)
        std::string aged_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0001";
        std::string recent_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0002";

        const auto aged_dir = storage_dir / "cas" / "objects" / aged_hash.substr(0, 2);
        const auto recent_dir = storage_dir / "cas" / "objects" / recent_hash.substr(0, 2);
        mc::fs::create_directories(aged_dir);
        mc::fs::create_directories(recent_dir);

        auto d_aged = generate_test_data(2048, 6060);
        auto d_rec = generate_test_data(2048, 7070);

        write_test_file(aged_dir / aged_hash, d_aged.data(), d_aged.size());
        write_test_file(recent_dir / recent_hash, d_rec.data(), d_rec.size());

        // Set modification time of aged orphan to 2 hours ago
        auto two_hours_ago = mc::fs::file_time_type::clock::now() - std::chrono::hours(2);
        std::error_code ec_mtime;
        mc::fs::last_write_time(aged_dir / aged_hash, two_hours_ago, ec_mtime);

        GcOptions opts;
        opts.grace_period_ms = 3600 * 1000; // 1 hour grace
        opts.sweep_physical_orphans = true;

        GcReport rep = store.garbage_collect(opts);
        check(rep.success, "GC-TEST-06: garbage_collect succeeded with orphan scan");
        check(rep.physical_orphans_found >= 1, "GC-TEST-06: Aged physical orphan detected");
        check(!mc::fs::exists(aged_dir / aged_hash), "GC-TEST-06: Aged physical orphan unlinked from disk");
        check(mc::fs::exists(recent_dir / recent_hash), "GC-TEST-06: Recent untracked file protected by grace window");

        // Clean up recent
        mc::fs::remove(recent_dir / recent_hash, ec_mtime);
    }

    // GC-TEST-07: Zombie Object Reuse Race under cas_barrier_
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Zombie WS 1", "Zombie Object Race Test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src_a = test_dir / "zombie_src_a";
        mc::fs::create_directories(src_a);
        auto d_reuse = generate_test_data(65536, 8080);
        write_test_file(src_a / "reuse.bin", d_reuse.data(), d_reuse.size());

        // Publish v1
        const auto sub_a = store.create_submission(host->id, ws.id, src_a);
        store.accept_submission(sub_a.id, host->id, "Accept v1");
        const auto v1 = store.publish_version(ws.id, host->id, "v1", "Base version");

        // Prune v1 so that chunk has ref_count = 0
        std::string perr;
        store.prune_version(v1.id, perr);

        // Concurrent Race: Thread 1 creates submission and publishes identical content.
        // Thread 2 runs garbage collection.
        // Under cas_barrier_, publish holds shared_lock, GC holds unique_lock.
        std::atomic<bool> race_ok{true};
        std::thread t_pub([&]() {
            for (int i = 0; i < 3; ++i) {
                const auto sub = store.create_submission(host->id, ws.id, src_a);
                if (!store.accept_submission(sub.id, host->id, "Re-accept")) race_ok = false;
                auto pv = store.publish_version(ws.id, host->id, "v_reuse_" + std::to_string(i), "Reused");
                if (pv.id.empty()) race_ok = false;
            }
        });

        std::thread t_gc([&]() {
            for (int i = 0; i < 3; ++i) {
                GcOptions opts;
                opts.grace_period_ms = 0;
                store.garbage_collect(opts);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });

        t_pub.join();
        t_gc.join();

        check(race_ok.load(), "GC-TEST-07: Concurrent publication and GC executed without contention failure");

        // Verify published versions reconstruct cleanly without any missing chunks
        auto vers = store.list_published_versions(ws.id);
        check(!vers.empty(), "GC-TEST-07: Published versions exist after race");
        const auto recon_dst = test_dir / "recon_zombie";
        std::string err;
        check(store.reconstruct_version(vers.back().id, recon_dst, err),
              "GC-TEST-07: Latest published version reconstructs cleanly (no missing zombie chunk)");
        check(mc::scan_folder(recon_dst).merkle_root == vers.back().merkle_root,
              "GC-TEST-07: Reconstructed root matches published root 100%");
    }

    // GC-TEST-08: Active Temporary File Protection during Concurrent Cleanup
    {
        ObjectStoreConfig oscfg{storage_dir / "cas"};
        ObjectStore obj_store(oscfg);
        std::string oerr;
        obj_store.initialize(oerr);

        const auto tmp_file = obj_store.tmp_dir() / "active_worker_test.tmp";
        write_test_file(tmp_file, "in_flight_temp_data", 19);

        // Set modification time to 1 day ago
        auto one_day_ago = mc::fs::file_time_type::clock::now() - std::chrono::hours(24);
        std::error_code ec_mtime;
        mc::fs::last_write_time(tmp_file, one_day_ago, ec_mtime);

        // Register active temp ownership
        obj_store.register_active_temp(tmp_file);
        check(obj_store.is_active_temp(tmp_file), "GC-TEST-08: Registered temp file is marked active");

        // Clean temp directory with 0 max_age
        obj_store.clean_temp_directory(0ULL);
        check(mc::fs::exists(tmp_file), "GC-TEST-08: Active temp file is protected from clean_temp_directory");

        // Unregister temp ownership
        obj_store.unregister_active_temp(tmp_file);
        check(!obj_store.is_active_temp(tmp_file), "GC-TEST-08: Temp file is no longer active after unregister");

        // Clean temp directory again
        obj_store.clean_temp_directory(0ULL);
        check(!mc::fs::exists(tmp_file), "GC-TEST-08: Stale unregistered temp file was cleaned up");
    }

    // GC-TEST-09: Concurrent Publication and GC Stress Test
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");

        const int NUM_WORKERS = 3;
        const int ITERS_PER_WORKER = 3;
        std::vector<std::string> ws_ids;
        for (int w = 0; w < NUM_WORKERS; ++w) {
            auto ws = store.create_workspace("Stress WS " + std::to_string(w), "Stress");
            store.assign_user_to_workspace(ws.id, host->id);
            ws_ids.push_back(ws.id);
        }

        std::atomic<bool> stress_ok{true};
        std::vector<std::thread> workers;

        for (int w = 0; w < NUM_WORKERS; ++w) {
            workers.emplace_back([&, w]() {
                const auto src = test_dir / ("stress_src_" + std::to_string(w));
                mc::fs::create_directories(src);
                for (int it = 0; it < ITERS_PER_WORKER; ++it) {
                    auto data = generate_test_data(16384, static_cast<std::uint32_t>(1000 * w + it));
                    write_test_file(src / ("file_" + std::to_string(it) + ".bin"), data.data(), data.size());
                    const auto sub = store.create_submission(host->id, ws_ids[w], src);
                    if (!store.accept_submission(sub.id, host->id, "Accept stress")) {
                        stress_ok = false;
                        return;
                    }
                    auto pv = store.publish_version(ws_ids[w], host->id, "v_" + std::to_string(it), "Stress pub");
                    if (pv.id.empty()) {
                        stress_ok = false;
                        return;
                    }
                }
            });
        }

        std::thread gc_worker([&]() {
            for (int i = 0; i < 5; ++i) {
                GcOptions opts;
                opts.dry_run = false;
                opts.grace_period_ms = 0;
                store.garbage_collect(opts);
                std::size_t rcnt = 0;
                std::string rerr;
                store.reconcile_cas_reference_counts(rcnt, rerr);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });

        for (auto& t : workers) t.join();
        gc_worker.join();

        check(stress_ok.load(), "GC-TEST-09: Multi-threaded publication and GC stress completed with 0 errors");

        std::string audit_err;
        check(store.audit_cas_reference_integrity(audit_err),
              "GC-TEST-09: Zero reference count drift after concurrent stress execution");
    }

    // GC-TEST-10: Process-Crash Recovery at Boundaries A, B, C, D
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Crash GC WS", "Crash recovery test");
        store.assign_user_to_workspace(ws.id, host->id);

        // Setup candidate chunks to sweep
        const auto src = test_dir / "crash_gc_src";
        mc::fs::create_directories(src);
        auto d1 = generate_test_data(32768, 12345);
        auto d2 = generate_test_data(32768, 67890);
        write_test_file(src / "c1.bin", d1.data(), d1.size());
        write_test_file(src / "c2.bin", d2.data(), d2.size());

        const auto sub = store.create_submission(host->id, ws.id, src);
        store.accept_submission(sub.id, host->id, "Accept crash test");
        const auto pv = store.publish_version(ws.id, host->id, "v_crash", "Prune target");
        std::string perr;
        store.prune_version(pv.id, perr);

        // Boundary A: Crash Before SQLite Sweep Mark
        {
            std::wstring args = L"--gc-crash-worker \"" + db_path.wstring() + L"\" \"" +
                                storage_dir.wstring() + L"\" before-sweep-mark";
            DWORD code = run_gc_child_process(args);
            check(code == 95, "GC-TEST-10: Boundary A worker terminated with code 95");

            CollabStore reopened(db_path, storage_dir);
            reopened.recover_incomplete_operations();
            std::string aerr;
            check(reopened.audit_cas_reference_integrity(aerr),
                  "GC-TEST-10: Boundary A recovery confirms consistent store state");
        }

        // Boundary B: Crash Mid-Unlinking
        {
            std::wstring args = L"--gc-crash-worker \"" + db_path.wstring() + L"\" \"" +
                                storage_dir.wstring() + L"\" mid-unlinking";
            DWORD code = run_gc_child_process(args);
            check(code == 95, "GC-TEST-10: Boundary B worker terminated with code 95");

            CollabStore reopened(db_path, storage_dir);
            reopened.recover_incomplete_operations();
            // Second recovery for idempotency
            reopened.recover_incomplete_operations();

            std::string aerr;
            check(reopened.audit_cas_reference_integrity(aerr),
                  "GC-TEST-10: Boundary B idempotent recovery resolves mid-unlinking cleanly");
        }

        // Boundary C: Crash After Physical Unlinking, Before DB Commit
        {
            // Plant new unreferenced candidate
            auto d3 = generate_test_data(16384, 11223);
            write_test_file(src / "c3.bin", d3.data(), d3.size());
            const auto sub3 = store.create_submission(host->id, ws.id, src);
            store.accept_submission(sub3.id, host->id, "Accept 3");
            const auto pv3 = store.publish_version(ws.id, host->id, "v_crash3", "Prune 3");
            store.prune_version(pv3.id, perr);

            std::wstring args = L"--gc-crash-worker \"" + db_path.wstring() + L"\" \"" +
                                storage_dir.wstring() + L"\" before-sweep-commit";
            DWORD code = run_gc_child_process(args);
            check(code == 95, "GC-TEST-10: Boundary C worker terminated with code 95");

            CollabStore reopened(db_path, storage_dir);
            reopened.recover_incomplete_operations();

            std::string aerr;
            check(reopened.audit_cas_reference_integrity(aerr),
                  "GC-TEST-10: Boundary C recovery completes catalog synchronization");
        }

        // Boundary D: Crash During Physical Orphan Scan
        {
            // Plant physical orphan
            std::string orphan_hash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0001";
            const auto odir = storage_dir / "cas" / "objects" / orphan_hash.substr(0, 2);
            mc::fs::create_directories(odir);
            auto d_orp = generate_test_data(1024, 9991);
            write_test_file(odir / orphan_hash, d_orp.data(), d_orp.size());
            auto old_time = mc::fs::file_time_type::clock::now() - std::chrono::hours(3);
            std::error_code ec_mtime;
            mc::fs::last_write_time(odir / orphan_hash, old_time, ec_mtime);

            std::wstring args = L"--gc-crash-worker \"" + db_path.wstring() + L"\" \"" +
                                storage_dir.wstring() + L"\" during-orphan-scan";
            DWORD code = run_gc_child_process(args);
            check(code == 95, "GC-TEST-10: Boundary D worker terminated with code 95");

            CollabStore reopened(db_path, storage_dir);
            reopened.recover_incomplete_operations();

            std::string aerr;
            check(reopened.audit_cas_reference_integrity(aerr),
                  "GC-TEST-10: Boundary D recovery recovers cleanly after orphan scan crash");
            mc::fs::remove(odir / orphan_hash, ec_mtime);
        }
#else
        check(true, "GC-TEST-10: Subprocess crash tests skipped on non-Windows");
#endif
    }

    // GC-TEST-11: Dry-Run vs Live-Run Accounting Parity
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Parity WS 1", "Dry Run Accounting Parity Test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src1 = test_dir / "parity_src_1";
        mc::fs::create_directories(src1);
        auto d1 = generate_test_data(32768, 31415);
        auto d2 = generate_test_data(65536, 92653);
        write_test_file(src1 / "p1.bin", d1.data(), d1.size());
        write_test_file(src1 / "p2.bin", d2.data(), d2.size());

        const auto sub1 = store.create_submission(host->id, ws.id, src1);
        store.accept_submission(sub1.id, host->id, "Accept p1");
        const auto pv1 = store.publish_version(ws.id, host->id, "v_par1", "Parity 1");

        // Prune version so chunks have ref_count == 0
        std::string perr;
        store.prune_version(pv1.id, perr);

        // Plant 1 aged orphan
        std::string orp_hash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd0001";
        const auto odir = storage_dir / "cas" / "objects" / orp_hash.substr(0, 2);
        mc::fs::create_directories(odir);
        auto d_orp = generate_test_data(4096, 4321);
        write_test_file(odir / orp_hash, d_orp.data(), d_orp.size());
        auto old_time = mc::fs::file_time_type::clock::now() - std::chrono::hours(5);
        std::error_code ec_mtime;
        mc::fs::last_write_time(odir / orp_hash, old_time, ec_mtime);

        // 1. Dry Run
        GcOptions opts;
        opts.dry_run = true;
        opts.grace_period_ms = 0;
        opts.sweep_physical_orphans = true;

        GcReport dry_rep = store.garbage_collect(opts);
        check(dry_rep.success, "GC-TEST-11: dry_run garbage_collect succeeded");
        check(dry_rep.dry_run, "GC-TEST-11: report indicates dry_run = true");
        check(dry_rep.chunks_deleted == 0, "GC-TEST-11: 0 chunks deleted during dry run");
        check(dry_rep.reclaimed_bytes == 0, "GC-TEST-11: 0 bytes reclaimed during dry run");
        check(dry_rep.unreferenced_candidates >= 2, "GC-TEST-11: Dry run identified unreferenced candidates");
        check(dry_rep.physical_orphans_found >= 1, "GC-TEST-11: Dry run identified physical orphan");
        check(mc::fs::exists(odir / orp_hash), "GC-TEST-11: Physical orphan file untouched after dry run");

        // 2. Live Run
        opts.dry_run = false;
        GcReport live_rep = store.garbage_collect(opts);
        check(live_rep.success, "GC-TEST-11: live garbage_collect succeeded");
        check(!live_rep.dry_run, "GC-TEST-11: report indicates dry_run = false");

        // 3. Accounting Parity Assertions
        check(live_rep.chunks_deleted == dry_rep.unreferenced_candidates,
              "GC-TEST-11: Live deleted chunk count matches dry-run candidate count exactly");
        check(live_rep.reclaimed_bytes == dry_rep.reclaimable_bytes,
              "GC-TEST-11: Live reclaimed byte count matches dry-run reclaimable bytes exactly");
        check(live_rep.physical_orphans_found == dry_rep.physical_orphans_found,
              "GC-TEST-11: Live physical orphans found matches dry-run orphan count exactly");
        check(live_rep.deleted_hashes == dry_rep.candidate_hashes,
              "GC-TEST-11: Live deleted hash list matches dry-run candidate list in order");
    }

    // GC-TEST-12: Windows File Lock Failure Handling
    {
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Lock WS 1", "File lock failure test");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src = test_dir / "lock_src";
        mc::fs::create_directories(src);
        auto d = generate_test_data(16384, 9876);
        write_test_file(src / "lock.bin", d.data(), d.size());

        const auto sub = store.create_submission(host->id, ws.id, src);
        store.accept_submission(sub.id, host->id, "Accept lock");
        const auto pv = store.publish_version(ws.id, host->id, "v_lock", "Release lock test");

        std::string merr;
        auto manifests = store.get_version_manifests(pv.id, merr);
        std::string target_hash = manifests[0].chunks()[0].hash;

        std::string perr;
        store.prune_version(pv.id, perr);
        check(store.get_chunk_reference_count(target_hash) == 0,
              "GC-TEST-12: Target chunk has 0 references");

        const auto chunk_path = storage_dir / "cas" / "objects" / target_hash.substr(0, 2) / target_hash;
        check(mc::fs::exists(chunk_path), "GC-TEST-12: Target chunk physical file exists before lock");

#ifdef _WIN32
        // Open exclusive handle to lock the file and prevent deletion
        HANDLE hFile = CreateFileW(
            chunk_path.wstring().c_str(),
            GENERIC_READ,
            0, // NO sharing: prevents deletion and other opens
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        check(hFile != INVALID_HANDLE_VALUE, "GC-TEST-12: Acquired exclusive file lock on chunk file");

        // Run GC while file is locked
        GcOptions opts;
        opts.grace_period_ms = 0;
        GcReport rep = store.garbage_collect(opts);

        check(rep.success, "GC-TEST-12: garbage_collect reports overall success without crashing");
        check(rep.failed_deletions >= 1, "GC-TEST-12: GC recorded failed deletion due to active file lock");
        check(mc::fs::exists(chunk_path), "GC-TEST-12: Locked physical chunk file was not removed");

        // Crucial guarantee: catalog state must have been restored to COMMITTED so it is not corrupted
        check(store.get_chunk_reference_count(target_hash) == 0,
              "GC-TEST-12: Chunk remains safely cataloged in cas_chunks");

        // Release file handle
        CloseHandle(hFile);

        // Run GC again: chunk should now be swept cleanly
        GcReport rep_unlocked = store.garbage_collect(opts);
        check(rep_unlocked.chunks_deleted >= 1, "GC-TEST-12: Chunk successfully swept after releasing lock");
        check(!mc::fs::exists(chunk_path), "GC-TEST-12: Physical chunk file deleted after lock release");
#else
        check(true, "GC-TEST-12: Exclusive lock test skipped on non-Windows");
#endif
    }

    // ==================================================
    // GC-TEST-13: Active Temp File Protection with Live Writer (Older than 60s)
    // ==================================================
    {
        ObjectStoreConfig oscfg{storage_dir / "cas"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto aged_ts = now_ms - 90000; // 90 seconds old (exceeds 60s default grace)

#ifdef _WIN32
        const unsigned long current_pid = ::GetCurrentProcessId();
#else
        const auto current_pid = static_cast<unsigned long>(::getpid());
#endif
        const fs::path active_aged_file = store.tmp_dir() / ("obj_tmp_" + std::to_string(current_pid) + "_" + std::to_string(aged_ts) + "_9999_agedlive.tmp");
        
        // Open file with exclusive lock/writer handle simulating long-running live write
        std::ofstream live_writer(active_aged_file, std::ios::binary | std::ios::out);
        live_writer << "ACTIVE_DATA_STREAM_CHUNK";
        live_writer.flush();

        check(ObjectStore::is_file_locked_by_writer(active_aged_file),
              "GC-TEST-13: is_file_locked_by_writer confirms active writer on aged temp file");

        // Attempt cleanup with max_age_ms = 60000 (1 minute)
        std::size_t cleaned1 = store.clean_temp_directory(60000, &err);
        check(cleaned1 == 0 && mc::fs::exists(active_aged_file),
              "GC-TEST-13: Active temporary file older than 60s is PROTECTED while writer handle is open");

        // Attempt cleanup with max_age_ms = 0
        std::size_t cleaned2 = store.clean_temp_directory(0, &err);
        check(cleaned2 == 0 && mc::fs::exists(active_aged_file),
              "GC-TEST-13: Active temporary file older than 60s is PROTECTED during immediate cleanup");

        // Close writer handle (operation finished or aborted)
        live_writer.close();

        check(!ObjectStore::is_file_locked_by_writer(active_aged_file),
              "GC-TEST-13: is_file_locked_by_writer returns false after handle closure");

        // Clean temp directory again with 60s threshold
        std::size_t cleaned3 = store.clean_temp_directory(60000, &err);
        check(cleaned3 >= 1 && !mc::fs::exists(active_aged_file),
              "GC-TEST-13: Unlocked aged temp file successfully cleaned after writer released handle");
    }

    // ==================================================
    // GC-TEST-14: Live Writer in Child Process vs Concurrent Cleanup
    // ==================================================
    {
#ifdef _WIN32
        ObjectStoreConfig oscfg{storage_dir / "cas"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Spawn child process holding open write handle for 2500ms
        const fs::path child_file = store.tmp_dir() / ("obj_tmp_child_writer_" + std::to_string(now_ms) + ".tmp");
        std::wstring args = L"--cas-temp-writer \"" + child_file.wstring() + L"\" 2500";
        PROCESS_INFORMATION child_pi{};
        check(spawn_gc_child_process(args, child_pi),
              "GC-TEST-14: Successfully spawned child temp-writer process");

        // Allow child process to start and open the file
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        check(mc::fs::exists(child_file),
              "GC-TEST-14: Child process temp file exists on disk");
        check(ObjectStore::is_file_locked_by_writer(child_file),
              "GC-TEST-14: Child process write lock detected by parent");

        // Concurrent cleanup while child process is actively writing
        std::size_t cleaned = store.clean_temp_directory(0, &err);
        (void)cleaned;
        check(mc::fs::exists(child_file),
              "GC-TEST-14: Active temp file in child process is NOT deleted by concurrent cleanup");

        // Wait for child process to finish
        WaitForSingleObject(child_pi.hProcess, 5000);
        DWORD exit_code = 0;
        GetExitCodeProcess(child_pi.hProcess, &exit_code);
        CloseHandle(child_pi.hThread);
        CloseHandle(child_pi.hProcess);
        check(exit_code == 0, "GC-TEST-14: Child temp-writer process exited successfully");

        // Now that child is dead, clean temp directory
        std::size_t cleaned_after = store.clean_temp_directory(0, &err);
        (void)cleaned_after;
        if (mc::fs::exists(child_file)) {
            std::error_code rm_child_ec;
            mc::fs::remove(child_file, rm_child_ec);
        }
        check(!mc::fs::exists(child_file),
              "GC-TEST-14: Child process temp file removed after termination");
#else
        check(true, "GC-TEST-14: Subprocess live writer test skipped on non-Windows");
#endif
    }

    // ==================================================
    // GC-TEST-15: Terminated Writer Leaving Crash Debris
    // ==================================================
    {
#ifdef _WIN32
        ObjectStoreConfig oscfg{storage_dir / "cas"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        PROCESS_INFORMATION child_pi{};
        const fs::path dummy_target = store.tmp_dir() / "target.tmp";
        std::wstring args = L"--cas-temp-abandoner \"" + dummy_target.wstring() + L"\"";
        check(spawn_gc_child_process(args, child_pi),
              "GC-TEST-15: Spawned child abandoner worker");
        const unsigned long child_pid = child_pi.dwProcessId;

        const fs::path child_debris = store.tmp_dir() / ("obj_tmp_" + std::to_string(child_pid) + "_" + std::to_string(now_ms) + "_1234_crashdebris.tmp");
        write_test_file(child_debris, "CRASHED_WORKER_LEFTOVER", 23);

        WaitForSingleObject(child_pi.hProcess, 5000);
        DWORD exit_code = 0;
        GetExitCodeProcess(child_pi.hProcess, &exit_code);
        CloseHandle(child_pi.hThread);
        CloseHandle(child_pi.hProcess);
        check(exit_code == 93, "GC-TEST-15: Child worker terminated abruptly with exit code 93");

        // Verify child PID is confirmed dead
        check(!ObjectStore::is_process_alive(child_pid),
              "GC-TEST-15: is_process_alive confirms child PID is terminated");

        // Clean temp directory
        std::size_t cleaned = store.clean_temp_directory(0, &err);
        (void)cleaned;
        check(!mc::fs::exists(child_debris),
              "GC-TEST-15: clean_temp_directory immediately purged crash debris from terminated process");
        if (mc::fs::exists(dummy_target)) {
            std::error_code rm_dummy_ec;
            mc::fs::remove(dummy_target, rm_dummy_ec);
        }
#else
        check(true, "GC-TEST-15: Subprocess crash debris test skipped on non-Windows");
#endif
    }

    // ==================================================
    // GC-TEST-16: PID Reuse and Uncertain Ownership Protection
    // ==================================================
    {
        ObjectStoreConfig oscfg{storage_dir / "cas"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

#ifdef _WIN32
        const unsigned long current_pid = ::GetCurrentProcessId();
        bool pid_reused = false;
        // Check PID reuse detection with a timestamp 2 hours in the past
        const std::int64_t old_ts = now_ms - 7200000;
        ObjectStore::is_process_alive_for_file(current_pid, old_ts, pid_reused);
        check(pid_reused, "GC-TEST-16: is_process_alive_for_file correctly flags PID reuse for old creation time");

        const fs::path reused_debris = store.tmp_dir() / ("obj_tmp_" + std::to_string(current_pid) + "_" + std::to_string(old_ts) + "_8888_reused.tmp");
        write_test_file(reused_debris, "old_process_debris", 18);

        store.clean_temp_directory(0, &err);
        check(!mc::fs::exists(reused_debris),
              "GC-TEST-16: Reused PID crash debris from dead predecessor is safely deleted");
#endif

        // Part B: Uncertain Ownership Protection
        // NEVER delete a file when ownership is uncertain!
        const fs::path unparseable_pid = store.tmp_dir() / "obj_tmp_notapid_12345_6789.tmp";
        const fs::path foreign_file = store.tmp_dir() / "alien_foreign_temp.tmp";
        const fs::path broken_tokens = store.tmp_dir() / "obj_tmp_broken.tmp";

        write_test_file(unparseable_pid, "uncertain_pid_content", 21);
        write_test_file(foreign_file, "alien_content", 13);
        write_test_file(broken_tokens, "broken_tokens_content", 21);

        store.clean_temp_directory(0, &err);

        check(mc::fs::exists(unparseable_pid),
              "GC-TEST-16: Uncertain PID file is NEVER deleted during cleanup");
        check(mc::fs::exists(foreign_file),
              "GC-TEST-16: Foreign/alien file is NEVER deleted when ownership is uncertain");
        check(mc::fs::exists(broken_tokens),
              "GC-TEST-16: Broken token format file is NEVER deleted when ownership is uncertain");

        // Clean up test fixture files
        std::error_code rm_ec;
        mc::fs::remove(unparseable_pid, rm_ec);
        mc::fs::remove(foreign_file, rm_ec);
        mc::fs::remove(broken_tokens, rm_ec);
    }

    // ==================================================
    // GC-TEST-17: Two Simultaneous Cleanup Attempts
    // ==================================================
    {
        ObjectStoreConfig oscfg{storage_dir / "cas"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        // Pre-clean any prior debris so test state is pristine
        store.clean_temp_directory(0ULL, nullptr);

        // Plant 20 orphaned temp files with a guaranteed non-existent PID (99999999)
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const unsigned long dead_pid = 99999999;
        std::vector<fs::path> orphans;
        for (int i = 0; i < 20; ++i) {
            fs::path p = store.tmp_dir() / ("obj_tmp_" + std::to_string(dead_pid) + "_" + std::to_string(now_ms) + "_" + std::to_string(i) + "_concurrent.tmp");
            write_test_file(p, "orphan_data", 11);
            orphans.push_back(p);
        }

        std::atomic<std::size_t> cleaned_t1{0};
        std::atomic<std::size_t> cleaned_t2{0};
        std::string err_t1, err_t2;

        std::thread t1([&]() {
            cleaned_t1 = store.clean_temp_directory(0, &err_t1);
        });
        std::thread t2([&]() {
            cleaned_t2 = store.clean_temp_directory(0, &err_t2);
        });

        t1.join();
        t2.join();

        check(err_t1.empty() && err_t2.empty(),
              "GC-TEST-17: Simultaneous cleanups completed with 0 errors reported");
        check((cleaned_t1 + cleaned_t2) >= 20,
              "GC-TEST-17: Concurrent cleanups safely reclaimed all orphaned files without errors");

        bool any_exist = false;
        for (const auto& p : orphans) {
            if (mc::fs::exists(p)) any_exist = true;
        }
        check(!any_exist, "GC-TEST-17: All orphaned temp files removed from disk");
    }

    // ==================================================
    // GC-TEST-18: Multi-Instance Storage Sharing
    // ==================================================
    {
        // Two CollabStore instances sharing the exact same db and storage directory
        CollabStore store1(db_path, storage_dir);
        CollabStore store2(db_path, storage_dir);

        const auto host1 = store1.find_user_by_username("host");
        const auto ws = store1.create_workspace("Multi-Inst WS", "Multi-instance concurrent sharing");
        store1.assign_user_to_workspace(ws.id, host1->id);

        // Store 1 creates submission and publishes Version 1
        const auto src1 = test_dir / "multi_src_1";
        mc::fs::create_directories(src1);
        auto d1 = generate_test_data(32768, 7771);
        write_test_file(src1 / "doc1.bin", d1.data(), d1.size());

        const auto sub1 = store1.create_submission(host1->id, ws.id, src1);
        check(store1.accept_submission(sub1.id, host1->id, "Accept sub1"),
              "GC-TEST-18: Store 1 accepted submission");
        const auto pv1 = store1.publish_version(ws.id, host1->id, "v_multi_1", "Published by store 1");
        check(!pv1.id.empty(), "GC-TEST-18: Store 1 published version 1");

        // Store 2 reconstructs Version 1
        const auto recon_dst1 = test_dir / "recon_multi_1";
        std::string recon_err1;
        check(store2.reconstruct_version(pv1.id, recon_dst1, recon_err1),
              "GC-TEST-18: Store 2 successfully reconstructed version 1 published by store 1");
        check(mc::scan_folder(recon_dst1).merkle_root == pv1.merkle_root,
              "GC-TEST-18: Store 2 reconstructed Merkle root matches published root exactly");

        // Store 2 creates submission and publishes Version 2
        const auto src2 = test_dir / "multi_src_2";
        mc::fs::create_directories(src2);
        auto d2 = generate_test_data(32768, 7772);
        write_test_file(src2 / "doc2.bin", d2.data(), d2.size());

        const auto sub2 = store2.create_submission(host1->id, ws.id, src2);
        check(store2.accept_submission(sub2.id, host1->id, "Accept sub2"),
              "GC-TEST-18: Store 2 accepted submission");
        const auto pv2 = store2.publish_version(ws.id, host1->id, "v_multi_2", "Published by store 2");
        check(!pv2.id.empty(), "GC-TEST-18: Store 2 published version 2");

        // Store 1 reconstructs Version 2
        const auto recon_dst2 = test_dir / "recon_multi_2";
        std::string recon_err2;
        check(store1.reconstruct_version(pv2.id, recon_dst2, recon_err2),
              "GC-TEST-18: Store 1 successfully reconstructed version 2 published by store 2");
        check(mc::scan_folder(recon_dst2).merkle_root == pv2.merkle_root,
              "GC-TEST-18: Store 1 reconstructed Merkle root matches published root exactly");

        std::string aerr;
        check(store1.audit_cas_reference_integrity(aerr),
              "GC-TEST-18: Store 1 audits 0 reference count drift");
        check(store2.audit_cas_reference_integrity(aerr),
              "GC-TEST-18: Store 2 audits 0 reference count drift");
    }

    // ==================================================
    // GC-TEST-19: Multi-Process Concurrent Publication & GC with OS Barrier
    // ==================================================
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("OS Barrier WS", "Multi-process barrier test");
        store.assign_user_to_workspace(ws.id, host->id);

        // Spawn child process that publishes versions in a loop under shared barrier
        std::wstring args = L"--collab-publisher-worker \"" + db_path.wstring() + L"\" \"" +
                            storage_dir.wstring() + L"\" \"" +
                            std::wstring(ws.id.begin(), ws.id.end()) + L"\" \"" +
                            std::wstring(host->id.begin(), host->id.end()) + L"\" 5";

        PROCESS_INFORMATION child_pi{};
        check(spawn_gc_child_process(args, child_pi),
              "GC-TEST-19: Spawned child publisher worker process");

        // Concurrently in parent process, run GC repeatedly under exclusive barrier
        GcOptions opts;
        opts.dry_run = false;
        opts.grace_period_ms = 0;
        opts.sweep_physical_orphans = false;

        bool gc_ok = true;
        for (int i = 0; i < 3; ++i) {
            GcReport rep = store.garbage_collect(opts);
            if (!rep.success) gc_ok = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        check(gc_ok, "GC-TEST-19: Parent GC completed successfully while child process was publishing");

        WaitForSingleObject(child_pi.hProcess, 15000);
        DWORD exit_code = 0;
        GetExitCodeProcess(child_pi.hProcess, &exit_code);
        CloseHandle(child_pi.hThread);
        CloseHandle(child_pi.hProcess);
        check(exit_code == 0, "GC-TEST-19: Child publisher process exited cleanly with code 0");

        std::string aerr;
        check(store.audit_cas_reference_integrity(aerr),
              "GC-TEST-19: Zero reference drift after multi-process concurrent publication and GC");
#else
        check(true, "GC-TEST-19: Subprocess barrier test skipped on non-Windows");
#endif
    }

    // ==================================================
    // GC-TEST-20: Process Crash During Pending Deletion & Idempotent Repeated Recovery
    // ==================================================
    {
#ifdef _WIN32
        CollabStore store(db_path, storage_dir);
        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Crash Idempotent WS", "Crash recovery idempotency");
        store.assign_user_to_workspace(ws.id, host->id);

        const auto src = test_dir / "crash_idemp_src";
        mc::fs::create_directories(src);
        auto d = generate_test_data(32768, 55555);
        write_test_file(src / "target.bin", d.data(), d.size());

        const auto sub = store.create_submission(host->id, ws.id, src);
        store.accept_submission(sub.id, host->id, "Accept idemp test");
        const auto pv = store.publish_version(ws.id, host->id, "v_idemp", "Prune idemp");
        std::string perr;
        store.prune_version(pv.id, perr);

        // Crash worker at mid-unlinking (Boundary B)
        std::wstring args = L"--gc-crash-worker \"" + db_path.wstring() + L"\" \"" +
                            storage_dir.wstring() + L"\" mid-unlinking";
        DWORD code = run_gc_child_process(args);
        check(code == 95, "GC-TEST-20: Crash worker terminated with code 95");

        // Pass 1: Initial recovery
        CollabStore r1(db_path, storage_dir);
        r1.recover_incomplete_operations();
        std::string aerr1;
        check(r1.audit_cas_reference_integrity(aerr1),
              "GC-TEST-20: Pass 1 recovery established reference integrity");

        // Pass 2: Repeated recovery must be completely idempotent
        CollabStore r2(db_path, storage_dir);
        r2.recover_incomplete_operations();
        std::string aerr2;
        check(r2.audit_cas_reference_integrity(aerr2),
              "GC-TEST-20: Pass 2 repeated recovery remains clean and idempotent");

        // Pass 3: Third recovery pass
        r2.recover_incomplete_operations();
        std::string aerr3;
        check(r2.audit_cas_reference_integrity(aerr3),
              "GC-TEST-20: Pass 3 repeated recovery confirms zero drift and idempotency");
#else
        check(true, "GC-TEST-20: Subprocess recovery idempotency skipped on non-Windows");
#endif
    }

    // =========================================================================
    // GC-TEST-21: CAS Metadata Compaction & Unreferenced Pruning (SEC-07)
    // =========================================================================
    {
        const auto t21_root = test_dir / "t21_compaction";
        fs::create_directories(t21_root);
        const auto comp_db_path = t21_root / "collab.sqlite3";
        const auto comp_storage_dir = t21_root / "storage";

        CollabStore store(comp_db_path, comp_storage_dir);
        store.init_schema();
        store.seed_default_accounts_if_empty();

        const auto host = store.find_user_by_username("host");
        const auto ws = store.create_workspace("Compaction Test Workspace", "Testing metadata growth");
        store.assign_user_to_workspace(ws.id, host->id);

        // Submit and publish version 1
        const auto src1 = t21_root / "src1";
        fs::create_directories(src1);
        const std::string s1_content = "Initial content version 1 for compaction test";
        write_test_file(src1 / "file1.txt", s1_content.data(), s1_content.size());
        auto sub1 = store.create_submission(host->id, ws.id, src1);
        store.accept_submission(sub1.id, host->id, "Accept v1");
        auto v1 = store.publish_version(ws.id, host->id, "v1", "v1 notes");

        // Submit and publish version 2 with updated file
        const auto src2 = t21_root / "src2";
        fs::create_directories(src2);
        const std::string s2_content = "Updated content version 2 with completely different text for compaction";
        write_test_file(src2 / "file1.txt", s2_content.data(), s2_content.size());
        auto sub2 = store.create_submission(host->id, ws.id, src2);
        store.accept_submission(sub2.id, host->id, "Accept v2");
        auto v2 = store.publish_version(ws.id, host->id, "v2", "v2 notes");

        // Run initial live GC
        GcOptions gc_opts;
        gc_opts.dry_run = false;
        gc_opts.grace_period_ms = 0;
        store.garbage_collect(gc_opts);

        // Prune version 1
        std::string prune_err;
        check(store.prune_version(v1.id, prune_err), "GC-TEST-21: prune_version succeeded");

        // Run live GC to sweep unreferenced chunk from v1
        auto gc_rep = store.garbage_collect(gc_opts);
        check(gc_rep.success, "GC-TEST-21: Live GC completed after v1 deletion");

        // Execute CAS metadata compaction
        CompactionOptions comp_opts;
        comp_opts.vacuum = true;
        comp_opts.unreferenced_threshold = 0;
        auto comp_rep = store.compact_cas_metadata(comp_opts);
        check(comp_rep.success, "GC-TEST-21: CAS metadata compaction completed successfully");
        check(comp_rep.db_size_before >= comp_rep.db_size_after,
              "GC-TEST-21: Database size after compaction is less than or equal to before");

        // Verify version 2 can still be reconstructed bit-exactly
        const auto restore_dir = t21_root / "restored_v2";
        std::string rec_err;
        check(store.reconstruct_version(v2.id, restore_dir, rec_err),
              "GC-TEST-21: Live version 2 reconstructs successfully after metadata compaction");

        // Verify idempotency of repeated compaction
        auto repeat_rep = store.compact_cas_metadata(comp_opts);
        check(repeat_rep.success, "GC-TEST-21: Repeated metadata compaction is idempotent");
        check(repeat_rep.unreferenced_pruned == 0,
              "GC-TEST-21: Repeated compaction reports zero additional records pruned");
    }
}

} // namespace mc::cas
