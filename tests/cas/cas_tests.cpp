#include "cas_tests.hpp"
#include "merklechain/cas/chunker.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/object_verifier.hpp"
#include "merklechain/hash.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

namespace mc::cas {

namespace {

std::vector<std::uint8_t> generate_pattern_data(std::size_t size, std::uint32_t seed = 42) {
    std::vector<std::uint8_t> data(size);
    std::mt19937 rng(seed);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::uint8_t>(rng() & 0xFF);
    }
    return data;
}

void write_test_file(const fs::path& p, const void* data, std::size_t size) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (size > 0 && data != nullptr) {
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
}

#ifdef _WIN32
#include <windows.h>

DWORD run_cas_child_process(const std::wstring& arguments) {
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

bool run_two_concurrent_cas_children(const std::wstring& args1, const std::wstring& args2, DWORD& code1, DWORD& code2) {
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size()) return false;
    executable.resize(length);

    std::wstring command1 = L"\"" + executable + L"\" " + args1;
    std::wstring command2 = L"\"" + executable + L"\" " + args2;

    STARTUPINFOW s1{}, s2{};
    s1.cb = sizeof(s1);
    s2.cb = sizeof(s2);
    PROCESS_INFORMATION p1{}, p2{};

    if (!CreateProcessW(executable.c_str(), command1.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &s1, &p1)) {
        return false;
    }
    if (!CreateProcessW(executable.c_str(), command2.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &s2, &p2)) {
        CloseHandle(p1.hThread);
        CloseHandle(p1.hProcess);
        return false;
    }

    HANDLE handles[2] = { p1.hProcess, p2.hProcess };
    WaitForMultipleObjects(2, handles, TRUE, INFINITE);

    GetExitCodeProcess(p1.hProcess, &code1);
    GetExitCodeProcess(p2.hProcess, &code2);

    CloseHandle(p1.hThread);
    CloseHandle(p1.hProcess);
    CloseHandle(p2.hThread);
    CloseHandle(p2.hProcess);
    return true;
}
#endif

} // namespace

void run_cas_tests(const mc::fs::path& fixture_root, void (*check)(bool, const char*)) {
    const fs::path root = fixture_root / "cas_test_suite";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);

    // =========================================================================
    // 1. FastCDC Boundary & Determinism Tests
    // =========================================================================

    // CAS-FCDC-01: Empty file / buffer produces 0 chunks
    {
        FastCDCChunker chunker;
        auto chunks = chunker.chunk_buffer(nullptr, 0);
        check(chunks.empty(), "CAS-FCDC-01: Empty buffer produces 0 chunks");

        const fs::path empty_file = root / "empty.txt";
        write_test_file(empty_file, nullptr, 0);
        auto file_chunks = chunker.chunk_file(empty_file);
        check(file_chunks.empty(), "CAS-FCDC-01: Empty file produces 0 chunks");
    }

    // CAS-FCDC-02: Small file (< min_size) produces exactly 1 chunk
    {
        ChunkerConfig cfg;
        cfg.min_size = 4096;
        cfg.avg_size = 8192;
        cfg.max_size = 16384;
        FastCDCChunker chunker(cfg);

        auto data = generate_pattern_data(100, 101);
        auto chunks = chunker.chunk_buffer(data.data(), data.size());
        const bool ok = chunks.size() == 1 &&
                        chunks[0].offset == 0 &&
                        chunks[0].size == 100 &&
                        chunks[0].hash == mc::sha256_data(data.data(), data.size());
        check(ok, "CAS-FCDC-02: Small buffer (< min_size) produces exactly 1 chunk with matching SHA-256");
    }

    // CAS-FCDC-03: Boundary sizes (== min_size, == avg_size, == max_size)
    {
        ChunkerConfig cfg;
        cfg.min_size = 2048;
        cfg.avg_size = 4096;
        cfg.max_size = 8192;
        FastCDCChunker chunker(cfg);

        auto data_min = generate_pattern_data(2048, 201);
        auto chunks_min = chunker.chunk_buffer(data_min.data(), data_min.size());
        check(chunks_min.size() == 1 && chunks_min[0].size == 2048,
              "CAS-FCDC-03: Exact min_size buffer produces 1 chunk");

        auto data_max = generate_pattern_data(8192, 202);
        auto chunks_max = chunker.chunk_buffer(data_max.data(), data_max.size());
        std::uint64_t total_size = 0;
        for (const auto& c : chunks_max) total_size += c.size;
        check(total_size == 8192 && !chunks_max.empty(),
              "CAS-FCDC-03: Exact max_size buffer chunk sum equals total size");
    }

    // CAS-FCDC-04: Deterministic chunking across multiple iterations
    {
        FastCDCChunker chunker;
        auto data = generate_pattern_data(65536, 303);
        auto c1 = chunker.chunk_buffer(data.data(), data.size());
        auto c2 = chunker.chunk_buffer(data.data(), data.size());
        bool identical = (c1.size() == c2.size()) && !c1.empty();
        for (std::size_t i = 0; i < c1.size() && identical; ++i) {
            if (c1[i] != c2[i]) identical = false;
        }
        check(identical, "CAS-FCDC-04: FastCDC chunking is 100% deterministic on identical data");
    }

    // CAS-FCDC-05: FastCDC shift resistance vs Fixed chunking
    {
        // 128 KB base buffer
        auto base_data = generate_pattern_data(128 * 1024, 404);

        // Modified buffer: insert 17 bytes at offset 5000 (shifting all subsequent byte positions)
        std::vector<std::uint8_t> mod_data;
        mod_data.reserve(base_data.size() + 17);
        mod_data.insert(mod_data.end(), base_data.begin(), base_data.begin() + 5000);
        std::string insertion = "SHIFT_TEST_BYTES!";
        mod_data.insert(mod_data.end(), insertion.begin(), insertion.end());
        mod_data.insert(mod_data.end(), base_data.begin() + 5000, base_data.end());

        // A. Fixed chunking (8KB)
        FixedChunker fixed_chunker(8192);
        auto fixed_base = fixed_chunker.chunk_buffer(base_data.data(), base_data.size());
        auto fixed_mod = fixed_chunker.chunk_buffer(mod_data.data(), mod_data.size());

        std::size_t fixed_matches = 0;
        for (const auto& cb : fixed_base) {
            for (const auto& cm : fixed_mod) {
                if (cb.hash == cm.hash) {
                    ++fixed_matches;
                    break;
                }
            }
        }

        // B. FastCDC chunking (min 2KB, avg 8KB, max 16KB)
        ChunkerConfig fcfg;
        fcfg.min_size = 2048;
        fcfg.avg_size = 8192;
        fcfg.max_size = 16384;
        FastCDCChunker fcdc_chunker(fcfg);
        auto fcdc_base = fcdc_chunker.chunk_buffer(base_data.data(), base_data.size());
        auto fcdc_mod = fcdc_chunker.chunk_buffer(mod_data.data(), mod_data.size());

        std::size_t fcdc_matches = 0;
        for (const auto& cb : fcdc_base) {
            for (const auto& cm : fcdc_mod) {
                if (cb.hash == cm.hash) {
                    ++fcdc_matches;
                    break;
                }
            }
        }

        // FastCDC re-synchronizes after the edit; fixed chunking destroys all downstream chunks!
        const double fcdc_reuse_pct = (fcdc_base.empty()) ? 0.0 : (100.0 * static_cast<double>(fcdc_matches) / static_cast<double>(fcdc_base.size()));
        const double fixed_reuse_pct = (fixed_base.empty()) ? 0.0 : (100.0 * static_cast<double>(fixed_matches) / static_cast<double>(fixed_base.size()));

        check(fcdc_reuse_pct > 70.0 && fcdc_reuse_pct > fixed_reuse_pct,
              "CAS-FCDC-05: FastCDC exhibits shift resistance (high chunk reuse after offset insertion)");
    }

    // CAS-FCDC-06: Config validation
    {
        ChunkerConfig bad_cfg;
        bad_cfg.min_size = 16384;
        bad_cfg.avg_size = 8192; // min > avg
        bad_cfg.max_size = 32768;
        std::string err;
        check(!bad_cfg.validate(err), "CAS-FCDC-06: ChunkerConfig rejects min_size > avg_size");

        bool threw = false;
        try {
            FastCDCChunker bad_chunker(bad_cfg);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        check(threw, "CAS-FCDC-06: FastCDCChunker constructor throws on invalid configuration");
    }

    // CAS-FCDC-07: Stream chunking matches buffer chunking
    {
        FastCDCChunker chunker;
        auto data = generate_pattern_data(96 * 1024, 505);
        const fs::path test_file = root / "stream_test.bin";
        write_test_file(test_file, data.data(), data.size());

        auto buf_chunks = chunker.chunk_buffer(data.data(), data.size());
        auto stream_chunks = chunker.chunk_file(test_file);

        bool match = (buf_chunks.size() == stream_chunks.size());
        for (std::size_t i = 0; i < buf_chunks.size() && match; ++i) {
            if (buf_chunks[i] != stream_chunks[i]) match = false;
        }
        check(match, "CAS-FCDC-07: Sliding window stream chunking matches buffer chunking identically");
    }

    // =========================================================================
    // 2. ObjectStore Core & Concurrency Tests
    // =========================================================================

    // CAS-OBJ-01: Identical content produces identical chunk hash / object ID
    {
        ObjectStoreConfig oscfg{root / "cas_store_1"};
        ObjectStore store(oscfg);
        std::string err;
        check(store.initialize(err), "CAS-OBJ-01: ObjectStore initialization succeeded");

        auto data = generate_pattern_data(1024, 606);
        std::string hash1 = mc::sha256_data(data.data(), data.size());
        std::string hash2 = mc::sha256_data(data.data(), data.size());
        check(hash1 == hash2 && hash1.size() == 64, "CAS-OBJ-01: Identical data yields identical 64-hex SHA-256");

        auto put1 = store.put_object(data.data(), data.size());
        check(put1.status == PutResultStatus::StoredNew && put1.hash == hash1,
              "CAS-OBJ-01: New object stored with correct SHA-256 object ID");
    }

    // CAS-OBJ-02: Duplicate chunks stored once (deduplication)
    {
        ObjectStoreConfig oscfg{root / "cas_store_1"};
        ObjectStore store(oscfg);
        auto data = generate_pattern_data(1024, 606); // same as above

        auto put2 = store.put_object(data.data(), data.size());
        check(put2.status == PutResultStatus::AlreadyExists,
              "CAS-OBJ-02: Duplicate put_object returns AlreadyExists");

        auto stats = store.compute_stats();
        check(stats.total_objects == 1,
              "CAS-OBJ-02: Physical object count remains 1 after duplicate insertion");
    }

    // CAS-OBJ-03: Corrupted object detection
    {
        ObjectStoreConfig oscfg{root / "cas_store_corrupt"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        auto data = generate_pattern_data(2048, 707);
        auto put = store.put_object(data.data(), data.size());

        // Corrupt object on disk by flipping bytes
        const fs::path obj_path = store.object_path(put.hash);
        check(fs::exists(obj_path), "CAS-OBJ-03: Object exists on disk");

        {
            std::fstream f(obj_path, std::ios::in | std::ios::out | std::ios::binary);
            f.seekp(10);
            f.put(static_cast<char>(0xFF));
        }

        // Verify with ObjectVerifier
        auto vres = ObjectVerifier::verify_object(obj_path, put.hash, data.size());
        check(!vres.valid && !vres.error.empty(),
              "CAS-OBJ-03: ObjectVerifier detects corrupted disk object");

        // get_object with verify_on_read rejects corrupted object
        std::vector<std::uint8_t> read_data;
        bool read_ok = store.get_object(put.hash, read_data);
        check(!read_ok && read_data.empty(),
              "CAS-OBJ-03: get_object with verify_on_read rejects corrupted object");

        auto rep = ObjectVerifier::verify_store(store);
        check(rep.corrupt_objects == 1 && !rep.is_healthy(),
              "CAS-OBJ-03: verify_store report flags corrupted object");
    }

    // CAS-OBJ-04: File reconstruction matches original SHA-256 byte-for-byte
    {
        ObjectStoreConfig oscfg{root / "cas_store_recon"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        FastCDCChunker chunker;
        auto orig_data = generate_pattern_data(80000, 808);
        const std::string orig_sha256 = mc::sha256_data(orig_data.data(), orig_data.size());

        auto chunk_infos = chunker.chunk_buffer(orig_data.data(), orig_data.size());
        FileManifest manifest(orig_data.size(), orig_sha256, chunk_infos);

        for (const auto& c : chunk_infos) {
            store.put_object(orig_data.data() + c.offset, static_cast<std::size_t>(c.size), c.hash);
        }

        const fs::path recon_path = root / "reconstructed_file.bin";
        bool recon_ok = store.reconstruct_file(manifest, recon_path, err, true);
        check(recon_ok, "CAS-OBJ-04: File reconstruction succeeded");

        std::uintmax_t rbytes = 0;
        std::string recon_sha256 = mc::sha256_file(recon_path, &rbytes);
        check(rbytes == orig_data.size() && recon_sha256 == orig_sha256,
              "CAS-OBJ-04: Reconstructed file matches original size and SHA-256 byte-for-byte");
    }

    // CAS-OBJ-05: Non-hard-linking guarantee
    {
        ObjectStoreConfig oscfg{root / "cas_store_recon"};
        ObjectStore store(oscfg);
        const fs::path recon_path = root / "reconstructed_file.bin";

        // Verify hard link count is exactly 1 (independent working copy file)
        std::error_code link_ec;
        auto link_count = fs::hard_link_count(recon_path, link_ec);
        check(!link_ec && link_count == 1,
              "CAS-OBJ-05: Reconstructed working copy is an independent file with hard_link_count == 1");

        // Mutating the working copy does NOT alter the CAS object
        {
            std::ofstream f(recon_path, std::ios::binary | std::ios::app);
            f.write("MODIFICATION", 12);
        }

        auto rep = ObjectVerifier::verify_store(store);
        check(rep.is_healthy(),
              "CAS-OBJ-05: Modifying reconstructed file leaves immutable CAS objects completely unaffected");
    }

    // CAS-OBJ-06: Concurrent insertion safety
    {
        ObjectStoreConfig oscfg{root / "cas_store_concurrent"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        // Generate 20 distinct chunks
        std::vector<std::vector<std::uint8_t>> test_chunks;
        for (std::size_t i = 0; i < 20; ++i) {
            test_chunks.push_back(generate_pattern_data(4096, static_cast<std::uint32_t>(1000 + i)));
        }

        // 8 threads concurrently inserting random subsets of the 20 chunks
        const std::size_t num_threads = 8;
        const std::size_t iterations_per_thread = 50;
        std::vector<std::thread> workers;
        std::atomic<bool> all_ok{true};

        for (std::size_t t = 0; t < num_threads; ++t) {
            workers.emplace_back([&store, &test_chunks, iterations_per_thread, t, &all_ok]() {
                std::mt19937 rng(static_cast<std::uint32_t>(2000 + t));
                for (std::size_t iter = 0; iter < iterations_per_thread; ++iter) {
                    const std::size_t idx = rng() % test_chunks.size();
                    const auto& chunk_data = test_chunks[idx];
                    auto res = store.put_object(chunk_data.data(), chunk_data.size());
                    if (!res.is_ok()) {
                        all_ok = false;
                    }
                }
            });
        }

        for (auto& w : workers) {
            w.join();
        }

        check(all_ok, "CAS-OBJ-06: 8 concurrent threads executed 400 put_object calls without error");

        auto stats = store.compute_stats();
        check(stats.total_objects == 20,
              "CAS-OBJ-06: Concurrent insertion produced exactly 20 unique objects (zero duplicates or lost writes)");

        auto rep = ObjectVerifier::verify_store(store);
        check(rep.is_healthy() && rep.valid_objects == 20,
              "CAS-OBJ-06: Store verification report confirms all 20 concurrent objects are 100% valid");
    }

    // CAS-OBJ-07: Interrupted temporary writes do not create valid-looking objects
    {
        ObjectStoreConfig oscfg{root / "cas_store_orphan"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        // Simulate an interrupted write leaving a raw .tmp file in .tmp/
        const fs::path orphan_file = store.tmp_dir() / "obj_tmp_interrupted_12345.tmp";
        write_test_file(orphan_file, "INCOMPLETE_DATA", 15);

        // Verify it is not visible as an object
        std::string dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        check(!store.has_object(dummy_hash),
              "CAS-OBJ-07: Interrupted temp write is not queryable via has_object()");

        auto rep = ObjectVerifier::verify_store(store);
        check(rep.orphaned_temp_files == 1,
              "CAS-OBJ-07: ObjectVerifier detects orphaned temp file in .tmp/");

        std::size_t cleaned = store.clean_temp_directory(&err);
        check(cleaned == 1 && !fs::exists(orphan_file),
              "CAS-OBJ-07: clean_temp_directory() successfully purges orphaned temp files");
    }

    // =========================================================================
    // 3. Manifest Serialization Tests
    // =========================================================================

    // CAS-MAN-01: JSON manifest serialization roundtrip
    {
        std::vector<ChunkInfo> chunks = {
            {0, 4096, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {4096, 4096, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            {8192, 1000, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
        };
        FileManifest orig_man(9192, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", chunks);

        std::string json = ManifestSerializer::serialize_json(orig_man, true);
        FileManifest parsed_man;
        std::string err;
        bool ok = ManifestSerializer::deserialize_json(json, parsed_man, err);
        check(ok && orig_man == parsed_man,
              "CAS-MAN-01: FileManifest JSON serialization roundtrip preserves all fields");
    }

    // CAS-MAN-02: Binary manifest serialization roundtrip
    {
        std::vector<ChunkInfo> chunks = {
            {0, 8192, "1111111111111111111111111111111111111111111111111111111111111111"},
            {8192, 4096, "2222222222222222222222222222222222222222222222222222222222222222"}
        };
        FileManifest orig_man(12288, "3333333333333333333333333333333333333333333333333333333333333333", chunks);

        auto bin = ManifestSerializer::serialize_binary(orig_man);
        FileManifest parsed_man;
        std::string err;
        bool ok = ManifestSerializer::deserialize_binary(bin.data(), bin.size(), parsed_man, err);
        check(ok && orig_man == parsed_man,
              "CAS-MAN-02: FileManifest compact binary serialization roundtrip succeeds");
    }

    // CAS-MAN-03: Manifest validation rejects malformed manifests
    {
        // Chunk gap
        std::vector<ChunkInfo> gap_chunks = {
            {0, 4096, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {5000, 4096, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
        };
        FileManifest gap_man(8192, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", gap_chunks);
        std::string err;
        check(!gap_man.validate(err),
              "CAS-MAN-03: Manifest validation rejects chunk offset gap");

        // Hash length invalid
        std::vector<ChunkInfo> bad_hash = {
            {0, 4096, "bad_short_hash"}
        };
        FileManifest bad_man(4096, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", bad_hash);
        check(!bad_man.validate(err),
              "CAS-MAN-03: Manifest validation rejects invalid chunk hash");
    }

    // CAS-MAN-04: Binary manifest integer overflow / DoS payload rejection
    {
        // Construct a synthetic truncated header claiming 2 billion chunks
        std::vector<std::uint8_t> malicious_payload;
        malicious_payload.push_back('M');
        malicious_payload.push_back('C');
        malicious_payload.push_back('A');
        malicious_payload.push_back('S');
        // Version 1
        malicious_payload.push_back(1); malicious_payload.push_back(0); malicious_payload.push_back(0); malicious_payload.push_back(0);
        // Total size 0
        for (int i = 0; i < 8; ++i) malicious_payload.push_back(0);
        // File SHA-256 (64 '0' chars)
        for (int i = 0; i < 64; ++i) malicious_payload.push_back('0');
        // Chunk count: 0x7FFFFFFF (2.1 billion)
        malicious_payload.push_back(0xFF); malicious_payload.push_back(0xFF); malicious_payload.push_back(0xFF); malicious_payload.push_back(0x7F);

        FileManifest out_man;
        std::string err;
        bool ok = ManifestSerializer::deserialize_binary(malicious_payload.data(), malicious_payload.size(), out_man, err);
        check(!ok && !err.empty(),
              "CAS-MAN-04: Binary manifest parser rejects integer overflow / DoS chunk_count attack");
    }

    // CAS-MAN-05: Malformed JSON manifest rejection
    {
        FileManifest out_man;
        std::string err;
        bool r1 = ManifestSerializer::deserialize_json("", out_man, err);
        check(!r1, "CAS-MAN-05: JSON parser rejects empty input");

        bool r2 = ManifestSerializer::deserialize_json("{\"version\":999}", out_man, err);
        check(!r2, "CAS-MAN-05: JSON parser rejects unsupported manifest version");

        bool r3 = ManifestSerializer::deserialize_json("{\"version\":1,\"total_size\":10,\"file_sha256\":\"bad\",\"chunks\":[]}", out_man, err);
        check(!r3, "CAS-MAN-05: JSON parser rejects invalid file_sha256");
    }

    // =========================================================================
    // 4. Advanced Stream Buffer Invariance & Edge Cases
    // =========================================================================

    // CAS-STREAM-01: Boundary invariance across varying stream read buffer sizes
    {
        FastCDCChunker chunker;
        auto data = generate_pattern_data(256 * 1024, 8888);
        auto ref_chunks = chunker.chunk_buffer(data.data(), data.size());

        const std::vector<std::size_t> chunk_read_sizes = {127, 512, 1024, 2048, 4096, 16384, 65536};
        bool all_sizes_matched = true;

        for (std::size_t read_sz : chunk_read_sizes) {
            // Custom stream simulating partial read calls of size read_sz
            struct ChunkedStreamBuf : public std::streambuf {
                const std::uint8_t* src;
                std::size_t total;
                std::size_t pos{0};
                std::size_t step;

                ChunkedStreamBuf(const std::uint8_t* s, std::size_t tot, std::size_t st)
                    : src(s), total(tot), step(st) {}

                std::streamsize xsgetn(char* s, std::streamsize n) override {
                    if (pos >= total) return 0;
                    std::size_t to_read = std::min(static_cast<std::size_t>(n), std::min(step, total - pos));
                    std::memcpy(s, src + pos, to_read);
                    pos += to_read;
                    return static_cast<std::streamsize>(to_read);
                }

                int underflow() override {
                    if (pos >= total) return traits_type::eof();
                    return traits_type::to_int_type(src[pos]);
                }

                int uflow() override {
                    if (pos >= total) return traits_type::eof();
                    return traits_type::to_int_type(src[pos++]);
                }
            };

            ChunkedStreamBuf sbuf(data.data(), data.size(), read_sz);
            std::istream test_stream(&sbuf);
            auto stream_chunks = chunker.chunk_stream(test_stream);

            if (stream_chunks.size() != ref_chunks.size()) {
                all_sizes_matched = false;
                break;
            }
            for (std::size_t i = 0; i < ref_chunks.size(); ++i) {
                if (stream_chunks[i] != ref_chunks[i]) {
                    all_sizes_matched = false;
                    break;
                }
            }
        }

        check(all_sizes_matched,
              "CAS-STREAM-01: FastCDC stream chunk boundaries are identical across all read buffer sizes (127B to 64KB)");
    }

    // CAS-OBJ-08: Path traversal rejection in ObjectStore
    {
        ObjectStoreConfig oscfg{root / "cas_traversal_test"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        bool threw = false;
        try {
            store.object_path("../../etc/passwd");
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        check(threw, "CAS-OBJ-08: ObjectStore::object_path() rejects path traversal attempts");
        check(!store.has_object("../../etc/passwd"), "CAS-OBJ-08: has_object() rejects path traversal attempts");
    }

    // CAS-OBJ-09: Truncated object detection
    {
        ObjectStoreConfig oscfg{root / "cas_trunc_test"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        auto data = generate_pattern_data(8192, 9999);
        auto put = store.put_object(data.data(), data.size());

        const fs::path opath = store.object_path(put.hash);
        // Truncate object to 100 bytes
        fs::resize_file(opath, 100, ec);

        auto vres = ObjectVerifier::verify_object(opath, put.hash, 8192);
        check(!vres.valid && !vres.error.empty(),
              "CAS-OBJ-09: ObjectVerifier detects truncated object file");

        std::vector<std::uint8_t> read_buf;
        bool read_ok = store.get_object(put.hash, read_buf);
        check(!read_ok, "CAS-OBJ-09: get_object() rejects truncated object file");
    }

    // CAS-OBJ-10: Corrupted chunk detection during reconstruction aborts and cleans staging file
    {
        ObjectStoreConfig oscfg{root / "cas_recon_abort_test"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        FastCDCChunker chunker;
        auto data = generate_pattern_data(32768, 7771);
        auto chunks = chunker.chunk_buffer(data.data(), data.size());
        FileManifest man(data.size(), mc::sha256_data(data.data(), data.size()), chunks);

        for (const auto& c : chunks) {
            store.put_object(data.data() + c.offset, static_cast<std::size_t>(c.size), c.hash);
        }

        // Corrupt chunk 1
        if (chunks.size() > 1) {
            const fs::path bad_obj = store.object_path(chunks[1].hash);
            std::fstream f(bad_obj, std::ios::in | std::ios::out | std::ios::binary);
            f.seekp(0);
            f.put('X');
        }

        const fs::path dest = root / "recon_abort_dest.bin";
        bool recon_ok = store.reconstruct_file(man, dest, err, true);
        check(!recon_ok && !err.empty(),
              "CAS-OBJ-10: File reconstruction aborts when an underlying chunk is corrupted");
        check(!fs::exists(dest),
              "CAS-OBJ-10: Aborted reconstruction does not create or leave corrupted destination file");
    }

    // CAS-OBJ-11: Large file reconstruction (2 MB)
    {
        ObjectStoreConfig oscfg{root / "cas_large_test"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        FastCDCChunker chunker;
        auto large_data = generate_pattern_data(2 * 1024 * 1024, 5555);
        const std::string expected_hash = mc::sha256_data(large_data.data(), large_data.size());

        auto chunks = chunker.chunk_buffer(large_data.data(), large_data.size());
        FileManifest man(large_data.size(), expected_hash, chunks);

        for (const auto& c : chunks) {
            store.put_object(large_data.data() + c.offset, static_cast<std::size_t>(c.size), c.hash);
        }

        const fs::path large_dest = root / "large_reconstructed.bin";
        bool recon_ok = store.reconstruct_file(man, large_dest, err, true);
        check(recon_ok, "CAS-OBJ-11: Multi-megabyte large file reconstructed successfully");

        std::uintmax_t bytes_read = 0;
        std::string actual_hash = mc::sha256_file(large_dest, &bytes_read);
        check(bytes_read == large_data.size() && actual_hash == expected_hash,
              "CAS-OBJ-11: Reconstructed large file matches original 2MB SHA-256 byte-for-byte");
    }

    // CAS-OBJ-12: Empty file reconstruction
    {
        ObjectStoreConfig oscfg{root / "cas_empty_recon"};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        FileManifest empty_man(0, kEmptySha256, {});
        const fs::path empty_dest = root / "empty_reconstructed.txt";
        bool recon_ok = store.reconstruct_file(empty_man, empty_dest, err, true);
        check(recon_ok && fs::exists(empty_dest) && fs::file_size(empty_dest) == 0,
              "CAS-OBJ-12: Empty file reconstruction creates verified 0-byte destination file");
    }

    // =========================================================================
    // 6. Cross-Process Concurrency & Crash Recovery Tests
    // =========================================================================

#ifdef _WIN32
    // CAS-PROC-01: Cross-process concurrent duplicate insertion
    {
        const fs::path proc_store_root = root / "cas_proc_concurrency";
        ObjectStoreConfig oscfg{proc_store_root};
        oscfg.verify_on_read = true;
        oscfg.verify_on_write = true;
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const std::size_t chunk_size = 16384;
        const std::uint32_t seed = 12345;
        auto expected_data = generate_pattern_data(chunk_size, seed);
        const std::string expected_hash = mc::sha256_data(expected_data.data(), expected_data.size());

        std::wstring args1 = L"--cas-proc-worker \"" + proc_store_root.wstring() + L"\" " + std::to_wstring(seed) + L" " + std::to_wstring(chunk_size) + L" 50";
        std::wstring args2 = L"--cas-proc-worker \"" + proc_store_root.wstring() + L"\" " + std::to_wstring(seed) + L" " + std::to_wstring(chunk_size) + L" 50";

        DWORD code1 = 999, code2 = 999;
        bool launched = run_two_concurrent_cas_children(args1, args2, code1, code2);
        check(launched && code1 == 0 && code2 == 0,
              "CAS-PROC-01: Two concurrent OS processes inserting identical chunk exit cleanly with code 0");

        check(store.has_object(expected_hash),
              "CAS-PROC-01: Target object exists in store after concurrent process insertion");

        check(store.object_size(expected_hash) == chunk_size,
              "CAS-PROC-01: Target object size matches exact chunk size");

        std::vector<std::uint8_t> read_data;
        bool read_ok = store.get_object(expected_hash, read_data);
        check(read_ok && read_data == expected_data,
              "CAS-PROC-01: Target object content verified byte-for-byte with zero corruption");

        auto vres = ObjectVerifier::verify_object(store.object_path(expected_hash), expected_hash, chunk_size);
        check(vres.valid && vres.error.empty(),
              "CAS-PROC-01: ObjectVerifier confirms final object integrity");

        std::size_t orphan_tmp = store.clean_temp_directory();
        check(orphan_tmp == 0,
              "CAS-PROC-01: Competing processes leave zero leaked or uncleaned temp files");
    }

    // CAS-PROC-02: Existing object is verified before being accepted as valid & heals corruption
    {
        const fs::path heal_store_root = root / "cas_proc_heal";
        ObjectStoreConfig oscfg{heal_store_root};
        oscfg.verify_on_read = true;
        oscfg.verify_on_write = true;
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const std::size_t chunk_size = 8192;
        const std::uint32_t seed = 9999;
        auto expected_data = generate_pattern_data(chunk_size, seed);
        const std::string expected_hash = mc::sha256_data(expected_data.data(), expected_data.size());

        // Pre-create shard directory and a CORRUPTED file at target path (same size, wrong content)
        const fs::path dest_path = store.object_path(expected_hash);
        fs::create_directories(dest_path.parent_path());
        std::vector<std::uint8_t> corrupt_data(chunk_size, 0xEE);
        write_test_file(dest_path, corrupt_data.data(), corrupt_data.size());

        // Verify that ObjectVerifier rejects the corrupted file
        auto pre_verify = ObjectVerifier::verify_object(dest_path, expected_hash, chunk_size);
        check(!pre_verify.valid,
              "CAS-PROC-02: Verification confirms pre-existing object is corrupted");

        // Now run child worker to insert valid chunk
        std::wstring args = L"--cas-proc-worker \"" + heal_store_root.wstring() + L"\" " + std::to_wstring(seed) + L" " + std::to_wstring(chunk_size) + L" 1";
        DWORD child_code = run_cas_child_process(args);
        check(child_code == 0,
              "CAS-PROC-02: Child worker detects corrupted existing object and heals it, exiting with code 0");

        // Verify healed object is valid
        std::vector<std::uint8_t> read_data;
        bool read_ok = store.get_object(expected_hash, read_data);
        check(read_ok && read_data == expected_data,
              "CAS-PROC-02: Existing object was verified, rejected, and healed with valid chunk data");
    }

    // CAS-CRASH-01: Crash Recovery During Temporary Object Writing (Fault Point a)
    {
        const fs::path crash1_root = root / "cas_crash_temp_write";
        ObjectStoreConfig oscfg{crash1_root};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const std::size_t chunk_size = 32768;
        const std::uint32_t seed = 4444;
        auto expected_data = generate_pattern_data(chunk_size, seed);
        const std::string expected_hash = mc::sha256_data(expected_data.data(), expected_data.size());

        // Run child process with temp-write fault point -> exits with code 91
        std::wstring args = L"--cas-crash-worker \"" + crash1_root.wstring() + L"\" temp-write " + std::to_wstring(seed) + L" " + std::to_wstring(chunk_size);
        DWORD code = run_cas_child_process(args);
        check(code == 91,
              "CAS-CRASH-01: Injected crash during temp object writing terminates child process with code 91");

        // Verify target object was NOT created
        check(!store.has_object(expected_hash),
              "CAS-CRASH-01: Aborted temp write did not promote premature object to objects directory");

        // Verify orphaned partial temp file exists in .tmp/
        std::size_t orphan_tmp = 0;
        if (fs::exists(store.tmp_dir())) {
            for (const auto& e : fs::directory_iterator(store.tmp_dir())) {
                if (e.is_regular_file()) ++orphan_tmp;
            }
        }
        check(orphan_tmp >= 1,
              "CAS-CRASH-01: Orphaned temporary file is present in .tmp directory after mid-write termination");

        // Clean temp directory
        std::size_t cleaned = store.clean_temp_directory();
        check(cleaned >= 1,
              "CAS-CRASH-01: clean_temp_directory() successfully detects and reclaims orphaned temp files");

        // Re-attempt write: must succeed cleanly
        auto put_res = store.put_object(expected_data.data(), expected_data.size());
        check(put_res.status == PutResultStatus::StoredNew && put_res.hash == expected_hash,
              "CAS-CRASH-01: Re-running insertion after recovery successfully promotes object as StoredNew");

        std::vector<std::uint8_t> read_data;
        check(store.get_object(expected_hash, read_data) && read_data == expected_data,
              "CAS-CRASH-01: Recovered object read back byte-for-byte identical");
    }

    // CAS-CRASH-02: Crash Recovery After Object Written But Before Promotion (Fault Point b)
    {
        const fs::path crash2_root = root / "cas_crash_before_promote";
        ObjectStoreConfig oscfg{crash2_root};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const std::size_t chunk_size = 32768;
        const std::uint32_t seed = 5555;
        auto expected_data = generate_pattern_data(chunk_size, seed);
        const std::string expected_hash = mc::sha256_data(expected_data.data(), expected_data.size());

        // Run child process with before-promote fault point -> exits with code 92
        std::wstring args = L"--cas-crash-worker \"" + crash2_root.wstring() + L"\" before-promote " + std::to_wstring(seed) + L" " + std::to_wstring(chunk_size);
        DWORD code = run_cas_child_process(args);
        check(code == 92,
              "CAS-CRASH-02: Injected crash before promotion terminates child process with code 92");

        // Verify target object was NOT promoted
        check(!store.has_object(expected_hash),
              "CAS-CRASH-02: Crash before promotion leaves no object in objects directory");

        // Verify fully-written temp file in .tmp/ is safely cleaned
        std::size_t cleaned = store.clean_temp_directory();
        check(cleaned >= 1,
              "CAS-CRASH-02: clean_temp_directory() cleans pre-promotion temp file");

        // Subsequent insertion succeeds
        auto put_res = store.put_object(expected_data.data(), expected_data.size());
        check(put_res.status == PutResultStatus::StoredNew && store.has_object(expected_hash),
              "CAS-CRASH-02: Normal insertion after pre-promotion crash succeeds with verified object");
    }

    // CAS-CRASH-03: Crash Recovery Immediately After Promotion (Fault Point c)
    {
        const fs::path crash3_root = root / "cas_crash_after_promote";
        ObjectStoreConfig oscfg{crash3_root};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const std::size_t chunk_size = 32768;
        const std::uint32_t seed = 6666;
        auto expected_data = generate_pattern_data(chunk_size, seed);
        const std::string expected_hash = mc::sha256_data(expected_data.data(), expected_data.size());

        // Run child process with after-promote fault point -> exits with code 93
        std::wstring args = L"--cas-crash-worker \"" + crash3_root.wstring() + L"\" after-promote " + std::to_wstring(seed) + L" " + std::to_wstring(chunk_size);
        DWORD code = run_cas_child_process(args);
        check(code == 93,
              "CAS-CRASH-03: Injected crash immediately after promotion terminates child process with code 93");

        // Verify target object DOES exist in store and is verified
        check(store.has_object(expected_hash),
              "CAS-CRASH-03: Object exists in CAS store because atomic rename completed before crash");

        auto vres = ObjectVerifier::verify_object(store.object_path(expected_hash), expected_hash, chunk_size);
        check(vres.valid && vres.error.empty(),
              "CAS-CRASH-03: Promoted object passes full integrity verification");

        // Retrying insertion immediately recognizes AlreadyExists with zero corruption
        auto retry_res = store.put_object(expected_data.data(), expected_data.size());
        check(retry_res.status == PutResultStatus::AlreadyExists,
              "CAS-CRASH-03: Subsequent write correctly detects AlreadyExists with zero data corruption");
    }

    // CAS-CRASH-04: Crash Recovery During Manifest Creation (Fault Point d)
    {
        const fs::path crash4_root = root / "cas_crash_manifest";
        const fs::path manifest_path = crash4_root / "interrupted.manifest.mcas";
        ObjectStoreConfig oscfg{crash4_root};
        ObjectStore store(oscfg);
        std::string err;
        store.initialize(err);

        const std::size_t data_size = 65536;
        const std::uint32_t seed = 7777;
        auto expected_data = generate_pattern_data(data_size, seed);
        const std::string expected_file_hash = mc::sha256_data(expected_data.data(), expected_data.size());

        // Run child process that stores chunks but crashes halfway through writing manifest file (exit 94)
        std::wstring args = L"--cas-manifest-crash \"" + crash4_root.wstring() + L"\" \"" + manifest_path.wstring() + L"\" " + std::to_wstring(seed) + L" " + std::to_wstring(data_size);
        DWORD code = run_cas_child_process(args);
        check(code == 94,
              "CAS-CRASH-04: Injected crash during manifest file creation terminates child process with code 94");

        // Read truncated manifest from disk
        check(fs::exists(manifest_path),
              "CAS-CRASH-04: Truncated manifest file exists on disk from aborted creation");

        std::ifstream mfile(manifest_path, std::ios::binary | std::ios::ate);
        const auto msize = static_cast<std::size_t>(mfile.tellg());
        mfile.seekg(0);
        std::vector<std::uint8_t> mdata(msize);
        mfile.read(reinterpret_cast<char*>(mdata.data()), static_cast<std::streamsize>(msize));
        mfile.close();

        FileManifest parsed_manifest;
        std::string parse_err;
        bool parse_ok = ManifestSerializer::deserialize_binary(mdata.data(), mdata.size(), parsed_manifest, parse_err);
        check(!parse_ok && !parse_err.empty(),
              "CAS-CRASH-04: Truncated manifest is strictly rejected by deserialize_binary()");

        // Verify underlying CAS chunk objects stored before crash are intact in objects/
        FastCDCChunker chunker;
        auto chunks = chunker.chunk_buffer(expected_data.data(), expected_data.size());
        bool all_chunks_intact = true;
        for (const auto& c : chunks) {
            if (!store.has_object(c.hash) || store.object_size(c.hash) != c.size) {
                all_chunks_intact = false;
                break;
            }
        }
        check(all_chunks_intact && !chunks.empty(),
              "CAS-CRASH-04: All underlying CAS chunk objects stored before manifest crash remain intact");

        // Recovery: Re-serialize manifest cleanly and reconstruct original file
        FileManifest recovered_manifest(data_size, expected_file_hash, chunks);
        const auto complete_bin = ManifestSerializer::serialize_binary(recovered_manifest);
        write_test_file(manifest_path, complete_bin.data(), complete_bin.size());

        FileManifest verified_manifest;
        bool recovered_parse = ManifestSerializer::deserialize_binary(complete_bin.data(), complete_bin.size(), verified_manifest, parse_err);
        check(recovered_parse && verified_manifest.chunk_count() == chunks.size(),
              "CAS-CRASH-04: Re-generated manifest validates and matches full chunk inventory");

        const fs::path reconstructed_path = crash4_root / "reconstructed.bin";
        bool recon_ok = store.reconstruct_file(verified_manifest, reconstructed_path, err, true);
        check(recon_ok,
              "CAS-CRASH-04: File reconstruction succeeds from recovered manifest");

        std::uintmax_t rbytes = 0;
        std::string rhash = mc::sha256_file(reconstructed_path, &rbytes);
        check(rbytes == data_size && rhash == expected_file_hash,
              "CAS-CRASH-04: Reconstructed file matches 64KB original data byte-for-byte after manifest recovery");
    }
#endif

    // Cleanup test fixtures
    fs::remove_all(root, ec);
}

} // namespace mc::cas
