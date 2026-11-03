#include "merklechain/cas/chunker.hpp"
#include "merklechain/cas/file_manifest.hpp"
#include "merklechain/cas/manifest_serializer.hpp"
#include "merklechain/cas/object_store.hpp"
#include "merklechain/cas/object_verifier.hpp"
#include "merklechain/hash.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace mc::cas;

namespace {

using Clock = std::chrono::high_resolution_clock;

struct BenchmarkFile {
    std::string name;
    std::vector<std::uint8_t> content;
};

struct Dataset {
    std::string name;
    std::string description;
    std::vector<BenchmarkFile> files;

    Dataset(std::string n, std::string d) : name(std::move(n)), description(std::move(d)), files() {}

    std::uint64_t total_size() const {
        std::uint64_t s = 0;
        for (const auto& f : files) s += f.content.size();
        return s;
    }
};

struct StrategyResult {
    std::string strategy_name;
    std::uint64_t original_bytes{0};
    std::uint64_t chunk_stored_bytes{0};   // Pure chunk payload in CAS objects/
    std::uint64_t manifest_bytes{0};       // Metadata overhead in binary MCAS format
    std::uint64_t stored_bytes{0};         // Total physical footprint: chunks + manifests
    std::uint64_t unique_chunks{0};
    std::uint64_t duplicate_chunks{0};
    double chunking_ms{0.0};
    double hashing_ms{0.0};
    double store_ms{0.0};
    double reconstruction_ms{0.0};

    // Overall storage reduction accounting for manifest metadata
    double storage_reduction_pct() const {
        if (original_bytes == 0) return 0.0;
        if (stored_bytes >= original_bytes) return 0.0;
        return 100.0 * (1.0 - static_cast<double>(stored_bytes) / static_cast<double>(original_bytes));
    }

    // Chunk-only payload reduction (excluding manifest overhead)
    double chunk_only_reduction_pct() const {
        if (original_bytes == 0) return 0.0;
        if (chunk_stored_bytes >= original_bytes) return 0.0;
        return 100.0 * (1.0 - static_cast<double>(chunk_stored_bytes) / static_cast<double>(original_bytes));
    }

    double total_ingest_ms() const {
        return chunking_ms + hashing_ms + store_ms;
    }

    double ingest_throughput_mb_s() const {
        const double ms = total_ingest_ms();
        if (ms <= 0.0) return 0.0;
        return (static_cast<double>(original_bytes) / (1024.0 * 1024.0)) / (ms / 1000.0);
    }

    double reconstruction_throughput_mb_s() const {
        if (reconstruction_ms <= 0.0) return 0.0;
        return (static_cast<double>(original_bytes) / (1024.0 * 1024.0)) / (reconstruction_ms / 1000.0);
    }
};

// Dataset Generators
std::vector<std::uint8_t> make_random_bytes(std::size_t size, std::uint32_t seed) {
    std::vector<std::uint8_t> b(size);
    std::mt19937 rng(seed);
    for (std::size_t i = 0; i < size; ++i) {
        b[i] = static_cast<std::uint8_t>(rng() & 0xFF);
    }
    return b;
}

std::vector<std::uint8_t> make_text_content(std::size_t lines, const std::string& prefix = "LOG_LINE") {
    std::ostringstream ss;
    for (std::size_t i = 0; i < lines; ++i) {
        ss << prefix << " [" << std::setw(6) << std::setfill('0') << i
           << "] event_code=" << (i % 47)
           << " status=OK timestamp=" << (1600000000 + i * 10)
           << " payload=ContentAddressedStorageBenchmarkTextDataLine\n";
    }
    const std::string s = ss.str();
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

// 1. Multi-version Source Code Directory
Dataset create_source_code_dataset() {
    Dataset ds{"1. Multi-Version Source Code Directory", "15 source files evolving across 4 revisions"};
    const std::string base_cpp =
        "#include <iostream>\n#include <vector>\n#include <string>\n"
        "namespace demo {\n"
        "void execute_algorithm(int n) {\n"
        "    std::vector<int> v(n, 42);\n"
        "    for (auto& x : v) x *= 2;\n"
        "    std::cout << \"Executed: \" << v.size() << \" items\\n\";\n"
        "}\n"
        "}\n";

    // Revision 1: 15 files
    for (int i = 0; i < 15; ++i) {
        std::ostringstream ss;
        ss << "// File " << i << ".cpp\n" << base_cpp;
        for (int j = 0; j < 80; ++j) {
            ss << "// Function block " << j << " for module " << i << "\n"
               << "int calc_" << i << "_" << j << "(int a) { return a * " << (j + 1) << " + " << i << "; }\n";
        }
        std::string s = ss.str();
        ds.files.push_back({"r1_file_" + std::to_string(i) + ".cpp", {s.begin(), s.end()}});
    }

    // Revision 2: 10 files unchanged, 5 files edited
    for (int i = 0; i < 15; ++i) {
        if (i < 10) {
            ds.files.push_back({"r2_file_" + std::to_string(i) + ".cpp", ds.files[static_cast<size_t>(i)].content});
        } else {
            auto content = ds.files[static_cast<size_t>(i)].content;
            std::string edit = "\n// --- REVISION 2 ADDITION ---\nint rev2_patch() { return 999; }\n";
            content.insert(content.begin() + static_cast<std::ptrdiff_t>(content.size() / 2), edit.begin(), edit.end());
            ds.files.push_back({"r2_file_" + std::to_string(i) + ".cpp", std::move(content)});
        }
    }

    // Revision 3: 8 files unchanged, 7 files modified with comments
    for (int i = 0; i < 15; ++i) {
        auto content = ds.files[static_cast<size_t>(15 + i)].content;
        if (i % 2 == 0) {
            std::string edit = "// Copyright 2026 Syncora Project - Rev 3 Header\n";
            content.insert(content.begin(), edit.begin(), edit.end());
        }
        ds.files.push_back({"r3_file_" + std::to_string(i) + ".cpp", std::move(content)});
    }

    // Revision 4: 12 files unchanged, 3 refactored
    for (int i = 0; i < 15; ++i) {
        auto content = ds.files[static_cast<size_t>(30 + i)].content;
        if (i > 11) {
            std::string edit = "\n// Hotfix patch v4\nvoid patch4() {}\n";
            content.insert(content.end(), edit.begin(), edit.end());
        }
        ds.files.push_back({"r4_file_" + std::to_string(i) + ".cpp", std::move(content)});
    }

    return ds;
}

// 2. Large Text Files with Shift Injections (Shift Resistance)
Dataset create_shift_dataset() {
    Dataset ds{"2. Large Text Files with Shift Injections", "2 MB base file with small insertions at various offsets"};
    auto base = make_text_content(20000, "TRANSACTION_RECORD"); // ~2 MB
    ds.files.push_back({"base_2mb.log", base});

    // Version 2: insert 150 bytes near start (offset 15,000)
    auto v2 = base;
    std::string ins1 = "\n>>> ALERT: CRITICAL LOG RECORD INJECTED AT OFFSET 15K FOR SHIFT DEDUPLICATION BENCHMARK TEST <<<\n";
    v2.insert(v2.begin() + 15000, ins1.begin(), ins1.end());
    ds.files.push_back({"v2_near_start_insert.log", v2});

    // Version 3: insert 250 bytes in middle (offset 1,000,000)
    auto v3 = v2;
    std::string ins2 = "\n>>> ALERT: MID-STREAM TRANSACTION MARKER INSERTED AT 1MB BOUNDARY TEST DATA POINT <<<\n";
    v3.insert(v3.begin() + 1000000, ins2.begin(), ins2.end());
    ds.files.push_back({"v3_mid_insert.log", v3});

    // Version 4: delete 300 bytes around offset 500,000
    auto v4 = v3;
    if (v4.size() > 500500) {
        v4.erase(v4.begin() + 500000, v4.begin() + 500300);
    }
    ds.files.push_back({"v4_deletion_shift.log", v4});

    return ds;
}

// 3. Repeated Binary Content
Dataset create_repeated_binary_dataset() {
    Dataset ds{"3. Repeated Binary Content", "5 files built from combinations of four 128 KB blocks"};
    auto b1 = make_random_bytes(128 * 1024, 1111);
    auto b2 = make_random_bytes(128 * 1024, 2222);
    auto b3 = make_random_bytes(128 * 1024, 3333);
    auto b4 = make_random_bytes(128 * 1024, 4444);

    // File 1: b1, b2, b3, b4 (512 KB)
    std::vector<std::uint8_t> f1;
    f1.insert(f1.end(), b1.begin(), b1.end());
    f1.insert(f1.end(), b2.begin(), b2.end());
    f1.insert(f1.end(), b3.begin(), b3.end());
    f1.insert(f1.end(), b4.begin(), b4.end());
    ds.files.push_back({"binary_f1.bin", f1});

    // File 2: b2, b1, b4, b3 (512 KB)
    std::vector<std::uint8_t> f2;
    f2.insert(f2.end(), b2.begin(), b2.end());
    f2.insert(f2.end(), b1.begin(), b1.end());
    f2.insert(f2.end(), b4.begin(), b4.end());
    f2.insert(f2.end(), b3.begin(), b3.end());
    ds.files.push_back({"binary_f2.bin", f2});

    // File 3: b1, b1, b3, b3 (512 KB)
    std::vector<std::uint8_t> f3;
    f3.insert(f3.end(), b1.begin(), b1.end());
    f3.insert(f3.end(), b1.begin(), b1.end());
    f3.insert(f3.end(), b3.begin(), b3.end());
    f3.insert(f3.end(), b3.begin(), b3.end());
    ds.files.push_back({"binary_f3.bin", f3});

    // File 4: b4, b2, b2, b1 (512 KB)
    std::vector<std::uint8_t> f4;
    f4.insert(f4.end(), b4.begin(), b4.end());
    f4.insert(f4.end(), b2.begin(), b2.end());
    f4.insert(f4.end(), b2.begin(), b2.end());
    f4.insert(f4.end(), b1.begin(), b1.end());
    ds.files.push_back({"binary_f4.bin", f4});

    // File 5: b3, b4, b1, b2 (512 KB)
    std::vector<std::uint8_t> f5;
    f5.insert(f5.end(), b3.begin(), b3.end());
    f5.insert(f5.end(), b4.begin(), b4.end());
    f5.insert(f5.end(), b1.begin(), b1.end());
    f5.insert(f5.end(), b2.begin(), b2.end());
    ds.files.push_back({"binary_f5.bin", f5});

    return ds;
}

// 4. Unmodified Files across Revisions
Dataset create_unmodified_files_dataset() {
    Dataset ds{"4. Unmodified Files across Revisions", "8 files (~100 KB each) replicated across 3 snapshot iterations"};
    std::vector<std::vector<std::uint8_t>> assets;
    for (int i = 0; i < 8; ++i) {
        assets.push_back(make_random_bytes(100 * 1024, static_cast<std::uint32_t>(5000 + i)));
    }

    // 3 snapshots of the 8 assets
    for (int snap = 1; snap <= 3; ++snap) {
        for (int i = 0; i < 8; ++i) {
            ds.files.push_back({"snap" + std::to_string(snap) + "_asset_" + std::to_string(i) + ".dat", assets[static_cast<size_t>(i)]});
        }
    }
    return ds;
}

// 5. Completely Unrelated Files
Dataset create_unrelated_dataset() {
    Dataset ds{"5. Completely Unrelated Files", "4 high-entropy independent files (~250 KB each) with 0% shared content"};
    for (int i = 0; i < 4; ++i) {
        ds.files.push_back({"unrelated_" + std::to_string(i) + ".bin", make_random_bytes(256 * 1024, static_cast<std::uint32_t>(9000 + i * 37))});
    }
    return ds;
}

// 6. Empty and Small Files
Dataset create_small_and_empty_dataset() {
    Dataset ds{"6. Empty and Small Files", "20 files: 5 empty, 5 small (100-500B), 5 medium (1-3KB), 5 boundary (4KB)"};
    for (int i = 0; i < 5; ++i) {
        ds.files.push_back({"empty_" + std::to_string(i) + ".txt", {}});
    }
    for (int i = 0; i < 5; ++i) {
        ds.files.push_back({"small_" + std::to_string(i) + ".txt", make_random_bytes(static_cast<size_t>(100 + i * 80), static_cast<std::uint32_t>(7100 + i))});
    }
    for (int i = 0; i < 5; ++i) {
        ds.files.push_back({"med_" + std::to_string(i) + ".txt", make_random_bytes(static_cast<size_t>(1024 + i * 500), static_cast<std::uint32_t>(7200 + i))});
    }
    for (int i = 0; i < 5; ++i) {
        ds.files.push_back({"boundary_" + std::to_string(i) + ".txt", make_random_bytes(4096, static_cast<std::uint32_t>(7300 + i))});
    }
    return ds;
}

// Strategy Evaluators
StrategyResult evaluate_full_copy(const Dataset& ds, const fs::path& store_root) {
    StrategyResult r;
    r.strategy_name = "Full-Copy Storage (A)";
    r.original_bytes = ds.total_size();

    std::error_code ec;
    fs::remove_all(store_root, ec);
    fs::create_directories(store_root, ec);

    const auto t0 = Clock::now();
    std::vector<std::string> file_hashes;
    file_hashes.reserve(ds.files.size());
    for (const auto& f : ds.files) {
        file_hashes.push_back(mc::sha256_data(f.content.data(), f.content.size()));
    }
    const auto t1 = Clock::now();
    r.hashing_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    r.chunking_ms = 0.0; // No chunking in full-copy

    // Store whole-file copies
    const auto t2 = Clock::now();
    for (std::size_t i = 0; i < ds.files.size(); ++i) {
        const auto& f = ds.files[i];
        const fs::path p = store_root / (std::to_string(i) + "_" + f.name);
        std::ofstream out(p, std::ios::binary);
        if (!f.content.empty()) {
            out.write(reinterpret_cast<const char*>(f.content.data()), static_cast<std::streamsize>(f.content.size()));
        }
    }
    const auto t3 = Clock::now();
    r.store_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    // Calculate physical stored size
    for (const auto& entry : fs::directory_iterator(store_root, ec)) {
        if (entry.is_regular_file(ec)) {
            r.stored_bytes += fs::file_size(entry.path(), ec);
            ++r.unique_chunks;
        }
    }
    r.chunk_stored_bytes = r.stored_bytes;
    r.manifest_bytes = 0;
    r.duplicate_chunks = 0;

    // Symmetric reconstruction benchmark: write all files to disk in recon_dir
    const fs::path recon_dir = store_root / "reconstructed";
    fs::create_directories(recon_dir, ec);

    const auto t4 = Clock::now();
    for (std::size_t i = 0; i < ds.files.size(); ++i) {
        const auto& f = ds.files[i];
        const fs::path src_p = store_root / (std::to_string(i) + "_" + f.name);
        const fs::path dst_p = recon_dir / (std::to_string(i) + "_" + f.name);
        fs::copy_file(src_p, dst_p, fs::copy_options::overwrite_existing, ec);
    }
    const auto t5 = Clock::now();
    r.reconstruction_ms = std::chrono::duration<double, std::milli>(t5 - t4).count();

    fs::remove_all(store_root, ec);
    return r;
}

StrategyResult evaluate_chunk_strategy(const Dataset& ds, const fs::path& store_root, IChunker& chunker, const std::string& name) {
    StrategyResult r;
    r.strategy_name = name;
    r.original_bytes = ds.total_size();

    std::error_code ec;
    fs::remove_all(store_root, ec);
    fs::create_directories(store_root, ec);

    ObjectStoreConfig cfg{store_root, false, false, 2};
    ObjectStore store(cfg);
    std::string err;
    store.initialize(err);

    // 1. Chunking and Hashing
    std::vector<FileManifest> manifests;
    manifests.reserve(ds.files.size());

    double total_chunking_time = 0.0;
    double total_hashing_time = 0.0;

    for (const auto& f : ds.files) {
        const auto t0 = Clock::now();
        auto chunks = chunker.chunk_buffer(f.content.data(), f.content.size());
        const auto t1 = Clock::now();

        std::string fsha = mc::sha256_data(f.content.data(), f.content.size());
        const auto t2 = Clock::now();

        total_chunking_time += std::chrono::duration<double, std::milli>(t1 - t0).count();
        total_hashing_time += std::chrono::duration<double, std::milli>(t2 - t1).count();

        manifests.emplace_back(f.content.size(), std::move(fsha), std::move(chunks));
    }
    r.chunking_ms = total_chunking_time;
    r.hashing_ms = total_hashing_time;

    // 2. Storage and Deduplication Ingestion
    const auto t_store_start = Clock::now();
    for (std::size_t i = 0; i < ds.files.size(); ++i) {
        const auto& f = ds.files[i];
        const auto& man = manifests[i];
        for (const auto& c : man.chunks()) {
            store.put_object(f.content.data() + c.offset, static_cast<std::size_t>(c.size), c.hash);
        }
    }
    const auto t_store_end = Clock::now();
    r.store_ms = std::chrono::duration<double, std::milli>(t_store_end - t_store_start).count();

    auto stats = store.compute_stats();
    r.unique_chunks = stats.total_objects;
    r.chunk_stored_bytes = stats.total_bytes;
    r.duplicate_chunks = stats.deduplicated_puts;

    // Calculate metadata footprint from serialized binary manifests
    std::uint64_t total_manifest_bytes = 0;
    for (const auto& man : manifests) {
        auto bin = ManifestSerializer::serialize_binary(man);
        total_manifest_bytes += bin.size();
    }
    r.manifest_bytes = total_manifest_bytes;
    r.stored_bytes = r.chunk_stored_bytes + r.manifest_bytes;

    // 3. Reconstruction Benchmark: reconstruct all files to test output directory
    const fs::path recon_dir = store_root / "reconstructed";
    fs::create_directories(recon_dir, ec);

    const auto t_recon_start = Clock::now();
    for (std::size_t i = 0; i < ds.files.size(); ++i) {
        const auto& f = ds.files[i];
        const auto& man = manifests[i];
        const fs::path dest = recon_dir / (std::to_string(i) + "_" + f.name);
        store.reconstruct_file(man, dest, err, false);
    }
    const auto t_recon_end = Clock::now();
    r.reconstruction_ms = std::chrono::duration<double, std::milli>(t_recon_end - t_recon_start).count();

    fs::remove_all(store_root, ec);
    return r;
}

// Compute median result across multiple runs
StrategyResult compute_median_result(std::vector<StrategyResult>& runs) {
    if (runs.empty()) return StrategyResult{};
    if (runs.size() == 1) return runs[0];

    StrategyResult med = runs[0];
    const std::size_t mid = runs.size() / 2;

    auto median_val = [mid](std::vector<double>& v) -> double {
        std::sort(v.begin(), v.end());
        return v[mid];
    };

    std::vector<double> chunking_times, hashing_times, store_times, recon_times;
    for (const auto& r : runs) {
        chunking_times.push_back(r.chunking_ms);
        hashing_times.push_back(r.hashing_ms);
        store_times.push_back(r.store_ms);
        recon_times.push_back(r.reconstruction_ms);
    }

    med.chunking_ms = median_val(chunking_times);
    med.hashing_ms = median_val(hashing_times);
    med.store_ms = median_val(store_times);
    med.reconstruction_ms = median_val(recon_times);

    return med;
}

void print_dataset_header(const Dataset& ds) {
    std::cout << "\n========================================================================================\n";
    std::cout << " DATASET: " << ds.name << "\n";
    std::cout << " Description: " << ds.description << "\n";
    std::cout << " Total Files: " << ds.files.size()
              << " | Total Raw Size: " << ds.total_size() << " bytes ("
              << std::fixed << std::setprecision(2) << (static_cast<double>(ds.total_size()) / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
}

void print_result_row(const StrategyResult& r) {
    std::cout << std::left << std::setw(30) << r.strategy_name
              << " | Raw: " << std::right << std::setw(8) << (r.original_bytes / 1024) << " KB"
              << " | Chunks: " << std::setw(8) << (r.chunk_stored_bytes / 1024) << " KB"
              << " | Total: " << std::setw(8) << (r.stored_bytes / 1024) << " KB"
              << " | Dedup: " << std::setw(6) << std::fixed << std::setprecision(1) << r.storage_reduction_pct() << "%"
              << " | Chunks (U/D): " << std::setw(5) << r.unique_chunks << "/" << std::setw(5) << r.duplicate_chunks
              << " | Ingest: " << std::setw(6) << std::fixed << std::setprecision(1) << r.total_ingest_ms() << "ms"
              << " | Recon: " << std::setw(6) << std::fixed << std::setprecision(1) << r.reconstruction_ms << "ms\n";
}

} // namespace

int main() {
    std::cout << "========================================================================================\n";
    std::cout << "                 SYNCORA PHASE 3 - CAS & FASTCDC INDEPENDENT BENCHMARK                \n";
    std::cout << "  Comparing: Full-Copy (A) vs Fixed-Size 8KB (B) vs FastCDC 4KB/8KB/16KB (C)           \n";
    std::cout << "  Accounting: Includes Both Pure Chunk Payload & Binary MCAS Manifest Overhead          \n";
    std::cout << "  Iterations: 3 passes (Reporting Median to eliminate filesystem caching jitter)        \n";
    std::cout << "========================================================================================\n";

    const fs::path bench_root = "build/benchmark_tmp";
    std::error_code ec;
    fs::remove_all(bench_root, ec);
    fs::create_directories(bench_root, ec);

    FixedChunker fixed_chunker(8192); // 8 KB fixed blocks

    ChunkerConfig fcdc_cfg;
    fcdc_cfg.min_size = 4096;
    fcdc_cfg.avg_size = 8192;
    fcdc_cfg.max_size = 16384;
    fcdc_cfg.normalization_level = 1;
    FastCDCChunker fastcdc_chunker(fcdc_cfg);

    std::vector<Dataset> datasets = {
        create_source_code_dataset(),
        create_shift_dataset(),
        create_repeated_binary_dataset(),
        create_unmodified_files_dataset(),
        create_unrelated_dataset(),
        create_small_and_empty_dataset()
    };

    constexpr int kIterations = 3;

    StrategyResult total_full{"Full-Copy Storage (A)"};
    StrategyResult total_fixed{"Fixed-Size Chunking 8KB (B)"};
    StrategyResult total_fcdc{"FastCDC Chunking 4K/8K/16K (C)"};

    for (const auto& ds : datasets) {
        print_dataset_header(ds);

        std::vector<StrategyResult> full_runs;
        std::vector<StrategyResult> fixed_runs;
        std::vector<StrategyResult> fcdc_runs;

        for (int iter = 0; iter < kIterations; ++iter) {
            full_runs.push_back(evaluate_full_copy(ds, bench_root / "full"));
            fixed_runs.push_back(evaluate_chunk_strategy(ds, bench_root / "fixed", fixed_chunker, "Fixed-Size Chunking 8KB (B)"));
            fcdc_runs.push_back(evaluate_chunk_strategy(ds, bench_root / "fcdc", fastcdc_chunker, "FastCDC Chunking 4K/8K/16K (C)"));
        }

        auto r_full = compute_median_result(full_runs);
        auto r_fixed = compute_median_result(fixed_runs);
        auto r_fcdc = compute_median_result(fcdc_runs);

        print_result_row(r_full);
        print_result_row(r_fixed);
        print_result_row(r_fcdc);

        // Accumulate totals
        total_full.original_bytes += r_full.original_bytes;
        total_full.chunk_stored_bytes += r_full.chunk_stored_bytes;
        total_full.manifest_bytes += r_full.manifest_bytes;
        total_full.stored_bytes += r_full.stored_bytes;
        total_full.unique_chunks += r_full.unique_chunks;
        total_full.duplicate_chunks += r_full.duplicate_chunks;
        total_full.hashing_ms += r_full.hashing_ms;
        total_full.store_ms += r_full.store_ms;
        total_full.reconstruction_ms += r_full.reconstruction_ms;

        total_fixed.original_bytes += r_fixed.original_bytes;
        total_fixed.chunk_stored_bytes += r_fixed.chunk_stored_bytes;
        total_fixed.manifest_bytes += r_fixed.manifest_bytes;
        total_fixed.stored_bytes += r_fixed.stored_bytes;
        total_fixed.unique_chunks += r_fixed.unique_chunks;
        total_fixed.duplicate_chunks += r_fixed.duplicate_chunks;
        total_fixed.chunking_ms += r_fixed.chunking_ms;
        total_fixed.hashing_ms += r_fixed.hashing_ms;
        total_fixed.store_ms += r_fixed.store_ms;
        total_fixed.reconstruction_ms += r_fixed.reconstruction_ms;

        total_fcdc.original_bytes += r_fcdc.original_bytes;
        total_fcdc.chunk_stored_bytes += r_fcdc.chunk_stored_bytes;
        total_fcdc.manifest_bytes += r_fcdc.manifest_bytes;
        total_fcdc.stored_bytes += r_fcdc.stored_bytes;
        total_fcdc.unique_chunks += r_fcdc.unique_chunks;
        total_fcdc.duplicate_chunks += r_fcdc.duplicate_chunks;
        total_fcdc.chunking_ms += r_fcdc.chunking_ms;
        total_fcdc.hashing_ms += r_fcdc.hashing_ms;
        total_fcdc.store_ms += r_fcdc.store_ms;
        total_fcdc.reconstruction_ms += r_fcdc.reconstruction_ms;
    }

    std::cout << "\n========================================================================================\n";
    std::cout << "                    OVERALL AGGREGATE BENCHMARK SUMMARY (MEDIAN OF 3 RUNS)              \n";
    std::cout << "========================================================================================\n";
    std::cout << std::left << std::setw(32) << "Metric"
              << " | " << std::setw(16) << "Full-Copy (A)"
              << " | " << std::setw(16) << "Fixed 8KB (B)"
              << " | " << std::setw(16) << "FastCDC (C)" << "\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    auto print_summary_line = [](const std::string& name, const std::string& a, const std::string& b, const std::string& c) {
        std::cout << std::left << std::setw(32) << name
                  << " | " << std::setw(16) << a
                  << " | " << std::setw(16) << b
                  << " | " << std::setw(16) << c << "\n";
    };

    auto fmt_mb = [](std::uint64_t bytes) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MB";
        return ss.str();
    };

    auto fmt_kb = [](std::uint64_t bytes) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / 1024.0) << " KB";
        return ss.str();
    };

    auto fmt_pct = [](double pct) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << pct << " %";
        return ss.str();
    };

    auto fmt_ms = [](double ms) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << ms << " ms";
        return ss.str();
    };

    auto fmt_mb_s = [](double val) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << val << " MB/s";
        return ss.str();
    };

    print_summary_line("Original Input Size", fmt_mb(total_full.original_bytes), fmt_mb(total_fixed.original_bytes), fmt_mb(total_fcdc.original_bytes));
    print_summary_line("Chunk Payload Storage", fmt_mb(total_full.chunk_stored_bytes), fmt_mb(total_fixed.chunk_stored_bytes), fmt_mb(total_fcdc.chunk_stored_bytes));
    print_summary_line("Binary Manifest Overhead", fmt_kb(total_full.manifest_bytes), fmt_kb(total_fixed.manifest_bytes), fmt_kb(total_fcdc.manifest_bytes));
    print_summary_line("Total Stored Footprint", fmt_mb(total_full.stored_bytes), fmt_mb(total_fixed.stored_bytes), fmt_mb(total_fcdc.stored_bytes));
    print_summary_line("Payload Reduction (%)", fmt_pct(total_full.chunk_only_reduction_pct()), fmt_pct(total_fixed.chunk_only_reduction_pct()), fmt_pct(total_fcdc.chunk_only_reduction_pct()));
    print_summary_line("Total Footprint Reduction (%)", fmt_pct(total_full.storage_reduction_pct()), fmt_pct(total_fixed.storage_reduction_pct()), fmt_pct(total_fcdc.storage_reduction_pct()));
    print_summary_line("Unique Stored Chunks", std::to_string(total_full.unique_chunks), std::to_string(total_fixed.unique_chunks), std::to_string(total_fcdc.unique_chunks));
    print_summary_line("Duplicate Chunks Reused", std::to_string(total_full.duplicate_chunks), std::to_string(total_fixed.duplicate_chunks), std::to_string(total_fcdc.duplicate_chunks));
    print_summary_line("Chunking Time (Median)", "0.00 ms", fmt_ms(total_fixed.chunking_ms), fmt_ms(total_fcdc.chunking_ms));
    print_summary_line("Hashing Time (Median)", fmt_ms(total_full.hashing_ms), fmt_ms(total_fixed.hashing_ms), fmt_ms(total_fcdc.hashing_ms));
    print_summary_line("Total Ingest Time (Median)", fmt_ms(total_full.total_ingest_ms()), fmt_ms(total_fixed.total_ingest_ms()), fmt_ms(total_fcdc.total_ingest_ms()));
    print_summary_line("Ingestion Throughput", fmt_mb_s(total_full.ingest_throughput_mb_s()), fmt_mb_s(total_fixed.ingest_throughput_mb_s()), fmt_mb_s(total_fcdc.ingest_throughput_mb_s()));
    print_summary_line("Reconstruction Time (to disk)", fmt_ms(total_full.reconstruction_ms), fmt_ms(total_fixed.reconstruction_ms), fmt_ms(total_fcdc.reconstruction_ms));
    print_summary_line("Reconstruction Throughput", fmt_mb_s(total_full.reconstruction_throughput_mb_s()), fmt_mb_s(total_fixed.reconstruction_throughput_mb_s()), fmt_mb_s(total_fcdc.reconstruction_throughput_mb_s()));

    std::cout << "========================================================================================\n\n";

    fs::remove_all(bench_root, ec);
    return 0;
}
