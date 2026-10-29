#include "merklechain/chunk_sync.hpp"
#include "merklechain/hash.hpp"
#include "merklechain/staging_file.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
namespace {
constexpr std::size_t kTrials = 5;
using Clock = std::chrono::steady_clock;

struct Measurement {
    std::int64_t elapsed_us{};
    std::uintmax_t payload_bytes_transferred{};
    std::uintmax_t source_bytes_processed{};
    std::uintmax_t bytes_reused{};
    std::uintmax_t staging_bytes_written{};
    std::size_t reused_chunks{};
    bool used_chunks{false};
};

std::string fixture_bytes(std::size_t size, std::uint32_t seed) {
    std::string bytes(size, '\0');
    std::uint32_t state = seed;
    for (auto& byte : bytes) {
        state = state * 1664525U + 1013904223U;
        byte = static_cast<char>(state >> 24U);
    }
    return bytes;
}

void write_file(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("could not write benchmark fixture");
}

std::int64_t elapsed_microseconds(Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count();
}

template<class Value>
Value median(std::vector<Value> values) {
    if (values.empty()) throw std::logic_error("cannot compute an empty benchmark median");
    std::sort(values.begin(), values.end());
    return values[values.size() / 2U];
}

Measurement run_whole_file_trial(const fs::path& source, const fs::path& stage_path,
                                 const std::string& expected_sha256,
                                 std::uintmax_t expected_file_size) {
    Measurement result;
    std::uintmax_t source_bytes_processed = 0;
    const auto start = Clock::now();

    if (mc::sha256_file(source, &source_bytes_processed) != expected_sha256)
        throw std::runtime_error("whole-file benchmark source hash changed");
    mc::StagingFile staging(stage_path);
    mc::copy_file_to_staging(source, staging, expected_sha256, &source_bytes_processed);
    if (mc::sha256_file(source, &source_bytes_processed) != expected_sha256)
        throw std::runtime_error("whole-file benchmark source changed during copy");
    if (staging.size() != expected_file_size || staging.sha256() != expected_sha256)
        throw std::runtime_error("whole-file staged SHA-256 or size mismatch");

    result.elapsed_us = elapsed_microseconds(start);
    result.payload_bytes_transferred = expected_file_size;
    result.source_bytes_processed = source_bytes_processed;
    result.staging_bytes_written = staging.bytes_written();
    return result;
}

Measurement run_chunk_trial(const fs::path& source, const fs::path& destination,
                            const fs::path& stage_path,
                            const std::string& expected_source_sha256,
                            const std::string& expected_destination_sha256,
                            std::uintmax_t expected_file_size) {
    Measurement measurement;
    const auto start = Clock::now();
    // This digest represents the destination hash already captured by preview.
    // Compute it once per scenario, outside this timed function.
    mc::StagingFile staging(stage_path);
    const auto transfer = mc::copy_file_chunked_or_fallback(
        source, destination, staging, expected_source_sha256, expected_destination_sha256);
    if (staging.size() != expected_file_size || staging.sha256() != expected_source_sha256)
        throw std::runtime_error("chunk reconstruction failed full-file SHA-256 or size verification");

    measurement.elapsed_us = elapsed_microseconds(start);
    measurement.payload_bytes_transferred = transfer.bytes_transferred;
    measurement.source_bytes_processed = transfer.source_bytes_processed;
    measurement.bytes_reused = transfer.reused_bytes;
    measurement.staging_bytes_written = staging.bytes_written();
    measurement.reused_chunks = transfer.reused_chunks;
    measurement.used_chunks = transfer.used_chunks;
    return measurement;
}

void print_summary(const std::string& label, const std::string& method,
                   const std::vector<Measurement>& trials) {
    std::vector<std::int64_t> elapsed;
    std::vector<std::uintmax_t> payload, source_processed, reused, staged;
    std::vector<std::size_t> reused_chunks;
    std::size_t fallback_trials = 0;
    for (const auto& trial : trials) {
        elapsed.push_back(trial.elapsed_us);
        payload.push_back(trial.payload_bytes_transferred);
        source_processed.push_back(trial.source_bytes_processed);
        reused.push_back(trial.bytes_reused);
        staged.push_back(trial.staging_bytes_written);
        reused_chunks.push_back(trial.reused_chunks);
        if (method == "fixed_chunks" && !trial.used_chunks) ++fallback_trials;
    }
    std::cout << "scenario=" << label
              << ", method=" << method
              << ", trials=" << trials.size()
              << ", median_elapsed_us=" << median(std::move(elapsed))
              << ", median_payload_bytes_transferred=" << median(std::move(payload))
              << ", median_source_bytes_processed=" << median(std::move(source_processed))
              << ", median_bytes_reused=" << median(std::move(reused))
              << ", median_staging_bytes_written=" << median(std::move(staged));
    if (method == "fixed_chunks") {
        std::cout << ", median_reused_chunks=" << median(std::move(reused_chunks))
                  << ", whole_file_fallback_trials=" << fallback_trials;
    }
    std::cout << ", counter_scope=logical_byte_accounting_not_physical_disk_io_or_network_traffic\n";
}

void run_case(const fs::path& root, const std::string& label,
              const std::string& source_bytes, const std::string& previous_bytes) {
    const auto case_root = root / label;
    const auto source = case_root / "source.bin";
    const auto destination = case_root / "destination.bin";
    write_file(source, source_bytes);
    write_file(destination, previous_bytes);

    // These fixture hashes are prepared outside all timed trial regions.
    const auto expected_source_sha256 = mc::sha256_file(source);
    const auto expected_destination_sha256 = mc::sha256_file(destination);
    const auto expected_file_size = static_cast<std::uintmax_t>(source_bytes.size());
    std::vector<Measurement> whole_trials;
    std::vector<Measurement> chunk_trials;
    whole_trials.reserve(kTrials);
    chunk_trials.reserve(kTrials);

    // Alternate strategy order to reduce a consistent first/second-run bias.
    for (std::size_t trial = 0; trial < kTrials; ++trial) {
        const auto run_whole = [&] {
            whole_trials.push_back(run_whole_file_trial(source,
                case_root / ("whole-stage-" + std::to_string(trial) + ".bin"),
                expected_source_sha256, expected_file_size));
        };
        const auto run_chunked = [&] {
            chunk_trials.push_back(run_chunk_trial(source, destination,
                case_root / ("chunk-stage-" + std::to_string(trial) + ".bin"),
                expected_source_sha256, expected_destination_sha256, expected_file_size));
        };
        if (trial % 2U == 0U) { run_whole(); run_chunked(); }
        else { run_chunked(); run_whole(); }
    }

    std::cout << "fixture=" << label << ", file_bytes=" << expected_file_size << '\n';
    print_summary(label, "whole_file", whole_trials);
    print_summary(label, "fixed_chunks", chunk_trials);
}
}

int main() {
    try {
        // Cleanup is limited to this benchmark's existing disposable fixture directory.
        const fs::path root = fs::current_path() / "build" / "chunk-benchmark-fixtures";
        if (fs::exists(root)) fs::remove_all(root);

        constexpr std::size_t mib = 1024U * 1024U;
        const auto unchanged = fixture_bytes(8U * mib, 0x12345678U);
        run_case(root, "unchanged", unchanged, unchanged);

        auto small_edit = unchanged;
        small_edit[64U * 1024U] ^= static_cast<char>(0x5a);
        run_case(root, "small-edit", small_edit, unchanged);

        const auto append_base = fixture_bytes(8U * mib, 0x2468ace0U);
        run_case(root, "append", append_base + "append-fixture-data", append_base);
        run_case(root, "truncate", append_base.substr(0, 5U * mib), append_base);

        const auto large_previous = fixture_bytes(64U * mib, 0x87654321U);
        auto large_edit = large_previous;
        large_edit[32U * mib + 7U] ^= static_cast<char>(0xa5);
        run_case(root, "large-file", large_edit, large_previous);

        const auto binary_previous = fixture_bytes(3U * mib + 17U, 0x0badc0deU);
        auto binary_edit = binary_previous;
        binary_edit[17U] ^= static_cast<char>(0x80);
        binary_edit.back() ^= static_cast<char>(0x01);
        run_case(root, "binary-data", binary_edit, binary_previous);

        fs::remove_all(root);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "benchmark failed: " << error.what() << '\n';
        return 1;
    }
}
