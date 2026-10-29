#pragma once
#include "merklechain/chunk_sync.hpp"
#include "merklechain/scheduler.hpp"
#include "merklechain/types.hpp"
#include <functional>
#include <string>
#include <vector>

namespace mc {

struct SyncScope {
    std::string mode{"all"}; // "all" or "selective"
    std::vector<std::string> paths;

    bool is_in_scope(const std::string& rel_path) const {
        if (mode != "selective") return true;
        for (const auto& p : paths) {
            if (rel_path == p) return true;
            if (rel_path.rfind(p + "/", 0) == 0) return true;
        }
        return false;
    }
};

std::vector<SyncJob> compare_manifests(const FileManifest& a, const FileManifest& b,
                                       const fs::path& root_a, const fs::path& root_b,
                                       const SyncScope& scope = {});

struct SyncExecutionOptions {
    SchedulerAuthorization authorization{};
    bool use_scheduler{false};
    bool use_chunking{false};
    std::uintmax_t chunk_size_bytes{kDefaultChunkSize};
    SchedulerWeights scheduler_weights{};
    BinaryHeapScheduler::Clock::time_point scheduler_now{BinaryHeapScheduler::Clock::now()};
    fs::file_time_type::clock::time_point file_clock_now{fs::file_time_type::clock::now()};
};

bool execute_plan(std::vector<SyncJob>& jobs, const fs::path& destination_root,
                  const fs::path& backup_root,
                  const std::function<void(const SyncJob&)>& after_verified_job={},
                  SyncExecutionOptions options={});
}
