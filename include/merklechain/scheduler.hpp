#pragma once

#include "merklechain/types.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace mc {

// Scores are integer-valued and deterministic for the supplied metadata and
// clock readings. Weights are deliberately bounded to keep score arithmetic
// well within int64_t.
struct SchedulerWeights {
    std::int64_t add_priority{400};
    std::int64_t modify_priority{300};
    std::int64_t delete_priority{200};
    std::int64_t unchanged_priority{0};
    std::int64_t preserve_priority{0};
    std::uintmax_t size_quantum_bytes{1024U * 1024U};
    std::int64_t size_points_per_quantum{1};
    std::uintmax_t max_size_quanta{1000};
    std::chrono::minutes modification_window{120};
    std::int64_t modification_points_per_minute{1};
    std::int64_t aging_points_per_minute{1};
};

// This is an authorization gate only. The scheduler does not perform work;
// the normal synchronization approval flow remains responsible for execution.
struct SchedulerAuthorization {
    bool changes_approved{false};
    bool deletions_confirmed{false};
};

class BinaryHeapScheduler {
public:
    using Clock = std::chrono::system_clock;

    explicit BinaryHeapScheduler(SchedulerWeights weights = {});

    // mtime_now is explicit so callers and tests can provide a deterministic
    // filesystem-clock reference. Enqueue time defaults to the wall clock.
    void enqueue(SyncJob job, const FileMetadata& metadata,
                 Clock::time_point enqueued_at = Clock::now(),
                 fs::file_time_type::clock::time_point mtime_now = fs::file_time_type::clock::now());

    // Returns no job if empty or if the highest-priority mutating job lacks
    // approval. A denied job stays at the head; priority never grants consent.
    std::optional<SyncJob> try_dequeue(Clock::time_point now = Clock::now(),
                                       SchedulerAuthorization authorization = {});
    std::size_t size() const noexcept;
    bool empty() const noexcept;

private:
    struct Entry {
        SyncJob job;
        std::int64_t base_priority{};
        std::int64_t heap_key{};
        std::int64_t enqueued_minute{};
        std::uint64_t sequence{};
    };
    struct LowerPriority {
        bool operator()(const Entry& left, const Entry& right) const noexcept;
    };

    SchedulerWeights weights_;
    std::vector<Entry> heap_;
    std::uint64_t next_sequence_{};
    Clock::time_point last_observed_time_{};
};

} // namespace mc
