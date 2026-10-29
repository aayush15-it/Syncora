#include "merklechain/scheduler.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace mc {
namespace {
constexpr std::int64_t kMaxWeight = 1000000;

std::int64_t saturating_add(std::int64_t a, std::int64_t b) noexcept {
    if (b > 0 && a > std::numeric_limits<std::int64_t>::max() - b) return std::numeric_limits<std::int64_t>::max();
    if (b < 0 && a < std::numeric_limits<std::int64_t>::min() - b) return std::numeric_limits<std::int64_t>::min();
    return a + b;
}

std::int64_t saturating_multiply(std::int64_t a, std::int64_t b) noexcept {
    if (a == 0 || b == 0) return 0;
    if (a > 0 && b > 0 && a > std::numeric_limits<std::int64_t>::max() / b) return std::numeric_limits<std::int64_t>::max();
    if (a < 0 && b < 0 && a < std::numeric_limits<std::int64_t>::max() / b) return std::numeric_limits<std::int64_t>::max();
    if (a > 0 && b < 0 && b < std::numeric_limits<std::int64_t>::min() / a) return std::numeric_limits<std::int64_t>::min();
    if (a < 0 && b > 0 && a < std::numeric_limits<std::int64_t>::min() / b) return std::numeric_limits<std::int64_t>::min();
    return a * b;
}

void validate(const SchedulerWeights& w) {
    const auto bounded = [](std::int64_t n) { return n >= 0 && n <= kMaxWeight; };
    if (!bounded(w.add_priority) || !bounded(w.modify_priority) || !bounded(w.delete_priority) ||
        !bounded(w.unchanged_priority) || !bounded(w.preserve_priority) ||
        !bounded(w.size_points_per_quantum) || !bounded(w.modification_points_per_minute) ||
        !bounded(w.aging_points_per_minute) || w.size_quantum_bytes == 0 ||
        w.max_size_quanta > 1000000 || w.modification_window.count() < 0 ||
        w.modification_window.count() > 1000000) {
        throw std::invalid_argument("scheduler weights must be nonnegative, bounded, and use a nonzero size quantum");
    }
}

std::int64_t op_priority(Operation op, const SchedulerWeights& w) {
    switch (op) {
        case Operation::Add: return w.add_priority;
        case Operation::Modify: return w.modify_priority;
        case Operation::Delete: return w.delete_priority;
        case Operation::Unchanged: return w.unchanged_priority;
        case Operation::Preserve: return w.preserve_priority;
    }
    return 0;
}

std::int64_t epoch_minute(BinaryHeapScheduler::Clock::time_point time) {
    return std::chrono::duration_cast<std::chrono::minutes>(time.time_since_epoch()).count();
}

std::int64_t modification_age_minutes(std::int64_t modified_ticks,
                                     fs::file_time_type::clock::time_point now,
                                     std::int64_t window_minutes) {
    using Duration = fs::file_time_type::duration;
    using Rep = Duration::rep;
    const auto now_ticks = static_cast<std::int64_t>(now.time_since_epoch().count());
    if (modified_ticks >= now_ticks || window_minutes == 0) return 0;

    // The only useful age range is the configured recency window. Compare
    // unsigned tick differences against that bound before converting the
    // difference back to the clock's signed duration representation.
    const auto window_ticks = std::chrono::duration_cast<Duration>(std::chrono::minutes(window_minutes)).count();
    const auto age_ticks = static_cast<std::uint64_t>(now_ticks) -
                           static_cast<std::uint64_t>(modified_ticks);
    if (age_ticks >= static_cast<std::uint64_t>(window_ticks)) return window_minutes;
    const auto bounded_ticks = static_cast<Rep>(age_ticks);
    return std::chrono::duration_cast<std::chrono::minutes>(Duration(bounded_ticks)).count();
}

bool authorized(Operation op, SchedulerAuthorization authorization) {
    switch (op) {
        case Operation::Add:
        case Operation::Modify:
            return authorization.changes_approved;
        case Operation::Delete:
            return authorization.changes_approved && authorization.deletions_confirmed;
        case Operation::Unchanged:
        case Operation::Preserve:
            return true;
    }
    return false;
}
} // namespace

BinaryHeapScheduler::BinaryHeapScheduler(SchedulerWeights weights) : weights_(weights) {
    validate(weights_);
}

void BinaryHeapScheduler::enqueue(SyncJob job, const FileMetadata& metadata,
                                  Clock::time_point enqueued_at,
                                  fs::file_time_type::clock::time_point mtime_now) {
    if (metadata.relative_path != job.relative_path) throw std::invalid_argument("scheduler job and metadata paths differ");
    if (next_sequence_ == std::numeric_limits<std::uint64_t>::max()) throw std::overflow_error("scheduler insertion sequence exhausted");

    const auto size_quanta = std::min<std::uintmax_t>(metadata.size / weights_.size_quantum_bytes, weights_.max_size_quanta);
    std::int64_t base = op_priority(job.operation, weights_);
    base = saturating_add(base, saturating_multiply(static_cast<std::int64_t>(size_quanta), weights_.size_points_per_quantum));

    const auto window = weights_.modification_window.count();
    const auto age_minutes = modification_age_minutes(metadata.modified_ticks, mtime_now, window);
    const auto fresh_minutes = age_minutes >= window ? 0 : window - age_minutes;
    base = saturating_add(base, saturating_multiply(fresh_minutes, weights_.modification_points_per_minute));

    const auto queued_minute = epoch_minute(enqueued_at);
    // With one fixed aging rate, every queued job gains the same score per
    // elapsed minute. Comparing base - enqueue-minute*rate is therefore
    // equivalent to comparing the full aged score, without rebuilding the
    // heap on every extraction.
    const auto age_offset = saturating_multiply(queued_minute, weights_.aging_points_per_minute);
    const auto key = age_offset == std::numeric_limits<std::int64_t>::min()
        ? std::numeric_limits<std::int64_t>::max()
        : saturating_add(base, -age_offset);
    job.enqueued_at = enqueued_at;
    Entry entry{std::move(job), base, key, queued_minute, next_sequence_++};
    heap_.push_back(std::move(entry));
    std::push_heap(heap_.begin(), heap_.end(), LowerPriority{});
    if (last_observed_time_ < enqueued_at) last_observed_time_ = enqueued_at;
}

std::optional<SyncJob> BinaryHeapScheduler::try_dequeue(Clock::time_point now, SchedulerAuthorization authorization) {
    if (heap_.empty()) return std::nullopt;
    if (now < last_observed_time_) now = last_observed_time_;
    last_observed_time_ = now;
    const auto& first = heap_.front();
    if (!authorized(first.job.operation, authorization)) return std::nullopt;

    std::pop_heap(heap_.begin(), heap_.end(), LowerPriority{});
    Entry entry = std::move(heap_.back());
    heap_.pop_back();
    const auto elapsed_minutes = std::max<std::int64_t>(0, epoch_minute(now) - entry.enqueued_minute);
    const auto aging_bonus = saturating_multiply(elapsed_minutes, weights_.aging_points_per_minute);
    const auto score = saturating_add(entry.base_priority, aging_bonus);
    entry.job.priority = static_cast<int>(std::max<std::int64_t>(std::numeric_limits<int>::min(),
        std::min<std::int64_t>(std::numeric_limits<int>::max(), score)));
    return std::move(entry.job);
}

std::size_t BinaryHeapScheduler::size() const noexcept { return heap_.size(); }
bool BinaryHeapScheduler::empty() const noexcept { return heap_.empty(); }

bool BinaryHeapScheduler::LowerPriority::operator()(const Entry& left, const Entry& right) const noexcept {
    if (left.heap_key != right.heap_key) return left.heap_key < right.heap_key;
    return left.sequence > right.sequence; // FIFO for equal computed priority.
}

} // namespace mc
