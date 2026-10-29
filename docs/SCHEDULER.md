# Local job scheduler design

BinaryHeapScheduler is a C++17 component used by the Local Mode synchronization
pipeline through `execute_plan`. It orders the existing `SyncJob` mutations;
the existing staging, copy, verification, backup, activity-recording, and
version-snapshot paths still perform the work. Restore uses that same execution
function in its existing plan order, with scheduling disabled, so restore
journal behavior and replay ordering are unchanged. Network Mode does not use
the scheduler.

## Priority calculation

All terms use nonnegative integer weights. For a job at a dequeue time:

    priority =
        operation_base
      + min(floor(file_size / size_quantum_bytes), max_size_quanta)
          * size_points_per_quantum
      + max(0, modification_window_minutes - file_age_minutes)
          * modification_points_per_minute
      + max(0, current_epoch_minute - enqueue_epoch_minute)
          * aging_points_per_minute

Default operation bases are Add 400, Modify 300, Delete 200, Unchanged 0, and
Preserve 0. Defaults also award one point per MiB, cap the size term at 1,000
units, award one point for each minute of recency in a 120-minute window, and
award one aging point per full waiting minute. SchedulerWeights lets a caller
configure each weight, size quantum, size cap, recency window, and aging rate.
Negative and excessive values are rejected.

FileMetadata.modified_ticks is interpreted in the std::filesystem file clock.
The enqueue API takes an explicit mtime_now reference for repeatable
calculation. Wall-clock enqueue and dequeue timestamps are each mapped to a
whole-minute epoch bucket; aging is the nonnegative difference of those
buckets.

## Ordering and authorization

Higher scores are extracted first. Equal scores use FIFO insertion sequence;
path spelling and random job IDs do not affect ordering. With a single aging
rate, each queued job's score increases by the same amount as time advances.
The heap compares the equivalent fixed key
base_priority - aging_rate * enqueue_epoch_minute, retaining normal
logarithmic heap insertion and extraction while producing the same ordering.
The reported SyncJob.priority is the effective score at extraction, clamped
to the field's int range.

try_dequeue takes a SchedulerAuthorization. Add and Modify require
changes_approved; Delete requires both changes_approved and
deletions_confirmed. If the highest-priority mutating job is not authorized,
the method returns no job and leaves it queued. A score cannot grant consent.
The caller must still use the existing typed approval and deletion-confirmation
workflow before supplying authorization. Network Mode is not involved.

`execute_plan` validates approval before queue construction and checks again
immediately before each mutation. Its scheduler receives the same explicit
authorization values; selecting a job cannot change them. The Local Mode CLI
asks for change approval and, if a plan contains any Delete, asks separately
for deletion confirmation. The current manifest comparison does not generate
Delete jobs: destination-only files remain `Preserve`. The Delete execution
path exists for explicitly constructed plans and saves a verified recovery
copy before removing the target.

For scheduled execution, Add/Modify priority metadata is read from the source;
Delete metadata is read from its destination. The Local Mode queue is built
from one approved plan, using plan insertion order for equal-score FIFO ties.
The API accepts fixed wall-clock and file-clock references for deterministic
tests. Existing queued jobs with older `enqueued_at` timestamps can gain aging
priority over newer jobs. The current Local Mode planner submits a batch, so
aging is an ordering term for jobs whose enqueue timestamps differ; it does not
create a persistent background queue.

The current planner produces independent per-file mutations. Before dispatch,
`execute_plan` rejects duplicate paths and file/directory ancestor conflicts
(case-insensitive for ASCII path letters), rather than allowing priority order
to violate a dependency. Parent directories are created as needed by the
existing executor. Source hashes, destination preconditions, staged hashes,
recovery copies, and per-target verification are still checked by the executor.
Local Mode also scans the completed destination and compares its Merkle root
with the approved source-plus-preserved-files manifest before recording a
post-sync version.

## Validation coverage

The test executable contains 11 unit checks for empty queues, operation ordering,
stable equal-priority ordering, aging, modification time, extreme timestamp
handling, file size, approval and deletion gates, and ordered extraction of
5,000 jobs. Integration checks exercise mixed Add/Modify/Delete execution,
destination-only preservation, equal-priority FIFO, aging, approval rejection,
path dependency conflicts, source/destination mutation detection, execution
failure, verified Delete recovery copies, and restore compatibility. See
`docs/TEST_PLAN.md` and the latest dated implementation-status entry for the
actual runtime results.
