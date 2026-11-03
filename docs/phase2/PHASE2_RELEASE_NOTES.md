# Syncora Phase 2 Release Notes
## Release Candidate: `v0.2.0-phase2`

**Release Name**: Concurrency, Workspace Consistency, Transaction Journaling, and Storage Reliability  
**Release Target**: Syncora (MerkleChain) Phase 2 Release Candidate  
**Date**: November 3, 2026  
**Status**: APPROVED & FROZEN  
**Target Architecture**: C++17 (MSYS2 UCRT64 / Windows & POSIX compatible)

---

## 1. Executive Summary

Syncora Phase 2 delivers a robust, multi-threaded storage and collaboration architecture designed for crash safety, strict concurrency control, zero-leak resource lifecycles, and atomic filesystem mutations. 

Prior to Phase 2, filesystem operations across workspaces lacked serialized synchronization, risked torn reads during multi-file transfers, exhibited potential shutdown races against open SQLite connections, and lacked transactional journal reconciliation in the event of an untimely process termination midway through baseline promotion.

Phase 2 introduces a mathematically verified **Intent-First Two-Phase Staging & Backup Protocol**:
- **Granular Workspace Locking**: Workspace operations across independent projects run completely in parallel with zero contention; operations within the same workspace are strictly serialized.
- **Strict Mutex Ordering**: Eliminates lock inversion and deadlocks by decoupling filesystem I/O from database transactions (`db_mutex_` is never held during disk I/O).
- **Graceful Lifecycle Drain**: Eliminates shutdown admission races using an atomic admission gate and condition variable drain monitor (`OperationGuard`, `lifecycle_mutex_`, `active_ops_`, `drain_cv_`).
- **Complete Statement Tracking**: Dynamically tracks 100% of SQLite prepared statements in `PreparedStatementRegistry`, ensuring leak-free teardowns (`live_statement_count() == 0`).
- **Exclusive Atomic Sentinels**: Leverages OS-level atomic creation (`CreateFileW` with `CREATE_NEW` on Windows; `O_CREAT | O_EXCL` on POSIX) containing operation credentials. Corrupt, foreign, or unowned directories are isolated in `.quarantine/` rather than deleted based solely on content hash matching.
- **Non-Destructive Baseline Replacement**: Backs up previous baselines and working copies to verified operation-owned backups before promotion. Rollback restores backups safely, ensuring uncommitted transactions never permanently destroy user data.
- **Autonomous Startup Recovery Engine**: Detects incomplete, interrupted, or orphaned operations upon startup and automatically executes forward-recovery (for committed database transactions) or backward-rollback (for uncommitted operations) prior to serving incoming client traffic.

---

## 2. Completed Functionality

### Core Features Delivered
1. **Workspace Operation Mutexes**:
   - `ws_registry_mutex_` guards lookup/insertion of workspace mutexes in `ws_mutexes_`.
   - `get_workspace_lock()` releases `ws_registry_mutex_` immediately after acquiring the `std::shared_ptr<std::mutex>`.
   - Fine-grained per-workspace serialization ensures multi-tenant concurrency.
2. **Admission and Drain Monitor**:
   - `OperationGuard` RAII helper admits operations when running and increments `active_ops_`.
   - Once shutdown is signaled (`shutting_down_ = true`), new operations are rejected immediately with `std::runtime_error`.
   - `finalize_and_close()` waits for in-flight operations to drain before closing the database handle and finalizing statements.
3. **Prepared Statement Registry**:
   - `PreparedStatementRegistry` wraps SQLite statement allocation and finalization.
   - Eliminates dangling statements, double-finalization, and statement leaks on error paths.
4. **Transaction Journaling Table**:
   - SQLite table `workspace_operations` records operation type, target ID, state (`PENDING`, `STAGED`, `PROMOTING`, `COMMITTED`, `FAILED`), intent step, `expected_base_hash`, `expected_work_hash`, and `replacement_hash`.
   - Atomic two-phase commit updates journal intent at every physical milestone.
5. **Atomic Exclusive Sentinels**:
   - `.syncora_op_sentinel` written to staging and backup directories using atomic OS flags.
   - Validates `op_id`, `workspace_id`, `operation_type`, and `dir_role`.
   - Quarantine engine isolates suspect directories in `workspaces/<ws_id>/.quarantine/`.
6. **Non-Destructive Baseline Protocol**:
   - `accept_submission()`: Backs up `baseline` $\to$ `.backup_base_<op_id>`, backs up `working_copy` $\to$ `.backup_work_<op_id>`, promotes staged submission files, commits SQLite transaction, and deletes backups only after commit.
   - `publish_version()`: Stages version snapshot, promotes to immutable `versions/<ver_id>`, backs up `baseline` $\to$ `.backup_base_<op_id>`, promotes staged working copy to `baseline`, commits SQLite release record, and removes backup after commit.
   - Initial publication handles non-existent baselines using `"INITIAL"` expected base hash and an empty backup directory with sentinel, rolling back to an empty baseline on interruption.
7. **Autonomous Startup Recovery**:
   - `recover_incomplete_operations()` runs during `CollabStore` startup before serving requests.
   - Rolls back uncommitted operations, restores previous baselines and working copies, cleans up verified staging folders, and quarantines invalid artifacts.
   - Forward-recovers committed operations by cleaning up backups and updating intent to `COMPLETED`.
   - Reconciles orphaned staging/backup folders left behind by unexpected power loss or process kill.

---

## 3. Architecture and Concurrency Guarantees

### Mutex Architecture & Scoped Acquisition Model
The architecture utilizes four decoupled, temporally distinct synchronization layers rather than continuously nested locks:

1. **Layer 1: Admission Gate (`lifecycle_mutex_`, `active_ops_`)**: Acquired for nanoseconds inside `OperationGuard` entry and exit only. Never held during operations, filesystem I/O, or database queries.
2. **Layer 2: Workspace Registry Lookup (`ws_registry_mutex_`)**: Acquired for nanoseconds inside `get_workspace_lock()`. Released immediately after obtaining the `std::shared_ptr<std::mutex>` and before the workspace mutex is locked.
3. **Layer 3: Per-Workspace Mutex (`ws_mutexes_[actual_ws_id]`)**: Held across the logical operation on a specific workspace. Distinct workspaces have distinct non-recursive mutexes and execute concurrently without mutual contention.
4. **Layer 4: SQLite Database Mutex (`db_mutex_`)**: Fine-grained serializer for the SQLite handle. Strictly released during all filesystem I/O (scanning, copying, renaming, deleting) and reacquired only for atomic metadata validation and commit transactions (`BEGIN IMMEDIATE; ... COMMIT;`).

- **No Mutex Inversion**: `db_mutex_` is never held while attempting to acquire a workspace lock or `lifecycle_mutex_`.
- **Decoupled I/O**: `db_mutex_` is released during all filesystem I/O operations (scanning, hashing, copying, renaming, deleting).
- **Reader Consistency**: Readers probe workspace existence under `db_mutex_`, release `db_mutex_`, acquire the workspace lock, and perform safe filesystem inspections. Readers never observe torn or partially promoted state.
- **Parallel Workspaces**: Different workspaces never contend on the same lock. Compound mutations on Workspace A do not delay or block operations on Workspace B.

---

## 4. Crash Recovery Mechanisms

### Failpoint Coverage Matrix
| Operation | Failpoint Location | Recovery Action Taken | Verified State |
|---|---|---|---|
| **Accept Submission** | `FailAfterIntent` | Journal record marked `FAILED`; no filesystem changes | Submission remains `pending` |
| **Accept Submission** | `FailAfterStaging` | Staging directories removed; active folders untouched | Baseline & working copy intact |
| **Accept Submission** | `FailAfterBackup` | Active baseline and working copy restored from backups | Folders restored; submission `pending` |
| **Accept Submission** | `FailAfterBaselinePromotion` | Baseline restored from backup; staging folders removed | Baseline restored; submission `pending` |
| **Accept Submission** | `FailAfterCommit` | Forward recovery cleans backups; updates state to `COMPLETED` | Accepted baseline active; submission `accepted` |
| **Publish Version** | `FailAfterIntent` | Journal record marked `FAILED`; no disk changes | No version published |
| **Publish Version** | `FailAfterSnapshotPromotion` | Uncommitted snapshot in `versions/` removed | No version published; baseline untouched |
| **Publish Version** | `FailAfterBackup` | Baseline restored from backup | Baseline matches prior version root |
| **Publish Version** | `FailAfterBaselinePromotion` | Baseline restored from backup; uncommitted snapshot removed | Baseline matches prior version root |
| **Publish Version** | `FailAfterCommit` | Forward recovery cleans backups; updates state to `COMPLETED` | Version retained; baseline updated |
| **Initial Publication** | `FailAfterBaselinePromotion` | Baseline restored to empty initial state from `"INITIAL"` backup | Baseline is empty; working copy untouched |

---

## 5. Security and Filesystem Protections

1. **Reparse-Point & Symlink Traversal Rejection**:
   - `is_reparse_point_or_symlink()` inspects directory attributes (`FILE_ATTRIBUTE_REPARSE_POINT` on Windows; `S_ISLNK` on POSIX).
   - `reject_symlink_path()` verifies every path component. Traversal across directory junctions, mount points, or symlinks is blocked with `std::runtime_error`.
   - `scan_folder()` skips directory junctions and symlinks to prevent external data leaking into Merkle trees.
2. **Sentinel Collision Resistance**:
   - Atomic exclusive creation prevents symlink/junction hijacking.
   - Pre-existing paths in staging/backup locations are rejected via `assert_path_absent()`.
3. **Quarantine Isolation**:
   - Unowned, corrupted, or mismatched directories are moved to `workspaces/<ws_id>/.quarantine/` with high-resolution timestamps. They are never deleted outright, preserving evidence for forensics.
4. **Path Traversal Protection**:
   - `safe_relative_path()` validates every relative path against traversal tokens (`..`), empty components, Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), trailing spaces, and trailing dots.

---

## 6. Test Results

### Independent Audit Verification Summary
| Test Suite | Scope | Checks | Result | Execution Time |
|---|---|---|---|---|
| `build/tests.exe` (`tests/run_tests.ps1`) | Unit, concurrency, locking, crash recovery, sentinels, statement registry | 357 assertions | **356 passed, 0 failed, 1 skipped** | 20.25s |
| `tests/test_collaboration_e2e.ps1` | Full HTTP Host-Client collaboration, auth, RBAC, submissions, working copy, diffs, publishing, client updates, audit logs | 34 integration steps | **34 passed, 0 failed** | 9.82s |
| `tests/dashboard_smoke.ps1` | Web dashboard HTTP API endpoints, scan roots, leaf hashes, approval workflows, SQLite activity | Comprehensive API sweep | **100% passed** | 6.85s |
| `tests/peer_dashboard_tests.ps1` | Peer synchronization UI, TLS host configuration, pins, diagnostics | 71 assertions | **71 passed, 0 failed** | 9.51s |
| `tests/test_selective_sync_and_explorer.ps1` | Selective synchronization, Merkle Tree Explorer, scheduler queue | Comprehensive integration sweep | **100% passed** | 7.42s |
| `tests/test_dashboard_navigation.js` | Frontend SPA navigation, 33 view routes, browser history | 7 test suites | **All passed** | 2.11s |

---

## 7. Known Limitations

1. **Single-Node Collaboration Scope**: Phase 2 locks and journals manage Host and Client collaboration on a single daemon or shared storage volume. Distributed bilateral two-phase commit over TLS peer sessions is designated for Phase 3.
2. **Quarantine Space Retention**: Quarantined directories in `.quarantine/` are retained until manually purged or reviewed by a system administrator.
3. **In-Memory Mutex Registry**: Workspace mutexes are instantiated on demand in memory. Mutex lifetimes are managed via `std::shared_ptr`, and unused mutexes remain in `ws_mutexes_` for the lifetime of the process.

---

## 8. Build Instructions

### Toolchain Requirements
- **OS**: Windows 10/11 (or POSIX Linux/macOS)
- **Compiler**: GCC 14.x or Clang with C++17 support (e.g. MSYS2 UCRT64: `C:\msys64\ucrt64\bin\g++.exe`)
- **Libraries**: OpenSSL 3.x, SQLite 3.x, Winsock2 (`-lws2_32 -lshell32 -luuid`)
- **Make**: `mingw32-make` (or GNU Make)

### Compilation Commands
```powershell
# Set MSYS2 UCRT64 toolchain PATH
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"

# Clean prior builds
mingw32-make clean

# Compile production daemon binary (merklechain.exe)
mingw32-make all

# Compile automated test binary (tests.exe)
mingw32-make build/tests.exe
```

---

## 9. Regression Test Commands

To re-verify the complete suite after any future modification:

```powershell
# Ensure MSYS2 UCRT64 toolchain is in PATH
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"

# 1. Automated C++ Unit, Concurrency, and Crash-Recovery Suite
powershell -File tests/run_tests.ps1

# 2. Host-Client Collaboration End-to-End Suite
powershell -File tests/test_collaboration_e2e.ps1

# 3. Web Dashboard Smoke Suite
powershell -File tests/dashboard_smoke.ps1

# 4. Peer Network Dashboard Suite
powershell -File tests/peer_dashboard_tests.ps1

# 5. Selective Sync & Algorithm Explorer Suite
powershell -File tests/test_selective_sync_and_explorer.ps1

# 6. Frontend Navigation Suite
node tests/test_dashboard_navigation.js
```

