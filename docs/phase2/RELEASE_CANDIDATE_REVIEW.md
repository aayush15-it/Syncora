# Syncora Phase 2 — Release Candidate Review & Architecture Assessment
## Pre-Commit Audit, Lock Architecture Clarification, and Phase 3 Evaluation

**Author**: Senior Software Architect  
**Date**: November 3, 2026  
**Document Status**: Final Release Candidate Review  
**Target Release**: Syncora `v0.2.0-phase2`  
**Artifact Path**: `docs/phase2/RELEASE_CANDIDATE_REVIEW.md`

---

## 1. Corrected Lock Architecture

### Conceptual Misconception Corrected
In earlier draft descriptions, the locking model was shorthand-summarized as "four nested locks." **This was inaccurate.** In the actual C++17 implementation, the synchronization mechanisms are **not continuously nested**. Describing them as continuously nested implies that four mutexes are acquired simultaneously and held for the entire duration of an operation, which would cause severe lock contention and potential deadlocks.

Instead, the architecture utilizes **four decoupled, temporally distinct synchronization layers** with strict scope isolation:

```
[Incoming Request]
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: Admission Gate & Drain Monitor (lifecycle_mutex_ & active_ops_)        │
│ Scope: Nanoseconds during OperationGuard construction and destruction only.      │
│ Invariant: NEVER held while executing filesystem I/O, DB queries, or ws locks. │
└─────────────────────────────────────────────────────────────────────────────────┘
       │
       ▼  (lifecycle_mutex_ is RELEASED)
┌─────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: Workspace Registry Lookup (ws_registry_mutex_)                         │
│ Scope: Nanoseconds inside get_workspace_lock().                                 │
│ Invariant: RELEASED IMMEDIATELY after obtaining the std::shared_ptr<std::mutex>│
│            and BEFORE std::unique_lock<std::mutex> is acquired.                 │
└─────────────────────────────────────────────────────────────────────────────────┘
       │
       ▼  (ws_registry_mutex_ is RELEASED)
┌─────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: Per-Workspace Mutex (ws_mutexes_[actual_ws_id])                        │
│ Scope: Held for the duration of the logical workspace mutation/read.            │
│ Invariant: Workspace A and Workspace B have distinct non-recursive mutexes.     │
│            Does NOT block database access or operations on other workspaces.    │
└─────────────────────────────────────────────────────────────────────────────────┘
       │
       ▼  (Filesystem I/O executes under Layer 3 with db_mutex_ UNLOCKED)
┌─────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: SQLite Database Mutex (db_mutex_)                                      │
│ Scope: Microseconds to milliseconds during discrete DB queries & commits only.  │
│ Invariant: STRICTLY RELEASED during all filesystem operations (scan, copy,      │
│            rename, delete). Acquired briefly for intent, re-probe, and commit.  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Mechanics by Layer

#### Layer 1: Lifecycle Admission Gate (`lifecycle_mutex_`, `active_ops_`, `drain_cv_`)
- **Responsibility**: Prevents shutdown races and guarantees zero use-after-close on the SQLite database handle.
- **Acquisition Pattern**:
  ```cpp
  CollabStore::OperationGuard::OperationGuard(CollabStore& store) : store_(store) {
      std::unique_lock<std::mutex> lock(store_.lifecycle_mutex_);
      if (store_.shutting_down_) {
          throw std::runtime_error("CollabStore is shutting down; operation rejected");
      }
      ++store_.active_ops_;
  } // lifecycle_mutex_ is unlocked here!
  ```
- **Duration**: Less than $1\ \mu\text{s}$. Released before any workspace lookup or filesystem access begins.
- **Teardown**: The destructor briefly re-locks `lifecycle_mutex_`, decrements `active_ops_`, and signals `drain_cv_` if `active_ops_ == 0`.
- **Drain Barrier**: `finalize_and_close()` sets `shutting_down_ = true` under `lifecycle_mutex_` and waits on `drain_cv_`. It does not proceed to finalize statements or close SQLite until all active operations have exited.

#### Layer 2: Workspace Registry Mutex (`ws_registry_mutex_`)
- **Responsibility**: Thread-safe lazy instantiation and retrieval of per-workspace mutex pointers in `ws_mutexes_`.
- **Acquisition Pattern**:
  ```cpp
  std::unique_lock<std::mutex> CollabStore::get_workspace_lock(const std::string& ws_id) const {
      std::shared_ptr<std::mutex> ws_mutex;
      {
          std::lock_guard<std::mutex> reg_lock(ws_registry_mutex_);
          auto it = ws_mutexes_.find(ws_id);
          if (it == ws_mutexes_.end()) {
              ws_mutex = std::make_shared<std::mutex>();
              ws_mutexes_[ws_id] = ws_mutex;
          } else {
              ws_mutex = it->second;
          }
      } // <--- ws_registry_mutex_ is explicitly released HERE!
      return std::unique_lock<std::mutex>(*ws_mutex); // Mutex acquired after registry unlocked!
  }
  ```
- **Verification**: `ws_registry_mutex_` is never held while locking `*ws_mutex`, never held during database transactions, and never held during filesystem I/O.

#### Layer 3: Per-Workspace Mutex (`ws_mutexes_[actual_ws_id]`)
- **Responsibility**: Coarse-grained logical serialization for a single workspace's directory tree (`workspaces/<ws_id>/`).
- **Isolation Guarantee**: Operations on Workspace `ws-1` lock `ws_mutexes_["ws-1"]`. Operations on Workspace `ws-2` lock `ws_mutexes_["ws-2"]`. Neither workspace contends with or blocks the other.
- **Duration**: Held for the duration of compound operations (`accept_submission`, `publish_version`, `create_submission`, `write_working_copy_file_content`, diff calculations).

#### Layer 4: SQLite Database Mutex (`db_mutex_`)
- **Responsibility**: Serializes access to the single shared `sqlite3* db_` connection handle and `PreparedStatementRegistry`.
- **Scope Contract**: **Discrete, scoped acquisition**. In `accept_submission` and `publish_version`:
  1. `db_mutex_` acquired briefly to resolve workspace alias and probe status $\to$ **Released**.
  2. Workspace mutex acquired (Layer 3).
  3. `db_mutex_` acquired briefly to re-validate submission under lock $\to$ **Released**.
  4. Filesystem scan and path absence checks performed $\to$ **`db_mutex_` is NOT held**.
  5. `db_mutex_` acquired briefly to insert `workspace_operations` intent record $\to$ **Released**.
  6. Filesystem staging and recursive copying performed $\to$ **`db_mutex_` is NOT held**.
  7. `db_mutex_` acquired briefly to advance journal to `STAGED` $\to$ **Released**.
  8. Filesystem active directories backed up with exclusive sentinels $\to$ **`db_mutex_` is NOT held**.
  9. `db_mutex_` acquired briefly to advance journal to `PROMOTING` $\to$ **Released**.
  10. Filesystem promotion (rename staging to active) performed $\to$ **`db_mutex_` is NOT held**.
  11. `db_mutex_` acquired for the atomic SQLite commit transaction (`BEGIN IMMEDIATE; ... COMMIT;`), journal marked `COMMITTED` $\to$ **Released**.
  12. Filesystem verified backups cleaned up $\to$ **`db_mutex_` is NOT held**.
  13. `db_mutex_` acquired briefly to mark journal `COMPLETED` $\to$ **Released**.

---

## 2. File-by-File Phase 2 Release Inventory

Every tracked file currently modified in the working tree has been audited to determine its exact classification and ownership:

| File Path | Classification | Detailed Justification & Phase Ownership |
|---|---|---|
| `.gitignore` | **Phase 2 Tooling / Hygiene** | Adds `/collab_workspaces/` to ignore local test workspaces created by the collaboration test daemon. Essential to keep git status clean. |
| `include/merklechain/collab_store.hpp` | **Phase 2 Implementation** | Declares `OperationGuard`, `PreparedStatementRegistry`, `WorkspaceOperationRecord`, `SentinelValidationResult`, `CollabFaultPoint`, and public recovery APIs (`recover_incomplete_operations`). Core Phase 2 interface contract. |
| `src/collab_store.cpp` | **Phase 2 Implementation** | Implements the four-level synchronization architecture, atomic sentinel creation (`CreateFileW` / `O_CREAT \| O_EXCL`), transaction journaling, non-destructive baseline backup, and autonomous recovery engine. |
| `include/merklechain/scanner.hpp` | **Phase 2 Implementation** | Declares `is_reparse_point_or_symlink()` and `is_path_within_boundary()`. Required for filesystem junction rejection and sentinel validation. |
| `src/scanner.cpp` | **Phase 2 Implementation** | Implements reparse point detection, boundary containment checks, and explicit exclusion of `.syncora_op_sentinel` during directory scanning to prevent metadata from corrupting content Merkle roots. |
| `include/merklechain/sync.hpp` | **Phase 2 Implementation** | Exports `reject_symlink_path()` for cross-module use by `CollabStore` working copy file operations. |
| `src/sync.cpp` | **Phase 2 Implementation** | Updates `reject_symlink_path()` to reject Windows directory junctions and enforce canonical boundary root containment. |
| `src/versioning.cpp` | **Phase 2 Hardening** | Updates `reject_symlink_if_present()` and `ensure_no_symlink()` to use `is_reparse_point_or_symlink()` and `is_path_within_boundary()`. |
| `include/merklechain/types.hpp` | **Shared Utility Refactoring** | Implements fast, inline, allocation-efficient `to_hex()` and `to_lower_ascii()`. Used across Phase 2 sentinels, hashing, and peer sync. |
| `src/hash.cpp` | **Shared Utility Refactoring** | Refactors `digest_hex()` to delegate to common `to_hex()`, eliminating duplicate hex conversion code. |
| `src/peer/peer_sync.cpp` | **Shared Utility Refactoring** | Refactors `digest_to_hex()` to delegate to common `to_hex()`. Clean, zero-overhead refactor. |
| `src/web_server.cpp` | **Phase 2 Implementation & UI Bridge** | Connects HTTP REST endpoints to `CollabStore`. Contains Phase 2 fixes: canonical alias resolution for `"ws-default"`, verification of boolean return on `accept_submission()`, and lifecycle error mapping. |
| `tests/collab_store_tests.cpp` | **Phase 2 Regression Tests** | Adds 1,378 lines of deterministic tests covering `CP1-T1..T7`, `CP2-T1..T7`, `OWN-T1..T5`, `INIT-T1..T4`, `SUB-T1..T4`, `PUB-T1..T4`, `MAN-T1..T3`, `FIN-T1..T3`. Only 1 legacy comment removed. |
| `tests/test_main.cpp` | **Phase 2 Regression Tests** | Adds path containment and Windows junction security test checks; invokes all Phase 2 test suites. Zero pre-existing checks altered or removed. |
| `web/app.js` | **Phase 2 Web UI & Earlier Collaboration** | Frontend SPA routing and logic for Host and Client collaboration workspaces, submission reviews, diff visualizers, and version history. Required by `dashboard_smoke.ps1` and `test_dashboard_navigation.js`. |
| `web/index.html` | **Phase 2 Web UI & Earlier Collaboration** | HTML structure for collaboration views (Host Overview, Client Submit, Review, Diff Modal, Activity). |
| `web/styles.css` | **Phase 2 Web UI Styling** | CSS styles for the refined charcoal/graphite UI, diff viewers, and modal controls. |
| `docs/phase2/PHASE2_FINAL_AUDIT.md` | **Phase 2 Documentation** | Independent production audit report detailing all invariant checks, test outputs, and exit codes. |
| `docs/phase2/PHASE2_RELEASE_NOTES.md` | **Phase 2 Documentation** | Comprehensive release notes and freeze specification for `v0.2.0-phase2`. |
| `docs/phase3/PHASE3_ROADMAP.md` | **Phase 3 Planning** | Roadmap proposal for Phase 3 distributed synchronization, CAS, and three-way merging. |

---

## 3. Git Staging Safety & Recommendations

### Explicit Recommended Staging Command
The following command explicitly stages **only** verified Phase 2 source code, tests, web assets, configuration, and documentation:

```bash
git add .gitignore \
        include/merklechain/collab_store.hpp \
        include/merklechain/scanner.hpp \
        include/merklechain/sync.hpp \
        include/merklechain/types.hpp \
        src/collab_store.cpp \
        src/hash.cpp \
        src/peer/peer_sync.cpp \
        src/scanner.cpp \
        src/sync.cpp \
        src/versioning.cpp \
        src/web_server.cpp \
        tests/collab_store_tests.cpp \
        tests/test_main.cpp \
        web/app.js \
        web/index.html \
        web/styles.css \
        docs/phase2/PHASE2_FINAL_AUDIT.md \
        docs/phase2/PHASE2_RELEASE_NOTES.md \
        docs/phase2/RELEASE_CANDIDATE_REVIEW.md \
        docs/phase3/PHASE3_ROADMAP.md
```

### Files That Must Remain Unstaged
The following directories and files are detected in the workspace and **must strictly remain unstaged**:

1. `scratch/` (including `append_phase2_tests.py`, `apply_fixes.py`, `fix_copy_dir.py`, `fix_header.py`, etc.):
   - *Reason*: User-owned working scripts and scratch files. They must be preserved intact and never committed to version control.
2. `.agents/`:
   - *Reason*: Local environment configuration for agent tooling. Machine-specific.
3. `skills-lock.json`:
   - *Reason*: Tooling lockfile for local skill registry.
4. `collab_workspaces/`:
   - *Reason*: Local runtime data generated during local `--dashboard` runs. (Now properly ignored by `.gitignore`).

---

## 4. Git Commit and Tag Recommendation

### Commit Message Candidate
```
Phase 2: concurrency, lifecycle, journaling and crash recovery

- Add OperationGuard admission gate and drain-and-close lifecycle protocol
- Implement thread-safe PreparedStatementRegistry with zero statement leaks
- Introduce per-workspace mutex serialization without global contention
- Implement intent-first two-phase transaction journaling (workspace_operations)
- Implement atomic exclusive ownership sentinels (.syncora_op_sentinel)
- Add non-destructive baseline backup and failpoint crash recovery engine
- Verify physical manifest reconciliation and reparse-point / symlink isolation
- Add deterministic test suites (356 unit/recovery tests, 34 E2E tests, 0 failed)
```

### Release Tag Candidate
```bash
git tag -a v0.2.0-phase2 -m "Syncora Phase 2 Release: Concurrency, Lifecycle, Journaling and Crash Recovery"
```

---

## 5. Phase 3 Milestone 3.1 Architectural Assessment

Content-Addressed Storage (CAS) and Content-Defined Chunking (FastCDC) represent a significant architectural evolution. Below is an unvarnished systems review of the proposed design against Syncora's existing codebase.

### Critical Evaluation of Proposed Subsystems

#### 1. Immutable Object-Store Layout
- **Design**: Two-character fan-out directory structure: `<storage_root>/objects/xx/yy...` (256 top-level directories).
- **Assessment**: Sound. Prevents directory entry linear lookup bottlenecks on NTFS and ext4 when object counts scale into hundreds of thousands.
- **Missing Decision**: What is the physical blob structure?
  - *Raw payload*: Storing raw bytes makes read-back simple, but requires hashing the entire file to verify integrity and cannot store compression headers.
  - *Envelope/Framed blob (Recommended)*: 16-byte header containing magic bytes (`MC_OBJ1`), compression algorithm flag (0=None, 1=LZ4, 2=Deflate), uncompressed size, and chunk SHA-256 digest. This allows instant header validation before allocating decompression buffers.

#### 2. FastCDC Chunking vs Fixed-Size Chunking
- **Design**: FastCDC for files $\ge 64\text{ KB}$; whole-file blobs for files $< 64\text{ KB}$.
- **Assessment**: Correct. FastCDC avoids the boundary shift problem where inserting 1 byte shifts all subsequent fixed 64KB chunk boundaries.
- **Negative Overhead Warning**: For files $< 16\text{ KB}$, chunk manifest overhead (storing a 32-byte hash and 8-byte offset in SQLite) exceeds any possible deduplication benefit. The threshold must be enforced: files below $16\text{ KB}$ must be stored as inline blobs with no sub-chunking.

#### 3. Deduplication Claims Challenged
- **Roadmap Claim**: *"Reduces disk space consumption by 70–95% on typical codebases"*.
- **Architectural Challenge**: This claim is **unsupported** for diverse production workloads.
  - Across completely distinct workspaces (e.g., a C++ project vs. a Python project), inter-workspace deduplication is typically $< 5\%$.
  - For compressed binary files (PNG, JPEG, MP4, ZIP, SQLite files), FastCDC deduplication is effectively **$0\%$**.
  - **Realistic Claim**: 70–90% storage savings apply **specifically to incremental historical versions of text and source code assets within the same repository**. Phase 3 documentation and benchmarks must explicitly state this condition.

#### 4. File-to-Chunk Materialization & Hard-Linking Safety
- **Assessment**: On Windows/NTFS, creating thousands of small files sequentially carries high I/O overhead.
- **Safety Critical Invariant**: Files in `working_copy` **MUST NEVER BE HARD-LINKED** to objects in `objects/`.
  - In Syncora, the host directly edits files in `working_copy` (e.g. via text editor or REST API).
  - If a file in `working_copy` were hard-linked to an object in `objects/`, any in-place file mutation by the host would immediately corrupt the immutable object store and invalidate historical versions!
  - `working_copy` must always be physically materialized (copied or written). Only read-only historical snapshots (`versions/<ver_id>`) could theoretically utilize hard links.

#### 5. Garbage Collection: Reference Counting vs. Mark-and-Sweep
- **Design Risk**: Maintaining an atomic reference count column in SQLite (`ref_count`) across concurrent insertions and deletions is highly vulnerable to drift or double-decrements if an operation crashes midway.
- **Architectural Recommendation**: Use **Mark-and-Sweep with a Generational Grace Period**:
  1. *Mark*: Scan all committed versions across all workspaces in `collab.sqlite3` to accumulate the set of reachable object hashes.
  2. *Sweep*: Enumerate `objects/` directory. Delete any object not in the reachable set **UNLESS** its filesystem creation timestamp is newer than a safety threshold (e.g. 2 hours).
  3. The 2-hour grace period guarantees that active in-flight staging operations writing new chunks are never garbage-collected before their database commit boundary.

#### 6. Integration with Phase 2 Merkle Trees & Invariants
- **Design Invariant**: In Phase 1 and Phase 2, `FileManifest` computes `merkle_root` over canonical relative paths and full-file SHA-256 hashes (`file.sha256`).
- **Architectural Rule**: FastCDC chunking must operate as an **underlying storage layout optimization**, not a change to the cryptographic Merkle tree definition.
  - `file.sha256` remains the SHA-256 of the complete uncompressed file.
  - `FileManifest::merkle_root` remains identical whether files are stored as loose copies or reconstructed from chunks.
  - An internal SQLite table `file_chunks (file_sha256, chunk_index, chunk_sha256, offset, length)` maps full files to chunks.
  - This guarantees **100% backward compatibility** with Phase 1 and Phase 2 manifests, peer sync protocols, and existing test assertions.

#### 7. Crash-Safe Object Insertion
- To prevent partial/truncated objects from corrupting the CAS store during a system crash:
  1. Write incoming chunk to a temporary file: `<storage_root>/objects/.tmp_<uuid>`.
  2. `fsync` / `FlushFileBuffers` the temporary file.
  3. Execute atomic rename (`fs::rename`) into the final location `<storage_root>/objects/xx/yy...`.
  4. If the destination object already exists, delete the temporary file (idempotent duplicate detection).

---

## 6. Outstanding Decisions Requiring User Approval

Before any release commit or Phase 3 development begins, the following three decisions require your explicit authorization:

1. **Phase 2 Release Authorization**:
   - Approve the selective staging list of 17 source/test/UI files plus 4 documentation files.
   - Authorize executing `git add`, `git commit` with message `"Phase 2: concurrency, lifecycle, journaling and crash recovery"`, and creating annotated tag `v0.2.0-phase2`.
2. **Phase 3 Milestone 3.1 Scope Approval**:
   - Approve the corrected Content-Addressed Storage architecture (Mark-and-Sweep GC with 2-hour grace period, whole-file Merkle tree preservation, envelope header framing, and strict materialization of working copies).
3. **Benchmark Verification Requirement**:
   - Authorize creating an automated storage benchmark (`benchmarks/cas_benchmark.cpp`) as the first deliverable of Milestone 3.1 to empirically measure deduplication ratios before modifying production store paths.

