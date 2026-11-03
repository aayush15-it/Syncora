# Syncora Phase 3 — Milestone 3.2: Production CAS Integration Report

> **Document Version:** 1.0  
> **Status:** Implementation Complete & Production Verified  
> **Release Target:** Syncora v0.3.0 (Milestone 3.2)  
> **Author:** Senior C++ Storage-Engine Architect & Database Systems Engineer  
> **Date:** November 3, 2026  

---

## 1. Executive Summary

Milestone 3.2 of Syncora has successfully integrated the audited Content-Addressed Storage (CAS) prototype and FastCDC chunking engine into Syncora's production collaboration, submission acceptance, and version publishing workflows (`CollabStore`).

### Key Accomplishments
1. **FastCDC Ingestion in `accept_submission()`**: Incoming client submissions are stream-chunked with normalized FastCDC boundaries (min 4 KB, avg 8 KB, max 16 KB), stored into sharded immutable CAS objects (`objects/xx/hash`), and reconstructed into staging directories before atomic promotion to workspace baseline and working copy.
2. **Version Publishing with Immutable Manifests in `publish_version()`**: Publishing a version chunks all working copy files, generates binary `FileManifest` structures, records manifests into `version_manifests`, links chunks into `version_manifest_chunks`, and updates `cas_chunks` reference counts atomically inside SQLite transactions.
3. **Verified Version Reconstruction (`reconstruct_version()`)**: Implemented a standalone version reconstruction API that verifies reconstructed file and folder Merkle roots, enforcing independent regular files (`hard_link_count == 1`).
4. **Zero-Drift CAS Reference Counting**: Maintained strict mathematical equality between `cas_chunks.reference_count` and the number of active references in `version_manifest_chunks`, verified via `audit_cas_reference_integrity()`.
5. **Phase 2 Release & Backward Compatibility Preservation**: The Phase 2 release commit and tag `v0.2.0-phase2` remain untouched. Legacy versions published without manifest records gracefully fall back to existing directory snapshots.
6. **Strict Concurrency & Lock Hierarchy**: Maintained `OperationGuard` $\rightarrow$ `workspace_lock` $\rightarrow$ `db_mutex_`. `db_mutex_` is never held during filesystem I/O, hashing, chunking, or reconstruction.

---

## 2. Complete Inventory of Changes

### 2.1 Core Subsystem Modifications

| File | Change Description |
| :--- | :--- |
| `include/merklechain/collab_store.hpp` | Added CAS header includes, `CollabVersionManifestRecord`, `CollabCasChunkRecord`, public methods `reconstruct_version()`, `get_version_manifests()`, `get_chunk_reference_count()`, `audit_cas_reference_integrity()`, `cas_store()`, `cas_root_dir()`, and private member `std::unique_ptr<cas::ObjectStore> cas_store_`. |
| `src/collab_store.cpp` | Integrated FastCDC chunking & CAS reconstruction in `accept_submission()`; integrated FastCDC chunking, manifest serialization, and atomic SQLite schema updates in `publish_version()`; implemented `reconstruct_version()`, `get_version_manifests()`, `get_chunk_reference_count()`, and `audit_cas_reference_integrity()`. Updated `init_schema()` with `cas_chunks`, `version_manifests`, and `version_manifest_chunks`. |
| `src/cas/object_store.cpp` | Hardened `put_object()` concurrency against transient Windows file sharing locks with retry backoff and non-destructive exception handling during duplicate detection and atomic promotion. |
| `Makefile` | Added `$(CAS_SOURCES)` to `merklechain.exe` build dependencies and added `tests/cas/cas_collab_integration_tests.cpp` to `TEST_SOURCES`. |
| `tests/cas/cas_tests.hpp` | Added declaration for `run_cas_collab_integration_tests()`. |
| `tests/cas/cas_collab_integration_tests.cpp` | Added 8 production integration test cases covering end-to-end CAS workflows (`CAS-INT-01` through `CAS-INT-08`). |
| `tests/test_main.cpp` | Integrated invocation of `run_cas_collab_integration_tests()` into the primary test harness. |

---

## 3. SQLite Metadata Schema & Foreign Key Discipline

Milestone 3.2 extends the existing SQLite schema with three normalized tables:

```sql
-- 1. CAS physical chunk object catalog
CREATE TABLE IF NOT EXISTS cas_chunks (
    chunk_hash TEXT PRIMARY KEY,
    chunk_size INTEGER NOT NULL,
    reference_count INTEGER NOT NULL DEFAULT 0 CHECK(reference_count >= 0),
    created_at_ms INTEGER NOT NULL,
    verified_at_ms INTEGER NOT NULL,
    storage_state TEXT NOT NULL DEFAULT 'COMMITTED'
);
CREATE INDEX IF NOT EXISTS idx_cas_chunks_ref ON cas_chunks(reference_count);
CREATE INDEX IF NOT EXISTS idx_cas_chunks_state ON cas_chunks(storage_state);

-- 2. Version manifest catalog
CREATE TABLE IF NOT EXISTS version_manifests (
    manifest_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES published_versions(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    whole_file_sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    manifest_blob BLOB,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(version_id, relative_path)
);
CREATE INDEX IF NOT EXISTS idx_version_manifests_ver ON version_manifests(version_id);
CREATE INDEX IF NOT EXISTS idx_version_manifests_ws ON version_manifests(workspace_id);
CREATE INDEX IF NOT EXISTS idx_version_manifests_hash ON version_manifests(whole_file_sha256);

-- 3. Version manifest chunk cross-reference
CREATE TABLE IF NOT EXISTS version_manifest_chunks (
    manifest_id TEXT NOT NULL REFERENCES version_manifests(manifest_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    chunk_hash TEXT NOT NULL REFERENCES cas_chunks(chunk_hash),
    chunk_size INTEGER NOT NULL,
    PRIMARY KEY (manifest_id, chunk_index)
);
CREATE INDEX IF NOT EXISTS idx_manifest_chunks_hash ON version_manifest_chunks(chunk_hash);
CREATE INDEX IF NOT EXISTS idx_manifest_chunks_man ON version_manifest_chunks(manifest_id);
```

### Foreign Key Invariant & Insertion Ordering
With `PRAGMA foreign_keys = ON;`, `version_manifest_chunks.chunk_hash` references `cas_chunks(chunk_hash)`. Therefore, during `publish_version()`:
1. `cas_chunks` is upserted **first** with `reference_count = reference_count + 1`.
2. `version_manifest_chunks` is inserted **second**, ensuring all foreign keys are satisfied immediately.
3. If any step fails, SQLite automatically rolls back all table mutations, preserving reference integrity.

---

## 4. Concurrency & Lock Hierarchy Verification

The Phase 2 lock hierarchy has been maintained with zero violations:

$$\text{OperationGuard} \longrightarrow \text{workspace\_lock} \longrightarrow \text{db\_mutex\_}$$

### Audit Findings
- **Workspace Concurrency**:
  - `ws_registry_mutex_` is acquired only to locate or insert the workspace mutex, and is released immediately.
  - Operations on different workspaces run concurrently without blocking.
- **I/O Isolation**:
  - `db_mutex_` is acquired only for metadata validation, intent logging, and transactional commits.
  - FastCDC chunking, file read/write, SHA-256 computation, and CAS store operations are executed under `workspace_lock` with `db_mutex_` released.
- **Windows High-Concurrency File Sharing**:
  - Multi-threaded insertion tests (`CAS-OBJ-06`: 8 threads x 400 puts) verified that concurrent deduplication checks handle brief sharing violations gracefully without corrupting files or deleting in-flight writes.

---

## 5. Crash Recovery & Transaction Boundaries

Milestone 3.2 operations align with transaction boundaries A through H:

| Boundary | Point | State | Action upon Interruption |
| :---: | :--- | :--- | :--- |
| **A** | Before operation intent recorded | `None` | No state mutated; clean no-op. |
| **B** | After intent logged in journal | `PENDING` | Detected on startup; journal marked `FAILED`, staging cleaned. |
| **C** | During FastCDC chunking & CAS puts | `PENDING` | CAS objects written are immutable; staging files cleaned; no DB commits. |
| **D** | After staging directories prepared | `STAGED` | Verified backups exist; staging removed if uncommitted. |
| **E** | During baseline/working copy promotion | `PROMOTING` | Sentinel validation restores verified backup baseline/working copy. |
| **F** | Mid-SQLite transaction | `PROMOTING` | SQLite WAL rollback rolls back `published_versions`, `version_manifests`, `cas_chunks`. |
| **G** | Post-commit cleanup | `COMMITTED` | Operation succeeded; backups purged; sentinels cleared. |
| **H** | Post-recovery completion | `COMMITTED` | Full state verified matching Merkle root. |

---

## 6. Backward Compatibility Verification

The integration guarantees complete backward compatibility:
- Historical Phase 2 versions stored on disk at `workspaces/<ws_id>/versions/<ver_id>/` without `version_manifests` records are detected by `reconstruct_version()`.
- `reconstruct_version()` automatically falls back to validating the legacy snapshot against `published_versions.merkle_root` and copying the directory.
- Verified in `CAS-INT-06`: legacy version restored byte-for-byte and verified against the expected Merkle root.

---

## 7. Quality Assurance Summary

- **C++ Standard**: C++17 (`-std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2`).
- **Compiler Warnings**: 0 warnings.
- **Unit & Integration Suite**: 483 assertions passing (0 failures, 1 Windows-specific subprocess skip).
- **Collaboration E2E Suite**: 34 assertions passing (0 failures).
- **Dashboard Smoke Suite**: All views, scans, approvals, and sync tests passing.
- **CAS Benchmark**: Completed with 65.0% total footprint reduction across all test datasets (71.0% on shift-injected datasets).

