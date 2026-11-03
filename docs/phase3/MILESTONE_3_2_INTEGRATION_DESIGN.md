# Syncora Phase 3 — Milestone 3.2: Production CAS Integration Design

> **Document Version:** 1.0  
> **Status:** Approved Architecture Specification  
> **Target Release:** Syncora v0.3.0 (Milestone 3.2)  
> **Authors:** Senior C++ Storage-Engine Architect & Database Systems Engineer  

---

## 1. Executive Summary & Architectural Goals

Milestone 3.2 integrates Syncora's independently audited Content-Addressed Storage (CAS) prototype and FastCDC chunking engine into the core collaboration platform:
1. **Submission Acceptance (`CollabStore::accept_submission`)**: Physical content is chunked via FastCDC, stored into immutable CAS objects, and reconstructed into the host working copy through verified staging files.
2. **Version Publishing (`CollabStore::publish_version`)**: Published versions generate immutable `FileManifest` structures stored transactionally in SQLite, linking version metadata to chunk references.
3. **Version Reconstruction (`CollabStore::reconstruct_version`)**: A clean, internal C++ API reconstructing published versions from CAS chunks into target directories with cryptographic integrity verification.
4. **Crash Recovery & Concurrency**: The existing `workspace_operations` journal and sentinel protocol are extended to encompass CAS chunk ingestion, manifest staging, and reference-count transactions while preserving Phase 2 lock ordering and crash-resilience.

---

## 2. Invariants & Non-Negotiable Constraints

1. **Phase 2 Release Preservation**:
   - The annotated tag `v0.2.0-phase2` and its release commit remain untouched.
   - All 356 Phase 2 unit/recovery assertions and 34 collaboration E2E tests must pass without modification or weakening.
2. **Cryptographic Identity Invariant**:
   - Whole-file SHA-256 remains the authoritative file identity.
   - Directory Merkle leaf construction remains strictly:
     $$\text{leaf\_hash} = \text{SHA-256}("leaf" + \text{relative\_path} + \text{whole\_file\_sha256})$$
   - CAS chunk hashes are distinct and internal to the storage layer; they never alter whole-file hashes or Merkle roots.
3. **No Hard-Linking**:
   - Host working-copy files and client update targets must never be hard-linked to immutable CAS objects (`hard_link_count == 1`).
4. **Lock Ordering Discipline**:
   - Lock hierarchy is strictly preserved:
     $$\text{OperationGuard} \longrightarrow \text{workspace\_lock (per-workspace mutex)} \longrightarrow \text{db\_mutex\_ (SQLite serialization)}$$
   - `db_mutex_` must **never** be held across filesystem I/O, FastCDC chunking, cryptographic hashing, or file reconstruction.
5. **No Premature Scope Expansion**:
   - Garbage collection (unreferenced chunk purging) is explicitly out of scope for Milestone 3.2 and deferred to Milestone 3.3.

---

## 3. Current vs Proposed Architecture & Data Flow

### 3.1 Current Architecture (Phase 2)
In Phase 2, `CollabStore` stores submissions, working copies, baselines, and versions as whole-directory copies on the filesystem:
- Submissions: `workspaces/<ws_id>/submissions/<sub_id>/`
- Working Copy: `workspaces/<ws_id>/working_copy/`
- Baseline: `workspaces/<ws_id>/baseline/`
- Published Versions: `workspaces/<ws_id>/versions/<ver_id>/`

Every submission acceptance and version publication performs full recursive file copies (`copy_directory_recursive()`), resulting in high storage amplification and redundant I/O for unchanged files.

```
[Phase 2 Data Flow]
Submission Folder ---> copy_directory_recursive() ---> Staging Base / Work
                                                              |
                                                              v (Atomic Rename)
                                                     Baseline & Working Copy
                                                              |
                                                              v (Atomic Rename)
Working Copy --------> copy_directory_recursive() ---> Version Snapshot
```

### 3.2 Proposed CAS Architecture (Milestone 3.2)
In Milestone 3.2, content is stored in an immutable, shared `ObjectStore` rooted at `base_storage_dir_ / "cas"`:
- CAS Object Store: `cas/objects/<shard>/<chunk_hash>`
- CAS Temporary Directory: `cas/.tmp/obj_tmp_<pid>_<timestamp>_<random>.tmp`
- Database: Stores manifests in `version_manifests` and chunk references in `version_manifest_chunks`.
- Working Copy: Reconstructed file-by-file from CAS chunks via staging files (`.reconstruct.<timestamp>.tmp`).

```
[Milestone 3.2 CAS Data Flow]
Submission Files ---> FastCDC Chunker ---> ObjectStore (Deduplicated CAS Objects)
                             |                                |
                             v                                v
                       FileManifest                  Reconstruct Staging
                             |                                |
                             v                                v (Verify Whole-File SHA-256)
                       Binary MCAS                   Promote Working Copy
                             |
                             v (Atomic DB Commit)
              SQLite (version_manifests & chunks)
```

---

## 4. SQLite Metadata Schema & Migration Strategy

### 4.1 Schema Definition

```sql
-- 1. Track physical CAS chunk objects
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

-- 2. Associate immutable published versions with their file manifests
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

-- 3. Associate ordered chunks with each file manifest
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

### 4.2 Migration Strategy
- `init_schema()` executes the DDL using `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`.
- Because foreign keys reference existing tables (`workspaces`, `published_versions`), existing databases seamlessly gain the new tables without data loss or schema rewrites.
- Fresh databases initialize all tables in a single unified schema bootstrap.

### 4.3 Reference Counting Policy
- **Definition:** `cas_chunks.reference_count` tracks the **exact total number of active manifest-to-chunk references** (`COUNT(*)` in `version_manifest_chunks`).
- **Policy Invariant:**
  $$\forall h \in \text{cas\_chunks},\quad \text{cas\_chunks.reference\_count}[h] = \sum_{\text{vmc} \in \text{version\_manifest\_chunks}} \mathbb{I}(\text{vmc.chunk\_hash} == h)$$
- **Guarantees:**
  1. A chunk appearing multiple times across different version manifests has its reference count incremented once per manifest occurrence.
  2. If an insertion rolls back, the decrements exactly cancel the uncommitted increments.
  3. `CHECK(reference_count >= 0)` guarantees that reference counts can never become negative.
  4. The audit integrity query:
     ```sql
     SELECT c.chunk_hash, c.reference_count, COUNT(v.chunk_hash) 
     FROM cas_chunks c 
     LEFT JOIN version_manifest_chunks v ON c.chunk_hash = v.chunk_hash 
     GROUP BY c.chunk_hash 
     HAVING c.reference_count != COUNT(v.chunk_hash);
     ```
     strictly returns 0 rows at all times.

---

## 5. Workflow Details

### 5.1 Submission Acceptance Workflow (`accept_submission`)

1. **Operation Admission**: Acquire `OperationGuard op_guard(*this)`.
2. **Workspace Lock**: Look up `ws_id` and acquire `auto ws_lock = get_workspace_lock(ws_id)`.
3. **Validation**: Read `sub` under `db_mutex_`, verify status is `"pending"`, scan submission directory, verify Merkle root.
4. **Journal Intent**: Register `WorkspaceOperationRecord` with `state="PENDING"`, `intent_step="CAS_INGEST"`.
5. **CAS Ingestion (db_mutex_ NOT held)**:
   - For each file in the submission, scan and compute authoritative whole-file SHA-256.
   - Chunk file bytes with `FastCDCChunker`.
   - Insert chunks into `ObjectStore::put_object()`. If chunk already exists, it is deduplicated.
   - Construct `FileManifest` for the file.
6. **Staged Reconstruction (db_mutex_ NOT held)**:
   - Create staging baseline (`staging_base`) and staging working copy (`staging_work`) with sentinels.
   - Reconstruct files into `staging_base` and `staging_work` from CAS using `ObjectStore::reconstruct_file()`.
   - Verify whole-file SHA-256 on reconstructed files.
   - Scan staging directories to verify that the Merkle root matches `sub.merkle_root`.
7. **Promotion (Atomic Renames)**:
   - Update journal to `state="STAGED"`, `intent_step="BACKUP_DIRECTORIES"`.
   - Rename existing `baseline` -> `backup_base`, `working_copy` -> `backup_work`.
   - Update journal to `state="PROMOTING"`, `intent_step="PROMOTE_BASELINE"`.
   - Rename `staging_base` -> `baseline`, remove sentinel.
   - Update journal to `intent_step="PROMOTE_WORKING_COPY"`.
   - Rename `staging_work` -> `working_copy`, remove sentinel.
8. **Transactional Commit**:
   - Acquire `db_mutex_`.
   - `BEGIN IMMEDIATE;`
   - Update submission status to `'accepted'`.
   - Update journal record to `state="COMMITTED"`, `intent_step="CLEANUP"`.
   - `COMMIT;`
9. **Cleanup**:
   - Purge `backup_base` and `backup_work`.
   - Update journal to `state="COMMITTED"`, `intent_step="COMPLETED"`.

### 5.2 Version Publishing Workflow (`publish_version`)

1. **Operation Admission & Lock**: Acquire `OperationGuard` and `get_workspace_lock(actual_ws_id)`.
2. **Scan Working Copy**: Scan `working_copy`, verify completion, obtain file inventory and Merkle root.
3. **Journal Intent**: Register journal intent with `state="PENDING"`, `intent_step="CAS_INGEST"`.
4. **CAS Ingestion & Manifest Generation (db_mutex_ NOT held)**:
   - For each file in working copy:
     - Chunk via `FastCDCChunker`.
     - Insert/deduplicate chunks in `ObjectStore`.
     - Construct `FileManifest`.
     - Serialize manifest to compact binary `MCAS` bytes.
5. **Staging Snapshot & Baseline**:
   - Create `staging_ver` and `staging_base` with sentinels.
   - Copy working copy files to `staging_ver` and `staging_base`.
   - Verify Merkle roots match `manifest.merkle_root`.
   - Rename `staging_ver` -> `final_ver`.
   - Backup existing baseline -> `backup_base`.
   - Rename `staging_base` -> `base_dir`.
6. **Transactional Commit**:
   - Acquire `db_mutex_`.
   - `BEGIN IMMEDIATE;`
   - Insert row into `published_versions`.
   - Insert rows into `version_manifests` (storing `manifest_blob`).
   - Insert rows into `version_manifest_chunks`.
   - Update `cas_chunks` reference counts:
     ```sql
     INSERT INTO cas_chunks (chunk_hash, chunk_size, reference_count, created_at_ms, verified_at_ms, storage_state)
     VALUES (?, ?, 1, ?, ?, 'COMMITTED')
     ON CONFLICT(chunk_hash) DO UPDATE SET reference_count = reference_count + 1, verified_at_ms = ?;
     ```
   - Insert `client_updates` notifications for active clients.
   - Remove sentinel from `final_ver`.
   - Update journal record to `state="COMMITTED"`, `intent_step="CLEANUP"`.
   - `COMMIT;`
7. **Cleanup**:
   - Purge `backup_base`.
   - Update journal to `state="COMMITTED"`, `intent_step="COMPLETED"`.

---

## 6. Version Reconstruction API

A dedicated internal C++ method is introduced to `CollabStore`:

```cpp
bool reconstruct_version(const std::string& version_id,
                         const fs::path& destination_dir,
                         std::string& error_out);
```

### Execution Steps:
1. Acquire `OperationGuard`.
2. Acquire `db_mutex_` to query `version_manifests` for `version_id`.
   - If no manifests exist (legacy Phase 2 version), fallback to copying from `workspace_versions_dir / version_id` if present.
3. Release `db_mutex_`.
4. Create atomic temporary directory: `destination_dir.parent_path() / (".reconstruct_ver_" + op_id)`.
5. For each manifest:
   - Validate relative path (rejecting `..`, absolute paths, leading slashes, Windows drive letters).
   - Fetch chunks from `ObjectStore` and reconstruct the file via `ObjectStore::reconstruct_file()`.
   - Verify whole-file SHA-256 against `version_manifests.whole_file_sha256`.
6. Verify directory Merkle root against `published_versions.merkle_root`.
7. Atomically promote reconstructed directory to `destination_dir`.

---

## 7. Crash Recovery & Journal Invariants

The `workspace_operations` journal tracks operation progress through discrete states:

```
[PENDING] ----> [STAGED] ----> [PROMOTING] ----> [COMMITTED] ----> [COMPLETED]
    |               |               |
    v               v               v
(Rollback)     (Rollback)      (Rollback)
    |               |               |
    +---------------+---------------+-----> [FAILED] (ROLLED_BACK)
```

### Crash Recovery Invariant Matrix:

| Crash Boundary | On-Disk State | Journal State | Recovery Action | Guarantee |
|---|---|---|---|---|
| **A. During chunk ingestion** | Some chunks in CAS; staging dirs absent | `PENDING` / `CAS_INGEST` | Mark journal `FAILED`. CAS chunks remain as unreferenced blobs. | No partial files visible. Workspace untouched. |
| **B. Chunks written, before manifest persistence** | Chunks in CAS; DB has no manifests | `PENDING` / `STAGE_SNAPSHOT` | Mark journal `FAILED`. Staging dirs removed. | DB consistent. Workspace untouched. |
| **C. Manifest staged, before SQLite commit** | Snapshot staged; DB uncommitted | `PROMOTING` | Rollback uncommitted filesystem renames from `backup_*`. Mark `FAILED`. | DB rollback prevents uncommitted version from existing. |
| **D. During working-copy promotion** | Baseline promoted, work copy in backup | `PROMOTING` / `PROMOTE_BASELINE` | Restore `baseline` and `working_copy` from `backup_base` and `backup_work`. | Working copy restored to previous state. |
| **E. During version snapshot promotion** | Snapshot renamed, baseline unpromoted | `PROMOTING` / `PROMOTE_BASELINE` | Purge uncommitted version snapshot using sentinel. Restore baseline. | No partial version exposed. |
| **F. After DB commit, before backup cleanup** | DB committed; backup dirs present | `COMMITTED` / `CLEANUP` | Replay forward: remove verified backup dirs. Mark `COMPLETED`. | Committed state finalized safely. |
| **G. Object inserted, before ref metadata committed** | Chunks in CAS; `cas_chunks` has no ref | `PENDING` | Journal marked `FAILED`. Chunks remain unreferenced in CAS. | Zero reference count corruption. |
| **H. During rollback** | Interrupted rollback on disk | `FAILED` / `ROLLED_BACK` | Re-run recovery idempotently using sentinels. | Deterministic convergence. |

---

## 8. Backward Compatibility Strategy

1. **Legacy Published Versions**:
   Versions published under Phase 2 do not contain entries in `version_manifests`.
   - `reconstruct_version()` inspects `version_manifests`. If empty, it serves content directly from the existing `workspace_versions_dir(ws_id) / version_id` directory.
   - Legacy versions are **not** blindly modified or rewritten; they retain their original filesystem snapshot.
2. **Client Updates**:
   `apply_update()` checks if the version directory exists on the host. If missing, it uses `reconstruct_version()` to recreate it dynamically from CAS manifests before applying updates to the client folder.
3. **Workspace File Operations**:
   Host working copy editing (`list_working_copy_files`, `read_working_copy_file_content`, `write_working_copy_file_content`, `delete_working_copy_file`, `compute_working_copy_diff`) operates on standard OS files in `working_copy/`, completely unaffected by underlying CAS storage.

---

## 9. Identified Risks & Mitigations

| Risk | Impact | Architectural Mitigation |
|---|---|---|
| **Lock Contention during Chunking** | Server unresponsive during large file ingestion | FastCDC chunking and CAS writes occur strictly under workspace lock with `db_mutex_` released. Other workspaces operate concurrently. |
| **Hard Link Corruption** | Client/Host edits mutate immutable CAS objects | Working-copy checkout is strictly performed via independent byte copying through staging files. hard link count asserted to be 1. |
| **Reference Count Desynchronization** | Chunk reference counts drift from manifest counts | Reference increments are committed in the same SQLite transaction as version manifests. FK constraints cascade cleanly. |
| **Partial Manifest Exposure** | Corrupt manifests crash deserializer | Manifests are serialized to memory and validated before writing to DB. Deserialization validates magic, version, and length caps. |
| **Path Traversal via Manifest Paths** | Malicious paths overwrite system files | Path verification rejects all traversal sequences (`..`), absolute paths, and invalid path separators before reconstruction. |

---

## 10. Implementation Sequence

1. **Storage Infrastructure**:
   Add `ObjectStore` instance to `CollabStore` initialized at `base_storage_dir_ / "cas"`.
2. **Schema Migration**:
   Update `init_schema()` with `cas_chunks`, `version_manifests`, and `version_manifest_chunks`.
3. **CAS Ingestion in `accept_submission`**:
   Implement FastCDC chunking, CAS insertion, and staged reconstruction.
4. **CAS Ingestion & Manifest Storage in `publish_version`**:
   Implement manifest generation, binary serialization, and transactional reference counting.
5. **Version Reconstruction API**:
   Implement `reconstruct_version()` with full cryptographic verification and legacy fallback.
6. **Comprehensive Test Suite**:
   Implement tests for CAS submissions, version publishing, reference counting consistency, crash recovery, and legacy compatibility.
7. **Verification & Audit**:
   Build cleanly and run the complete test suite (433+ tests), collaboration E2E, and smoke tests.

