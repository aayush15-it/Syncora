# Syncora Milestone 3.4 — Architecture Specification & Implementation Plan
## Distributed CAS Synchronization: Delta Network Protocol, Chunk Negotiation & Peer Integration

**Author**: Senior C++ Storage & Distributed Systems Architecture Team  
**Date**: November 4, 2026  
**Document Status**: Frozen Architecture Specification & Implementation Plan  
**Target Release**: Milestone 3.4 (`v0.3.0-m3.4`)  
**Base Commit**: `e1ab1b0` (Release Tag `v0.3.0-m3.3`)  
**Stack**: C++17, SQLite (WAL mode), OpenSSL (TLS 1.2+ & SHA-256), Win32 / POSIX Sockets  

---

## 1. Executive Summary & Problem Statement

### 1.1 The Problem: Whole-File Transfer Bottleneck
Milestones 3.1 through 3.3 established a high-performance Content-Addressed Storage (CAS) engine in Syncora:
- **M3.1**: FastCDC content-defined chunking (4 KB min, 8 KB avg, 16 KB max), SHA-256 content addressing, and file reconstruction.
- **M3.2**: Integration with `CollabStore`, version manifests, chunk reference counting, and atomic version publication.
- **M3.3**: GC sweeping engine, reference compaction, active temporary-file ownership, and OS-level multi-process coordination (`InterprocessCasBarrier`).

However, Syncora's bilateral network synchronization subsystem (`mc::peer::PeerService`, `mc::peer::PeerSession`) still operates in **whole-file transfer mode**:
- When a 100 MB file undergoes a 2 MB modification, `PeerService` transmits all 100 MB across the TLS wire using sequential `MessageType::FileData` frames.
- This creates severe network I/O overhead, saturates low-bandwidth peer connections, and completely ignores the local CAS deduplication engine.

```
Current Whole-File Transfer (M3.3):
Peer A (100 MB file, 2 MB edit) ------------------ 100 MB Wire Stream ------------------> Peer B
                                                                                        (100 MB wasted I/O)

Target Distributed CAS Delta Transfer (M3.4):
Peer A ---------------- File Manifest (hashes H1..H1600) ----------------> Peer B
Peer A <--------------- Chunk Request (lacks only H32..H64) -------------- Peer B
Peer A ---------------- 2 MB Delta Chunks (H32..H64) --------------------> Peer B
                                                                                        (98 MB bandwidth saved!)
```

### 1.2 Milestone 3.4 Objectives
Milestone 3.4 bridges the Content-Addressed Storage engine to the bilateral peer network layer:
1. **CAS-Aware Wire Protocol**: Backward-compatible extensions to `mc::peer::MessageType` enabling chunk manifest exchange and missing-chunk negotiation.
2. **Chunk Set Difference ($O(\Delta)$ Wire Transfer)**: The receiver identifies missing chunks and requests *only* what it does not already possess in its local CAS object store.
3. **Chunk Verification & Ingestion**: Ingests missing chunks into the local CAS store, cryptographically verifying each chunk's SHA-256 hash before storage.
4. **Local File Reconstruction**: Reconstructs the target file using existing local chunks and newly ingested delta chunks via `ObjectStore::reconstruct_file()`.
5. **Atomic Transactional Commit**: Leverages the existing Phase 2/3 `PeerTransactionCoordinator` two-phase staging and baseline advance mechanisms.
6. **Concurrent GC Safety**: Maintains `InterprocessCasBarrier` shared guards across the entire receiver pipeline (negotiation $\to$ transfer $\to$ reconstruction $\to$ promotion) and sender serving paths to prevent concurrent GC sweeps from removing in-flight chunks.
7. **Zero-Trust Security & Anti-Probing**: Enforces strict relative path validation, manifest bounds checking, and sender-side chunk request authorization to prevent arbitrary CAS object harvesting.

---

## 2. Architecture & Gap Analysis (Current vs Target State)

### 2.1 Component Comparison Matrix

| Subsystem Component | Current Implementation (M3.3) | Target Milestone 3.4 Implementation |
| :--- | :--- | :--- |
| **Peer Frame Protocol** (`peer_protocol.hpp`) | 9 frame types (`Hello`, `ManifestRequest`, `Manifest`, `FileRequest`, `FileData`, `FileEnd`, `Approval`, `SyncResult`, `Error`). | Add 4 backward-compatible frame types: `ChunkManifestRequest` (10), `ChunkManifest` (11), `ChunkRequest` (12), `ChunkData` (13). |
| **Manifest Exchange** (`peer_sync.hpp`) | Directory-level `FileManifest` exchanging file paths, sizes, and whole-file SHA-256. | Two-stage manifest: (1) Directory-level manifest establishes sync plan; (2) Per-file `mc::cas::FileManifest` carries FastCDC chunk descriptors. |
| **Missing Content Resolution** | Receiver requests entire file by relative path (`FileRequest`). | Receiver computes hash set difference against local `ObjectStore::has_object()` and requests only missing chunk hashes. |
| **Wire Data Transfer** | Sequential file byte stream chunks (64 KB buffers, `FileData`). | Content-addressed chunk transfer (`ChunkData`), keyed by SHA-256 chunk hash (max 16 KB payload per chunk). |
| **File Assembly on Receiver** | Bytes appended linearly to `StagingFile`. | Chunks stored into local CAS; file reconstructed via `ObjectStore::reconstruct_file()` from local + newly received chunks. |
| **Whole-File Validation** | Receiver hashes linear staging file on `FileEnd`. | Dual validation: (1) Per-chunk SHA-256 verified upon receipt; (2) Reconstructed whole-file SHA-256 verified against manifest. |
| **GC & Multi-Process Safety** | In-process `cas_barrier_` + OS-level `.cas_barrier.lock`. Peer transfer does not hold CAS barrier. | Receiver holds `CasSharedBarrierGuard` from negotiation through promotion; sender holds barrier during chunk reads; GC cannot sweep active transfer chunks. |
| **Request Authorization** | Receiver requests any file path in workspace. | Senders validate `ChunkRequest` hashes against `session_advertised_hashes`; arbitrary CAS object probing is rejected. |
| **Protocol Compatibility** | Rejects unknown frame types. | Capability negotiation in `Hello`: if peer does not advertise `cas_delta_v1`, automatically fall back to legacy whole-file sync. |

---

## 3. The 6 Core Workstreams

```
+---------------------------------------------------------------------------------------------------------+
|                                    Workstream Execution Pipeline                                        |
|                                                                                                         |
|   +-----------------------+       +------------------------+       +--------------------------------+   |
|   | 1. Manifest Exchange  | ----> | 2. Chunk Negotiation   | ----> | 3. Delta Transfer              |   |
|   | Exchange & validate   |       | Query local CAS;       |       | Stream missing chunks          |   |
|   | FastCDC chunk lists   |       | find missing set       |       | over TLS wire                  |   |
|   +-----------------------+       +------------------------+       +--------------------------------+   |
|                                                                                    |                    |
|   +-----------------------+       +------------------------+                       |                    |
|   | 6. Atomic Commit      | <---- | 5. File Reconstruction | <---- +--------------------------------+   |
|   | Two-phase journal &   |       | Staged streaming       |       | 4. Chunk Verification          |   |
|   | baseline advance      |       | assembly & verification|       | Validate SHA-256 & ingest      |   |
|   +-----------------------+       +------------------------+       +--------------------------------+   |
+---------------------------------------------------------------------------------------------------------+
```

### Workstream 1: Manifest Exchange & Validation
- **Sender Responsibilities**:
  - When a file transfer (`AddLocal`, `UpdateLocal`, `AddRemote`, `UpdateRemote`) is planned, the sender loads or computes the `mc::cas::FileManifest`.
  - Encodes the manifest using `mc::cas::ManifestSerializer::serialize_binary()`.
  - Records all chunk hashes in `session_advertised_hashes` (for request authorization).
  - Transmits a `MessageType::ChunkManifest` frame containing the relative path and serialized chunk manifest.
- **Receiver Responsibilities & FastCDC Bounds Validation**:
  - Validates `relative_path`: rejects absolute paths, `..` traversal, null bytes, backslashes (normalized to `/`), and illegal characters.
  - Validates manifest structure according to FastCDC parameters (`kDefaultFastCDCConfig`):
    - Non-final chunks: `size >= 4096` and `size <= 16384` bytes.
    - Final chunk: `size >= 1` and `size <= 16384` bytes (for non-empty files).
    - Empty file: `chunks.empty()` and `total_size == 0`.
    - Offsets must be strictly contiguous: `chunk[0].offset == 0` and `chunk[i].offset == chunk[i-1].offset + chunk[i-1].size`.
    - Sum of chunk sizes must exactly equal `total_size`.
  - Rejects malformed manifests with `MessageType::Error("malformed chunk manifest")`.

### Workstream 2: Chunk Negotiation & Preconditions
- **Precondition Clarification (Local CAS Presence vs Working Copy)**:
  - Having a file present in the working copy directory does **not** guarantee its chunks exist in the CAS object store (`cas/objects/`).
  - Chunks exist in CAS only if they were previously ingested (via `publish_version`, `accept_submission`, prior delta sync, or explicit CAS scan).
  - Therefore, chunk negotiation queries the **local CAS object store directly** (`ObjectStore::has_object()`), not the filesystem directory.
- **Algorithm**:
  Given received `FileManifest` with chunks $C = \{h_1, h_2, \dots, h_n\}$:
  ```cpp
  // Receiver acquires shared barrier BEFORE querying local CAS
  mc::cas::CasSharedBarrierGuard barrier_guard(cas_barrier_);

  std::vector<std::string> missing_chunks;
  for (const auto& chunk : manifest.chunks()) {
      if (!object_store.has_object(chunk.hash)) {
          missing_chunks.push_back(chunk.hash);
      }
  }
  ```
- **Negotiation Frame**:
  - Receiver sends `MessageType::ChunkRequest` containing:
    - Relative path (context binding).
    - Missing chunk count (uint32).
    - Array of 64-hex lowercase chunk hashes requested.
  - **Zero-Chunk Transfer**: If `missing_chunks.empty()`, the receiver already possesses 100% of the chunks in its local CAS store (e.g. file rename, revert, or duplicate content). Zero chunk bytes are transferred over the wire!

### Workstream 3: Delta Transfer & Remote Request Authorization
- **Remote Request Authorization (Anti-Probing Defense)**:
  - Senders maintain `session_advertised_hashes` (hashes of all chunks present in manifests sent during this session).
  - Upon receiving `ChunkRequest`:
    1. Validates hash syntax (exactly 64 lowercase hex characters).
    2. Validates that every requested hash exists in `session_advertised_hashes`.
    3. If any hash was not advertised: sender rejects the request immediately with `MessageType::Error("unauthorized chunk request: hash not in session manifest")` and terminates the transfer. This prevents malicious peers from probing the sender's CAS catalog for arbitrary objects.
- **Request & Frame Bounds**:
  - Maximum missing chunk hashes in a single `ChunkRequest`: 4096 hashes (representing up to 64 MB of data per request, payload size $\approx 262\text{ KB}$, well within the 1 MB frame bound). Requests exceeding 4096 hashes are rejected as DoS attempts.
- **Streaming Transfer**:
  - Sender reads chunks one by one from local `ObjectStore::get_object(hash, data)` under `CasSharedBarrierGuard`.
  - Transmits individual `MessageType::ChunkData` frames:
    - Header: 64-character chunk hash.
    - Payload: Raw chunk bytes ($\le 16\text{ KB}$).
  - Memory consumption is strictly bounded by single chunk size ($\le 16\text{ KB}$), keeping peak RAM $< 10\text{ MB}$.

### Workstream 4: Chunk Verification & Ingestion
- **Cryptographic Invariant**: Never trust remote input.
  Upon receiving `ChunkData` with reported hash $H_{claimed}$ and payload $B$:
  1. Verify length of $B$ matches expected size from the manifest ($\le 16\text{ KB}$).
  2. Compute cryptographic digest: $H_{actual} = \text{SHA-256}(B)$.
  3. Verify $H_{actual} == H_{claimed}$. If mismatched, drop the connection and send `MessageType::Error("corrupted chunk payload")`.
  4. Ingest chunk into local store via `object_store.put_object(B.data(), B.size(), H_{actual})`.
  5. The object is now an immutable, verified CAS entity in `cas/objects/xx/hash`.

### Workstream 5: Local File Reconstruction
- **Streaming Reconstruction**:
  - Receiver invokes `object_store.reconstruct_file(manifest, staging_path, err, true)`.
  - `reconstruct_file()` reads chunk by chunk from local CAS into the staging file (`.staged_<hash>.tmp`).
  - Verifies whole-file SHA-256 digest on the fly against `manifest.file_sha256()`.
  - Verifies reconstructed file size matches `manifest.total_size()`.
  - Guarantees working files are never hardlinked directly to CAS objects (mutation safety).

### Workstream 6: Atomic Integration & Journaling
- **Commit Safety & Baseline Advance**:
  - Staged file is passed to `PeerTransactionCoordinator`.
  - Coordinator verifies file hash matches `expected_new_hash` in `peer_operations` journal.
  - Creates backup recovery artifact for destination file.
  - Executes verified filesystem replacement via atomic rename / transaction commit.
  - Commits updated manifest to `PeerBaselineStore`.
  - Releases recovery material only after bilateral terminal state.
  - Releases `CasSharedBarrierGuard`.

---

## 4. Wire Protocol Evolution & Message Types

### 4.1 Extended MessageType Definition (`include/merklechain/peer/peer_protocol.hpp`)
```cpp
enum class MessageType : std::uint16_t {
    Hello = 1,
    ManifestRequest = 2,
    Manifest = 3,
    FileRequest = 4,      // Legacy whole-file request
    FileData = 5,         // Legacy whole-file stream data
    FileEnd = 6,          // Legacy whole-file termination
    Approval = 7,
    SyncResult = 8,
    Error = 9,
    
    // Milestone 3.4 CAS Delta Extensions
    ChunkManifestRequest = 10, // Request chunk manifest for relative path
    ChunkManifest = 11,        // Binary serialized mc::cas::FileManifest
    ChunkRequest = 12,         // List of missing chunk hashes requested by receiver
    ChunkData = 13             // Content-addressed chunk payload
};
```

### 4.2 Standard Syncora Frame Header (12 Bytes)
All frames use the standard 12-byte big-endian header:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic 'M' 'C'           |       Protocol '0' '1'        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      MessageType (uint16)     |         Flags (uint16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (uint32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Data...                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- Magic: `0x4D433031` ("MC01").
- `kMaximumFramePayload`: 1,048,576 bytes (1 MB).

### 4.3 Capability Advertisement in `Hello` Frame
In `MessageType::Hello`, peers exchange capability strings:
```
identity=peer_alpha;version=1.0;caps=cas_delta_v1,whole_file
```
- **Parsing Rules**: Semicolon-delimited key-value tokens. Unknown tokens are silently ignored (forward compatibility).
- **Capability Flag**: `caps` contains comma-separated features. The presence of `cas_delta_v1` activates CAS delta synchronization.
- **Backward Compatibility Guarantee**:
  - If remote peer does *not* include `cas_delta_v1` in `Hello`, the session automatically configures itself for legacy whole-file transfer (`FileRequest` / `FileData` / `FileEnd`).
  - Existing Phase 2 whole-file test suites continue to pass without modification.

### 4.4 Binary Payload Specifications for CAS Messages

#### `ChunkManifestRequest` Frame Payload (Type 10)
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Relative Path Length              | uint16_t (big-endian)                 |
| Relative Path                     | UTF-8 string (normalized '/')         |
+-----------------------------------+---------------------------------------+
```

#### `ChunkManifest` Frame Payload (Type 11)
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Relative Path Length              | uint16_t (big-endian)                 |
| Relative Path                     | UTF-8 string (normalized '/')         |
| Serialized FileManifest           | Binary payload from ManifestSerializer|
|                                   | (Magic 'MCAS', version, chunk table)  |
+-----------------------------------+---------------------------------------+
```

#### `ChunkRequest` Frame Payload (Type 12)
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Relative Path Length              | uint16_t (big-endian)                 |
| Relative Path                     | UTF-8 string                          |
| Missing Chunk Count ($N$)         | uint32_t (big-endian, max 4096)       |
| Repeated Chunk Hashes             | $N \times 64$ ASCII hex bytes         |
+-----------------------------------+---------------------------------------+
```

#### `ChunkData` Frame Payload (Type 13)
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Chunk Hash                        | 64 ASCII hex bytes                    |
| Chunk Payload                     | Raw chunk bytes ($1 \le \text{size} \le 16384$) |
+-----------------------------------+---------------------------------------+
```

---

## 5. Security, Path Traversal & Cryptographic Invariants

1. **Zero-Trust Input Validation**:
   - Every `relative_path` in manifests and requests is validated via `validate_relative_path()`:
     - Rejects paths starting with `/` or `\\`.
     - Rejects paths containing `../` or `..\\`.
     - Rejects drive letters (e.g. `C:`).
     - Rejects non-printable or null characters.
2. **Cryptographic Chunk Identification**:
   - Every chunk is identified solely by its SHA-256 hash.
   - The receiver recalculates SHA-256 before writing to CAS. Tampered chunks are dropped immediately.
3. **Whole-File Digest Enforcement**:
   - The reconstructed file's SHA-256 must match `manifest.file_sha256()`.
   - The reconstructed file's size must match `manifest.total_size()`.
   - If either fails, the staging file is unlinked, the operation is flagged `Failed`, and the session halts safely.
4. **Remote Chunk Request Authorization (Anti-Probing)**:
   - Senders maintain `session_advertised_hashes`.
   - Any `ChunkRequest` referencing a hash outside this set is rejected with `MessageType::Error`.
5. **Denial-of-Service (DoS) Protection**:
   - Maximum frame payload strictly enforced at $1\text{ MB}$ (`kMaximumFramePayload`).
   - Maximum missing chunk count per `ChunkRequest` bounded at 4096 hashes.
   - Maximum chunks per file bounded at 50,000 chunks (supporting files up to $\sim 800\text{ MB}$).

---

## 6. Concurrency, Lock Hierarchy & CAS Barrier Lifetime

### 6.1 Total Lock Hierarchy Order
To prevent deadlocks across multi-process and multi-threaded operations, locks must strictly be acquired in this global order:
```
OperationGuard (Lifecycle) -> InterprocessCasBarrier (Shared) -> Workspace Mutex -> DB Mutex
```

### 6.2 Receiver Pipeline CAS Barrier Lifetime (Mandatory Issue A Resolution)
Holding a CAS barrier only during physical chunk writing is insufficient: if the receiver identifies that chunks $H_1$ and $H_2$ exist locally, a concurrent GC sweep in another process could delete those chunks before the receiver reconstructs the file.

**Enforced Receiver Lifetime Invariant**:
1. The receiver acquires `CasSharedBarrierGuard` **before** querying `ObjectStore::has_object()` during chunk negotiation.
2. The guard is held **continuously** through:
   - Missing chunk set difference calculation.
   - Delta chunk streaming and ingestion (`put_object()`).
   - File reconstruction (`reconstruct_file()`).
   - Atomic transactional promotion and baseline advance (`commit_operations()`).
3. The guard is released **only after** the destination file is atomically promoted and committed to the database.
4. **Result**: Any concurrent GC sweep (`InterprocessCasBarrier` exclusive lock) is blocked from sweeping *any* CAS chunk until the entire transfer and reconstruction pipeline completes.

```
Receiver Execution Timeline:
[Acquire CasSharedBarrierGuard]
   |---> 1. Query has_object() & compute missing set
   |---> 2. Receive missing ChunkData & ingest via put_object()
   |---> 3. Reconstruct file to staging path
   |---> 4. Atomic rename & commit baseline in SQLite
[Release CasSharedBarrierGuard]
```

### 6.3 Sender Pipeline CAS Barrier Lifetime
1. Sender acquires `CasSharedBarrierGuard` when generating the chunk manifest.
2. Sender retains `CasSharedBarrierGuard` while reading chunk data from `ObjectStore::get_object()` to transmit `ChunkData` frames.
3. GC cannot sweep chunks while the sender is actively reading and serving them.

---

## 7. Failure Modes & Transfer Recovery (Safe Restart Strategy)

Milestone 3.4 adopts **Strategy 1: Safe Restart** for handling interruptions, crashes, and network disconnections:

```
+-------------------------------------------------------------------------------+
|                       Safe Restart Recovery Pipeline                          |
|                                                                               |
|   Network Drop / Crash Mid-Transfer                                           |
|          |                                                                    |
|          v                                                                    |
|   1. Clean Incomplete Staging Artifacts (.staged_*.tmp)                       |
|   2. Verified Chunks Remain in CAS Store (put_object is immutable)            |
|   3. RAII / Process Exit releases CasSharedBarrierGuard                       |
|          |                                                                    |
|          v Reconnect / Startup Recovery                                       |
|   4. Peer Re-Exchanges Manifests                                              |
|   5. Receiver Queries Local CAS: Previously received chunks ARE present!      |
|   6. Receiver Requests ONLY remaining unreceived chunks                       |
|   7. Sync completes successfully (Natural Resume, Zero Duplication)           |
+-------------------------------------------------------------------------------+
```

### 7.1 Invariants of Safe Restart:
1. **Uncommitted Staging Cleanup**: Any incomplete `.staged_*.tmp` file is unlinked immediately upon session disconnect or during startup recovery (`CollabStore::recover_startup()`).
2. **Immutable Chunk Preservation**: Chunks received and cryptographically verified prior to the interruption remain stored in `cas/objects/xx/hash`. Because CAS objects are immutable and content-addressed, their presence in CAS does not corrupt any catalog or baseline.
3. **Natural Deduplicated Resume**: On reconnection, the peers re-negotiate. The receiver's `has_object()` check detects the previously ingested chunks as present. The receiver requests *only* the remaining missing chunks, providing seamless resume without complex checkpoint state machines.
4. **Process Crash Idempotency**: If a worker process terminates abruptly (`std::_Exit(94)`), OS file locks are released automatically, startup recovery unlinks dangling temporary files, and working copy files remain completely intact.

---

## 8. Adversarial Test Matrix (21 Mandatory Scenarios)

The test suite will implement 21 deterministic adversarial test scenarios in `tests/peer_sync_cas_delta_tests.cpp`:

| Scenario ID | Test Name | Simulated Condition | Expected Invariant & Behavior |
| :--- | :--- | :--- | :--- |
| **CAS-NET-01** | Identical Files Sync (Pre-Populated CAS) | Both peers possess identical files with chunks already in local CAS. | `missing_chunks` is empty; 0 `ChunkData` frames transferred; 0 wire payload bytes; instant agreement. |
| **CAS-NET-02** | Partial Chunk Reuse (80% Baseline) | 80% of chunks already exist in receiver's CAS from prior versions. | Exactly 20% missing chunks requested; 80% chunks fetched from local CAS; whole-file SHA-256 verified. |
| **CAS-NET-03** | Middle Modification | 1 MB file modified in 64 KB middle region. | Non-modified chunks before and after edit reused; only affected chunks transferred ($> 80\%$ bandwidth reduction). |
| **CAS-NET-04** | File Rename / Move | File renamed with unchanged contents; chunks exist in receiver CAS. | Manifest path updated; 0 chunks transferred; file reconstructed at new path from local CAS. |
| **CAS-NET-05** | Corrupted Chunk Payload | Single bit flipped in transit in `ChunkData` payload. | SHA-256 mismatch detected; chunk rejected; error frame returned; staging unlinked. |
| **CAS-NET-06** | Mismatched Manifest Root | Sender sends manifest where `file_sha256` does not match chunk chain. | Reconstruction whole-file hash check fails; transaction aborted cleanly; destination untouched. |
| **CAS-NET-07** | Network Interruption & Safe Restart | Connection severed after 50% of missing chunks transferred. | Partial staging unlinked; verified chunks preserved; re-sync requests only remaining 50% chunks. |
| **CAS-NET-08** | Duplicate Chunk Delivery | Redundant or identical chunk hash delivered multiple times. | Handled idempotently via `ObjectStore::put_object()`; zero duplicate storage; refcounts intact. |
| **CAS-NET-09** | Concurrent Bilateral Transfers | Multiple bilateral sessions transferring concurrently across workspaces. | Workspace-isolated journals prevent crosstalk; zero catalog corruption; independent locks. |
| **CAS-NET-10** | Concurrent GC during Transfer | GC runs while receiver is ingesting chunks and reconstructing. | Receiver holds `CasSharedBarrierGuard` from negotiation to promotion; GC blocked until promotion finishes. |
| **CAS-NET-11** | Receiver Crash Mid-Transfer | Receiver process terminated with `std::_Exit(94)` during ingestion. | Startup recovery cleans orphan staging; working copy completely untouched and uncorrupted. |
| **CAS-NET-12** | Path Traversal Injection | Manifest contains `../../etc/passwd`, `C:\`, or null bytes. | `validate_relative_path()` rejects entry immediately; session terminated with error. |
| **CAS-NET-13** | Large File Streaming | 100 MB file transfer under tight memory profile. | Bounded 16 KB chunk streaming; peak RAM remains $< 10\text{ MB}$. |
| **CAS-NET-14** | Legacy Peer Compatibility | Remote peer `Hello` lacks `cas_delta_v1` capability flag. | Gracefully falls back to whole-file `FileRequest`/`FileData` streaming; sync succeeds. |
| **CAS-NET-15** | Initial Full Sync on Empty CAS | Receiver CAS store is completely empty (`has_object` returns false for all chunks). | Receiver requests 100% of chunks; all chunks transferred, verified, ingested into CAS, and reconstructed. |
| **CAS-NET-16** | Remote Chunk Request Authorization | Peer requests chunk hash not advertised in session's manifests. | Sender checks `session_advertised_hashes`; rejects with `MessageType::Error("unauthorized chunk request")`. |
| **CAS-NET-17** | Malformed Chunk Manifest Validation | Manifest with chunk $> 16\text{ KB}$, non-final chunk $< 4\text{ KB}$, or non-contiguous offsets. | Manifest parser rejects frame as malformed; transfer aborted safely without writing to disk. |
| **CAS-NET-18** | Sender Interprocess GC Safety | Sender reading chunks while concurrent GC attempts sweep. | Sender holds `CasSharedBarrierGuard` during chunk read; GC cannot sweep chunks being streamed. |
| **CAS-NET-19** | Request Flooding & Frame Limit Bounds | Remote peer sends `ChunkRequest` with $> 4096$ hashes or payload $> 1\text{ MB}$. | Sender rejects request immediately as protocol violation / DoS attempt. |
| **CAS-NET-20** | Repeated Crash & Safe Restart Recovery | Receiver crashes on chunk 10, restarts, crashes on chunk 20, restarts. | Each restart recovers cleanly; previously verified chunks retained; final run completes successfully. |
| **CAS-NET-21** | Zero-Byte / Empty File CAS Sync | File with 0 bytes total size, 0 chunks, and empty manifest. | Handled cleanly; zero chunk requests generated; empty file created and staged atomically. |

---

## 9. Performance Benchmark Plan

To validate real-world bandwidth savings and CPU efficiency, a dedicated benchmark executable `benchmarks/cas_network_benchmark.cpp` will be implemented:

### 9.1 Benchmark Datasets:
1. **Dataset A (Initial Full Sync)**: 50 MB mixed directory (source code, text, binary assets) with empty receiver CAS.
2. **Dataset B (Small In-Place Edit)**: 50 MB directory with a 10-line edit inside a 5 MB file.
3. **Dataset C (Head Insertion)**: 10 MB file with 500 bytes inserted at byte offset 0 (testing FastCDC boundary-shifting resilience).
4. **Dataset D (Many Small Files)**: 500 files of 4 KB each with 5 files modified.

### 9.2 Metrics Recorded:
- **Actual Wire Payload Bytes** (total TCP/TLS socket bytes transmitted, including headers and framing).
- **Bandwidth Reduction Ratio**:
  $$\text{Reduction} = \left(1 - \frac{\text{CAS Delta Wire Bytes}}{\text{Whole File Wire Bytes}}\right) \times 100\%$$
- **Transfer Duration** (milliseconds).
- **Peak RAM Consumption** (RSS in megabytes).
- **Reconstruction Duration** (milliseconds).

### 9.3 Realistic Success Targets:
- **Dataset B & Dataset C**: Demonstrating $> 80\%$ bandwidth reduction compared to legacy whole-file transfer (typically $> 95\%$ on Dataset B and $> 85\%$ on Dataset C).
- **Dataset A (Initial Full Sync)**: Expected $\sim 0\%$ bandwidth reduction (slight framing overhead), confirming baseline overhead remains $< 2\%$.
- **Peak RAM**: Remains $< 15\text{ MB}$ across all datasets during streaming transfer and reconstruction.

---

## 10. Implementation Roadmap & Execution Stages

```
Phase 3 Milestone 3.4 Execution Stages:
1. [Stage 1] Protocol Wire Extensions:
   - Add ChunkManifestRequest (10), ChunkManifest (11), ChunkRequest (12), ChunkData (13) to peer_protocol.hpp/cpp.
   - Add binary framing serialization/deserialization helpers and frame bound enforcement.
2. [Stage 2] Chunker & Manifest Peer Helpers:
   - Implement peer manifest conversion helpers, FastCDC parameter validation, and missing-chunk resolution.
   - Implement session_advertised_hashes authorization tracker.
3. [Stage 3] PeerService CAS Delta Engine:
   - Integrate capability negotiation into Hello frame exchange.
   - Integrate chunk negotiation, streaming, and SHA-256 verification into peer_service.cpp.
   - Wire CasSharedBarrierGuard across the receiver pipeline (negotiation -> promotion).
4. [Stage 4] Atomic Reconstruction & Staging:
   - Connect ObjectStore::reconstruct_file() to PeerTransactionCoordinator staging pipeline.
   - Implement Safe Restart recovery and uncommitted staging cleanup.
5. [Stage 5] Adversarial Testing (CAS-NET-01 through CAS-NET-21):
   - Implement all 21 deterministic adversarial test scenarios in tests/peer_sync_cas_delta_tests.cpp.
6. [Stage 6] Benchmarking:
   - Implement and execute benchmarks/cas_network_benchmark.cpp across Datasets A-D.
7. [Stage 7] Independent Audit & Release:
   - Formal M3.4 audit report and release freeze at v0.3.0-m3.4.
```

---

## 11. Implementation Gate & Authorization Criteria

This document represents the frozen architecture specification for Milestone 3.4.

### Mandatory Gate Invariants:
1. **Preservation of Existing Releases**: Release tags `v0.2.0-phase2`, `v0.3.0-m3.2`, `v0.3.2-cas-integration`, and `v0.3.0-m3.3` remain completely frozen and unmodified.
2. **Implementation Gate**: No production C++ or test code shall be modified until this revised specification has been reviewed and committed.
3. **Commit SHA Verification**: The specification commit SHA must be reported and verified against a clean working tree.
