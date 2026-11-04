# Syncora Milestone 3.4 — Architecture Specification & Implementation Plan
## Distributed CAS Synchronization: Delta Network Protocol, Chunk Negotiation & Peer Integration

**Author**: Senior C++ Storage & Distributed Systems Architecture Team  
**Date**: November 4, 2026  
**Document Status**: Architecture Specification & Implementation Plan  
**Target Release**: Milestone 3.4 (`v0.3.0-m3.4`)  
**Base Commit**: `e1ab1b0` (Release Tag `v0.3.0-m3.3`)  
**Stack**: C++17, SQLite (WAL mode), OpenSSL (TLS 1.2+ & SHA-256), Win32 / POSIX Sockets

---

## 1. Executive Summary & Problem Statement

### The Problem: Whole-File Transfer Bottleneck
Milestones 3.1 through 3.3 established a high-performance Content-Addressed Storage (CAS) engine with FastCDC chunking, immutable object storage, reference counting, multi-process coordination (`InterprocessCasBarrier`), and autonomous crash recovery.

However, the existing bilateral network synchronization subsystem (`mc::peer::PeerService`, `mc::peer::PeerSession`) still transfers **entire files sequentially**:
- If a 100 MB file has only 2 MB modified in the middle, `PeerService` streams all 100 MB across the TLS wire via sequential `MessageType::FileData` frames.
- This creates excessive network I/O, saturates low-bandwidth peer connections, and completely fails to leverage the local CAS deduplication engine.

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

### Milestone 3.4 Objective
Milestone 3.4 connects the Content-Addressed Storage engine to the bilateral peer network layer. It introduces:
1. **CAS-Aware Wire Protocol**: Extensions to `mc::peer::MessageType` allowing manifest exchange and chunk-level negotiation.
2. **Chunk Set Difference ($O(\Delta)$ Wire Transfer)**: The receiver identifies missing chunks and requests *only* what it does not already possess in its local CAS root.
3. **Chunk Verification & Ingestion**: Ingests missing chunks into local CAS, verifying hash and size before promotion.
4. **Local File Reconstruction**: Reconstructs the target working file using existing local chunks and newly ingested delta chunks through `ObjectStore::reconstruct_file()`.
5. **Atomic Transactional Commit**: Uses the existing Phase 2/3 `PeerTransactionCoordinator` staging and baseline advance mechanisms.
6. **Concurrent GC Safety**: Employs `InterprocessCasBarrier` shared guards to ensure active network transfers cannot have their constituent chunks swept by concurrent GC.

---

## 2. Architecture & Gap Analysis (Current vs Target State)

### Component Comparison Matrix

| Subsystem Component | Current Implementation (M3.3) | Target Milestone 3.4 Implementation |
| :--- | :--- | :--- |
| **Peer Frame Protocol** (`peer_protocol.hpp`) | 9 frame types (`Hello`, `ManifestRequest`, `Manifest`, `FileRequest`, `FileData`, `FileEnd`, `Approval`, `SyncResult`, `Error`). | Add 4 backward-compatible frame types: `ChunkManifestRequest` (10), `ChunkManifest` (11), `ChunkRequest` (12), `ChunkData` (13). |
| **Manifest Exchange** (`peer_sync.hpp`) | Directory-level `FileManifest` exchanging file paths, sizes, and whole-file SHA-256. | Two-stage manifest: (1) Directory-level manifest establishes sync plan; (2) Per-file `mc::cas::FileManifest` carries chunk list. |
| **Missing Content Resolution** | Receiver requests entire file by relative path (`FileRequest`). | Receiver computes hash difference against local `ObjectStore::has_object()` and requests only missing chunk hashes. |
| **Wire Data Transfer** | Sequential file byte stream chunks (64 KB buffers, `FileData`). | Content-addressed chunk transfer (`ChunkData`), keyed by SHA-256 chunk hash. |
| **File Assembly on Receiver** | Bytes appended linearly to `StagingFile`. | Chunks stored into local CAS; file reconstructed via `ObjectStore::reconstruct_file()` from local + newly received chunks. |
| **Whole-File Validation** | Receiver hashes linear staging file on `FileEnd`. | Dual validation: (1) Per-chunk SHA-256 verified on receipt; (2) Reconstructed whole-file SHA-256 verified against manifest. |
| **GC & Multi-Process Safety** | In-process `cas_barrier_` + OS-level `.cas_barrier.lock`. Peer transfer does not hold CAS barrier. | Peer transfer holds `CasSharedBarrierGuard` during chunk read/ingestion/reconstruction; GC cannot sweep active transfer chunks. |
| **Backward Compatibility** | Rejects unknown frame types. | Protocol version negotiation: if peer does not advertise CAS capability in `Hello`, fall back cleanly to whole-file streaming. |

---

## 3. The 6 Core Workstreams

```
+---------------------------------------------------------------------------------------------------------+
|                                    Workstream Execution Pipeline                                        |
|                                                                                                         |
|   +-----------------------+       +------------------------+       +--------------------------------+   |
|   | 1. Manifest Exchange  | ----> | 2. Chunk Negotiation   | ----> | 3. Delta Transfer              |   |
|   | Exchange & validate   |       | Query local CAS;       |       | Stream missing chunks          |   |
|   | chunk manifests       |       | find missing set       |       | over TLS wire                  |   |
|   +-----------------------+       +------------------------+       +--------------------------------+   |
|                                                                                    |                    |
|   +-----------------------+       +------------------------+                       |                    |
|   | 6. Atomic Commit      | <---- | 5. File Reconstruction | <---- +--------------------------------+   |
|   | Two-phase journal &   |       | Staged streaming       |       | 4. Chunk Verification          |   |
|   | baseline advance      |       | assembly & verification|       | Validate SHA-256 & ingest      |   |
|   +-----------------------+       +------------------------+       +--------------------------------+   |
+---------------------------------------------------------------------------------------------------------+
```

### Workstream 1: Manifest Exchange
- **Sender Responsibilities**:
  - When a file mutation (`AddLocal`, `UpdateLocal`, `AddRemote`, `UpdateRemote`) is planned, the sender loads or computes the `mc::cas::FileManifest`.
  - Encodes the manifest using `mc::cas::ManifestSerializer::serialize_binary()`.
  - Sends a `ChunkManifest` frame containing the relative path, file size, whole-file SHA-256, and chunk descriptors (hash, offset, size).
- **Receiver Responsibilities**:
  - Validates relative path: rejects absolute paths, `..` traversal, null bytes, backslashes (normalized to `/`), and illegal characters.
  - Validates manifest structure: verifies chunk count $> 0$, contiguous non-overlapping offsets, chunk size within $[16\text{ KB}, 256\text{ KB}]$ bounds, and sum of chunk sizes equals `total_size`.

### Workstream 2: Chunk Negotiation
- **Algorithm**:
  Given received `FileManifest` with chunks $C = \{h_1, h_2, \dots, h_n\}$:
  ```cpp
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
    - List of 64-hex lowercase chunk hashes requested.
  - If `missing_chunks.empty()`, the receiver already possesses all chunks (e.g. file was renamed, or reverted to a prior version). Zero chunk transfer required!

### Workstream 3: Delta Transfer
- **Streaming Protocol**:
  - Sender receives `ChunkRequest`.
  - For each requested chunk hash:
    - Verifies hash syntax (64 hex characters).
    - Reads chunk data from local `ObjectStore::get_object(hash, data)`.
    - Transmits a `MessageType::ChunkData` frame:
      - Header: 64-character chunk hash (ASCII hex).
      - Payload: Chunk binary content (bounded by `kMaximumFramePayload` = 1 MB).
- **Backpressure & Bounded Memory**:
  - Chunks are read and transmitted one-by-one. No batch chunk loading into RAM.
  - Memory consumption is strictly bounded by single chunk size (max 256 KB).

### Workstream 4: Chunk Verification & Ingestion
- **Cryptographic Invariant**: Never trust remote data.
  Upon receiving `ChunkData` with reported hash $H_{claimed}$ and payload $B$:
  1. Verify length of $B$ matches expected size from the manifest.
  2. Compute $H_{actual} = \text{SHA-256}(B)$.
  3. If $H_{actual} \ne H_{claimed}$, drop connection and send `MessageType::Error("corrupted chunk payload")`.
  4. Ingest chunk into local store via `object_store.put_object(B.data(), B.size(), H_{actual})`.
  5. The object is now an immutable, verified CAS entity in `cas/objects/xx/hash`.

### Workstream 5: File Reconstruction
- **Streaming Reconstruction**:
  - Receiver invokes `object_store.reconstruct_file(manifest, staging_path, err, true)`.
  - `reconstruct_file()` reads chunk by chunk from local CAS into the staging file.
  - Verifies whole-file SHA-256 digest on the fly.
  - Guarantees working files are never hardlinked directly to CAS objects (mutation safety).

### Workstream 6: Atomic Integration & Journaling
- **Commit Safety**:
  - Reconstructed staging file is handed to `PeerTransactionCoordinator`.
  - Coordinator verifies file hash matches `expected_new_hash` recorded in `peer_operations` journal.
  - Creates backup recovery artifact for destination file.
  - Executes verified filesystem replacement via atomic rename / transaction commit.
  - Commits updated manifest to `PeerBaselineStore`.
  - Releases recovery material only after bilateral terminal state.

---

## 4. Wire Protocol Evolution & Message Types

### Extended MessageType Definition (`include/merklechain/peer/peer_protocol.hpp`)
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

### Capability Advertisement in `Hello` Frame
- In `MessageType::Hello`, peers advertise their capability string:
  ```
  identity:peer_alpha;capabilities:cas_delta_v1,whole_file
  ```
- **Backward Compatibility Guarantee**:
  - If a connected peer does *not* advertise `cas_delta_v1`, the session automatically falls back to existing `FileRequest` / `FileData` whole-file transfer.
  - Existing Phase 2 test suites continue to pass without modification.

### Binary Framing for CAS Messages

#### `ChunkManifest` Frame Payload
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Relative Path Length              | uint16_t (big-endian)                 |
| Relative Path                     | UTF-8 string (normalized '/')         |
| Serialized FileManifest           | Binary payload from ManifestSerializer|
+-----------------------------------+---------------------------------------+
```

#### `ChunkRequest` Frame Payload
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Relative Path Length              | uint16_t (big-endian)                 |
| Relative Path                     | UTF-8 string                          |
| Missing Chunk Count               | uint32_t (big-endian)                 |
| Repeated Chunk Hashes             | 64 ASCII hex bytes per chunk hash     |
+-----------------------------------+---------------------------------------+
```

#### `ChunkData` Frame Payload
```
+-----------------------------------+---------------------------------------+
| Field                             | Format / Size                         |
+-----------------------------------+---------------------------------------+
| Chunk Hash                        | 64 ASCII hex bytes                    |
| Chunk Payload                     | Raw chunk bytes (variable size)       |
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
4. **Denial-of-Service (DoS) Protection**:
   - Maximum frame payload enforced at $1\text{ MB}$ (`kMaximumFramePayload`).
   - Maximum chunk manifest entries bounded (e.g. 50,000 chunks = 3.2 GB file maximum per manifest).

---

## 6. Concurrency & Lock Hierarchy

### Network Transfer vs Global Maintenance Barrier
A network transfer can take seconds or minutes. Holding an exclusive lock or blocking the entire database during a network transfer is an anti-pattern.

```
Total Lock Hierarchy Order:
OperationGuard (Lifecycle) -> InterprocessCasBarrier (Shared) -> Workspace Mutex -> DB Mutex
```

### Invariants:
1. **Never Hold DB Mutex During Network I/O**:
   - Database operations (logging progress, updating session state) acquire `db_mutex_`, execute in $< 5\text{ ms}$, and release `db_mutex_`.
   - Socket `send()` and `recv()` occur completely outside `db_mutex_`.
2. **Shared Barrier for Transfer Operations**:
   - When the receiver is ingesting chunks into `ObjectStore` or reconstructing a file, it acquires a `CasSharedBarrierGuard cas_lock(cas_barrier)`.
   - This allows concurrent readers, submissions, and publications.
   - It blocks any concurrent `garbage_collect` sweep from unlinking chunks while the transfer is assembling the file!
   - As soon as reconstruction finishes, the shared barrier is released.
3. **No Deadlocks with Crash Recovery**:
   - If the network drops or the remote peer crashes during transfer, RAII guard releases `CasSharedBarrierGuard`.
   - The OS kernel automatically cleans any locks on process termination.

---

## 7. Adversarial Test Matrix (14 Mandatory Scenarios)

The test suite will implement 14 deterministic adversarial test scenarios in `tests/peer_sync_cas_delta_tests.cpp`:

| Scenario ID | Test Name | Simulated Condition | Expected Invariant & Behavior |
| :--- | :--- | :--- | :--- |
| **CAS-NET-01** | Identical Files Sync | Peer A and Peer B have identical files. | Zero chunks transferred; 0 bytes delta payload; instant manifest agreement. |
| **CAS-NET-02** | Partial Chunk Reuse | Peer B possesses 80% of chunks from prior versions. | Exactly 20% missing chunks requested; 80% chunks reused locally without transfer. |
| **CAS-NET-03** | Middle Modification | 1 MB file modified in 64 KB middle region. | Chunks before and after edit reused; only 1 or 2 affected chunks transferred. |
| **CAS-NET-04** | File Rename / Move | File renamed with unchanged contents. | Manifest path updated; 0 chunks transferred; file reconstructed/promoted from local CAS. |
| **CAS-NET-05** | Corrupted Chunk Payload | Wire payload tampered by 1 flipped bit. | SHA-256 mismatch detected; chunk rejected; error frame sent; staging unlinked. |
| **CAS-NET-06** | Mismatched Manifest Root | Remote peer sends manifest with falsified whole-file root. | Reconstruction verification detects discrepancy; transaction aborted cleanly. |
| **CAS-NET-07** | Network Interruption | Connection severed mid-chunk stream. | Session marked `RecoveryRequired` / `Aborted`; partial chunks unlinked; resumeable. |
| **CAS-NET-08** | Duplicate Chunk Delivery | Same chunk hash delivered multiple times or exists locally. | Handled idempotently via `ObjectStore::put_object()`; zero duplicate storage. |
| **CAS-NET-09** | Concurrent Transfers | Multiple bilateral sessions transferring concurrently. | Workspace-isolated journals prevent crosstalk; zero catalog corruption. |
| **CAS-NET-10** | Concurrent GC during Transfer | GC runs while peer is receiving and reconstructing. | `InterprocessCasBarrier` shared guard protects in-flight chunks from sweep. |
| **CAS-NET-11** | Receiver Crash Mid-Transfer | Receiver process terminated with `std::_Exit(94)`. | Startup recovery cleans orphan staging; working copy completely untouched. |
| **CAS-NET-12** | Path Traversal Injection | Remote manifest contains `../../etc/passwd`. | Path validation rejects entry immediately; session terminated with error. |
| **CAS-NET-13** | Large File Streaming | 100 MB file transfer under tight memory limit. | Bounded 64 KB memory streaming; peak RAM remains $< 10\text{ MB}$. |
| **CAS-NET-14** | Legacy Peer Compatibility | Remote peer does not support CAS delta messages. | Gracefully falls back to whole-file `FileRequest`/`FileData` streaming. |

---

## 8. Performance Benchmark Plan

To validate the real-world bandwidth and performance advantage of CAS delta sync, a dedicated benchmark executable `benchmarks/cas_network_benchmark.cpp` will be implemented:

### Benchmark Datasets:
1. **Dataset A (Initial Full Sync)**: 50 MB mixed directory (code, text, binary assets).
2. **Dataset B (Small In-Place Edit)**: 50 MB directory with a 10-line edit inside a 5 MB file.
3. **Dataset C (Head Insertion)**: 10 MB file with 500 bytes inserted at byte offset 0 (testing FastCDC shifting resilience).
4. **Dataset D (Many Small Files)**: 500 files of 4 KB each with 5 files modified.

### Metrics Recorded:
- **Total Bytes Transferred** (Wire bytes: whole-file vs CAS delta).
- **Deduplication Ratio** ($\frac{\text{Bytes Saved}}{\text{Total File Size}}$).
- **Transfer Duration** (Milliseconds).
- **Peak RAM Consumption** (Megabytes).
- **Reconstruction Time** (Milliseconds).

**Target Success Criterion**: Demonstrating $> 80\%$ bandwidth reduction on Dataset B and Dataset C compared to legacy whole-file transfer.

---

## 9. Implementation Roadmap & Milestones

```
Phase 3 Milestone 3.4 Execution Stages:
1. [Stage 1] Protocol Wire Extensions: Add ChunkManifest/ChunkRequest frame types to peer_protocol.
2. [Stage 2] Chunker & Manifest Peer Helpers: Helper methods for peer manifest serialization and missing chunk resolution.
3. [Stage 3] PeerService CAS Delta Engine: Integrate chunk negotiation, streaming, and verification into peer_service.cpp.
4. [Stage 4] Atomic Reconstruction & Staging: Connect ObjectStore reconstruct to PeerTransactionCoordinator.
5. [Stage 5] Adversarial Testing (CAS-NET-01 to CAS-NET-14): Implement all 14 tests in tests/peer_sync_cas_delta_tests.cpp.
6. [Stage 6] Benchmarking: Implement and run benchmarks/cas_network_benchmark.cpp.
7. [Stage 7] Independent Audit & Release: Formal audit report and release v0.3.0-m3.4.
```

---

## 10. Approval & Next Steps

This specification establishes the architectural foundation for Milestone 3.4.

**Next Action**: Upon user review and approval of this specification, we will proceed to **Stage 1 & Stage 2**: implementing the protocol frame extensions and missing-chunk negotiation engine.
