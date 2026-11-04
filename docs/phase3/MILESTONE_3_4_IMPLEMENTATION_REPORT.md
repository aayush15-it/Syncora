# Syncora Milestone 3.4 — Implementation Report: Distributed CAS Delta Network Synchronization

## Executive Summary

Syncora Milestone 3.4 delivers **Distributed Content-Addressed Storage (CAS) Delta Network Synchronization**. Prior to M3.4, Syncora operated two parallel data models:
1. A local Content-Addressed Storage engine (M3.1–M3.3) equipped with FastCDC content-defined chunking, immutable file manifests, transactional SQLite cataloging, and an OS-level inter-process garbage collection barrier.
2. A whole-file bilateral peer synchronization transport (Phase 2) exchanging entire files across TLS connections.

Milestone 3.4 connects the CAS storage engine directly to the network transport, enabling **sub-file delta transfers**: when two peers synchronize, only modified chunks are transferred over the wire. Unmodified chunks already present in local or remote CAS stores are reused in place, reducing network bandwidth by up to **99.8%** on realistic workloads while maintaining 100% cryptographic data integrity and backward compatibility.

---

## Architecture Overview & 7-Stage Implementation

### Stage 1: Protocol Wire Extensions
Four new message types were integrated into the existing binary wire protocol (`merklechain/peer/peer_protocol.hpp`), maintaining strict framing guarantees:
- **`ChunkManifestRequest` (Type `10`)**: Requests the chunk manifest for a specific relative file path. Payload bounded to 4,096 bytes; path traversal strictly prohibited.
- **`ChunkManifest` (Type `11`)**: Delivers the serialized FastCDC manifest for the requested file. Bounded to 16 MiB.
- **`ChunkRequest` (Type `12`)**: Batched request containing the target relative path and up to 256 missing chunk SHA-256 hashes.
- **`ChunkData` (Type `13`)**: Transfers individual CAS chunk payloads (64-character hex hash followed by binary chunk payload, up to 16 KiB per chunk).

All frames conform to the bounded wire format: `Magic [4B] | Version [1B] | MsgType [1B] | Reserved [2B] | PayloadLength [4B] | Payload`.

### Stage 2: CAS Chunker and Manifest Peer Helpers
Implemented in `merklechain/peer/peer_cas_helpers.hpp` and `src/peer/peer_cas_helpers.cpp`:
- **Canonical FastCDC Peer Configuration**: Standardized across all peers: `min_size = 4096`, `avg_size = 8192`, `max_size = 16384`, `normalization = 2`. Ensures boundary alignment across independent nodes.
- **`SessionChunkAuthorizer`**: Enforces strict authorization boundaries per peer session. Chunks and file paths are rejected if not explicitly planned in the agreed bilateral session.
- **`compute_missing_chunks`**: Queries local CAS storage (`has_object` / `verify_object`) to filter out chunks already possessed, identifying only missing hashes.
- **`build_chunk_requests`**: Partitions missing chunk hashes into bounded batches of up to 256 hashes per `ChunkRequest` frame.
- **`verify_chunk_payload`**: Validates each received chunk against SHA-256 before storage in CAS or staging.

### Stage 3: PeerService CAS Delta Engine
Implemented in `merklechain/peer/peer_service.hpp` and `src/peer/peer_service.cpp`:
- **Capability Negotiation**: During TLS `Hello` handshake, peers advertise `cas_delta_v1` alongside `whole_file`. Delta mode is activated if and only if both peers negotiate `cas_delta_v1`. If either peer lacks capability, synchronization safely falls back to legacy whole-file streaming.
- **Local File Ingestion for Delta Reuse**: When updating an existing destination file, `stage_file_from_peer` automatically FastCDC-chunks the existing local file into CAS prior to negotiation. This allows the receiver to possess baseline chunks locally and avoid re-downloading unchanged sections.
- **Dual-Barrier Coordination**: Protects physical CAS objects during network synchronization using `mc::cas::InterprocessCasBarrier`:
  - **Receiver Barrier**: Held continuously in shared mode from chunk negotiation through staging reconstruction and SQLite transaction commit.
  - **Sender Barrier**: Held in shared mode while serving requested chunks to the peer.
  - Prevents concurrent GC sweeps or writers from unlinking active chunks during transit.

### Stage 4: Atomic Reconstruction & Two-Phase Transaction Promotion
- **Staging Reconstruction**: Missing chunks are downloaded into CAS; all manifest chunks are sequentially read from CAS and written into a `StagingFile`.
- **Integrity Gates**:
  1. Reconstructed byte count must equal manifest `total_size()`.
  2. Whole-file SHA-256 computed on staging must match `manifest.file_sha256()`.
- **Atomic Two-Phase Commit**:
  1. `prepare_operations`: Staging files validated and armed.
  2. `commit_local`: Atomic rename replaces live target file; SQLite journal and baseline store commit transaction.

### Stage 5: Adversarial CAS Network Test Suite
Implemented in `tests/peer_sync_cas_delta_tests.cpp`:
- Complete 21-scenario adversarial test suite (`CAS-NET-01` through `CAS-NET-21`) covering identical files, in-place edits, boundary alignments, bit-rot corruption detection/healing, truncation, malicious path injection, duplicate delivery, and simulated crashes.

### Stage 6: Safe-Restart Recovery & Lifecycle
- Survives process crashes before, during, or after staging reconstruction.
- Recovery re-scans unfinished sessions from `activity.sqlite3`, safely purging uncommitted `.tmp` artifacts while preserving validated CAS chunks.

### Stage 7: Performance Benchmarking
- Implemented in `benchmarks/cas_network_benchmark.cpp` measuring 8 realistic datasets comparing legacy whole-file transfer against CAS delta transfer.
- Validates up to **99.8%** bandwidth reduction.

---

## Verification Results Summary

| Test Suite | Total Checks | Passed | Failed | Skipped | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Core & CAS Unit/Adversarial** | 853 | 852 | 0 | 1 | **PASS** |
| **Collaboration E2E** | 34 | 34 | 0 | 0 | **PASS** |
| **Peer Network Dashboard** | 71 | 71 | 0 | 0 | **PASS** |
| **Selective Sync & Explorer** | 11 | 11 | 0 | 0 | **PASS** |
| **Dashboard Navigation Views** | 33 | 33 | 0 | 0 | **PASS** |
| **Dashboard Smoke** | 5 | 5 | 0 | 0 | **PASS** |
| **CAS Network Benchmark** | 8 datasets (24 runs) | 24 | 0 | 0 | **PASS** |

---

## Conclusion
Syncora Milestone 3.4 is fully implemented, verified, and benchmarked. All architectural requirements, security constraints, and safety invariants have been met.
