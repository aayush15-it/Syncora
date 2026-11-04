# Syncora Milestone 3.4 — Limitations, Operational Boundaries & Non-Goals

## 1. Scope and Architectural Boundaries

Syncora Milestone 3.4 implements **point-to-point (bilateral) Content-Addressed Storage delta synchronization** over authenticated TLS connections. This document describes the deliberate boundaries, trade-offs, and non-goals established for M3.4.

---

## 2. Technical Limitations & Trade-Offs

### 2.1 CPU vs. Network Latency Trade-Off
- **Behavior**: FastCDC chunking and SHA-256 calculation introduce measurable CPU computation time before wire transmission begins.
- **Impact**: On high-speed local loopback connections with infinite bandwidth, legacy whole-file streaming finishes slightly faster in wall-clock time than CAS delta because legacy skips chunking.
- **Boundary**: CAS delta is optimized for distributed network environments where WAN/Wi-Fi bandwidth and egress quotas are the primary cost and latency bottlenecks.

### 2.2 Bilateral Scope (Two Devices Only)
- **Limitation**: M3.4 protocol negotiation, session journals, and transaction coordinators operate bilaterally between exactly two devices (Host and Client).
- **Non-Goal**: Multi-device concurrent synchronization (e.g. 3+ peers simultaneously syncing to the same shared folder) is outside the scope of M3.4 and forms the primary objective of **Milestone 3.5**.

### 2.3 Single Active Session per Folder Pair
- **Boundary**: The inter-process CAS maintenance barrier (`InterprocessCasBarrier`) and database locks permit only one active peer synchronization session per folder pair at any given time.
- **Handling**: Concurrent connection attempts are queued or rejected cleanly with descriptive error messages.

### 2.4 Chunk Granularity and Sizing Limits
- **Configuration**: Standard FastCDC chunk parameters are hard-coded to canonical peer bounds:
  - Minimum chunk size: 4,096 bytes
  - Average chunk size: 8,192 bytes
  - Maximum chunk size: 16,384 bytes
  - Normalization: 2
- **Implication**: Files smaller than 4,096 bytes are treated as single-chunk objects. The maximum chunk size transferred over a single `ChunkData` frame is 16 KiB.

### 2.5 Ephemeral Staging Storage
- **Boundary**: Staging files are assembled in `.merklechain/` temporary staging directories on the same physical volume as the destination folder to enable atomic `rename` operations.
- **Implication**: Cross-device or cross-filesystem synchronization requires sufficient staging space on the target volume.

### 2.6 Dynamic Bandwidth Throttling & Resumption
- **Boundary**: Interrupted chunk transfers within an active session will fail closed and abort the current staging attempt.
- **Recovery**: Staged chunks already committed to the local CAS store remain cataloged and valid; upon restarting the session, already-received chunks are reused locally and do not need to be re-downloaded over the network.

---

## 3. Explicit Non-Goals (Preserved for Future Milestones)

| Feature / Capability | Target Milestone | Rationale for Exclusion in M3.4 |
| :--- | :---: | :--- |
| **Multi-Peer Conflict Resolution** | Milestone 3.5 | Requires distributed vector clocks and multi-device consensus. |
| **P2P Mesh / NAT Traversal (STUN/TURN)** | Milestone 3.6 | Focuses on direct connectivity; M3.4 targets direct IP/port configurations. |
| **CAS Chunk Compression (zstd/LZ4)** | Post-Phase 3 | FastCDC chunking alone achieves 98%+ reductions on modified files; wire compression is an orthogonal optimization. |
| **Public Cloud Storage Adapters (S3/GCS)** | Post-Phase 3 | Core Syncora architecture remains zero-cloud and sovereign peer-to-peer. |

---

## 4. Operational Invariants Enforced

1. **Cryptographic Ground Truth**: No chunk is ever written or committed to the target workspace without matching its expected SHA-256 hash.
2. **Crash-Safety**: All filesystem mutations use atomic file replacement (`atomic_replace_file` / `MoveFileExW`). Partial transfers never contaminate live user directories.
3. **Barrier Invariance**: Physical CAS objects are guarded by the inter-process maintenance barrier during every network read and write operation.
