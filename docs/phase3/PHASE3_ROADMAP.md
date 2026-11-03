# Syncora Phase 3 Architecture Proposal & Product Roadmap
## Distributed Synchronization, Content-Addressed Chunk Storage, Three-Way Merging, and Real-Time Peer Collaboration

**Author**: Senior Software Architecture Team  
**Date**: November 3, 2026  
**Document Status**: Proposal / Awaiting User Approval  
**Target Milestone**: Syncora v0.3.0  
**Stack Continuity**: C++17 Backend (GCC/Clang, SQLite, OpenSSL, Winsock/BSD sockets) + Vanilla HTML5/CSS3/ES6 Frontend (No external frameworks or node dependencies at runtime)

---

## 1. Context & Architectural Motivation

Phase 2 established a bulletproof single-node transactional foundation for Syncora:
- Workspace-level serialization without global contention.
- Admission-controlled lifecycle drain eliminating shutdown races.
- Prepared statement tracking with zero statement leaks.
- Two-phase journaled staging, atomic exclusive sentinels, and non-destructive baseline backups.
- Physical manifest reconciliation and autonomous crash recovery.

However, an analysis of the current system reveals four fundamental architectural gaps that prevent Syncora from scaling to large multi-user distributed teams and bandwidth-constrained network topologies:
1. **Full Directory Duplication ($O(N \times V)$ Disk Growth)**: `CollabStore` copies entire directory trees for every submission and published version snapshot. Large repositories rapidly exhaust disk space.
2. **Disconnected Peer Network Engine**: The TLS peer synchronization coordinator (`PeerSession`, `PeerProtocol`) operates as a standalone CLI/daemon, separate from `CollabStore` workspaces and the `workspace_operations` journal.
3. **Absence of Three-Way Merge**: Diffs are purely binary/two-way. When concurrent edits occur across clients or between a client submission and the host working copy, there is no automatic three-way merge resolution.
4. **Coarse-Grained Polling**: Clients poll `/api/client/updates` on timers rather than receiving instantaneous reactive event streams.

Phase 3 bridges these gaps while strictly maintaining the zero-dependency, high-performance C++17 and Vanilla web stack.

---

## 2. Feature Specification & Prioritization

```mermaid
graph TD
    subgraph Essential Features (Milestone 3.1 & 3.2)
        F1["Feature 1: Content-Addressed Chunk Deduplication (CAS)"]
        F2["Feature 2: Peer Network & Workspace Journal Integration"]
        F3["Feature 3: 3-Way Semantic Merging & Conflict Markers"]
        F4["Feature 4: Delta-Compressed Network Wire Protocol"]
    end

    subgraph Optional Enhancements (Milestone 3.3)
        F5["Feature 5: Workspace Branching & Semantic Forks"]
        F6["Feature 6: Real-Time Server-Sent Events (SSE)"]
    end

    F1 --> F2
    F1 --> F4
    F2 --> F3
    F3 --> F5
    F4 --> F6
```

---

### Feature 1: Content-Addressed Chunk Deduplication & Object Store (CAS)
- **Priority**: **Essential (Highest)**
- **Purpose & User Value**: Eliminates duplicate file storage across submissions, baselines, and version releases. Reduces disk space consumption by 70–95% on typical codebases by storing identical files and chunks only once.
- **Technical Design**:
  - Introduce an immutable content-addressed object store under `<storage_root>/objects/xx/yy...` (matching Git/Oasis object architecture).
  - Small files ($< 64\text{ KB}$) are stored as whole compressed blobs.
  - Large files ($\ge 64\text{ KB}$) are split using FastCDC (Content-Defined Chunking) or fixed-size 64KB hashing.
  - Published versions and submissions become lightweight **Tree Manifests** pointing to lists of chunk SHA-256 digests rather than deep physical directory clones.
  - When a version is checked out or promoted to `working_copy`, files are hard-linked (on NTFS/ext4) or re-materialized on demand.
- **Backend Changes**:
  - `src/storage.cpp` & `src/chunk_sync.cpp`: Integrate `ObjectStore` engine into `CollabStore`.
  - Schema update: Create SQLite table `cas_objects` (hash, size, compressed_size, ref_count, created_at_ms) and `cas_manifest_entries`.
  - `CollabStore::publish_version()` and `create_submission()`: Ingest files into CAS rather than calling `copy_directory_recursive()`.
- **Frontend Changes**:
  - "Storage Diagnostics" view in Dashboard displaying deduplication ratio, total chunks, total referenced size vs physical size stored, and space savings percentage.
- **Data Structures & Algorithms**:
  - Content-Defined Chunking (Rabin fingerprinting / FastCDC).
  - SHA-256 Merkle DAG (Directed Acyclic Graph) of tree manifests.
  - Reference counting garbage collector for unreferenced objects (`collect_unreferenced_objects()`).
- **API Changes**:
  - `GET /api/host/storage/stats`: Returns JSON deduplication metrics (`raw_bytes`, `deduped_bytes`, `savings_pct`, `object_count`).
  - `POST /api/host/storage/gc`: Triggers a safe Mark-and-Sweep garbage collection pass on unreferenced blobs.
- **Dependencies**: OpenSSL EVP SHA-256 (existing), zlib or miniz (single-header header-only compression).
- **Complexity & Implementation Risk**: Medium-High. Risk of orphaned objects or premature garbage collection; mitigated by reference-count tracking in SQLite transaction boundary.
- **Testing Strategy**:
  - Unit tests verifying multi-version publication with 90% identical files only increases disk usage by the 10% delta.
  - Crash tests verifying GC never deletes objects referenced by pending journal operations.

---

### Feature 2: Bilateral Peer Network & Workspace Journal Integration
- **Priority**: **Essential**
- **Purpose & User Value**: Enables two remote hosts or a host and a client across different machines to synchronize collaboration workspaces over mutual TLS (mTLS), bringing Phase 2's crash recovery and transaction journaling to distributed multi-device environments.
- **Technical Design**:
  - Connect `mc::peer::PeerSession` and `mc::peer::PeerService` to `CollabStore`.
  - When a peer sync is initiated for a workspace, the coordinator acquires the workspace lock, generates a bilateral plan, stages incoming objects in `.staging_peer_<op_id>`, writes atomic sentinels, and commits using a distributed Two-Phase Commit (2PC) state machine.
  - If a peer disconnects or crashes midway through sync, the local journal rollback engine restores the verified baseline.
- **Backend Changes**:
  - `src/peer/peer_controller.cpp`: Add workspace-aware sync handlers (`sync_workspace(ws_id, peer_config)`).
  - `src/peer/peer_protocol.cpp`: Add frame types for `MSG_WORKSPACE_METADATA`, `MSG_MANIFEST_EXCHANGE`, `MSG_CHUNK_BATCH_REQUEST`, `MSG_CHUNK_BATCH_RESPONSE`.
- **Frontend Changes**:
  - Peer Network view in Dashboard updated to allow selecting which local workspace is synchronized with remote peer addresses.
  - Interactive modal displaying incoming peer proposal with bilateral diff viewer.
- **Data Structures & Algorithms**:
  - Bilateral 2PC (Prepare, PreparedAck, Commit, CommitAck, Abort).
  - SHA-256 Plan Fingerprinting for tamper-proof mutual plan authorization.
- **API Changes**:
  - `POST /api/peer/workspaces/sync`: Initiates mTLS synchronization for a specific workspace against a pinned remote peer.
  - `GET /api/peer/workspaces/status`: Streams progress of chunk transfers and verification.
- **Dependencies**: OpenSSL 3.x TLS (existing), Winsock/POSIX Sockets (existing).
- **Complexity & Implementation Risk**: High. Network timeouts, network partitions, and asynchronous disconnects require rigorous state-machine isolation.
- **Testing Strategy**:
  - Loopback TLS multi-threaded tests simulating packet truncation, dropouts, unannounced socket shutdown, and invalid certificate pin rejections.
  - Interrupted peer sync failpoint tests verifying local baseline is never left in torn state.

---

### Feature 3: Three-Way Semantic Merge & Visual Conflict Resolution
- **Priority**: **Essential**
- **Purpose & User Value**: Allows host reviewers to merge divergent client submissions or concurrent working copy edits without overwriting lines. Provides automated merges for clean edits and inline visual conflict markers for colliding lines.
- **Technical Design**:
  - Diff3-style Three-Way Merge algorithm taking three inputs:
    1. **Base**: The common ancestor baseline version ($O$).
    2. **Ours**: The current host working copy ($A$).
    3. **Theirs**: The incoming client submission ($B$).
  - Clean non-overlapping edits from either side are automatically integrated into the merged result.
  - Overlapping conflicting line modifications generate conflict blocks:
    ```
    <<<<<<< HOST WORKING COPY
    Server listening on port 8080
    =======
    Server listening on port 9090
    >>>>>>> CLIENT SUBMISSION (alice)
    ```
- **Backend Changes**:
  - `src/collab_store.cpp`: Implement `merge_submission_three_way(sub_id, reviewer_id, strategy)`.
  - Implement line-level Myers diff with 3-way reconciliation in `src/merge.cpp` (new module).
- **Frontend Changes**:
  - "Interactive Conflict Resolver" view in Web Dashboard: Side-by-side comparison panes (Ours, Base, Theirs) with a bottom resolved editor allowing one-click selection of "Accept Ours", "Accept Theirs", or custom edits before accepting the submission.
- **Data Structures & Algorithms**:
  - Longest Common Subsequence (LCS) / Myers Diff Algorithm.
  - Three-way hunk reconciliation graph.
- **API Changes**:
  - `GET /api/host/submissions/merge-preview?submission_id=<id>`: Returns preview of 3-way merge including conflicted files, cleanly merged files, and conflict hunk line numbers.
  - `POST /api/host/submissions/resolve-merge`: Accepts resolved content per file and completes submission acceptance.
- **Dependencies**: Standard library only (no external diff libraries required).
- **Complexity & Implementation Risk**: Medium. Line-ending normalization (CRLF vs LF) and binary file handling must fail safely (binary collisions force manual selection of Ours vs Theirs).
- **Testing Strategy**:
  - Matrix test suite covering: non-overlapping edits, identical concurrent edits, adjacent edits, true collisions, UTF-8 unicode handling, and binary file collision rejection.

---

### Feature 4: Delta-Compressed Network Wire Protocol
- **Priority**: **Essential**
- **Purpose & User Value**: Optimizes client update polling and application. Rather than downloading whole files or complete snapshots, clients request only missing content chunks. Reduces network bandwidth by up to 98% for iterative software updates.
- **Technical Design**:
  - Client sends its local manifest hash set (`have_chunks`).
  - Host calculates difference ($want\_chunks = target\_chunks \setminus have\_chunks$).
  - Host streams a packed, compressed chunk archive over HTTP or TLS peer transport.
  - Client unpacks chunks into its local staging directory, validates hashes, and atomically swaps working files.
- **Backend Changes**:
  - `src/web_server.cpp`: Add endpoint `POST /api/client/updates/delta-download`.
  - `CollabStore::apply_update`: Support chunked client patching.
- **Frontend Changes**:
  - Client view shows download progress in terms of transferred bytes vs total version size (demonstrating bandwidth saved).
- **Data Structures & Algorithms**:
  - Hash Set Difference ($O(K)$ lookup).
  - Variable-length chunk stream framing.
- **API Changes**:
  - `POST /api/client/updates/delta-manifest`: Exchanging client chunk inventory.
  - `GET /api/client/updates/delta-stream`: Binary chunk bundle transfer.
- **Dependencies**: Existing OpenSSL and streaming socket primitives.
- **Complexity & Implementation Risk**: Low-Medium. Streaming backpressure must be properly managed.
- **Testing Strategy**:
  - Automated integration test simulating a 10MB project where a 10-line file edit transfers $< 5\text{ KB}$ across the wire.

---

### Feature 5: Workspace Branching & Semantic Forks
- **Priority**: **Optional Enhancement**
- **Purpose & User Value**: Enables multiple development streams within the same workspace (e.g. `main`, `feature/auth`, `hotfix/security`). Clients can target specific branches, and hosts can review and merge branches independently.
- **Technical Design**:
  - Extend workspace database schema: `workspace_branches` table (id, workspace_id, name, head_version_id, created_at_ms).
  - Stored files reference the CAS object store, meaning creating a branch has zero storage overhead ($O(1)$ pointer creation).
- **Backend Changes**:
  - `create_branch(ws_id, branch_name, source_version_id)`.
  - `switch_workspace_branch(ws_id, branch_name)`.
- **Frontend Changes**:
  - Branch selector dropdown in the navigation header.
  - Branch tree visualization displaying commits, forks, and merges.
- **API Changes**:
  - `GET /api/host/workspaces/branches?workspace_id=<id>`
  - `POST /api/host/workspaces/branches` (create branch)
- **Dependencies**: Built on Feature 1 (CAS Object Store).
- **Complexity & Implementation Risk**: Medium.
- **Testing Strategy**:
  - Branch creation, concurrent work across branches without mutual interference, and fast-forward merge tests.

---

### Feature 6: Real-Time Server-Sent Events (SSE) & Activity Streaming
- **Priority**: **Optional Enhancement**
- **Purpose & User Value**: Replaces client timer polling with instant push notifications when client submissions arrive, reviews complete, or releases are published. Improves UI responsiveness from seconds to milliseconds.
- **Technical Design**:
  - Implement HTTP `text/event-stream` endpoint in `web_server.cpp`.
  - Maintain a thread-safe subscriber registry of open client socket descriptors.
  - When `record_event()` or publication occurs, push JSON events to subscribed listeners.
- **Backend Changes**:
  - `web_server.cpp`: Add `GET /api/events/stream` with chunked transfer encoding and non-blocking heartbeat.
- **Frontend Changes**:
  - `web/app.js`: Connect `new EventSource('/api/events/stream')`. Update badge counts and refresh file diffs instantly without full page reloads.
- **Dependencies**: Standard WinSock/POSIX socket event loops.
- **Complexity & Implementation Risk**: Low.
- **Testing Strategy**:
  - Multi-client subscription tests, client disconnect cleanup, and ping-pong heartbeat verification.

---

## 3. Implementation Roadmap & Milestones

| Milestone | Target Scope | Key Deliverables | Estimated Risk |
|---|---|---|---|
| **Milestone 3.1: Content-Addressed Storage (CAS)** | Feature 1 | `ObjectStore`, CAS schema, FastCDC chunking, zero-copy deduplication, CAS test suite | Medium |
| **Milestone 3.2: 3-Way Merge & Delta Sync** | Feature 3 & Feature 4 | Diff3 engine, visual conflict editor in Dashboard, delta network stream, E2E merge tests | Low-Medium |
| **Milestone 3.3: Bilateral Peer-Workspace Integration** | Feature 2 | TLS PeerSession + CollabStore journal integration, distributed 2PC, multi-machine tests | High |
| **Milestone 3.4: Real-Time Polish & Branching** | Feature 5 & Feature 6 | Workspace branching, SSE push notifications, end-to-end stress test, v0.3.0 release | Low |

---

## 4. Architectural Rules for Phase 3
1. **Preserve Phase 2 Safety Contracts**: Every new operation modifying filesystem state must continue to use `OperationGuard`, fine-grained per-workspace locks, atomic sentinels, and the two-phase commit journal.
2. **Never Hold DB Mutex During Network or File I/O**: Network packet transfers (chunk transfers, TLS handshakes) must never block database transactions or other workspaces.
3. **No External Framework Bloat**: Maintain zero third-party framework dependencies. Continue using pure C++17 and Vanilla HTML5/CSS/JavaScript.

