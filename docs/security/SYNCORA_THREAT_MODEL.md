# Syncora Threat Model & Security Architecture

**Document Version:** 1.0  
**Classification:** Internal Technical Security Architecture  
**Target Release:** v0.3.0-m3.4 (`b31dbfe1341a8b06dd8be2bd03017ff5c1376753`)  
**Auditor:** Independent Security Review  

---

## 1. Executive Summary & Purpose

Syncora is a high-assurance, peer-to-peer distributed file synchronization engine implemented in C++17. Its core architecture combines:
- **FastCDC (Fast Content-Defined Chunking)** for variable-length chunk deduplication.
- **Content-Addressed Storage (CAS)** keyed by cryptographic SHA-256 digests.
- **Merkle Tree State Graphs** for rapid hierarchical divergence detection.
- **ACID Transactional Journaling** backed by SQLite3.
- **Mutual TLS (mTLS)** transport with hard cryptographic certificate pinning.
- **Multi-Process Concurrency Control** via OS-level advisory file locks (`LockFileEx`/`flock`) and in-process shared mutexes.
- **Local Web Management Dashboard** exposed via loopback HTTP/WebSocket.

This document establishes the formal **Threat Model** for Syncora across all system surfaces, enumerating trust boundaries, entry points, adversary profiles, assets, and security guarantees.

---

## 2. System Architecture & Component Interactions

```
+-----------------------------------------------------------------------------------+
|                                 LOCAL HOST BOUNDARY                               |
|                                                                                   |
|  +------------------------+                     +-------------------------------+  |
|  | Web Browser / Frontend |                     | External Peer (Over Network)  |  |
|  | (127.0.0.1:47831)      |                     | (TLS 1.3 / mTLS + Pinning)    |  |
|  +-----------+------------+                     +---------------+---------------+  |
|              | HTTP / WS (Loopback Only)                        | TCP / TLS Port   |
|              v                                                  v                  |
|  +------------------------+                     +-------------------------------+  |
|  |  Local Web Server      |                     |  Peer Transport & Protocol    |  |
|  |  (CSRF + Host Guard)   |                     |  (Wire Framing <= 1 MiB)      |  |
|  +-----------+------------+                     +---------------+---------------+  |
|              | In-Process RPC                                   | Protocol Frames  |
|              +--------------------+       +---------------------+                  |
|                                   v       v                                        |
|                          +-------------------------+                               |
|                          | Peer Sync Coordinator / |                               |
|                          | CollabStore Engine      |                               |
|                          +------------+------------+                               |
|                                       |                                            |
|         +-----------------------------+-----------------------------+              |
|         v                                                           v              |
|  +-------------------------------+                         +--------------------+  |
|  | Interprocess CAS Barrier      |                         | Transaction        |  |
|  | (Shared/Exclusive OS Lock)    |                         | Coordinator        |  |
|  +---------------+---------------+                         +---------+----------+  |
|                  |                                                   |             |
|                  v                                                   v             |
|  +-------------------------------+                         +--------------------+  |
|  | CAS Object Store              |                         | Staging & Finalize |  |
|  | (Content-Addressed SHA-256)   |                         | (Handle-based Move)|  |
|  +---------------+---------------+                         +---------+----------+  |
|                  |                                                   |             |
|                  +-----------------------+   +-----------------------+             |
|                                          v   v                                     |
|  +-------------------------------------------------------------------------------+ |
|  |                               FILESYSTEM STORAGE                              | |
|  |  - Sync Root Workspace: `<sync_root>/`                                        | |
|  |  - Staging Isolation:   `<sync_root>/.merklechain/staging/`                   | |
|  |  - CAS Storage Pool:    `<sync_root>/.merklechain/cas/objects/xx/yyyy...`     | |
|  |  - SQLite Database:     `<sync_root>/.merklechain/activity.sqlite3`           | |
|  |  - Lock Control File:   `<sync_root>/.merklechain/cas/.cas_lock`              | |
|  +-------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
```

---

## 3. Trust Boundaries & Security Domains

Syncora segregates its operational environment into distinct security zones separated by well-defined trust boundaries:

| Boundary ID | Boundary Name | Untrusted Domain | Trusted Domain | Enforcement Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **TB-NET** | Network Transport Boundary | External Network / Public Internet | Local Peer Process Space | Mutual TLS 1.3, X.509 CA chain verification, SHA-256 public key certificate pinning, 1 MiB framing bounds. |
| **TB-PROC** | Inter-Process Concurrency Boundary | Concurrent OS Processes (Worker, CLI, Web) | Active Storage Pool | `InterprocessCasBarrier` with OS file locking (`LockFileEx`/`flock`), PID liveness checks, and cooperative shared/exclusive lock states. |
| **TB-FS** | Filesystem Sandbox Boundary | Arbitrary Filesystem & Peer Path Directives | Canonical Sync Root Tree | Handle-based atomic renames (`FILE_RENAME_FLAG_POSIX_SEMANTICS`), path sanitization rejecting `..`, UNC, drive letters, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`). |
| **TB-WEB** | Local Dashboard Loopback Boundary | Local Web Browsers & Third-Party Origin Scripts | Dashboard API & Management State | Strict `127.0.0.1` binding, `Host` header enforcement, `Origin` whitelist validation on state-modifying requests, cryptographically strong anti-CSRF tokens, restrictive CSP. |
| **TB-DB** | Metadata Persistence Boundary | Malicious Input File Metadata / Query Data | SQLite Database Filesystem | 100% parameterized SQLite statements (`sqlite3_bind_*`), absence of raw string interpolation, explicit WAL mode, and transactional rollback journals. |
| **TB-CAS** | Content Verification Boundary | Remote Peer Chunks / Staged Bit Streams | Content-Addressed Store | Cryptographic SHA-256 pre-verification of raw chunk bytes before object promotion; quarantine of mismatched chunks. |

---

## 4. Entry Points & Attack Surface

The system exposes five primary entry points accessible to external or local actors:

1. **EP-1: Peer Network Transport Listener (TCP Socket)**  
   - *Interface:* TLS 1.3 server socket listening on configured peer port (e.g., 42424).
   - *Protocol:* Custom binary framed protocol over TLS (`merklechain::peer::PeerProtocol`).
   - *Potential Inputs:* Raw byte frames, Handshake tokens, Manifest payloads, Chunk request vectors, Raw chunk data blobs.

2. **EP-2: Web Dashboard Management Interface (HTTP/WebSocket)**  
   - *Interface:* Local HTTP/1.1 and WebSocket server bound to `127.0.0.1:47831`.
   - *Potential Inputs:* HTTP GET/POST headers (`Host`, `Origin`, `Authorization`), JSON action payloads, WebSocket frame payloads.

3. **EP-3: Monitored Local Sync Root (Filesystem Scanner & Watcher)**  
   - *Interface:* Local directory tree traversed by recursive directory scanner.
   - *Potential Inputs:* Symlinks, hardlinks, junction points, Alternate Data Streams (ADS), deep directory hierarchies, non-UTF8 filenames, files modified concurrently during scanning.

4. **EP-4: CLI & Configuration Ingestion**  
   - *Interface:* Command-line invocation flags and `config.ini` files.
   - *Potential Inputs:* TLS certificate and private key file paths, directory paths, port numbers, peer fingerprints.

5. **EP-5: Persistent Metadata & CAS Object Files**  
   - *Interface:* Direct files on disk under `.merklechain/`.
   - *Potential Inputs:* Corrupted SQLite records, orphaned temporary staging files, manipulated CAS object blobs on disk.

---

## 5. Attacker Categories & Threat Scenarios

To thoroughly evaluate Syncora's defensive architecture, ten adversary profiles were evaluated:

### Category 1: Rogue or Compromised Network Peer (CAT-01)
* **Profile:** An attacker operating an endpoint running the Syncora protocol that has network connectivity to the victim node.
* **Capabilities:** May possess a valid or invalid TLS certificate; can send arbitrary malformed byte streams, oversized frames, forged file manifests, cyclic manifests, non-existent chunk hashes, or conflicting Merkle roots.
* **Objectives:** Remote code execution (RCE), heap corruption, memory exhaustion, arbitrary file overwrite outside the sync root, unauthorized file retrieval.
* **Mitigations in Syncora:**
  - Strict mutual TLS handshake with SHA-256 certificate pinning (`CRYPTO_memcmp`). Untrusted peers are terminated prior to protocol execution.
  - Mandatory frame length validation capping frame payloads at `kMaximumFramePayload` (1 MiB).
  - Validation of all manifest counts against `kMaxChunksPerManifest` (10,000) and `kMaxTotalFileSize` (1 TiB).
  - SHA-256 pre-verification of every received chunk against its advertised hash before writing to CAS.

### Category 2: Network Man-in-the-Middle / Traffic Tamperer (CAT-02)
* **Profile:** An attacker positioned on the network path between two legitimate Syncora nodes (e.g., public Wi-Fi, compromised router).
* **Capabilities:** Packet sniffing, frame modification, packet replay, session hijacking, TLS downgrade attempts.
* **Objectives:** Eavesdrop on sensitive synced file contents, inject corrupted chunks, forge metadata.
* **Mitigations in Syncora:**
  - Exclusive use of TLS 1.3 with authenticated cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
  - Mutual certificate validation with mutual pinning: client pins server certificate, server pins client certificate.
  - Replay attacks are mitigated by TLS-level sequence numbering and ephemeral key exchange (ECDHE).

### Category 3: Local Unprivileged Attacker on Same Host (CAT-03)
* **Profile:** A malicious user or unprivileged process running concurrently on the same OS host as Syncora.
* **Capabilities:** Can inspect local filesystem permissions, open loopback network sockets, send requests to `127.0.0.1:47831`, create conflicting file locks.
* **Objectives:** Intercept synced data, trigger unauthorized sync actions, crash the sync daemon, hijack local HTTP/WebSocket ports.
* **Mitigations in Syncora:**
  - Web dashboard enforces strict CSRF token validation and rejects requests with mismatched `Host` or foreign `Origin` headers.
  - SQLite database files and CAS directories inherit host user ACLs.
  - Inter-process barrier uses OS-level mandatory/advisory locks keyed to the unique canonical path of the sync directory.

### Category 4: Cross-Origin / Malicious Browser Attacker (CAT-04)
* **Profile:** An attacker who induces the user to visit a malicious website in their browser while Syncora is running.
* **Capabilities:** Browser issues cross-origin HTTP GET/POST or WebSocket connection attempts against `http://127.0.0.1:47831` (e.g., via JavaScript `fetch()` or `WebSocket`).
* **Objectives:** DNS rebinding, cross-site request forgery (CSRF) to trigger sync or dump file listings, WebSocket hijacking to stream file updates.
* **Mitigations in Syncora:**
  - **Host Header Validation:** Explicitly checks `Host == 127.0.0.1:port` or `localhost:port`. Rejects arbitrary DNS rebinding hostnames.
  - **Origin Header Check:** State-modifying HTTP POST endpoints require `Origin: http://127.0.0.1:port` or `http://localhost:port`.
  - **CSRF Token:** Non-GET requests require a valid, session-scoped cryptographic token compared with `constant_time_equal`.
  - **Strict Content Security Policy (CSP):** `default-src 'self'`.

### Category 5: Process Crash, Power Failure & Disruption Adversary (CAT-05)
* **Profile:** Sudden abnormal termination of the Syncora process or system (e.g., `kill -9`, blue screen, power loss, disk full) during critical operations.
* **Capabilities:** Leaves incomplete staging files, half-written CAS objects, partially populated SQLite journals, or locked mutexes.
* **Objectives:** Induce corrupted file state, orphaned locks preventing future restart, metadata desynchronization, lost data.
* **Mitigations in Syncora:**
  - **Atomic File Promotion:** Target files are assembled in isolated staging paths and promoted via atomic filesystem move operations (`MoveFileExW` / POSIX rename).
  - **Atomic CAS Writes:** Chunks are written to PID-tagged temporary files (`.tmp.<pid>.<uuid>`) and atomically renamed into CAS object storage only after SHA-256 verification.
  - **SQLite WAL Mode & Journaling:** Operations are tracked in an ACID journal (`restore_journal`, `active_operations`), replaying or rolling back unfinished operations upon startup.
  - **Lock File Auto-Release:** OS file handles are automatically cleaned up and unlocked by the kernel upon process termination.

### Category 6: Malicious File Path & Filesystem Traversal Adversary (CAT-06)
* **Profile:** An attacker who crafts files or directory hierarchies designed to escape the synchronization root or trigger OS filesystem vulnerabilities.
* **Capabilities:** Submits relative paths containing `../`, null bytes, drive letters (`C:`), Windows namespace prefixes (`\\?\`), NTFS Alternate Data Streams (`file.txt:hidden`), symlinks/reparse points pointing outside the root, or reserved Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
* **Objectives:** Arbitrary file overwrite, reading sensitive system files (`/etc/passwd`, `C:\Windows\System32`), crashing the Windows filesystem driver.
* **Mitigations in Syncora:**
  - `mc::is_safe_relative_path` and `PeerCasHelpers::validate_relative_path` enforce strict normalization: reject absolute paths, directory traversal (`..`), empty segments, colons (`:`), and Windows reserved names.
  - `StagingFile` opens parent directories with `FILE_FLAG_BACKUP_SEMANTICS`, verifies they are not reparse points via `GetFileInformationByHandleEx`, and calls `GetFinalPathNameByHandleW` to confirm path resolution remains within the approved sandbox.

### Category 7: CAS Cryptographic & Bit-Rot Adversary (CAT-07)
* **Profile:** Corrupted storage media, bit flips, or an adversary attempting to engineer an intentional SHA-256 hash collision.
* **Capabilities:** Flipping bits in stored CAS objects on disk, modifying object files while Syncora is idle, or crafting two differing payloads with the same digest.
* **Objectives:** Silent data corruption, serving corrupted chunks to peers, polluting the global deduplication store.
* **Mitigations in Syncora:**
  - Cryptographic primitive: SHA-256 (256-bit collision resistance, computationally infeasible to collide).
  - Optional and enforced verify-on-read: `verify_object()` reads and recalculates SHA-256 before serving objects to peers or reconstructing files.
  - Immediate quarantine and deletion of corrupted objects, falling back to network retrieval or verified whole-file synchronization.

### Category 8: Concurrent Multi-Process Race Adversary (CAT-08)
* **Profile:** Multiple Syncora processes (e.g., CLI sync command, background daemon, web server worker, garbage collection tool) executing simultaneously against the same workspace.
* **Capabilities:** Concurrent read/write to `.merklechain/activity.sqlite3`, concurrent GC unlinking objects while a sync process is reading or referencing them.
* **Objectives:** Data race, file locking violations, dangling CAS chunk references, database corruption.
* **Mitigations in Syncora:**
  - `InterprocessCasBarrier` implements two-tier locking: in-process `std::shared_mutex` plus OS file locks (`LockFileEx` on Windows / `flock` on POSIX).
  - Operations categorize locks: Version publication and chunk ingestion take **Shared** locks; Garbage Collection sweeps take **Exclusive** locks.
  - GC implements a configurable grace period (`grace_period_ms`) preventing recently staged or referenced chunks from being purged prematurely.

### Category 9: Supply Chain & Build Pipeline Adversary (CAT-09)
* **Profile:** An adversary targeting third-party dependencies, build toolchains, or artifact distribution pipelines.
* **Capabilities:** Compromising upstream libraries, injecting malicious code into build scripts, tampering with binaries post-compilation.
* **Objectives:** Backdoor Syncora binaries, bypass integrity checks.
* **Mitigations in Syncora:**
  - Minimal dependency footprint: Syncora depends solely on the C++17 Standard Library, OpenSSL (libcrypto/libssl), SQLite3, and native OS APIs (Win32 / POSIX).
  - All compiler warnings treated strictly (`-Wall -Wextra -Wpedantic -Wconversion -Wshadow`).
  - Windows binary signing support via Authenticode (`Set-AuthenticodeSignature`).

### Category 10: Resource Exhaustion & Denial of Service (DoS) Adversary (CAT-10)
* **Profile:** A peer or client sending inputs calculated to maximize resource consumption (CPU, memory, disk, network bandwidth).
* **Capabilities:** Sending manifests claiming billions of chunks, requesting missing chunks repeatedly in an infinite loop, streaming massive continuous files.
* **Objectives:** Out-of-Memory (OOM) crashes, CPU starvation, disk exhaustion.
* **Mitigations in Syncora:**
  - Strict upper bounds: `kMaxChunksPerManifest = 10000`, `kMaxTotalFileSize = 1 TiB`, `kMaximumFramePayload = 1 MiB`.
  - Bounded memory streaming: Chunk payloads are transferred and verified sequentially; receiver does not buffer entire multi-gigabyte files in RAM.

---

## 6. Security Assets & Critical Invariants

| Asset | Security Invariant |
| :--- | :--- |
| **User Data Files** | Files within the sync root must never be overwritten with unverified content. Overwrites must be atomic. No file outside the sync root may ever be modified. |
| **CAS Object Store** | Every object stored in `.merklechain/cas/objects/` must exactly match its SHA-256 pathname digest. |
| **Merkle Tree State** | The Merkle root must deterministically represent the recursive cryptographic digest of all file paths and chunk manifests in the directory tree. |
| **SQLite Activity Journal** | Database operations must remain ACID. Recovery must be idempotent and crash-resilient across process restarts. |
| **Cryptographic Secrets** | TLS private keys and session tokens must never be written to logs, debug streams, or transmitted unencrypted. |

---

## 7. Assumptions, Operational Prerequisites & Non-Goals

1. **OS Kernel & Local Administrator:** Syncora relies on the host operating system's kernel for process isolation and access control. If an attacker possesses local Administrator or `root` privileges on the host, all user-space isolation guarantees are nullified.
2. **Cryptographic Foundations:** The security of Syncora relies on the cryptographic strength of SHA-256 and TLS 1.3 primitives provided by OpenSSL.
3. **Physical Security:** Hardware memory corruption (e.g., non-ECC RAM bit-flips) or physical physical storage extraction is out of scope.
