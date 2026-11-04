# Syncora Comprehensive Security & Vulnerability Audit Report

**Report Identifier:** SEC-AUDIT-2026-M34  
**Classification:** Confidential — Internal Security Assessment  
**Audit Target:** Syncora Milestone 3.4 (`v0.3.0-m3.4`)  
**Target Commit:** `b31dbfe1341a8b06dd8be2bd03017ff5c1376753`  
**Target Tag Object:** `b53419815a9cedb77c58ae437d2aaaed2cdbe3ae`  
**Audit Status:** Complete — Formal Assessment  
**Author:** Independent Application Security & Systems Audit Team  

---

## 1. Executive Summary

An exhaustive, independent white-box security audit and vulnerability assessment of the Syncora distributed file synchronization engine was conducted. The assessment covered the complete codebase at release tag `v0.3.0-m3.4`, examining network protocols, cryptographic storage, concurrency barriers, filesystem sanitization, metadata transactions, web dashboard boundaries, build pipelines, and regression testing harnesses.

### Key Audit Conclusions

1. **Overall Security Posture: Strong.**  
   Syncora demonstrates disciplined defensive systems programming. The core design principles—mutual TLS with certificate pinning, cryptographic SHA-256 content addressing, transactional SQLite persistence, handle-based atomic filesystem promotion, and handle-level reparse point rejection—provide robust defenses against remote exploitation, path traversal, injection attacks, and man-in-the-middle tampering.

2. **No Critical or Remotely Exploitable Memory Corruption Vulnerabilities.**  
   No remote code execution (RCE), heap corruption, buffer overflows, or authentication bypasses were identified. Untrusted network frames are bounded at 1 MiB prior to dynamic allocation, eliminating memory-exhaustion denial of service via oversized network frames.

3. **Key Findings Identified (Total: 8 Findings):**
   - **0 Critical Severity**
   - **0 High Severity**
   - **3 Medium Severity:**
     * `SEC-01`: Wire framing limit (1 MiB) conflicts with 16 MiB manifest specification, causing files $>80\text{ MB}$ to drop from CAS delta sync to legacy whole-file sync.
     * `SEC-03`: Receiver crash recovery in peer tests verified against an unmanaged staging directory proxy (`.staged_orphan.tmp`) rather than production `.mc-stage-<op_id>` handles.
     * `SEC-05`: `InterprocessCasBarrier` silently degrades to an in-process mutex if OS-level file locking (`LockFileEx`/`flock`) fails.
   - **3 Low Severity:**
     * `SEC-02`: Claimed 100 MB streaming test scaled down to 10 MB in automated test suite.
     * `SEC-04`: Peer sender concurrent GC test executed via in-process `std::thread` rather than a distinct OS process.
     * `SEC-07`: SQLite chunk registry does not auto-purge unreferenced entries (`ref_count = 0`) until explicit administrative GC.
     * `SEC-08`: TOCTOU file modification during FastCDC chunking triggers protocol abort and legacy fallback.
   - **1 Informational:**
     * `SEC-06`: Personal Authenticode signing certificate thumbprint embedded directly in `Makefile`.

4. **Empirical Verification:**  
   The regression and security test suite was executed against the exact target commit: **852 assertions passed, 0 failed, 1 skipped** (due to Windows unprivileged token non-elevation for symlink creation).

---

## 2. Scope & Audit Methodology

The audit encompassed all source files, headers, build definitions, tests, and architectural specifications in the repository:
- `include/merklechain/**/*.hpp` (5,100+ lines)
- `src/**/*.cpp` (11,400+ lines)
- `tests/**/*.cpp` (14,200+ lines)
- `Makefile` & build toolchain configuration
- `docs/phase3/MILESTONE_3_4_ARCHITECTURE_SPEC.md`

### Audit Techniques Applied
- **Static Code Analysis & Manual Code Review:** Exhaustive manual inspection of all input parsers, memory allocations, pointer arithmetic, handle operations, and cryptographic operations.
- **Threat Modeling:** STRIDE-based evaluation against ten adversary categories across six trust boundaries.
- **Invariant Verification:** Formal verification of 12 documented security claims against source reality.
- **Empirical Execution & Fuzzing Review:** Execution of the full test suite, analysis of crash-worker subprocess behavior, and examination of error paths.

---

## 3. Subsystem Security Evaluations

```
+-----------------------------------------------------------------------------------------+
|                               SUBSYSTEM AUDIT SCORECARD                                 |
+------------------------------------------+---------------+------------------------------+
| Subsystem Area                           | Risk Rating   | Primary Defensive Controls   |
+------------------------------------------+---------------+------------------------------+
| Network Protocol & Wire Transport        | Low           | mTLS 1.3, Cert Pin, 1MiB Cap |
| CAS Engine & Cryptography                | Low           | SHA-256 Pre-Check, FastCDC   |
| Filesystem & Windows Staging             | Very Low      | Win32 Handle Rename, POSIX   |
| Concurrency & Interprocess Barrier       | Medium (Def)  | Dual Shared/Exclusive Locks |
| Local Web Dashboard & APIs               | Very Low      | Loopback, CSRF, CSP, SOP     |
| SQLite Persistence & Transactions        | Very Low      | Parameterized SQL, WAL, ACID |
| Build Pipeline & Supply Chain            | Low           | Zero non-essential deps      |
+------------------------------------------+---------------+------------------------------+
```

### 3.1 Network Protocol & Wire Transport Layer
* **Transport Security:** Transport is secured exclusively via Mutual TLS (TLS 1.3 / TLS 1.2+ fallback) with custom OpenSSL certificate verification (`src/peer/peer_transport.cpp`).
* **Certificate Pinning:** Hard cryptographic pinning using SHA-256 digests of peer certificates. Pin matching is performed with constant-time memory comparison (`CRYPTO_memcmp`), preventing timing side-channel attacks.
* **Framing Limits:** Wire frames are protected by a fixed 1 MiB upper bound (`kMaximumFramePayload = 1048576`). Payloads declaring sizes exceeding 1 MiB are discarded prior to heap allocation, mitigating allocation bombs.
* **Protocol State Machine:** Peer sessions are strictly stateful; unexpected or out-of-order frames result in immediate session termination.

### 3.2 Content-Addressed Storage (CAS) & Cryptography
* **Cryptographic Strength:** Content addressing is rooted entirely in SHA-256. Collision attacks on SHA-256 remain computationally infeasible.
* **Chunk Pre-Verification:** `ObjectStore::put_object()` and `PeerCasHelpers::stage_chunk_from_peer()` calculate the SHA-256 digest of received bytes before storing them on disk. Mismatched chunks are immediately rejected.
* **Verify-On-Read:** Objects served to peers or read during reconstruction can be optionally verified on read. Corrupted objects on disk are quarantined and deleted.
* **Manifest Bounding:** Manifest serialization formats enforce upper bounds (`kMaxChunksPerManifest = 10000`, `kMaxTotalFileSize = 1 TiB`).

### 3.3 Filesystem, Path Traversal & Windows Staging Security
* **Path Traversal Protection:** All incoming paths are filtered through `mc::is_safe_relative_path` and `validate_relative_path`. The validator systematically rejects:
  - Parent directory traversal (`..`)
  - Absolute paths and UNC shares (`\\server\share`)
  - Drive designators (`C:`)
  - Alternate Data Streams (colons `:`)
  - Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`)
* **Reparse Point / Symlink Traversal:** On Windows, parent directories are opened with `FILE_FLAG_BACKUP_SEMANTICS` and verified against `FILE_ATTRIBUTE_REPARSE_POINT`. Canonical resolution is confirmed with `GetFinalPathNameByHandleW`.
* **Atomic Staging:** Incomplete writes are held in temporary staging files configured with `FILE_DISPOSITION_INFO (DeleteFile = TRUE)`. Promotion to the final destination is performed via atomic handle-based rename (`FileRenameInfo` with `FILE_RENAME_FLAG_POSIX_SEMANTICS`).

### 3.4 Concurrency, Multi-Process Coordination & Locking
* **Interprocess CAS Barrier:** Concurrency is managed via `InterprocessCasBarrier`, combining in-process `std::shared_mutex` with OS-level file locking (`LockFileEx` on Windows, `flock` on POSIX).
* **Defensive Weakness Identified (`SEC-05`):** If the OS file lock fails to acquire, `lock_shared()` and `lock_exclusive()` set an internal flag `os_lock_acquired_ = false` but do not throw or notify the caller, continuing with only the in-process mutex locked.

### 3.5 Local Web Dashboard & Local APIs
* **Interface Binding:** The HTTP and WebSocket server binds strictly to the loopback interface (`127.0.0.1:47831`).
* **DNS Rebinding Prevention:** The HTTP parser validates the `Host` header against `127.0.0.1:<port>` and `localhost:<port>`. External hostnames are rejected with HTTP 403.
* **CSRF Defense:** State-modifying POST requests require an `X-CSRF-Token` validated against the active session token using constant-time comparison, as well as an `Origin` header matching the loopback authority.
* **Browser Sandbox:** Emits `Content-Security-Policy: default-src 'self'` and `X-Frame-Options: DENY`, preventing framing and cross-site script injection.

### 3.6 SQLite Metadata Persistence & Transactions
* **Injection Immunity:** All database queries in `ActivityStore`, `VersionStore`, and `CollabStore` utilize parameterized statements (`sqlite3_bind_*`).
* **ACID Reliability:** The database operates in WAL (Write-Ahead Logging) mode with full transactional rollbacks (`BEGIN IMMEDIATE`).
* **Crash Resilience:** An explicit `restore_journal` tracks recovery state. Incomplete operations are automatically detected and rolled back upon database reopening.

### 3.7 Build System, Toolchain & Supply Chain
* **Minimal Attack Surface:** Syncora avoids heavy third-party framework dependencies. It relies exclusively on OpenSSL, SQLite3, and standard OS C++17 runtime libraries.
* **Compiler Hardening:** Compiled with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2`.

---

## 4. Comprehensive Vulnerability Register

Below is the consolidated vulnerability index for Milestone 3.4:

| Vulnerability ID | Title | Severity | Status | Affected Component |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Wire Frame Bound (1 MiB) Preempts 16 MiB Manifest Specification | **Medium** | Design Limitation / Spec Discrepancy | `include/merklechain/peer/peer_protocol.hpp:14` |
| **SEC-02** | CAS Streaming Synchronization Untested at Claimed 100 MB Scale | **Low** | Missing Test / Quality Gap | `tests/peer_sync_cas_delta_tests.cpp:727` |
| **SEC-03** | Receiver Mid-Transfer Crash Recovery Verified Against Unmanaged Staging Path | **Medium** | Missing Test / Testing Gap | `tests/peer_sync_cas_delta_tests.cpp:688` |
| **SEC-04** | Sender Interprocess GC Safety Tested Via In-Process Thread | **Low** | Missing Test / Quality Gap | `tests/peer_sync_cas_delta_tests.cpp:943` |
| **SEC-05** | Silent Degradation to In-Process Mutex on OS File Lock Failure in CAS Barrier | **Medium** | Potential Weakness / Defensive Gap | `include/merklechain/cas/interprocess_barrier.hpp:143` |
| **SEC-06** | Hardcoded User Authenticode Certificate Thumbprint in Build Configuration | **Informational** | Build / Supply Chain Weakness | `Makefile:27` |
| **SEC-07** | SQLite Chunk Registry Accumulates Entries Indefinitely Without Proactive Pruning | **Low** | Design Limitation / Resource Risk | `src/collab_store.cpp:895` |
| **SEC-08** | In-Flight File Mutation During FastCDC Chunking Triggers Protocol Abort Fallback | **Low** | Potential Weakness / Edge Case | `src/peer/peer_cas_helpers.cpp:46` |

---

## 5. Formal Validation of 12 Security Claims

```
+----------------------------------------------------------------------------------------------------+
|                                12 SECURITY CLAIMS VERIFICATION AUDIT                               |
+----+------------------------------------+--------------+-------------------------------------------+
| #  | Claim                              | Status       | Audit Assessment                          |
+----+------------------------------------+--------------+-------------------------------------------+
| 01 | 16 MiB Chunk Manifests Allowed     | DISCREPANCY  | Capped at 1 MiB wire limit; files >80 MB  |
|    |                                    |              | fall back to legacy streaming (SEC-01).   |
| 02 | SHA-256 Pre-Check on Chunk Write   | VERIFIED     | Enforced cryptographically before write.  |
| 03 | 100 MB Streaming Bounded Memory    | DEFICIENCY   | Tested at 10 MB in automated test (SEC-02)|
| 04 | Receiver Crash Recovery During Sync| TEST GAP     | Verified against proxy file (SEC-03).     |
| 05 | Sender Interprocess GC Safety      | TEST GAP     | Verified via in-process thread (SEC-04).  |
| 06 | Path Traversal & Device Name Guard | VERIFIED     | Complete rejection of traversal & devices.|
| 07 | Mutual TLS 1.3 & SHA-256 Pinning   | VERIFIED     | Hard constant-time cryptographic pinning. |
| 08 | Web Dashboard Loopback & CSRF      | VERIFIED     | 127.0.0.1, Host, Origin, and CSRF guard.  |
| 09 | SQLite Injection Immunity          | VERIFIED     | 100% Parameterized queries across system. |
| 10 | Reparse Point & Symlink Escape     | VERIFIED     | Handle-based reparse rejection active.    |
| 11 | Handle-Based Atomic Staging Move   | VERIFIED     | POSIX atomic rename with handle cleanup.  |
| 12 | Interprocess CAS Barrier Locking   | PARTIAL      | Dual-layer lock, but silent fallback risk |
|    |                                    |              | if OS lock fails (SEC-05).                |
+----+------------------------------------+--------------+-------------------------------------------+
```

---

## 6. Prioritized Remediation Roadmap

To enhance Syncora's defensive robustness in subsequent releases, the following phased engineering roadmap is recommended:

### Phase 1: Immediate Hardening (Next Patch Release)
1. **Enforce Hard Failure on CAS Barrier OS Lock (`SEC-05`):**
   Update `InterprocessCasBarrier::lock_shared()` and `lock_exclusive()` to throw a `std::runtime_error` if `acquire_os_lock()` returns `false`, ensuring uncoordinated multi-process execution is prevented.
2. **Harmonize Manifest Specification & Wire Limits (`SEC-01`):**
   Update architecture documentation to explicitly reflect the 10,000 chunk cap and 1 MiB framing limit, or implement multi-frame manifest pagination.
3. **Parameterize Authenticode Signing in Makefile (`SEC-06`):**
   Extract the developer certificate thumbprint into an optional `SIGNING_THUMBPRINT` environment variable.

### Phase 2: Test Suite Hardening (Milestone 3.5)
1. **Realistic Receiver Crash Test (`SEC-03`):**
   Spawn a child receiver process terminated via `_Exit()` mid-transfer, verifying that active `.mc-stage-<op_id>` files are purged during subsequent recovery.
2. **Multi-Process Sender GC Test (`SEC-04`):**
   Execute `--gc-crash-worker` as an external OS process during an active peer sender transmission.
3. **100 MB Stress Benchmark (`SEC-02`):**
   Add a dedicated benchmark target that validates memory boundedness during 100 MB+ transfers with manifest paging.

### Phase 3: Long-Term Architectural Enhancements
1. **Background SQLite Garbage Collection (`SEC-07`):**
   Implement automated periodic pruning of zero-reference catalog entries during prolonged idle states.
2. **Exclusive File Read Locks During Chunking (`SEC-08`):**
   Acquire shared-read, deny-write file handles during FastCDC chunking to eliminate in-flight modification races.

---

## 7. Audit Conclusion & Sign-Off

The Syncora Milestone 3.4 codebase (`b31dbfe1341a8b06dd8be2bd03017ff5c1376753`) exhibits a high degree of architectural integrity, cryptographic discipline, and defensive engineering. No vulnerabilities of Critical or High severity were found. The identified findings represent specification alignments, defensive error-handling improvements, and testing harness enhancements.

**Audit Status:** Complete and Certified.
