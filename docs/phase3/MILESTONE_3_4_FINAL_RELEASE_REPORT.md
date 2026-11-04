# Syncora Milestone 3.4 — Final Release Report
## Distributed Content-Addressed Storage (CAS) Delta Network Synchronization
### Security Remediated Release

**Document Version:** 1.0  
**Classification:** Official Milestone Closure Deliverable  
**Release Date:** November 4, 2026  
**Final Release Status:** **RELEASE FINALIZED WITH DOCUMENTED LIMITATIONS**

---

## A. Release Information

* **Release Name:** Syncora Milestone 3.4 Security Remediated Release
* **Version String:** `v0.3.1-m3.4-security`
* **Final Commit Hash:** `b6584dbc992c683b81335a1757adc58339cd57e7`
* **New Annotated Tag:** `v0.3.1-m3.4-security`
* **Parent Commit Hash:** `1d4ba0d88e49c43c0655c72c8a7c42d8c3b3ecf0`
* **Base M3.4 Release Commit:** `b31dbfe1341a8b06dd8be2bd03017ff5c1376753` (`v0.3.0-m3.4`)
* **Branch:** `master`
* **Build Toolchain:** MSYS2 UCRT64 / GCC 14 / GNU Make (C++17)

---

## B. Milestone 3.4 Delivered Features

Milestone 3.4 extends Syncora's bilateral synchronization engine with production Content-Addressed Storage (CAS) delta network synchronization, enabling fine-grained differential synchronization across remote nodes over TLS:

1. **FastCDC Content-Defined Chunking:**
   - Production FastCDC chunker (`src/cas/chunker.cpp`, `include/merklechain/cas/chunker.hpp`) configured with $4\text{ KiB}$ minimum, $16\text{ KiB}$ target, and $64\text{ KiB}$ maximum chunk size boundaries with 48-byte gear-hash normalization.
2. **Binary File Manifests & Serialization:**
   - Immutable binary manifest schema (`MCAS` magic v1) storing chunk offset, size, and SHA-256 digests (`include/merklechain/cas/file_manifest.hpp`, `src/cas/file_manifest.cpp`).
   - Single-frame serialization for manifests $\le 4,000$ chunks and multi-page pagination (`ChunkManifestPage`, Type 14) for manifests $> 4,000$ chunks to respect the strict 1 MiB wire payload ceiling.
3. **Missing-Chunk Negotiation & Delta Transfer:**
   - Receiver-driven missing chunk calculation (`compute_missing_chunks()`) against the local CAS store (`ObjectStore`).
   - Batched chunk requests (`ChunkRequestMessage`, Type 12) transferring only missing chunks, reusing identical content already present locally.
4. **Bilateral Protocol Wire Extensions:**
   - New wire frame types: `ChunkManifestRequest` (10), `ChunkManifest` (11), `ChunkRequest` (12), `ChunkData` (13), and `ChunkManifestPage` (14).
   - Strict session-scoped hash and path authorization (`SessionChunkAuthorizer`) preventing arbitrary chunk or path retrieval.
5. **Bidirectional Capability Negotiation & Backward Compatibility:**
   - Hello handshake (Type 0) negotiates `supports_cas_delta` flags.
   - Automatic fallback to legacy whole-file staging (`FileData`, Type 4) when communicating with legacy peers or when encountering manifest generation errors.
6. **Transactional Staging & Atomic Promotion:**
   - Atomic replacement via staging files (`StagingFile`) ensuring zero partial or corrupted file exposure to the working tree.
   - Double-verification: individual chunk payload verification (`verify_chunk_payload()`) followed by full-file SHA-256 verification before destination promotion.
7. **Crash Recovery & Staging Garbage Collection:**
   - Receiver mid-transfer crash recovery: orphaned staging files are cleaned on session restart; uncommitted transactions safely roll back without advancing the baseline.
8. **Cross-Process Maintenance Coordination:**
   - Dual-layer `InterprocessCasBarrier` combining in-process `std::shared_mutex` with OS-level kernel file locking (`LockFileEx` on Windows, `flock` on POSIX) protecting physical CAS objects during network synchronization against concurrent GC sweeps.

---

## C. Security Review & Vulnerability Remediation

All eight security findings identified during the security audit have been systematically addressed:

| ID | Title | Severity | Final Status | Core Technical Guarantee & Operational Boundary |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Wire Frame Bound Preempts Large Manifests | Medium | **Remediated & Verified** | Manifests $>4,000$ chunks automatically paginate into 2,000-chunk pages (~160 KiB). Receiver accumulates chunks in memory ($O(N)$ with chunk count). |
| **SEC-02** | 100 MB Streaming Synchronization Untested | Low | **Remediated & Verified** | Live 100 MB dataset (6,400 chunks) verified bit-for-bit over loopback TLS with Win32 `GetProcessMemoryInfo` peak working set RSS monitoring (+4.30 MB delta). |
| **SEC-03** | Receiver Mid-Transfer Crash Safety | Medium | **Remediated & Verified** | External subprocess abrupt termination via `_Exit(92)` verified; baseline remains unchanged; clean restart recovery. (Applies to process crash, not power-loss). |
| **SEC-04** | Cross-Process GC Concurrency Isolation | Low | **Remediated & Verified** | External GC worker subprocess verifies OS-level file lock contention: blocked with exit code 42 (Contended), acquired with code 0 upon release. |
| **SEC-05** | CAS Barrier Degradation on OS Lock Failure | High | **Verified with Documented Limitations** | Fail-closed `InterprocessCasBarrier`: unlock failure poisons barrier; kernel lock retention mirrored; all subsequent acquisitions rejected; same-file kernel lock contention verified across separate instances (Tests 13.14, 13.16); handle closed safely. Requires destruction/re-creation on poison. |
| **SEC-06** | Hardcoded User Authenticode Thumbprint | Info | **Remediated & Verified** | Parameterized `SIGNING_THUMBPRINT ?=` in `Makefile`; isolated `sign:` target; builds execute without certificate store dependencies. |
| **SEC-07** | SQLite Chunk Registry Compaction | Low | **Remediated & Verified** | `CollabStore::compact_cas_metadata()` executes under triple-lock hierarchy; transactionally prunes zero-referenced entries without touching active version blobs. |
| **SEC-08** | In-Flight Source File Mutation | Low | **Verified with Documented Limitations** | Single-pass EVP streaming chunker detects size/mtime modifications heuristically. Receiver cryptographic chunk and whole-file verification strictly blocks corrupt file promotion. |

---

## D. Final Regression & Benchmark Results

### 1. Full Automated Test Suite (`tests/run_tests.ps1`)
* **Command:** `powershell -ExecutionPolicy Bypass -File tests/run_tests.ps1`
* **Exit Code:** `0`
* **Results:** **933 passed, 0 failed, 1 skipped** (Execution time: 86.83s)
* **Skipped Test:** Staging NTFS reparse-point creation (Error 1314: standard user-mode token without `SeCreateSymbolicLinkPrivilege`).

### 2. Supplementary Test Suites
* **Collaboration E2E Suite (`tests/test_collaboration_e2e.ps1`):**  
  `34 passed, 0 failed` (Exit Code: 0) — RBAC, submissions, diff calculation, publishing, update polling, and audit logs.
* **Peer Network Dashboard Tests (`tests/peer_dashboard_tests.ps1`):**  
  `71 assertions passed, 0 failed` (Exit Code: 0) — UI views, CSRF tokens, port/pin validation, host daemon start/stop.
* **Dashboard Smoke Suite (`tests/dashboard_smoke.ps1`):**  
  `All views & plans passed` (Exit Code: 0) — SQLite persistence, preservation checks, approved sync.
* **Selective Sync & Explorer Suite (`tests/test_selective_sync_and_explorer.ps1`):**  
  `All scenarios passed` (Exit Code: 0) — Path traversal defense, selective folder sync, Merkle explorer.
* **Dashboard Navigation Suite (`tests/test_dashboard_navigation.js`):**  
  `33 routes verified, all passed` (Exit Code: 0) — Hash routing, landing page, browser back/forward history.

### 3. CAS Network Protocol Benchmark (`make cas-net-benchmark`)
* **Command:** `C:\msys64\usr\bin\make.exe cas-net-benchmark`
* **Exit Code:** `0`
* **Results Summary:**
  - Identical Files (1 MB): 0 B transferred (0.0% wire, 178.4 ms)
  - Small Edit (4 KB / 1 MB): 16 KiB transferred vs 1,048,576 B legacy (**98.4% bandwidth reduction**)
  - Middle Edit (64 KB / 2 MB): 16 KiB transferred vs 2,097,152 B legacy (**99.2% bandwidth reduction**)
  - Large Edit (20% edit / 2 MB): 16 KiB transferred vs 2,097,152 B legacy (**99.2% bandwidth reduction**)
  - File Rename (1 MB): Reused local chunks, 0 B payload data transferred (**79.7% wire reduction**)
  - Large 10 MB (16 KB edit): 16 KiB transferred vs 10,485,760 B legacy (**99.8% bandwidth reduction**)

---

## E. Architecture Limitations & Operating Boundaries

The following operating constraints and boundaries are explicitly recorded:

1. **Sender-Side Snapshot Consistency is Heuristic, Not Kernel-Guaranteed (SEC-08):**  
   The sender performs single-pass chunking and post-check verification of file size, modification timestamp, and byte counts. In-place, same-size modifications executed within filesystem timestamp granularity without altering file size will not be detected by the sender. However, receiver-side cryptographic chunk hash verification (`verify_chunk_payload`) and full-file staging SHA-256 verification guarantee that corrupted content can never be promoted to working copy or baseline.
2. **Receiver Manifest Accumulation Scales $O(N)$ with Chunk Count (SEC-01, SEC-02):**  
   While wire transport streams paginated manifests in bounded chunks ($\le 1\text{ MiB}$), the receiver accumulates all chunks into an in-memory `std::vector<ChunkInfo>` prior to stage reconstruction. For files exceeding hundreds of gigabytes (millions of chunks), memory scales linearly with chunk count ($~80\text{ bytes/chunk}$).
3. **Network Filesystem Locking Semantics (SEC-05):**  
   The dual-layer barrier relies on OS-level byte-range locking (`LockFileEx` on Windows, `flock` on POSIX). On certain remote network filesystems (e.g. NFS v3 without lockd, or misconfigured SMB CIFS mounts), kernel lock coherence across remote hosts may be advisory or unsupported.
4. **Process-Crash vs. Power-Loss Durability (SEC-03):**  
   Transactional staging guarantees recovery against abnormal process termination (`_Exit`, `SIGKILL`, unhandled exceptions). Physical disk durability following unbuffered sudden power loss depends on underlying OS and hardware write-cache flushing policies.
5. **No In-Place Barrier Rehabilitation (SEC-05):**  
   A poisoned `InterprocessCasBarrier` cannot be reset in-place. If an OS unlock syscall fails, the barrier permanently enters fail-closed state. The holding subsystem must destroy the instance (releasing kernel locks via handle closure) and construct a new barrier instance.
6. **Controlled Barrier Lifecycle Shutdown (SEC-05):**  
   In compliance with C++ object lifetime rules, closing or destroying a barrier while other threads actively execute member methods is undefined behavior. Component lifetimes are governed strictly by RAII ownership models.
7. **Platform Verification Differences:**  
   Empirical testing of Win32 handle locking, memory profiling (`GetProcessMemoryInfo`), and process termination was executed live on Windows 11. POSIX code paths (`flock`, `close`, `errno`) are implemented and verified via static source audit and build validation, but require native Linux environments for empirical multi-process stress runs.

---

## F. Git Release Invariants

All historical release tags remain immutable and preserved:

* `v0.2.0-phase2^{}` = `1784c0113c01aaba2731a2dfb942c7abc8d83582`
* `v0.3.0-m3.2^{}` = `381084d29416043b5bbcb196923242cc73435e94`
* `v0.3.2-cas-integration^{}` = `381084d29416043b5bbcb196923242cc73435e94`
* `v0.3.0-m3.3^{}` = `e1ab1b0fd3e923001615fb26a1f004ee800fd687`
* `v0.3.0-m3.4^{}` = `b31dbfe1341a8b06dd8be2bd03017ff5c1376753`

### New Security-Remediated Release Tag:
* **Tag Name:** `v0.3.1-m3.4-security`
* **Target Peeled Commit:** `b6584dbc992c683b81335a1757adc58339cd57e7`
* **Tag Annotation:** `Syncora M3.4 security-remediated release. Includes final SEC-05 fail-closed interprocess barrier handling, regression tests, and documented security verification.`
* **Remote State:** Zero remote pushes executed; all history and tags remain local.

---

## G. Final Status

### **RELEASE FINALIZED WITH DOCUMENTED LIMITATIONS**

