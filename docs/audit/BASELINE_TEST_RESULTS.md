# MerkleChain Automated Testing — Baseline Test Results

**Execution Date:** October 2026  
**Environment:** Windows 11 Enterprise (64-bit), MSYS2 UCRT64 GNU C++17 Toolchain  
**Execution Context:** Independent autonomous test execution directly in workspace  

---

## 1. Test Execution Summary

| Suite Name | Execution Command | Checks / Assertions | Duration | Exit Code | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C++ Core Engine & Regressions** | `.\build\tests.exe` | 218 checks, 1 skipped | 13.80s | `0` | **PASS** |
| **Chunk Hashing & Deduplication Benchmark** | `.\build\chunk_benchmark.exe` | 6 full scenarios (30 trials) | 3.20s | `0` | **PASS** |
| **Host-Client Collaboration E2E** | `powershell -ExecutionPolicy Bypass -File tests/test_collaboration_e2e.ps1` | 34 assertions | 8.82s | `0` | **PASS** |
| **Peer Network Dashboard Integration** | `powershell -ExecutionPolicy Bypass -File tests/peer_dashboard_tests.ps1` | 71 assertions | 9.94s | `0` | **PASS** |
| **Dashboard Smoke & Security Suite** | `powershell -ExecutionPolicy Bypass -File tests/dashboard_smoke.ps1` | 5 core scenarios | 7.91s | `0` | **PASS** |
| **Selective Sync & Algorithm Explorer** | `powershell -ExecutionPolicy Bypass -File tests/test_selective_sync_and_explorer.ps1` | 12 assertions | 7.84s | `0` | **PASS** |
| **Frontend Navigation & Routing Engine** | `node tests/test_dashboard_navigation.js` | 33 views, 7 route tests | 1.85s | `0` | **PASS** |
| **TOTAL** | — | **374 checks / assertions** | **~53.3s** | `0` | **100% PASS** |

---

## 2. Test Suite Breakdowns & Verification Evidence

### 2.1 C++ Core Engine & Regressions (`build/tests.exe`)
* **Total Checks:** 218 passed, 0 failed, 1 skipped.
* **Component Coverage:**
  * **Job Scheduler Priority Heap:** FIFO insertion tie-breaking, mod-time recency weighting, file size scaling, dynamic aging over time, administrative deletion approval gates.
  * **Peer Wire Protocol:** 16-byte magic framing (`MCPEER01`), big-endian length headers, fragmentation decoding, coalesced frame handling, oversized frame rejection, truncated stream detection.
  * **TLS & Mutual Authentication:** Loopback TLS 1.2+ mutual handshake, pinned SHA-256 certificate validation, untrusted CA rejection, TLS handshake timeout enforcement, disconnect during in-flight frame handling.
  * **Bilateral Peer Reconciliation State Machine:** 2-phase commit, durable session IDs, state transition journal validation, stale plan detection, verified rollback upon disconnect/abort, crash recovery replay.
  * **Chunk Sync & Deduplication:** Empty file SHA-256, small edit chunk reuse, exact-boundary edits, append prefix reuse, truncation reconstruction, corrupted chunk fallback to verified whole-file copy, in-flight source/destination mutation detection.
  * **SQLite Activity & Baselines:** Schema migration, parent-child version lineages, atomic baseline restoration, snapshot rollback upon interrupted restore, reference counting for deduplicated blobs.
  * **Collaboration Engine:** PBKDF2 password hashing (100,000 rounds), session token issuance and validation, user suspension and immediate session revocation, workspace creation, member assignments, submission staging, change review diff generation, version publishing, client update staging, Merkle root verification, and path traversal rejection.

### 2.2 Chunk Sync Benchmark Engine (`build/chunk_benchmark.exe`)
Six distinct real-world disk scenarios were executed against 1MB-chunked files to verify byte efficiency, throughput, and verified fallback:

| Scenario | File Size | Method | Median Elapsed | Payload Transferred | Bytes Reused | Reused Chunks |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Unchanged** | 8.00 MB | Whole File | 33.5 ms | 8.00 MB | 0 B | 0 |
| | 8.00 MB | Fixed Chunks | 88.7 ms | **0 B** | **8.00 MB** | 8 (100%) |
| **Small Edit** | 8.00 MB | Whole File | 34.0 ms | 8.00 MB | 0 B | 0 |
| | 8.00 MB | Fixed Chunks | 90.6 ms | **1.00 MB** | **7.00 MB** | 7 (87.5%) |
| **Append** | 8.00 MB (+19B) | Whole File | 36.1 ms | 8.00 MB | 0 B | 0 |
| | 8.00 MB (+19B) | Fixed Chunks | 92.5 ms | **19 B** | **8.00 MB** | 8 (100%) |
| **Truncate** | 5.00 MB | Whole File | 21.5 ms | 5.00 MB | 0 B | 0 |
| | 5.00 MB | Fixed Chunks | 63.3 ms | **0 B** | **5.00 MB** | 5 (100%) |
| **Large File** | 64.00 MB | Whole File | 398.8 ms | 64.00 MB | 0 B | 0 |
| | 64.00 MB | Fixed Chunks | 1015.8 ms | **1.00 MB** | **63.00 MB** | 63 (98.4%) |
| **Binary Data** | 3.00 MB | Whole File | 21.8 ms | 3.00 MB | 0 B | 0 |
| | 3.00 MB | Fixed Chunks | 53.0 ms | **1.00 MB** | **2.00 MB** | 2 (66.7%) |

*Key Benchmark Finding:* Chunk synchronization eliminates between **66.7% and 100%** of logical byte transfers across modifications, with 0 whole-file fallback failures observed across all benchmark trials.

### 2.3 Host-Client Collaboration End-to-End Suite (`tests/test_collaboration_e2e.ps1`)
Verified the complete multi-user collaboration workflow through the live C++ backend:
1. **Host Authentication:** Seeded host account authenticated with PBKDF2 verification, session token generated (`52` chars), role verified as `host`.
2. **Client Provisioning:** Host provisioned client `alice_<guid>` with granular permissions (`submit`, `view_versions`, `download_updates`, `accept_updates`). Verified database persistence.
3. **Client Authentication:** Alice authenticated successfully, session token issued, role verified as `client`.
4. **RBAC Enforcement:** Alice attempted to access `/api/host/clients` and was immediately rejected with HTTP `403 Forbidden`.
5. **Client Submission:** Alice submitted a multi-file project (`document.txt`, `readme.md`, `sub/helper.cpp`). Backend staged submission, verified local Merkle root (`64` hex characters), and recorded submission status as `PENDING`.
6. **Host Review & Working Copy:** Host inspected submissions queue, accepted submission into workspace baseline and working copy. Verified 3 working files populated on disk.
7. **Diff Calculation:** Host edited `document.txt`. Backend computed unified line-by-line diff (`7` change entries), correctly identifying `MODIFIED` change type. Change summary confirmed `1` modified file and `2` unchanged files.
8. **Version Publishing:** Host published immutable release `v1.1-approved` with Merkle root `2f97d9e2a6805489...`. Baseline updated.
9. **Client Update Polling:** Alice polled `/api/client/updates`, received notification of version `ver_b40eb212422bfc90c5a4`.
10. **Client Update Application:** Alice accepted and applied update to local target directory. Target files unpacked, `document.txt` verified against published edits, subfolders verified.
11. **Version History & Audit Log:** Verified `/api/host/workspaces/versions` and `/api/host/activity` recorded submission, edit, and publication events.
12. **Session Invalidation:** Alice logged out. Subsequent requests with Alice's session token were immediately rejected with HTTP `401 Unauthorized`.

### 2.4 Peer Dashboard Integration Suite (`tests/peer_dashboard_tests.ps1`)
* **Assertions Passed:** 71 passed, 0 failed.
* **Coverage:**
  * Loopback daemon startup and CSRF token generation (`64` hex characters).
  * HTML structure verification for all 7 Peer Network views and all Local Workspace views.
  * Zero secret key material verified in served frontend assets.
  * Charcoal/graphite visual aesthetic confirmed without blue dominance.
  * Cross-origin request forgery (CORS / Origin header) validation.
  * Peer configuration validation (IPv4 address, port range, pinned cert hash format, folder accessibility).
  * Peer host listener lifecycle (`STOPPED` -> `LISTENING` -> `STOPPED`).
  * Rejection of unauthorized sync approval without active session.

### 2.5 Selective Sync & Algorithm Explorer (`tests/test_selective_sync_and_explorer.ps1`)
* **Coverage:**
  * File selection scope validation (empty scope rejected, path traversal rejected).
  * Selective synchronization of single file (`file1.txt` updated, unselected `dest_only.txt` preserved).
  * Stale plan invalidation when selection scope changes after preview.
  * Folder-level selective sync (nested `sub1/` synced, `sub2/` excluded).
  * Merkle Tree Explorer real tree depth and leaf hash verification.
  * Scheduler queue preview verifying real priority queue ranking and scores.
  * Chunk & Reuse live metric verification showing non-zero transfer counters.

### 2.6 Frontend Navigation Suite (`tests/test_dashboard_navigation.js`)
* **Coverage:**
  * Exact 33-view parity between HTML containers and JavaScript `validViews` set.
  * Default load URL hash normalization (`#home`).
  * Direct URL deep-linking (`#algorithm`).
  * Invalid route fallback to `#home`.
  * Browser Back/Forward history transitions across views.
  * Safe handling of deprecated route names.

