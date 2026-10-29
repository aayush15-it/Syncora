# MerkleChain feature audit — 2026-10-24

This audit is based on source and runtime evidence. “Tested” refers to the currently observed test suite and local dashboard smoke, not LAN behavior or features not represented by the backend.

| Capability | Status | Evidence and limits |
|---|---|---|
| Recursive file scan, SHA-256 and deterministic Merkle root | Implemented and tested | `src/scanner.cpp`, `src/hash.cpp`; regression coverage includes recursive scan, repeatable hashing, empty files, deterministic roots, and incomplete-scan refusal in `tests/test_main.cpp`. |
| Local A-to-B comparison, approval and guarded execution | Implemented and tested | `src/sync.cpp`, `src/web_server.cpp`; the executor validates each mutation at execution, stages and verifies content, creates recovery copies, records activity, and verifies final root. Core suite and disposable dashboard smoke passed. |
| Destination-only preservation | Implemented and tested | `compare_manifests` emits PRESERVE for B-only files; sync and dashboard smoke verify those files remain intact. Current comparison does not produce DELETE operations. |
| Staging and recovery protections | Implemented but incompletely tested | `src/staging_file.cpp`, `src/sync.cpp`, `src/versioning.cpp`; hash gates and recovery/journal cases are in the core suite. Windows symlink staging case remains skipped with error 1314; ancestor reparse-point replacement and final absolute-rename races remain limitations. |
| Fixed-size chunk reuse and whole-file fallback | Implemented and tested | `src/chunk_sync.cpp`; default chunk size is 1 MiB, manifests have per-chunk SHA-256 and full-file SHA-256 checks, reconstruction uses staging, malformed metadata/failures fall back to verified whole-file copy. No content-defined chunking. |
| Transfer accounting | Implemented in Local Mode; dashboard-runtime pending | Executor job results and migrated SQLite activity now expose payload bytes, source bytes processed, bytes reused, staging bytes written, chunk size, total/reused chunks, and fallback reason. These are logical accounting counters, not physical disk I/O or network traffic. Current UI data is wired to those backend fields but the latest browser/API smoke could not run. |
| Rabin/content-defined chunking | Not implemented | Current chunk module uses fixed-size ranges; no Rabin fingerprint implementation or rolling boundary code was found. |
| Binary-heap priority scheduler | Implemented and tested | `src/scheduler.cpp`, `include/merklechain/scheduler.hpp`, `docs/SCHEDULER.md`; operation base weights, size, modification recency, aging, and FIFO tie-breaking are implemented. Scheduler unit tests passed. No throughput/load adaptation. |
| Adaptive scheduling | Not implemented | Priority is deterministic from configured/static weights, size, mtime, and queue age. It does not learn or dynamically retune weights from observed performance. |
| Version snapshots and parent links | Implemented and tested | `src/versioning.cpp`; version metadata contains root, timestamp, file count and parent ID. Snapshot data uses complete content objects, and restore verifies data and final root. Database reopen, shared references, recovery, and restore tests are in the core suite. |
| Differential patch/delta storage | Not implemented | Snapshot files reference full SHA-256 content objects; no patch/delta reconstruction format is implemented. Parent links are history metadata, not diffs. |
| Persistent content-addressed deduplication | Implemented and tested within a local VersionStore | SQLite `content_objects` is keyed by SHA-256, `version_files` references objects, triggers/reconciliation maintain counts, and tests cover shared references. This is local persistent snapshot-object deduplication; it is not cross-device/global network deduplication. |
| Local HTTP dashboard and native picker | Implemented; current UI built, runtime review pending | `src/web_server.cpp`, `src/folder_picker.cpp`, `web/`; backend API remains loopback-only and existing API smoke is historical. The current screenshot-referenced UI is compiled/statically checked; latest dashboard-test stopped before assertions due PowerShell AuthorizationManager, and browser socket inspection is blocked in this environment. Native folder selection/cancel still needs interactive validation. |
| Dashboard API validation/security | Implemented; smoke tested, not comprehensively fuzzed | Server binds IPv4 loopback, bounds requests, validates JSON fields, Host/Origin and CSRF, keeps the exact plan server-side, rescans before sync, and uses guarded restore grants. It is a single-threaded local service; it is not peer authentication or a substitute for OS security. |
| Owner-client authorization, pairing and folder permissions | Not implemented | No peer identities, pairing protocol, revocation or network authorization backend exists. |
| TCP manifest/file exchange and two-laptop sync | Not implemented | `--network` remains disabled and starts no listener. |

## Current validation evidence

- UCRT64 production target compiled and linked without warnings to `build/merklechain-redesign.exe`; default `build/merklechain.exe` could not be replaced because Windows returned Permission denied. The existing file was not removed or altered.
- `mingw32-make test`: 78 passed, 0 failed, 1 skipped. The skipped test is the staging symbolic-link check (Windows error 1314), not a pass.
- `node --check web/app.js`: passed.
- Disposable loopback smoke through the normal Make run target: redesigned HTML served; scan returned roots, source/destination file hashes and priority queue fields; an unapproved sync was rejected; approved sync verified final root and preserved B-only content. This did not exercise an actual browser session or the native picker UI.
- Local loopback dashboard is distinct from disabled Network Mode. No peer listener was started.

## Final dashboard execution gate — 2026-10-24

The current source builds, and the shared core test suite passes (78 passed, 0 failed, 1 skipped). The reproducible dashboard smoke script and Make target are present, but Windows Application Control blocked launching the current rebuilt application. The earlier loopback smoke used a prior build and is not evidence for the final scheduler-preview refinements. Dashboard browser/API validation of the current executable is therefore pending administrator-approved signing or managed-policy authorization. Native folder picker UI and visual browser review also remain pending.

## Screenshot-referenced dashboard UI update — 2026-10-24

- `web/` now contains a vanilla HTML/CSS/JS graphite/slate/silver/ice-blue multi-page console. Backend-driven roots, file hashes/counts, scheduler order/priority, chunk accounting, versions and SQLite activity are shown only when available. Devices/pairing and live benchmark results are labeled unavailable; no fixtures or hard-coded sample metrics are presented.
- The UI has native folder-picker controls and explicit review/approval; C++ synchronization and restore safety remain authoritative. Network Mode stays disabled.
- Core test target executed: **78 passed, 0 failed, 1 skipped** (Windows symlink privilege error 1314). Current dashboard smoke did not execute: the `dashboard-test` Make target stopped at PowerShell `AuthorizationManager check failed` before assertions. The ordinary run target started a new instance on loopback port 47832; current browser rendering/API behavior could not be confirmed because this environment denies local socket probes and disables browser control. This revision is therefore built and statically checked, but not dashboard-runtime-validated.
- See the latest sections in `docs/IMPLEMENTATION_STATUS.md` and `docs/TEST_PLAN.md` for exact commands, limitations, and release checks.

