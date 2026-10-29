# Test plan and results

Entries below record historical milestones; the newest dated result is
authoritative for current execution status.

Run `mingw32-make test` only where execution of the project binary is authorized. Baseline before versioning changes: 14 checks passed on 2026-10-24. The expanded suite compiles and adds checks for legacy migration fields, version parent links, restore approval, multi-revision edit/deletion restoration, timestamp restoration and rollback, database reopen/refcount repair, corrupt target and rollback-snapshot objects, rollback after a mid-restore destination conflict, pre-restore snapshot recovery, retry after blocked replay, child-process termination after the first verified file operation followed by restart recovery, injected rollback failure and retry, simulated journal recovery across database reopen, protection of rollback versions referenced by active journals, shared-content counts, and approved leaf-version deletion/collection. The earlier test invocation was blocked by Windows Application Control (error 4551); the current suite was rebuilt but not launched because no authorized execution environment is available. No expanded test result is claimed. The child-process and fault-injection cases are test-only and are not enabled in the production executable (`nm -C` found zero hook symbols in the production binary and two in the test binary). A prior separate CLI run covered manual approval and paths with spaces.

Uncovered planned areas include runtime validation of the new subprocess/fault-injection cases, corrupted per-file backup injection (corrupt object-store recovery content is covered in source), permission/reparse-point cases, scheduler behavior, chunking/reconstruction, content-index reconciliation, protocol framing/authentication, HTTP/API behavior, and two-process LAN transfer. Results must be updated from actual command output; no benchmark results are currently claimed.

The scheduler now has 11 compiled checks for empty queues, operation ordering, FIFO ties, aging, modification recency, extreme timestamp handling, size weighting, change approval, explicit delete confirmation, and a 5,000-job heap. They have not executed. They are standalone and do not call the synchronization or restore pipelines.

## Authorized Windows execution options reviewed (2026-10-24)

The known event details are Windows Application Control policy VerifiedAndReputableDesktop, Event 3077, and Event 3089 with zero signatures; error 4551 blocked the unsigned test executable. Microsoft documents that Smart App Control blocks unknown unsigned code by default. Administrator-approved ways forward are to use a properly signed build recognized by Smart App Control, or have the device's authorized administrator/IT owner review and authorize the specific test binary using the applicable managed App Control policy. For managed devices, Microsoft documents managed file rules/supplemental policies (when allowed by the base policy) and managed-installer deployment. Managed-installer authorization applies only when the organization has configured and approved that deployment mechanism. Do not change Smart App Control settings, self-authorize an unsigned executable, or use another launcher to get around policy.

References: [Smart App Control overview](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview), [App Control policy and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create), [Managed installer authorization](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer).

## Initial peer protocol/configuration test attempt — 2026-10-25

- Build command: `& 'C:\msys64\ucrt64\bin\mingw32-make.exe' TARGET=build/merklechain-peer-stage2.exe` — completed successfully; application linked without compiler warnings reported.
- Test command: `& 'C:\msys64\ucrt64\bin\mingw32-make.exe' test` — test executable compilation completed without warnings. The test recipe launch failed with Windows Application Control error 4551 (`make (e=4551)`), before `main` or any assertion ran.
- Current-source counts: **0 executed, 0 passed, 0 failed, 0 skipped**. The existing 78 passed / 0 failed / 1 skipped result is historical and predates all peer protocol/configuration changes.
- New but runtime-unverified checks cover binary fragmented frames, coalesced and empty frames, malformed magic/version/type, oversized input/output, truncated end-of-stream, and strict host configuration parsing (role mismatch, unknown property, duplicate property). These do not exercise a TLS socket or live certificates; the current test fixtures contain placeholder PEM text.
- Before further peer stages: obtain authorization from the device administrator to sign the specific test executable with a publisher accepted by the active policy, or to authorize its hash/publisher through the managed App Control process. Do not execute via another launcher, alter Windows policy, or self-authorize. Then rerun the complete normal `test` target and record its printed totals. A test skip is not a pass.
- Separate peer-stage gate: add real TLS client/server handshake, pin/trust failure, timeout/disconnect, authenticated transport and two-endpoint tests before enabling any host/client command. Until then, no listener or peer-sync CLI is available, and `--network` remains disabled.

## Winsock TLS transport current revision — 2026-10-25

- `& 'C:\msys64\ucrt64\bin\mingw32-make.exe' test` completed normally and executed the full suite: **87 passed, 0 failed, 2 skipped** (exit 0). The standard target compiled `tests/test_main.cpp` and `tests/peer_transport_tests.cpp`, then launched `build/tests.exe`.
- Protocol framing/configuration and all prior Local Mode regression checks executed. The new TLS cases generate real test-only RSA identities and certificates through OpenSSL APIs, but their loopback group was skipped at its preflight because the operating system denied/timed out local TCP; an earlier raw attempt returned `WSAEACCES` 10013. No TLS handshake test ran. The separate staging symlink check remains skipped with error 1314. Skips are not included in the pass count.
- Production target `build/merklechain-peer-transport.exe` built successfully with C++17 warning flags and no warnings. `nm -C` found no test-only raw/partial transport hooks or restore/chunk fault-injection hooks in that executable.
- Required follow-up: run the complete suite in an administrator-approved environment where loopback TCP is permitted, confirm every TLS case actually executes, and resolve symlink-test permission separately through an approved configuration. Do not change or bypass policy from this task.
- Test history: an intermediate run reached 90 passed / 3 failed and then aborted because TCP connects were blocked/timed out; raw loopback produced `WSAEACCES` 10013. The tests were hardened to avoid false-positive rejection assertions and to report denied loopback as skipped. The final current-source run is the 87/0/2 result above; the intermediate failures are retained here for traceability.
- Still pending before CLI: real TLS runtime validation, handshake/message-order session state machine, host/client commands, persistent bidirectional baseline and conflict plan, exact-plan approval, safe transfer, and authorized two-endpoint integration. Network Mode remains disabled.

### Offline TLS credential validation — 2026-10-25

- The latest full test execution completed: **89 passed, 0 failed, 2 skipped** (exit 0). Two new checks executed with real generated credentials: OpenSSL loaded matching CA-signed host/client certificate and key files, and rejected a mismatched local certificate/private-key pair.
- The loopback TLS group still skipped at the bounded TCP preflight because the operating system denied/timed out loopback. Consequently, chain/pin checks during an actual handshake, TLS timeout handling, frame transport, and disconnect behavior remain unvalidated at runtime. The separate symbolic-link test still skipped with Windows error 1314.

## Latest runtime results — 2026-10-24

- The earlier unsigned-binary execution block is no longer the current result. The user ran the normal test target in an environment where execution was permitted, and this continuation reran it successfully:
  `& C:\msys64\ucrt64\bin\mingw32-make.exe test` — exit 0; 44 checks passed, 0 failed. This target rebuilt and launched `build/tests.exe`; its output confirms actual execution.
- The initial report in this continuation failed with `NOT NULL constraint failed: version_records.merkle_root`. `create_snapshot` now explicitly binds the already-computed manifest Merkle root to INSERT parameter 5 with checked SQLite status. The regression assertion verifies exact roots persisted for three newly created versions. The schema constraint is unchanged.
- The successful run includes scheduler authorization checks, version/root persistence, multiple revision restoration, file deletion/addition, timestamps, repeated and restart journal replay, actual child-process interruption, injected rollback failure and retry, corrupt stored content rejection/retry, and refcount repair after reopen.
- Final production build: `& C:\msys64\ucrt64\bin\mingw32-make.exe` — exit 0; no compiler warnings. Production remains built with test fault injection disabled. Test build uses `-DMERKLECHAIN_TESTING`.
- No tests are currently reported as pending within the implemented versioning/recovery and scheduler unit-check scope. Permission/reparse-point edge cases and other uncovered areas listed above remain future validation. This does not validate chunk synchronization, benchmarking, dashboard/API, or network behavior.
- Scheduler integration and chunk synchronization were not implemented. Network Mode remains disabled and no listener was started.

## Local Mode scheduler integration — 2026-10-24

- Added executable integration coverage for mixed Add/Modify/Delete scheduling and exact priority order, destination-only preservation, Delete recovery copy, and resulting Merkle root; a stored pre-sync snapshot restores the original tree successfully.
- Added integration checks for equal-score FIFO ordering, aging across older/newer enqueue timestamps, change-approval rejection, Delete rejection without explicit deletion confirmation, conflicting file/directory plan rejection before dispatch, source/destination mutation rejection, and partial execution failure.
- Final full test target after integration: `& C:\msys64\ucrt64\bin\mingw32-make.exe test` — exit 0; 51 passed, 0 failed. All listed checks executed using disposable directories under `build/test-fixtures`.
- The production build and absence of test-only fault-injection symbols are recorded in the newest implementation-status entry. No chunk-transfer test or Network Mode test was run or claimed.

## Fixed-size chunk synchronization — 2026-10-24

- The expanded test source adds disposable fixture checks for unchanged files; edits near the beginning, middle, and end; exact chunk boundaries; appended data; truncation; empty and small binary files; large multi-chunk content; corrupted/truncated staged chunks; missing/incompatible manifest metadata; and a source mutation during transfer.
- The normal test command was attempted: `& C:\msys64\ucrt64\bin\mingw32-make.exe test`. The test executable compiled, then Windows Application Control blocked its launch with error 4551. No expanded test case executed and there is no runtime pass/fail count for chunk synchronization. The earlier 51/0 result predates these chunk changes.
- Compile-only test build: `& C:\msys64\ucrt64\bin\mingw32-make.exe build/tests.exe` — exit 0, no reported warnings. Production build: `& C:\msys64\ucrt64\bin\mingw32-make.exe` — exit 0, no reported warnings. Symbol inspection found no restore or chunk fault-injection hooks in `build/merklechain.exe`.
- Do not benchmark until the full correctness suite runs and passes in an authorized environment. Do not change Windows security policy or use an alternate execution path to evade the block.
- See `docs/CHUNK_SYNC.md` for format and safety behavior. Restore-journal tests, scheduler integration, and final-root coverage are retained in the expanded suite but were not re-executed in this blocked run.

## Chunk synchronization review and current runtime results — 2026-10-24

- Static review covered chunk-size bounds, descriptor-count and range validation, offset/length arithmetic, empty/exact/partial boundaries, stream conversion limits, hash comparison, staging cleanup, fallback, source/destination mutation checks, and commit ordering. Source descriptors must cover exactly `[0, file_size)` with contiguous ranges and expected chunk lengths. Staging passes per-chunk and full-file SHA-256 checks before the executor can commit it.
- Added fault-injected malformed-manifest checks: missing descriptor, overlap, incorrect final chunk length, and malformed chunk digest. Each takes verified whole-file fallback. Existing cases cover corruption/truncation, missing/incompatible metadata, source mutation, empty/small/exact/partial/large/binary files, append, truncation, and edits at multiple positions.
- Final `& C:\msys64\ucrt64\bin\mingw32-make.exe test`: **exit 0; 70 passed, 0 failed**. The current suite executed; the earlier 51/0 result predates chunk synchronization and the 66/0 result predates the four malformed-manifest cases.
- Production build `& C:\msys64\ucrt64\bin\mingw32-make.exe`: **exit 0**, no reported warnings. Production symbol inspection found no `restore_fault_point`, `set_restore_fault_point_for_testing`, `chunk_fault`, or `set_chunk_fault_point_for_testing` symbols.
- Reproducible `benchmark` target completed with deterministic fixtures and full-hash verification. 1 MiB chunk results: unchanged 8 MiB: 0/8 MiB payload bytes; small edit in 8 MiB: 1/8 MiB; edit in 64 MiB: 1/64 MiB; binary edit in 3 MiB + 17 bytes: 1 MiB + 17 bytes / 3 MiB + 17 bytes. This measures payload bytes only, not wall-clock or network throughput.
- Benchmarking ran only after a complete correctness suite passed. The fixture runner writes under and removes only `build/chunk-benchmark-fixtures`.
- Remaining risk: staging symlink rejection and file creation are separate operations, so a concurrent local actor with write access to the destination directory could race the temporary path. No remote manifest parsing or network transfer is involved. Version restoration explicitly remains whole-file and restore-journal semantics are unchanged.

## Windows staging handles and current execution status — 2026-10-24

- The staging helper uses Windows `CreateFileW` with `CREATE_NEW` and `FILE_FLAG_OPEN_REPARSE_POINT`; an existing leaf fails creation atomically. It holds the created file and parent directory handles, rejects a reparse parent/leaf, validates the resolved parent, prevents external write/delete opens while active, and performs rename and cleanup through the owned handle.
- Direct runtime regression run: **75 passed, 0 failed**. It covered file and directory collisions, failed creation, owned-file cleanup, handle-based commit, and quarantine cleanup. Symbolic-link creation was attempted using both Windows flags and skipped with OS error 1314 (required privilege unavailable). This run predates byte-accounting instrumentation and an additional executor-level collision assertion.
- Current source revision build: production and test compilation both succeeded with no reported warnings. The current test executable was launched only through the normal `mingw32-make test` target; Application Control blocked it with error 4551. Current-source runtime validation is pending, with no pass/fail count claimed for that build.
- Test-only hook scan on `build/merklechain.exe` returned no matches. No security settings or alternate execution methods were used.
- Enhanced benchmark compilation succeeded. `mingw32-make benchmark` then attempted its normal target launch and was blocked with error 4551. No enhanced benchmark results are available. Its output distinguishes timed values, measured byte counters, scratch estimates, and unavailable process peak-memory measurement.
- Remaining staging boundary limitation: the leaf uses atomic exclusive creation and is held against substitution, but ancestor components still use path-based Win32 lookup and the commit target is absolute. Automatic review rejected the proposed native relative-create and wider ancestor-handle rewrites as unvalidated/high-risk; those edits were not applied. The current evidence does not establish protection against a concurrent ancestor reparse-point replacement during path resolution.

## Current staging revision — 2026-10-24

- The current production, test, and benchmark targets compiled successfully via the explicit MSYS2 UCRT64 Make executable (each exit 0; no warnings reported). Production symbol inspection found no restore/chunk test fault-injection symbols.
- Static-only changes: `StagingFile::commit_to` now verifies the caller-provided expected SHA-256 itself before handle rename. A new mismatch regression assertion is compiled. Explicit `discard()` reports handle deletion failure, and the executor appends cleanup errors to the job diagnostic. Parent directory open sharing no longer allows ordinary delete/rename while its handle is held.
- No binary was launched in this turn. Current runtime counts: executed 0, passed 0, failed 0, skipped 0. The known Smart App Control/Application Control error 4551 requires administrator-approved signing or managed policy authorization for the specific binary. Do not attempt alternate launch methods.
- Symlink test status: a prior attempt skipped after Windows error 1314 (`ERROR_PRIVILEGE_NOT_HELD`). Run it in an administrator-approved environment with Developer Mode for the unprivileged symlink flag or an approved `SeCreateSymbolicLinkPrivilege` assignment. Do not change local security settings without approval. References: [CreateSymbolicLinkW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsymboliclinkw), [Privilege constants](https://learn.microsoft.com/en-us/windows/desktop/secauthz/privilege-constants).
- Historical 75 passed / 0 failed predates byte accounting and executor collision assertion; it also predates this commit-time verification test. It is not a result for current sources.
- Benchmark execution remains gated on a passing current full suite. No timing, memory, or byte-accounting measurements are claimed for the present revision.
- Residual risk: ancestor components and the final absolute rename target use ordinary Win32 path resolution. No claim is made against concurrent ancestor reparse-point replacement. See `docs/CHUNK_SYNC.md` and the latest implementation-status entry.

### Build recheck — 2026-10-24

All three normal UCRT64 build targets were rechecked and returned exit 0 (`all`, `build/tests.exe`, and `build/chunk_benchmark.exe`; each reported up to date). This is compile/build status only. No current-revision tests or benchmark were executed. Error 4551 and administrator-approved execution remain unresolved.

### Release-gate status confirmation — 2026-10-24

Current revision: **0 executed, 0 passed, 0 failed, 0 skipped**. The symlink check has a separate outstanding permission issue: historical error 1314 caused a skip, not a pass. First obtain administrator approval for executing the test binary under the device's signing or managed App Control policy; also run the symlink test in an approved environment with Developer Mode or the approved symbolic-link user right. Then run the full suite; run the benchmark only after it passes. The ancestor reparse-point race remains unresolved, and Network Mode stays disabled.

## Dashboard and native folder picker — 2026-10-24

- Build: latest dashboard application sources compiled/linked to `build/merklechain-dashboard.exe`. Default `all` relink remains blocked because Windows denied replacing `build/merklechain.exe` (Permission denied); resolve the file lock/permission and relink default target before release. `node --check web/app.js` passed.
- Core suite: `mingw32-make test` executed; **78 passed, 0 failed, 1 skipped**. Skip: staging symlink creation unavailable with Windows error 1314; do not count as pass.
- Manual authorized loopback smoke passed against disposable folders: static serving/traversal denial, origin and JSON validation, root/path validation, approval rejection, stale and duplicate plan rejection, approved sync/final Merkle verification, destination-only preservation, activity/version listing, guarded restore, loopback-only bind.
- Dashboard has no dedicated automated integration tests. Native picker compiled but its selection and cancellation were not exercised; browser UI interactions/visual review remain pending. Existing smoke used direct HTTP requests, not the browser JS.
- Manual smoke covered ADD and preservation, not a Delete operation; the current comparison engine does not emit Delete jobs. The handler requires explicit deletion confirmation if one is supplied.
- Network Mode stayed disabled; no peer listener was started. Local dashboard binds only to `127.0.0.1`.
- Release follow-up: resolve default output overwrite denial, relink, then manually exercise browser scan/approval and native Browse selection/cancel. Keep existing Smart App Control-approved test execution policy; historical symlink privilege issue remains separate.

## Dashboard redesign check — 2026-10-24

- `web/app.js` syntax check passed with Node `--check`.
- Application source built and linked successfully to `build/merklechain-redesign.exe` with the UCRT64 Makefile and no compiler warnings. Default target relink was blocked by Windows `Permission denied` replacing existing `build/merklechain.exe`; resolve the output lock/permission before distributing the default artifact.
- Full existing suite executed: **78 passed, 0 failed, 1 skipped**. The skip was staging symbolic-link creation (error 1314); dashboard-specific UI tests are not part of this suite.
- Disposable loopback API smoke via normal Make target passed: assets/pages served, scan response exposed roots/file hashes/scheduler queue inputs, unapproved sync rejected, approved sync completed with final root verification, and destination-only content was preserved.
- Pending manual checks: browser visual/interaction review, native Browse dialog selection and cancel, and dashboard DELETE confirmation (current comparator does not generate Delete jobs). The dashboard is single-threaded and reports no live transfer progress until the executor returns; its UI does not animate invented progress.
- For the full evidence and classifications, see `docs/FEATURE_AUDIT.md`. No Network Mode was enabled or tested.

## Final dashboard smoke attempt — 2026-10-24

- Core tests: **78 passed, 0 failed, 1 skipped** (symlink creation, OS error 1314). Node JavaScript syntax check passed.
- `mingw32-make dashboard-test TARGET=build/merklechain-redesign-release.exe` reached the smoke script, but Application Control blocked `Start-Process` before the app launched. Current dashboard smoke counts are 0 executed; no page/API assertion passed or failed in this attempt. Do not treat the prior build’s direct loopback smoke as validation of this final binary.
- Obtain administrator-approved signing or managed-policy authorization for the current application binary, then rerun the documented `dashboard-test` target. Also manually review browser interaction and native folder-picker selection/cancel. Do not use another launcher to work around the block.

## Current dashboard revision — 2026-10-24

- `node --check web/app.js`: executed successfully.
- Production app linked as `build/merklechain-ui-final.exe` with the UCRT64 Make target; test and benchmark targets compiled. Production symbol inspection found no test-only fault-injection symbols.
- `mingw32-make test`: **78 passed, 0 failed, 1 skipped**. Skip: staging symlink creation returned Windows error 1314. The first run had 77 passed / 1 failed / 1 skipped; the failed source-mutation case had an invalid expectation that a rejected partial transfer reports complete staging metrics. Its assertion now checks rejection, zero credited payload and reuse, and unchanged destination; the full suite was rerun and completed with 78/0/1.
- `mingw32-make dashboard-test TARGET=build/merklechain-ui-final.exe`: failed before tests began with PowerShell `AuthorizationManager check failed`; dashboard assertions executed: 0. No PowerShell policy changes or alternate script launch were attempted.
- Normal `run-dashboard` target launched `build/merklechain-ui-final.exe --dashboard 47832` and remains active in the current session. Direct loopback probes are denied by this environment's socket sandbox. Browser control reports local browser use disabled. Therefore the current served page and interactions remain unverified. The prior process/tab on port 47831 was not stopped because its executable could not be identified.
- Benchmark was not run. Run it only after correctness and dashboard validation gates as appropriate. Network Mode remains disabled.

### Current execution status

Core tests: **78 passed, 0 failed, 1 skipped** (actual execution). Dashboard smoke: **0 assertions executed** due PowerShell AuthorizationManager block. Browser UI: not runtime-verified. Build success is not UI runtime evidence.

### Next action

Open `http://127.0.0.1:47832/` in an authorized browser session and inspect the new page; run the dashboard smoke target in an authorized PowerShell environment. Do not stop port 47831 unless its process identity is confirmed. Then manually verify the native picker and guarded version restore flow.
# Peer planner and transport gate — 2026-10-25

Final command executed after the plan-approval digest regression fix:

```powershell
& 'C:\msys64\ucrt64\bin\mingw32-make.exe' test
```

Result: **104 passed, 0 failed, 2 skipped**, exit code 0.

- Executed: protocol and strict configuration checks; 2 offline OpenSSL credential checks; bidirectional planner/baseline tests; staging and Local Mode checks; chunk-sync checks; activity/versioning and restore-journal recovery checks.
- Skipped TLS transport group: the test preflight bound its disposable listener on `127.0.0.1:54227`, then nonblocking connect readiness indicated an exceptional result. `getsockopt(SO_ERROR)` returned `WSAEACCES (10013)`. The probe watches both writability and exceptional readiness, so this is no longer the earlier false timeout classification. The exact enforcing Windows component is not known. No live TLS assertions are counted as passed.
- Skipped staging symbolic-link/reparse-point case: Windows error 1314 (required privilege unavailable). This is separate from loopback access and is not counted as passing coverage.
- The 2 offline credential checks did execute: generated trusted host/client credentials loaded, and a mismatched local certificate/key was rejected. These do not substitute for runtime TLS handshake/pin/timeout/frame tests.
- Planner unit tests cover both-side first-sync additions, baseline changes, independent edits, deletion inference from the baseline, concurrent edits, delete-versus-modify, incomplete scans, conflict resolution, deterministic digest and approval rebinding, aggregate authorization-flag tampering, duplicate paths, non-mutation, and SQLite baseline reopen/isolation.
- Real two-endpoint network integration: **0 executed**. A disposable listener was created solely by the test preflight; no production peer listener was started. `--network` remains disabled.

Production build command:

```powershell
& 'C:\msys64\ucrt64\bin\mingw32-make.exe' TARGET=build/merklechain-peer-planner.exe
```

Result: exit code 0, linked successfully with C++17 warning flags and no compiler warnings reported. Build success does not validate live network transport.

## Required authorized rerun

Run the standard test target in an administrator-approved environment where loopback TCP is permitted for the test process. Do not weaken, disable, or evade Windows policy. Confirm the TLS group reaches its handshake tests. For reparse-point coverage, separately arrange an approved Developer Mode or symbolic-link privilege configuration; do not treat its 1314 skip as a pass. Only after required correctness tests execute and pass should peer transfer or CLI work proceed.

## Stage 4 offline protocol groundwork — 2026-10-25

Latest full test command:

```powershell
& 'C:\msys64\ucrt64\bin\mingw32-make.exe' test
```

Result: **107 passed, 0 failed, 2 skipped**, exit 0.

- Added offline manifest codec assertions: valid encode/decode including signed timestamp bit preservation; reject truncated and trailing payloads; reject traversal path and configured file-size excess.
- TLS transport group remains skipped after test listener bind; connect completion reports `WSAEACCES (10013)` from `getsockopt(SO_ERROR)` for `127.0.0.1:65334`. Offline certificate tests pass as part of the suite, but no handshake or transport assertion ran.
- Staging reparse-point assertion remains skipped on error 1314.
- Production build: `& 'C:\msys64\ucrt64\bin\mingw32-make.exe' TARGET=build/merklechain-peer-stage4-prep.exe` — exit 0, no compiler warnings reported.
- File transfer tests: 0 executed. Physical two-laptop tests: 0 executed. The manifest codec does not constitute transfer validation.

### Current command availability

Peer configuration parsing exists, but no peer CLI is implemented. Do not run the sample `--peer-host` or `--peer-sync` commands yet. Laptop A/B end-to-end procedure is pending a mutation-safe transfer/session protocol, authorized TLS loopback execution, transfer tests, and baseline/recovery validation. Existing `--network` remains disabled and starts no listener.

### Final current-source rerun — 2026-10-25

After adding UTF-8 and trailing-separator validation to the bounded manifest codec, the complete standard target ran again: **107 passed, 0 failed, 2 skipped**, exit 0. The TLS group skipped with WSAEACCES (10013) from `getsockopt(SO_ERROR)` at `127.0.0.1:55736`; the separate staging symlink skip remains Windows error 1314. No file transfer or physical endpoint test ran. Production target was force-rebuilt successfully with no warnings.

## Bilateral peer session journal — current validation (2026-10-25)

Command executed:

```powershell
& 'C:\msys64\ucrt64\bin\mingw32-make.exe' test
```

Result: **126 passed, 0 failed, 2 skipped** (exit 0).

- Executed session-journal unit checks exercise local SQLite transitions, identity and plan binding, approval/deletion authorization, preparation/commit gates, result-root verification, duplicate/stale acknowledgments, one-sided commit recovery advice, rollback/abort agreement, restart by closing and reopening SQLite, and retention-release conditions.
- The reopen scenario is a database close/reopen simulation. It does not kill the process during a filesystem mutation and does not validate power-loss durability or an actual peer executor.
- Live TLS transport group: **skipped**, not passed. The disposable loopback test reached exceptional connect readiness and `getsockopt(SO_ERROR)` returned **WSAEACCES (10013)** for `127.0.0.1:57249`. Two offline credential checks ran, but TLS handshake, pin/trust rejection over a handshake, deadlines, frames, and disconnect tests did not execute.
- Staging reparse-point regression: **skipped**, not passed, because Windows returned error **1314** (required privilege unavailable).
- Actual peer file-transfer tests: **0 executed**. Two-laptop integration tests: **0 executed**.

Production build check:

```powershell
& 'C:\msys64\ucrt64\bin\mingw32-make.exe' TARGET=build/merklechain-peer-session.exe
```

Exit 0; Make reported target up to date. The already-linked production executable includes `build/peer_session.o`; test-only fault-injection symbol search returned no matches. This is a build/artifact check, not network validation.

### Required next validation

The session journal is not coupled to a transfer executor or actual recovery files. Before adding peer CLI or permitting mutation, integrate journal transitions with staging, verified rollback artifacts, version/activity records, commit retry, and idempotent baseline advancement. Then run live TLS and end-to-end peer tests in an administrator-approved environment that permits loopback for the test process. Resolve error 1314 through a separately approved symbolic-link privilege configuration. Do not alter or bypass Windows policy. `--network` remains disabled and no production listener was started.
