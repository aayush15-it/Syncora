# Peer synchronization initial assessment — 2026-10-24

This is the source/dependency audit before peer-network changes. No peer code or CLI behavior had been modified when this assessment was written.

## Existing reusable pieces

- `src/scanner.cpp` / `include/merklechain/scanner.hpp`: recursive scan, normalized relative paths, SHA-256 file digests, incomplete-scan flag and warnings; symlinks are skipped. `safe_relative_path` rejects rooted, traversal, and colon/alternate-stream paths.
- `src/hash.cpp`: OpenSSL EVP SHA-256 and deterministic manifest Merkle root.
- `src/chunk_sync.cpp`: fixed-size per-chunk hashes, verified staging reconstruction and whole-file fallback.
- `src/staging_file.cpp` / `src/sync.cpp`: exclusive staging, expected-hash gate, mutation rechecks, exact approval flags, backups, activity events and one-way execution. The comparator preserves destination-only entries and does not infer deletion.
- `src/versioning.cpp` / `src/storage.cpp`: content-addressed snapshots, references, durable restore journal, recovery replay and SQLite activity.
- `src/scheduler.cpp`: deterministic binary max-heap; authorization is not implied by selection.
- `src/web_server.cpp`: separate HTTP service bound explicitly to `127.0.0.1`; it is not reusable as peer transport and must remain isolated.
- `src/main.cpp`: explicit `--local`, loopback `--dashboard`, version/restore commands; legacy `--network` exits with code 3 and a no-listener message.

## Missing peer components

- No peer-specific Winsock transport, TLS/mutual authentication, framed protocol, peer configuration loader, or peer host/client CLI exists.
- No persistent common baseline is stored per peer/folder. Existing manifest comparison is one-way A-to-B and deliberately preserves B-only files; it cannot distinguish initial absence from a deletion.
- No bidirectional conflict planner, approval bound to a peer-plan digest, peer audit identity, or authenticated file transfer exists.
- No peer protocol or conflict tests exist. The current `tests/test_main.cpp` exercises the shared local core, not a second endpoint.

## Dependencies/build constraints

- Queried installed UCRT64 packages: OpenSSL **3.5.2**, SQLite **3.50.4**; `openssl version` reports OpenSSL 3.5.2. The Makefile already links OpenSSL and `ws2_32` and builds C++17 with the existing warning flags. Thus an established TLS dependency is present; no plaintext substitute is necessary.
- No standalone JSON dependency is installed or used by the existing build. Peer configuration/protocol parsing must use a bounded, strict parser or add only a justified small dependency.
- Windows UCRT64 runtime DLL lookup requires the MSYS2 UCRT64 `bin` directory on `PATH` when running from PowerShell. Do not overwrite the active/default executable; build a named alternate target during validation.

## Security and correctness risks to resolve before peer execution

1. Peer transport must be independent of the dashboard and use TLS 1.2+, chain validation, and configured expected peer certificate/public-key pins in both directions. Missing/invalid pins, trust roots, keys, or certificates must fail closed.
2. TLS handshake and frame read/write need finite timeouts; frame/parser code must handle fragmentation and reject malformed/oversized/out-of-order messages before allocating or writing.
3. Remote Merkle roots cannot be accepted without validating the bounded manifest, canonical path uniqueness, file sizes, and SHA-256 fields. Incomplete local scans cannot authorize deletion.
4. First contact has no deletion baseline. Later absence may mean deletion only relative to a committed common baseline; concurrent edit and delete-versus-edit are unresolved conflicts that must preserve both sides and block success.
5. The existing executor is A-to-B and cannot directly execute a remote bidirectional plan. Reuse the staged executor for verified local materialization; do not weaken its approval, recovery, or per-mutation checks.
6. Baseline advancement must be transactional and occur only after all planned transfers, root verification, and unresolved-conflict checks succeed. Interrupted sessions must be retryable without promoting a partial state.
7. Existing restore journal semantics, default local mode, dashboard loopback binding, and `--network` no-listener behavior must remain unchanged.

## Initial staged implementation plan

1. TLS/authentication, strict peer configuration, bounded versioned frame codec, and unit tests.
2. Validated manifest codec plus SQLite peer identity/common-baseline state and deterministic two-sided conflict planner.
3. Approval digest/expiry, authenticated bounded file transfer into staging/cache, existing safe executor/recovery integration, and commit-only baseline update.
4. Explicit `--peer-host`, `--peer-sync`, `--peer-help`; configuration and private-network firewall documentation.
5. Build/regression/protocol tests; local two-endpoint integration only if the environment supports it. Physical two-laptop verification remains separately labeled.

No network listener or peer command is active at this audit stage.

## Follow-up: protocol/configuration groundwork — 2026-10-25

The source now contains a bounded frame codec, strict flat-JSON peer config loader, and OpenSSL TLS-context/authentication helpers. They are linked into the custom peer-stage application target. These additions do not yet provide a socket transport or complete Stage 2: there is no Winsock connect/listen/accept loop, no TLS handshake, no enforced handshake/read/write deadline, and no authenticated session state machine. Config and frame checks were added to the test source but the current executable was blocked by Application Control before any test ran. See `docs/IMPLEMENTATION_STATUS.md` for current counts and exact commands. Do not advance into bidirectional planning or enable a listener until the transport/security stage is implemented and can be validated under authorized execution.

## Follow-up: Winsock TLS transport added — 2026-10-25

Dedicated nonblocking Winsock connect/listen/accept and OpenSSL TLS frame transport is now implemented. It requires both trusted certificate-chain validation and exact certificate SHA-256 pin matching, caps frame data through the existing decoder, and uses configured finite deadlines. Its dedicated loopback tests generate CA-signed test certificates, but the current host denied/timed out the loopback preflight (observed `WSAEACCES` 10013), so no TLS handshake scenario ran. The current full suite still completed its non-network checks with 87 pass, 0 fail, and 2 skips. This is not evidence that transport works at runtime. No peer CLI or listener startup path exists; proceed only after loopback validation can run in an authorized environment.

An offline credential-validation follow-up now constructs `PeerTlsContext` from the generated real certificates before probing loopback and verifies that a mismatched cert/key pair is rejected. Latest full result is 89 passed, 0 failed, 2 skipped. This validates credential loading and pair matching only; all live TLS transport cases remain skipped. No peer CLI or listener startup path exists.

## Bidirectional planner and corrected loopback preflight — 2026-10-25

- Added a standalone planner and SQLite baseline store in `peer_sync`. Planning uses complete, Merkle-validated manifests plus the last common baseline to classify additions, modifications, deletions, and conflicts. It does not mutate either folder or commit the baseline. Incomplete scans are rejected. Delete-versus-modify and concurrent edits remain conflicts until explicit resolution; deletion actions require separate confirmation.
- Plan approval is SHA-256 bound to canonical paths, file metadata, roots, actions, resolutions, per-entry requirements, and aggregate approval/deletion/conflict gates. Static review found the aggregate gates had initially been omitted; the canonical digest now binds them and regression tests tamper with all three.
- SQLite baseline writes replace the root and file rows in one `BEGIN IMMEDIATE` transaction. Reads reconstruct and validate the stored Merkle root. The caller must explicitly commit a reconciled manifest after successful verification; no transfer path currently invokes it.
- The loopback helper now monitors both write and exception readiness and reads `SO_ERROR`. Latest result: `WSAEACCES (10013)` at `getsockopt(SO_ERROR)` after exceptional readiness for `127.0.0.1:54227`, not a select timeout. This confirms access denial at the Winsock API boundary; evidence does not identify the enforcing Windows component. The live TLS test group remains skipped. Offline credential tests ran separately.
- Latest standard full suite: **104 passed, 0 failed, 2 skipped**. The skips are the denied loopback TLS group and staging symbolic-link creation (`ERROR_PRIVILEGE_NOT_HELD`, 1314). Production app build to `build/merklechain-peer-planner.exe` succeeded with no warnings. No two-endpoint test ran, no application listener was started, and `--network` remains disabled.
- Next gate: obtain administrator-approved conditions permitting loopback TCP, execute all TLS tests, and separately resolve symlink privilege coverage. Only then proceed to a staged, approval-bound transfer executor and peer CLI; neither is implemented in the planner phase.

## Stage 4 interface audit and offline manifest codec — 2026-10-25

The current transport exposes authenticated TLS connections and bounded framed messages; authentication is complete before `PeerConnection` is returned open. However, transport does not enforce a multi-message application session state machine. The protocol has frame types for manifests and file data but no established manifest pagination, transfer sequencing, retry token, or bilateral commit protocol.

Reusable local components are `StagingFile` (exclusive sibling staging and expected-hash commit), chunk synchronization (verified local source/destination reconstruction), `execute_plan` (one-way local filesystem executor with authorization, rechecks, recovery copies, activity and final root verification), `ActivityStore`, `VersionStore`, and `PeerBaselineStore`. The local executor cannot directly receive a network stream. The baseline store can persist a caller-supplied reconciled manifest, but is not itself proof that both endpoints committed.

Added a one-frame binary manifest codec to the planner module, capped by the existing 1 MiB frame limit. It validates count and file-size limits, paths, case-folded path uniqueness, digest formats, exact payload consumption, and the complete Merkle root. It preserves modification-time signed bits. Manifests too large for one frame are rejected; pagination remains future work.

Current full test run: **107 passed, 0 failed, 2 skipped**. TLS loopback preflight returns WSAEACCES (10013) at `getsockopt(SO_ERROR)` after exception readiness. Staging symbolic-link creation skips with error 1314. The production executable compiled successfully to `build/merklechain-peer-stage4-prep.exe` with no warnings. No live handshake, file transfer, or two-laptop test ran.

A transfer executor and peer CLI are intentionally not wired yet: safe two-sided commit/rollback and duplicate retry semantics need an explicit session journal and offline failure tests before networking may mutate user files. The live TLS test group also remains unavailable under the current socket environment. No host listener was started, and the old `--network` command stays disabled. Current exact laptop commands are unavailable because those CLI commands do not exist; the example config in `docs/CONFIGURATION.md` remains illustrative only.

The final post-hardening run retained **107 passed, 0 failed, 2 skipped**. The live TLS preflight port was `127.0.0.1:55736` and `getsockopt(SO_ERROR)` returned WSAEACCES (10013). Manifest codec validation now explicitly rejects invalid UTF-8 and trailing separators. Production was force-rebuilt successfully; test-only hook symbols remain absent.
