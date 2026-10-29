# Bilateral peer transaction and recovery design

## Scope

This document defines an offline-tested session journal before any peer operation is allowed to mutate user files. It does not claim distributed atomicity. Two file systems and two SQLite databases cannot participate in one atomic commit with the current architecture.

## Proposed sequence

1. **Created** — persist a random session ID, local/remote peer identities, and timestamps before network work.
2. **Authenticated** — only after the TLS connection has completed mutual CA and pin verification. Bind the authenticated remote identity to the configured identity and session.
3. **ManifestsValidated** — exchange bounded manifests; validate completeness, path safety, hashes, roots, and the same committed baseline on both sides.
4. **PlanAgreed** — each side independently computes the plan; exchange and compare the exact plan hash and expected reconciled root. A mismatch terminates before preparation.
5. **ApprovalPending** — store approval only when bound to session ID and plan hash. Deletion confirmation is a distinct flag. Rejection aborts before any destination mutation.
6. **Prepared** — each peer has durably recorded verified staged inputs, recovery material, and its prepare acknowledgment. Both prepared flags are required before entering commit coordination.
7. **CommitPending** — durable decision to finish the agreed plan. Each local file commit is individually staged and hash-verified; the peer records its own commit result. Recovery copies and journal records remain retained.
8. **Committed** — reached only after local commit verification and a matching authenticated peer acknowledgment bind the same session ID, plan hash, and expected final root. Only then may both baseline stores advance. Baseline advancement itself is not atomic across peers; a lost acknowledgment leaves the session pending and the old baseline in place.
9. **Aborted** — reached only before any commit, after local rollback/cleanup is verified and a peer abort/no-commit acknowledgment is recorded. Recovery material may be released only after this terminal condition.
10. **RecoveryRequired** — any ambiguous, failed, or contradictory state. Keep rollback material. Never report the session as synchronized or advance baseline.

## Message binding and idempotency

Every prepare, commit, abort, and acknowledgment message carries the session ID, plan hash, sender identity, and relevant final root. Duplicate identical messages are no-ops. A different hash, identity, root, or contradictory terminal message is rejected and moves the journal to `RecoveryRequired`. State changes use one SQLite transaction per local transition. No single transaction spans both machines.

## Crash and disconnect recovery

After restart, load the journal and query the authenticated peer for its durable status. Reconciliation is deterministic:

- Both peers report the same verified commit and result root: mark committed and retry baseline advancement idempotently.
- One peer committed while the other is prepared or commit-pending: resume the second peer's commit; retain recovery copies. Do not roll back the committed side unilaterally.
- One peer committed while the other reports aborted, a different plan/root, or no durable record: `RecoveryRequired`; preserve both versions and require an explicit repair procedure.
- Neither peer committed and both confirm no-commit/abort: verify local rollback/cleanup on each side, then mark aborted.
- Peer is unreachable or reports unknown state: wait and retain all recovery material. Never infer success from a timeout.

A peer that never reconnects therefore leaves the session unresolved and does not advance the common baseline. An operator may later resume the same session or perform a separately audited restore; silently discarding recovery data is not allowed.

## Stage 5 Coordinator and Local Transaction Journal Integration (2026-10-25)

The bilateral peer session journal is now fully integrated with concrete file commits, staging artifacts, recovery copies, `VersionStore`, `ActivityStore`, and `PeerBaselineStore` via `PeerTransactionCoordinator`:

1. **Operation-level Transaction Journal**:
   - `peer_session_operations` SQLite table durably persists every planned transfer with a foreign key to `peer_sessions`.
   - Every operation has a stable session ID (`transaction_id`), deterministic `operation_id` computed via SHA-256 digest of session ID, canonical relative path, action (`AddLocal`, `UpdateLocal`, `DeleteLocal`), prior content hash, and expected new content hash.
   - Persists intended paths, prior content hash, expected new hash, staging artifact path (`.mc-stage-<op_id>`), recovery artifact path (`<recovery_root>/<op_id>.bak`), operation state (`Planned`, `Staged`, `RecoveryPrepared`, `Prepared`, `Committed`, `Finalized`, `RolledBack`, `Failed`), and error diagnostic.

2. **Durable Preparation & Destination Preservation**:
   - Staging files are allocated exclusively via `StagingFile` and durably retained across the prepare/commit boundary via `StagingFile::keep()`.
   - Before ANY existing destination file is replaced or deleted, the coordinator creates a verified backup in `recovery_artifact` and asserts its SHA-256 matches `prior_content_hash`.
   - Existing destinations remain untouched on disk until the bilateral commit phase.
   - Preparation state is recorded in SQLite and marked `local_prepared` in `PeerSessionJournal`.

3. **Atomic Replacement & Verified Commits**:
   - Commit requires bilateral preparation (`local_prepared` and `peer_prepared`).
   - Destination replacements retire existing files via temporary atomic renaming (`.mc-retiring-<op_id>`).
   - Post-commit content hashes are strictly verified against `expected_new_hash` before recording success.
   - After applying all operations, a full recursive scan of `sync_root` is verified against `expected_final_root` before calling `journal_.mark_local_commit_verified`.
   - A snapshot is created in `VersionStore` and audit records are logged in `ActivityStore`.
   - Retries are idempotent: already-committed operations verify disk content and succeed without re-mutation.

4. **Partial-Commit Reconciliation**:
   - **Both peers prepared, neither committed**: On peer abort, `evaluate_peer_recovery` advises `AbortUncommitted`. `rollback_operations` restores destinations from verified recovery copies and marks `local_rollback_verified`.
   - **One peer committed, other disconnected / lost ack**: `evaluate_peer_recovery` advises `ResumeCommit` or `WaitForPeer`. Recovery artifacts and uncommitted state remain preserved; baseline cannot advance.
   - **Crash during replacement**: Retiring files (`.mc-retiring-<op_id>`) and recovery artifacts are preserved. `reconcile_and_recover` detects retiring files, restores original files if uncommitted, or completes staging rename if commit was verified.
   - **Verified commit followed by failed history write**: Destination files remain verified and committed on disk. Session is marked `RecoveryRequired` with diagnostic; retry resumes and finalizes history idempotently.
   - **Successful file operation with failed baseline write**: `finalize_bilateral_commit` fails closed; recovery material is retained; baseline does not advance until the baseline store write succeeds.
   - **Rollback failure**: If rollback is interrupted or fails, session remains `RecoveryRequired` and recovery material is retained for manual reconciliation.
   - **Recovery artifact corruption or missing artifact**: Fails closed before any mutation or rollback; blocks commit/rollback and marks `RecoveryRequired`.
   - **Stale plan or changed destination**: Destination hash modification after planning triggers immediate rejection during preparation without overwriting unexpected data.

5. **Windows 11 Security Controls & Environment Diagnostics**:
   - Registry inspection confirmed `HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState = 1` (Windows 11 Smart App Control in Enforcement Mode).
   - Under policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}` (`VerifiedAndReputableDesktop`), the Windows kernel Code Integrity driver (`ci.dll`) logs Event 3077 with status `0xc0e90002` (`STATUS_IMAGE_NOT_AT_REQUIRED_POLICY_LEVEL`) and blocks unsigned newly compiled binaries (error 4551).
   - In accordance with instructions, Windows security controls, firewall rules, and Application Control policies were not bypassed or disabled.
   - Execution in a production or CI environment requires either an administrator-configured developer exclusion policy or Authenticode signing with a certificate recognized by the Microsoft Trusted Root Program.
   - Loopback TCP tests continue to encounter `WSAEACCES (10013)` under host filtering policy and remain documented as unverified pending an administrator-approved loopback environment.

## Stage 6: Transaction Safety Audit, Durable Recovery Reconciliation, and Peer Service Workflow (2026-10-25)

### 1. Safety Audit Findings & Gaps Remediated

A comprehensive code audit of `PeerTransactionCoordinator`, `StagingFile`, `PeerBaselineStore`, `VersionStore`, `ActivityStore`, and `PeerSessionJournal` was conducted against 9 essential safety invariants:

1. **Pre-mutation Verification**:
   - `prepare_operations` verifies destination content against `prior_content_hash`, copies target to `<recovery_root>/<op_id>.bak`, and asserts the backup's SHA-256 equals `prior_content_hash` before any change.
2. **Interruption Reconciliation**:
   - Replacements use `.mc-retiring-<op_id>` rename and staging uses `.mc-stage-<op_id>`. Interrupted operations can be fully reconciled from disk state alone.
3. **Parameter Bindings**:
   - All operations are strictly bound to `session_id`, `plan_hash`, `relative_path`, `prior_content_hash`, `expected_new_hash`, and required user approvals.
4. **Idempotency**:
   - Repeated calls to `commit_local` and `rollback_operations` are idempotent; committed files matching expected hash advance cleanly without error.
5. **Terminal Failure Gates**:
   - Failed history write (`VersionStore` or `ActivityStore`) or failed baseline write (`PeerBaselineStore`) prevents finalization, marks `RecoveryRequired`, and leaves recovery material intact.
6. **Baseline Advancement Gate**:
   - `finalize_bilateral_commit` asserts both `local_commit_verified` and `peer_commit_verified`, `session.state == Committed`, and verifies every single operation is in `Committed` or `Finalized` state before calling `commit_reconciled_manifest`.
7. **Recovery Artifact Retention**:
   - `release_recovery_material` is called strictly after baseline advancement succeeds; in all error, rollback, or crash scenarios, recovery backups are retained.
8. **Path Containment**:
   - `safe_relative_path` rejects paths with `..`, `.`, `:`, drive letters, root names, leading `/`, or absolute paths.
9. **Stale Destination Detection Immediately Before Commit (Audit Gap Remediated)**:
   - **Audit Finding**: `prepare_operations` validated `target` against `prior_content_hash`, but `commit_local` previously only checked `recovery_artifact` before renaming `target` to `retiring` in `UpdateLocal` and before deleting in `DeleteLocal`.
   - **Remediation**: Added explicit pre-commit verification in `commit_local` immediately prior to `fs::rename(target, retiring)` and `fs::remove(target)`. If destination was modified between prepare and commit, `commit_local` immediately aborts with `stale destination contents before commit`, flags `RecoveryRequired`, and preserves user files without clobbering.

### 2. Durable Recovery Reconciliation Architecture

`PeerTransactionCoordinator::reconcile_interrupted_session` inspects disk and journal state to safely recover interrupted sessions without relying on simulated memory flags:

- **Crash Point A: Exit after creating backup or staging**:
  - Uncommitted staging files (`.mc-stage-...`) are removed as orphaned artifacts; original destinations remain verified against `prior_content_hash`.
- **Crash Point B: Exit between retiring destination and installing new file**:
  - Detected by `!fs::exists(target) && fs::exists(retiring)`.
  - Default rollback (`resume_commit = false`): atomically renames `.mc-retiring` back to `target`, verifies SHA-256 against `prior_content_hash`, and cleans orphaned staging files.
  - Resume commit (`resume_commit = true`): installs verified staging file to `target`, verifies post-commit hash, and unlinks retiring file.
- **Crash Point C: Exit after file installation with lingering retiring file**:
  - Detected by `fs::exists(target) && sha256_file(target) == op.expected_new_hash && fs::exists(retiring)`.
  - Safely unlinks lingering `.mc-retiring` file and advances operation state to `Committed`.
- **Crash Point D: New file installed but history write interrupted**:
  - Local commit was achieved; retry re-verifies destination, resumes snapshot and activity recording, and transitions operations to `Finalized`.
- **Crash Point E: History succeeds but baseline advancement fails**:
  - Operations remain finalized, but `recovery_material_retained` remains `true` and baseline is unchanged. Retrying `finalize_bilateral_commit` advances baseline and releases recovery copies.
- **Crash Point F: Lost peer commit acknowledgment**:
  - Evaluated via `evaluate_peer_recovery(local, remote)`. When remote reports `Committed` with matching plan hash and Merkle root, local marks `peer_commit_verified = true`, advances baseline, and releases recovery copies.
- **Crash Point G: Missing or corrupted recovery artifact**:
  - Detected when `!fs::exists(recovery_artifact) || sha256_file(recovery_artifact) != op.prior_content_hash`.
  - Reconciliation halts immediately, sets `manual_recovery_required = true`, logs diagnostic in journal, and refuses any destructive action to prevent silent data loss.

### 3. Durability Guarantees of Storage & Filesystem Stack

- **SQLite Journal Durability**:
  - Uses `BEGIN IMMEDIATE; ... COMMIT;` with full mutex serialization.
  - In default journal mode with OS flushing, transactions are 100% durable against process crashes and OS kernel crashes.
  - Hardware Power-Loss Durability: Physical durability against sudden power loss is subject to device write cache behavior; consumer SSDs without hardware Power Loss Protection (PLP) may lose write-cached sectors on abrupt power cut. We explicitly do not claim physical power-loss durability from ordinary reopen tests.
- **NTFS Filesystem Operations & Flush Behavior**:
  - `StagingFile` opens files with `CREATE_NEW` and explicit flags (`FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN`).
  - `StagingFile::flush()` explicitly executes Win32 `FlushFileBuffers(handle_)`, flushing OS dirty pages to the storage controller prior to SHA-256 integrity computation.
  - File replacement uses atomic rename within the same volume, updating NTFS directory entry metadata recorded in the NTFS `$LogFile` journal.
- **Distributed Atomicity**:
  - We explicitly **do not claim distributed atomicity**. Two autonomous laptops across an IP network cannot achieve atomic multi-master synchronization without a distributed consensus coordinator. Each peer maintains local durability and deterministic reconciliation rules; uncommitted or ambiguous sessions fail closed with preserved recovery backups.

### 4. Dedicated Peer Service & Wire Protocol (`PeerService`)

Implemented in `include/merklechain/peer/peer_service.hpp` and `src/peer/peer_service.cpp` (kept strictly separate from `src/web_server.cpp`):

- **Transport**: Authenticated mutual TLS with leaf certificate SHA-256 fingerprint pinning (`PeerTlsContext`, `PeerListener`, `PeerConnection`).
- **Wire Protocol**: Bounded binary frames (`kMaximumFramePayload = 1 MiB`, `kFrameHeaderSize = 12`) using `FrameDecoder`.
- **Manifest Codec**: Bounded binary manifest wire codec (`encode_peer_manifest`, `decode_peer_manifest`).
- **Bidirectional Planner**: `plan_bidirectional` evaluates local, remote, and baseline manifests.
- **Approval Flow**: `ApprovalPayload` wire exchange with explicit required user confirmation ("Type YES: ").
- **Staging & Verification**: Files are transferred via `MessageType::FileRequest`, `MessageType::FileData` (64 KiB chunks), and `MessageType::FileEnd` streamed into `StagingFile` and hash-verified before commit.
- **Host Safeguard**: Host never mutates files simply because a connection is established; waits for client plan proposal, bilateral verification, and explicit authorization.

### 5. Explicit Peer CLI Commands

Added to `src/main.cpp`:
- `merklechain.exe --peer-host --config <path>`: Runs Host daemon.
- `merklechain.exe --peer-sync --config <path>`: Runs Client sync workflow with plan display and interactive approval.
- `merklechain.exe --peer-help`: Displays comprehensive peer synchronization guide and JSON configuration schema.
- `--local`, `--dashboard`, and disabled `--network` (exit code 3) are strictly preserved.
- Plaintext fallback is prohibited; TLS mutual authentication with certificate pinning is mandatory.
