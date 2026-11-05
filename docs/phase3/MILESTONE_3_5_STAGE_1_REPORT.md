# Milestone 3.5 — Stage 1 Completion Report
## CollabStore Workspace Branching Engine & SQLite Migration

**Release Scope:** Milestone 3.5 — Stage 1 (Backend Core)  
**Status:** COMPLETE & VERIFIED  
**Date:** November 2026  
**Target Environment:** Windows 11, MSYS2 UCRT64, GCC 13+ (C++17), SQLite 3, OpenSSL 3  

---

## 1. Executive Summary

Stage 1 of Milestone 3.5 establishes the persistent workspace branching engine within `CollabStore`. This foundation enables distributed teams to develop features, bug fixes, and experiments on isolated branches backed by immutable published versions and Content-Addressed Storage (CAS) manifests, without copying files or duplicating CAS physical blobs.

All Stage 1 requirements specified in `docs/phase3/MILESTONE_3_5_ARCHITECTURE_SPEC.md` have been implemented, tested, and verified:
1. **Durable SQLite Schema & Idempotent Migration:** Introduced `workspace_branches` and `workspaces.active_branch_id` with automatic migration that upgrades legacy workspaces to a default `main` branch referencing the latest published version.
2. **Complete Branch Lifecycle APIs:** Implemented `create_branch`, `list_branches`, `find_branch_by_name`, `find_branch_by_id`, `get_active_branch`, `switch_branch`, and `delete_branch`.
3. **Zero-Copy Branching Semantics:** Branch creation is an $O(1)$ metadata insertion pointing to existing version manifests; no physical directories or CAS chunks are duplicated.
4. **Atomic Switching & Two-Phase Crash Recovery:** Branch switching reconstructs target version state into isolated staging directories, backs up existing working copy and baseline, promotes staged directories, and updates `active_branch_id`. If interrupted, `recover_switch_branch_op` restores from backups or finalizes forward commit.
5. **Lock Hierarchy & Concurrency:** All operations respect `OperationGuard -> cas_barrier_ (shared) -> workspace_lock -> db_mutex_`. Filesystem operations and CAS reconstruction occur outside `db_mutex_`.
6. **Windows MAX_PATH Resilience:** Replaced lengthy temporary path generators with compact staging naming to prevent NTFS `MAX_PATH` exhaustion during deep workspace version reconstruction.

---

## 2. Schema Architecture & Database Migration

### 2.1 SQLite Schema Additions

The SQLite catalog was extended with the `workspace_branches` table and an `active_branch_id` column on `workspaces`:

```sql
CREATE TABLE IF NOT EXISTS workspace_branches (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    head_version_id TEXT REFERENCES published_versions(id) ON DELETE SET NULL,
    created_at_ms INTEGER NOT NULL,
    created_by_user_id TEXT,
    is_default INTEGER DEFAULT 0,
    UNIQUE(workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_workspace_branches_ws ON workspace_branches(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_branches_head ON workspace_branches(head_version_id);
```

### 2.2 Schema Alteration & Migration (`migrate_workspace_branches_nolock`)

During `CollabStore::init_schema()`:
1. `PRAGMA table_info(workspaces)` checks whether `active_branch_id` exists. If missing, it issues `ALTER TABLE workspaces ADD COLUMN active_branch_id TEXT;`.
2. `migrate_workspace_branches_nolock()` runs idempotently:
   - For every existing workspace, it checks if a `main` branch exists in `workspace_branches`.
   - If missing, it queries `SELECT id FROM published_versions WHERE workspace_id = ? ORDER BY created_at_ms DESC, rowid DESC LIMIT 1` to find the latest version.
   - It inserts the default `main` branch (`is_default = 1`) referencing the latest version ID (or `NULL` if no versions exist).
   - It updates `workspaces.active_branch_id` to point to the `main` branch ID.
3. Repeated startup runs detect existing branches and perform zero mutations, ensuring full idempotency.

---

## 3. Implemented Engine APIs

The following APIs were implemented in `include/merklechain/collab_store.hpp` and `src/collab_store.cpp`:

| API | Signature | Description |
|---|---|---|
| `create_branch` | `CollabBranch create_branch(workspace_id, name, source_version_id = "", user_id = "")` | Creates a new branch pointing to `source_version_id` (or active branch head if omitted). Validates name, workspace isolation, and name uniqueness. |
| `list_branches` | `std::vector<CollabBranch> list_branches(workspace_id)` | Lists all branches for a workspace, ordering default branch first, then alphabetically. Computes `is_active` dynamically. |
| `find_branch_by_name` | `std::optional<CollabBranch> find_branch_by_name(workspace_id, name)` | Looks up branch by exact name within a workspace. |
| `find_branch_by_id` | `std::optional<CollabBranch> find_branch_by_id(branch_id)` | Looks up branch by globally unique branch ID (`br_...`). |
| `get_active_branch` | `std::optional<CollabBranch> get_active_branch(workspace_id)` | Retrieves the currently active branch resolved from `workspaces.active_branch_id`. |
| `switch_branch` | `bool switch_branch(workspace_id, branch_name_or_id, user_id = "")` | Atomically swaps `working_copy` and `baseline` to match the target branch's head version and updates `active_branch_id`. Supports branch name or branch ID. |
| `delete_branch` | `bool delete_branch(workspace_id, branch_name_or_id)` | Deletes branch metadata row. Strictly rejects deleting the default branch (`is_default = 1`) or currently active branch. Preserves all versions and CAS chunks. |

---

## 4. Safety, Concurrency & Recovery Design

### 4.1 Strict Lock Hierarchy

To prevent deadlocks between database operations, CAS unlinking, and concurrent branch switching:
$$\text{OperationGuard} \longrightarrow \text{cas\_barrier\_ (shared)} \longrightarrow \text{workspace\_lock} \longrightarrow \text{db\_mutex\_}$$

- `OperationGuard`: Tracks active operation lifecycle for graceful drain and shutdown.
- `cas_barrier_`: Held in shared mode (`CasSharedBarrierGuard`) to prevent CAS GC sweeps from removing chunks referenced by the target branch during reconstruction.
- `workspace_lock`: Serializes filesystem and branch mutations per workspace so parallel requests on different workspaces proceed concurrently.
- `db_mutex_`: Serializes SQLite transactions and statement executions. Released before filesystem operations and CAS manifest reconstructions.

### 4.2 Atomic Switching & Journaled Recovery

Branch switching executes via a four-phase staging and backup pattern:
1. **Journal Intent (`SWITCH_BRANCH`):** Inserts a pending record into `workspace_operations` recording `target_id`, `state = 'PENDING'`, and `intent_step = 'STAGE_WORK'`.
2. **CAS Reconstruction:** Reconstructs the target version into `.staging_work_<op_id>` and replicates to `.staging_base_<op_id>`, embedding verified operation sentinels.
3. **Atomic Swap & Backup:** Moves `working_copy` to `.backup_work_<op_id>` and `baseline` to `.backup_base_<op_id>`, then promotes staged directories to `working_copy` and `baseline`.
4. **Database Commit:** Executes `BEGIN IMMEDIATE; UPDATE workspaces SET active_branch_id = ?; UPDATE workspace_operations SET state = 'COMMITTED'; COMMIT;`. Backups and staging are then safely removed.

If a crash or fault occurs:
- If uncommitted: `recover_switch_branch_op()` restores `working_copy` and `baseline` from `.backup_work_<op_id>` and `.backup_base_<op_id>` and removes staging debris.
- If committed: `recover_switch_branch_op()` cleans up leftover backup directories and finalizes the operation.

### 4.3 Windows MAX_PATH Hardening

On Windows NTFS without opt-in extended path prefixes, nested temporary directory names can exceed the 260-character `MAX_PATH` limit. To eliminate path exhaustion:
- Replaced 65-character version staging directory names with compact identifiers (`.rec_<token>`).
- Replaced 47-character file staging names with compact tokens (`.rf_<timestamp>.tmp`).
- Shortened operation IDs to `sw_<token>`.

---

## 5. Verification Matrix & Test Evidence

### 5.1 Branching Test Suite (`tests/branching_tests.cpp`)

A dedicated test suite was implemented and integrated into the global test harness, exercising 42 specific assertions:

| Category | Test Case | Expected Result | Status |
|---|---|---|---|
| **Migration** | `Default main branch provision` | Workspace receives `main`, `is_default=1`, `is_active=1` | PASS |
| **Migration** | `Empty version linkage` | Workspace without versions has empty `head_version_id` | PASS |
| **Migration** | `Version linkage on migration` | Workspace with version has `main` pointing to version ID | PASS |
| **Migration** | `Idempotency on store reopen` | Repeated reopenings preserve single `main` and branch IDs | PASS |
| **Creation** | `Valid branch names` | `feature/auth-provider`, `fix-bug_123`, `release/v1.0.0`, `patch.1` accepted | PASS |
| **Creation** | `Duplicate branch rejection` | Same branch name on same workspace throws error | PASS |
| **Creation** | `Invalid branch names` | Empty, spaces, colons, tildes, carets, traversal (`..`), `/./`, leading/trailing slashes, >128 chars rejected | PASS |
| **Creation** | `Foreign version rejection` | Pointing to non-existent version or version from another workspace rejected | PASS |
| **Creation** | `Zero-copy CAS verification` | CAS chunk count before and after branch creation is identical | PASS |
| **Switching** | `Switch and active update` | `switch_branch` activates new branch and updates `active_branch_id` | PASS |
| **Switching** | `Working copy restoration` | Working copy matches target version files and Merkle root | PASS |
| **Switching** | `Branch divergence` | Edits on feature advance feature head only; `main` head remains at v1 | PASS |
| **Switching** | `Switch back to main` | Working copy restored to v1 Merkle root and files | PASS |
| **Switching** | `Idempotent no-op switch` | Switching to already active branch succeeds immediately | PASS |
| **Switching** | `Invalid switch rejection` | Switching to non-existent branch or foreign workspace branch rejected | PASS |
| **Deletion** | `Default branch protection` | Deleting `main` (`is_default=1`) rejected | PASS |
| **Deletion** | `Active branch protection` | Deleting currently active branch rejected | PASS |
| **Deletion** | `Safe inactive deletion` | Deleting inactive non-default branch succeeds | PASS |
| **Deletion** | `Immutability of data` | Published versions and CAS physical blobs are preserved after branch deletion | PASS |
| **Recovery** | `FailAfterBranchSwitchStaging` | Fault injected after staging; recovery cleans staging; active branch unchanged | PASS |
| **Recovery** | `FailAfterBranchSwitchBackup` | Fault injected after backup; recovery restores working copy and baseline | PASS |
| **Recovery** | `FailAfterBranchSwitchPromotion` | Fault injected after promotion before DB commit; recovery rolls back to previous branch | PASS |
| **Concurrency** | `Concurrent branch creation` | 5 threads create branches concurrently without deadlock or DB lock contention | PASS |
| **Concurrency** | `Concurrent queries & switching`| Reader threads continuously list and query branches while switches occur | PASS |

### 5.2 Verification Suite Results

```text
==========================================================
 MerkleChain Test Suite Automation Runner (tests/run_tests.ps1)
==========================================================
Total Checks: 1019 passed, 0 failed, 1 skipped
Exit Code: 0
Duration: 61.87s
Status: SUCCESS

==========================================================
 Collaboration E2E Test Suite (tests/test_collaboration_e2e.ps1)
==========================================================
Total Checks: 34 passed, 0 failed
Exit Code: 0
Status: SUCCESS

==========================================================
 Dashboard Smoke Test Suite (tests/dashboard_smoke.ps1)
==========================================================
All 5 views and API workflows verified
Exit Code: 0
Status: SUCCESS
```

---

## 6. Release Management & Git Integrity

The repository's historical releases and signed commit tags remain protected:
- `v0.2.0-phase2^{}`: `1784c0113c01aaba2731a2dfb942c7abc8d83582`
- `v0.3.0-m3.2^{}`: `381084d29416043b5bbcb196923242cc73435e94`
- `v0.3.2-cas-integration^{}`: `381084d29416043b5bbcb196923242cc73435e94`
- `v0.3.0-m3.3^{}`: `e1ab1b0fd3e923001615fb26a1f004ee800fd687`
- `v0.3.0-m3.4^{}`: `b31dbfe1341a8b06dd8be2bd03017ff5c1376753`
- `v0.3.1-m3.4-security^{}`: `b6584dbc992c683b81335a1757adc58339cd57e7`

No commits were pushed to remote origin.

---

## 7. Stage 1 Scope Boundaries & Next Steps

Stage 1 is complete. As mandated by the architecture specification:
- Web server endpoints (`/api/collab/branches`, `/api/collab/branches/create`, `/api/collab/branches/switch`) are scheduled for **Stage 2**.
- Server-Sent Events (SSE) live branch status streaming is scheduled for **Stage 2**.
- Web Dashboard UI branch selector dropdown is scheduled for **Stage 2**.
- Three-way merge engine and vector clock conflict detection are scheduled for **Stage 3**.
