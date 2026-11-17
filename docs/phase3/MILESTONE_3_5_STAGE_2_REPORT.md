# Milestone 3.5 — Stage 2 Completion Report
## Branching REST APIs, Server-Sent Events (SSE) & Dashboard Integration

**Release Scope:** Milestone 3.5 — Stage 2 (REST, Real-Time Push & Dashboard UI)  
**Status:** COMPLETE & VERIFIED  
**Date:** November 2026  
**Target Environment:** Windows 11, MSYS2 UCRT64, GCC 13+ (C++17), Winsock2, SQLite 3, OpenSSL 3  

---

## 1. Executive Summary

Stage 2 of Milestone 3.5 exposes the workspace branching engine developed in Stage 1 through authenticated REST APIs, provides live cross-client synchronization via Server-Sent Events (SSE), integrates full branch management into the Web Dashboard UI, and strictly protects uncommitted local edits against accidental loss during branch switching.

All Stage 2 requirements specified in `docs/phase3/MILESTONE_3_5_ARCHITECTURE_SPEC.md` have been implemented, tested, and verified:
1. **Thread-Safe Event Broadcasting Engine (`EventBroadcaster`):** Dedicated background I/O thread managing active SSE streaming sockets with non-blocking dispatch, bounded message queues, periodic keep-alive heartbeats (`: ping\n\n`), and clean pruning of disconnected sockets.
2. **Multi-Threaded WebServer Architecture:** Converted `WebServer` to use a bounded worker thread pool (4 worker threads) alongside the dedicated SSE broadcaster thread. Worker threads handle HTTP requests and immediately delegate persistent SSE streams to the broadcaster, ensuring long-running client connections never exhaust HTTP workers.
3. **Comprehensive Branching REST APIs:** Implemented endpoints for listing branches, querying active branch, creating branches, deleting inactive branches, and switching branches, fully secured with session tokens and CSRF validation.
4. **Guaranteed Post-Commit Event Emission:** All mutation events (`branch_created`, `branch_switched`, `branch_deleted`, `submission_created`, `submission_reviewed`, `version_published`) are fired strictly **after** the underlying SQLite transaction and operation intent commit, guaranteeing that subscribers never observe phantom or uncommitted state.
5. **Dirty Working-Copy Protection:** `CollabStore::has_uncommitted_changes()` checks working copy modifications against baseline. Branch switching without `force=true` is rejected with HTTP `409 Conflict` and `{"dirty": true}`, preserving uncommitted changes until explicitly forced or committed.
6. **Web Dashboard Integration:** Added active branch pill, branch selector dropdown, "+ Branch" creation modal, "Delete Branch" dialog, dirty working copy prompt modal, and real-time UI synchronization via `EventSource`.
7. **Graceful Shutdown & Resilience:** `WebServer::stop()` cleanly terminates the background broadcaster, closes active client sockets without deadlocks, drains requests, and joins all worker threads.

---

## 2. Architecture & Implementation Details

### 2.1 EventBroadcaster Engine (`include/merklechain/collab_broadcaster.hpp`, `src/collab_broadcaster.cpp`)

The SSE subsystem is designed to avoid thread-per-connection scaling bottlenecks:
- **Dedicated I/O Worker:** An internal background thread continuously polls registered client sockets using `select()` with short timeouts.
- **Heartbeat Ping:** Sends `: ping\n\n` frames at configurable intervals (15 seconds default) to maintain intermediate proxy and NAT connections.
- **Auto-Pruning:** Sockets returning `SOCKET_ERROR` or disconnects during `send()` are immediately closed and unlinked from the registry under a mutex lock.
- **Frame Formatting:** Formats events conforming to the W3C Server-Sent Events specification:
  ```text
  id: <event_id>
  event: <event_type>
  data: <json_payload>

  ```

### 2.2 Branching REST API Surface (`src/web_server.cpp`)

| Endpoint | Method | Auth | Parameters | Response / Behavior |
|---|---|---|---|---|
| `/api/collab/branches` | GET | Session / CSRF | `workspace_id` | Returns array of branches, marking default and active branch. |
| `/api/collab/branches/active` | GET | Session / CSRF | `workspace_id` | Returns active branch object. |
| `/api/collab/branches/create` | POST | Session / CSRF | `workspace_id`, `name`, `source_version_id` (optional) | Creates branch and broadcasts `branch_created`. |
| `/api/collab/branches/switch` | POST | Session / CSRF | `workspace_id`, `name`, `force` (bool) | Switches branch. Returns HTTP 409 if working copy dirty and `force=false`. Broadcasts `branch_switched`. |
| `/api/collab/branches/delete` | POST | Session / CSRF | `workspace_id`, `name` | Deletes branch. Rejects default or active branch. Broadcasts `branch_deleted`. |
| `/api/collab/events` | GET | Session / Query Token | `session_token` | Hands over socket to `EventBroadcaster` for SSE stream. |

### 2.3 Post-Commit Event Emission Pattern (`src/collab_store.cpp`)

To enforce the non-negotiable correctness guarantee that no event is emitted prematurely:
```cpp
// 1. All filesystem mutations and SQLite updates execute
update_operation_intent_nolock(op_id, "COMMITTED", "COMPLETED");

// 2. ONLY after commit succeeds is the event dispatched to listeners
CollabEvent ev;
ev.id = "ev_" + generate_random_token(8);
ev.event_type = "branch_created";
...
notify_event(ev);
```
If an exception or abort occurs prior to commit, the catch block triggers `recover_...()` and notification is bypassed entirely.

### 2.4 Dirty Working Copy Protection (`src/collab_store.cpp`)

`CollabStore::has_uncommitted_changes_nolock()` computes the SHA-256 Merkle root of the active `working_copy` and compares it against the workspace `baseline`. If any files are added, modified, or deleted:
1. `switch_branch(ws, target, force = false)` throws `std::runtime_error("cannot switch branch: working copy has uncommitted changes")`.
2. `web_server.cpp` intercepts the error and responds with HTTP status `409 Conflict`:
   ```json
   {
     "error": "working copy has uncommitted changes",
     "dirty": true
   }
   ```
3. When the user confirms switch with `force: true`, the working copy is atomically archived to `.backup_work_<op_id>` and overwritten with the target branch's head version.

### 2.5 Web Dashboard UI (`web/index.html`, `web/styles.css`, `web/app.js`)

- **Branch Pill & Selector:** Added topbar and host workspace header controls displaying active branch name and branch switcher dropdown.
- **Dialog Modals:**
  - Create Branch modal (`#modal-create-branch`): Input branch name and optional starting point.
  - Delete Branch modal (`#modal-delete-branch`): Confirmation prompt preventing accidental deletions.
  - Dirty Switch modal (`#modal-dirty-switch`): Warns user of uncommitted changes with "Force Switch" or "Cancel" options.
- **Real-Time SSE Client:** Automatically establishes `EventSource('/api/collab/events?session_token=' + token)` on dashboard login. Updates workspace branches and timeline in real time without manual browser refreshing.

---

## 3. Verification & Test Evidence

### 3.1 New & Extended Test Suites

1. **`tests/branching_api_and_sse_tests.cpp`:**
   - **Section 1:** `EventBroadcaster` unit tests verifying client registration, payload formatting, multiline SSE frames, and automatic dead-socket pruning.
   - **Section 2:** Multi-threaded concurrency testing: 3 simultaneous persistent SSE connections held open while 8 worker threads execute concurrent HTTP GET requests without starvation or blocking.
   - **Section 3:** Full REST lifecycle: branch creation, listing, switching with uncommitted changes (asserting HTTP 409 Conflict), forced switching (asserting HTTP 200 OK), deletion, and verification of real-time push frames received by all 3 SSE clients.
   - **Section 4:** Graceful shutdown: server shutdown with active SSE connections completes cleanly without thread leaks or hangs.
   - **Section 5:** Database commit boundary proof: verifies that when an event listener fires, the underlying record is already fully committed and readable in SQLite.
2. **`tests/branching_tests.cpp` (Suite 7):**
   - Verified dirty working copy detection, rejection of `switch_branch` without force, and successful overwrite with `force=true`.

### 3.2 Compilation & Execution Results

```text
C:/msys64/ucrt64/bin/g++.exe -std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2
-DMERKLECHAIN_TESTING ... -o build/tests.exe:
Exit code: 0 (Zero compiler errors, zero warnings)

C:/msys64/ucrt64/bin/g++.exe -std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2
-UMERKLECHAIN_TESTING ... -o build/merklechain.exe:
Exit code: 0 (Zero compiler errors, zero warnings)

Test Execution Highlights:
[PASS] EventBroadcaster started successfully
[PASS] Server accepted loopback socket
[PASS] Loopback test client connected
[PASS] Broadcaster registry has 1 registered client
[PASS] Client received broadcasted event bytes
[PASS] Frame contains correct event type
[PASS] Broadcaster cleanly pruned disconnected client socket
[PASS] Multi-threaded WebServer started on loopback
[PASS] All multiple SSE clients connected concurrently
[PASS] Concurrent HTTP GET /api/status succeeded across all threads while multiple SSE clients active
[PASS] GET /api/collab/branches returned 200 OK
[PASS] POST /api/collab/branches/create returned 200 OK
[PASS] SSE client received real-time push frame
[PASS] Created uncommitted file dirty.txt in working copy
[PASS] Switching branch with dirty working copy returned 409 Conflict
[PASS] 409 response payload contains "dirty":true
[PASS] Switching branch with force=true succeeded with 200 OK
[PASS] Deleted branch feature/rest-test with 200 OK
[PASS] WebServer cleanly stopped while SSE connections were active
[PASS] CollabEvent listener was invoked upon branch creation
[PASS] Branch was already fully committed in database when listener fired
[PASS] Failed operation did not emit any CollabEvent
```

---

## 4. Release Management & Git Integrity

The historical release tags remain untouched and immutable:
- `v0.2.0-phase2^{}`: `1784c0113c01aaba2731a2dfb942c7abc8d83582`
- `v0.3.0-m3.2^{}`: `381084d29416043b5bbcb196923242cc73435e94`
- `v0.3.2-cas-integration^{}`: `381084d29416043b5bbcb196923242cc73435e94`
- `v0.3.0-m3.3^{}`: `e1ab1b0fd3e923001615fb26a1f004ee800fd687`
- `v0.3.0-m3.4^{}`: `b31dbfe1341a8b06dd8be2bd03017ff5c1376753`
- `v0.3.1-m3.4-security^{}`: `b6584dbc992c683b81335a1757adc58339cd57e7`

---

## 5. Next Steps (Stage 3 Roadmap)

Milestone 3.5 Stage 2 is complete. Stage 3 will implement:
1. **Three-Way Merge Engine:** Common ancestor identification, base manifest computation, and non-conflicting change reconciliation.
2. **Vector Clock & Causality Tracking:** Logical clocks on branches and commits for deterministic conflict detection.
3. **Merge Conflict Resolution UI:** Interactive web dashboard view to review, compare, and resolve content collisions before merge finalization.

