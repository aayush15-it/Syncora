# Syncora Milestone 3.5 — Architecture & Specification
## Workspace Branching & Real-Time Event Streaming (SSE)

**Document Version:** 1.0  
**Target Milestone:** Milestone 3.5 (`v0.3.5-branching-sse`)  
**Status:** Approved Architecture Specification  
**Author:** Principal Distributed Systems Architect  
**Dependencies:** Phase 2 Workspace Engine, Milestone 3.1–3.4 Content-Addressed Storage (CAS)  

---

## 1. Executive Summary & Objective

Milestone 3.5 advances Syncora from linear version releases and periodic polling to:
1. **Workspace Branching & Semantic Forks**: Multi-stream development within workspaces (e.g. `main`, `feature/auth`, `hotfix`) utilizing zero-copy Content-Addressed Storage (CAS) pointers. Creating a branch or switching branches has $O(1)$ disk overhead by referencing immutable CAS chunk manifests.
2. **Real-Time Server-Sent Events (SSE) Engine**: Low-latency HTTP activity push streaming via `GET /api/events/stream`, replacing client timer polling with instant notification of published releases, branch changes, and client submissions.
3. **Multi-Threaded Dashboard Concurrency**: Concurrent connection dispatch in `web_server.cpp` ensuring persistent SSE streams never block standard API or static asset delivery.

---

## 2. Component Architecture

```mermaid
graph TD
    subgraph Browser / Client Tier
        UI["Web Dashboard (web/app.js)"]
        ES["EventSource (/api/events/stream)"]
    end

    subgraph HTTP & Concurrency Tier (src/web_server.cpp)
        WS["Multi-Threaded Web Server"]
        EB["EventBroadcaster (Thread-Safe Registry)"]
        ROUTER["API Router (/api/host/workspaces/branches)"]
    end

    subgraph Storage & Collaboration Engine (CollabStore)
        WBM["Branch Manager (workspace_branches)"]
        CAS["CAS ObjectStore (Immutable Blobs)"]
        DB[("SQLite collab.sqlite3")]
    end

    UI -->|HTTP POST /switch-branch| ROUTER
    ES -->|Long-Lived HTTP GET| WS
    WS --> EB
    ROUTER --> WBM
    WBM --> CAS
    WBM --> DB
    WBM -.->|Trigger Event| EB
    EB -.->|SSE Push Frame| ES
```

---

## 3. Database Schema Extensions

### 3.1 Table: `workspace_branches`

```sql
CREATE TABLE IF NOT EXISTS workspace_branches (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    head_version_id TEXT REFERENCES published_versions(id) ON DELETE SET NULL,
    created_at_ms INTEGER NOT NULL,
    created_by_user_id TEXT REFERENCES users(id),
    is_default INTEGER DEFAULT 0,
    UNIQUE(workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_workspace_branches_ws ON workspace_branches(workspace_id);
```

### 3.2 Schema Migration for `workspaces` Table
- Add column `active_branch_id TEXT REFERENCES workspace_branches(id)` if not present.
- Every workspace automatically initializes with a default branch named `main` (`is_default = 1`).
- If versions already exist in a workspace, the default branch's `head_version_id` points to the latest published version.

---

## 4. Zero-Copy Branching Mechanics

1. **Branch Creation (`create_branch`)**:
   - Creates a new record in `workspace_branches`.
   - `head_version_id` is set to the specified version (or current branch's head).
   - Storage overhead is $O(1)$ (single SQLite row insertion, 0 duplicate file bytes).
2. **Branch Switching (`switch_branch`)**:
   - Reconciles the physical working directory (`working_copy`) with the target branch's `head_version_id`.
   - Files present in the target version are materialized from CAS objects (`ObjectStore::get_object`).
   - Files absent from the target version are removed from the working copy.
   - Updates `workspaces.active_branch_id`.
   - Protected under per-workspace mutex (`ws_registry_mutex_`) to prevent concurrent modification races.
3. **Branch Deletion (`delete_branch`)**:
   - Prohibits deleting the active branch or the default `main` branch.
   - Deleting a branch does NOT delete CAS blobs (blobs remain governed by CAS reference counting and GC).
4. **Publishing Integration (`publish_version`)**:
   - Publishing a new release advances `workspace_branches.head_version_id` for the currently active branch.
   - Lineage is maintained via `published_versions.parent_version_id`.

---

## 5. Real-Time Server-Sent Events (SSE) Engine

### 5.1 Protocol Specification
- **Endpoint**: `GET /api/events/stream`
- **Headers**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: text/event-stream; charset=utf-8
  Cache-Control: no-cache
  Connection: keep-alive
  X-Accel-Buffering: no
  Access-Control-Allow-Origin: *
  ```
- **Frame Format**:
  ```text
  event: <event_type>
  data: {"workspace_id":"ws-default","type":"<event_type>","timestamp_ms":1793815000000,...}

  ```
- **Keep-Alive Heartbeat**:
  - Broadcaster sends `: ping\n\n` comment frame every 15 seconds to detect broken client connections and prevent intermediate proxy timeouts.

### 5.2 Thread-Safe Broadcaster Design (`EventBroadcaster`)
- Maintains a list of active client sockets.
- Synchronized with `std::mutex` and non-blocking socket writes (`send()`).
- If `send()` fails with `WSAECONNRESET`, `WSAESHUTDOWN`, or error, the broken socket descriptor is removed and closed gracefully.
- Thread-safe `broadcast(const std::string& event, const std::string& json_payload)`.

### 5.3 Web Server Concurrency Architecture
- Update `run_web_server()` to spawn detached worker threads for accepted client sockets (`std::thread([client = std::move(client)] { ... }).detach()`).
- Prevents long-lived SSE connections from blocking incoming HTTP requests.

---

## 6. HTTP API Specification

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/host/workspaces/branches?workspace_id=<id>` | List all branches in workspace with head versions | Host / Member |
| `POST` | `/api/host/workspaces/branches` | Create new branch `{workspace_id, name, source_version_id}` | Host |
| `POST` | `/api/host/workspaces/switch-branch` | Switch active branch `{workspace_id, name}` | Host |
| `DELETE` | `/api/host/workspaces/branches` | Delete non-active branch `{workspace_id, name}` | Host |
| `GET` | `/api/events/stream` | Real-time Server-Sent Events stream | Any authenticated |

---

## 7. Web Dashboard Integration

1. **Navigation & Header**:
   - Branch selector dropdown displaying current active branch with branch icon.
   - One-click branch switcher with confirmation modal.
   - "New Branch" modal with source version selection.
2. **Real-Time Reactivity (`web/app.js`)**:
   - Instantiates `new EventSource('/api/events/stream')`.
   - Listens for events:
     - `branch_switched`, `branch_created`, `version_published`, `submission_created`, `submission_reviewed`.
   - Updates UI elements in real time without requiring manual browser reload.

---

## 8. Verification Strategy & Test Matrix

1. **Branching Unit & Integration Tests (`tests/cas/branching_tests.cpp`)**:
   - `BRANCH-01`: Create default `main` branch upon workspace creation.
   - `BRANCH-02`: Zero-copy branch creation from version head (verifies 0 physical copies).
   - `BRANCH-03`: Switch branch materializes correct files from CAS store.
   - `BRANCH-04`: Prohibit deleting active or default branch.
   - `BRANCH-05`: Publishing updates branch head pointer.
   - `BRANCH-06`: Concurrent branch switching serialization under workspace lock.
2. **Server-Sent Events Tests (`tests/sse_tests.cpp` / PowerShell integration)**:
   - `SSE-01`: Client connects and receives valid `text/event-stream` headers.
   - `SSE-02`: Event broadcast pushes JSON payload to multiple concurrent subscribers.
   - `SSE-03`: Heartbeat ping received on idle connection.
   - `SSE-04`: Disconnected socket cleaned from broadcaster registry without leak.
3. **Regression Matrix**:
   - Full automated test suite passes with zero regressions (`tests/run_tests.ps1`).
   - Collaboration E2E, Dashboard smoke, and peer tests continue passing.

