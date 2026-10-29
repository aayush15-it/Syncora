# MerkleChain — Peer Network Dashboard

## 1. Overview & Architecture

The MerkleChain Peer Network Dashboard provides an interactive, graphical interface for the C++17 MerkleChain file synchronization engine. It replaces routine command-line operations with a visual workflow while preserving the CLI as a supported interface.

### Architectural Principles

1. **C++ Engine Independence**: All synchronization, file scanning, SHA-256 hashing, Merkle tree computation, planning, TLS transport, certificate pinning, approvals, staging, recovery, and SQLite transaction logging remain strictly in C++.
2. **Zero Frontend Frameworks**: The user interface is built exclusively using HTML5, vanilla CSS3, and modern vanilla JavaScript ES6+. No external frameworks (React, Vue, Angular, Tailwind, etc.) or CDN dependencies are used.
3. **Graphite / Charcoal / Silver Aesthetics**: Styled in a dark charcoal palette (`#111418`, `#1a2027`, `#212932`) with silver typography (`#f0f3f6`, `#cdd5df`), metallic accents, and restrained functional highlights (emerald `#34d399` for success/verified, amber `#fbbf24` for warnings/conflicts, and crimson `#f87171` for deletions/errors). Blue dominance is completely avoided.
4. **Strict Security Boundaries**:
   - The web dashboard control API is strictly loopback-only (`127.0.0.1`) with `SO_EXCLUSIVEADDRUSE`. It cannot be accessed over LAN.
   - Peer file transfers occur over a separate dedicated network port (default `47832`) protected by Mutual TLS (mTLS) with bidirectional leaf-certificate SHA-256 pinning.
   - Zero private key material is ever returned via API, logged, or exposed in frontend storage.

---

## 2. Supported Views

The dashboard provides 7 dedicated Peer Network views alongside the preserved Local Workspace views:

| View | Purpose | Key Elements |
|---|---|---|
| **1. Overview** | Device identity, role, link status, and integrity summary | Device ID, operational state, sync root path, peer endpoint, certificate pin status, mutual TLS handshake state, plan preview, recent session ledger |
| **2. Device Pairing** | Two-laptop setup, credentials, and pin validation | Host/Client selector, local identity, sync root folder browser, peer IP/port, PEM certificate paths, expected 64-hex SHA-256 pin, live configuration validation and copyable local certificate pin |
| **3. Peer Connection** | Service lifecycle and transport authentication | Start/Stop service controls, current phase, active session ID, authenticated remote peer identity, mutual TLS version, live engine event log |
| **4. Synchronization Center** | Merkle comparison and bilateral plan inspection | Add/Update/Delete counters (local and remote), conflict alert banner, searchable and filterable proposed changes table with path, action, local/remote sizes, and SHA-256 digests |
| **5. Approval Workflow** | Cryptographic plan authorization | Cryptographic session ID and plan hash display, mandatory change approval checkbox, separate confirmation checkbox for destructive deletions, decline/cancel button, commit button |
| **6. Transfer Progress** | Honest, real-time execution progress | 7-stage phase track (Listen, Handshake, Manifest, Plan, Approve, Transfer, Commit), current file name, actual bytes transferred / total bytes, files transferred / total files, transfer event stream |
| **7. Activity & Recovery** | Persisted SQLite transaction history and diagnostics | SQLite session ledger table (session ID, role, peer, start/completion times, files, bytes, status), crash recovery diagnostics, unfinished session count, WAL journal health, recovery advice |

---

## 3. How to Launch the Dashboard

### Prerequisites

- Windows with MSYS2 UCRT64 toolchain.
- `build/merklechain.exe` compiled (`mingw32-make all`).

### Starting the Dashboard

1. Run using the PowerShell launcher:
   ```powershell
   powershell -ExecutionPolicy Bypass -File run-dashboard.ps1
   ```
   Or specify a custom port:
   ```powershell
   powershell -ExecutionPolicy Bypass -File run-dashboard.ps1 -Port 47831
   ```

2. Or run the executable directly:
   ```powershell
   build\merklechain.exe --dashboard 47831
   ```

3. Open your web browser to:
   ```
   http://127.0.0.1:47831
   ```

The dashboard binds exclusively to `127.0.0.1`. Remote browser requests from the LAN are blocked by network stack socket binding and Host header validation.

---

## 4. Two-Laptop Configuration Guide

### Network Architecture

```
+------------------------------------+           +------------------------------------+
|         Laptop A (Host)            |           |        Laptop B (Client)           |
|                                    |           |                                    |
| Dashboard: http://127.0.0.1:47831  |           | Dashboard: http://127.0.0.1:47831  |
| (Local browser only)               |           | (Local browser only)               |
|                                    |           |                                    |
| Peer Listener: 0.0.0.0:47832       |<========= | Client Initiator connects to       |
| Mutual TLS with Client Pin Pinning |   mTLS    | 192.168.1.105:47832                |
| Sync Root: C:\Data\Folder_A        | (Port     | Mutual TLS with Host Pin Pinning   |
+------------------------------------+   47832)  | Sync Root: C:\Data\Folder_B        |
                                                 +------------------------------------+
```

### Step 1: Certificate Preparation

Generate certificates using OpenSSL or your organization's CA:
- Common Root CA: `ca.crt`
- Laptop A (Host): `host.crt` and `host.key`
- Laptop B (Client): `client.crt` and `client.key`

Calculate the SHA-256 fingerprint of each leaf certificate:
```powershell
# On Laptop A:
openssl x509 -in host.crt -noout -fingerprint -sha256
# On Laptop B:
openssl x509 -in client.crt -noout -fingerprint -sha256
```
*(Alternatively, enter certificate paths into the Device Pairing view and click "Validate Configuration" to compute and copy the fingerprint directly).*

### Step 2: Configure Laptop A (Host)

1. Open `http://127.0.0.1:47831/#pairing` on Laptop A.
2. Configure:
   - **Device Role**: `Host`
   - **Local Device Identifier**: `laptop-alpha`
   - **Sync Root Directory**: `C:\Users\...\disposable_test_a`
   - **Listen Address**: `0.0.0.0`
   - **Peer Service Port**: `47832`
   - **Local Certificate**: `certs/host.crt`
   - **Local Private Key**: `certs/host.key`
   - **CA Certificate**: `certs/ca.crt`
   - **Expected Peer Certificate Pin**: Paste Laptop B's 64-hex client certificate fingerprint.
3. Click **Validate Configuration** to verify paths and compute local certificate pin.
4. Click **Save & Activate Configuration**.
5. Navigate to **Peer Connection** and click **Start Service ▶**. The status badge changes to `LISTENING`.

### Step 3: Configure Laptop B (Client)

1. Open `http://127.0.0.1:47831/#pairing` on Laptop B.
2. Configure:
   - **Device Role**: `Client`
   - **Local Device Identifier**: `laptop-beta`
   - **Sync Root Directory**: `C:\Users\...\disposable_test_b`
   - **Peer Host Address**: Laptop A's LAN IPv4 address (e.g. `192.168.1.105`)
   - **Peer Service Port**: `47832`
   - **Local Certificate**: `certs/client.crt`
   - **Local Private Key**: `certs/client.key`
   - **CA Certificate**: `certs/ca.crt`
   - **Expected Peer Certificate Pin**: Paste Laptop A's 64-hex host certificate fingerprint.
3. Click **Validate Configuration** and then **Save & Activate Configuration**.
4. Navigate to **Peer Connection** and click **Connect & Synchronize ▶**.

### Step 4: Review, Approval, and Commit

1. Both laptops perform mutual TLS verification and exchange Merkle manifests.
2. The negotiated plan appears in the **Synchronization Center**.
3. Inspect planned Additions, Modifications, and Deletions.
4. If conflicts exist: Commit is blocked until conflicts are resolved.
5. In **Approval Workflow**:
   - Check `[x] I approve the planned file additions and modifications.`
   - If deletions exist, check `[x] I separately confirm the permanent deletion of <N> files.`
   - Click **Approve & Proceed to Transfer →**.
6. View real-time byte counters and file names in **Transfer Progress**.
7. Once complete, session records are stored in the local SQLite ledger and visible in **Activity & Recovery**.

---

## 5. UI vs. CLI Feature Matrix

| Feature / Operation | Web Dashboard | CLI Command |
|---|:---:|:---:|
| Local folder comparison | Supported (`#synchronize`) | Supported (`--local`) |
| Local synchronization execution | Supported (Interactive approval) | Supported (Interactive prompt) |
| Local snapshot versioning | Supported (`#versions`) | Supported (`--versions`) |
| Guarded snapshot restoration | Supported (Confirmation dialog) | Supported (`--restore`) |
| Merkle manifest leave inspection | Supported (`#merkle`) | Engine internal / logging |
| Fixed-size chunk reuse metrics | Supported (`#chunks`) | Engine internal / logging |
| Max-heap priority queue inspection | Supported (`#scheduler`) | Engine internal |
| Peer mTLS configuration validation | Supported (`#pairing`) | Supported via config file validation |
| Leaf certificate SHA-256 pin compute | Supported (`#pairing`) | OpenSSL CLI required |
| Start/stop Host peer listener | Supported (`#connection`) | Supported (`--peer-host`) |
| Client peer connect & sync | Supported (`#connection`) | Supported (`--peer-sync`) |
| Plan review & conflict flagging | Supported (`#peer-sync`) | Terminal table output |
| Interactive cryptographic approval | Supported (`#approval`) | Interactive terminal prompt `[y/N]` |
| Destructive deletion confirmation | Supported (Separate checkbox) | Interactive terminal prompt `[y/N]` |
| Live honest transfer progress | Supported (`#progress`) | Terminal progress events |
| Peer session history & ledger | Supported (`#peer-activity`) | SQLite CLI inspection |
| Crash recovery diagnostics | Supported (`#peer-activity`) | CLI startup reconciliation |

---

## 6. Security Boundaries & Controls

1. **Dashboard Loopback Isolation**:
   - Bind address: `127.0.0.1` using Windows Winsock `SO_EXCLUSIVEADDRUSE`.
   - Host header validation: Requests with unexpected Host headers receive `403 Forbidden`.
   - Origin header validation: All mutating POST endpoints enforce `Origin: http://127.0.0.1:<port>`. Cross-origin browser requests receive `403 Forbidden`.
   - CSRF protection: Random 64-hex session token required on every mutating API request.
   - Content Security Policy (CSP): Strict CSP headers (`default-src 'self'`) prevent inline script injection and external resource loading.

2. **Peer Transport Security**:
   - Mutual TLS 1.3 encryption with client and server certificate verification.
   - Leaf certificate SHA-256 fingerprint pinning: Connections immediately terminate if the presented certificate fingerprint does not match the configured 64-hex pin.
   - Zero private key leakage: Private keys are loaded into OpenSSL memory exclusively inside the C++ engine; never returned via HTTP, logged, or exposed in frontend code.

3. **Safety Enforcement**:
   - Approvals are cryptographically bound to the negotiated `plan_hash`.
   - Deletions require explicit separate confirmation.
   - Unresolved conflicts strictly block commitment.
   - Destination files remain untouched if approval is declined or connection aborted.

---

## 7. Integrated Dashboard Navigation Architecture

The unified MerkleChain dashboard seamlessly hosts all 10 Local Workspace views alongside the 7 Peer Network views in a single responsive interface:

1. **Routing System**:
   - Client-side vanilla hash routing (`#overview`, `#pairing`, `#connection`, `#peer-sync`, `#approval`, `#progress`, `#peer-activity`, `#synchronize`, `#versions`, `#algorithm`, `#merkle`, `#chunks`, `#scheduler`, `#activity`, `#settings`). Deprecated `#devices` route safely redirects to `#synchronize`, and deprecated `#benchmarks` redirects to `#overview`, with device pairing and remote authorization maintained exclusively in the Peer Network (`#pairing`).
   - Browser `hashchange` event listener manages state transitions, enabling natural browser Back and Forward history navigation.
   - Unknown or invalid hashes fall back safely to `#overview` without uncaught exceptions.
   - Direct deep-linking (e.g., opening `http://127.0.0.1:47831/#algorithm`) immediately activates the target section and synchronizes breadcrumbs.

2. **Automated Verification**:
   - `tests/test_dashboard_navigation.js`: Automated Node.js integration test verifying view presence, hash synchronization, deep linking, invalid route fallback, history navigation, and offline API resilience.
   - `tests/peer_dashboard_tests.ps1`: End-to-end PowerShell integration suite validating all views, CSRF, security boundaries, and automated navigation tests (71 assertions passed).
   - `tests/dashboard_smoke.ps1`: Verified local scan, planning, approval enforcement, SQLite ledger, and snapshot endpoints.

