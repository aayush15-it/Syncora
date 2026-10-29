# MerkleChain Platform — Known Limitations & Operational Boundaries

**System:** MerkleChain (Secure File Synchronization & Collaboration Platform)  
**Date:** October 2026  
**Auditor:** Senior Software Architect & Engineering Specialist  

---

## 1. Architectural & Environmental Boundaries

### 1.1 Native HTTP Daemon Scope
* **Design Purpose:** The built-in native HTTP server in `src/web_server.cpp` is implemented with Windows Sockets (`Winsock2`) specifically as a local management dashboard daemon binding to loopback (`127.0.0.1` / `localhost`).
* **Operational Boundary:** It is not intended to serve as a high-concurrency, internet-facing public reverse proxy (e.g., NGINX, Cloudflare). If MerkleChain dashboard access is required across untrusted networks, it should be placed behind a reverse proxy terminating HTTPS with rate limiting and WAF capabilities.
* **HTTP Protocol Subset:** The lightweight daemon implements standard HTTP/1.1 GET/POST/OPTIONS handling but does not implement intermediate `100 Continue` preliminary handshakes. HTTP clients (such as Windows PowerShell 5.1 `Invoke-RestMethod` or `curl`) sending large request bodies should disable `Expect: 100-continue` headers (`[System.Net.ServicePointManager]::Expect100Continue = $false` or `curl -H "Expect:"`) to prevent socket timeouts.

### 1.2 Fixed Chunk Deduplication Granularity (1MB)
* **Design Purpose:** Files are split into fixed 1MB chunks (`1,048,576` bytes) for chunk manifest generation and deduplication.
* **Operational Boundary:**
  * Chunk synchronization delivers maximum byte-transfer reduction (80%–100%) for modifications, appends, and truncations on files $\ge$ 1MB.
  * For files smaller than 1MB, or for small byte insertions that shift all subsequent byte offsets (the classic rolling-hash sliding window problem), fixed chunks do not reuse trailing content. A future enhancement could introduce Content-Defined Chunking (CDC, e.g., FastCDC or Rabin fingerprints) for sub-chunk insertion resilience.

### 1.3 In-Memory Web Text Editor Size Cap (5MB)
* **Design Purpose:** The host change review UI allows line-by-line inspection and editing of working copy documents directly in the browser.
* **Operational Boundary:**
  * Files larger than 5MB are restricted from the in-browser text editor (`file exceeds text editor size limit (5MB)`) to prevent DOM memory bloat and browser thread freezing.
  * Similarly, line-by-line unified diff calculation (`compute_file_diff`) is bypassed for files exceeding 2MB or containing null bytes, falling back to clean binary file digest comparisons.

### 1.4 Database Concurrency & Scaling (SQLite 3)
* **Design Purpose:** Metadata, version histories, audit events, and peer baselines are stored in SQLite 3 databases (`activity.sqlite3`, `baselines.sqlite3`, `collab.sqlite3`) using Write-Ahead Logging (WAL mode) and synchronous normal pragma.
* **Operational Boundary:**
  * SQLite WAL mode supports high-performance concurrent readers and serialized writers within a single operating system environment.
  * It is not designed for distributed multi-server clustering or concurrent write scaling across network file shares (SMB/NFS).

### 1.5 Windows Code Integrity & Toolchain Constraints
* **Design Purpose:** MerkleChain targets Windows 10/11 64-bit environments with MSYS2 UCRT64 GNU C++17.
* **Operational Boundary:**
  * Under Windows 11 Smart App Control (SAC Policy `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`), newly compiled binaries must strictly maintain standard PE compliance.
  * Stripping DWARF debug symbols (`strip -s`) and avoiding static imports of `bcrypt.dll` and `ole32.dll` is mandatory. Reintroducing static links to `bcrypt.lib` or unstripped debug sections will trigger SAC kernel denial (`0xc0e90002`).

### 1.6 Deletion dual-gate authorization
* **Design Purpose:** Accidental deletions are prevented by requiring both change approval and explicit deletion confirmation.
* **Operational Boundary:** Automated headless synchronization scripts that intend to propagate file deletions must explicitly provide both `approve = true` and `confirm_deletions = true` in their synchronization plan submissions. If `confirm_deletions` is false, all deletions are safely rejected and destination files remain preserved.

