# MerkleChain Test Handoff Package

**Document Version**: 1.0 (Stage 9 Continuation)  
**Date**: 2026-10-25  
**Target Environment**: Windows 11 Enterprise / Pro (64-bit)  
**Security Status**: Inactive under Windows Application Control (Error 4551); awaits authorized execution environment or legitimate administrator code signing.

---

## 1. Build Instructions and Required Dependencies

### Required Toolchain (MSYS2 UCRT64)
- **C++ Compiler**: GCC 15.2.0 (x86_64-w64-mingw32-g++) targeting C++17
- **Build Tool**: GNU Make 4.4.1 (`mingw32-make.exe`)
- **Cryptography**: OpenSSL 3.5.2 (`libssl-3-x64.dll`, `libcrypto-3-x64.dll`, headers via `pkg-config`)
- **Database**: SQLite 3.50.4 (`libsqlite3-0.dll`, headers via `pkg-config`)
- **System Libraries**: `-lws2_32 -lole32 -lshell32 -luuid -lbcrypt`
- **Shell**: PowerShell 5.1+ or PowerShell 7+

### Build Commands
Run from the repository root:

```powershell
# 1. Build production executable (build/merklechain.exe)
C:\msys64\ucrt64\bin\mingw32-make.exe all

# 2. Build test suite executable (build/tests.exe)
C:\msys64\ucrt64\bin\mingw32-make.exe build/tests.exe

# 3. Clean build artifacts
C:\msys64\ucrt64\bin\mingw32-make.exe clean
```

> [!NOTE]
> Compilation uses strict diagnostic flags: `-std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2`. Both executables build cleanly with zero compiler and linker warnings.

---

## 2. Test Execution Command and Expected Reporting Format

### Execution Commands

In an authorized environment or with an administrator-signed binary:

```powershell
# Preferred: Automated PowerShell runner with accurate telemetry
powershell -NoProfile -File tests/run_tests.ps1

# If using an administrator-approved code signing certificate:
powershell -NoProfile -File tests/run_tests.ps1 -SignCertThumbprint <CERT_THUMBPRINT>

# Alternative: Direct GNU Make target (MSYS2 UCRT64 environment)
C:\msys64\ucrt64\bin\mingw32-make.exe test
```

### Expected Reporting Format
The test runner streams check outcomes in real time:
- Individual checks: `[PASS] <description>`, `[FAIL] <description>`, or `[SKIP] <description>`.
- Core engine summary: `Test checks: <passes> passed, <failures> failed, <skips> skipped`.
- Final banner format:
  - **Success**: `[SUCCESS] All executed tests passed in <duration>s (<passCount> passed, <skipCount> skipped). (Exit Code: 0)`
  - **Failure**: `[FAILED] Test run exited with error code: <exitCode> in <duration>s (<failCount> failed, <passCount> passed, <skipCount> skipped).`
  - **Security Block**: `[BLOCKED] Execution blocked by Windows Code Integrity / Smart App Control policy (Error 4551).`

---

## 3. The 15 Peer-Service Scenarios & Current Verification Status

All 15 peer-service integration tests are fully implemented and registered in `run_peer_service_tests()` ([tests/peer_service_tests.cpp](file:///c:/Users/Aayush/OneDrive/Desktop/DATA.S%20MERKLE/tests/peer_service_tests.cpp)):

| # | Scenario Title | Key Verification & Assertions | Status in Current SAC Environment |
|---|----------------|-------------------------------|-----------------------------------|
| 1 | Valid Bilateral TLS Sync | End-to-end mTLS handshake, bilateral file exchange, Merkle root convergence. | Unexecuted in current invocation (Code-complete; passed in prior baseline) |
| 2 | Wrong Certificate Pin Rejection | Rejects peer whose certificate DER SHA-256 does not match configured pin. | Unexecuted in current invocation (Code-complete; passed in prior baseline) |
| 3 | Untrusted Certificate Rejection | Rejects client certificate issued by a CA unknown to the host trust store. | Unexecuted in current invocation (Code-complete; passed in prior baseline) |
| 4 | Bidirectional Add/Modify | Concurrent additions and modifications across both peers merge without data loss. | Unexecuted in current invocation (Code-complete; passed in prior baseline) |
| 5 | Independent Non-Conflicting Edits | Separate files edited concurrently on both peers merge cleanly to identical roots. | Unexecuted in current invocation (Code-complete; test timing aligned) |
| 6 | Concurrent Conflicts Detection | Concurrent edits on identical file detected as conflict; aborts without disk mutation. | Unexecuted in current invocation (Code-complete; passed in prior baseline) |
| 7 | Interactive Approval Declined | Declining plan approval or deletion confirmation terminates cleanly without mutations. | Unexecuted in current invocation (Code-complete; passed in prior baseline) |
| 8 | Invalid/Stale Plan Rejection | Host rejects client approval containing tampered or stale plan hash with Error frame. | Unexecuted in current invocation (Code-complete & registered) |
| 9 | Mid-Transfer Disconnect | TCP disconnect during chunk stream fails closed without leaving corrupted files. | Unexecuted in current invocation (Code-complete & registered) |
| 10 | Corrupt File Data Rejection | Staging SHA-256 hash mismatch throws and prevents destination commit. | Unexecuted in current invocation (State machine & exception handling corrected) |
| 11 | Destination Preservation on Failure | Pre-existing destination file remains untouched when preparation fails. | Unexecuted in current invocation (State machine & exception handling corrected) |
| 12 | Recovery from Interrupted Replace | Recovers destination from `.mc-retiring-*` artifact during startup reconciliation. | Unexecuted in current invocation (State machine transition corrected) |
| 13 | Idempotent Second Sync (No-op) | Subsequent sync with no changes executes 0 operations and preserves roots. | Unexecuted in current invocation (Code-complete & registered) |
| 14 | Durable History and Baselines | Both peers record durable activity in `activity.sqlite3` and matching baseline roots. | Unexecuted in current invocation (Code-complete & registered) |
| 15 | Path Traversal Request Rejection | Host rejects `../outside.txt` file requests with Error frame. | Unexecuted in current invocation (Code-complete & registered) |

> [!IMPORTANT]
> Because Windows Smart App Control blocked execution of `build/tests.exe` (Win32 Error 4551), **0 tests were executed in the latest invocation**. Compiling tests does not constitute passing tests. Full validation requires execution in an administrator-authorized environment.

---

## 4. Administrator Authorization Requirements

### Context
Windows 11 Smart App Control / Windows Defender Application Control (WDAC) enforces policy ID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}` (`VerifiedAndReputableDesktop`). Newly compiled binaries in user directories are blocked by default.

### Mandatory Compliance Rules
- **Do not** disable Smart App Control or place it in "Off" mode.
- **Do not** disable Windows Defender Firewall.
- **Do not** attempt registry tampering or memory injection to bypass policy.

### Legitimate Authorization Options
1. **Option 1: Enterprise Code-Signing (Recommended for Production Workstations)**:
   - The device administrator signs `build/tests.exe` with an Authenticode certificate trusted by `Cert:\LocalMachine\Root` or `Cert:\LocalMachine\TrustedPublisher`.
   - If WDAC is enforced via managed policies, the signer's public key must be included in a supplemental WDAC policy rule.
   - Run: `powershell -NoProfile -File tests/run_tests.ps1 -SignCertThumbprint <THUMBPRINT>`.
2. **Option 2: Authorized Staging / Evaluation Environment**:
   - Execute the test suite on an administrator-managed testing machine where Application Control is configured in Audit/Evaluation mode or where a path rule authorizes the build directory.

---

## 5. Disposable-Folder Procedure for Subsequent Two-Laptop Acceptance Testing

Once automated tests pass in an authorized environment, execute the physical two-laptop validation protocol between Laptop A (Host) and Laptop B (Client) over LAN.

### Step 1: Disposable Directory Setup
Do not use personal or production directories. Create clean disposable directories:
- **Laptop A**: `C:\MerkleChain-Test\A`
- **Laptop B**: `C:\MerkleChain-Test\B`

### Step 2: Credential & Certificate Generation
1. Generate an offline Root CA on secure, isolated media:
   ```bash
   openssl req -x509 -newkey rsa:4096 -days 30 -nodes -keyout ca-key.pem -out ca.pem -subj "/CN=MerkleChain Test CA"
   ```
2. Generate Host identity on Laptop A (private key never leaves Laptop A):
   ```bash
   openssl req -newkey rsa:2048 -nodes -keyout host-key.pem -out host.csr -subj "/CN=Laptop A"
   openssl x509 -req -in host.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out host.pem -days 7
   ```
3. Generate Client identity on Laptop B (private key never leaves Laptop B):
   ```bash
   openssl req -newkey rsa:2048 -nodes -keyout client-key.pem -out client.csr -subj "/CN=Laptop B"
   openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client.pem -days 7
   ```
4. Compute SHA-256 certificate fingerprints:
   ```bash
   openssl x509 -in client.pem -outform DER | openssl dgst -sha256
   openssl x509 -in host.pem -outform DER | openssl dgst -sha256
   ```

### Step 3: Configuration Files
- **Laptop A** (`config/peer_host.json`):
  Copy from [config/peer_host.example.json](file:///c:/Users/Aayush/OneDrive/Desktop/DATA.S%20MERKLE/config/peer_host.example.json). Set `sync_root` to `C:/MerkleChain-Test/A` and `expected_peer_sha256` to Client's exact 64-hex fingerprint.
- **Laptop B** (`config/peer_client.json`):
  Copy from [config/peer_client.example.json](file:///c:/Users/Aayush/OneDrive/Desktop/DATA.S%20MERKLE/config/peer_client.example.json). Set `sync_root` to `C:/MerkleChain-Test/B`, `host_address` to Laptop A's numeric LAN IPv4 address, and `expected_peer_sha256` to Host's exact 64-hex fingerprint.

### Step 4: Physical Acceptance Scenarios
1. **Initial Addition**: Add `note_a.txt` on A and `note_b.txt` on B. Verify both files sync to both laptops and final Merkle roots match.
2. **Content Modification**: Edit `note_a.txt` on A. Run sync from B. Verify updated content propagates to B.
3. **Independent Edits**: Edit `note_a.txt` on A and `note_b.txt` on B concurrently. Verify non-conflicting merge.
4. **Conflicting Edits**: Edit `shared.txt` with different content on both sides. Verify sync detects conflict and aborts without disk mutation.
5. **Deletion Confirmation**: Delete a file on B. Verify interactive prompt requires explicit confirmation before removing on A.
6. **Cancellation**: At approval prompt, decline (`NO`). Verify zero disk mutations.
7. **Network Disconnect**: Disconnect Wi-Fi during transfer of a 100 MB file. Verify failure fails closed with no destination corruption.
8. **No-op Sync**: Run sync immediately after successful sync. Verify 0 operations reported.

---

## 6. Credential & Personal File Audit Confirmation

- **Private Keys**: Verified zero private keys (`*.key`, `*.pem`, `*.pfx`) in `config/`, `src/`, or root. All key material is generated ephemerally inside unit tests or provided via external administrator paths.
- **Real Credentials**: Verified zero hardcoded credentials, tokens, or network secrets in configuration files.
- **Personal Files**: All paths refer to disposable test paths (`C:/MerkleChain-Test/A`, `C:/MerkleChain-Test/B`).

---

## 7. Production Readiness Declaration

> [!WARNING]
> **MerkleChain is NOT certified production-ready.**  
> While code compilation is 100% clean and core engine logic is verified, the system cannot be declared production-ready until:
> 1. The full automated test suite is executed and passes in an authorized environment.
> 2. The physical two-laptop acceptance protocol has been fully verified on separate hardware over a local network.
