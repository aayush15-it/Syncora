# Configuration and Peer Provisioning Guide

## 1. Local Configuration Defaults

`config/settings.json` documents default local synchronization and storage parameters.
Local metadata is written beneath the selected sync root in `.merklechain/`:
- **Activity Database**: `.merklechain/activity.sqlite3` (schema migrations, file activity logs, and version metadata).
- **Object Store**: `.merklechain/objects/` (content-addressed version storage).
- **Recovery Directory**: `.merklechain/recovery/` (pre-commit backup snapshots for atomic rollback).
- **Peer Baselines**: `.merklechain/baselines.sqlite3` (per-peer bilateral Merkle baseline records).

---

## 2. Peer CLI Commands

MerkleChain supports authenticated, encrypted peer synchronization via dedicated CLI commands:

- **Host (Listener)**:
  ```powershell
  .\build\merklechain.exe --peer-host --config config/peer_host.json
  ```
- **Client (Initiator)**:
  ```powershell
  .\build\merklechain.exe --peer-sync --config config/peer_client.json
  ```
- **Peer Help & Schema Reference**:
  ```powershell
  .\build\merklechain.exe --peer-help
  ```

Existing local modes (`--local`, `--versions`, `--restore`, and loopback `--dashboard`) remain intact. The legacy `--network` flag remains disabled (exit code 3) to prevent unauthenticated network access.

---

## 3. Secure Certificate & Key Provisioning

MerkleChain enforces mutual TLS (mTLS) with SHA-256 certificate pinning. Plaintext communication is prohibited and has no fallback. Follow these operational security rules when provisioning credentials:

### Rule 1: Generate Private Keys Locally on Each Laptop
Generate each machine's private key directly on that machine so the private key never crosses the network:
```powershell
# On Laptop A (Host):
openssl genrsa -out certs/host-key.pem 3072

# On Laptop B (Client):
openssl genrsa -out certs/client-key.pem 3072
```
Restrict NTFS access control lists (ACLs) so only the executing user can read the private key:
```powershell
icacls certs/host-key.pem /inheritance:r /grant:r "%USERNAME%:F"
icacls certs/client-key.pem /inheritance:r /grant:r "%USERNAME%:F"
```

### Rule 2: Keep the Root CA Private Key Offline
Never place the Certificate Authority (CA) private key on either Laptop A or Laptop B.
Generate the CA on a secure, offline administrative system:
```powershell
# On offline administrative machine:
openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca-key.pem -out ca.pem -subj "/CN=MerkleChain Peer CA"
```
Keep `ca-key.pem` strictly offline on encrypted removable media. Copy only `ca.pem` to Laptop A and Laptop B.

### Rule 3: Certificate Signing via CSRs
Generate Certificate Signing Requests (CSRs) on each laptop and transfer only the CSR to the offline CA:
```powershell
# On Laptop A:
openssl req -new -key certs/host-key.pem -out certs/host.csr -subj "/CN=laptop_a"

# On Laptop B:
openssl req -new -key certs/client-key.pem -out certs/client.csr -subj "/CN=laptop_b"

# On Offline CA Machine:
openssl x509 -req -in host.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out host.pem -days 90 -sha256
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client.pem -days 90 -sha256
```
Copy only the signed leaf certificates (`host.pem`, `client.pem`) and the public root `ca.pem` to the respective laptops.

### Rule 4: Compute Real SHA-256 Fingerprints (Never Use Placeholders)
MerkleChain verifies that the peer presents a certificate whose SHA-256 fingerprint matches `expected_peer_sha256`.
Extract the exact 64-character lowercase hexadecimal hash:
```powershell
# To get Laptop A's certificate fingerprint for Laptop B's config:
(openssl x509 -in certs/host.pem -outform DER | openssl dgst -sha256).split("=")[1].Trim().ToLower()

# To get Laptop B's certificate fingerprint for Laptop A's config:
(openssl x509 -in certs/client.pem -outform DER | openssl dgst -sha256).split("=")[1].Trim().ToLower()
```
*Do not use example fingerprints as real configuration values.*

### Rule 5: Key and Certificate Sanity Verification
Verify that the private key matches the certificate before launching:
```powershell
# Verify modulus matches:
$certMod = (openssl x509 -noout -modulus -in certs/host.pem | openssl md5)
$keyMod  = (openssl rsa -noout -modulus -in certs/host-key.pem | openssl md5)
if ($certMod -eq $keyMod) { "Keys match" } else { "ERROR: Mismatched key and cert!" }

# Verify certificate is not expired and verifies against CA:
openssl verify -CAfile certs/peer-ca.pem certs/host.pem
```

---

## 4. Listener Exposure & Windows Defender Firewall Scoping

### Understanding Listener Bind Addresses
- **Loopback (`127.0.0.1`)**: Accepts connections originating only from the local machine. Used for local testing and web dashboard.
- **Specific LAN IPv4 (`192.168.1.X`)**: Accepts connections arriving on that specific network interface adapter.
- **Any Interface (`0.0.0.0`)**: Accepts connections on **all** active network interfaces (Wi-Fi, Ethernet, VPN, Virtual Switch).

### Firewall Scoping Best Practices
If the Host binds to `0.0.0.0` or a physical LAN interface, incoming traffic will be blocked by Windows Defender Firewall unless an explicit rule is configured.

**CRITICAL SECURITY CONSTRAINTS**:
1. **NEVER disable Windows Defender Firewall.**
2. **NEVER disable or weaken Windows Application Control or Smart App Control.**
3. **NEVER open the port on the `Public` network profile.** Ensure the Wi-Fi connection is marked as `Private` in Windows Network Settings.
4. **Scope the firewall rule strictly** to the specific port, protocol (TCP), and the specific IPv4 address of Laptop B:

```powershell
# Run on Laptop A in an elevated PowerShell session:
New-NetFirewallRule `
    -DisplayName "MerkleChain Peer Host (Restricted)" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 9443 `
    -Profile Private `
    -RemoteAddress 192.168.1.100
```
*(Replace `192.168.1.100` with the actual LAN IPv4 address of Laptop B).*

---

## 5. Peer Configuration Templates

### Laptop A (Host) Configuration: `config/peer_host.json`
```json
{
  "schema_version": 1,
  "role": "host",
  "identity": "laptop_a",
  "sync_root": "C:/MerkleChain-Test/A",
  "bind_address": "0.0.0.0",
  "port": 9443,
  "certificate_file": "certs/host.pem",
  "private_key_file": "certs/host-key.pem",
  "ca_file": "certs/peer-ca.pem",
  "expected_peer_sha256": "4b2e1f8a9c0d3e5b7a6f4e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
  "handshake_timeout_seconds": 10,
  "io_timeout_seconds": 30,
  "max_manifest_files": 100000,
  "max_file_size_bytes": 107374182400
}
```

### Laptop B (Client) Configuration: `config/peer_client.json`
```json
{
  "schema_version": 1,
  "role": "client",
  "identity": "laptop_b",
  "sync_root": "C:/MerkleChain-Test/B",
  "host_address": "192.168.1.50",
  "port": 9443,
  "certificate_file": "certs/client.pem",
  "private_key_file": "certs/client-key.pem",
  "ca_file": "certs/peer-ca.pem",
  "expected_peer_sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  "handshake_timeout_seconds": 10,
  "io_timeout_seconds": 30,
  "max_manifest_files": 100000,
  "max_file_size_bytes": 107374182400
}
```

*Note: Replace `host_address` with Laptop A's actual LAN IPv4 address, and replace `expected_peer_sha256` with each peer's real certificate leaf SHA-256 hash.*
