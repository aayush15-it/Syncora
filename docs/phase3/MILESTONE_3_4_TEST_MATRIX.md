# Syncora Milestone 3.4 — Adversarial Network Test Matrix

## Overview
This document specifies the comprehensive test matrix designed to validate the Distributed Content-Addressed Storage (CAS) Delta Network Synchronization engine under nominal, edge, and adversarial network conditions.

The test suite is implemented in `tests/peer_sync_cas_delta_tests.cpp` and integrated directly into the primary C++ test runner (`build/tests.exe`).

---

## Complete Test Case Inventory (`CAS-NET-01` to `CAS-NET-21`)

| Case ID | Scenario Name | Category | Fault / Adversarial Injection | Expected Behavior | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CAS-NET-01** | Identical Files Pre-Populated CAS | Nominal / Deduplication | Both peers possess identical file and baseline. | Zero chunk payloads transferred across wire; final Merkle roots match. | **PASS** |
| **CAS-NET-02** | Partial Chunk Reuse (~80% Common) | Nominal / Delta | Tail 20 KB of 100 KB file modified. | Reuses 80 KB unmodified prefix chunks; transfers only modified chunks. >=65 KB wire savings. | **PASS** |
| **CAS-NET-03** | Middle-of-File Modification | Nominal / Delta | 16 KB modified in center of 512 KB file. | FastCDC maintains chunk boundaries before and after edit; transfers only middle chunks; >=400 KB saved. | **PASS** |
| **CAS-NET-04** | File Rename with Pre-Populated CAS | Nominal / Deduplication | File renamed from `original.bin` to `renamed.bin` with unchanged content. | Receiver identifies all chunk hashes locally in CAS; 0 chunk payloads downloaded; old file removed, new file created. | **PASS** |
| **CAS-NET-05** | Corrupted Local Chunk Detection & Repair | Adversarial / Integrity | In-place bit flip injected into receiver's physical CAS chunk file. | Receiver's `verify_object` flags corrupt chunk, requests fresh copy from sender, repairs CAS, and completes file reconstruction. | **PASS** |
| **CAS-NET-06** | Mismatched File SHA-256 in Manifest | Adversarial / Security | Sender presents a manifest where claimed `file_sha256` does not match operation metadata. | Receiver strictly rejects manifest before downloading chunks; operation aborts closed. | **PASS** |
| **CAS-NET-07** | Repeated Content Within Single File | Nominal / Deduplication | 128 KB file constructed from four identical 32 KB blocks. | Duplicate chunk hashes requested at most once; local CAS increments references; >=2 chunks reused locally. | **PASS** |
| **CAS-NET-08** | Duplicate Chunk Delivery & Idempotency | Nominal / Concurrency | Same chunk payload ingested multiple times sequentially. | `put_object` reports `AlreadyExists` idempotently without corruption or data loss. | **PASS** |
| **CAS-NET-09** | Concurrent Bilateral Transfers | Nominal / Concurrency | Simultaneous independent bidirectional transfers across separate peer pairs. | Both transfers succeed without port, file, or database lock contention. | **PASS** |
| **CAS-NET-10** | Truncated Chunk Payload on Wire | Adversarial / Network | Injected network disconnection mid-chunk payload delivery. | Receiver aborts staging before corruption reaches destination; atomic replace never executes. | **PASS** |
| **CAS-NET-11** | Safe-Restart Recovery After Crash | Adversarial / Crash Recovery | Simulated process crash leaving orphan staging debris (`.merklechain-tmp-...`). | Subsequent synchronization session cleans orphan debris, re-syncs cleanly, and reconstructs valid target file. | **PASS** |
| **CAS-NET-12** | Empty File (0-Byte) Handling | Boundary Condition | Synchronization of a 0-byte file via CAS delta protocol. | Empty file produces 0 chunks; manifest has 0 chunks and empty SHA-256; empty file committed correctly. | **PASS** |
| **CAS-NET-13** | Exact Chunk Boundary Modification | Boundary Condition | Data modified at exact canonical FastCDC boundary (4096 / 8192 B). | FastCDC cleanly shifts cut-point; boundary change does not cascade into unrelated chunks. | **PASS** |
| **CAS-NET-14** | Backward Compatibility / Fallback | Protocol Negotiation | Peer advertises only `whole_file` (omitting `cas_delta_v1`). | Host successfully negotiates legacy mode and streams file via `FileData`/`FileEnd` without error. | **PASS** |
| **CAS-NET-15** | Initial Full Sync on Empty CAS | Nominal / Cold Start | Initial synchronization when receiver possesses an empty CAS store. | Receiver downloads all chunks sequentially, verifies hashes, populates CAS, and produces verified target file. | **PASS** |
| **CAS-NET-16** | SessionChunkAuthorizer Security | Adversarial / Security | Malicious request for unapproved file path or unauthorized chunk hash. | Authorizer rejects request before disk read; connection sends Error frame. | **PASS** |
| **CAS-NET-17** | Manifest Exceeds Max Chunks Limit | Adversarial / Resource Exhaustion | Manifest contains more than maximum allowable chunks (>10,000). | Chunker / deserializer rejects oversized manifest; prevents memory exhaustion. | **PASS** |
| **CAS-NET-18** | Reconstructed Byte Count Verification | Adversarial / Integrity | Injected length discrepancy between reconstructed file and manifest `total_size`. | Staging verification detects mismatch; aborts staging file before commit. | **PASS** |
| **CAS-NET-19** | CAS Dual-Barrier Protection Under GC | Adversarial / Concurrency | GC sweep executed concurrently while network transfer is actively reading/writing CAS chunks. | Shared barrier held by receiver/sender blocks GC exclusive lock until transfer and promotion finish. | **PASS** |
| **CAS-NET-20** | Path Traversal Protection in Chunk Manifest | Adversarial / Security | Path containing `../`, absolute drive letters, or `.merklechain` internal paths. | Path validator strictly rejects traversal before any disk access. | **PASS** |
| **CAS-NET-21** | Large Chunk Manifest Stream Handling | Stress / Throughput | Transfer of 1 MiB multi-chunk file across 128+ chunk boundaries. | Complete manifest exchange, missing chunk calculation, batching, and reassembly complete cleanly. | **PASS** |

---

## Regression Test Matrix Summary

| Test Category | Suite File | Total Assertions | Pass | Fail | Skip |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Unit & Adversarial** | `build/tests.exe` | 853 | 852 | 0 | 1 |
| **Collaboration E2E** | `tests/test_collaboration_e2e.ps1` | 34 | 34 | 0 | 0 |
| **Peer Network Dashboard** | `tests/peer_dashboard_tests.ps1` | 71 | 71 | 0 | 0 |
| **Selective Sync & Explorer** | `tests/test_selective_sync_and_explorer.ps1` | 11 | 11 | 0 | 0 |
| **Dashboard Navigation** | `tests/test_dashboard_navigation.js` | 33 | 33 | 0 | 0 |
| **Dashboard Smoke** | `tests/dashboard_smoke.ps1` | 5 | 5 | 0 | 0 |
| **Total Test Checks** | — | **1,007** | **1,006** | **0** | **1** |

*Note: The single skipped test in `tests.exe` corresponds to the Windows directory junction unprivileged creation probe when run in non-elevated developer shells, which skips safely as designed.*
