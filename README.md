# MerkleChain

MerkleChain is a Windows C++17 local-folder synchronization prototype. Its Local Mode scans and hashes two existing folders, builds deterministic Merkle roots, previews an A-to-B plan, requires explicit approval, stages and verifies copies, backs up replaced destination content, and writes activity to SQLite. Files found only in B are preserved during normal synchronization; there is no implicit deletion.

## Requirements

MSYS2 UCRT64 GCC, Make, OpenSSL, and SQLite development headers/libraries. The verified environment versions are GCC 15.2.0, GNU Make 4.4.1, OpenSSL 3.5.2, and SQLite 3.50.4. Install missing dependencies in an MSYS2 UCRT64 terminal:

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-sqlite3 mingw-w64-ucrt-x86_64-pkgconf
```

The Makefile uses relative project paths and selects `C:/msys64/ucrt64/bin/g++.exe` because the `C:\MinGW` shim in this environment fails to start. Adjust `CXX` and `PKG_CONFIG` in the Makefile if MSYS2 is installed elsewhere.

## Build and run

From the project directory:

```sh
mingw32-make
mingw32-make test
mingw32-make run-local
mingw32-make run-dashboard
build/merklechain.exe --help
```

In PowerShell, use an MSYS2 UCRT64 terminal or add `C:\msys64\ucrt64\bin` to `PATH` before launching the executable so its OpenSSL and SQLite runtime DLLs can be found. The Makefile exports that directory for build/test/run targets.

Local Mode asks for Folder A (source) and Folder B (destination), shows the full plan, and only applies ADD/MODIFY items after the user types `YES`. Replaced destination files are retained under `B/.merklechain/recovery/`; SQLite activity is under `B/.merklechain/activity.sqlite3`. Keep that internal directory out of user content. `--network` exits with an explicit not-implemented message and does not open a listener.

### Interactive local dashboard

From the project directory, run:

```sh
mingw32-make run-dashboard
```

Then open `http://127.0.0.1:47831/` in a browser. The server can use a different port with `mingw32-make run-dashboard DASHBOARD_PORT=47832`. It serves only the files in `web/` and binds exclusively to IPv4 loopback. The dashboard uses a compact Workspace/Inspect sidebar and graphite/slate/silver/ice-blue palette. Views include Overview, Synchronize, Devices & Access, Versions, Algorithm Explorer, Merkle tree, Chunks & reuse, Scheduler, Benchmarks, Activity & Diagnostics, and Settings. It offers editable paths and native Windows Browse dialogs, scans and compares through the existing C++ engine, and requires explicit approval before synchronization. Destination-only files remain preserved. Sync responses are based on real executor results and final Merkle-root verification. Version listing and guarded restore use `VersionStore`; activity reads the destination SQLite database. Merkle tree shows real manifest roots and file hashes only (not invented internal nodes). Chunk counters come from actual executor/activity records and are logical payload/source-processing/reuse/staging accounting, not physical disk I/O or network traffic. Devices & Access and benchmark results are clearly marked unavailable where no backend/API exists. Scheduler ordering is a deterministic heap preview, not an adaptive system.

The dashboard API is single-threaded, validates the Host and same-origin Origin, uses a per-process cryptographically random CSRF token, bounds JSON request/response sizes, and retains the reviewed plan server-side for ten minutes. Approved sync requests rescan both folders and compare the current manifest roots and plan fingerprint before execution. The local dashboard listener is not Network Mode; `--network` remains disabled and does not start a listener. Do not expose or proxy this loopback service to other interfaces.

Dashboard runtime coverage and remaining checks are recorded in `docs/IMPLEMENTATION_STATUS.md` and `docs/TEST_PLAN.md`. The native folder picker compiled, but interactive selection/cancellation still needs a manual desktop check in an environment that permits UI automation.

Every approved Local Mode run that contains changes writes a full snapshot of B before the run. A verified run also writes a post-sync snapshot. Content is stored by SHA-256 under `B/.merklechain/objects/`; SQLite version metadata tracks each path reference and parent version. List and restore versions with:

```sh
build/merklechain.exe --versions "C:\\path\\to\\folder"
build/merklechain.exe --restore "C:\\path\\to\\folder" VERSION_ID
```

Restore requires typing `YES`, saves a full pre-restore recovery snapshot, restores the chosen manifest (including removal of paths added later), verifies the final Merkle root, and preserves removed/replaced data under `.merklechain/recovery/`. These are full-content snapshots; differential deltas and retention/garbage-collection policy are not implemented.

## Current implementation status

Implemented: core shared data types; SHA-256 streaming; deterministic path-and-content Merkle tree; recursive regular-file scanner; incomplete-scan refusal; safe relative-path checks; one-way add/modify comparison; manual approval; source and destination revalidation; staged hash verification; recoverable replacement backups; migrated SQLite file activity with lifecycle timestamps, byte counts, result, and verification fields; full content-addressed version snapshots; explicit version parent links; per-path content reference counts; approved restore with recovery snapshot and final Merkle verification.

Not implemented: peer pairing or transfer, orphan-object reconciliation, automatic content-store garbage-collection policy/CLI, differential version storage/retention policy, normal-sync deletion planning, configuration loading/validation, robust cross-process locking, and Network Mode. The version store exposes approved leaf-version deletion and verified collection of unreferenced objects as library operations. Restore uses a pre-restore snapshot and per-file recovery copies; a multi-file restore is recoverable but is not an atomic filesystem transaction. Current validation status is in `docs/IMPLEMENTATION_STATUS.md`.

