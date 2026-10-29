# Architecture

The current vertical slice is divided into contracts under `include/merklechain` and implementations under `src`:

- `types.hpp`: shared value types and enums.
- `hash`: OpenSSL streaming SHA-256 and deterministic Merkle root.
- `scanner`: recursive regular-file enumeration, canonical relative paths, scan warnings.
- `sync`: manifest comparison and explicitly approved staged A-to-B copy.
- `storage`: SQLite activity persistence.
- `main`: command-line entry points and user interaction.

The Merkle tree sorts paths lexicographically. Each leaf hashes the concatenated bytes `leaf` + UTF-8 canonical relative path + lowercase hexadecimal SHA-256. Each parent hashes `node` + left child hex digest + right child hex digest; an unpaired final child is duplicated. The hash fields have fixed 64-character encodings, so this preserves the existing deterministic encoding without delimiters. The empty tree hashes `MERKLECHAIN-EMPTY-v1`. Roots detect manifest differences; destination content is still independently rehashed after each copy.

The scanner skips symlinks and the `.merklechain` application directory. It records scan warnings and marks the manifest incomplete when file enumeration or hashing fails. Incomplete manifests cannot produce a plan. Destination-only paths are represented as preserved entries and never deleted during ordinary sync. Existing targets are moved into a recovery directory before the staged file is committed.

`ActivityStore` migrates the earlier `file_activity` table in place, retaining old rows and adding start/completion timestamps, actual staged bytes, and a verification result. `VersionStore` creates full manifest snapshots in SQLite and stores each unique file payload once under its SHA-256. `version_files` references `content_objects`; SQLite triggers keep object reference counts in step with version entries. Snapshots form an explicit parent chain. Restore requires approval, checks the stored manifest and every object, takes a current-state recovery snapshot, applies verified ADD/MODIFY operations, moves paths absent from the selected version into recovery storage, then verifies the final Merkle root. A partial restore retains its recovery snapshot and per-file backups for manual recovery.

Network transport, HTTP/API, and UI are not yet part of this running architecture. Local mode does not start a listener.
