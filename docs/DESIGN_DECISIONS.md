# Design decisions

- Default direction is Folder A to Folder B. No automatic bidirectional merge is attempted.
- A destination-only file is preserved. Deletion is not planned by the current implementation.
- A replacement is staged beside its destination, hashed, then committed by filesystem rename. Any previous destination is retained under `.merklechain/recovery`.
- File identity uses SHA-256 content hashes, not file size or modification time.
- Merkle leaves include both canonical relative path and content hash; tree shape is deterministic.
- The initial transfer unit is a whole file. No claim of block-level transfer or deduplication savings is made.
- Durable activity is stored in SQLite; configuration sample is documentation only until a validated settings loader exists.
- Version history currently uses full snapshots. Unique payloads are content-addressed by SHA-256 and referenced by version/path rows; restoration checks every object hash and the resulting manifest root.
- Restoring a folder state is an explicit approved operation. It first snapshots current state and retains files removed by the restore in the recovery directory.
