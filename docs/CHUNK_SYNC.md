# Fixed-size chunk synchronization

## Current format

Local Mode uses fixed-size chunks. The default is 1 MiB; the execution option
allows a configured size from 1 byte through 64 MiB. Format version 1 is an
ephemeral manifest containing the complete file size and SHA-256, chunk size,
and an ordered descriptor for each chunk:

```text
manifest: version, chunk_size, file_size, file_sha256
chunk:    offset, size, sha256
```

The final chunk can be shorter than the configured size. Empty files have no
chunk descriptors and retain the SHA-256 of the empty byte sequence. Manifests
are calculated from the current files for each synchronization; they are not
persisted or accepted from a remote peer.

## Reuse and reconstruction

For Modify jobs, the executor first confirms that the destination still has
the hash captured by the approved plan. It computes source and destination
manifests. A destination chunk is reused only when its offset, length, and
SHA-256 all match the corresponding source chunk; the bytes are read and hashed
again before use. Other source chunks are read, checked against their chunk
hashes, and written to a sibling staging file. Add jobs have no destination
chunks to reuse.

After reconstruction, every staged chunk and the complete staged file are
verified. The source whole-file hash is checked again. The existing executor
then checks the staged file hash, rechecks source and destination preview
hashes immediately before commit, moves any old destination into recovery, and
renames the staged file into place. Local Mode performs its existing final
destination Merkle-root check before recording the post-sync version.
Approval, scheduler ordering, safe-path/dependency checks, and activity
recording remain in the existing synchronization path. Version restoration
continues to disable chunking and keeps the existing journal/replay flow.

## Fallback and failure behavior

If source chunk metadata is missing or incompatible, chunk reconstruction is
truncated/corrupt, or staged chunk verification fails, the incomplete stage is
removed and the existing whole-file copy path is used. That fallback still
requires the expected complete-file SHA-256. If the source changed after
preview or during chunk transfer, fallback verification fails and the
destination is not committed. A changed destination is rejected by the
executor's before-commit check. Missing destination chunk metadata simply
disables reuse; all source chunks can still be transferred and verified.

The current chunk manifests are local and regenerated, so they cannot become
stale across restarts. Future remote metadata must validate the format version,
chunk size, contiguous offsets, exact lengths, descriptor count, and hashes
before it can be used. Network Mode is not implemented and this code starts no
listener.

## Validation scope

The test source includes disposable fixtures for unchanged files; changes in
the first, middle, last, and exact-boundary chunks; append and truncation;
empty, small binary, and multi-megabyte files; corrupted/truncated staged
chunks; missing/incompatible metadata; and source mutation during transfer.
Test-only faults are guarded by `MERKLECHAIN_TESTING` and are not present in the
production binary. See the latest chunk-sync entry in
`docs/IMPLEMENTATION_STATUS.md` and `docs/TEST_PLAN.md` for actual build and
execution status.

## Current validation and byte benchmark

The current expanded suite completed through the normal Make target with 70
passed and 0 failed. It includes fault-injected manifests with a missing
descriptor, overlapping ranges, incorrect final chunk length, and an invalid
chunk digest; each uses whole-file fallback and verifies the complete result
hash. The application build completed without reported warnings, and
production symbol inspection found no test-only chunk or restore fault hooks.

Run the deterministic payload-byte comparison with `mingw32-make benchmark`.
It generates fixtures under `build/chunk-benchmark-fixtures`, verifies both
outputs by full SHA-256, and removes that fixture directory. The current run
reported:

| Fixture | Whole-file payload | Chunk source payload | Reused chunks |
| --- | ---: | ---: | ---: |
| Unchanged, 8 MiB | 8 MiB | 0 bytes | 8 |
| Small edit, 8 MiB | 8 MiB | 1 MiB | 7 |
| Edit, 64 MiB | 64 MiB | 1 MiB | 63 |
| Binary edit, 3 MiB + 17 bytes | 3 MiB + 17 bytes | 1 MiB + 17 bytes | 2 |

These are deterministic payload counts, not throughput measurements. Local
manifest hashing and destination reads are excluded. Staging uses a sibling
temporary path and rejects an observed symlink; because inspection and file
creation are separate operations, a concurrent local writer to that directory
can still race temporary-file creation. No remote manifest or Network Mode
path is enabled. Version restore continues to disable chunking.

## Windows staging safety and current benchmark status

Chunk and whole-file transfers now write through `StagingFile`. On Windows it
uses `CreateFileW` with `CREATE_NEW` and `FILE_FLAG_OPEN_REPARSE_POINT`, holds
the created file and parent directory handles, rejects a reparse parent or
leaf, checks the resolved parent, and denies external write/delete sharing
while the stage is open. It hashes and renames the same file handle, and it
removes incomplete data through that handle. A pre-existing stage file or
directory causes the operation to fail without deleting that entry. Version
restore remains on the whole-file executor path and restore-journal code was
not changed.

The full test run for the staging helper passed 75 checks with no failures;
the symbolic-link regression was skipped because Windows returned error 1314
for both symlink creation attempts. This run preceded later byte-counter
instrumentation and one executor-level collision assertion. The current
production and test binaries compiled without reported warnings, but the
current test launch was blocked by Application Control error 4551. The
enhanced benchmark also compiled, but its normal target launch was blocked by
the same error, so no updated measurements are reported.

The benchmark reports elapsed microseconds, source bytes processed, reused
destination bytes, final staging bytes written, and scratch-buffer estimates.
It times fixture-excluded source validation, copy/reconstruction, and full
hash verification. Peak process memory is reported unavailable because the
fixture strings remain allocated and process-wide working-set peaks cannot be
isolated per operation. Scratch estimates omit manifest and allocator
overhead. Run the normal targets after an administrator-authorized execution
approval: `mingw32-make test`, then `mingw32-make benchmark`.

The leaf check/create race is closed by `CREATE_NEW`, and the held file handle
prevents another process from replacing that staging leaf before handle-based
rename. Ancestor components and the absolute rename target still use ordinary
Win32 path resolution. Automatic review rejected unvalidated native relative
creation and a broader ancestor-handle rewrite, so resistance to a concurrent
ancestor reparse-point replacement is not claimed.

## Current staging and validation status — 2026-10-24

The executor stages chunk or whole-file output through the retained `StagingFile` handle. `commit_to(target, expected_sha256)` flushes and verifies that handle against the expected full-file digest immediately before renaming. A mismatch refuses commit. The executor additionally checks source/destination mutation before replacement and verifies the committed handle afterward. Recovery backup, journal, and activity paths are unchanged. Cleanup reports failure to the executor, which includes it in the job diagnostic; destructor cleanup remains best effort.

The parent directory handle is held without `FILE_SHARE_DELETE`; the staging leaf is created with `CREATE_NEW`, rejects reparse entries, and remains held without write/delete sharing. No pre-existing entry is removed on a creation collision. This does not secure path resolution for ancestors or the final absolute rename target; concurrent ancestor reparse-point replacement remains outside the guarantee. Restore remains whole-file and journal semantics are unchanged.

Current revision builds: production, test executable, and benchmark all compile with exit code 0 and no reported warnings via `C:\msys64\ucrt64\bin\mingw32-make.exe`. No tests or benchmark were launched in this turn due the known Smart App Control / Application Control error 4551. Current runtime counts are 0 executed, 0 passed, 0 failed, 0 skipped. The historical 75/0 run predates current instrumentation and assertions; it is not current validation.

The reparse/symlink regression was previously skipped with error 1314. Use only an administrator-approved test environment with Developer Mode (for the documented unprivileged `CreateSymbolicLinkW` flag) or the approved `SeCreateSymbolicLinkPrivilege` user right. After administrator approval of binary execution, run the normal complete test target; only after it passes, run the benchmark. No current benchmark measurements are available.

### Build recheck — 2026-10-24

The production, test, and benchmark Make targets were rechecked with the explicit UCRT64 executable and all returned exit 0 as up to date. No runtime tests or benchmark measurements were produced by this recheck. See `docs/IMPLEMENTATION_STATUS.md` for the current security approval requirement and ancestor-path limitation.

### Release-gate status confirmation — 2026-10-24

For the current revision, runtime counts are **0 executed, 0 passed, 0 failed, 0 skipped**. No benchmark measurements are available. Administrator authorization for the test binary under Smart App Control/App Control is required before test execution. The symlink test also needs an approved Developer Mode or symbolic-link privilege configuration; historical error 1314 was a skip. Benchmark only after the full suite passes. Ancestor and final-rename paths remain outside the guaranteed reparse-point protection; Network Mode is disabled.
