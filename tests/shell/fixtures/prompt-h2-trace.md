# H2 build-identity Linux trace

`prompt-h2-debian-bookworm-glibc-aarch64.strace` is a real non-root capture
on Debian bookworm / glibc / aarch64 with the build-identity walk (raw capture
SHA-256 `22f66acfeb1fcab7d1c29f9a571288db0018c6466ed7259830d948fb413c97eb`).
All 3566 physical records remain, including shell setup. The pinned binary
tree is 1169–1173 and contains 2547 parsed records, including exit events;
all five tasks exit successfully. No syscall fixes are projected onto it.
The older N3 and N4 fixtures remain available as historical regressions.

Machine paths and hostname use `USER`, `SOURCE`,
`CASE_BUILD_IDENTITY_TRACE_0000000`, and `TRACE_HOST` placeholders. The long
case placeholder preserves the original base path byte length, so normalized
hex-encoded context components retain their actual 60-byte chunk boundaries.
The two executable readlink results use the normalized target string length
(30 rather than 32 bytes); all other byte counts and opaque serialized buffers
remain historical evidence, not replayable snapshots.

The installed `bin/bingsu` symlink resolves to
`/home/USER/target/debug/bingsu`. The helper observes the link twice (resolution
and binding revalidation), walks its target ancestors with search-only,
no-follow directory descriptors, checks the final regular file by held
parent/name, opens it with the resolver's exact no-follow/nonblocking flags,
and obtains its metadata through libc's empty-name stat variants. It reads
no executable contents. The target is learned from earlier readlink results
in each process's trace; the budget contains no target path constant.

The portable tests also cover a second relative ancestor link and reject
unrelated readlinks, content I/O on ancestors or the executable, extra paths,
unheld/closed descriptors, future link evidence, followed walks, truncated
link output, missing regular-file verification and relaxed final-open flags.
