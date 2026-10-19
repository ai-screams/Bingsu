# N4 Linux trace provenance

`prompt-n4-debian-bookworm-glibc-aarch64.strace` replaces the synthetic N4
fixture. It is the non-root Debian bookworm / glibc / aarch64 **debug** capture
from HEAD `4371ab3`, with the fd and namespace-link fixes below projected onto it. It is **not**
a capture of the fixed binary. The unmodified captures remain in
`target/linux-trace/trace-n4-{nonroot,root}.txt`.

| Capture | Original SHA-256 | Original lines | Adjusted lines |
| --- | --- | ---: | ---: |
| nonroot | `6f45bf97427d3084db30e810b7d8a67837d155e1237893a9e33b5ffefc5f14b5` | 3350 | 3320 |
| root | `b29a4ebcf4b89070f621f56b49080510a0d1141a24577f73144db5167f75d8bf` | 3135 | 3096 |

Both originals reproduce the post-filter `fcntl(F_GETFD) = -1 EPERM` failure.
For each capture the projection removes exactly ten such calls (including
paired unfinished/resumed records), removes the first of each of ten duplicate
kernel `fstatfs` calls, and moves the six `/proc` walk-directory closes before
the filter. That first projection produced 3317 nonroot lines and 2449 parsed calls.
Its local copies remain `target/linux-trace/adjusted-n4-{nonroot,root}.txt`;
they predate the namespace-link projection below.

The committed nonroot fixture retains shell setup and all helper/collector
records. `USER`, `CASE`, `SOURCE` and `TRACE_HOST` replace machine-specific path
components and hostnames; hex-encoded context names are normalized too. As in
the N3 fixture, byte counts and opaque serialized buffers are historical trace
evidence, not replayable snapshot data. Root pid is 2809; helper/collector tree
is 2810–2813. There are 2473 parsed calls in that tree after both projections.

The user-namespace fix projects the committed nonroot fixture further:

| Process | Projection | Reason |
| --- | --- | --- |
| Prompt 2809 | Two namespace opens and their metadata/ACL/close calls become two `readlinkat(ns_fd, name, ..., 28)` calls before seccomp: 10 calls → 2 | Parent-userns nsfs targets may deny open/stat although procfs readlink succeeds |
| Helper 2810 | Each of 16 old `time` open/statfs/statx/fcntl/close groups becomes the verified `timens_offsets` open/statx/statfs/fcntl/close plus two namespace readlinks: 5 calls → 7 | The historical helper only probed `time`; current shared judgement also requires valid `time_for_children` and offsets observations |

The second projection replaces 111 physical records with 114 (3317 → 3320).
It preserves historical unrelated interleaving and fd numbers; gaps where
namespace target descriptors disappeared are intentional. New calls are a
contract projection, not measured timings or evidence of a post-fix run.
Both link results use the captured inode `4026532442`; helper offsets checks
use the procfs facts captured by the prompt. Serialized snapshot/marker bytes
remain historical and do not encode the new domain discriminator.

The trace gate accepts these two relative link names only, under the caller's
own `/proc/<pid>/ns`, with exactly 28 buffer bytes. The prompt requires an open,
filesystem-observed ns directory and rejects namespace target opens. All link
reads are pre-filter; `prompt-syscalls.tsv` is unchanged. The helper's legacy
proc-open allowance remains for the unchanged N3 historical fixture, but its
new readlink allowance has the same name, owner and buffer bounds as the prompt.

The shared parser accepts exactly `time:[<decimal>]`: 1–20 ASCII decimal
digits, nonzero u64, at most 27 bytes, no signs, spaces, NUL or trailing bytes.
Leading zeroes are decimal digits and remain subject to the same length bound.
Reading 28 bytes detects truncation even after a valid 27-byte prefix.
The domain is the fixed nsfs discriminator `0x6e736673` followed by the parsed
inode (two little-endian u64s). `readlink` exposes the inode but no device number;
old device-based markers therefore refresh once. Where target opens work, the
native test compares the parsed inode with `fstat`'s inode directly.

This first prompt finds `contexts-v2` absent and renders the default with a
notice. The helper later publishes. Generated small traces in
`test_prompt_trace_budget.py` separately exercise successful held snapshot
reads, read bounds, descriptor ownership, and refused paths. The historical
N3 capture remains unchanged.

A fresh capture of the fixed binary should cover debug and release, root and
non-root, and the current / last-good / refused-file paths. Run the native
`prompt_read::tests::held_reader_under_real_seccomp` test (its test-only filter
kills any fcntl probe) and `native_publisher_reader_identity_agrees_and_walk_fds_are_closed`
inside a user namespace/rootless container as well. No fcntl allowance was
added to the production syscall table.

Saved OSC 11 observations remain deferred by the N4 review ruling: the
observation file and its address still need a follow-up design. COLORFGBG is
only a bounded display-envelope word and does not change the B1 record format.
