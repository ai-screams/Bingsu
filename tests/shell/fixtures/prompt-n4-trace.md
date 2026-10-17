# N4 Linux trace provenance

`prompt-n4-debian-bookworm-glibc-aarch64.strace` replaces the synthetic N4
fixture. It is the non-root Debian bookworm / glibc / aarch64 **debug** capture
from HEAD `4371ab3`, with the fd fixes below projected onto it. It is **not**
a capture of the fixed binary. The unmodified captures remain in
`target/linux-trace/trace-n4-{nonroot,root}.txt`.

| Capture | Original SHA-256 | Original lines | Adjusted lines |
| --- | --- | ---: | ---: |
| nonroot | `6f45bf97427d3084db30e810b7d8a67837d155e1237893a9e33b5ffefc5f14b5` | 3350 | 3317 |
| root | `b29a4ebcf4b89070f621f56b49080510a0d1141a24577f73144db5167f75d8bf` | 3135 | 3096 |

Both originals reproduce the post-filter `fcntl(F_GETFD) = -1 EPERM` failure.
For each capture the projection removes exactly ten such calls (including
paired unfinished/resumed records), removes the first of each of ten duplicate
kernel `fstatfs` calls, and moves the six `/proc` walk-directory closes before
the filter. Other syscalls, return values, buffer sizes and process trees are
unchanged. The projected traces both pass `assert_prompt_trace_budget`.
Their local copies are `target/linux-trace/adjusted-n4-{nonroot,root}.txt`.

The committed nonroot fixture retains shell setup and all helper/collector
records. `USER`, `CASE`, `SOURCE` and `TRACE_HOST` replace machine-specific path
components and hostnames; hex-encoded context names are normalized too. As in
the N3 fixture, byte counts and opaque serialized buffers are historical trace
evidence, not replayable snapshot data. Root pid is 2809; helper/collector tree
is 2810–2813. There are 2449 parsed calls in that tree after the projection.

This first prompt finds `contexts-v2` absent and renders the default with a
notice. The helper later publishes. Generated small traces in
`test_prompt_trace_budget.py` separately exercise successful held snapshot
reads, read bounds, descriptor ownership, and refused paths. The historical
N3 capture remains unchanged.

The lead must recapture the fixed binary in debug and release, as root and
non-root, including current / last-good / refused-file paths. Run the native
`prompt_read::tests::held_reader_under_real_seccomp` test (its test-only filter
kills any fcntl probe) and `native_publisher_reader_identity_agrees_and_walk_fds_are_closed`
inside a user namespace/rootless container as well. No fcntl allowance was
added to the production syscall table.

Saved OSC 11 observations remain deferred by the N4 review ruling: the
observation file and its address still need a follow-up design. COLORFGBG is
only a bounded display-envelope word and does not change the B1 record format.
