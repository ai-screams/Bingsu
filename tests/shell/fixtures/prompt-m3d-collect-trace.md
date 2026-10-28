# Collecting prompt trace provenance

`prompt-m3d-collect-linux-1.strace.gz` is one traced prompt whose refresh helper
started, supervised and published one collecting collector. It was captured on
2026-10-29 in a `rust:1.98-slim-bookworm` container, as the non-root `tester`
user (uid 1000), on Debian bookworm / glibc / aarch64, with release builds
(`cargo build --release -p bingsu -p bingsu-collect`): the installed
`bin/bingsu` resolves to `/home/tester/target/release/bingsu` and the pinned
collector is `/home/tester/target/release/bingsu-collect`. The checkout was
`4df4f96` with the uncommitted edits of the change that added this fixture.

The capture test is
`test_prompt_binary_names_only_allowed_system_paths_and_pinned_roots[global-missing]`
with `--basetemp=/home/tester/pt` (the trace is its `_1` directory). It runs
one untraced prompt in a hand-made repository (`repo/.git` with `HEAD`,
`objects` and `refs/heads`), waits for the helper, then traces the second:

```text
strace -f -q -y -s 65536 -e trace=all -o TRACE \
  bash --noprofile --norc /home/tester/pt/test_prompt_binary_names_only_1/s.bash
```

Reduction: in records of `read`, `pread64`, `write` and `pwrite64` (and
resumed `read`/`pread64` records), the first quoted data buffer longer than 120
characters is cut to its first 120 characters in strace's own truncation form
(`"…"...`). No record was added, removed or reordered; return values and fd
annotations are unchanged. The file is gzip-compressed (`gzip -n -9`).

| Form | SHA-256 | Bytes / records |
| -- | -- | --: |
| Raw | `f8ebd91fef1270b4cefb95a71c4e9ef60f9f87b2ccbfc16e5711aec5bc77f36e` | 4059415 / 5077 |
| Reduced (decompressed fixture) | `18c030e2e135874a418bc047bc6f0dbe731f5821b2bcd9663afefbd3632c8fab` | 811305 / 5077 |

`tools/fsbudget/tests/fixtures/m3d-bookworm-aarch64-shipped-collection.strace`
is the collector task of the reduced trace: every record of pid 1098, in order.
