# E4 Linux trace provenance

Captured on 2026-10-26 in a `rust:1.98-slim-bookworm` container, as the
non-root `tester` user (uid 1000), on Debian bookworm / glibc / aarch64.
These are the existing E4 captures, reduced on the same date, not a new run
or a projection of successful collection. The binaries were debug builds:
the installed `bin/bingsu` resolves to `/home/tester/target/debug/bingsu`,
and the pinned collector is `/home/tester/target/debug/bingsu-collect`.
The corresponding build targets are `cargo build -p bingsu -p bingsu-collect`
(without `--release`); the original build command/image digest was not saved
in the trace. The checkout at reduction is
`a246860110c7b1dc4f0fdc9ff9a84bce0ca5b5e3` with uncommitted gate/test edits;
this is not an independently verified capture-time source hash.

The capture test is
`test_prompt_binary_names_only_allowed_system_paths_and_pinned_roots`,
parametrized as global-missing (`_0`) and global-present (`_1`). It initializes
the shell with trusted roots, then runs Bash with hostile prompt-time path
variables. Its capture command is:

```text
strace -f -q -y -s 65536 -e trace=all -o TRACE \
  bash --noprofile --norc /home/tester/pt/test_prompt_binary_names_only_N/s.bash
```

The unmodified local sources remain at
`target/e4/linux-traces/test_prompt_binary_names_only_{0,1}.trace`.

| Capture | Raw SHA-256 | Raw bytes / physical records |
| --- | --- | ---: |
| `_0` | `16a738c1f99353367aa6660cd948a6accbf336c1f2164227ac3dcfca60065a5f` | 104,629,300 / 3,820 |
| `_1` | `30433e87cb8a2a9dfd0a13878f3929643384d9c55643b81d080c46a9f7819710` | 368,328 / 2,445 |

| Fixture | Retained PIDs | Physical records / parsed records including exits | Bytes (uncompressed) |
| --- | --- | ---: | ---: |
| `prompt-e4-linux-0.strace` | 3467, 3468, 3469 | 3,410 / 3,068 | 444,055 |
| `prompt-e4-linux-1.strace` | 3479, 3480, 3481 | 2,040 / 1,695 | 258,217 |

## Reduction and verification

1. Use the gate's `tree(lines, pinned_exe)` to retain the prompt from its
   initial exec, plus every descendant/thread. Drop only shell/setup records
   outside that scope (410 and 405 records respectively). Neither capture
   reaches a collector exec; no collector records were removed.
2. On `read`, `pread64`, `readv`, `preadv`, and `preadv2` records, including
   resumed records, replace each nonempty quoted buffer with `"<payload>"`.
   Keep empty EOF buffers. For vectored reads only quoted iov buffer contents
   change; vector structure and lengths remain. This changes 912 physical
   records in `_0`, and 25 in `_1`.
3. Keep all other bytes in retained records, including write payloads for
   diagnosis, paths, fd annotations, offsets, flags, requested lengths,
   return values, errors, signals, exits, and unfinished/resumed interleaving.
   In particular, do not strip `readlink`/`readlinkat` results: the gate needs
   those strings to follow executable identity.
4. Parse both the original scoped trace and the reduced trace. Compare every
   record in order: PID, syscall, return, index and argument list must match,
   allowing only the quoted buffer substitutions in argument 1 of read-family
   calls. Both parses have zero errors. Both files fit the existing fixture
   size range without compression; the old `.xz` files are removed.

Reduced SHA-256 values (also asserted by the replay test):

- `_0`: `66caaeed9d79a542f5d6837581e96cc9e00f907d996a9220c5709ad48108e684`
- `_1`: `4dde46365d2758ba745a656fa7d116603513d4858cde4c65e0b470d4e5f9c34c`

The placeholders are not actual bytes read and do not claim to match return
lengths. These are syscall-shape fixtures, not replayable file snapshots.
The replay retains exact fd-operation inventories, rejects injected write,
fcntl mutation, dup and expanded statx-mask calls on the real `_0` collector
fd, and retains the synthetic global-input mutation controls. `_1` must still
fail the positive global-input coverage assertion.

## `_1` helper exit investigation

The following line numbers refer to the **unmodified** `_1` source above.
Helper PID 3480 exits normally with code 1 at line 2444; watchdog thread 3481
exits with code 0. There is no helper SIGKILL, SIGXCPU or seccomp refusal.

- Lines 1706–1735 read the existing snapshot and sequence. Decoding the
  original 96-byte sequence buffer gives generation 1 and verified 1; neither
  counter is near overflow.
- Configuration absence/parent revalidation finishes at line 2374. The final
  clock observation is lines 2375–2396: boot ID reads succeed, proc/ns and
  timens metadata succeed, and both namespace links are `time:[4026532442]`.
  The boot ID and namespace agree with the earlier observations.
- Lines 2397–2408 close the retained configuration ancestor fds. Lines
  2409–2417 verify `snapshot.lock` and try to recover the four stage names:
  `.sequence.stage`, `.snapshot.stage`, `.last-good.stage`, `.marker.stage`.
  All four opens return ENOENT. These are cleanup probes, not the initiating
  error. No sequence stage creation was attempted.
- Lines 2418–2424 unlock and close the snapshot lock, store and runtime fds.
  After `getuid`, watchdog shutdown/futex joining and signal-stack cleanup,
  the helper calls `exit_group(1)`.

There are **zero helper write/writev/pwrite64/pwritev calls** in this capture,
so no error was written to log or state files. Both prompt and helper argv
contain `--log-level=off`. `commands/log.rs::event` returns immediately for
that level. The source's `refresh incomplete` report is therefore suppressed;
it is not a message recovered from a file.

The matching path is `commands/refresh.rs::run`: after `loader.revalidate()`
and `loader.verified()`, the clock check at `let now = b.check(clock)?`
(line 299 at reduction) precedes sequence staging and the broker. `Budget`
allows 500 ms of refresh work, capped by 2 seconds from process start.
The trace reaches that final clock observation but never creates the next
sequence stage. With valid sequence counters, the trace strongly points to
a rejected clock/time budget at this checkpoint. `LockedStore::drop` then
runs `recover`; `refresh_with_broker` maps the error to `Incomplete`, and
`commands/helper.rs::run` maps that result to exit code 1. The broker's
`git_global::attach` and collector verification were never reached.

This supports a **tracing-environment deadline artifact**, rather than an
error while reading present global config. It does not prove that verdict:
the capture has no timestamps, vDSO clock values are absent, and logging is
disabled. A clock failure/regression cannot be conclusively excluded from
this trace. A same-container comparison with and without tracing is still
needed to establish that the real global-present collection path succeeds.
That follow-up was blocked during reduction by permission denied on
`/Users/hanyul/.colima/default/docker.sock`; no Linux rerun is claimed.
Do not treat the passing path replay as successful collection coverage or
relax product deadlines/the positive coverage check to make this pass.

`_0` also is not an end-to-end success capture: it checks the collector
executable and observes all three missing global files, but later dies from
SIGXCPU during collection catalog work. Its fd-shape evidence remains useful.
