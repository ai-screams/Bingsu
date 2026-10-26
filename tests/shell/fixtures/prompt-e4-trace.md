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

## CI musl global-present: source audit and reproduction

The reported CI `fcntl(13<.../cfg-t/git/config>, F_SETFD, FD_CLOEXEC) = 0`
comes from musl, via this call chain:

1. `commands/helper.rs` broker -> `git_global::attach` -> `load` ->
   `resolve`/`config` -> `git_global::read_bounded`.
2. `std::fs::OpenOptions::open` -> Unix `File::open_c` -> libc `open`.
   In the inspected Rust 1.98.1 source, `std/src/sys/fs/unix.rs:70-73`
   aliases `open` as `open64` for musl; `File::open_c` at line 1381
   supplies `O_CLOEXEC` and calls it. This is not gix or a project fcntl.
3. musl `src/fcntl/open.c`, `open`, lines 16-18: after `__sys_open_cp`,
   a successful fd with `O_CLOEXEC` triggers
   `__syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC)`.
   The original implementation is reproduced in the
   [upstream musl discussion](https://openwall.com/lists/musl/2025/11/25/3).
   The Rust source is also available at
   [Unix File::open_c](https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/sys/fs/unix.rs#L1381).
   CI tracks `stable`, so its exact compiler/musl revision must be recorded
   from that run; the reported syscall alone does not establish a version.

The collector does **not** use this open wrapper:
`PinnedCollector::verify` -> `sys::open_data_at_nofollow` -> `sys::open_at`
calls `libc::openat` directly. musl `src/fcntl/openat.c:16` returns
`syscall_cp(SYS_openat, fd, filename, flags|O_LARGEFILE, mode)` with no
follow-up fcntl (also visible in the
[musl import diff](https://android.googlesource.com/platform/external/musl/+/de1aff4a6d5ce868deb3cdd1686164fd534bbf2f%5E1..de1aff4a6d5ce868deb3cdd1686164fd534bbf2f/)).
Consequently the setter exception is local to `helper_global_input`, not
the shared metadata predicate or collector predicate.

For each successfully opened global config/ignore, the complete normal fd
path is as follows. Configs and the chosen ignore use the same reader.

| Step | Syscall and source | Gate change |
| --- | --- | --- |
| Open | `open`/`openat`, readonly + NONBLOCK + NOCTTY + CLOEXEC; `read_bounded` -> std -> libc | Already allowed, exact path/flags and held fd |
| Close-on-exec | `fcntl(fd, F_SETFD, FD_CLOEXEC)`; musl `open.c` | Only new allowance, exactly three arguments and return 0 |
| Before stamp | `fstat`; `sys::file_stamp` -> `File::metadata` -> Unix `file_attr`. GNU variants use empty-name `statx(..., STATX_ALL, ...)` or `newfstatat(..., AT_EMPTY_PATH)` | Already allowed |
| Read | `read` through `Take<&mut File>::read_to_end` -> `default_read_to_end` -> `Take::read`/`read_buf` -> Unix `FileDesc` | Already allowed, at most cap+1 = 65,537 per request; EOF read counts for empty configs |
| After stamp | Same metadata calls; `sys::file_stamp` compares identity/times/size | Already allowed |
| Debug drop check | `fcntl(fd, F_GETFD)`; `OwnedFd::drop` -> `debug_assert_fd_is_open` (`std/src/os/fd/owned.rs`, `std/src/sys/fs/unix.rs`) | Already allowed |
| Drop | `close(fd)`; `OwnedFd::drop` | Already allowed |

`geteuid()` between the first stamp and reading has no fd argument and is
already in the helper syscall list. `Take` uses the default read-to-end
implementation, not `File::read_to_end`'s size hint/stream-position path:
there is no `lseek`, `pread64`, `readv`, ioctl, mmap, xattr, or fd duplication
to add for these global inputs. Early errors drop the opened file; failed
opens never reach the fcntl. No other new fd calls are authorized.

`test_helper_global_inputs_allow_complete_musl_fd_sequence` is explicitly a
**source-derived synthetic trace**, covering all three successful opens,
empty-config EOF reads, nonempty ignore reads, stamps, setter, and debug/
release close behavior. It is not a replacement for a successful live run.
Injection controls reject clearing/other setter values, wrong arity,
failed setters, other fcntl changes, collector setters and invalid fd/PID
ownership. The Korean `이것을 실패시키는 것:` comments describe each control.

### Reproduce on native x86_64 Linux

`.github/workflows/shell.yml`'s three Shell PTY jobs build **debug**, not
release: `cargo build -p bingsu -p bingsu-collect --target
x86_64-unknown-linux-musl`. All three Dockerfiles install strace. The job
runs as root, copies both binaries to root-owned `/usr/local/bin`, places
test directories under `/root/pytest`, and grants `SYS_PTRACE`. The separate
`filter-calls` job varies debug/release and GNU/musl but runs other selected
tests; it is not these failing container jobs.

From the checkout on a native x86_64 Linux host with the musl Rust target
installed, the focused equivalent is:

```sh
cargo build -p bingsu -p bingsu-collect --target x86_64-unknown-linux-musl
docker build -f tests/shell/containers/cur-d13.Dockerfile -t bingsu-cur-d13 tests/shell/containers
docker run --rm --cap-add SYS_PTRACE -v "$PWD:/w" -w /w \
  -e BINGSU_BIN=/usr/local/bin/bingsu -e PYTHONDONTWRITEBYTECODE=1 \
  -e CI=true -e BINGSU_TEST_SHELLS='bash zsh fish' -e LC_ALL=C.UTF-8 \
  bingsu-cur-d13 sh -c '
    install -m 0755 target/x86_64-unknown-linux-musl/debug/bingsu target/x86_64-unknown-linux-musl/debug/bingsu-collect /usr/local/bin/ &&
    exec python3 -m pytest tests/shell/test_prompt_env_paths.py \
      -k "binary_names_only and global-present" -q -rA -p no:cacheprovider --basetemp=/root/pytest'
```

Use `min-u22` with `BINGSU_TEST_SHELLS='bash zsh'`, or `min-d12` with
`BINGSU_TEST_SHELLS=fish`, to match the other images; this particular test
always invokes Bash. The shape-only fixture and observation-recording env
vars in the full CI suite are not consumed by this focused test.

For the previous local debug/strace timeout, build both binaries with the
same command plus `--release`, and change **both** install paths from
`debug/` to `release/`. For a native, non-container Linux run, point
`BINGSU_BIN` at the absolute release binary, keep its matching collector
beside it, and use a user-owned `--basetemp` under HOME (not world-writable
`/tmp`). macOS cannot run this Linux gate directly; prefer a native Linux
VM/host over x86 emulation for timing evidence.

Release reduces debug computation/drop checks and collector binary size,
but does not guarantee meeting the deadline on an overloaded/traced host.
`CI=true` and `BINGSU_TEST_SHELLS` do not raise the fixed 500 ms work / 2 s
lifetime limits; there is no timeout override in these paths. `BINGSU_BIN`
must be set explicitly or pytest defaults to `target/debug/bingsu`.
The test itself requires all three opens and successful reads, so an early
clock exit remains a failure. Keep the full syscall trace and that coverage
assertion. A new live Linux run was unavailable during this change because
Docker socket access was denied; only portable trace tests were executed.
