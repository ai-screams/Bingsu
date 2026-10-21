# Collector experiments

These independent probes add no product dependency or executor behavior.
Run from the checkout root with Python 3.10+, a C11 compiler, and bash/python3
at the Linux system locations. X-14/X-16 also need the existing Rust toolchain;
X-14 needs git and its separate locked dependencies.

```sh
python3 bench/probes/run-collector-probes.py --case X-02 --out target/x02.json --ledger-out target/x02.tsv
python3 bench/probes/run-collector-probes.py --case X-32 --out target/x32.json --ledger-out target/x32.tsv
python3 -m pytest bench/tests/test_collector_probes.py -q -p no:cacheprovider
python3 bench/probes/run-collector-probes.py --case all --out target/collector-probes.json --ledger-out target/collector-acceptance.tsv
```

Each completed C probe is run again with `--mutate-expectation`; it must
exit 90. X-02 changes the expected canary count from one to two; X-32
inverts the SETSID cell's session expectation and still records every cell. Build failures and timeouts cannot count as a
killed mutation. X-14/X-16 use their existing real-kernel harnesses and reject
a mutated evidence expectation. 이것을 실패시키는 것: CLOEXEC 해제 누락,
세션 분리 실패, 관찰하지 않은 셀을 PASS로 처리하는 것.

JSON schema version 1 contains `results`, each with `case`, `platform`,
`kernel`, `libc`, `arch`, `build_id` (SHA-256 of experiment inputs), `outcome`,
and `evidence`. Evidence includes raw records, exit/errno/canary/fd results,
mutation proof, and build/OS metadata. X-32 also records elapsed microseconds
for spawn through child census/reaping, and `close_ns` for the fallback's
explicit close loop (zero for native flag cases); these are experiment costs, not a
product latency budget. `collector-acceptance.tsv` lists every required
environment/architecture/criterion cell and its exact command. Status is
`observed`/`PASS`, `not observed`/`BLOCKED`, or `failed`/`FAIL`. A reviewed
X-32 platform difference may use `observed`/`FAIL` with a reason beginning
`observed platform difference:` and matching complete native JSON evidence.
An observation requires matching JSON evidence. A word saying PASS is insufficient.

Exit 0 means all selected host cells passed; exit 1 is a failed observation;
exit 2 means an unavailable environment or missing acceptance cell. `--case
all` additionally requires the whole ledger to pass, so it returns 2 while any
required VM remains unobserved. `--ledger-out` writes a separate merged ledger;
the checked-in ledger is never silently changed. Review evidence before
copying observed rows into it. Do not substitute synthetic parser fixtures,
emulation, SDK declarations, or deployment targets for native OS observations.

## Linux X-02 matrix

Run on native x86_64 and aarch64 with Linux >=6.3 at `vm.memfd_noexec=0`, `1`,
and `2`. Also run a <=6.2 kernel: the sysctl is absent and the NOEXEC_SEAL flag
must actually return EINVAL before retrying without that flag. Other errors
never enable the retry. Distro backports may require a separately reviewed
matrix row rather than classifying by the release number alone.

The probe never changes sysctl. GitHub CI measures only each runner's default
value. To prepare the other rows, boot a **throwaway test VM**, install the
compiler/bash/python3, and run inside that guest (never on the host):

```sh
# Only inside the disposable guest; repeat for 0, 1 and 2.
sudo sysctl -w vm.memfd_noexec=2
python3 bench/probes/run-collector-probes.py --case X-02 --require-environment linux-ge6.3-noexec2 --out target/x02-noexec2.json --ledger-out target/x02-noexec2.tsv
```

A container shares its host kernel and may inherit a more restrictive ancestor
PID namespace policy. Prefer a disposable VM for sysctl changes; an ordinary
container is sufficient for the default-value row. With this checkout as the
current working directory, the following runs that row without sysctl writes:

```sh
docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 sh -ec 'apt-get update -qq; apt-get install -y --no-install-recommends gcc libc6-dev python3 bash; python3 bench/probes/run-collector-probes.py --case X-02 --out target/x02-container.json --ledger-out target/x02-container.tsv'
```

Use a VM with the requested old kernel for `linux-le6.2-einval`; changing a
container image cannot change its kernel. `/bin/sh` must have a root-owned
system symlink chain to an ELF interpreter. The pinned-fd walk and hostile
link/proc fixtures are experiment code only. Missing `/proc` is tested through
an unavailable proc-fd prefix; this does not claim a separate proc-less VM.
All copied scripts are sealed; the single script fd is made inheritable only
in the exec child. The interpreter fd keeps CLOEXEC. Native exec is tested
on system ELF fds, not on executable memfds.

For existing experiments, use the commands in the ledger. Native musl targets
need `musl-gcc`, the matching Rust target/linker, and Linux UAPI include flags
as in CI (`BINGSU_X16_CFLAGS`). No QEMU result substitutes for a native row.

## macOS X-32 matrix

The minimum **candidate** is macOS 11.0; this experiment does not set the
product support minimum. Run the exact ledger command in native 11.0 VMs on
both architectures. `-mmacosx-version-min=11.0` is only build metadata.
Current macOS observations and `macos-latest` CI do not replace those VMs.

The two flags are exercised separately and together. SETSID alone measures
session separation and can inherit descriptors; CLOEXEC_DEFAULT and the
combined case must retain only the intended dup2 report fd above stdio.
Forced missing-flag/EINVAL cases use only a single-threaded fork child that
calls setsid first, closes every descriptor up to the precomputed hard/system
ceiling except the explicit report fd, then execs. The parent has a concurrent
fd opener, an inheritable fd 1025, and a lowered soft limit 256. Enumeration
of parent descriptors cannot provide this race protection. Other errors
reject fallback. This verifies a candidate fallback, not product installation.
The current product remains unchanged while minimum-VM acceptance is pending.

CI uploads JSON and merged TSV for ubuntu-24.04 x86_64, ubuntu-24.04-arm,
and the actual macos-latest version. Historical X-14/X-16 executions are not
guessed into this ledger; rerun the listed commands to attach evidence.

### X-32 report-fd race (PR #100)

The original macOS 26.6.2 (25G83, Darwin 25.6.0 arm64) artifact contains
successful `setsid` and `cloexec_default` reports, followed by exit 90 at the
report read. Thus `both` lost its report; the fallback cells never ran. That
artifact did not collect the pipe numbers or child status, so it cannot alone
prove an OS-specific flag or session difference.

An instrumented copy of revision 121e34f reproduced the same `both` failure
on macOS 27.0.1 after two successful flag-alone cells:
`cell=both pipe=4,3`, `got=0 status=23552 exit=92 signal=0`.
The [diagnostic record](probes/results/x32-report-fd-race-macos-27.0.1-aarch64.json)
is separate from acceptance evidence. It also records 100 corrected runs with
all cells passing, including 13 naturally occurring writer-fd-3 collisions.
Darwin allocates the two pipe fds separately; the competing opener can release
3 between allocations. With a CLOEXEC writer at 3, `dup2(3,3)` preserves
CLOEXEC, and exec closes the report fd. This affects native spawn file actions
and the fork/exec fallback. The corrected probe moves a writer at 3 to a
CLOEXEC fd >=4 before installing the dup2 action. The native regression forces
this layout for every cell, and removing the correction produces five EOF /
exit-92 cells (post-exec `write` errno EBADF), without losing later records.
See Apple's [pipe allocation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_pipe.c)
and [spawn actions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c).

Every completed cell now has its own outcome, spawn/setup/read/wait errno,
child exit/signal/raw wait status, report byte count, original writer fd, and
session/fd measurements. The normal C executable returns 0 when it finishes
recording; Python derives the suite failure from those observations. EOF,
child failure, malformed records and missing cells remain probe errors. The
merged TSV preserves successful siblings when another cell fails.

CI uses `--allow-observed-platform-differences`. This changes only the CLI
exit policy: JSON and TSV retain FAIL. It requires a pre-existing reviewed
`observed`/`FAIL` input row, matching source build, OS version/build, Darwin,
architecture, compiler/SDK/flags, failure criterion and evidence, plus complete
cells and a verified expectation mutation. Probe crashes, transport errors,
missing cells, new failures, and stale observations always fail CI. Output
ledgers never automatically create reviewed exceptions. No macOS 26 exception
is registered for the fd race: it is a probe bug also reproduced on 27. The
corrected macOS 26 run is still required before claiming its cells pass.
