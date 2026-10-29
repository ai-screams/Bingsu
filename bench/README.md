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

## F3 CI failure reproduction and time budget

From the checkout root on Linux (Python 3.10+, stable Rust, `cc`, Git,
binutils and `strace` installed), the argv regression needs no product build:

```sh
python3 -m venv /tmp/f3-ci-tests
/tmp/f3-ci-tests/bin/python -m pip install --require-hashes --only-binary=:all: -r tests/shell/requirements.txt
/tmp/f3-ci-tests/bin/python -m pytest bench/tests/test_git_product.py -q -p no:cacheprovider -k normalizes_path_argv
```

To reproduce the native M3b step, including the five real F3 cases:

```sh
export CARGO_PROFILE_RELEASE_STRIP=none
cargo build --locked -j 2 --release -p bingsu -p bingsu-collect
python3 scripts/check_collector_symbols.py target/release/bingsu-collect --sibling target/release/bingsu --unstripped-dir target/release/symbol-audit --strip
python3 bench/git-product.py --prepare target/release/bingsu --out "${RUNNER_TEMP:-/tmp}/measurements/preparation.json"
python3 bench/collector-product.py --prepare target/release/bingsu
CI=1 BINGSU_BIN="$PWD/target/release/bingsu" /tmp/f3-ci-tests/bin/python -m pytest tests/shell/test_collector_security.py bench/tests/test_collector_product.py bench/tests/test_git_product.py tools/fsbudget/tests -q -rA -p no:cacheprovider --basetemp=/tmp/f3-m3b-native
```

The real Linux cases require the host kernel's collector protection features;
a container still uses its host kernel and seccomp policy. The argv regression
above isolates the Python failure from those runtime prerequisites.

First-run inputs supplied for PR #144 at 5776aa9: x86 Linux failed at 14m09s,
ARM Linux at 24m35s, macOS was about 23 minutes before cancellation, and Intel
macOS stopped early at the roots unit test. The late Linux musl release build,
fixture preparation and tests were not yet run. Provisionally allowing 6–9
minutes for that suffix puts ARM at 31–34 minutes before cleanup: unsafe for
the unchanged 30-minute limit.

Planning estimates below are **not measured passing CI durations**. Individual
step logs were unavailable locally. They allow for moving the independent
X-14 builds out of the Linux product jobs, reducing 60 F1 corpus rows from 200
to 20 warm observations (12,000 to 1,200 attempts), eliminating the two extra
macOS cross-target release builds per cell, and bounded evidence packaging.
The supplied macOS elapsed time does not isolate failed cleanup; its original
estimate conservatively treats 23 minutes as the pre-upload envelope.

| Cell | Original full-pass estimate | Revised planning estimate |
| --- | --- | --- |
| ubuntu-24.04 | 20–23 min | 13–20 min |
| ubuntu-24.04-arm | 31–34 min | 21–28 min |
| macos-latest | 24–26 min, excluding the broken recursive upload | 13–22 min |

CI run 4 passed the ubuntu-24.04 and ubuntu-24.04-arm Dedicated collector
cells. Intel macOS failed the F1 analyzer with `live fd reassigned`; adapting
the analyzer to Intel observations is follow-up work, so that cell is excluded
from this PR’s Dedicated collector matrix. macos-latest was cancelled by matrix
fail-fast at 15m05s, not by its own failure. The required F3 matrix is Linux
x86/ARM and macos-latest, with `fail-fast: false` to preserve each cell’s evidence.

The new X-14 job retains native x86/ARM glibc and musl gates, with a separate
20-minute limit (estimated 5–12 minutes). Confirm these estimates with the next
CI run; cache misses and shared-runner load remain uncertain. No timeout was
raised. All real-collection, syscall, resource and exact-PASS checks remain.
F1 timings are observation evidence, not performance gates: each artifact
records `requested_rounds`, all raw samples and `performance_gate: false`.
The local default remains 200; the separate M3c pair benchmark still requires
200 alternating rounds.

On macOS, collection creates `open-flags/root/absolute -> /`. The old
`m3b-traces/**/*.trace` upload [follows symbolic links](https://github.com/actions/upload-artifact/blob/main/src/shared/search.ts) and can search the entire
runner, explaining a long search even with no native strace files. F3 adds
more of these product contexts, not a large native macOS trace stream.
`pack_collector_evidence.py` never follows those links: it compresses every
M3b raw trace and F3 sample JSON, records link targets and byte counts in an
inventory, and preserves complete F1/F2 trees with links as links. The upload
receives explicit archives; packing and upload each have a two-minute bound.
Raw evidence is not truncated. Test output is still uploaded separately.

The Intel `Ancestor { at: 3 }` failure identifies `/System/Volumes/Data` in the
hardcoded `/System/Volumes/Data/home` autofs test, before the locality check.
It is an unestablished test precondition, not evidence of an Intel locality
implementation defect; the runner's precise owner/mode/ACL was not available.
The replacement first pins a private local control root, then injects non-local
and unknown observations into the shared creation routine. It requires that
the locality check was reached and rejects both results without skipping.
The separate native descriptor test still checks the OS locality observation.

## Controlled paired protocol (M3d D1)

`git-product.py`, `collector-product.py` and `n7_measure.n7_pairs` use
`protocol.py`. Existing `measure_pair(base, candidate, rounds)` calls still work;
product-specific metrics and raw observations remain in the result. A successful
measurement has status `OBSERVED`; missing evidence has status `BLOCKED`, never
PASS. Each adapter declares required numeric metrics; any missing field blocks
the session. Balanced block starts are shuffled using the recorded seed.
Legacy n7 front/publication batches are `BLOCKED`, `diagnostic-only`, and
`certification_eligible: false`; their numbers remain under `diagnostic_summary`.
This does not certify formal B5–B7 or change a product budget.

Build and prepare both release sibling pairs first, then stop builds, tests,
traces and other measurement processes. Output must be outside every checkout
and linked worktree (including paths reached through symlinks). Product scratch
roots remain under `target` for the existing trusted-root checks. For example:

```sh
python3 bench/git-product.py --base /trusted/base/release/bingsu \
  --candidate /trusted/candidate/release/bingsu --rounds 200 \
  --cases no-git,git-clean --mode gate --out /external/measurements/git.json
```

`--cases no-git,git-clean,git-dirty,tracked-19000,budget-bound` defaults to all
five cases. Both product CLIs accept `--mode gate|experiment --condition <json>`.
The JSON condition has `power`, `load_range`, and `synthetic_load`; the CLI mode
wins over a JSON mode. Gate uses AC, or `mains-assumed` only when no power device
exists. Load average is a covariate, not a gate threshold. Unknown power, missing
reference/host fields and thermal warnings block admission. Explicit thermal
`unavailable` is recorded on hosts without portable telemetry; experiment power
comparisons require observable normal heat and the declared power/load range.

The same session calibrates the base release binary through rejected command
dispatch (usage exit 2, no helper), using 5 blocks of 20 invocations. Block 0 is
discarded, as determined by D0. Admission compares before/after reference medians
with the `p95_of_medians` of the remaining calibration blocks. With
`git-product.py --admission ci-r2` (the pull request gate job), a GitHub Actions
runner (`GITHUB_ACTIONS=true` and `mains-assumed` power) instead compares with
1.03 times their `median_of_medians`; elsewhere the request blocks the run
rather than widening or being ignored, and every other admission check stays.
Each gate block records `admission_basis`; the result records
`admission_requested` and `admission_applied`. Calibration is
bound to host, kernel, architecture and session. The implementation conservatively
requires calibration median spread to be within 5%; this operational stability
check does not raise any product limit.

Each binary's first invocation is retained separately and excluded from warm
samples. Each row requires at least 200 samples per binary. Measurement blocks
contain up to 20 alternating pairs; even/odd alternation is preserved. Block and
case order use recorded random seeds. Invalid blocks, their samples, before/after
conditions and reasons remain in raw evidence; only accepted blocks contribute
to summaries. A block has at most 3 attempts before the session becomes BLOCKED.

Experiment transitions poll at most 15 reference blocks for normal heat and
3 consecutive medians within 5%. Nonzero synthetic load must equal half the
logical cores (integer division): single-thread CPU processes run with nice 19,
plus `taskpolicy -b` on macOS, for at most 60 seconds, and are cleaned up on exit.
If this administrative duration expires, the cell is BLOCKED. Cell selection is
explicit; callers scheduling multiple conditions must balance and randomize
cell order. Cold measurements remain separate record-only work.

Raw JSON includes p50, p95, variance, n, min/max, seeds, discarded attempts,
calibration, host/kernel/libc/architecture, binary hashes, revision labels and
invocation metadata. `persist_raw` writes unique evidence files; CLI `--out`
also retains the requested filename. `bench.yml` builds both revisions first and
writes/uploads evidence under `$RUNNER_TEMP/measurements`.
