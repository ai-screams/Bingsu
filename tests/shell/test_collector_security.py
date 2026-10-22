"""Compiler-free M3b integration. Prepare all fixtures in the native host job."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def real_bin():
    return Path(os.environ.get("BINGSU_BIN", ROOT / "target/debug/bingsu")).resolve()


SPEC = importlib.util.spec_from_file_location("security_product", ROOT / "bench/collector-product.py")
product = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(product)


@pytest.fixture(scope="module")
def preparation():
    # No auto-discovery, compiler or toolchain fallback in shell images.
    binary = real_bin()
    try:
        return product.prepared(binary)
    except (ValueError, OSError, KeyError, TypeError) as error:
        message = (
            f"M3b security preparation unavailable for {binary}: {error}. "
            "After the last binary build, prepare this sibling pair on the host with "
            f"`python3 bench/collector-product.py --prepare {shlex.quote(str(binary))}`, "
            "then rerun pytest with the same BINGSU_BIN."
        )
        if os.environ.get("CI"):
            pytest.fail(message, pytrace=False)
        pytest.skip(message)


def native_contract(preparation, group, name):
    binary = preparation["contracts"][group]
    assert product.digest(binary) == preparation["contract_hashes"][group], "stale native contract binary"
    result = subprocess.run([binary, "--exact", name, "--nocapture", "--test-threads=1"],
                            capture_output=True, timeout=90)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout), result.stdout
    return result


# 이것을 실패시키는 것: 한도/exec 실패를 실제 공유 보호·감독·발행 경로에 연결하지 않는 것.
@pytest.mark.parametrize("mode", ["cpu", "nofile"] + (["as", "exec"] if sys.platform == "linux" else []))
def test_security_table_resource_failures_preserve_front(preparation, tmp_path, mode):
    result = subprocess.run([preparation["fixture"], "--limit-" + mode], capture_output=True, timeout=30)
    if mode == "cpu":
        assert result.returncode in (-signal.SIGKILL, -signal.SIGXCPU) and result.stdout == b"CPU1\n", result
    else:
        assert result.returncode == 0 and result.stdout == b"RESOURCE PASS\n", result
    # A valid Update survives the subsequent failure through the actual shared
    # supervisor and atomic store. The 50ms request deadline still wins over a
    # CPU-bound worker; CPU1 above independently verifies its kernel ceiling.
    scratch = tmp_path / mode
    scratch.mkdir(mode=0o700)
    failed = product.run([preparation["fixture"], "--helper-case", scratch, "--" + mode + "-worker"],
                         env={**os.environ, "TMPDIR": str(scratch)})
    report = json.loads(failed.stdout)
    assert report["published"] and report["reaped"] and report["partial_values"] == 1, report
    assert report["reason"] in {"Protocol", "Deadline", "Resource"}, report
    assert report["probe"] == f"probe-{mode}-pass", report
    # 이것을 실패시키는 것: probe 성공 Update를 빼거나 실패 저장소 대신 별도 reader fixture를 읽는 것.
    reader = product.run([preparation["fixture"], "--read", scratch], env={**os.environ, "TMPDIR": str(scratch)})
    assert reader.returncode == 0 and reader.stderr == b""
    record = bytes.fromhex(json.loads(reader.stdout)["record_hex"])
    assert record.startswith(b"B1\x1f") and record.endswith(b"\x1e") and record.count(b"\x1f") == 9
    assert f"probe-{mode}-pass".encode() in record, record



# 이것을 실패시키는 것: 실패·잠금·경쟁·고정 주소·회수의 실제 계약 시험을 선택만 하고 실행하지 않는 것.
@pytest.mark.parametrize("group,name", [
    ("collector_lifecycle", "partial_survives_only_after_validated_updates"),
    ("collector_lifecycle", "slow_drip_does_not_extend_spawn_deadline"),
    ("collector_lifecycle", "early_exit_never_signals_recycled_pid"),
    ("collector_lifecycle", "immediate_ready_is_not_read_or_decoded_before_confinement"),
    ("collector_lifecycle", "verified_screen_spawns_once_before_helper_tsync"),
    ("collection_store", "publication_checks_same_fd_bytes_and_identity"),
    ("collection_store", "hash_collision_never_reuses_or_overwrites_other_cwd"),
    ("collection_store", "helper_close_never_unlocks_live_worker"),
    ("collection_store", "gc_cannot_split_lock_inode_or_delete_inflight_store"),
    ("collection_store", "legacy_gc_prunes_only_empty_suffixes"),
    ("collection_store", "gc_time_cap_stops_before_filesystem_work"),
    ("collection_store", "review_deep_context_undercount"),
    ("collection_store", "review_cross_context_starvation"),
])
def test_product_security_contract(preparation, group, name):
    native_contract(preparation, group, name)


# 이것을 실패시키는 것: 첫 완료 초과 표본의 감지/종료·초과량·표본 간격 분포를 놓치는 것.
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sampled footprint contract")
def test_macos_first_completed_overlimit_sample(preparation):
    result = native_contract(preparation, "collector_lifecycle", "macos_first_completed_overlimit_sample_terminates")
    print(result.stdout.decode())
    for label in (b"footprint overshoot bytes", b"completed sample interval us", b"sample-to-kill-request us"):
        assert label + b": count=" in result.stdout, result.stdout


# 이것을 실패시키는 것: B2 하한을 제품 필터 측정으로 재사용하거나 Ready를 읽지 않고 측정하는 것.
def test_b2_lower_bound_is_replaced_by_product_filter_evidence(preparation, tmp_path):
    sample = product.observe(real_bin(), preparation, tmp_path)
    assert sample["events"]["ready"] >= sample["events"]["spawn_return"]
    assert preparation["policy"]["table_sha256"] == product.digest(ROOT / "crates/bingsu-collect/collector-syscalls.tsv")
    assert preparation["policy"]["product_mask"] == 0 and preparation["policy"]["fixture_mask"] == 1 << 31
    assert sample["as_baseline"] > 0 and sample["collector_peak_rss_bytes"] > 0
    if sys.platform == "linux":
        assert 0 < preparation["policy"]["initial_bpf_instructions"] <= 4096
        assert 0 < preparation["policy"]["final_bpf_instructions"] <= 4096
        assert sample["filter_install_ns"] > 0
    assert sample["m1_stub_exit_ns"] > 0 and sample["m1_stub_limits_ns"] > 0


def assert_ci_contract(texts):
    required = {
        "ci.yml": ("ubuntu-24.04-arm", "macos-latest", "M3b native musl lifecycle security",
                   "--prepare target/release/bingsu", "collector-tests/bin/python",
                   "test_shipped_collector_ready_has_installed_limits", "test_failure_modes_trace_collector_effects",
                   "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[as]",
                   "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[exec]",
                   "PASSED tests/shell/test_collector_security.py::test_macos_first_completed_overlimit_sample",
                   "check_collector_symbols.py", "check_collector_dependencies.py", "test_collector_no_spawn_macos.py",
                   "root_cannot_restore_limits_or_capabilities", "B2 limits PASS",
                   "test runtime::x14_threads_and_status_survive_fork_is_refused ... ok",
                   "test runtime::x16_all_mutations_are_denied_with_fsize_zero ... ok", "X-14 PASS", "X-14", "X-02", "X-32"),
        "shell.yml": ("libc: [gnu, musl]", "--ignore tests/shell/test_collector_security.py"),
        "bench.yml": ("base_ref:", "--rounds 200", "--base base/target/release/bingsu", "--out candidate/target/m3b-product.json",
                      "if: always()", "if-no-files-found: error"),
    }
    for file, tokens in required.items():
        for token in tokens:
            assert token in texts[file], (file, token)
    collector = re.search(r"(?ms)^  collector:\n(.*?)(?=^  [\w-]+:|\Z)", texts["ci.yml"])[1]
    for libc in ("native", "musl"):
        assert f'--basetemp="$RUNNER_TEMP/m3b-traces/{libc}"' in collector
    artifact = collector.split("      - name: Preserve M3b raw security traces on failure\n")[1].split("      - name:")[0]
    for token in ("if: failure()", "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
                  "name: m3b-security-traces-${{ matrix.os }}", "path: ${{ runner.temp }}/m3b-traces/**/*.trace"):
        assert token in artifact, token
    # Both full-suite jobs must exclude the unprepared security module. The
    # Linux job applies the same invocation to all three container images.
    for job in ("shell-linux", "shell-macos"):
        block = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [\w-]+:|\Z)", texts["shell.yml"])
        assert block, job
        assert "--ignore tests/shell/test_collector_security.py" in block[1], job
    ledger = (ROOT / "bench/probes/collector-acceptance.tsv").read_text()
    for case in ("X-02", "X-14", "X-16", "X-32"):
        assert case + "\t" in ledger, case


# 이것을 실패시키는 것: 필수 native/권한/macOS/실험 행을 CI에서 빼거나 측정 부재를 숨기는 것.
def test_ci_has_no_silent_acceptance_skip():
    assert_ci_contract({name: (ROOT / ".github/workflows" / name).read_text()
                        for name in ("ci.yml", "shell.yml", "bench.yml")})


# 이것을 실패시키는 것: 필수 셀 하나를 삭제한 CI도 게이트가 수용하는 것.
@pytest.mark.parametrize("file,token", [
    ("ci.yml", "M3b native musl lifecycle security"),
    ("ci.yml", "test_shipped_collector_ready_has_installed_limits"),
    ("ci.yml", "test_failure_modes_trace_collector_effects"),
    ("ci.yml", "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[exec]"),
    ("ci.yml", "PASSED tests/shell/test_collector_security.py::test_macos_first_completed_overlimit_sample"),
    ("ci.yml", "check_collector_symbols.py"),
    ("ci.yml", "check_collector_dependencies.py"),
    ("ci.yml", "root_cannot_restore_limits_or_capabilities"),
    ("ci.yml", "test runtime::x14_threads_and_status_survive_fork_is_refused ... ok"),
    ("ci.yml", "test runtime::x16_all_mutations_are_denied_with_fsize_zero ... ok"),
    ("ci.yml", '--basetemp="$RUNNER_TEMP/m3b-traces/native"'),
    ("ci.yml", '--basetemp="$RUNNER_TEMP/m3b-traces/musl"'),
    ("ci.yml", "if: failure()"),
    ("ci.yml", "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"),
    ("ci.yml", "path: ${{ runner.temp }}/m3b-traces/**/*.trace"),
    ("bench.yml", "--rounds 200"),
])
def test_missing_ci_cell_is_refused(file, token):
    saved = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    changed = dict(saved)
    changed[file] = changed[file].replace(token, "REMOVED")
    with pytest.raises(AssertionError):
        assert_ci_contract(changed)
    assert saved[file] == (ROOT / ".github/workflows" / file).read_text()


@pytest.mark.parametrize("job", ["shell-linux", "shell-macos"])
def test_each_unprepared_shell_job_must_exclude_security(job):
    texts = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    start = texts["shell.yml"].index(f"\n  {job}:")
    before, block = texts["shell.yml"][:start], texts["shell.yml"][start:]
    texts["shell.yml"] = before + block.replace("--ignore tests/shell/test_collector_security.py", "", 1)
    with pytest.raises(AssertionError, match=job):
        assert_ci_contract(texts)


def assert_native_trace(lines, fixture, body_bytes):
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    from fsbudget.attribute import collector_attribute
    from fsbudget.gate import check
    observed = collector_attribute(lines,
                                   {"front": fixture, "helper": fixture, "collector": fixture,
                                    "verbs": {"front": "--trace", "helper": "--trace-helper", "collector": "--security-worker"}})
    print("collector CLOEXEC open pairs:", json.dumps(observed.cloexec_pairs))
    assert not observed.errors, observed.errors
    # One descriptor contract: three F_GETFL, one regular lock stat/ACL;
    # one fixed bootstrap statm open/read, one neutral-root cwd query.
    want = {"collector": {"exec": 1, "fd_query": 3, "fstat": 1, "acl": 1,
                           "cwd": 1, "openat": 1, "read": 1}}
    assert not check(observed.counts, want, "exact", ["collector"]), observed.counts
    assert {role for role in observed.counts} == {"front", "helper", "collector"}

    # Validate the actual publisher window against the phase formula, rather
    # than reasserting the formula's own constants in a Rust fixture.
    from collections import Counter
    from fsbudget.classify import collection_publication_kind
    from fsbudget.formula import collection_expected
    from fsbudget.strace_parse import parse
    calls = parse("\n".join(lines))
    assert not calls.errors, calls.errors
    begin, = [c for c in calls if c.name == "write" and '"D2-PUBLICATION-BEGIN\\n"' in c.args]
    end, = [c for c in calls if c.name == "write" and '"D2-PUBLICATION-END\\n"' in c.args]
    phase = [c for c in calls if c.pid == begin.pid and begin.index < c.index < end.index]
    expected = collection_expected(3, body_bytes, False, False)
    counts = Counter(k for c in phase if (k := collection_publication_kind(c)))
    measured = {key: counts[key] for key in expected}
    assert not check({"helper-publication": measured}, {"helper-publication": expected}, "exact", ["helper-publication"]), counts
    assert not any(c.name in {"clone", "clone3", "fork", "vfork", "execve", "execveat", "socket", "connect"} for c in phase)
    return observed


# 이것을 실패시키는 것: 실제 TEST_MASK worker의 파일 쓰기/자식/소켓 효과 또는 역할 누락을 놓치는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux native strace product filter")
def test_native_collector_trace_has_no_forbidden_effect(preparation, tmp_path):
    import shutil
    strace = shutil.which("strace")
    assert strace, "the native Linux gate requires strace"
    trace = tmp_path / "collector.trace"
    scratch = tmp_path / "trace-store"
    scratch.mkdir(mode=0o700)
    fixture = preparation["fixture"]
    result = product.run([strace, "-f", "-q", "-y", "-s", "65536", "-e", "trace=all", "-o", trace,
                          fixture, "--trace", scratch], env={**os.environ, "TMPDIR": str(scratch)})
    assert json.loads(result.stdout.splitlines()[-1])["published"], result.stdout
    response, = (scratch / "runtime").rglob("response")
    assert_native_trace(trace.read_text().splitlines(), fixture, response.stat().st_size - 64)


# 이것을 실패시키는 것: 출하 execute()에서 base/AS 보호를 빼도 fixture만 검사하여 통과시키는 것.
def test_shipped_collector_ready_has_installed_limits(preparation, tmp_path):
    import fcntl
    import select
    import struct
    lock = tmp_path / "shipped.lock"
    lock.touch(mode=0o600)
    request, writer = os.pipe()
    lock_fd = os.open(lock, os.O_RDONLY)
    copies = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 20) for fd in (request, lock_fd)]
    def setup():
        os.dup2(copies[0], 3)
        os.dup2(copies[1], 5)
    try:
        with subprocess.Popen([real_bin().with_name("bingsu-collect"), "__collect-v1"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env={}, cwd="/", close_fds=False, preexec_fn=setup) as child:
            try:
                ready = bytearray()
                while len(ready) < 104:
                    assert select.select([child.stdout], [], [], 2)[0], "shipped collector did not reach Ready"
                    chunk = os.read(child.stdout.fileno(), 104 - len(ready))
                    assert chunk, "shipped collector exited before Ready"
                    ready.extend(chunk)
                assert ready[:8] == b"BNGIPC02" and ready[10] == 1, ready
                baseline, = struct.unpack_from("<Q", ready, 96)
                assert baseline > 0
                if sys.platform == "linux":
                    limits = Path(f"/proc/{child.pid}/limits").read_text()
                    for name, ceiling in (("Max cpu time", 1), ("Max open files", 64),
                                          ("Max file size", 0), ("Max core file size", 0),
                                          ("Max address space", baseline + 33_554_432)):
                        row = re.search(rf"(?m)^{name}\s+(\d+)\s+(\d+)\s", limits)
                        assert row and 0 <= int(row[1]) <= int(row[2]) <= ceiling, (name, limits)
            finally:
                child.kill()
                child.wait(timeout=3)
    finally:
        for fd in (request, writer, lock_fd, *copies):
            os.close(fd)


def assert_failure_trace(lines, fixture, mode):
    from collections import Counter
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    from fsbudget.attribute import collector_attribute
    from fsbudget.formula import collector_product_expected
    from fsbudget.gate import check
    from fsbudget.strace_parse import parse
    from fsbudget.classify import split_args
    observed = collector_attribute(lines, {"front": fixture, "helper": fixture, "collector": fixture,
        "verbs": {"front": "--trace", "helper": "--trace-helper", "collector": mode}})
    print("collector CLOEXEC open pairs:", json.dumps(observed.cloexec_pairs))
    calls = parse("\n".join(lines))
    assert not calls.errors, calls.errors
    # Front/helper pass mode as a later argument too. Only the successful
    # pinned executable with the exact worker argv starts this worker.
    workers = [c for c in calls if c.name == "execve" and c.ret == "0"
               and split_args(c.args)[:2] == [json.dumps(fixture), json.dumps([fixture, mode])]]
    assert len(workers) == 1, workers
    worker_exec, = workers
    worker = worker_exec.pid
    # The NOFILE probe deliberately opens only /dev/null until EMFILE. Keep
    # collector_attribute strict; account for precisely those probe diagnostics
    # here, with all other errors still rejected. No product allowance changes.
    # The same PID opens /dev/null for stdio in the vfork child while it is
    # still a helper. Only calls after the worker exec are resource probes.
    probes = [c for c in calls if c.pid == worker and c.index > worker_exec.index and c.name in {"open", "openat"}
              and '"/dev/null"' in split_args(c.args)]
    expected_errors = []
    if mode == "--nofile-worker":
        worker_calls = [c for c in calls if c.pid == worker and c.index > worker_exec.index]
        expected_pairs = []
        assert probes and 0 < sum(not c.ret.startswith("-1") for c in probes) < 64, probes
        assert probes[-1].ret.startswith("-1 EMFILE"), probes[-1]
        for c in probes:
            args = split_args(c.args)
            flags = set(args[1 if c.name == "open" else 2].split("|"))
            assert {"O_RDONLY", "O_CLOEXEC"} <= flags <= {"O_RDONLY", "O_CLOEXEC", "O_LARGEFILE"}, c
            # Legacy open remains unknown-fs except for absolute own statm.
            reason = "collector forbidden effect" if c.name == "open" else "collector read outside the M3b bootstrap"
            expected_errors.append(f"pid {worker} (collector): {reason}: {c.name}({c.args})")
            # musl's immediate redundant F_SETFD belongs to this successful
            # O_CLOEXEC open, even on EPERM. It adds no expected diagnostic;
            # check its attribution independently and keep every other error.
            at = worker_calls.index(c)
            following = worker_calls[at + 1] if at + 1 < len(worker_calls) else None
            following_args = split_args(following.args) if following else []
            opened_fd = re.match(r"^\d+", c.ret)
            paired_fd = re.fullmatch(r"(\d+)(?:<.+>)?", following_args[0]) if following_args else None
            if (not c.ret.startswith("-1") and following and following.name == "fcntl"
                    and following_args[1:] == ["F_SETFD", "FD_CLOEXEC"]
                    and opened_fd and paired_fd and int(opened_fd[0]) == int(paired_fd[1])):
                expected_pairs.append({"pid": worker, "open": f"{c.name}({c.args})", "open_ret": c.ret,
                                       "fcntl": f"fcntl({following.args})", "fcntl_ret": following.ret})
        assert [pair for pair in observed.cloexec_pairs if '"/dev/null"' in pair["open"]] == expected_pairs
    else:
        assert not probes, probes
    assert Counter(observed.errors) == Counter(expected_errors), observed.errors
    if mode == "--exec-worker":
        attempts = [c for c in calls if c.pid == worker and c.name == "execve" and '"/never-executed"' in c.args]
        assert len(attempts) == 1 and attempts[0].ret.startswith("-1 EPERM"), attempts
    assert observed.counts["collector"]["exec"] == (2 if mode == "--exec-worker" else 1)
    effects = collector_product_expected("partial")["collector-effects"]
    measured = {key: observed.counts["collector"].get(key, 0) for key in effects}
    assert not check({"collector-effects": measured}, {"collector-effects": effects}, "exact", ["collector-effects"]), measured
    return observed


# 이것을 실패시키는 것: mode를 전달하는 front/helper도 worker로 선택하거나 exec 전 stdio를 NOFILE 탐침으로 세는 것.
# Source filenames and exact original line numbers are in the adjacent
# d2s-bookworm-aarch64-sources.json; these fixtures contain verbatim excerpts.
@pytest.mark.parametrize("mode", ["cpu", "nofile", "as", "exec", "ready-failure", "malformed"])
def test_bookworm_failure_trace_replay(mode):
    directory = ROOT / "tools/fsbudget/tests/fixtures"
    lines = (directory / f"d2s-bookworm-aarch64-{mode}.strace").read_text().splitlines()
    fixture = "/home/tester/target/debug/collector-product-fixture/collector-product"
    assert_failure_trace(lines, fixture, f"--{mode}-worker")
    # 이것을 실패시키는 것: 실제 재생에서도 collector의 금지 효과/잘못된 exec를 허용하는 것.
    from fsbudget.strace_parse import parse
    from fsbudget.classify import split_args
    worker, = [c.pid for c in parse("\n".join(lines)) if c.name == "execve"
               and split_args(c.args)[1] == json.dumps([fixture, f"--{mode}-worker"])]
    for effect in ('write(9</forbidden>, "x", 1) = 1',
                   'openat(AT_FDCWD</>, "/dev/null", O_RDWR) = 9</dev/null>',
                   'execve("/never-executed", ["/never-executed"], 0x0) = 0'):
        changed = list(lines)
        # Insert before exit so the process still has its collector role.
        at = next((i for i, line in enumerate(changed) if line.startswith(f"{worker}  +++")), len(changed))
        changed.insert(at, f"{worker}  {effect}")
        with pytest.raises(AssertionError):
            assert_failure_trace(changed, fixture, f"--{mode}-worker")


# 이것을 실패시키는 것: 실패 worker의 파일 쓰기/생성/소켓을 실제 trace 대신 상수 0으로 대조하는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace failure-mode effects")
@pytest.mark.parametrize("mode", ["--cpu-worker", "--nofile-worker", "--as-worker", "--exec-worker",
                                  "--ready-failure-worker", "--malformed-worker"])
def test_failure_modes_trace_collector_effects(preparation, tmp_path, mode):
    import shutil
    strace = shutil.which("strace")
    assert strace, "the native Linux gate requires strace"
    trace = tmp_path / "failure.trace"
    scratch = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    fixture = preparation["fixture"]
    # -y keeps device annotations comparable on glibc and musl.
    result = product.run([strace, "-f", "-q", "-y", "-s", "65536", "-o", trace,
                          fixture, "--trace", scratch, mode], env={**os.environ, "TMPDIR": str(scratch)})
    assert result.stderr == b""
    report = json.loads(result.stdout.splitlines()[-1])
    assert report["reaped"], report
    assert report["published"] == (mode != "--ready-failure-worker"), report
    if mode in {"--cpu-worker", "--nofile-worker", "--as-worker", "--exec-worker"}:
        assert report["probe"] == "probe-" + mode[2:-7] + "-pass", report
    assert_failure_trace(trace.read_text().splitlines(), fixture, mode)


# 이것을 실패시키는 것: 실패 trace의 금지 효과를 분류해도 measured를 상수 0으로 덮는 것.
def test_failure_trace_budget_uses_measured_effects(monkeypatch):
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    import fsbudget.attribute as attribution
    fixture = "/fixture"
    lines = [
        '10 execve("/fixture", ["/fixture", "--trace"], 0x0) = 0',
        '10 clone(flags=SIGCHLD) = 11',
        '11 execve("/fixture", ["/fixture", "--trace-helper"], 0x0) = 0',
        '11 clone(flags=SIGCHLD) = 12',
        '12 execve("/fixture", ["/fixture", "--malformed-worker"], 0x0) = 0',
    ]
    assert_failure_trace(lines, fixture, "--malformed-worker")
    # 이것을 실패시키는 것: libc가 더하는 O_LARGEFILE만으로 NOFILE 탐침을 거부하는 것.
    nofile = [line.replace("--malformed-worker", "--nofile-worker") for line in lines]
    for call in ("open", "openat"):
        prefix = 'AT_FDCWD</>, ' if call == "openat" else ''
        for flags in ("O_RDONLY|O_CLOEXEC", "O_RDONLY|O_LARGEFILE|O_CLOEXEC"):
            probes = [f'12 {call}({prefix}"/dev/null", {flags}) = 7</dev/null>',
                      f'12 {call}({prefix}"/dev/null", {flags}) = -1 EMFILE (Too many open files)']
            assert_failure_trace(nofile + probes, fixture, "--nofile-worker")
    real_attribute = attribution.collector_attribute
    def counts_only(*args):
        result = real_attribute(*args)
        result.errors.clear()  # Isolate the independent formula comparison.
        return result
    monkeypatch.setattr(attribution, "collector_attribute", counts_only)
    for effect in ('write(9</file>, "x", 1) = 1', 'socket(AF_INET, SOCK_STREAM, 0) = 9<socket:[1]>',
                   'rename("/a", "/b") = 0', 'unlink("/a") = 0', 'fsync(9</file>) = 0',
                   'fork() = -1 EPERM (Operation not permitted)'):
        with pytest.raises(AssertionError):
            assert_failure_trace(lines + ['12 ' + effect], fixture, "--malformed-worker")


# 이것을 실패시키는 것: NOFILE의 musl 짝을 추가 오류로 세거나 다른 F_SETFD 오류도 함께 지우는 것.
@pytest.mark.parametrize("call", ["open", "openat"])
@pytest.mark.parametrize("result", ["0", "-1 EPERM (Operation not permitted)"])
@pytest.mark.parametrize("fd", ["4</dev/null>", "4"], ids=["named-fd", "bare-fd"])
def test_nofile_musl_pairs_preserve_all_other_errors(call, result, fd):
    fixture = "/fixture"
    lines = [
        '10 execve("/fixture", ["/fixture", "--trace"], 0x0) = 0',
        '10 clone(flags=SIGCHLD) = 11',
        '11 execve("/fixture", ["/fixture", "--trace-helper"], 0x0) = 0',
        '11 clone(flags=SIGCHLD) = 15532',
        '15532 execve("/fixture", ["/fixture", "--nofile-worker"], 0x0) = 0',
    ]
    prefix = 'AT_FDCWD</>, ' if call == "openat" else ''
    opening = f'15532 {call}({prefix}"/dev/null", O_RDONLY|O_LARGEFILE|O_CLOEXEC)'
    paired = f'15532 fcntl({fd}, F_SETFD, FD_CLOEXEC) = ' + result
    probes = [opening + ' = 4</dev/null>', paired,
              opening + ' = -1 EMFILE (Too many open files)']
    got = assert_failure_trace(lines + probes, fixture, "--nofile-worker")
    assert len(got.errors) == 2 and len(got.cloexec_pairs) == 1
    assert got.cloexec_pairs[0]["fcntl_ret"] == result
    for changed in (
        [probes[0], paired.replace(f'({fd}', '(5</dev/null>'), probes[2]],
        [probes[0], paired.replace('FD_CLOEXEC', '0'), probes[2]],
        [probes[0], '15532 getpid() = 15532', paired, probes[2]],
        [probes[0], paired, paired, probes[2]],
        [probes[0].replace('|O_CLOEXEC', ''), paired, probes[2]],
        [*probes, paired],
        [*probes, '15532 write(9</forbidden>, "x", 1) = 1'],
    ):
        with pytest.raises(AssertionError):
            assert_failure_trace(lines + changed, fixture, "--nofile-worker")
