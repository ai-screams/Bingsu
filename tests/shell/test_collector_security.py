"""Compiler-free M3b integration. Prepare all fixtures in the native host job."""
import importlib.util
import json
import os
from pathlib import Path
import re
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
    return product.prepared(real_bin())


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
    # Product catalog grants no worker. It must remain a silent exit0 B1 even
    # after a failed fixture collection, with unknown/previous logical values.
    front = product.run([real_bin(), "prompt", "--ctx", "1", "--record", "B1", "--width", "80",
                         "--runtime-root=1:2:/unavailable"], env={})
    assert front.stderr == b"" and front.stdout.startswith(b"B1\x1f") and front.stdout.endswith(b"\x1e")
    assert front.stdout.count(b"\x1f") == 9


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
    ("ci.yml", "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[exec]"),
    ("ci.yml", "PASSED tests/shell/test_collector_security.py::test_macos_first_completed_overlimit_sample"),
    ("ci.yml", "check_collector_symbols.py"),
    ("ci.yml", "check_collector_dependencies.py"),
    ("ci.yml", "root_cannot_restore_limits_or_capabilities"),
    ("ci.yml", "test runtime::x14_threads_and_status_survive_fork_is_refused ... ok"),
    ("ci.yml", "test runtime::x16_all_mutations_are_denied_with_fsize_zero ... ok"),
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


# 이것을 실패시키는 것: 실제 TEST_MASK worker의 파일 쓰기/자식/소켓 효과 또는 역할 누락을 놓치는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux native strace product filter")
def test_native_collector_trace_has_no_forbidden_effect(preparation, tmp_path):
    import shutil
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    from fsbudget.attribute import collector_attribute
    from fsbudget.gate import check
    strace = shutil.which("strace")
    assert strace, "the native Linux gate requires strace"
    trace = tmp_path / "collector.trace"
    scratch = tmp_path / "trace-store"
    scratch.mkdir(mode=0o700)
    fixture = preparation["fixture"]
    result = product.run([strace, "-f", "-q", "-yy", "-s", "65536", "-e", "trace=all", "-o", trace,
                          fixture, "--trace", scratch], env={**os.environ, "TMPDIR": str(scratch)})
    assert json.loads(result.stdout.splitlines()[-1])["published"], result.stdout
    observed = collector_attribute(trace.read_text().splitlines(),
                                   {"front": fixture, "helper": fixture, "collector": fixture,
                                    "verbs": {"front": "--trace", "helper": "--trace-helper", "collector": "--security-worker"}})
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
    from fsbudget.classify import kind
    from fsbudget.formula import collection_expected
    from fsbudget.strace_parse import parse
    calls = parse(trace.read_text())
    assert not calls.errors, calls.errors
    begin, = [c for c in calls if c.name == "write" and '"D2-PUBLICATION-BEGIN\\n"' in c.args]
    end, = [c for c in calls if c.name == "write" and '"D2-PUBLICATION-END\\n"' in c.args]
    phase = [c for c in calls if c.pid == begin.pid and begin.index < c.index < end.index]
    response, = (scratch / "runtime").rglob("response")
    expected = collection_expected(3, response.stat().st_size - 64, False, False)
    counts = Counter(k for c in phase if (k := kind(c)))
    measured = {key: counts[key] for key in expected}
    assert not check({"helper-publication": measured}, {"helper-publication": expected}, "exact", ["helper-publication"]), counts
    assert not any(c.name in {"clone", "clone3", "fork", "vfork", "execve", "execveat", "socket", "connect"} for c in phase)
