"""M3c acceptance ledger and evidence parser (X-08, X-09, X-10, X-11, X-13, X-15).

이것을 실패시키는 것: 누락된 셀, PASS 한 단어, build-id·hash·host·명령·종료
코드·원시 출력이 빠진 증거, 실행되지 않은(ignored·BLOCKED·skip) probe를
수용하는 것.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parents[1] / "probes"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


m3c = load("m3c_probes", "run-m3c-probes.py")
old = load("collector_probes_for_m3c", "run-collector-probes.py")

REQUIRED = {
    "X-08": {"fifty_ms_stage_a", "zero_filter_processes"},
    "X-09": {"replace_alternates_a_only"},
    "X-10": {"request_roots_ignore_environment"},
    "X-11": {"runtime_probe", "forced_unsupported_fallback"},
    "X-13": {"both_resolvers", "rename_during_walk", "inner_mount_refused", "cwd_on_other_mount_allowed"},
    "X-15": {"docker_default_errno", "forced_enosys", "forced_eperm"},
}


# 이것을 실패시키는 것: 계획이 요구한 셀 하나(예: X-13 cwd-on-other-mount,
# X-15 Docker errno)를 빼거나, 커밋된 행을 실행 완료(observed)로 표시하는 것.
def test_m3c_ledger_requires_every_acceptance_cell(tmp_path, monkeypatch):
    assert {case: set(spec["cells"]) for case, spec in m3c.CASES.items()} == REQUIRED
    assert m3c.CASES["X-11"]["environments"] == ("macos-current",)
    assert "macos-current" not in m3c.CASES["X-15"]["environments"]
    rows = m3c.ledger_rows()
    assert len(rows) == 64
    # This plan marks no experiment as executed: every committed cell waits.
    assert {(r["status"], r["outcome"]) for r in rows} == {("not observed", "BLOCKED")}
    assert all(r["command"].startswith("python3 bench/probes/run-m3c-probes.py --case " + r["case"]) for r in rows)
    lines = (HERE / "collector-acceptance.tsv").read_text().splitlines()
    for damage in ("missing", "duplicate", "observed-without-evidence"):
        changed = list(lines)
        index = next(i for i, line in enumerate(changed) if line.startswith("X-13\tlinux-glibc\tx86_64\tcwd_on_other_mount_allowed\t"))
        if damage == "missing":
            del changed[index]
        elif damage == "duplicate":
            changed.append(changed[index])
        else:
            cells = changed[index].split("\t")
            cells[4:7] = ["observed", "PASS", ""]
            changed[index] = "\t".join(cells)
        path = tmp_path / (damage + ".tsv")
        path.write_text("\n".join(changed) + "\n")
        with pytest.raises(ValueError):
            m3c.ledger_rows(path=path)


# 이것을 실패시키는 것: 두 runner의 소유 case가 겹치거나 어느 쪽도 검증하지
# 않는 행이 생기는 것.
def test_runners_partition_the_shared_ledger():
    assert set(old.M3C_CASES) == set(m3c.CASES)
    everything = {(r["case"], r["environment"], r["arch"], r["cell"]) for r in old.all_ledger_rows()}
    mine = {(r["case"], r["environment"], r["arch"], r["cell"]) for r in m3c.ledger_rows()}
    theirs = {(r["case"], r["environment"], r["arch"], r["cell"]) for r in old.ledger_rows(allow_stale=True)}
    assert mine | theirs == everything and not mine & theirs


def libtest(label, extra=""):
    return (f"running 1 test\n{extra}test {label} ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.10s\n")


X13 = ["x13_resolvers_share_static_verdicts", "linux_openat2_coarse_rename_reads_zero_external_bytes",
       "cwd_on_other_mount_is_allowed"]


def synthetic(cell="both_resolvers", case="X-13", environment="linux-glibc"):
    """A complete, current Linux observation, built the way the runner records it."""
    musl = environment == "linux-musl"
    target = "x86_64-unknown-linux-musl" if musl else None
    result = m3c.ProbeResult(case, "Linux", "6.8.0-45-generic", "musl (static target)" if musl else "glibc 2.39", "x86_64",
                             m3c.build_id(case), m3c.source_hash(case), m3c.lock_hash(), m3c.table_hash(), "PASS")
    runs = []
    for spec in {p for probes in m3c.CASES[case]["cells"].values() for p in probes.get("linux", probes.get("any", []))
                 if isinstance(p, m3c.Rust)}:
        runs.append({"command": m3c.rust_command(spec, target), "returncode": 0, "stdout": libtest(spec.module + spec.name),
                     "stderr": f"     Running tests/{spec.target}.rs (target/debug/deps/{spec.target}-0123)\n"})
    result.evidence = {"environment": environment, "runs": runs,
                       "cells": {c: {"outcome": "PASS", "evidence": []} for c in m3c.CASES[case]["cells"]}}
    row = {"case": case, "environment": environment, "arch": "x86_64", "cell": cell, "status": "observed",
           "outcome": "PASS", "evidence_file": "x.json", "command": "c", "reason": ""}
    from dataclasses import asdict
    return row, {"schema_version": 1, "results": [asdict(result)]}


def test_complete_synthetic_evidence_is_accepted():
    for cell in REQUIRED["X-13"]:
        row, saved = synthetic(cell)
        assert m3c.validate_observed(row, saved)["case"] == "X-13"


# 이것을 실패시키는 것: PASS 조건에서 build-id·source/lock/table hash·
# host/kernel/libc/arch·명령·종료 코드·원시 출력 중 하나의 검사를 빼는 것.
@pytest.mark.parametrize("damage", [
    "build_id", "source_hash", "lock_hash", "table_hash", "platform", "kernel", "libc", "arch",
    "command", "returncode", "stdout", "runs", "old-kernel", "wrong-platform", "success-word",
    "ignored", "cell-outcome", "missing-run", "stale-source", "other-test-passed",
])
def test_pass_requires_complete_raw_evidence(damage):
    row, saved = synthetic()
    result = saved["results"][0]
    run = result["evidence"]["runs"][0]
    if damage in ("build_id", "source_hash", "lock_hash", "table_hash", "platform", "kernel", "libc", "arch"):
        del result[damage]
    elif damage in ("command", "returncode", "stdout"):
        for r in result["evidence"]["runs"]:
            del r[damage]
    elif damage == "runs":
        result["evidence"]["runs"] = []
    elif damage == "old-kernel":
        result["kernel"] = "5.8.18"
    elif damage == "wrong-platform":
        result["platform"] = "Darwin"
    elif damage == "success-word":
        for r in result["evidence"]["runs"]:
            r["stdout"] = "PASS\ntest result: ok.\n"
    elif damage == "ignored":
        for r in result["evidence"]["runs"]:
            r["stdout"] = "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out\n"
    elif damage == "cell-outcome":
        result["evidence"]["cells"]["both_resolvers"]["outcome"] = "BLOCKED"
    elif damage == "missing-run":
        result["evidence"]["runs"] = [r for r in result["evidence"]["runs"]
                                      if "x13_resolvers_share_static_verdicts" not in r["command"]]
    elif damage == "stale-source":
        result["source_hash"] = "0" * 64
    elif damage == "other-test-passed":
        for r in result["evidence"]["runs"]:
            r["stdout"] = libtest("some_other_test")
    with pytest.raises((ValueError, KeyError, TypeError, m3c.Blocked)):
        m3c.validate_observed(row, saved)


def test_x15_docker_errno_classes():
    good = {"command": ["docker", "run"], "returncode": 0,
            "stdout": "X-15 openat2 errno={} docker=27.3.1 seccomp=default\n"}
    for errno, resolver in ((0, "Openat2"), (1, "Stepwise"), (38, "Stepwise")):
        run = dict(good, stdout=good["stdout"].format(errno))
        assert m3c.check_docker(run)["resolver"] == resolver
    for stdout in ("X-15 openat2 errno=13 docker=27.3.1 seccomp=default\n", "PASS\n", ""):
        with pytest.raises(ValueError):
            m3c.check_docker(dict(good, stdout=stdout))


# 이것을 실패시키는 것: 실행되지 않은 probe(ignored, "BLOCKED:" panic, 다른 host,
# 부재 도구, 미준비 F1 corpus)를 PASS나 FAIL로 세는 것.
def test_absent_probe_is_blocked(monkeypatch, tmp_path):
    probe = m3c.Rust("bingsu-collect", "safe_read", "cwd_on_other_mount_is_allowed", ignored=True)
    ignored = {"returncode": 0, "stdout": "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out\n"}
    with pytest.raises(m3c.Blocked):
        m3c.check_rust(probe, ignored)
    panic = {"returncode": 101, "stdout": "test cwd_on_other_mount_is_allowed ... FAILED\n"
             "---- stdout ----\npanicked: BLOCKED: CAP_SYS_ADMIN required\n"
             "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out\n"}
    with pytest.raises(m3c.Blocked):
        m3c.check_rust(probe, panic)
    failed = {"returncode": 101, "stdout": "test cwd_on_other_mount_is_allowed ... FAILED\n"
              "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out\n"}
    with pytest.raises(ValueError):
        m3c.check_rust(probe, failed)
    assert m3c.check_rust(probe, {"returncode": 0, "stdout": libtest(probe.name), "stderr": ""})["test"] == probe.name
    missing = {"returncode": 1, "stdout": "", "stderr": "python3: No module named pytest\n"}
    with pytest.raises(m3c.Blocked):
        m3c.check_pytest(m3c.Pytest("tests/shell/x.py::t"), missing)
    # The observation lines of a passing test arrive in its --show-output block.
    shown = {"returncode": 0, "stderr": "", "stdout": libtest(probe.name) +
             "\nsuccesses:\n\n---- cwd_on_other_mount_is_allowed stdout ----\nX observed=1\n"}
    observed = m3c.Rust(probe.package, probe.target, probe.name, lines=(r"^X observed=1$",))
    assert m3c.check_rust(observed, shown)["observations"]
    assert "--show-output" in m3c.rust_command(probe) and "--nocapture" not in m3c.rust_command(probe)
    node = "tests/shell/x.py::t"
    quiet = {"returncode": 0, "stderr": "", "stdout": f".   [100%]\n=== PASSES ===\nPASSED {node}\n1 passed in 0.08s\n"}
    assert m3c.check_pytest(m3c.Pytest(node), quiet) == {"test": node}
    for wrong in (quiet["stdout"].replace("1 passed", "2 passed"), quiet["stdout"].replace("PASSED ", "FAILED ")):
        with pytest.raises(ValueError):
            m3c.check_pytest(m3c.Pytest(node), dict(quiet, stdout=wrong))
    skipped = {"returncode": 0, "stdout": "SKIPPED [1] tests/shell/x.py: host F1 corpus not selected\n"}
    with pytest.raises(m3c.Blocked):
        m3c.check_pytest(m3c.Pytest("tests/shell/x.py::t"), skipped)
    assert m3c.run_probe("X-13", ["/nonexistent/m3c-probe"], 5).outcome == "BLOCKED"
    monkeypatch.setattr(m3c.platform, "release", lambda: "5.8.0")
    monkeypatch.setattr(m3c.platform, "system", lambda: "Linux")
    blocked = m3c.execute_case("X-13")
    assert blocked.outcome == "BLOCKED" and "5.9" in blocked.evidence["reason"]
    monkeypatch.setattr(m3c.platform, "system", lambda: "Darwin")
    assert m3c.execute_case("X-15").outcome == "BLOCKED"


def test_missing_preparation_blocks_the_f1_cell(monkeypatch):
    monkeypatch.setattr(m3c.platform, "system", lambda: "Darwin")
    case = copy.deepcopy(m3c.CASES["X-08"])
    case["cells"] = {"zero_filter_processes": {"any": [m3c.Pytest(
        "tests/shell/test_git_collection_security.py::test_hostile_git_canaries_have_zero_effects",
        "target/does-not-exist.json")]}}
    monkeypatch.setitem(m3c.CASES, "X-08", case)
    result = m3c.execute_case("X-08")
    assert result.outcome == "BLOCKED"
    assert result.evidence["cells"]["zero_filter_processes"]["outcome"] == "BLOCKED"


def test_run_probe_records_command_and_returncode():
    result = m3c.run_probe("X-13", [sys.executable, "-c", "print('raw'); raise SystemExit(3)"], 10)
    assert (result.outcome, result.evidence["returncode"], result.evidence["stdout"]) == ("FAIL", 3, "raw\n")
    assert result.evidence["command"][0] == sys.executable
    assert all(len(getattr(result, key)) == 64 for key in ("build_id", "source_hash", "lock_hash", "table_hash"))
    slow = m3c.run_probe("X-13", [sys.executable, "-c", "import time; time.sleep(30)"], 0.5)
    assert slow.outcome == "FAIL" and "timeout" in slow.evidence["reason"]


def test_write_ledger_keeps_other_rows(tmp_path):
    rows = m3c.ledger_rows()
    rows[0] = dict(rows[0], reason="changed")
    out = tmp_path / "ledger.tsv"
    m3c.write_ledger(out, rows)
    text = out.read_text().splitlines()
    original = (HERE / "collector-acceptance.tsv").read_text().splitlines()
    assert len(text) == len(original)
    assert sum(a != b for a, b in zip(text, original)) == 1
    assert json.dumps(text[0]) == json.dumps(original[0])


# 이것을 실패시키는 것: validate_observed의 libc·--target 묶음을 빼서 glibc
# 실행을 linux-musl 셀로(또는 그 반대로) 다시 붙일 수 있게 하는 것.
@pytest.mark.parametrize("forge", ["relabel-env", "relabel-env-and-libc", "musl-run-in-glibc-cell", "wrong-arch-target",
                                   "glibc-libc-on-musl-run"])
def test_musl_cells_are_bound_to_the_musl_target(forge):
    row, saved = synthetic(environment="linux-musl")
    assert m3c.validate_observed(row, saved)["libc"].startswith("musl")
    result = saved["results"][0]
    if forge.startswith("relabel-env"):
        row, saved = synthetic()
        result = saved["results"][0]
        row["environment"] = result["evidence"]["environment"] = "linux-musl"
        if forge == "relabel-env-and-libc":
            result["libc"] = "musl (static target)"
    elif forge == "glibc-libc-on-musl-run":
        result["libc"] = "glibc 2.39"
    elif forge == "musl-run-in-glibc-cell":
        row["environment"] = result["evidence"]["environment"] = "linux-glibc"
        result["libc"] = "glibc 2.39"
    else:
        for run in result["evidence"]["runs"]:
            run["command"] = [c.replace("x86_64-unknown", "aarch64-unknown") for c in run["command"]]
    with pytest.raises(ValueError):
        m3c.validate_observed(row, saved)


# 이것을 실패시키는 것: musl 셀에서 host glibc F1 worker의 pytest를 실행하거나
# 그 결과를 PASS로 받는 것.
def test_musl_x08_pytest_cells_are_blocked(monkeypatch):
    monkeypatch.setattr(m3c.platform, "system", lambda: "Linux")
    monkeypatch.setattr(m3c.platform, "release", lambda: "6.8.0")
    ran = []
    monkeypatch.setattr(m3c, "run_probe", lambda *a, **k: ran.append(a) or m3c.new_result("X-08"))
    case = copy.deepcopy(m3c.CASES["X-08"])
    case["cells"] = {"zero_filter_processes": case["cells"]["zero_filter_processes"]}
    monkeypatch.setitem(m3c.CASES, "X-08", case)
    result = m3c.execute_case("X-08", target="x86_64-unknown-linux-musl")
    cell = result.evidence["cells"]["zero_filter_processes"]
    assert cell["outcome"] == "BLOCKED" and m3c.MUSL_PYTEST in cell["evidence"][0]["blocked"] and not ran
    row, saved = synthetic("zero_filter_processes", "X-08", "linux-musl")
    with pytest.raises(ValueError, match="glibc worker"):
        m3c.validate_observed(row, saved)


# 이것을 실패시키는 것: 두 runner의 build identity에서 crates/bingsu-collect/build.rs를
# 빼는 것(build script는 collector 바이너리 바이트를 바꾼다).
@pytest.mark.parametrize("runner, identity, case", [(m3c, "source_hash", "X-13"), (old, "build_id", "X-16")])
def test_build_script_is_part_of_the_build_identity(monkeypatch, runner, identity, case):
    before = getattr(runner, identity)(case)
    real = Path.read_bytes
    script = (HERE.parents[1] / "crates/bingsu-collect/build.rs").resolve()
    monkeypatch.setattr(Path, "read_bytes", lambda self: real(self) + b"//x" if self.resolve() == script else real(self))
    assert getattr(runner, identity)(case) != before
