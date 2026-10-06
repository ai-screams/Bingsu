"""The scaffold's deterministic gate (spec section 9 M1 row, change (6)):
on a synthetic program with known calls, classification, attribution and
formula values must match exactly, and the marker windows must be clean.
Linux only (strace)."""
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from fsbudget.formula import Coeffs, HelperAxes, front_expected, helper_expected
from conftest import REQUIRE_STRACE
from fsbudget.gate import check

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = pathlib.Path(os.environ.get("FSB_SYNTHETIC", ROOT / "target/debug/fsb-synthetic"))
RULES = [["helper", r'"--role", "helper"'], ["writer", r'"--role", "writer"'], ["worker", r'"--role", "worker"']]
WRITER = {"openat": 2, "fstat": 1, "flock": 1, "write": 1, "renameat": 1}
WORKER = {"openat": 1, "fstat": 1, "read": 1}
NAMES = "config.toml,local.toml"

pytestmark = pytest.mark.skipif(not REQUIRE_STRACE and (shutil.which("strace") is None or not BIN.exists()),
                                reason="needs Linux strace and target/debug/fsb-synthetic")


def fixture(tmp: pathlib.Path):
    run = tmp / "run"
    cfg = tmp / "cfg"
    (cfg / "conf.d").mkdir(parents=True)
    run.mkdir()
    (run / "snapshot").write_bytes(b"\0" * 5000)
    (run / "snapshot-header").write_bytes(b"\0" * 64)
    (run / "marker").write_bytes(b"\0" * 128)
    (run / "session").write_bytes(b"\0" * 100)
    (run / "worker-input").write_bytes(b"w" * 10)
    (cfg / "config.toml").write_bytes(b"a" * 10)
    (cfg / "local.toml").write_bytes(b"b" * 5000)
    (cfg / "conf.d" / "10-x.toml").write_bytes(b"c")
    os.symlink("config.toml", cfg / "link.toml")
    return tmp


def run(tmp, env_extra=None, changed=False):
    fx = fixture(tmp)
    rules = tmp / "rules.json"
    rules.write_text(json.dumps(RULES))
    report = tmp / "report.json"
    env = dict(os.environ, FSB_NAMES=NAMES, **(env_extra or {}))
    if changed:
        env["FSB_CHANGED"] = "1"
    out = subprocess.run([sys.executable, "-m", "fsbudget", "run", "--rules", str(rules), "--markers", "-o", str(report),
                          "--", str(BIN), "--role", "front", "--fixture", str(fx)],
                         env=env, cwd=ROOT / "tools/fsbudget", capture_output=True, text=True)
    got = json.loads(report.read_text())
    axes = {l.split(" ", 2)[1]: json.loads(l.split(" ", 2)[2]) for l in out.stdout.splitlines() if l.startswith("AXES ")}
    fa, ha = axes["front"], axes["helper"]
    snap = ha.pop("snapshot_bytes")
    expected = {
        "front": front_expected(fa["C"], fa["section"], fa["session"], 4096),
        "helper": helper_expected(HelperAxes(**ha), Coeffs(), changed, 4096, snap),
        "writer": WRITER,
        "worker": WORKER,
    }
    return got, expected


@pytest.mark.parametrize("changed", [False, True])
def test_synthetic_matches_formula_exactly(tmp_path, changed):
    got, expected = run(tmp_path, changed=changed)
    assert got["errors"] == [], got["errors"]
    assert check(got["counts"], expected, "exact", ["front", "helper", "writer", "worker"]) == []
    assert "command" in got["counts"]  # /bin/true is counted, not budgeted


# 이것을 실패시키는 것: 분류나 공식이 호출 하나를 놓치는 것(같은 호출을 공식에 알리지 않고 하나 더 함).
def test_gate_catches_an_unreported_call(tmp_path):
    got, expected = run(tmp_path, {"FSB_MUTATE": "extra-fstat"})
    bad = check(got["counts"], expected, "exact", ["helper"])
    assert any(b.startswith("helper.fstat") for b in bad), bad


# 이것을 실패시키는 것: 역할을 실행 경로가 아닌 다른 것으로 정해 도우미 호출이 다른 역할로 새는 것.
def test_gate_catches_misattribution(tmp_path):
    got, expected = run(tmp_path, {"FSB_MUTATE": "misattr"})
    bad = check(got["counts"], expected, "exact", ["helper"])
    assert bad, "helper calls landed in another role but the gate passed"
