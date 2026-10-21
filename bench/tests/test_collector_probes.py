"""Acceptance parser and real host-probe mutation anchors.

이것을 실패시키는 것: 누락된 셀, PASS 한 단어, 잘못된 errno/canary/fd 증거를 수용하는 것.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "probes/run-collector-probes.py"
SPEC = importlib.util.spec_from_file_location("collector_probes", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def current_x32():
    saved = SOURCE.parent / "results/x32-macos-27.0.1-aarch64.json"
    return json.loads(saved.read_text())["results"][0]


def test_ledger_requires_every_acceptance_cell(monkeypatch, tmp_path):
    rows = probe.ledger_rows()
    assert len(rows) == 108
    assert sum(row["status"] == "observed" and row["case"] == "X-32"
               and row["environment"] == "macos-current" and row["arch"] == "aarch64" for row in rows) == 6
    # Missing one required kernel/arch/criterion cell must block acceptance.
    text = (SOURCE.parent / "collector-acceptance.tsv").read_text()
    (tmp_path / "collector-acceptance.tsv").write_text("\n".join(text.splitlines()[:-1]) + "\n")
    monkeypatch.setattr(probe, "HERE", tmp_path)
    with pytest.raises(ValueError, match="missing or duplicated"):
        probe.ledger_rows()


@pytest.mark.parametrize("damage", ["missing", "duplicate", "errno", "leak", "sid", "race", "close_time", "word"])
def test_x32_evidence_rejects_mutations(damage):
    records = [json.loads(line) for line in current_x32()["evidence"]["stdout"].splitlines()]
    if damage == "missing":
        records.pop()
    elif damage == "duplicate":
        records[-1] = copy.deepcopy(records[0])
    elif damage == "errno":
        records[0]["evidence"]["errno"] = 1
    elif damage == "leak":
        records[1]["evidence"]["leaks"] = 1
    elif damage == "sid":
        records[2]["evidence"]["sid"] = records[2]["evidence"]["parent_sid"]
    elif damage == "race":
        records[-1]["evidence"]["opens"] = 0
    elif damage == "close_time":
        records[3]["evidence"]["close_ns"] = 0
    stdout = "PASS" if damage == "word" else "\n".join(map(json.dumps, records))
    with pytest.raises((ValueError, KeyError)):
        probe.validate("X-32", stdout)


def test_recorded_x32_evidence_and_mutation():
    result = current_x32()
    assert set(probe.validate("X-32", result["evidence"]["stdout"])) == set(probe.CELLS["X-32"])
    assert result["evidence"]["os_version"] == "27.0.1"
    assert result["evidence"]["deployment_target"] == "11.0"
    assert result["evidence"]["mutation"]["returncode"] == 90
    with pytest.raises(ValueError, match="mutated session"):
        probe.validate("X-32", result["evidence"]["stdout"], mutate=True)


def x02_fixture():
    # Synthetic parser input only; never entered in the observation ledger.
    cells = {}
    for name in ("bash_handoff", "python_handoff"):
        cells[name] = dict(closed_exit=2, closed_canary=0, open_exit=0, open_canary=1,
                           exec_errno=0, leaks=0, seals=47, fallback_errno=0, noexec_errno=13)
    cells.update(native_modes=dict(rdonly_exit=0, opath_exit=0, opath_read_errno=9, canaries=2),
                 shebang_boundary=dict(exec_errno=2, canary=0, nested_rejected=1),
                 size_and_noexec=dict(accepted_bytes=65536, rejected_bytes=65537, fallback_errno=0, other_errno_rejected=1),
                 system_walk=dict(links=2, merged_usr=1, native=1, exit=0, canary=1),
                 refusals=dict.fromkeys(("relative", "relative_link", "env", "proc_missing", "replaced_link", "writable_chain"), 1))
    return cells


@pytest.mark.parametrize("cell,key,value", [("bash_handoff", "open_canary", 0),
                                          ("python_handoff", "seals", 7),
                                          ("native_modes", "opath_read_errno", 0),
                                          ("shebang_boundary", "exec_errno", 13),
                                          ("size_and_noexec", "fallback_errno", 1),
                                          ("system_walk", "links", 0),
                                          ("refusals", "replaced_link", 0)])
def test_x02_parser_mutations(cell, key, value):
    cells = x02_fixture()
    serialize = lambda: "\n".join(json.dumps(dict(cell=k, evidence=v)) for k, v in cells.items())
    probe.validate("X-02", serialize())
    cells[cell][key] = value
    with pytest.raises(ValueError):
        probe.validate("X-02", serialize())


def test_existing_experiments_need_actual_evidence():
    for case in ("X-14", "X-16"):
        with pytest.raises(ValueError):
            probe.validate(case, f"{case} PASS\n")
    text = "X-14 status PASS changes=2 index_unchanged=1 baseline=100 limit=200\nX-14 PASS\n"
    assert probe.validate("X-14", text)["status"]["changes"] == 2
    with pytest.raises(ValueError):
        probe.validate("X-14", text, mutate=True)
    text = "\n".join(f"X-16 {cell} EPERM unchanged" for cell in probe.CELLS["X-16"])
    text += "\nX-16 PASS cells=6 fsize=0 control_truncated=1\ntest result: ok. 1 passed; 0 failed;\n"
    assert len(probe.validate("X-16", text)) == 6
    with pytest.raises(ValueError):
        probe.validate("X-16", text, mutate=True)


def test_run_probe_exit_and_timeout():
    result = probe.run_probe("X-32", [sys.executable, "-c", "raise SystemExit(7)"], 5)
    assert result.outcome == "FAIL" and result.evidence["returncode"] == 7
    result = probe.run_probe("X-32", [sys.executable, "-c", "import time; time.sleep(30)"], 0.05)
    assert result.outcome == "FAIL" and "timeout" in result.evidence["reason"]
    result = probe.run_probe("X-32", ["x32-deliberately-missing-executable"], 5)
    assert result.outcome == "BLOCKED"
