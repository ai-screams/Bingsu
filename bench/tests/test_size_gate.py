"""PR time and size gate verdicts; the CI job shape is pinned from ci.yml."""
import importlib.util
import json
import math
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("size_gate", ROOT / "bench/size_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def summary(p50, p95, n=200):
    return {"n": n, "p50": p50, "p95": p95, "variance": 0.0, "min": p50, "max": p95}


def variant(p50, p95, n):
    # nearest-rank p95 is index ceil(.95 n) - 1: the first k values are p50, the rest p95
    k = math.ceil(.95 * n) - 1
    samples = [{"prompt_ns": p50}] * k + [{"prompt_ns": p95}] * (n - k)
    return {"summary": {"prompt_ns": gate.protocol.summary([s["prompt_ns"] for s in samples])}, "samples": samples}


def paired(base, cand, n=200, status="OBSERVED", n_cand=None):
    return {"status": status, "variants": {"base": variant(*base, n), "candidate": variant(*cand, n_cand or n)}}


# 이것을 실패시키는 것: 비율 방향을 뒤집는 것(base/candidate), p50이나 p95 중 하나만 검사하는 것.
def test_relative_gate_fails_above_threshold_and_records_absolute():
    result = gate.relative_gate(paired((8e6, 12e6), (9.2e6, 12.1e6)), "prompt_ns", 1.10)
    assert result["status"] == "FAIL"
    assert result["ratio_p50"] == pytest.approx(1.15) and result["ratio_p95"] == pytest.approx(12.1 / 12)
    assert result["absolute"]["observed_ms"] == pytest.approx(9.2) and result["absolute"]["target_ms"] == 10.0
    # p95 alone over the threshold also fails
    assert gate.relative_gate(paired((8e6, 12e6), (8e6, 14e6)), "prompt_ns", 1.10)["status"] == "FAIL"
    # faster candidate and exactly at the threshold pass
    assert gate.relative_gate(paired((8e6, 12e6), (6e6, 9e6)), "prompt_ns", 1.10)["status"] == "PASS"
    assert gate.relative_gate(paired((10e6, 10e6), (11e6, 11e6)), "prompt_ns", 1.10)["status"] == "PASS"


# 이것을 실패시키는 것: 절대 시간 목표 초과를 FAIL 사유로 쓰는 것.
def test_absolute_overrun_alone_is_not_a_failure():
    result = gate.relative_gate(paired((20e6, 30e6), (20e6, 30e6)), "prompt_ns", 1.10)
    assert result["status"] == "PASS"
    assert result["absolute"]["observed_ms"] == 20.0 and result["absolute"]["disposition"]


# 이것을 실패시키는 것: 합계만 검사하거나 두 바이너리 중 하나만 검사하는 것.
def test_size_gate_checks_each_binary_and_sum():
    base = {"front": 100, "collector": 100, "combined": 200}
    ok = gate.size_gate(base, {"front": 100, "collector": 100, "combined": 200}, 200)
    assert ok["status"] == "PASS" and ok["over"] == []
    # one binary over its cap while the sum stays under the sum cap
    caps = {"front": 100, "collector": 100, "combined": 500}
    one = gate.size_gate(base, {"front": 101, "collector": 50, "combined": 151}, caps)
    assert one["status"] == "FAIL" and one["over"] == ["front"]
    # both under their caps, sum over
    both = gate.size_gate(base, {"front": 100, "collector": 101, "combined": 201}, {"front": 100, "collector": 101, "combined": 200})
    assert both["status"] == "FAIL" and both["over"] == ["combined"]
    assert gate.size_gate(base, base, None)["status"] == "BLOCKED"
    assert gate.size_gate(base, {"front": 1}, 10)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 200쌍 미만이나 관측 안 된 측정을 PASS로 세는 것, 임계값 미정을 PASS/FAIL로 세는 것.
def test_gate_is_blocked_without_two_hundred_pairs():
    assert gate.relative_gate(paired((8e6, 9e6), (8e6, 9e6), n=199), "prompt_ns", 1.10)["status"] == "BLOCKED"
    assert gate.relative_gate(paired((8e6, 9e6), (8e6, 9e6), status="BLOCKED"), "prompt_ns", 1.10)["status"] == "BLOCKED"
    assert gate.relative_gate({"status": "BLOCKED", "variants": {}}, "prompt_ns", 1.10)["status"] == "BLOCKED"
    pending = gate.relative_gate(paired((8e6, 9e6), (80e6, 90e6)), "prompt_ns", None)
    assert pending["status"] == "BLOCKED" and "U3" in pending["reason"]
    assert gate.aggregate([{"status": "PASS"}, {"status": "BLOCKED"}]) == "BLOCKED"
    assert gate.aggregate([{"status": "BLOCKED"}, {"status": "FAIL"}]) == "FAIL"


NAN, INF = float("nan"), float("inf")


def mutated(side, **changes):
    value = paired((8e6, 12e6), (9e6, 12e6))
    if "samples" in changes:
        value["variants"][side]["samples"] = changes.pop("samples")
    value["variants"][side]["summary"]["prompt_ns"].update(changes)
    return value


# 이것을 실패시키는 것: 증거 값의 유한성·완전성·원시 표본 수 검증을 빼는 것.
@pytest.mark.parametrize("bad", [
    mutated("candidate", p50=NAN, p95=NAN), mutated("base", p50=INF), mutated("candidate", n=NAN),
    mutated("candidate", p50=-1.0), mutated("candidate", samples=[]), mutated("base", n=True),
    mutated("candidate", p95=None), mutated("candidate", variance=NAN),
])
def test_invalid_evidence_is_blocked_not_passed(bad):
    assert gate.relative_gate(bad, "prompt_ns", 1.10)["status"] == "BLOCKED"


def test_missing_p95_or_samples_is_blocked_without_threshold():
    bad = paired((8e6, 12e6), (9e6, 12e6))
    del bad["variants"]["candidate"]["summary"]["prompt_ns"]["p95"]
    assert gate.relative_gate(bad, "prompt_ns", None)["status"] == "BLOCKED"
    bad = paired((8e6, 12e6), (9e6, 12e6))
    del bad["variants"]["base"]["samples"]
    assert gate.relative_gate(bad, "prompt_ns", None)["status"] == "BLOCKED"


def with_samples(side, samples):
    value = paired((8e6, 12e6), (9e6, 12e6))
    value["variants"][side]["samples"] = samples
    return value


# 이것을 실패시키는 것: 표본의 metric 값 검증이나 base/candidate 쌍 수 일치 검사를 빼는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
@pytest.mark.parametrize("samples", [[{}] * 200, [{"prompt_ns": NAN}] * 200, [{"prompt_ns": -1}] * 200,
                                     [{"prompt_ns": None}] * 200, [1] * 200])
def test_raw_samples_must_carry_finite_metric(side, samples):
    assert gate.relative_gate(with_samples(side, samples), "prompt_ns", 1.10)["status"] == "BLOCKED"


def test_pair_counts_must_match():
    assert gate.relative_gate(paired((8e6, 12e6), (9e6, 12e6), n_cand=201), "prompt_ns", 1.10)["status"] == "BLOCKED"
    assert gate.relative_gate(paired((8e6, 12e6), (9e6, 12e6), n=201, n_cand=200), "prompt_ns", 1.10)["status"] == "BLOCKED"


# 이것을 실패시키는 것: summary를 표본에서 다시 계산해 대조하지 않고 믿는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
def test_summary_must_agree_with_samples(side):
    value = paired((8e6, 12e6), (9e6, 12e6))
    other = variant(800e6, 1200e6, 200)
    value["variants"][side]["samples"] = other["samples"]
    assert gate.relative_gate(value, "prompt_ns", 1.10)["status"] == "BLOCKED"
    # all-1 against all-100 samples with a summary that says 1 and 1: ratio is 100, not 1
    lie = paired((1, 1), (100, 100))
    lie["variants"]["candidate"]["summary"]["prompt_ns"] = dict(lie["variants"]["base"]["summary"]["prompt_ns"])
    assert gate.relative_gate(lie, "prompt_ns", 1.10)["status"] == "BLOCKED"


# 이것을 실패시키는 것: summary 필드의 형 검사(bool, 200.0)를 빼고 값만 비교하는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
@pytest.mark.parametrize("field,bad", [("n", 200.0), ("n", True), ("variance", False), ("p50", True)])
def test_summary_field_types_are_checked(side, field, bad):
    value = paired((1, 1), (1, 1))
    row = value["variants"][side]["summary"]["prompt_ns"]
    # the honest value equals the bad one, so only the type can tell them apart
    row[field] = bad if field == "n" else row[field]
    if field == "variance":
        row["variance"] = False
        assert row["variance"] == 0
    if field == "p50":
        value = paired((1, 1), (1, 1))
        value["variants"][side]["samples"] = [{"prompt_ns": 1}] * 200
        value["variants"][side]["summary"]["prompt_ns"] = {**row, "p50": True, "p95": True, "min": True, "max": True}
    assert gate.relative_gate(value, "prompt_ns", 1.10)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 큰 정수 표본에서 OverflowError를 잡지 않는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
def test_huge_integer_sample_is_blocked_without_raising(side):
    value = paired((8e6, 12e6), (9e6, 12e6))
    value["variants"][side]["samples"] = [{"prompt_ns": 10**400}] * 200
    assert gate.relative_gate(value, "prompt_ns", 1.10)["status"] == "BLOCKED"


def test_huge_integer_size_does_not_raise():
    big = {"front": 10**400, "collector": 1, "combined": 10**400 + 1}
    assert gate.size_gate(big, big, 1000)["status"] == "FAIL"
    assert gate.size_gate(big, big, 10**401)["status"] == "PASS"


# 이것을 실패시키는 것: 비율이 유한한지 계산 뒤에 확인하지 않는 것.
@pytest.mark.parametrize("threshold", [None, 1.1])
def test_overflowing_ratio_is_blocked_and_serializes(tmp_path, threshold):
    value = paired((1e-308, 1e-308), (1e308, 1e308))
    assert gate.relative_gate(value, "prompt_ns", threshold)["status"] == "BLOCKED"
    sizes = tmp_path / "s.json"
    sizes.write_text(json.dumps({"stripped_bytes": {"front": 1, "collector": 1, "combined": 2}}))
    meas = tmp_path / "m.json"
    meas.write_text(json.dumps({"cases": {"no-git": value}}))
    args = ["--measurement", str(meas), "--base-preparation", str(sizes), "--candidate-preparation", str(sizes), "--out", str(tmp_path / "v.json")]
    assert gate.main(args + (["--threshold", str(threshold)] if threshold else [])) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"


@pytest.mark.parametrize("threshold", [NAN, INF, -1.0, 0, True])
def test_invalid_threshold_is_blocked(threshold):
    assert gate.relative_gate(paired((8e6, 9e6), (80e6, 90e6)), "prompt_ns", threshold)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 빈·부분·NaN cap을 건너뛰는 것, combined를 front+collector와 대조하지 않는 것.
@pytest.mark.parametrize("cap", [{}, {"combined": 500}, {"front": 100, "collector": 100}, NAN, 0, -5,
                                 {"front": 100, "collector": 100, "combined": NAN}, True])
def test_size_gate_blocks_incomplete_or_invalid_cap(cap):
    side = {"front": 100, "collector": 100, "combined": 200}
    assert gate.size_gate(side, side, cap)["status"] == "BLOCKED"


def test_size_gate_blocks_inconsistent_combined():
    ok = {"front": 100, "collector": 100, "combined": 200}
    assert gate.size_gate(ok, {"front": 100, "collector": 100, "combined": 150}, 1000)["status"] == "BLOCKED"
    assert gate.size_gate({"front": 1, "collector": 1, "combined": 5}, ok, 1000)["status"] == "BLOCKED"


def test_cli_blocks_nan_evidence_instead_of_raising(tmp_path):
    def write(name, text):
        path = tmp_path / name
        path.write_text(text)
        return path
    sizes = write("s.json", json.dumps({"stripped_bytes": {"front": 1, "collector": 1, "combined": 2}}))
    meas = write("m.json", '{"cases": {"no-git": %s}}' % json.dumps(mutated("candidate", p50=NAN)).replace("NaN", "NaN"))
    args = ["--measurement", str(meas), "--base-preparation", str(sizes), "--candidate-preparation", str(sizes),
            "--out", str(tmp_path / "v.json"), "--threshold", "nan"]
    assert gate.main(args) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"


def workflow_triggers():
    text = (ROOT / ".github/workflows/ci.yml").read_text().replace("\r\n", "\n")
    match = re.search(r"^on:\n((?:[ ]+.*\n|\n)+)", text, re.M)
    assert match, "workflow trigger block missing"
    return match.group(1)


# 이것을 실패시키는 것: workflow의 on.pull_request 삭제.
def test_workflow_triggers_on_pull_request():
    assert re.search(r"^  pull_request:", workflow_triggers(), re.M)


def job_text():
    text = (ROOT / ".github/workflows/ci.yml").read_text().replace("\r\n", "\n")
    match = re.search(r"^  prompt-gate:\n(.*?)(?=^  [a-z][a-z-]*:\n)", text, re.S | re.M)
    assert match, "prompt-gate job missing"
    return match.group(1)


# 이것을 실패시키는 것: pull_request 조건 제거, 교대 200쌍 대신 적은 수, 판정 단계에서 --enforce를 기본으로 거는 것, action을 SHA 대신 태그로 쓰는 것.
def test_pr_job_runs_on_pull_request_trigger():
    job = job_text()
    assert "github.event_name == 'pull_request'" in job
    assert "--rounds 200" in job and "bench/size_gate.py" in job
    assert "persist-credentials: false" in job
    assert "GATE_ENFORCE: 'false'" in job and "GATE_TIME_RATIO: ''" in job and "GATE_SIZE_CAP_BYTES: ''" in job
    assert "--enforce" in job and '"$GATE_ENFORCE" = true' in job
    for use in re.findall(r"uses: (\S+)", job):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use), use
    assert "permissions" not in job  # inherits workflow-level contents: read


def test_cli_records_verdict_and_stays_green_until_enforced(tmp_path):
    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return path
    sizes = {"stripped_bytes": {"front": 10, "collector": 20, "combined": 30}}
    big = {"stripped_bytes": {"front": 10, "collector": 20, "combined": 31}}
    meas = write("m.json", {"cases": {"no-git": paired((8e6, 9e6), (80e6, 90e6))}})
    args = ["--measurement", str(meas), "--base-preparation", str(write("b.json", sizes)),
            "--candidate-preparation", str(write("c.json", big)), "--out", str(tmp_path / "v.json")]
    assert gate.main(args) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"
    assert gate.main([*args, "--threshold", "1.1", "--cap-bytes", "30"]) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "FAIL"
    assert gate.main([*args, "--threshold", "1.1", "--cap-bytes", "30", "--enforce"]) == 1
