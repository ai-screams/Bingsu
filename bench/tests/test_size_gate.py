"""PR time and size gate verdicts; the CI job shape is pinned from ci.yml."""
import importlib.util
import json
import math
import re
import subprocess
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


def sizes(front, collector, cli=1_000):
    """A preparation's stripped sizes: the three files, combined and installed."""
    return {"front": front, "collector": collector, "cli": cli,
            "combined": front + collector, "installed": front + collector + cli}


# 이것을 실패시키는 것: 비율 방향을 뒤집는 것(base/candidate), p50이나 p95 중 하나만 검사하는 것.
def test_relative_gate_fails_above_threshold_and_records_absolute():
    result = gate.relative_gate(paired((8e6, 12e6), (9.2e6, 12.1e6)), "prompt_ns", (1.10, 1.10))
    assert result["status"] == "FAIL"
    assert result["ratio_p50"] == pytest.approx(1.15) and result["ratio_p95"] == pytest.approx(12.1 / 12)
    assert result["absolute"]["observed_ms"] == pytest.approx(9.2) and result["absolute"]["target_ms"] == 10.0
    # p95 alone over the threshold also fails
    assert gate.relative_gate(paired((8e6, 12e6), (8e6, 14e6)), "prompt_ns", (1.10, 1.10))["status"] == "FAIL"
    # faster candidate and exactly at the threshold pass
    assert gate.relative_gate(paired((8e6, 12e6), (6e6, 9e6)), "prompt_ns", (1.10, 1.10))["status"] == "PASS"
    assert gate.relative_gate(paired((10e6, 10e6), (11e6, 11e6)), "prompt_ns", (1.10, 1.10))["status"] == "PASS"


# U3 T1 (p50 1.03, p95 1.10). 103/100 and 110/100 equal the float literals exactly.
# 이것을 실패시키는 것: 두 한계를 바꿔 쓰거나 하나로 합치는 것, 경계에서 >= 로 판정하는 것.
@pytest.mark.parametrize("base,cand,status", [
    ((100e6, 100e6), (103e6, 103e6), "PASS"), ((100e6, 100e6), (103000001, 103e6), "FAIL"),
    ((100e6, 100e6), (100e6, 110e6), "PASS"), ((100e6, 100e6), (100e6, 110000001), "FAIL"),
    ((100e6, 100e6), (104e6, 104e6), "FAIL"), ((100e6, 100e6), (103e6, 110e6), "PASS"),
])
def test_approved_ratio_limits(base, cand, status):
    assert gate.relative_gate(paired(base, cand), "prompt_ns", (1.03, 1.10))["status"] == status


# 이것을 실패시키는 것: 절대 시간 목표 초과를 FAIL 사유로 쓰는 것.
def test_absolute_overrun_alone_is_not_a_failure():
    result = gate.relative_gate(paired((20e6, 30e6), (20e6, 30e6)), "prompt_ns", (1.10, 1.10))
    assert result["status"] == "PASS"
    assert result["absolute"]["observed_ms"] == 20.0 and result["absolute"]["disposition"]


# 첫 릴리스의 상한: front + collector <= 2,500,000, 세 파일의 합 <= 7,000,000, 실행 파일마다의 상한은 없다.
# 이것을 실패시키는 것: 경계에서 >= 로 판정하는 것, 한 바이너리를 따로 상한에 대는 것, installed를 판정에서 빼는 것,
# 두 상한을 바꿔 대는 것.
def test_size_gate_caps_combined_and_installed():
    base = sizes(100, 100)

    def judge(candidate):
        return gate.size_gate(base, candidate, 2_500_000, 7_000_000)
    edge = judge(sizes(1_250_000, 1_250_000, 4_500_000))
    assert edge["status"] == "PASS" and edge["over"] == []
    assert edge["cap_bytes"] == {"combined": 2_500_000, "installed": 7_000_000}
    combined = judge(sizes(1_250_001, 1_250_000))
    assert combined["status"] == "FAIL" and combined["over"] == ["combined"]
    installed = judge(sizes(1_000_000, 1_000_000, 5_000_001))
    assert installed["status"] == "FAIL" and installed["over"] == ["installed"]
    both = judge(sizes(1_250_001, 1_250_000, 4_500_000))
    assert both["status"] == "FAIL" and both["over"] == ["combined", "installed"]
    # one binary far over half its cap while the sums fit
    assert judge(sizes(2_499_999, 1, 3_999_999))["status"] == "PASS"
    for caps in ((None, 7_000_000), (2_500_000, None)):
        r = gate.size_gate(base, base, *caps)
        assert r["status"] == "BLOCKED" and r["reason"] == "cap not set", caps
    assert gate.size_gate(base, {"front": 1}, 10, 10)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 기준 크기나 릴리스 기록 검증을 후보의 상한 판정보다 앞에 두는 것(누락이 확정된 초과를 BLOCKED로
# 덮음), 후보의 릴리스 기록이 없거나 어긋날 때 installed를 통과로 치는 것.
def test_candidate_over_cap_fails_even_without_base_size():
    over, big = sizes(1_250_001, 1_250_000), sizes(1_000, 1_000, 7_000_000)
    for base in (None, {}, {"front": 1}):
        r = gate.size_gate(base, over, 2_500_000, 7_000_000)
        assert r["status"] == "FAIL" and r["over"] == ["combined"]
        r = gate.size_gate(base, big, 2_500_000, 7_000_000)
        assert r["status"] == "FAIL" and r["over"] == ["installed"]
    fits = sizes(1_250_000, 1_250_000)
    assert gate.size_gate(None, fits, 2_500_000, 7_000_000)["status"] == "BLOCKED"
    assert gate.size_gate(None, {"front": 1}, 2_500_000, 7_000_000)["status"] == "BLOCKED"  # bad candidate
    assert gate.size_gate(None, over, None, 7_000_000)["status"] == "BLOCKED"  # no cap, no verdict
    base = sizes(100, 100)
    for record in ({k: v for k, v in fits.items() if k != "installed"}, {**fits, "installed": fits["combined"]},
                   {k: v for k, v in fits.items() if k != "cli"}):
        r = gate.size_gate(base, record, 2_500_000, 7_000_000)
        assert r["status"] == "BLOCKED" and "release size" in r["reason"], record
    without_record = {k: v for k, v in over.items() if k != "installed"}
    r = gate.size_gate(base, without_record, 2_500_000, 7_000_000)
    assert r["status"] == "FAIL" and r["over"] == ["combined"]
    # A combined that is not front + collector cannot hide a proven installed overrun, nor pass.
    bad_combined = {**big, "combined": big["combined"] + 1}
    r = gate.size_gate(base, bad_combined, 2_500_000, 7_000_000)
    assert r["status"] == "FAIL" and r["over"] == ["installed"]
    r = gate.size_gate(base, {**fits, "combined": fits["combined"] + 1}, 2_500_000, 7_000_000)
    assert r["status"] == "BLOCKED" and r["reason"] == "missing or inconsistent size"


# 이것을 실패시키는 것: 200쌍 미만이나 관측 안 된 측정을 PASS로 세는 것, 임계값 미정을 PASS/FAIL로 세는 것.
def test_gate_is_blocked_without_two_hundred_pairs():
    assert gate.relative_gate(paired((8e6, 9e6), (8e6, 9e6), n=199), "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"
    assert gate.relative_gate(paired((8e6, 9e6), (8e6, 9e6), status="BLOCKED"), "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"
    assert gate.relative_gate({"status": "BLOCKED", "variants": {}}, "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"
    pending = gate.relative_gate(paired((8e6, 9e6), (80e6, 90e6)), "prompt_ns", None)
    assert pending["status"] == "BLOCKED" and "not set" in pending["reason"]
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
    assert gate.relative_gate(bad, "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"


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
    assert gate.relative_gate(with_samples(side, samples), "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"


def test_pair_counts_must_match():
    assert gate.relative_gate(paired((8e6, 12e6), (9e6, 12e6), n_cand=201), "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"
    assert gate.relative_gate(paired((8e6, 12e6), (9e6, 12e6), n=201, n_cand=200), "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"


# 이것을 실패시키는 것: summary를 표본에서 다시 계산해 대조하지 않고 믿는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
def test_summary_must_agree_with_samples(side):
    value = paired((8e6, 12e6), (9e6, 12e6))
    other = variant(800e6, 1200e6, 200)
    value["variants"][side]["samples"] = other["samples"]
    assert gate.relative_gate(value, "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"
    # all-1 against all-100 samples with a summary that says 1 and 1: ratio is 100, not 1
    lie = paired((1, 1), (100, 100))
    lie["variants"]["candidate"]["summary"]["prompt_ns"] = dict(lie["variants"]["base"]["summary"]["prompt_ns"])
    assert gate.relative_gate(lie, "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"


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
    assert gate.relative_gate(value, "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"


# 이것을 실패시키는 것: 큰 정수 표본에서 OverflowError를 잡지 않는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
def test_huge_integer_sample_is_blocked_without_raising(side):
    value = paired((8e6, 12e6), (9e6, 12e6))
    value["variants"][side]["samples"] = [{"prompt_ns": 10**400}] * 200
    assert gate.relative_gate(value, "prompt_ns", (1.10, 1.10))["status"] == "BLOCKED"


def test_huge_integer_size_does_not_raise():
    big = sizes(10**400, 1, 1)
    assert gate.size_gate(big, big, 1000, 1000)["status"] == "FAIL"
    assert gate.size_gate(big, big, 10**401, 10**401)["status"] == "PASS"


# 이것을 실패시키는 것: 비율이 유한한지 계산 뒤에 확인하지 않는 것.
@pytest.mark.parametrize("threshold", [None, (1.1, 1.1)])
def test_overflowing_ratio_is_blocked_and_serializes(tmp_path, threshold):
    value = paired((1e-308, 1e-308), (1e308, 1e308))
    assert gate.relative_gate(value, "prompt_ns", threshold)["status"] == "BLOCKED"
    sizes = tmp_path / "s.json"
    sizes.write_text(json.dumps({"stripped_bytes": {"front": 1, "collector": 1, "combined": 2}}))
    meas = tmp_path / "m.json"
    meas.write_text(json.dumps({"cases": {"no-git": value}}))
    args = ["--measurement", str(meas), "--base-preparation", str(sizes), "--candidate-preparation", str(sizes), "--out", str(tmp_path / "v.json")]
    assert gate.main(args + (["--ratio-p50", "1.1", "--ratio-p95", "1.1"] if threshold else [])) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"


@pytest.mark.parametrize("threshold", [(NAN, 1.1), (1.03, INF), (-1.0, 1.1), (1.03, 0), (True, 1.1), 1.1, (1.03,), [1.03, 1.1]])
def test_invalid_threshold_is_blocked(threshold):
    assert gate.relative_gate(paired((8e6, 9e6), (80e6, 90e6)), "prompt_ns", threshold)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 0·음수·NaN·bool·dict cap을 건너뛰는 것, combined를 front+collector와 대조하지 않는 것.
@pytest.mark.parametrize("cap", [{}, {"combined": 500}, NAN, 0, -5, True, 500.0])
def test_size_gate_blocks_incomplete_or_invalid_cap(cap):
    side = sizes(100, 100)
    assert gate.size_gate(side, side, cap, 10_000)["status"] == "BLOCKED"
    assert gate.size_gate(side, side, 10_000, cap)["status"] == "BLOCKED"


def test_size_gate_blocks_inconsistent_combined():
    ok = sizes(100, 100)
    assert gate.size_gate(ok, {**ok, "combined": 150}, 1000, 10_000)["status"] == "BLOCKED"
    assert gate.size_gate({"front": 1, "collector": 1, "combined": 5}, ok, 1000, 10_000)["status"] == "BLOCKED"


def test_cli_blocks_nan_evidence_instead_of_raising(tmp_path):
    def write(name, text):
        path = tmp_path / name
        path.write_text(text)
        return path
    sizes = write("s.json", json.dumps({"stripped_bytes": {"front": 1, "collector": 1, "combined": 2}}))
    meas = write("m.json", '{"cases": {"no-git": %s}}' % json.dumps(mutated("candidate", p50=NAN)).replace("NaN", "NaN"))
    args = ["--measurement", str(meas), "--base-preparation", str(sizes), "--candidate-preparation", str(sizes),
            "--out", str(tmp_path / "v.json"), "--ratio-p50", "nan", "--ratio-p95", "nan"]
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
    # Approved values (U3 ratios, the first release's size caps); FAIL fails the job, BLOCKED only warns.
    assert "GATE_ENFORCE: 'true'" in job and "GATE_RATIO_P50: '1.03'" in job
    assert "GATE_RATIO_P95: '1.10'" in job and "GATE_SIZE_CAP_BYTES: '2500000'" in job
    assert "GATE_INSTALLED_CAP_BYTES: '7000000'" in job
    # The verdict step's argument array, word for word (a flag in a comment or given twice fails).
    args = re.search(r"^ +args=\((.*?)\)$", job, re.M | re.S).group(1).split()
    assert args == ["--ratio-p50", '"$GATE_RATIO_P50"', "--ratio-p95", '"$GATE_RATIO_P95"',
                    "--cap-bytes", '"$GATE_SIZE_CAP_BYTES"', "--installed-cap-bytes", '"$GATE_INSTALLED_CAP_BYTES"',
                    "--record-only", '"$GATE_RECORD_ONLY"'], args
    assert "--admission ci-r2" in job  # rule R2 is requested only here
    assert "--enforce" in job and '"$GATE_ENFORCE" = true' in job
    assert "::warning::prompt gate verdict" in job  # BLOCKED stays visible
    for use in re.findall(r"uses: (\S+)", job):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use), use
    assert "permissions" not in job  # inherits workflow-level contents: read


def test_cli_records_verdict_and_fails_only_on_enforced_fail(tmp_path):
    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return path
    small = {"stripped_bytes": sizes(10, 20)}
    big = {"stripped_bytes": sizes(11, 20)}
    meas = write("m.json", {"cases": {"no-git": paired((8e6, 9e6), (80e6, 90e6))}})
    args = ["--measurement", str(meas), "--base-preparation", str(write("b.json", small)),
            "--candidate-preparation", str(write("c.json", big)), "--out", str(tmp_path / "v.json")]
    assert gate.main(args) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"
    limits = ["--ratio-p50", "1.03", "--ratio-p95", "1.10", "--cap-bytes", "30", "--installed-cap-bytes", "2000"]
    assert gate.main([*args, *limits]) == 0
    report = json.loads((tmp_path / "v.json").read_text())
    assert report["status"] == "FAIL" and report["threshold"] == {"p50": 1.03, "p95": 1.10}
    assert report["size"]["over"] == ["combined"]
    assert gate.main([*args, *limits, "--enforce"]) == 1  # FAIL
    assert gate.main([*args, "--enforce"]) == 0  # BLOCKED: no limits given
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"
    with pytest.raises(SystemExit):
        gate.main([*args, "--ratio-p50", "1.03"])


def test_cli_summary_names_why_nothing_was_measured(tmp_path, capsys):
    sizes = tmp_path / "s.json"
    sizes.write_text(json.dumps({"stripped_bytes": {"front": 1, "collector": 1, "combined": 2}}))
    meas = tmp_path / "m.json"
    meas.write_text(json.dumps({"status": "BLOCKED", "reason": "stale prepared fixture"}))
    gate.main(["--measurement", str(meas), "--base-preparation", str(sizes), "--candidate-preparation", str(sizes), "--out", str(tmp_path / "v.json")])
    out = json.loads(capsys.readouterr().out)
    assert any("stale prepared fixture" in r for r in out["blocked_by"])


# 기록 전용 칸은 판정에 들지 않는다: 그 칸의 FAIL은 RECORDED로 남고(본래 판정은 observed_status), 다른 칸의 판정이
# 결과가 된다. 기록 전용 칸뿐이면 판정할 칸이 없어 BLOCKED다. 이것을 실패시키는 것: --record-only를 무시하는 것
# (그 칸의 FAIL이 결과가 됨), 기록 전용 칸만으로 PASS를 내는 것.
def test_record_only_cases_are_kept_but_not_judged(tmp_path):
    prepared = tmp_path / "s.json"
    prepared.write_text(json.dumps({"stripped_bytes": sizes(10, 20)}))
    common = ["--base-preparation", str(prepared), "--candidate-preparation", str(prepared), "--out", str(tmp_path / "v.json"),
              "--ratio-p50", "1.03", "--ratio-p95", "1.10", "--cap-bytes", "30", "--installed-cap-bytes", "1030", "--enforce",
              "--record-only", "prompt-commands-max"]
    meas = tmp_path / "m.json"
    meas.write_text(json.dumps({"cases": {"no-git": paired((8e6, 9e6), (8e6, 9e6)),
                                          "prompt-commands-max": paired((8e6, 9e6), (80e6, 90e6))}}))
    assert gate.main(["--measurement", str(meas), *common]) == 0
    report = json.loads((tmp_path / "v.json").read_text())
    assert report["status"] == "PASS"
    row = report["time"]["prompt-commands-max"]
    assert row["status"] == "RECORDED" and row["observed_status"] == "FAIL" and "U-23" in row["record_only"]
    assert gate.main(["--measurement", str(meas), *common[:-2]]) == 1
    meas.write_text(json.dumps({"cases": {"prompt-commands-max": paired((8e6, 9e6), (8e6, 9e6))}}))
    assert gate.main(["--measurement", str(meas), *common]) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"


# 이것을 실패시키는 것: 기록 전용 칸을 CI 판정 단계에 넘기지 않는 것(측정 칸이 FAIL로 판정됨), 측정 칸에서 빼는 것,
# 판정하는 기존 칸(no-git, git-clean, git-dirty)을 빼거나 기록 전용으로 돌리는 것.
def test_ci_records_the_command_time_cases_only():
    job = job_text()
    cases = re.search(r"GATE_CASES: (\S+)", job).group(1).split(",")
    record = re.search(r"GATE_RECORD_ONLY: (\S+)", job).group(1).split(",")
    commands = ["prompt-env64k", "prompt-env64k-commands", "prompt-commands-hit", "prompt-commands-max",
                "prompt-commands-max-empty", "prompt-commands-redraw", "prompt-commands-max-empty-redraw",
                "prompt-text-max", "prompt-env-segments"]
    judged = ["no-git", "git-clean", "git-dirty"]
    assert record == commands and cases == judged + commands
    assert [c for c in cases if c not in record] == judged
    assert '--record-only "$GATE_RECORD_ONLY"' in job


# 이것을 실패시키는 것: --enforce에서 PASS/BLOCKED 구분 없이 0 아닌 코드로 끝내기, 빈 증거를 PASS로 치기.
def test_enforced_pass_and_empty_evidence(tmp_path, capsys):
    prepared = tmp_path / "s.json"
    prepared.write_text(json.dumps({"stripped_bytes": sizes(10, 20)}))
    common = ["--base-preparation", str(prepared), "--candidate-preparation", str(prepared), "--out", str(tmp_path / "v.json"),
              "--ratio-p50", "1.03", "--ratio-p95", "1.10", "--cap-bytes", "30", "--installed-cap-bytes", "1030", "--enforce"]
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"cases": {"no-git": paired((8e6, 9e6), (8e6, 9e6))}}))
    assert gate.main(["--measurement", str(ok), *common]) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "PASS"
    for empty in ({}, {"cases": {}}):
        meas = tmp_path / "e.json"
        meas.write_text(json.dumps(empty))
        capsys.readouterr()
        assert gate.main(["--measurement", str(meas), *common]) == 0
        assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"
        assert json.loads(capsys.readouterr().out)["status"] == "BLOCKED"


# 이것을 실패시키는 것: aggregate에서 `not statuses`(증거 0건)를 PASS로 떨어뜨리기.
def test_aggregate_of_no_results_is_blocked():
    assert gate.aggregate([]) == "BLOCKED"


# Release build sizes at 7cbe991 on macOS arm64 (front, collector, cli).
RELEASE = {"front": 768_240, "collector": 1_280_544, "cli": 2_939_584, "combined": 2_048_784, "installed": 4_988_368}


# 릴리스 크기는 세 파일과 그 합, 기준과의 차이를 기록하고, 후보의 합은 installed 상한이 판정한다. 이것을 실패시키는 것:
# installed에서 bingsu(cli)를 빼거나 다른 합을 받아들이는 것, 차이 방향을 뒤집는 것, 파일 하나를 기록에서 빼는 것.
def test_release_size_records_each_file_and_their_sum():
    bigger = {**RELEASE, "cli": RELEASE["cli"] + 1_048_576, "installed": RELEASE["installed"] + 1_048_576}
    record = gate.release_size(RELEASE, bigger)
    assert record["status"] == "RECORDED" and "reason" not in record
    assert record["base"] == {"files": {"bingsu": 2_939_584, "bingsu-prompt": 768_240, "bingsu-collect": 1_280_544},
                              "installed": 4_988_368}
    assert record["delta"] == {"bingsu": 1_048_576, "bingsu-prompt": 0, "bingsu-collect": 0, "installed": 1_048_576}
    # A bigger bingsu moves installed only; front + collector stays at its cap.
    over = gate.size_gate(RELEASE, bigger, 2_048_784, 4_988_368)
    assert over["status"] == "FAIL" and over["over"] == ["installed"]
    assert gate.size_gate(RELEASE, bigger, 2_048_784, 4_988_368 + 1_048_576)["status"] == "PASS"
    for bad in ({**RELEASE, "installed": RELEASE["combined"]},  # a tree without bingsu-prompt
                {**RELEASE, "installed": RELEASE["installed"] + 1}, {**RELEASE, "installed": float(RELEASE["installed"])},
                {k: v for k, v in RELEASE.items() if k != "installed"}, {k: v for k, v in RELEASE.items() if k != "cli"},
                {**RELEASE, "cli": True}, {**RELEASE, "cli": float(RELEASE["cli"])}, None):
        for record in (gate.release_size(bad, RELEASE), gate.release_size(RELEASE, bad)):
            assert record["status"] == "RECORDED" and "delta" not in record, bad
            assert "missing or inconsistent release size" in record["reason"], bad


# 이것을 실패시키는 것: 릴리스 크기를 보고서나 요약에서 빼는 것, CLI가 installed 상한을 판정에 넘기지 않는 것,
# 기록이 어긋난 후보를 PASS로 치는 것.
def test_cli_judges_the_release_size(tmp_path, capsys):
    base, cand = tmp_path / "b.json", tmp_path / "c.json"
    base.write_text(json.dumps({"stripped_bytes": RELEASE}))
    huge = {**RELEASE, "cli": 50_000_000, "installed": RELEASE["combined"] + 50_000_000}
    cand.write_text(json.dumps({"stripped_bytes": huge}))
    meas = tmp_path / "m.json"
    meas.write_text(json.dumps({"cases": {"no-git": paired((8e6, 9e6), (8e6, 9e6))}}))
    common = ["--measurement", str(meas), "--base-preparation", str(base), "--out", str(tmp_path / "v.json"),
              "--ratio-p50", "1.03", "--ratio-p95", "1.10", "--cap-bytes", "2500000",
              "--installed-cap-bytes", "7000000", "--enforce"]
    capsys.readouterr()
    assert gate.main([*common, "--candidate-preparation", str(cand)]) == 1
    report = json.loads((tmp_path / "v.json").read_text())
    assert report["status"] == "FAIL" and report["size"]["over"] == ["installed"]
    assert report["installed_cap_bytes"] == 7_000_000
    assert report["release_size"]["delta"]["installed"] == 50_000_000 - 2_939_584
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "FAIL" and out["size"]["over"] == ["installed"]
    assert out["size"]["cap_bytes"] == {"combined": 2_500_000, "installed": 7_000_000}
    assert out["release_size"]["candidate"]["installed"] == 52_048_784
    # The released size itself passes.
    cand.write_text(json.dumps({"stripped_bytes": RELEASE}))
    assert gate.main([*common, "--candidate-preparation", str(cand)]) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "PASS"
    capsys.readouterr()
    # A preparation without the three files cannot pass the installed cap: BLOCKED, named in the summary.
    cand.write_text(json.dumps({"stripped_bytes": {k: v for k, v in RELEASE.items() if k != "installed"}}))
    assert gate.main([*common, "--candidate-preparation", str(cand)]) == 0
    report = json.loads((tmp_path / "v.json").read_text())
    assert report["status"] == "BLOCKED" and "missing" in report["release_size"]["reason"]
    assert json.loads(capsys.readouterr().out)["blocked_by"] == ["missing or inconsistent release size"]


# 진짜 strip을 거친 크기: bingsu에만 1 MiB 정적 배열을 링크하면 installed만 그만큼 늘고, bingsu-prompt에 링크하면
# combined와 installed가 함께 는다. 두 상한은 각각 그 변이를 FAIL로 잡는다. 이것을 실패시키는 것: installed를 combined만으로
# 세는 것(dedicated일 때 cli를 빼는 것), cli 대신 다른 파일을 재는 것, 한 상한을 판정에서 빼는 것.
def test_the_caps_catch_a_bigger_bingsu_or_prompt(tmp_path):
    spec = importlib.util.spec_from_file_location("git_product_sizes", ROOT / "bench/git-product.py")
    product = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product)
    plain = "fn main() { std::hint::black_box(1); }\n"
    padded = ("static PAD: [u8; 1 << 20] = [7; 1 << 20];\n"
              "fn main() { std::hint::black_box(&PAD); }\n")
    prepared = {}
    for side, cli, front in (("base", plain, plain), ("cli", padded, plain), ("front", plain, padded)):
        folder = tmp_path / side
        folder.mkdir()
        for name, source in (("bingsu", cli), ("bingsu-prompt", front), ("bingsu-collect", plain)):
            (folder / (name + ".rs")).write_text(source)
            subprocess.run(["rustc", "-O", "-o", str(folder / name), str(folder / (name + ".rs"))],
                           check=True, capture_output=True)
        out = tmp_path / (side + "-stripped")
        out.mkdir()
        prepared[side] = product.stripped_sizes(folder / "bingsu", folder / "bingsu-prompt", out, True)
    base = prepared["base"]
    record = gate.release_size(base, prepared["cli"])
    grown = record["delta"]["bingsu"]
    assert 1 << 20 <= grown <= (1 << 20) + (64 << 10), record
    assert record["delta"]["installed"] == grown
    assert record["delta"]["bingsu-prompt"] == record["delta"]["bingsu-collect"] == 0
    assert prepared["cli"]["combined"] == base["combined"]
    # Caps half a MiB above the base: each padded file is over what it moves.
    half = 1 << 19
    caps = (base["combined"] + half, base["installed"] + half)
    assert gate.size_gate(base, base, *caps)["status"] == "PASS"
    assert gate.size_gate(base, prepared["cli"], *caps)["over"] == ["installed"]
    assert gate.size_gate(base, prepared["front"], *caps)["over"] == ["combined", "installed"]
    roomy = (base["combined"] + half, base["installed"] + (4 << 20))
    judged = gate.size_gate(base, prepared["front"], *roomy)
    assert judged["status"] == "FAIL" and judged["over"] == ["combined"]
