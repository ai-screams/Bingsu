"""bench/shell_gate.py: the verdict is a ratio, evidence that is short or
unstable blocks, and a real zsh session times what it says it times."""
import json
import os
import shutil
import sys
import uuid

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "bench"))
import protocol as p  # noqa: E402
import shell_gate as g  # noqa: E402


def paired(base, candidate):
    def side(values):
        rows = [{g.METRIC: v} for v in values]
        return dict(samples=rows, summary={g.METRIC: p.summary(values)})
    return dict(status="OBSERVED", variants=dict(base=side(base), candidate=side(candidate)))


def measurement(base, candidate):
    return dict(cases={case: paired(base, candidate) for case in g.RECORDS})


THRESHOLD = (1.25, 1.50)
FAST, SLOW = [1e6] * 200, [100e6] * 200


# 이것을 실패시키는 것: 200쌍 미만을 판정하는 것.
def test_short_rounds_block():
    got = p.paired("base", "candidate", 199, None, lambda *_: {}, required_metrics=(g.METRIC,))
    assert got["status"] == "BLOCKED"
    assert g.verdict(dict(cases={c: got for c in g.RECORDS}), THRESHOLD)["status"] == "BLOCKED"
    short = measurement([1e6] * 199, [1e6] * 199)
    assert g.verdict(short, THRESHOLD)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 불안정한 기준을 표본 없이 PASS로 세는 것.
def test_unstable_reference_blocks(monkeypatch, tmp_path):
    monkeypatch.setattr(p, "calibrate", lambda *_, **__: dict(stable=False))
    exe = tmp_path / "bingsu"
    exe.write_text("x")
    got = p.paired(str(exe), str(exe), 200, None, lambda *_: {g.METRIC: 1}, required_metrics=(g.METRIC,))
    assert (got["status"], got["reason"]) == ("BLOCKED", "unstable calibration")
    assert g.verdict(dict(cases={c: got for c in g.RECORDS}), THRESHOLD)["status"] == "BLOCKED"


# 이것을 실패시키는 것: 절대 시간으로 판정하는 것, 비율 문턱을 지나치는 것, 위쪽 꼬리를 보지 않는 것.
def test_verdict_uses_ratio_not_absolute():
    assert g.verdict(measurement(SLOW, SLOW), THRESHOLD)["status"] == "PASS"
    assert g.verdict(measurement(FAST, [1.3e6] * 200), THRESHOLD)["status"] == "FAIL"
    assert g.verdict(measurement(FAST, [1.2e6] * 200), THRESHOLD)["status"] == "PASS"
    tail = [1e6] * 180 + [1.6e6] * 20
    assert g.verdict(measurement(FAST, tail), THRESHOLD)["status"] == "FAIL"
    row = g.verdict(measurement(SLOW, SLOW), THRESHOLD)["rows"]["prompt"]
    assert row["absolute"]["target_ms"] is None and row["absolute"]["disposition"] is None


# 이것을 실패시키는 것: 행 하나가 없어도 다른 행으로 PASS를 내는 것, 판정 파일이 없을 때 죽는 것.
def test_missing_row_blocks(tmp_path):
    one = dict(cases={"prompt": paired(FAST, FAST)})
    assert g.verdict(one, THRESHOLD)["status"] == "BLOCKED"
    assert g.main(["--measurement", str(tmp_path / "absent.json"), "--ratio-p50", "1.25", "--ratio-p95", "1.5",
                   "--out", str(tmp_path / "v.json")]) == 0
    assert json.loads((tmp_path / "v.json").read_text())["status"] == "BLOCKED"


# 이것을 실패시키는 것: --enforce에서 PASS가 아닌 판정을 통과시키는 것, 강제 없이 실패시키는 것.
@pytest.mark.parametrize("enforce,candidate,code", [(False, [9e6] * 200, 0), (True, [9e6] * 200, 1), (True, FAST, 0)])
def test_cli_exit_code(tmp_path, enforce, candidate, code):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(measurement(FAST, candidate)))
    args = ["--measurement", str(path), "--ratio-p50", "1.25", "--ratio-p95", "1.5", "--out", str(tmp_path / "v.json")]
    assert g.main(args + ["--enforce"] * enforce) == code


@pytest.fixture
def controlled(monkeypatch):
    identity = p.identity()
    reference = dict(n=20, p50=100.0, p95=100.0, variance=0.0, min=100.0, max=100.0)
    monkeypatch.setattr(p, "calibrate", lambda *_, **__: dict(stable=True, p95_of_medians=100.0, median_of_medians=100.0,
                                                       **identity))
    monkeypatch.setattr(p, "snapshot", lambda _: dict(power="ac", load_1m=0.1, thermal="normal", reference=reference,
                                                      host=identity["host"], kernel=identity["kernel"], arch=identity["arch"]))


def real_binary():
    binary = ROOT / "target/debug/bingsu"
    if not binary.exists() or shutil.which("zsh") is None:
        pytest.fail("BLOCKED: this test needs target/debug/bingsu and zsh")
    return binary


# 이것을 실패시키는 것: 시작 때 받은 프롬프트 표지로 Enter를 재는 것(0에 가까운 값), 레코드를 그리지 않은 hook을 재는 것,
# transient 행이 transient를 지나지 않는 것.
def test_real_session_times_enter_to_prompt(controlled):
    binary = real_binary()
    result = g.measure(str(binary), str(binary), 200, dict(p.DEFAULT))
    assert result["status"] == "OBSERVED", result
    for case, row in result["cases"].items():
        assert row["variants"]["base"]["summary"][g.METRIC]["n"] == 200
        assert row["variants"]["candidate"]["summary"][g.METRIC]["min"] > 100_000, row["variants"]["candidate"]["summary"]
        assert row["transient_drawn"] == dict(base=case == "transient-enter", candidate=case == "transient-enter")


# 이것을 실패시키는 것: 크기 변경에서 다시 그리지 않아도 표본을 내는 것, 같은 폭을 다시 보내는 것(신호가 없어 시간 초과).
def test_resize_row_times_the_redraw(controlled):
    binary = real_binary()
    row = g.measure_case("resize-fake", str(binary), str(binary), 200, dict(p.DEFAULT))
    assert row["status"] == "OBSERVED", row
    assert row["variants"]["candidate"]["summary"][g.METRIC]["min"] > 100_000


# 이것을 실패시키는 것: hook이 레코드를 그리지 않았는데 빈 프롬프트 시간을 재는 것.
def test_hooks_that_draw_nothing_block(controlled, tmp_path):
    shim = tmp_path / "bingsu"
    shim.write_text("#!/bin/sh\necho :\n")
    shim.chmod(0o755)
    row = g.measure_case("prompt", str(shim), str(shim), 200, dict(p.DEFAULT))
    assert row["status"] == "BLOCKED" and "did not draw" in row["reason"], row


def live_shells(monkeypatch):
    """Every shell the module starts, whatever happens to its Session."""
    started = []
    popen = g.subprocess.Popen

    def spy(command, *args, **kwargs):
        process = popen(command, *args, **kwargs)
        if command[:3] == ["zsh", "-f", "-i"]:
            started.append(process)
        return process

    monkeypatch.setattr(g.subprocess, "Popen", spy)
    return started


# 이것을 실패시키는 것: transient 행에서 어느 쪽이든 transient를 건너뛴 시간으로 판정하는 것.
@pytest.mark.parametrize("side", ["base", "candidate"])
def test_row_without_a_transient_blocks(controlled, monkeypatch, side):
    binary = real_binary()
    original = g.Session.__init__

    def without_transient(self, binary, case, root):
        original(self, binary, case, root)
        if root.name == side:
            os.write(self.master, b"_bingsu_transient() { :; }\r")
            self.read_prompt()
            self.enter()
            self.seen = self.output

    monkeypatch.setattr(g.Session, "__init__", without_transient)
    row = g.measure_case("transient-enter", str(binary), str(binary), 200, dict(p.DEFAULT))
    assert row["status"] == "BLOCKED" and row["reason"].startswith("no transient drawn"), row
    assert g.verdict(dict(cases={c: row for c in g.RECORDS}), THRESHOLD)["status"] == "BLOCKED"
    assert g.measure_case("prompt", str(binary), str(binary), 200, dict(p.DEFAULT))["status"] == "OBSERVED"


# 이것을 실패시키는 것: 둘째 세션이 실패할 때 첫 세션을 등록해 두지 않는 것(셸이 남음).
def test_failed_second_session_closes_the_first(controlled, tmp_path, monkeypatch):
    binary = real_binary()
    shells = live_shells(monkeypatch)
    row = g.measure_case("prompt", str(binary), str(tmp_path / "missing"), 200, dict(p.DEFAULT))
    assert row["status"] == "BLOCKED", row
    assert len(shells) == 1 and shells[0].poll() is not None


# 이것을 실패시키는 것: 초기화 중 실패에서 셸과 PTY를 닫지 않는 것.
def test_failed_startup_closes_the_shell(controlled, monkeypatch):
    binary = real_binary()
    shells = live_shells(monkeypatch)
    monkeypatch.setattr(g.Session, "enter", lambda self: (_ for _ in ()).throw(ValueError("no prompt in time")))
    fds = len(os.listdir("/dev/fd"))
    row = g.measure_case("prompt", str(binary), str(binary), 200, dict(p.DEFAULT))
    assert row["status"] == "BLOCKED" and row["reason"] == "no prompt in time", row
    assert len(shells) == 1 and shells[0].poll() is not None
    assert len(os.listdir("/dev/fd")) == fds


# 허용되지 않은 시도의 표본도 결과에 남는다: 다시 재서 좋은 값만 고르는 것을 볼 수 있어야 한다.
# 이것을 실패시키는 것: 거부한 블록을 버리는 것, 셸을 다시 띄워 다시 재는 것.
def test_refused_attempts_stay_in_the_output(controlled, monkeypatch):
    binary = real_binary()
    admit, refused = p.admit, []

    def refuse_first(block, condition, calibration):
        if not refused:
            refused.append(block)
            block.update(kept=False, reason="test")
            return False
        return admit(block, condition, calibration)

    monkeypatch.setattr(p, "admit", refuse_first)
    calls = []
    original = g.Session.__init__
    monkeypatch.setattr(g.Session, "__init__", lambda self, *a: (calls.append(a), original(self, *a))[1])
    row = g.measure_case("prompt", str(binary), str(binary), 200, dict(p.DEFAULT))
    assert row["status"] == "OBSERVED", row
    assert [b["kept"] for b in row["blocks"]].count(False) == 1 and row["blocks"][0]["samples"]["base"], row["blocks"][0]
    assert len(row["blocks"]) == 11 and len(calls) == 2


# 이것을 실패시키는 것: 측정 값을 저장소 안에 쓰는 것.
def test_output_stays_outside_the_repository():
    with pytest.raises(ValueError):
        p.validate_output(ROOT / "target" / uuid.uuid4().hex)
