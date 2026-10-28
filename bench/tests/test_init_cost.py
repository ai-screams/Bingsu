"""init added time: a valid snapshot first, then alternating shell starts."""
import importlib.util
import json
from pathlib import Path
from subprocess import CompletedProcess
import sys

import pytest

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))
SPEC = importlib.util.spec_from_file_location("init_cost", BENCH / "init_cost.py")
init_cost = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(init_cost)
p = init_cost.protocol
COLD = (b"bingsu: reading your settings did not finish in time; the prompt starts with "
        b"the built-in look and takes your settings when they are ready\n")


@pytest.fixture
def controlled(monkeypatch, tmp_path):
    monkeypatch.setattr(p, "calibrate", lambda _: dict(stable=True, p95_of_medians=100, **p.identity()))
    monkeypatch.setattr(p, "snapshot", lambda _: {**p.identity(), "power": "ac", "load_1m": 1.0,
                                                  "thermal": "normal", "reference": p.summary([100] * 20)})
    monkeypatch.setattr(init_cost, "ROOT", tmp_path)
    (tmp_path / "target").mkdir()
    monkeypatch.setattr(init_cost, "shell_version", lambda shell, path: "test 9.9")
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if command[1:2] == ["init"]:
            return CompletedProcess(command, 0, b"script\n", init_cost_stderr[0])
        return CompletedProcess(command, 0, b"", b"")
    init_cost_stderr = [b""]
    monkeypatch.setattr(init_cost, "run_shell", run)
    monkeypatch.setattr(init_cost.M3B, "prompt_context", lambda binary, directory: (["prompt"], {"PATH": "/bin"}))
    return calls, init_cost_stderr


# 이것을 실패시키는 것: 첫 prompt로 정상 스냅샷(ok:none)을 만들지 못했거나 init이 cold 알림을 낸 상태에서
# 셸 시작을 재는 것.
@pytest.mark.parametrize("damage", ["prompt", "cold-init"])
def test_init_cost_requires_valid_snapshot_before_timing(controlled, monkeypatch, damage):
    calls, stderr = controlled
    if damage == "prompt":
        def refused(binary, directory):
            raise ValueError("normal product snapshot unavailable")
        monkeypatch.setattr(init_cost.M3B, "prompt_context", refused)
    else:
        stderr[0] = COLD
    got = init_cost.measure("/b/bingsu", "zsh", 200, dict(p.DEFAULT))
    assert got["status"] == "BLOCKED" and "init_added_ns" not in got
    assert not [c for c in calls if c[1:2] != ["init"]]  # no shell start was timed


# 이것을 실패시키는 것: init 줄이 있는 rc와 없는 rc를 교대하지 않거나(한쪽을 몰아 재기),
# 두 rc의 차이를 init 줄 하나 밖으로 넓히는 것, 차이를 중앙값 차이가 아닌 값으로 쓰는 것.
@pytest.mark.parametrize("shell", ["zsh", "bash", "fish"])
def test_init_cost_alternates_with_and_without_init(controlled, monkeypatch, shell):
    calls, _ = controlled
    times = {"without": 1_000, "with": 4_000}
    order = []
    def timed(command, env, variant, expected):
        order.append(variant)
        return times[variant]
    monkeypatch.setattr(init_cost, "time_shell", timed)
    got = init_cost.measure("/b/bingsu", shell, 200, dict(p.DEFAULT))
    assert got["status"] == "OBSERVED", got.get("reason")
    timed_order = order[2:]  # the first process of each variant is cold
    assert len(timed_order) == 400
    for i in range(0, 400, 2):
        assert sorted(timed_order[i:i + 2]) == ["with", "without"]
    assert got["init_added_ns"] == {"n": 200, "p50": 3_000, "p95": 3_000,
                                    "basis": "median(with init) - median(without init); p95 likewise"}
    line = {"zsh": 'eval "$(/b/bingsu init zsh)"\n', "bash": 'eval "$(/b/bingsu init bash)"\n',
            "fish": "/b/bingsu init fish | source\n"}[shell]
    assert got["rc"] == {"without": "", "with": line}
    assert json.dumps(got)
