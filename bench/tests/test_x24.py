import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import x24_writer_frequency as x24  # noqa: E402

SCRIPT = pathlib.Path(x24.__file__)


# 이것을 실패시키는 것: 상태가 같아도 쓰기 자식을 세거나, 초 단위 시각이 바뀌어도 세지 않는 것.
def test_state_change_counting():
    events = [
        x24.Prompt(t=0.0, cwd="/a", status=0, duration_s=None),
        x24.Prompt(t=0.2, cwd="/a", status=0, duration_s=None),   # same second, same state
        x24.Prompt(t=1.5, cwd="/a", status=0, duration_s=None),   # next second
        x24.Prompt(t=1.6, cwd="/b", status=0, duration_s=None),   # cwd changed
        x24.Prompt(t=200.0, cwd="/b", status=1, duration_s=3.0),  # status, duration, minute
    ]
    assert x24.writer_spawns(events, "%H:%M:%S") == 4
    assert x24.writer_spawns(events, "%H:%M") == 3


# 이것을 실패시키는 것: 2초 미만의 duration을 상태로 세거나(보이지 않는 값), 2초를 세지 않는 것(경계).
def test_duration_shows_from_two_seconds():
    base = x24.Prompt(t=0.0, cwd="/a", status=0, duration_s=None)
    assert x24.writer_spawns([base, x24.Prompt(0.1, "/a", 0, 1.99)], "%H:%M") == 1
    assert x24.writer_spawns([base, x24.Prompt(0.1, "/a", 0, 2.0)], "%H:%M") == 2


# 이것을 실패시키는 것: 출력에 합성 자료라는 표시가 없거나, 같은 seed가 다른 결과를 내는 것(재현 불가).
def test_output_is_synthetic_and_seeded():
    def run(seed):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "--seed", seed],
                              capture_output=True, text=True, check=True, timeout=60).stdout
    out = run("7")
    rows = [json.loads(l) for l in out.splitlines()]
    assert len(rows) == 6 and all(r["source"] == "synthetic" and r["x"] == "X-24" for r in rows)
    assert run("7") == out and run("8") != out
