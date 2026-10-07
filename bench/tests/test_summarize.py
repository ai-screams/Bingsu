import json
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import summarize  # noqa: E402

ROWS = {
    "prompt-empty": {"median_ms": 2.0, "p95_ms": 2.5},
    "header64+marker128": {"median_ms": 0.02, "p95_ms": 0.03},
    "min-child-spawn-call": {"median_ms": 0.4, "p95_ms": 0.6},
    "sandbox-ready/dedicated": {"median_ms": 0.9, "p95_ms": 1.2},
    "env-limits/dedicated": {"median_ms": 1.5, "p95_ms": 2.0},
}


# 이것을 실패시키는 것: 도우미·쓰기 자식 생성 호출을 한 번만 더하거나, OS별 작업 프로세스 행을 바꿔 쓰는 것.
def test_serial_sum_parts():
    lin = summarize.serial_sum(ROWS, "linux")
    assert lin["parts"] == ["prompt-empty", "header64+marker128", "min-child-spawn-call (helper)",
                            "sandbox-ready/dedicated", "min-child-spawn-call (writer)"]
    assert round(lin["median_ms"], 2) == round(2.0 + 0.02 + 0.4 + 0.9 + 0.4, 2)
    mac = summarize.serial_sum(ROWS, "macos")
    assert "env-limits/dedicated" in mac["parts"]


# 이것을 실패시키는 것: 같은 값을 OVER로 보는 것(>=), 넘는 값을 ok로 보는 것.
def test_over_flag_is_strictly_greater():
    assert summarize.verdict(3.0, 3.0) == "ok"
    assert summarize.verdict(3.01, 3.0) == "OVER"


# 이것을 실패시키는 것: 부분 경로 측정만으로 "목표를 지킴"(ok)이라고 판정하는 것.
def test_subpath_verdict_never_says_ok():
    assert summarize.subpath_verdict(2.0, 3.0) == "unjudged"
    assert summarize.subpath_verdict(3.0, 3.0) == "unjudged"
    assert summarize.subpath_verdict(3.5, 3.0) == "OVER"


X23 = {
    "redraw:/b/bingsu prompt --ctx 1 --redraw": {"median_ms": 2.5, "p95_ms": 3.0},
    "snapshot-present-read": {"median_ms": 0.05, "p95_ms": 0.08},
    "header64+marker128": {"median_ms": 0.02, "p95_ms": 0.03},
    "init-gen:/b/bingsu init zsh": {"median_ms": 1.2, "p95_ms": 1.5},
    "init-gen:/b/bingsu init fish": {"median_ms": 1.1, "p95_ms": 1.4},
    "init-zsh:env ZDOTDIR=/t/zsh-empty zsh -i -c exit": {"median_ms": 10.0, "p95_ms": 11.0},
    "init-zsh:env ZDOTDIR=/t/zsh-init zsh -i -c exit": {"median_ms": 14.0, "p95_ms": 15.0},
    "init-zsh-cold:env ZDOTDIR=/t/zsh-init zsh -i -c exit": {"median_ms": 90.0, "p95_ms": 90.0},
    "init-fish:env XDG_CONFIG_HOME=/t/fish-empty fish -i -c exit": {"median_ms": 20.0, "p95_ms": 21.0},
    "init-fish:env XDG_CONFIG_HOME=/t/fish-init fish -i -c exit": {"median_ms": 19.0, "p95_ms": 20.0},
}


# 이것을 실패시키는 것: redraw 추정에서 fixture 읽기 몫을 빼먹는 것.
def test_redraw_estimate_adds_fixture_read():
    assert round(summarize.redraw_estimate(X23), 2) == 2.55


# 이것을 실패시키는 것: init 추정에 스냅샷 전체 읽기를 더하거나(머리·표식만이 그 몫),
# 차가운 시작 행을 섞거나, 음수 차를 그대로 쓰는 것.
def test_init_added_estimate_takes_header_marker_share_only():
    assert round(summarize.init_added_estimate(X23, "zsh"), 2) == 4.02
    assert round(summarize.init_added_estimate(X23, "fish"), 2) == 0.02


# 이것을 실패시키는 것: 추정(합·차)으로 OVER를 내거나, 측정한 부분 경로가 목표를 넘었는데 OVER를 내지 않는 것,
# 생성기 행을 셸 이름(끝)으로 가르지 않는 것.
def test_composite_over_but_estimate_unjudged():
    lines = summarize.x23_lines(X23, "linux")
    assert lines[0] == ("X-23 redraw (linux): run median 2.50 ms [unjudged vs 3.0]; "
                        "estimate with fixture read 2.55 ms [estimate, unjudged]")
    assert lines[1] == ("X-23 init added (linux, zsh): generator run median 1.20 ms [unjudged vs 5.0]; "
                        "estimate 4.02 ms [estimate, unjudged]")
    assert lines[2].startswith("X-23 init added (linux, bash): generator run not measured")
    # estimate above the target, measured run below it: still unjudged
    high = dict(X23, **{"snapshot-present-read": {"median_ms": 0.9, "p95_ms": 1.0},
                        "init-zsh:env ZDOTDIR=/t/zsh-init zsh -i -c exit": {"median_ms": 30.0, "p95_ms": 31.0}})
    hl = summarize.x23_lines(high, "linux")
    assert "OVER" not in hl[0] and "3.40 ms [estimate, unjudged]" in hl[0]
    assert "OVER" not in hl[1] and "20.02 ms [estimate, unjudged]" in hl[1]
    # a measured sub-path run above the target is OVER
    over = dict(X23, **{"redraw:/b/bingsu prompt --ctx 1 --redraw": {"median_ms": 3.4, "p95_ms": 4.0},
                        "init-gen:/b/bingsu init zsh": {"median_ms": 8.5, "p95_ms": 9.0}})
    ol = summarize.x23_lines(over, "macos")
    assert "[OVER vs 3.0]" in ol[0] and "[OVER vs 8.0]" in ol[1]
    assert all("[ok" not in l for l in lines + hl + ol)


# 이것을 실패시키는 것: 직렬 합(추정)으로 판정하는 것, 잰 prompt 실행이 목표를 넘었는데 OVER를 내지 않는 것.
def test_x22_judges_prompt_run_not_serial_sum():
    rows = dict(ROWS, **{"sandbox-ready/dedicated": {"median_ms": 9.0, "p95_ms": 14.0}})
    line = summarize.x22_line(rows, "linux")
    assert "prompt run median 2.00 ms [unjudged vs 10]" in line and "OVER" not in line
    slow = dict(rows, **{"prompt-empty": {"median_ms": 11.0, "p95_ms": 16.0}})
    line = summarize.x22_line(slow, "linux")
    assert "[OVER vs 10]" in line and "[OVER vs 15]" in line and line.endswith("[estimate, unjudged]")


# 이것을 실패시키는 것: 목표와 같은 부분 경로 값을 OVER로 보는 것(경계: 같음은 넘음이 아님).
def test_subpath_equal_to_target_is_unjudged_in_lines():
    rows = dict(ROWS, **{"prompt-empty": {"median_ms": 10.0, "p95_ms": 15.0}})
    assert "[OVER" not in summarize.x22_line(rows, "linux")
    eq = dict(X23, **{"redraw:/b/bingsu prompt --ctx 1 --redraw": {"median_ms": 3.0, "p95_ms": 3.0},
                      "init-gen:/b/bingsu init zsh": {"median_ms": 5.0, "p95_ms": 5.0}})
    el = summarize.x23_lines(eq, "linux")
    assert "[unjudged vs 3.0]" in el[0] and "[unjudged vs 5.0]" in el[1]


# 이것을 실패시키는 것: 직렬 합의 부분 행이 빠졌을 때 traceback으로 죽거나 0으로 채우는 것(줄 누락 경계).
def test_missing_part_is_not_measured_not_zero():
    rows = {k: v for k, v in ROWS.items() if k != "min-child-spawn-call"}
    line = summarize.x22_line(rows, "linux")
    assert line.endswith("serial estimate not measured (min-child-spawn-call)"), line
    assert summarize.x22_line({}, "linux") == "X-22 front path (linux): prompt run not measured (prompt-empty)"
    no_fixture = {k: v for k, v in X23.items() if k != "snapshot-present-read"}
    assert summarize.x23_lines(no_fixture, "linux")[0].endswith("estimate not measured (snapshot-present-read)")


# 이것을 실패시키는 것: na 행을 버리거나(not measured로 보임) 값처럼 쓰는 것.
def test_na_row_is_unavailable():
    rows = dict(ROWS, **{"min-child-spawn-call": {"na": "spawn failed (round 3)"}})
    line = summarize.x22_line(rows, "linux")
    assert line.endswith("serial estimate unavailable (min-child-spawn-call unavailable: spawn failed (round 3))"), line
    na_gen = dict(X23, **{"init-gen:/b/bingsu init zsh": {"na": "non-zero exit codes [1]"}})
    assert "generator run unavailable (init-gen:/b/bingsu init zsh unavailable" in summarize.x23_lines(na_gen, "linux")[1]
    assert summarize.startup_line({"prompt-empty": {"na": "x"}}, "macos").startswith("startup (macos): unavailable")


# 이것을 실패시키는 것: startup 판정을 부분 경로처럼 unjudged로 내거나 같음을 넘음으로 보는 것.
def test_startup_is_ok_or_over():
    assert summarize.startup_line({"prompt-empty": {"median_ms": 3.0, "p95_ms": 4.0}}, "macos") == \
        "startup (macos): median 3.00 ms [ok vs 3.0]"
    assert "[OVER vs 1.0]" in summarize.startup_line({"prompt-empty": {"median_ms": 1.5, "p95_ms": 2.0}}, "linux")


# 이것을 실패시키는 것: 6MB와 같은 크기를 OVER로 보거나, 넘는 크기를 ok로 보는 것, 마지막 조합이 아닌 행을 판정하는 것.
def test_size_judges_last_combination_only():
    lines = summarize.size_lines({("macos", "base"): 7_000_000, ("macos", "regex-yaml-json"): 6_000_000})
    assert lines[0].startswith("size (macos) base: 7000000 bytes") and "[" not in lines[0]
    assert lines[1].endswith("[ok vs 6.0 MB]")
    over = summarize.size_lines({("linux", "regex-yaml-json"): 6_000_001})
    assert over[0].endswith("[OVER vs 6.0 MB]")


def _hf(path, *cmds_times):
    path.write_text(json.dumps({"results": [{"command": c, "times": t, "exit_codes": [0] * len(t)}
                                            for c, t in cmds_times]}))


def _row(**kw):
    return json.dumps({"matrix": "file", "os": "macos", "arch": "aarch64", **kw})


# 이것을 실패시키는 것: prompt.json의 prompt 실행을 prompt-empty로 두지 않는 것, 바닥값 행을 prompt-empty로
# 덮는 것, 같은 표본에서 분위수를 nearest-rank로 내지 않는 것.
def test_load_maps_rows(tmp_path):
    _hf(tmp_path / "prompt.json", ("/b/bingsu prompt --ctx 1", [0.002, 0.001, 0.003]), ("/usr/bin/true", [0.0005]))
    (tmp_path / "m1-file-macos.jsonl").write_text(
        json.dumps({"meta": {"os": "macos", "commit": "abc"}}) + "\n"
        + _row(row="header64+marker128", n=2, median_ns=20000, p95_ns=30000) + "\n")
    rows, os, sizes = summarize.load(tmp_path)
    assert os == "macos" and sizes == {}
    assert rows["prompt-empty"] == {"median_ms": 2.0, "p95_ms": 3.0}
    assert rows["prompt:/usr/bin/true"] == {"median_ms": 0.5, "p95_ms": 0.5}
    assert rows["header64+marker128"] == {"median_ms": 0.02, "p95_ms": 0.03}


GOOD = _row(row="header64+marker128", n=1, median_ns=1, p95_ns=1) + "\n"
BAD = {
    "not-json": ("a.jsonl", GOOD + "{not json\n", "a.jsonl:2: not JSON"),
    "not-object": ("a.jsonl", GOOD + "[1]\n", "a.jsonl:2: not a JSON object"),
    "unknown-shape": ("a.jsonl", GOOD + _row(row="x", n=1) + "\n", "a.jsonl:2: neither measured nor na"),
    "no-times": ("init-gen.json", json.dumps({"results": [{"command": "c", "times": []}]}), "'c' has no times"),
    "not-hyperfine": ("redraw.json", json.dumps({"x": 1}), "not a hyperfine export"),
}


# 이것을 실패시키는 것: 읽을 수 없는 입력(형식이 틀린 JSON, 모르는 행, times 없는 hyperfine 결과)을 건너뛰거나
# 0으로 채우는 것, 종료 코드 2로 끝내지 않는 것. 읽을 수 있는 행을 함께 두어 "결과 없음"이 대신 걸리지 않게 한다.
@pytest.mark.parametrize("case", sorted(BAD))
def test_bad_input_fails(tmp_path, case, capsys):
    name, text, why = BAD[case]
    (tmp_path / "ok.jsonl").write_text(GOOD.replace("header64", "other"))
    (tmp_path / name).write_text(text)
    with pytest.raises(summarize.InputError, match=re.escape(why)):
        summarize.load(tmp_path)
    assert summarize.main([str(tmp_path)]) == 2
    assert why in capsys.readouterr().err


# 이것을 실패시키는 것: 같은 행이 두 파일에 있을 때 나중 것으로 덮는 것, 두 OS의 행을 섞는 것,
# 없는 폴더·빈 폴더를 빈 표로 넘기는 것.
def test_duplicate_mixed_missing_empty_fail(tmp_path):
    r = _row(row="header64+marker128", n=1, median_ns=1, p95_ns=1)
    (tmp_path / "a.jsonl").write_text(r + "\n")
    (tmp_path / "b.jsonl").write_text(r + "\n")
    with pytest.raises(summarize.InputError, match="twice: a.jsonl:1 and b.jsonl:1"):
        summarize.load(tmp_path)
    (tmp_path / "b.jsonl").write_text(r.replace('"macos"', '"linux"').replace("header64", "other") + "\n")
    with pytest.raises(summarize.InputError, match="more than one OS"):
        summarize.load(tmp_path)
    with pytest.raises(summarize.InputError, match="not a folder"):
        summarize.load(tmp_path / "absent")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(summarize.InputError, match="no results"):
        summarize.load(empty)
