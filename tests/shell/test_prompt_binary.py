"""The dedicated `bingsu-prompt` binary against the `bingsu prompt` entry it
shares its files with: the same records, its own helper rule, and nothing
but `prompt`."""
import os
import subprocess
import time

import pytest

from conftest import real_bin, real_prompt

ROOTS = ["--runtime-root=1:2:/r", "--config-root=/c", "--config-root-written=/c", "--state-root=/s", "--home=/h"]
BASE = ["--ctx", "1", "--record", "B1", "--shell", "bash", "--width", "80", "--pwd", "/"]


def run(program, argv0, args):
    return subprocess.run([argv0, *args], executable=program, env={}, capture_output=True, timeout=10)


# The whole prompt has 50 ms (crates/bingsu/src/prompt_io.rs); a prompt that is over it
# ends at once with exit 0 and nothing on either stream. On a slow runner one process can
# be, and a test that wants a record from a prompt would fail for no reason.
TRIES = 3


def run_in_time(program, argv0, args, record=True):
    """`run`, once more when it ended the way a prompt over its time ends (exit
    0, nothing on stdout or stderr) and a record was expected: up to TRIES
    runs. Any other result is the answer at once, a failure included. When
    every run was empty the test fails, with the number of runs and how long
    each took."""
    elapsed = []
    for _ in range(TRIES):
        started = time.monotonic()
        r = run(program, argv0, args)
        elapsed.append(round((time.monotonic() - started) * 1000))
        if not (record and r.returncode == 0 and r.stdout == b"" and r.stderr == b""):
            return r
    raise AssertionError(f"all {TRIES} runs ended with no output (ms each: {elapsed})")


def entries_agree(cli, dedicated, args, record=True):
    """Both entries give the same answer; for an input that has a record,
    that answer is a record, so two empty answers never pass for "the same"."""
    a = run_in_time(cli, str(cli), args, record)
    b = run_in_time(dedicated, str(dedicated), args, record)
    if record:
        assert a.stdout.startswith(b"B1\x1f") and b.stdout.startswith(b"B1\x1f"), (a, b)
    assert (b.returncode, b.stdout, b.stderr) == (a.returncode, a.stdout, a.stderr)


# 이것을 실패시키는 것: 두 진입점이 같은 봉투에서 다른 record를 내는 것(공유 파일 밖의 분기), 둘 다 빈 출력인 것을 "같다"로
# 통과시키는 것(record가 있어야 하는 입력은 `B1\x1f`로 시작해야 함). 지원하지 않는 record 버전(B9)만 본래 빈 출력이다.
@pytest.mark.parametrize("args,record", [
    (["prompt", *BASE, "--redraw"], True),
    (["prompt", *BASE, "--redraw", "--host", "--helper-exe=/evil"], True),
    (["prompt", "--ctx", "1", "--record", "B9", "--redraw"], False),
    (["prompt", *BASE, "--redraw", "--ctx", "1"], True),
    (["prompt", *BASE, "--redraw", "--helper-exe=relative"], True),
    (["prompt", *BASE, "--redraw", "--helper-exe=/a", "--helper-exe=/a"], True),
])
def test_same_record_as_the_cli_entry(args, record):
    entries_agree(real_bin(), real_prompt(), args, record)


# 이것을 실패시키는 것: prompt가 아닌 명령을 받는 것(다른 명령 코드가 이 바이너리로 들어옴).
@pytest.mark.parametrize("args", [[], ["init", "bash"], ["config", "check"], ["--version"], ["__refresh-v1"], ["Prompt"]])
def test_only_prompt_runs(args):
    r = run(real_prompt(), str(real_prompt()), args)
    assert (r.returncode, r.stdout, r.stderr) == (2, b"", b""), r


def helper_started(tmp_path, program, argv0, extra):
    """Whether the prompt started `probe` as its helper: the probe records
    its argv in a file the moment it runs, and the spawn happens before the
    prompt writes its record, so a second's wait after it exits is margin."""
    marker = tmp_path / "started"
    probe = tmp_path / "probe"
    probe.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$0\" \"$1\" > '{marker}'\n")
    probe.chmod(0o700)
    args = ["prompt", *BASE, *ROOTS, *[a.replace("@PROBE@", str(probe)) for a in extra]]
    r = run_in_time(program, argv0.replace("@PROBE@", str(probe)), args)
    assert r.returncode == 0 and r.stdout.startswith(b"B1\x1f"), r
    deadline = time.monotonic() + 1
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    return marker.read_text().split() if marker.exists() else None


# 이것을 실패시키는 것: 전용 진입점이 argv0로 돌아가는 것, helper 단어를 쓰지 않는 것, 값 자리의
# helper 글을 플래그로 읽는 것, CLI 진입점의 argv0 fallback을 잃는 것.
@pytest.mark.parametrize("program,argv0,extra,want", [
    ("prompt", "@PROBE@", [], None),
    ("prompt", "/unused", ["--helper-exe=@PROBE@"], "@PROBE@"),
    ("prompt", "@PROBE@", ["--host", "--helper-exe=@PROBE@"], None),
    ("prompt", "/unused", ["--helper-exe=@PROBE@", "--helper-exe=@PROBE@"], None),
    ("cli", "@PROBE@", [], "@PROBE@"),
    ("cli", "/unused", ["--helper-exe=@PROBE@"], "@PROBE@"),
    ("cli", "@PROBE@", ["--helper-exe=@PROBE@", "--helper-exe=@PROBE@"], None),
])
def test_helper_rule_per_entry(tmp_path, program, argv0, extra, want):
    binary = real_prompt() if program == "prompt" else real_bin()
    started = helper_started(tmp_path, binary, argv0, extra)
    if want is None:
        assert started is None, started
    else:
        assert started == [str(tmp_path / "probe"), "__refresh-v1"], started


# 이것을 실패시키는 것: 이 바이너리에 다른 역할 표식을 넣거나 빠뜨리는 것(init의 형제 검사가 받지 못함).
def test_one_prompt_role_marker():
    data = real_prompt().read_bytes()
    marker = b"BNGROLE-ID02\0\0\0\0"
    assert data.count(marker) == 1
    at = data.index(marker)
    assert data[at + 16] == 3
    sibling = b"BNGSIBLING-ID02\0"
    assert data.count(sibling) == 1
    built = data[data.index(sibling) + 16:data.index(sibling) + 48]
    assert data[at + 17:at + 49] == built
    cli = real_bin().read_bytes()
    assert cli[cli.index(sibling) + 16:cli.index(sibling) + 48] == built


def stand_in(tmp_path, name, body):
    """A program that counts its runs in `<name>.runs` and then does `body`."""
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\necho x >> '{tmp_path}/{name}.runs'\n{body}\n")
    path.chmod(0o700)
    return path


def runs_of(tmp_path, name):
    f = tmp_path / f"{name}.runs"
    return len(f.read_text().split()) if f.exists() else 0


# 이것을 실패시키는 것: 마감 모양(종료 0, 출력 없음)이 아닌 결과를 다시 시도하는 것(0이 아닌 종료, 다른 출력, stderr가 있는 것),
# 재시도 횟수를 TRIES와 다르게 하는 것, 모두 비었는데 실패하지 않는 것, 실패 메시지에 횟수와 각 시도의 시간이 없는 것,
# record를 기대하지 않는 입력(본래 빈 출력)을 다시 시도하는 것.
def test_only_the_over_time_shape_is_run_again(tmp_path):
    assert TRIES == 3
    for name, body in [("exit3", "exit 3"), ("stderr", "echo oops >&2; exit 0"), ("record", "printf 'B1\\037x'")]:
        prog = stand_in(tmp_path, name, body)
        r = run_in_time(prog, str(prog), [])
        assert runs_of(tmp_path, name) == 1, (name, r)
    # Empty twice, then a record: the third run is the answer.
    prog = stand_in(tmp_path, "late", f"[ $(wc -l < '{tmp_path}/late.runs') -ge 3 ] && printf 'B1\\037x'; exit 0")
    r = run_in_time(prog, str(prog), [])
    assert r.stdout.startswith(b"B1\x1f") and runs_of(tmp_path, "late") == 3
    # Empty every time: a failure that says how many runs and how long each took.
    prog = stand_in(tmp_path, "never", "exit 0")
    with pytest.raises(AssertionError, match=r"all 3 runs.*ms each: \[\d+, \d+, \d+\]"):
        run_in_time(prog, str(prog), [])
    assert runs_of(tmp_path, "never") == 3
    # An input with no record to give is empty by design: once, and no failure.
    prog = stand_in(tmp_path, "design", "exit 0")
    assert run_in_time(prog, str(prog), [], record=False).stdout == b"" and runs_of(tmp_path, "design") == 1


# 이것을 실패시키는 것: 두 진입점이 모두 비어 있는데 같다고 통과시키는 것(`B1` 단언을 지움), 한쪽만 다른 것을 같다고
# 보는 것, 기대하지 않는 입력의 같은 빈 출력을 실패로 보는 것.
def test_two_empty_answers_are_not_the_same_record(tmp_path):
    same = stand_in(tmp_path, "same", "printf 'B1\\037same'")
    other = stand_in(tmp_path, "other", "printf 'B1\\037other'")
    empty = stand_in(tmp_path, "empty", "exit 0")
    entries_agree(same, same, [])
    with pytest.raises(AssertionError):
        entries_agree(same, other, [])
    with pytest.raises(AssertionError):
        entries_agree(empty, empty, [])
    entries_agree(empty, empty, [], record=False)
    # The same answer that is no record (both entries printing the same junk) is no pass either.
    junk = stand_in(tmp_path, "junk", "printf 'not a record'")
    with pytest.raises(AssertionError):
        entries_agree(junk, junk, [])
    entries_agree(junk, junk, [], record=False)
