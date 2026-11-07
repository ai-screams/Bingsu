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


# 이것을 실패시키는 것: 두 진입점이 같은 봉투에서 다른 record를 내는 것(공유 파일 밖의 분기).
@pytest.mark.parametrize("args", [
    ["prompt", *BASE, "--redraw"],
    ["prompt", *BASE, "--redraw", "--host", "--helper-exe=/evil"],
    ["prompt", "--ctx", "1", "--record", "B9", "--redraw"],
    ["prompt", *BASE, "--redraw", "--ctx", "1"],
    ["prompt", *BASE, "--redraw", "--helper-exe=relative"],
    ["prompt", *BASE, "--redraw", "--helper-exe=/a", "--helper-exe=/a"],
])
def test_same_record_as_the_cli_entry(args):
    cli = run(real_bin(), str(real_bin()), args)
    dedicated = run(real_prompt(), str(real_prompt()), args)
    assert (dedicated.returncode, dedicated.stdout, dedicated.stderr) == (cli.returncode, cli.stdout, cli.stderr)


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
    r = run(program, argv0.replace("@PROBE@", str(probe)), args)
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
