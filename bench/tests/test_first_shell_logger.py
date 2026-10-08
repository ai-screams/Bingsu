"""bench/first-shell-logger.sh, sourced by zsh and bash 5 with a stand-in
`bingsu` on PATH and the log in a temporary folder (the user's rc and log
are never touched). Each listed shell (BINGSU_TEST_SHELLS) that the logger
supports must be installed; a missing one fails."""
import os
import platform
import re
import subprocess

import pytest

from conftest import ROOT, SHELLS

LOGGER = ROOT / "bench/first-shell-logger.sh"
LOGGER_SHELLS = [s for s in SHELLS if s in ("zsh", "bash")]
FLAGS = {"bash": ["--norc", "--noprofile"], "zsh": ["-f"]}
FAKE = '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_ARGV"\nsleep "${FAKE_SLEEP:-0}"\nexit "${FAKE_RC:-0}"\n'


def boot_id():
    if platform.system() == "Darwin":
        return subprocess.run(["sysctl", "-n", "kern.bootsessionuuid"], capture_output=True, text=True,
                              check=True).stdout.strip()
    return open("/proc/sys/kernel/random/boot_id").read().strip()


def setup(tmp):
    (tmp / "bin").mkdir()
    (tmp / "bin/bingsu").write_text(FAKE)
    (tmp / "bin/bingsu").chmod(0o755)
    return {"PATH": f"{tmp / 'bin'}:{os.environ['PATH']}", "HOME": str(tmp), "LC_ALL": "C",
            "BINGSU_M1_FIRST_SHELL_LOG": str(tmp / "first.tsv"), "FAKE_ARGV": str(tmp / "argv")}


def source(shell, env, tmp, pre=""):
    return subprocess.run([shell, *FLAGS[shell], "-c", f'{pre}source "{LOGGER}"; echo "leak=${{_m1_phase-}}${{_m1_boot-}}"'],
                          env=env, cwd=tmp, capture_output=True, text=True, timeout=30)


def rows(tmp):
    log = tmp / "first.tsv"
    return [l.split("\t") for l in log.read_text().splitlines()] if log.exists() else []


# 이것을 실패시키는 것: 첫 셸을 cold, 둘째를 warm으로 남기지 않는 것, 셋째 셸이 줄을 더 남기는 것, 부팅 정체를
# 다른 출처에서 읽는 것, init에 셸 이름을 넘기지 않는 것, 작업 변수를 셸에 남기는 것.
# 목록의 셸이 없으면 subprocess가 FileNotFoundError로 실패한다.
@pytest.mark.parametrize("shell", LOGGER_SHELLS)
def test_cold_then_warm_then_nothing(shell, tmp_path):
    env = setup(tmp_path)
    for _ in range(3):
        r = source(shell, env, tmp_path)
        assert r.returncode == 0 and r.stdout == "leak=\n", r
    got = rows(tmp_path)
    assert [g[2:5] for g in got] == [[shell, "phase=cold", "status=0"], [shell, "phase=warm", "status=0"]], got
    assert {g[1] for g in got} == {boot_id()}
    assert all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", g[0]) and re.fullmatch(r"\d+us", g[5]) for g in got)
    assert (tmp_path / "argv").read_text() == f"init {shell}\n" * 2
    assert sorted(p.name for p in tmp_path.glob("first.tsv.*")) == [f"first.tsv.{boot_id()}.cold",
                                                                    f"first.tsv.{boot_id()}.warm"]


# 이것을 실패시키는 것: init이 실패한 셸도 줄을 남기는 것(그 시간은 측정이 아님), 실패한 셸이 예약한 phase를
# 돌려주지 않아 다음 셸이 cold를 다시 재지 못하는 것.
@pytest.mark.parametrize("shell", LOGGER_SHELLS)
def test_failed_init_logs_nothing(shell, tmp_path):
    env = setup(tmp_path)
    assert source(shell, dict(env, FAKE_RC="3"), tmp_path).returncode == 0
    assert rows(tmp_path) == [] and list(tmp_path.glob("first.tsv.*")) == []
    source(shell, env, tmp_path)
    assert [g[3] for g in rows(tmp_path)] == ["phase=cold"]


# 이것을 실패시키는 것: phase를 원자적으로 예약하지 않고 행 수로 고르는 것. 두 셸이 같이 시작하면 둘 다 0행을 보고
# cold를 두 번 쓰고, 그 뒤로 warm은 영영 남지 않는다. 가짜 init이 0.3초 자므로 두 셸의 고르는 시점이 겹친다.
@pytest.mark.parametrize("shell", LOGGER_SHELLS)
def test_two_shells_at_once_take_cold_and_warm(shell, tmp_path):
    env = dict(setup(tmp_path), FAKE_SLEEP="0.3")
    for _ in range(3):
        for f in tmp_path.glob("first.tsv*"):
            f.rmdir() if f.is_dir() else f.unlink()
        procs = [subprocess.Popen([shell, *FLAGS[shell], "-c", f'source "{LOGGER}"'], env=env, cwd=tmp_path,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        assert all(p.wait(timeout=30) == 0 for p in procs)
        assert sorted(g[3] for g in rows(tmp_path)) == ["phase=cold", "phase=warm"], rows(tmp_path)


# 이것을 실패시키는 것: 기록 폴더가 없을 때 이유 없이 아무것도 남기지 않는 것(조용한 건너뜀), 그때 init을 재는 것.
@pytest.mark.parametrize("shell", LOGGER_SHELLS)
def test_missing_log_folder_says_so(shell, tmp_path):
    env = dict(setup(tmp_path), BINGSU_M1_FIRST_SHELL_LOG=str(tmp_path / "absent/first.tsv"))
    r = source(shell, env, tmp_path)
    assert r.returncode == 0 and f"no folder {tmp_path / 'absent'}" in r.stderr, r
    assert not (tmp_path / "absent").exists() and not (tmp_path / "argv").exists()


# 이것을 실패시키는 것: 빼는 방향이나 단위가 틀린 것(0.2초 잠드는 init이 0.2초 이상 2초 미만으로 남지 않음).
@pytest.mark.parametrize("shell", LOGGER_SHELLS)
def test_time_is_the_init_run(shell, tmp_path):
    env = setup(tmp_path)
    source(shell, dict(env, FAKE_SLEEP="0.2"), tmp_path)
    us = int(rows(tmp_path)[0][5][:-2])
    assert 200_000 <= us < 2_000_000, us


# 이것을 실패시키는 것: 소수 자리를 그대로 붙이는 것(zsh 9자리에서 넘침), 쉼표 소수점을 못 읽는 것, 짧은 소수부를
# 0으로 채우지 않는 것, 앞의 0을 8진수로 읽는 것.
@pytest.mark.parametrize("shell", LOGGER_SHELLS)
def test_microseconds_of_one_clock_value(shell, tmp_path):
    fn = re.search(r"^_m1_us_of\(\) \{\n.*?^\}\n", LOGGER.read_text(), re.S | re.M).group(0)
    cases = {"1791259131.123456789": 1791259131123456, "5,000001": 5000001, "12.5": 12500000,
             "7.080000": 7080000}
    script = fn + "".join(f'_m1_us_of "{v}"\n' for v in cases)
    r = subprocess.run([shell, *FLAGS[shell], "-c", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and r.stdout.split() == [str(v) for v in cases.values()], r


# 이것을 실패시키는 것: 시계를 두 번 읽는 사이에 잰 명령과 상태 저장 말고 다른 것(명령 치환, 변환)을 두는 것.
def test_bracket_holds_only_the_measured_command():
    text = LOGGER.read_text()
    inside = re.search(r"_m1_clock0=\$EPOCHREALTIME\n(.*?)\n\s*_m1_clock1=\$EPOCHREALTIME", text, re.S).group(1)
    assert [l.strip() for l in inside.splitlines()] == ['bingsu init "$_m1_sh" >/dev/null 2>&1', "_m1_rc=$?"]


# 이것을 실패시키는 것: EPOCHREALTIME이 없는 셸에서 빈 값으로 계산해 틀린 줄을 남기거나 오류로 셸 시작을 막는 것,
# 이유를 말하지 않는 것(조용한 건너뜀).
def test_no_clock_logs_nothing_and_says_so(tmp_path):
    if "bash" not in LOGGER_SHELLS:
        pytest.fail("this test needs bash in BINGSU_TEST_SHELLS")
    env = setup(tmp_path)
    r = source("bash", env, tmp_path, pre="unset EPOCHREALTIME; ")
    assert r.returncode == 0 and "no EPOCHREALTIME" in r.stderr, r
    assert rows(tmp_path) == [] and not (tmp_path / "argv").exists()
