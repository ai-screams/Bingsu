"""The first visible prompt (M3a Task V3): the real binary renders the
built-in default theme for each shell, two lines, through the M1 hooks."""
import os
import pathlib

import pyte
import pytest

import subprocess

from conftest import ROOT, Install, minimal_record, trusted_env
from test_init_words import source
from pty_session import Session

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
COLS, ROWS = 100, 30
# Paths reach the shell quoted (source line) or through the environment
# (cd), so a temporary folder with spaces or quotes does not split them.
CD = {"zsh": 'cd -- "$BINGSU_T_DIR"', "bash": 'cd -- "$BINGSU_T_DIR"', "fish": "cd -- $BINGSU_T_DIR"}


def screen_rows(transcript: bytes):
    scr = pyte.Screen(COLS, ROWS)
    pyte.ByteStream(scr).feed(transcript)
    return [r.rstrip() for r in scr.display]


def start(tmp_path, shell, folder):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    folder.mkdir(parents=True)
    env["BINGSU_T_DIR"] = str(folder)
    s = Session(shell, env, cols=COLS, rows=ROWS)
    s.run(source(shell, init).decode().rstrip("\n"))
    s.run(CD[shell])
    return s


# 이것을 실패시키는 것: hook이 `--shell`·`--pwd`를 넘기지 않는 것(최소 레코드 `> `가 그려짐), prompt가
# 렌더러를 부르지 않는 것, 윗줄을 버리는 것, 실패한 명령 뒤 char가 바뀌지 않는 것.
# 윗줄 판정에 `"cd " not in r` 같은 부분 문자열 제외를 넣지 않는다: 에코된 명령 줄은 `" 1"`로 끝나지 않아
# 이미 걸러지고(제외를 지워도 3셸 통과), hostname이 `...cd`인 runner에서는 정상 윗줄을 버린다.
@pytest.mark.parametrize("shell", SHELLS)
def test_default_prompt_is_drawn(tmp_path, shell):
    folder = tmp_path / "vis-prompt"
    s = start(tmp_path, shell, folder)
    s.run("false")
    rows = screen_rows(s.close())
    # The prompt after `false`: its upper row holds the folder and the
    # status 1, the row below starts with the failure char.
    hits = [i for i, r in enumerate(rows) if "vis-prompt" in r and r.endswith(" 1")]
    assert hits, "\n".join(rows)
    assert rows[hits[0] + 1].lstrip().startswith("\u2717"), rows[hits[0] + 1]
    assert not any(r.startswith("> ") for r in rows), rows


# Upgrade the other way round: a hook from M3a calls a binary that predates
# the display words (an older binary under the pinned path). 이것을 실패시키는 것:
# 새 hook이 bad-args 최소 레코드를 받고 셸을 멈추거나 오류를 찍는 것, 옛 바이너리를 흉내 낸 가짜가 새 단어를 받는 것.
@pytest.mark.parametrize("shell", SHELLS)
def test_new_hook_with_older_binary_keeps_the_shell_usable(tmp_path, shell):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(minimal_record(), script=ROOT / "tests/shell/fake_bingsu_m2.sh")
    # The fake answers the new words as the old parser does, byte for byte.
    # Run through the installed link, so its argv.log lands in tmp_path.
    r = subprocess.run([str(inst.exe), "prompt", "--ctx", "1", "--record", "B1", "--width", "80", "--shell", "zsh"],
                       capture_output=True)
    assert (r.returncode, r.stderr, r.stdout) == (0, b"", minimal_record(status=b"error:bad-args")), r
    (inst.dir / "argv.log").unlink()
    s = Session(shell, env, cols=COLS, rows=ROWS)
    s.run(source(shell, init).decode().rstrip("\n"))
    s.run("echo STILL""_USABLE")
    rows = screen_rows(s.close())
    assert any(r.startswith("STILL_USABLE") for r in rows), rows
    assert any(r.startswith("> ") for r in rows), rows
    assert inst.calls() and all(b"--shell" in c for c in inst.calls()), inst.calls()
