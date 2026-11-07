"""Shell-side gates for zsh (spec section 7): calls per prompt, what the hooks
execute, and one notice across the widgets. Counts, never times. The redraw
gate names D3's tests in test_zsh_hooks.py. Rows are in tests/gate-acceptance.tsv."""
import os
import re
import shutil
import sys

import pytest

import pty_session
from conftest import Install, trusted_env
from shell_support import real_bin, real_collector
from pty_session import Session, visible
from screen_session import ScreenSession
from test_zsh_hooks import VI, VI_RECORD, fields, interrupted, redraws, to_main, to_vicmd, typed_screen, wait_redraws
from test_zsh_screen import FAIL_CHAR, OK_CHAR, SHORT_HOST, enter, settle

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")

NOTICE = b"bingsu: the runtime folder changed"
PROMPTS = 5
VI_PLAIN = VI_RECORD | {"right": b""}  # typed text ends the row


def real_session(tmp_path, shell="zsh", rc=""):
    """The real binary in a shell whose rc lines run before init is sourced."""
    inst = Install(tmp_path)
    env = trusted_env(tmp_path) | SHORT_HOST
    init = tmp_path / "init.zsh"
    init.write_bytes(inst.init("zsh", env))
    s = Session(shell, env, cols=200)
    s.run(f'{rc}\nsource "{init}"', timeout=30)
    return s, inst, ScreenSession(s, 24, 200)


# N 프롬프트에 호출 N번, 그 사이의 키 입력·vi 전환·transient는 0번.
# 이것을 실패시키는 것: 프롬프트를 두 번 부르는 것, 키 입력이나 위젯이 bingsu를 부르는 것.
def test_zsh_call_count_per_prompt(tmp_path):
    s, inst, screen = typed_screen(tmp_path, VI, record=fields(**VI_PLAIN))
    settle(screen)
    before = len(inst.calls())
    for n in range(PROMPTS):
        enter(screen, f"print ROW{n}")  # transient runs on each Enter
        s.p.send("abc")
        assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith("abc"), stable=True), screen.lines()
        s.p.send("\x7f\x7f\x7f")
        assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith("INS>"), stable=True), screen.lines()
        to_vicmd(screen)
        to_main(screen)
    assert len(inst.calls()) == before + PROMPTS, inst.calls()[before:]
    assert not redraws(inst), redraws(inst)
    s.kill()


# 이것을 실패시키는 것: hook이나 위젯이 PATH에서 찾아 외부 명령을 부르는 것(성공이든 실패든 시도로 센다).
@pytest.mark.skipif(not sys.platform.startswith("linux") or shutil.which("strace") is None, reason="needs strace on Linux")
def test_zsh_hooks_exec_only_pinned_binary(tmp_path, monkeypatch):
    trace = tmp_path / "exec.trace"
    strace, zsh = shutil.which("strace"), shutil.which("zsh")
    monkeypatch.setitem(pty_session.ARGV, strace, ["-f", "-qq", "-v", "-e", "trace=execve,execveat", "-o", str(trace), "--",
                                                   zsh, *pty_session.ARGV["zsh"]])
    s, inst, screen = real_session(tmp_path, strace, VI)
    s.run("(exit 3)", timeout=30)
    s.p.send("\x1b")
    s.p.send("i")
    s.run("true", timeout=30)
    settle(screen)  # a size change in a running hook makes no redraw
    screen.resize(24, 120)
    assert screen.wait(lambda v: b'"--redraw"' in trace.read_bytes(), timeout=20), trace.read_text(errors="replace")
    s.kill()
    calls = re.findall(r'exec(?:ve|veat)\((?:\S+, )?"([^"]+)"', trace.read_text(errors="replace"))
    assert calls[0] == zsh, calls
    # The prompt program the hook runs (bingsu-prompt beside a matching build,
    # through this install's link) and the helper it names (the pinned bingsu).
    pinned = {str(inst.exe), str(inst.front()), str(real_bin()), str(real_collector())}
    # 이것을 실패시키는 것: 확인한 bingsu-prompt 대신 다른 프로그램을 부르는 것(위 집합 밖), 형제를 쓰지 않는 것.
    assert inst.dedicated and str(inst.front()) in calls[1:], calls
    assert set(calls[1:]) <= pinned, sorted(set(calls[1:]) - pinned)
    assert len(calls) >= 4, calls


# 프롬프트의 모든 경로가 빈 PATH에서 돈다. 표식은 종료 코드에 따라 바뀌므로 hook이 실제로 돌았음을 보인다.
# 이것을 실패시키는 것: hook이나 위젯이 이름으로 외부 명령을 찾는 것.
def test_zsh_hooks_run_with_empty_path(tmp_path):
    s, _, screen = real_session(tmp_path, rc=f"path=()\n{VI}")
    settle(screen)
    enter(screen, "(exit 3)")
    assert screen.wait(lambda v: FAIL_CHAR in v.lines()[v.cursor()[0]], stable=True), screen.lines()
    enter(screen, "true")
    assert screen.wait(lambda v: OK_CHAR in v.lines()[v.cursor()[0]], stable=True), screen.lines()
    s.p.send("\x1b")
    settle(screen)
    s.p.send("i")
    settle(screen)
    screen.resize(24, 120)
    settle(screen)
    interrupted(screen, "typed")
    s.run("true")
    out = visible(s.close())
    assert b"command not found" not in out and b"bingsu:" not in out, out


# 알림은 프롬프트 hook에서 한 번이고, 위젯은 그 경로를 지나지 않는다.
# 이것을 실패시키는 것: 같은 상태에서 다시 알리는 것, redraw·transient·vi 위젯이 알림을 내는 것.
def test_zsh_notice_once_across_redraw_transient_vi(tmp_path):
    record = fields(status=b"degraded:runtime-root", **VI_PLAIN)
    s, inst, screen = typed_screen(tmp_path, VI, record=record)
    enter(screen, "true")  # transient
    to_vicmd(screen)
    to_main(screen)
    screen.resize(24, 120)
    wait_redraws(screen, inst, 1)
    interrupted(screen, "typed")  # transient through send-break
    s.run("true")
    assert redraws(inst) and s.close().count(NOTICE) == 1
