"""The full-screen terminal session (crates/bingsu/src/commands/tty/session.rs)
under a real interactive zsh with job control: Ctrl-Z, `bg` and `fg`, and a
resize under the alternate screen, judged on the screen model and the
transcript together (the terminal mode alone does not show the alternate
screen, the cursor or bracketed paste).

Until a command uses the session, its entry point is the ignored child test
`commands::tty::session::tests::screen_child` of the bingsu test binary, built
on the host (`cargo test -p bingsu --bin bingsu --no-run`); the minimum-shell
images cannot run that binary."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ROOT, real_bin, trusted_env
from pty_session import Session
from screen_session import ScreenSession
from shell_support import cargo_test_binaries
from test_prompt_deadline import is_static

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")

CHILD = "commands::tty::session::tests::screen_child"
# Starts the child with the session's signals blocked (the mask is kept across
# exec, and the zsh job keeps its pid and process group): libtest's other
# threads never take them, and the child lets them through on its own thread,
# as a bingsu with one thread takes them (see the session module comment).
MASKED = ("import os,signal,sys;"
          "signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGHUP,"
          "signal.SIGTSTP,signal.SIGCONT,signal.SIGWINCH});"
          "os.execv(sys.argv[1],sys.argv[1:])")
ENTER = b"\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l"
LEAVE = b"\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l"


@pytest.fixture(scope="module")
def session_binary():
    supplied = os.environ.get("BINGSU_TTY_SESSION_TEST_BIN")
    if not supplied and sys.platform == "linux" and is_static(real_bin()):
        pytest.skip("the session's test binary runs on the GNU host")
    candidates = [Path(supplied)] if supplied else sorted(
        cargo_test_binaries(ROOT / "target/debug", "bingsu", "bingsu"),
        key=lambda p: p.stat().st_mtime_ns, reverse=True)
    for binary in candidates:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            continue
        listed = subprocess.run([str(binary), "--list", "--ignored"], capture_output=True, timeout=15)
        if listed.returncode == 0 and f"{CHILD}: test".encode() in listed.stdout:
            return str(binary)
    pytest.fail("build the bingsu test binary before pytest (cargo test -p bingsu --bin bingsu --no-run) "
                "or set BINGSU_TTY_SESSION_TEST_BIN")


def on_alternate(view, text):
    """The alternate screen is on, with the cursor hidden and bracketed paste
    on, and its first row starts with `text`."""
    screen = view.screen
    return (screen.private_mode(1049) and screen.cursor.hidden and screen.private_mode(2004)
            and view.lines()[0].startswith(text))


def on_main(view, text):
    """The main screen is back, with the cursor shown and synchronized output
    off, and `text` is on it. Bracketed paste is judged on the transcript:
    zsh's line editor turns it on again at its prompt."""
    screen = view.screen
    return (not screen.private_mode(1049) and not screen.cursor.hidden and not screen.private_mode(2026)
            and any(text in line for line in view.lines()))


# Ctrl-Z, `bg`, `fg`, a resize and `q` in one job. 이것을 실패시키는 것: 멈추기 전에 대체 화면·커서·붙여 넣기와
# termios를 되돌리지 않는 것, bg로 이어 간 작업이 그리거나 터미널을 잡는 것(배경에서 쓰면 tostop 없이도 화면에
# 보이고, tcsetattr은 SIGTTOU로 작업을 다시 멈춤), fg 때 다시 들어가 전부 다시 그리지 않는 것, 대체 화면 중 크기
# 변경을 알리지 않는 것, 끝날 때 복구 열을 차례대로 보내지 않는 것.
def test_ctrl_z_bg_fg_and_resize_under_zsh(session_binary, tmp_path):
    env = {**trusted_env(tmp_path), "HOME": str(tmp_path)}
    with Session("zsh", env, cols=80, rows=24) as sh:
        screen = ScreenSession(sh, 24, 80)
        sh.run(f"cd '{tmp_path}' && stty -g > before")
        sh.p.sendline(f"'{sys.executable}' -c '{MASKED}' '{session_binary}' --exact {CHILD} --ignored --nocapture "
                      "--test-threads=1 > report 2>&1")
        assert screen.wait(lambda v: on_alternate(v, "SCREEN 1 80x24"), stable=True), screen.lines()

        sh.p.send(b"\x1a")
        assert screen.wait(lambda v: on_main(v, "suspended"), stable=True), screen.lines()
        sh.run("stty -g > stopped")

        sh.run("bg")
        sh.run("jobs -l > jobs")
        assert "running" in (tmp_path / "jobs").read_text(), (tmp_path / "jobs").read_text()
        # The background job draws nothing.
        assert not screen.wait(lambda v: v.screen.private_mode(1049), timeout=0.5), screen.lines()

        sh.p.sendline("fg")
        assert screen.wait(lambda v: on_alternate(v, "SCREEN 2 80x24"), stable=True), screen.lines()

        screen.resize(30, 100)
        assert screen.wait(lambda v: on_alternate(v, "SCREEN 3 100x30"), stable=True), screen.lines()

        sh.p.send(b"q")
        assert screen.wait(lambda v: on_main(v, "jobs -l > jobs"), stable=True), screen.lines()
        assert not any("SCREEN" in line for line in screen.lines()), screen.lines()
        sh.run("stty -g > after")
        transcript = sh.log.getvalue()

    before = (tmp_path / "before").read_text()
    assert (tmp_path / "stopped").read_text() == before
    assert (tmp_path / "after").read_text() == before
    report = [line.split("ANSWER ", 1)[1] for line in (tmp_path / "report").read_text().splitlines()
              if "ANSWER " in line]
    assert report == ["Resumed(Size { cols: 80, rows: 24 })", "Resized(Size { cols: 100, rows: 30 })", "done"]
    # Entered twice (start, fg) and left twice (Ctrl-Z, q), each sequence in
    # its order; the job put everything back before zsh said it stopped.
    assert transcript.count(ENTER) == 2 and transcript.count(LEAVE) == 2, transcript
    first = transcript.index(ENTER)
    assert transcript.index(LEAVE, first) < transcript.index(b"suspended", first)
    assert transcript.rindex(LEAVE) > transcript.rindex(ENTER)
