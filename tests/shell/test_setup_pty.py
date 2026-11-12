"""`bingsu setup` on a pseudo-terminal: the terminal is restored on every way
out of the background query, and a late answer does not reach the command
line.

The test plays the terminal. `sh` prints the terminal settings (`stty -g`)
before and after `bingsu setup`, and the test answers (or does not answer) the
query `OSC 11 ; ?` the way a terminal would."""
import io
import os
import pty
import re
import select
import shutil
import signal
import tempfile
import time
from pathlib import Path

import pexpect
import pytest

from conftest import real_bin

QUERY = rb"\x1b\]11;\?\x1b\\"
DARK = b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\"
# The answer time limit is 200 ms and a silent terminal is read for 50 ms more
# (crates/bingsu/src/commands/tty.rs); a late answer is sent in the middle of
# that window (225 ms after the query was written).
LATE_WINDOW_MIDDLE = 0.225


@pytest.fixture
def home():
    # The folder is under /tmp, a short real path (no link on the way).
    root = Path(tempfile.mkdtemp(prefix="bsetup-")).resolve()
    root.chmod(0o700)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def spawn(home, *args, background=False):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    run = f'"{real_bin()}" setup {" ".join(args)}'
    # In the background `$!` names bingsu itself (not a shell around it), for a signal.
    run = f"{run} & echo BPID=$!; wait $!" if background else run
    script = f"echo BEFORE=$(stty -g); {run}; echo RC=$?; echo AFTER=$(stty -g)"
    child = pexpect.spawn("/bin/sh", ["-c", script], env=env, timeout=10)
    # pexpect waits 50 ms before every send by default; the late answer must
    # arrive inside a 50 ms window.
    child.delaybeforesend = None
    child.transcript = io.BytesIO()
    child.logfile_read = child.transcript
    return child


def finish(child):
    """Reads to the end; returns (exit code of setup, settings before, settings after, text)."""
    child.expect(pexpect.EOF)
    text = child.transcript.getvalue().decode("utf-8", "replace")
    before, after = (re.search(rf"{k}=(\S+)", text).group(1) for k in ("BEFORE", "AFTER"))
    return int(re.search(r"RC=(\d+)", text).group(1)), before, after, text


def config(home):
    path = home / "cfg/bingsu/config.toml"
    return path.read_text() if path.exists() else None


# 이것을 실패시키는 것: 응답을 받은 뒤 `tcsetattr`로 되돌리지 않는 것(Drop의 복구 삭제), 응답을 화면에
# 되풀이(echo)하는 것, 응답을 읽지 못하거나 밝기 판정이 뒤집히는 것(어두운 배경이 dark로 안 나옴).
def test_reply_restores_the_terminal_and_is_not_echoed(home):
    child = spawn(home, "--icons", "nerd")
    child.expect(QUERY)
    child.send(DARK)
    child.expect(rb"the terminal looks dark")
    child.send("\n")
    child.expect(rb"\[Y/n\] ")
    child.send("\n")
    code, before, after, text = finish(child)
    assert code == 0, text
    assert before == after, (before, after)
    assert "rgb:1e1e" not in text, "the answer must not be echoed"
    assert 'mode = "dark"' in config(home)


# 이것을 실패시키는 것: 응답이 없을 때 시간 제한 없이 기다리는 것, 시간 초과 뒤 복구하지 않는 것,
# 시간 초과를 선택 질문("the terminal did not say")으로 잇지 않는 것.
def test_silence_times_out_restores_and_asks(home):
    child = spawn(home, "--icons", "nerd")
    child.expect(QUERY)
    started = time.monotonic()
    child.expect(rb"the terminal did not say", timeout=3)
    assert time.monotonic() - started < 2.0
    child.send("l\n")
    child.expect(rb"\[Y/n\] ")
    child.send("\n")
    code, before, after, text = finish(child)
    assert code == 0, text
    assert before == after, (before, after)
    assert 'mode = "light"' in config(home)


# 이것을 실패시키는 것: 응답 대기 중 Ctrl-C(0x03)를 취소로 처리하지 않는 것, 취소 뒤 복구하지 않는 것,
# 취소하고도 파일을 만드는 것, 종료 코드가 130이 아닌 것.
def test_ctrl_c_during_the_query_cancels_restores_and_writes_nothing(home):
    child = spawn(home, "--icons", "nerd")
    child.expect(QUERY)
    child.send(b"\x03")
    code, before, after, text = finish(child)
    assert code == 130, text
    assert "cancelled" in text
    assert before == after, (before, after)
    assert config(home) is None
    assert not (home / "cfg").exists()


# 이것을 실패시키는 것: SIGTERM에 핸들러를 두지 않는 것(터미널이 raw인 채 죽음), 신호 뒤 복구 경로를
# 건너뛰는 것.
def test_sigterm_during_the_query_restores_the_terminal(home):
    child = spawn(home, "--icons", "nerd", background=True)
    child.expect(QUERY)
    pid = int(re.search(rb"BPID=(\d+)", child.transcript.getvalue()).group(1))
    os.kill(pid, signal.SIGTERM)
    code, before, after, text = finish(child)
    assert code == 130, text
    assert before == after, (before, after)
    assert config(home) is None


class RawTerminal:
    """A pseudo-terminal read in a tight loop, for the one test whose answer
    must land in a 50 ms window: pexpect's own delays (a read, a send) are as
    long as the window."""

    def __init__(self, script, env):
        pid, fd = pty.fork()
        if pid == 0:
            os.execve("/bin/sh", ["/bin/sh", "-c", script], env)
        self.pid, self.fd, self.log = pid, fd, b""

    def read_until(self, pattern, timeout=5.0):
        """Reads until `pattern` (bytes) is in the log; returns the time it was seen."""
        end = time.monotonic() + timeout
        while pattern not in self.log:
            left = end - time.monotonic()
            assert left > 0, (pattern, self.log)
            if select.select([self.fd], [], [], left)[0]:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                self.log += chunk
        assert pattern in self.log, (pattern, self.log)
        return time.perf_counter()

    def finish(self):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if select.select([self.fd], [], [], 0.2)[0]:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                self.log += chunk
        os.waitpid(self.pid, 0)
        os.close(self.fd)
        text = self.log.decode("utf-8", "replace")
        before, after = (re.search(rf"{k}=(\S+)", text).group(1) for k in ("BEFORE", "AFTER"))
        return int(re.search(r"RC=(\d+)", text).group(1)), before, after, text


# 이것을 실패시키는 것: 시간 제한 뒤 짧게 더 읽어 버리는 것과 `tcsetattr(TCSAFLUSH)`·`tcflush`를 뺀 것
# (늦은 응답이 입력 줄에 남아 다음 질문의 답을 오염시킴: 답 "l"이 "light"가 아니라 "auto"가 됨).
def test_a_late_answer_does_not_reach_the_next_question(home):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    script = (f'echo BEFORE=$(stty -g); "{real_bin()}" setup --icons nerd; '
              'echo RC=$?; echo AFTER=$(stty -g)')
    t = RawTerminal(script, env)
    seen = t.read_until(b"\x1b]11;?\x1b\\")
    # 225 ms after the query: past the 200 ms limit, inside the 50 ms read.
    while time.perf_counter() < seen + LATE_WINDOW_MIDDLE:
        time.sleep(0.001)
    os.write(t.fd, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
    t.read_until(b"the terminal did not say")
    time.sleep(0.3)
    os.write(t.fd, b"l\n")
    t.read_until(b"[Y/n] ")
    os.write(t.fd, b"\n")
    code, before, after, text = t.finish()
    assert code == 0, text
    assert before == after, (before, after)
    assert 'mode = "light"' in config(home), config(home)
