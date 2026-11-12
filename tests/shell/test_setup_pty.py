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
import resource
import select
import shutil
import signal
import sys
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


# Opens every descriptor from 3 to 1099 and then becomes `bingsu`, so that its
# `/dev/tty` opens above FD_SETSIZE (1024). Python's own descriptors are
# closed on exec; the dup2 copies are not.
HIGH_DESCRIPTORS = (
    "import os,resource,sys;"
    "s,h=resource.getrlimit(resource.RLIMIT_NOFILE);"
    "resource.setrlimit(resource.RLIMIT_NOFILE,(min(max(s,2048),h),h));"
    "z=os.open(\"/dev/null\",os.O_RDWR);"
    "os.set_inheritable(z,True);"
    "[os.dup2(z,n) for n in range(3,1100)];"
    "os.close(z) if z>=1100 else None;"
    "os.execv(sys.argv[1],sys.argv[1:])"
)


def spawn(home, *args, background=False, high_fds=False):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    run = f'"{real_bin()}" setup {" ".join(args)}'
    if high_fds:
        run = f"'{sys.executable}' -c '{HIGH_DESCRIPTORS}' {run}"
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
        self.script_env = env

    def read_until(self, pattern, timeout=5.0):
        """Reads until `pattern` (bytes) is in the log; returns the time it was seen."""
        end = time.monotonic() + timeout
        while pattern not in self.log:
            left = end - time.monotonic()
            if left <= 0:
                self.kill()
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

    def read_any(self, patterns, timeout=3.0):
        """Reads until one of `patterns` is in the log; returns it, or `None` on timeout."""
        end = time.monotonic() + timeout
        while not any(p in self.log for p in patterns):
            left = end - time.monotonic()
            if left <= 0:
                return None
            if select.select([self.fd], [], [], left)[0]:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:
                    return None
                if not chunk:
                    return None
                self.log += chunk
        return next(p for p in patterns if p in self.log)

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        except OSError:
            pass

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


def raw_terminal(home, after=""):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    script = (f'echo BEFORE=$(stty -g); "{real_bin()}" setup --icons nerd; echo RC=$?; {after}'
              'echo AFTER=$(stty -g)')
    return RawTerminal(script, env)


# 이것을 실패시키는 것: 취소(Ctrl-C) 직후에는 버리기 없이 끝내는 것(질문 뒤 25 ms 안에 오는 늦은 응답이
# 셸 입력 줄에 남음: 뒤따른 `read`가 그 글자를 받음).
def test_a_late_answer_after_a_cancel_is_discarded_too(home):
    t = raw_terminal(home, after="read -r LEFT; echo LEFT=[$LEFT]; ")
    t.read_until(b"\x1b]11;?\x1b\\")
    os.write(t.fd, b"\x03")
    time.sleep(0.01)
    os.write(t.fd, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
    t.read_until(b"RC=")
    time.sleep(0.1)
    os.write(t.fd, b"\n")
    code, before, after, text = t.finish()
    assert code == 130, text
    assert "LEFT=[]" in text, text
    assert before == after
    assert config(home) is None


# 이것을 실패시키는 것: 터미널 설명자가 FD_SETSIZE(1024) 이상일 때 거르지 않는 것(`FD_SET`이 abort해 터미널이
# raw로 남음). 거르면 터미널이 없는 것으로 보아 인자를 요구하고, 터미널은 그대로다.
def test_a_terminal_on_a_high_descriptor_is_not_used(home):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard < 1200:
        pytest.skip("the hard descriptor limit is below 1200")
    child = spawn(home, "--icons", "nerd", high_fds=True)
    code, before, after, text = finish(child)
    assert code == 2, text
    assert "no terminal to ask" in text, text
    assert before == after
    assert config(home) is None


# The two tests below send a byte 225 ms after the query: past the 200 ms limit and inside the 50 ms read
# that follows. On a busy machine the test (or bingsu) can be a few tens of milliseconds late, and then the
# byte lands in the other window: the answer is taken as an answer, or arrives after the terminal is
# restored. Such a run proves nothing about the discarding, so it is tried again: the test passes when one
# run lands in the window and behaves, and fails when none of TRIES does (a bingsu that does not discard
# never has a run that behaves).
TRIES = 12


def attempt_home(home, n):
    sub = home / f"a{n}"
    sub.mkdir(mode=0o700)
    return sub


def wait_late(t):
    seen = t.read_until(b"\x1b]11;?\x1b\\")
    while time.perf_counter() < seen + LATE_WINDOW_MIDDLE:
        time.sleep(0.001)


def late_answer_is_discarded(home):
    """One run. `True`: the answer came in the window and did not reach the next question."""
    t = raw_terminal(home)
    wait_late(t)
    os.write(t.fd, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
    got = t.read_any([b"the terminal did not say", b"the terminal looks"])
    if got == b"the terminal looks":  # taken as an answer: no late answer in this run
        os.write(t.fd, b"\n")
        t.read_until(b"[Y/n] ")
        os.write(t.fd, b"n\n")
        t.finish()
        return False
    if got is None:
        t.kill()
        return False
    time.sleep(0.3)
    os.write(t.fd, b"l\n")
    t.read_until(b"[Y/n] ")
    os.write(t.fd, b"\n")
    code, before, after, text = t.finish()
    # A leaked answer makes "l" no choice and the default (auto) is used: that run came after the read.
    return code == 0 and before == after and 'mode = "light"' in (config(home) or "")


# 이것을 실패시키는 것: 시간 제한 뒤 짧게 더 읽어 버리는 것과 `tcsetattr`·`tcflush`를 뺀 것(늦은 응답이 입력 줄에
# 남아 다음 질문의 답을 오염시킴: 답 "l"이 "light"가 아니라 "auto"가 됨).
def test_a_late_answer_does_not_reach_the_next_question(home):
    assert any(late_answer_is_discarded(attempt_home(home, n)) for n in range(TRIES))


def ctrl_c_in_the_discard_cancels(home):
    """One run. `True`: the Ctrl-C came in the window and cancelled."""
    t = raw_terminal(home)
    wait_late(t)
    os.write(t.fd, b"\x03")
    got = t.read_any([b"cancelled", b"Color mode"])
    if got == b"cancelled":
        code, before, after, text = t.finish()
        return code == 130 and "Color mode" not in text and before == after and config(home) is None
    if got is None:
        t.kill()
        return False
    # The Ctrl-C was lost (it came after the read, or was ignored): answer and stop.
    os.write(t.fd, b"\n")
    t.read_until(b"[Y/n] ")
    os.write(t.fd, b"n\n")
    t.finish()
    return False


# 이것을 실패시키는 것: 시간 초과 뒤 버리기 읽기 중 온 Ctrl-C(0x03)를 무시하고 질문으로 넘어가는 것.
def test_ctrl_c_while_the_late_answer_is_being_discarded_cancels(home):
    assert any(ctrl_c_in_the_discard_cancels(attempt_home(home, n)) for n in range(TRIES))


# Becomes its own process group (so it is not the terminal's foreground job), ignores SIGTTOU (so a change of
# the terminal mode would not stop it) and becomes `bingsu`.
BACKGROUND_JOB = (
    "import os,signal,sys;"
    "signal.signal(signal.SIGTTOU,signal.SIG_IGN);"
    "os.setpgid(0,0);"
    "os.execv(sys.argv[1],sys.argv[1:])"
)


# 이것을 실패시키는 것: 전경 작업인지 확인하지 않는 것(SIGTTOU를 무시한 배경 작업이 전경 셸 밑에서 터미널 모드를
# 바꾸고, 복구의 `tcflush`가 사용자가 미리 친 글자를 버림). 확인하면 터미널이 없는 것으로 보아 질문 없이 인자를 요구한다.
def test_a_background_job_does_not_touch_the_terminal(home):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    script = (f"echo BEFORE=$(stty -g); '{sys.executable}' -c '{BACKGROUND_JOB}' \"{real_bin()}\" setup --icons nerd; "
              "echo RC=$?; read -r LEFT; echo LEFT=[$LEFT]; echo AFTER=$(stty -g)")
    t = RawTerminal(script, env)
    os.write(t.fd, b"typed\n")
    if t.read_any([b"RC="], timeout=3.0) is None:
        t.kill()
    code, before, after, text = t.finish()
    assert code == 2, text
    assert "no terminal to ask" in text, text
    assert b"\x1b]11;?" not in t.log
    assert "LEFT=[typed]" in text, text
    assert before == after


# 이것을 실패시키는 것: 터미널이 끊긴 뒤(복구 `tcsetattr`이 실패함) 복구 실패를 panic으로 다루는 것(종료 코드 101),
# 끊긴 터미널에서 끝나지 않고 기다리는 것. 끊기면 SIGHUP 처리기가 취소로 끝낸다. 0바이트 읽기 처리 자체는 단위
# 시험(`reading_a_reply_ends_on_hang_up…`)이 잡는다: 끊김에는 SIGHUP이 먼저 와서 이 시험으로는 가려지지 않는다.
def test_a_hung_up_terminal_ends_without_a_panic(home):
    err, rc = home / "stderr", home / "rc"
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    # The shell ignores SIGHUP so that it outlives the hang-up and records how bingsu ended.
    script = f'trap "" HUP; "{real_bin()}" setup --icons nerd 2>"{err}"; echo $? > "{rc}"'
    t = RawTerminal(script, env)
    t.read_until(b"\x1b]11;?\x1b\\")
    os.close(t.fd)
    end = time.monotonic() + 5
    while time.monotonic() < end:
        done, _ = os.waitpid(t.pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.01)
    else:
        os.kill(t.pid, signal.SIGKILL)
        os.waitpid(t.pid, 0)
        pytest.fail("bingsu did not end after the terminal hung up")
    text = err.read_text()
    assert "panicked" not in text, text
    assert int(rc.read_text()) != 101, text
    assert config(home) is None
