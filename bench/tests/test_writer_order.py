"""Effect of the fd cleanup order on a shell's $(...): the front must
release fds 1 and 2 before spawning a child that outlives it (spec section 4
side-effect rules; earlier experiment: about 1 s delay in all three shells).
Subprocesses only: no terminal, no GUI."""
import os
import re
import subprocess
import time

import pytest

from conftest import ROOT, SHELLS

BIN = ROOT / "target/release/m1-writer-child"
# The front's exit status is passed on: a printf after the substitution
# would otherwise report its own status (0) for a front that failed.
SCRIPT = {"bash": 'x=$("{bin}" --demo {order}) || exit $?; printf %s "$x"',
          "zsh": 'x=$("{bin}" --demo {order}) || exit $?; printf %s "$x"',
          "fish": 'set x ("{bin}" --demo {order}); or exit $status; printf %s $x'}
FLAGS = {"bash": ["--norc", "--noprofile"], "zsh": ["-f"], "fish": ["--no-config"]}


def run(shell, order):
    t = time.monotonic()
    out = subprocess.run([shell, *FLAGS[shell], "-c", SCRIPT[shell].format(bin=BIN, order=order)],
                         capture_output=True, timeout=10)
    return time.monotonic() - t, out


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def child_pid(out):
    m = re.search(rb"^CHILD_PID (\d+)$", out.stderr, re.M)
    assert m, out.stderr
    pid = int(m.group(1))
    assert pid > 1, pid  # kill(0 or 1, 0) would ask about a group or init
    return pid


# 이것을 실패시키는 것: fd 1·2를 놓기 전에 자식을 만드는 것(빠르지 않음), 자식을 만들지 않거나 곧 끝나는 자식을 만드는 것
# (돌아온 뒤 살아 있는 자식이 없음), 레코드를 잃는 것(flush 없이 fd 1을 바꿈), 앞단이 0이 아닌 상태로 끝나는 것(셸이 그 상태로 끝남).
# 목록의 셸이 없으면 subprocess가 FileNotFoundError로 실패한다.
@pytest.mark.parametrize("shell", SHELLS)
def test_release_first_does_not_hold_the_shell(shell):
    fast, out = run(shell, "release-first")
    # The shell is back while the 1 s child still runs: it did not wait for
    # it. Looked at 0.3 s later, so a child that exits at once (and lingers
    # briefly as a zombie) does not pass for the sleeping one.
    pid = child_pid(out)
    time.sleep(0.3)
    assert alive(pid), f"no writer child running after the shell returned: {pid}"
    slow, slow_out = run(shell, "spawn-first")
    assert out.returncode == 0 and slow_out.returncode == 0, (out, slow_out)
    assert out.stdout == b"record" and slow_out.stdout == b"record", (out.stdout, slow_out.stdout)
    child_pid(slow_out)
    assert fast < 0.5, fast
    assert slow > 0.8, slow
