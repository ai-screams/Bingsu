"""Effect of the fd cleanup order on a shell's $(...): the front must
release fds 1 and 2 before spawning a child that outlives it (spec section 4
side-effect rules; earlier experiment: about 1 s delay in all three shells).
Subprocesses only: no terminal, no GUI."""
import subprocess
import time

import pytest

from conftest import ROOT, SHELLS

BIN = ROOT / "target/release/m1-writer-child"
SCRIPT = {"bash": 'x=$("{bin}" --demo {order}); printf %s "$x"', "zsh": 'x=$("{bin}" --demo {order}); printf %s "$x"',
          "fish": 'set x ("{bin}" --demo {order}); printf %s $x'}
FLAGS = {"bash": ["--norc", "--noprofile"], "zsh": ["-f"], "fish": ["--no-config"]}


def elapsed(shell, order):
    t = time.monotonic()
    out = subprocess.run([shell, *FLAGS[shell], "-c", SCRIPT[shell].format(bin=BIN, order=order)],
                         capture_output=True, timeout=10)
    return time.monotonic() - t, out


# 이것을 실패시키는 것: fd 1·2를 놓기 전에 자식을 만드는 것, 레코드를 잃는 것(flush 없이 fd 1을 바꿈),
# 실행 파일이 실패로 끝나는 것. 목록의 셸이 없으면 subprocess가 FileNotFoundError로 실패한다.
@pytest.mark.parametrize("shell", SHELLS)
def test_release_first_does_not_hold_the_shell(shell):
    fast, out = elapsed(shell, "release-first")
    slow, slow_out = elapsed(shell, "spawn-first")
    assert out.returncode == 0 and slow_out.returncode == 0, (out.stderr, slow_out.stderr)
    assert out.stdout == b"record" and slow_out.stdout == b"record", (out.stdout, slow_out.stdout)
    assert fast < 0.5, fast
    assert slow > 0.8, slow
