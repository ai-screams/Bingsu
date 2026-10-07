"""Real strace (Linux): a child killed while blocked in a syscall must leave
a trace the parser accounts for, using the same flags the scaffold uses."""
import shutil
import subprocess
import sys

import pytest

from conftest import REQUIRE_STRACE
from fsbudget.strace_parse import STRACE_FLAGS, parse

PROG = """
import os, signal, time
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.read(r, 1)  # blocks until killed
    os._exit(0)
time.sleep(0.3)
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)
"""


# 이것을 실패시키는 것: 종료 기록을 지우는 strace 옵션(-qq, 부모의 "+++ exited with 0 +++"가 사라짐)을 쓰거나,
# 죽은 자식의 끝나지 않은 호출이 남기는 실제 기록(결과 없는 resumed)을 구조 오류로 보는 것.
@pytest.mark.skipif(not REQUIRE_STRACE and (sys.platform != "linux" or shutil.which("strace") is None),
                    reason="needs Linux strace")
def test_child_killed_mid_syscall_parses_cleanly(tmp_path):
    trace = tmp_path / "trace"
    subprocess.run(["strace", *STRACE_FLAGS, "-o", str(trace), "--", sys.executable, "-c", PROG], check=True, timeout=30)
    text = trace.read_text(errors="replace")
    assert "+++ killed by SIGKILL +++" in text, text[-2000:]
    assert "+++ exited with 0 +++" in text, text[-2000:]
    calls = parse(text)
    assert calls.errors == [], calls.errors
