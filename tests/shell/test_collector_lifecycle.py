"""Product lifecycle evidence; builds belong to the native test jobs."""
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, real_bin
from snapshot_support import SnapshotSession

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import parse as parse_trace


# 이것을 실패시키는 것: 제거한 legacy collector 진입점을 다시 허용하는 것.
def test_legacy_collector_entry_is_removed():
    result = subprocess.run([str(real_bin()), "__collect-legacy-v1"],
                            capture_output=True, timeout=2)
    assert result.returncode == 2, result
    assert result.stdout == b""


# 이것을 실패시키는 것: 앞단의 collection 대기, 제품 worker 생성 또는 실제 trace 회차 생략.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace acceptance row")
def test_four_hundred_product_prompts_never_wait_for_collection(tmp_path):
    strace = shutil.which("strace")
    assert strace, "this Linux acceptance test must execute strace"
    session = SnapshotSession(tmp_path)
    session.put("icons = 'ascii'\n")
    session.init()
    assert session.run("reload").returncode == 0
    completed = 0
    for index in range(400):
        trace = tmp_path / f"lifecycle-{index}.trace"
        result = subprocess.run(
            [strace, "-f", "-q", "-y", "-s", "65536", "-e",
             "trace=process,signal,pidfd_open,pidfd_send_signal,waitid",
             "-o", str(trace), str(real_bin()), *session.prompt_args()],
            env=session.env, capture_output=True, timeout=4)
        assert result.returncode == 0 and result.stderr == b"", result
        assert result.stdout.startswith(b"B1\x1f") and result.stdout.endswith(b"\x1e")
        text = trace.read_text()
        calls = parse_trace(text)
        assert not calls.errors, calls.errors
        executions = [call for call in calls if call.name == "execve" and call.ret == "0"]
        assert len(executions) == 2, executions
        assert '"__refresh-v1"' in executions[1].args, executions
        assert "__collect" not in text, text
        assert executions[0].pid == calls.first_pid
        assert not any(call.name in ("wait4", "waitid", "waitpid")
                       for call in calls if call.pid == calls.first_pid)
        completed += 1
    assert completed == 400, "all prompt traces must actually execute"
    assert not list(session.store().rglob("collection.lock"))
