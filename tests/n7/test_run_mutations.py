"""Self-tests for the mutation harness; no cargo or source mutations needed."""
import os
import signal
import sys

import run_mutations as harness


# 이것을 실패시키는 것: timeout이 직접 자식만 죽이거나 SIGTERM을 무시한 손자를 남기는 것.
def test_timeout_reaps_grandchild_before_returning(tmp_path):
    ready = tmp_path / "ready"
    late = tmp_path / "late"
    grandchild = (
        "import os, pathlib, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid())); "
        "time.sleep(3); "
        f"pathlib.Path({str(late)!r}).touch()"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "time.sleep(30)"
    )
    try:
        code, output = harness.execute([sys.executable, "-c", parent], tmp_path / "log", 1)
        assert ready.exists(), "grandchild was never scheduled; test did not exercise cleanup"
        assert code == harness.TIMEOUT and "N7 HARNESS TIMEOUT" in output
        pid = int(ready.read_text())
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("grandchild survived timeout")
        assert not late.exists()
    finally:
        if ready.exists():
            try:
                os.kill(int(ready.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


# 이것을 실패시키는 것: timeout 전에 출력된 FAILED를 변이 검출로 세는 것.
def test_timeout_after_named_failure_is_error_and_restores(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"original")
    calls = iter([(0, "anchor PASSED"), (harness.TIMEOUT, "anchor FAILED")])
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "execute", lambda *args: next(calls))
    case = {"id": "timeout", "kind": "python", "anchor": "anchor", "command": [],
            "patches": [{"file": "source", "before": "original", "after": "mutant"}]}
    result = harness.run(case, tmp_path)
    assert result["status"] == "ERROR"
    assert source.read_bytes() == b"original"
    assert (tmp_path / "timeout-restored.json").exists()
