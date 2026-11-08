"""Exercise completion synchronization even where native boot IDs are denied."""
import subprocess
import sys

import pytest
import snapshot_support


# 이것을 실패시키는 것: 미실행·실행 중인 helper를 완료로 취급해 부재 검사를 통과시키는 것.
def test_wait_quiet_requires_helper_exit(tmp_path, monkeypatch):
    fake = tmp_path / "fake-bingsu"
    finished = tmp_path / "finished"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, time\n"
        "time.sleep(0.3)\n"
        f"pathlib.Path({str(finished)!r}).touch()\n"
    )
    fake.chmod(0o700)
    monkeypatch.setattr(snapshot_support, "real_bin", lambda: fake)
    session = snapshot_support.SnapshotSession(tmp_path)
    session._helper_count = 1
    # No wrapper has even started: absence of a PID/file must not mean done.
    with pytest.raises(AssertionError, match="helpers did not exit"):
        session.wait_quiet(timeout=0.02)
    with subprocess.Popen([str(session._launcher), "__refresh-v1"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            with pytest.raises(AssertionError, match="helpers did not exit"):
                session.wait_quiet(timeout=0.02)
            session.wait_quiet(timeout=3)
            assert finished.exists(), "completion preceded the helper's final effect"
        finally:
            out, err = child.communicate(timeout=3)
        assert child.returncode == 0, (out, err)


# 이것을 실패시키는 것: await_text가 마감 꼴(상태 0, 빈 stdout·stderr)을 재시도하지 않는 것,
# 상태가 0이 아니거나 stderr가 있는 빈 결과까지 재시도하는 것.
@pytest.mark.parametrize("bad", [(1, b"", b""), (0, b"", b"error\n")], ids=["status", "stderr"])
def test_await_text_retries_only_the_deadline_shape(tmp_path, bad):
    session = snapshot_support.SnapshotSession(tmp_path)
    good = subprocess.CompletedProcess([], 0, b"B1\x1fTEXT\x1e", b"")
    deadline = subprocess.CompletedProcess([], 0, b"", b"")
    results = iter([deadline, deadline, good])
    session.run = lambda *args, timeout=5: next(results)
    assert session.await_text("TEXT") == good.stdout
    results = iter([subprocess.CompletedProcess([], *bad), good])
    with pytest.raises(AssertionError):
        session.await_text("TEXT")
