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
