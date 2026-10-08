"""bench/hook_cost.py refuses a shell without the in-shell clock instead of
reporting 0 ns samples. `bash` on PATH is replaced by /bin/sh (bash 3.2 in
POSIX mode on macOS, dash on Debian and Ubuntu): neither has EPOCHREALTIME."""
import json
import os
import subprocess
import sys

from conftest import ROOT

SCRIPT = ROOT / "bench/hook_cost.py"


# 이것을 실패시키는 것: 시계가 없는 셸에서 0ns 표본 200개를 잰 값으로 내는 것(na가 아님), 시계 검사를 하지 않는 것.
def test_shell_without_clock_is_na(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "bash").symlink_to("/bin/sh")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(PATH=f"{fake}:{os.environ['PATH']}", HOME=str(tmp_path))
    r = subprocess.run([sys.executable, "-B", str(SCRIPT), "bash"], env=env, cwd=tmp_path,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    [row] = [json.loads(l) for l in r.stdout.splitlines()]
    assert row["row"] == "bash" and row["na"].startswith("bash has no EPOCHREALTIME clock"), row
    assert "median_ns" not in row
