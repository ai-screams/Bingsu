"""K82: real pre-filter clock walk with a procfs/getpid namespace mismatch."""
import json
import os
import subprocess
import sys

import pytest

from conftest import ROOT, real_bin
from test_prompt_deadline import is_static


# 이것을 실패시키는 것: 앞단이 mounted procfs의 self 대신 libc getpid로 process 폴더를 여는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="native Linux procfs fixture")
def test_mounted_proc_self_survives_a_different_visible_pid(tmp_path):
    # Check the installed binary before asking Cargo: static-musl shell
    # containers have neither Cargo nor cc. The native GNU host runs this.
    if is_static(real_bin()):
        pytest.skip("static musl: interposition unavailable; numeric-link unit fixture still runs")
    build = subprocess.run([
        "cargo", "test", "-j", "2", "-p", "bingsu", "--bin", "bingsu",
        "--no-run", "--message-format=json",
    ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=120)
    binaries = [row["executable"] for line in build.stdout.splitlines()
                if (row := json.loads(line)).get("reason") == "compiler-artifact"
                and row.get("executable") and row.get("profile", {}).get("test")]
    (binary,) = binaries
    if is_static(binary):
        pytest.skip("static musl: interposition unavailable; numeric-link unit fixture still runs")
    lib = tmp_path / "proc-pid.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-Wall", "-Werror",
                    str(ROOT / "tests/shell/fixtures/proc_pid_interpose.c"), "-o", str(lib)], check=True)
    result = subprocess.run([
        binary, "--exact", "prompt_read::tests::mounted_proc_clock_matches_publisher",
        "--test-threads=1", "--nocapture",
    ], env={**os.environ, "LD_PRELOAD": str(lib)}, capture_output=True, timeout=10)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"1 passed" in result.stdout, result.stdout
