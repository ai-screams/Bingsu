"""The size sweep's read count follows ceil(size / BUF) with no end-check
read (spec section 8 read-count rule; spec section 9 M1 row (7)). Linux only
(strace); FSB_REQUIRE_STRACE=1 turns the skip into a failure."""
import json
import re
import shutil
import subprocess
import sys

import pytest

from conftest import REQUIRE_STRACE, ROOT

BIN = ROOT / "target/release/m1-file-costs"
pytestmark = pytest.mark.skipif(not REQUIRE_STRACE and (shutil.which("strace") is None or not BIN.exists()),
                                reason="needs Linux strace and target/release/m1-file-costs")


NAMES = ["header", "marker", "sweep-64", "sweep-256", "sweep-1024", "sweep-4096"]


def fixture(d):
    d.mkdir()
    (d / "header").write_bytes(b"\0" * 64)
    (d / "marker").write_bytes(b"\0" * 128)
    for n in (64, 256, 1024, 4096):
        (d / f"sweep-{n}").write_bytes(b"\0" * n)
    return d


# 이것을 실패시키는 것: 끝 확인 읽기를 하나 더 하거나 BUF가 아닌 크기로 읽는 것, 창 밖에서 파일 시스템을 건드리는 것,
# fsb:end를 빼는 것(창이 열린 채 끝남), 실행 파일이 실패로 끝나는 것.
def test_sweep_read_counts(tmp_path):
    d = fixture(tmp_path / "run")
    rules = tmp_path / "rules.json"
    rules.write_text("[]")
    out = tmp_path / "r.json"
    run = subprocess.run([sys.executable, "-m", "fsbudget", "run", "--rules", str(rules), "--markers", "-o", str(out),
                          "--", str(BIN), "--dir", str(d), "--once"],
                         cwd=ROOT / "tools/fsbudget", capture_output=True, text=True)
    rep = json.loads(out.read_text())
    assert run.returncode == 0 and rep["exit"] == 0, run.stderr
    assert rep["errors"] == [], rep["errors"]
    # The runtime folder open, then header 64 + marker 128 + sweep 64, 256,
    # 1024, 4096: one openat, fstat and read each with BUF = 4096.
    assert rep["counts"]["front"] == {"openat": 7, "fstat": 6, "read": 6}, rep["counts"]


# 이것을 실패시키는 것: 파일을 폴더 fd가 아니라 절대 경로나 AT_FDCWD 기준으로 여는 것(open·openat(AT_FDCWD, …)),
# 폴더 fd를 파일마다 다시 여는 것.
def test_files_open_relative_to_the_folder_fd(tmp_path):
    d = fixture(tmp_path / "run")
    trace = tmp_path / "trace"
    run = subprocess.run(["strace", "-qq", "-e", "trace=open,openat", "-o", str(trace), "--",
                          str(BIN), "--dir", str(d), "--once"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    lines = trace.read_text().splitlines()
    dirs = [m for l in lines if (m := re.match(rf'openat\(AT_FDCWD, "{re.escape(str(d))}", [^)]*O_DIRECTORY[^)]*\) = (\d+)$', l))]
    assert len(dirs) == 1, lines
    fd = dirs[0].group(1)
    for name in NAMES:
        hits = [l for l in lines if f'"{name}"' in l or f"/{name}\"" in l]
        assert len(hits) == 1 and hits[0].startswith(f'openat({fd}, "{name}", '), (name, hits)
