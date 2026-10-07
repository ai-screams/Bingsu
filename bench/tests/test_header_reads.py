"""The size sweep's read count follows ceil(size / BUF) with no end-check
read (spec section 8 read-count rule; spec section 9 M1 row (7)). Linux only
(strace); FSB_REQUIRE_STRACE=1 turns the skip into a failure."""
import json
import shutil
import subprocess
import sys

import pytest

from conftest import REQUIRE_STRACE, ROOT

BIN = ROOT / "target/release/m1-file-costs"
pytestmark = pytest.mark.skipif(not REQUIRE_STRACE and (shutil.which("strace") is None or not BIN.exists()),
                                reason="needs Linux strace and target/release/m1-file-costs")


# 이것을 실패시키는 것: 끝 확인 읽기를 하나 더 하거나 BUF가 아닌 크기로 읽는 것, 창 밖에서 파일 시스템을 건드리는 것,
# fsb:end를 빼는 것(창이 열린 채 끝남), 실행 파일이 실패로 끝나는 것.
def test_sweep_read_counts(tmp_path):
    (tmp_path / "header").write_bytes(b"\0" * 64)
    (tmp_path / "marker").write_bytes(b"\0" * 128)
    for n in (64, 256, 1024, 4096):
        (tmp_path / f"sweep-{n}").write_bytes(b"\0" * n)
    rules = tmp_path / "rules.json"
    rules.write_text("[]")
    out = tmp_path / "r.json"
    run = subprocess.run([sys.executable, "-m", "fsbudget", "run", "--rules", str(rules), "--markers", "-o", str(out),
                          "--", str(BIN), "--dir", str(tmp_path), "--once"],
                         cwd=ROOT / "tools/fsbudget", capture_output=True, text=True)
    rep = json.loads(out.read_text())
    assert run.returncode == 0 and rep["exit"] == 0, run.stderr
    assert rep["errors"] == [], rep["errors"]
    # header 64 + marker 128 + sweep 64, 256, 1024, 4096: one read each with BUF = 4096.
    assert rep["counts"]["front"] == {"openat": 6, "fstat": 6, "read": 6}, rep["counts"]
