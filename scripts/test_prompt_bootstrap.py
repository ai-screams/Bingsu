#!/usr/bin/env python3
"""The approved pre-filter file is part of the pinned, scanned TCB."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import check_cli_prompt_forbid as gate

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "target/debug/core-cfg-check"

class Bootstrap(unittest.TestCase):
    # 이것을 실패시키는 것: bootstrap 해시 또는 forbid 검사를 게이트에서 빼는 것.
    def test_bootstrap_bytes_and_forbid_are_pinned(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "target") as temp:
            root = pathlib.Path(temp)
            for name in ["scripts/check_cli_prompt_forbid.py", *gate.TCB_SHA256]:
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dest)
            def run():
                return subprocess.run([sys.executable, str(root / "scripts/check_cli_prompt_forbid.py"),
                                       "--checker", str(CHECKER)], capture_output=True, text=True)
            good = run()
            self.assertEqual(good.returncode, 0, good.stderr)
            path = root / "crates/bingsu/src/prompt_spawn.rs"
            original = path.read_bytes()
            path.write_bytes(original + b"\n// changed bootstrap\n")
            changed = run()
            self.assertNotEqual(changed.returncode, 0)
            self.assertIn("prompt_spawn.rs: sha256", changed.stderr)
            path.write_bytes(original.replace(b"#![forbid(", b"#![allow(", 1))
            changed = run()
            self.assertIn("prompt_spawn.rs: first inner attribute", changed.stderr)
            path.write_bytes(original)

if __name__ == "__main__":
    unittest.main()
