#!/usr/bin/env python3
"""Exercise the Python file selection and the real prompt I/O token checker."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "target/debug/core-cfg-check"


class PromptIo(unittest.TestCase):
    # 이것을 실패시키는 것: prompt_io 호출 스캔 제거 또는 cfg 가지/별칭/매크로 인자 생략.
    def test_prompt_io_is_scanned_in_every_cfg_branch(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "target") as temp:
            root = pathlib.Path(temp)
            for rel in ["scripts/check_core_cfg.py", "crates/bingsu/clippy.toml"]:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / rel, path)
            core = root / "crates/bingsu-core/src/f.rs"
            core.parent.mkdir(parents=True)
            core.write_text("pub fn f() {}")
            adapter = root / "crates/bingsu/src/prompt.rs"
            adapter.parent.mkdir(parents=True)
            adapter.write_text("pub fn f() {}")
            io = adapter.with_name("prompt_io.rs")
            clean = '#[cfg(target_os = "linux")] fn f() {}\n'

            def run(source):
                io.write_text(source)
                return subprocess.run([sys.executable, str(root / "scripts/check_core_cfg.py"),
                                       "--phase", "tokens", "--checker", str(CHECKER)],
                                      cwd=root, capture_output=True, text=True)
            good = run(clean)
            self.assertEqual(good.returncode, 0, good.stderr)
            for token in ["var", "var_os", "vars", "vars_os", "home_dir", "exit", "write_all",
                          "include", "macro_rules", "cfg_attr"]:
                with self.subTest(token=token):
                    bad = run(clean + f'#[cfg(target_os = "other")] fn hidden() {{ m!(r#{token}); }}')
                    self.assertNotEqual(bad.returncode, 0, bad.stderr)
                    self.assertIn(f"prompt I/O forbidden token {token}", bad.stderr)
            bad = run(clean + 'use std::env::var as read_setting;')
            self.assertIn("prompt I/O forbidden token var", bad.stderr)
            self.assertEqual(run(clean + '// var exit write_all\nconst S: &str = "var";').returncode, 0)


if __name__ == "__main__":
    unittest.main()
