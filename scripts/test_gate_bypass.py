#!/usr/bin/env python3
"""Verify bypass fixtures are rejected even after the TCB hash pins are updated."""
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import check_cli_prompt_forbid as gate

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tools/core-cfg-check/tests/fixtures/bypass"
CHECKER = ROOT / "target/debug/core-cfg-check"


class BypassGates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "target")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        for name in ["scripts/check_cli_prompt_forbid.py", "scripts/check_core_cfg.py",
                     "crates/bingsu/clippy.toml", *gate.TCB_SHA256]:
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        core = self.root / "crates/bingsu-core/src/f.rs"
        core.parent.mkdir(parents=True)
        core.write_text("pub fn f() {}\n")

    def replace_tcb(self, name, fixture):
        dest = self.root / name
        shutil.copyfile(FIXTURES / fixture, dest)
        script = self.root / "scripts/check_cli_prompt_forbid.py"
        shutil.copyfile(ROOT / "scripts/check_cli_prompt_forbid.py", script)
        script.write_text(script.read_text().replace(
            gate.TCB_SHA256[name], hashlib.sha256(dest.read_bytes()).hexdigest()))

    def run_gate(self, script, *extra):
        return subprocess.run(
            [sys.executable, str(self.root / "scripts" / script),
             "--checker", str(CHECKER), *extra],
            cwd=self.root, capture_output=True, text=True)

    def assert_rejected(self, output, reason):
        self.assertNotEqual(output.returncode, 0, output.stdout + output.stderr)
        self.assertIn(reason, output.stderr)
        self.assertNotIn("sha256", output.stderr)

    # 이것을 실패시키는 것: identity pin을 다시 써서 worker 모듈을 앞단으로 가져오는 것.
    def test_identity_worker_after_hash_renewal(self):
        self.replace_tcb("crates/bingsu-identity/src/lib.rs", "identity/worker.rs")
        self.assert_rejected(self.run_gate("check_cli_prompt_forbid.py"),
                             "identity must not declare modules or imports")

    # 이것을 실패시키는 것: 각 fixture의 금지 토큰 하나를 identity 검사에서 빼는 것.
    def test_identity_inputs_after_hash_renewal(self):
        for token in ["include", "include_str", "include_bytes", "env", "option_env",
                      "macro_rules"]:
            with self.subTest(token=token):
                self.replace_tcb("crates/bingsu-identity/src/lib.rs", f"identity/{token}.rs")
                self.assert_rejected(self.run_gate("check_cli_prompt_forbid.py"),
                                     f"identity forbidden token {token} outside build_id include")

    # 이것을 실패시키는 것: RULES 소비·영역 검사를 제거하여 미끼 표를 허용하는 것.
    def test_k24_decoy_after_hash_renewal(self):
        self.replace_tcb("crates/bingsu/src/sandbox.rs", "k24/decoy.rs")
        self.assert_rejected(self.run_gate("check_cli_prompt_forbid.py"), "RULES:")

    # 이것을 실패시키는 것: enter 본문 고정을 제거하여 추가 번호나 허용 기본 동작을 받는 것.
    def test_k24_entry_after_hash_renewal(self):
        for fixture in ["k24/literal.rs", "k24/alias.rs", "k24/miss_allow.rs"]:
            with self.subTest(fixture=fixture):
                self.replace_tcb("crates/bingsu/src/sandbox.rs", fixture)
                self.assert_rejected(self.run_gate("check_cli_prompt_forbid.py"),
                                     "enter() must")

    # 이것을 실패시키는 것: 튜플·구조체 필드에 클로저를 저장하도록 허용하는 것.
    def test_k03_closure_fields(self):
        shutil.copyfile(FIXTURES / "wt/crates/bingsu-core/src/zz2.rs",
                        self.root / "crates/bingsu-core/src/zz2.rs")
        self.assert_rejected(self.run_gate("check_core_cfg.py", "--phase", "tokens"),
                             "closure stored in a tuple or struct field")

    # 이것을 실패시키는 것: prompt_io 토큰 단계에서 외부 mod를 허용하는 것.
    def test_k68_cfg_module_after_hash_renewal(self):
        self.replace_tcb("crates/bingsu/src/prompt_io.rs", "k68/bin/src/prompt_io.rs")
        evil = self.root / "crates/bingsu/src/prompt_io/evil.rs"
        evil.parent.mkdir()
        shutil.copyfile(FIXTURES / "k68/bin/src/prompt_io/evil.rs", evil)
        self.assert_rejected(self.run_gate("check_core_cfg.py", "--phase", "tokens"),
                             "out-of-line")

    # 이것을 실패시키는 것: raw·deadline 바인딩 개수를 고정하지 않는 것.
    def test_k83_shadows_after_hash_renewal(self):
        for fixture in ["k83/shadow2.rs", "k83/shadow_dl.rs"]:
            with self.subTest(fixture=fixture):
                self.replace_tcb("crates/bingsu/src/prompt.rs", fixture)
                self.assert_rejected(self.run_gate("check_cli_prompt_forbid.py"),
                                     "core-cfg-check --adapter")

    # 이것을 실패시키는 것: raw 초기식 고정을 제거하여 잘린 인자를 받는 것.
    def test_k83_initializer_after_hash_renewal(self):
        self.replace_tcb("crates/bingsu/src/prompt.rs", "k83/init.rs")
        self.assert_rejected(self.run_gate("check_cli_prompt_forbid.py"),
                             "core-cfg-check --adapter")


if __name__ == "__main__":
    unittest.main()
