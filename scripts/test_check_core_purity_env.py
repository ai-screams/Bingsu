#!/usr/bin/env python3
"""Run the shell gate with command stand-ins, but a real cargo doc/rustdoc.

The rustdoc child records its environment and argv; a generated HTML page
proves it really ran. No source-text assertion can stand in for this probe.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RustdocEnvironment(unittest.TestCase):
    # 이것을 실패시키는 것: rustdoc 호출 삭제 또는 세 RUSTDOCFLAGS/target flags의 unset 제거.
    def test_rustdoc_child_receives_no_injected_flags(self):
        cargo, rustdoc, rustc = (shutil.which(name) for name in ("cargo", "rustdoc", "rustc"))
        self.assertTrue(cargo and rustdoc and rustc, "Rust tools are required")
        with tempfile.TemporaryDirectory(dir=ROOT / "target") as temp:
            root = pathlib.Path(temp)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copyfile(ROOT / "scripts/check-core-purity.sh", scripts / "check-core-purity.sh")
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="bingsu-core"\nversion="0.0.0"\nedition="2024"\n[workspace]\n')
            (root / "src/lib.rs").write_text('#![no_std]\n/// Documented probe.\npub fn probe() {}\n')
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log = root / "rustdoc.jsonl"
            probe = bin_dir / "rustdoc-probe"
            flags = ["RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_BUILD_RUSTDOCFLAGS",
                     "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTDOCFLAGS",
                     "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTDOCFLAGS",
                     "CARGO_TARGET_M3A_PROBE_RUSTDOCFLAGS", "CARGO_TARGET_M3A_PROBE_RUSTFLAGS"]

            def executable(path, body):
                path.write_text(f"#!{sys.executable}\n" + body)
                path.chmod(0o755)

            executable(probe, "import os, sys, json\n"
                       f"with open({str(log)!r}, 'a') as f: f.write(json.dumps({{'env': {{n: os.environ[n] for n in {flags!r} if n in os.environ}}, 'args': sys.argv[1:]}}) + '\\n')\n"
                       f"os.execv({rustdoc!r}, [{rustdoc!r}, *sys.argv[1:]])\n")
            # Only doc is real. Remaining phases need no synthetic workspace,
            # clippy config or cargo-deny, and cannot recursively run this test.
            executable(bin_dir / "cargo", "import os, sys\n"
                       f"if sys.argv[1] == 'doc': os.execv({cargo!r}, [{cargo!r}, *sys.argv[1:]])\n")
            executable(bin_dir / "python3", "import sys\n"
                       f"if '-c' in sys.argv: print({str(bin_dir / 'checker')!r})\n")
            executable(bin_dir / "checker", "")
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       RUSTDOC=str(probe))
            for name in flags:
                env[name] = "--cfg=m3a_poison"
            result = subprocess.run(["bash", str(scripts / "check-core-purity.sh")],
                                    cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(log.exists(), "the gate never invoked rustdoc")
            observations = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue(any("src/lib.rs" in r["args"] for r in observations), observations)
            for row in observations:
                self.assertEqual(row["env"], {}, row)
                self.assertFalse(any("m3a_poison" in arg for arg in row["args"]), row)
            self.assertTrue((root / "target/doc/bingsu_core/index.html").exists())


if __name__ == "__main__":
    unittest.main()
