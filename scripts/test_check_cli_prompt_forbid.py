#!/usr/bin/env python3
"""Collector fixture isolation gates, run on the host by check-core-purity.sh.

These tests need cargo and Python 3.11+; minimum-shell containers only check
that the installed product rejects the fixture argument.
Usage: python3 -B scripts/test_check_cli_prompt_forbid.py
"""
import copy
import json
import pathlib
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import check_cli_prompt_forbid as gate

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProductFixtureIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["cargo", "build", "--quiet", "-p", "bingsu", "--message-format=json"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        paths = [d["executable"] for d in map(json.loads, build.stdout.splitlines())
                 if d.get("reason") == "compiler-artifact" and d["target"]["name"] == "bingsu"
                 and d.get("executable")]
        if len(paths) != 1:
            raise AssertionError(f"expected one built bingsu executable, got {paths}")
        cls.binary = pathlib.Path(paths[0])

    # 이것을 실패시키는 것: 시험 target·의존 진입점 또는 fixture 문자열을 제품에 포함하는 것.
    def test_product_fixture_is_unreachable(self):
        self.assertEqual(gate.check_product_fixture_isolation(self.binary), [])
        with tempfile.TemporaryDirectory() as temp:
            altered = pathlib.Path(temp) / "product-with-fixture"
            for marker in (b"collector_builtin", b"collector_builtin_test_only_31"):
                with self.subTest(marker=marker):
                    altered.write_bytes(self.binary.read_bytes() + marker)
                    self.assertIn("product binary contains a collector fixture symbol or string",
                                  gate.check_product_fixture_isolation(altered))

    # 이것을 실패시키는 것: 시험 target의 수·소유 package·종류 또는 제품 의존 진입점 검사를 빼는 것.
    def test_fixture_build_gate_rejects_product_entry(self):
        clean = json.loads(subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version=1"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout)
        for entry in ("missing", "duplicate", "product", "binary", "dependency"):
            with self.subTest(entry=entry):
                metadata = copy.deepcopy(clean)
                owner = next(p for p in metadata["packages"] if p["name"] == "bingsu-core-tests")
                target = next(t for t in owner["targets"] if t["name"] == "collector_builtin")
                if entry == "missing":
                    owner["targets"].remove(target)
                elif entry == "duplicate":
                    owner["targets"].append(copy.deepcopy(target))
                elif entry == "product":
                    owner["name"] = "bingsu"
                elif entry == "binary":
                    target["kind"] = ["bin"]
                else:
                    product = next(p for p in metadata["packages"] if p["name"] == "bingsu")
                    product["dependencies"].append({"name": "bingsu-core-tests"})
                with patch.object(gate.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(metadata))):
                    self.assertTrue(gate.check_product_fixture_isolation())


if __name__ == "__main__":
    unittest.main()
