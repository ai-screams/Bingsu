#!/usr/bin/env python3
"""Exercise the append-only diagnostic code gate without changing git metadata.
Run: python3 -B scripts/test_check_diag_codes.py
"""
import contextlib
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_diag_codes as gate


class DiagnosticCodes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=gate.ROOT / "target")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.head = self.root / gate.REL
        self.head.parent.mkdir(parents=True)
        self.base = self.root / "base.txt"

    def check_files(self, base, head):
        self.base.write_text(base)
        self.head.write_text(head)
        with patch.object(gate, "ROOT", self.root):
            return self.run_gate(["--base-file", str(self.base)])

    def run_gate(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = gate.main(args)
        return result, out.getvalue(), err.getvalue()

    # 이것을 실패시키는 것: 같은 목록이나 새 코드 추가를 거부하는 것.
    def test_same_and_added_codes(self):
        for head in ["E101 stable\n", "E101 stable\nW407 stable\n"]:
            with self.subTest(head=head):
                result, out, err = self.check_files("# base\nE101 stable\n", head)
                self.assertEqual(result, 0, err)
                self.assertIn("1 base codes kept", out)

    # 이것을 실패시키는 것: 기준에 있던 코드의 삭제를 통과시키는 것.
    def test_removed_code_fails(self):
        result, _, err = self.check_files("E101 stable\nW407 stable\n", "E101 stable\n")
        self.assertEqual(result, 1)
        self.assertIn("W407 was removed", err)

    # 이것을 실패시키는 것: stable에서 deprecated로의 허용된 전이를 거부하는 것.
    def test_deprecation_passes(self):
        result, _, err = self.check_files("E101 stable\n", "E101 deprecated 0.4\n")
        self.assertEqual(result, 0, err)

    # 이것을 실패시키는 것: 폐기된 코드를 되살리거나 폐기 버전을 바꾸는 것.
    def test_deprecated_code_cannot_return_or_change_version(self):
        for status in ["stable", "deprecated 0.5"]:
            with self.subTest(status=status):
                result, _, err = self.check_files("E101 deprecated 0.4\n", f"E101 {status}\n")
                self.assertEqual(result, 1)
                self.assertIn("E101 changed", err)

    # 이것을 실패시키는 것: 없는 기준 ref를 조용히 통과시키는 것.
    def test_missing_ref_fails(self):
        with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            result, _, err = self.run_gate(["origin/missing"])
        self.assertEqual(result, 1)
        self.assertIn("is not a commit here", err)

    # 이것을 실패시키는 것: 레지스트리가 생기기 전의 기준을 오류로 취급하는 것.
    def test_base_without_list_passes(self):
        results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, stdout="")]
        with patch.object(gate.subprocess, "run", side_effect=results) as run:
            result, out, err = self.run_gate(["origin/main"])
        self.assertEqual(result, 0, err)
        self.assertIn("nothing to compare", out)
        self.assertEqual(run.call_args_list[1].args[0][1], "ls-tree")

    # 이것을 실패시키는 것: 기준 목록을 읽지 못했는데도 현재 목록만 검사하는 것.
    def test_git_show_failure_fails(self):
        results = [subprocess.CompletedProcess([], 0),
                   subprocess.CompletedProcess([], 0, stdout=gate.REL),
                   subprocess.CompletedProcess([], 1, stderr="cannot read object")]
        with patch.object(gate.subprocess, "run", side_effect=results):
            result, _, err = self.run_gate(["origin/main"])
        self.assertEqual(result, 1)
        self.assertIn("cannot read object", err)

    # 이것을 실패시키는 것: 유효한 기준 ref에서도 비교를 생략하는 것.
    def test_git_ref_compares_list(self):
        self.head.write_text("E101 stable\n")
        results = [subprocess.CompletedProcess([], 0),
                   subprocess.CompletedProcess([], 0, stdout=gate.REL),
                   subprocess.CompletedProcess([], 0, stdout="E101 stable\nW407 stable\n")]
        with patch.object(gate, "ROOT", self.root), patch.object(gate.subprocess, "run", side_effect=results):
            result, _, err = self.run_gate(["origin/main"])
        self.assertEqual(result, 1)
        self.assertIn("W407 was removed", err)


if __name__ == "__main__":
    unittest.main()
