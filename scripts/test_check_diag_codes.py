#!/usr/bin/env python3
"""Exercise the append-only diagnostic code gate without changing git metadata.
Run: python3 -B scripts/test_check_diag_codes.py
"""
import contextlib
import io
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_diag_codes as gate

REGISTRY = "crates/bingsu-core/src/diag_codes.rs"
REVIEWS = "crates/bingsu-core/diag-code-reviews.json"

class DiagnosticCodes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=gate.ROOT / "target")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.head = self.root / gate.REL
        self.head.parent.mkdir(parents=True)
        self.base = self.root / "base.txt"
        self.registry = self.root / REGISTRY
        self.registry.parent.mkdir(parents=True)
        self.registry.write_text('const MEANING: &str = "invalid TOML";\n')
        self.base_registry = self.root / "base.rs"
        self.base_registry.write_text(self.registry.read_text())

    def check_files(self, base, head):
        self.base.write_text(base)
        self.head.write_text(head)
        with patch.object(gate, "ROOT", self.root):
            return self.run_gate(["--base-file", str(self.base), "--base-registry", str(self.base_registry)])

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
                   subprocess.CompletedProcess([], 0, stdout="E101 stable\nW407 stable\n"),
                   subprocess.CompletedProcess([], 0, stdout=self.base_registry.read_text())]
        with patch.object(gate, "ROOT", self.root), patch.object(gate.subprocess, "run", side_effect=results):
            result, _, err = self.run_gate(["origin/main"])
        self.assertEqual(result, 1)
        self.assertIn("W407 was removed", err)

    def review(self, kind="wording", reason="Same invalid TOML condition; clearer wording"):
        entry = {"before": hashlib.sha256(self.base_registry.read_bytes()).hexdigest(),
                 "after": hashlib.sha256(self.registry.read_bytes()).hexdigest(),
                 "kind": kind, "reason": reason}
        (self.root / REVIEWS).write_text(json.dumps([entry]))

    # 이것을 실패시키는 것: 번호·상태만 비교하고 같은 번호의 진단 레지스트리 변경을 놓치는 것.
    def test_same_code_and_status_cannot_silently_change_meaning(self):
        self.registry.write_text('const MEANING: &str = "permission denied";\n')
        result, _, err = self.check_files("E101 stable\n", "E101 stable\n")
        self.assertEqual(result, 1)
        self.assertIn("explicit wording/meaning review", err)

    # 이것을 실패시키는 것: 의미 검토를 이유로 모든 문구 수정을 금지하는 것.
    def test_reviewed_wording_and_meaning_changes_have_an_explicit_path(self):
        self.registry.write_text('const MEANING: &str = "TOML syntax is invalid";\n')
        for kind in ("wording", "meaning"):
            with self.subTest(kind=kind):
                self.review(kind, "Reviewed E101: still TOML syntax; no number reused")
                result, _, err = self.check_files("E101 stable\n", "E101 stable\n")
                self.assertEqual(result, 0, err)

    # 이것을 실패시키는 것: 예전 해시·빈 근거·잘못된 분류·중복 검토를 수용하는 것.
    def test_review_is_bound_to_the_exact_diff_and_explained(self):
        self.registry.write_text("changed\n")
        for kind, reason in [("skip", "because"), ("wording", " ")]:
            self.review(kind, reason)
            self.assertEqual(self.check_files("E101 stable\n", "E101 stable\n")[0], 1)
        self.review()
        self.registry.write_text("changed again\n")
        self.assertEqual(self.check_files("E101 stable\n", "E101 stable\n")[0], 1)
        self.review()
        review = self.root / REVIEWS
        review.write_text(json.dumps(json.loads(review.read_text()) * 2))
        self.assertEqual(self.check_files("E101 stable\n", "E101 stable\n")[0], 1)

    # 이것을 실패시키는 것: 검토 기록으로 삭제·상태 역행까지 우회하는 것.
    def test_review_does_not_override_append_only_rules(self):
        self.registry.write_text("changed\n")
        self.review("meaning", "New code for a new condition")
        result, _, err = self.check_files("E101 stable\nW407 stable\n", "E101 stable\n")
        self.assertEqual(result, 1)
        self.assertIn("W407 was removed", err)

    # 이것을 실패시키는 것: --base-file만 주거나 기준 레지스트리를 읽지 못해도 통과시키는 것.
    def test_missing_base_registry_fails_closed(self):
        self.base.write_text("E101 stable\n")
        self.assertEqual(self.run_gate(["--base-file", str(self.base)])[0], 1)
        results = [subprocess.CompletedProcess([], 0),
                   subprocess.CompletedProcess([], 0, stdout=gate.REL),
                   subprocess.CompletedProcess([], 0, stdout="E101 stable\n"),
                   subprocess.CompletedProcess([], 1, stderr="missing source")]
        with patch.object(gate.subprocess, "run", side_effect=results):
            result, _, err = self.run_gate(["origin/main"])
        self.assertEqual(result, 1)
        self.assertIn("cannot read base registry", err)


if __name__ == "__main__":
    unittest.main()
