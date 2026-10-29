#!/usr/bin/env python3
"""Exercise the prompt clock site pin on copies of crates/bingsu/src.
Run: python3 -B scripts/test_check_prompt_clock_sites.py
"""
import pathlib
import shutil
import tempfile
import unittest

import check_prompt_clock_sites as gate

READ = "crates/bingsu/src/prompt_read.rs"
IO = "crates/bingsu/src/prompt_io.rs"
APPROVAL = "            crate::prompt_io::ClockUse::Approval,\n"


class PromptClockSites(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=gate.ROOT / "target")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        shutil.copytree(gate.ROOT / gate.SRC, self.root / gate.SRC)

    def edit(self, rel, old, new):
        path = self.root / rel
        text = path.read_text()
        self.assertEqual(text.count(old), 1, old)
        path.write_text(text.replace(old, new))

    # 이것을 실패시키는 것: 실제 트리의 자리가 SITES와 다른 것(제품 변경 뒤 표를 고치지 않음).
    def test_prompt_clock_call_sites_are_pinned(self):
        self.assertEqual(gate.check(), [])
        self.assertEqual(gate.check(self.root), [])

    # 이것을 실패시키는 것: 새 호출 자리를 SITES 비교에서 빼는 것.
    def test_new_site_fails(self):
        self.edit(IO, "pub fn observe_clock() -> Result<Clock, ClockError> {\n",
                  "pub fn observe_clock() -> Result<Clock, ClockError> {\n"
                  "    let _ = monotonic_ns(\n        #[cfg(test)]\n        ClockUse::Entry,\n    );\n")
        self.assertEqual(gate.check(self.root), ["unpinned clock read site: ('crates/bingsu/src/prompt_io.rs', 'observe_clock', 'Entry')"])

    # 이것을 실패시키는 것: 용도를 비교하지 않는 것.
    def test_changed_use_fails(self):
        self.edit(READ, APPROVAL, APPROVAL.replace("Approval", "Deadline"))
        self.assertEqual(gate.check(self.root), [
            "unpinned clock read site: ('crates/bingsu/src/prompt_read.rs', 'observe', 'Deadline')",
            "pinned clock read site missing: ('crates/bingsu/src/prompt_read.rs', 'observe', 'Approval')",
        ])

    # 이것을 실패시키는 것: 사라진 자리를 알리지 않는 것, 같은 함수의 두 번째 자리를 하나로 세는 것.
    def test_removed_and_duplicated_sites_fail(self):
        self.edit(READ, "        clock.now = crate::prompt_io::monotonic_ns(\n" + "            #[cfg(test)]\n" + APPROVAL + "        )?;\n",
                  "")
        self.assertEqual(gate.check(self.root), ["pinned clock read site missing: ('crates/bingsu/src/prompt_read.rs', 'observe', 'Approval')"])
        self.edit(IO, "    deadline.remaining(now)?;\n",
                  "    deadline.remaining(now)?;\n    let _ = monotonic_ns(\n        #[cfg(test)]\n        ClockUse::Deadline,\n    );\n")
        self.assertIn("clock read site appears 2 times: ('crates/bingsu/src/prompt_io.rs', 'deadline_now', 'Deadline')",
                      gate.check(self.root))

    # 이것을 실패시키는 것: ClockUse 인자 없는 호출(시험 빌드에서 세지 않는 시계 읽기)을 받아들이는 것.
    def test_call_without_use_fails(self):
        self.edit(IO, "pub fn observe_clock() -> Result<Clock, ClockError> {\n",
                  "pub fn observe_clock() -> Result<Clock, ClockError> {\n    let _ = monotonic_ns();\n")
        errors = gate.check(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("without an enclosing fn or a #[cfg(test)] ClockUse argument", errors[0])

    # 이것을 실패시키는 것: 시험 모듈·tests.rs의 호출을 제품 자리로 세는 것.
    def test_test_code_is_skipped(self):
        self.edit(IO, "#[cfg(test)]\nmod tests {\n",
                  "#[cfg(test)]\nmod tests {\n    fn extra() { let _ = super::monotonic_ns(super::ClockUse::Entry); }\n")
        (self.root / gate.SRC / "commands/tests.rs").write_text("fn f() { let _ = monotonic_ns(); }\n")
        self.assertEqual(gate.check(self.root), [])

    # 보조 증거의 한계: 기존 자리를 한 번 더 실행하는 변화(반복문에 check_deadline 추가)는 자리를 바꾸지 않는다.
    # 그 변이는 실행 횟수 계수기(prompt_read::tests::clock_reads)가 잡는다.
    def test_extra_check_of_an_existing_site_is_not_this_gate(self):
        self.edit(READ, "    fn respond(mut self) -> Vec<u8> {\n        loop {\n            check_deadline(self.deadline);\n",
                  "    fn respond(mut self) -> Vec<u8> {\n        loop {\n            check_deadline(self.deadline);\n"
                  "            check_deadline(self.deadline);\n")
        self.assertEqual(gate.check(self.root), [])


if __name__ == "__main__":
    unittest.main()
