"""Tests for gen.py input validation. Run: python3 -B tools/gen-ucd-tables/test_gen.py"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gen  # noqa: E402


class Ranges(unittest.TestCase):
    def test_reads_single_and_range(self):
        got = gen.ranges("0041 ; A # x\n0042..0044 ; B # y\n", lambda v: 0)
        self.assertEqual(got, [(0x41, 0x41, "A"), (0x42, 0x44, "B")])

    def test_rejects_low_above_high(self):
        with self.assertRaisesRegex(SystemExit, "low above high"):
            gen.ranges("0050..0040 ; A\n")

    def test_rejects_above_max_code_point(self):
        with self.assertRaisesRegex(SystemExit, "above U\\+10FFFF"):
            gen.ranges("10FFFF..110000 ; A\n")

    def test_accepts_max_code_point(self):
        self.assertEqual(gen.ranges("10FFFF ; A\n"), [(0x10FFFF, 0x10FFFF, "A")])

    def test_rejects_overlap_with_same_key(self):
        with self.assertRaisesRegex(SystemExit, "overlapping"):
            gen.ranges("0040..0050 ; A\n0050..0060 ; B\n", lambda v: 0)

    def test_overlap_only_within_key(self):
        text = "0040..0050 ; P\n0050..0060 ; Q\n"
        self.assertEqual(len(gen.ranges(text, lambda v: v)), 2)

    def test_adjacent_is_not_overlap(self):
        self.assertEqual(len(gen.ranges("0040..0050 ; A\n0051 ; B\n", lambda v: 0)), 2)

    def test_no_key_allows_overlap(self):
        self.assertEqual(len(gen.ranges("0000..10FFFF ; N\n0040 ; W\n")), 2)


class Load(unittest.TestCase):
    def test_hash_mismatch_stops(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "emoji-data.txt").write_text("tampered")
            with self.assertRaisesRegex(SystemExit, "sha256"):
                gen.load(pathlib.Path(d), "emoji-data.txt")

    def test_committed_data_matches_hashes(self):
        for name in gen.SHA256:
            gen.load(gen.DATA, name)


if __name__ == "__main__":
    unittest.main()
