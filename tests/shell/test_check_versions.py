"""Boundary tests for check_versions.rule_matches and the --record mode
(run: python3 -m pytest tests/shell)."""
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

from check_versions import rule_matches


@pytest.mark.parametrize(
    "rule,v,want",
    [
        ("*", (0, 0), True),
        (">=5.1", (5, 0), False),
        (">=5.1", (5, 1), True),
        (">=5.1", (5, 9), True),
        (">=5.1", (4, 9), False),
        ("<4.0", (3, 6), True),
        ("<4.0", (4, 0), False),
        ("<4.0", (4, 9), False),
    ],
)
def test_rule_matches(rule, v, want):
    assert rule_matches(rule, v) is want


def test_unknown_rule_raises():
    with pytest.raises(ValueError):
        rule_matches("==5.1", (5, 1))


# 이것을 실패시키는 것: --record 갈래의 `return`을 지우는 것(인자 "--record"가 split("=")에서 터짐),
# 있는 셸을 JSON에서 빠뜨리는 것.
def test_record_prints_one_json_line_of_present_shells():
    script = pathlib.Path(__file__).resolve().parent / "check_versions.py"
    r = subprocess.run([sys.executable, str(script), "--record"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r.stdout
    got = json.loads(lines[0])
    assert set(got) == {s for s in ("bash", "zsh", "fish") if shutil.which(s)}, got
    assert all(v for v in got.values()), got
