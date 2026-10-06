"""Boundary tests for check_versions.rule_matches (run: python3 -m pytest tests/shell)."""
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
