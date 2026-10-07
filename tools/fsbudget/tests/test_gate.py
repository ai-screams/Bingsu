import pytest

from fsbudget.gate import check

WANT = {"helper": {"openat": 2, "fstat": 2}}


# 이것을 실패시키는 것: exact·le 밖의 모드를 비교 없이 통과시키는 것.
def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        check({"helper": {"openat": 9}}, WANT, "exactly", ["helper"])


# 이것을 실패시키는 것: 측정이 통째로 없는 예산 역할을 통과시키는 것(le 모드에서 0 <= 기대값이라 빈 통과).
@pytest.mark.parametrize("mode", ["exact", "le"])
def test_missing_role_is_a_violation(mode):
    assert check({"command": {"openat": 5}}, WANT, mode, ["helper"]) == ["helper: no calls measured"]


# 이것을 실패시키는 것: le 모드가 넘침을 놓치거나 모자람을 위반으로 보는 것.
def test_le_mode():
    assert check({"helper": {"openat": 1, "fstat": 2}}, WANT, "le", ["helper"]) == []
    assert check({"helper": {"openat": 3, "fstat": 2}}, WANT, "le", ["helper"]) == ["helper.openat: measured 3, formula 2 (le)"]
    assert check({"helper": {"openat": 1, "fstat": 2}}, WANT, "exact", ["helper"]) == ["helper.openat: measured 1, formula 2 (exact)"]


# 이것을 실패시키는 것: 역할을 정하지 못한 task의 호출(unresolved)을 gated_roles에 없다는 이유로 통과시키는 것.
@pytest.mark.parametrize("mode", ["exact", "le"])
def test_unresolved_calls_are_a_violation(mode):
    got = {"helper": {"openat": 2, "fstat": 2}, "unresolved": {"openat": 1}}
    assert check(got, WANT, mode, ["helper"]) == ["unresolved: {'openat': 1} (calls of a task with no known role)"]
