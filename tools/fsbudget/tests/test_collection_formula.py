"""Publication-only fixture ledger; admission and sweep have separate phases."""
import pytest
from fsbudget.formula import collection_expected


# 이것을 실패시키는 것: helper의 네 chain/lock 검증이나 same-fd staging 검증을 예산에서 빼는 것.
def test_publication_phase_coefficients():
    assert collection_expected(3, 100, False, False) == {
        "openat": 5, "fstat": 86, "statfs": 32, "read": 2,
        "write": 1, "renameat": 1, "unlinkat": 0, "flock": 0, "fsync": 0,
    }
    base = collection_expected(2, 100, False, False)
    longer = collection_expected(3, 100, False, False)
    assert longer["fstat"] - base["fstat"] == 16
    assert longer["statfs"] - base["statfs"] == 8


# 이것을 실패시키는 것: current 회전의 read/rename 또는 잔여 stage의 unlink를 빼는 것.
def test_rotation_and_recovery_are_helper_work():
    assert collection_expected(3, 262_080, True, True) == {
        "openat": 5, "fstat": 103, "statfs": 36, "read": 19,
        "write": 1, "renameat": 2, "unlinkat": 1, "flock": 0, "fsync": 0,
    }


# 이것을 실패시키는 것: body 상한에 64-byte header를 합산하지 않는 것.
def test_publication_axes_are_bounded():
    for components, body in [(-1, 0), (3301, 0), (3, -1), (3, 262_081)]:
        with pytest.raises(ValueError):
            collection_expected(components, body, False, False)
    for body in [0, 1, 16_384, 16_385, 262_080]:
        assert collection_expected(3, body, False, False)["read"] == 2
