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


# 이것을 실패시키는 것: 앞단의 부재1/정상5와 O_PATH ACL·16KiB 청크 계수를 바꾸는 것.
def test_front_prefetch_and_read_coefficients():
    from fsbudget.formula import collection_front_expected as front
    assert front(0, (), (), absent=True) == {
        "openat": 1, "fstat": 0, "fstatfs": 0, "fgetxattr": 0, "getxattr": 0, "read": 0}
    assert front(3, (100, 262144), (36, 262080)) == {
        "openat": 5, "fstat": 5, "fstatfs": 5, "fgetxattr": 5, "getxattr": 3, "read": 19}
    for depth in range(3):
        assert front(depth, (), ())["openat"] == depth + 1
    assert front(3, (None, 100), (36,))["fstat"] == 4
    for body, reads in [(0, 1), (1, 2), (16384, 2), (16385, 3), (262080, 17)]:
        assert front(3, (body + 64, None), (body,))["read"] == reads


# 이것을 실패시키는 것: 잘못된 선취 축이나 총 파일 상한을 허용하는 것.
def test_front_axes_fail_closed():
    from fsbudget.formula import collection_front_expected as front
    for directories, sizes, bodies in [(-1, (), ()), (4, (), ()), (2, (1,), ()),
                                      (3, (1, 2, 3), ()), (3, (-1,), ()),
                                      (3, (1,), (-1,)), (3, (1,), (262081,))]:
        with pytest.raises(ValueError):
            front(directories, sizes, bodies)
    with pytest.raises(ValueError):
        front(1, (), (), absent=True)
