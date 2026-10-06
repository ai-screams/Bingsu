from fsbudget.formula import Coeffs, HelperAxes, ceil_div, front_expected, helper_expected


def test_ceil_rules():
    assert [ceil_div(n, 4096) for n in (0, 1, 4096, 4097)] == [0, 1, 1, 2]


# Values worked out by hand from the spec tables (section 8 helper axes,
# fixed terms, front axis C).
# 이것을 실패시키는 것: 끝 확인 읽기(+1)를 빼거나 고정 항을 잘못 더하는 것.
def test_helper_unchanged_and_changed():
    ax = HelperAxes(F=2, P=5, L=1, R=3, D=1, E_b=[100], M=1, B=[10, 5000], acl=False, lock_fd_inherited=False)
    co = Coeffs()
    u = helper_expected(ax, co, changed=False, buf=4096, snapshot_bytes=6000)
    assert u == {"openat": 5 + 3 + 1 + 4, "fstat": 5 + 3 + 2 + 3, "readlink": 1, "getdents": 2, "statfs": 1,
                 "acl": 0, "read": 2, "write": 1, "fsync": 0, "renameat": 1, "unlinkat": 0, "flock": 1}
    c = helper_expected(ax, co, changed=True, buf=4096, snapshot_bytes=6000)
    assert c["openat"] == u["openat"] + 2 + 1
    assert c["read"] == 2 + (1 + 1) + (2 + 1)
    assert c["write"] == 1 + 2
    assert c["renameat"] == 2


def test_front_normal():
    assert front_expected(C=4, section_bytes=5000, session_bytes=100, buf=4096) == {
        "openat": 7, "fstat": 7, "read": 2 + 1 + 1 + 1}
