import pytest

from fsbudget.formula import primitives


# 이것을 실패시키는 것: 표를 고르지 않는 것(musl 항이 안 먹음), 나갈 때 이전 표 대신 기본 표로 되돌리는 것(중첩 호출),
# 본문이 예외를 던져도 표를 되돌리지 않는 것.
def test_primitives_for_selects_the_libc_table_and_restores_the_previous_one():
    base = primitives._primitives
    with primitives._primitives_for("musl", "x86_64"):
        inner = primitives._primitives
        assert inner is not base
        assert inner["passwd"] == primitives.MUSL_PRIMITIVES["passwd"] != base["passwd"]
        with primitives._primitives_for("gnu", "x86_64"):
            assert primitives._primitives is not inner
        assert primitives._primitives is inner
    assert primitives._primitives is base


def test_primitives_for_restores_after_an_error():
    base = primitives._primitives
    with pytest.raises(RuntimeError):
        with primitives._primitives_for("gnu", "x86_64"):
            raise RuntimeError
    assert primitives._primitives is base
    with pytest.raises(KeyError):
        with primitives._primitives_for("gnu", "no-such-arch"):
            pass
    assert primitives._primitives is base
