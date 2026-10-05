"""Shell-screen layer of the hostile-value matrix: every class through every
shell under test. M1 proves "not executed, structure not reinterpreted";
sanitization (M2) is not expected here."""
import os
import pathlib
import sys

import pytest

from conftest import Install, short_dir, trusted_env
from pty_session import Session, visible

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "hostile"))  # tests/hostile/
import matrix  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()


def rows():
    for c in matrix.rows():
        yield c[0], c[1], c[2] == "yes", c[5]


def payload(spec, canary):
    if spec.startswith("repeat:"):
        _, byte, n = spec.split(":")
        return bytes([int(byte, 16)]) * int(n)
    return bytes.fromhex(spec).replace(b"CANARY", str(canary).encode())


def record(shell, data):
    left = b"L<" + data + b">L "
    if shell == "zsh":
        left = left.replace(b"%", b"%%")  # what a correct core emits for zsh data
    return b"B1\x1f7\x1f" + left + b"\x1fRMARK\x1f\x1f\x1f\x1f\x1fok:none\x1e"


# 이것을 실패시키는 것: 어느 셸이든 값의 일부를 명령으로 실행하거나 필드 경계를 바꾸는 것.
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("cls,spec,uses_canary,pty", list(rows()))
def test_hostile_class(tmp_path, shell, cls, spec, uses_canary, pty):
    canary = short_dir() / "c"
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(record(shell, payload(spec, canary)))
    s = Session(shell, env, cols=200)
    s.run(f"source {init}")
    s.run("true")
    out = visible(s.close())
    assert not canary.exists(), f"{cls} executed in {shell}"
    if pty == "observe":
        print(f"OBSERVE {shell} {cls}: left={b'L<' in out} right={b'RMARK' in out}")
    elif pty == "noexec":
        assert b"L<" in out and b">L" in out, f"{cls}: left field lost in {shell}"
        if shell in ("zsh", "fish"):
            assert b"RMARK" in out, f"{cls}: right field lost in {shell}"
    else:
        assert b"L<" not in out, f"{cls}: rejected record was drawn in {shell}"
