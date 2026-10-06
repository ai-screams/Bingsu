"""Shell-screen layer of the hostile-value matrix: every class through every
shell under test. M1 proves "not executed, structure not reinterpreted";
sanitization (M2) is not expected here."""
import os
import pathlib
import sys

import pexpect
import pytest

from conftest import Install, short_dir, trusted_env
from pty_session import Session, visible

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "hostile"))  # tests/hostile/
import matrix  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
ROWS = matrix.rows()
# Every fallback prompt (all three hooks) ends with this mark.
MINIMAL = "❯ ".encode()


def record(shell, data):
    left = b"L<" + data + b">L "
    if shell == "zsh":
        left = left.replace(b"%", b"%%")  # what a correct core emits for zsh data
    return b"B1\x1f7\x1f" + left + b"\x1fRMARK\x1f\x1f\x1f\x1f\x1fok:none\x1e"


def drawn(shell, out, data):
    """True if one screen line holds the left field in order and, in zsh and
    fish, the right field after it."""
    want = b"L<" + visible(data) + b">L"
    for line in out.split(b"\n"):
        i = line.find(want)
        if i < 0:
            continue
        if shell == "bash" or line.find(b"RMARK", i + len(want)) >= 0:
            return True
    return False


# 이것을 실패시키는 것: 어느 셸이든 값의 일부를 명령으로 실행하거나 필드 경계를 바꾸는 것
# (왼쪽 필드가 한 줄에 순서대로 그려지지 않음, 오른쪽 필드가 그 뒤에 없음),
# 거부해야 할 레코드를 그리는 것, NUL을 지울 때 bash 경고를 화면에 내는 것.
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("cls,spec,canary_col,pty", [(r[0], r[1], r[2], r[5]) for r in ROWS],
                         ids=[r[0] for r in ROWS])
def test_hostile_class(tmp_path, shell, cls, spec, canary_col, pty):
    canary = short_dir() / "c"
    data = matrix.payload(spec, str(canary).encode())
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(record(shell, data))
    s = Session(shell, env, cols=200)
    # A rejected record must give the minimal prompt quickly: a reader that
    # accepted the 1 MiB value would draw it and time out here instead.
    limit = 3 if pty == "minimal" else 15
    try:
        s.run(f"source {init}", timeout=limit)
        s.run("true", timeout=limit)
    except pexpect.TIMEOUT:
        pytest.fail(f"{cls}: no prompt within {limit} s in {shell}; screen tail "
                    f"{visible(s.log.getvalue())[-300:]!r}")
    out = visible(s.close())
    if canary_col == "yes":
        assert not canary.exists(), f"{cls} executed in {shell}"
    if pty == "observe":
        assert b"null byte" not in out and b"warning:" not in out, f"{cls}: shell warning on screen in {shell}"
        print(f"OBSERVE {shell} {cls}: left={b'L<' in out} right={b'RMARK' in out}")
    elif pty == "noexec":
        assert drawn(shell, out, data), f"{cls}: fields not drawn in order on one line in {shell}"
    else:
        assert b"L<" not in out, f"{cls}: rejected record was drawn in {shell}"
        assert MINIMAL in out, f"{cls}: no minimal prompt in {shell}"
