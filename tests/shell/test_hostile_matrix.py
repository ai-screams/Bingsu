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
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "golden/record"))  # tests/golden/record/
from run import nul_override, nul_rows, shell_version  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
ROWS = matrix.rows()
# Every fallback prompt (all three hooks) ends with this mark.
MINIMAL = "❯ ".encode()
LOCALES = ("en_US.UTF-8", "C", "ko_KR.UTF-8")


def cases():
    # NUL classes (pty "observe") have their screen outcome pinned per
    # shell x version x locale in nul_expected.tsv, so each runs in every locale.
    for r in ROWS:
        for loc in (LOCALES if r[5] == "observe" else (None,)):
            yield pytest.param(r[0], r[1], r[2], r[5], loc, id=r[0] if loc is None else f"{r[0]}-{loc}")


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
# 거부해야 할 레코드를 그리는 것, NUL을 지울 때 셸 경고를 화면에 내는 것,
# NUL 행의 화면 결과를 셸·버전·로캘 칸마다 고정한 값과 맞춰 보지 않는 것(한 값으로 합치거나 고정 없는 칸을 통과시킴).
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("cls,spec,canary_col,pty,locale", list(cases()))
def test_hostile_class(tmp_path, shell, cls, spec, canary_col, pty, locale):
    canary = short_dir() / "c"
    data = matrix.payload(spec, str(canary).encode())
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    if locale:
        env["LC_ALL"] = locale
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
        # Checked whether or not the cell is pinned.
        assert b"null byte" not in out and b"warning:" not in out, f"{cls}: shell warning on screen in {shell}"
        pinned = nul_override(nul_rows(), f"hostile_{cls}", shell, shell_version(shell), env["LC_ALL"], column="pty")
        if pinned is None:
            if os.environ.get("BINGSU_RECORD_OBSERVATIONS") != "1":
                pytest.fail(f"{cls}: no pty pin for {shell} {env['LC_ALL']} in nul_expected.tsv; record, review and pin it")
            print(f"OBSERVE-PTY {shell} {env['LC_ALL']} hostile_{cls}: left={b'L<' in out} right={b'RMARK' in out} "
                  f"minimal={MINIMAL in out}")
            return
        if pinned == "noexec":
            # bash drops every NUL before the reader (accept-stripped); zsh
            # draws the NUL byte as it is.
            shown = data.replace(b"\x00", b"") if shell == "bash" else data
            assert drawn(shell, out, shown), f"{cls}: fields not drawn in order on one line in {shell}"
        else:
            assert b"L<" not in out, f"{cls}: rejected record was drawn in {shell}"
            assert MINIMAL in out, f"{cls}: no minimal prompt in {shell}"
    elif pty == "noexec":
        assert drawn(shell, out, data), f"{cls}: fields not drawn in order on one line in {shell}"
    else:
        assert b"L<" not in out, f"{cls}: rejected record was drawn in {shell}"
        assert MINIMAL in out, f"{cls}: no minimal prompt in {shell}"
