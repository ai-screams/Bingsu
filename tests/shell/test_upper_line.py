"""Record upper line (record change plan 12, R-04): each hook joins the upper line
and the left field with one constant newline, only when the upper line is
not empty, and its escaping covers both."""
import os

import pytest

from pty_session import visible
from test_bash_hooks import start as bash_start
from test_fish_hooks import start as fish_start
from test_zsh_hooks import opt_lines, start as zsh_start

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()


def upper_record(upper, left=b"> "):
    return b"B1\x1f8\x1f" + left + b"\x1f\x1f\x1f\x1f\x1f\x1f" + upper + b"\x1fok:none\x1e"


def last_line_with(out, mark):
    lines = [l for l in out.replace(b"\r", b"").split(b"\n") if mark in l]
    assert lines, out[-400:]
    return lines[-1]


# 이것을 실패시키는 것: 윗줄을 버리는 것, 줄바꿈 없이 붙이는 것, 윗줄이 비었는데 줄바꿈을 넣는 것,
# PROMPT_BANG의 `!` 이스케이프가 윗줄을 빠뜨리는 것.
@pytest.mark.skipif("zsh" not in SHELLS, reason="zsh not under test")
@pytest.mark.parametrize("subst,bang", [(True, True), (True, False), (False, True), (False, False)])
@pytest.mark.parametrize("upper", [b"UP!LINE", b""])
def test_zsh_upper_line(tmp_path, subst, bang, upper):
    s, _, _ = zsh_start(tmp_path, rc_before=opt_lines(prompt_subst=subst, prompt_bang=bang), record=upper_record(upper))
    s.run('print -r -- "<P=${(V)PROMPT}|V=${(V)_bingsu_ps1}>"')
    got = last_line_with(visible(s.close()), b"<P=")
    shown = upper.replace(b"!", b"!!") if bang else upper
    want = shown + b"\\n> " if upper else b"> "
    if subst:
        assert got == b"<P=${_bingsu_ps1}|V=" + want + b">", got
    else:
        assert got.startswith(b"<P=" + want + b"|"), got


# 이것을 실패시키는 것: bash에서 윗줄을 버리거나, 윗줄이 비었는데 줄바꿈을 넣는 것,
# 값 대입 경로의 `\` 이스케이프가 윗줄을 빠뜨리는 것,
# POSIX 모드(promptvars 끔이어도 확장됨)에서 참조 방식을 쓰지 않는 것.
@pytest.mark.skipif("bash" not in SHELLS, reason="bash not under test")
@pytest.mark.parametrize("mode", ["promptvars", "nopromptvars", "posix"])
@pytest.mark.parametrize("upper", [b"UP\\LINE", b""])
def test_bash_upper_line(tmp_path, mode, upper):
    rc = {"promptvars": "", "nopromptvars": "shopt -u promptvars", "posix": "shopt -u promptvars; set -o posix"}[mode]
    s, _, _ = bash_start(tmp_path, rc_before=rc, record=upper_record(upper))
    s.run("printf '<P=%q|V=%q>\\n' \"$PS1\" \"${_bingsu_ps1-}\"")
    got = last_line_with(visible(s.close()), b"<P=")
    if mode != "nopromptvars":
        want_v = b"$'UP\\\\LINE\\n> '" if upper else b"\\>\\ "
        assert got == b"<P=\\$\\{_bingsu_ps1\\}|V=" + want_v + b">", got
    else:
        want_p = b"$'UP\\\\\\\\LINE\\n> '" if upper else b"\\>\\ "
        assert got.startswith(b"<P=" + want_p + b"|"), got


# 이것을 실패시키는 것: fish에서 윗줄을 버리거나, 비었을 때 줄바꿈을 찍는 것.
@pytest.mark.skipif("fish" not in SHELLS, reason="fish not under test")
@pytest.mark.parametrize("upper", [b"UPLINE", b""])
def test_fish_upper_line(tmp_path, upper):
    s, _ = fish_start(tmp_path, upper_record(upper))[:2]
    # The newline is shown as <NL> so the whole prompt stays on one line of
    # the transcript (string escape differs between fish versions).
    s.run("set -l p (fish_prompt | string collect); printf '<%s>\\n' (string replace -a \\n '<NL>' -- \"$p\")")
    got = last_line_with(visible(s.close()), b"<")
    want = b"<" + upper + b"<NL>> >" if upper else b"<> >"
    assert got == want, got
