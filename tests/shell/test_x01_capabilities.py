"""X-01 shell capability probes (resize redraw, transient prompt) with
minimal rc files, pinned per shell and version in x01_expected.tsv."""
import os
import pathlib
import re
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pty_session import Session, visible  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
RC = {
    # State changes only in the trap, as bingsu's --redraw would; zsh's own
    # SIGWINCH redisplay alone keeps showing the old value.
    ("zsh", "resize"): "setopt prompt_subst\n_w=start\nPROMPT='P${_w}> '\nTRAPWINCH() { _w=$COLUMNS; zle && zle reset-prompt }\n",
    ("zsh", "transient"): "precmd() { PROMPT='FULL> ' }\n_t() { PROMPT='T> '; zle reset-prompt }\nzle -N zle-line-finish _t\n",
    ("bash", "resize"): "shopt -s checkwinsize\nPS1='P$COLUMNS> '\n",
    ("bash", "transient"): "PS1='FULL> '\n",
    ("fish", "resize"): "function fish_prompt; printf 'P%s> ' $COLUMNS; end\n",
    ("fish", "transient"): ("set -g fish_transient_prompt 1\n"
                           "function fish_prompt; if contains -- --final-rendering $argv; printf 'T> '; "
                           "else; printf 'FULL> '; end; end\n"),
}


def version(shell):
    cmd = {"zsh": ["zsh", "-fc", "echo $ZSH_VERSION"], "bash": ["bash", "-c", 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"'],
           "fish": ["fish", "--version"]}[shell]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return tuple(int(x) for x in re.search(r"(\d+)\.(\d+)", out).groups())


def rule_matches(rule, v):
    if rule == "*":
        return True
    m = re.fullmatch(r"(>=|<)(\d+)\.(\d+)", rule)
    want = (int(m.group(2)), int(m.group(3)))
    return v >= want if m.group(1) == ">=" else v < want


def expected(shell, cap):
    v = version(shell)
    for line in (HERE / "x01_expected.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            sh, rule, c, outcome = line.split("\t")
            if sh == shell and c == cap and rule_matches(rule, v):
                return outcome
    raise AssertionError(f"no expected row for {shell} {v} {cap}")


def probe(shell, cap, tmp):
    rc = tmp / f"rc.{shell}"
    rc.write_text(RC[(shell, cap)])
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp), "LC_ALL": os.environ.get("BINGSU_TEST_LOCALE", "C.UTF-8"),
           "XDG_CONFIG_HOME": str(tmp / "cfg"), "TERM": "xterm-256color"}
    s = Session(shell, env, cols=80)
    s.run(f"source {rc}")
    if cap == "resize":
        if shell == "bash":
            s.run("true")  # let checkwinsize see the start size
        s.p.setwinsize(24, 61)
        try:
            s.expect(b"P61> ", timeout=3)
            outcome = "supported"
        except Exception:
            s.run("true")
            outcome = "next-prompt" if b"P61> " in visible(s.log.getvalue()) else "unsupported"
    else:
        if shell == "bash":
            s.run('[[ -n ${BLE_VERSION-} ]] && echo BLE_PRESENT || echo BLE_ABSENT')
            outcome = "supported" if b"\nBLE_PRESENT" in visible(s.log.getvalue()) else "unsupported"
        else:
            s.run("echo X1")
            outcome = "supported" if b"T> echo X1" in visible(s.log.getvalue()) else "unsupported"
    transcript = s.close()
    (tmp / f"{shell}-{cap}.transcript").write_bytes(transcript)
    return outcome


# 이것을 실패시키는 것: 기대 표와 다른 셸 동작(버전 바뀜, 장치가 사라짐), 또는 탐침 rc의 결함.
@pytest.mark.parametrize("cap", ["resize", "transient"])
@pytest.mark.parametrize("shell", SHELLS)
def test_capability(tmp_path, shell, cap):
    got = probe(shell, cap, tmp_path)
    want = expected(shell, cap)
    assert got == want, f"{shell} {version(shell)} {cap}: got {got}, want {want}; transcript in {tmp_path}"


if __name__ == "__main__" and sys.argv[1:] == ["--record"]:
    import tempfile
    for sh in SHELLS:
        extra = ""
        if sh == "fish":
            extra = subprocess.run(["fish", "-c", "set -q fish_handle_reflow; and echo $fish_handle_reflow; or echo unset"],
                                   capture_output=True, text=True).stdout.strip()
        for cap in ("resize", "transient"):
            with tempfile.TemporaryDirectory() as td:
                print(f"{sh}\t{'.'.join(map(str, version(sh)))}\t{cap}\t{probe(sh, cap, pathlib.Path(td))}\treflow={extra}")
