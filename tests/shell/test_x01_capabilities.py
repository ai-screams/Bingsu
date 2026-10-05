"""X-01 shell capability probes (resize redraw, transient prompt) with
minimal rc files, pinned per shell and version in x01_expected.tsv."""
import os
import pathlib
import re
import sys

import pexpect
import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "golden/record"))  # tests/golden/record/
from check_versions import rule_matches  # noqa: E402
from pty_session import Session, visible  # noqa: E402
from run import shell_version  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
RC = {
    # State changes only in the trap, as bingsu's --redraw would; zsh's own
    # SIGWINCH redisplay alone keeps showing the old value.
    ("zsh", "resize"): "setopt prompt_subst\n_w=start\nPROMPT='P${_w}> '\nTRAPWINCH() { _w=$COLUMNS; zle && zle reset-prompt }\n",
    ("zsh", "transient"): "precmd() { PROMPT='FULL> ' }\n_t() { PROMPT='T> '; zle reset-prompt }\nzle -N zle-line-finish _t\n",
    ("bash", "resize"): "shopt -s checkwinsize\nPS1='P$COLUMNS> '\n",
    # Not a measurement: bash has a transient prompt only through ble.sh, and
    # --norc with HOME in the test folder never loads it, so this probe always
    # finds none (the spec's definition, not a shell behaviour).
    ("bash", "transient"): "PS1='FULL> '\n",
    ("fish", "resize"): "function fish_prompt; printf 'P%s> ' $COLUMNS; end\n",
    ("fish", "transient"): ("set -g fish_transient_prompt 1\n"
                           "function fish_prompt; if contains -- --final-rendering $argv; printf 'T> '; "
                           "else; printf 'FULL> '; end; end\n"),
}


# fish's reflow setting, read inside the probe session after the rc: typed as
# RE""FLOW so the echoed input never matches, printed as REFLOW=<value>.
REFLOW_CMD = 'if set -q fish_handle_reflow; echo "RE""FLOW=<$fish_handle_reflow>"; else; echo "RE""FLOW=unset"; end'
REFLOW = re.compile(rb"\nREFLOW=(<[^>\n]*>|unset)")


def expected(shell, cap):
    v = shell_version(shell)
    for line in (HERE / "x01_expected.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            sh, rule, c, outcome = line.split("\t")
            if sh == shell and c == cap and rule_matches(rule, v):
                return outcome
    raise AssertionError(f"no expected row for {shell} {v} {cap}")


def probe(shell, cap, tmp):
    """(outcome, reflow): reflow is fish's fish_handle_reflow in this session
    ("<value>" or "unset"), "" for the other shells."""
    rc = tmp / f"rc.{shell}"
    assert "'" not in str(rc), f"rc path {rc} needs a quote-free folder"
    rc.write_text(RC[(shell, cap)])
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp), "LC_ALL": os.environ.get("BINGSU_TEST_LOCALE", "C.UTF-8"),
           "XDG_CONFIG_HOME": str(tmp / "cfg"), "TERM": "xterm-256color"}
    s = Session(shell, env, cols=80)
    try:
        s.run(f"source '{rc}'")
        reflow = ""
        if shell == "fish":
            s.run(REFLOW_CMD)
            reflow = REFLOW.search(visible(s.log.getvalue())).group(1).decode()
        if cap == "resize":
            if shell == "bash":
                s.run("true")  # let checkwinsize see the start size
            s.p.setwinsize(24, 61)
            try:
                s.expect(b"P61> ", timeout=3)
                outcome = "supported"
            except pexpect.TIMEOUT:
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
    finally:
        s.kill()
    (tmp / f"{shell}-{cap}.transcript").write_bytes(transcript)
    return outcome, reflow


# 이것을 실패시키는 것: 기대 표와 다른 셸 동작(버전 바뀜, 장치가 사라짐), 또는 탐침 rc의 결함.
# bash transient만은 측정이 아니라 정의(ble.sh 부재)라서, 기대 표를 supported로 바꾸는 것만 이것을 실패시킨다.
@pytest.mark.parametrize("cap", ["resize", "transient"])
@pytest.mark.parametrize("shell", SHELLS)
def test_capability(tmp_path, shell, cap):
    got, _ = probe(shell, cap, tmp_path)
    want = expected(shell, cap)
    assert got == want, f"{shell} {shell_version(shell)} {cap}: got {got}, want {want}; transcript in {tmp_path}"


if __name__ == "__main__" and sys.argv[1:] == ["--record"]:
    import tempfile
    for sh in SHELLS:
        for cap in ("resize", "transient"):
            with tempfile.TemporaryDirectory() as td:
                outcome, reflow = probe(sh, cap, pathlib.Path(td))
                print(f"{sh}\t{'.'.join(map(str, shell_version(sh)))}\t{cap}\t{outcome}\treflow={reflow}")
