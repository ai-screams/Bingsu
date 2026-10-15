"""A prompt call that a signal ended (spec section 6 rule 2; decisions P18,
P19): the shell draws its own fallback and does not call the binary again
until the next command. Before this rule fish 3.6 reported the signal,
redrew the prompt, called the binary again and looped (a defect since M1).
Also: a `degraded:sandbox` record is reported once per session."""
import os

import pexpect
import pytest

from conftest import ROOT, Install, minimal_record, run_shell_script, trusted_env
from test_init_words import source
from pty_session import Session

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
FALLBACK = "\u276f ".encode()
SIGSYS_FAKE = ROOT / "tests/shell/fake_bingsu_sigsys.sh"


def calls(inst):
    log = inst.dir / "calls.log"
    return log.read_text().count("call") if log.exists() else 0


def fake(tmp_path, sig):
    """Like fake_bingsu_sigsys.sh, but dies by `sig`."""
    f = tmp_path / f"fake_{sig}.sh"
    f.write_text(f'#!/bin/sh\nprintf \'call\\n\' >> "${{0%/*}}/calls.log"\nkill -s {sig} $$\n')
    f.chmod(0o755)
    return f


def failing(tmp_path, kind):
    """A binary a signal ends, or a pinned path with nothing behind it (127)."""
    return tmp_path / "missing" if kind == "missing" else fake(tmp_path, kind)


def start(tmp_path, shell, record=None, script=None):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(record or b"", script=script or SIGSYS_FAKE)
    s = Session(shell, env, cols=100, rows=30)
    s.run(source(shell, init).decode().rstrip("\n"))
    return inst, s


# A command that sets no status in fish (the status generation stays).
STATUSLESS = {"zsh": "x=1", "bash": "x=1", "fish": "set x 1"}


# 이것을 실패시키는 것: 신호로 끝난 호출을 기억하지 않는 것(빈 줄·다시 그리기마다 다시 부름, fish 3.6은 무한 반복),
# 다음 명령 뒤에도 다시 부르지 않는 것, 대체 프롬프트를 그리지 않는 것.
@pytest.mark.parametrize("shell", SHELLS)
def test_signal_ended_call_waits_for_the_next_command(tmp_path, shell):
    inst, s = start(tmp_path, shell)
    s.run("true")
    # The prompt after the last command, drawn after its (killed) call.
    s.expect(FALLBACK)
    before = calls(inst)
    assert before >= 1
    for _ in range(3):
        s.p.sendline("")
        s.expect(FALLBACK)
    assert calls(inst) == before, (calls(inst), before)
    s.run("true")
    assert calls(inst) > before
    s.close()


# 이것을 실패시키는 것: fish에서 dead 상태를 fish_postexec 대신 status generation으로 푸는 것(`set x 1` 뒤에도 대체
# 프롬프트가 남음).
@pytest.mark.parametrize("shell", SHELLS)
def test_a_command_that_sets_no_status_is_the_next_command(tmp_path, shell):
    inst, s = start(tmp_path, shell)
    s.run("true")
    s.expect(FALLBACK)
    before = calls(inst)
    s.run(STATUSLESS[shell])
    assert calls(inst) > before, (calls(inst), before)
    s.close()


# An interactive bash with `set -e`: a call that a signal ended, or a pinned
# path with nothing behind it, must not end the shell.
# 이것을 실패시키는 것: bash에서 치환 대입 뒤의 `|| _bingsu_st=$?`를 빼는 것(대입의 실패 상태로 errexit가 셸을 끝냄).
@pytest.mark.parametrize("kind", ["SEGV", "SYS", "missing"])
def test_set_e_bash_survives_a_failed_call(tmp_path, kind):
    if "bash" not in SHELLS:
        pytest.skip("bash not in BINGSU_TEST_SHELLS")
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / "init.bash"
    init.write_bytes(inst.init("bash", env))
    inst.use_fake(b"", script=failing(tmp_path, kind))
    s = Session("bash", env, cols=100, rows=30)
    try:
        s.run("set -e; " + source("bash", init).decode().rstrip("\n"))
        s.run('echo AL""IVE')
    except pexpect.EOF:
        pass
    out = s.close()
    # The typed line is AL""IVE: only the output of echo spells ALIVE.
    assert b"ALIVE" in out, out[-400:]


# The user's ERR (bash `set -E`) or ZERR trap: a failed call keeps its status
# for the hook but fires no trap. probe_fail shows the trap is live.
# 이것을 실패시키는 것: 치환 대입 뒤의 `|| _bingsu_st=$?`를 빼는 것(대입과 치환 안의 바이너리에서 trap이 불림).
# `||` 문맥이 치환의 서브셸까지 덮으므로 치환 안에 따로 `||`를 두지 않는다(두어도 이 시험이 구별하지 못함).
TRAP = {
    "bash": 'set -E\ntrap \'printf "%s\\n" "${FUNCNAME[*]-top}" >> "$BINGSU_T_LOG"\' ERR\n',
    "zsh": 'TRAPZERR() { print -r -- "${funcstack[*]}" >> "$BINGSU_T_LOG" }\n',
}


@pytest.mark.parametrize("kind", ["SEGV", "missing"])
@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_failed_call_fires_no_error_trap(tmp_path, shell, kind):
    if shell not in SHELLS:
        pytest.skip(f"{shell} not in BINGSU_TEST_SHELLS")
    inst = Install(tmp_path)
    log = tmp_path / "trap.log"
    env = dict(trusted_env(tmp_path), BINGSU_T_LOG=str(log))
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(b"", script=failing(tmp_path, kind))
    body = (source(shell, init) + TRAP[shell].encode()
            + b"_bingsu_install\n_bingsu_install\nprobe_fail() { false; }\nprobe_fail\necho DONE\n")
    r = run_shell_script(shell, body, env, tmp_path)
    lines = log.read_text().splitlines() if log.exists() else []
    assert r.stdout.endswith(b"DONE\n"), (r.stdout, r.stderr)
    assert any("probe_fail" in x for x in lines), lines
    assert not any("_bingsu_call" in x for x in lines), lines


# 이것을 실패시키는 것: degraded:sandbox 알림을 매 프롬프트 찍는 것, 찍지 않는 것, 다른 상태에서 찍는 것.
@pytest.mark.parametrize("shell", SHELLS)
def test_sandbox_notice_once(tmp_path, shell):
    inst, s = start(tmp_path, shell, record=minimal_record(status=b"degraded:sandbox"),
                    script=ROOT / "tests/shell/fake_bingsu.sh")
    for _ in range(3):
        s.run("true")
    text = s.close().decode("utf-8", "replace")
    assert text.count("could not start its system call filter") == 1, text
