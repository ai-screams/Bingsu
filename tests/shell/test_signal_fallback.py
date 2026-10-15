"""A prompt call that a signal ended (spec section 6 rule 2; decision
P19): the shell draws its own fallback and does not call the binary again
until the next command. Before this rule fish 3.6 reported the signal,
redrew the prompt, called the binary again and looped (a defect since M1)."""
import os

import pytest

from conftest import ROOT, Install, trusted_env
from test_init_words import source
from pty_session import Session

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
FALLBACK = "\u276f ".encode()
SIGSYS_FAKE = ROOT / "tests/shell/fake_bingsu_sigsys.sh"


def calls(inst):
    log = inst.dir / "calls.log"
    return log.read_text().count("call") if log.exists() else 0


def start(tmp_path, shell, record=None, script=None):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(record or b"", script=script or SIGSYS_FAKE)
    s = Session(shell, env, cols=100, rows=30)
    s.run(source(shell, init).decode().rstrip("\n"))
    return inst, s


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

