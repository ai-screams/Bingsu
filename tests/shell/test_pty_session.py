"""The PTY driver itself (tests/shell/pty_session.py)."""
import os
import time

import pexpect
import pytest

from conftest import trusted_env
from pty_session import Session

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
zsh_only = pytest.mark.skipif("zsh" not in SHELLS, reason="zsh not under test")


# A child that keeps asking terminal questions must not keep expect() alive.
# respond_queries=True is the driver's explicit switch; a fish session sets it itself.
# 이것을 실패시키는 것: expect()가 질의에 답할 때마다 timeout을 새로 시작하는 것(약 6초 뒤에야 끝남).
@zsh_only
def test_expect_timeout_is_one_deadline(tmp_path):
    with Session("zsh", trusted_env(tmp_path), respond_queries=True) as s:
        s.p.sendline("for i in {1..30}; do printf '\\033[c'; sleep 0.2; done")
        t = time.monotonic()
        with pytest.raises(pexpect.TIMEOUT):
            s.expect(b"NEVER_PRINTED", timeout=1)
        assert time.monotonic() - t < 3


# 이것을 실패시키는 것: __exit__이 child를 끝내지 않는 것.
@zsh_only
def test_context_manager_ends_the_child(tmp_path):
    with Session("zsh", trusted_env(tmp_path)) as s:
        pass
    assert not s.p.isalive()
    assert s not in Session.live


# fish 4.0.2 never sends OSC 133;B. Waiting for it before every command made
# each run() take about 4 s (two waits of 2 s). Kills its mutation on fish
# 4.0.2 only; on fish 3.6 and 4.9 it is green either way.
# 이것을 실패시키는 것: 첫 프롬프트에 133;B가 없어도 _ready가 매번 기다리는 것(fish 4.0.2에서 run 세 번이 약 12초).
@pytest.mark.skipif("fish" not in SHELLS, reason="fish not under test")
def test_fish_run_does_not_wait_for_a_mark_it_never_sends(tmp_path):
    with Session("fish", trusted_env(tmp_path)) as s:
        t = time.monotonic()
        for _ in range(3):
            s.run("true")
        assert time.monotonic() - t < 3


# Only the first prompt decides: on a fish that sends 133;B, a later prompt
# that comes after the 2 s wait (a slow command) keeps the waits on, or input
# typed during later query rounds would be dropped. Runs where the first
# prompt brings 133;B (fish 4.9); skipped elsewhere.
# 이것을 실패시키는 것: _ready의 `if self.n == 0` 조건을 지우는 것(늦은 프롬프트 하나로 기다림이 꺼짐).
@pytest.mark.skipif("fish" not in SHELLS, reason="fish not under test")
def test_fish_slow_command_keeps_the_prompt_mark_wait(tmp_path):
    with Session("fish", trusted_env(tmp_path)) as s:
        if not s.prompt_mark:
            pytest.skip("this fish sends no OSC 133;B")
        s.run("sleep 2.5")
        assert s.prompt_mark
