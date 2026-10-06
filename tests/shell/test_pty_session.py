"""The PTY driver itself (tests/shell/pty_session.py)."""
import os
import time

import pexpect
import pytest

from conftest import trusted_env
from pty_session import Session, sends_prompt_end

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
# each run() take about 4 s (two waits of 2 s), about 12 s for three. The
# 7 s budget leaves room for a loaded machine and still catches that. Kills
# its mutation on fish 4.0.2 only; on fish 3.6 and 4.9 it is green either way.
# 이것을 실패시키는 것: fish 4.0에서도 _ready가 133;B를 기다리는 것(4.0.2에서 run 세 번이 약 12초).
@pytest.mark.skipif("fish" not in SHELLS, reason="fish not under test")
def test_fish_run_does_not_wait_for_a_mark_it_never_sends(tmp_path):
    with Session("fish", trusted_env(tmp_path)) as s:
        t = time.monotonic()
        for _ in range(3):
            s.run("true")
        assert time.monotonic() - t < 7



# 이것을 실패시키는 것: 판정을 뒤집는 것(4.0이 B를 기대하면 run마다 4초, 4.9가 기대하지 않으면 입력이 버려짐),
# 비교 기준을 (4, 0)으로 낮추는 것.
@pytest.mark.parametrize("text,expected", [
    ("fish, version 3.6.0", False),
    ("fish, version 4.0.2", False),
    ("fish, version 4.1.0", True),
    ("fish, version 4.9.3", True),
    ("fish, version 5.0.0", True),
    ("", False),
])
def test_prompt_end_mark_is_decided_by_version(text, expected):
    assert sends_prompt_end(text) is expected
