"""The PTY driver itself (tests/shell/pty_session.py)."""
import os
import time

import pexpect
import pytest

from conftest import trusted_env
from pty_session import Session

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")


# A child that keeps asking terminal questions must not keep expect() alive.
# respond_queries=True is the driver's explicit switch; a fish session sets it itself.
# 이것을 실패시키는 것: expect()가 질의에 답할 때마다 timeout을 새로 시작하는 것(약 6초 뒤에야 끝남).
def test_expect_timeout_is_one_deadline(tmp_path):
    with Session("zsh", trusted_env(tmp_path), respond_queries=True) as s:
        s.p.sendline("for i in {1..30}; do printf '\\033[c'; sleep 0.2; done")
        t = time.monotonic()
        with pytest.raises(pexpect.TIMEOUT):
            s.expect(b"NEVER_PRINTED", timeout=1)
        assert time.monotonic() - t < 3


# 이것을 실패시키는 것: __exit__이 child를 끝내지 않는 것.
def test_context_manager_ends_the_child(tmp_path):
    with Session("zsh", trusted_env(tmp_path)) as s:
        pass
    assert not s.p.isalive()
    assert s not in Session.live
