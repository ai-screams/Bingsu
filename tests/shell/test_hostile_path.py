"""Spec section 7 security table, fixed executable path row: a fake
`bingsu` first in PATH must never run; the hook calls the pinned path."""
import os

from conftest import Install, minimal_record, short_dir, trusted_env
from pty_session import Session

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()


# 이것을 실패시키는 것: hook이 `bingsu`를 PATH로 찾는 것.
def test_fake_bingsu_first_in_path_never_runs(tmp_path):
    for shell in SHELLS:
        base = tmp_path / shell
        base.mkdir()
        inst = Install(base)
        env = trusted_env(base)
        init = base / f"init.{shell}"
        init.write_bytes(inst.init(shell, env))
        inst.use_fake(minimal_record())
        evil = base / "evil"
        evil.mkdir()
        canary = short_dir() / "c"
        (evil / "bingsu").write_text(f"#!/bin/sh\ntouch {canary}\n")
        os.chmod(evil / "bingsu", 0o755)
        s = Session(shell, dict(env, PATH=f"{evil}:{env['PATH']}"))
        s.run(f"source {init}")
        s.run("true")
        s.close()
        assert not canary.exists(), f"{shell} ran bingsu from PATH"
        assert len(inst.calls()) >= 2, f"{shell} did not call the pinned path"
