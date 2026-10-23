"""Shared shell fixtures; helpers have a stable name across pytest suites."""
import os
import shutil

import pytest

# Re-export for existing shell tests; cross-suite consumers import shell_support.
from shell_support import (
    ROOT, FAKE, SHELL_CMD, COLD_INIT_NOTICE, Install, real_bin, real_collector,
    trusted_env, run_shell_script, short_dir, minimal_record, _SHORT_DIRS,
)


@pytest.fixture(autouse=True)
def _cleanup():
    """After each test: end PTY sessions a failing test left running and
    remove the short canary folders."""
    yield
    import sys
    pty = sys.modules.get("pty_session")
    if pty is not None:
        for s in list(pty.Session.live):
            s.kill()
    while _SHORT_DIRS:
        shutil.rmtree(_SHORT_DIRS.pop(), ignore_errors=True)


@pytest.fixture
def shells():
    return [s for s in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()]
