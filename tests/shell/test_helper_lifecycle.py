"""N7 lifecycle integration, reusing N3 native probes and N6 pipe machinery."""
import os
import signal
import subprocess
import sys
import time

import pytest
from snapshot_support import SnapshotSession, require_native_boot
from test_snapshot_refresh import appearance
from conftest import ROOT, real_bin
from test_prompt_deadline import is_static


@pytest.fixture
def _native_boot_required():
    require_native_boot()


# 이것을 실패시키는 것: helper가 설정된 command를 실행하는 것(고정 내장 수집과 구분).
def test_helper_never_executes_configured_commands(tmp_path, _native_boot_required):
    session = SnapshotSession(tmp_path)
    canary = session.base / "must-not-exist"
    session.put(f'''[segment."custom/probe"]
kind='command'
command=['/usr/bin/touch', '{canary}']
[layout.line2]
left=['custom/probe','char']
''')
    session.init()
    result = session.run("reload")
    assert result.returncode in (0, 3), result.stderr
    end = time.monotonic() + 4
    while not (session.store() / "snapshot").exists() and time.monotonic() < end:
        session.prompt()
        time.sleep(0.02)
    assert (session.store() / "snapshot").exists(), "helper must finish a real publication"
    for _ in range(5):
        session.prompt()
    session.wait_quiet()
    assert not canary.exists()


# 이것을 실패시키는 것: prompt 수준 전달을 고정하거나 helper가 BINGSU_LOG를 경로로 해석하는 것.
def test_each_prompt_forwards_level_to_fixed_log_root(tmp_path, _native_boot_required):
    session = SnapshotSession(tmp_path)
    session.put(appearance("LOG"))
    session.init()
    session.await_text("LOG")
    session.wait_quiet()
    log_root = next(word.split("=", 1)[1] for word in session.words if word.startswith("--log-root="))
    from pathlib import Path
    log = Path(log_root) / "refresh.log"
    assert not log.exists()
    args = [word if word != "--log-level=off" else "--log-level=debug" for word in session.prompt_args()]
    session.env["BINGSU_LOG"] = str(session.base / "attacker.log")
    result = session.run(*args)
    assert result.returncode == 0 and result.stderr == b""
    end = time.monotonic() + 4
    while not log.exists() and time.monotonic() < end:
        time.sleep(0.02)
    assert log.exists() and b"refresh" in log.read_bytes()
    assert not (session.base / "attacker.log").exists()
    session.wait_quiet()
    # bootstrap deliberately clears the environment. Also exercise the helper
    # entry directly so an accidental environment lookup cannot hide behind it.
    direct = session.run("__refresh-v1", *args[1:])
    assert direct.returncode == 0 and direct.stdout == direct.stderr == b"", direct
    assert not (session.base / "attacker.log").exists()
    previous = log.read_bytes()
    session.prompt()
    session.wait_quiet()
    assert log.read_bytes() == previous


# 이것을 실패시키는 것: NSS보다 늦게 watchdog을 시작하거나 kill 요청을 생략하는 것.
def test_nss_stall_requests_kill_independently(tmp_path):
    if is_static(real_bin()):
        pytest.skip("static musl cannot preload NSS stall; native helper limit tests still run")
    library = tmp_path / "nss-stall.dylib"
    flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
    subprocess.run(["cc", "-O2", "-Wall", "-Werror", *flags,
                    str(ROOT / "tests/shell/fixtures/n7_nss_stall.c"), "-o", str(library)], check=True)
    ready = tmp_path / "nss-entered"
    key = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
    env = {**os.environ, key: str(library), "N7_NSS_READY": str(ready)}
    started = time.monotonic()
    child = subprocess.Popen([str(real_bin()), "__refresh-v1", "--ctx", "1", "--record", "B1",
                              "--width", "0", "--runtime-root=1:2:/r", "--config-root=/c",
                              "--config-root-written=/c", "--state-root=/s", "--home=/h"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # This is a userspace NSS stall, so SIGKILL delivery is observable. It
        # makes no claim about termination of a kernel uninterruptible mount I/O.
        out, err = child.communicate(timeout=3.5)
        assert ready.read_bytes() == b"entered\n"
        assert child.returncode == -signal.SIGKILL, (child.returncode, out, err)
        assert 1.5 <= time.monotonic() - started < 3.5
        assert out == err == b""
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
