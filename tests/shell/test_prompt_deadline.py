"""N6: the actual single-threaded executable, including its actual write loop.
No production injection hooks; dynamic-libc fault probes are separate from the
unconditional full-pipe, SIGALRM-mask, SIGPIPE and shared-fd tests.
"""
import ctypes
import errno
import fcntl
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

import pytest
from conftest import ROOT, real_bin

ARGV = ["prompt", "--ctx", "1", "--record", "B1", "--width", "80"]


@pytest.fixture(scope="module")
def interposer():
    # Static musl cannot load a fault injector. The non-injected tests below
    # still exercise the real blocked writer on that target.
    description = subprocess.check_output(["file", str(real_bin())], text=True)
    if "statically linked" in description or "static-pie linked" in description:
        pytest.skip("static musl: libc interposition unavailable; native blocked-pipe tests still run")
    with tempfile.TemporaryDirectory(dir=ROOT / "target", prefix="n6-") as tmp:
        lib = pathlib.Path(tmp) / "deadline.dylib"
        flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC", "-ldl"]
        subprocess.run(["cc", "-O2", "-Wall", "-Werror", *flags,
                        str(ROOT / "tests/shell/fixtures/deadline_interpose.c"), "-o", str(lib)], check=True)
        yield lib


def injected(lib, mode):
    key = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
    return {**os.environ, key: str(lib), "N6_TEST_MODE": str(mode)}


def thread_count(pid):
    if sys.platform == "linux":
        return len(list(pathlib.Path(f"/proc/{pid}/task").iterdir()))
    # External libproc observation, never production getdents/task enumeration.
    class TaskInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ("virtual", "resident", "total_user", "total_system", "threads_user", "threads_system")] + [
                    (name, ctypes.c_int32) for name in
                    ("policy", "faults", "pageins", "cow", "sent", "received", "mach", "unix", "switches",
                     "threadnum", "running", "priority")]
    info = TaskInfo()
    proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    got = proc.proc_pidinfo(pid, 4, 0, ctypes.byref(info), ctypes.sizeof(info))
    if got == 0 and ctypes.get_errno() == errno.ESRCH:
        raise FileNotFoundError(pid)
    assert got == ctypes.sizeof(info), ("external thread observation failed", ctypes.get_errno())
    return info.threadnum


def blocked(env=None, block_alarm=False):
    r, w = os.pipe()
    child = None
    try:
        flags = fcntl.fcntl(w, fcntl.F_GETFL)
        fcntl.fcntl(w, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        while True:
            try:
                os.write(w, b"x" * 4096)
            except BlockingIOError:
                break
        # Fill any remainder too (macOS's PIPE_BUF is smaller than 4096).
        while True:
            try:
                os.write(w, b"x")
            except BlockingIOError:
                break
        fcntl.fcntl(w, fcntl.F_SETFL, flags)
        before = fcntl.fcntl(w, fcntl.F_GETFL)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM}) if block_alarm else None
        start = time.monotonic()
        try:
            child = subprocess.Popen([str(real_bin()), *ARGV], stdout=w, stderr=subprocess.PIPE, env=env)
        finally:
            if mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        # The pipe stays full and unread until the child has exited.
        counts = []
        while child.poll() is None and time.monotonic() - start < 1:
            try:
                counts.append(thread_count(child.pid))
            except FileNotFoundError:
                break  # Linux process exited between poll and task enumeration.
            time.sleep(0.002)
        _, err = child.communicate(timeout=0.2)
        assert child.returncode == 0 and err == b""
        assert counts and max(counts) == 1, counts
        assert time.monotonic() - start < 1  # scheduler-tolerant watchdog, not an RT claim
        assert fcntl.fcntl(w, fcntl.F_GETFL) == before
        os.close(w)
        w = -1
        data = b""
        while chunk := os.read(r, 65536):
            data += chunk
        assert data and set(data) == {ord("x")}, "an expired writer appended a record"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate()
        os.close(r)
        if w >= 0:
            os.close(w)


# 이것을 실패시키는 것: 타이머 없는 무한 쓰기, SA_RESTART, 상속한 SIGALRM 차단 유지, 스레드 생성·fd 플래그 변경.
@pytest.mark.parametrize("block_alarm", [False, True])
def test_full_pipe_is_abandoned_by_single_thread(block_alarm):
    blocked(block_alarm=block_alarm)


# 이것을 실패시키는 것: 첫 만료 뒤 반복 타이머를 없애 check/handler/write 경쟁에서 영원히 멈추는 것.
def test_signal_before_write_is_interrupted_again(interposer):
    blocked(injected(interposer, 1))


# 이것을 실패시키는 것: 부분 쓰기·EINTR 뒤 레코드 바이트를 잃거나 중복하는 것.
def test_native_partial_writes_and_eintr_preserve_bytes(interposer):
    normal = subprocess.run([str(real_bin()), *ARGV], capture_output=True, check=True)
    probed = subprocess.run([str(real_bin()), *ARGV], capture_output=True,
                            env=injected(interposer, 2), timeout=1)
    assert normal.stdout.startswith(b"B1\x1f")
    assert probed.returncode == 0 and probed.stderr == b"" and probed.stdout == normal.stdout


# 이것을 실패시키는 것: 설치 실패·시계 실패·준비 중 만료 뒤 보호 없는 출력, EINTR 폭주에 예산 재시작.
@pytest.mark.parametrize("mode", [3, 4, 5, 6, 7, 8, 9])
def test_setup_failure_clock_failure_and_expiry_emit_nothing(interposer, mode):
    result = subprocess.run([str(real_bin()), *ARGV], capture_output=True,
                            env=injected(interposer, mode), timeout=1)
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
