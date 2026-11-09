"""A FUSE mount whose daemon is stopped: lookups under it wait without an answer.

bindfs runs in the foreground as this test's child, so the test owns the
daemon PID. SIGSTOP leaves the kernel waiting on a daemon that never replies.
SIGKILL ends a process waiting there only while its request is still queued:
a request a daemon thread already read waits uninterruptibly
(fs/fuse/dev.c request_wait_answer). SIGSTOP stops each thread only on its
way back to user space, so a thread blocked reading /dev/fuse can still take
a request sent right after the signal; the fixture therefore waits until
every daemon thread shows the stopped state before any lookup. This fixture
does not model an uninterruptible kernel wait. Linux only.
"""
import contextlib
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

from shell_support import Blocked


def _mounted(path):
    target = os.fsencode(str(path))
    return any(line.split()[4] == target for line in pathlib.Path("/proc/self/mountinfo").read_bytes().splitlines())


PROC = pathlib.Path("/proc")
STOP_TIMEOUT = 5.0
_sleep = time.sleep


class Vanished(Exception):
    """A thread listed under /proc/<pid>/task was gone before its stat was read."""


def task_states(pid, proc=None):
    """The state letter of each thread of `pid` (/proc/<pid>/task/*/stat).
    Raises Vanished when a listed thread exits before its stat is read."""
    states = []
    for task in ((proc or PROC) / str(pid) / "task").iterdir():
        try:
            text = (task / "stat").read_text()
        except FileNotFoundError:
            raise Vanished(task.name) from None
        # The state follows the command name's closing parenthesis.
        states.append(text.rsplit(")", 1)[1].split()[0])
    return states


def all_stopped(states):
    """Every thread is stopped (T, or t when traced), and there is one."""
    return bool(states) and all(state in ("T", "t") for state in states)


def wait_stopped(pid, proc=None, timeout=None):
    """Return once every thread of `pid` is stopped. A thread that exits
    while a sample is read (libfuse retires idle workers) restarts the
    sample; the daemon itself gone, or no stop within the timeout, is Blocked."""
    proc = proc or PROC
    end = time.monotonic() + (STOP_TIMEOUT if timeout is None else timeout)
    while True:
        # 이것을 실패시키는 것: 사라진 스레드에서 예외로 끝나는 것, 데몬이 끝난 것(폴더 없음, zombie)을
        # 다시 시도하는 것, 시간 상한 없이 기다리는 것.
        try:
            states = task_states(pid, proc)
            if all_stopped(states):
                return
            # An unreaped daemon keeps its folder: a zombie has exited too.
            if states and all(state in ("Z", "X") for state in states):
                raise Blocked("bindfs exited before it stopped")
        except Vanished:
            pass
        except FileNotFoundError:
            # The task folder itself is gone: the daemon exited.
            if not (proc / str(pid)).exists():
                raise Blocked("bindfs exited before it stopped") from None
        if time.monotonic() > end:
            raise Blocked(f"bindfs did not stop within {STOP_TIMEOUT if timeout is None else timeout} s")
        _sleep(0.001)


@contextlib.contextmanager
def blocked_mount(base: pathlib.Path, prepare=lambda path: None):
    """Mount `base`/source on `base`/mount, call prepare(mount) while it answers, then stop the daemon.

    Yields the mount path once a probe lookup under it is seen to stall.
    Raises Blocked when the host cannot build the mount."""
    if sys.platform != "linux":
        raise Blocked("blocked FUSE mount needs Linux")
    for tool in ("bindfs", "fusermount3"):
        if not shutil.which(tool):
            raise Blocked(f"{tool} is not installed")
    if not os.path.exists("/dev/fuse"):
        raise Blocked("/dev/fuse is missing")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    source, mount = base / "source", base / "mount"
    source.mkdir(mode=0o700)
    mount.mkdir(mode=0o700)
    daemon = subprocess.Popen(["bindfs", "-f", "--no-allow-other", str(source), str(mount)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    is_stopped = False
    try:
        end = time.monotonic() + 5
        while not _mounted(mount):
            if daemon.poll() is not None:
                raise Blocked(f"bindfs exited {daemon.returncode}: {daemon.stderr.read().decode(errors='replace')}")
            if time.monotonic() > end:
                raise Blocked("bindfs did not mount within 5 s")
            time.sleep(0.01)
        prepare(mount)
        daemon.send_signal(signal.SIGSTOP)
        is_stopped = True
        # 이것을 실패시키는 것: 데몬 스레드가 모두 멈추기 전에 조회하는 것(먼저 읽힌 요청은 SIGKILL로도 끝나지 않음).
        wait_stopped(daemon.pid)
        # 이것을 실패시키는 것: 데몬을 멈추지 않아 마운트가 계속 응답하는 것(막히지 않은 fixture).
        probe = subprocess.Popen(["stat", str(mount / "probe")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            probe.wait(timeout=0.3)
            raise Blocked(f"a lookup under the stopped mount returned ({probe.returncode})")
        except subprocess.TimeoutExpired:
            probe.kill()
            probe.wait(timeout=5)
        yield mount
    finally:
        if is_stopped:
            daemon.send_signal(signal.SIGCONT)
        if _mounted(mount):
            # Bounded: an unmount that waits on the daemon must not hang the job.
            try:
                done = subprocess.run(["fusermount3", "-u", str(mount)], capture_output=True, timeout=10)
                lazy = done.returncode != 0
            except subprocess.TimeoutExpired:
                lazy = True
            if lazy:
                subprocess.run(["fusermount3", "-uz", str(mount)], capture_output=True, timeout=10)
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=5)
        daemon.stdout.close()
        daemon.stderr.close()
        assert not _mounted(mount), ("mount left behind", mount)
