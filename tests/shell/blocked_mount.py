"""A FUSE mount whose daemon is stopped: lookups under it wait without an answer.

bindfs runs in the foreground as this test's child, so the test owns the
daemon PID. SIGSTOP leaves the kernel waiting on a daemon that never replies;
SIGKILL still ends a process waiting there (the wait is killable), so this
fixture does not model an uninterruptible kernel wait. Linux only.
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
    stopped = False
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
        stopped = True
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
        if stopped:
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
