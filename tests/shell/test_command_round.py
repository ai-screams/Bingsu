"""Command rounds through the real helper, supervisor and relay (M6 C2, Linux).

The helper spawns the command supervisor before its own filter and grants it
the configured units only after the marker is installed; the supervisor
approves each unit again right before its relay spawn."""
import os
from pathlib import Path
import signal
import sys
import time

import pytest
from snapshot_support import SnapshotSession, require_native_boot

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the trusted relay runs on Linux only (C2 ruling J3)")

SESSION = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"


@pytest.fixture
def _native_boot_required():
    require_native_boot()


class CommandSession(SnapshotSession):
    """Prompts carry a session value, as the shell hooks pass one."""

    session = SESSION

    def prompt_args(self):
        return super().prompt_args() + ["--session", self.session]


def config(argv, extra=""):
    words = ", ".join(f"'{w}'" for w in argv)
    return (f"[segment.\"custom/probe\"]\nkind='command'\ncommand=[{words}]\n{extra}"
            "[layout.line2]\nleft=['custom/probe','char']\n")


def supervisors():
    """Live command supervisors (Linux /proc): pid and parent pid."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        if argv[1:2] == [b"__command-v1"]:
            found.append((int(entry.name), int(stat.rsplit(")", 1)[1].split()[1])))
    return found


def children(pid):
    out = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                stat = (entry / "stat").read_text()
            except OSError:
                continue
            if int(stat.rsplit(")", 1)[1].split()[1]) == pid:
                out.append(int(entry.name))
    return out


def until(check, timeout=4.0, step=0.01):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


def ready(session, canary=None):
    session.init()
    session.prompt()
    session.wait_quiet()
    return session


# 양성 대조: 설정 단위가 실제로 실행된다(도우미 → 감독 → 중계 → 대상). 이것을 실패시키는 것: 도우미가
# 표식 설치 뒤 허가를 보내지 않는 것(helper.rs의 round.grant 호출 삭제).
def test_configured_command_runs(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    canary = session.base / "ran"
    session.put(config(["/usr/bin/touch", str(canary)]))
    ready(session)
    assert until(lambda: (session.prompt(), canary.exists())[1]), "the unit never ran"
    session.wait_quiet()


# 이것을 실패시키는 것: 허가 단위를 고를 때 not_run을 거르지 않는 것(plan::runnable의 거름 삭제):
# 믿을 수 있는 레이아웃이 그리지 않는 단위(NotInTrustedLayout)도 실행된다.
def test_not_run_unit_never_runs(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    canary = session.base / "never"
    session.put(f"[segment.\"custom/probe\"]\nkind='command'\ncommand=['/usr/bin/touch', '{canary}']\n"
                "[layout.line2]\nleft=['char']\n")
    ready(session)
    for _ in range(5):
        session.prompt()
    session.wait_quiet()
    assert not canary.exists()


def lock_of(pid):
    """The session lock a supervisor holds at fd 5 (its name carries the session digest)."""
    try:
        return os.readlink(f"/proc/{pid}/fd/5")
    except OSError:
        return None


# U-15: 셸 세션마다 동시 감독은 하나다. 이것을 실패시키는 것: command_grant::prepare의 세션 잠금
# (close_only_lock)을 지우는 것(1초 걸리는 명령 동안 연속 프롬프트가 같은 세션의 감독을 여럿 띄운다).
def test_one_supervisor_per_session(tmp_path, _native_boot_required):
    sessions = []
    for name, value in (("a", SESSION), ("b", OTHER)):
        s = CommandSession(tmp_path / name)
        s.session = value
        s.put(config(["/bin/sleep", "1"], "timeout='1s'\n"))
        sessions.append(ready(s))
    most = {}
    for _ in range(10):
        for s in sessions:
            s.prompt()
        time.sleep(0.05)
        per = {}
        for pid, _ in supervisors():
            lock = lock_of(pid)
            if lock is not None:
                per[lock] = per.get(lock, 0) + 1
        for lock, n in per.items():
            most[lock] = max(most.get(lock, 0), n)
    for s in sessions:
        s.wait_quiet()
    # Each session ran one, and never two at once.
    assert len(most) == 2 and set(most.values()) == {1}, most


# 생존 신호(U-1): 출력 없는 대상도 도우미가 죽으면 끝난다. 이것을 실패시키는 것: 감독이 허가 파이프 EOF에서
# 자식을 끝내지 않는 것(read_grant_pipe의 stop 삭제): 대상이 자기 마감(1 s)까지 남는다.
def test_target_ends_soon_after_helper_death(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.put(config(["/bin/sleep", "5"], "timeout='1s'\n"))
    ready(session)
    session.prompt()
    found = until(lambda: [(s, p, c) for s, p in supervisors() for c in children(s)])
    assert found, "no running target"
    supervisor, helper, target = found[0]
    os.kill(helper, signal.SIGKILL)
    killed = time.monotonic()
    gone = until(lambda: not Path(f"/proc/{target}").exists()
                 or Path(f"/proc/{target}/stat").read_text().split()[2] == "Z", timeout=2.0)
    took = time.monotonic() - killed
    assert gone and took < 0.5, took
    until(lambda: not any(s == supervisor for s, _ in supervisors()), timeout=2.0)
    session.wait_quiet()
