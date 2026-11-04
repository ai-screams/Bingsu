"""The command cgroup layer through the real helper, supervisor and relay (M6 C3, Linux).

These run in the privileged container cell (`BINGSU_CGROUP_CELL=priv`): the
atomic path needs a delegated cgroup v2 tree, which a default container
refuses (X-04). Elsewhere they skip; CI asserts each one PASSED in that cell."""
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest
from test_command_round import CommandSession, OTHER, SESSION, config, ready, supervisors, until

atomic_cell = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("BINGSU_CGROUP_CELL") != "priv",
    reason="needs the privileged cgroup cell (BINGSU_CGROUP_CELL=priv)")


def parent(session=SESSION):
    """The session's cgroup parent under this process's cgroup (the helper inherits it)."""
    line = next(l for l in Path("/proc/self/cgroup").read_text().splitlines() if l.startswith("0::"))
    digest = hashlib.sha256(session.encode()).digest()[:16].hex()
    return Path("/sys/fs/cgroup" + line[3:].rstrip("/")) / f"bingsu-cmd-{digest}"


def units(path):
    if not path.exists():
        return []
    return sorted(p.name for p in path.iterdir() if p.is_dir() and p.name.startswith("u") and len(p.name) == 17)


def alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def own_pid_unit(pidfile, seconds):
    """A unit that writes its pid, then waits (the same process)."""
    return config(["/bin/sh", "-c", f"echo $$ > {pidfile}; exec sleep {seconds}"], f"timeout='{seconds}s'\n")


def started(pidfile, timeout=4.0):
    assert until(lambda: pidfile.exists() and pidfile.read_text().strip(), timeout=timeout), "the unit never ran"
    return int(pidfile.read_text())


# 감독이 SIGKILL되면(도우미도 함께 죽어 그 회차의 정리가 없음) 같은 세션의 다음 도우미가 잠금 직후, 새 감독을
# 띄우기 전에 남은 단위 cgroup을 kill·제거한다. 이것을 실패시키는 것: prepare의 잠금 직후 회수를 지우는 것(옛
# 대상이 새 단위가 도는 동안에도 살아 있다).
@atomic_cell
def test_reclaim_after_supervisor_sigkill(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    session.put(own_pid_unit(pidfile, 3))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    session.prompt()
    old = started(pidfile)
    supervisor, helper = until(lambda: supervisors())[0]
    os.kill(helper, signal.SIGSTOP)
    os.kill(supervisor, signal.SIGKILL)
    os.kill(helper, signal.SIGKILL)
    leftover = units(parent())
    assert leftover and alive(old), "the old target must outlive its supervisor"
    pidfile.unlink()
    session.prompt()
    new = started(pidfile)
    # The reclaim ran under the lock, before this round's supervisor.
    assert new != old and not alive(old)
    assert not set(leftover) & set(units(parent()))
    session.wait_quiet(timeout=8)


# 대상이 자기 단위 cgroup 아래 하위 cgroup(깊이 2)을 만들어도, 그 회차가 끝나면(감독 reap 뒤 도우미의 회수)
# 세션 부모 아래 단위 폴더는 0이다. 이것을 실패시키는 것: Round::abandon의 감독 뒤 회수를 지우는 것(다음
# 회차까지 폴더가 남는다).
@atomic_cell
def test_round_removes_its_own_cgroups(tmp_path):
    session = CommandSession(tmp_path)
    made = session.base / "made"
    session.put(config(["/bin/sh", "-c",
                        "d=/sys/fs/cgroup$(cut -c4- /proc/self/cgroup); mkdir $d/a $d/a/b $d/c && touch " + str(made)],
                       "timeout='1s'\n"))
    ready(session)
    session.wait_quiet(timeout=8)
    assert made.exists(), "the unit made no nested cgroup"
    assert units(parent()) == []


# 회수는 잠금을 쥔 도우미만 한다. 살아 있는 감독의 명령은 같은 세션의 다음 프롬프트(잠금 경합)도, 다른
# 세션의 프롬프트도 건드리지 않는다. 이것을 실패시키는 것: 잠금을 얻기 전에 회수하는 것(prepare의 회수를
# close_only_lock 앞으로).
@atomic_cell
def test_reclaim_never_touches_live_supervisor(tmp_path):
    other = CommandSession(tmp_path / "b")
    other.session = OTHER
    other.put(own_pid_unit(other.base / "pid", 1))
    ready(other)
    other.wait_quiet(timeout=8)
    session = CommandSession(tmp_path / "a")
    pidfile = session.base / "pid"
    session.put(own_pid_unit(pidfile, 3))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    session.prompt()
    # Within the round's own helper lifetime (2 s), which ends the unit anyway.
    target = started(pidfile)
    session.prompt()
    time.sleep(0.3)
    assert alive(target), "a busy prompt of the same session reclaimed a live supervisor's unit"
    other.prompt()
    time.sleep(0.3)
    assert alive(target), "another session reclaimed this session's unit"
    session.wait_quiet(timeout=8)
    other.wait_quiet(timeout=8)


SURVIVOR = r"""
import os, sys, time
f, opened, go = sys.argv[1:4]
fd = os.open(f, os.O_RDONLY | os.O_DIRECT)
open(opened, "w").close()
while not os.path.exists(go):
    time.sleep(0.01)
os.read(fd, 4096)
time.sleep(60)
"""


def bindfs(source, mount):
    for tool in ("bindfs", "fusermount3"):
        if subprocess.run(["sh", "-c", f"command -v {tool}"], capture_output=True).returncode:
            return None
    mount.mkdir(mode=0o700)
    daemon = subprocess.Popen(["bindfs", "-f", "--no-allow-other", str(source), str(mount)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not until(lambda: any(l.split()[4] == str(mount) for l in Path("/proc/self/mountinfo").read_text().splitlines()),
                 timeout=5.0):
        daemon.kill()
        return None
    return daemon


# 살아 남은 자손: 멈춘 FUSE 데몬(이중 bindfs의 안쪽) 위 O_DIRECT read에 막힌 대상은 cgroup.kill 뒤에도 populated=1이라 그 회차의
# 회수는 단위 폴더를 남긴다. 데몬을 다시 살리면 같은 세션 다음 회수가 그 폴더를 제거한다(X-04). fixture가
# 서지 않으면(bindfs 없음, 대상이 막히지 않음) BLOCKED로 skip한다. 이것을 실패시키는 것: 회수를 지우는 것
# (prepare와 abandon 두 곳: 데몬 회복 뒤에도 폴더가 남는다).
@atomic_cell
def test_orphan_live_descendant_reclaimed(tmp_path):
    source = tmp_path / "src"
    source.mkdir(mode=0o700)
    (source / "f").write_bytes(os.urandom(1 << 20))
    # Two mounts: the outer daemon takes the read and waits on the stopped
    # inner one, so the target's request was already sent and cannot be
    # abandoned on SIGKILL (one stopped daemon leaves it pending, and a
    # pending request is dropped on a fatal signal).
    inner = bindfs(source, tmp_path / "i")
    daemon = inner and bindfs(tmp_path / "i", tmp_path / "m")
    if daemon is None:
        if inner:
            inner.kill()
        pytest.skip("BLOCKED: bindfs and /dev/fuse are needed for the survivor fixture")
    try:
        session = CommandSession(tmp_path / "s")
        opened, go = tmp_path / "opened", tmp_path / "go"
        script = tmp_path / "survivor.py"
        script.write_text(SURVIVOR)
        session.put(config(["/usr/bin/python3", str(script), str(tmp_path / "m" / "f"), str(opened), str(go)],
                           "timeout='1s'\n"))
        ready(session)
        session.wait_quiet(timeout=8)
        opened.unlink(missing_ok=True)
        go.unlink(missing_ok=True)
        session.prompt()
        assert until(lambda: opened.exists()), "the target never opened the file"
        inner.send_signal(signal.SIGSTOP)
        go.touch()
        session.wait_quiet(timeout=8)
        stuck = units(parent())
        if not stuck:
            pytest.skip("BLOCKED: the descendant did not survive cgroup.kill on this kernel and FUSE")
        inner.send_signal(signal.SIGCONT)
        go.unlink()
        session.prompt()
        session.wait_quiet(timeout=8)
        assert not set(stuck) & set(units(parent())), "the survivor's cgroup stayed after the daemon came back"
    finally:
        for d in (inner, daemon):
            d.send_signal(signal.SIGCONT)
            d.terminate()
        for m in ("m", "i"):
            subprocess.run(["fusermount3", "-uz", str(tmp_path / m)], capture_output=True)
