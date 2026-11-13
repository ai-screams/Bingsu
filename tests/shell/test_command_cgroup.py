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
from test_command_round import CommandSession, OTHER, config, lock_of, ready, supervisors, until

atomic_cell = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("BINGSU_CGROUP_CELL") != "priv",
    reason="needs the privileged cgroup cell (BINGSU_CGROUP_CELL=priv)")


def parent(cs):
    """The session's cgroup parent under this process's cgroup (the helper inherits it): its
    digest covers the runtime root's (dev, ino), where the session lock lives, and the session."""
    line = next(l for l in Path("/proc/self/cgroup").read_text().splitlines() if l.startswith("0::"))
    root = os.stat(cs.neutral().parent)
    key = root.st_dev.to_bytes(8, "little") + root.st_ino.to_bytes(8, "little") + b"\0" + cs.session.encode()
    digest = hashlib.sha256(key).digest()[:16].hex()
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
    supervisor, helper = until(lambda: supervisors(session))[0]
    os.kill(helper, signal.SIGSTOP)
    os.kill(supervisor, signal.SIGKILL)
    os.kill(helper, signal.SIGKILL)
    leftover = units(parent(session))
    assert leftover and alive(old), "the old target must outlive its supervisor"
    pidfile.unlink()
    session.prompt()
    new = started(pidfile)
    # The reclaim ran under the lock, before this round's supervisor.
    assert new != old and not alive(old)
    assert not set(leftover) & set(units(parent(session)))
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
    assert units(parent(session)) == []


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
        stuck = units(parent(session))
        if not stuck:
            pytest.skip("BLOCKED: the descendant did not survive cgroup.kill on this kernel and FUSE")
        inner.send_signal(signal.SIGCONT)
        go.unlink()
        session.prompt()
        session.wait_quiet(timeout=8)
        assert not set(stuck) & set(units(parent(session))), "the survivor's cgroup stayed after the daemon came back"
    finally:
        for d in (inner, daemon):
            d.send_signal(signal.SIGCONT)
            d.terminate()
        for m in ("m", "i"):
            subprocess.run(["fusermount3", "-uz", str(tmp_path / m)], capture_output=True)


# 최선 노력 경로(위임 cgroup 없음, 기본 셀): 마감에 감독이 필터 아래에서 중계의 그룹에 SIGKILL을 보내, 대상이
# setsid 없이 남긴 자손도 끝난다. 원자 경로의 셀에서도 같은 결과다(cgroup.kill). 이것을 실패시키는 것: 감독
# 필터의 kill 그룹 블록에서 쥔 그룹 비교를 지우는 것(모든 kill이 EPERM이 되어 자손이 남음).
@pytest.mark.skipif(sys.platform != "linux", reason="the trusted relay runs on Linux only")
def test_best_effort_group_kill_under_the_filter(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    session.put(config(["/bin/sh", "-c", f"sleep 60 & echo $! > {pidfile}; exec sleep 5"], "timeout='1s'\n"))
    ready(session)
    session.wait_quiet(timeout=8)
    descendant = started(pidfile)
    assert until(lambda: not alive(descendant), timeout=2.0), "the target's descendant outlived its unit"


def leave_a_live_unit(session, pidfile, seconds=3):
    """Kill a running round's supervisor and helper: its unit keeps running in its cgroup."""
    session.prompt()
    old = started(pidfile)
    supervisor, helper = until(lambda: supervisors(session))[0]
    os.kill(helper, signal.SIGSTOP)
    os.kill(supervisor, signal.SIGKILL)
    os.kill(helper, signal.SIGKILL)
    return old


# 잠금과 cgroup 부모가 같은 정체에 묶인다: 같은 세션 값이라도 런타임 뿌리가 다른 helper는 잠금도 부모도
# 따로라 서로의 살아 있는 단위를 회수하지 않는다. 이것을 실패시키는 것: 부모 이름 요약에서 런타임 뿌리를 빼는
# 것(다른 잠금을 쥔 helper가 같은 부모를 회수해 살아 있는 대상을 죽임).
@atomic_cell
def test_runtime_roots_never_share_a_cgroup_parent(tmp_path):
    a = CommandSession(tmp_path / "a")
    b = CommandSession(tmp_path / "b")
    for s in (a, b):
        s.put(own_pid_unit(s.base / "pid", 3))
        ready(s)
        s.wait_quiet(timeout=8)
        (s.base / "pid").unlink(missing_ok=True)
    assert a.session == b.session and parent(a) != parent(b)
    a.prompt()
    target = started(a.base / "pid")
    b.prompt()
    time.sleep(0.3)
    assert alive(target), "a helper with another runtime root reclaimed this round's live unit"
    a.wait_quiet(timeout=8)
    b.wait_quiet(timeout=8)


# 회차 끝 회수는 감독의 reap을 확인했을 때만 한다. 마감까지 멈춰 있던 감독의 회차는 회수하지 않고, 그 감독이
# 끝난 뒤 같은 세션 다음 helper가 잠금 직후 회수한다. 이것을 실패시키는 것: Round::end의 회수를 wait의 결과와
# 무관하게 하는 것(멈춘 감독의 단위가 그 회차에 제거됨).
@atomic_cell
def test_round_end_reclaims_only_after_the_supervisor_is_reaped(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    session.put(own_pid_unit(pidfile, 3))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    session.prompt()
    target = started(pidfile)
    supervisor, _ = until(lambda: [(s, p) for s, p in supervisors(session) if lock_of(s) is not None])[0]
    os.kill(supervisor, signal.SIGSTOP)
    session.wait_quiet(timeout=8)
    assert units(parent(session)) and alive(target), "a round reclaimed without reaping its supervisor"
    # Still stopped, it holds the session lock; once it runs again it ends
    # its unit, and the next round's reclaim under the lock removes it.
    os.kill(supervisor, signal.SIGCONT)
    assert until(lambda: not alive(supervisor), timeout=3.0)
    pidfile.unlink()
    session.prompt()
    started(pidfile)
    assert not alive(target)
    session.wait_quiet(timeout=8)


# 회수는 잠금 바로 다음, 중립 폴더 검사 같은 조기 반환보다 앞이다. 이것을 실패시키는 것: prepare의 회수를 중립
# 폴더 검사 뒤로 옮기는 것(모든 단위가 중립 폴더라 그 회차가 Skip::Neutral로 끝나고 잔여물이 남음).
@atomic_cell
def test_reclaim_runs_before_the_neutral_check(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    session.put(own_pid_unit(pidfile, 3))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    old = leave_a_live_unit(session, pidfile)
    (session.neutral() / "stray").write_text("x")
    session.prompt()
    assert until(lambda: not alive(old), timeout=2.0), "a round refused by its neutral folder left the leftovers"
    session.wait_quiet(timeout=8)


# 원자 경로의 감독은 fd 6(세션 cgroup 부모)을 close-on-exec로 쥔다. 그래서 clone3로 띄운 중계에도, 그
# 대상에도 넘어가지 않는다(대상 {0,1,2}). 이것을 실패시키는 것: 감독 run()의 fd 6 FD_CLOEXEC 설정을 지우는 것.
@atomic_cell
def test_supervisor_keeps_its_cgroup_parent_from_children(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    session.put(own_pid_unit(pidfile, 3))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    session.prompt()
    target = started(pidfile)
    supervisor, _ = until(lambda: [(s, p) for s, p in supervisors(session) if lock_of(s) is not None])[0]
    flags = next(l for l in Path(f"/proc/{supervisor}/fdinfo/6").read_text().splitlines() if l.startswith("flags:"))
    fds = sorted(int(n) for n in os.listdir(f"/proc/{target}/fd"))
    assert int(flags.split()[1], 8) & os.O_CLOEXEC, flags
    assert fds == [0, 1, 2], fds
    session.wait_quiet(timeout=8)


# 후보가 없는 회차라도 설정에 명령 단위가 있으면 잠금 직후 회수한다(C4 판정 Q4). 감독 SIGKILL로 남은 대상은, 그
# 단위가 화면에서 빠져(not_run) 실행할 것이 없는 다음 프롬프트에서 끝난다. 이것을 실패시키는 것: prepare의
# 후보 없는 회차 회수를 지우는 것(남은 대상이 계속 산다). 명령 단위가 아예 없는 설정은 잠금도 회수도 하지
# 않는다(test_command_round.py::test_round_without_units_starts_no_supervisor).
@atomic_cell
def test_reclaim_without_candidates(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    unit = ["/bin/sh", "-c", f"echo $$ > {pidfile}; exec sleep 3"]
    session.put(config(unit, "timeout='3s'\n"))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    old = leave_a_live_unit(session, pidfile)
    words = ", ".join(f"'{w}'" for w in unit)
    session.put(f"[segment.\"custom/probe\"]\nkind='command'\ncommand=[{words}]\ntimeout='3s'\n"
                "[layout.line2]\nleft=['char']\n")
    session.prompt()
    assert until(lambda: not alive(old), timeout=2.0), "a round without candidates left the leftovers"
    session.wait_quiet(timeout=8)


# 환경 frame이 없는 회차(앞단이 70 KB 환경을 넘기지 않음)도 실행할 단위가 있으면 잠금 직후 회수한다. 이것을
# 실패시키는 것: prepare에서 환경 확인을 잠금·회수 앞으로 되돌리는 것(남은 대상이 계속 산다).
@atomic_cell
def test_reclaim_without_an_environment(tmp_path):
    session = CommandSession(tmp_path)
    pidfile = session.base / "pid"
    session.put(config(["/bin/sh", "-c", f"echo $$ > {pidfile}; exec sleep 3"], "timeout='3s'\n"))
    ready(session)
    session.wait_quiet(timeout=8)
    pidfile.unlink(missing_ok=True)
    old = leave_a_live_unit(session, pidfile)
    session.env["BINGSU_BIG"] = "x" * (70 * 1024)
    session.prompt()
    assert until(lambda: not alive(old), timeout=2.0), "a round without an environment left the leftovers"
    session.wait_quiet(timeout=8)
