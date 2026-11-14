"""Command rounds through the real helper, supervisor and relay (M6 C2, Linux and macOS).

The helper spawns the command supervisor before its own filter and grants it
the configured units only after the marker is installed; the supervisor
approves each unit again right before its relay spawn."""
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest
from blocked_mount import blocked_mount
from shell_support import Blocked, real_collector
from snapshot_support import SnapshotSession, require_native_boot

# Process and file-descriptor views below come from /proc on Linux and from
# ps and lsof on macOS. A test that needs a Linux-only fact (a FUSE mount,
# no_new_privs) is marked so.
linux_only = pytest.mark.skipif(sys.platform != "linux", reason="needs a Linux-only fact")
macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="the macOS relay and script copies")

SESSION = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"


@pytest.fixture
def _native_boot_required():
    require_native_boot()


class CommandSession(SnapshotSession):
    """Prompts carry a session value, as the shell hooks pass one; `level`
    switches the helper's log on (refresh.log under the pinned log root)."""

    session = SESSION
    level = "off"
    pwd = None

    def prompt_args(self):
        args = super().prompt_args() + (["--session", self.session] if self.session else [])
        # The pinned collector, as the shell hook passes one, so the
        # collection runs and its folder facts reach the round. A session that
        # adds init's pin itself (LifetimeSession) keeps its one word.
        if not hasattr(self, "collector_word"):
            args.append(f"--collector-exe={real_collector()}")
        if self.pwd is not None:
            args[args.index("--pwd") + 1] = str(self.pwd)
        return [f"--log-level={self.level}" if a == "--log-level=off" else a for a in args]

    def log(self):
        root = next(w.split("=", 1)[1] for w in self.words if w.startswith("--log-root="))
        path = Path(root) / "refresh.log"
        return path.read_bytes() if path.exists() else b""

    def neutral(self):
        return Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu" / "neutral"


def config(argv, extra=""):
    words = ", ".join(f"'{w}'" for w in argv)
    return (f"[segment.\"custom/probe\"]\nkind='command'\ncommand=[{words}]\n{extra}"
            "[layout.line2]\nleft=['custom/probe','char']\n")


def processes():
    """Live processes: (pid, parent pid, state letter, argv words)."""
    found = []
    if sys.platform != "linux":
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,state=,args="], capture_output=True, text=True).stdout
        for line in out.splitlines():
            words = line.split()
            if len(words) >= 4:
                found.append((int(words[0]), int(words[1]), words[2][0], words[3:]))
        return found
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        fields = stat.rsplit(")", 1)[1].split()
        found.append((int(entry.name), int(fields[1]), fields[0],
                      [w.decode(errors="replace") for w in argv if w]))
    return found


def supervisors(session):
    """`session`'s live command supervisors: pid and parent pid. A
    supervisor's parent is the helper that spawned it, and that helper's argv
    carries the session's pinned runtime root, so supervisors of other test
    runs on the same machine are never signalled. A supervisor whose helper
    has died is not listed: ask `gone(pid)` about one already found."""
    root = next(w for w in session.words if w.startswith("--runtime-root="))
    found = processes()
    helpers = {pid for pid, _, _, argv in found if argv[1:2] == ["__refresh-v1"] and root in argv}
    return [(pid, ppid) for pid, ppid, _, argv in found
            if argv[1:2] == ["__command-v1"] and ppid in helpers]


def children(pid):
    return [p for p, ppid, _, _ in processes() if ppid == pid]


def gone(pid):
    """Whether `pid` has exited (a zombie counts)."""
    return not any(p == pid and state != "Z" for p, _, state, _ in processes())


def until(check, timeout=4.0, step=0.01):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


def forget_results(session):
    """Removes the published command responses of this session's context, so
    the next prompt runs its units again: a unit that runs past its timeout
    (as the tests here use to keep a target alive) is a failure the response
    keeps for 10 s (C4)."""
    root = Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu"
    for path in root.rglob("collections-v1/*/store/command"):
        path.unlink()


def ready(session, canary=None):
    """Init and one settled round; its command results are forgotten, so a
    test's first prompt runs its units."""
    session.init()
    session.prompt()
    session.wait_quiet()
    forget_results(session)
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


# 명령 회차 시험의 세션도 실제 셸처럼 collector를 넘겨 수집을 돌린다(기본 테마의 첫 줄이 git을
# 그려 수집을 요청한다). 수집이 없으면 회차가 셸 폴더를 저장소 대신 쓰는 경로만 시험된다. 이것을 실패시키는 것:
# CommandSession이 collector를 넘기지 않는 것("collection unsafe", 수집 응답 없음).
def test_command_session_runs_the_collection(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.level = "debug"
    session.put(config(["/usr/bin/true"]))
    ready(session)
    responses = lambda: list(session.store().glob("collections-v1/*/store/response"))
    assert until(lambda: (session.prompt(), session.wait_quiet(), responses())[2]), session.log()
    assert b"collection unsafe" not in session.log()


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
    if sys.platform != "linux":
        # -b -w: without them lsof took about 0.9 s per call on a Mac, longer
        # than the supervisor of a 1 s unit lives, so it read nothing.
        out = subprocess.run(["lsof", "-b", "-w", "-a", "-p", str(pid), "-d", "5", "-Fn"],
                             capture_output=True, text=True).stdout
        return next((line[1:] for line in out.splitlines() if line.startswith("n")), None)
    try:
        return os.readlink(f"/proc/{pid}/fd/5")
    except OSError:
        return None


# 감독 찾기는 시험이 띄운 세션의 것만 고른다: 같은 기계에서 도는 다른 시험(다른 팀원의 실행 포함)의 감독에
# SIGKILL·SIGSTOP을 보내지 않게. 이것을 실패시키는 것: supervisors가 helper의 런타임 뿌리를 보지 않는 것(두 세션의
# 감독이 서로의 목록에 섞임).
def test_supervisor_lookup_sees_only_its_session(tmp_path, _native_boot_required):
    sessions = []
    for name, value in (("a", SESSION), ("b", OTHER)):
        s = CommandSession(tmp_path / name)
        s.session = value
        s.put(config(["/bin/sleep", "1"], "timeout='1s'\n"))
        sessions.append(ready(s))
    a, b = sessions
    a.prompt()
    b.prompt()
    both = until(lambda: (supervisors(a), supervisors(b)) if supervisors(a) and supervisors(b) else None)
    assert both, "each session runs a supervisor"
    mine, theirs = both
    assert not {pid for pid, _ in mine} & {pid for pid, _ in theirs}, both
    for s in sessions:
        s.wait_quiet()


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
        for pid, _ in (sup for s in sessions for sup in supervisors(s)):
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
    found = until(lambda: [(s, p, c) for s, p in supervisors(session) for c in children(s)])
    assert found, "no running target"
    supervisor, helper, target = found[0]
    os.kill(helper, signal.SIGKILL)
    killed = time.monotonic()
    ended = until(lambda: gone(target), timeout=2.0)
    took = time.monotonic() - killed
    assert ended and took < 0.5, took
    until(lambda: gone(supervisor), timeout=2.0)
    session.wait_quiet()


# 세션 잠금은 감독이 사는 동안 풀리지 않는다(감독이 close-only 사본을 쥔다). 이것을 실패시키는 것: 감독에
# 잠금 사본을 넘기지 않는 것(spawn_supervisor의 fd 5 dup 삭제): 도우미가 죽으면 잠금이 풀려 같은 세션에
# 둘째 감독이 뜬다.
def test_lock_held_while_supervisor_alive(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.put(config(["/bin/sleep", "1"], "timeout='1s'\n"))
    ready(session)
    session.prompt()
    found = until(lambda: [(s, p) for s, p in supervisors(session) if lock_of(s) is not None])
    assert found, "no supervisor"
    supervisor, helper = found[0]
    os.kill(supervisor, signal.SIGSTOP)
    try:
        os.kill(helper, signal.SIGKILL)
        until(lambda: gone(helper), timeout=2.0)
        session.wait_quiet()
        session.prompt()
        session.wait_quiet()
        others = [s for s, _ in supervisors(session) if s != supervisor]
        assert others == [], "a second supervisor while the first holds the lock"
    finally:
        os.kill(supervisor, signal.SIGCONT)
    # It sees the helper gone (end of file), ends its child and exits.
    assert until(lambda: gone(supervisor), timeout=3.0)
    session.prompt()
    assert until(lambda: supervisors(session)), "the next prompt starts a supervisor again"
    session.wait_quiet()


# 실행 파일 해석(PATH 정제, 셸 폴더)은 표식 설치 뒤에 한다. 멈춘 마운트 위의 PATH 항목에 막혀도 표식은
# 매 회차 갱신된다. 이것을 실패시키는 것: 허가 단위 해석(command_grant::units)을 broker 안의 prepare로
# 옮기는 것(도우미가 표식 전에 막히고 watchdog이 끝내 표식이 그대로).
@linux_only
def test_blocked_path_entry_never_holds_the_marker(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    session.put(config(["probe-cmd"]))
    ready(session)
    marker = session.store() / "marker"
    try:
        with blocked_mount(tmp_path / "fuse") as mount:
            session.env["PATH"] = f"{mount}/bin:" + session.env["PATH"]
            before = marker.read_bytes()
            session.prompt()
            assert until(lambda: marker.read_bytes() != before, timeout=3.0), "the marker was held back"
            session.wait_quiet(timeout=6)
    except Blocked as error:
        pytest.skip(str(error))


def script(path, body):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o700)


# J9: 같은 회차 수집이 알린 저장소 루트가 PATH 정제의 저장소다. 셸이 저장소 하위 폴더에 있어도 루트 아래
# bin은 빠진다. U-24부터는 셸 폴더 위의 `.git` 조상도 저장소라, 수집이 이 회차에 끝나지 않아도 결과가 같다.
# 이것을 실패시키는 것: 저장소 규칙에서 수집 루트와 조상 검사를 둘 다 지우는 것(셸 폴더로 대체되어 루트 바로 아래
# bin이 남음).
def test_collected_repo_root_excludes_its_bin(tmp_path, _native_boot_required):
    from test_helper_lifecycle import LifetimeSession

    class Session(LifetimeSession, CommandSession):
        pass

    repo = tmp_path / "repo"
    sub = repo / "sub"
    sub.mkdir(parents=True, mode=0o700)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    canary = tmp_path / "ran"
    script(repo / "bin" / "probe-cmd", f"touch '{canary}'")
    other = tmp_path / "other"
    outside = tmp_path / "outside"
    script(other / "bin" / "probe-out", f"touch '{outside}'")
    session = Session(tmp_path / "s")
    session.level = "debug"
    session.env["PATH"] = f"{repo}/bin:{other}/bin:" + session.env["PATH"]
    session.put(f"[segment.\"custom/a\"]\nkind='command'\ncommand=['probe-cmd']\n"
                f"[segment.\"custom/b\"]\nkind='command'\ncommand=['probe-out']\n"
                "[layout.line2]\nleft=['custom/a','custom/b','char']\n")
    session.init()
    session.wait_quiet()
    session.pwd = sub
    session.prompt()
    session.wait_quiet()
    assert outside.exists(), ("the control unit never ran", session.log())
    assert not canary.exists(), ("a PATH folder under the collected repository root ran", session.log())


# U-24: 수집 세그먼트를 그리지 않는 설정은 어느 회차에도 수집 루트가 없다. 그래도 셸 폴더 위에서 `.git`을 가진
# 조상(바깥 저장소와 그 안의 저장소 모두)은 저장소라, 그 아래 PATH 폴더의 명령은 돌지 않는다. 양성 대조: 저장소
# 밖 폴더의 같은 명령은 돈다. 이것을 실패시키는 것: 명령 회차에서 조상 검사를 지우는 것, 가장 가까운 저장소에서
# 멈추는 것(바깥 저장소의 bin이 돈다).
def test_repository_bins_stay_out_without_a_collection(tmp_path, _native_boot_required):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    sub = inner / "sub"
    sub.mkdir(parents=True, mode=0o700)
    subprocess.run(["git", "init", "-q", str(outer)], check=True)
    subprocess.run(["git", "init", "-q", str(inner)], check=True)
    ran_outer, ran_inner, outside = tmp_path / "ran-outer", tmp_path / "ran-inner", tmp_path / "outside"
    script(outer / "bin" / "probe-outer", f"touch '{ran_outer}'")
    script(inner / "bin" / "probe-inner", f"touch '{ran_inner}'")
    script(tmp_path / "other" / "bin" / "probe-out", f"touch '{outside}'")
    session = CommandSession(tmp_path / "s")
    session.level = "debug"
    session.env["PATH"] = f"{outer}/bin:{inner}/bin:{tmp_path}/other/bin:" + session.env["PATH"]
    session.put("[segment.\"custom/a\"]\nkind='command'\ncommand=['probe-outer']\n"
                "[segment.\"custom/b\"]\nkind='command'\ncommand=['probe-inner']\n"
                "[segment.\"custom/c\"]\nkind='command'\ncommand=['probe-out']\n"
                "[layout.line1]\nleft=['custom/a','custom/b','custom/c','char']\n")
    session.pwd = sub
    ready(session)
    for _ in range(2):
        session.prompt()
    session.wait_quiet()
    assert until(lambda: outside.exists()), ("the control unit never ran", session.log())
    assert not ran_outer.exists() and not ran_inner.exists(), ("a repository's PATH folder ran", session.log())


# U-24 L1: 셸이 저장소 안의 링크(`docs -> 바깥 폴더`)로 들어가면 실제 폴더에는 `.git` 조상이 없지만, 셸이 준 경로의
# 접두사인 저장소는 여전히 저장소다. 절대 경로로 PATH에 넣은 저장소 bin(direnv의 PATH_add 같은)은 돌지 않는다.
# 이것을 실패시키는 것: 명령 회차의 조상 검사에서 셸 경로 접두사 검사를 지우는 것(실제 폴더만 보아 저장소 bin이 돈다).
def test_a_repository_link_to_elsewhere_keeps_its_bin_out(tmp_path, _native_boot_required):
    repo = tmp_path / "repo"
    elsewhere = tmp_path / "elsewhere"
    repo.mkdir(mode=0o700)
    elsewhere.mkdir(mode=0o700)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "docs").symlink_to(elsewhere)
    ran, outside = tmp_path / "ran", tmp_path / "outside"
    script(repo / "bin" / "probe-cmd", f"touch '{ran}'")
    script(tmp_path / "other" / "bin" / "probe-out", f"touch '{outside}'")
    session = CommandSession(tmp_path / "s")
    session.level = "debug"
    session.env["PATH"] = f"{repo}/bin:{tmp_path}/other/bin:" + session.env["PATH"]
    session.put("[segment.\"custom/a\"]\nkind='command'\ncommand=['probe-cmd']\n"
                "[segment.\"custom/b\"]\nkind='command'\ncommand=['probe-out']\n"
                "[layout.line1]\nleft=['custom/a','custom/b','char']\n")
    session.pwd = repo / "docs"
    ready(session)
    for _ in range(2):
        session.prompt()
    session.wait_quiet()
    assert until(lambda: outside.exists()), ("the control unit never ran", session.log())
    assert not ran.exists(), ("the repository's bin ran through its link", session.log())


# J9 대체: 수집 루트가 없으면 셸 폴더가 저장소를 대신한다. 이것을 실패시키는 것: units()의 repo_id를
# 늘 None으로 하는 것(셸 폴더 아래 bin의 실행 파일이 돈다). 양성 대조: 저장소 밖 폴더의 같은 명령은 돈다.
def test_shell_folder_stands_for_the_repository(tmp_path, _native_boot_required):
    proj = tmp_path / "proj"
    other = tmp_path / "other"
    proj.mkdir(mode=0o700)
    inside, outside = tmp_path / "inside", tmp_path / "outside"
    script(proj / "bin" / "probe-cmd", f"touch '{inside}'")
    script(other / "bin" / "probe-out", f"touch '{outside}'")
    session = CommandSession(tmp_path / "s")
    session.env["PATH"] = f"{proj}/bin:{other}/bin:" + session.env["PATH"]
    session.put(f"[segment.\"custom/a\"]\nkind='command'\ncommand=['probe-cmd']\n"
                f"[segment.\"custom/b\"]\nkind='command'\ncommand=['probe-out']\n"
                "[layout.line2]\nleft=['custom/a','custom/b','char']\n")
    session.pwd = proj
    ready(session)
    for _ in range(2):
        session.prompt()
    session.wait_quiet()
    assert until(lambda: outside.exists()), "the control unit outside the shell folder never ran"
    assert not inside.exists(), "a PATH folder under the shell folder ran"


def neutral_round(tmp_path, damage):
    session = CommandSession(tmp_path / "s")
    session.level = "info"
    canary = tmp_path / "ran"
    session.put(config(["/usr/bin/touch", str(canary)]))
    session.init()
    session.wait_quiet()
    folder = session.neutral()
    # Made before the first round, as someone else's leftovers would be.
    if damage == "file":
        folder.mkdir(mode=0o700)
        (folder / "left").write_text("x")
        folder.chmod(0o500)
    elif damage == "0700":
        folder.mkdir(mode=0o700)
        folder.chmod(0o700)
    elif damage == "owner":
        folder.mkdir(mode=0o700)
        folder.chmod(0o500)
        os.chown(folder, 65534, 65534)
    for _ in range(3):
        session.prompt()
    session.wait_quiet()
    return session, canary


# K2: 중립 폴더는 비어 있고 내 것이고 정확히 0500일 때만 neutral 단위가 돈다. 이것을 실패시키는 것:
# neutral()의 빈 폴더 검사를 지우는 것(file), 모드 비교를 지우는 것(0700), 소유자 비교를 지우는 것
# (owner, root만 다른 소유자로 바꿀 수 있다). 양성 대조: 손대지 않은 폴더(ok).
@pytest.mark.parametrize("damage", ["ok", "file", "0700", "owner"])
def test_neutral_folder_must_be_empty_and_0500(tmp_path, damage, _native_boot_required):
    if damage == "owner" and os.geteuid() != 0:
        pytest.skip("only root can hand the folder to another user")
    session, canary = neutral_round(tmp_path, damage)
    if damage == "ok":
        assert canary.exists()
        assert oct(session.neutral().stat().st_mode & 0o7777) == "0o500"
    else:
        assert not canary.exists()
        assert b"neutral folder is not empty" in session.log(), session.log()


# K2: 단위는 중립 폴더에 아무것도 남기지 못한다(쓰기 권한 없음, EACCES). root는 모드를 무시하므로 건너뛴다.
# 이것을 실패시키는 것: 중립 폴더를 0700으로 만드는 것(set_permissions의 0o500).
@pytest.mark.skipif(os.geteuid() == 0, reason="root writes through 0500")
def test_unit_cannot_write_in_the_neutral_folder(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    denied = tmp_path / "denied"
    session.put(config(["/bin/sh", "-c", f'touch left || touch "{denied}"']))
    ready(session)
    session.prompt()
    session.wait_quiet()
    assert until(lambda: denied.exists()), "the unit never tried"
    assert list(session.neutral().iterdir()) == []


# 자손이 stdout을 쥐고 있어도 도우미 회차는 대상이 끝나면 끝난다(감독은 stdout EOF를 기다리지 않음).
# 이것을 실패시키는 것: Run::finished가 stdout EOF까지 기다리게 하는 것(회차가 자손의 3초를 기다림).
def test_stdout_holder_does_not_block_prompt(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    session.put(config(["/bin/sh", "-c", "/bin/sleep 3 & echo held"]))
    ready(session)
    started = time.monotonic()
    session.prompt()
    prompt_s = time.monotonic() - started
    session.wait_quiet(timeout=10)
    round_s = time.monotonic() - started
    assert prompt_s < 0.5, prompt_s
    # Well before the helper's 2 s deadline, where a wait on stdout would end.
    assert round_s < 1.0, round_s


# macOS에서도 단위마다 프로세스는 하나다: 감독의 자식은 단위 수와 같고 각각 이미 대상이며 자식이 없다. 그리고 회차
# 로그에 relay가 없다는 거부가 없다. 이것을 실패시키는 것: macOS에서 prepare가 Skip::NoRelay를 내는 것(감독이 뜨지
# 않음), relay가 대상을 자식으로 띄우는 것(감독의 자식이 bingsu), Scripts가 스크립트 없는 회차에도 폴더를 여는 것.
@macos_only
def test_macos_unit_is_one_process_the_relay_execs_into(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    session.level = "info"
    units = "".join(f"[segment.\"custom/u{i}\"]\nkind='command'\ncommand=['/bin/sleep', '1']\ntimeout='1s'\n"
                    for i in range(3))
    session.put(units + "[layout.line2]\nleft=['custom/u0','custom/u1','custom/u2','char']\n")
    ready(session)
    session.prompt()

    def running():
        table = processes()
        for pid, _ in supervisors(session):
            kids = [(p, argv) for p, ppid, state, argv in table if ppid == pid and state != "Z"]
            if len(kids) == 3 and all(argv == ["/bin/sleep", "1"] for _, argv in kids):
                return [p for p, _ in kids]
        return None

    kids = until(running, timeout=2.0)
    assert kids, [(s, children(s)) for s, _ in supervisors(session)]
    for k in kids:
        assert children(k) == [], "a target has a child of its own"
    session.wait_quiet()
    assert b"no trusted relay" not in session.log(), session.log()
    # The scripts folder is made at a round's first script only.
    assert not scripts_folder(session).exists()


def alive_pid(pidfile):
    """The pid a unit wrote, once it has written it."""
    text = pidfile.read_text().strip() if pidfile.exists() else ""
    return int(text) if text.isdigit() else None


# C3 판정 R6(macOS 최선 노력 종료): relay는 자기 프로세스 그룹을 이끌고, 대상이 끝나면 reap 전에 그 그룹을 끝낸다.
# 그래서 대상이 남긴 같은 그룹의 손자는 회차가 끝나면 없다. 이것을 실패시키는 것: OwnedChild::reap_group의 killpg를
# 지우는 것(손자 sleep 30이 남음), relay 생성의 POSIX_SPAWN_SETPGROUP을 지우는 것.
@macos_only
def test_macos_group_grandchild_ends_with_the_round(tmp_path, _native_boot_required):
    pidfile = tmp_path / "grandchild"
    session = CommandSession(tmp_path / "s")
    session.put(config(["/bin/sh", "-c", f"/bin/sleep 30 & echo $! > {pidfile}"]))
    ready(session)
    session.prompt()
    pid = until(lambda: alive_pid(pidfile))
    assert pid, "the unit never ran"
    session.wait_quiet()
    assert until(lambda: gone(pid), timeout=1.0), "a grandchild in the relay's group outlived the round"


# C3 판정 R6: helper가 죽어 감독이 회차를 멈춰도 대상의 종료를 reap하기 전에 그룹을 끝낸다. 이것을 실패시키는 것:
# OwnedChild::reap_group의 killpg를 지우는 것, relay 생성의 POSIX_SPAWN_SETPGROUP을 지우는 것(손자가 감독의 그룹 밖).
@macos_only
def test_macos_group_grandchild_ends_when_the_helper_dies(tmp_path, _native_boot_required):
    pidfile = tmp_path / "grandchild"
    session = CommandSession(tmp_path / "s")
    session.put(config(["/bin/sh", "-c", f"/bin/sleep 30 & echo $! > {pidfile}; /bin/sleep 30"], "timeout='1s'\n"))
    ready(session)
    session.prompt()
    pid = until(lambda: alive_pid(pidfile))
    assert pid, "the unit never ran"
    found = until(lambda: supervisors(session))
    assert found, "no supervisor"
    os.kill(found[0][1], signal.SIGKILL)
    assert until(lambda: gone(pid), timeout=0.5), "a grandchild outlived the helper's death"
    session.wait_quiet()


def scripts_folder(session):
    return Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu" / "scripts"


def session_tag(value):
    return hashlib.sha256(value.encode()).hexdigest()[:32]


# C2 판정 Q1: macOS 스크립트 단위는 helper가 만든 사본으로 돌고, 감독이 끝나면 사본은 지워진다. 이것을
# 실패시키는 것: Round::end의 remove_all 호출을 지우는 것(사본이 남음), 사본 대신 원본 경로를 허가에 넣는 것
# (relay가 0600이 아닌 원본을 거부해 카나리가 없음).
@macos_only
def test_macos_script_runs_from_a_copy_that_is_then_removed(tmp_path, _native_boot_required):
    canary = tmp_path / "ran"
    tool = tmp_path / "bin" / "tool"
    script(tool, f"touch '{canary}'")
    session = CommandSession(tmp_path / "s")
    session.put(config([str(tool)]))
    ready(session)
    assert until(lambda: (session.prompt(), canary.exists())[1]), "the script never ran"
    session.wait_quiet()
    assert list(scripts_folder(session).iterdir()) == []


# C2 판정 Q1: 감독이 살아 있는 동안 helper가 끝나면 사본은 남고, 같은 세션의 다음 회차(세션 잠금을 얻은
# helper)가 지운다. 다른 세션 태그의 파일은 남는다. 이것을 실패시키는 것: Round::end의 wait 결과 검사를 지우는
# 것(멈춘 감독 아래 사본이 지워짐), prepare의 sweep을 지우는 것(남은 사본이 그대로), sweep의 접두사 비교를 지우는 것.
@macos_only
def test_macos_copy_outlives_a_stopped_supervisor_until_the_sweep(tmp_path, _native_boot_required):
    tool = tmp_path / "bin" / "tool"
    script(tool, "/bin/sleep 1")
    session = CommandSession(tmp_path / "s")
    session.put(config([str(tool)], "timeout='1s'\n"))
    ready(session)
    folder = scripts_folder(session)
    other = folder / f"{session_tag(OTHER)}-{'0' * 32}"
    session.prompt()
    found = until(lambda: [(s, p) for s, p in supervisors(session)
                           if any(f.name.startswith(session_tag(SESSION)) for f in folder.iterdir())])
    assert found, "no supervisor with a copy"
    supervisor, helper = found[0]
    other.write_bytes(b"x")
    os.kill(supervisor, signal.SIGSTOP)
    try:
        assert until(lambda: gone(helper), timeout=4.0), "the helper did not end"
        mine = [f for f in folder.iterdir() if f.name.startswith(session_tag(SESSION))]
        assert len(mine) == 1, mine
    finally:
        try:
            os.kill(supervisor, signal.SIGCONT)
        except ProcessLookupError:
            pass
    assert until(lambda: gone(supervisor), timeout=3.0)
    session.wait_quiet()
    # The next script round of the session sweeps; its own copy goes at its end.
    session.prompt()
    session.wait_quiet()
    assert [f.name for f in folder.iterdir()] == [other.name]


# J7: 세션 값이 없으면 감독을 띄우지 않고 그 사실을 로그한다. 이것을 실패시키는 것: Skip::NoSession의
# 로그 문구를 None으로 하는 것.
def test_no_session_runs_nothing_and_says_so(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    session.session = None
    session.level = "info"
    canary = tmp_path / "ran"
    session.put(config(["/usr/bin/touch", str(canary)]))
    ready(session)
    session.prompt()
    session.wait_quiet()
    assert not canary.exists()
    assert b"no session value from the shell" in session.log(), session.log()


# GATE-CLOCK-READS.3: 단위마다 exec가 하나 늘 뿐(중계가 대상으로 exec), 프로세스는 늘지 않는다. 감독의 자식은
# 단위 수와 같고 각각 이미 대상이며, 같은 pid에서 중계가 돌았다(중계가 건 NoNewPrivs). 이것을 실패시키는 것:
# 중계가 대상을 자식으로 띄우는 것(relay의 execveat 대신 생성), 감독이 중계를 건너뛰고 대상을 바로 띄우는 것.
@linux_only
def test_each_unit_is_one_process_the_relay_execs_into(tmp_path, _native_boot_required):
    # The proof below is the target's no_new_privs: it holds only when nothing
    # above the relay already had the flag.
    own = Path("/proc/self/status").read_text()
    assert "NoNewPrivs:\t0" in own, "the test process must not have no_new_privs"
    session = CommandSession(tmp_path / "s")
    units = "".join(f"[segment.\"custom/u{i}\"]\nkind='command'\ncommand=['/bin/sleep', '1']\ntimeout='1s'\n"
                    for i in range(3))
    session.put(units + "[layout.line2]\nleft=['custom/u0','custom/u1','custom/u2','char']\n")
    ready(session)
    session.prompt()
    sleep = os.path.realpath("/bin/sleep")

    def running():
        for pid, _ in supervisors(session):
            kids = children(pid)
            try:
                exes = sorted(os.readlink(f"/proc/{k}/exe") for k in kids)
            except OSError:
                continue
            if len(kids) == 3 and exes == [sleep] * 3:
                return kids
        return None

    kids = until(running, timeout=2.0)
    assert kids, [(s, children(s)) for s, _ in supervisors(session)]
    for k in kids:
        assert children(k) == [], "a target has a child of its own"
        # The supervisor spawned `bingsu __exec-v2` as this pid, and the relay
        # set no_new_privs there before execveat: neither the helper nor the
        # supervisor has the flag at spawn time, so it proves the relay ran.
        status = Path(f"/proc/{k}/status").read_text()
        assert "NoNewPrivs:\t1" in status, status
    session.wait_quiet()


def runs(path):
    return len(path.read_text().splitlines()) if path.exists() else 0


def command_response(session):
    """The bytes of the published command response(s) of this session's context."""
    root = Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu"
    return b"".join(p.read_bytes() for p in root.rglob("collections-v1/*/store/command"))


def rounds(session, n):
    for _ in range(n):
        session.prompt()
        session.wait_quiet(timeout=8)


NOT_PUBLISHED = b"command round: results not published"


ROUND_FINISHED = b"command round finished"


def supervised_rounds(session, limit=8):
    """Rounds until one that ran the units also published; how many ran
    them. A round ran the units when it logged `command round finished`
    (debug log); a round that never reached the command round ("refresh
    incomplete" under load) ran nothing and does not count (m6-T9). A round
    whose publication was deferred ran the units, counts, and the next round
    runs them again (C4 ruling P1)."""
    assert session.level == "debug"
    ran = 0
    for _ in range(limit):
        finished = session.log().count(ROUND_FINISHED)
        deferred = session.log().count(NOT_PUBLISHED)
        rounds(session, 1)
        if session.log().count(ROUND_FINISHED) > finished:
            ran += 1
            if session.log().count(NOT_PUBLISHED) == deferred:
                return ran
    raise AssertionError(f"no round ran and published the units in {limit} prompts")


def rounds_until(session, check, limit=5):
    """Rounds until `check()` holds; how many ran, at most `limit`. A round
    that decided nothing (its collection answered late, so no language was
    decided, or it never reached the command round) logs no deferral either
    (m6-T9), so a test that needs a value waits for the value itself."""
    for n in range(1, limit + 1):
        rounds(session, 1)
        if check():
            return n
    raise AssertionError(f"not there after {limit} rounds")


def published(session, value):
    """Rounds until `value` is in the command response; how many ran."""
    return rounds_until(session, lambda: value in command_response(session))


def counting(counter, value="v"):
    return ["/bin/sh", "-c", f"echo x >> {counter}; echo {value}"]


# GATE-CMD-SPAWN.3: 캐시 기간 안에는 다시 실행하지 않고 감독도 띄우지 않는다. 결과는 명령 응답에 발행된다. 이것을
# 실패시키는 것: prepare의 적중 판정을 지우는 것(프롬프트마다 다시 실행), 발행을 지우는 것(응답이 없어 다음 회차가
# 적중하지 못함), 모두 적중한 회차에도 감독을 띄우는 것.
def test_cache_hit_runs_nothing(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    counter = session.base / "runs"
    session.put(config(counting(counter, "cached-value"), "cache='30s'\n"))
    session.level = "debug"
    ready(session)
    before = runs(counter)
    ran = supervised_rounds(session)
    assert runs(counter) == before + ran, (before, ran, runs(counter))
    before += ran
    # Each round that starts a supervisor ends with this line.
    supervised = session.log().count(b"command round finished")
    rounds(session, 4)
    assert runs(counter) == before, "a unit inside its cache time ran again"
    assert session.log().count(b"command round finished") == supervised, "a cached round started a supervisor"
    assert b"cached-value" in command_response(session)


# cache가 없으면 기본 0이라 회차마다 실행한다(C4 판정 P3). 이것을 실패시키는 것: 기본 캐시 기간을 0보다 크게
# 두는 것.
def test_no_cache_runs_every_round(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    counter = session.base / "runs"
    session.put(config(counting(counter)))
    ready(session)
    before = runs(counter)
    rounds(session, 3)
    assert runs(counter) == before + 3, (before, runs(counter))


# 실패(종료 0이 아님)는 10초 동안 다시 실행하지 않는다. 이것을 실패시키는 것: 실패 항목을 쓰지 않는 것, 실패를
# cache 기간(기본 0)으로 세는 것.
def test_failure_cached_10s(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    counter = session.base / "runs"
    session.put(config(["/bin/sh", "-c", f"echo x >> {counter}; exit 3"]))
    session.level = "debug"
    ready(session)
    before = runs(counter)
    ran = supervised_rounds(session)
    first = runs(counter)
    assert first == before + ran, (before, ran, first)
    rounds(session, 3)
    assert runs(counter) == first, "a failed unit ran again inside 10 s"


# 적중은 이 셸의 원본 환경 요약값과 맞을 때만이다. 다른 KUBECONFIG로 낸 프롬프트는 다른 셸의 값을 쓰지 않고 다시
# 실행하고, 같은 값으로 다시 내면 적중한다. 이것을 실패시키는 것: 적중 판정에서 환경 요약값 비교를 지우는 것(값이
# 바뀌어도 실행하지 않음), env_digest에 env_allow를 넣지 않는 것. 발행이 미뤄진 회차(저장소 busy, 예산 초과)는
# 다음 회차가 다시 실행하는 설계라, 명령을 돌리고 발행한 회차까지 기다린 뒤 센다(supervised_rounds).
def test_cache_hit_is_display_match(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    counter = session.base / "runs"
    session.put(config(counting(counter), "cache='30s'\nenv_allow=['KUBECONFIG']\n"))
    session.env["KUBECONFIG"] = "/a"
    session.level = "debug"
    ready(session)
    before = runs(counter)
    ran = supervised_rounds(session)
    assert runs(counter) == before + ran, (before, ran, runs(counter))
    session.env["KUBECONFIG"] = "/b"
    ran += supervised_rounds(session)
    assert runs(counter) == before + ran, "another environment's entry was taken as a hit"
    rounds(session, 2)
    assert runs(counter) == before + ran, runs(counter)


# 단위가 회차 상한(8)보다 많으면, 시도한 지 가장 오래된 것부터 고른다: 12개가 두 회차 안에 모두 실행된다. 이것을
# 실패시키는 것: units()에 응답의 시도 시각을 넘기지 않는 것(매 회차 같은 8개).
def test_round_robin_reaches_every_unit(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    marks = session.base / "marks"
    marks.mkdir()
    segments = "".join(
        f"[segment.\"custom/u{i:02}\"]\nkind='command'\ncommand=['/usr/bin/touch', '{marks}/u{i:02}']\n"
        for i in range(12))
    left = ", ".join(f"'custom/u{i:02}'" for i in range(12))
    session.put(segments + f"[layout.line2]\nleft=[{left}, 'char']\n")
    ready(session)
    rounds(session, 2)
    assert sorted(p.name for p in marks.iterdir()) == [f"u{i:02}" for i in range(12)]


# 실행 파일을 찾지 못한 단위도 시도로 남긴다(10초 실패 항목). 그래서 찾지 못하는 단위 8개가 회차 상한을 차지해도
# 다음 회차는 뒤의 단위로 넘어간다. 이것을 실패시키는 것: 해석 실패 단위의 실패 항목을 발행하지 않는 것(units()의
# unresolved_ids 기록이나 publish_results의 그 항목을 지우는 것: 뒤의 두 단위가 영원히 돌지 않음).
def test_unresolved_units_do_not_hold_the_round(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    marks = session.base / "marks"
    marks.mkdir()
    missing = "".join(f"[segment.\"custom/m{i}\"]\nkind='command'\ncommand=['bingsu-no-such-command-{i}']\n"
                      for i in range(8))
    real = "".join(f"[segment.\"custom/r{i}\"]\nkind='command'\ncommand=['/usr/bin/touch', '{marks}/r{i}']\n"
                   for i in range(2))
    left = ", ".join([f"'custom/m{i}'" for i in range(8)] + [f"'custom/r{i}'" for i in range(2)])
    session.put(missing + real + f"[layout.line2]\nleft=[{left}, 'char']\n")
    ready(session)
    rounds(session, 3)
    assert sorted(p.name for p in marks.iterdir()) == ["r0", "r1"]


# relay 입력 상한(16 KiB)을 넘는 환경의 단위도 실패 항목으로 남겨 순서를 넘긴다. 이것을 실패시키는 것: units()의
# relay 입력 상한 분기에서 실패 항목 기록을 지우는 것(뒤의 두 단위가 영원히 돌지 않음).
def test_oversize_units_do_not_hold_the_round(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    marks = session.base / "marks"
    marks.mkdir()
    big = "".join(f"[segment.\"custom/b{i}\"]\nkind='command'\ncommand=['/usr/bin/true']\nenv_allow=['BINGSU_BIG']\n"
                  for i in range(8))
    real = "".join(f"[segment.\"custom/r{i}\"]\nkind='command'\ncommand=['/usr/bin/touch', '{marks}/r{i}']\n"
                   for i in range(2))
    left = ", ".join([f"'custom/b{i}'" for i in range(8)] + [f"'custom/r{i}'" for i in range(2)])
    session.put(big + real + f"[layout.line2]\nleft=[{left}, 'char']\n")
    session.env["BINGSU_BIG"] = "x" * (20 * 1024)
    ready(session)
    rounds(session, 3)
    assert sorted(p.name for p in marks.iterdir()) == ["r0", "r1"]


# 명령만 있는 레이아웃(수집 없음)도 발행 뒤 GC 회수를 돌린다. 그래서 cwd를 여럿 다녀 예약이 예산을 채워도 다음
# cwd의 발행이 된다. 이것을 실패시키는 것: helper가 명령 발행 뒤 collection_runtime을 세우지 않는 것(8번째
# cwd부터 예약이 막혀 발행이 계속 실패).
def test_command_only_rounds_reclaim_the_store_budget(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    # No dir or git on either line: nothing else selects a collection.
    session.put(config(["/bin/sh", "-c", "echo v"]) + "[layout.line1]\nleft=['char']\n")
    ready(session)
    root = Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu"
    for i in range(10):
        folder = (session.base / f"cwd{i:02}").resolve()
        folder.mkdir()
        session.pwd = folder
        rounds(session, 1)
        bound = [p for p in root.rglob("collections-v1/*/store/command") if os.fsencode(folder) in p.read_bytes()]
        assert bound, f"no command response for the folder of round {i}"


# C4c: 도우미가 `match`로 고른 값을 발행하고 앞단은 그 값을 그린다. 이것을 실패시키는 것: 도우미가 결과 항목에
# 패턴을 적용하지 않는 것(원문을 그림), 패턴 요약값을 붙이지 않는 것(앞단이 숨김).
def test_match_picks_the_published_value(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.put(config(["/bin/sh", "-c", "echo go version go1.23.1 darwin/arm64"],
                       "cache='3600s'\nmatch='go([0-9.]+)'\n"))
    session.level = "info"
    ready(session)
    published(session, b"1.23.1")
    record = session.prompt()
    session.wait_quiet(timeout=8)
    assert b"1.23.1" in record and b"darwin" not in record, record


# `match`만 바꾸면 명령을 다시 실행하지 않고, 저장한 원문 첫 줄에 새 패턴을 맞춰 발행한다(U-9c). 바꾼 뒤 옛
# 패턴의 값을 숨기는 것은 앞단 단위 시험(display a_patterned_unit_shows_only_entries_matched_with_its_pattern)이 맡는다.
# 이것을 실패시키는 것: prepare에서 다시 맞추기를 지우는 것(새 값이 캐시 기간 동안
# 나오지 않음), 패턴 변경을 캐시 빗나감으로 보는 것(다시 실행), 아무것도 실행하지 않는 회차에서 다시 맞춘 항목을
# 발행하지 않는 것.
# `beside`: another unit without a cache runs every round, so the re-matched entry goes out with that round's
# results instead of alone.
# `removed`: the edit drops `match`, and the whole first line comes back without running.
@pytest.mark.parametrize("removed", [False, True])
@pytest.mark.parametrize("beside", [False, True])
def test_match_only_change_reapplies_without_exec(tmp_path, _native_boot_required, beside, removed):
    session = CommandSession(tmp_path)
    counter = session.base / "runs"
    run = ["/bin/sh", "-c", f"echo x >> {counter}; echo a/b/kube-ctx"]
    other = ("[segment.\"custom/other\"]\nkind='command'\ncommand=['/bin/sh', '-c', 'echo other-value']\n"
             if beside else "")

    def config_with(match):
        text = other + config(run, "cache='3600s'\n" + (f"match='{match}'\n" if match else ""))
        return text.replace("left=['custom/probe','char']", "left=['custom/other','custom/probe','char']") if beside else text
    session.put(config_with("(a/[a-z]+)"))
    session.level = "info"
    ready(session)
    published(session, b"a/b/kube-ctx")
    before = runs(counter)
    record = session.prompt()
    session.wait_quiet(timeout=8)
    assert b"a/b" in record and b"kube-ctx" not in record, record
    session.put(config_with(None if removed else "([^/]+)$"))
    want = b"a/b/kube-ctx" if removed else b"kube-ctx"
    # The prompt right after the edit still reads the old snapshot, whose
    # pattern the old value matches; the helper publishes the new snapshot
    # and the re-matched value in the same round.
    for _ in range(6):
        record = session.prompt()
        session.wait_quiet(timeout=8)
        if want in record:
            break
    assert want in record and (removed or b"a/b" not in record), record
    assert runs(counter) == before, "changing match alone ran the command again"
    assert (b"values matched again under a changed match" in session.log()) != beside


# 문법 오류나 크기 상한을 넘는 `match`는 config check가 E203으로 알리고, 그 단위만 실행하지 않으며 다른 단위는
# 그린다. 이것을 실패시키는 것: config check나 스냅샷 발행에서 match 검사를 부르지 않는 것(그 단위가 돌거나
# 오류가 없음), 다른 단위까지 끄는 것.
def test_match_size_limit_rejected_at_compile(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    counter = session.base / "runs"
    bad = ("[segment.\"custom/bad\"]\nkind='command'\n"
           f"command=['/bin/sh', '-c', 'echo x >> {counter}; echo bad-value']\nmatch='\\w{{50}}'\n")
    session.put(bad + config(["/bin/sh", "-c", "echo good-value"], "cache='3600s'\n")
                .replace("left=['custom/probe','char']", "left=['custom/bad','custom/probe','char']"))
    session.level = "info"
    ready(session)
    published(session, b"good-value")
    record = session.prompt()
    session.wait_quiet(timeout=8)
    assert b"good-value" in record and b"bad-value" not in record, record
    assert runs(counter) == 0, "the unit with a match over the limit ran"
    r = subprocess.run([str(session._launcher), "config", "check"], cwd=session.base, env=session.env,
                       capture_output=True, timeout=20)
    out = r.stdout + r.stderr
    assert b"E203" in out and b"custom/bad" in out and b"size limit" in out, out


# rounds_until은 조건이 설 때까지 회차를 더 돌리고, 다섯 회차 안에 서지 않으면 실패한다. 이것을 실패시키는 것: 첫
# 회차 뒤 조건을 보지 않고 돌아오는 것(아무것도 정하지 않은 회차 뒤에 값을 단언함), 상한 없이 도는 것, 상한에서
# 실패하지 않는 것.
def test_rounds_until_waits_for_the_value():
    class Session:
        prompts = 0

        def prompt(self):
            self.prompts += 1

        def wait_quiet(self, timeout):
            pass

    session = Session()
    assert rounds_until(session, lambda: session.prompts >= 3) == 3
    session = Session()
    with pytest.raises(AssertionError, match="after 5 rounds"):
        rounds_until(session, lambda: False)
    assert session.prompts == 5


# supervised_rounds는 명령 회차에 닿은 회차만 세고, 발행이 미뤄진 회차는 세되 다음 회차까지 돌며, 발행한 회차에서
# 멈춘다. 이것을 실패시키는 것: 명령 회차에 닿지 못한 회차(refresh incomplete)도 세는 것, 미뤄진 회차에서 멈추는
# 것, 상한 없이 도는 것.
def test_supervised_rounds_counts_rounds_that_ran_the_units():
    class Session:
        level = "debug"

        def __init__(self, script):
            self.script = list(script)
            self.lines = b""

        def prompt(self):
            self.lines += self.script.pop(0) if self.script else b"refresh incomplete\n"

        def wait_quiet(self, timeout):
            pass

        def log(self):
            return self.lines

    incomplete = b"refresh incomplete\n"
    deferred = NOT_PUBLISHED + b"; the store was busy\n" + ROUND_FINISHED + b"\n"
    published = ROUND_FINISHED + b"\n"
    assert supervised_rounds(Session([incomplete, deferred, incomplete, published])) == 2
    assert supervised_rounds(Session([published])) == 1
    session = Session([])
    with pytest.raises(AssertionError, match="in 8 prompts"):
        supervised_rounds(session)


# tests/command-acceptance.tsv의 행마다 실제 시험이 있다(넘긴 행은 "-"와 넘긴 Task). 이것을 실패시키는
# 것: 표의 시험 이름 오타, 지운 시험을 가리키는 행, 넘긴 행에 시험을 적는 것.
def test_command_table_names_real_tests():
    import csv, re
    from conftest import ROOT
    rows = list(csv.DictReader((ROOT / "tests/command-acceptance.tsv").read_text().splitlines(), delimiter="\t"))
    assert rows and len({r["id"] for r in rows}) == len(rows)
    for row in rows:
        if row["stage"] not in ("C2", "C3", "C4"):
            assert (row["platform"], row["test"]) == ("-", "-"), row["id"]
            continue
        path, name = row["test"].split("::")
        source = (ROOT / path).read_text()
        pattern = (rf"^def {re.escape(name)}\(" if path.endswith(".py")
                   else rf"^\s*fn {re.escape(name)}\(\)")
        assert len(re.findall(pattern, source, re.M)) == 1, (row["id"], path, name)


# 단위가 없는 회차는 감독을 띄우지 않는다. 감독은 세션 잠금을 얻은 뒤에만 생성되므로 잠금 파일과 중립 폴더가
# 없으면 감독도 없었다. 이것을 실패시키는 것: prepare의 NoUnits 조기 반환을 지우는 것.
def test_round_without_units_starts_no_supervisor(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    session.put("[layout.line2]\nleft=['char']\n")
    ready(session)
    root = Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu"
    seen = []
    for _ in range(3):
        session.prompt()
        seen += [p for p, _ in supervisors(session)]
    session.wait_quiet()
    assert seen == []
    assert list(root.glob("command-*.lock")) == [] and not session.neutral().exists()


# TERM만 다른 두 셸(같은 폴더)은 helper가 발행한 같은 명령 값을 둘 다 그린다: TERM은 명령에 넘기지만 요약값에는
# 넣지 않는다(F1-b). `env_allow`에 TERM을 쓴 단위는 다시 세어 다른 TERM 셸에는 그리지 않는다. 이것을 실패시키는
# 것: 요약값에 TERM을 다시 넣는 것(다른 터미널의 값을 숨김), env_allow에 쓴 TERM까지 빼는 것.
@pytest.mark.parametrize("listed", [False, True])
def test_command_value_is_shared_across_terminals(tmp_path, _native_boot_required, listed):
    session = CommandSession(tmp_path)
    allow = "env_allow=['TERM']\n" if listed else ""
    session.put(config(["/bin/sh", "-c", "echo shown-value"], "cache='30s'\n" + allow))
    session.env["TERM"] = "xterm-256color"
    session.level = "info"
    ready(session)
    published(session, b"shown-value")
    assert b"shown-value" in session.prompt()
    session.wait_quiet(timeout=8)
    session.env["TERM"] = "tmux-256color"
    assert (b"shown-value" in session.prompt()) != listed
    session.wait_quiet(timeout=8)


# 앞단이 이 셸의 명령 응답 값을 그린다(C4b). 다른 KUBECONFIG 셸에는 그 값을 그리지 않는다. 이것을 실패시키는 것:
# 앞단의 command 응답 읽기나 값 채우기를 빼는 것(값이 안 보임), 환경 요약값 비교를 빼는 것(다른 셸에도 보임).
def test_command_value_is_drawn_for_its_own_shell(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.put(config(["/bin/sh", "-c", "echo shown-value"], "cache='30s'\nenv_allow=['KUBECONFIG']\n"))
    session.env["KUBECONFIG"] = "/a"
    session.level = "info"
    ready(session)
    published(session, b"shown-value")
    assert b"shown-value" in session.prompt()
    session.wait_quiet(timeout=8)
    session.env["KUBECONFIG"] = "/b"
    assert b"shown-value" not in session.prompt()
    session.wait_quiet(timeout=8)


def fail_an_edit(session):
    """`config edit` whose editor saves a file that does not parse; it exits 1."""
    editor = session.base / "bad-editor.sh"
    editor.write_text("#!/bin/sh\nprintf '[broken\\n' > \"$1\"\n")
    editor.chmod(0o700)
    session.env["EDITOR"] = str(editor)
    # A prompt starts a refresh round; a save that meets a running round is
    # not published ("another refresh is running"), so the marker stays
    # valid. The save stays on disk, so the next try publishes it. Wait for
    # the round to end, a bounded number of tries. 이것을 실패시키는 것: 바쁨을 재시도 없이 통과로 읽는 것(표식이
    # 무효가 되지 않아 뒤 단언이 실패), 상한 없이 기다리는 것.
    for _ in range(40):
        session.wait_quiet()
        result = session.run("config", "edit")
        assert result.returncode == 1, (result.stdout, result.stderr)
        assert b"were not applied" in result.stderr, result.stderr
        if b"another refresh is running" not in result.stderr:
            return
        time.sleep(0.25)
    raise AssertionError(f"every try met a running refresh: {result.stderr!r}")


# 실패한 편집 뒤의 프롬프트(M7 E, 명령 없이): 유효한 설정으로 발행한 뒤 가짜 편집기가 무효 내용을 저장한다.
# `config edit`은 1로 끝나고, 그 뒤 프롬프트 레코드는 (1) 표시 설정이 편집 전과 같고(텍스트 세그먼트가 그대로
# 그려짐), (2) `degraded:trust-invalid`를 내고, (3) 상태 표시 `!`가 있다.
# 이것을 실패시키는 것: 무효일 때 발행(표식 무효화)을 건너뛰는 것(상태 표시가 없음), 무효 설정이 표시 스냅샷을
# 바꾸는 것(EDITSHOW가 사라짐).
def test_a_failed_edit_keeps_the_display_and_marks_the_state(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.put("[segment.\"custom/label\"]\nkind='text'\ntext='EDITSHOW'\n"
                "[layout.line2]\nleft=['custom/label','char']\n")
    session.init()
    session.await_text("EDITSHOW")
    session.wait_quiet()
    before = session.prompt()
    assert b"degraded:trust-invalid" not in before, before
    fail_an_edit(session)
    for _ in range(3):
        record = session.prompt()
        assert b"EDITSHOW" in record, record
        assert b"degraded:trust-invalid" in record, record
        assert b"!" in record, record
        session.wait_quiet()


# 실패한 편집 뒤에는 이전 설정의 명령이 돌지 않는다. 먼저 편집 전에는 돈다는 것을 확인한 뒤(양성 대조), 무효 저장
# 뒤 몇 번의 프롬프트에도 카나리 파일이 생기지 않음을 본다. 이것을 실패시키는 것: 무효일 때 발행(표식 무효화)을
# 건너뛰어 마지막 정상 설정의 명령이 계속 도는 것.
def test_a_failed_edit_stops_the_commands_of_the_previous_settings(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    canary = session.base / "ran"
    session.put(config(["/usr/bin/touch", str(canary)]))
    ready(session)
    assert until(lambda: (session.prompt(), canary.exists())[1]), "the unit never ran"
    session.wait_quiet()
    canary.unlink()
    forget_results(session)
    fail_an_edit(session)
    for _ in range(4):
        session.prompt()
        session.wait_quiet()
        forget_results(session)
    assert not canary.exists(), "a command ran after an invalid save"
