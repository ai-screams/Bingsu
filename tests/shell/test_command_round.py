"""Command rounds through the real helper, supervisor and relay (M6 C2, Linux).

The helper spawns the command supervisor before its own filter and grants it
the configured units only after the marker is installed; the supervisor
approves each unit again right before its relay spawn."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest
from blocked_mount import blocked_mount
from shell_support import Blocked
from snapshot_support import SnapshotSession, require_native_boot

linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="the trusted relay runs on Linux only (C2 ruling J3, PR 10b)")

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
@linux_only
def test_configured_command_runs(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    canary = session.base / "ran"
    session.put(config(["/usr/bin/touch", str(canary)]))
    ready(session)
    assert until(lambda: (session.prompt(), canary.exists())[1]), "the unit never ran"
    session.wait_quiet()


# 이것을 실패시키는 것: 허가 단위를 고를 때 not_run을 거르지 않는 것(plan::runnable의 거름 삭제):
# 믿을 수 있는 레이아웃이 그리지 않는 단위(NotInTrustedLayout)도 실행된다.
@linux_only
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
@linux_only
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
@linux_only
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


# 세션 잠금은 감독이 사는 동안 풀리지 않는다(감독이 close-only 사본을 쥔다). 이것을 실패시키는 것: 감독에
# 잠금 사본을 넘기지 않는 것(spawn_supervisor의 fd 5 dup 삭제): 도우미가 죽으면 잠금이 풀려 같은 세션에
# 둘째 감독이 뜬다.
@linux_only
def test_lock_held_while_supervisor_alive(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path)
    session.put(config(["/bin/sleep", "1"], "timeout='1s'\n"))
    ready(session)
    session.prompt()
    found = until(lambda: [(s, p) for s, p in supervisors() if lock_of(s) is not None])
    assert found, "no supervisor"
    supervisor, helper = found[0]
    os.kill(supervisor, signal.SIGSTOP)
    try:
        os.kill(helper, signal.SIGKILL)
        until(lambda: not Path(f"/proc/{helper}/cmdline").exists()
              or Path(f"/proc/{helper}/cmdline").read_bytes() == b"", timeout=2.0)
        session.wait_quiet()
        session.prompt()
        session.wait_quiet()
        others = [s for s, _ in supervisors() if s != supervisor]
        assert others == [], "a second supervisor while the first holds the lock"
    finally:
        os.kill(supervisor, signal.SIGCONT)
    # It sees the helper gone (end of file), ends its child and exits.
    assert until(lambda: not any(s == supervisor for s, _ in supervisors()), timeout=3.0)
    session.prompt()
    assert until(lambda: supervisors()), "the next prompt starts a supervisor again"
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
# bin은 빠진다. 이것을 실패시키는 것: Round::grant에 수집 루트 대신 None을 넘기는 것(셸 폴더로 대체되어
# 루트 바로 아래 bin이 남음).
@linux_only
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
    session.env["PATH"] = f"{repo}/bin:{other}/bin:/usr/bin:/bin"
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


# J9 대체: 수집 루트가 없으면 셸 폴더가 저장소를 대신한다. 이것을 실패시키는 것: units()의 repo_id를
# 늘 None으로 하는 것(셸 폴더 아래 bin의 실행 파일이 돈다). 양성 대조: 저장소 밖 폴더의 같은 명령은 돈다.
@linux_only
def test_shell_folder_stands_for_the_repository(tmp_path, _native_boot_required):
    proj = tmp_path / "proj"
    other = tmp_path / "other"
    proj.mkdir(mode=0o700)
    inside, outside = tmp_path / "inside", tmp_path / "outside"
    script(proj / "bin" / "probe-cmd", f"touch '{inside}'")
    script(other / "bin" / "probe-out", f"touch '{outside}'")
    session = CommandSession(tmp_path / "s")
    session.env["PATH"] = f"{proj}/bin:{other}/bin:/usr/bin:/bin"
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
@linux_only
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
@linux_only
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
@linux_only
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


# J3(PR 10a): macOS에는 신뢰된 중계가 아직 없어 설정 단위가 있어도 감독을 띄우지 않는다(실행 0, 감독 0,
# 로그 한 줄). 이것을 실패시키는 것: command_grant::prepare의 NoRelay 판정을 지우는 것(감독이 뜨고
# 로그가 없다).
@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS side of C2 ruling J3")
def test_macos_runs_no_command_without_a_relay(tmp_path):
    session = CommandSession(tmp_path / "s")
    session.level = "info"
    canary = tmp_path / "ran"
    session.put(config(["/usr/bin/touch", str(canary)]))
    session.init()
    session.wait_quiet()
    seen = []
    for _ in range(3):
        session.prompt()
        out = subprocess.run(["ps", "-axo", "command="], capture_output=True, text=True).stdout
        seen += [line for line in out.splitlines() if "__command-v1" in line]
        session.wait_quiet()
    assert not canary.exists()
    assert seen == []
    assert b"no trusted relay on this platform" in session.log(), session.log()


# J7: 세션 값이 없으면 감독을 띄우지 않고 그 사실을 로그한다. 이것을 실패시키는 것: Skip::NoSession의
# 로그 문구를 None으로 하는 것.
@linux_only
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
# 단위 수와 같고 각각 이미 대상이다. 이것을 실패시키는 것: 중계가 대상을 자식으로 띄우는 것(relay의
# execveat 대신 생성), 감독이 단위마다 둘을 띄우는 것.
@linux_only
def test_each_unit_is_one_process_the_relay_execs_into(tmp_path, _native_boot_required):
    session = CommandSession(tmp_path / "s")
    units = "".join(f"[segment.\"custom/u{i}\"]\nkind='command'\ncommand=['/bin/sleep', '1']\ntimeout='1s'\n"
                    for i in range(3))
    session.put(units + "[layout.line2]\nleft=['custom/u0','custom/u1','custom/u2','char']\n")
    ready(session)
    session.prompt()
    sleep = os.path.realpath("/bin/sleep")

    def running():
        for pid, _ in supervisors():
            kids = children(pid)
            try:
                exes = sorted(os.readlink(f"/proc/{k}/exe") for k in kids)
            except OSError:
                continue
            if len(kids) == 3 and exes == [sleep] * 3:
                return kids
        return None

    kids = until(running, timeout=2.0)
    assert kids, [(s, children(s)) for s, _ in supervisors()]
    for k in kids:
        assert children(k) == [], "a target has a child of its own"
    session.wait_quiet()


# tests/command-acceptance.tsv의 행마다 실제 시험이 있다(넘긴 행은 "-"와 넘긴 Task). 이것을 실패시키는
# 것: 표의 시험 이름 오타, 지운 시험을 가리키는 행, 넘긴 행에 시험을 적는 것.
def test_command_table_names_real_tests():
    import csv, re
    from conftest import ROOT
    rows = list(csv.DictReader((ROOT / "tests/command-acceptance.tsv").read_text().splitlines(), delimiter="\t"))
    assert rows and len({r["id"] for r in rows}) == len(rows)
    for row in rows:
        if row["stage"] != "C2":
            assert (row["platform"], row["test"]) == ("-", "-"), row["id"]
            continue
        path, name = row["test"].split("::")
        source = (ROOT / path).read_text()
        pattern = (rf"^def {re.escape(name)}\(" if path.endswith(".py")
                   else rf"^\s*fn {re.escape(name)}\(\)")
        assert len(re.findall(pattern, source, re.M)) == 1, (row["id"], path, name)
