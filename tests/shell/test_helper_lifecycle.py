"""N7 lifecycle integration, reusing N3 native probes and N6 pipe machinery."""
from contextlib import nullcontext
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

import pytest
from blocked_mount import blocked_mount
from shell_support import Blocked, role_processes
from snapshot_support import SnapshotSession, require_native_boot
from test_snapshot_refresh import appearance
from conftest import ROOT, real_bin, real_collector
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
    # 이것을 실패시키는 것: 제품의 빈 worker catalog에서도 collection 저장소를 만드는 것.
    assert not list(session.store().rglob("collection.lock"))


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


class LifetimeSession(SnapshotSession):
    """A SnapshotSession whose prompts also pass init's collector pin and any --pwd.

    The launcher records each helper's exit status, so a watchdog kill shows as -9.
    init pins the collector next to the binary it runs as (the launcher), so a
    copy of the real collector sits there."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config_word = None
        collector = self._launcher.with_name("bingsu-collect")
        shutil.copyfile(real_collector(), collector)
        collector.chmod(0o755)

    def init(self):
        result = super().init()
        pins = re.findall(rb"'--collector-exe=([^']*)'", result.stdout)
        assert len(pins) == 1, ("exactly one init collector pin", pins)
        self.collector_word = "--collector-exe=" + os.fsdecode(pins[0])
        # Resolved now: once a config root's mount stops answering, any lookup there waits forever.
        self.config_word = os.fsencode(next(word for word in self.words if word.startswith("--config-root=")))
        return result

    def prompt_args(self, pwd=None):
        args = super().prompt_args() + [self.collector_word]
        if pwd is not None:
            args[args.index("--pwd") + 1] = str(pwd)
        return args

    def prompt_at(self, pwd):
        result = self.run(*self.prompt_args(pwd), timeout=2)
        assert result.returncode == 0 and result.stderr == b"", result
        return result.stdout

    def traced(self, tracer, timeout):
        """One prompt run under `tracer`; counted like run() so wait_quiet waits for its helper."""
        with self._count_lock:
            self._helper_count += 1
        return subprocess.run([*tracer, str(self._launcher), *self.prompt_args()], cwd=self.base,
                              env=self.env, capture_output=True, timeout=timeout)

    def statuses(self):
        """Exit statuses of the helpers that have finished, as the launcher wrote them."""
        return [int(path.read_text()) for path in self._completed.glob("[0-9]*") if path.suffix != ".pending"]

    def helpers(self):
        """Live real helpers of this session's config context (not their launchers).

        Matches the --config-root word init pinned; never touches the config folder."""
        mine = self.config_word
        if mine is None:
            return []
        found = []
        for pid in role_processes({"helper"}):
            try:
                if mine in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0"):
                    found.append(pid)
            except OSError:
                continue
        return found


def poll(condition, timeout, what):
    end = time.monotonic() + timeout
    while not (value := condition()):
        assert time.monotonic() < end, what
        time.sleep(0.005)
    return value


def fail_blocked(error):
    pytest.fail(f"BLOCKED: {error.reason}", pytrace=False)


def stop_helpers(*sessions):
    # A mutated helper can wait on the stopped mount forever; end it before the mount is released.
    for session in sessions:
        for pid in session.helpers():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def traced_kill(lines, exe):
    """(helper start, first kill time) of the one real helper in an `strace -f -ttt` trace.

    The kill is kill(<helper>, SIGKILL): in this fixture only the helper's own
    watchdog sends it. The helper must then end with `+++ killed by SIGKILL +++`."""
    # The exec line may be split by another thread's call (`<unfinished ...>`); its start time is the call's.
    starts = {line.split()[0]: float(line.split()[1]) for line in lines
              if f' execve("{exe}", ' in line and '"__refresh-v1"' in line}
    assert len(starts) == 1, ("one real helper exec", starts, [line for line in lines if "execve" in line])
    (helper, started), = starts.items()
    kills = [float(line.split()[1]) for line in lines if re.search(rf" kill\({helper}, SIGKILL\)", line)]
    assert kills, ("the helper never requested its own kill", helper)
    assert any(line.split()[0] == helper and "+++ killed by SIGKILL +++" in line for line in lines), (
        "the helper did not end by SIGKILL", helper)
    return started, kills[0]


# 이것을 실패시키는 것: watchdog의 수명 마감 뒤 kill_self 호출을 지우는 것(정상: 도우미가 지연 뒤 스스로 끝나고,
# 막힌 마운트: 도우미가 마운트에서 끝없이 기다림). 둘 다 kill 요청과 SIGKILL 종료가 사라진다.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace and FUSE fixture")
@pytest.mark.parametrize("mount", ["normal", "blocked-mount"])
def test_helper_requests_kill_after_deadline_on_normal_and_blocked_mount(tmp_path, mount):
    """GATE-HELPER-LIFETIME.1: past its 2 s lifetime the helper sends itself SIGKILL.

    normal: strace holds the helper's first flock call for 3 s on an ordinary
    folder, a stall outside the kernel's file wait that the watchdog must outlast. blocked
    mount: the config root sits on a FUSE mount whose daemon is stopped, so the
    helper waits in the kernel after taking the lock. The spec does not bound
    the lifetime there, so only the kill request and its time are asserted."""
    strace = shutil.which("strace")
    assert strace, "this Linux gate must execute strace"
    exe = str(real_bin())
    trace = tmp_path / "helper.trace"
    command = [strace, "-f", "-ttt", "-q", "-s", "256", "-o", str(trace), "-e", "trace=execve,clone,clone3,kill,tgkill,flock"]
    if mount == "normal":
        command += ["-e", "inject=flock:delay_enter=3000000"]

    def prepare(config):
        session = LifetimeSession(tmp_path / "s", config=config)
        session.put(appearance("LIFE"))
        session.init()
        session.wait_quiet()
        return session

    holder = {}
    context = (nullcontext(tmp_path / "cfg") if mount == "normal"
               else blocked_mount(tmp_path / "fuse", prepare=lambda path: holder.update(session=prepare(path / "cfg"))))
    try:
        with context as config:
            session = holder.get("session") or prepare(config)
            try:
                result = session.traced(command, timeout=8)
                assert result.returncode == 0, result
                started, killed = traced_kill(trace.read_text().splitlines(), exe)
                print(f"\nhelper kill after start: {killed - started:.3f} s ({mount})")
                # The lifetime starts after exec; only the normal stall bounds when the kill lands.
                assert killed - started >= helper_lifetime_s() - 0.01, (killed - started)
                if mount == "normal":
                    assert killed - started < 3.0, ("kill after the injected stall ended", killed - started)
                session.wait_quiet()
                assert -signal.SIGKILL in session.statuses(), session.statuses()
            finally:
                stop_helpers(session)
    except Blocked as error:
        fail_blocked(error)


def helper_lifetime_s():
    source = (ROOT / "crates/bingsu/src/commands/helper_limits.rs").read_text().replace("\r\n", "\n")
    value, = re.findall(r"pub const LIFETIME: Duration = Duration::from_secs\((\d+)\);", source)
    return int(value)


# 이것을 실패시키는 것: sys::try_lock에서 LOCK_NB를 지우는 것(같은 문맥 도우미가 잠금에서 기다리며 쌓인다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux FUSE fixture")
def test_one_blocked_helper_per_context_after_lock(tmp_path):
    """GATE-HELPER-LIFETIME.3: after the lock, one blocked helper per config context.

    Context A's config root is on a stopped FUSE mount; its first helper takes
    the store lock and waits there. Each later A prompt's helper must find the
    lock taken and exit on its own. Context B shares A's runtime and state roots
    but not its config root, and publishes while A's helper is still blocked."""
    shared = {"runtime": tmp_path / "run", "state": tmp_path / "state"}
    holder = {}

    def prepare(mount):
        a = LifetimeSession(tmp_path / "a", tag="a", config=mount / "cfg", **shared)
        a.put(appearance("CTXA"))
        a.init()
        a.wait_quiet()
        holder["a"] = a

    # B's cold init (up to the 500 ms first compile) happens before A blocks: only B's
    # republication of an edit has to fit inside A's helper lifetime.
    b = LifetimeSession(tmp_path / "b", tag="b", **shared)
    b.put(appearance("BASEB"))
    b.init()
    b.wait_quiet()
    try:
        with blocked_mount(tmp_path / "fuse", prepare=prepare):
            a = holder["a"]
            try:
                before = len(a.statuses())
                a.prompt()
                blocked, = poll(a.helpers, 1, "context A's helper never started")
                started = time.monotonic()
                # Alive past any normal refresh: it waits on the mount, holding the store lock.
                while time.monotonic() - started < 0.3:
                    assert a.helpers() == [blocked], a.helpers()
                    time.sleep(0.01)
                for _ in range(4):
                    a.prompt()
                    poll(lambda: a.helpers() == [blocked], 1, "a second context A helper stayed alive")
                b.put(appearance("CTXB"))
                b.await_text("CTXB", timeout=1.5)
                assert a.helpers() == [blocked], ("A's blocked helper ended before B published", a.helpers())
                print(f"\ncontext B published {time.monotonic() - started:.3f} s after A's helper was seen blocked")
                # The four later helpers ended on their own (Busy is a success exit), none by a kill.
                assert sorted(a.statuses()) == sorted([0] * (before + 4)), (before, a.statuses())
                b.wait_quiet()
            finally:
                stop_helpers(a, b)
    except Blocked as error:
        fail_blocked(error)
