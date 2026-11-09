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
from types import SimpleNamespace
import blocked_mount as blocked_mount_module
from blocked_mount import all_stopped, blocked_mount, task_states, wait_stopped
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


def _until(check, timeout=4.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.01)
    return check()


# 이것을 실패시키는 것: 스레드 하나만 멈춰도 멈췄다고 보는 것, 스레드 목록이 비면 멈췄다고 보는 것,
# 추적 중 멈춤(t)을 멈춤으로 보지 않는 것.
def test_blocked_mount_waits_for_every_thread_to_stop():
    assert all_stopped(["T", "T"]) and all_stopped(["t", "T"])
    assert not all_stopped(["T", "S"]) and not all_stopped(["R"]) and not all_stopped([])


# 이것을 실패시키는 것: /proc의 상태 칸을 잘못 읽는 것, 스레드 일부만 읽는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="reads /proc")
def test_task_states_reads_every_thread():
    code = "import threading, time; [threading.Thread(target=time.sleep, args=(30,), daemon=True).start() for _ in range(3)]; time.sleep(30)"
    child = subprocess.Popen([sys.executable, "-c", code])
    try:
        assert _until(lambda: len(task_states(child.pid)) == 4), task_states(child.pid)
        assert not all_stopped(task_states(child.pid))
        child.send_signal(signal.SIGSTOP)
        assert _until(lambda: all_stopped(task_states(child.pid))), task_states(child.pid)
    finally:
        child.kill()
        child.wait()


def fake_proc(root, pid, states):
    """A /proc tree for `pid` whose threads have `states` (None: listed, no stat)."""
    task = root / str(pid) / "task"
    for tid, state in states.items():
        (task / str(tid)).mkdir(parents=True, exist_ok=True)
        if state is not None:
            (task / str(tid) / "stat").write_text(f"{tid} (bind fs) {state} 1 2 3\n")
    return root


def sleeping(monkeypatch, steps):
    """Patch the stop wait's sleep: call steps[i] on the i-th sleep."""
    calls = []

    def sleep(_):
        if len(calls) < len(steps):
            steps[len(calls)]()
        calls.append(1)
    monkeypatch.setattr(blocked_mount_module, "_sleep", sleep)
    return calls


# 이것을 실패시키는 것: 늦게 멈추는 스레드를 기다리지 않는 것, 사라진 스레드에서 예외로 끝나는 것,
# 데몬이 끝난 것(폴더 없음, zombie)을 시간 초과까지 다시 시도하는 것, 시간 상한 없이 기다리는 것.
def test_wait_stopped_resamples_until_every_thread_stops(tmp_path, monkeypatch):
    proc = fake_proc(tmp_path / "late", 7, {7: "T", 8: "S"})
    calls = sleeping(monkeypatch, [lambda: None, lambda: fake_proc(proc, 7, {8: "T"})])
    wait_stopped(7, proc, timeout=5)
    assert len(calls) == 2
    # A worker listed without its stat (it exited): the sample starts over.
    proc = fake_proc(tmp_path / "gone", 7, {7: "T", 9: None})
    calls = sleeping(monkeypatch, [lambda: (proc / "7/task/9").rmdir()])
    wait_stopped(7, proc, timeout=5)
    assert len(calls) == 1
    # The daemon itself gone: Blocked at once, not after the timeout.
    proc = fake_proc(tmp_path / "exit", 7, {7: "S"})
    sleeping(monkeypatch, [lambda: shutil.rmtree(proc / "7")])
    start = time.monotonic()
    with pytest.raises(Blocked, match="exited"):
        wait_stopped(7, proc, timeout=5)
    assert time.monotonic() - start < 1
    proc = fake_proc(tmp_path / "zombie", 7, {7: "Z"})
    sleeping(monkeypatch, [])
    start = time.monotonic()
    with pytest.raises(Blocked, match="exited"):
        wait_stopped(7, proc, timeout=5)
    assert time.monotonic() - start < 1
    proc = fake_proc(tmp_path / "never", 7, {7: "S"})
    sleeping(monkeypatch, [])
    with pytest.raises(Blocked, match="did not stop"):
        wait_stopped(7, proc, timeout=0.05)


class _FakeDaemon:
    pid = 4242
    returncode = None

    def __init__(self, events):
        self.events = events
        self.stdout = self.stderr = SimpleNamespace(close=lambda: None, read=lambda: b"")

    def poll(self):
        return None

    def send_signal(self, sig):
        self.events.append(signal.Signals(sig).name)

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class _FakeProbe:
    returncode = None

    def wait(self, timeout=None):
        if timeout == 0.3:
            raise subprocess.TimeoutExpired("stat", timeout)
        return -9

    def kill(self):
        pass


def fake_fixture(tmp_path, monkeypatch, steps, timeout=5.0):
    """blocked_mount with a fake bindfs, mount table and /proc: the events
    it caused, in order."""
    events, mounted = [], [True]
    proc = fake_proc(tmp_path / "proc", _FakeDaemon.pid, {_FakeDaemon.pid: "S"})

    def popen(argv, **_):
        if argv[0] == "bindfs":
            return _FakeDaemon(events)
        states = task_states(_FakeDaemon.pid, proc)
        events.append(("probe", "stopped" if all_stopped(states) else "running"))
        return _FakeProbe()

    def run(argv, **_):
        mounted[0] = False
        return SimpleNamespace(returncode=0)
    exists = os.path.exists
    monkeypatch.setattr(blocked_mount_module.sys, "platform", "linux")
    monkeypatch.setattr(blocked_mount_module.shutil, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(blocked_mount_module.os.path, "exists", lambda p: p == "/dev/fuse" or exists(p))
    monkeypatch.setattr(blocked_mount_module.subprocess, "Popen", popen)
    monkeypatch.setattr(blocked_mount_module.subprocess, "run", run)
    monkeypatch.setattr(blocked_mount_module, "_mounted", lambda path: mounted[0])
    monkeypatch.setattr(blocked_mount_module, "PROC", proc)
    monkeypatch.setattr(blocked_mount_module, "STOP_TIMEOUT", timeout)
    sleeping(monkeypatch, [step(proc) for step in steps])
    return events


# 이것을 실패시키는 것: fixture가 멈춤 대기를 건너뛰고 조회하는 것, 멈추지 않을 때 조회하는 것,
# 시간 초과 뒤 SIGCONT를 보내지 않는 것.
def test_blocked_mount_probes_only_after_every_thread_stopped(tmp_path, monkeypatch):
    late = lambda proc: lambda: fake_proc(proc, _FakeDaemon.pid, {_FakeDaemon.pid: "T"})
    events = fake_fixture(tmp_path / "late", monkeypatch, [lambda proc: lambda: None, late])
    with blocked_mount(tmp_path / "late" / "fuse"):
        pass
    assert events == ["SIGSTOP", ("probe", "stopped"), "SIGCONT"], events
    events = fake_fixture(tmp_path / "never", monkeypatch, [], timeout=0.05)
    with pytest.raises(Blocked, match="did not stop"):
        with blocked_mount(tmp_path / "never" / "fuse"):
            pass
    assert events == ["SIGSTOP", "SIGCONT"], events

