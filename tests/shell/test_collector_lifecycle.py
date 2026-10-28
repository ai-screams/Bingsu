"""Product lifecycle evidence; builds belong to the native test jobs."""
import contextlib
from contextlib import nullcontext
from pathlib import Path
import re
import os
import shutil
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from blocked_mount import blocked_mount
from conftest import ROOT, minimal_record, real_bin
from shell_support import Blocked, role_processes, zombie_children
from snapshot_support import SnapshotSession
from test_helper_lifecycle import LifetimeSession, fail_blocked, helper_lifetime_s, poll, stop_helpers
from test_snapshot_refresh import appearance

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import parse as parse_trace, scan


def poll_waits_for_collection(call):
    args = scan(call.args)[0]
    polling = call.name in {"poll", "ppoll"}
    timeout_index = 2 if polling else 4
    if len(args) <= timeout_index:
        return True  # An interrupted call may not have printed its timeout.
    timeout = args[timeout_index]
    zero_timeout = (timeout == "0" if call.name == "poll" else
                    re.fullmatch(r"\{tv_sec=0,\s*tv_(?:nsec|usec)=0\}", timeout))
    # Rust probes standard fds at startup with a zero timeout. FD annotations
    # can contain numbers (pipe IDs, paths); only descriptor numbers matter.
    descriptors = re.sub(r"<[^>]*>", "", args[0] if polling else " ".join(args[1:4]))
    fds = re.findall(r"\bfd=(-?\d+)" if polling else r"-?\d+", descriptors)
    return not zero_timeout or any(int(fd) not in (0, 1, 2) for fd in fds)


def helper_exec_status_reads(front, spawns):
    """Identify only the parent's one-shot posix_spawn exec-status read.

    prompt_spawn calls libc::posix_spawn directly. musl creates a CLOEXEC
    pipe immediately before clone, closes the parent's writer, then reads an
    int: EOF means exec succeeded; four bytes report the child's exec errno.
    This is helper bootstrap, not a channel for collection results.
    """
    allowed = set()
    for spawn in spawns:
        index = front.index(spawn)
        if not index:
            continue
        pipe = front[index - 1]
        if pipe.name not in {"pipe", "pipe2"} or pipe.ret != "0":
            continue
        args = scan(pipe.args)[0]
        if pipe.name == "pipe2" and (len(args) != 2 or args[1] != "O_CLOEXEC"):
            continue
        ends = re.fullmatch(r"\[(\d+<pipe:\[(\d+)\]>), (\d+<pipe:\[\2\]>)\]", args[0])
        if not ends:
            continue
        reader, _, writer = ends.groups()
        if any(int(fd.split("<", 1)[0]) < 3 for fd in (reader, writer)) or reader == writer:
            continue
        following = iter(front[index + 1:])
        call = next(following, None)
        if call and call.name == "close" and call.args == writer and call.ret == "0":
            call = next(following, None)
        if not call or call.name != "read":
            continue
        args = scan(call.args)[0]
        if (len(args) == 3 and args[0] == reader and args[2] in {"1", "2", "3", "4"}
                and (call.ret == "0" or (args[2] == "4" and call.ret == "4"))):
            allowed.add(call.index)
    return allowed


def assert_no_collection_wait(text, *, deadline_empty=False):
    calls = parse_trace(text)
    assert not calls.errors, calls.errors
    executions = [call for call in calls if call.name in ("execve", "execveat")]
    assert executions and executions[0].pid == calls.first_pid, executions
    assert executions[0].name == "execve" and executions[0].ret == "0", executions
    # The deadline can expire even before bootstrap. Otherwise retain the
    # fixed refresh-helper contract; neither process may launch a collector.
    assert len(executions) in ((1, 2) if deadline_empty else (2,)), executions
    for call in executions[1:]:
        assert call.name == "execve" and call.ret == "0" and '"__refresh-v1"' in call.args, call
        assert call.pid != calls.first_pid, call
    assert "__collect" not in text, text
    front = [call for call in calls if call.pid == calls.first_pid]
    spawns = [call for call in front if call.name in ("clone", "clone3", "fork", "vfork")
              and re.fullmatch(r"[1-9][0-9]*", call.ret)]
    assert len(spawns) == len(executions) - 1, spawns
    if spawns:
        assert int(spawns[0].ret) == executions[1].pid, spawns
    exec_status_reads = helper_exec_status_reads(front, spawns)
    for call in front:
        assert call.name not in {"wait4", "waitid", "waitpid"} and not call.name.startswith("pidfd_"), (
            "front collection wait", call)
        if call.name in {"poll", "ppoll", "select", "pselect6"}:
            assert not poll_waits_for_collection(call), ("front collection wait", call)
        if call.name in {"read", "readv", "pread64", "preadv", "preadv2",
                         "recvfrom", "recvmsg", "recvmmsg"}:
            if call.index in exec_status_reads:
                continue
            fd = scan(call.args)[0][0]
            # Files and standard fds are allowed. Nonstandard IPC can wait
            # for collection, even when an alarm cuts the call short or it
            # returns EAGAIN instead of blocking.
            assert not re.fullmatch(r"(?:[3-9]|[1-9][0-9]+)<(?:pipe:|socket:|anon_inode:).*>", fd), (
                "front collection read", call)


def assert_prompt_record(output):
    assert (len(output) <= 65536 and output.startswith(b"B1\x1f8\x1f")
            and output.endswith(b"\x1e") and output.count(b"\x1e") == 1
            and output.count(b"\x1f") == 9), ("malformed prompt record", output)
    assert re.fullmatch(rb"[a-z]+:[a-z-]+\x1e", output.rsplit(b"\x1f", 1)[1]), (
        "malformed prompt status", output)


# 이것을 실패시키는 것: 제거한 legacy collector 진입점을 다시 허용하는 것.
def test_legacy_collector_entry_is_removed():
    result = subprocess.run([str(real_bin()), "__collect-legacy-v1"],
                            capture_output=True, timeout=2)
    assert result.returncode == 2, result
    assert result.stdout == b""


# 이것을 실패시키는 것: 앞단의 collection 대기, 제품 worker 생성 또는 실제 trace 회차 생략.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace acceptance row")
def test_four_hundred_product_prompts_never_wait_for_collection(tmp_path, capsys):
    strace = shutil.which("strace")
    assert strace, "this Linux acceptance test must execute strace"
    session = SnapshotSession(tmp_path)
    session.put("icons = 'ascii'\n")
    session.init()
    assert session.run("reload").returncode == 0
    records = deadline_empty = 0
    for index in range(400):
        trace = tmp_path / f"lifecycle-{index}.trace"
        result = subprocess.run(
            [strace, "-f", "-q", "-y", "-s", "65536", "-e",
             "trace=process,signal,pipe,pipe2,close,pidfd_open,pidfd_send_signal,pidfd_getfd,waitid,"
             "read,readv,pread64,preadv,preadv2,recvfrom,recvmsg,recvmmsg,poll,ppoll,select,pselect6",
             "-o", str(trace), str(real_bin()), *session.prompt_args()],
            env=session.env, capture_output=True, timeout=4)
        assert result.returncode == 0 and result.stderr == b"", result
        # Validate every trace, including empty deadline exits. strace overhead
        # consumes the same absolute 50 ms product budget; record frequency is
        # not evidence of whether the front waited for collection.
        assert_no_collection_wait(trace.read_text(), deadline_empty=not result.stdout)
        if result.stdout:
            assert_prompt_record(result.stdout)
            records += 1
        else:
            deadline_empty += 1
    with capsys.disabled():
        print(f"\ncollection lifecycle: records={records}, deadline-empty={deadline_empty}, "
              f"traced={records + deadline_empty}")
    assert records + deadline_empty == 400, "all prompt traces must actually execute"
    assert records > 0, "all 400 traced prompts were empty; no product record was observed"
    assert not list(session.store().rglob("collection.lock"))


def lifecycle_trace(extra=""):
    """Small portable trace fixture: only the refresh helper may be spawned."""
    return ('10 execve("/bin/bingsu", ["/bin/bingsu", "prompt"], 0x1) = 0\n'
            '10 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 11\n'
            '11 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], 0x2) = 0\n'
            + extra + '10 exit_group(0) = ?\n10 +++ exited with 0 +++\n'
            '11 +++ exited with 0 +++\n')


# 이것을 실패시키는 것: 빈 출력 허용이 앞단의 collector 대기도 허용하는 것.
@pytest.mark.parametrize("extra,error", [
    ('10 wait4(11, NULL, 0, NULL) = 11\n', "collection wait"),
    ('10 wait4(11, NULL, 0, NULL) = -1 ECHILD (No child processes)\n', "collection wait"),
    ('10 waitid(P_PIDFD, 7<anon_inode:[pidfd]>, {}, WEXITED, NULL) = 0\n', "collection wait"),
    ('10 read(7<pipe:[123]>, "", 64) = 0\n', "collection read"),
    ('10 readv(7<socket:[123]>, [], 0) = 0\n', "collection read"),
    ('10 read(7<pipe:[123]>,  <unfinished ...>\n', "collection read"),
    ('10 poll([{fd=7<anon_inode:[pidfd]>, events=POLLIN}], 1, -1) = 0\n', "collection wait"),
    ('10 poll([{fd=7<pipe:[123]>, events=POLLIN}], 1, 0) = 0\n', "collection wait"),
    ('10 poll([{fd=0</dev/null>, events=0}], 1, 1) = 0\n', "collection wait"),
    ('10 ppoll([{fd=0</dev/null>, events=0}], 1, NULL, NULL, 0) = 0\n', "collection wait"),
    ('10 ppoll([{fd=0</dev/null>, events=0}], 1, {tv_sec=0, tv_nsec=1}, NULL, 0) = 0\n',
     "collection wait"),
    ('10 ppoll([{fd=7<pipe:[123]>, events=0}], 1, {tv_sec=0, tv_nsec=0}, NULL, 0) = 0\n',
     "collection wait"),
    ('10 select(3, [0</dev/null>], NULL, NULL, {tv_sec=0, tv_usec=1}) = 0\n', "collection wait"),
    ('10 select(8, [7<pipe:[123]>], NULL, NULL, {tv_sec=0, tv_usec=0}) = 0\n', "collection wait"),
    ('10 pselect6(3, [0</dev/null>], NULL, NULL, NULL, NULL) = 0\n', "collection wait"),
    ('10 pselect6(8, [7<pipe:[123]>], NULL, NULL, {tv_sec=0, tv_nsec=0}, NULL) = 0\n',
     "collection wait"),
    ('10 pidfd_open(11, 0) = 7<anon_inode:[pidfd]>\n', "collection wait"),
    ('10 pidfd_send_signal(7<anon_inode:[pidfd]>, 0, NULL, 0) = 0\n', "collection wait"),
    ('10 pidfd_getfd(7<anon_inode:[pidfd]>, 0, 0) = 8<pipe:[123]>\n', "collection wait"),
    ('10 clone(child_stack=NULL, flags=SIGCHLD) = 12\n', None),
    ('12 execve("/bin/bingsu", ["/bin/bingsu", "__collect-v1"], 0x3) = 0\n', None),
])
def test_lifecycle_trace_rejects_collection_wait_mutations(extra, error):
    # No stdout/record is needed for this check: a deadline-empty run must fail
    # for the same wait mutation as a run that managed to emit a record.
    with pytest.raises(AssertionError, match=error):
        assert_no_collection_wait(lifecycle_trace(extra), deadline_empty=True)


def test_lifecycle_trace_allows_rust_startup_ppoll():
    # Preserve the exact Debian bookworm trace that triggered the false positive.
    startup = ('3675 ppoll([{fd=0</dev/null>, events=0}, {fd=1<pipe:[237063]>, events=0}, '
               '{fd=2<pipe:[237064]>, events=0}], 3, {tv_sec=0, tv_nsec=0}, NULL, 0) = 0 (Timeout)\n')
    trace = lifecycle_trace(startup).replace('10 ', '3675 ')
    assert_no_collection_wait(trace)
    assert_no_collection_wait(trace, deadline_empty=True)


def musl_spawn_trace(read='1829 read(3<pipe:[70689]>, "", 4) = 0\n', *, pipe="pipe2"):
    creation = ('1829 pipe2([3<pipe:[70689]>, 4<pipe:[70689]>], O_CLOEXEC) = 0\n'
                if pipe == "pipe2" else
                '1829 pipe([3<pipe:[70689]>, 4<pipe:[70689]>]) = 0\n')
    trace = lifecycle_trace().replace('10 ', '1829 ')
    trace = trace.replace('1829 clone(', creation + '1829 clone(')
    return trace.replace('1829 exit_group(',
                         '1829 close(4<pipe:[70689]>) = 0\n' + read
                         + '1829 close(3<pipe:[70689]>) = 0\n1829 exit_group(')


# 이것을 실패시키는 것: musl의 helper exec 상태 pipe를 collection 대기로 오인하는 것.
def test_lifecycle_trace_allows_musl_helper_exec_status_eof():
    # Preserve the exact minimum-shell failure, including its PID, pipe and count.
    trace = musl_spawn_trace()
    assert '1829 read(3<pipe:[70689]>, "", 4) = 0\n' in trace
    assert_no_collection_wait(trace)
    assert_no_collection_wait(trace, deadline_empty=True)


@pytest.mark.parametrize("pipe", ["pipe", "pipe2"])
@pytest.mark.parametrize("read", [
    '1829 read(3<pipe:[70689]>, "", 1) = 0\n',
    '1829 read(3<pipe:[70689]>, "", 2) = 0\n',
    '1829 read(3<pipe:[70689]>, "", 3) = 0\n',
    '1829 read(3<pipe:[70689]>, "\\2\\0\\0\\0", 4) = 4\n',
])
def test_lifecycle_trace_allows_bounded_helper_exec_status(read, pipe):
    assert_no_collection_wait(musl_spawn_trace(read, pipe=pipe))


@pytest.mark.parametrize("read,error", [
    ('1829 wait4(11, NULL, 0, NULL) = 11\n'
     '1829 read(3<pipe:[70689]>, "", 4) = 0\n', "collection wait"),
    ('1829 read(7<pipe:[123]>, "", 4) = 0\n', "collection read"),
    ('1829 read(3<pipe:[123]>, "", 4) = 0\n', "collection read"),
    ('1829 read(4<pipe:[70689]>, "", 4) = 0\n', "collection read"),
    ('1829 read(3<pipe:[70689]>, "", 5) = 0\n', "collection read"),
    ('1829 read(3<pipe:[70689]>, "", 0) = 0\n', "collection read"),
    ('1829 read(3<pipe:[70689]>, "", 4) = -1 EAGAIN (Resource temporarily unavailable)\n',
     "collection read"),
    ('1829 readv(3<pipe:[70689]>, [], 0) = 0\n', "collection read"),
    ('1829 read(3<pipe:[70689]>, "", 4) = 0\n'
     '1829 read(3<pipe:[70689]>, "", 4) = 0\n', "collection read"),
    ('1829 close(3<pipe:[70689]>) = 0\n'
     '1829 read(3<pipe:[70689]>, "", 4) = 0\n', "collection read"),
])
def test_musl_spawn_exception_rejects_collection_wait_mutations(read, error):
    with pytest.raises(AssertionError, match=error):
        assert_no_collection_wait(musl_spawn_trace(read), deadline_empty=True)


@pytest.mark.parametrize("extra,error", [
    ('1829 wait4(11, NULL, 0, NULL) = 11\n', "collection wait"),
    ('1829 read(7<pipe:[123]>, "", 4) = 0\n', "collection read"),
])
def test_musl_exec_status_read_does_not_exempt_later_collection_waits(extra, error):
    trace = musl_spawn_trace().replace('1829 exit_group(', extra + '1829 exit_group(')
    with pytest.raises(AssertionError, match=error):
        assert_no_collection_wait(trace, deadline_empty=True)


@pytest.mark.parametrize("old,new", [
    ('1829 pipe2(', '11 pipe2('),
    (', O_CLOEXEC)', ', 0)'),
    (' = 0\n1829 clone(', ' = -1 EMFILE (Too many open files)\n1829 clone('),
    ('1829 clone(', '1829 read(7</file>, "x", 1) = 1\n1829 clone('),
    ('1829 pipe2([3<pipe:[70689]>, 4<pipe:[70689]>], O_CLOEXEC) = 0\n', ''),
])
def test_musl_spawn_exception_requires_own_pipe_just_before_spawn(old, new):
    with pytest.raises(AssertionError, match="collection read"):
        assert_no_collection_wait(musl_spawn_trace().replace(old, new))


@pytest.mark.parametrize("extra", [
    '10 poll([{fd=0</dev/null>, events=0}, {fd=1<pipe:[123]>, events=0}], 2, 0) = 0 (Timeout)\n',
    '10 select(3, [0</dev/null>], [1<pipe:[123]>], [2<pipe:[456]>], {tv_sec=0, tv_usec=0}) = 0\n',
    '10 pselect6(3, [0</dev/null>], [1<pipe:[123]>], NULL, {tv_sec=0, tv_nsec=0}, NULL) = 0\n',
    '10 read(0<pipe:[123]>, "", 64) = 0\n',
])
def test_lifecycle_trace_allows_standard_fd_checks(extra):
    assert_no_collection_wait(lifecycle_trace(extra))


def test_lifecycle_trace_allows_file_reads_and_deadline_exit():
    assert_no_collection_wait(lifecycle_trace(
        '10 read(7</store/collections-v1/response>, "header", 6) = 6\n'))
    assert_no_collection_wait('10 execve("/bin/bingsu", ["bingsu", "prompt"], 0x1) = 0\n'
                              '10 exit_group(0) = ?\n10 +++ exited with 0 +++\n',
                              deadline_empty=True)
    assert_prompt_record(minimal_record())


@pytest.mark.parametrize("output", [b"garbage", b"B1\x1fpartial", b"B1\x1f8\x1e",
                                   minimal_record() * 2, minimal_record(status=b"bad")])
def test_lifecycle_rejects_malformed_nonempty_output(output):
    with pytest.raises(AssertionError, match="malformed prompt"):
        assert_prompt_record(output)


@pytest.mark.parametrize("records", [0, 1])
def test_lifecycle_counts_deadline_empty_runs_but_requires_a_record(tmp_path, monkeypatch, capsys, records):
    session = SimpleNamespace(env={}, put=lambda _: None, init=lambda: None,
                              run=lambda _: subprocess.CompletedProcess([], 0),
                              prompt_args=lambda: ["prompt"], store=lambda: tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "SnapshotSession", lambda _: session)
    monkeypatch.setattr(shutil, "which", lambda _: "strace")

    def run(command, **kwargs):
        path = Path(command[command.index("-o") + 1])
        path.write_text(lifecycle_trace())
        index = int(path.stem.split("-")[1])
        return subprocess.CompletedProcess(command, 0, minimal_record() if index < records else b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    expected = pytest.raises(AssertionError, match="all 400 traced prompts were empty") if not records else nullcontext()
    with expected:
        # Keep the fixture's report captured; the real acceptance run reports
        # through capsys.disabled() even with the requested pytest -q gate.
        test_four_hundred_product_prompts_never_wait_for_collection(
            tmp_path, SimpleNamespace(disabled=nullcontext))
    report = capsys.readouterr().out
    assert f"records={records}, deadline-empty={400 - records}, traced=400" in report


ROLES = {"front", "helper", "collector"}


def lingering_zombies(grace=0.25):
    """Zombies with a role parent that are still there after `grace` seconds.

    A collector that just exited stays a zombie until the helper's next reap
    poll (1 ms); only one that outlives the grace was left unreaped."""
    seen = set(zombie_children(ROLES))
    end = time.monotonic() + grace
    while seen and time.monotonic() < end:
        seen &= set(zombie_children(ROLES))
        time.sleep(0.005)
    return sorted(seen)


@contextlib.contextmanager
def subreaper():
    """Make this process the subreaper of its descendants for the block.

    The front never waits for its helper, so helpers' launchers end up here;
    a collector ends up here only when its helper exited without reaping it.
    reap_orphans() reaps the zombies that reached this process and returns
    the PIDs of those that were collectors."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0, ctypes.get_errno()  # PR_SET_CHILD_SUBREAPER
    try:
        yield
    finally:
        libc.prctl(36, 0, 0, 0, 0)
        reap_orphans()


def reap_orphans():
    collectors = []
    for entry in Path("/proc").iterdir():
        try:
            fields = dict(line.split(":", 1) for line in (entry / "status").read_text().splitlines() if ":" in line)
        except OSError:
            continue
        pid = int(entry.name) if entry.name.isdigit() else None
        if pid is None or fields["State"].split()[0] != "Z" or int(fields["PPid"]) != os.getpid():
            continue
        if fields["Name"].strip() == "bingsu-collect":
            collectors.append(pid)
        os.waitpid(pid, os.WNOHANG)
    return collectors


def stalled(pid):
    """True while the process waits in the kernel on an unanswered FUSE request."""
    try:
        channel = Path(f"/proc/{pid}/wchan").read_text()
    except OSError:
        return False
    return "fuse" in channel or "request_wait_answer" in channel


# 이것을 실패시키는 것: OwnedChild::reap에서 waitid를 지우는 것(죽인 collector가 도우미 아래 좀비로 남아
# 회수 시도가 도우미 마감까지 이어진다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc census and FUSE fixture")
def test_n_prompts_leave_zero_zombies_including_killed_children(tmp_path, capsys):
    """GATE-ZOMBIES.1: N=400 product prompts leave no zombie under a role process.

    The run mixes completed collections, collectors killed at their request
    deadline (their folder is on a stopped FUSE mount) and helpers killed by
    the watchdog at their 2 s lifetime (their config root is on that mount).
    After every prompt no zombie with a front, helper or collector parent may
    outlive a short grace; after the run and one lifetime no role process is left."""
    holder = {}
    folders = [f"d{index}" for index in range(40)]

    def prepare(mount):
        stalled_config = LifetimeSession(tmp_path / "w", tag="w", config=mount / "cfg")
        stalled_config.put(appearance("WATCHDOG"))
        stalled_config.init()
        stalled_config.wait_quiet()
        for name in folders:
            (mount / name).mkdir()
        holder["w"] = stalled_config

    try:
        with subreaper(), blocked_mount(tmp_path / "fuse", prepare=prepare) as mount:
            watched = holder["w"]
            session = LifetimeSession(tmp_path / "s", tag="s")
            repo = session.base / "repo"
            try:
                session.put("[style]\ntemplate='Z {dir} {git} {char}'\n")
                session.init()
                session.wait_quiet()
                repo.mkdir()
                subprocess.run(["git", "init", "-q", str(repo)], check=True, env={"PATH": os.environ["PATH"]})
                records = live_samples = 0
                killed_collectors, seen = set(), set()
                for index in range(400):
                    if index % 100 == 50:
                        watched.prompt()
                    elif index % 10 == 5:
                        records += bool(session.prompt_at(mount / folders[index // 10]))
                    else:
                        records += bool(session.prompt_at(repo))
                    collectors = role_processes({"collector"})
                    seen |= {pid for pid in collectors if stalled(pid)}
                    # A stalled collector cannot leave the stopped mount on its own: gone means killed.
                    killed_collectors |= seen - set(collectors)
                    live_samples += bool(role_processes({"helper"}))
                    assert not (left := lingering_zombies()), ("zombies left under a role process", index, left)
                    # 이것을 실패시키는 것: 죽인 collector만 회수하지 않고 회수했다고 보고하는 것(도우미가 끝나며 좀비가 여기로 온다).
                    assert not (orphaned := reap_orphans()), ("collectors their helper exited without reaping", index, orphaned)
                poll(lambda: not role_processes(ROLES), helper_lifetime_s() + 1, "role processes outlived the lifetime")
                assert zombie_children(ROLES) == [] and reap_orphans() == []
                session.wait_quiet()
                watched.wait_quiet()
                watchdog_kills = watched.statuses().count(-signal.SIGKILL)
                with capsys.disabled():
                    print(f"\nzombie census: records={records}, live-helper-samples={live_samples}, "
                          f"collector-kills={len(killed_collectors)}, watchdog-kills={watchdog_kills}")
                assert records > 0 and live_samples > 0, (records, live_samples)
                assert killed_collectors, "no collector was seen killed at its deadline"
                assert watchdog_kills > 0, ("no helper was killed by the watchdog", watched.statuses())
            finally:
                stop_helpers(watched, session)
    except Blocked as error:
        fail_blocked(error)
