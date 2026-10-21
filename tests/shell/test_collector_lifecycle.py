"""Product lifecycle evidence; builds belong to the native test jobs."""
from contextlib import nullcontext
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from conftest import ROOT, minimal_record, real_bin
from snapshot_support import SnapshotSession

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
    for call in front:
        assert call.name not in {"wait4", "waitid", "waitpid"} and not call.name.startswith("pidfd_"), (
            "front collection wait", call)
        if call.name in {"poll", "ppoll", "select", "pselect6"}:
            assert not poll_waits_for_collection(call), ("front collection wait", call)
        if call.name in {"read", "readv", "pread64", "preadv", "preadv2",
                         "recvfrom", "recvmsg", "recvmmsg"}:
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
             "trace=process,signal,pidfd_open,pidfd_send_signal,pidfd_getfd,waitid,"
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
