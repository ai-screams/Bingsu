"""Judging one capture: helper stage captures, front captures and the deadline
and marker attempts, on top of the call vocabulary of `trace_support.py`."""
import re
import sys

import pytest
from shell_support import ROOT

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import EXIT_EVENT, parse as parse_trace

from trace_support import OPENS, RESPONSE_HEADERS, ROOT_CALLS, args_of, assert_prompt_trace_budget, call_paths, content_paths, is_root, prompt_collection_sources, prompt_cwd, prompt_root_io, prompt_sources, successful_spawns, tree


def collector_exit(lines, collector):
    """The traced collector's exit code. 75 is wire::DEADLINE_EXIT_CODE: the
    collector ran past its 50 ms request deadline. The supervisor still
    publishes a Deadline partial when a verified update arrived before it."""
    pid = next(l.split()[0] for l in lines if is_root(l, collector))
    ends = [l for l in lines if l.split()[0] == pid and "+++ exited with" in l]
    assert len(ends) == 1, ("collector end", ends)
    return int(ends[0].split("exited with")[1].split()[0])


def measured_helper_attribution(lines, exe, collector, helper_vocabulary=True):
    """Helper-role counts of one traced prompt, in the helper vocabulary.

    Errors about the front or the helper (and parse or attribution errors)
    fail the gate; the collector's own calls are gated by the collector
    security rows, outside this formula.
    """
    from fsbudget.attribute import collector_attribute
    _, scoped = tree(lines, exe)
    collectors = sum(is_root(line, collector) for line in scoped)
    # The command supervisor and relay are the pinned binary's other verbs;
    # they and the target are counted in their own roles, never the helper's.
    roles = collector_attribute(scoped, {"front": exe, "helper": exe, "collector": collector,
                                         "supervisor": exe, "relay": exe,
                                         "collectors": collectors}, helper_vocabulary=helper_vocabulary)
    errors = [e for e in roles.errors if "(collector):" not in e]
    assert not errors, errors
    return collectors, roles


def measured_helper_calls(lines, exe, collector, helper_vocabulary=True):
    collectors, roles = measured_helper_attribution(lines, exe, collector, helper_vocabulary)
    return collectors, roles.counts


def check_helper_capture(stage, lines, exe, collector, plan, *, evidence=None):
    from fsbudget.formula import (helper_stage_expected, helper_collect_expected, helper_command_expected,
                                  helper_builtin_expected, supervisor_expected)
    from fsbudget.gate import check, check_builtin, check_collect, check_command
    if evidence is None:
        evidence = {}
    builtin = stage.startswith("builtin_")
    status = collector_exit(lines, collector) if stage == "collect" or builtin else None
    evidence["collector_exit"] = status
    collectors, roles = measured_helper_attribution(lines, exe, collector)
    evidence["role_counts"] = roles.counts
    assert collectors == int(stage == "collect" or builtin), ("collector spawns", collectors)
    command_roles = {"supervisor", "relay", "command"} & set(roles.counts)
    # 이것을 실패시키는 것: 명령 단계에서 감독·relay·대상 역할이 비는 것(그 호출이 helper에 섞임), 명령 없는
    # 단계나 실행할 것 없는 명령 단계에 그 역할이 생기는 것.
    # Builtin stages: their exact supervisor check below fails on a missing
    # or extra role's calls.
    assert builtin or command_roles == ({"supervisor", "relay", "command"} if stage == "command_miss"
                                        else set()), command_roles
    if builtin:
        # GATE-FS-HELPER.1 builtin stages; GATE-CMD-FSBUDGET.1: the probe's
        # supervisor spawns one relay as a unit round's does, the fast path's
        # starts with nothing to run (idle). Which formula applies comes from
        # the trace: a round that published the collection's response (even
        # after a deadline) is held to the full one; without it, the deadline
        # bounds apply and the stage tries again. The command supervisor is
        # always checked exactly, by the relays it spawned.
        # 이것을 실패시키는 것: 내장 단계의 감독 호출을 정확 비교에서 빼는 것, fast 감독을 단위 회차 식으로 보는 것,
        # 마감 회차의 판정을 종료 코드로 정하는 것, 응답 없는 정상 종료를 받는 것.
        assert status in (0, 75), ("unexpected collector exit", status)
        errors, published, installed = check_builtin(
            roles, helper_builtin_expected(plan), stage, deadline=helper_builtin_expected(plan, deadline=True),
            evidence=evidence)
        if status == 0 and not published:
            errors.append("builtin: the collector answered but no response was published")
        # The probe stage's fixture runs its probe once: a round that had an
        # answer or installed a result spawned one relay. Only a probe round
        # without either (a deadline with nothing verified) leaves the
        # supervisor idle, as the fast stage always does.
        # 이것을 실패시키는 것: 측정한 생성 수로 idle을 고르는 것(발행한 probe 회차가 relay 없이 통과).
        idle = stage == "builtin_fast" or not (published or installed)
        supervisor = {"supervisor": supervisor_expected(0 if idle else 1, atomic=plan.cgroup_parent, arch=plan.arch,
                                                        libc=plan.libc, idle=idle)}
        evidence.update(supervisor_counts=roles.counts.get("supervisor", {}), supervisor_expected=supervisor["supervisor"],
                        relay_counts=roles.counts.get("relay", {}))
        errors += check({"supervisor": roles.counts.get("supervisor", {})}, supervisor, "exact", ["supervisor"])
    elif stage == "command_miss":
        errors = check_command(roles, helper_command_expected(plan), evidence=evidence)
        # GATE-CMD-FSBUDGET.1: the supervisor's calls, exact for this round's
        # one spawn on the path the host gave (the atomic path with the
        # session's cgroup parent, best effort without). The relay and the
        # target are counted only.
        # 이것을 실패시키는 것: 감독 식에서 시계·생성·cgroup 항 하나를 빼거나 더하는 것, 원자 경로와 최선 노력
        # 경로를 바꿔 세는 것, 감독 호출을 정확 비교에서 빼는 것.
        supervisor = {"supervisor": supervisor_expected(1, atomic=plan.cgroup_parent, arch=plan.arch, libc=plan.libc)}
        evidence.update(supervisor_counts=roles.counts.get("supervisor", {}), supervisor_expected=supervisor["supervisor"],
                        relay_counts=roles.counts.get("relay", {}))
        errors += check({"supervisor": roles.counts.get("supervisor", {})}, supervisor, "exact", ["supervisor"])
        published = False
    elif stage != "collect":
        measured = {"helper": roles.counts.get("helper", {})}
        expected = {"helper": helper_stage_expected(plan)}
        evidence.update(phase_counts=measured, phase_expected=expected)
        errors = check(measured, expected, "exact", ["helper"])
        published = False
    else:
        assert status in (0, 75), ("unexpected collector exit", status)
        deadline = helper_collect_expected(plan, deadline=True) if status == 75 else None
        errors, published = check_collect(roles, helper_collect_expected(plan),
                                          deadline=deadline, evidence=evidence)
    evidence.update(published=published, errors=errors)
    assert not errors, errors
    return published


# 이것을 실패시키는 것: 도우미 재검증 경로에 같은 파일의 fstat 하나를 더하는 것, 수집 비용을 앞단으로 옮기는 것,
# 공식에 옛 고정 항(e["read"] += 2)을 되살리는 것, debug 바이너리로 재는 것, helper 어휘에서 fd statx나
# chdir를 지우는 것, 제품이 chdir·mkdirat·fchmod·lseek·dup 호출을 하나 더 내는 것,
# 마감 회차의 호출을 버리거나 최대 COLLECT_ATTEMPTS(40)회에서 실제 응답 발행이 한 번도 없는 것.
# Under strace the collector can miss its deadline (exit 75) several times in a
# row on a loaded runner; every such attempt is still checked in full. CI musl
# release published in 1 of 8 attempts: (7/8)**12 is about 0.20 per run, (7/8)**40
# about 0.005. The loop stops at the first publication, so only runs near failure
# pay for more attempts (an attempt took about 0.5-0.9 s in CI).
COLLECT_ATTEMPTS = 40


# A fixture in a module that is not a test file: `test_prompt_env_paths.py` imports it by name, which is how
# pytest finds it for the live helper-stage test; `test_prompt_trace_budget.py` calls `.__wrapped__` directly.
@pytest.fixture
def helper_stage_evidence(tmp_path_factory):
    # A dedicated upload root, separate from all other pytest fixtures.
    return tmp_path_factory.getbasetemp() / "helper-stage-evidence"


# Fixture metadata, pinned independently from the product source.
FRONT_CHUNK = 16 * 1024


FRONT_CASES = ('normal', 'checksum-last-good', 'body-limit', 'header-only', 'selected-band', 'env-segment')


def front_attempt_plan(case, body, through_index=None):
    """`body` bytes read through the selected variant; a checksum failure stops
    the current copy at `through_index` bytes."""
    from fsbudget.formula import FrontAttempt
    read = {'normal': body, 'selected-band': body, 'env-segment': body, 'body-limit': 0, 'header-only': 0,
            'checksum-last-good': body if through_index is None else through_index}[case]
    current = FrontAttempt('current', True, case not in ('header-only', 'body-limit'), read, read > 0)
    one_copy = case in ('normal', 'selected-band', 'env-segment')
    return [current] + ([] if one_copy else [FrontAttempt('last_good', True, True, body, True)])


def assert_front_reads(trace, store, attempts, *, evidence=None):
    from fsbudget.formula import front_read_bytes
    paths = [str(store / name) for name in ('snapshot', 'last-good', 'marker')]
    boot = '/proc/sys/kernel/random/boot_id'
    expected = {path: [] for path in paths}
    for a in attempts:
        path = paths[0 if a.copy == 'current' else 1]
        expected[path] = ([64] if a.header_read else []) + ([128] if a.prefix_read else [])
        expected[path] += [min(FRONT_CHUNK, a.body_bytes_read - offset)
                           for offset in range(0, a.body_bytes_read, FRONT_CHUNK)]
    expected[paths[2]] = [208]
    expected[boot] = [37, 0]  # in-place procfs boot observation: final EOF required
    actual = {path: [] for path in expected}
    for call in trace:
        args = args_of(call)
        if call.name == 'read' and args:
            match = re.fullmatch(r'\d+<(/[^<>]*)>', args[0])
            if match and match[1] in actual:
                actual[match[1]].append(int(call.ret))
    measured = front_read_bytes(trace, list(expected))
    if evidence is not None:
        evidence.update(read_chunks=actual, expected_chunks=expected, read_bytes=measured)
    # 이것을 실패시키는 것: TrustMetadata까지 읽게 길이 계산 변경, last-good 선택 뒤 현재 사본 재읽기.
    assert actual == expected, ('front read sequence', actual, expected)
    # 이것을 실패시키는 것: 사본별 바이트를 합산해 초과 읽기를 다른 사본의 여유로 상쇄하는 것.
    assert measured == {path: sum(chunks) for path, chunks in expected.items()}


def front_fact_kind(call):
    """Count each libc's held-fd primitive; pathname stats cannot substitute."""
    args = args_of(call)
    # 이것을 실패시키는 것: 플랫폼 fd stat 변형을 ignore하거나 pathname stat으로 대체하는 것.
    if call.name == 'fstat':
        return 'fstat'
    if call.name == 'newfstatat' and args[1] == '""' and args[3] == 'AT_EMPTY_PATH':
        return 'fstat'
    if (call.name == 'statx' and args[1] == '""'
            and args[2] == 'AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH' and args[3] == 'STATX_BASIC_STATS'):
        return 'fstat'
    raise AssertionError(('unexpected front facts primitive', call))


def front_env_pipe_calls(front, boundary, spawns):
    """Exact environment pipe of the front: only with a helper spawn, before the filter."""
    pipes = [c for c in front if c.name == 'pipe2' and c.args.endswith('O_NONBLOCK|O_CLOEXEC')]
    # 이것을 실패시키는 것: 도우미를 띄우지 않는 회차에도 환경 파이프를 만드는 것(env-no-spawn).
    assert len(pipes) == len(spawns), ('front environment pipe count', pipes, spawns)
    accounted = []
    for pipe in pipes:
        match = re.fullmatch(r'\[(\d+)<pipe:\[(\d+)\]>, (\d+)<pipe:\[\2\]>\], O_NONBLOCK\|O_CLOEXEC', pipe.args)
        assert match and pipe.ret == '0', ('front environment pipe creation', pipe)
        reader, inode, writer = match.groups()
        read_fd, write_fd = (f'{fd}<pipe:[{inode}]>' for fd in (reader, writer))
        # Every call that names either end, wherever in its arguments: a poll,
        # select or splice on the pipe is not in the allowed shape.
        # 이것을 실패시키는 것: 이름 목록에 든 호출만 보는 것(쓰기 쪽 poll이 끼어도 통과, env-poll-writer).
        names = re.compile(rf"(?<![0-9])(?:{re.escape(read_fd)}|{re.escape(write_fd)})")
        channel = [c for c in front if c is not pipe and names.search(c.args)]
        shape = [(c.name, args_of(c)[0] if args_of(c) else '') for c in channel]
        # Write, write-end close, spawn, read-end close, all before the filter. A retried
        # write is also caught by the primitive count below.
        # 이것을 실패시키는 것: 쓰기 쪽을 생성 뒤에 닫는 것(test_prompt_trace_budget.py의 env-open-writer).
        assert (shape == [('write', write_fd), ('close', write_fd), ('close', read_fd)]
                and pipe.index < channel[0].index < channel[1].index < spawns[0].index < channel[2].index < boundary), (
            'front environment pipe sequence', pipe, channel, spawns)
        write = channel[0]
        # 이것을 실패시키는 것: 일부만 받아들인 쓰기를 통과시키는 것(env-short).
        assert write.ret == args_of(write)[2], ('one write takes the whole frame', write)
        accounted.extend([pipe, *channel])
    return accounted


def front_spawn_pipe_calls(front, boundary, libc, evidence):
    """Exact parent error channel, never a general pipe exemption."""
    from collections import Counter
    from fsbudget.formula import ENV_PIPE_PRIMITIVES, POSIX_SPAWN_PRIMITIVES
    spawns = successful_spawns(front)
    assert len(spawns) <= 1, ('front helper spawns', spawns)
    expected = Counter(POSIX_SPAWN_PRIMITIVES[libc]) if spawns else Counter()
    accounted = front_env_pipe_calls(front, boundary, spawns)
    if spawns:
        expected.update(ENV_PIPE_PRIMITIVES)
    pipes = [c for c in front if c.name == 'pipe2' and c.index not in {a.index for a in accounted}]
    error_pipes = POSIX_SPAWN_PRIMITIVES[libc].get('pipe2', 0) if spawns else 0
    assert len(pipes) == error_pipes, ('front spawn pipe count', pipes, expected)
    for pipe in pipes:
        match = re.fullmatch(r'\[(\d+)<pipe:\[(\d+)\]>, (\d+)<pipe:\[\2\]>\], O_CLOEXEC', pipe.args)
        assert match and pipe.ret == '0', ('front spawn pipe creation', pipe)
        reader, inode, writer = match.groups()
        assert reader != writer, ('front spawn pipe endpoints', pipe)
        read_fd, write_fd = (f'{fd}<pipe:[{inode}]>' for fd in (reader, writer))
        # Include every read/close on this pipe: duplicates cannot borrow slack.
        channel = [c for c in front if c.name in ('read', 'close')
                   and args_of(c)[0] in (read_fd, write_fd)]
        assert [(c.name, args_of(c), c.ret) for c in channel] == [
            ('close', [write_fd], '0'),
            ('read', [read_fd, '""', '4'], '0'),
            ('close', [read_fd], '0'),
        ], ('front spawn pipe sequence', channel)
        assert pipe.index < spawns[0].index < channel[0].index, ('front spawn pipe order', pipe, spawns)
        assert all(c.index < boundary for c in [pipe, *channel]), ('late front spawn pipe', channel)
        accounted.extend([pipe, *channel])
    actual = Counter(c.name for c in accounted)
    evidence.update(spawn_pipe_counts=actual, spawn_pipe_expected=expected)
    assert actual == expected, ('front spawn pipe primitives', actual, expected)
    return {c.index for c in accounted}


def check_front_capture(lines, exe, pinned, store, attempts, *, arch, libc, evidence):
    from collections import Counter
    from fsbudget.strace_parse import Trace
    from fsbudget.formula import front_attempts_expected, collection_front_expected, STARTUP_PRIMITIVES
    _, scoped = tree(lines, exe)
    root = int(next(line.split()[0] for line in scoped if is_root(line, exe)))
    parsed = parse_trace('\n'.join(scoped))
    # 이것을 실패시키는 것: 불완전 캡처 또는 필터 없이 앞단 계수를 통과시키는 것.
    assert not parsed.errors, parsed.errors
    front = Trace()
    front.extend(c for c in parsed if c.pid == root and c.name != EXIT_EVENT)
    # 이것을 실패시키는 것: trace=all에 새 syscall을 남겨도 계수 대상이 아니라며 버리는 것.
    startup_model = STARTUP_PRIMITIVES[arch, libc]
    # lseek is counted below, never ignored or allowed on arbitrary fds.
    assert all(c.name in ROOT_CALLS | {'lseek'} for c in front), [c for c in front if c.name not in ROOT_CALLS | {'lseek'}]
    # 이것을 실패시키는 것: snapshot을 mmap하여 TrustMetadata 읽기를 read 계수 밖으로 옮기는 것.
    for call in front:
        assert call.name != 'readv', ('unexpected front read primitive', call)
        if call.name != 'read':
            assert not set(content_paths(call)) & {str(store / n) for n in ('snapshot', 'last-good', 'marker')}, ('front content primitive', call)
    filters = [c.index for c in front if c.name == 'prctl' and 'PR_SET_SECCOMP' in c.args and c.ret == '0']
    assert len(filters) == 1, filters
    cwd = prompt_cwd(next(c for c in front if c.name == 'execve'))
    prompt_root_io(front, filters[0], exe, pinned, root, cwd)
    spawn_pipe_calls = front_spawn_pipe_calls(front, filters[0], libc, evidence)
    dirs, files = prompt_sources(pinned)
    collection_dirs, _ = prompt_collection_sources(pinned, cwd)
    boot_paths = {'/', '/proc', f'/proc/{root}', f'/proc/{root}/ns',
                  f'/proc/{root}/timens_offsets', '/proc/sys', '/proc/sys/kernel',
                  '/proc/sys/kernel/random', '/proc/sys/kernel/random/boot_id'}
    held, counts, primitives = {}, Counter(), Counter()
    startup = {name: Counter() for name in ('front_fds', 'front_cache', 'front_libgcc', 'front_libc', 'front_maps', 'stack_guard')}
    seeks = []

    def startup_kind(path):
        if path in ('/proc/self/fd', f'/proc/{root}/fd'):
            return 'front_fds'
        if path == '/etc/ld.so.cache':
            return 'front_cache'
        if path in ('/proc/self/maps', f'/proc/{root}/maps'):
            return 'front_maps'
        for suffix, kind in (('libgcc_s.so.1', 'front_libgcc'), ('libc.so.6', 'front_libc')):
            if re.fullmatch(r'/(?:usr/)?lib(?:64)?/(?:[^/]+/)?' + re.escape(suffix), path):
                return kind
        raise AssertionError(('unaccounted front startup path', path))
    for c in front:
        if c.index in spawn_pipe_calls:
            continue
        args = args_of(c)
        paths = call_paths(c)
        if c.name in OPENS:
            assert paths, ('unaccounted front open', c)
            kind = None if paths[0] in dirs | files | boot_paths | collection_dirs else startup_kind(paths[0])
            if kind is None:
                counts['openat'] += 1
            else:
                assert c.index < filters[0], ('late front startup open', c)
                startup[kind]['openat'] += 1
            if not c.ret.startswith('-1'):
                held[int(c.ret.split('<')[0])] = kind
            continue
        if c.name == 'getxattr':
            match = re.fullmatch(r'"/proc/self/fd/(\d+)"', args[0])
        else:
            match = re.fullmatch(r'(\d+)(?:<[^<>]*>)?', args[0]) if args else None
        fd = int(match[1]) if match else None
        if c.name in ('read', 'pread64', 'lseek'):
            assert fd in held, ('untracked front descriptor', c)
            kind = held[fd]
            if c.name == 'lseek':
                assert kind == 'front_maps' and c.index < filters[0], ('unexpected front seek', c)
                assert len(args) == 3 and not c.ret.startswith('-1'), ('front startup seek', c)
                seeks.append(args[2])
                startup['stack_guard']['seek'] += 1
            elif kind is None:
                assert c.name == 'read', ('unexpected front read primitive', c)
                counts['read'] += 1
            else:
                assert c.index < filters[0], ('late front startup read', c)
                startup[kind][c.name] += 1
            continue
        if fd not in held:
            continue
        if c.name == 'close':
            held.pop(fd)
        elif held[fd] is not None:
            continue
        elif c.name in ('fstat', 'newfstatat', 'statx'):
            counts[front_fact_kind(c)] += 1
            primitives[c.name] += 1
        elif c.name in ('fstatfs', 'fgetxattr', 'getxattr', 'readlinkat', 'read'):
            counts[c.name] += 1
    expected = Counter(front_attempts_expected(len(dirs), attempts, FRONT_CHUNK))
    # Plain config has no collection store: prefetch still probes its namespace.
    expected.update(collection_front_expected(0, (), (), absent=True))
    startup_expected = {name: Counter(startup_model.get(name, {})) for name in startup}
    evidence.update(C=len(dirs), counts=counts, expected=expected, fact_primitives=primitives,
                    arch=arch, libc=libc, startup_counts=startup, startup_expected=startup_expected)
    assert startup == startup_expected, ('front startup primitives', startup, startup_expected)
    assert seeks == (['SEEK_CUR', 'SEEK_SET'] if startup_model['stack_guard'].get('seek') else []), ('front startup seek pair', seeks)
    # 이것을 실패시키는 것: 앞단 open/facts/read 하나 추가, collection prefetch를 비용에서 빼는 것.
    assert counts == expected, ('front axis C', counts, expected)
    assert_front_reads(front, store, attempts, evidence=evidence)


def child_strace_argv(evidence, argv, timestamps=False):
    """The child_capture strace command; only the marker test adds -ttt."""
    return ["strace", "-f", "-q", "-y", "-s", "65536", "-e", "trace=all",
            *(["-ttt"] if timestamps else []), "-o", str(evidence), *argv]


TIMED_LINE = re.compile(r"^(\d+)( +)(\d+)\.(\d{6}) (.*)$")


def strip_trace_times(text):
    """A -ttt trace as the untimed trace parse_trace reads; fails closed on
    any line without its time column."""
    out = []
    for line in text.splitlines():
        m = TIMED_LINE.match(line)
        assert m, ("untimed line in a -ttt trace", line)
        out.append(f"{m[1]}{m[2]}{m[5]}")
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


# Under strace the front can pass its 50 ms deadline and exit 0 without a
# record (front_deadline_exit); such an attempt is judged in full and retried.
MARKER_ATTEMPTS = 8


def silent_armed_front(cap):
    """(front events, setitimer index, it_value in µs) of a capture whose front
    armed ITIMER_REAL with a positive it_value (setitimer returned 0), attempted
    no write to fd 1 at all, exited 0, and left stdout empty. Anything else is
    None. Each event is (time in µs or None, line)."""
    timed = re.compile(r"(\d+)\s+(?:(\d+)\.(\d{6})\s+)?(.*)$")
    rows = [(m[1], int(m[2]) * 1_000_000 + int(m[3]) if m[2] else None, m[4])
            for line in cap.lines if (m := timed.match(line))]
    if not rows or not re.match(r'execve\("[^"]*", \["[^"]*", "prompt"', rows[0][2]):
        return None
    root = rows[0][0]
    front = [(at, line) for pid, at, line in rows if pid == root]
    armed = next((i for i, (_, line) in enumerate(front) if line.startswith("setitimer(ITIMER_REAL,")), None)
    # 이것을 실패시키는 것: 실패했거나 없는 setitimer를 받는 것.
    if armed is None or not front[armed][1].endswith(") = 0") or cap.record:
        return None
    value = re.search(r"it_value=\{tv_sec=(\d+), tv_usec=(\d+)\}", front[armed][1])
    # 이것을 실패시키는 것: 0인 it_value(타이머 해제)를 받는 것.
    if not value or int(value[1]) * 1_000_000 + int(value[2]) <= 0:
        return None
    # 이것을 실패시키는 것: 앞단의 fd 1 쓰기 시도(실패한 것 포함)를 어디서든 받는 것, 0 아닌 종료,
    # 비지 않은 stdout을 받는 것.
    if any(re.match(r"(write|writev|pwrite64|pwritev2?)\(1[<,]", line) for _, line in front):
        return None
    if front[-1][1] != "+++ exited with 0 +++":
        return None
    return front, armed, int(value[1]) * 1_000_000 + int(value[2])


def last_event_before_exit(front, armed):
    """The time of the front's last event before exit_group, after setitimer.
    strace reads a line's time while the tracee is stopped and resumes it
    afterwards (stop-then-resume ordering, UNVERIFIED), so the exit_group
    line's own time can be later than the exit."""
    ends = [i for i, (_, line) in enumerate(front) if line.startswith("exit_group(")]
    return front[ends[-1] - 1][0] if ends and ends[-1] > armed else None


def front_deadline_exit(cap):
    """"front-deadline" when the trace proves the front's own deadline ended
    it: a silent armed front (silent_armed_front) that then either took a
    kernel SIGALRM or, by the -ttt times, made its last event before
    exit_group strictly later than the setitimer start plus its positive
    it_value. Anything else is None.

    The front computes its remaining time just before setitimer, so its
    deadline cannot end later than setitimer start + it_value. strace times
    are realtime, the product's clock is monotonic: equal or unreadable
    times prove nothing. A realtime step back can only refuse a retry; a
    step forward can retry an attempt early, and a retried attempt is
    still judged in full, so the cost is one more capture of an empty record."""
    silent = silent_armed_front(cap)
    if silent is None:
        return None
    front, armed, it_value = silent
    alarm = next((i for i, (_, line) in enumerate(front) if i > armed
                  and line.startswith("--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL")), None)
    if alarm is None:
        start, at = front[armed][0], last_event_before_exit(front, armed)
        # 이것을 실패시키는 것: 경계 같음을 증명으로 보는 것(>=), it_value를 빼는 것.
        if start is None or at is None or not at > start + it_value:
            return None
    return "front-deadline"


def front_deadline_window(cap):
    """"front-deadline-window" when a silent valid-marker exit does not
    contradict the front's deadline. That is all it says about the deadline;
    the record it lacks must still come in another of MARKER_ATTEMPTS attempts.

    The front reads its remaining time after the event before setitimer, so
    its deadline cannot come before that event + it_value: its last event
    before exit_group reaching that time, boundary included, leaves the exit
    no earlier than the deadline could be. The upper end of the same deadline
    is what front_deadline_exit needs, and the stored run 18 stops 62 µs short
    of it. An exit before the window, or unreadable times, is not this shape."""
    silent = silent_armed_front(cap)
    # 이것을 실패시키는 것: invalid 조건에도 이 모양을 주는 것.
    if cap.invalid or silent is None:
        return None
    front, armed, it_value = silent
    earliest, at = front[armed - 1][0], last_event_before_exit(front, armed)
    # 이것을 실패시키는 것: 경계 같음을 빼는 것(>), it_value를 빼는 것, 시각 없는 trace를 받는 것,
    # 하한을 setitimer 자신의 시각으로 올리는 것.
    if earliest is None or at is None or at < earliest + it_value:
        return None
    return "front-deadline-window"


def marker_shape(cap):
    return front_deadline_exit(cap) or front_deadline_window(cap)


def judge_marker_trace(cap, shape=None):
    """The allowlist judgment of the whole capture, deadline or not: every
    path, call and audit rule and every upper bound. Only an empty stdout
    waives the two record-bound items, the one filter and the record write
    in the front's call table; a front without a filter then has every call
    held to the pre-filter rules.
    The collector count stays with judge_marker_attempt; collection
    coverage (repository and global-input reads) was never this test's."""
    c = cap.context
    # 이것을 실패시키는 것: 버리는 마감 시도의 경로·syscall 금지 판정을 건너뛰는 것.
    assert_prompt_trace_budget(cap.untimed, c["exe"], c["pinned"], global_inputs=tuple(c["global_inputs"]),
                               # Stored contexts predate bingsu-prompt: the cli entry.
                               entry=c.get("entry", "cli"), helper_exe=c.get("helper_exe"),
                               collector_exe=c["collector_exe"], collectors=None,
                               repository_roots=c["roots"], repository_evidence=(),
                               # 이것을 실패시키는 것: 비지 않은 stdout에서 필터·기록 쓰기를 면제하는 것.
                               platform=tuple(c["platform"]), front_deadline=cap.record == b"",
                               headers=getattr(cap, "headers", RESPONSE_HEADERS))


def judge_marker_attempt(cap, shape=None, trace_judge=judge_marker_trace):
    """One marker-condition capture. Every attempt keeps the role bounds and
    the full trace judgment; a deadline shape (marker_shape) waives only the
    record, and the collector spawn only when the front ended before it
    created the helper (the helper never waits on the front, so a later
    deadline cannot stop its spawn)."""
    from fsbudget.attribute import role_children
    trace_judge(cap, shape)
    children = role_children(cap.trace, entry_of(cap.trace))
    # 이것을 실패시키는 것: 마감 시도에서 역할 상한(helper 둘, collector·명령 자식)을 넘기는 것.
    assert children["front"] <= 1 and children["helper"] <= 1, children
    assert children["collector"] == children["command"] == 0, children
    if shape is None or children["front"]:
        # 이것을 실패시키는 것: 표식 무효면 worker mask 0.
        assert children["helper"] == 1, children
    # 이것을 실패시키는 것: 마감 모양이 아닌 빈 stdout을 통과시키는 것(레코드 소실 회귀).
    if shape is None:
        assert cap.record, "no record and no deadline shape"
    if shape is None and cap.invalid:
        assert b"degraded:trust-invalid" in cap.record, cap.record


def entry_of(trace):
    """The prompt entry a trace ran ("cli" or "dedicated"), which the capture
    records on it from the program the hook called; stored traces of the CLI
    entry carry none."""
    return getattr(trace, "entry", "cli")
