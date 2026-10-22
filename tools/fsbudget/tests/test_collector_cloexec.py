"""Regression lines from the M3b musl CI failure, with narrow pairing mutations."""
import pytest

from fsbudget.attribute import collector_attribute
from fsbudget.classify import collector_bootstrap_kind
from fsbudget.strace_parse import parse

PID = 15532
PINNED = {"front": "/fixture", "helper": "/fixture", "collector": "/fixture",
          "verbs": {"front": "--trace", "helper": "--trace-helper", "collector": "--security-worker"}}
HEAD = [
    '15530 execve("/fixture", ["/fixture", "--trace"], 0x0) = 0',
    '15530 clone(flags=SIGCHLD) = 15531',
    '15531 execve("/fixture", ["/fixture", "--trace-helper"], 0x0) = 0',
    '15531 clone(flags=SIGCHLD) = 15532',
    '15532 execve("/fixture", ["/fixture", "--security-worker"], 0x0) = 0',
    '15532 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=12}) = 0',
]
OPEN = 'open("/proc/self/statm", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 4</proc/15532/statm>'
FCNTL = 'fcntl(4</proc/15532/statm>, F_SETFD, FD_CLOEXEC)'


def trace(*calls):
    return HEAD + [f"{PID} {call}" for call in calls]


# 이것을 실패시키는 것: musl의 바로 다음 CLOEXEC fcntl을 별도 효과로 세거나 EPERM 반환을 숨기는 것.
@pytest.mark.parametrize("result", ["0", "-1 EPERM (Operation not permitted)"])
@pytest.mark.parametrize("opening", [OPEN, OPEN.replace('open(', 'openat(AT_FDCWD</>, ')], ids=["open", "openat"])
@pytest.mark.parametrize("shape", ["whole", "split", "other-pid-between"])
def test_musl_cloexec_is_one_open_with_recorded_result(opening, result, shape):
    lines = trace(opening, FCNTL + " = " + result)
    if shape == "split":
        lines[-2:] = [f'{PID} {opening.split(" = ")[0][:-1]} <unfinished ...>',
                      '15531 getpid() = 15531',
                      f'{PID} <... {opening.split("(")[0]} resumed>) = 4</proc/15532/statm>',
                      f'{PID} {FCNTL[:-1]} <unfinished ...>',
                      f'{PID} <... fcntl resumed>) = {result}']
    elif shape == "other-pid-between":
        lines.insert(-1, '15531 getpid() = 15531')
    got = collector_attribute(lines, PINNED)
    assert not got.errors, got.errors
    assert got.counts == collector_attribute(trace(opening), PINNED).counts
    assert got.counts["collector"] == {"exec": 1, "openat": 1}
    assert got.cloexec_pairs == [{"pid": PID, "open": opening.split(" = ")[0],
                                  "open_ret": "4</proc/15532/statm>",
                                  "fcntl": FCNTL, "fcntl_ret": result}]
    # The context-free classification must stay forbidden.
    assert collector_bootstrap_kind(parse(f'{PID} {FCNTL} = {result}')[0]) == "unknown-fs"


# 이것을 실패시키는 것: fd/플래그/인접성/횟수/성공 open/O_CLOEXEC 조건을 하나라도 완화하는 것.
@pytest.mark.parametrize("calls,forbidden", [
    ([OPEN, FCNTL.replace('4<', '5<')], 1),
    ([OPEN, FCNTL.replace('FD_CLOEXEC', '0')], 1),
    ([OPEN, FCNTL.replace('FD_CLOEXEC', '1')], 1),
    ([OPEN, FCNTL.replace('FD_CLOEXEC', 'FD_CLOEXEC|0x2')], 1),
    ([OPEN, FCNTL.replace('FD_CLOEXEC)', 'FD_CLOEXEC, 0)')], 1),
    ([OPEN, 'getpid() = 15532', FCNTL], 1),
    ([OPEN, FCNTL, FCNTL], 1),
    ([OPEN.replace('|O_CLOEXEC', ''), FCNTL], 1),
    ([OPEN.replace('4</proc/15532/statm>', '-1 EMFILE (Too many open files)'), FCNTL], 1),
    ([FCNTL], 1),
    ([OPEN.replace('open(', 'openat2(AT_FDCWD</>, ').replace(
        'O_RDONLY|O_LARGEFILE|O_CLOEXEC)', '{flags=O_RDONLY|O_CLOEXEC}, 24)'), FCNTL], 1),
], ids=["different-fd", "clear-flag", "numeric-flag", "extra-flag", "extra-argument", "not-next-call",
        "second-fcntl", "no-cloexec", "failed-open", "no-open", "openat2"])
@pytest.mark.parametrize("result", ["0", "-1 EPERM (Operation not permitted)"])
def test_unpaired_setfd_stays_forbidden(calls, forbidden, result):
    lines = trace(*(call if " = " in call else call + " = " + result for call in calls))
    got = collector_attribute(lines, PINNED)
    assert sum("collector forbidden effect: fcntl(" in e for e in got.errors) == forbidden, got.errors
    assert len(got.cloexec_pairs) == (1 if len(calls) == 3 and calls[1] == FCNTL else 0)


# 이것을 실패시키는 것: 같은 process의 다른 TID가 한 open으로 짝을 빌리거나 PID 재사용에 짝을 남기는 것.
@pytest.mark.parametrize("reuse", [False, True], ids=["other-thread", "reused-pid"])
def test_pair_cannot_cross_pid_or_lifetime(reuse):
    if reuse:
        lines = trace(OPEN, '+++ exited with 0 +++') + [
            '15531 clone(flags=SIGCHLD) = 15532', HEAD[4], f'{PID} {FCNTL} = 0']
        pinned = {**PINNED, "collectors": 2}
    else:
        lines = trace('clone(flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = 15533', OPEN)
        lines.append('15533 ' + FCNTL + ' = 0')
        pinned = PINNED
    got = collector_attribute(lines, pinned)
    assert not got.cloexec_pairs
    assert any("collector forbidden effect: fcntl(" in e for e in got.errors), got.errors
