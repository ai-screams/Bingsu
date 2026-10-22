"""SIGKILL's unreadable syscall number is a terminal trace event, not an effect."""
from pathlib import Path

import pytest

from fsbudget.attribute import attribute, collector_attribute
from fsbudget.classify import collector_bootstrap_kind, collector_kind, kind
from fsbudget.strace_parse import EXIT_EVENT, UNKNOWN_SYSCALL, parse


FIXTURE = Path(__file__).parent / "fixtures/d2s-ubuntu-aarch64-unknown-syscall.strace"
WHOLE = "13794 ???() = ?"
SPLIT = "13794 ???( <unfinished ...>\n13794 <... ??? resumed>)                = ?"
KILLED = "13794 +++ killed by SIGKILL +++"
PINNED = {"front": "/fixture", "helper": "/fixture", "collector": "/fixture"}
PREFIX = [
    '1 execve("/fixture", ["/fixture", "prompt"], 0x0) = 0',
    '1 clone(flags=SIGCHLD) = 2',
    '2 execve("/fixture", ["/fixture", "__refresh-v1"], 0x0) = 0',
    '2 clone(flags=SIGCHLD) = 13794',
    '13794 execve("/fixture", ["/fixture", "__collect-v1"], 0x0) = 0',
]


# 이것을 실패시키는 것: 실제 4521/4525줄 또는 whole 형태를 거부하거나 인자·결과·파일 효과를 꾸며내는 것.
@pytest.mark.parametrize("record", [WHOLE, SPLIT], ids=["whole", "split"])
def test_unknown_syscall_requires_same_pid_sigkill(record):
    # Other PIDs may run between entry, resume and death.
    text = record.replace("\n", "\n2 getpid() = 2\n") + "\n2 getpid() = 2\n" + KILLED
    trace = parse(text)
    assert not trace.errors, trace.errors
    call, = [c for c in trace if c.name == UNKNOWN_SYSCALL]
    assert (call.pid, call.args, call.ret) == (13794, "", "")
    assert all(classify(call) is None for classify in (kind, collector_kind, collector_bootstrap_kind))
    assert trace[-1].name == EXIT_EVENT
    # Mutation: killing a different PID cannot justify this record.
    assert parse(text.replace(KILLED, "2 +++ killed by SIGKILL +++")).errors


# 이것을 실패시키는 것: 정상 종료·다음 호출·숫자 결과·두 번·중간 신호·인자·짝 없는 ???를 허용하는 것.
@pytest.mark.parametrize("record", [WHOLE, SPLIT], ids=["whole", "split"])
@pytest.mark.parametrize("mutation", [
    "normal-exit", "another-call", "numeric-result", "twice", "signal", "args", "missing-kill",
])
def test_unknown_syscall_rejects_nonterminal_mutations(record, mutation):
    text = record + "\n" + KILLED
    assert not parse(text).errors
    if mutation == "normal-exit":
        text = text.replace(KILLED, "13794 +++ exited with 0 +++")
    elif mutation == "another-call":
        text = text.replace(KILLED, "13794 getpid() = 13794\n" + KILLED)
    elif mutation == "numeric-result":
        text = text.replace("= ?", "= 0")
    elif mutation == "twice":
        text = record + "\n" + text
    elif mutation == "signal":
        text = text.replace(KILLED, "13794 --- SIGTERM {si_signo=SIGTERM} ---\n" + KILLED)
    elif mutation == "args":
        text = text.replace("???(", "???(3")
    else:
        text = record
    assert parse(text).errors, text


# 이것을 실패시키는 것: resumed 누락/고아 resumed 또는 이미 열린 정상 호출 위의 ???를 허용하는 것.
@pytest.mark.parametrize("record", [
    "13794 ???( <unfinished ...>",
    "13794 <... ??? resumed>)                = ?",
    "13794 read(3<pipe:[40119]>, <unfinished ...>\n" + SPLIT,
])
def test_unknown_syscall_rejects_unmatched_records(record):
    assert parse(record + "\n" + KILLED).errors


# 이것을 실패시키는 것: helper kill을 명시하지 않아도 허용하거나 별도 보고 없이 효과 예산에 섞는 것.
@pytest.mark.parametrize("record", [WHOLE, SPLIT], ids=["whole", "split"])
def test_collector_terminal_unknown_is_reported_only_on_helper_kill(record):
    lines = PREFIX + record.splitlines() + [KILLED]
    got = collector_attribute(lines, PINNED, helper_kill=True)
    assert not got.errors, got.errors
    assert got.counts["collector"] == {"exec": 1, UNKNOWN_SYSCALL: 1}
    # Mutation: the same trace on a success path must fail.
    assert collector_attribute(lines, PINNED).errors


# 이것을 실패시키는 것: SIGKILL로 끝나기만 하면 helper의 ???도 허용하는 것.
def test_helper_role_cannot_have_unknown_syscall():
    lines = PREFIX + [WHOLE, KILLED]
    assert not collector_attribute(lines, PINNED, helper_kill=True).errors
    # Mutation: move the exact terminal pair from collector to helper.
    changed = PREFIX + [line.replace("13794", "2") for line in (WHOLE, KILLED)]
    errors = collector_attribute(changed, PINNED, helper_kill=True).errors
    assert any("(helper): unknown syscall requires" in e for e in errors), errors


# 이것을 실패시키는 것: 스레드마다 한 번씩 ???를 허용하여 프로세스당 최대 한 번 검사를 우회하는 것.
def test_unknown_syscall_is_at_most_once_per_process():
    start = PREFIX + ['13794 clone(flags=CLONE_THREAD|CLONE_VM) = 13796']
    first = [WHOLE, KILLED]
    assert not collector_attribute(start + first, PINNED, helper_kill=True).errors
    # Mutation: a second thread of the same process also loses its syscall number.
    second = [line.replace("13794", "13796") for line in first]
    errors = collector_attribute(start + first + second, PINNED, helper_kill=True).errors
    assert any("once per process" in e for e in errors), errors


# 이것을 실패시키는 것: ??? 이후 같은 프로세스의 다른 스레드가 계속 호출해도 허용하는 것.
def test_unknown_syscall_is_the_process_last_call():
    start = PREFIX + ['13794 clone(flags=CLONE_THREAD|CLONE_VM) = 13796']
    lines = start + [WHOLE, KILLED]
    assert not collector_attribute(lines, PINNED, helper_kill=True).errors
    # Mutation: a live sibling thread issues another call after the terminal event.
    errors = collector_attribute(lines + ['13796 getpid() = 13794'], PINNED, helper_kill=True).errors
    assert any("call after terminal unknown syscall" in e for e in errors), errors


# 이것을 실패시키는 것: 별도 이벤트 분류를 핑계로 기존 prompt gate의 알 수 없는 호출도 허용하는 것.
def test_generic_attribution_stays_fail_closed():
    got = attribute(parse(WHOLE + "\n" + KILLED), [], markers=False)
    assert any("unknown syscall outside collector helper kill path" in e for e in got.errors), got.errors


# 이것을 실패시키는 것: 실제 Ubuntu arm64의 생성/exec 순서 또는 ??? entry 순서를 잃는 것.
def test_real_ubuntu_trace_excerpt():
    lines = FIXTURE.read_text().splitlines()
    fixture = "/home/runner/work/Bingsu/Bingsu/target/release/collector-product-fixture/collector-product"
    pinned = {role: fixture for role in ("front", "helper", "collector")}
    pinned["verbs"] = {"front": "--trace", "helper": "--trace-helper", "collector": "--as-worker"}
    got = collector_attribute(lines, pinned, helper_kill=True)
    assert not got.errors, got.errors
    assert got.counts["collector"] == {"exec": 1, UNKNOWN_SYSCALL: 1}
    # Mutation: a later ordinary syscall of that PID invalidates the unreadable record.
    at = lines.index(KILLED)
    changed = lines[:at] + ["13794 getpid() = 13794"] + lines[at:]
    assert collector_attribute(changed, pinned, helper_kill=True).errors
