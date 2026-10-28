"""Creation-site child accounting, including vfork completion order."""
import pytest

from fsbudget.attribute import first_index, role_children
from fsbudget.strace_parse import parse


def sample(extra='', verb='__collect-v1'):
    return parse(f'''10 execve("/bin/bingsu", ["/bin/bingsu", "prompt"], []) = 0
11 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], []) = 0
10 clone(flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 11
11 clone(flags=CLONE_THREAD|CLONE_VM) = 12
12 futex(0x123, FUTEX_WAIT, 0, NULL) = 0
11 read(3</store/snapshot>, "header", 64) = 64
11 read(4</store/.marker.stage>, "marker", 208) = 208
13 execve("/bin/bingsu-collect", ["/bin/bingsu-collect", "{verb}"], []) = 0
11 vfork() = 13
{extra}''')


# 이것을 실패시키는 것: exec 선행 출력에서 부모 귀속 손실, watchdog를 프로세스로 집계, 실패 clone 집계.
def test_role_children_creation_site_and_threads():
    trace = sample('11 clone3({}, 88) = -1 ENOSYS (Function not implemented)')
    # 이것을 실패시키는 것: assert role_children(trace) == {'front': 1, 'helper': 1, 'collector': 0, 'command': 0} 조건을 제거하거나 반전하는 변이.
    assert role_children(trace) == {'front': 1, 'helper': 1, 'collector': 0, 'command': 0}
    # 이것을 실패시키는 것: assert first_index(trace, 'helper', lambda c: c.name == 'read') == 5 조건을 제거하거나 반전하는 변이.
    assert first_index(trace, 'helper', lambda c: c.name == 'read') == 5


# 이것을 실패시키는 것: collector 자식·알 수 없는 명령 exec·helper 중복 생성 누락.
@pytest.mark.parametrize('extra,verb,want', [
    ('13 fork() = 14\n14 exit_group(0) = ?', '__collect-v1', {'front': 1, 'helper': 1, 'collector': 1, 'command': 0}),
    ('', 'wrong', {'front': 1, 'helper': 1, 'collector': 0, 'command': 0}),
    ('10 fork() = 15\n15 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], []) = 0', '__collect-v1', {'front': 2, 'helper': 1, 'collector': 0, 'command': 0}),
])
def test_role_children_negative_controls(extra, verb, want):
    trace = sample(extra, verb)
    # 이것을 실패시키는 것: if verb != 'wrong' 조건을 제거하거나 반전하는 변이.
    if verb != 'wrong':
        # 이것을 실패시키는 것: assert role_children(trace) == want 조건을 제거하거나 반전하는 변이.
        assert role_children(trace) == want
    # 이것을 실패시키는 것: if verb == 'wrong' 조건을 제거하거나 반전하는 변이.
    if verb == 'wrong':
        with pytest.raises(ValueError):
            role_children(trace)
        with pytest.raises(ValueError):
            first_index(trace, 'collector', lambda c: True)


# 이것을 실패시키는 것: 구조 오류·생성 부모가 없는 프로세스를 조용히 무시하는 것.
@pytest.mark.parametrize('extra', ['garbage', '99 read(3, "x", 1) = 1'])
def test_role_children_fail_closed(extra):
    with pytest.raises(ValueError):
        role_children(sample(extra))


# 이것을 실패시키는 것: clone·clone3·fork·vfork 중 한 플랫폼의 생성을 무시하거나 실패한 시도를 세는 것.
@pytest.mark.parametrize('primitive', ['clone', 'clone3', 'fork', 'vfork'])
def test_each_spawn_primitive_has_exact_count_and_failed_control(primitive):
    trace = sample()
    trace[2].name = primitive
    # 이것을 실패시키는 것: assert role_children(trace)['front'] == 1 조건을 제거하거나 반전하는 변이.
    assert role_children(trace)['front'] == 1
    trace[2].ret = '-1 EAGAIN (Resource temporarily unavailable)'
    with pytest.raises(ValueError):
        role_children(trace)


# 이것을 실패시키는 것: exit 뒤 재사용된 collector PID를 이전 수명에 합쳐 생성 수를 누락하는 것.
def test_reused_pid_is_a_separate_creation():
    trace = sample('13 +++ exited with 0 +++\n11 vfork() = 13\n'
                   '13 execve("/bin/bingsu-collect", ["/bin/bingsu-collect", "__collect-v1"], []) = 0')
    # 이것을 실패시키는 것: assert role_children(trace)['helper'] == 2 조건을 제거하거나 반전하는 변이.
    assert role_children(trace)['helper'] == 2


# 이것을 실패시키는 것: CLONE_THREAD 자식을 exec해 no-worker collector 계수를 우회하는 변이.
def test_thread_exec_is_not_zero_collectors():
    source = parse('''10 execve("/bin/bingsu", ["/bin/bingsu", "prompt"], []) = 0
10 vfork() = 11
11 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], []) = 0
11 clone(flags=CLONE_THREAD|CLONE_VM) = 12
12 execve("/bin/bingsu-collect", ["/bin/bingsu-collect", "__collect-v1"], []) = 0''')
    with pytest.raises(ValueError, match='thread exec'):
        role_children(source)


# A later pinned exec must never erase a shell, including early vfork output.
@pytest.mark.parametrize('role', ['front', 'helper', 'collector'])
@pytest.mark.parametrize('before_return', [False, True])
def test_exec_relays_are_rejected_permanently(role, before_return):
    lines = [f'{c.pid} {c.name}({c.args}) = {c.ret}' for c in sample()]
    pid = {'front': 10, 'helper': 11, 'collector': 13}[role]
    product = next(i for i, line in enumerate(lines) if line.startswith(f'{pid} execve'))
    shell = f'{pid} execve("/bin/sh", ["/bin/sh", "-c", "relay"], []) = 0'
    if not before_return and role != 'front':
        spawn = next(i for i, line in enumerate(lines) if line.endswith(f'= {pid}'))
        lines[product], lines[spawn] = lines[spawn], lines[product]
        product = spawn
    lines.insert(product, shell)
    trace = parse('\n'.join(lines))
    for check in (role_children, lambda t: first_index(t, role, lambda c: True)):
        with pytest.raises(ValueError, match='exec transition'):
            check(trace)


@pytest.mark.parametrize('pid', [10, 11, 13])
def test_repeated_product_exec_is_rejected(pid):
    trace = sample()
    call = next(c for c in trace if c.pid == pid and c.name == 'execve')
    with pytest.raises(ValueError, match='exec transition'):
        role_children(sample(f'{pid} execve({call.args}) = 0'))


def test_timing_evidence_starts_at_validated_exec():
    trace = parse('''10 execve("/bin/bingsu", ["/bin/bingsu", "prompt"], []) = 0
11 read(3</store/snapshot>, "old", 192) = 192
11 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], []) = 0
10 vfork() = 11
11 read(3</store/snapshot>, "new", 192) = 192''')
    assert first_index(trace, 'helper', lambda c: c.name == 'read') == 4


@pytest.mark.parametrize('pid', [10, 11, 13])
@pytest.mark.parametrize('name,args', [
    ('execve', '"/bin/sh", ["/bin/sh"], []'),
    ('execveat', 'AT_FDCWD, "/bin/sh", ["/bin/sh"], [], 0'),
])
def test_unexpected_successful_exec_in_any_product_role(pid, name, args):
    with pytest.raises(ValueError, match='exec transition'):
        role_children(sample(f'{pid} {name}({args}) = 0'))
