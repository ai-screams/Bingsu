"""PR #117 ubuntu-24.04-arm musl open/close/resume (raw lines 5139–5141).

The surrounding lifecycle is synthetic, with normalized PIDs/paths. It also
checks thread sharing and a vfork child closing its private inherited copy.
"""
from pathlib import Path

import pytest

from fsbudget.attribute import collector_attribute

TRACE = (Path(__file__).parent / "fixtures/m3c-ubuntu-aarch64-musl-open-reuse.strace").read_text()
PINNED = {"front": "/bin/bingsu", "helper": "/bin/bingsu", "collector": "/bin/bingsu-collect"}
OPEN = '11 openat(AT_FDCWD</>, "/", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY <unfinished ...>'
CLOSE = '21 close(47</proc/sys/kernel/random/boot_id>) = 0'
RETURN = '11 <... openat resumed>) = 47</>'


def observe(text):
    return collector_attribute(text.splitlines(), PINNED)


# 이것을 실패시키는 것: 새 open fd를 반환 전 등록하거나 vfork 자식의 close를 부모에 전파하는 것.
@pytest.mark.parametrize("fd", [47, 89])
@pytest.mark.parametrize("call", [
    'openat(AT_FDCWD</>, "/", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY',
    'open("/", O_RDONLY|O_CLOEXEC',
    'openat2(AT_FDCWD</>, "/", {flags=O_RDONLY|O_CLOEXEC}, 24',
    'creat("/new", 0600',
])
def test_open_reuse_waits_for_return(fd, call):
    text = TRACE.replace(OPEN, '11 ' + call + ' <unfinished ...>')
    text = text.replace(RETURN, RETURN.replace('openat', call.split('(')[0])).replace('47<', f'{fd}<')
    if call.startswith('creat('):
        text = text.replace(f'{fd}</>', f'{fd}</new>').replace('S_IFDIR|0755', 'S_IFREG|0600')
    got = observe(text)
    assert not got.errors, got.errors
    assert got.counts == {
        "front": {"exec": 1, "spawn": 1},
        "helper": {"exec": 1, "openat": 2 if call.startswith('openat(') else 1,
                   **({"unknown-fs": 1} if not call.startswith('openat(') else {}),
                   "thread": 1, "fstat": 1, "spawn": 1},
        "collector": {"exec": 1},
    }


# 이것을 실패시키는 것: 겹친 open 때문에 실제 double close·다른 객체·부모 fd close를 숨기는 것.
@pytest.mark.parametrize("old,new,reason", [
    (CLOSE, CLOSE.replace('boot_id>', 'different>'), 'lifetime/identity mismatch: close'),
    (CLOSE, CLOSE + '\n' + CLOSE, 'lifetime/identity mismatch: close'),
    ('11 close(47</>) = 0', '11 close(47</>) = 0\n11 close(47</>) = 0', 'lifetime/identity mismatch: close'),
    ('11 fstat(47</>', '11 fstat(47</different>', 'lifetime/identity mismatch: fstat'),
    (CLOSE, '', 'open returned a live descriptor'),
    (CLOSE, CLOSE.replace('= 0', '= -1 EBADF (Bad file descriptor)'), 'open returned a live descriptor'),
    ('CLONE_VM|CLONE_FILES|CLONE_THREAD', 'CLONE_VM|SIGCHLD', 'open returned a live descriptor'),
    ('12 close(47</>)', '11 close(47</>)', 'lifetime/identity mismatch: close'),
])
def test_open_overlap_does_not_excuse_lifetime_errors(old, new, reason):
    assert old in TRACE
    errors = observe(TRACE.replace(old, new)).errors
    assert any(reason in e for e in errors), errors


# 이것을 실패시키는 것: 반환 이후 close까지 앞당겨 아직 열린 번호의 재할당을 허용하는 것.
def test_close_must_precede_open_return():
    text = TRACE.replace(CLOSE + '\n', '').replace(RETURN, RETURN + '\n' + CLOSE)
    assert any('open returned a live descriptor' in e for e in observe(text).errors)


# 이것을 실패시키는 것: openat 전체를 반환 시점으로 옮겨 진입 시점 dirfd의 수명 검사를 잃는 것.
@pytest.mark.parametrize("live", [True, False])
def test_open_dirfd_is_checked_at_entry(live):
    before = '11 openat(AT_FDCWD</>, "/dir", O_RDONLY) = 9</dir>\n'
    close = '21 close(9</dir>) = 0\n'
    text = TRACE.replace(OPEN, before + ('' if live else close) + OPEN.replace('AT_FDCWD</>', '9</dir>'))
    if live:
        text = text.replace(CLOSE, close + CLOSE)
    errors = observe(text).errors
    if live:
        assert not errors, errors
    else:
        assert any('lifetime/identity mismatch: openat(9</dir>' in e for e in errors), errors


# 이것을 실패시키는 것: 실패한 open을 생성으로 세거나 반환 시 CLOEXEC를 잃는 것.
@pytest.mark.parametrize("failure", [False, True])
def test_open_return_preserves_failure_and_cloexec(failure):
    if failure:
        text = TRACE.replace(RETURN, '11 <... openat resumed>) = -1 EACCES (Permission denied)')
        reason = 'lifetime/identity mismatch: fstat(47'
    else:
        text = TRACE.replace('12 close(47</>) = 0\n', '')
        exec_line = next(line for line in text.splitlines() if line.startswith('12 execve'))
        text = text.replace(exec_line, exec_line + '\n12 close(47</>) = 0')
        reason = 'pid 12 (collector): descriptor lifetime/identity mismatch: close(47'
    errors = observe(text).errors
    assert any(reason in e for e in errors), errors
