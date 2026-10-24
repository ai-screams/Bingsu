"""Unedited bookworm aarch64 B3 -f -yy capture, including startup records."""
from pathlib import Path

import pytest

from fsbudget.classify import split_args
from fsbudget.repository import check_repository_trace
from fsbudget.strace_parse import parse


TRACE = Path(__file__).with_name('fixtures').joinpath(
    'm3c-bookworm-aarch64-repository-openat2.strace').read_text()
PPOLL = next(line for line in TRACE.splitlines() if ' ppoll(' in line)
CAPGET = next(line for line in TRACE.splitlines() if ' capget(' in line)
ROOT = '/tmp/b3-trace-upxabt_2'


# 이것을 실패시키는 것: 실제 ppoll/capget 행을 거부하거나 중첩 이름·비트셋 안에서 인자를 나누는 것.
@pytest.mark.parametrize('line,needle,name,argc', [
    (PPOLL, '<char', 'ppoll', 5),
    (CAPGET, '<<CAP_CHOWN', 'capget', 2),
], ids=['ppoll', 'capget'])
@pytest.mark.parametrize('split', [False, True], ids=['whole', 'resumed'])
def test_exact_repository_startup_records(line, needle, name, argc, split):
    original = parse(line)
    if split:
        pid = line.split()[0]
        line = line.replace(needle, f' <unfinished ...>\n{pid}  <... {name} resumed>{needle}', 1)
    calls = parse(line)
    assert not calls.errors, calls.errors
    call, = calls
    assert (call.pid, call.name, call.args, call.ret) == (
        original[0].pid, name, original[0].args, original[0].ret)
    args = split_args(call.args)
    assert len(args) == argc
    assert ', '.join(args) == call.args
    if name == 'ppoll':
        assert args[0] == ('[{fd=0</dev/null<char 1:3>>, events=0}, '
                           '{fd=1<pipe:[1586202]>, events=0}, {fd=2<pipe:[1586203]>, events=0}]')
    else:
        assert args[0] == '{version=_LINUX_CAPABILITY_VERSION_3, pid=0}'
        assert args[1].startswith('{effective=1<<CAP_CHOWN|1<<CAP_DAC_OVERRIDE|')
        assert args[1].endswith('1<<CAP_SETFCAP, inheritable=0}')


# 이것을 실패시키는 것: -yy 장치 주석을 /dev/null 전용으로 만들거나 block·이스케이프 경로를 거부하는 것.
@pytest.mark.parametrize('device', [
    r'</dev/null<char 1:3>>',
    r'</dev/sda<block 8:0>>',
    r'</tmp/a\74b\76, ) = 9<char 123:456>>',
])
def test_device_fd_names(device):
    calls = parse(PPOLL.replace('</dev/null<char 1:3>>', device))
    assert not calls.errors, calls.errors
    assert f'fd=0{device}, events=0' in split_args(calls[0].args)[0]


# 이것을 실패시키는 것: 균형만 맞는 임의 중첩·잘못된 장치 형태·닫힘 누락·fd 없는 이름까지 허용하는 것.
@pytest.mark.parametrize('device', [
    '</dev/null<char 1:3>', '</dev/null<char 1:3>>>',
    '</dev/null<char 1:3>>junk>', '</dev/null<char 1:3>tail>',
    '</dev/null<char 1:3><block 8:0>>', '</dev/null<char 1:<3>>>',
    '</dev/null<other 1:3>>', '</dev/null<char 1>>',
    '</dev/null<char -1:3>>', '</dev/null<char 1:x>>',
    '</dev/null<char 1:3:4>>', '</dev/null<char 1:3 extra>>',
    '</dev/null<arbitrary>>', '<pipe:[1]<char 1:3>>',
    '<relative<char 1:3>>',
])
def test_repository_ppoll_rejects_bad_device_names(device):
    calls = parse(PPOLL.replace('</dev/null<char 1:3>>', device))
    assert calls.errors and not calls


# 이것을 실패시키는 것: -yy 이름을 fd 번호/AT_FDCWD 밖에서도 허용하는 것.
def test_repository_ppoll_requires_fd_before_device_name():
    assert parse(PPOLL.replace('fd=0<', 'fd=<')).errors
    assert parse(PPOLL.replace('fd=0<', 'fd=word<')).errors


# 이것을 실패시키는 것: capability 비트셋 지원으로 임의 shift·단일 꺾쇠·손상된 피연산자를 허용하는 것.
@pytest.mark.parametrize('bits', [
    '1<CAP_CHOWN', '1<<<CAP_CHOWN', '1>>CAP_CHOWN', '1<>CAP_CHOWN',
    '<<CAP_CHOWN', '1<<', '1<<CAP_', '1<<CAP_chown', '1<<OTHER',
    '1<<CAP_CHOWN>', '1<<CAP_CHOWN<extra>', '1<<CAP_CHOWN|',
    '1<<CAP_CHOWN||1<<CAP_KILL', '1<<CAP_CHOWN|1<CAP_KILL',
])
def test_repository_capget_rejects_malformed_bits(bits):
    assert parse(CAPGET.replace('1<<CAP_CHOWN', bits)).errors


# 이것을 실패시키는 것: capability 표현을 구조체 필드 값 밖의 임의 꺾쇠 인자로 허용하는 것.
@pytest.mark.parametrize('args', [
    '1<<CAP_CHOWN, 0', '[1<<CAP_CHOWN, 0]', '{1<<CAP_CHOWN, other=0}',
    '{effective=[1<<CAP_CHOWN, 0]}', '{effective=x1<<CAP_CHOWN}',
])
def test_capability_bits_require_struct_field(args):
    assert parse(f'2012 capget({args}) = 0').errors


# 이것을 실패시키는 것: E1 이전 캡처의 누락된 readonly mount 관찰을 현재 계약으로 수용하는 것.
def test_bookworm_repository_openat2_offline_replay():
    assert len(TRACE.splitlines()) == 364
    with pytest.raises(AssertionError, match="'content'") as caught:
        check_repository_trace(TRACE, ROOT, 'openat2')
    phase, observed, expected = caught.value.args[0]
    assert phase == 'content' and observed['fstatfs'] == 1
    assert expected == {**observed, 'fstatfs': 2}


# 이것을 실패시키는 것: 현재 readonly 경로의 두 fd별 fstatfs를 모델에서 빠뜨리는 것.
def test_repository_replay_with_synthetic_readonly_mount_observation():
    # Preserve the historical capture verbatim; this addition is synthetic, not Linux evidence.
    access = next(line for line in TRACE.splitlines(keepends=True) if ' faccessat2(' in line)
    mount = f'2012  fstatfs(6<{ROOT}/worktree>, {{f_type=OVERLAYFS_SUPER_MAGIC, f_flags=ST_RELATIME}}) = 0\n'
    current = TRACE.replace(access, access + mount)
    assert check_repository_trace(current, ROOT, 'openat2') == {
        'probe': {'openat': 1, 'fstat': 1, 'fstatfs': 1, 'statx': 1, 'openat2': 1},
        'read-layer': {'openat': 1, 'fstat': 4, 'landlock_create_ruleset': 1,
                       'landlock_add_rule': 3, 'landlock_restrict_self': 1},
        'content': {'openat2': 1, 'fstat': 1, 'fstatfs': 2, 'statx': 1,
                    'read': 2, 'faccessat2': 1},
    }
    with pytest.raises(AssertionError, match="'content'"):
        check_repository_trace(current.replace(mount, mount + mount), ROOT, 'openat2')


# 이것을 실패시키는 것: 절대 slash의 미사용 cwd 예외를 상대 경로·다른 경로·실제 dirfd까지 넓히는 것.
@pytest.mark.parametrize('replacement', [
    'AT_FDCWD</tmp/src>, "."',
    'AT_FDCWD</tmp/src>, "/tmp/src"',
    '99</tmp/src>, "/"',
])
def test_repository_unused_cwd_exception_is_only_fixed_slash(replacement):
    old = 'AT_FDCWD</tmp/src>, "/"'
    assert old in TRACE
    with pytest.raises(AssertionError, match='outside selected roots'):
        check_repository_trace(TRACE.replace(old, replacement), ROOT, 'openat2')
