"""Independent arithmetic/byte controls for the live front attempt gate."""
import pytest
from fsbudget.formula import FrontAttempt, front_attempts_expected, front_read_bytes
from fsbudget.strace_parse import parse


# 이것을 실패시키는 것: 사본별 ceil 대신 합산 ceil, 고정 prefix/marker/boot 항 제거.
@pytest.mark.parametrize('body', [0, 1, 16384, 16385, 16 * 1024 * 1024])
def test_front_attempt_arithmetic(body):
    attempts = [FrontAttempt(copy, True, True, body, True) for copy in ('current', 'last_good')]
    assert front_attempts_expected(7, attempts, 16384) == {
        'openat': 19, 'fstat': 19, 'fstatfs': 19, 'fgetxattr': 19,
        'getxattr': 8, 'readlinkat': 3, 'read': 7 + 2 * ((body + 16383) // 16384)}


# 이것을 실패시키는 것: 머리 또는 prefix에서 거부한 사본에 본문 비용을 부과하는 것.
def test_front_rejected_attempts():
    assert front_attempts_expected(1, [FrontAttempt('current', True, False, 0, False)], 16384)['read'] == 4
    assert front_attempts_expected(1, [FrontAttempt('current', True, True, 0, False)], 16384)['read'] == 5


# 이것을 실패시키는 것: 재읽기·순서·독립 본문 상한·고정 marker 검사를 삭제하는 것.
@pytest.mark.parametrize('C,attempts,chunk,marker', [
    (0, [FrontAttempt('current', True, True, 1, True)], 16384, 208),
    (1, [FrontAttempt('current', True, True, 1, True)], 0, 208),
    (1, [FrontAttempt('current', True, True, 1, True)], 16384, 209),
    (1, [], 16384, 208),
    (1, [FrontAttempt('last_good', True, True, 1, True)], 16384, 208),
    (1, [FrontAttempt('current', True, True, 1, True)] * 2, 16384, 208),
    (1, [FrontAttempt('current', False, True, 0, False)], 16384, 208),
    (1, [FrontAttempt('current', True, False, 1, False)], 16384, 208),
    (1, [FrontAttempt('current', True, False, 0, True)], 16384, 208),
    (1, [FrontAttempt('current', True, True, -1, False)], 16384, 208),
    (1, [FrontAttempt('current', True, True, 16777217, False)], 16384, 208),
])
def test_front_invalid_axes(C, attempts, chunk, marker):
    with pytest.raises(ValueError):
        front_attempts_expected(C, attempts, chunk, marker)


# 이것을 실패시키는 것: 요청 길이·다른 파일·닫힌 fd 재사용을 읽은 바이트에 더하는 것.
def test_front_returned_bytes():
    trace = parse('1 read(3</snapshot>, "abc", 64) = 3\n'
                  '1 read(3</snapshot>, "", 61) = 0\n'
                  '1 close(3</snapshot>) = 0\n'
                  '1 read(3</other>, "abc", 64) = 3')
    assert front_read_bytes(trace, ['/snapshot', '/last-good']) == {'/snapshot': 3, '/last-good': 0}


# 이것을 실패시키는 것: 파싱 오류·다중 PID·실패 read·다른 읽기 primitive를 무시하는 것.
@pytest.mark.parametrize('line', ['bad', '1 read(3</snapshot>, "", 1) = -1 EIO (I/O error)',
    '1 read(3</snapshot>, "a", 0) = 1', '1 pread64(3</snapshot>, "a", 1, 0) = 1',
    '1 readv(3</snapshot>, [], 0) = 0', '1 read(3</snapshot>, "", 1) = ? ',
    '2 read(3</snapshot>, "a", 1) = 1'])
def test_front_unmeasurable_bytes(line):
    with pytest.raises(ValueError):
        front_read_bytes(parse('1 read(3</snapshot>, "", 1) = 0\n' + line), ['/snapshot'])
