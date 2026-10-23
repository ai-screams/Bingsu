"""Exact -f -yy records from bookworm aarch64 b3rt/repository-openat2.strace."""
from pathlib import Path

import pytest

from fsbudget.classify import split_args
from fsbudget.strace_parse import StructureError, parse, scan


FIXTURE = Path(__file__).parent / "fixtures/m3c-bookworm-aarch64-repository-grammar.strace"
PPOLL, CAPGET, CAPGET_ZERO = FIXTURE.read_text().splitlines()
CAP_BITS = (
    "1<<CAP_CHOWN|1<<CAP_DAC_OVERRIDE|1<<CAP_FOWNER|1<<CAP_FSETID|1<<CAP_KILL|"
    "1<<CAP_SETGID|1<<CAP_SETUID|1<<CAP_SETPCAP|1<<CAP_NET_BIND_SERVICE|1<<CAP_NET_RAW|"
    "1<<CAP_SYS_CHROOT|1<<CAP_SYS_PTRACE|1<<CAP_SYS_ADMIN|1<<CAP_MKNOD|"
    "1<<CAP_AUDIT_WRITE|1<<CAP_SETFCAP"
)
CAP_HEADER = "{version=_LINUX_CAPABILITY_VERSION_3, pid=0}"


def record(line, split):
    if not split:
        return line
    pid, body = line.split(None, 1)
    name, args = body.split("(", 1)
    # Split inside the new syntax too; scanning must follow reassembly.
    boundary = args.index("<") + 1
    return (f"{pid} {name}({args[:boundary]} <unfinished ...>\n"
            f"{pid} <... {name} resumed>{args[boundary:]}")


# 이것을 실패시키는 것: 실제 -yy 장치 주석·capability 비트를 fd 이름으로 오해하거나 인자 경계·재결합을 잃는 것.
@pytest.mark.parametrize("split", [False, True], ids=["whole", "split"])
@pytest.mark.parametrize("line,name,args,ret", [
    (PPOLL, "ppoll", [
        "[{fd=0</dev/null<char 1:3>>, events=0}, {fd=1<pipe:[1586202]>, events=0}, "
        "{fd=2<pipe:[1586203]>, events=0}]",
        "3", "{tv_sec=0, tv_nsec=0}", "NULL", "0",
    ], "0 (Timeout)"),
    (CAPGET, "capget", [CAP_HEADER,
        f"{{effective={CAP_BITS}, permitted={CAP_BITS}, inheritable=0}}"], "0"),
], ids=["ppoll", "capget"])
def test_exact_repository_records(line, name, args, ret, split):
    calls = parse(record(line, split))
    assert not calls.errors, calls.errors
    call, = calls
    assert (call.pid, call.name, call.ret) == (int(line.split()[0]), name, ret)
    assert split_args(call.args) == args


# 이것을 실패시키는 것: capability가 제거된 실제 capget 레코드를 잘못 해석하는 것.
def test_exact_zero_capability_record():
    calls = parse(CAPGET_ZERO)
    assert not calls.errors, calls.errors
    call, = calls
    assert (call.pid, call.name, call.ret) == (2012, "capget", "0")
    assert split_args(call.args) == [CAP_HEADER, "{effective=0, permitted=0, inheritable=0}"]


# 이것을 실패시키는 것: -yy의 char/block 장치 꼬리만 허용하지 않거나 경로 안 쉼표·괄호·이스케이프를 재해석하는 것.
@pytest.mark.parametrize("fd", [
    "0</dev/null<char 1:3>>", "3</dev/sda<block 8:0>>",
    r"3</tmp/a\74b\76,)=<char 123:456>>", "3</dev/null>",
])
def test_device_fd_names_are_opaque(fd):
    assert scan(f'{fd}, "", 1')[0] == [fd, '""', "1"]


# 이것을 실패시키는 것: 장치 지원을 임의 중첩·잘못된 장치 꼬리·fd 없는 주석·닫히지 않은 꺾쇠까지 넓히는 것.
@pytest.mark.parametrize("fd", [
    "0</dev/null<other 1:3>>", "0</dev/null<char 1>>",
    "0</dev/null<char -1:3>>", "0</dev/null<char 1:x>>",
    "0</dev/null<char 1:3:4>>", "0</dev/null<char 1:3 >>",
    "0<pipe:[1]<char 1:3>>", "0<relative<char 1:3>>",
    "0</dev/null<arbitrary>>", "0</dev/null<char 1:3><block 8:0>>",
    "0</dev/null<char 1:3<block 8:0>>>", "0</dev/null<char 1:3>tail>",
    "0</dev/null<char 1:3>", "0</dev/null<char 1:3", "0</dev/null<char 1:3>>>",
    "</dev/null<char 1:3>>", '"0"</dev/null<char 1:3>>',
])
@pytest.mark.parametrize("split", [False, True], ids=["whole", "split"])
def test_malformed_device_annotations_are_refused(fd, split):
    calls = parse(record(PPOLL.replace("0</dev/null<char 1:3>>", fd), split))
    assert calls.errors and not calls
    with pytest.raises(StructureError):
        scan(f'{fd}, "", 1')


# 이것을 실패시키는 것: capability 한정 토큰을 일반 shift·bare 꺾쇠·불완전한 capability 이름으로 넓히는 것.
@pytest.mark.parametrize("bit", [
    "1<CAP_CHOWN", "1<<<CAP_CHOWN", "1<<<<CAP_CHOWN", "1<<CAP_CHOWN>",
    "2<<CAP_CHOWN", "11<<CAP_CHOWN", "0x1<<CAP_CHOWN", "-1<<CAP_CHOWN",
    "1<<CHOWN", "1<<CAP_", "1<<CAP_chown", "1<<CAP_CHOWNtail",
    "1<<CAP_CHOWN<<CAP_KILL", "<1<<CAP_CHOWN>", "1<<CAP_CHOWN<junk>",
    "1<<CAP_CHOWN|", "1<<CAP_CHOWN|0", "1<<CAP_CHOWN|2<<CAP_KILL",
])
@pytest.mark.parametrize("split", [False, True], ids=["whole", "split"])
def test_malformed_capability_bits_are_refused(bit, split):
    calls = parse(record(CAPGET.replace("1<<CAP_CHOWN", bit), split))
    assert calls.errors and not calls
    with pytest.raises(StructureError):
        scan(f"{{effective={bit}, permitted=0, inheritable=0}}")


# 이것을 실패시키는 것: capability struct 밖의 shift·bare 꺾쇠나 손상된 바깥 괄호를 허용하는 것.
@pytest.mark.parametrize("args", [
    "1<<CAP_CHOWN", "[1<<CAP_CHOWN]", "{1<<CAP_CHOWN}",
    "{other=1<<CAP_CHOWN}", "[effective=1<<CAP_CHOWN]",
    "{effective=<CAP_CHOWN>}", "{effective=1<<CAP_CHOWN]",
    "{effective=1<<CAP_CHOWN", "{effective=1<<CAP_CHOWN}> ",
])
def test_capability_bits_require_a_complete_struct_field(args):
    calls = parse(f"2012 capget({CAP_HEADER}, {args}) = 0")
    assert calls.errors and not calls
    with pytest.raises(StructureError):
        scan(args)
