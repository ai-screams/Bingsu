import pytest

from fsbudget.classify import kind
from fsbudget.strace_parse import parse

TRACE = """\
100 execve("/x/fsb-synthetic", ["/x/fsb-synthetic", "--role", "front"], 0x7ffd /* 3 vars */) = 0
100 openat(AT_FDCWD</>, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache>
100 prctl(PR_SET_NAME, "fsb:begin") = 0
100 openat(AT_FDCWD</>, "/r", O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC <unfinished ...>
101 read(5<pipe:[1234]>, "R", 1) = 1
100 <... openat resumed>) = 4</r>
100 newfstatat(4</r>, "", {st_mode=S_IFDIR|0700, ...}, AT_EMPTY_PATH) = 0
100 read(4</r/h>, "\\0\\0", 64) = 64
100 read(0</dev/null>, "", 1) = 0
100 fgetxattr(4</r>, "system.posix_acl_access", 0x0, 0) = -1 ENODATA (No data available)
100 fgetxattr(4</r>, "user.other", 0x0, 0) = -1 ENODATA (No data available)
100 close(4</r>) = 0
100 getdents64(4</r>, 0x55 /* 3 entries */, 4096) = 80
100 --- SIGCHLD {si_signo=SIGCHLD} ---
100 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: unfinished/resumed를 합치지 않거나, 신호 줄을 호출로 세는 것.
def test_parse_merges_unfinished_and_skips_signals():
    calls = parse(TRACE)
    names = [c.name for c in calls]
    assert names.count("openat") == 2
    assert "---" not in "".join(names)
    resumed = [c for c in calls if c.name == "openat" and c.ret.startswith("4")]
    assert resumed and resumed[0].pid == 100 and '"/r"' in resumed[0].args
    assert calls.errors == []


BROKEN = {
    "no PID prefix": ('openat(AT_FDCWD</>, "/x", O_RDONLY) = 3</x>\n', "no PID prefix"),
    "unparsed record": ('100 openat(AT_FDCWD</>, "/x", O_RDONLY\n', "unparsed record"),
    "orphan resumed": ("100 <... openat resumed>) = 3</x>\n", "resumed without an unfinished call"),
    "resumed for another call": ("100 read(3</x> <unfinished ...>\n100 <... openat resumed>) = 3</x>\n",
                                 "openat resumed but read was unfinished"),
    "second unfinished": ('100 read(3</x> <unfinished ...>\n100 openat(AT_FDCWD</>, "/y" <unfinished ...>\n'
                          "100 <... openat resumed>) = 4</y>\n", "second unfinished call"),
    "unfinished at end": ("100 read(3</x>, <unfinished ...>\n", "still unfinished at the end"),
}


# 이것을 실패시키는 것: 파서가 알아보지 못한 줄, 짝 없는·겹친 resumed, 끝까지 열린 unfinished를 조용히 넘기는 것.
@pytest.mark.parametrize("name", BROKEN)
def test_structural_errors_are_reported(name):
    text, want = BROKEN[name]
    errors = parse(text).errors
    assert any(want in e for e in errors), (name, errors)


# 이것을 실패시키는 것: 죽은 프로세스의 끝나지 않은 호출을 구조 오류로 보는 것(정상 추적이 실패함).
def test_killed_process_may_leave_a_call_unfinished():
    assert parse("100 wait4(-1 <unfinished ...>\n100 +++ killed by SIGKILL +++\n").errors == []


# strace 5.16 and 6.13 close a call cut short by death (SIGKILL, or another
# thread's exit_group) with a resumed record that carries no result, then
# write the exit record.
# 이것을 실패시키는 것: 결과 없는 resumed(`<... read resumed> <unfinished ...>) = ?`)를 알아보지 못하는 것.
def test_call_cut_short_by_death_parses():
    text = ("11 read(3<pipe:[24017]>,  <unfinished ...>\n11 <... read resumed> <unfinished ...>) = ?\n"
            "11 +++ killed by SIGKILL +++\n")
    calls = parse(text)
    assert calls.errors == []
    assert [(c.name, c.ret) for c in calls] == [("read", "?")]


# 이것을 실패시키는 것: 파이프·/dev/null 읽기를 파일 읽기로 세거나, close를 세거나, ACL이 아닌 xattr을 ACL로 세는 것,
# 또는 공식 밖의 파일 시스템 호출에 종류를 주지 않는 것.
def test_classify_counts_only_filesystem_calls():
    kinds = [kind(c) for c in parse(TRACE)]
    assert kinds.count("read") == 1
    assert kinds.count("acl") == 1
    assert kinds.count("unknown-fs") == 1  # fgetxattr of a non-ACL attribute
    assert kinds.count("fstat") == 1
    assert kinds.count("getdents") == 1
    assert "close" not in kinds


FD_CASES = [
    ('fchmodat(AT_FDCWD</r>, "x", 0644) = 0', "unknown-fs"),                 # relative path
    ('fchmod(3</r/x>, 0644) = 0', "unknown-fs"),                             # pathless, file fd
    ('lseek(3</r/x>, 0, SEEK_SET) = 0', "unknown-fs"),                       # never classified
    ('fcntl(3</r/x>, F_SETFD, FD_CLOEXEC) = 0', "unknown-fs"),
    ('fcntl(3, F_GETFD) = 1', "unknown-fs"),                                 # unnamed fd
    ('fcntl(5<pipe:[9]>, F_GETFL) = 0', None),
    ('ioctl(3</r/x>, FIONREAD, [0]) = 0', "unknown-fs"),
    ('ioctl(1</dev/pts/0>, TCGETS, {c_iflag=0}) = 0', None),
    ('mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3</r/x>, 0) = 0x7f00', "unknown-fs"),
    ('mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f00', None),
    ('read(7, "a", 1) = 1', "read"),                                         # unnamed fd counts
    ('setsid() = 31', None),
    ('read(3</dev/shm/bingsu>, "a", 1) = 1', "read"),                         # /dev/shm is a filesystem
    ('fstat(3</dev/shm/bingsu>, {st_mode=S_IFREG|0600, ...}) = 0', "fstat"),
    ('fcntl(3</dev/shm/bingsu>, F_GETFD) = 1', "unknown-fs"),
    ('ioctl(3</dev/shm/bingsu>, FIONREAD, [0]) = 0', "unknown-fs"),
    ('mmap(NULL, 4096, PROT_READ, MAP_SHARED, 3</dev/shm/bingsu>, 0) = 0x7f00', "unknown-fs"),
    ('read(3</dev/sda1>, "a", 1) = 1', "read"),                               # a block device is not exempt
    ('read(0</dev/null>, "", 1) = 0', None),
    ('read(0</dev/pts/3>, "a", 1) = 1', None),
    ('write(1<pipe:[77]>, "a", 1) = 1', None),
    ('read(4<socket:[88]>, "a", 1) = 1', None),
    ('read(5<weird:[1]>, "a", 1) = 1', "read"),                               # an unknown kind counts
]


# 이것을 실패시키는 것: 상대 경로나 경로 없는 파일 fd 호출, 분류하지 않은 호출을 None으로 두는 것(기본 허용),
# fcntl·ioctl·mmap을 fd와 무관하게 비파일로 보는 것, 이름 없는 fd를 비파일로 보는 것,
# `/dev/` 아래를 모두 비파일로 보는 것(`/dev/shm` 파일이 빠짐).
@pytest.mark.parametrize(("line", "want"), FD_CASES)
def test_classify_default_deny_and_fd_identity(line, want):
    (c,) = parse("40 " + line + "\n")
    assert kind(c) == want, line
