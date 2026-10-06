import pytest

from fsbudget.attribute import attribute, prologue_allowed
from fsbudget.strace_parse import parse

RULES = [["helper", r'"--role", "helper"'], ["writer", r'"--role", "writer"'], ["worker", r'"--role", "worker"']]

TRACE = """\
10 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
10 openat(AT_FDCWD</>, "/etc/ld.so.cache", O_RDONLY) = 3</etc/ld.so.cache>
10 prctl(PR_SET_NAME, "fsb:begin") = 0
10 openat(AT_FDCWD</>, "/a", O_RDONLY) = 3</a>
10 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 11
11 execve("/proc/self/exe", ["/proc/self/exe", "--role", "helper"], 0x0 /* 0 vars */) = 0
11 openat(AT_FDCWD</>, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3</lib/x86_64-linux-gnu/libc.so.6>
11 prctl(PR_SET_NAME, "fsb:begin") = 0
11 openat(AT_FDCWD</>, "/h", O_RDONLY) = 4</h>
11 prctl(PR_SET_NAME, "fsb:end") = 0
10 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88) = 12
12 execve("/bin/true", ["/bin/true"], 0x0 /* 0 vars */) = 0
12 openat(AT_FDCWD</>, "/etc/ld.so.cache", O_RDONLY) = 3</etc/ld.so.cache>
10 openat(AT_FDCWD</>, "/b", O_RDONLY) = 4</b>
10 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: 자식을 부모 역할에 묶어 두는 것(exec 뒤 역할 전환 누락).
def test_roles_follow_exec_and_markers():
    got = attribute(parse(TRACE), RULES, markers=True)
    assert got.errors == []
    assert got.counts["front"]["openat"] == 2
    assert got.counts["helper"]["openat"] == 1
    assert got.counts["command"]["openat"] == 1


VFORK_LATE = """\
20 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
20 prctl(PR_SET_NAME, "fsb:begin") = 0
20 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
21 execve("/proc/self/exe", ["/proc/self/exe", "--role", "helper"], 0x0 /* 0 vars */) = 0
20 <... clone resumed>) = 21
21 prctl(PR_SET_NAME, "fsb:begin") = 0
21 openat(AT_FDCWD</>, "/h", O_RDONLY) = 3</h>
21 prctl(PR_SET_NAME, "fsb:end") = 0
20 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: vfork 부모의 늦은 반환 줄이 자식의 exec 역할을 덮어쓰는 것.
def test_late_vfork_return_keeps_child_role():
    got = attribute(parse(VFORK_LATE), RULES, markers=True)
    assert got.errors == []
    assert got.counts.get("helper", {}).get("openat") == 1
    assert "openat" not in got.counts.get("front", {})


HEAD = '30 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0\n'
BAD = {
    "outside window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'
                      '30 openat(AT_FDCWD</>, "/late", O_RDONLY) = 3</late>\n',
    "unknown prologue path": '30 openat(AT_FDCWD</>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>\n'
                             '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "nested begin": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                    '30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "end without begin": '30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "open at end": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n',
    "marker failed": '30 prctl(PR_SET_NAME, "fsb:begin") = -1 EINVAL (Invalid argument)\n'
                     '30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "unknown fs call inside window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                                     '30 fchmodat(AT_FDCWD</>, "/x", 0644) = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "unknown fs call outside window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'
                                      '30 access("/etc/hosts", R_OK) = 0\n',
    "relative path in window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                               '30 fchmodat(AT_FDCWD</r>, "x", 0644) = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "trusted path, disallowed syscall": '30 fchmodat(AT_FDCWD</>, "/etc/ld.so.cache", 0644) = 0\n'
                                        '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "file-backed mmap in window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                                  '30 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3</r/x>, 0) = 0x7f00\n'
                                  '30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "ioctl on a file in window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                                 '30 ioctl(3</r/x>, FIONREAD, [0]) = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "pre-exec child opens a library": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                                      '30 clone(child_stack=NULL, flags=SIGCHLD) = 31\n'
                                      '31 openat(AT_FDCWD</>, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3</lib/x86_64-linux-gnu/libc.so.6>\n'
                                      '30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "parser error reaches the gate": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'
                                     '30 <... openat resumed>) = 3</x>\n',
    "other fsb marker name": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:ending") = 0\n',
    "fsb marker on another prctl option": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_GET_NAME, "fsb:end") = 0\n',
    "fsb marker with extra arguments": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end", 0) = 0\n',
    "exec inside window": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n'
                          '30 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0\n'
                          '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
    "untrusted .so in prologue": '30 openat(AT_FDCWD</>, "/tmp/evil.so", O_RDONLY) = 3</tmp/evil.so>\n'
                                 '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
}


LIB = "/lib/x86_64-linux-gnu"
# A glibc 2.35 loader and Rust std start-up as strace -f -y prints them.
LOADER = (
    '30 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)\n'
    '30 openat(AT_FDCWD</>, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache>\n'
    '30 newfstatat(3</etc/ld.so.cache>, "", {st_mode=S_IFREG|0644, st_size=20000, ...}, AT_EMPTY_PATH) = 0\n'
    '30 mmap(NULL, 20000, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7f0000000000\n'
    '30 close(3</etc/ld.so.cache>) = 0\n'
    f'30 openat(AT_FDCWD</>, "{LIB}/glibc-hwcaps/x86-64-v3/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)\n'
    f'30 openat(AT_FDCWD</>, "{LIB}/libc.so.6", O_RDONLY|O_CLOEXEC) = 3<{LIB}/libc.so.6>\n'
    f'30 read(3<{LIB}/libc.so.6>, "\\177ELF", 832) = 832\n'
    f'30 pread64(3<{LIB}/libc.so.6>, "\\6\\0", 784, 64) = 784\n'
    f'30 newfstatat(3<{LIB}/libc.so.6>, "", {{st_mode=S_IFREG|0755, st_size=2220400, ...}}, AT_EMPTY_PATH) = 0\n'
    f'30 mmap(NULL, 2264656, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3<{LIB}/libc.so.6>, 0) = 0x7f0000100000\n'
    f'30 mmap(0x7f0000128000, 1658880, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3<{LIB}/libc.so.6>, 0x28000) = 0x7f0000128000\n'
    f'30 close(3<{LIB}/libc.so.6>) = 0\n'
    '30 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0000400000\n'
    '30 openat(AT_FDCWD</>, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 3</proc/30/maps>\n'
    '30 newfstatat(3</proc/30/maps>, "", {st_mode=S_IFREG|0444, st_size=0, ...}, AT_EMPTY_PATH) = 0\n'
    '30 read(3</proc/30/maps>, "5600", 1024) = 1024\n'
    '30 close(3</proc/30/maps>) = 0\n'
    '30 poll([{fd=0, events=0}, {fd=1, events=0}, {fd=2, events=0}], 3, 0) = 0 (Timeout)\n'
    '30 rt_sigaction(SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[PIPE], sa_flags=SA_RESTORER}, {sa_handler=SIG_DFL}, 8) = 0\n'
)


# 이것을 실패시키는 것: 실제 로더 순서(파일 mmap, AT_EMPTY_PATH fstat, /proc/<pid>/maps)를 막는 것.
def test_trusted_loader_paths_pass():
    body = LOADER + '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'
    assert attribute(parse(HEAD + body), RULES, markers=True).errors == []


# The aarch64 loader as strace 5.16 prints it on Ubuntu 22.04 (glibc 2.35):
# faccessat instead of access, AT_FDCWD named with the cwd, and fds named
# with the merged /usr path while the openat argument says /lib.
ALIB = "/lib/aarch64-linux-gnu"
AUSR = "/usr/lib/aarch64-linux-gnu"
AARCH64_LOADER = (
    '30 faccessat(AT_FDCWD</w>, "/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)\n'
    '30 openat(AT_FDCWD</w>, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache>\n'
    '30 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=5083, ...}) = 0\n'
    '30 mmap(NULL, 5083, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0xe339df51a000\n'
    f'30 openat(AT_FDCWD</w>, "{ALIB}/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3<{AUSR}/libgcc_s.so.1>\n'
    f'30 read(3<{AUSR}/libgcc_s.so.1>, "\\177ELF", 832) = 832\n'
    f'30 newfstatat(3<{AUSR}/libgcc_s.so.1>, "", {{st_mode=S_IFREG|0644, st_size=84296, ...}}, AT_EMPTY_PATH) = 0\n'
    f'30 mmap(0xfc3b38010000, 148168, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3<{AUSR}/libgcc_s.so.1>, 0) = 0xfc3b38010000\n'
    f'30 close(3<{AUSR}/libgcc_s.so.1>) = 0\n'
    '30 openat(AT_FDCWD</w>, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 3</proc/30/maps>\n'
    '30 read(3</proc/30/maps>, "5600", 1024) = 1024\n'
)


# 이것을 실패시키는 것: aarch64 로더의 faccessat을 시작 구간 짝에서 빼는 것, /usr/lib/aarch64-linux-gnu를 빼는 것.
def test_aarch64_loader_paths_pass():
    body = AARCH64_LOADER + '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'
    assert attribute(parse(HEAD + body), RULES, markers=True).errors == []


# Every library folder the prologue trusts, written out here (not read from
# TRUSTED_LIB_DIRS) so that dropping one from the list fails a case.
LIB_DIRS = ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
            "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"]


# 이것을 실패시키는 것: TRUSTED_LIB_DIRS에서 폴더 하나를 빼는 것, glibc-hwcaps 하위 폴더를 막는 것,
# 또는 허용 폴더의 더 깊은 하위 폴더·lib 이름이 아닌 파일을 허용하는 것.
@pytest.mark.parametrize("d", LIB_DIRS)
def test_each_trusted_library_folder(d):
    assert prologue_allowed("openat", f"{d}/libc.so.6")
    assert prologue_allowed("openat", f"{d}/glibc-hwcaps/x86-64-v3/libc.so.6")
    assert not prologue_allowed("openat", f"{d}/sub/libc.so.6")
    assert not prologue_allowed("openat", f"{d}/evil.so")
    assert not prologue_allowed("unlinkat", f"{d}/libc.so.6")


# 이것을 실패시키는 것: 표식 창 검사의 어느 한 규칙이라도 열린 쪽으로 두는 것.
@pytest.mark.parametrize("name", BAD)
def test_window_rules_fail_closed(name):
    got = attribute(parse(HEAD + BAD[name]), RULES, markers=True)
    assert got.errors, f"{name}: scaffold accepted a broken window"
