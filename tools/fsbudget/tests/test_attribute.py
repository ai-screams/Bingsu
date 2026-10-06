import threading

import pytest

from fsbudget.attribute import attribute, prologue_allowed
from fsbudget.strace_parse import parse

RULES = [["helper", r'"--role", "helper"'], ["writer", r'"--role", "writer"'], ["worker", r'"--role", "worker"'],
         ["command", r'^"/bin/true"']]

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


# A child's first lines can come before its parent's clone return (seen on
# Debian 13): the child takes its parent's role, not the root's.
EARLY_CHILD = """\
40 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
40 prctl(PR_SET_NAME, "fsb:begin") = 0
40 clone(child_stack=NULL, flags=SIGCHLD) = 41
41 execve("/s", ["/s", "--role", "helper"], 0x0 /* 0 vars */) = 0
41 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD <unfinished ...>
42 prctl(PR_SET_NAME, "fsb:begin") = 0
42 openat(AT_FDCWD</>, "/h2", O_RDONLY) = 3</h2>
42 prctl(PR_SET_NAME, "fsb:end") = 0
41 <... clone resumed>) = 42
40 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: 부모의 clone 반환보다 먼저 나온 자식에게 뿌리(front) 역할을 주는 것.
def test_child_seen_before_its_parents_return_takes_the_parents_role():
    got = attribute(parse(EARLY_CHILD), RULES, markers=True)
    assert got.errors == []
    assert got.counts == {"helper": {"openat": 1}}


# A grandchild whose parent's only record so far is an unfinished clone:
# both returns come after the grandchild's calls. The role comes from the
# nearest ancestor that has one (the root), never a default `command`.
EARLY_GRANDCHILD = """\
30 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>
31 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>
32 openat(AT_FDCWD</>, "/home/u/repo/secret", O_RDONLY) = 3</home/u/repo/secret>
32 read(3</home/u/repo/secret>, "s", 1) = 1
31 <... clone resumed>) = 32
30 <... clone resumed>) = 31
"""


# 이것을 실패시키는 것: 부모도 역할이 없을 때 기본값 command를 주는 것, 조상을 한 단계만 보는 것,
# 뿌리를 첫 기록(끝나지 않은 clone)이 아니라 첫 완료 호출의 pid로 잡는 것.
def test_early_grandchild_takes_the_ancestors_role():
    got = attribute(parse(EARLY_GRANDCHILD), RULES, markers=True)
    assert "command" not in got.counts
    assert not any("no spawn call" in e for e in got.errors), got.errors
    assert any(e.startswith("pid 32 (front): openat outside window") for e in got.errors), got.errors
    assert any(e.startswith("pid 32 (front): read outside window") for e in got.errors), got.errors


# 이것을 실패시키는 것: 어떤 spawn도 설명하지 않는 task를 오류 없이 넘기거나 command로 빼는 것.
def test_task_with_no_spawn_chain_fails_and_stays_gated():
    trace = ('30 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0\n'
             '44 openat(AT_FDCWD</>, "/x", O_RDONLY) = 3</x>\n')
    got = attribute(parse(trace), RULES, markers=True)
    assert "pid 44: no spawn call leads to a task with a role" in got.errors
    assert any(e.startswith("pid 44 (unresolved): openat outside window") for e in got.errors), got.errors
    assert "command" not in got.counts


# Two tasks that name each other as the spawned child (only possible in a
# broken or crafted trace): the walk up must stop, not loop.
SPAWN_CYCLE = """\
30 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
31 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>
32 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>
31 <... clone resumed>) = 32
32 <... clone resumed>) = 31
"""


# 이것을 실패시키는 것: 조상 풀기에서 순환을 막지 않는 것(끝나지 않음).
def test_spawn_cycle_fails_instead_of_looping():
    result = []
    t = threading.Thread(target=lambda: result.append(attribute(parse(SPAWN_CYCLE), RULES, markers=True)), daemon=True)
    t.start()
    t.join(5)
    assert result, "attribute() did not finish on a spawn cycle"
    assert "pid 31: no spawn call leads to a task with a role" in result[0].errors


# A TID number reused after an exit starts fresh: no role, window or
# start-up state from the task that had it before.
REUSED_TID = """\
50 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
50 prctl(PR_SET_NAME, "fsb:begin") = 0
50 clone(child_stack=NULL, flags=SIGCHLD) = 51
51 execve("/s", ["/s", "--role", "helper"], 0x0 /* 0 vars */) = 0
51 prctl(PR_SET_NAME, "fsb:begin") = 0
51 prctl(PR_SET_NAME, "fsb:end") = 0
51 +++ exited with 0 +++
50 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD <unfinished ...>
51 prctl(PR_SET_NAME, "fsb:begin") = 0
51 openat(AT_FDCWD</>, "/t", O_RDONLY) = 3</t>
51 prctl(PR_SET_NAME, "fsb:end") = 0
50 <... clone resumed>) = 51
50 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: 종료 기록에서 그 TID의 역할을 지우지 않는 것(재사용한 번호가 helper로 셈).
def test_reused_tid_does_not_inherit_the_old_role():
    got = attribute(parse(REUSED_TID), RULES, markers=True)
    assert got.errors == []
    assert got.counts == {"front": {"openat": 1}}


# The helper exits after exec and before its first fsb:begin (start-up
# state still on); the number comes back as a front thread, which has no
# start-up section, so its loader-like call is outside the window.
REUSED_AFTER_STARTUP = """\
70 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
70 prctl(PR_SET_NAME, "fsb:begin") = 0
70 clone(child_stack=NULL, flags=SIGCHLD) = 71
71 execve("/s", ["/s", "--role", "helper"], 0x0 /* 0 vars */) = 0
71 +++ killed by SIGKILL +++
70 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 71
71 openat(AT_FDCWD</>, "/etc/ld.so.cache", O_RDONLY) = 3</etc/ld.so.cache>
70 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: 종료 기록에서 그 TID의 시작 구간 상태를 지우지 않는 것(재사용한 번호의 호출이 시작 구간으로 면제됨).
def test_reused_tid_has_no_startup_section():
    got = attribute(parse(REUSED_AFTER_STARTUP), RULES, markers=True)
    assert any("pid 71 (front): openat outside window" in e for e in got.errors), got.errors


# 이것을 실패시키는 것: 창을 연 채 끝난 TID를 오류로 보지 않는 것, 또는 종료 뒤에도 그 창을 열린 채로 두는 것
# (끝에서 같은 창을 또 보고함).
def test_exit_with_an_open_window_is_one_error():
    trace = ('80 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0\n'
             '80 prctl(PR_SET_NAME, "fsb:begin") = 0\n80 clone(child_stack=NULL, flags=SIGCHLD) = 81\n'
             '81 execve("/s", ["/s", "--role", "helper"], 0x0 /* 0 vars */) = 0\n'
             '81 prctl(PR_SET_NAME, "fsb:begin") = 0\n81 +++ exited with 0 +++\n'
             '80 prctl(PR_SET_NAME, "fsb:end") = 0\n')
    assert attribute(parse(trace), RULES, markers=True).errors == ["pid 81: exited with 0 with its fsb window open"]


# A command's own children may exec anything: only gated roles must match a rule.
COMMAND_CHILD = """\
60 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0
60 prctl(PR_SET_NAME, "fsb:begin") = 0
60 clone(child_stack=NULL, flags=SIGCHLD) = 61
61 execve("/bin/true", ["/bin/true"], 0x0 /* 0 vars */) = 0
61 clone(child_stack=NULL, flags=SIGCHLD) = 62
62 execve("/usr/bin/anything", ["/usr/bin/anything"], 0x0 /* 0 vars */) = 0
62 openat(AT_FDCWD</>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>
60 prctl(PR_SET_NAME, "fsb:end") = 0
"""


# 이것을 실패시키는 것: 명령 프로세스의 자손이 규칙 밖 exec을 할 때도 role escape로 보는 것.
def test_command_descendants_stay_commands():
    got = attribute(parse(COMMAND_CHILD), RULES, markers=True)
    assert got.errors == []
    assert got.counts == {"command": {"openat": 1}}


HEAD = '30 execve("/s", ["/s", "--role", "front"], 0x0 /* 0 vars */) = 0\n'
WIN = '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'
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
    # Near misses of the start-up pairs: each one passes if its rule is widened.
    "another process's maps": '30 openat(AT_FDCWD</>, "/proc/1/maps", O_RDONLY) = 3</proc/1/maps>\n' + WIN,
    "maps under /proc/self/root": '30 openat(AT_FDCWD</>, "/proc/self/root/proc/self/maps", O_RDONLY) = 3</proc/30/maps>\n' + WIN,
    "ld.so.cache prefix": '30 openat(AT_FDCWD</>, "/etc/ld.so.cache.d/x", O_RDONLY) = 3</etc/ld.so.cache.d/x>\n' + WIN,
    "ld.so prefix for preload": '30 access("/etc/ld.so.conf", R_OK) = 0\n' + WIN,
    "hwcaps escape": '30 openat(AT_FDCWD</>, "/lib/glibc-hwcaps/../../home/u/libx.so", O_RDONLY) = 3</home/u/libx.so>\n' + WIN,
    "start-up openat for writing": '30 openat(AT_FDCWD</>, "/etc/ld.so.cache", O_RDWR) = 3</etc/ld.so.cache>\n' + WIN,
    "start-up openat that creates": ('30 openat(AT_FDCWD</>, "/lib/libc.so.6", O_WRONLY|O_CREAT|O_TRUNC, 0644)'
                                     ' = 3</lib/libc.so.6>\n' + WIN),
    "role escape": ('30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 clone(child_stack=NULL, flags=SIGCHLD) = 31\n'
                    '31 execve("/usr/bin/evil", ["/usr/bin/evil"], 0x0 /* 0 vars */) = 0\n'
                    '30 prctl(PR_SET_NAME, "fsb:end") = 0\n'),
    "exit with an open window": ('30 prctl(PR_SET_NAME, "fsb:begin") = 0\n30 clone(child_stack=NULL, flags=SIGCHLD) = 31\n'
                                 '31 execve("/s", ["/s", "--role", "helper"], 0x0 /* 0 vars */) = 0\n'
                                 '31 prctl(PR_SET_NAME, "fsb:begin") = 0\n31 +++ exited with 0 +++\n'
                                 '30 clone(child_stack=NULL, flags=SIGCHLD) = 31\n'
                                 '31 execve("/s", ["/s", "--role", "worker"], 0x0 /* 0 vars */) = 0\n'
                                 '31 prctl(PR_SET_NAME, "fsb:end") = 0\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n'),
    "task without a spawn call": '30 prctl(PR_SET_NAME, "fsb:begin") = 0\n44 getpid() = 44\n30 prctl(PR_SET_NAME, "fsb:end") = 0\n',
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
