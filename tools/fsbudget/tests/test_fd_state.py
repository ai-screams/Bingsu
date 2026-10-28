"""fd_table_at_exec: the descriptor table a process holds right after its exec.

Synthetic traces in the shapes the live gate meets: glibc posix_spawn (clone3
with CLONE_VFORK; addopen lands through open+dup2+close), musl on aarch64
(clone, open at the lowest free fd, dup3, an O_CLOEXEC error pipe), helper
threads that share one table, and the fail-closed refusals.
"""
import pytest

from fsbudget.attribute import FdEntry, FdStateError, fd_table_at_exec
from fsbudget.strace_parse import parse

TTY = "/dev/pts/0"
PIPE = "pipe:[700]"


def initial(**extra):
    table = {fd: FdEntry(fd, TTY, False, "inherited") for fd in (0, 1, 2)}
    for fd, (path, cloexec) in extra.items():
        table[int(fd[2:])] = FdEntry(int(fd[2:]), path, cloexec, "inherited")
    return table


def spawn_child(child=101, null=4):
    """glibc's posix_spawn child: three addopen actions, then exec."""
    lines = []
    for fd in (0, 1, 2):
        lines += [f'{child} openat(AT_FDCWD</w>, "/dev/null", O_RDWR) = {null}</dev/null>',
                  f'{child} dup2({null}</dev/null>, {fd}<{TTY}>) = {fd}</dev/null>',
                  f'{child} close({null}</dev/null>) = 0']
    return lines + [f'{child} execve("/bin/helper", ["/bin/helper", "__refresh-v1"], 0x0) = 0']


def front(*before, child=101, null=4):
    return "\n".join([
        *before,
        '100 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f00, stack_size=0x9000}, 88 <unfinished ...>',
        *spawn_child(child, null),
        f'100 <... clone3 resumed>) = {child}',
        '100 exit_group(0) = ?',
        '100 +++ exited with 0 +++',
    ]) + "\n"


def summary(table):
    return {fd: (e.path, e.cloexec, e.origin) for fd, e in table.items()}


DEV_NULL_STDIO = {fd: ("/dev/null", False, "spawn-action") for fd in (0, 1, 2)}


# 이것을 실패시키는 것: 성공한 execve에서 cloexec 항목을 지우지 않는 것(fd 3이 남는다),
# clone 때 부모의 cloexec 표시를 버리고 False로 복사하는 것(fd 3이 남는다).
def test_fd_state_applies_parent_cloexec_and_exec_closure():
    """F_SETFD in the parent and no close in the child: fd 3 is gone at exec."""
    text = front('100 fcntl(3<pipe:[700]>, F_SETFD, FD_CLOEXEC) = 0')
    got = fd_table_at_exec(parse(text), 101, initial(fd3=(PIPE, False)))
    assert summary(got) == DEV_NULL_STDIO
    # Control: without the parent's F_SETFD the same fd survives the exec.
    kept = fd_table_at_exec(parse(front()), 101, initial(fd3=(PIPE, False)))
    assert summary(kept) == {**DEV_NULL_STDIO, 3: (PIPE, False, "inherited")}


# 이것을 실패시키는 것: dup2 결과를 원본의 cloexec로 복사하는 것, open 결과를 spawn 자식 밖에서도
# spawn-action으로 적는 것, F_DUPFD_CLOEXEC·dup3 O_CLOEXEC·close_range를 무시하는 것.
def test_fd_state_follows_dup_open_and_close_range():
    text = front(
        '100 openat(AT_FDCWD</w>, "/proc/self/fd", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 10</proc/100/fd>',
        '100 fcntl(3<pipe:[700]>, F_DUPFD_CLOEXEC, 7) = 11<pipe:[700]>',
        '100 dup3(3<pipe:[700]>, 12, O_CLOEXEC) = 12<pipe:[700]>',
        '100 dup(3<pipe:[700]>) = 13<pipe:[700]>',
        '100 openat(AT_FDCWD</w>, "/w/f", O_RDONLY) = 14</w/f>',
        '100 close_range(20, 4294967295, 0) = 0',
        '100 close_range(13, 13, CLOSE_RANGE_CLOEXEC) = 0',
        '100 close(10</proc/100/fd>) = 0',
        child=101, null=15)
    got = fd_table_at_exec(parse(text), 101, initial(fd3=(PIPE, False), fd20=(PIPE, False)))
    assert summary(got) == {**DEV_NULL_STDIO, 3: (PIPE, False, "inherited"), 14: ("/w/f", False, "opened")}


# 이것을 실패시키는 것: musl의 오류 파이프(O_CLOEXEC)를 상속으로 남기는 것, dup3(n, fd, 0)을 무시하는 것.
def test_fd_state_reads_the_musl_spawn_shape():
    text = "\n".join([
        '100 pipe2([5<pipe:[9]>, 6<pipe:[9]>], O_CLOEXEC) = 0',
        '100 clone(child_stack=0x7f00, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 101',
        '101 close(5<pipe:[9]>) = 0',
        *[line for fd in (0, 1, 2) for line in (
            f'101 openat(AT_FDCWD</w>, "/dev/null", O_RDWR|O_LARGEFILE) = 5</dev/null>',
            f'101 dup3(5</dev/null>, {fd}<{TTY}>, 0) = {fd}</dev/null>',
            '101 close(5</dev/null>) = 0')],
        '101 execve("/bin/helper", ["/bin/helper"], 0x0) = 0',
        '100 close(6<pipe:[9]>) = 0',
    ]) + "\n"
    assert summary(fd_table_at_exec(parse(text), 101, initial())) == DEV_NULL_STDIO


# 이것을 실패시키는 것: CLONE_FILES 스레드가 연 fd를 그 스레드 표에만 두는 것(공유 표를 복사로 다룸).
def test_fd_state_shares_one_table_between_threads():
    text = front(
        '100 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0, stack=0x7e00, stack_size=0x8000}, 88) = 102',
        '102 openat(AT_FDCWD</w>, "/w/leak", O_RDONLY) = 9</w/leak>',
        '102 exit(0) = ?',
        '102 +++ exited with 0 +++',
        null=10)
    got = fd_table_at_exec(parse(text), 101, initial())
    assert summary(got) == {**DEV_NULL_STDIO, 9: ("/w/leak", False, "opened")}


# 이것을 실패시키는 것: fork 뒤 부모가 닫은 fd를 자식 표에서도 지우는 것(자식은 clone 때의 사본).
def test_fd_state_copies_the_table_at_fork():
    text = "\n".join([
        '100 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f) = 101',
        '100 close(3<pipe:[700]>) = 0',
        '101 execve("/bin/x", ["/bin/x"], 0x0) = 0',
    ]) + "\n"
    got = fd_table_at_exec(parse(text), 101, initial(fd3=(PIPE, False)))
    assert summary(got) == {**summary(initial()), 3: (PIPE, False, "inherited")}


# 이것을 실패시키는 것: 실패한 호출(-1)을 효과로 적용하는 것.
def test_fd_state_ignores_failed_calls():
    text = front('100 fcntl(3<pipe:[700]>, F_SETFD, FD_CLOEXEC) = -1 EPERM (Operation not permitted)',
                 '100 close(4) = -1 EBADF (Bad file descriptor)', null=5)
    got = fd_table_at_exec(parse(text), 101, initial(fd3=(PIPE, False)))
    assert summary(got) == {**DEV_NULL_STDIO, 3: (PIPE, False, "inherited")}


# 이것을 실패시키는 것: 표 밖 fd 사용·모르는 fd 생성·F_GETFD 불일치·부모 모를 프로세스·exec 없음을
# 조용히 넘기는 것(닫힌 쪽이 아니라 깨끗한 표를 낸다).
@pytest.mark.parametrize("damage,lines,pid,message", [
    ("unknown-use", ['100 read(8<pipe:[1]>, "", 4) = 0'], 101, "not in the table"),
    ("unmodeled-creator", ['100 fanotify_mark_fd(1) = 8<anon_inode:[x]>'], 101, "unmodeled descriptor"),
    ("getfd-mismatch", ['100 fcntl(3<pipe:[700]>, F_GETFD) = 0x1 (flags FD_CLOEXEC)'], 101, "F_GETFD"),
    ("scm-rights", ['100 recvmsg(3<pipe:[700]>, {msg_control=[{cmsg_type=SCM_RIGHTS, cmsg_data=[8]}]}, 0) = 1'],
     101, "SCM_RIGHTS"),
    ("unknown-parent", [], 555, "no exec"),
])
def test_fd_state_fails_closed(damage, lines, pid, message):
    text = front(*lines)
    with pytest.raises(FdStateError, match=message):
        fd_table_at_exec(parse(text), pid, initial(fd3=(PIPE, False)))


# 이것을 실패시키는 것: 부모를 모르는 자식에게 빈 표를 주어 깨끗한 결과를 내는 것.
def test_fd_state_refuses_a_task_without_a_known_parent():
    text = '300 execve("/bin/x", ["/bin/x"], 0x0) = 0\n'
    trace = parse('100 getpid() = 100\n' + text)
    with pytest.raises(FdStateError, match="parent"):
        fd_table_at_exec(trace, 300, initial())


# 이것을 실패시키는 것: 따옴표 문자열 안의 "7<x>"를 fd 사용으로 읽어 깨끗한 trace를 거부하는 것.
def test_fd_state_reads_no_fd_inside_strings():
    text = front('100 write(1</dev/pts/0>, "exec 7<x> 1025>&100", 19) = 19')
    assert summary(fd_table_at_exec(parse(text), 101, initial())) == DEV_NULL_STDIO
