"""F-01 / X-06: at prompt time HOME, USER, XDG_* and BINGSU_LOG point into a
repository; the hook must still pass only the roots pinned by init, and the
binary (with every process and thread it starts) must touch nothing under
the repository."""
import os
import ast
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# 이것을 실패시키는 것: 여러 테스트 모음의 conftest 이름 충돌로 통합 수집이 실패하는 것.
from shell_support import ROOT, SHELL_CMD, Install, minimal_record, real_bin, short_dir, trusted_env
from pty_session import Session

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import EXIT_EVENT, parse as parse_trace, scan

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
HOSTILE_VARS = ["HOME", "USER", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CACHE_HOME", "BINGSU_LOG"]
CALL = b"_bingsu_call --width 80\n"


# 이것을 실패시키는 것: 제품 prompt가 시험 전용 --collector-fixture 인자를 받아들이는 것.
def test_product_rejects_collector_fixture():
    base = [str(real_bin()), "prompt", "--ctx", "1", "--record", "B1", "--width", "80"]
    argv = subprocess.run(base + ["--collector-fixture"], capture_output=True, check=True)
    assert b"error:bad-args" in argv.stdout


def pinned_roots(trusted):
    """The root words and original config spelling init pins for `trusted` (same rule as test_init_words)."""
    run_root = os.path.realpath(trusted["XDG_RUNTIME_DIR"] + "/bingsu")
    st = os.stat(run_root)
    return {
        b"--runtime-root=": f"--runtime-root={st.st_dev}:{st.st_ino}:{run_root}".encode(),
        b"--git-global-home=": b"--git-global-home=" + os.fsencode(trusted.get("HOME", "")),
        b"--git-global-xdg=": b"--git-global-xdg=" + os.fsencode(trusted.get("XDG_CONFIG_HOME", "")),
        b"--config-root-written=": b"--config-root-written=" + (trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--config-root=": b"--config-root=" + os.path.realpath(trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--state-root=": b"--state-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu").encode(),
        b"--log-root=": b"--log-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu/log").encode(),
    }


def init_collector_exe(script):
    # This bash fixture uses plain paths; consume init's quoted pin, not the
    # build location or a sibling guessed from the symlink used to run init.
    pins = re.findall(rb"'--collector-exe=([^']*)'", script)
    assert len(pins) == 1, ("exactly one init collector pin", pins)
    path = os.fsdecode(pins[0])
    assert path.startswith("/") and os.path.normpath(path) == path, path
    assert os.path.basename(path) == "bingsu-collect", path
    return path


def export_line(shell, values):
    """One command line that exports every value (no value holds a quote)."""
    if shell == "fish":
        return "; ".join(f"set -gx {k} '{v}'" for k, v in values.items())
    return "export " + " ".join(f"{k}='{v}'" for k, v in values.items())


# 이것을 실패시키는 것: hook이 프롬프트 때 환경 변수로 뿌리 또는 설정 작성 경로를 만드는 것
# (예: `@CONFIG_ROOT@` 대신 "--config-root=$XDG_CONFIG_HOME/bingsu", 세 셸 각각).
@pytest.mark.parametrize("shell", SHELLS)
def test_prompt_time_path_environment_does_not_change_pinned_root_args(tmp_path, shell):
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, trusted))
    inst.use_fake(minimal_record())
    want = pinned_roots(trusted)
    repo = tmp_path / "repo"
    repo.mkdir()
    canary = short_dir() / "c"
    hostile = {k: f"{repo}/{k.lower()} dir $(touch {canary})" for k in HOSTILE_VARS}
    s = Session(shell, trusted)
    s.run(f"source {init}")
    before = len(inst.calls())
    s.run(export_line(shell, hostile))
    s.run("true")
    s.run("true")
    s.close()
    calls = inst.calls()
    assert len(calls) - before >= 2, f"{shell}: fewer than two prompts after the change"
    assert not canary.exists(), f"{shell}: a hostile value was executed"
    for argv in calls:
        assert not any(str(repo).encode() in a for a in argv), (shell, argv)
        for flag, word in want.items():
            assert [a for a in argv if a.startswith(flag)] == [word], (shell, flag, argv)


# strace's %network and %process calls other than the root's execve and its
# exit (exit_group): sockets, signals to other processes, spawning, waiting.
NETWORK_OR_PROCESS = {
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg",
    "sendmmsg", "recvfrom", "recvmsg", "recvmmsg", "shutdown", "getsockopt", "setsockopt",
    "getsockname", "getpeername", "clone", "clone3", "fork", "vfork", "execve", "execveat",
    "kill", "tkill", "tgkill", "wait4", "waitid", "pidfd_open", "pidfd_send_signal",
}
SPAWN_CALL = re.compile(r"^(\d+)\s+(?:clone3?|fork|vfork)\(")
RETURN = re.compile(r"\)\s+=\s+(\d+)$")
RESUMED_SPAWN = re.compile(r"^(\d+)\s+<\.\.\. (?:clone3?|fork|vfork) resumed>.*\)\s+=\s+(\d+)$")
SYSCALL = re.compile(r"^\d+\s+(\w+)\(")
# The calls the adapter makes itself: rows of crates/bingsu/prompt-syscalls.tsv
# with both a syscall and a libc name (core-cfg-check --adapter holds the
# `libc` column to the code; the seccomp filter allows the whole `syscall`
# column, which adds the allocator's and the kernel's calls).
TABLE = os.path.join(os.path.dirname(__file__), "..", "..", "crates", "bingsu", "prompt-syscalls.tsv")
_ROWS = [r.split("\t") for r in open(TABLE).read().splitlines() if r and not r.startswith("#")][1:]
ADAPTER_CALLS = {r[0] for r in _ROWS if r[0] != "-" and r[1] != "-"}
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def is_root(line, exe):
    """An execve whose pathname (its first quoted string) is the pinned exe;
    the same string inside argv does not count."""
    m = SYSCALL.match(line)
    q = QUOTED.search(line)
    return bool(m and m.group(1) == "execve" and q and q.group(1) == exe)


def tree(lines, exe):
    """The trace lines of the pinned binary. The root is the pid of the
    execve of `exe`; its lines count from that execve on. A child counts if
    a pid already counted made the clone, clone3, fork or vfork call after
    the root execve (the call line, finished or <unfinished ...>, decides;
    the return may come later). A child's lines count wherever they are in
    the trace: strace may write a child's first line before the parent's
    return line. Returns (pids, lines). Pid reuse inside one prompt is not
    tracked (environment assumption). One prompt is assumed: only the first
    execve of `exe` becomes the root; to read several calls from one trace,
    build a closure per root."""
    lines = [l for l in lines if l.strip()]
    start = next((i for i, l in enumerate(lines) if is_root(l, exe)), None)
    if start is None:
        return set(), []
    root = lines[start].split()[0]
    edges, pending = [], {}
    for i, l in enumerate(lines):
        m = SPAWN_CALL.match(l)
        if m:
            r = RETURN.search(l)
            if r:
                edges.append((m.group(1), r.group(1), i))
            else:
                pending[m.group(1)] = i
            continue
        m = RESUMED_SPAWN.match(l)
        if m and m.group(1) in pending:
            edges.append((m.group(1), m.group(2), pending.pop(m.group(1))))
    pids, grew = {root}, True
    while grew:
        grew = False
        for parent, child, at in edges:
            if at > start and parent in pids and child not in pids and int(child) > 0:
                pids.add(child)
                grew = True
    scoped = [l for i, l in enumerate(lines)
              if (l.split()[0] == root and i >= start) or (l.split()[0] in pids and l.split()[0] != root)]
    return pids, scoped


# 이것을 실패시키는 것: 순서를 잊고 execve 전의 edge(셸이 띄운 자식)나 root pid의 execve 전 줄(셸 몫)까지 bingsu에 붙이는 것,
# 부모의 반환 줄보다 먼저 찍힌 자식 줄을 빼는 것, argv에 exe 문자열이 든 다른 execve를 root로 보는 것.
def test_tree_follows_trace_order():
    trace = [
        '100 clone(child_stack=NULL, flags=CLONE_CHILD_SETTID|SIGCHLD) = 101',
        '101 openat(AT_FDCWD, "/repo/x", O_RDONLY) = 3',
        '100 openat(AT_FDCWD, "/shell/rc", O_RDONLY) = 3',
        '200 execve("/usr/bin/env", ["/usr/bin/env", "/pinned/bin/bingsu"], 0x1 /* 1 vars */) = 0',
        '100 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "prompt"], 0x1 /* 1 vars */) = 0',
        '100 clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0}, 88 <unfinished ...>',
        '102 openat(AT_FDCWD, "/early", O_RDONLY) = 3',
        '100 <... clone3 resumed>) = 102',
        '102 statx(AT_FDCWD, "/pinned/root/x", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = 0',
    ]
    pids, scoped = tree(trace, "/pinned/bin/bingsu")
    assert pids == {"100", "102"}
    assert not any('"/repo/x"' in l or '"/shell/rc"' in l for l in scoped)
    assert any('"/early"' in l for l in scoped)


# 이것을 실패시키는 것: => 주석이 든 clone3의 자식·스레드 또는 부모 반환 전 자식 기록을 prompt 범위에서 빼는 것.
@pytest.mark.parametrize("split", [False, True], ids=["whole", "split"])
def test_tree_follows_clone3_struct_updates(split):
    before = '10 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_PARENT_SETTID, exit_signal=SIGCHLD}'
    after = ' => {parent_tid=[11]}, 88) = 11'
    child = '11 openat(AT_FDCWD, "/early", O_RDONLY) = 3'
    spawn = ([before + ' <unfinished ...>', child, '10 <... clone3 resumed>' + after]
             if split else [before + after, child])
    lines = ['10 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "prompt"], []) = 0',
             *spawn,
             '11 clone3({flags=CLONE_VM|CLONE_FILES|CLONE_THREAD|CLONE_PARENT_SETTID, exit_signal=0}'
             ' => {parent_tid=[12]}, 88) = 12',
             '12 close(3</early>) = 0']
    pids, scoped = tree(lines, "/pinned/bin/bingsu")
    assert pids == {"10", "11", "12"}
    assert scoped == lines


def named_paths(line):
    """The paths a syscall line names: execve its pathname only (argv
    follows), any other call every quoted string (both paths of linkat,
    renameat2, symlinkat; a symlink's target text is checked too, which only
    rejects more). Resumed lines carry results, not arguments, and are skipped.
    A result buffer printed on the call line (the target of readlinkat, for
    one) is checked as a path too, which errs toward a false failure; when
    M3a reads links under the roots, narrow that syscall to its pathname
    (the first quoted string)."""
    m = SYSCALL.match(line)
    if not m:
        return []
    if m.group(1) == "write":
        return []  # traced for the syscall table; its quoted text is the record
    found = QUOTED.findall(line)
    return found[:1] if m.group(1) == "execve" else found


# What the dynamic loader and Rust's start-up name (glibc, observed in the
# three images on 2026-10-05): the loader cache and preload list, the
# libraries, and /proc/self/maps (main-thread stack guard). The static musl
# build names none of them.
SYSTEM_PATHS = re.compile(r"^/etc/ld\.so\.(cache|preload)$|^/(usr/)?lib(64)?/.+\.so(\.\d+)*$|^/proc/self/maps$")


DIRFD_CALL = re.compile(r'^(\d+)\s+(\w+)\((\d+|AT_FDCWD), "((?:[^"\\]|\\.)*)"')
OPENS = {"openat", "openat2", "open"}


def resolve_dirfds(lines):
    """Each line with the paths it names, a name relative to a descriptor
    resolved against the path that descriptor was opened with (Task R1: the
    runtime root walk opens "/" and then one name at a time with
    `openat(fd, name, O_NOFOLLOW)`). Descriptors are tracked per process
    from the `= N` of each open; a relative name under a descriptor this
    trace did not see opened stays relative and fails. Close/dup/fork fd
    lifetimes and unfinished/resumed calls are outside this small decoder's
    fixtures. The live gate uses assert_prompt_trace_budget with strace -y
    descriptor paths and the shared parser; test_prompt_trace_budget covers
    inherited/duplicated descriptors and unfinished/resumed calls."""
    fds = {}
    out = []
    for line in lines:
        paths = named_paths(line)
        m = DIRFD_CALL.match(line)
        # An empty name with AT_EMPTY_PATH is the descriptor itself (allowed below).
        if m and paths and paths[0] and m.group(3) != "AT_FDCWD" and not paths[0].startswith("/"):
            base = fds.get((m.group(1), m.group(3)))
            if base is not None:
                paths = [base.rstrip("/") + "/" + paths[0]] + paths[1:]
        r = RETURN.search(line)
        if m and m.group(2) in OPENS and r and paths:
            fds[(m.group(1), r.group(1))] = paths[0]
        out.append((line, paths))
    return out


def allowed(path, line, exe, roots, *, allow_walk=True):
    """Spec section 5 (front-end prompt opens no file of the current folder
    or repository) and X-06 (only the roots pinned by init). A relative path
    never passes. A folder above a pinned root passes only as a folder
    (`O_PATH|O_NOFOLLOW|O_DIRECTORY`): the runtime root walk checks each
    ancestor without opening its contents. Helper calls also check the syscall
    and single-component walk shape separately."""
    if path == "" and "AT_EMPTY_PATH" in line:
        return True  # fstat of an fd already open (glibc 2.35, 2.36): names no path
    if path == exe or SYSTEM_PATHS.match(path):
        return True
    if any(path == r or path.startswith(r + "/") for r in roots):
        return True
    above = path == "/" or any(r.startswith(path.rstrip("/") + "/") for r in roots)
    return (allow_walk and above
            and all(flag in line for flag in ("O_PATH", "O_NOFOLLOW", "O_DIRECTORY")))


# 이것을 실패시키는 것: 기술자 기준 상대 이름을 풀지 않는 것(걷기가 상대 경로로 거부됨), 모르는 기술자 기준 이름을
# 통과시키는 것, 뿌리 위 폴더를 폴더가 아닌 열기에도 허용하는 것, 기술자를 프로세스마다 따로 세지 않는 것,
# AT_EMPTY_PATH의 빈 이름을 기술자 아래의 새 이름으로 붙이는 것.
def test_dirfd_walk_resolves_and_stays_under_the_roots():
    roots = ["/run/user/1/bingsu"]
    lines = [
        '7 openat(AT_FDCWD, "/", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 3',
        '7 openat(3, "run", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 4',
        '7 openat(4, "user", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 5',
        '7 openat(5, "1", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 6',
        '7 openat(6, "bingsu", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 7',
        '7 openat(7, "snapshot", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 8',
    ]
    lines.append('7 newfstatat(8, "", {st_mode=S_IFREG|0600, st_size=64, ...}, AT_EMPTY_PATH) = 0')
    got = resolve_dirfds(lines)
    assert [p for _, p in got][-2] == ["/run/user/1/bingsu/snapshot"]
    assert [p for _, p in got][-1] == [""]
    assert all(allowed(p, l, "/x/bingsu", roots) for l, ps in got for p in ps)
    bad = [
        '7 openat(AT_FDCWD, "/run", O_RDONLY|O_CLOEXEC) = 9',  # a folder above, not as a folder
        '7 openat(4, "other", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 10',  # beside the root
        '7 openat(42, "x", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 11',  # an fd never seen opened
        '8 openat(7, "snapshot", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 12',  # fd 7 of another process
    ]
    for b in bad:
        (line, paths), = resolve_dirfds(lines + [b])[-1:]
        assert not all(allowed(p, line, "/x/bingsu", roots) for p in paths), b


# strace -y supplies kernel-resolved dirfd paths, including inherited/duplicated
# fds. Reuse the fsbudget parser for unfinished/resumed calls and quoted args.
SPAWNS = {"clone", "clone3", "fork", "vfork"}
# A positive allowlist for the entire helper/collector subtree, including libc
# startup, the watchdog and publication. Network is restricted to failed local
# nscd discovery below; no Internet socket, wait, arbitrary exec or signal.
# pipe2 is musl posix_spawn's exec-error channel (also used by the root).
HELPER_CALLS = set("""
execve clone clone3 exit exit_group arch_prctl set_tid_address set_robust_list
rseq brk mmap mprotect munmap mremap madvise futex sched_yield getrandom
rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack restart_syscall
read readv pread64 write writev pwrite64 close dup dup2 dup3 fcntl ioctl poll ppoll pipe2
lseek fstat newfstatat stat lstat statx statfs fstatfs getdents64
open openat openat2 access faccessat faccessat2 readlink readlinkat
mkdir mkdirat unlink unlinkat rename renameat renameat2 fchmod fchmodat
flock fsync fdatasync ftruncate getxattr lgetxattr fgetxattr
getuid geteuid getgid getegid getpid getrlimit setrlimit prlimit64
setsid umask chdir clock_gettime nanosleep clock_nanosleep prctl seccomp
socket connect
""".split()) | {
    "sched_getaffinity",  # Rust/glibc main and watchdog thread stack setup queries CPU affinity.
    "gettid",  # Rust/glibc stack setup identifies the main/watchdog thread.
}
ROOT_CALLS = {r[0] for r in _ROWS if r[0] != "-"} | set("""
execve clone clone3 vfork arch_prctl set_tid_address getrlimit prlimit64
read readv pread64 close fcntl poll ppoll ioctl pipe2 open openat openat2
access faccessat faccessat2 fstat newfstatat stat statx readlink readlinkat
getdents64 prctl getuid getpid fstatfs fgetxattr getxattr setitimer
""".split()) | {
    # Rust runtime start on glibc: the main-thread stack guard reads its own
    # attributes (pthread_getattr_np fills the CPU set) and thread id.
    # 이것을 실패시키는 것: 이 둘을 빼는 것(Debian glibc 컨테이너의 prompt 루트가 부른다).
    "sched_getaffinity",  # Rust/glibc main-thread stack setup queries CPU affinity.
    "gettid",  # Rust/glibc main-thread stack setup identifies the thread.
}
# Only pathname arguments, never read buffers, xattr names or readlink results.
# Each entry is (pathname argument, dirfd argument or None).
FILE_ARGS = {
    **{n: [(0, None)] for n in (
        "execve open access readlink stat lstat statfs mkdir unlink chdir getxattr lgetxattr"
    ).split()},
    **{n: [(1, 0)] for n in (
        "openat openat2 faccessat faccessat2 readlinkat newfstatat statx mkdirat unlinkat fchmodat"
    ).split()},
    "rename": [(0, None), (1, None)],
    "renameat": [(1, 0), (3, 2)],
    "renameat2": [(1, 0), (3, 2)],
}
NSS_PATHS = {"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"}
NSCD_PATHS = {"/var/run/nscd/socket", "/run/nscd/socket"}


def args_of(call):
    return scan(call.args)[0]


def call_paths(call):
    args = args_of(call)
    paths = []
    for index, dirfd in FILE_ARGS.get(call.name, []):
        quoted = QUOTED.fullmatch(args[index])
        assert quoted, ("unreadable or truncated pathname", call)
        path = quoted.group(1)
        # Reject escaped spellings conservatively; the fixture uses plain paths.
        assert "\\" not in path, ("escaped pathname", call)
        if path and not path.startswith("/") and dirfd is not None:
            base = re.fullmatch(r'\d+<(/[^<>]*)>', args[dirfd])
            if base:
                path = base.group(1).rstrip("/") + "/" + path
        if path.startswith("/"):
            path = os.path.normpath(path)
        paths.append(path)
    if call.name == "connect":
        paths.extend(QUOTED.findall(args[1]))
    return paths


def open_flags(text):
    """Open flags as strace prints them. O_LARGEFILE is dropped: strace adds it
    on x86_64 and not on aarch64, and it changes no access.
    이것을 실패시키는 것: O_LARGEFILE을 남기는 것(x86_64 CI의 helper 걷기 단계가 거부된다)."""
    return set(text.split("|")) - {"O_LARGEFILE"}


def helper_readonly_fd_metadata(call):
    # 실제 Linux trace의 같은 fd 조회 형태만 허용한다. statx의 반환 stx_mask와
    # 요청 마스크는 다르므로, 반환에 MNT_ID가 있어도 요청 권한을 넓히지 않는다.
    args = args_of(call)
    if call.name == "fstat":
        return len(args) == 2
    if call.name == "newfstatat":
        return len(args) == 4 and args[1] == '""' and args[3] == "AT_EMPTY_PATH"
    if call.name == "statx":
        return (len(args) == 5 and args[1] == '""'
                and set(args[2].split("|")) == {"AT_STATX_SYNC_AS_STAT", "AT_EMPTY_PATH"}
                and args[3] == "STATX_ALL")
    if call.name == "fcntl":
        return len(args) == 2 and args[1] == "F_GETFD"
    return False


def helper_global_input(call, path, files, held):
    # D1c: before sending a Git request, the trusted helper reads init-pinned
    # XDG git/config, HOME .gitconfig, then the selected excludes file. This
    # fixture has empty/missing configs, so only XDG git/ignore is selected;
    # no include, configured excludes target, or directory prefix is allowed.
    # User global sources intentionally follow symlinks (unlike repository
    # safe_read); git_global::read_bounded checks regular file, uid/root owner,
    # 64 KiB cap and same-fd stamps. This fixture has no links: a successful
    # open must resolve to the exact requested file, never another target.
    if path not in files:
        return False
    args = args_of(call)
    if call.name in {"open", "openat"}:
        if call.name == "openat":
            if args[0] not in {"AT_FDCWD", "AT_FDCWD</>"}:
                return False
            args = args[1:]
        return (len(args) == 2 and args[0] == f'"{path}"'
                and open_flags(args[1]) == {"O_RDONLY", "O_NONBLOCK", "O_NOCTTY", "O_CLOEXEC"}
                and (call.ret == "-1 ENOENT (No such file or directory)"
                     or re.fullmatch(r"\d+<" + re.escape(path) + r">", call.ret) is not None))
    if held.get(args[0]) != path:
        return False
    # git_global::read_bounded -> std OpenOptions::open -> musl open():
    # src/fcntl/open.c sets CLOEXEC again after a successful O_CLOEXEC open.
    # https://openwall.com/lists/musl/2025/11/25/3 (original open.c, lines 15-20)
    # Keep this out of helper_readonly_fd_metadata: the collector uses
    # sys::open_at -> libc::openat, whose musl wrapper has no such fcntl.
    # 이것을 실패시키는 것: musl 전역 입력 open을 거부하거나 CLOEXEC 해제·다른 fd 변경까지 허용하는 것.
    if call.name == "fcntl" and args[1:] == ["F_SETFD", "FD_CLOEXEC"]:
        return call.ret == "0"
    # Same-fd stamps and bounded reads, then close. These inputs are read
    # before the helper filter, so the general helper syscall list is not
    # sufficient: every other operation on their fds must fail here.
    if call.name == "close":
        return len(args) == 1
    if helper_readonly_fd_metadata(call):
        return True
    return (call.name == "read" and len(args) == 3 and args[2].isdecimal()
            and call.ret.isdecimal() and 0 <= int(call.ret) <= int(args[2]) <= 65_537)


def helper_walk_step(call, path, roots):
    # Runtime-root validation opens only pinned ancestors, one component at a time, without content access.
    if call.name != "openat" or not any(r.startswith(path.rstrip("/") + "/") for r in roots):
        return False
    args = args_of(call)
    name = QUOTED.fullmatch(args[1]).group(1)
    flags = open_flags(args[2])
    if not {"O_PATH", "O_NOFOLLOW", "O_DIRECTORY"} <= flags:
        return False
    if flags - {"O_RDONLY", "O_PATH", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"}:
        return False
    if name == "/":
        return path == "/" and args[0] in {"AT_FDCWD", "AT_FDCWD</>"}
    parent = re.fullmatch(r'\d+<(/[^<>]*)>', args[0])
    return (bool(parent) and name not in {"", ".", ".."} and "/" not in name
            and os.path.dirname(path) == parent.group(1))


def descriptor_child(call, path):
    """A single plain name relative to a kernel-annotated held parent."""
    args = args_of(call)
    name = QUOTED.fullmatch(args[1])
    parent = re.fullmatch(r'\d+<(/[^<>]*)>', args[0])
    return (bool(name and parent) and name.group(1) not in {"", ".", ".."}
            and "/" not in name.group(1)
            and path == parent.group(1).rstrip("/") + "/" + name.group(1))


def helper_mkdir_step(call, path, roots):
    # R1's shared creator and runtime publication/collector staging use only
    # mkdirat(held-parent, one-name, 0700). Config roots are never created.
    writable = roots[:1] + roots[2:]
    below = any(path == r or path.startswith(r + "/") for r in writable)
    # A fresh XDG_STATE_HOME can itself be missing above the state/log pin.
    state_parent = any(r.startswith(path + "/") for r in roots[2:])
    return (call.name == "mkdirat" and descriptor_child(call, path)
            and args_of(call)[2] == "0700" and (below or state_parent))


def helper_created_open(call, path, created):
    # fchmod needs a readable fd on Linux. Permit that ancestor open only
    # after this PID actually created the same directory; never read entries.
    if call.name != "openat" or (call.pid, path) not in created:
        return False
    flags = open_flags(args_of(call)[2])
    return (descriptor_child(call, path)
            and {"O_RDONLY", "O_NOFOLLOW", "O_DIRECTORY"} <= flags
            and not flags - {"O_RDONLY", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"})


def helper_chain_stat(call, path, roots):
    # Chain::revalidate checks held parent/name connections without following
    # links. Only one component under a held parent belongs to this allowance.
    if call.name != "newfstatat" or args_of(call)[3] != "AT_SYMLINK_NOFOLLOW":
        return False
    if not any(r.startswith(path.rstrip("/") + "/") for r in roots):
        return False
    return descriptor_child(call, path)


def helper_ancestor_stat(call, path, roots):
    # ConfigRootPin::check and config_load's absence observation/revalidation
    # inspect missing prefixes of pinned roots with symlink_metadata (lstat).
    # glibc/Rust can implement that with statx or newfstatat. This grants only
    # path-based, no-follow metadata: never an open or fd content operation.
    if call.name not in {"lstat", "newfstatat", "statx"}:
        return False  # plain stat follows links and has no no-follow flag
    if not any(r.startswith(path.rstrip("/") + "/") for r in roots):
        return False
    args = args_of(call)
    if call.name == "lstat":
        return args[0] == f'"{path}"'
    if args[0] not in {"AT_FDCWD", "AT_FDCWD</>"} or args[1] != f'"{path}"':
        return False
    if call.name == "newfstatat":
        return args[3] == "AT_SYMLINK_NOFOLLOW"
    flags = open_flags(args[2])
    return ("AT_SYMLINK_NOFOLLOW" in flags
            and not flags - {"AT_SYMLINK_NOFOLLOW", "AT_STATX_SYNC_AS_STAT"})


def helper_nss_root_stat(call, path):
    # glibc NSS stats "/" to detect a changed root before reloading nsswitch.conf; metadata only.
    # https://github.com/bminor/glibc/blob/release/2.36/master/nss/nss_database.c (root_ino/root_dev)
    return (call.name == "newfstatat" and path == "/" and args_of(call)[1] == '"/"'
            and args_of(call)[0] in {"AT_FDCWD", "AT_FDCWD</>"}
            and args_of(call)[3] == "0")


def content_paths(call):
    """Check -y fd names too: an inherited fd must not bypass the path gate.

    Ancestor metadata is allowed, but read/getdents/mmap of its contents is not.
    Buffers remain opaque; only the descriptor's kernel annotation is a path.
    """
    if call.name in {"read", "readv", "pread64", "write", "writev", "pwrite64", "getdents64"}:
        fd = args_of(call)[0]
    elif call.name == "mmap":
        fd = args_of(call)[4]
    else:
        return []
    match = re.fullmatch(r'\d+<(/[^<>]*)>', fd)
    return [os.path.normpath(match.group(1))] if match else []


def fixed_exec(call, exe, verb):
    args = args_of(call)
    words = QUOTED.findall(args[1])
    return (call.name == "execve" and args[0] == f'"{exe}"'
            and (words == [exe, verb] if verb in {"__collect-v1", "__collect-legacy-v1"} else words[:2] == [exe, verb])
            and (args[2] == "[]" or re.fullmatch(r'0x[0-9a-f]+ /\* 0 vars \*/', args[2]))
            and call.ret == "0")


def successful_spawns(calls):
    attempts = [c for c in calls if c.name in SPAWNS]
    good = [c for c in attempts if c.ret.isdecimal() and int(c.ret) > 0]
    # glibc tries clone3 once before falling back to clone on older kernels.
    fallback = [c for c in attempts if c not in good]
    assert len(fallback) <= len(good) and all(c.name == "clone3" and c.ret.startswith("-1 ENOSYS")
                                      for c in fallback), ("unexpected spawn attempt", fallback)
    return good


def prompt_sources(pinned):
    """Exact contexts-v2 address: canonical bytes, 60-byte chunks, no wildcard."""
    store = pinned[0] + "/contexts-v2"
    for label, path in zip(("config", "state"), pinned[1:3]):
        data = os.fsencode(path)
        store += "/" + label + "/" + "/".join(data[i:i + 60].hex() for i in range(0, len(data), 60))
    store += "/store"
    dirs = {"/"}
    part = store
    while part != "/":
        dirs.add(part)
        part = os.path.dirname(part)
    return dirs, {store + "/" + n for n in ("snapshot", "last-good", "marker")}



def prompt_collection_sources(pinned, cwd):
    if cwd is None or not 1 <= len(cwd) <= 65536 or not cwd.startswith(b"/") or b"\0" in cwd:
        return set(), set()
    _, snapshots = prompt_sources(pinned)
    context = os.path.dirname(next(iter(snapshots)))
    root = context + "/collections-v1"
    address = root + "/" + hashlib.sha256(cwd).hexdigest()
    store = address + "/store"
    return {root, address, store}, {store + "/response", store + "/previous"}


def prompt_cwd(call):
    words = [ast.literal_eval('b"' + word + '"') for word in QUOTED.findall(args_of(call)[1])]
    values = [words[i+1] for i in range(1, len(words)-1) if words[i] == b"--pwd"]
    return values[0] if len(values) == 1 else None

def prompt_open(call, path, pinned, root, cwd=None):
    if call.name != "openat":
        return False
    args = args_of(call)
    flags = open_flags(args[2])
    dirs, files = prompt_sources(pinned)
    collection_dirs, collection_files = prompt_collection_sources(pinned, cwd)
    dirs |= collection_dirs
    files |= collection_files
    process = f"/proc/{root}"
    kernel_dirs = {"/proc", process, process + "/ns", "/proc/sys", "/proc/sys/kernel", "/proc/sys/kernel/random"}
    kernel_files = {process + "/timens_offsets", "/proc/sys/kernel/random/boot_id"}
    if path == "/":
        shape = bool(re.fullmatch(r"AT_FDCWD(?:</[^<>]*>)?", args[0])) and args[1] == '"/"'
    else:
        shape = descriptor_child(call, path)
    if not shape:
        return False
    if path in dirs:
        return {"O_PATH", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"} <= flags and not flags - {
            "O_RDONLY", "O_PATH", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"}
    if path in kernel_dirs:
        return flags == {"O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"}
    if path in files:
        return flags == {"O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"}
    if path in kernel_files:
        return flags == {"O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC"}
    return False


def time_namespace_readlink(call, path, owner):
    # The procfs walk is checked by the adapters. Read only these two links,
    # relative to the current process's ns fd, with the parser's 27+1 bound.
    # No nsfs target open/stat permission is needed in an unprivileged userns.
    return (call.name == "readlinkat"
            and path in {f"/proc/{owner}/ns/time", f"/proc/{owner}/ns/time_for_children"}
            and descriptor_child(call, path)
            and args_of(call)[3] == "28")


def proc_self_readlink(call, path):
    # K82: one bounded kernel link lookup, relative to the verified proc fd.
    return (call.name == "readlinkat" and path == "/proc/self"
            and descriptor_child(call, path) and args_of(call)[3] == "11")


class HelperExecutableWalk:
    """Per-process executable chain, expanded only by earlier link results."""

    def __init__(self, exe):
        self.roots = {exe}
        self.links = set()
        self.held = {}
        self.regular = set()

    def parent_held(self, call, path):
        args = args_of(call)
        return (descriptor_child(call, path)
                and self.held.get(args[0]) == os.path.dirname(path))

    def readlink(self, call, path):
        # Build identity reads one link name under its held parent, bounded by
        # read_link_at's 4096+1 truncation detector; the output is evidence only.
        if (call.name != "readlinkat" or not self.parent_held(call, path)
                or not any(r == path or r.startswith(path + "/") for r in self.roots)):
            return False
        args = args_of(call)
        target = QUOTED.fullmatch(args[2])
        if (args[3] != "4097" or not target or "\\" in target.group(1)
                or not call.ret.isdecimal()
                or not 0 < int(call.ret) < 4097
                or len(os.fsencode(target.group(1))) != int(call.ret)):
            return False
        target = target.group(1)
        # Preserve the unresolved suffix when an ancestor itself is a link.
        # Keep prefixes traversed before '..' too: those are real walk steps.
        for root in tuple(self.roots):
            if root == path or root.startswith(path + "/"):
                expansion = os.path.join(os.path.dirname(path), target) + root[len(path):]
                parts = expansion.split("/")
                for i in range(1, len(parts) + 1):
                    self.roots.add(os.path.normpath("/".join(parts[:i]) or "/"))
        self.links.add(path)
        return True

    def file_op(self, call, path):
        # Only the verified last regular file may get a readable descriptor;
        # its flags prevent following links/blocking/devices. No content I/O.
        if call.name == "newfstatat":
            return (self.parent_held(call, path)
                    and args_of(call)[3] == "AT_SYMLINK_NOFOLLOW")
        if call.name == "openat":
            return (path not in self.links and path in self.regular
                    and self.parent_held(call, path)
                    and open_flags(args_of(call)[2]) == {
                        "O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"})
        return False

    def observe(self, call):
        args = args_of(call)
        paths = call_paths(call)
        if (call.name == "newfstatat" and paths and paths[0] in self.roots
                and self.file_op(call, paths[0])):
            self.regular.discard(paths[0])
            if call.ret == "0" and "st_mode=S_IFREG|" in args[2]:
                self.regular.add(paths[0])
        if call.name in OPENS:
            result = re.fullmatch(r"(\d+)<(/[^<>]*)>", call.ret)
            if result:
                fd, path = result.groups()
                # Any successful open reuses the fd, even outside this walk.
                self.held = {k: v for k, v in self.held.items() if not k.startswith(fd + "<")}
                if (paths == [path] and (helper_walk_step(call, path, self.roots)
                                        or path in self.roots and self.file_op(call, path))):
                    self.held[fd + "<" + path + ">"] = path
        if call.name == "close":
            self.held.pop(args[0], None)

    def fd_stat(self, call):
        # fstat and libc's empty-name equivalents inspect the successfully
        # opened target descriptor, never a pathname or an unobserved fd.
        args = args_of(call)
        if args[0] not in self.held:
            return False
        if call.name == "fstat":
            return True
        if call.name == "newfstatat":
            return args[1] == '""' and args[3] == "AT_EMPTY_PATH"
        if call.name == "statx":
            return (args[1] == '""' and "AT_EMPTY_PATH" in open_flags(args[2])
                    and not open_flags(args[2]) - {"AT_EMPTY_PATH", "AT_STATX_SYNC_AS_STAT"})
        return False


class HelperCollectorExecutable(HelperExecutableWalk):
    """The exact init pin, opened by PinnedCollector::verify before spawn."""

    def file_op(self, call, path):
        # collector.rs verifies the build/role with pread64 and rechecks the
        # held file and parent/name stamps before spawn. Unlike build identity
        # lookup for bingsu, this canonical pin never follows executable links.
        if call.name == "openat":
            return (self.parent_held(call, path) and len(args_of(call)) == 3
                    and open_flags(args_of(call)[2]) == {
                        "O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"}
                    and (call.ret.startswith("-1 ")
                         or re.fullmatch(r"\d+<" + re.escape(path) + r">", call.ret)))
        return (call.name == "newfstatat" and self.parent_held(call, path)
                and args_of(call)[3] == "AT_SYMLINK_NOFOLLOW")

    def fd_op(self, call):
        args = args_of(call)
        if args[0] not in self.held:
            return False
        if helper_readonly_fd_metadata(call):
            return True
        if call.name == "close":
            return len(args) == 1
        if call.name == "fstatfs":
            return len(args) == 2
        if call.name == "fgetxattr":
            return args[1:] == ['"system.posix_acl_access"', "NULL", "0"]
        return (call.name == "pread64" and len(args) == 4 and args[2].isdecimal()
                and call.ret.isdecimal()
                and 0 <= int(call.ret) <= int(args[2]) <= 65_536
                and args[3].isdecimal() and int(args[3]) < 64 * 1024 * 1024)


def prompt_root_io(front, boundary, exe, pinned, root, cwd=None):
    """Track the root's prepared fds. No path operation survives the filter.

    Real N3 and N4 captures cover helper publication and first-prompt fallback.
    Linux CI must also capture successful current/last-good and refused-file reads.
    """
    held = {}
    acl_fallback = set()
    fs_observed = set()
    _, files = prompt_sources(pinned)
    files |= prompt_collection_sources(pinned, cwd)[1]
    table = {r[0] for r in _ROWS if r[0] != "-"}
    for c in front:
        args = args_of(c)
        paths = call_paths(c)
        post = c.index > boundary
        if post:
            assert c.name in table and not c.ret.startswith("-1 EPERM"), ("post-filter syscall", c)
            assert not paths, ("post-filter path", c)
        if post:
            assert not any(re.fullmatch(r"/proc(?:/\d+(?:/ns)?|/sys(?:/kernel(?:/random)?)?)?", path)
                           for path, prepared in held.values() if prepared), ("root kernel walk held after filter", c)
        if c.name == "clock_gettime":
            assert args[0] == "CLOCK_BOOTTIME", ("root clock", c)
        for path in paths:
            if post:
                raise AssertionError(("post-filter path", c))
            bootstrap = path == "/proc/self/fd" and c.name in {"openat", "open"}
            acl = re.fullmatch(r"/proc/self/fd/(\d+)", path)
            acl_ok = (c.name == "getxattr" and acl and int(acl.group(1)) in acl_fallback
                      and args[1:] == ['"system.posix_acl_access"', "NULL", "0"])
            system = path == exe and c.name == "execve" or bool(SYSTEM_PATHS.fullmatch(path))
            empty_stat = path == "" and c.name in {"newfstatat", "statx"} and "AT_EMPTY_PATH" in c.args
            assert (system or bootstrap or acl_ok or empty_stat or prompt_open(c, path, pinned, root, cwd)
                    or time_namespace_readlink(c, path, root)
                    or proc_self_readlink(c, path)), ("root path", c, path)
        if c.name == "readlinkat":
            fd = int(args[0].split("<")[0])
            expected = "/proc" if paths == ["/proc/self"] else f"/proc/{root}/ns"
            assert (held.get(fd) == (expected, True)
                    and fd in fs_observed), ("root namespace walk", c)
        if c.name in OPENS and paths:
            result = re.match(r"(\d+)(?:<.*>)?$", c.ret)
            if result:
                fd = int(result.group(1))
                held[fd] = (paths[0], prompt_open(c, paths[0], pinned, root, cwd))
                acl_fallback.discard(fd)
                fs_observed.discard(fd)
        if c.name in {"fstatfs", "fgetxattr"}:
            fd = int(args[0].split("<")[0])
            assert not post and fd in held and held[fd][1], ("root fd facts", c)
            if c.name == "fstatfs":
                assert fd not in fs_observed, ("root duplicate fstatfs", c)
                fs_observed.add(fd)
            if c.name == "fgetxattr":
                assert args[1:] == ['"system.posix_acl_access"', "NULL", "0"], ("root ACL", c)
                if c.ret.startswith("-1 EBADF"):
                    acl_fallback.add(fd)
        if c.name == "read" and post:
            fd = int(args[0].split("<")[0])
            assert fd in held and held[fd][1] and held[fd][0] in files, ("root held read", c)
            assert 0 < int(args[2]) <= 16384, ("root read length", c)
        if not post:
            for path in content_paths(c):
                # Kernel -y annotations use this PID instead of /proc/self.
                path = re.sub(rf"^/proc/{root}(?=/|$)", "/proc/self", path)
                assert (SYSTEM_PATHS.fullmatch(path) or path == "/proc/self/fd" and c.name == "getdents64"
                        or path == "/proc/sys/kernel/random/boot_id" and c.name == "read"
                        or c.name == "write" and args[0].startswith("1<")), ("root pre-filter content", c)
        if c.name == "close":
            fd = int(args[0].split("<")[0])
            if post:
                assert fd in held and held[fd][1], ("root held close", c)
            held.pop(fd, None)
            acl_fallback.discard(fd)


def assert_prompt_trace_budget(lines, exe, pinned, *, global_inputs=(), collector_exe=None):
    from fsbudget.attribute import collector_attribute
    collector_exe = collector_exe or os.path.join(os.path.dirname(exe), "bingsu-collect")
    _, scoped = tree(lines, exe)
    # E4: a default screen in a Git repository starts at most one collector.
    # Attribution still validates its pinned identity, creation parent and effects.
    # 이것을 실패시키는 것: collector를 0개로 막거나 두 번째 collector를 허용하는 것.
    collectors = sum(is_root(line, collector_exe) for line in scoped)
    assert collectors <= 1, ("extra collector", collectors)
    roles = collector_attribute(scoped, {"front": exe, "helper": exe,
                                "collector": collector_exe, "collectors": collectors})
    assert not roles.errors, roles.errors
    _assert_prompt_trace_budget(lines, exe, pinned, collector_limit=1, global_inputs=global_inputs,
                                collector_exe=collector_exe, check_collection=True)


def assert_historical_prompt_trace_budget(lines, exe, pinned):
    """Archived captures retain the previous fixed-stub allowance."""
    _assert_prompt_trace_budget(lines, exe, pinned, collector_limit=1)


def _assert_prompt_trace_budget(lines, exe, pinned, collector_limit, global_inputs=(),
                                collector_exe=None, check_collection=False):
    pids, scoped = tree(lines, exe)
    assert pids, "bingsu was not executed"
    trace = parse_trace("\n".join(scoped))
    assert not trace.errors, trace.errors
    calls = [c for c in trace if c.name != EXIT_EVENT]
    root = int(scoped[0].split()[0])
    front = [c for c in calls if c.pid == root]
    helper = [c for c in calls if c.pid != root]
    assert all(c.name in ROOT_CALLS for c in front), [c for c in front if c.name not in ROOT_CALLS]
    timers = [c for c in front if c.name == "setitimer"]
    assert len(timers) <= 1, ("one entry timer", timers)
    for timer in timers:
        args = args_of(timer)
        assert args[0] == "ITIMER_REAL" and args[2] == "NULL", ("entry timer", timer)
        value = re.fullmatch(r"\{it_interval=\{tv_sec=0, tv_usec=1000\}, it_value=\{tv_sec=0, tv_usec=(\d+)\}\}", args[1])
        assert value and 0 < int(value[1]) <= 50_000 and timer.ret == "0", ("entry timer", timer)
    spawns = successful_spawns(front)
    # 이것을 실패시키는 것: prompt가 helper 외 스레드/프로세스를 만들거나 helper 생성을 생략하는 것.
    assert len(spawns) == 1, ("exactly one prompt spawn", spawns)
    spawn, = spawns
    for attempt in (c for c in front if c.name in SPAWNS):
        assert attempt.name in {"clone", "clone3", "vfork"} and "CLONE_THREAD" not in attempt.args
        if attempt.name != "vfork":
            assert "CLONE_VM" in attempt.args and "CLONE_VFORK" in attempt.args, attempt
    helper_pid = int(spawn.ret)
    filters = [c for c in front if c.name == "prctl" and "PR_SET_SECCOMP" in c.args]
    # 이것을 실패시키는 것: helper 생성이 prompt seccomp 설치 뒤로 옮겨지거나 필터 설치가 실패하는 것.
    assert len(filters) == 1 and filters[0].ret == "0", filters
    assert all(c.index < filters[0].index for c in front if c.name in SPAWNS), spawn
    assert all(c.index < filters[0].index for c in timers), ("post-filter timer", timers)
    execs = [c for c in helper if c.name in {"execve", "execveat"}]
    refresh = [c for c in execs if c.pid == helper_pid]
    # 이것을 실패시키는 것: 고정 exe/argv[1]/빈 환경 계약을 깨거나 helper를 재-exec하는 것.
    assert len(refresh) == 1 and fixed_exec(refresh[0], exe, "__refresh-v1"), refresh
    # With CLONE_VFORK, exec has released the parent, but strace can print
    # the child's execve *resumed* line after the parent's prctl. Compare
    # entry lines, not the parser's completion order, across these two PIDs.
    exec_entry = next(i for i, line in enumerate(scoped)
                      if line.split()[0] == str(helper_pid) and is_root(line, exe))
    filter_entry = next(i for i, line in enumerate(scoped)
                        if line.split()[0] == str(root) and "PR_SET_SECCOMP" in line)
    assert exec_entry < filter_entry, refresh
    # 이것을 실패시키는 것: root의 다른 exec, 네트워크·signal·wait 호출 또는 표 밖 write/exit를 허용하는 것.
    initial = front[0]
    assert initial.name == "execve" and QUOTED.findall(args_of(initial)[1])[1] == "prompt"
    stray = [c for c in front[1:] if c.name in NETWORK_OR_PROCESS - SPAWNS]
    assert not stray, ("root network or process calls", stray)
    seen = {c.name for c in front[1:] if c.name in NETWORK_OR_PROCESS | {"write", "exit", "exit_group"}} - SPAWNS
    assert seen == ADAPTER_CALLS, ("root syscall table", seen, ADAPTER_CALLS)
    cwd = prompt_cwd(initial)
    prompt_root_io(front, filters[0].index, exe, pinned, root, cwd)
    if check_collection and cwd is not None:
        assert_collection_trace(front, filters[0].index, pinned, cwd)
    # 이것을 실패시키는 것: helper 하위 트리에 새 syscall, 임의 자식/exec, 외부 네트워크를 더하는 것.
    assert all(c.name in HELPER_CALLS | {"kill"} for c in helper), [c for c in helper if c.name not in HELPER_CALLS | {"kill"}]
    # Exactly the pinned collector executable/verb, no additional argv and an
    # empty environment. Only archived captures use the old in-binary stub.
    collectors = [c for c in execs if c.pid != helper_pid]
    collector_path = collector_exe or exe
    collector_verb = "__collect-v1" if collector_exe else "__collect-legacy-v1"
    assert len(collectors) <= collector_limit and all(fixed_exec(c, collector_path, collector_verb) for c in collectors), collectors
    mains = {helper_pid} | {c.pid for c in collectors}
    owners = {pid: pid for pid in mains}
    children = []
    for pid in {c.pid for c in helper}:
        made = successful_spawns([c for c in helper if c.pid == pid])
        assert not made or pid in mains, ("worker spawned a child", made)
        threads = [c for c in made if "CLONE_THREAD" in c.args]
        processes = [c for c in made if c not in threads]
        assert len(threads) <= 1, ("extra watchdog", threads)
        owners.update({int(c.ret): pid for c in threads})
        assert len(processes) <= (collector_limit if pid == helper_pid else 0), processes
        assert all(int(c.ret) in {x.pid for x in collectors} for c in processes), processes
        children.extend(int(c.ret) for c in made)
    assert set(map(int, pids)) == {root, helper_pid, *children}, ("unbudgeted child", pids)
    created = set()
    global_held = {}
    exe_walks = {pid: HelperExecutableWalk(exe) for pid in owners}
    collector_walk = HelperCollectorExecutable(collector_exe) if collector_exe else None
    for c in helper:
        exe_walk = exe_walks[c.pid]
        collector_owner = collector_walk is not None and c.pid == helper_pid
        # 이것을 실패시키는 것: collector 고정 경로의 fd를 관찰 없이 읽거나 쓰기·변경에 쓰는 것.
        args = args_of(c)
        collector_fd = (collector_exe and args
                        and re.fullmatch(r"\d+<" + re.escape(collector_exe) + r">", args[0]))
        if collector_fd:
            assert collector_owner and collector_walk.fd_op(c), ("helper collector fd", c)
        # 이것을 실패시키는 것: content_paths에 없는 전역 입력 fd 변경·복제를 필터 설치 전에 허용하는 것.
        global_fd = re.fullmatch(r"\d+<(/[^<>]*)>", args[0]) if args else None
        if global_fd and global_fd.group(1) in global_inputs:
            path = global_fd.group(1)
            assert (c.pid == helper_pid
                    and helper_global_input(c, path, global_inputs, global_held)), ("helper global input fd", c)
        if c.name == "kill":
            # helper_limits::kill_self: strace can exhaust the helper's overall
            # deadline. Its watchdog kills its own TGID, never a reusable child
            # PID; helper_filter permits only this target and SIGKILL.
            # 이것을 실패시키는 것: helper 자기 종료를 막거나 다른 TGID·신호·collector의 kill을 허용하는 것.
            assert owners[c.pid] == helper_pid and args_of(c) == [str(helper_pid), "SIGKILL"], ("helper self kill", c)
        if c.name in {"mkdir", "mkdirat"}:
            paths = call_paths(c)
            assert len(paths) == 1 and helper_mkdir_step(c, paths[0], pinned), ("helper mkdir", c)
            if c.ret == "0":
                created.add((c.pid, paths[0]))
        if c.name == "socket":
            assert args_of(c)[0] == "AF_UNIX", ("non-NSS socket", c)
        if c.name == "connect":
            assert "AF_UNIX" in c.args and set(call_paths(c)) <= NSCD_PATHS, c
            assert c.ret.startswith(("-1 ENOENT", "-1 ECONNREFUSED")), ("unexpected NSS daemon", c)
        # 이것을 실패시키는 것: helper/collector가 pinned roots 밖의 repo·상대 경로·임의 시스템 파일에 접근하는 것.
        contents = content_paths(c)
        # Learning a link target grants walk/metadata access only, including
        # when a chain path overlaps an otherwise broadly allowed pathname.
        assert not any(r == path or r.startswith(path.rstrip("/") + "/")
                       for path in contents for r in exe_walk.roots), ("helper path", c, "executable content")
        paths = call_paths(c) + contents
        if c.name in {"fstat", "newfstatat", "statx"}:
            fd = args_of(c)[0]
            annotation = re.fullmatch(r"\d+<(/[^<>]*)>", fd)
            empty = c.name == "fstat" or args_of(c)[1] == '""'
            if empty and annotation and annotation.group(1) in exe_walk.roots:
                assert exe_walk.fd_stat(c), ("helper executable metadata", c)
        for path in paths:
            if c in collectors and path == collector_path:
                continue  # Exact pinned exec/argv/environment checked above; no other file access.
            if collector_exe and path == collector_exe:
                # 이것을 실패시키는 것: init 고정 collector 검증을 막거나 같은 디렉터리 전체를 허용하는 것.
                assert collector_owner and (
                    collector_walk.fd_op(c) if path in contents
                    else collector_walk.file_op(c, path)
                ), ("helper collector executable", c, path)
                continue
            if path in global_inputs:
                assert (c.pid == helper_pid
                        and helper_global_input(c, path, global_inputs, global_held)), ("helper global input", c, path)
                continue
            # Historical N3 captures still contain namespace opens. New link
            # reads get this exact budget, never the broad legacy proc allowance.
            if c.name in {"readlink", "readlinkat"}:
                assert (time_namespace_readlink(c, path, owners[c.pid])
                        or exe_walk.readlink(c, path)), ("helper namespace link", c)
                continue
            # -y resolves /proc/self dirfds to /proc/<tgid>. Only this
            # process's numeric spelling is equivalent, not another PID's.
            own_proc = f"/proc/{owners[c.pid]}"
            if path == own_proc or path.startswith(own_proc + "/"):
                path = "/proc/self" + path[len(own_proc):]
            system = (path in NSS_PATHS | NSCD_PATHS | {"/dev/null", "/proc/self", "/proc/sys/kernel/random/boot_id"}
                      or path.startswith("/proc/self/"))
            detached = c.name == "chdir" and path == "/"
            # The helper resolves the pinned executable hop by hop for its build
            # identity, so the executable joins the walk roots (ancestors only as
            # no-follow walk steps and metadata, never content).
            # 이것을 실패시키는 것: exe를 걷기 뿌리에서 빼는 것(컨테이너에서 bin 조상 stat이 거부된다).
            # Link targets learned earlier need the same no-follow ancestor
            # traversal and metadata checks to verify the executable binding.
            walk_roots = [*pinned, exe, *exe_walk.roots]
            if collector_owner:
                walk_roots.append(collector_exe)
            walk = helper_walk_step(c, path, walk_roots)
            nss_root = helper_nss_root_stat(c, path)
            creation = (c.name == "mkdirat" and helper_mkdir_step(c, path, pinned)
                        or helper_created_open(c, path, created))
            chain_stat = helper_chain_stat(c, path, walk_roots)
            ancestor_stat = helper_ancestor_stat(c, path, walk_roots)
            if c.name != "execve" and path in exe_walk.roots and path != "/" and not any(
                    r.startswith(path + "/") for r in exe_walk.roots):
                assert exe_walk.file_op(c, path), ("helper executable path", c, path)
                continue
            assert (system or detached or walk or nss_root or creation or chain_stat or ancestor_stat
                    or allowed(path, c.args, exe, pinned, allow_walk=False)), ("helper path", c, path)
        exe_walk.observe(c)
        if collector_owner:
            collector_walk.observe(c)
        if c.pid == helper_pid:
            if c.name in OPENS:
                opened = re.fullmatch(r"(\d+)<(/[^<>]*)>", c.ret)
                if opened:
                    fd, path = opened.groups()
                    global_held = {k: v for k, v in global_held.items() if not k.startswith(fd + "<")}
                    if helper_global_input(c, path, global_inputs, global_held):
                        global_held[c.ret] = path
            elif c.name == "close":
                global_held.pop(args_of(c)[0], None)


def assert_global_inputs_exercised(lines, exe, global_inputs, global_present):
    """Require coverage in this run, even if the helper's watchdog killed it.

    Called after the path gate: observing a name alone never authorizes access.
    Empty config files must still have a successful read (EOF is sufficient).
    """
    _, scoped = tree(lines, exe)
    calls = parse_trace("\n".join(scoped))
    assert not calls.errors, calls.errors
    # 이것을 실패시키는 것: watchdog 종료를 이유로 도달하지 않은 전역 입력 검사를 통과시키는 것.
    opens = [c for c in calls if c.name in OPENS and call_paths(c) in [[p] for p in global_inputs]]
    assert [call_paths(c)[0] for c in opens] == list(global_inputs), ("global input opens missing/order", opens)
    assert all((not c.ret.startswith("-1")) == global_present for c in opens), opens
    if global_present:
        assert {p for c in calls if c.name == "read" and c.ret.isdecimal()
                for p in content_paths(c) if p in global_inputs} == set(global_inputs), "global input reads missing"


# 이것을 실패시키는 것: prompt가 시스템 경로와 init이 박은 네 뿌리 밖의 경로를 건드리는 것 —
# 상대 경로("x", Path::exists 포함), 환경 변수가 가리키는 폴더(repo 아래), 현재 폴더, 그 접근을 스레드나 자식 프로세스에서 하는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("global_present", [False, True], ids=["global-missing", "global-present"])
def test_prompt_binary_names_only_allowed_system_paths_and_pinned_roots(tmp_path, global_present):
    """Every path argument of every traced call (open, stat, rename, link,
    ...) of the binary and its threads and children. SYSTEM_PATHS was
    observed on Debian and Ubuntu glibc (aarch64, the three test images) and
    takes the loader paths of Fedora (/lib64), Arch (/usr/lib) and Alpine
    (/lib/ld-musl-*.so.1) by its shape; the CI musl build on x86_64
    also spawns the fixed helper before its filter. NixOS and Guix
    (/nix/store, /gnu/store) are not covered and fail here."""
    assert shutil.which("strace"), "Linux path gate must execute strace"
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    trusted["HOME"] = str(tmp_path / "home-t")
    global_inputs = tuple(str(path) for path in (
        Path(trusted["XDG_CONFIG_HOME"]) / "git/config", Path(trusted["HOME"]) / ".gitconfig",
        Path(trusted["XDG_CONFIG_HOME"]) / "git/ignore",
    ))
    # Exact init-time locations, independent of the hostile prompt environment.
    # 이것을 실패시키는 것: 각 전역 입력을 같은 뿌리의 다른 파일로 바꾸거나 쓰기 플래그로 여는 것.
    if global_present:
        for path in global_inputs:
            source = Path(path)
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(".DS_Store\n" if source.name == "ignore" else "")
    script = inst.init("bash", trusted)
    collector_exe = init_collector_exe(script)
    repo = tmp_path / "repo"
    repo.mkdir()
    env = dict(trusted, **{k: str(repo / k.lower()) for k in HOSTILE_VARS})
    f = tmp_path / "s.bash"
    f.write_bytes(script + b"\n" + CALL)
    trace = tmp_path / "trace"
    # Trace all calls; call_paths selects pathname arguments, not quoted data buffers.
    r = subprocess.run(["strace", "-f", "-q", "-y", "-s", "65536", "-e", "trace=all", "-o", str(trace)]
                       + SHELL_CMD["bash"] + [str(f)], env=env, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    # execve names the pinned path (the symlink); its target never shows.
    exe = str(inst.exe)
    pinned = [os.path.realpath(trusted[k] + sub) for k, sub in
              (("XDG_RUNTIME_DIR", "/bingsu"), ("XDG_CONFIG_HOME", "/bingsu"),
               ("XDG_STATE_HOME", "/bingsu"), ("XDG_STATE_HOME", "/bingsu/log"))]
    lines = trace.read_text(errors="replace").splitlines()
    assert_prompt_trace_budget(lines, exe, pinned, global_inputs=global_inputs,
                               collector_exe=collector_exe)
    assert_global_inputs_exercised(lines, exe, global_inputs, global_present)


TABLE_SYSCALLS = {r[0] for r in _ROWS if r[0] != "-"}


# 이것을 실패시키는 것: 필터 뒤에 표에 없는 호출이 필요한 것(이 환경의 할당자·unwind가 부르는 호출을 표에서 빠뜨림),
# 정상 프롬프트에서 호출이 EPERM으로 거부되는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("pwd", ["/srv/p", "/" + "a/" * 32767])
def test_calls_after_the_filter_are_in_the_table(tmp_path, pwd):
    """Every call the prompt makes after its seccomp filter is installed
    (strace -e trace=all, from the PR_SET_SECCOMP line on) is a row of the
    table, and none is refused: the table is complete for this libc and
    allocator. LD_PRELOAD in the environment (an allocator under test) is
    passed through."""
    assert shutil.which("strace"), "Linux syscall gate must execute strace"
    exe = str(Install(tmp_path).exe)
    trace = tmp_path / "trace"
    args = [exe, "prompt", "--ctx", "1", "--record", "B1", "--width", "100", "--runtime-root=1:2:/r",
            "--shell", "bash", "--pwd", pwd, "--status", "1"]
    env = {"PATH": os.environ["PATH"], **({"LD_PRELOAD": os.environ["LD_PRELOAD"]} if "LD_PRELOAD" in os.environ else {})}
    r = subprocess.run(["strace", "-f", "-qq", "-e", "trace=all", "-o", str(trace)] + args,
                       env=env, capture_output=True, timeout=60)
    assert r.returncode == 0 and r.stdout.endswith(b"\x1e") and b"degraded:sandbox" not in r.stdout, r
    lines = trace.read_text(errors="replace").splitlines()
    at = next(i for i, l in enumerate(lines) if "PR_SET_SECCOMP" in l)
    after = [l for l in lines[at + 1:] if SYSCALL.match(l)]
    names = {SYSCALL.match(l).group(1) for l in after}
    assert names <= TABLE_SYSCALLS, sorted(names - TABLE_SYSCALLS)
    refused = [l for l in after if "= -1 EPERM" in l]
    assert refused == [], refused[:5]


def assert_collection_trace(calls, boundary, pinned, cwd, *, required=None):
    """Exact C3 increment, separate from existing runtime/context C-axis calls."""
    from fsbudget.formula import collection_front_expected
    dirs, files = prompt_collection_sources(pinned, cwd)
    assert dirs, "fixture needs a canonical cwd"
    root, address, store = sorted(dirs, key=len)
    expected = [root, address, store, store + "/response", store + "/previous"]
    _, snapshots = prompt_sources(pinned)
    if required is None:
        required = any(c.name == "openat" and call_paths(c) == [os.path.dirname(root) + "/snapshot"] for c in calls)
    opens, held, sizes, reads = [], {}, {}, {}
    valid_headers = {}
    counts = {name: 0 for name in ("openat", "fstat", "fstatfs", "fgetxattr", "getxattr", "read")}
    facts = {}
    stopped = False
    for c in calls:
        args = args_of(c)
        paths = call_paths(c)
        scoped = [p for p in paths if p == root or p.startswith(root + "/")]
        if c.name == "openat" and scoped:
            assert not stopped and len(opens) < 5, ("collection extra open", c)
            path = scoped[0]
            assert path == expected[len(opens)], ("collection address/order", c, expected)
            assert c.index < boundary, ("collection post-filter open", c)
            assert prompt_open(c, path, pinned, c.pid, cwd), ("collection flags/parent", c)
            if opens:
                parent = int(args[0].split("<")[0])
                assert held.get(parent) == os.path.dirname(path), ("collection parent fd", c)
                assert facts[parent] == {"fstat", "fstatfs", "fgetxattr", "getxattr"}, ("collection unverified parent", c)
            opens.append(c); counts["openat"] += 1
            result = re.match(r"(\d+)(?:<.*>)?$", c.ret)
            if result:
                fd = int(result.group(1)); held[fd] = path; facts[fd] = set()
            elif path in dirs:
                stopped = True
            continue
        if scoped:
            raise AssertionError(("collection unexpected path effect", c))
        if c.name == "getxattr":
            match = re.fullmatch(r'"/proc/self/fd/(\d+)"', args[0])
            fd = int(match.group(1)) if match else -1
        elif c.name in {"fstat", "newfstatat", "statx", "fstatfs", "fgetxattr", "read", "close"}:
            match = re.match(r"(\d+)(?:<.*>)?$", args[0])
            fd = int(match.group(1)) if match else -1
        else:
            continue
        if fd not in held:
            continue
        path = held[fd]
        if c.name == "close":
            held.pop(fd); facts.pop(fd)
            continue
        name = "fstat" if c.name in {"newfstatat", "statx"} else c.name
        if name == "read":
            assert c.index > boundary and path in files, ("collection read phase/fd", c)
            assert facts[fd] == {"fstat", "fstatfs", "fgetxattr"}, ("collection unverified file", c)
            previous = reads.setdefault(path, [])
            want = 64 if not previous else min(16384, sizes[path] - sum(previous))
            assert want > 0 and int(args[2]) == want and c.ret == str(want), ("collection bounded read", c, want)
            if not previous:
                header = ast.literal_eval("b" + args[1])
                assert len(header) == 64, ("collection header bytes", c)
                total = int.from_bytes(header[12:16], "little") + 64
                valid_headers[path] = (header[:8] == b"BNGRES03" and header[8:12] == bytes([3,0,64,0])
                                       and header[20:] == bytes(44) and total == sizes[path] and total <= 262144)
            else:
                assert valid_headers[path], ("collection body after invalid header", c)
            previous.append(want)
        else:
            assert c.index < boundary and name not in facts[fd], ("collection facts count/phase", c)
            if name == "fstat":
                if c.name in {"newfstatat", "statx"}:
                    assert args[1] == '""' and "AT_EMPTY_PATH" in c.args, ("collection fd metadata", c)
                size = re.search(r"st[x]?_size=(\d+)", c.args)
                assert size, ("collection file length observation", c)
                sizes[path] = int(size.group(1))
            if name in {"getxattr", "fgetxattr"}:
                assert args[1:] == ['"system.posix_acl_access"', "NULL", "0"], ("collection ACL arguments", c)
                if name == "getxattr":
                    assert path in dirs and "fgetxattr" in facts[fd], ("collection ACL fallback", c)
            facts[fd].add(name)
        counts[name] += 1
    if not opens:
        assert not required, "collection root open missing"
        return counts
    if opens[0].ret.startswith("-1 ENOENT"):
        assert counts == collection_front_expected(0, (), (), absent=True), counts
        return counts
    assert len(opens) <= 5
    # Full normal fixture: exact facts counts and exact immutable header/body reads.
    if len(opens) == 5 and all(not c.ret.startswith("-1") for c in opens):
        want = collection_front_expected(3, tuple(sizes[p] for p in expected[3:]), tuple(sizes[p]-64 for p in reads))
        # Only an invalid declaration may stop before its exact fstat length.
        want["read"] = sum(1 + ((sizes[p]-64+16383)//16384 if valid_headers[p] else 0) for p in reads)
        assert counts == want, ("collection syscall count", counts, want)
        for path, chunks in reads.items():
            assert (not valid_headers[path] and chunks == [64]) or sum(chunks) == sizes[path], ("collection incomplete read", path, chunks)
    return counts


def assert_collector_trace_budget(lines: list[str], pinned: dict, expected: dict) -> None:
    """M3b product role/kind gate; historical M3a fixtures keep their own gate."""
    from fsbudget.attribute import collector_attribute
    from fsbudget.gate import check
    measured = collector_attribute(lines, pinned)
    assert not measured.errors, measured.errors
    assert set(measured.counts) == set(expected), ("missing or extra role", measured.counts, expected)
    errors = check(measured.counts, expected, "exact", expected.keys())
    assert not errors, errors


# GATE-FS-HELPER.1: helper calls per publication stage of a release build.
HELPER_STAGES = {"unchanged": ("unchanged",), "publish": ("publish",),
                 "collect": ("unchanged", "collect"), "failure-last-good": ("failure-last-good",),
                 "failure-recover": ("failure-recover",)}
TEMPLATES = {"plain": "[style]\ntemplate='BASE {char}'\n", "edited": "[style]\ntemplate='EDIT {char}'\n",
             "collect": "[style]\ntemplate='BASE {dir} {git} {char}'\n", "broken": "[broken"}


def elf_facts(path):
    """(has .symtab, PT_INTERP) of a 64-bit little-endian ELF executable."""
    import struct
    data = Path(path).read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", ("64-bit little-endian ELF", path)
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
    interp = None
    for i in range(phnum):
        kind, _, offset, _, _, size = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if kind == 3:
            interp = data[offset:offset + size].rstrip(b"\0").decode()
    names_at = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 0x18)[0]
    sections = set()
    for i in range(shnum):
        name = struct.unpack_from("<I", data, shoff + i * shentsize)[0]
        sections.add(data[names_at + name:data.index(b"\0", names_at + name)].decode())
    return ".symtab" in sections, interp


def require_release_helper(exe):
    # Budget gates count a release build (followups 106): the release profile
    # strips symbols and a debug build keeps .symtab (and extra fd checks).
    # 이것을 실패시키는 것: debug 바이너리로 이 게이트를 돌리는 것(.symtab이 남아 있어 실패).
    symtab, interp = elf_facts(exe)
    assert not symtab, (f"{exe} keeps .symtab: helper call budgets are measured on the stripped release profile; "
                        "build with --release")
    # The product's musl builds are static (no PT_INTERP); its glibc builds are not.
    return "musl" if interp is None else "gnu"


def path_names(path):
    return len(Path(os.path.realpath(path)).parts) - 1


def nss_reads(libc, user_uid):
    """(nsswitch.conf, /etc/passwd) read calls of the helper's passwd lookup.

    glibc reads nsswitch.conf to EOF and /etc/passwd up to the user's line in
    st_blksize stdio buffers; musl reads only /etc/passwd, in its 1 KiB BUFSIZ
    buffer. An nscd socket would add a different exchange, so it must be absent.
    """
    for socket_path in ("/var/run/nscd/socket", "/run/nscd/socket"):
        assert not os.path.exists(socket_path), "an nscd socket changes the NSS calls; run without nscd"
    data = Path("/etc/passwd").read_bytes()
    at = next(m.end() for m in re.finditer(rb"(?m)^[^:\n]*:[^:\n]*:(\d+):.*$\n?", data)
              if int(m.group(1)) == user_uid)
    if libc == "musl":
        return 0, -(-at // 1024)
    nsswitch, passwd = os.stat("/etc/nsswitch.conf"), os.stat("/etc/passwd")
    return -(-nsswitch.st_size // nsswitch.st_blksize) + 1, -(-at // passwd.st_blksize)


def context_store(runtime, config, state):
    path = Path(runtime) / "bingsu" / "contexts-v2" / "config"
    for index, value in enumerate((os.fsencode(config), os.fsencode(state))):
        for i in range(0, len(value), 60):
            path /= value[i:i + 60].hex()
        if index == 0:
            path /= "state"
    return path / "store"


def helper_processes(base):
    """Running refresh helpers of this fixture (cmdline names its roots)."""
    found = []
    for entry in Path("/proc").iterdir():
        try:
            line = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if entry.name.isdigit() and b"__refresh-v1" in line and os.fsencode(str(base)) in line:
            found.append(entry.name)
    return found


def wait_helpers(base, timeout=15):
    import time
    end = time.monotonic() + timeout
    while helper_processes(base):
        assert time.monotonic() < end, ("refresh helper did not exit", helper_processes(base))
        time.sleep(0.05)


def warm_collection_previous(store, prompt, wait):
    """Reach the formula's two-publication state before starting any trace.

    CollectionStore::publish rotates only an existing response. Three warm-up
    prompts need not produce two responses (admission/deadline may defer one).
    Missing previous is normal; unsafe files and other IO errors are not.
    Allow at most three further untraced prompts, then fail preparation clearly.
    """
    import stat

    def size(name):
        info = (store / name).lstat()
        assert stat.S_ISREG(info.st_mode), ("non-regular collection slot", store / name)
        assert info.st_size >= 64, ("short collection slot", store / name)
        return info.st_size

    for attempt in range(4):
        response_bytes = size("response")  # also proves the parent still exists
        try:
            previous_bytes = size("previous")
        except FileNotFoundError:
            # Only an absent leaf is a preparation state. Recheck the parent
            # so removal of the store is not silently treated as first publish.
            assert stat.S_ISDIR(store.lstat().st_mode), ("collection store", store)
            if attempt == 3:
                raise AssertionError(f"warm-up did not rotate response into previous: {store}")
            prompt()
            wait()
        else:
            return {"response_bytes": response_bytes, "previous_bytes": previous_bytes}


class HelperStageFixture:
    """Real init, warm-up prompts and one traced prompt for a helper stage.

    The base lives next to the build output, not under /tmp: a group- or
    world-writable ancestor makes every trust walk add ACL and group queries
    the stage formula does not include, so the fixture refuses one.
    """

    def __init__(self, stage):
        import tempfile
        root = real_bin().parent.parent
        self.base = Path(tempfile.mkdtemp(prefix="helper-stage-", dir=root)).resolve()
        for ancestor in [self.base, *self.base.parents]:
            assert not os.stat(ancestor).st_mode & 0o022, ("group/other-writable ancestor", ancestor)
        self.stage = stage
        self.seq = 0
        self.inst = Install(self.base)
        self.env = trusted_env(self.base)
        self.env["HOME"] = str(self.base / "home-t")
        os.mkdir(self.env["HOME"], 0o700)
        self.config = Path(self.env["XDG_CONFIG_HOME"]) / "bingsu"
        self.config.mkdir(parents=True, mode=0o700)
        self.put("collect" if stage == "collect" else "plain")
        self.script = self.inst.init("bash", self.env)
        self.collector = init_collector_exe(self.script)
        wait_helpers(self.base)
        self.pwd = self.base
        if stage == "collect":
            self.pwd = self.base / "repo"
            self.pwd.mkdir()
            subprocess.run(["git", "init", "-q", str(self.pwd)], check=True, env={"PATH": os.environ["PATH"]})
            (self.pwd / "a").write_text("x")
        # The first prompts publish and, for collect, admit and store a response
        # untraced: under strace a cold admission can exceed its 20 ms budget.
        for _ in range(3 if stage == "collect" else 1):
            self.prompt()
            wait_helpers(self.base)
        self.store = context_store(self.env["XDG_RUNTIME_DIR"], os.path.realpath(self.config),
                                   os.path.realpath(Path(self.env["XDG_STATE_HOME"]) / "bingsu"))
        assert (self.store / "snapshot").is_file(), "warm-up did not publish"
        self.collection = {}
        if stage == "collect":
            stores = list((self.store / "collections-v1").glob("*/store"))
            runtime = Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"
            breakers = list((runtime / "collection-control-v1/sessions").glob("*/breaker"))
            assert len(stores) == len(breakers) == 1, ("one store and breaker after warm-up", stores, breakers)
            sizes = warm_collection_previous(stores[0], self.prompt, lambda: wait_helpers(self.base))
            self.collection = {"catalog_bytes": (runtime / ".collections.catalog").stat().st_size,
                               "breaker_bytes": breakers[0].stat().st_size,
                               **sizes,
                               "collector_components": path_names(Path(self.collector).parent),
                               "collector_bytes": Path(self.collector).stat().st_size}
        if stage == "publish":
            self.put("edited")
        elif stage == "failure-last-good":
            (self.store / "snapshot").unlink()
            self.put("broken")
        elif stage == "failure-recover":
            (self.store / "snapshot").chmod(0o644)

    def put(self, name):
        path = self.config / "config.toml"
        pending = path.with_name("config.toml.new")
        pending.write_text(TEMPLATES[name])
        pending.chmod(0o600)
        pending.replace(path)

    def prompt(self, trace=None):
        f = self.base / "prompt.bash"
        # Each run is a fresh bash: start its prompt counter after the last
        # run's, as one long-lived shell would, so the collection breaker
        # sees a new sequence instead of a replayed one.
        self.seq += 1
        f.write_bytes(self.script + b"\n_bingsu_seq=" + str(self.seq).encode() + b"\ncd '"
                      + os.fsencode(str(self.pwd)) + b"'\n" + CALL)
        strace = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-s", "4096",
                  "-e", "trace=all",
                  "-o", str(trace)] if trace else []
        r = subprocess.run(strace + SHELL_CMD["bash"] + [str(f)], env=self.env, capture_output=True, timeout=60)
        assert r.returncode == 0, r.stderr
        return r

    def plan(self, libc):
        import platform
        from fsbudget.formula import HelperAxes, HelperPlan, MAX_RW_COUNT
        nsswitch_reads, passwd_reads = nss_reads(libc, os.getuid())
        state = Path(self.env["XDG_STATE_HOME"]) / "bingsu"
        config_bytes = (self.config / "config.toml").stat().st_size
        snapshot = self.store / ("last-good" if self.stage == "failure-last-good" else "snapshot")
        context = 4 + -(-len(os.fsencode(os.path.realpath(self.config))) // 60) + -(-len(os.fsencode(os.path.realpath(state))) // 60)
        return HelperPlan(
            stages=HELPER_STAGES[self.stage],
            ax=HelperAxes(F=1, P=path_names(self.config), L=0, R=3, D=0, M=0, B=[config_bytes]),
            runtime_components=path_names(Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"),
            context_components=context,
            snapshot_bytes=snapshot.stat().st_size, marker_bytes=208, buf=MAX_RW_COUNT,
            state_components=path_names(state), exe_link_components=path_names(self.inst.dir),
            exe_components=path_names(real_bin().parent),
            nsswitch_reads=nsswitch_reads, passwd_reads=passwd_reads, libc=libc,
            arch=platform.machine(), **self.collection)


def collector_exit(lines, collector):
    """The traced collector's exit code. 75 is wire::DEADLINE_EXIT_CODE: the
    collector ran past its 50 ms request deadline and nothing was published."""
    pid = next(l.split()[0] for l in lines if is_root(l, collector))
    ends = [l for l in lines if l.split()[0] == pid and "+++ exited with" in l]
    assert len(ends) == 1, ("collector end", ends)
    return int(ends[0].split("exited with")[1].split()[0])


def measured_helper_attribution(lines, exe, collector, helper_vocabulary=True):
    """Helper-role counts of one traced prompt, in the helper vocabulary.

    Errors about the front or the helper (and parse or attribution errors)
    fail the gate; the collector's own calls are gated by the collector
    security rows, outside this formula.
    """
    from fsbudget.attribute import collector_attribute
    _, scoped = tree(lines, exe)
    collectors = sum(is_root(line, collector) for line in scoped)
    roles = collector_attribute(scoped, {"front": exe, "helper": exe, "collector": collector,
                                         "collectors": collectors}, helper_vocabulary=helper_vocabulary)
    errors = [e for e in roles.errors if "(collector):" not in e]
    assert not errors, errors
    return collectors, roles


def measured_helper_calls(lines, exe, collector, helper_vocabulary=True):
    collectors, roles = measured_helper_attribution(lines, exe, collector, helper_vocabulary)
    return collectors, roles.counts


def check_helper_capture(stage, lines, exe, collector, plan, *, evidence=None):
    from fsbudget.formula import helper_stage_expected, helper_collect_expected
    from fsbudget.gate import check, check_collect
    if evidence is None:
        evidence = {}
    status = collector_exit(lines, collector) if stage == "collect" else None
    evidence["collector_exit"] = status
    collectors, roles = measured_helper_attribution(lines, exe, collector)
    evidence["role_counts"] = roles.counts
    assert collectors == int(stage == "collect"), ("collector spawns", collectors)
    if stage != "collect":
        measured = {"helper": roles.counts.get("helper", {})}
        expected = {"helper": helper_stage_expected(plan)}
        evidence.update(phase_counts=measured, phase_expected=expected)
        errors = check(measured, expected, "exact", ["helper"])
        published = False
    else:
        assert status in (0, 75), ("unexpected collector exit", status)
        errors, published = check_collect(roles, helper_collect_expected(plan, deadline=status == 75),
                                          deadline=status == 75, evidence=evidence)
    evidence.update(published=published, errors=errors)
    assert not errors, errors
    return published


# 이것을 실패시키는 것: 도우미 재검증 경로에 같은 파일의 fstat 하나를 더하는 것, 수집 비용을 앞단으로 옮기는 것,
# 공식에 옛 고정 항(e["read"] += 2)을 되살리는 것, debug 바이너리로 재는 것, helper 어휘에서 fd statx나
# chdir를 지우는 것, 제품이 chdir·mkdirat·fchmod·lseek·dup 호출을 하나 더 내는 것,
# 마감 회차의 호출을 버리거나 최대 6회에서 실제 응답 발행이 한 번도 없는 것.
@pytest.fixture
def helper_stage_evidence(tmp_path_factory):
    # A dedicated upload root, separate from all other pytest fixtures.
    return tmp_path_factory.getbasetemp() / "helper-stage-evidence"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("stage", list(HELPER_STAGES))
def test_live_helper_calls_match_stage_formula(stage, helper_stage_evidence):
    """GATE-FS-HELPER.1: exact stages; collect prefix exact and tail <=.

    Every attempt is checked before retrying, including exit 75. At least one
    of at most six fresh collect fixtures must actually rename a response.
    """
    assert shutil.which("strace"), "the helper stage gate must execute strace"
    libc = require_release_helper(real_bin())
    import json
    # Traces live outside the product fixture: cleanup must never erase a
    # failed attempt or earlier deadline attempts. --basetemp locates these
    # artifacts for the controller; each invocation needs its own basetemp.
    for attempt in range(1, (6 if stage == "collect" else 1) + 1):
        artifacts = helper_stage_evidence / stage / f"attempt-{attempt}"
        artifacts.mkdir(parents=True)
        trace = artifacts / "trace.strace"
        evidence = {"stage": stage, "attempt": attempt, "collector_exit": None,
                    "published": None, "phase_counts": None, "phase_expected": None,
                    "trace": str(trace)}
        fixture = None
        try:
            fixture = HelperStageFixture(stage)
            result = fixture.prompt(trace)
            evidence["prompt_exit"] = result.returncode
            (artifacts / "stdout").write_bytes(result.stdout)
            (artifacts / "stderr").write_bytes(result.stderr)
            lines = trace.read_text(errors="replace").splitlines()
            published = check_helper_capture(stage, lines, str(fixture.inst.exe), fixture.collector,
                                             fixture.plan(libc), evidence=evidence)
            if stage != "collect" or published:
                return
        except BaseException as error:
            evidence["failure"] = str(error)
            raise
        finally:
            (artifacts / "attempt.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
            print(f"helper stage evidence: {artifacts}")
            if fixture is not None:
                wait_helpers(fixture.base)
                shutil.rmtree(fixture.base, ignore_errors=True)
    pytest.fail(f"collect: zero publishes across all 6 checked attempts; evidence: {helper_stage_evidence / stage}")


# Fixture metadata, pinned independently from the product source.
FRONT_CHUNK = 16 * 1024
FRONT_CASES = ('normal', 'checksum-last-good', 'body-limit', 'header-only')


# 이것을 실패시키는 것: 제품 READ_CHUNK를 바꾸고 fixture 메타데이터는 그대로 두는 것.
def test_front_chunk_matches_product_constant():
    source = (ROOT / 'crates/bingsu-core/src/snapshot.rs').read_text().replace('\r\n', '\n')
    match = re.search(r'pub const READ_CHUNK: usize = (\d+) \* (\d+);', source)
    assert match and int(match[1]) * int(match[2]) == FRONT_CHUNK


def front_attempt_plan(case, body):
    from fsbudget.formula import FrontAttempt
    current = FrontAttempt('current', True, case not in ('header-only', 'body-limit'),
                           body if case in ('normal', 'checksum-last-good') else 0,
                           case in ('normal', 'checksum-last-good'))
    return [current] + ([] if case == 'normal' else [FrontAttempt('last_good', True, True, body, True)])


def assert_front_reads(trace, store, attempts, *, evidence=None):
    from fsbudget.formula import front_read_bytes
    paths = [str(store / name) for name in ('snapshot', 'last-good', 'marker')]
    boot = '/proc/sys/kernel/random/boot_id'
    expected = {path: [] for path in paths}
    for a in attempts:
        path = paths[0 if a.copy == 'current' else 1]
        expected[path] = ([64] if a.header_read else []) + ([128] if a.prefix_read else [])
        expected[path] += [min(FRONT_CHUNK, a.body_bytes_read - offset)
                           for offset in range(0, a.body_bytes_read, FRONT_CHUNK)]
    expected[paths[2]] = [208]
    expected[boot] = [37, 0]  # in-place procfs boot observation: final EOF required
    actual = {path: [] for path in expected}
    for call in trace:
        args = args_of(call)
        if call.name == 'read' and args:
            match = re.fullmatch(r'\d+<(/[^<>]*)>', args[0])
            if match and match[1] in actual:
                actual[match[1]].append(int(call.ret))
    measured = front_read_bytes(trace, list(expected))
    if evidence is not None:
        evidence.update(read_chunks=actual, expected_chunks=expected, read_bytes=measured)
    # 이것을 실패시키는 것: TrustMetadata까지 읽게 길이 계산 변경, last-good 선택 뒤 현재 사본 재읽기.
    assert actual == expected, ('front read sequence', actual, expected)
    # 이것을 실패시키는 것: 사본별 바이트를 합산해 초과 읽기를 다른 사본의 여유로 상쇄하는 것.
    assert measured == {path: sum(chunks) for path, chunks in expected.items()}


def front_fact_kind(call):
    """Count each libc's held-fd primitive; pathname stats cannot substitute."""
    args = args_of(call)
    # 이것을 실패시키는 것: 플랫폼 fd stat 변형을 ignore하거나 pathname stat으로 대체하는 것.
    if call.name == 'fstat':
        return 'fstat'
    if call.name == 'newfstatat' and args[1] == '""' and args[3] == 'AT_EMPTY_PATH':
        return 'fstat'
    if (call.name == 'statx' and args[1] == '""'
            and args[2] == 'AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH' and args[3] == 'STATX_BASIC_STATS'):
        return 'fstat'
    raise AssertionError(('unexpected front facts primitive', call))


def check_front_capture(lines, exe, pinned, store, attempts, *, evidence):
    from collections import Counter
    from fsbudget.strace_parse import Trace
    from fsbudget.formula import front_attempts_expected, collection_front_expected
    _, scoped = tree(lines, exe)
    root = int(next(line.split()[0] for line in scoped if is_root(line, exe)))
    parsed = parse_trace('\n'.join(scoped))
    # 이것을 실패시키는 것: 불완전 캡처 또는 필터 없이 앞단 계수를 통과시키는 것.
    assert not parsed.errors, parsed.errors
    front = Trace()
    front.extend(c for c in parsed if c.pid == root and c.name != EXIT_EVENT)
    # 이것을 실패시키는 것: trace=all에 새 syscall을 남겨도 계수 대상이 아니라며 버리는 것.
    assert all(c.name in ROOT_CALLS for c in front), [c for c in front if c.name not in ROOT_CALLS]
    # 이것을 실패시키는 것: snapshot을 mmap하여 TrustMetadata 읽기를 read 계수 밖으로 옮기는 것.
    for call in front:
        if call.name != 'read':
            assert not set(content_paths(call)) & {str(store / n) for n in ('snapshot', 'last-good', 'marker')}, ('front content primitive', call)
    filters = [c.index for c in front if c.name == 'prctl' and 'PR_SET_SECCOMP' in c.args and c.ret == '0']
    assert len(filters) == 1, filters
    cwd = prompt_cwd(next(c for c in front if c.name == 'execve'))
    prompt_root_io(front, filters[0], exe, pinned, root, cwd)
    dirs, files = prompt_sources(pinned)
    collection_dirs, _ = prompt_collection_sources(pinned, cwd)
    boot_paths = {'/', '/proc', f'/proc/{root}', f'/proc/{root}/ns',
                  f'/proc/{root}/timens_offsets', '/proc/sys', '/proc/sys/kernel',
                  '/proc/sys/kernel/random', '/proc/sys/kernel/random/boot_id'}
    held, counts, primitives = {}, Counter(), Counter()
    for c in front:
        args = args_of(c)
        paths = call_paths(c)
        if c.name in OPENS and paths and paths[0] in dirs | files | boot_paths | collection_dirs:
            counts['openat'] += 1
            if not c.ret.startswith('-1'):
                held[int(c.ret.split('<')[0])] = paths[0]
            continue
        if c.name == 'getxattr':
            match = re.fullmatch(r'"/proc/self/fd/(\d+)"', args[0])
        else:
            match = re.fullmatch(r'(\d+)(?:<[^<>]*>)?', args[0]) if args else None
        fd = int(match[1]) if match else None
        if fd not in held:
            continue
        if c.name == 'close':
            held.pop(fd)
        elif c.name in ('fstat', 'newfstatat', 'statx'):
            counts[front_fact_kind(c)] += 1
            primitives[c.name] += 1
        elif c.name in ('fstatfs', 'fgetxattr', 'getxattr', 'readlinkat', 'read'):
            counts[c.name] += 1
    expected = Counter(front_attempts_expected(len(dirs), attempts, FRONT_CHUNK))
    # Plain config has no collection store: prefetch still probes its namespace.
    expected.update(collection_front_expected(0, (), (), absent=True))
    evidence.update(C=len(dirs), counts=counts, expected=expected, fact_primitives=primitives)
    # 이것을 실패시키는 것: 앞단 open/facts/read 하나 추가, collection prefetch를 비용에서 빼는 것.
    assert counts == expected, ('front axis C', counts, expected)
    assert_front_reads(front, store, attempts, evidence=evidence)


@pytest.fixture
def front_capture(request, tmp_path_factory):
    """Use A2's init/warm-up/trace harness; hold its publication lock while corrupting."""
    import fcntl
    import json
    from dataclasses import asdict
    require_release_helper(real_bin())
    assert shutil.which('strace'), 'front gate must execute strace'
    case = getattr(request, 'param', 'normal')
    artifacts = tmp_path_factory.getbasetemp() / 'front-evidence' / request.node.name
    artifacts.mkdir(parents=True)
    evidence = {'case': case, 'chunk': FRONT_CHUNK}
    fixture = None
    lock = None
    try:
        fixture = HelperStageFixture('unchanged')
        lock = (fixture.store / 'snapshot.lock').open('rb')
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = bytearray((fixture.store / 'snapshot').read_bytes())
        body = int.from_bytes(data[76:80], 'little')
        metadata = int.from_bytes(data[80:84], 'little')
        # 이것을 실패시키는 것: metadata 없는 fixture로 TrustMetadata 0 읽기를 공허하게 증명하는 것.
        assert metadata > 0 and len(data) == 64 + 128 + body + metadata
        last = fixture.store / 'last-good'
        last.write_bytes(data)
        last.chmod(0o600)
        if case == 'checksum-last-good':
            data[160] ^= 1
        elif case == 'body-limit':
            limit = 16 * 1024 * 1024 + 1
            data[60:64] = (128 + limit).to_bytes(4, 'little')
            data[76:80] = limit.to_bytes(4, 'little')
            data = data[:192 + body] + bytearray(limit - body) + data[192 + body:]
        elif case == 'header-only':
            data[0] ^= 1
        (fixture.store / 'snapshot').write_bytes(data)
        attempts = front_attempt_plan(case, body)
        evidence.update(attempts=[asdict(a) for a in attempts], body=body, metadata=metadata)
        trace = artifacts / 'trace.strace'
        result = fixture.prompt(trace)
        (artifacts / 'stdout').write_bytes(result.stdout)
        (artifacts / 'stderr').write_bytes(result.stderr)
        pinned = [os.path.realpath(Path(fixture.env[key]) / 'bingsu')
                  for key in ('XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME')]
        yield trace.read_text().splitlines(), str(fixture.inst.exe), pinned, fixture.store, attempts, evidence
    except BaseException as error:
        evidence['failure'] = str(error)
        raise
    finally:
        (artifacts / 'attempt.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if lock is not None:
            lock.close()
        if fixture is not None:
            wait_helpers(fixture.base)
            shutil.rmtree(fixture.base, ignore_errors=True)


# 이것을 실패시키는 것: TrustMetadata 길이 추가, last-good 뒤 현재 사본 재읽기, 사본별 머리/prefix 읽기 생략.
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux strace runtime gate')
@pytest.mark.parametrize('front_capture', FRONT_CASES, indirect=True)
def test_live_front_attempts_match_axis_c(front_capture):
    lines, exe, pinned, store, attempts, evidence = front_capture
    check_front_capture(lines, exe, pinned, store, attempts, evidence=evidence)


# 이것을 실패시키는 것: FrontDecoder의 end에 TrustMetadata 길이를 더하는 것.
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux strace runtime gate')
def test_front_never_reads_trust_metadata_section(front_capture):
    lines, exe, pinned, store, attempts, evidence = front_capture
    check_front_capture(lines, exe, pinned, store, attempts, evidence=evidence)
