"""F-01 / X-06: at prompt time HOME, USER, XDG_* and BINGSU_LOG point into a
repository; the hook must still pass only the roots pinned by init, and the
binary (with every process and thread it starts) must touch nothing under
the repository."""
import os
import platform
import ast
import hashlib
import json
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path
import zlib

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
# nscd discovery below; no Internet socket, arbitrary exec or signal, and wait
# only as pidfd supervision of the audited collector (_assert_prompt_trace_budget).
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
    return {root, address, store}, {store + "/response", store + "/previous", store + "/command"}


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


# The stored-response envelope a live capture may read: the current one only. A
# recorded fixture (an older build's observation) names its own envelope in
# tests/shell/fixtures/recorded-envelopes.tsv, and only portable tests pass it.
RESPONSE_HEADERS = (b"BNGRES05\x05\x00",)
# The command response the prompt prefetches beside them (C4b), and its cap.
COMMAND_HEADER = b"BNGCMD01\x01\x00"
COMMAND_RESPONSE_MAX = 471_082


def assert_prompt_trace_budget(lines, exe, pinned, *, global_inputs=(), collector_exe=None,
                               collectors=None, repository_roots=None, repository_evidence=(), platform=None,
                               front_deadline=False, headers=RESPONSE_HEADERS):
    """`collectors` is the exact count a live capture arranged; stored traces
    leave it None and may hold at most one. With `repository_roots`, a
    collector's calls after its request are audited by assert_repository_trace
    in shipped mode against exactly those roots (the bootstrap stays with
    collector_attribute). `repository_evidence` names files the collector must
    read (non-empty) inside that window. `platform`, an (arch, libc) pair,
    admits that platform's exact libc start-up primitives (STARTUP_PRIMITIVES,
    musl's O_CLOEXEC fcntl); stored traces leave it None. `front_deadline`
    judges a front that SIGALRM ended before its filter (deadline_shape):
    no filter and no record, every front call held to the pre-filter rules."""
    from fsbudget.attribute import assert_repository_trace, collector_attribute
    collector_exe = collector_exe or os.path.join(os.path.dirname(exe), "bingsu-collect")
    _, scoped = tree(lines, exe)
    # E4: a default screen in a Git repository starts at most one collector.
    # Attribution still validates its pinned identity, creation parent and effects.
    # 이것을 실패시키는 것: 시험이 정한 collector 수(0 또는 1)와 다른 수를 허용하는 것, 두 번째 collector를 허용하는 것.
    roots = [line.split()[0] for line in scoped if is_root(line, collector_exe)]
    if collectors is not None:
        assert len(roots) == collectors, ("collector count", len(roots), collectors)
    assert len(roots) <= 1, ("extra collector", len(roots))
    window = bool(roots) and repository_roots is not None
    roles = collector_attribute(scoped, {"front": exe, "helper": exe,
                                "collector": collector_exe, "collectors": len(roots), "platform": platform},
                                repository_window=window)
    assert not roles.errors, roles.errors
    if window:
        # 이것을 실패시키는 것: collector가 요청 뒤 roots 밖·조상 내용·쓰기를 여는 것(이 감사를 건너뛰는 것 포함).
        assert_repository_trace([line for line in scoped if line.split()[0] == roots[0]],
                                {"mode": "shipped", "roots": list(repository_roots),
                                 "evidence": list(repository_evidence), "libc": platform and platform[1]}, {})
    _assert_prompt_trace_budget(lines, exe, pinned, collector_limit=1, global_inputs=global_inputs,
                                collector_exe=collector_exe, check_collection=True,
                                audited_collector=int(roots[0]) if window else None, platform=platform,
                                front_deadline=front_deadline, headers=headers)


def assert_historical_prompt_trace_budget(lines, exe, pinned):
    """Archived captures retain the previous fixed-stub allowance."""
    _assert_prompt_trace_budget(lines, exe, pinned, collector_limit=1)


def _assert_prompt_trace_budget(lines, exe, pinned, collector_limit, global_inputs=(),
                                collector_exe=None, check_collection=False, audited_collector=None, platform=None,
                                front_deadline=False, headers=RESPONSE_HEADERS):
    pids, scoped = tree(lines, exe)
    assert pids, "bingsu was not executed"
    trace = parse_trace("\n".join(scoped))
    assert not trace.errors, trace.errors
    calls = [c for c in trace if c.name != EXIT_EVENT]
    supervision = []
    if audited_collector is not None:
        # A collecting collector is audited by collector_attribute (bootstrap)
        # and assert_repository_trace (after its request), not by this helper
        # table; its exec stays here for the pinned identity checks below.
        # The helper's supervision of that one child is exact: pidfd_open of
        # its pid, then waitid and SIGKILL on that pidfd only.
        # 이것을 실패시키는 것: collector exec까지 빼는 것, 다른 pid·fd·신호의 감독 호출을 허용하는 것.
        calls = [c for c in calls if c.pid != audited_collector or c.name in {"execve", "execveat"}]
        opened = [c for c in calls if c.name == "pidfd_open" and args_of(c) == [str(audited_collector), "0"]
                  and re.fullmatch(r"\d+<anon_inode:\[pidfd\]>", c.ret)]
        assert len(opened) == 1, ("collector pidfd", opened)
        pidfd = opened[0].ret
        supervision = opened + [c for c in calls if c.pid != audited_collector and (
            c.name == "waitid" and args_of(c)[:2] == ["P_PIDFD", pidfd] and args_of(c)[3:] == ["WNOHANG|WEXITED", "NULL"]
            or c.name == "pidfd_send_signal" and args_of(c) == [pidfd, "SIGKILL", "NULL", "0"])]
        calls = [c for c in calls if c not in supervision]
    root = int(scoped[0].split()[0])
    front = [c for c in calls if c.pid == root]
    helper = [c for c in calls if c.pid != root]
    # The front's own x86_64 glibc stack-guard seeks: the collector's rule
    # (fsbudget.attribute.stack_guard_seek), for the platform the caller
    # measured only, and the whole sequence or none.
    # 이것을 실패시키는 것: 다른 플랫폼·다른 fd의 앞단 lseek, 짝 없는 seek을 받는 것.
    # Only before the front's filter (glibc start-up); they stay in every
    # other check, including the I/O rules, and are left out only of the
    # root-call table.
    # 이것을 실패시키는 것: 필터 뒤의 seek 쌍을 받는 것, 받은 seek을 I/O 검사에서 지우는 것.
    from fsbudget.attribute import stack_guard_allowance, stack_guard_seek
    sealed = next((c.index for c in front if c.name == "prctl" and "PR_SET_SECCOMP" in c.args), float("inf"))
    allowance, guard = stack_guard_allowance(platform), []
    for c in front:
        if c.index < sealed and len(guard) < allowance and stack_guard_seek(c, root, len(guard)):
            guard.append(c)
    assert len(guard) in (0, allowance), ("incomplete front stack-guard seeks", guard)
    assert all(c.name in ROOT_CALLS for c in front if c not in guard), [c for c in front if c.name not in ROOT_CALLS and c not in guard]
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
    if front_deadline and not filters:
        # The front ended before its filter (deadline_shape requires that),
        # so every call is held to the pre-filter rules. A front that
        # installed its filter keeps it as the boundary.
        # 이것을 실패시키는 것: 필터를 설치한 앞단의 필터 뒤 호출을 필터 전 규칙으로 보는 것.
        boundary = front[-1].index + 1
    else:
        assert len(filters) == 1 and filters[0].ret == "0", filters
        boundary = filters[0].index
    assert all(c.index < boundary for c in front if c.name in SPAWNS), spawn
    assert all(c.index < boundary for c in timers), ("post-filter timer", timers)
    execs = [c for c in helper if c.name in {"execve", "execveat"}]
    refresh = [c for c in execs if c.pid == helper_pid]
    # 이것을 실패시키는 것: 고정 exe/argv[1]/빈 환경 계약을 깨거나 helper를 재-exec하는 것.
    assert len(refresh) == 1 and fixed_exec(refresh[0], exe, "__refresh-v1"), refresh
    # With CLONE_VFORK, exec has released the parent, but strace can print
    # the child's execve *resumed* line after the parent's prctl. Compare
    # entry lines, not the parser's completion order, across these two PIDs.
    exec_entry = next(i for i, line in enumerate(scoped)
                      if line.split()[0] == str(helper_pid) and is_root(line, exe))
    filter_entry = next((i for i, line in enumerate(scoped)
                         if line.split()[0] == str(root) and "PR_SET_SECCOMP" in line), len(scoped))
    assert exec_entry < filter_entry, refresh
    # 이것을 실패시키는 것: root의 다른 exec, 네트워크·signal·wait 호출 또는 표 밖 write/exit를 허용하는 것.
    initial = front[0]
    assert initial.name == "execve" and QUOTED.findall(args_of(initial)[1])[1] == "prompt"
    stray = [c for c in front[1:] if c.name in NETWORK_OR_PROCESS - SPAWNS]
    assert not stray, ("root network or process calls", stray)
    seen = {c.name for c in front[1:] if c.name in NETWORK_OR_PROCESS | {"write", "exit", "exit_group"}} - SPAWNS
    # A front deadline attempt ends before its record write.
    assert seen == ADAPTER_CALLS or front_deadline and seen <= ADAPTER_CALLS, ("root syscall table", seen, ADAPTER_CALLS)
    cwd = prompt_cwd(initial)
    prompt_root_io(front, boundary, exe, pinned, root, cwd)
    if check_collection and cwd is not None:
        assert_collection_trace(front, boundary, pinned, cwd, headers=headers)
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
        # A collecting helper adds its supervisor thread (collector_supervisor) to the watchdog.
        # 이것을 실패시키는 것: 감사한 collector 없이 둘째 스레드를 허용하는 것, 수집하는 helper의 감독 스레드를 거부하는 것.
        limit = 2 if audited_collector is not None else 1
        assert len(threads) <= limit, ("extra watchdog", threads)
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
        if c.name == "restart_syscall":
            # A thread's interrupted futex wait resumes (strace stops it): no
            # arguments or path. Any other resumed call is unexplained here.
            # 이것을 실패시키는 것: futex 아닌 restart 모양을 건너뛰는 것.
            assert c.args == "<... resuming interrupted futex ...>", ("helper restart", c)
            continue
        # A call its task's exit cut short (strace prints `= ?`) has only the
        # arguments printed before <unfinished ...>; the path rules below need
        # all of them, so a path-bearing one fails closed with the exit that
        # ended it (m3d-F8). Decide that without reading the arguments: the
        # cut can come before the path itself.
        # 이것을 실패시키는 것: 인자가 덜 온 경로 호출을 IndexError나 일부 인자로 판정하는 것(경로 인자 전에서 잘린 경우 포함).
        if c.ret == "?" and (c.name in FILE_ARGS or re.search(r"(?:^|, )\d+</", c.args)):
            ended = next((line.split(None, 1)[1] for line in scoped[::-1]
                          if line.split()[0] == str(c.pid) and line.split(None, 1)[1].startswith("+++ ")), None)
            raise AssertionError(("helper path call cut short by its task's exit", c, ended))
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


# Under strace a run can end at one of two deadlines the trace proves
# (deadline_shape); such an attempt is judged in full and then retried.
ALLOWLIST_ATTEMPTS = 12


def allowlist_capture(base, case):
    """One fresh, traced prompt of the allowlist test in `base`."""
    from types import SimpleNamespace
    base.mkdir(parents=True)
    global_present = case == "global-present"
    inst = Install(base)
    trusted = trusted_env(base)
    trusted["HOME"] = str(base / "home-t")
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
    if case == "no-collection":
        config = Path(trusted["XDG_CONFIG_HOME"]) / "bingsu/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(TEMPLATES["plain"])
        config.chmod(0o600)
    script = inst.init("bash", trusted)
    collector_exe = init_collector_exe(script)
    # A hand-made repository (the test images have no git): an unborn branch.
    repo = base / "repo"
    for sub in ("objects", "refs/heads"):
        (repo / ".git" / sub).mkdir(parents=True)
    (repo / ".git/HEAD").write_text("ref: refs/heads/main\n")
    env = dict(trusted, **{k: str(repo / k.lower()) for k in HOSTILE_VARS})
    f = base / "s.bash"
    f.write_bytes(script + b"\n" + CALL)
    if case != "no-collection":
        warm = subprocess.run(SHELL_CMD["bash"] + [str(f)], env=env, cwd=repo, capture_output=True, timeout=60)
        assert warm.returncode == 0, warm.stderr
        wait_helpers(base)
    trace = base / "trace"
    # Trace all calls; call_paths selects pathname arguments, not quoted data buffers.
    r = subprocess.run(["strace", "-f", "-q", "-y", "-s", "65536", "-e", "trace=all", "-o", str(trace)]
                       + SHELL_CMD["bash"] + [str(f)], env=env, cwd=repo, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    wait_helpers(base)
    real = os.path.realpath(repo)
    return SimpleNamespace(
        lines=trace.read_text(errors="replace").splitlines(), trace=trace,
        # execve names the pinned path (the symlink); its target never shows.
        exe=str(inst.exe), collector_exe=collector_exe, global_inputs=global_inputs,
        global_present=global_present, collectors=int(case != "no-collection"),
        pinned=[os.path.realpath(trusted[k] + sub) for k, sub in
                (("XDG_RUNTIME_DIR", "/bingsu"), ("XDG_CONFIG_HOME", "/bingsu"),
                 ("XDG_STATE_HOME", "/bingsu"), ("XDG_STATE_HOME", "/bingsu/log"))],
        roots=[real, real + "/.git"],
        # Stage A reads HEAD in every repository it finds (the recorded
        # release capture reads 21 bytes from it), so a non-empty read
        # proves collection reached this repository.
        evidence=[real + "/.git/HEAD"],
        platform=(platform.machine(), "musl" if elf_facts(real_bin())[1] is None else "gnu"))


def judge_allowlist(cap, shape=None):
    """The whole allowlist judgment of one capture. A deadline shape waives
    only what that deadline prevents: collector-deadline the repository
    evidence; front-alarm the front's filter and record, the exact collector
    count and both coverage checks. Every path, call and audit rule stays."""
    assert_prompt_trace_budget(cap.lines, cap.exe, cap.pinned, global_inputs=cap.global_inputs,
                               collector_exe=cap.collector_exe,
                               collectors=None if shape == "front-alarm" else cap.collectors,
                               repository_roots=cap.roots,
                               repository_evidence=() if shape else cap.evidence,
                               platform=cap.platform, front_deadline=shape == "front-alarm",
                               headers=getattr(cap, "headers", RESPONSE_HEADERS))
    if cap.collectors and shape != "front-alarm":
        assert_global_inputs_exercised(cap.lines, cap.exe, cap.global_inputs, cap.global_present)


def deadline_shape(cap):
    """Which deadline, if any, the trace proves.

    front-alarm: the front took SIGALRM and then made only rt_sigreturn calls
    up to exit_group(0), with no filter installed (strace can stretch its
    vfork past the deadline). collector-deadline: the collector exited 75
    before its evidence read, a non-empty read of the case's .git/HEAD (its
    request deadline came first). The partial window is still audited in
    full; only the missing evidence is waived.
    """
    from fsbudget.classify import repository_path
    _, scoped = tree(cap.lines, cap.exe)
    root = scoped[0].split()[0]
    front = [line for line in scoped if line.split()[0] == root]
    alarm = next((i for i, line in enumerate(front) if line.split(None, 1)[1].startswith("--- SIGALRM ")), None)
    # 이것을 실패시키는 것: SIGALRM 뒤 출력·다른 호출이 있거나 필터를 설치한 앞단을 마감으로 보는 것.
    if alarm is not None and not any("PR_SET_SECCOMP" in line for line in front):
        after = {m[1] for line in front[alarm:] if (m := re.match(r"\d+\s+([a-z0-9_]+)\(", line))}
        if after == {"rt_sigreturn", "exit_group"} and front[-1].endswith("+++ exited with 0 +++"):
            return "front-alarm"
    collectors = [line.split()[0] for line in scoped if is_root(line, cap.collector_exe)]
    if collectors:
        pid = collectors[0]
        mine = [line for line in scoped if line.split()[0] == pid]
        def path(c):
            try:
                return repository_path(c)
            except AssertionError:  # pipes and other unnamed descriptors
                return None
        calls = parse_trace("\n".join(mine))
        evidenced = any(c.name in {"read", "pread64", "readv"} and re.match(r"[1-9]\d*$", c.ret)
                        and path(c) in cap.evidence for c in calls)
        # 이것을 실패시키는 것: 증거 read 뒤의 exit 75, exit 75 아닌 종료를 마감으로 보는 것,
        # 경계를 저장소 접근 전으로 되돌리는 것(HEAD를 연 뒤 읽기 전의 마감이 즉시 실패).
        if mine[-1].endswith("+++ exited with 75 +++") and not evidenced:
            return "collector-deadline"
    return None


def run_allowlist(capture, judge=judge_allowlist, shape_of=deadline_shape, limit=ALLOWLIST_ATTEMPTS, label="allowlist"):
    """Judge every attempt in full; retry only an attempt whose failure the
    trace proves to be a deadline, and only after it passes its own full
    judgment. Any other failure, or any violation, ends the test at once."""
    from collections import Counter
    shapes = Counter()
    try:
        for attempt in range(1, limit + 1):
            cap = capture(attempt)
            try:
                judge(cap)
            except AssertionError:
                # 이것을 실패시키는 것: 마감이 증명되지 않은 실패를 재시도하는 것, 마감 시도의 판정을 건너뛰는 것.
                shape = shape_of(cap)
                if shape is None:
                    raise
                judge(cap, shape)
                shapes[shape] += 1
                continue
            return attempt, shapes
        pytest.fail(f"{label}: no attempt without a deadline in {limit}; shapes {dict(shapes)}")
    finally:
        print(f"{label} attempts: {attempt}, deadline shapes: {dict(shapes)}")


# 이것을 실패시키는 것: prompt가 시스템 경로와 init이 박은 네 뿌리 밖의 경로를 건드리는 것 —
# 상대 경로("x", Path::exists 포함), 환경 변수가 가리키는 폴더(repo 아래), 현재 폴더, 그 접근을 스레드나 자식 프로세스에서 하는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("case", ["no-collection", "global-missing", "global-present"])
def test_prompt_binary_names_only_allowed_system_paths_and_pinned_roots(tmp_path, case):
    """Every path argument of every traced call (open, stat, rename, link,
    ...) of the binary and its threads and children. SYSTEM_PATHS was
    observed on Debian and Ubuntu glibc (aarch64, the three test images) and
    takes the loader paths of Fedora (/lib64), Arch (/usr/lib) and Alpine
    (/lib/ld-musl-*.so.1) by its shape; the CI musl build on x86_64
    also spawns the fixed helper before its filter. NixOS and Guix
    (/nix/store, /gnu/store) are not covered and fail here.

    The collector count is fixed per case. no-collection compiles a template
    without {dir} or {git}: the helper selects no request and starts none.
    The git cases run one untraced prompt first, so the traced prompt's
    helper finds a published snapshot and starts exactly one collector in
    the case's own repository (whether a first prompt after init has time
    left to admit one varies with the machine). Its calls after the request
    are audited against that repository's two roots. Each attempt keeps its
    own folder (attempt-N) and trace."""
    assert shutil.which("strace"), "Linux path gate must execute strace"
    if case != "no-collection":
        # Under strace a debug helper often runs out of time before it admits
        # the collector (measured: 4 of 6 traced prompts started none), so
        # the exact-one cells run on release only (shell.yml filter-calls).
        require_release_helper(real_bin())
    run_allowlist(lambda attempt: allowlist_capture(tmp_path / f"attempt-{attempt}", case))


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


def assert_collection_trace(calls, boundary, pinned, cwd, *, required=None, headers=RESPONSE_HEADERS):
    """Exact C3 increment, separate from existing runtime/context C-axis calls."""
    from fsbudget.formula import collection_front_expected
    dirs, files = prompt_collection_sources(pinned, cwd)
    assert dirs, "fixture needs a canonical cwd"
    root, address, store = sorted(dirs, key=len)
    expected = [root, address, store, store + "/response", store + "/previous", store + "/command"]
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
            assert not stopped and len(opens) < 6, ("collection extra open", c)
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
                command = path.endswith("/command")
                valid_headers[path] = ((header[:10] == COMMAND_HEADER if command else header[:10] in headers)
                                       and header[10:12] == bytes([64, 0]) and header[20:] == bytes(44)
                                       and total == sizes[path]
                                       and total <= (COMMAND_RESPONSE_MAX if command else 262144))
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
    assert len(opens) <= 6
    # Full normal fixture: exact facts counts and exact immutable header/body
    # reads. The command response is often absent (ENOENT) or left unread.
    if len(opens) == 6 and all(not c.ret.startswith("-1") for c in opens[:5]):
        want = collection_front_expected(3, tuple(sizes.get(p) for p in expected[3:]), tuple(sizes[p]-64 for p in reads))
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
                 "failure-recover": ("failure-recover",),
                 "command_miss": ("unchanged", "command_miss"), "command_hit": ("unchanged", "command_hit"),
                 "command_not_run": ("unchanged", "command_not_run")}
# Command stages (M6 C4): one config unit run through the relay, on a screen
# without dir or git. The miss runs it (no cache: every round); the hit finds
# the warm-up's result inside its cache time; not_run keeps the unit off the
# screen. All three take the session lock and reclaim (C4 ruling Q4; the
# security review's R-1 names both rounds with nothing to run). Paths the
# helper reaches in these rounds, and why:
#   /proc/self/cgroup: the atomic path's input, the delegated cgroup subpath
#     (C3 ruling R3); the helper path rules admit it under /proc/self/.
#   /sys/fs/cgroup/<own>, its cgroup.procs, the session parent bingsu-cmd-*
#     and its unit cgroups: the helper's reclaim under the session lock (C3
#     ruling R1, CMD-CGROUP-PROCS); uname is the 5.14 check before them.
#   /proc/self/fd, /dev/null (three opens) and chdir("/"): the supervisor
#     spawn's fd census and its posix_spawn child before exec, as the
#     collector spawn (miss only).
#   /usr and /usr/bin walks and the target's header pread: exec_path's
#     PATH and target checks (C2; miss only).
#   the collection catalog, GC lock, store folders, collection.lock,
#     command and .command.stage: the response store (C4 ruling P1) and the
#     GC after publication (hit reads the response only).
COMMAND_UNIT = "[segment.\"custom/probe\"]\nkind='command'\ncommand=['/usr/bin/true']\n"
COMMAND_SCREEN = "[layout.line1]\nleft=['char']\n[layout.line2]\nleft=[{shown}'char']\n"
COMMAND_PATH = "/usr/bin"
TEMPLATES = {"plain": "[style]\ntemplate='BASE {char}'\n", "edited": "[style]\ntemplate='EDIT {char}'\n",
             "collect": "[style]\ntemplate='BASE {dir} {git} {char}'\n", "broken": "[broken"}
TEMPLATES["command_miss"] = COMMAND_UNIT + COMMAND_SCREEN.format(shown="'custom/probe', ")
TEMPLATES["command_hit"] = COMMAND_UNIT + "cache='30s'\n" + COMMAND_SCREEN.format(shown="'custom/probe', ")
TEMPLATES["command_not_run"] = COMMAND_UNIT + COMMAND_SCREEN.format(shown="")
# The unit drawn only from 120 columns: the prompts here are 80 wide.
TEMPLATES["command_wide"] = (COMMAND_UNIT + "cache='30s'\n" + COMMAND_SCREEN.format(shown="")
                             + "[layout.when.wide]\nmin_cols=120\n[layout.when.wide.line2]\nleft=['custom/probe','char']\n")
# C5: an env segment drawn on the only line (front strace case `env-segment`).
TEMPLATES["env_segment"] = "[segment.\"custom/aws\"]\nkind='env'\nenv='AWS_PROFILE'\n[style]\ntemplate='BASE {custom/aws} {char}'\n"
# 64 bands of 4 columns, the first key widest, each drawing 600 text bytes: width
# 80 selects a variant past INDEX's chunk, with more variants after it.
TEMPLATES["bands"] = "".join(f"[layout.when.b{i:02}]\nmin_cols={(64 - i) * 4}\nmax_cols={(64 - i) * 4 + 3}\n"
                             f"[layout.when.b{i:02}.style]\ntemplate='{'x' * 600} {{char}}'\n" for i in range(64))


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


def passwd_seeks(libc, user_uid, data=None):
    """musl's fclose of /etc/passwd seeks back once over the bytes its 1 KiB
    reads took past the user's line; computed from this host's file."""
    if libc != "musl":
        return 0
    data = Path("/etc/passwd").read_bytes() if data is None else data
    at = next(m.end() for m in re.finditer(rb"(?m)^[^:\n]*:[^:\n]*:(\d+):.*$\n?", data)
              if int(m.group(1)) == user_uid)
    return int(min(-(-at // 1024) * 1024, len(data)) > at)


# exec_path's LINKS_MAX: the product follows at most this many hops.
TARGET_LINKS_MAX = 40


def target_links(path):
    """Symlink hops from `path` to its file, each a plain name in the same
    folder ending at a regular file: the only shape the formula counts.
    Anything else (another folder, `.` or `..`, a loop, a broken link, a
    folder, more hops than the product follows) fails here."""
    # A loop ends at the hop cap; `.` and `..` end at a folder, which the
    # last check refuses.
    hops, folder, name = 0, os.path.dirname(path), os.path.basename(path)
    while os.path.islink(os.path.join(folder, name)):
        name = os.readlink(os.path.join(folder, name))
        assert "/" not in name, ("unreviewed target link", path, name)
        hops += 1
        assert hops <= TARGET_LINKS_MAX, ("too many target links", path)
    final = os.path.join(folder, name)
    assert os.path.isfile(final) and not os.path.islink(final), ("target is not a regular file", path, name)
    return hops


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


def bash_prompt_script(script, pwd, seq, probe=b""):
    import shlex
    return (script + b"\n_bingsu_seq=" + str(seq).encode() + b"\ncd "
            + os.fsencode(shlex.quote(str(pwd))) + b"\n" + probe + CALL)


def pinned_prompt_argv(script, exe, pwd, seq, env, base):
    """Ask A2's real hook for its expanded invocation without running product code.

    Bash permits an unquoted pathname as a function name with `function`.
    Shadow only this fixture's pinned executable; init and _bingsu_call stay
    intact. The NUL-delimited result preserves empty and quoted arguments.
    """
    import shlex
    exe = str(exe)
    # Fixture install paths are plain words; never interpolate shell syntax.
    assert re.fullmatch(r"[/a-zA-Z0-9_.-]+", exe), exe
    output = base / "prompt-argv.bin"
    output.unlink(missing_ok=True)
    probe = (f"function {exe} {{ printf '%s\\0' {shlex.quote(exe)} \"$@\" > "
             f"{shlex.quote(str(output))}; }}\n").encode()
    path = base / "prompt-argv.bash"
    path.write_bytes(bash_prompt_script(script, pwd, seq, probe))
    result = subprocess.run(SHELL_CMD["bash"] + [str(path)], env=env,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    wire = output.read_bytes()
    assert wire.endswith(b"\0"), wire
    argv = [os.fsdecode(word) for word in wire[:-1].split(b"\0")]
    assert argv[:2] == [exe, "prompt"], argv
    return argv


# 이것을 실패시키는 것: init의 다른 root pin 행 수에 의존하거나 실제 prompt argv를 누락하는 것.
def test_pinned_prompt_argv_from_real_init(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    # Real init emits shell-encoded pins; exercise quotes and a physical newline.
    env["XDG_CONFIG_HOME"] += " ' quoted\nconfig"
    script = inst.init("bash", env)
    (tmp_path / "init.bash").write_bytes(script)
    argv = pinned_prompt_argv(script, inst.exe, tmp_path, 7, env, tmp_path)
    assert argv[:8] == [str(inst.exe), "prompt", "--ctx", "1", "--record", "B1", "--width", "80"]
    assert argv[argv.index("--pwd") + 1] == str(tmp_path)
    assert argv[argv.index("--seq") + 1] == "8"
    assert re.fullmatch(r"[0-9a-f]{32}", argv[argv.index("--session") + 1])
    for flag, word in pinned_roots(env).items():
        assert [os.fsencode(a) for a in argv if os.fsencode(a).startswith(flag)] == [word]
    assert "--collector-exe=" + init_collector_exe(script) in argv
    # Extra flag-bearing lines (such as init's exported command roots) cannot
    # select a different invocation or make extraction ambiguous.
    extra = b"\n# --runtime-root=decoy --config-root=decoy\n"
    assert pinned_prompt_argv(script + extra * 3, inst.exe, tmp_path, 7, env, tmp_path) == argv
    # Compare every word with the same hook calling the existing fake binary.
    inst.use_fake(minimal_record())
    path = tmp_path / "actual-prompt.bash"
    path.write_bytes(bash_prompt_script(script, tmp_path, 7))
    result = subprocess.run(SHELL_CMD["bash"] + [str(path)], env=env, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert inst.calls() == [[os.fsencode(word) for word in argv[1:]]]


class HelperStageFixture:
    """Real init, warm-up prompts and one traced prompt for a helper stage.

    The base lives next to the build output, not under /tmp: a group- or
    world-writable ancestor makes every trust walk add ACL and group queries
    the stage formula does not include, so the fixture refuses one.
    """

    def __init__(self, stage, *, template=None, config="plain"):
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
        command = stage.startswith("command_")
        self.put("collect" if stage == "collect" else stage if command else config, template=template)
        if command:
            self.env["PATH"] = COMMAND_PATH
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
        # Command stages: the first round publishes the snapshot, the second
        # leaves the unit's response (and the session cgroup parent).
        for _ in range(3 if stage == "collect" else 2 if command else 1):
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
        self.command = {}
        if command:
            # A unit off the screen never ran: no response, no lookup.
            responses = list((self.store / "collections-v1").glob("*/store/command"))
            assert len(responses) == int(stage != "command_not_run"), ("command responses after warm-up", responses)
            procs = own_cgroup() / "cgroup.procs"
            self.command = {"command_bytes": responses[0].stat().st_size if responses else 0,
                            "catalog_bytes": (Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu/.collections.catalog").stat().st_size
                            if responses else 0,
                            "cgroup_procs_bytes": len(procs.read_bytes()),
                            "cgroup_parent": session_cgroup_parent(
                                self.script, Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"),
                            "path_names": path_names(COMMAND_PATH), "target_names": path_names("/usr/bin"),
                            "target_links": target_links("/usr/bin/true") if stage == "command_miss" else 0,
                            # The repository scan walks the shell's folder by its names
                            # (U-24): a canonical folder, so no link is followed.
                            "shell_names": path_names(self.pwd)}
            assert os.path.realpath(self.pwd) == str(self.pwd), ("a canonical shell folder", self.pwd)
        if stage == "publish":
            self.put("edited")
        elif stage == "failure-last-good":
            (self.store / "snapshot").unlink()
            self.put("broken")
        elif stage == "failure-recover":
            (self.store / "snapshot").chmod(0o644)

    def put(self, name, *, template=None):
        path = self.config / "config.toml"
        pending = path.with_name("config.toml.new")
        pending.write_text(TEMPLATES[name] if template is None else
                           f"[style]\ntemplate='{template}'\n[layout.when.narrow.style]\ntemplate='{template}'\n")
        pending.chmod(0o600)
        pending.replace(path)

    def prompt(self, trace=None, prelude=b"", pass_fds=()):
        f = self.base / "prompt.bash"
        # Each run is a fresh bash: start its prompt counter after the last
        # run's, as one long-lived shell would, so the collection breaker
        # sees a new sequence instead of a replayed one.
        self.seq += 1
        f.write_bytes(bash_prompt_script(self.script, self.pwd, self.seq, prelude))
        strace = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-s", "4096",
                  "-e", "trace=all",
                  "-o", str(trace)] if trace else []
        r = subprocess.run(strace + SHELL_CMD["bash"] + [str(f)], env=self.env, capture_output=True, timeout=60,
                           pass_fds=pass_fds)
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
            passwd_seeks=passwd_seeks(libc, os.getuid()),
            arch=platform.machine(), **self.collection, **self.command)


def own_cgroup():
    """The cgroup v2 folder of this process (the helper's, as its descendant)."""
    line = next(l for l in Path("/proc/self/cgroup").read_text().splitlines() if l.startswith("0::"))
    return Path("/sys/fs/cgroup" + line[3:].rstrip("/"))


def session_cgroup_parent(script, runtime, own=None):
    """Whether the helper takes the atomic path, decided from the host and
    never from the traced calls. A cgroup folder this process may write to
    (not read-only, not someone else's) delegates: the warm-up must then have
    made this session's own parent (its exact name, owned by this user), or
    the fixture fails; the privileged cell must delegate. Otherwise the round
    is best effort."""
    own = own_cgroup() if own is None else own
    # init writes the session as a shell word (quoted or not) in the hooks.
    session = re.search(rb"_bingsu_session:=['\"]?([0-9a-f]{32})", script)[1]
    root = os.stat(runtime)
    key = root.st_dev.to_bytes(8, "little") + root.st_ino.to_bytes(8, "little") + b"\0" + session
    parent = own / f"bingsu-cmd-{hashlib.sha256(key).digest()[:16].hex()}"
    delegated = os.access(own, os.W_OK) and not os.statvfs(own).f_flag & os.ST_RDONLY
    # 이것을 실패시키는 것: 특권 셀에서 위임을 요구하지 않는 것, 같은 uid의 아무 bingsu-cmd-* 폴더를 이 세션의 부모로
    # 받는 것, 위임된 셀에서 부모가 없을 때 best effort로 셈하는 것(데움 실패가 원자 경로 비용을 지움).
    assert delegated or os.environ.get("BINGSU_CGROUP_CELL") != "priv", ("the privileged cell delegates", own)
    if delegated:
        assert (parent.is_dir() and not parent.is_symlink()
                and parent.stat().st_uid == os.getuid()), ("the warm-up's session parent", parent)
    return delegated


def collector_exit(lines, collector):
    """The traced collector's exit code. 75 is wire::DEADLINE_EXIT_CODE: the
    collector ran past its 50 ms request deadline. The supervisor still
    publishes a Deadline partial when a verified update arrived before it."""
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
    # The command supervisor and relay are the pinned binary's other verbs;
    # they and the target are counted in their own roles, never the helper's.
    roles = collector_attribute(scoped, {"front": exe, "helper": exe, "collector": collector,
                                         "supervisor": exe, "relay": exe,
                                         "collectors": collectors}, helper_vocabulary=helper_vocabulary)
    errors = [e for e in roles.errors if "(collector):" not in e]
    assert not errors, errors
    return collectors, roles


def measured_helper_calls(lines, exe, collector, helper_vocabulary=True):
    collectors, roles = measured_helper_attribution(lines, exe, collector, helper_vocabulary)
    return collectors, roles.counts


def check_helper_capture(stage, lines, exe, collector, plan, *, evidence=None):
    from fsbudget.formula import helper_stage_expected, helper_collect_expected, helper_command_expected
    from fsbudget.gate import check, check_collect, check_command
    if evidence is None:
        evidence = {}
    status = collector_exit(lines, collector) if stage == "collect" else None
    evidence["collector_exit"] = status
    collectors, roles = measured_helper_attribution(lines, exe, collector)
    evidence["role_counts"] = roles.counts
    assert collectors == int(stage == "collect"), ("collector spawns", collectors)
    command_roles = {"supervisor", "relay", "command"} & set(roles.counts)
    # 이것을 실패시키는 것: 명령 단계에서 감독·relay·대상 역할이 비는 것(그 호출이 helper에 섞임), 명령 없는
    # 단계나 실행할 것 없는 명령 단계에 그 역할이 생기는 것.
    assert command_roles == ({"supervisor", "relay", "command"} if stage == "command_miss" else set()), command_roles
    if stage == "command_miss":
        errors = check_command(roles, helper_command_expected(plan), evidence=evidence)
        published = False
    elif stage != "collect":
        measured = {"helper": roles.counts.get("helper", {})}
        expected = {"helper": helper_stage_expected(plan)}
        evidence.update(phase_counts=measured, phase_expected=expected)
        errors = check(measured, expected, "exact", ["helper"])
        published = False
    else:
        assert status in (0, 75), ("unexpected collector exit", status)
        deadline = helper_collect_expected(plan, deadline=True) if status == 75 else None
        errors, published = check_collect(roles, helper_collect_expected(plan),
                                          deadline=deadline, evidence=evidence)
    evidence.update(published=published, errors=errors)
    assert not errors, errors
    return published


# 이것을 실패시키는 것: 도우미 재검증 경로에 같은 파일의 fstat 하나를 더하는 것, 수집 비용을 앞단으로 옮기는 것,
# 공식에 옛 고정 항(e["read"] += 2)을 되살리는 것, debug 바이너리로 재는 것, helper 어휘에서 fd statx나
# chdir를 지우는 것, 제품이 chdir·mkdirat·fchmod·lseek·dup 호출을 하나 더 내는 것,
# 마감 회차의 호출을 버리거나 최대 COLLECT_ATTEMPTS(40)회에서 실제 응답 발행이 한 번도 없는 것.
# Under strace the collector can miss its deadline (exit 75) several times in a
# row on a loaded runner; every such attempt is still checked in full. CI musl
# release published in 1 of 8 attempts: (7/8)**12 is about 0.20 per run, (7/8)**40
# about 0.005. The loop stops at the first publication, so only runs near failure
# pay for more attempts (an attempt took about 0.5-0.9 s in CI).
COLLECT_ATTEMPTS = 40


@pytest.fixture
def helper_stage_evidence(tmp_path_factory):
    # A dedicated upload root, separate from all other pytest fixtures.
    return tmp_path_factory.getbasetemp() / "helper-stage-evidence"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("stage", list(HELPER_STAGES))
def test_live_helper_calls_match_stage_formula(stage, helper_stage_evidence):
    """GATE-FS-HELPER.1: exact stages; collect prefix exact and tail <=.

    Every attempt is checked before retrying, including exit 75. At least one
    of at most COLLECT_ATTEMPTS fresh collect fixtures must actually rename a response.
    """
    assert shutil.which("strace"), "the helper stage gate must execute strace"
    libc = require_release_helper(real_bin())
    import json
    # Traces live outside the product fixture: cleanup must never erase a
    # failed attempt or earlier deadline attempts. --basetemp locates these
    # artifacts for the controller; each invocation needs its own basetemp.
    for attempt in range(1, (COLLECT_ATTEMPTS if stage == "collect" else 1) + 1):
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
            evidence["publish_attempt"] = attempt if published else None
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
    pytest.fail(f"collect: zero publishes across all {COLLECT_ATTEMPTS} checked attempts; evidence: {helper_stage_evidence / stage}")


# The helper's E_n cap (user decision U2), pinned independently from the product source.
HELPER_E_N_CAP = 1024


# 이것을 실패시키는 것: 제품 AXIS_CAPS의 E_n을 바꾸고 이 게이트의 고정값은 그대로 두는 것.
def test_helper_e_n_cap_matches_product_constant():
    source = (ROOT / 'crates/bingsu/src/commands/io_meter.rs').read_text().replace('\r\n', '\n')
    caps = re.search(r'pub\(crate\) const AXIS_CAPS: AxisCaps = AxisCaps \{(.*?)\};', source, re.S)
    assert caps and re.search(r'\be_n: ([\d_]+),', caps[1])[1].replace('_', '') == str(HELPER_E_N_CAP)


HELPER_B_CAP = 2 * 1024 * 1024
KIB256 = 256 * 1024


def write_private(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".new")
    pending.write_bytes(data)
    pending.chmod(0o600)
    pending.replace(path)


def held_recheck(call, held):
    """Whether `call` rechecks retained evidence: fstat of a held descriptor,
    statx or newfstatat of a held descriptor itself (empty name, AT_EMPTY_PATH)
    or of one held name relative to a held folder descriptor. A lookup by path
    (AT_FDCWD, or a name with a slash) is not."""
    m = re.match(r'(\d+)<([^<>]*)>(?:, "([^"]*)")?', call.args)
    if call.name not in ("fstat", "statx", "newfstatat") or not m:
        return False
    base, name = m[2], m[3]
    if call.name == "fstat":
        return name is None and base in held
    if name == "":
        return "AT_EMPTY_PATH" in call.args and base in held
    return name is not None and "/" not in name and base in held and f"{base}/{name}" in held


def held_chain(fixture):
    config = Path(os.path.realpath(fixture.config / "config.toml"))
    return {str(p) for p in [config, *config.parents]}


def axis_cap_case(axis, fixture):
    """Make `fixture`'s config cross `axis`; return (paths the helper must stop
    touching, the crossing call finder, the call kinds still allowed after it)."""
    root = os.path.realpath(fixture.config)
    plain = TEMPLATES["plain"].encode()
    if axis == "E_n":
        conf_d = fixture.config / "conf.d"
        conf_d.mkdir(mode=0o700)
        # 1,100 names and `.`, `..`: the first listing alone passes the cap.
        for i in range(1100):
            (conf_d / f"n{i:04}.txt").write_bytes(b"")
        listing = f"<{os.path.realpath(conf_d)}>"

        def crossing(calls):
            reads = [c for c in calls if c.name == "getdents64" and listing in c.args]
            assert reads, "the helper never listed conf.d"
            seen = 0
            for c in reads:
                m = re.search(r"/\* (\d+) entries \*/", c.args)
                assert m, ("getdents64 without an entry count", c)
                seen += int(m[1])
                if seen > HELPER_E_N_CAP:
                    assert c is reads[-1], ("listing went on past the batch holding the cap", len(reads))
                    return c
            pytest.fail(f"the listing never passed the cap: {seen} entries")
        return [root], crossing, None
    if axis.startswith("R-"):
        # Entries that pass the lexical check and are walked before R counts the
        # next one: the 255th stops with no call of its own, the 254th is the last walked.
        written = {"R-missing": [f"parts/none-{i:03}.toml" for i in range(255)],
                   "R-duplicate": ["parts/same.toml"] * 255, "R-cycle": ["config.toml"] * 255}[axis]
        (fixture.config / "parts").mkdir(mode=0o700)
        write_private(fixture.config / "parts/same.toml", b"")
        refs = ", ".join(f'"{r}"' for r in written)
        write_private(fixture.config / "config.toml", f"extends = [{refs}]\n".encode() + plain)
        last = {"R-missing": '"none-253.toml"', "R-duplicate": '"same.toml"', "R-cycle": '"config.toml"'}[axis]

        def crossing(calls):
            walked = [c for c in calls if c.name in ("openat", "newfstatat", "statx") and last in c.args]
            assert walked, f"the helper never walked {last}"
            missing = {m[0] for c in calls if (m := re.search(r'"none-\d+\.toml"', c.args))}
            opens = sum(c.name == "openat" for c in walked)
            # The root reads config.toml twice more than the list names it.
            assert (len(missing), opens) == {"R-missing": (254, 0), "R-duplicate": (0, 254), "R-cycle": (0, 256)}[axis]
            return walked[-1]
        held = held_chain(fixture) | {root + "/parts", root + "/parts/same.toml"}
        return [root], crossing, lambda c: held_recheck(c, held)
    if axis == "R":
        # config.toml, the absent config.local.toml and 255 refused entries: 257.
        refs = ", ".join(f'"$THEME_{i}"' for i in range(255))
        write_private(fixture.config / "config.toml", f"extends = [{refs}]\n".encode() + plain)
        config = f"<{os.path.realpath(fixture.config / 'config.toml')}>"

        def crossing(calls):
            reads = [c for c in calls if c.name == "read" and config in c.args]
            assert reads, "the helper never read config.toml"
            return reads[-1]
        # The refused entry has no call of its own. Between the read and it the
        # trusted file's retained evidence is checked again: its descriptors
        # and the names that bind them (config.toml and the folders above it).
        return [root], crossing, lambda c: held_recheck(c, held_chain(fixture))
    assert axis == "B"
    themes = fixture.base / "themes"
    refs = [themes / f"t{i}.toml" for i in range(8)]
    text = ("extends = [" + ", ".join(f'"{os.path.realpath(themes)}/t{i}.toml"' for i in range(8)) + "]\n").encode() + plain
    write_private(fixture.config / "config.toml", text)
    for r in refs:
        write_private(r, b"[style\n" + b"x" * (KIB256 - 7))
    last = f"<{os.path.realpath(refs[-1])}>"
    # The eighth theme gets one byte past what B has left, never its whole size.
    room = HELPER_B_CAP - len(text) - 7 * KIB256

    def crossing(calls):
        reads = [c for c in calls if c.name == "read" and last in c.args]
        assert reads, "the helper never read the eighth theme"
        got = sum(int(c.ret) for c in reads if c.ret.isdigit())
        assert got == room + 1, ("bytes read from the crossing theme", got, room + 1)
        return reads[-1]
    return [root, os.path.realpath(themes)], crossing, None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("axis", ["E_n", "R", "R-missing", "R-duplicate", "R-cycle", "B"])
def test_live_helper_stops_config_io_past_an_axis_cap(axis, tmp_path):
    """GATE-FS-HELPER.2: a config past one axis cap ends the release helper's
    round closed. After the call that crosses the cap (the conf.d batch holding
    raw entry cap + 1, the last read of config.toml before a lexically refused
    extends entry, the last walk before a missing, duplicate or cyclic one, the
    read of the theme that passes 2 MiB) no config source call follows, and
    snapshot, last-good, marker and sequence keep their bytes.

    이것을 실패시키는 것: 목록 항목을 걸러낸 뒤에만 세거나 세지 않는 것(목록이 끝까지 돌고 재목록이 따름), 거부된
    extends 항목을 R에서 빼는 것(재검증 걷기가 따름), 없는·중복·순환 항목을 걷기 뒤에 세거나 세지 않는 것(255번째가
    걸어짐), B 읽기를 남은 여유 + 1바이트로 묶지 않는 것, 상한을 넘은 뒤
    남은 뿌리 후보나 재검증을 이어 가는 것, 상한 초과에서 표식·snapshot·sequence를 쓰는 것.
    """
    assert shutil.which("strace"), "the helper axis gate must execute strace"
    require_release_helper(real_bin())
    fixture = HelperStageFixture("unchanged")
    try:
        names = ("snapshot", "last-good", "marker", "sequence")
        before = {n: (fixture.store / n).read_bytes() for n in names if (fixture.store / n).exists()}
        assert {"snapshot", "marker", "sequence"} <= set(before), sorted(before)
        watched, crossing, allowed = axis_cap_case(axis, fixture)
        trace = tmp_path / "trace.strace"
        fixture.prompt(trace)
        wait_helpers(fixture.base)
        after = {n: (fixture.store / n).read_bytes() for n in names if (fixture.store / n).exists()}
        assert after == before, "an exceeded cap changed the store"
        calls = parse_trace(trace.read_text(errors="replace"))
        assert not calls.errors, calls.errors[:5]
        at = crossing(calls)
        later = [c for c in calls[at.index + 1:] if c.name not in ("close", "exit_group")
                 and not (allowed and allowed(c)) and any(path in c.args for path in watched)]
        assert not later, ("config source calls after the cap", later[:5])
    finally:
        wait_helpers(fixture.base)
        shutil.rmtree(fixture.base, ignore_errors=True)


# Fixture metadata, pinned independently from the product source.
FRONT_CHUNK = 16 * 1024
FRONT_CASES = ('normal', 'checksum-last-good', 'body-limit', 'header-only', 'selected-band', 'env-segment')


# 이것을 실패시키는 것: 제품 READ_CHUNK를 바꾸고 fixture 메타데이터는 그대로 두는 것.
def test_front_chunk_matches_product_constant():
    source = (ROOT / 'crates/bingsu-core/src/snapshot.rs').read_text().replace('\r\n', '\n')
    match = re.search(r'pub const READ_CHUNK: usize = (\d+) \* (\d+);', source)
    assert match and int(match[1]) * int(match[2]) == FRONT_CHUNK


def front_attempt_plan(case, body, through_index=None):
    """`body` bytes read through the selected variant; a checksum failure stops
    the current copy at `through_index` bytes."""
    from fsbudget.formula import FrontAttempt
    read = {'normal': body, 'selected-band': body, 'env-segment': body, 'body-limit': 0, 'header-only': 0,
            'checksum-last-good': body if through_index is None else through_index}[case]
    current = FrontAttempt('current', True, case not in ('header-only', 'body-limit'), read, read > 0)
    one_copy = case in ('normal', 'selected-band', 'env-segment')
    return [current] + ([] if one_copy else [FrontAttempt('last_good', True, True, body, True)])


def snapshot_layout(data, width):
    """(front, compiled length, end of the variant selected at width), from the
    file's bytes and the wire layout, without the product's decoder."""
    import struct
    body = int.from_bytes(data[76:80], 'little')
    c = bytes(data[192:192 + body])
    common, count = struct.unpack_from('<II', c, 12)
    index = 20 + common
    at = 20

    def option(form, size):
        nonlocal at
        at += 1
        if not c[at - 1]:
            return None
        at += size
        return struct.unpack_from(form, c, at - size)[0]
    bands, at = [None] * int.from_bytes(c[at:at + 4], 'little'), at + 4
    for i in range(len(bands)):
        bands[i] = option('<H', 2), option('<H', 2), option('<i', 4)
    length = int.from_bytes(c[at:at + 4], 'little')
    order = struct.unpack_from(f'<{length}I', c, at + 4)
    assert length == len(bands) and count == length + 1
    band = next((i for i in order if (bands[i][0] or 0) <= width <= (0xffff if bands[i][1] is None else bands[i][1])), None)
    offset, size = struct.unpack_from('<II', c, index + (0 if band is None else band + 1) * 16)
    return index + count * 16, body, offset + size


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


def front_env_pipe_calls(front, boundary, spawns):
    """Exact environment pipe of the front: only with a helper spawn, before the filter."""
    pipes = [c for c in front if c.name == 'pipe2' and c.args.endswith('O_NONBLOCK|O_CLOEXEC')]
    # 이것을 실패시키는 것: 도우미를 띄우지 않는 회차에도 환경 파이프를 만드는 것(env-no-spawn).
    assert len(pipes) == len(spawns), ('front environment pipe count', pipes, spawns)
    accounted = []
    for pipe in pipes:
        match = re.fullmatch(r'\[(\d+)<pipe:\[(\d+)\]>, (\d+)<pipe:\[\2\]>\], O_NONBLOCK\|O_CLOEXEC', pipe.args)
        assert match and pipe.ret == '0', ('front environment pipe creation', pipe)
        reader, inode, writer = match.groups()
        read_fd, write_fd = (f'{fd}<pipe:[{inode}]>' for fd in (reader, writer))
        channel = [c for c in front if c.name in ('read', 'write', 'close', 'fcntl', 'dup2', 'dup3')
                   and args_of(c) and args_of(c)[0] in (read_fd, write_fd)]
        shape = [(c.name, args_of(c)[0]) for c in channel]
        # Write, write-end close, spawn, read-end close, all before the filter. A retried
        # write is also caught by the primitive count below.
        # 이것을 실패시키는 것: 쓰기 쪽을 생성 뒤에 닫는 것(test_prompt_trace_budget.py의 env-open-writer).
        assert (shape == [('write', write_fd), ('close', write_fd), ('close', read_fd)]
                and pipe.index < channel[0].index < channel[1].index < spawns[0].index < channel[2].index < boundary), (
            'front environment pipe sequence', pipe, channel, spawns)
        write = channel[0]
        # 이것을 실패시키는 것: 일부만 받아들인 쓰기를 통과시키는 것(env-short).
        assert write.ret == args_of(write)[2], ('one write takes the whole frame', write)
        accounted.extend([pipe, *channel])
    return accounted


def front_spawn_pipe_calls(front, boundary, libc, evidence):
    """Exact parent error channel, never a general pipe exemption."""
    from collections import Counter
    from fsbudget.formula import ENV_PIPE_PRIMITIVES, POSIX_SPAWN_PRIMITIVES
    spawns = successful_spawns(front)
    assert len(spawns) <= 1, ('front helper spawns', spawns)
    expected = Counter(POSIX_SPAWN_PRIMITIVES[libc]) if spawns else Counter()
    accounted = front_env_pipe_calls(front, boundary, spawns)
    if spawns:
        expected.update(ENV_PIPE_PRIMITIVES)
    pipes = [c for c in front if c.name == 'pipe2' and c.index not in {a.index for a in accounted}]
    error_pipes = POSIX_SPAWN_PRIMITIVES[libc].get('pipe2', 0) if spawns else 0
    assert len(pipes) == error_pipes, ('front spawn pipe count', pipes, expected)
    for pipe in pipes:
        match = re.fullmatch(r'\[(\d+)<pipe:\[(\d+)\]>, (\d+)<pipe:\[\2\]>\], O_CLOEXEC', pipe.args)
        assert match and pipe.ret == '0', ('front spawn pipe creation', pipe)
        reader, inode, writer = match.groups()
        assert reader != writer, ('front spawn pipe endpoints', pipe)
        read_fd, write_fd = (f'{fd}<pipe:[{inode}]>' for fd in (reader, writer))
        # Include every read/close on this pipe: duplicates cannot borrow slack.
        channel = [c for c in front if c.name in ('read', 'close')
                   and args_of(c)[0] in (read_fd, write_fd)]
        assert [(c.name, args_of(c), c.ret) for c in channel] == [
            ('close', [write_fd], '0'),
            ('read', [read_fd, '""', '4'], '0'),
            ('close', [read_fd], '0'),
        ], ('front spawn pipe sequence', channel)
        assert pipe.index < spawns[0].index < channel[0].index, ('front spawn pipe order', pipe, spawns)
        assert all(c.index < boundary for c in [pipe, *channel]), ('late front spawn pipe', channel)
        accounted.extend([pipe, *channel])
    actual = Counter(c.name for c in accounted)
    evidence.update(spawn_pipe_counts=actual, spawn_pipe_expected=expected)
    assert actual == expected, ('front spawn pipe primitives', actual, expected)
    return {c.index for c in accounted}


def check_front_capture(lines, exe, pinned, store, attempts, *, arch, libc, evidence):
    from collections import Counter
    from fsbudget.strace_parse import Trace
    from fsbudget.formula import front_attempts_expected, collection_front_expected, STARTUP_PRIMITIVES
    _, scoped = tree(lines, exe)
    root = int(next(line.split()[0] for line in scoped if is_root(line, exe)))
    parsed = parse_trace('\n'.join(scoped))
    # 이것을 실패시키는 것: 불완전 캡처 또는 필터 없이 앞단 계수를 통과시키는 것.
    assert not parsed.errors, parsed.errors
    front = Trace()
    front.extend(c for c in parsed if c.pid == root and c.name != EXIT_EVENT)
    # 이것을 실패시키는 것: trace=all에 새 syscall을 남겨도 계수 대상이 아니라며 버리는 것.
    startup_model = STARTUP_PRIMITIVES[arch, libc]
    # lseek is counted below, never ignored or allowed on arbitrary fds.
    assert all(c.name in ROOT_CALLS | {'lseek'} for c in front), [c for c in front if c.name not in ROOT_CALLS | {'lseek'}]
    # 이것을 실패시키는 것: snapshot을 mmap하여 TrustMetadata 읽기를 read 계수 밖으로 옮기는 것.
    for call in front:
        assert call.name != 'readv', ('unexpected front read primitive', call)
        if call.name != 'read':
            assert not set(content_paths(call)) & {str(store / n) for n in ('snapshot', 'last-good', 'marker')}, ('front content primitive', call)
    filters = [c.index for c in front if c.name == 'prctl' and 'PR_SET_SECCOMP' in c.args and c.ret == '0']
    assert len(filters) == 1, filters
    cwd = prompt_cwd(next(c for c in front if c.name == 'execve'))
    prompt_root_io(front, filters[0], exe, pinned, root, cwd)
    spawn_pipe_calls = front_spawn_pipe_calls(front, filters[0], libc, evidence)
    dirs, files = prompt_sources(pinned)
    collection_dirs, _ = prompt_collection_sources(pinned, cwd)
    boot_paths = {'/', '/proc', f'/proc/{root}', f'/proc/{root}/ns',
                  f'/proc/{root}/timens_offsets', '/proc/sys', '/proc/sys/kernel',
                  '/proc/sys/kernel/random', '/proc/sys/kernel/random/boot_id'}
    held, counts, primitives = {}, Counter(), Counter()
    startup = {name: Counter() for name in ('front_fds', 'front_cache', 'front_libgcc', 'front_libc', 'front_maps', 'stack_guard')}
    seeks = []

    def startup_kind(path):
        if path in ('/proc/self/fd', f'/proc/{root}/fd'):
            return 'front_fds'
        if path == '/etc/ld.so.cache':
            return 'front_cache'
        if path in ('/proc/self/maps', f'/proc/{root}/maps'):
            return 'front_maps'
        for suffix, kind in (('libgcc_s.so.1', 'front_libgcc'), ('libc.so.6', 'front_libc')):
            if re.fullmatch(r'/(?:usr/)?lib(?:64)?/(?:[^/]+/)?' + re.escape(suffix), path):
                return kind
        raise AssertionError(('unaccounted front startup path', path))
    for c in front:
        if c.index in spawn_pipe_calls:
            continue
        args = args_of(c)
        paths = call_paths(c)
        if c.name in OPENS:
            assert paths, ('unaccounted front open', c)
            kind = None if paths[0] in dirs | files | boot_paths | collection_dirs else startup_kind(paths[0])
            if kind is None:
                counts['openat'] += 1
            else:
                assert c.index < filters[0], ('late front startup open', c)
                startup[kind]['openat'] += 1
            if not c.ret.startswith('-1'):
                held[int(c.ret.split('<')[0])] = kind
            continue
        if c.name == 'getxattr':
            match = re.fullmatch(r'"/proc/self/fd/(\d+)"', args[0])
        else:
            match = re.fullmatch(r'(\d+)(?:<[^<>]*>)?', args[0]) if args else None
        fd = int(match[1]) if match else None
        if c.name in ('read', 'pread64', 'lseek'):
            assert fd in held, ('untracked front descriptor', c)
            kind = held[fd]
            if c.name == 'lseek':
                assert kind == 'front_maps' and c.index < filters[0], ('unexpected front seek', c)
                assert len(args) == 3 and not c.ret.startswith('-1'), ('front startup seek', c)
                seeks.append(args[2])
                startup['stack_guard']['seek'] += 1
            elif kind is None:
                assert c.name == 'read', ('unexpected front read primitive', c)
                counts['read'] += 1
            else:
                assert c.index < filters[0], ('late front startup read', c)
                startup[kind][c.name] += 1
            continue
        if fd not in held:
            continue
        if c.name == 'close':
            held.pop(fd)
        elif held[fd] is not None:
            continue
        elif c.name in ('fstat', 'newfstatat', 'statx'):
            counts[front_fact_kind(c)] += 1
            primitives[c.name] += 1
        elif c.name in ('fstatfs', 'fgetxattr', 'getxattr', 'readlinkat', 'read'):
            counts[c.name] += 1
    expected = Counter(front_attempts_expected(len(dirs), attempts, FRONT_CHUNK))
    # Plain config has no collection store: prefetch still probes its namespace.
    expected.update(collection_front_expected(0, (), (), absent=True))
    startup_expected = {name: Counter(startup_model.get(name, {})) for name in startup}
    evidence.update(C=len(dirs), counts=counts, expected=expected, fact_primitives=primitives,
                    arch=arch, libc=libc, startup_counts=startup, startup_expected=startup_expected)
    assert startup == startup_expected, ('front startup primitives', startup, startup_expected)
    assert seeks == (['SEEK_CUR', 'SEEK_SET'] if startup_model['stack_guard'].get('seek') else []), ('front startup seek pair', seeks)
    # 이것을 실패시키는 것: 앞단 open/facts/read 하나 추가, collection prefetch를 비용에서 빼는 것.
    assert counts == expected, ('front axis C', counts, expected)
    assert_front_reads(front, store, attempts, evidence=evidence)


@pytest.fixture
def front_capture(request, tmp_path_factory):
    """Use A2's init/warm-up/trace harness; hold its publication lock while corrupting."""
    import fcntl
    import json
    from dataclasses import asdict
    from fsbudget.formula import front_body_bytes
    libc = require_release_helper(real_bin())
    assert shutil.which('strace'), 'front gate must execute strace'
    case = getattr(request, 'param', 'normal')
    artifacts = tmp_path_factory.getbasetemp() / 'front-evidence' / request.node.name
    artifacts.mkdir(parents=True)
    evidence = {'case': case, 'chunk': FRONT_CHUNK, 'arch': platform.machine(), 'libc': libc}
    fixture = None
    lock = None
    try:
        config = {'selected-band': 'bands', 'env-segment': 'env_segment'}.get(case, 'plain')
        fixture = HelperStageFixture('unchanged', config=config)
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
        front, _, variant_end = snapshot_layout(data, 80)
        read = front_body_bytes(front, body, variant_end, FRONT_CHUNK)
        through_index = min(read, -(-front // FRONT_CHUNK) * FRONT_CHUNK)
        if case == 'selected-band':
            # 이것을 실패시키는 것: 고른 변종이 색인 청크 안이거나 구획 끝이라 버리기·조기 종료를 증명하지 못하는 fixture.
            assert through_index < variant_end < body, (front, variant_end, body)
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
        attempts = front_attempt_plan(case, read, through_index)
        evidence.update(attempts=[asdict(a) for a in attempts], body=body, metadata=metadata)
        trace = artifacts / 'trace.strace'
        if case == 'env-segment':
            # C5: the env segment's value comes from the environment the
            # prompt already holds, so the calls equal the normal case's.
            fixture.env['AWS_PROFILE'] = 'dev-acct'
        result = fixture.prompt(trace)
        if case == 'env-segment':
            # The hook keeps the record in shell variables; the prompt's write
            # of it is in the trace. 이것을 실패시키는 것: env segment 값을 그리지 않는 것(호출 비교가 공허해짐).
            assert 'dev-acct' in trace.read_text(), 'the record does not draw the env value'
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
    check_front_capture(lines, exe, pinned, store, attempts, arch=evidence['arch'], libc=evidence['libc'], evidence=evidence)


# 이것을 실패시키는 것: FrontDecoder의 end에 TrustMetadata 길이를 더하는 것.
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux strace runtime gate')
def test_front_never_reads_trust_metadata_section(front_capture):
    lines, exe, pinned, store, attempts, evidence = front_capture
    check_front_capture(lines, exe, pinned, store, attempts, arch=evidence['arch'], libc=evidence['libc'], evidence=evidence)


def child_strace_argv(evidence, argv, timestamps=False):
    """The child_capture strace command; only the marker test adds -ttt."""
    return ["strace", "-f", "-q", "-y", "-s", "65536", "-e", "trace=all",
            *(["-ttt"] if timestamps else []), "-o", str(evidence), *argv]


TIMED_LINE = re.compile(r"^(\d+)( +)(\d+)\.(\d{6}) (.*)$")


def strip_trace_times(text):
    """A -ttt trace as the untimed trace parse_trace reads; fails closed on
    any line without its time column."""
    out = []
    for line in text.splitlines():
        m = TIMED_LINE.match(line)
        assert m, ("untimed line in a -ttt trace", line)
        out.append(f"{m[1]}{m[2]}{m[5]}")
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


@pytest.fixture
def child_capture(tmp_path):
    # 이것을 실패시키는 것: debug 바이너리 또는 strace 없는 host를 live PASS로 세는 것.
    if sys.platform != "linux":
        pytest.skip("Linux release strace gate; native Linux run required")
    # 이것을 실패시키는 것: if real_bin().parent.name != "release" 조건을 제거하거나 반전하는 변이.
    if real_bin().parent.name != "release":
        pytest.skip("child-count measurement requires release")
    # 이것을 실패시키는 것: assert shutil.which("strace"), "required live tracing tool is missing" 조건을 제거하거나 반전하는 변이.
    assert shutil.which("strace"), "required live tracing tool is missing"

    def capture(template="{dir}{git}{char}", invalid=False, name=None, timestamps=False, redraw=False):
        # `name` keeps a retried attempt's evidence in its own folder.
        base = tmp_path / (name or str(len(list(tmp_path.iterdir()))))
        base.mkdir(parents=True)
        # Reuse A2's real hook, advancing session sequence and untraced warm-up.
        # A cold admission under strace may defer before it can spawn a worker.
        fixture = HelperStageFixture("unchanged" if template == "{char}" else "collect",
                                     template=template)
        try:
            return capture_prompt(fixture, base, invalid, timestamps, redraw)
        finally:
            wait_helpers(fixture.base)
            shutil.rmtree(fixture.base)

    def capture_prompt(fixture, base, invalid, timestamps, redraw):
        marker = fixture.store / "marker"
        wire = bytearray(marker.read_bytes())
        # 이것을 실패시키는 것: assert wire[:8] == b"BNGMRK02" and len(wire) == 208 조건을 제거하거나 반전하는 변이.
        assert wire[:8] == b"BNGMRK02" and len(wire) == 208
        # 이것을 실패시키는 것: if invalid 조건을 제거하거나 반전하는 변이.
        if invalid:
            wire[12] = 2
            crc = 0xffffffff
            for byte in b"bingsu-marker-v2\0" + wire[:176]:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
            wire[176:180] = (crc ^ 0xffffffff).to_bytes(4, "little")
            pending = marker.with_suffix(".b1")
            pending.write_bytes(wire)
            pending.chmod(0o600)
            pending.replace(marker)
        evidence = base / "child-count.strace"
        # Expand A2's exact hook without tracing bash or running a prompt.
        # A2 increments fixture.seq before setting the hook's pre-call counter;
        # use that same next counter so capture cannot replay the last warm-up.
        argv = pinned_prompt_argv(fixture.script, fixture.inst.exe, fixture.pwd,
                                  fixture.seq + 1, fixture.env, base)
        assert "--collector-exe=" + fixture.collector in argv, argv
        if redraw:
            argv = [*argv, "--redraw"]
        # What a full trace judgment needs after the fixture is gone.
        env, repo = fixture.env, os.path.realpath(fixture.pwd)
        (base / "context.json").write_text(json.dumps({
            "exe": str(fixture.inst.exe), "collector_exe": fixture.collector,
            "pinned": [os.path.realpath(env[k] + sub) for k, sub in
                       (("XDG_RUNTIME_DIR", "/bingsu"), ("XDG_CONFIG_HOME", "/bingsu"),
                        ("XDG_STATE_HOME", "/bingsu"), ("XDG_STATE_HOME", "/bingsu/log"))],
            "global_inputs": [str(Path(env["XDG_CONFIG_HOME"]) / "git/config"), str(Path(env["HOME"]) / ".gitconfig"),
                              str(Path(env["XDG_CONFIG_HOME"]) / "git/ignore")],
            "roots": [repo, repo + "/.git"],
            "platform": [platform.machine(), "musl" if elf_facts(real_bin())[1] is None else "gnu"]}, indent=1) + "\n")
        result = subprocess.run(child_strace_argv(evidence, argv, timestamps),
                                cwd=fixture.pwd, env=fixture.env, capture_output=True, timeout=60)
        (base / "stdout").write_bytes(result.stdout)
        (base / "stderr").write_bytes(result.stderr)
        # 이것을 실패시키는 것: assert result.returncode == 0, (result.stderr, evidence) 조건을 제거하거나 반전하는 변이.
        assert result.returncode == 0, (result.stderr, evidence)
        text = evidence.read_text()
        trace = parse_trace(strip_trace_times(text) if timestamps else text)
        # 이것을 실패시키는 것: assert not trace.errors, (trace.errors, evidence) 조건을 제거하거나 반전하는 변이.
        assert not trace.errors, (trace.errors, evidence)
        return trace, fixture.store, result.stdout
    return capture


# 이것을 실패시키는 것: helper 생략·중복 생성, collector 중복·자식 생성, 쓰기 전용·명령 프로세스 추가.
def test_live_child_count_is_bounded_per_role(child_capture):
    from fsbudget.attribute import role_children
    trace, _, _ = child_capture()
    children = role_children(trace)
    # 이것을 실패시키는 것: assert children == {"front": 1, "helper": 1, "collector": 0, "command": 0}, children 조건을 제거하거나 반전하는 변이.
    assert children == {"front": 1, "helper": 1, "collector": 0, "command": 0}, children


# 이것을 실패시키는 것: redraw에서 도우미를 띄우는 것, redraw 앞단이 설정 원본 폴더를 건드리는 것.
def test_redraw_spawns_no_process_and_reads_no_config_source(child_capture, tmp_path):
    from fsbudget.attribute import role_children

    def config_calls(name, trace):
        root = json.loads((tmp_path / name / "context.json").read_text())["pinned"][1]
        # The bytes a read returned do not count: a snapshot quotes its roots.
        def named(c):
            return re.sub(r'"(?:[^"\\]|\\.)*"', '""', c.args) if c.name in {"read", "pread64"} else c.args
        return [c for c in trace if c.name not in {"execve", "execveat"} and root in named(c)]

    trace, _, record = child_capture(name="prompt")
    assert role_children(trace)["front"] == 1
    # 양성 대조: 같은 검사가 일반 프롬프트 도우미의 설정 원본 읽기를 본다.
    assert config_calls("prompt", trace)
    trace, _, record = child_capture(name="redraw", redraw=True)
    assert record.startswith(b"B1\x1f") and record.endswith(b"\x1e")
    assert role_children(trace) == {"front": 0, "helper": 0, "collector": 0, "command": 0}
    assert len({c.pid for c in trace}) == 1, "a redraw is one process"
    assert not config_calls("redraw", trace)
    # 이것을 실패시키는 것: 도우미를 띄우지 않는 redraw에서도 환경 파이프를 만드는 것.
    assert not [c for c in trace if c.name in {"pipe", "pipe2"}], "a redraw makes no environment pipe"


BRANCH = "redrawbranch"


def git_repo(path):
    """A hand-made repository with one commit on BRANCH: the test images have no git."""
    def loose(kind, body):
        data = f"{kind} {len(body)}\0".encode() + body
        name = hashlib.sha1(data).hexdigest()
        target = path / ".git/objects" / name[:2] / name[2:]
        target.parent.mkdir(parents=True)
        target.write_bytes(zlib.compress(data))
        return name

    who = b"t <t@t> 0 +0000"
    tree = loose("tree", b"")
    commit = loose("commit", b"tree %s\nauthor %s\ncommitter %s\n\nc\n" % (tree.encode(), who, who))
    (path / ".git/refs/heads").mkdir(parents=True)
    (path / ".git/refs/heads" / BRANCH).write_text(commit + "\n")
    (path / ".git/HEAD").write_text(f"ref: refs/heads/{BRANCH}\n")
    return path


# 이것을 실패시키는 것: redraw가 저장 봉투 값이나 이전 수집 응답을 버리는 것, 새 폭을 쓰지 않는 것.
def test_redraw_renders_new_width_from_same_values(tmp_path):
    # A debug collector is too large to verify inside the helper's CPU limit.
    if real_bin().parent.name != "release":
        pytest.skip("real collection requires release")
    from test_helper_lifecycle import LifetimeSession, poll
    session = LifetimeSession(tmp_path / "s", tag="r")
    session.put("[layout.line1]\nleft=['dir']\nright=['git']\n[layout.line2]\nleft=['duration','char']\nright=[]\n")
    session.init()
    session.wait_quiet()
    repo = git_repo(session.base / "repo")
    stored = ["--status", "3", "--pipestatus", "3", "--duration-ms", "5000", "--jobs", "2"]

    def prompt(width, *extra):
        args = session.prompt_args(repo)
        args[args.index("--width") + 1] = str(width)
        result = session.run(*args, *stored, *extra, timeout=2)
        assert result.returncode == 0 and result.stderr == b"", result
        return result.stdout

    def collected():
        record = prompt(100)
        session.wait_quiet()
        return BRANCH.encode() in record and record

    wide = poll(collected, 20, "the first prompts never collected git")
    assert b"5.0s" in wide
    redraw = prompt(90, "--redraw")
    assert BRANCH.encode() in redraw and b"5.0s" in redraw
    assert redraw != wide, "the new width was not used"
    assert redraw == prompt(90), "a redraw differs from a prompt with the same envelope"
    session.wait_quiet()
    # 이것을 실패시키는 것: 세션의 도우미 집계가 값 자리의 `--redraw`를 플래그로 보는 것.
    before = session._helper_count
    prompt(90, "--redraw")
    assert session._helper_count == before
    prompt(90, "--host", "--redraw")
    assert session._helper_count == before + 1
    session.wait_quiet()


# 이것을 실패시키는 것: worker가 없는 화면에도 collector 생성.
def test_live_no_worker_segment_spawns_zero_collectors(child_capture):
    from fsbudget.attribute import role_children
    trace, _, _ = child_capture("{char}")
    # 이것을 실패시키는 것: assert role_children(trace) == {"front": 1, "helper": 0, "collector": 0, "command": 0} 조건을 제거하거나 반전하는 변이.
    assert role_children(trace) == {"front": 1, "helper": 0, "collector": 0, "command": 0}


# Under strace the front can pass its 50 ms deadline and exit 0 without a
# record (front_deadline_exit); such an attempt is judged in full and retried.
MARKER_ATTEMPTS = 8


def silent_armed_front(cap):
    """(front events, setitimer index, it_value in µs) of a capture whose front
    armed ITIMER_REAL with a positive it_value (setitimer returned 0), attempted
    no write to fd 1 at all, exited 0, and left stdout empty. Anything else is
    None. Each event is (time in µs or None, line)."""
    timed = re.compile(r"(\d+)\s+(?:(\d+)\.(\d{6})\s+)?(.*)$")
    rows = [(m[1], int(m[2]) * 1_000_000 + int(m[3]) if m[2] else None, m[4])
            for line in cap.lines if (m := timed.match(line))]
    if not rows or not re.match(r'execve\("[^"]*", \["[^"]*", "prompt"', rows[0][2]):
        return None
    root = rows[0][0]
    front = [(at, line) for pid, at, line in rows if pid == root]
    armed = next((i for i, (_, line) in enumerate(front) if line.startswith("setitimer(ITIMER_REAL,")), None)
    # 이것을 실패시키는 것: 실패했거나 없는 setitimer를 받는 것.
    if armed is None or not front[armed][1].endswith(") = 0") or cap.record:
        return None
    value = re.search(r"it_value=\{tv_sec=(\d+), tv_usec=(\d+)\}", front[armed][1])
    # 이것을 실패시키는 것: 0인 it_value(타이머 해제)를 받는 것.
    if not value or int(value[1]) * 1_000_000 + int(value[2]) <= 0:
        return None
    # 이것을 실패시키는 것: 앞단의 fd 1 쓰기 시도(실패한 것 포함)를 어디서든 받는 것, 0 아닌 종료,
    # 비지 않은 stdout을 받는 것.
    if any(re.match(r"(write|writev|pwrite64|pwritev2?)\(1[<,]", line) for _, line in front):
        return None
    if front[-1][1] != "+++ exited with 0 +++":
        return None
    return front, armed, int(value[1]) * 1_000_000 + int(value[2])


def last_event_before_exit(front, armed):
    """The time of the front's last event before exit_group, after setitimer.
    strace reads a line's time while the tracee is stopped and resumes it
    afterwards (stop-then-resume ordering, UNVERIFIED), so the exit_group
    line's own time can be later than the exit."""
    ends = [i for i, (_, line) in enumerate(front) if line.startswith("exit_group(")]
    return front[ends[-1] - 1][0] if ends and ends[-1] > armed else None


def front_deadline_exit(cap):
    """"front-deadline" when the trace proves the front's own deadline ended
    it: a silent armed front (silent_armed_front) that then either took a
    kernel SIGALRM or, by the -ttt times, made its last event before
    exit_group strictly later than the setitimer start plus its positive
    it_value. Anything else is None.

    The front computes its remaining time just before setitimer, so its
    deadline cannot end later than setitimer start + it_value. strace times
    are realtime, the product's clock is monotonic: equal or unreadable
    times prove nothing. A realtime step back can only refuse a retry; a
    step forward can retry an attempt early, and a retried attempt is
    still judged in full, so the cost is one more capture of an empty record."""
    silent = silent_armed_front(cap)
    if silent is None:
        return None
    front, armed, it_value = silent
    alarm = next((i for i, (_, line) in enumerate(front) if i > armed
                  and line.startswith("--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL")), None)
    if alarm is None:
        start, at = front[armed][0], last_event_before_exit(front, armed)
        # 이것을 실패시키는 것: 경계 같음을 증명으로 보는 것(>=), it_value를 빼는 것.
        if start is None or at is None or not at > start + it_value:
            return None
    return "front-deadline"


def front_deadline_window(cap):
    """"front-deadline-window" when a silent valid-marker exit does not
    contradict the front's deadline. That is all it says about the deadline;
    the record it lacks must still come in another of MARKER_ATTEMPTS attempts.

    The front reads its remaining time after the event before setitimer, so
    its deadline cannot come before that event + it_value: its last event
    before exit_group reaching that time, boundary included, leaves the exit
    no earlier than the deadline could be. The upper end of the same deadline
    is what front_deadline_exit needs, and the stored run 18 stops 62 µs short
    of it. An exit before the window, or unreadable times, is not this shape."""
    silent = silent_armed_front(cap)
    # 이것을 실패시키는 것: invalid 조건에도 이 모양을 주는 것.
    if cap.invalid or silent is None:
        return None
    front, armed, it_value = silent
    earliest, at = front[armed - 1][0], last_event_before_exit(front, armed)
    # 이것을 실패시키는 것: 경계 같음을 빼는 것(>), it_value를 빼는 것, 시각 없는 trace를 받는 것,
    # 하한을 setitimer 자신의 시각으로 올리는 것.
    if earliest is None or at is None or at < earliest + it_value:
        return None
    return "front-deadline-window"


def marker_shape(cap):
    return front_deadline_exit(cap) or front_deadline_window(cap)


def judge_marker_trace(cap, shape=None):
    """The allowlist judgment of the whole capture, deadline or not: every
    path, call and audit rule and every upper bound. Only an empty stdout
    waives the two record-bound items, the one filter and the record write
    in the front's call table; a front without a filter then has every call
    held to the pre-filter rules.
    The collector count stays with judge_marker_attempt; collection
    coverage (repository and global-input reads) was never this test's."""
    c = cap.context
    # 이것을 실패시키는 것: 버리는 마감 시도의 경로·syscall 금지 판정을 건너뛰는 것.
    assert_prompt_trace_budget(cap.untimed, c["exe"], c["pinned"], global_inputs=tuple(c["global_inputs"]),
                               collector_exe=c["collector_exe"], collectors=None,
                               repository_roots=c["roots"], repository_evidence=(),
                               # 이것을 실패시키는 것: 비지 않은 stdout에서 필터·기록 쓰기를 면제하는 것.
                               platform=tuple(c["platform"]), front_deadline=cap.record == b"",
                               headers=getattr(cap, "headers", RESPONSE_HEADERS))


def judge_marker_attempt(cap, shape=None, trace_judge=judge_marker_trace):
    """One marker-condition capture. Every attempt keeps the role bounds and
    the full trace judgment; a deadline shape (marker_shape) waives only the
    record, and the collector spawn only when the front ended before it
    created the helper (the helper never waits on the front, so a later
    deadline cannot stop its spawn)."""
    from fsbudget.attribute import role_children
    trace_judge(cap, shape)
    children = role_children(cap.trace)
    # 이것을 실패시키는 것: 마감 시도에서 역할 상한(helper 둘, collector·명령 자식)을 넘기는 것.
    assert children["front"] <= 1 and children["helper"] <= 1, children
    assert children["collector"] == children["command"] == 0, children
    if shape is None or children["front"]:
        # 이것을 실패시키는 것: 표식 무효면 worker mask 0.
        assert children["helper"] == 1, children
    # 이것을 실패시키는 것: 마감 모양이 아닌 빈 stdout을 통과시키는 것(레코드 소실 회귀).
    if shape is None:
        assert cap.record, "no record and no deadline shape"
    if shape is None and cap.invalid:
        assert b"degraded:trust-invalid" in cap.record, cap.record


def marker_capture(child_capture, tmp_path, invalid, attempt):
    from types import SimpleNamespace
    name = f"{'invalid' if invalid else 'valid'}/attempt-{attempt}"
    trace, _, record = child_capture(invalid=invalid, name=name, timestamps=True)
    text = (tmp_path / name / "child-count.strace").read_text(errors="replace")
    return SimpleNamespace(trace=trace, lines=text.splitlines(), untimed=strip_trace_times(text).splitlines(),
                           context=json.loads((tmp_path / name / "context.json").read_text()),
                           record=record, invalid=invalid)


# 이것을 실패시키는 것: 표식 무효면 worker mask 0.
def test_live_collector_count_ignores_marker_validity(child_capture, tmp_path):
    """Both marker conditions start exactly one collector. Each condition
    must reach that evidence with a record (the invalid one its degraded
    record) in at most MARKER_ATTEMPTS attempts. Only a deadline shape is
    retried, after its own judgment: a trace-proven front deadline, or in the
    valid condition an exit that does not contradict the deadline
    (front_deadline_window). Attempts stay in valid|invalid/attempt-N."""
    for invalid in (False, True):
        run_allowlist(lambda attempt: marker_capture(child_capture, tmp_path, invalid, attempt),
                      judge_marker_attempt, marker_shape, MARKER_ATTEMPTS,
                      label=f"marker {'invalid' if invalid else 'valid'}")


# 이것을 실패시키는 것: 머리 읽기 전에 collector 생성.
def test_live_collector_spawns_after_helper_header_and_marker_reads(child_capture):
    from fsbudget.attribute import first_index, role_children
    trace, store, _ = child_capture()
    # 이것을 실패시키는 것: assert role_children(trace)["helper"] == 1 조건을 제거하거나 반전하는 변이.
    assert role_children(trace)["helper"] == 1
    assert_child_timing(trace, store)


def assert_child_timing(trace, store):
    from fsbudget.attribute import first_index
    helper_exec = first_index(trace, "helper", lambda c: c.name == "execve" and c.ret == "0")
    main = trace[helper_exec].pid
    spawn = first_index(trace, "helper", lambda c: c.pid == main and c.name in SPAWNS
                        and "CLONE_THREAD" not in c.args and re.fullmatch(r"[1-9][0-9]*", c.ret))
    # The helper verifies its freshly staged marker by same-fd readback before
    # admission. This is distinct from the front reading the published marker.
    for name, size in (("snapshot", 192), (".marker.stage", 208)):
        read = first_index(trace, "helper", lambda c: c.pid == main and c.name == "read"
                           and args_of(c)[0].endswith("<" + str(store / name) + ">")
                           and c.ret.isdigit() and int(c.ret) >= size)
        # 이것을 실패시키는 것: 머리·표식 읽기를 collector 생성 뒤로 옮기는 것.
        assert read < spawn, (name, read, spawn)


# 이것을 실패시키는 것: 앞단의 marker 읽기로 helper 읽기를 대체하거나 읽기 순서·길이를 무시하는 것.
@pytest.mark.parametrize("mutation", ["none", "early", "front-marker", "short-header", "failed-marker"])
def test_child_timing_negative_controls(mutation):
    head = '11 read(3</store/snapshot>, "header", 192) = 192'
    marker = '11 read(4</store/.marker.stage>, "marker", 208) = 208'
    spawn = '11 vfork() = 13'
    # 이것을 실패시키는 것: if mutation == "front-marker" 조건을 제거하거나 반전하는 변이.
    if mutation == "front-marker":
        marker = marker.replace('11 read', '10 read')
    # 이것을 실패시키는 것: elif mutation == "short-header" 조건을 제거하거나 반전하는 변이.
    elif mutation == "short-header":
        head = head.replace('= 192', '= 1')
    # 이것을 실패시키는 것: elif mutation == "failed-marker" 조건을 제거하거나 반전하는 변이.
    elif mutation == "failed-marker":
        marker = marker.replace('= 208', '= -1 EBADF (Bad file descriptor)')
    prefix = ['10 execve("/bin/bingsu", ["/bin/bingsu", "prompt"], []) = 0',
              '10 vfork() = 11',
              '11 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], []) = 0']
    events = [spawn, head, marker] if mutation == "early" else [head, marker, spawn]
    trace = parse_trace('\n'.join(prefix + events + [
        '13 execve("/bin/bingsu-collect", ["/bin/bingsu-collect", "__collect-v1"], []) = 0']))
    # 이것을 실패시키는 것: if mutation == "none" 조건을 제거하거나 반전하는 변이.
    if mutation == "none":
        assert_child_timing(trace, Path('/store'))
    else:
        with pytest.raises((AssertionError, StopIteration)):
            assert_child_timing(trace, Path('/store'))


# Stored synthetic control: one collector in both traces, only timing differs.
# No product overlay or warm-up is needed to reach the timing assertion.
def test_stored_child_timing_control():
    from fsbudget.attribute import role_children
    fixtures = Path(__file__).parent / 'fixtures'
    passing = parse_trace((fixtures / 'b1-child-timing-passing.strace').read_text())
    moved = parse_trace((fixtures / 'b1-child-timing-before-reads.strace').read_text())
    expected = {"front": 1, "helper": 1, "collector": 0, "command": 0}
    assert role_children(passing) == role_children(moved) == expected
    assert_child_timing(passing, Path('/store'))
    with pytest.raises(AssertionError, match='snapshot'):
        assert_child_timing(moved, Path('/store'))


# Descriptors the real front hands to the helper, and the helper to the collector.
# The shell holds a pipe write end at each of these fds, without CLOEXEC.
SHELL_PIPE_FDS = (3, 4, 5, 6, 7, 8, 9, 1025)
FD_RECORDER = "bingsu-fd-record"
# The shell runs this child right before the prompt and waits for it, so the
# table it reads from /proc is the shell's table at that spawn. strace never
# sees how the fds came to be (pass_fds), so this record is the initial table.
RECORDER = """import json, os, sys
pid = sys.argv[2]
table = {}
for name in os.listdir(f"/proc/{pid}/fd"):
    flags = next(line for line in open(f"/proc/{pid}/fdinfo/{name}") if line.startswith("flags:")).split()[1]
    table[name] = [os.readlink(f"/proc/{pid}/fd/{name}"), bool(int(flags, 8) & 0o2000000)]
json.dump(table, sys.stdout)
"""
# Exit status of the shell fixture when it cannot raise its soft NOFILE above 1025.
NOFILE_BLOCKED = 97


class ShellPipes:
    """One pipe per SHELL_PIPE_FDS slot; the test keeps the read ends.

    The write ends reach bash at fds >= 100 (pass_fds) and the shell moves
    each onto its slot with `exec N>&M M>&-`: a plain redirection, no CLOEXEC."""

    def __init__(self):
        import fcntl
        self.read, self.passed, self.inode = {}, {}, {}
        for slot in SHELL_PIPE_FDS:
            r, w = os.pipe()
            high = fcntl.fcntl(w, fcntl.F_DUPFD_CLOEXEC, 100)
            os.close(w)
            assert high not in SHELL_PIPE_FDS, ("pass-through fd collides with a slot", high)
            self.read[slot], self.passed[slot], self.inode[slot] = r, high, os.fstat(r).st_ino

    def prelude(self, record):
        moves = " ".join(f"{slot}>&{high} {high}>&-" for slot, high in self.passed.items())
        return (f"_b2_n=$(ulimit -Sn)\n"
                f"if [[ $_b2_n != unlimited ]] && (( _b2_n < 1026 )); then ulimit -Sn 1026 || exit {NOFILE_BLOCKED}; fi\n"
                f"exec {moves}\n"
                f"{shlex.quote(sys.executable)} -I -c {shlex.quote(RECORDER)} {FD_RECORDER} $$ > {shlex.quote(str(record))}\n"
                ).encode()

    def close_passed(self):
        for fd in self.passed.values():
            os.close(fd)
        self.passed = {}

    def close(self):
        self.close_passed()
        for fd in self.read.values():
            os.close(fd)
        self.read = {}

    def assert_held(self, initial):
        # 이것을 실패시키는 것: fixture가 파이프를 셸에 넘기지 않거나 CLOEXEC로 두어 공허하게 통과하는 것.
        for slot in SHELL_PIPE_FDS:
            entry = initial.get(slot)
            assert entry and entry.path == f"pipe:[{self.inode[slot]}]" and not entry.cloexec, (
                "the shell must hold this pipe write end without CLOEXEC", slot, entry)


def shell_initial(record):
    import json
    from fsbudget.attribute import FdEntry
    return {int(fd): FdEntry(int(fd), path, cloexec, "inherited")
            for fd, (path, cloexec) in json.loads(Path(record).read_text()).items()}


def shell_fd_capture(stage, tmp_path):
    """(trace from the recorder's spawn on, the shell table there, fixture, pipes)
    for one traced prompt of `stage` through a bash that holds SHELL_PIPE_FDS."""
    from fsbudget.strace_parse import Trace
    assert shutil.which("strace"), "this Linux gate must execute strace"
    require_release_helper(real_bin())
    fixture = HelperStageFixture(stage)
    pipes = ShellPipes()
    try:
        record, trace_path = fixture.base / "fd-record.json", tmp_path / f"{stage}.strace"
        print(f"\nfd capture: {trace_path}")
        fixture.prompt(trace_path, prelude=pipes.prelude(record), pass_fds=tuple(pipes.passed.values()))
        initial = shell_initial(record)
        trace = parse_trace(trace_path.read_text(errors="replace"))
        assert not trace.errors, trace.errors[:5]
        shell = trace.first_pid
        recorder, = {c.pid for c in trace if c.name == "execve" and c.ret == "0" and f'"{FD_RECORDER}"' in c.args}
        spawn, = [c for c in trace if c.pid == shell and c.name in SPAWNS and c.ret.split(" ")[0] == str(recorder)]
    except BaseException:
        wait_helpers(fixture.base)
        shutil.rmtree(fixture.base, ignore_errors=True)
        raise
    finally:
        pipes.close()
    after = Trace()
    after.extend(c for c in trace if c.index > spawn.index)
    after.first_pid = shell
    return after, initial, fixture, pipes


def exec_pid(trace, path, verb):
    pids = {c.pid for c in trace if c.name == "execve" and c.ret == "0"
            and c.args.startswith(f'"{path}", ') and f'"{verb}"' in c.args}
    assert len(pids) == 1, ("one exec", path, verb, pids)
    return pids.pop()


def fd_summary(table):
    return {fd: (entry.path, entry.cloexec, entry.origin) for fd, entry in sorted(table.items())}


SPAWNED_DEV_NULL = ("/dev/null", False, "spawn-action")


def check_front_receives_shell_pipes(after, initial, pipes, exe):
    """Non-vacuity: the shell's pipes reach the front's exec, and the front marks each."""
    from fsbudget.attribute import fd_table_at_exec
    pipes.assert_held(initial)
    front = exec_pid(after, exe, "prompt")
    table = fd_table_at_exec(after, front, initial)
    for slot in SHELL_PIPE_FDS:
        assert table.get(slot) == initial[slot], ("the front must start with the shell's pipe", slot, table.get(slot))
    marked = {int(c.args.split("<")[0]) for c in after if c.pid == front and c.name == "fcntl"
              and c.args.endswith(", F_SETFD, FD_CLOEXEC") and c.ret == "0"}
    assert set(SHELL_PIPE_FDS) <= marked, ("the front's F_SETFD loop must mark every shell pipe", sorted(marked))


def helper_fd_table(after, exe, initial):
    """The helper's table at execve: fds 0-2 on the spawn's own /dev/null and
    fd 4 the read end of the front's environment pipe (pipe2 with O_NONBLOCK)."""
    from fsbudget.attribute import fd_table_at_exec
    front = exec_pid(after, exe, "prompt")
    env_pipes = [re.fullmatch(r'\[(\d+)<pipe:\[(\d+)\]>, (\d+)<pipe:\[\2\]>\], O_NONBLOCK\|O_CLOEXEC', c.args)
                 for c in after if c.pid == front and c.name == "pipe2" and c.ret == "0"
                 and c.args.endswith("O_NONBLOCK|O_CLOEXEC")]
    assert len(env_pipes) == 1 and env_pipes[0], ("one front environment pipe", env_pipes)
    inode = env_pipes[0][2]
    helper = fd_summary(fd_table_at_exec(after, exec_pid(after, exe, "__refresh-v1"), initial))
    assert helper == {**{fd: SPAWNED_DEV_NULL for fd in (0, 1, 2)},
                      4: (f"pipe:[{inode}]", False, "spawn-action")}, helper
    return helper


# 이것을 실패시키는 것: 앞단의 fcntl(F_SETFD) 루프를 건너뛰는 것(fd 3–9·1025가 도우미 exec에 남는다),
# fd 2의 addopen을 지우는 것(bash 훅의 2>/dev/null이 경로를 같게 만들어도 출처가 셸 상속이 된다),
# 환경 파이프의 adddup2를 지우는 것(fd 4가 없다), 도우미가 완전한 프레임 뒤에 EOF 읽기를 더 하는 것,
# 도우미가 fd 4를 NSS 뒤에 읽는 것(첫 open보다 늦다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_helper_fds_after_env(tmp_path):
    """GATE-FDS.1: at the helper's execve its table is exactly fds 0-2 on the
    spawn's own /dev/null and fd 4 the front's environment pipe, while the
    shell holds pipe write ends at 3-9 and 1025."""
    after, initial, fixture, pipes = shell_fd_capture("unchanged", tmp_path)
    try:
        exe = str(fixture.inst.exe)
        check_front_receives_shell_pipes(after, initial, pipes, exe)
        inode = helper_fd_table(after, exe, initial)[4][0]
        # U-9i: the helper reads the whole frame in one read and closes fd 4,
        # before its own first open (the loader's and stack guard's come before
        # main; on the cold init path there is no fd 4).
        helper = exec_pid(after, exe, "__refresh-v1")
        calls = [c for c in after if c.pid == helper and c.index > next(
            e.index for e in after if e.pid == helper and e.name == "execve")]
        on_env = [c for c in calls if args_of(c) and args_of(c)[0] == f"4<{inode}>"]
        front_write, = [c for c in after if c.name == "write" and args_of(c)[0].endswith(f"<{inode}>")]
        assert [(c.name, c.ret) for c in on_env] == [("read", front_write.ret), ("close", "0")], on_env
        first_open = next(c.index for c in calls if c.name in OPENS and not SYSTEM_PATHS.fullmatch(call_paths(c)[0]))
        assert on_env[-1].index < first_open, ("fd 4 is read before the helper opens anything", on_env)
    finally:
        wait_helpers(fixture.base)
        shutil.rmtree(fixture.base, ignore_errors=True)


# 이것을 실패시키는 것: 잠금의 adddup2 대상을 5에서 4로 바꾸는 것, collector 복사본을 F_DUPFD(CLOEXEC 없이)로
# 만들고 addclose 루프도 지우는 것(fd 7 이상이 남는다), 앞단 F_SETFD 루프를 건너뛰는 것(도우미 표에서 먼저 실패).
# 복사본 CLOEXEC와 addclose는 서로를 덮는 두 층이라 하나만 지우면 이 시험은 통과한다. addclose 하나는
# collector_process.rs의 spawn_closes_inherited_fds_outside_the_fixed_slots가 잡는다.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_live_collector_holds_only_fixed_fds(tmp_path):
    """GATE-FDS.2: at the collector's execve its table is exactly 0 and 2 on
    /dev/null, 1 the response pipe, 3 the request pipe and 5 the collection
    lock, all from the helper's spawn actions. On Linux there is no fd 6:
    the startup probe fd is macOS-only (collector.rs CollectorProbeFd)."""
    from fsbudget.attribute import fd_table_at_exec
    after, initial, fixture, pipes = shell_fd_capture("collect", tmp_path)
    try:
        exe = str(fixture.inst.exe)
        check_front_receives_shell_pipes(after, initial, pipes, exe)
        helper_fd_table(after, exe, initial)
        collector = fd_summary(fd_table_at_exec(after, exec_pid(after, fixture.collector, "__collect-v1"), initial))
        assert sorted(collector) == [0, 1, 2, 3, 5], collector
        assert collector[0] == collector[2] == SPAWNED_DEV_NULL, collector
        response, request, lock = collector[1], collector[3], collector[5]
        assert re.fullmatch(r"pipe:\[\d+\]", response[0]) and re.fullmatch(r"pipe:\[\d+\]", request[0]), collector
        assert response[0] != request[0], ("response and request are different pipes", collector)
        assert lock[0].endswith("/collection.lock"), collector
        assert response[1:] == request[1:] == lock[1:] == (False, "spawn-action"), collector
    finally:
        wait_helpers(fixture.base)
        shutil.rmtree(fixture.base, ignore_errors=True)


def env_prompt(tmp_path, env):
    """One traced prompt of a published fixture with `env` added to the
    shell's environment: (trace, fixture, front pid, helper pid)."""
    require_release_helper(real_bin())
    assert shutil.which("strace"), "this Linux gate must execute strace"
    fixture = HelperStageFixture("unchanged")
    try:
        fixture.env.update(env)
        path = tmp_path / "env.strace"
        fixture.prompt(path)
        wait_helpers(fixture.base)
        trace = parse_trace(path.read_text(errors="replace"))
        assert not trace.errors, trace.errors[:5]
        exe = str(fixture.inst.exe)
        return trace, fixture, exec_pid(trace, exe, "prompt"), exec_pid(trace, exe, "__refresh-v1")
    except BaseException:
        wait_helpers(fixture.base)
        shutil.rmtree(fixture.base, ignore_errors=True)
        raise


def env_pipe_of(trace, front):
    """The front's environment pipe: (inode, write calls on it)."""
    pipe, = [c for c in trace if c.pid == front and c.name == "pipe2" and c.args.endswith("O_NONBLOCK|O_CLOEXEC")]
    inode = re.fullmatch(r'\[\d+<(pipe:\[\d+\])>, \d+<\1>\], O_NONBLOCK\|O_CLOEXEC', pipe.args)[1]
    return inode, [c for c in trace if c.pid == front and c.name == "write" and args_of(c)[0].endswith(f"<{inode}>")]


def helper_env_reads(trace, helper, inode):
    return [c for c in trace if c.pid == helper and c.name == "read" and args_of(c)[0] == f"4<{inode}>"]


# 이것을 실패시키는 것: 환경을 도우미 envp로도 넘기는 것(도우미의 로더가 카나리를 올린다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux glibc loader")
def test_ld_preload_not_loaded_into_helper(tmp_path):
    """A shell LD_PRELOAD reaches the front's loader but never the helper's:
    the helper starts with an empty envp and gets the environment as bytes."""
    if require_release_helper(real_bin()) != "gnu":
        pytest.skip("static musl has no dynamic loader to preload into")
    canaries = tmp_path / "canaries"
    canaries.mkdir()
    library = tmp_path / "env-canary.so"
    subprocess.run(["cc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC", f'-DCANARY_DIR="{canaries}"',
                    str(ROOT / "tests/shell/fixtures/env_canary.c"), "-o", str(library)], check=True)
    trace, fixture, front, helper = env_prompt(tmp_path, {"LD_PRELOAD": str(library)})
    try:
        names = sorted(p.name.rsplit("-", 1)[0] for p in canaries.iterdir())
        # Non-vacuity: the shell's LD_PRELOAD reached the front's loader, and the helper ran.
        assert names == ["prompt"], names
        inode, _ = env_pipe_of(trace, front)
        reads = helper_env_reads(trace, helper, inode)
        assert len(reads) == 1 and "LD_PRELOAD=" in reads[0].args, ("the entry still reaches the helper as bytes", reads)
        # Positive control: the same library given to the helper through envp is loaded there.
        direct = subprocess.run([str(fixture.inst.exe), "__refresh-v1", "--ctx", "1", "--record", "B1"],
                                env={"LD_PRELOAD": str(library)}, capture_output=True, timeout=10)
        assert direct.returncode != 0
        assert sorted(p.name.rsplit("-", 1)[0] for p in canaries.iterdir()) == ["__refresh-v1", "prompt"]
    finally:
        shutil.rmtree(fixture.base, ignore_errors=True)


# 이것을 실패시키는 것: 도우미가 환경의 XDG_RUNTIME_DIR로 위치를 정하는 것(그 폴더를 연다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_helper_ignores_xdg_runtime_dir_from_env(tmp_path):
    """The environment never decides a location: with XDG_RUNTIME_DIR pointing
    into a repository, the helper names no path under it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    trace, fixture, front, helper = env_prompt(tmp_path, {"XDG_RUNTIME_DIR": str(repo)})
    try:
        inode, writes = env_pipe_of(trace, front)
        reads = helper_env_reads(trace, helper, inode)
        # Non-vacuity: the value reached the helper, as frame bytes.
        assert len(reads) == 1 and f"XDG_RUNTIME_DIR={repo}" in reads[0].args, reads
        # Neither the front nor the helper names the folder outside the frame itself.
        named = [c for c in trace if str(repo) in c.args and c not in reads and c not in writes]
        assert named == [], named
    finally:
        shutil.rmtree(fixture.base, ignore_errors=True)


# 이것을 실패시키는 것: 앞단 프레임의 상한 검사를 지우는 것(70 KB 프레임을 쓰고 일부만 들어간다).
# 설정 단위 실행 0은 감독(C2)이 생긴 뒤에 단언한다.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_oversize_env_block_means_no_env(tmp_path):
    """A 70 KB environment: the front writes nothing and the helper reads end
    of file, which is no environment for the round."""
    trace, fixture, front, helper = env_prompt(tmp_path, {"BINGSU_BIG": "x" * (70 * 1024)})
    try:
        inode, writes = env_pipe_of(trace, front)
        assert writes == [], writes
        reads = helper_env_reads(trace, helper, inode)
        assert [c.ret for c in reads] == ["0"], reads
    finally:
        shutil.rmtree(fixture.base, ignore_errors=True)


# How long after the shell exits its pipes must reach EOF. The helper lives
# 2 s (helper_limits LIFETIME); a helper holding a pipe keeps it open until then.
SHELL_EOF_WAIT_S = 0.5


# 이것을 실패시키는 것: 앞단의 fcntl(F_SETFD) 루프를 건너뛰는 것(막힌 도우미가 쓰지 않는 파이프를 쥐어
# EOF가 도우미 종료까지 오지 않는다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux FUSE fixture")
def test_shell_pipe_reaches_eof_while_helper_is_alive(tmp_path):
    """GATE-HELPER-LIFETIME.2: the helper never holds the shell's descriptors.

    The config root sits on a FUSE mount whose daemon is stopped, so the
    prompt's helper waits there. The shell holds pipe write ends at 3-9 and
    1025 and exits right after the prompt: every read end, and the shell's
    stdout and stderr, must reach EOF while that helper is still alive."""
    import select
    import time
    from blocked_mount import blocked_mount
    from shell_support import Blocked
    base = tmp_path / "s"
    base.mkdir(mode=0o700)
    session = {}

    def prepare(mount):
        env = trusted_env(base)
        env["HOME"] = str(base / "home-t")
        os.mkdir(env["HOME"], 0o700)
        env["XDG_CONFIG_HOME"] = str(mount / "cfg")
        config = mount / "cfg" / "bingsu"
        config.mkdir(parents=True, mode=0o700)
        (config / "config.toml").write_text(TEMPLATES["plain"])
        (config / "config.toml").chmod(0o600)
        script = Install(base).init("bash", env)
        wait_helpers(base)
        session.update(env=env, script=script)

    try:
        with blocked_mount(tmp_path / "fuse", prepare=prepare):
            pipes = ShellPipes()
            shell = None
            try:
                record = base / "fd-record.json"
                f = base / "prompt.bash"
                f.write_bytes(bash_prompt_script(session["script"], base, 2, pipes.prelude(record)))
                shell = subprocess.Popen(SHELL_CMD["bash"] + [str(f)], env=session["env"], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         pass_fds=tuple(pipes.passed.values()))
                pipes.close_passed()
                status = shell.wait(timeout=10)
                exited = time.monotonic()
                if status == NOFILE_BLOCKED:
                    raise Blocked("the shell cannot raise its soft NOFILE above 1025")
                pending = {f"fd {slot}": fd for slot, fd in pipes.read.items()}
                pending.update(stdout=shell.stdout.fileno(), stderr=shell.stderr.fileno())
                output = {name: b"" for name in pending}
                while pending and (left := exited + SHELL_EOF_WAIT_S - time.monotonic()) > 0:
                    ready, _, _ = select.select(list(pending.values()), [], [], left)
                    for name, fd in list(pending.items()):
                        if fd in ready:
                            data = os.read(fd, 65536)
                            output[name] += data
                            if not data:
                                del pending[name]
                helpers = helper_processes(base)
                assert not pending, ("no EOF within the wait: something alive holds the shell's descriptors",
                                     sorted(pending), helpers)
                # 이것을 실패시키는 것: 도우미가 이미 끝난 뒤에 EOF를 보고 통과하는 것(막힌 도우미가 없으면 공허하다).
                assert helpers, "the prompt's helper is not alive on the blocked mount: the EOF proves nothing"
                assert status == 0, (status, output["stderr"])
                pipes.assert_held(shell_initial(record))
            finally:
                for pid in helper_processes(base):
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                wait_helpers(base)
                if shell is not None:
                    shell.stdout.close()
                    shell.stderr.close()
                pipes.close()
    except Blocked as error:
        pytest.fail(f"BLOCKED: {error.reason}", pytrace=False)


SESSION_SCRIPT = b": \"${_bingsu_session:=0123456789abcdef0123456789abcdef}\"\n"


def session_parent_name(runtime):
    root = os.stat(runtime)
    key = (root.st_dev.to_bytes(8, "little") + root.st_ino.to_bytes(8, "little") + b"\0"
           + b"0123456789abcdef0123456789abcdef")
    return f"bingsu-cmd-{hashlib.sha256(key).digest()[:16].hex()}"


# 위임된 cgroup에서는 이 세션의 정확한 부모만 원자 경로의 근거다. 이것을 실패시키는 것: 같은 uid의 다른
# bingsu-cmd-* 폴더를 받는 것, 부모가 없는 위임 셀을 best effort로 세는 것, 특권 셀에서 위임 없음을 받는 것,
# 쓸 수 없는 폴더나 읽기 전용 마운트를 위임으로 보는 것, 정확한 이름의 symlink를 부모로 받는 것.
@pytest.mark.parametrize("case", ["exact", "other", "missing", "priv-undelegated", "undelegated",
                                  "read-only", "symlink"])
def test_session_cgroup_parent_needs_this_sessions_parent(case, tmp_path, monkeypatch):
    own, runtime = tmp_path / "own", tmp_path / "runtime"
    own.mkdir()
    runtime.mkdir()
    monkeypatch.delenv("BINGSU_CGROUP_CELL", raising=False)
    if case == "exact":
        (own / session_parent_name(runtime)).mkdir()
        assert session_cgroup_parent(SESSION_SCRIPT, runtime, own) is True
        return
    if case == "other":
        (own / "bingsu-cmd-00112233445566778899aabbccddeeff").mkdir()
    if case == "symlink":
        (tmp_path / "elsewhere").mkdir()
        (own / session_parent_name(runtime)).symlink_to(tmp_path / "elsewhere")
    if case == "read-only":
        # Writable by permission bits, but on a read-only mount: not delegated.
        flags = type("S", (), {"f_flag": os.ST_RDONLY})()
        monkeypatch.setattr(os, "access", lambda *_: True)
        monkeypatch.setattr(os, "statvfs", lambda *_: flags)
        assert session_cgroup_parent(SESSION_SCRIPT, runtime, own) is False
        return
    if case in ("priv-undelegated", "undelegated"):
        monkeypatch.setattr(os, "access", lambda *_: False)
        if case == "undelegated":
            assert session_cgroup_parent(SESSION_SCRIPT, runtime, own) is False
            return
        monkeypatch.setenv("BINGSU_CGROUP_CELL", "priv")
    with pytest.raises(AssertionError):
        session_cgroup_parent(SESSION_SCRIPT, runtime, own)



# 이것을 실패시키는 것: 사용자 줄 뒤에 남은 바이트가 있을 때 seek를 0으로 보는 것, 줄이 버퍼 끝(1024·2048)이나 파일
# 끝일 때 1로 보는 것(줄 끝 < 파일 크기로만 판정), glibc에 musl 항을 주는 것.
def test_passwd_seeks_follow_musl_stdio():
    root = b"root:x:0:0:root:/root:/bin/bash\n"
    rest = b"".join(b"u%d:x:%d:%d::/h:/bin/sh\n" % (i, 1000 + i, 1000 + i) for i in range(60))
    data = root + rest
    assert passwd_seeks("musl", 0, data) == 1                    # root first: the rest is buffered
    last = 1000 + 59
    assert passwd_seeks("musl", last, data) == 0                 # the last line: nothing left
    # A line that ends exactly where a 1 KiB read ends leaves nothing in the
    # buffer even with data after it; one that ends inside the last, partial
    # buffer leaves the rest of it.
    for edge in (1024, 2048):
        line = b"u:x:5:5:" + b"y" * (edge - len(b"u:x:5:5:") - 2) + b":\n"
        assert len(line) == edge
        assert passwd_seeks("musl", 5, line + b"after:x:6:6::/h:/bin/sh\n") == 0, edge
    partial = root + b"p:x:7:7::/h:/bin/sh\n" + b"tail:x:8:8::/h:/bin/sh\n"
    assert len(partial) < 1024
    assert passwd_seeks("musl", 7, partial) == 1                 # ends inside the buffer, data after
    assert passwd_seeks("gnu", 0, data) == 0


# 이것을 실패시키는 것: 링크를 따라가지 않는 것(gnutrue 같은 대상의 hop을 0으로 셈), 다른 폴더·`.`·`..`·고리·끊어진
# 링크·폴더로 끝나는 링크·제품 상한을 넘는 hop을 받는 것.
def test_target_links_count_same_folder_hops(tmp_path):
    (tmp_path / "real").write_bytes(b"x")
    (tmp_path / "mid").symlink_to("real")
    (tmp_path / "name").symlink_to("mid")
    assert target_links(str(tmp_path / "real")) == 0
    assert target_links(str(tmp_path / "name")) == 2
    (tmp_path / "away").symlink_to(tmp_path / "real")
    (tmp_path / "self").symlink_to("self")
    (tmp_path / "a").symlink_to("b")
    (tmp_path / "b").symlink_to("a")
    (tmp_path / "dot").symlink_to(".")
    (tmp_path / "up").symlink_to("..")
    (tmp_path / "broken").symlink_to("missing")
    (tmp_path / "folder").mkdir()
    (tmp_path / "to-folder").symlink_to("folder")
    for shape in ("away", "self", "a", "dot", "up", "broken", "to-folder", "folder"):
        with pytest.raises(AssertionError):
            target_links(str(tmp_path / shape))
    previous = "real"
    for i in range(TARGET_LINKS_MAX + 1):
        (tmp_path / f"h{i}").symlink_to(previous)
        previous = f"h{i}"
    assert target_links(str(tmp_path / f"h{TARGET_LINKS_MAX - 1}")) == TARGET_LINKS_MAX
    with pytest.raises(AssertionError):
        target_links(str(tmp_path / f"h{TARGET_LINKS_MAX}"))


# GATE-FS-FRONT command response shapes (C4b, U-9h as revised by C4b ruling Q1):
# the prompt prefetches `command` with the collection responses before the
# filter and reads it after the filter only when the snapshot draws a command
# segment. A store without the file costs one ENOENT open; a file the snapshot
# does not draw costs its open and facts and one unread close, also when only
# a wider band than this prompt's width draws it (unread_narrow); a drawn one
# adds its header and body reads.
COMMAND_FRONT_SHAPES = ("no_response", "unread", "unread_narrow", "read")


def front_calls(lines, exe):
    """The prompt process's calls of a traced prompt and its filter boundary."""
    from fsbudget.strace_parse import Trace
    _, scoped = tree(lines, exe)
    root = int(next(line.split()[0] for line in scoped if is_root(line, exe)))
    parsed = parse_trace("\n".join(scoped))
    assert not parsed.errors, parsed.errors
    front = Trace()
    front.extend(c for c in parsed if c.pid == root and c.name != EXIT_EVENT)
    filters = [c.index for c in front if c.name == "prctl" and "PR_SET_SECCOMP" in c.args and c.ret == "0"]
    assert len(filters) == 1, filters
    return front, filters[0]


# 이것을 실패시키는 것: command 사본을 prefetch에서 빼는 것(no_response의 ENOENT 1이 없음), 그리지 않는 응답을
# 읽는 것(unread에 read가 생김), 넓은 구간에만 있는 command를 좁은 폭에서 읽는 것(unread_narrow에 read가 생김),
# 열어 둔 사본을 닫지 않는 것(unread의 close 1이 없음), 그리는 응답을 끝까지 읽지 않는 것(read의 머리·본문 읽기
# 수가 식과 다름).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("shape", COMMAND_FRONT_SHAPES)
def test_live_front_command_response_shapes(shape, tmp_path):
    from fsbudget.formula import collection_front_expected
    assert shutil.which("strace"), "the front gate must execute strace"
    require_release_helper(real_bin())
    stage = {"no_response": "collect", "unread": "command_hit", "unread_narrow": "command_hit",
             "read": "command_hit"}[shape]
    fixture = HelperStageFixture(stage)
    try:
        if shape in ("unread", "unread_narrow"):
            # The unit stays declared and its response stays; the screen at
            # this width no longer draws it. Publish that snapshot first.
            fixture.put("command_not_run" if shape == "unread" else "command_wide")
            fixture.prompt()
            wait_helpers(fixture.base)
        trace = tmp_path / "trace.strace"
        fixture.prompt(trace)
        wait_helpers(fixture.base)
        lines = trace.read_text(errors="replace").splitlines()
        front, boundary = front_calls(lines, str(fixture.inst.exe))
        pinned = [os.path.realpath(Path(fixture.env[key]) / "bingsu")
                  for key in ("XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME")]
        cwd = os.fsencode(str(fixture.pwd))
        counts = assert_collection_trace(front, boundary, pinned, cwd, required=True)
        command_opens = [c for c in front if c.name == "openat" and call_paths(c)
                         and call_paths(c)[0].endswith("/store/command")]
        assert len(command_opens) == 1, command_opens
        opened = command_opens[0]
        fd = re.match(r"(\d+)", opened.ret)
        closes = [c for c in front if c.name == "close" and fd and args_of(c)[0].split("<")[0] == fd.group(1)
                  and c.index > opened.index]
        reads = [c for c in front if c.name == "read" and fd and args_of(c)[0].split("<")[0] == fd.group(1)
                 and c.index > opened.index]
        if shape == "no_response":
            assert opened.ret.startswith("-1 ENOENT"), opened
            return
        size = (fixture.response.stat().st_size if hasattr(fixture, "response") else
                next((fixture.store / "collections-v1").glob("*/store/command")).stat().st_size)
        assert fd and closes and closes[0].index > boundary, ("one close after the filter", closes)
        if shape in ("unread", "unread_narrow"):
            assert reads == [], reads
        else:
            assert len(reads) == 1 + -(-(size - 64) // 16_384), (size, reads)
        sizes = {}
        for name in ("response", "previous", "command"):
            files = list((fixture.store / "collections-v1").glob(f"*/store/{name}"))
            sizes[name] = files[0].stat().st_size if files else None
        body = (size - 64,) if shape == "read" else ()
        assert counts == collection_front_expected(3, (sizes["response"], sizes["previous"], sizes["command"]),
                                                   body), counts
    finally:
        wait_helpers(fixture.base)
        shutil.rmtree(fixture.base, ignore_errors=True)
