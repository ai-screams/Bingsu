"""F-01 / X-06: at prompt time HOME, USER, XDG_* and BINGSU_LOG point into a
repository; the hook must still pass only the roots pinned by init, and the
binary (with every process and thread it starts) must touch nothing under
the repository."""
import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, SHELL_CMD, Install, minimal_record, short_dir, trusted_env
from pty_session import Session

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import EXIT_EVENT, parse as parse_trace, scan

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
HOSTILE_VARS = ["HOME", "USER", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CACHE_HOME", "BINGSU_LOG"]
CALL = b"_bingsu_call --width 80\n"


def pinned_roots(trusted):
    """The root words and original config spelling init pins for `trusted` (same rule as test_init_words)."""
    run_root = os.path.realpath(trusted["XDG_RUNTIME_DIR"] + "/bingsu")
    st = os.stat(run_root)
    return {
        b"--runtime-root=": f"--runtime-root={st.st_dev}:{st.st_ino}:{run_root}".encode(),
        b"--config-root-written=": b"--config-root-written=" + (trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--config-root=": b"--config-root=" + os.path.realpath(trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--state-root=": b"--state-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu").encode(),
        b"--log-root=": b"--log-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu/log").encode(),
    }


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
            and (words == [exe, verb] if verb == "__collect-v1" else words[:2] == [exe, verb])
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


def prompt_open(call, path, pinned, root):
    if call.name != "openat":
        return False
    args = args_of(call)
    flags = open_flags(args[2])
    dirs, files = prompt_sources(pinned)
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


def prompt_root_io(front, boundary, exe, pinned, root):
    """Track the root's prepared fds. No path operation survives the filter.

    Real N3 and N4 captures cover helper publication and first-prompt fallback.
    Linux CI must also capture successful current/last-good and refused-file reads.
    """
    held = {}
    acl_fallback = set()
    fs_observed = set()
    _, files = prompt_sources(pinned)
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
            assert (system or bootstrap or acl_ok or empty_stat or prompt_open(c, path, pinned, root)
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
                held[fd] = (paths[0], prompt_open(c, paths[0], pinned, root))
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


def assert_prompt_trace_budget(lines, exe, pinned):
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
    prompt_root_io(front, filters[0].index, exe, pinned, root)
    # 이것을 실패시키는 것: helper 하위 트리에 새 syscall, 임의 자식/exec, 외부 네트워크를 더하는 것.
    assert all(c.name in HELPER_CALLS for c in helper), [c for c in helper if c.name not in HELPER_CALLS]
    # M3a collector exec: exactly the pinned executable and __collect-v1,
    # no additional argv and an empty environment. It precedes confinement.
    collectors = [c for c in execs if c.pid != helper_pid]
    assert len(collectors) <= 1 and all(fixed_exec(c, exe, "__collect-v1") for c in collectors), collectors
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
        assert len(processes) <= (1 if pid == helper_pid else 0), processes
        assert all(int(c.ret) in {x.pid for x in collectors} for c in processes), processes
        children.extend(int(c.ret) for c in made)
    assert set(map(int, pids)) == {root, helper_pid, *children}, ("unbudgeted child", pids)
    created = set()
    exe_walks = {pid: HelperExecutableWalk(exe) for pid in owners}
    for c in helper:
        exe_walk = exe_walks[c.pid]
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


# 이것을 실패시키는 것: prompt가 시스템 경로와 init이 박은 네 뿌리 밖의 경로를 건드리는 것 —
# 상대 경로("x", Path::exists 포함), 환경 변수가 가리키는 폴더(repo 아래), 현재 폴더, 그 접근을 스레드나 자식 프로세스에서 하는 것.
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace (Linux) not available")
def test_prompt_binary_names_only_allowed_system_paths_and_pinned_roots(tmp_path):
    """Every path argument of every traced call (open, stat, rename, link,
    ...) of the binary and its threads and children. SYSTEM_PATHS was
    observed on Debian and Ubuntu glibc (aarch64, the three test images) and
    takes the loader paths of Fedora (/lib64), Arch (/usr/lib) and Alpine
    (/lib/ld-musl-*.so.1) by its shape; the CI musl build on x86_64
    also spawns the fixed helper before its filter. NixOS and Guix
    (/nix/store, /gnu/store) are not covered and fail here."""
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    script = inst.init("bash", trusted)
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
    assert_prompt_trace_budget(trace.read_text(errors="replace").splitlines(), exe, pinned)


TABLE_SYSCALLS = {r[0] for r in _ROWS if r[0] != "-"}


# 이것을 실패시키는 것: 필터 뒤에 표에 없는 호출이 필요한 것(이 환경의 할당자·unwind가 부르는 호출을 표에서 빠뜨림),
# 정상 프롬프트에서 호출이 EPERM으로 거부되는 것.
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace (Linux) not available")
@pytest.mark.parametrize("pwd", ["/srv/p", "/" + "a/" * 32767])
def test_calls_after_the_filter_are_in_the_table(tmp_path, pwd):
    """Every call the prompt makes after its seccomp filter is installed
    (strace -e trace=all, from the PR_SET_SECCOMP line on) is a row of the
    table, and none is refused: the table is complete for this libc and
    allocator. LD_PRELOAD in the environment (an allocator under test) is
    passed through."""
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
