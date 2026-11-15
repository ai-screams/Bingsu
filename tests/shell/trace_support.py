"""The strace budget checker the prompt, helper and collector traces are judged by:
reading a trace into calls, classifying each call, the allowlists and the
per-stage budgets, and the fixtures that build helper and front captures.
`test_prompt_env_paths.py` runs it on live captures and
`test_prompt_trace_budget.py` on recorded and synthetic ones; neither holds
a copy."""
import ast
import hashlib
import os
import platform
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from shell_support import ROOT, SHELL_CMD, Install, real_bin, trusted_env

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import EXIT_EVENT, parse as parse_trace, scan


CALL = b"_bingsu_call --width 80\n"


def init_collector_exe(script):
    # This bash fixture uses plain paths; consume init's quoted pin, not the
    # build location or a sibling guessed from the symlink used to run init.
    pins = re.findall(rb"'--collector-exe=([^']*)'", script)
    assert len(pins) == 1, ("exactly one init collector pin", pins)
    path = os.fsdecode(pins[0])
    assert path.startswith("/") and os.path.normpath(path) == path, path
    assert os.path.basename(path) == "bingsu-collect", path
    return path


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


# What the dynamic loader and Rust's start-up name (glibc, observed in the
# three images on 2026-10-05): the loader cache and preload list, the
# libraries, and /proc/self/maps (main-thread stack guard). The static musl
# build names none of them.
SYSTEM_PATHS = re.compile(r"^/etc/ld\.so\.(cache|preload)$|^/(usr/)?lib(64)?/.+\.so(\.\d+)*$|^/proc/self/maps$")


OPENS = {"openat", "openat2", "open"}


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
    # The shared creator and runtime publication/collector staging use only
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
COMMAND_HEADER = b"BNGCMD02\x02\x00"


COMMAND_RESPONSE_MAX = 505_370


def assert_prompt_trace_budget(lines, exe, pinned, *, global_inputs=(), collector_exe=None,
                               collectors=None, repository_roots=None, repository_evidence=(), platform=None,
                               front_deadline=False, headers=RESPONSE_HEADERS, entry="cli", helper_exe=None):
    """`collectors` is the exact count a live capture arranged; stored traces
    leave it None and may hold at most one. With `repository_roots`, a
    collector's calls after its request are audited by assert_repository_trace
    in shipped mode against exactly those roots (the bootstrap stays with
    collector_attribute). `repository_evidence` names files the collector must
    read (non-empty) inside that window. `platform`, an (arch, libc) pair,
    admits that platform's exact libc start-up primitives (STARTUP_PRIMITIVES,
    musl's O_CLOEXEC fcntl); stored traces leave it None. `front_deadline`
    judges a front that SIGALRM ended before its filter (deadline_shape):
    no filter and no record, every front call held to the pre-filter rules.
    `entry` is the prompt entry the trace ran: "cli" (`bingsu prompt`, its
    own helper; stored traces) or "dedicated" (`bingsu-prompt`, whose helper
    is the hook's `--helper-exe=` path, `helper_exe`)."""
    from fsbudget.attribute import assert_repository_trace, collector_attribute
    helper = trace_helper(exe, entry, helper_exe)
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
    roles = collector_attribute(scoped, {"front": exe, "helper": helper,
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
                                front_deadline=front_deadline, headers=headers, entry=entry, helper_exe=helper)


def trace_helper(front, entry, helper_exe):
    """The helper a traced front may start: itself for the cli entry; for the
    dedicated entry only the hook's `--helper-exe=` path, never itself (it
    starts no helper without that word)."""
    # 이것을 실패시키는 것: 전용 front가 helper 경로 없이 자기 자신을 helper로 띄우는 trace를 받는 것.
    if entry == "cli":
        return front
    assert entry == "dedicated" and helper_exe and helper_exe != front, ("dedicated helper", entry, front, helper_exe)
    return helper_exe


def assert_historical_prompt_trace_budget(lines, exe, pinned):
    """Archived captures retain the previous fixed-stub allowance."""
    _assert_prompt_trace_budget(lines, exe, pinned, collector_limit=1)


def _assert_prompt_trace_budget(lines, exe, pinned, collector_limit, global_inputs=(),
                                collector_exe=None, check_collection=False, audited_collector=None, platform=None,
                                front_deadline=False, headers=RESPONSE_HEADERS, entry="cli", helper_exe=None):
    helper_exe = trace_helper(exe, entry, helper_exe)
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
    assert len(refresh) == 1 and fixed_exec(refresh[0], helper_exe, "__refresh-v1"), refresh
    # With CLONE_VFORK, exec has released the parent, but strace can print
    # the child's execve *resumed* line after the parent's prctl. Compare
    # entry lines, not the parser's completion order, across these two PIDs.
    exec_entry = next(i for i, line in enumerate(scoped)
                      if line.split()[0] == str(helper_pid) and is_root(line, helper_exe))
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
    collector_path = collector_exe or helper_exe
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
    exe_walks = {pid: HelperExecutableWalk(helper_exe) for pid in owners}
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
            walk_roots = [*pinned, helper_exe, *exe_walk.roots]
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
                    or allowed(path, c.args, helper_exe, pinned, allow_walk=False)), ("helper path", c, path)
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


def judge_allowlist(cap, shape=None):
    """The whole allowlist judgment of one capture. A deadline shape waives
    only what that deadline prevents: collector-deadline the repository
    evidence; front-alarm the front's filter and record, the exact collector
    count and both coverage checks; admission-deferred the repository evidence
    and the global inputs' check, with exactly no collector. Every path, call
    and audit rule stays."""
    assert_prompt_trace_budget(cap.lines, cap.exe, cap.pinned, global_inputs=cap.global_inputs,
                               collector_exe=cap.collector_exe,
                               # Stored captures predate bingsu-prompt: the cli entry.
                               entry=getattr(cap, "entry", "cli"), helper_exe=getattr(cap, "helper_exe", None),
                               collectors=None if shape == "front-alarm" else 0 if shape == "admission-deferred"
                               else cap.collectors,
                               repository_roots=cap.roots,
                               repository_evidence=() if shape else cap.evidence,
                               platform=cap.platform, front_deadline=shape == "front-alarm",
                               headers=getattr(cap, "headers", RESPONSE_HEADERS))
    if cap.collectors and shape not in ("front-alarm", "admission-deferred"):
        assert_global_inputs_exercised(cap.lines, cap.exe, cap.global_inputs, cap.global_present)


def deadline_shape(cap):
    """Which deadline, if any, the trace proves.

    front-alarm: the front took SIGALRM and then made only rt_sigreturn calls
    up to exit_group(0), with no filter installed (strace can stretch its
    vfork past the deadline). collector-deadline: the collector exited 75
    before its evidence read, a non-empty read of the case's .git/HEAD (its
    request deadline came first). admission-deferred: no collector, and the
    helper deferred the collection under load (`admission_deferred`). The
    partial window is still audited in full; only the missing evidence (and,
    deferred, the collector) is waived.
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
    elif cap.collectors and admission_deferred(scoped, cap.collector_exe):
        return "admission-deferred"
    return None


# An attempt whose collection the helper deferred: at most this many retries.
DEFERRED_ATTEMPTS = 3


def admission_deferred(scoped, collector_exe):
    """The helper reached the collection and deferred it under load: it
    verified the collector pin (opened it and read its header), took the GC
    lock, then exited 0 with no collector spawned, whether or not it had
    opened a collection store (the admission's budget, a busy worker lock or
    the breaker can each defer it). A helper that never reaches the
    collection (no pin check or no GC lock) is not this shape."""
    if any(is_root(line, collector_exe) for line in scoped):
        return False
    helpers = {line.split()[0] for line in scoped if '"__refresh-v1"' in line and "execve(" in line}
    if len(helpers) != 1:
        return False
    pid, = helpers
    mine = [line for line in scoped if line.split()[0] == pid]
    name = os.path.basename(collector_exe)
    pin = next((m[1] for line in mine
                if (m := re.search(rf'openat\(\d+<[^>]*>, "{re.escape(name)}", O_RDONLY\|O_NONBLOCK\|O_NOFOLLOW\|O_CLOEXEC\) = (\d+)<', line))),
               None)
    # 이것을 실패시키는 것: pin 확인(open과 header read), GC 잠금, exit 0 중 하나를 보지 않는 것.
    checked = pin is not None and any(re.search(rf"pread64\({pin}<[^>]*{re.escape(name)}>", line) for line in mine)
    gc_lock = any('".collections.gc.lock"' in line and not re.search(r"= -1 ", line) for line in mine)
    return checked and gc_lock and mine[-1].endswith("+++ exited with 0 +++")


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
                # 이것을 실패시키는 것: 미뤄진 수집을 DEFERRED_ATTEMPTS번 넘게 다시 도는 것(늘 미루는 회귀를 놓침).
                if shape == "admission-deferred" and shapes[shape] > DEFERRED_ATTEMPTS:
                    pytest.fail(f"{label}: the collection was deferred {shapes[shape]} times")
                continue
            return attempt, shapes
        pytest.fail(f"{label}: no attempt without a deadline in {limit}; shapes {dict(shapes)}")
    finally:
        print(f"{label} attempts: {attempt}, deadline shapes: {dict(shapes)}")


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
                 "command_not_run": ("unchanged", "command_not_run"),
                 "builtin_probe": ("unchanged", "collect", "builtin_probe"),
                 "builtin_fast": ("unchanged", "collect", "builtin_fast")}


COMMAND_PATH = "/usr/bin"


TEMPLATES = {"plain": "[style]\ntemplate='BASE {char}'\n", "edited": "[style]\ntemplate='EDIT {char}'\n",
             "collect": "[style]\ntemplate='BASE {dir} {git} {char}'\n", "broken": "[broken"}


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


# A collect fixture's untraced warm-up: at most this many prompts.
COLLECT_WARMUP_MAX = 10


def warm_until(prompt, ready, *, least, most):
    """Run `prompt` `least` times, then on until `ready()` holds, at most
    `most` times in all; returns how many ran. Past `most` the caller's own
    assertion on the state fails."""
    # 이것을 실패시키는 것: least 전에 멈추는 것, ready를 보지 않고 멈추는 것, most를 넘어 도는 것.
    ran = 0
    while ran < most:
        prompt()
        ran += 1
        if ran >= least and ready():
            break
    return ran


def collect_files(store, runtime):
    """The collection stores and session breakers a collect warm-up leaves."""
    return (list((store / "collections-v1").glob("*/store")),
            list((runtime / "collection-control-v1/sessions").glob("*/breaker")))


def collect_ready(store, runtime):
    """A collect warm-up is done when it left a store and a breaker."""
    stores, breakers = collect_files(store, runtime)
    return bool(stores) and bool(breakers)


# A command stage's untraced warm-up: at most this many prompts.
COMMAND_WARMUP_MAX = 10


def command_ready(store):
    """A command warm-up is done when a command response is stored."""
    return bool(list((store / "collections-v1").glob("*/store/command")))


def stage_warmup(stage, prompt, store, runtime):
    """HelperStageFixture's untraced warm-up for `stage`; returns the prompts run."""
    command, builtin = stage.startswith("command_"), stage.startswith("builtin_")
    if stage == "collect" or builtin:
        warm = warm_until(prompt, lambda: collect_ready(store, runtime), least=3, most=COLLECT_WARMUP_MAX)
        print(f"collect warm-up prompts: {warm}")
    elif command and stage != "command_not_run":
        warm = warm_until(prompt, lambda: command_ready(store), least=2, most=COMMAND_WARMUP_MAX)
        print(f"command warm-up prompts: {warm}")
    else:
        warm = warm_until(prompt, lambda: True, least=2 if command else 1, most=2 if command else 1)
    return warm


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


class HelperStageFixture:
    """Real init, warm-up prompts and one traced prompt for a helper stage.

    The base lives next to the build output, not under /tmp: a group- or
    world-writable ancestor makes every trust walk add ACL and group queries
    the stage formula does not include, so the fixture refuses one.
    """

    def __init__(self, stage, *, template=None, config="plain", entry="cli"):
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
        builtin = stage.startswith("builtin_")
        self.put("collect" if stage == "collect" else stage if command or builtin else config, template=template)
        if command:
            self.env["PATH"] = COMMAND_PATH
        self.tools = None
        if builtin:
            self.tools = folder_outside_repository(Path.home(), "bingsu-builtin-tools-")
            # The language's folder first; the shell itself comes from /usr/bin.
            if stage == "builtin_probe":
                self.env["PATH"] = f"{self.tools / 'bin'}:{COMMAND_PATH}"
                self.language = builtin_install(self.tools / "bin", "node")
            else:
                self.env["PATH"] = COMMAND_PATH
                self.language = pyenv_layout(self.tools, self.env)
        # The helper-stage formulas count the `bingsu prompt` front; the helper
        # is the same process under either entry. child_capture traces the
        # `bingsu-prompt` front ("dedicated").
        self.script = self.inst.init("bash", self.env, entry=entry)
        self.collector = init_collector_exe(self.script)
        wait_helpers(self.base)
        self.pwd = self.base
        self.shell_root = None
        if stage == "collect" or builtin:
            # The collector's discovery walks the shell's folder from "/" within
            # its 5 ms stage budget (budget::A_MS), five traced calls a level:
            # next to the build output it is eight names deep on a CI runner,
            # under a shallow folder of the home folder four, as in the local
            # containers. Only collect and builtin stages: command stages scan
            # the shell's folder too and keep the one they were measured with.
            self.shell_root = folder_outside_repository(Path.home(), "bingsu-stage-shell-")
            self.pwd = self.shell_root / "repo"
            self.pwd.mkdir()
            subprocess.run(["git", "init", "-q", str(self.pwd)], check=True, env={"PATH": os.environ["PATH"]})
            (self.pwd / "a").write_text("x")
            if stage == "builtin_fast":
                (self.pwd / ".python-version").write_text("3.12.1\n")
        self.store = context_store(self.env["XDG_RUNTIME_DIR"], os.path.realpath(self.config),
                                   os.path.realpath(Path(self.env["XDG_STATE_HOME"]) / "bingsu"))
        runtime = Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"

        def prompt_and_wait():
            self.prompt()
            wait_helpers(self.base)
        # The first prompts publish and, for collect, admit and store a response
        # untraced: under strace a cold admission can exceed its 20 ms budget,
        # and on a slow runner so can an untraced one, so collect goes on past
        # its three prompts until the store and the breaker are there.
        # Command stages: the first round publishes the snapshot, the second
        # leaves the unit's response (and the session cgroup parent); a slow
        # runner can defer that round, so a stage that runs its unit goes on
        # until the response is there. Builtin stages warm as collect does:
        # their round needs the stored answer.
        stage_warmup(stage, prompt_and_wait, self.store, runtime)
        assert (self.store / "snapshot").is_file(), "warm-up did not publish"
        # The GC stats every session lock's name (m6-C4a7); the warm-up left
        # this session's, if its config has command units.
        self.session_locks = len(list(runtime.glob("command-*.lock")))
        self.collection = {}
        if stage == "collect" or builtin:
            stores, breakers = collect_files(self.store, runtime)
            assert len(stores) == len(breakers) == 1, ("one store and breaker after warm-up", stores, breakers)
            sizes = warm_collection_previous(stores[0], self.prompt, lambda: wait_helpers(self.base))
            self.collection = {"catalog_bytes": (runtime / ".collections.catalog").stat().st_size,
                               "breaker_bytes": breakers[0].stat().st_size,
                               **sizes,
                               "collector_components": path_names(Path(self.collector).parent),
                               "collector_bytes": Path(self.collector).stat().st_size}
        self.command = {}
        if command or builtin:
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
                            "path_names": sum(path_names(f) for f in self.env["PATH"].split(":")) if builtin
                            else path_names(COMMAND_PATH),
                            "target_names": path_names(self.language.parent if stage == "builtin_probe" else
                                                       self.tools / "pyenv" / "shims") if builtin
                            else path_names("/usr/bin"),
                            "target_links": target_links("/usr/bin/true") if stage == "command_miss" else 0,
                            # The repository scan walks the shell's folder by its names
                            # : a canonical folder, so no link is followed.
                            "shell_names": path_names(self.pwd)}
            assert os.path.realpath(self.pwd) == str(self.pwd), ("a canonical shell folder", self.pwd)
            if builtin:
                # One catalog: the collection's (the same file, read once).
                assert self.command.pop("catalog_bytes") == self.collection["catalog_bytes"]
                # The probe's node is no manager's: classify stats each shim
                # home bingsu knows (version_manager::unsupported: asdf,
                # mise's data folder and /usr/local/share/mise, volta, nodenv,
                # goenv; ASDF_DIR and MISE_SHIMS_DIR add one each when set).
                # pyenv's shim folder matches first; python3 is a link to
                # python3.12 inside its bin.
                assert not {"ASDF_DIR", "MISE_SHIMS_DIR"} & set(self.env), "two more shim homes"
                self.command.update(path_folders=len(self.env["PATH"].split(":")),
                                    manager_homes=6 if stage == "builtin_probe" else 0,
                                    bin_links=int(stage == "builtin_fast"))
        if stage == "builtin_probe":
            # A new node (its identity changed): the cached probe no longer
            # matches, so the traced round runs it again.
            stamp = self.language.stat().st_mtime_ns + 1_000_000_000
            os.utime(self.language, ns=(stamp, stamp))
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
            arch=platform.machine(), session_locks=self.session_locks, **self.collection, **self.command)


def folder_outside_repository(parent, prefix):
    """A new folder under `parent`, outside every git repository and with no
    ancestor writable by group or others. A builtin stage's language tools
    live there: the round leaves PATH folders inside the shell's repository,
    or any folder above it holding `.git`, out of its lookup,
    and a fixture base next to the build output sits in the source checkout,
    as on a CI runner. The collect and builtin stages' shell folder too, to
    keep the collector's discovery shallow."""
    import tempfile
    parent = Path(parent).resolve()
    # 이것을 실패시키는 것: 도구 폴더를 fixture 기반(저장소 checkout 안)에 두는 것(CI 러너에서 PATH가 비고 내장
    # 회차가 아무것도 결정하지 않음), 저장소 안이거나 남이 쓸 수 있는 부모를 받는 것.
    for folder in [parent, *parent.parents]:
        assert not os.path.lexists(folder / ".git"), ("a tools folder inside a git repository", folder)
        assert not os.stat(folder).st_mode & 0o022, ("group/other-writable ancestor of the tools", folder)
    folder = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    folder.chmod(0o755)
    return folder


def builtin_install(folder, name):
    """The version stub (crates/bingsu-bench) copied under a language's
    command name: a probe never runs a `#!` script."""
    stub = Path(os.environ.get("BINGSU_VERSION_STUB", real_bin().with_name("version-stub")))
    assert stub.is_file(), f"build it first: cargo build -p bingsu-bench --bin version-stub ({stub})"
    folder.mkdir(parents=True, mode=0o755, exist_ok=True)
    target = folder / name
    target.write_bytes(stub.read_bytes())
    target.chmod(0o755)
    return target


def pyenv_layout(tools, env):
    """pyenv as it installs: its shim folder first on PATH (a `#!` script),
    3.12.1 installed with python3 a link to python3.12, and the repository's
    `.python-version` selecting it."""
    root = tools / "pyenv"
    shim = root / "shims" / "python3"
    shim.parent.mkdir(parents=True, mode=0o755)
    shim.write_text("#!/usr/bin/env bash\nexec pyenv exec python3 \"$@\"\n")
    shim.chmod(0o755)
    real = builtin_install(root / "versions" / "3.12.1" / "bin", "python3.12")
    (real.parent / "python3").symlink_to("python3.12")
    for folder in (root, root / "versions", root / "versions" / "3.12.1"):
        folder.chmod(0o755)
    env["PYENV_ROOT"] = str(root)
    env["PATH"] = f"{shim.parent}:{env['PATH']}"
    return real


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
    from fsbudget.formula import (helper_stage_expected, helper_collect_expected, helper_command_expected,
                                  helper_builtin_expected, supervisor_expected)
    from fsbudget.gate import check, check_builtin, check_collect, check_command
    if evidence is None:
        evidence = {}
    builtin = stage.startswith("builtin_")
    status = collector_exit(lines, collector) if stage == "collect" or builtin else None
    evidence["collector_exit"] = status
    collectors, roles = measured_helper_attribution(lines, exe, collector)
    evidence["role_counts"] = roles.counts
    assert collectors == int(stage == "collect" or builtin), ("collector spawns", collectors)
    command_roles = {"supervisor", "relay", "command"} & set(roles.counts)
    # 이것을 실패시키는 것: 명령 단계에서 감독·relay·대상 역할이 비는 것(그 호출이 helper에 섞임), 명령 없는
    # 단계나 실행할 것 없는 명령 단계에 그 역할이 생기는 것.
    # Builtin stages: their exact supervisor check below fails on a missing
    # or extra role's calls.
    assert builtin or command_roles == ({"supervisor", "relay", "command"} if stage == "command_miss"
                                        else set()), command_roles
    if builtin:
        # GATE-FS-HELPER.1 builtin stages; GATE-CMD-FSBUDGET.1: the probe's
        # supervisor spawns one relay as a unit round's does, the fast path's
        # starts with nothing to run (idle). Which formula applies comes from
        # the trace: a round that published the collection's response (even
        # after a deadline) is held to the full one; without it, the deadline
        # bounds apply and the stage tries again. The command supervisor is
        # always checked exactly, by the relays it spawned.
        # 이것을 실패시키는 것: 내장 단계의 감독 호출을 정확 비교에서 빼는 것, fast 감독을 단위 회차 식으로 보는 것,
        # 마감 회차의 판정을 종료 코드로 정하는 것, 응답 없는 정상 종료를 받는 것.
        assert status in (0, 75), ("unexpected collector exit", status)
        errors, published, installed = check_builtin(
            roles, helper_builtin_expected(plan), stage, deadline=helper_builtin_expected(plan, deadline=True),
            evidence=evidence)
        if status == 0 and not published:
            errors.append("builtin: the collector answered but no response was published")
        # The probe stage's fixture runs its probe once: a round that had an
        # answer or installed a result spawned one relay. Only a probe round
        # without either (a deadline with nothing verified) leaves the
        # supervisor idle, as the fast stage always does.
        # 이것을 실패시키는 것: 측정한 생성 수로 idle을 고르는 것(발행한 probe 회차가 relay 없이 통과).
        idle = stage == "builtin_fast" or not (published or installed)
        supervisor = {"supervisor": supervisor_expected(0 if idle else 1, atomic=plan.cgroup_parent, arch=plan.arch,
                                                        libc=plan.libc, idle=idle)}
        evidence.update(supervisor_counts=roles.counts.get("supervisor", {}), supervisor_expected=supervisor["supervisor"],
                        relay_counts=roles.counts.get("relay", {}))
        errors += check({"supervisor": roles.counts.get("supervisor", {})}, supervisor, "exact", ["supervisor"])
    elif stage == "command_miss":
        errors = check_command(roles, helper_command_expected(plan), evidence=evidence)
        # GATE-CMD-FSBUDGET.1: the supervisor's calls, exact for this round's
        # one spawn on the path the host gave (the atomic path with the
        # session's cgroup parent, best effort without). The relay and the
        # target are counted only.
        # 이것을 실패시키는 것: 감독 식에서 시계·생성·cgroup 항 하나를 빼거나 더하는 것, 원자 경로와 최선 노력
        # 경로를 바꿔 세는 것, 감독 호출을 정확 비교에서 빼는 것.
        supervisor = {"supervisor": supervisor_expected(1, atomic=plan.cgroup_parent, arch=plan.arch, libc=plan.libc)}
        evidence.update(supervisor_counts=roles.counts.get("supervisor", {}), supervisor_expected=supervisor["supervisor"],
                        relay_counts=roles.counts.get("relay", {}))
        errors += check({"supervisor": roles.counts.get("supervisor", {})}, supervisor, "exact", ["supervisor"])
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


# Fixture metadata, pinned independently from the product source.
FRONT_CHUNK = 16 * 1024


FRONT_CASES = ('normal', 'checksum-last-good', 'body-limit', 'header-only', 'selected-band', 'env-segment')


def front_attempt_plan(case, body, through_index=None):
    """`body` bytes read through the selected variant; a checksum failure stops
    the current copy at `through_index` bytes."""
    from fsbudget.formula import FrontAttempt
    read = {'normal': body, 'selected-band': body, 'env-segment': body, 'body-limit': 0, 'header-only': 0,
            'checksum-last-good': body if through_index is None else through_index}[case]
    current = FrontAttempt('current', True, case not in ('header-only', 'body-limit'), read, read > 0)
    one_copy = case in ('normal', 'selected-band', 'env-segment')
    return [current] + ([] if one_copy else [FrontAttempt('last_good', True, True, body, True)])


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
        # Every call that names either end, wherever in its arguments: a poll,
        # select or splice on the pipe is not in the allowed shape.
        # 이것을 실패시키는 것: 이름 목록에 든 호출만 보는 것(쓰기 쪽 poll이 끼어도 통과, env-poll-writer).
        names = re.compile(rf"(?<![0-9])(?:{re.escape(read_fd)}|{re.escape(write_fd)})")
        channel = [c for c in front if c is not pipe and names.search(c.args)]
        shape = [(c.name, args_of(c)[0] if args_of(c) else '') for c in channel]
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
                               # Stored contexts predate bingsu-prompt: the cli entry.
                               entry=c.get("entry", "cli"), helper_exe=c.get("helper_exe"),
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
    children = role_children(cap.trace, entry_of(cap.trace))
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


def entry_of(trace):
    """The prompt entry a trace ran ("cli" or "dedicated"), which the capture
    records on it from the program the hook called; stored traces of the CLI
    entry carry none."""
    return getattr(trace, "entry", "cli")
