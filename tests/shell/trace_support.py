"""The strace budget checker the prompt, helper and collector traces are judged by:
reading a trace into calls, classifying each call, and the allowlists and
budgets of the prompt and collection traces. `trace_captures.py` judges whole
helper and front captures on top of it, `trace_live.py` builds the live runs.
`test_prompt_env_paths.py` runs it on live captures and
`test_prompt_trace_budget.py` on recorded and synthetic ones; neither holds
a copy."""
import ast
import hashlib
import os
import re
import sys

import pytest
from shell_support import ROOT

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import EXIT_EVENT, parse as parse_trace, scan


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


ADAPTER_ROWS = [r.split("\t") for r in open(TABLE).read().splitlines() if r and not r.startswith("#")][1:]


ADAPTER_CALLS = {r[0] for r in ADAPTER_ROWS if r[0] != "-" and r[1] != "-"}


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


ROOT_CALLS = {r[0] for r in ADAPTER_ROWS if r[0] != "-"} | set("""
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
    table = {r[0] for r in ADAPTER_ROWS if r[0] != "-"}
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
