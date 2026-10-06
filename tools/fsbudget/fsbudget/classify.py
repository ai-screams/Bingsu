"""Map syscalls to the call kinds of the budget formula (spec 8).

Default deny: a syscall is either in NON_FS (never a filesystem call, with
the reason in the comment), fd-dependent (FD_DEPENDENT, decided by what the
fd is), a formula kind, or `unknown-fs`. `unknown-fs` covers relative and
absolute paths, pathless calls on file fds and any syscall nobody has
classified yet; the scaffold rejects it for gated roles (spec 8 front table:
"other filesystem calls = 0"). A harmless syscall that shows up as
`unknown-fs` in CI goes into NON_FS with its reason, never silently.
"""
import re

from .strace_parse import Call

NAMES = {
    "openat": {"open", "openat", "openat2", "creat"},
    "fstat": {"fstat", "fstat64", "newfstatat", "fstatat64", "statx", "stat", "lstat"},
    "readlink": {"readlink", "readlinkat"},
    "getdents": {"getdents", "getdents64"},
    "statfs": {"statfs", "fstatfs", "statfs64", "fstatfs64"},
    "read": {"read", "pread64", "readv", "preadv"},
    "write": {"write", "pwrite64", "writev", "pwritev"},
    "fsync": {"fsync", "fdatasync"},
    "renameat": {"rename", "renameat", "renameat2"},
    "unlinkat": {"unlink", "unlinkat"},
    "flock": {"flock"},
}
BY_NAME = {n: k for k, names in NAMES.items() for n in names}
XATTR = {"getxattr", "lgetxattr", "fgetxattr"}
NON_FS = {
    # descriptor table bookkeeping (no file content, no path)
    "close", "close_range", "dup", "dup2", "dup3", "pipe", "pipe2",
    # memory without a file (file-backed mmap is FD_DEPENDENT)
    "munmap", "mprotect", "brk", "madvise", "mremap", "membarrier",
    # process and thread control, including posix_spawn's child before exec
    "execve", "execveat", "clone", "clone3", "fork", "vfork", "exit", "exit_group", "wait4", "waitid",
    "setsid", "prctl", "arch_prctl", "set_tid_address", "set_robust_list", "rseq", "prlimit64",
    "seccomp", "kill", "tgkill", "pidfd_open", "pidfd_send_signal", "sched_getaffinity", "sched_yield",
    # signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "restart_syscall",
    # waiting and time
    "poll", "ppoll", "select", "pselect6", "futex", "nanosleep", "clock_nanosleep", "clock_gettime",
    # identity and randomness
    "getpid", "gettid", "getppid", "getuid", "geteuid", "getgid", "getegid", "getsid", "getrandom",
}
# Their meaning depends on the fd: a pipe, socket, terminal or anonymous
# mapping is not a filesystem call, a file (or an fd strace could not name)
# is `unknown-fs`. Value: which argument is the fd.
FD_DEPENDENT = {"fcntl": 0, "ioctl": 0, "mmap": 4}
# -y prints an fd as 4</path>, 5<pipe:[1]>, 6<socket:[2]>, 7<anon_inode:[eventfd]>.
FD_ARG = re.compile(r"^\s*(-?\d+)(?:<(.*)>)?\s*$")


def split_args(args: str) -> list[str]:
    """Top-level comma split that respects quotes, brackets and braces."""
    out, depth, cur, quote = [], 0, [], False
    i = 0
    while i < len(args):
        ch = args[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(args):
                cur.append(args[i + 1])
                i += 1
            elif ch == '"':
                quote = False
        elif ch == '"':
            quote = True
            cur.append(ch)
        elif ch in "([{<":
            depth += 1
            cur.append(ch)
        elif ch in ")]}>":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        out.append("".join(cur).strip())
    return out


# Descriptors that are not filesystem activity, each for a stated reason:
# the null/zero/random devices and terminals carry no file content, and
# strace -y names pipes, sockets and anonymous inodes without a path. Any
# other path (including /dev/shm/*, memfd and other /dev entries) is a file.
NON_FILE_PATHS = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx"}
NON_FILE_PATTERN = re.compile(r"/dev/pts/\d+|(pipe|socket|anon_inode):.*")


def fd_identity(arg: str) -> str | None:
    """'file:<path>', 'none' (justified non-file: see NON_FILE_*, or an
    anonymous mapping) or None (unknown: strace could not name it)."""
    m = FD_ARG.match(arg)
    if not m:
        return None
    if m.group(1) == "-1":
        return "none"
    name = m.group(2)
    if name is None:
        return None
    if name in NON_FILE_PATHS or NON_FILE_PATTERN.fullmatch(name):
        return "none"
    if name.startswith("/"):
        return "file:" + name
    return None


def kind(c: Call) -> str | None:
    if c.name in NON_FS:
        return None
    args = split_args(c.args)
    if c.name in FD_DEPENDENT:
        pos = FD_DEPENDENT[c.name]
        ident = fd_identity(args[pos]) if pos < len(args) else None
        return None if ident == "none" else "unknown-fs"
    if c.name in XATTR:
        return "acl" if '"system.posix_acl_' in c.args else "unknown-fs"
    k = BY_NAME.get(c.name)
    if k in {"read", "write"} or (k == "fstat" and c.name in {"fstat", "fstat64"}):
        # fd-only kinds: a pipe or device is not counted, an unnamed fd is.
        return None if args and fd_identity(args[0]) == "none" else k
    return k or "unknown-fs"
