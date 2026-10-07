"""Map syscalls to the call kinds of the budget formula (spec 8).

Default deny: a syscall is either in NON_FS (never a filesystem call, with
the reason in the comment), fd-dependent (FD_DEPENDENT, decided by what the
fd is), a formula kind, or `unknown-fs`. A formula kind needs its exact
syscall name in NAMES (aliases such as open, creat, openat2, stat, lstat and
statx are not there and stay `unknown-fs`) and, for a call that takes a
path, a path strace can place: absolute, or relative to a dirfd that -y
names as a file. A path relative to the cwd (AT_FDCWD or a legacy path
call) is `unknown-fs`. So are pathless calls on file fds and any syscall
nobody has classified yet; the scaffold rejects `unknown-fs` for gated
roles (spec 8 front table: "other filesystem calls = 0"). A harmless
syscall that shows up as `unknown-fs` in CI goes into NON_FS with its
reason, never silently.
"""
import re

from .strace_parse import EXIT_EVENT, Call, StructureError, scan

NAMES = {
    "openat": {"openat"},
    "fstat": {"fstat", "fstat64", "newfstatat", "fstatat64"},
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
# Where a formula call names a path: (dirfd position or None, path position).
# None means the legacy form, relative to the cwd.
PATH_ARGS = {
    "openat": [(0, 1)], "newfstatat": [(0, 1)], "fstatat64": [(0, 1)],
    "readlink": [(None, 0)], "readlinkat": [(0, 1)],
    "statfs": [(None, 0)], "statfs64": [(None, 0)],
    "rename": [(None, 0), (None, 1)], "renameat": [(0, 1), (2, 3)], "renameat2": [(0, 1), (2, 3)],
    "unlink": [(None, 0)], "unlinkat": [(0, 1)],
    "getxattr": [(None, 0)], "lgetxattr": [(None, 0)],
}
XATTR = {"getxattr", "lgetxattr", "fgetxattr"}
# The POSIX ACL attributes, compared whole (the name is the second argument).
ACL_NAMES = {'"system.posix_acl_access"', '"system.posix_acl_default"'}
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
MMAP_FLAGS = 3
# -y prints an fd as 4</path>, 5<pipe:[1]>, 6<socket:[2]>, 7<anon_inode:[eventfd]>.
FD_ARG = re.compile(r"^\s*(-?\d+)(?:<(.*)>)?\s*$")


def split_args(args: str) -> list[str]:
    """Top-level comma split (see strace_parse.scan). Arguments the parser
    did not validate and that do not scan come back as one raw argument,
    which no rule below accepts as a path or a non-file fd."""
    try:
        return scan(args)[0]
    except StructureError:
        return [args]


# Descriptors that are not filesystem activity, each for a stated reason:
# the null/zero/random devices and terminals carry no file content, and
# strace -y names pipes, sockets and anonymous inodes without a path. Any
# other path (including /dev/shm/*, memfd and other /dev entries) is a file.
NON_FILE_PATHS = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx"}
NON_FILE_PATTERN = re.compile(r"/dev/pts/\d+|(pipe|socket|anon_inode):.*")


def fd_identity(arg: str) -> str | None:
    """'file:<path>', 'none' (justified non-file: see NON_FILE_*) or None
    (unknown: strace could not name it, or not an fd at all)."""
    m = FD_ARG.match(arg)
    if not m:
        return None
    name = m.group(2)
    if name is None:
        return None
    if name in NON_FILE_PATHS or NON_FILE_PATTERN.fullmatch(name):
        return "none"
    if name.startswith("/"):
        return "file:" + name
    return None


def _placed(c: Call, args: list[str]) -> bool:
    """Every path argument is absolute or relative to a dirfd named as a file."""
    for d, p in PATH_ARGS.get(c.name, []):
        if p >= len(args) or not args[p].startswith('"'):
            return False
        if args[p].startswith('"/'):
            continue
        ident = fd_identity(args[d]) if d is not None and d < len(args) else None
        if not (ident and ident.startswith("file:")):
            return False
    return True


def kind(c: Call) -> str | None:
    if c.name in NON_FS or c.name == EXIT_EVENT:
        return None
    args = split_args(c.args)
    if c.name == "mmap" and len(args) > MMAP_FLAGS and "MAP_ANONYMOUS" in args[MMAP_FLAGS].split("|"):
        return None  # Linux ignores the fd of an anonymous mapping
    if c.name in FD_DEPENDENT:
        pos = FD_DEPENDENT[c.name]
        ident = fd_identity(args[pos]) if pos < len(args) else None
        return None if ident == "none" else "unknown-fs"
    if c.name in XATTR:
        return "acl" if len(args) > 1 and args[1] in ACL_NAMES and _placed(c, args) else "unknown-fs"
    k = BY_NAME.get(c.name)
    if k in {"read", "write"} or (k == "fstat" and c.name in {"fstat", "fstat64"}):
        # fd-only kinds: a pipe or device is not counted, an unnamed fd is.
        return None if args and fd_identity(args[0]) == "none" else k
    if k and not _placed(c, args):
        return "unknown-fs"
    return k or "unknown-fs"
