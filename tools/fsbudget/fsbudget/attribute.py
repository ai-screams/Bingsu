"""Attribute calls to roles (spec section 8 "role attribution") and enforce
the fsb marker windows fail-closed: a failed or unbalanced marker, or a
gated-role filesystem call outside a window, is an error.

The root pid is `front`. A child inherits its parent's role until it execs;
an exec whose argv matches a rule takes that role, any other exec is a
`command`. Gated roles count only inside per-TID fsb windows; commands are
counted in full (reported, not budgeted).
"""
import re
from collections import defaultdict
from dataclasses import dataclass, field

from .classify import FD_DEPENDENT, fd_identity, kind, split_args
from .strace_parse import Call

SPAWN = {"clone", "clone3", "fork", "vfork"}
MARKERS = ('PR_SET_NAME, "fsb:begin"', 'PR_SET_NAME, "fsb:end"')
# What a process may do between a successful exec and its first fsb:begin:
# exact (syscalls, path) pairs for the dynamic loader and the C runtime.
# A path alone is never enough (fchmodat on /etc/ld.so.cache is an error).
# Grow only with a recorded reason.
TRUSTED_LIB_DIRS = {
    # glibc's built-in search folders, used when ld.so.cache has no entry.
    "/lib", "/lib64", "/usr/lib", "/usr/lib64",
    # Debian and Ubuntu multiarch folders: x86_64 (CI runners) and aarch64
    # (the local test containers). With the merged /usr the loader opens
    # /lib/<triplet>/x.so and strace -y names the fd /usr/lib/<triplet>/x.so.
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
}
LIB_NAME = re.compile(r"^(lib[A-Za-z0-9_.+-]*|ld-linux[A-Za-z0-9_.-]*)\.so(\.[0-9]+)*$")
LOADER_FILE = {"openat", "newfstatat", "fstat", "mmap"}
PROLOGUE_RULES = [
    # glibc checks the preload list; aarch64 has no access syscall, so its
    # loader calls faccessat(AT_FDCWD, ...) (glibc 2.35 and 2.41, observed).
    ({"access", "faccessat", "openat"}, lambda p: p == "/etc/ld.so.preload"),
    (LOADER_FILE, lambda p: p == "/etc/ld.so.cache"),                       # library search cache
    (LOADER_FILE | {"read", "pread64"}, lambda p: _trusted_lib(p)),         # shared objects
    ({"openat", "newfstatat", "fstat", "read"},                             # main-thread stack guard (std)
     lambda p: re.fullmatch(r"/proc/(self|\d+)/maps", p) is not None),
]


def _trusted_lib(path: str) -> bool:
    parent, _, name = path.rpartition("/")
    hw = re.fullmatch(r"(.*)/glibc-hwcaps/[A-Za-z0-9_-]+", parent)
    in_dir = parent in TRUSTED_LIB_DIRS or bool(hw and hw.group(1) in TRUSTED_LIB_DIRS)
    return in_dir and bool(LIB_NAME.match(name))


def prologue_allowed(name: str, path: str | None) -> bool:
    return path is not None and any(name in calls and ok(path) for calls, ok in PROLOGUE_RULES)


def target(c: Call) -> str | None:
    """The absolute path a call acts on, or None when it cannot be named
    (relative to the cwd, unnamed fd). None never matches a prologue pair."""
    args = split_args(c.args)
    if not args:
        return None
    if c.name in FD_DEPENDENT:
        pos = FD_DEPENDENT[c.name]
        ident = fd_identity(args[pos]) if pos < len(args) else None
        return ident[5:] if ident and ident.startswith("file:") else None
    if args[0].startswith('"'):
        p = args[0].strip('"')
        return p if p.startswith("/") else None
    ident = fd_identity(args[0]) if not args[0].startswith("AT_FDCWD") else None
    if (c.name.endswith(("at", "at2")) or c.name == "statx") and len(args) > 1 and args[1].startswith('"'):
        name = args[1].strip('"')
        if name.startswith("/"):
            return name
        if name == "" and ident and ident.startswith("file:"):
            return ident[5:]
        return None
    return ident[5:] if ident and ident.startswith("file:") else None


@dataclass
class Attribution:
    counts: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def attribute(calls: list[Call], rules, markers: bool) -> Attribution:
    compiled = [(role, re.compile(pat)) for role, pat in rules]
    role: dict[int, str] = {}
    parent: dict[int, int] = {}
    window: dict[int, bool] = defaultdict(bool)
    # True only between a successful exec and that TID's first fsb:begin. A
    # child that has not exec'd (fork, vfork, thread) never gets it.
    prologue: dict[int, bool] = defaultdict(bool)
    root = calls[0].pid if calls else 0
    role[root] = "front"
    seen_root_exec = False
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    errors: list[str] = list(getattr(calls, "errors", []))  # parser structure errors fail the gate too
    for c in calls:
        if c.name in SPAWN and c.ret.split()[0].isdigit():
            child = int(c.ret.split()[0])
            parent[child] = c.pid
            # With CLONE_VFORK the parent's "resumed ... = N" line can come
            # after the child already exec'd: never overwrite that role.
            role.setdefault(child, role.get(c.pid, "front"))
            continue
        if c.pid not in role:
            role[c.pid] = role.get(parent.get(c.pid, root), "front")
        if c.name in {"execve", "execveat"} and c.ret.strip().startswith("0"):
            if c.pid == root and not seen_root_exec:
                seen_root_exec = True
            else:
                role[c.pid] = next((r for r, p in compiled if p.search(c.args)), "command")
            if window[c.pid]:
                errors.append(f"pid {c.pid}: exec inside an open window")
            window[c.pid], prologue[c.pid] = False, True
            continue
        if c.name == "prctl" and "fsb:" in c.args:
            # Only these two exact calls are markers; any other prctl naming
            # fsb: (another option, another name, extra arguments) is an error.
            if c.args not in MARKERS:
                errors.append(f"pid {c.pid}: malformed fsb marker: prctl({c.args})")
                continue
            if not c.ret.strip().startswith("0"):
                errors.append(f"pid {c.pid}: marker failed: {c.args} = {c.ret}")
            if c.args == MARKERS[0]:
                if window[c.pid]:
                    errors.append(f"pid {c.pid}: nested fsb:begin")
                window[c.pid], prologue[c.pid] = True, False
            else:
                if not window[c.pid]:
                    errors.append(f"pid {c.pid}: fsb:end without begin")
                window[c.pid] = False
            continue
        r = role[c.pid]
        k = kind(c)
        if not k:
            continue
        if r != "command":
            where = target(c)
            in_prologue = markers and not window[c.pid] and prologue[c.pid] and prologue_allowed(c.name, where)
            # unknown-fs first: only an exact prologue pair excuses it.
            if k == "unknown-fs" and not in_prologue:
                errors.append(f"pid {c.pid} ({r}): {c.name} is a filesystem call outside the formula "
                              f"(or an unclassified syscall): {where or c.args[:60]}")
                continue
            if markers and not window[c.pid]:
                if not in_prologue:
                    errors.append(f"pid {c.pid} ({r}): {c.name} outside window: {where or c.args[:60]}")
                continue
        counts[r][k] += 1
    if markers:
        for pid, open_ in window.items():
            if open_:
                errors.append(f"pid {pid}: window still open at the end of the trace")
    return Attribution({r: dict(v) for r, v in counts.items()}, errors)
