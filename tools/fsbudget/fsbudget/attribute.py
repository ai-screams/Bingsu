"""Attribute calls to roles (spec section 8 "role attribution") and enforce
the fsb marker windows fail-closed: a failed or unbalanced marker, or a
gated-role filesystem call outside a window, is an error.

The root pid is `front`. A child inherits its parent's role until it execs
(the parent is known from the spawn call's result anywhere in the trace,
because strace may print a child's first line before its parent's return).
An exec takes the role of the first rule its argv matches; a gated role
whose exec matches no rule is a `role escape` error (only a rule may name a
`command`). A command's own children and execs stay commands. An exit
record ends the TID: an open window there is an error, and a later task
with the same number starts fresh. Gated roles count only inside per-TID
fsb windows; commands are counted in full (reported, not budgeted).
"""
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .classify import FD_DEPENDENT, fd_identity, kind, split_args
from .strace_parse import EXIT_EVENT, UNKNOWN_SYSCALL, Call


SPAWN = {"clone", "clone3", "fork", "vfork"}
OPEN = {"open", "openat", "openat2", "creat"}
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
    ({"access", "faccessat", "openat"}, lambda p, pid: p == "/etc/ld.so.preload"),
    (LOADER_FILE, lambda p, pid: p == "/etc/ld.so.cache"),                  # library search cache
    (LOADER_FILE | {"read", "pread64"}, lambda p, pid: _trusted_lib(p)),    # shared objects
    # Main-thread stack guard (std): its own maps only; strace -y names the
    # fd /proc/<pid>/maps, so a number is accepted only when it is the pid.
    ({"openat", "newfstatat", "fstat", "read"},
     lambda p, pid: p == "/proc/self/maps" or (pid is not None and p == f"/proc/{pid}/maps")),
]
# A start-up openat only reads.
WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"}
# The role of a task no spawn chain explains. Not `command`: it stays gated,
# so its filesystem calls are errors too.
UNRESOLVED = "unresolved"


def _trusted_lib(path: str) -> bool:
    parent, _, name = path.rpartition("/")
    hw = re.fullmatch(r"(.*)/glibc-hwcaps/[A-Za-z0-9_-]+", parent)
    in_dir = parent in TRUSTED_LIB_DIRS or bool(hw and hw.group(1) in TRUSTED_LIB_DIRS)
    return in_dir and bool(LIB_NAME.match(name))


def prologue_allowed(name: str, path: str | None, pid: int | None = None) -> bool:
    return path is not None and any(name in calls and ok(path, pid) for calls, ok in PROLOGUE_RULES)


def _prologue_call(c: Call, path: str | None) -> bool:
    if c.name == "openat":
        args = split_args(c.args)
        if len(args) < 3 or WRITE_FLAGS & set(args[2].split("|")):
            return False
    return prologue_allowed(c.name, path, c.pid)


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
    cloexec_pairs: list = field(default_factory=list)
    helper_calls: list = field(default_factory=list)


def attribute(calls: list[Call], rules, markers: bool) -> Attribution:
    compiled = [(role, re.compile(pat)) for role, pat in rules]
    errors: list[str] = list(getattr(calls, "errors", []))  # parser structure errors fail the gate too
    # Pass 1: the parent of every spawned task, in trace order per number
    # (a number can be reused after an exit).
    spawns: dict[int, deque] = defaultdict(deque)
    for c in calls:
        if c.name in SPAWN and c.ret.split()[0].isdigit():
            spawns[int(c.ret.split()[0])].append(c.pid)
    role: dict[int, str] = {}
    window: dict[int, bool] = defaultdict(bool)
    # True only between a successful exec and that TID's first fsb:begin. A
    # child that has not exec'd (fork, vfork, thread) never gets it.
    prologue: dict[int, bool] = defaultdict(bool)
    # Tasks seen before their parent's return line: they took the role of the
    # parent at the front of their spawn queue, and that return line only
    # consumes the entry.
    early: set[int] = set()
    root = getattr(calls, "first_pid", None)
    if root is None:
        root = calls[0].pid if calls else 0
    role[root] = "front"
    seen_root_exec = False
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def resolve(pid: int) -> str | None:
        """The role `pid` inherits from its nearest ancestor that has one,
        assigned (as an early task) to every task on the way; None if the
        chain ends without a role. Never a default: only a rule makes a
        command."""
        chain = []
        while pid not in role:
            if not spawns[pid] or pid in chain:
                return None
            chain.append(pid)
            pid = spawns[pid][0]
        for t in chain:
            role[t] = role[pid]
            early.add(t)
        return role[pid]

    for c in calls:
        # Every record, a spawn return included, needs its task's role first.
        if c.pid not in role:
            # Its parent's return line has not come yet. The parent may be in
            # the same state (its only record so far an unfinished clone), so
            # walk up the spawn queues to the nearest task with a role.
            found = resolve(c.pid)
            if found is None:
                errors.append(f"pid {c.pid}: no spawn call leads to a task with a role")
                role[c.pid] = UNRESOLVED
        if c.name in SPAWN and c.ret.split()[0].isdigit():
            child = int(c.ret.split()[0])
            spawns[child].popleft()
            # With CLONE_VFORK the parent's "resumed ... = N" line can come
            # after the child already exec'd: never overwrite that role.
            if child in early:
                early.discard(child)
            else:
                role[child] = role[c.pid]
            continue
        if c.name == EXIT_EVENT:
            if markers and window[c.pid]:
                errors.append(f"pid {c.pid}: {c.args} with its fsb window open")
            for state in (role, window, prologue):
                state.pop(c.pid, None)
            continue
        if c.name in {"execve", "execveat"} and c.ret.strip().startswith("0"):
            if c.pid == root and not seen_root_exec:
                seen_root_exec = True
            else:
                new = next((r for r, p in compiled if p.search(c.args)), None)
                if new is None and role[c.pid] != "command":
                    errors.append(f"pid {c.pid} ({role[c.pid]}): role escape: exec matches no rule: {c.args[:80]}")
                role[c.pid] = new or "command"
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
        if c.name == UNKNOWN_SYSCALL:
            errors.append(f"pid {c.pid} ({r}): unknown syscall outside collector helper kill path")
            continue
        k = kind(c)
        if not k:
            continue
        if r != "command":
            where = target(c)
            in_prologue = markers and not window[c.pid] and prologue[c.pid] and _prologue_call(c, where)
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



@dataclass
class _Description:
    # Names are evidence about an open description, never its identity.
    aliases: set[str] = field(default_factory=set)


@dataclass
class _Descriptor:
    creation: tuple[int, str, int]
    description: _Description
    cloexec: bool


class _Descriptors:
    def __init__(self):
        self.tables = {}
        self.closed = {}
        self.serial = defaultdict(int)

    def start(self, process, parent=None):
        self.tables[process] = dict(self.tables[parent]) if parent is not None else {}
        self.closed[process] = set(self.closed[parent]) if parent is not None else set()

    def create(self, process, fd, name, cloexec=False, description=None):
        self.serial[process] += 1
        self.tables[process][fd] = _Descriptor(
            (process, fd, self.serial[process]),
            description if description is not None else _Description({name} if name else set()),
            cloexec,
        )
        self.closed[process].discard(fd)

    def close(self, process, fd):
        self.tables[process].pop(fd, None)
        self.closed[process].add(fd)

    def exec(self, process):
        for fd, entry in list(self.tables[process].items()):
            if entry.cloexec:
                self.close(process, fd)

    @staticmethod
    def token(arg):
        return re.fullmatch(r"(\d+)(?:<(.+)>)?", arg)

    @staticmethod
    def path(args, directory, path):
        name = args[path].strip('"')
        if name.startswith("/"):
            return name
        if directory is not None:
            match = re.fullmatch(r"(?:\d+|AT_FDCWD)<(/.*)>", args[directory])
            if match:
                return match[1].rstrip("/") + "/" + name
        return None

    def opened(self, c, process, bad):
        match = re.match(r"^(\d+)(?:<(.+)>)?", c.ret)
        entry = self.tables[process].get(match[1])
        # An abbreviated trace may omit a close or inherit a stale entry from
        # another process. Refuse reuse only with local, named evidence of the
        # same live description. A different/absent name is not that evidence.
        # Observed close and exec-CLOEXEC already remove entries from this table.
        if (entry and entry.creation[0] == process and match[2]
                and match[2] in entry.description.aliases):
            bad(c, "open returned a live descriptor")
        self.create(process, *match.groups(), "CLOEXEC" in c.args)

    def observe(self, c, process, args, success, bad, *, defer_open=False):
        table = self.tables[process]
        # Check uses before replacements (dup2 closes its destination).
        uses = [arg for arg in args if re.fullmatch(r"\d+<.+>", arg)]
        if args and c.name in {"read", "pread64", "readv", "write", "writev", "pwrite64",
                               "fstat", "newfstatat", "fstatat64", "statx",
                               "fcntl", "dup", "dup2", "dup3", "close"}:
            uses = [args[0], *uses]
        for arg in set(uses):
            if not (match := self.token(arg)):
                continue
            fd, name = match.groups()
            entry = table.get(fd)
            # A refused use of a closed number is consistent with the kernel.
            # Keep checking names even on failure: an annotation is still
            # evidence about the live description, independent of the result.
            if (success and fd in self.closed[process]) or (entry and name and entry.description.aliases
                                                          and name not in entry.description.aliases):
                bad(c, "descriptor lifetime/identity mismatch")
            elif entry is None and fd not in self.closed[process]:
                # Descriptors inherited from outside the trace have no observed
                # creation. Bind their first observation so dup cannot relabel it.
                self.create(process, fd, name)
            elif entry and name and not entry.description.aliases:
                entry.description.aliases.add(name)
        if not success:
            return
        if c.name == "close" and args:
            self.close(process, args[0].split('<')[0])
        elif c.name == "close_range":
            low, high = int(args[0]), int(args[1].replace('~0U', str(2**32 - 1)))
            for fd, entry in list(table.items()):
                if low <= int(fd) <= high:
                    if "CLOSE_RANGE_CLOEXEC" in c.args:
                        table[fd] = _Descriptor(entry.creation, entry.description, True)
                    else:
                        self.close(process, fd)
        elif (c.name in {"dup", "dup2", "dup3"} or c.name == "fcntl" and len(args) >= 2
              and args[1] in {"F_DUPFD", "F_DUPFD_CLOEXEC"}):
            src, dst = args[0].split('<')[0], re.match(r"^\d+", c.ret)[0]
            if c.name == "dup2" and src == dst:
                return
            source = table.get(src)
            self.create(process, dst, None, "CLOEXEC" in c.args,
                        source.description if source else None)
        elif c.name == "fcntl" and len(args) >= 3 and args[1] == "F_SETFD":
            fd = args[0].split('<')[0]
            if fd in table:
                entry = table[fd]
                table[fd] = _Descriptor(entry.creation, entry.description, "FD_CLOEXEC" in args[2])
        elif c.name in {"pipe", "pipe2", "socketpair"}:
            pair = args[3] if c.name == "socketpair" else args[0]
            for arg in split_args(pair.strip('[]')):
                if match := self.token(arg):
                    self.create(process, *match.groups(), "CLOEXEC" in c.args)
        elif c.name in OPEN:
            if not defer_open:
                self.opened(c, process, bad)
        elif (c.name in {"pidfd_open", "memfd_create"}
              or re.match(r"^\d+<", c.ret)):
            match = re.match(r"^(\d+)(?:<(.+)>)?", c.ret)
            self.create(process, *match.groups(), "CLOEXEC" in c.args or c.name == "pidfd_open")
        elif c.name in {"rename", "renameat", "renameat2", "unlink", "unlinkat"}:
            legacy = c.name in {"rename", "unlink"}
            old = self.path(args, None if legacy else 0, 0 if legacy else 1)
            new = (self.path(args, None if legacy else 2, 1 if legacy else 3)
                   if c.name.startswith("rename") else None)
            # Update all live descriptions, including inherited/duplicated fds.
            descriptions = {id(e.description): e.description
                            for fds in self.tables.values() for e in fds.values()}
            for description in descriptions.values():
                additions = set()
                for alias in description.aliases:
                    if old and (alias == old or alias.startswith(old + "/")):
                        additions.add(new + alias[len(old):] if new else alias + " (deleted)")
                    elif new and "RENAME_EXCHANGE" in c.args and (alias == new or alias.startswith(new + "/")):
                        additions.add(old + alias[len(new):])
                description.aliases.update(additions)


def _cloexec_pair(previous: Call | None, current: Call) -> bool:
    """musl open's redundant CLOEXEC: one immediate same-PID call, any result.

    This is attribution of an existing open, not a new permitted fcntl kind.
    The kernel policy still refuses F_SETFD; musl ignores that return value.
    """
    if previous is None or previous.pid != current.pid or previous.name not in {"open", "openat"}:
        return False
    opened = re.fullmatch(r"(\d+)(?:<.+>)?", previous.ret)
    args, before = split_args(current.args), split_args(previous.args)
    flag_at = 1 if previous.name == "open" else 2
    fd = _Descriptors.token(args[0]) if args else None
    return bool(current.name == "fcntl" and len(args) == 3
                and args[1:] == ["F_SETFD", "FD_CLOEXEC"]
                and opened and fd and int(opened[1]) == int(fd[1])
                and len(before) > flag_at and "O_CLOEXEC" in before[flag_at].split("|"))


def _probe_flags(text, required, optional=frozenset()):
    flags = text.split("|")
    return len(flags) == len(set(flags)) and required <= set(flags) <= required | optional


def _probe_root(c, args):
    if c.name == "openat" and len(args) == 3 and re.fullmatch(r"AT_FDCWD(?:</.*>)?", args[0]):
        args = args[1:]
    elif c.name != "open" or len(args) != 2:
        return False
    # musl adds O_LARGEFILE; O_PATH is the fixed-root capability variant.
    return args[0] == '"/"' and bool({"O_RDONLY", "O_PATH"} & set(args[1].split("|"))) and _probe_flags(
        args[1], {"O_CLOEXEC", "O_DIRECTORY"}, {"O_RDONLY", "O_LARGEFILE", "O_PATH"})


@dataclass
class _RepositoryProbe:
    opens: dict = field(default_factory=dict)
    entries: dict = field(default_factory=dict)
    seen: set = field(default_factory=set)

    def owner(self, entry):
        return next((name for name, held in self.entries.items()
                     if entry is not None and held.creation == entry.creation), None)

    def opened(self, c, table):
        # Bind the returned descriptor lifetime, including unfinished opens.
        for name, call in self.opens.items():
            if call is c and (fd := _Descriptors.token(c.ret)):
                self.entries[name] = table[fd[1]]

    def kind(self, c, args, entry):
        from .repository import held_metadata_kind

        if not args or not re.fullmatch(r"\d+</>", args[0]) or entry is None:
            return "unknown-fs"
        name = self.owner(entry)
        if name is None:
            return "unknown-fs"
        if c.name == "close" and len(args) == 1 and "close_" + name not in self.seen:
            self.seen.add("close_" + name)
            return None  # ownership cleanup is outside the formula
        if name != "root":
            return "unknown-fs"
        exact = held_metadata_kind(c, args)
        if c.name == "fstatfs" and len(args) == 2:
            exact = "fstatfs"
        elif c.name == "openat2" and len(args) == 4 and args[1] == '"."' and args[3] == "24":
            how = re.fullmatch(r"\{flags=([^,]+), resolve=([^,]+)\}", args[2])
            if (how and _probe_flags(how[1], {"O_RDONLY", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY"})
                    and _probe_flags(how[2], {"RESOLVE_NO_XDEV", "RESOLVE_NO_MAGICLINKS", "RESOLVE_BENEATH"})):
                exact = "openat2"
        if exact and exact not in self.seen:
            self.seen.add(exact)
            if exact == "openat2":
                self.opens["child"] = c
            return "probe_" + exact
        return "unknown-fs"


def collector_attribute(lines: list[str], pinned: dict, *, helper_kill: bool = False,
                        helper_vocabulary: bool = False) -> Attribution:
    """Product roles require a pinned exec AND its validated creation parent.

    Work in syscall *entry* order. A vfork child's exec may precede its
    parent's return. Reconstruct entries without changing the historical trace
    parser/fixtures. Threads share role, filter boundary and descriptor table.
    PID reuse starts a new lifetime; failed exec never changes the role.
    Only open's returned fd is installed at its return record: another
    thread can close the previous occupant between open's entry and return.
    Input descriptors are still checked at entry, including openat's dirfd.
    `pinned` contains front/helper/collector paths and optional exact argv verbs.
    `helper_kill` is explicit evidence from the caller's failure mode. Only
    then may a collector's last call lack its syscall number before SIGKILL.
    `helper_vocabulary` counts helper calls with classify.helper_kind (the
    per-stage helper gate); other callers keep the generic helper kinds. It
    also ends a helper's loader exemption at its first counted call, so a
    loader-shaped access after startup (say /proc/self/maps) is counted.
    """
    import json
    from .classify import collector_kind, collector_bootstrap_kind, helper_kind
    from .strace_parse import CALL_HEAD, LINE, RESUMED, UNKNOWN_HEAD, parse

    trace = parse("\n".join(lines))
    errors = list(trace.errors)
    starts = defaultdict(deque)
    exits = defaultdict(deque)
    pending_open, open_ends = {}, {}
    for i, line in enumerate(lines):
        match = LINE.match(line)
        if match and (head := CALL_HEAD.match(match[2])):
            starts[int(match[1]), head[1]].append(i)
            if head[1] in OPEN and match[2].endswith("<unfinished ...>"):
                pending_open[int(match[1])] = i
        elif match and (resumed := RESUMED.match(match[2])) and resumed[1] in OPEN:
            if (start := pending_open.pop(int(match[1]), None)) is not None:
                open_ends[start] = i
        elif match and UNKNOWN_HEAD.match(match[2]):
            starts[int(match[1]), UNKNOWN_SYSCALL].append(i)
        elif match and match[2].startswith("+++ "):
            exits[int(match[1])].append(i)
            pending_open.pop(int(match[1]), None)
    ordered = []
    for c in trace:
        if c.name == EXIT_EVENT:
            # Exit records have no outstanding successor in the same lifetime.
            at = exits[c.pid].popleft() if exits[c.pid] else len(lines)
        else:
            queue = starts[c.pid, c.name]
            at = queue.popleft() if queue else len(lines)
        deferred = c.name in OPEN and at in open_ends and bool(re.match(r"^\d+", c.ret))
        ordered.append((at, c, False, deferred))
        if deferred:
            ordered.append((open_ends[at], c, True, False))
    ordered.sort(key=lambda pair: pair[0])
    roles, owner, confined = {}, {}, set()
    descriptors = _Descriptors()
    counts = defaultdict(lambda: defaultdict(int))
    helper_calls = []

    def count(role, kind, call):
        counts[role][kind] += 1
        if helper_vocabulary and role == "helper":
            helper_calls.append((call, kind))

    root = trace.first_pid
    if root is not None:
        roles[root], owner[root] = "front", root
        descriptors.start(root)
    seen_exec = set()
    collector_execs = 0
    previous_calls, cloexec_pairs = {}, []
    unknown_calls = defaultdict(int)
    filters = defaultdict(int)
    repository_probe = {}
    bootstrap_ended = set()
    started = set()  # helper processes whose loader prologue is over
    verbs = {"front": "prompt", "helper": "__refresh-v1", "collector": "__collect-v1"}
    verbs.update(pinned.get("verbs", {}))

    def bad(c, reason):
        errors.append(f"pid {c.pid} ({roles.get(c.pid, UNRESOLVED)}): {reason}: {c.name}({c.args})")

    for _, c, open_result, deferred in ordered:
        if open_result:
            descriptors.opened(c, owner[c.pid], bad)
            if probe := repository_probe.get(owner[c.pid]):
                probe.opened(c, descriptors.tables[owner[c.pid]])
            continue
        if c.pid not in roles:
            bad(c, "no live spawn parent")
            roles[c.pid], owner[c.pid] = UNRESOLVED, c.pid
            descriptors.start(c.pid)
        role, process = roles[c.pid], owner[c.pid]
        previous = previous_calls.pop(c.pid, None)
        if c.name == EXIT_EVENT:
            roles.pop(c.pid, None)
            owner.pop(c.pid, None)
            # State belongs to the process owner until its last thread exits.
            if process not in owner.values():
                descriptors.tables.pop(process, None)
                descriptors.closed.pop(process, None)
                confined.discard(process)
                seen_exec.discard(process)
                unknown_calls.pop(process, None)
                filters.pop(process, None)
                repository_probe.pop(process, None)
                bootstrap_ended.discard(process)
            continue
        if unknown_calls[process]:
            bad(c, "call after terminal unknown syscall")
        previous_calls[c.pid] = c
        if c.name == UNKNOWN_SYSCALL:
            unknown_calls[process] += 1
            count(role, UNKNOWN_SYSCALL, c)
            if role != "collector" or not helper_kill or unknown_calls[process] > 1:
                bad(c, "unknown syscall requires collector helper kill path, once per process")
            continue
        args = split_args(c.args)
        result = c.ret.split()[0]
        success = bool(re.match(r"^\d+", c.ret))
        k = (collector_bootstrap_kind(c) if role == "collector"
             else helper_kind(c) if role == "helper" and helper_vocabulary else collector_kind(c))
        if k in {"spawn", "thread"}:
            if k == "spawn" and (role not in {"front", "helper"} or process in confined):
                bad(c, "spawn outside the pre-filter creation site")
            if success:
                child = int(result)
                roles[child] = role
                owner[child] = process if k == "thread" else child
                if k != "thread":
                    descriptors.start(child, process)
            count(role, k, c)
            continue
        if k == "exec":
            if result == "0":
                descriptors.exec(process)
                new = None
                for candidate in ("front", "helper", "collector"):
                    path = pinned.get(candidate)
                    if path and len(args) >= 2 and args[0] == json.dumps(path):
                        prefix = '[' + json.dumps(path) + ', ' + json.dumps(verbs[candidate])
                        if args[1].startswith(prefix + (']' if candidate == "collector" else ',')) or args[1] == prefix + ']':
                            new = candidate
                            break
                expected_parent = {"front": "front", "helper": "front", "collector": "helper"}
                if (new is None or role != expected_parent.get(new)
                        or process in seen_exec or process in confined
                        or (new == "front") != (c.pid == root)):
                    bad(c, "exec lacks pinned identity and creation parent")
                else:
                    roles[c.pid] = role = new
                    seen_exec.add(process)
                    started.discard(process)
                    collector_execs += int(new == "collector")
            count(role, "exec", c)
            continue
        if (c.name == "seccomp" and "SECCOMP_SET_MODE_FILTER" in c.args
                or c.name == "prctl" and "PR_SET_SECCOMP" in c.args) and result == "0":
            confined.add(process)
            filters[process] += 1
        entry = descriptors.tables[process].get(args[0].split("<")[0]) if args else None
        descriptors.observe(c, process, args, success, bad, defer_open=deferred)
        if role == "collector" and _cloexec_pair(previous, c):
            cloexec_pairs.append({"pid": c.pid,
                                  "open": f"{previous.name}({previous.args})", "open_ret": previous.ret,
                                  "fcntl": f"fcntl({c.args})", "fcntl_ret": c.ret})
            continue
        # Only the exact existing loader pairs may be excluded, before the
        # process's first filter. A collector never borrows helper NSS paths.
        helper_startup = not (helper_vocabulary and role == "helper") or process not in started
        if process not in confined and helper_startup and _prologue_call(c, target(c)):
            continue
        if helper_vocabulary and role == "helper" and k is not None:
            started.add(process)
        if role == "collector":
            if c.name == "uname" and process not in confined:
                k = "kernel_release"
            # The first result write is Ready (even a failed attempt ends the
            # window). Do not wait for the subsequent request read. A read
            # ruleset or post-seal restriction also ends it before read-layer IO.
            if (args and (c.name in {"write", "writev"} and args[0].split("<")[0] == "1"
                          or c.name in {"read", "readv"} and args[0].split("<")[0] == "3")
                    or c.name in {"landlock_create_ruleset", "landlock_add_rule"}
                    and any(flag in c.args for flag in ("LANDLOCK_ACCESS_FS_READ_FILE", "LANDLOCK_ACCESS_FS_READ_DIR"))
                    or c.name == "landlock_restrict_self" and filters[process] >= 2):
                bootstrap_ended.add(process)
            probe = repository_probe.get(process)
            probe_window = filters[process] == 2 and process not in bootstrap_ended
            # Linux only: two successful seccomp installs are required. Never
            # extend the macOS vocabulary or treat an fd number as its lifetime.
            if _probe_root(c, args) and probe_window and probe is None:
                k = "probe_openat"
                probe = repository_probe[process] = _RepositoryProbe(opens={"root": c})
            elif (probe and args and (probe.owner(entry) is not None and c.name != "fcntl"
                  or target(c) == "/" and c.name in {"openat2", "fstat", "fstat64", "newfstatat", "fstatat64", "fstatfs", "statx", "close"})):
                k = probe.kind(c, args, entry) if probe_window else "unknown-fs"
            if probe and success and not deferred and c.name in OPEN:
                probe.opened(c, descriptors.tables[process])
            if c.name in {"open", "openat", "openat2"} and any(flag in c.args for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE")):
                bad(c, "collector writable open")
            if k in {"write", "renameat", "unlinkat", "network", "unknown-fs", "fsync"}:
                bad(c, "collector forbidden effect")
            if k == "cwd" and (not args or args[0] != '"/"'):
                bad(c, "collector cwd is not neutral root")
            where = target(c)
            if where and k in {"openat", "read"} and where not in {"/proc/self/statm", f"/proc/{process}/statm"}:
                bad(c, "collector read outside the M3b bootstrap")
        if k:
            count(role, k, c)
    if not seen_exec and not counts:
        errors.append("no product process observed")
    required = pinned.get("collectors", 1)
    if collector_execs != required:
        errors.append(f"collector execs: measured {collector_execs}, expected {required}")
    return Attribution({r: dict(kinds) for r, kinds in counts.items()}, errors, cloexec_pairs, helper_calls)


def assert_repository_trace(lines: list[str], capabilities: dict, phases: dict) -> None:
    """Audit attempts, descriptor lifetimes and disjoint collection phases.

    Roots and optional primitive axes are fixture inputs, never inferred from
    successful calls. The output dictionary records measured phase counts.
    Linux uses the same parser/held-metadata primitives as the B3 gate.
    Darwin records calls before dispatch, including calls that later fail.
    """
    import ast
    import posixpath
    from pathlib import PurePosixPath
    from collections import Counter
    from .classify import collector_kind, repository_path, FD_ARG, NON_FS
    from .formula import CollectorAxes, collector_repository_expected, git_collection_limits
    from .repository import held_metadata_kind
    from .strace_parse import parse

    def below(path, root):
        return path == root or path.startswith(root.rstrip("/") + "/")

    roots = set(capabilities["roots"])
    assert 1 <= len(roots) <= 3 and "/" not in roots, "invalid content roots"
    assert all(p.startswith("/") and posixpath.normpath(p) == p for p in roots)
    ancestors = {"/"}
    for root in roots:
        ancestors.update(str(p) for p in PurePosixPath(root).parents)
    names = set(capabilities.get("names", []))
    limits = git_collection_limits(ancestor_directories=len(names))
    repo = capabilities.get("repo", capabilities["roots"][0])
    home = capabilities.get("home", posixpath.dirname(repo))
    assert all(p in ancestors and below(p, home) and below(repo, p) for p in names), "invalid ancestor capability"
    forbidden = capabilities.get("forbidden", [])
    expected_axes = capabilities.get("axes", {})
    transitions = {"acquisition": "acquisition", "stage_a_head": "A", "path_facts": "Path",
                   "ancestor_names": "ancestor-names", "before_read_layer": "read-layer",
                   "preflight_start": "B", "stage_c": "C", "stage_d": "D", "end": "end"}
    order = list(transitions.values())
    active, owner, listing = None, None, None
    seen, held, closed, counts, raw_counts = [], {}, set(), {}, {}
    first_exec = True

    def phase(event):
        nonlocal active, listing
        assert event in transitions, ("unknown phase", event)
        new = transitions[event]
        assert seen or new == "acquisition", "missing acquisition"
        assert not seen or order.index(new) > order.index(active) or new == active == "ancestor-names", "repository phase reversal"
        active = new
        seen.append(new)
        counts.setdefault(new, Counter())
        listing = None

    def path_check(name, path, flags=""):
        assert active not in (None, "end"), ("IO outside collection window", name, path)
        assert path is not None, ("unresolved repository path", name)
        assert not any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE")), ("forbidden write open", name, path)
        assert not any(below(path, denied) for denied in forbidden), ("outside/forbidden capability", name, path)
        if name in {"read", "pread", "pread64", "readv", "mmap"}:
            assert path not in capabilities.get("no_read", []), ("filtered content read", name, path)
        if name in OPEN or name in {"open-result", "read", "pread", "pread64", "readv", "mmap", "getdents", "getdents64", "bulk"}:
            assert not any(below(path, denied) for denied in capabilities.get("no_open", [])), ("forbidden submodule open", name, path)
        if active == "ancestor-names":
            assert name in {"getdents", "getdents64"}, ("ancestor entry metadata/content; must use already-held fd", name, path)
            allowed = path in names
        elif active == "acquisition" and path in ancestors:
            assert name not in {"read", "pread", "pread64", "readv", "mmap", "getdents", "getdents64", "bulk"}, ("ancestor content", name, path)
            if name in OPEN:
                assert "O_DIRECTORY" in flags, ("acquisition content open", name, path)
            allowed = True
        elif active == "acquisition" and posixpath.basename(path) == ".git" and posixpath.dirname(path) in ancestors:
            allowed = True  # fixed discovery candidate only
        elif active == "read-layer" and path == "/":
            allowed = name in {"open", "openat", "open-result", "fstat", "fstat64", "newfstatat", "statx"}
        else:
            allowed = any(below(path, root) for root in roots)
        assert allowed, ("outside selected roots", active, name, path)

    def use(fd, path):
        assert fd not in closed, ("closed repository fd", fd, path)
        assert fd in held, ("unheld repository fd", fd, path)
        assert held[fd] == path, ("repository fd alias changed", fd, path, held[fd])

    def bind(fd, path):
        assert fd not in held, ("live fd reassigned", fd, path)
        path_check("open-result", path)
        held[fd] = path
        closed.discard(fd)

    def raw(value):
        assert active == "ancestor-names" and listing is not None, "raw slot without held listing"
        assert value == raw_counts.get(listing, 0) + 1 and value <= 256, "ancestor raw 256 cap"
        raw_counts[listing] = value

    def directory(path, size):
        nonlocal listing
        if active == "ancestor-names":
            assert 0 < size <= limits["dir_chunk"], "ancestor buffer cap"
            assert raw_counts.get(path, 0) < 256, "ancestor raw 256 cap before next syscall"
            listing = path

    if capabilities.get("platform") == "darwin":
        for line in lines:
            if line.startswith("F1_PHASE "):
                phase(line.split()[1])
            elif line.startswith("F1_RAW "):
                raw(int(line.split()[1]))
            elif line.startswith("F1_BIND "):
                _, fd, path = line.split()
                bind(int(fd), bytes.fromhex(path).decode())
            elif line.startswith("F1_CLOSE "):
                fd = int(line.split()[1])
                held.pop(fd, None)
                closed.add(fd)
            elif line.startswith("F1_IO "):
                _, name, base, relative, flags, fd = line.split()
                base = bytes.fromhex(base).decode()
                relative = "" if relative == "-" else bytes.fromhex(relative).decode()
                number, flag = int(fd), int(flags)
                assert base.startswith("/") or relative.startswith("/"), ("unnamed capability", line)
                path = posixpath.normpath(posixpath.join(base, relative))
                if number >= 0:
                    use(number, base)
                readable = ""
                if name in {"open", "openat"}:
                    assert flag & (3 | 8 | 0x200 | 0x400) == 0, ("write open", line)
                    readable = "O_DIRECTORY" if flag & 0x100000 else ""
                if name == "mmap":
                    assert flag & 2 == 0, ("writable map", line)
                path_check(name, path, readable)
                if name == "getdents":
                    directory(path, flag)
                counts[active][name] += 1
    else:
        parsed = parse("\n".join(lines))
        assert not parsed.errors, parsed.errors
        for index, call in enumerate(parsed):
            args = split_args(call.args)
            effect = collector_kind(call)
            if effect == "exec" and first_exec and active is None and call.ret.startswith("0"):
                first_exec = False
                continue  # exactly one launch of the fixed worker
            assert effect not in {"exec", "spawn", "thread", "network"}, ("forbidden repository effect (attempt)", effect, call)
            if call.name == "write" and len(args) == 3 and args[0].split("<")[0] == "1":
                try:
                    message = ast.literal_eval(args[1])
                except (SyntaxError, ValueError):
                    message = ""
                if message.startswith("F1_PHASE "):
                    assert owner in (None, call.pid), "phase owner changed"
                    owner = call.pid
                    assert not call.ret.startswith("-1"), "failed phase observation"
                    phase(message.strip().split()[1])
                elif message.startswith("F1_RAW "):
                    raw(int(message.strip().split()[1]))
                continue
            if active is None:
                continue  # C1/B3 separately gate the shipped bootstrap
            assert call.pid == owner, ("other task in repository phase", call)
            if call.name == "close":
                if call.ret == "0":
                    fd = int(args[0].split("<")[0])
                    held.pop(fd, None)
                    closed.add(fd)
                continue
            if call.name in {"dup", "dup2", "dup3"} or call.name == "fcntl" and len(args) > 1 and args[1].startswith("F_DUPFD"):
                source = FD_ARG.fullmatch(args[0])
                assert source and source[2], ("unheld dup source", call)
                use(int(source[1]), source[2])
                if not call.ret.startswith("-1"):
                    target = int(call.ret.split("<")[0])
                    if call.name in {"dup2", "dup3"}:
                        held.pop(target, None)
                    held[target] = source[2]
                    closed.discard(target)
                continue
            if call.name == "fcntl":
                assert args[1] in {"F_GETFD", "F_SETFD"}, ("unknown fd effect", call)
                if args[1] == "F_SETFD":
                    assert args[2:] == ["FD_CLOEXEC"], call
                    previous = parsed[index - 1] if index else None
                    assert (previous and previous.name in OPEN and "O_CLOEXEC" in previous.args
                            and previous.ret.split("<")[0] == args[0].split("<")[0]), ("nonadjacent cloexec", call)
                continue
            if call.name in NON_FS or call.name == EXIT_EVENT:
                continue
            if call.name == "mmap" and "MAP_ANONYMOUS" in call.args:
                continue
            if call.name == "landlock_add_rule":
                paths = re.findall(r"parent_fd=(\d+)<(/[^>]+)>", call.args)
                assert active == "read-layer" and len(paths) == 1 and paths[0][1] in roots, ("Landlock root widening", call)
                use(int(paths[0][0]), paths[0][1])
                assert "LANDLOCK_ACCESS_FS_READ_FILE" in call.args and "LANDLOCK_ACCESS_FS_READ_DIR" in call.args
            if call.name in {"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"}:
                assert active == "read-layer", ("Landlock phase/widening", call)
                counts[active][call.name] += 1
                continue
            allowed = OPEN | {"stat", "lstat", "newfstatat", "fstatat64", "statx", "fstat", "fstat64", "fstatfs", "fstatfs64", "read", "pread64", "readv", "readlink", "readlinkat", "getdents", "getdents64", "faccessat2", "mmap", "lseek"}
            assert call.name in allowed, ("unknown repository effect", call)
            if call.name == "mmap":
                assert "PROT_WRITE" not in call.args and "MAP_PRIVATE" in call.args, call
            path = repository_path(call)
            path_check(call.name, path, call.args)
            # Validate argument descriptor generations, including relative
            # opens and mappings. AT_FDCWD is allowed only for absolute paths.
            index = 4 if call.name == "mmap" else 0
            fd = FD_ARG.fullmatch(args[index]) if len(args) > index else None
            if fd and int(fd[1]) >= 0:
                use(int(fd[1]), fd[2])
            if call.name in OPEN and not call.ret.startswith("-1"):
                result = FD_ARG.fullmatch(call.ret)
                assert result and result[2], ("unplaced open result", call)
                bind(int(result[1]), result[2])
            if call.name in {"getdents", "getdents64"}:
                directory(path, int(args[2]))
            primitive = held_metadata_kind(call, args) or call.name
            if primitive == "open" and active == "read-layer" and path == "/":
                primitive = "openat"  # same fixed-slash libc alias as B3
            counts[active][primitive] += 1
    assert seen and seen[-1] == "end", ("missing repository phase evidence/completion", seen)
    for name, axes in expected_axes.items():
        expected = collector_repository_expected(CollectorAxes(**axes))
        assert dict(counts.get(name, {})) == {k: v for k, v in expected.items() if v}, (name, counts.get(name), expected)
    phases.update({key: dict(value) for key, value in counts.items()})


def _product_roles(trace):
    """Resolve task lifetimes using creation edges and fixed product argv.

    A vfork exec can be recorded before the parent's spawn return. Resolve
    the entire lifetime before counting, including watchdog threads. Unknown
    process execs remain commands; they never disappear from the child count.
    """
    import ast
    # 이것을 실패시키는 것: if trace.errors 조건을 제거하거나 반전하는 변이.
    if trace.errors:
        raise ValueError(trace.errors)
    generations = defaultdict(int)
    tasks, keys = defaultdict(list), {}
    for c in trace:
        key = (c.pid, generations[c.pid])
        tasks[key].append(c)
        keys[c.index] = key
        # 이것을 실패시키는 것: if c.name == EXIT_EVENT 조건을 제거하거나 반전하는 변이.
        if c.name == EXIT_EVENT:
            generations[c.pid] += 1
    root = (trace.first_pid, 0)
    initial = next((c for c in tasks[root] if c.name == "execve" and c.ret == "0"), None)
    # 이것을 실패시키는 것: if initial is None 조건을 제거하거나 반전하는 변이.
    if initial is None:
        raise ValueError("missing successful root exec")
    exe = ast.literal_eval(split_args(initial.args)[0])
    parents, spawns = {}, []
    for c in trace:
        # 이것을 실패시키는 것: if c.name in SPAWN and re.fullmatch(r"[1-9][0-9]*", c.ret) 조건을 제거하거나 반전하는 변이.
        if c.name in SPAWN and re.fullmatch(r"[1-9][0-9]*", c.ret):
            pid = int(c.ret)
            # The lifetime whose records surround the parent's return (an
            # early child may already have exited); PID reuse stays separate.
            candidates = [k for k in tasks if k[0] == pid and k != root and k not in parents]
            # 이것을 실패시키는 것: if not candidates 조건을 제거하거나 반전하는 변이.
            if not candidates:
                raise ValueError(f"spawn has no child evidence: {c}")
            child = min(candidates, key=lambda k: tasks[k][0].index)
            parents[child] = keys[c.index]
            spawns.append((c, child))
    roles = {root: "front"}
    def resolve(key, visiting=frozenset()):
        # 이것을 실패시키는 것: if key in roles 조건을 제거하거나 반전하는 변이.
        if key in roles:
            return roles[key]
        # 이것을 실패시키는 것: if key not in parents or key in visiting 조건을 제거하거나 반전하는 변이.
        if key not in parents or key in visiting:
            raise ValueError(f"unresolved task: {key}")
        parent = resolve(parents[key], visiting | {key})
        role = parent
        for c in tasks[key]:
            # 이것을 실패시키는 것: if c.name in {"execve", "execveat"} and c.ret == "0" 조건을 제거하거나 반전하는 변이.
            if c.name in {"execve", "execveat"} and c.ret == "0":
                args = split_args(c.args)
                role = "command"
                # 이것을 실패시키는 것: if c.name == "execve" and len(args) == 3 조건을 제거하거나 반전하는 변이.
                if c.name == "execve" and len(args) == 3:
                    path = ast.literal_eval(args[0])
                    argv = ast.literal_eval(args[1])
                    empty_env = bool(re.fullmatch(r"(?:0x[0-9a-f]+ /\* 0 vars \*/|\[\])", args[2]))
                    # 이것을 실패시키는 것: if empty_env and argv[:2] == [exe, "__refresh-v1"] and path == exe and parent == "front" 조건을 제거하거나 반전하는 변이.
                    if empty_env and argv[:2] == [exe, "__refresh-v1"] and path == exe and parent == "front":
                        role = "helper"
                    collector = next((a.split("=", 1)[1] for a in ast.literal_eval(split_args(initial.args)[1])
                                      # 이것을 실패시키는 것: if a.startswith("--collector-exe=")), exe.rpartition("/")[0] + "/bingsu-collect") 조건을 제거하거나 반전하는 변이.
                                      if a.startswith("--collector-exe=")), exe.rpartition("/")[0] + "/bingsu-collect")
                    # 이것을 실패시키는 것: if empty_env and path == collector and argv == [collector, "__collect-v1"] and parent == " 조건을 제거하거나 반전하는 변이.
                    if empty_env and path == collector and argv == [collector, "__collect-v1"] and parent == "helper":
                        role = "collector"
        roles[key] = role
        return role
    for key in tasks:
        resolve(key)
    return keys, roles, spawns


def role_children(trace):
    """Successful process creations per parent role; threads are separate."""
    keys, roles, spawns = _product_roles(trace)
    counts = dict.fromkeys(("front", "helper", "collector", "command"), 0)
    for call, child in spawns:
        # 이것을 실패시키는 것: watchdog 스레드의 exec로 collector 프로세스 생성을 숨기는 변이.
        if "CLONE_THREAD" in call.args and any(c.name in {"execve", "execveat"} and c.ret == "0"
                                               for c in trace if keys[c.index] == child):
            raise ValueError("thread exec changes the product process identity")
        # 이것을 실패시키는 것: if "CLONE_THREAD" not in call.args 조건을 제거하거나 반전하는 변이.
        if "CLONE_THREAD" not in call.args:
            parent = roles[keys[call.index]]
            expected = {"front": "helper", "helper": "collector"}.get(parent)
            # 이것을 실패시키는 것: 쓰기 전용 자식·명령 exec를 정상 helper/collector로 세는 것.
            if expected and roles[child] != expected:
                raise ValueError(f"unexpected child role: {parent} -> {roles[child]}")
            counts[parent] += 1
    return counts


def first_index(trace, role, predicate):
    """First matching completed call in a role, failing closed if missing.

    Timing comparisons use calls in the helper's own main TID; its reads
    cannot execute during its pending process creation syscall.
    """
    keys, roles, _ = _product_roles(trace)
    return next(c.index for c in trace if roles[keys[c.index]] == role and predicate(c))
