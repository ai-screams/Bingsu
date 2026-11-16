"""The helper plan (axes of one round) and the checks and counters its steps share."""
from dataclasses import dataclass
from .common import ceil_div
from .synthetic import HelperAxes
from .tables import BUILTIN_BIN_LINKS_MAX, BUILTIN_PATH_FOLDERS_MAX, BUILTIN_SHIM_HOMES_MAX, BUILTIN_STAGES, BUILTIN_WALK_NAMES_MAX, COMMAND_STAGES, HelperStage, MAX_RW_COUNT, MUSL_PRIMITIVES, PRIMITIVES, STARTUP_PRIMITIVES


@dataclass
class HelperPlan:
    """One traced refresh helper run and the fixture facts it depends on.

    `stages` is one of ("unchanged",), ("publish",), ("failure-last-good",)
    or ("failure-recover",), with
    "collect" added when the screen selects collection. `ax` describes the
    config sources; the product shape covered here is one config.toml with
    conf.d, config.json, config.local.toml and config.local.json absent, no
    extends, links or approval record.
    Component counts are path names after "/": runtime, state and config
    (`ax.P`) roots, the folder holding the pinned executable link and the
    folder of its target. `failure-last-good` is a broken config with no
    current snapshot, so the helper reads last-good and publishes an invalid
    marker; `failure-recover` is a current snapshot whose mode refuses the
    read, so the run stops there and LockedStore's drop reclaims the slots.
    """
    stages: tuple
    ax: HelperAxes
    runtime_components: int
    context_components: int
    snapshot_bytes: int
    marker_bytes: int
    buf: int
    state_components: int
    exe_link_components: int
    exe_components: int
    sequence_bytes: int = 96
    # glibc NSS reads of nsswitch.conf (with EOF) and /etc/passwd up to the
    # user's line, from the host files and their st_blksize.
    nsswitch_reads: int = 0
    passwd_reads: int = 0
    # musl only: its getpwuid reads /etc/passwd through a 1 KiB stdio buffer
    # and fclose seeks back over the bytes it read past the user's line (one
    # lseek SEEK_CUR when any are left; root's first line leaves most of the
    # file). glibc's rewind is in the passwd primitive. From the host file.
    passwd_seeks: int = 0
    # Collect stage: names of the pinned collector's folder, its size (the
    # build check reads it), and the steady store of one earlier collection:
    # catalog, current response and previous response lengths.
    collector_components: int = 0
    collector_bytes: int = 0
    catalog_bytes: int = 0
    response_bytes: int = 0
    previous_bytes: int = 0
    # The shell session's breaker record (collection_breaker), present after
    # the earlier collection.
    breaker_bytes: int = 0
    # "gnu" or "musl", from the binary (PT_INTERP), never from the trace.
    libc: str = "gnu"
    # Capture/native runner architecture, never inferred from call counts.
    # The default preserves the original aarch64 captures; live sets it.
    arch: str = "aarch64"
    # Command stages (M6 C4, one config unit `/usr/bin/true` with
    # PATH=/usr/bin, the shell's session): the command response the warm-up
    # left (and the miss republishes at the same length), the cgroup.procs
    # length of the helper's own cgroup, whether the session cgroup parent
    # opens (the atomic path; a host that refuses its mkdir is best effort),
    # and the names of the PATH folder and of the target's folder. The
    # collection catalog length is `catalog_bytes`.
    command_bytes: int = 0
    cgroup_procs_bytes: int = 0
    cgroup_parent: bool = False
    path_names: int = 0
    target_names: int = 0
    # Symlink hops from the target's name to its file inside its folder (a
    # runner's /usr/bin/true can be a link to gnutrue): each is an lstat that
    # finds the link, its readlinkat and the name's lstat again.
    target_links: int = 0
    # Names of the shell's folder below "/": the command round's repository
    # scan walks them.
    shell_names: int = 0
    # Builtin stages: the PATH folders the round's one lookup walks (the
    # names of all of them are `path_names`), the version managers' shim
    # homes a found command is checked against when none matched, and the
    # links inside a manager's bin folder its executable follows.
    path_folders: int = 0
    manager_homes: int = 0
    bin_links: int = 0
    # Session locks (`command-<digest>.lock`) in the runtime root when the GC
    # runs: the GC stats each one's name (m6-C4a7); and how many of them are
    # older than a day and not this session's (each is opened and locked).
    session_locks: int = 0
    stale_locks: int = 0


def read_to_end_calls(n: int) -> int:
    """read(2) calls of Rust std's default_read_to_end on an empty Vec, for a
    file of `n` bytes: a 32-byte probe, then reads into the spare capacity of
    an amortized-doubling Vec (at least 32 more), at most 8 KiB per call
    until a full read doubles that cap, and the final read that returns 0."""
    if not 0 <= n <= 1 << 20:
        raise ValueError("config source size outside the reviewed range")
    calls, length = 1, min(32, n)
    if length == 0:
        return calls
    cap, limit = length, 8192
    while True:
        if length == cap:
            cap = max(cap * 2, length + 32)
        want = min(cap - length, limit)
        got = min(want, n - length)
        calls += 1
        if got == 0:
            return calls
        if got == want and want >= limit:
            limit *= 2
        length += got


_LIBC = {"gnu": {}, "musl": MUSL_PRIMITIVES}


_primitives = PRIMITIVES


def _use_primitives(table: dict) -> None:
    """Select the table `_add` counts with. The formulas that need a libc or
    platform table set it for one call and put `PRIMITIVES` back after; the
    table lives here, so `_add` and its selector are one module's variable."""
    global _primitives
    _primitives = table


def _add(total: dict, name: str, times: int = 1) -> None:
    if times < 0:
        raise ValueError(name)
    for kind, n in _primitives.get(name, PRIMITIVES[name]).items():
        total[kind] = total.get(kind, 0) + n * times


def _check_plan(p: HelperPlan) -> None:
    if (p.arch, p.libc) not in STARTUP_PRIMITIVES:
        raise ValueError("unreviewed helper architecture/libc")
    ax = p.ax
    base = [s for s in p.stages if s != "collect" and s not in COMMAND_STAGES and s not in BUILTIN_STAGES]
    command = [s for s in p.stages if s in COMMAND_STAGES]
    builtin = [s for s in p.stages if s in BUILTIN_STAGES]
    if (len(base) != 1 or base[0] not in {"unchanged", "publish", "failure-last-good", "failure-recover"}
            or len(p.stages) != len(set(p.stages)) or not set(p.stages) <= set(HelperStage.__args__)
            or len(command) > 1 or len(builtin) > 1):
        raise ValueError("stages: one non-collect stage, optionally collect or one command stage")
    # A base other than unchanged, or a command stage beside it, is refused by
    # the collect and command checks.
    if builtin and (
            "collect" not in p.stages
            or p.command_bytes < 64 or not 0 < p.cgroup_procs_bytes < 4096
            or min(p.shell_names, p.path_folders, p.target_names) < 1 or p.path_names < p.path_folders
            or p.path_folders > BUILTIN_PATH_FOLDERS_MAX
            or p.path_names > p.path_folders * BUILTIN_WALK_NAMES_MAX or p.target_names > BUILTIN_WALK_NAMES_MAX
            or p.manager_homes > BUILTIN_SHIM_HOMES_MAX or p.bin_links > BUILTIN_BIN_LINKS_MAX
            or p.target_links
            or (builtin[0] == "builtin_probe") != (p.manager_homes > 0)
            or (builtin[0] == "builtin_fast") != (p.bin_links > 0)):
        # Reviewed: a revalidated snapshot, a collection with the dir and git
        # screen, one language whose response the warm-up published; the
        # probe's command found as a regular file (no link), the fast path's
        # interpreter behind a link inside pyenv's bin.
        raise ValueError("unreviewed builtin shape")
    if command and (
            base != ["unchanged"] or "collect" in p.stages
            or (command[0] == "command_not_run") != (p.command_bytes == 0)
            or 0 < p.command_bytes < 64
            or (command[0] == "command_miss" and min(p.path_names, p.target_names) < 1)
            or (command[0] == "command_miss" and p.catalog_bytes < 64)
            or not 0 < p.cgroup_procs_bytes < 4096):
        # Reviewed: a revalidated snapshot, a screen without dir or git, one
        # unit whose response the warm-up published.
        raise ValueError("unreviewed command shape")
    if (ax.F != 1 or len(ax.B) != 1 or ax.L or ax.D or ax.E_n or ax.E_b or ax.M or ax.R != 3
            or ax.acl or ax.lock_fd_inherited):
        # Other source shapes (conf.d listings, extends, links, ACL fallbacks,
        # an inherited lock) have their own walks; review them before use.
        raise ValueError("unreviewed helper source shape")
    if min(ax.P, p.runtime_components, p.state_components, p.exe_link_components,
           p.exe_components, p.passwd_reads) < 1 or p.nsswitch_reads < 0 or not 4 <= p.context_components <= 64:
        raise ValueError("helper fixture axes")
    if p.libc not in _LIBC or (p.libc == "musl") != (p.nsswitch_reads == 0):
        raise ValueError("libc: gnu reads nsswitch.conf, musl does not")
    if p.passwd_seeks not in (0, int(p.libc == "musl")):
        raise ValueError("passwd seeks: musl's fclose only, at most one")
    if p.buf != MAX_RW_COUNT or p.marker_bytes != 208 or p.sequence_bytes != 96:
        raise ValueError("store transfers are whole-file calls of fixed record sizes")
    if "collect" in p.stages and (
            base != ["unchanged"] or p.collector_components < 1
            or not 65_536 < p.collector_bytes <= 64 << 20
            or min(p.catalog_bytes, p.response_bytes, p.previous_bytes, p.breaker_bytes) < 64):
        # Reviewed: a revalidated snapshot whose screen selects dir and git,
        # absent global Git inputs, a shell session with a newer sequence, and
        # the store and breaker record one earlier collection left.
        raise ValueError("unreviewed collect shape")


def verify_build_reads(size: int) -> int:
    """pread calls of collector::verify_build: 64 KiB first, then windows that
    keep a 48-byte overlap, so each later call reads 65,488 new bytes."""
    return 1 + ceil_div(max(0, size - 65_536), 65_488)
