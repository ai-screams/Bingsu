"""Collector formulas: success, repository, PathFacts limits, and the product cases built on collection."""
from dataclasses import dataclass
from .collection import collection_expected, collection_front_expected
from .common import ceil_div


def git_collection_limits(*, ancestor_directories: int) -> dict[str, int]:
    """F1 names-only phase limits from the fixed PathFacts contract.

    Raw entries are processed up to 256, not accumulated between directories.
    Each syscall buffer remains 8 KiB even when its final batch contains more
    entries than the processing limit. EOF costs one additional call.
    Full repository coefficients remain collector_repository_expected below.
    """
    if not 0 <= ancestor_directories <= 32:
        raise ValueError("ancestor capability count exceeds 32")
    return {"directories": ancestor_directories, "raw_per_directory": 256,
            "dir_chunk": 8192, "content_reads": 0, "entry_stats": 0,
            "landlock_rules": 0}


def collector_success_expected(worker: str, *, landlock: bool = False,
                               repository_probe: bool = False, openat2_succeeded: bool = True) -> dict[str, int]:
    """Exact Linux success budgets, with a separate shipped debug entry.

    The -O fixture and shipped release have three access-mode queries. Rust's
    OwnedFd drop checks in the shipped debug build add F_GETFD for statm and
    WorkerFds' result/request/lock, plus the ruleset when Landlock is installed.
    Build configuration selects the entry; measured fd_query never selects it.
    """
    queries = {"fixture": 3, "shipped-release": 3,
               "shipped-debug": 7 + int(landlock)}[worker]
    result = {"exec": 1, "fd_query": queries, "fstat": 1, "acl": 1,
              "cwd": 1, "openat": 1, "read": 1}
    if repository_probe:
        # fstat is one held-fd metadata primitive on every libc (fstat,
        # newfstatat or statx by shape); statx is the separate MNT_ID query.
        result.update({"probe_openat": 1, "probe_openat2": 1,
                       "probe_fstat": 1, "probe_fstatfs": 1, "probe_statx": 1,
                       "kernel_release": 1})
        if worker == "shipped-debug":
            result["fd_query"] += 1 + int(openat2_succeeded)
    return result


@dataclass
class CollectorAxes:
    # Fixture-defined axes, never fitted from the trace total. Components are
    # successful ordinary edges; candidates are failed leaf open attempts.
    components: int = 0
    candidates: int = 0
    symlinks: int = 0
    directories: int = 0
    raw_entries: int = 0
    dir_bytes: tuple[int, ...] = ()
    files: int = 0
    read_bytes: tuple[int, ...] = ()
    maps: int = 0
    probes: int = 0
    retries: int = 0
    backend: str = "openat2"
    phase: str = "content"
    roots: int = 0
    root_inputs: int = 0
    readonly: int = 0
    capped_directories: int = 0
    stat_leaves: int = 0
    stat_directory_groups: int = 0  # distinct cached directory edges, including shared ancestors
    worktree_hash_bytes: tuple[int, ...] = ()


def collector_repository_expected(ax: CollectorAxes) -> dict[str, int]:
    """Primitive table from safe_read/linux.rs; phase windows stay separate.

    Acquisition root: open/fstat/fstatfs/statx. fstat includes libc's held-fd
    newfstatat/statx metadata shapes; statx counts only the MNT_ID primitive.
    Ordinary edge adds lstat too.
    Content fast: openat2/fstat/fstatfs/statx per file or directory; stepwise
    uses components and their lstat instead. Each followed link adds two lstat
    observations and readlink. Mutable reads include one EOF/cap+1 observation.
    Read-layer validation: open+fstat slash, fstat each supplied root (including
    duplicates), then create + one add per distinct root + restrict.
    Retry axes count extra open attempts only; other retries need their own
    fixture phase instead of being hidden in a total allowance.
    Index stats: one no-follow newfstatat per leaf, no file open. Each non-root
    cached edge is opened once with lstat/fstat/mount checks and an exit lstat.
    Shared ancestors are counted once in stat_directory_groups, separately from
    non-cache components. Hashes use one original-root openat2 or one stepwise
    leaf open, then EOF and same-fd post-read fstat. No directory re-resolution.
    """
    scalars = [ax.components, ax.candidates, ax.symlinks, ax.directories,
               ax.raw_entries, ax.files, ax.maps, ax.probes, ax.retries,
               ax.roots, ax.root_inputs, ax.readonly, ax.capped_directories,
               ax.stat_leaves, ax.stat_directory_groups]
    if min(scalars + list(ax.dir_bytes) + list(ax.read_bytes) + list(ax.worktree_hash_bytes)) < 0:
        raise ValueError("negative repository axis")
    if ax.backend not in {"openat2", "stepwise"} or ax.phase not in {"acquisition", "content", "read-layer", "probe", "ancestor-names"}:
        raise ValueError("unreviewed repository primitive table")
    if ax.phase == "ancestor-names":
        # Use held ancestor descriptors only. Each directory has its own
        # chunk rounding and EOF, never per-entry stat/open or a new read root.
        if (len(ax.dir_bytes) != ax.directories or ax.directories > 32
                or ax.raw_entries > 256 * ax.directories
                or ax.capped_directories > ax.directories
                or any((ax.files, ax.components, ax.candidates, ax.symlinks,
                        ax.maps, ax.probes, ax.retries, ax.roots, ax.root_inputs,
                        ax.readonly, ax.stat_leaves, ax.stat_directory_groups))
                or ax.read_bytes or ax.worktree_hash_bytes):
            raise ValueError("names-only held ancestor axes")
        return {"getdents64": sum(ceil_div(n, 8192) + 1 for n in ax.dir_bytes) - ax.capped_directories}
    if ax.phase == "read-layer":
        if not 1 <= ax.roots <= ax.root_inputs <= 3:
            raise ValueError("selected roots only")
        return {"openat": 1, "fstat": 1 + ax.root_inputs,
                "landlock_create_ruleset": 1, "landlock_add_rule": ax.roots,
                "landlock_restrict_self": 1}
    if ax.phase == "probe":
        return {"openat": ax.probes, "openat2": ax.probes,
                "fstat": ax.probes, "fstatfs": ax.probes, "statx": ax.probes}
    if len(ax.read_bytes) != ax.files or len(ax.dir_bytes) != ax.directories or ax.capped_directories > ax.directories:
        raise ValueError("per-file and per-directory axes required")
    acquisition = ax.phase == "acquisition"
    opened = ax.components + 1 if acquisition else ax.files + ax.directories if ax.backend == "openat2" else ax.components
    stepwise = acquisition or ax.backend == "stepwise"
    hashes = len(ax.worktree_hash_bytes)
    opened += ax.stat_directory_groups + hashes
    return {"openat" if stepwise else "openat2": opened + ax.candidates + ax.retries,
            "fstat": opened + hashes,
            "newfstatat": (ax.components + hashes if stepwise else 0) + 2 * ax.symlinks + ax.stat_leaves + 2 * ax.stat_directory_groups,
            # Readonly rechecks mount flags on the held cwd fd, independently of opened content fds.
            "fstatfs": opened + ax.readonly, "statx": opened, "readlinkat": ax.symlinks,
            "read": sum(ceil_div(n, 16384) + 1 for n in ax.read_bytes + ax.worktree_hash_bytes),
            "getdents64": sum(ceil_div(n, 8192) + 1 for n in ax.dir_bytes) - ax.capped_directories,
            "mmap": ax.maps, "faccessat2": ax.readonly}


def collector_product_expected(case: str, *, body_bytes: int = 256,
                               previous_bytes: int = 256, cwd_bytes: int = 4,
                               gc_directories: int = 0, gc_files: int = 0) -> dict:
    """M3b phase increments, never total helper/path-walk C-axis costs.

    Cases select observations/branches; byte and directory axes determine the
    counts. GC inventory counts must be supplied from the controlled fixture,
    not copied from an aggregate trace. M3d retains full role coefficients.
    """
    cases = {"product-mask0", "fixture", "ready-failure", "partial", "malformed-flood",
             "current", "previous", "snapshot-change", "busy", "long-cwd", "collision",
             "legacy-gc", "runtime-unsafe", "proc-absent", "nofile-lowered"}
    if case not in cases or not 1 <= cwd_bytes <= 65536 or min(gc_directories, gc_files) < 0:
        raise ValueError("invalid M3b case/axes")
    # A fresh product runtime stops at its one absent namespace open. Unsafe runtime or
    # unavailable spawn prerequisites stop before any response/store access.
    stopped = case in {"runtime-unsafe", "proc-absent", "nofile-lowered"}
    absent = case == "product-mask0"
    front = ({} if stopped else collection_front_expected(0, (), (), absent=True) if absent
             else collection_front_expected(3, (64 + body_bytes, 64 + previous_bytes, None),
                                            (body_bytes, previous_bytes)))
    publishes = case in {"fixture", "partial", "malformed-flood", "long-cwd", "legacy-gc"}
    if case == "ready-failure":
        # Admission created all three directories before startup failed. The
        # three file slots are still absent, so there are six opens and no reads.
        front = collection_front_expected(3, (None, None, None), ())
    publication = collection_expected(3, body_bytes, False, False) if publishes else {}
    # collector-effects is the expected ceiling, not evidence. Linux failure
    # traces supply measured counts; untraced cases are labelled in the ledger.
    return {"front-prefetch": front, "helper-publication": publication,
            "helper-gc": {"getdents": 2 * gc_directories, "unlinkat": gc_files,
                          "fsync": 0},
            "collector-effects": {"spawn": 0, "network": 0, "write": 0,
                                  "renameat": 0, "unlinkat": 0, "fsync": 0}}
