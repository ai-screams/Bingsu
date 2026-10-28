"""Budget formulas (spec section 8 "filesystem call budget formula").

Coefficient values and per-axis caps are M3; M1 evaluates the shape with
caller-provided coefficients (all 1 for the synthetic program)."""
from dataclasses import dataclass, field, replace
from typing import Literal


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


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


@dataclass
class HelperAxes:
    F: int  # unique config source files
    P: int  # path components walked
    L: int  # symlinks walked
    R: int  # references and candidates tried
    D: int  # source folders listed (conf.d)
    # Directory entries per folder. An axis with its own cap (M3) but no term
    # in any call formula: recorded per fixture (spec 9 M1 row, change (6)).
    E_n: list[int] = field(default_factory=list)
    E_b: list[int] = field(default_factory=list)  # directory bytes per folder
    M: int = 0  # unique mounts (statfs)
    B: list[int] = field(default_factory=list)  # bytes per source file (changed)
    acl: bool = False
    lock_fd_inherited: bool = False


@dataclass
class Coeffs:
    c1: int = 1
    c2: int = 1
    c3: int = 1
    c4: int = 1
    c5: int = 1
    c6: int = 1
    c7: int = 1
    c8: int = 1
    c9: int = 1
    c11: int = 1
    c12: int = 1
    c13: int = 1


def synthetic_helper_expected(ax: HelperAxes, co: Coeffs, changed: bool, buf: int, snapshot_bytes: int) -> dict[str, int]:
    """The M1 synthetic program's helper: spec coefficients plus its fixed
    lock/header/marker terms. The product helper uses helper_stage_expected."""
    e = {
        "openat": co.c1 * ax.P + co.c2 * ax.R + co.c3 * ax.D + (co.c4 * ax.F if changed else 0),
        "fstat": co.c5 * ax.P + co.c6 * ax.R + co.c7 * ax.F,
        "readlink": co.c8 * ax.L,
        # Folder listings need a final call that returns 0: ceil + 1.
        "getdents": co.c9 * sum(ceil_div(b, buf) + 1 for b in ax.E_b),
        "statfs": co.c11 * ax.M,
        "acl": co.c12 * (ax.F + ax.P) if ax.acl else 0,
        # Sources can change in place: ceil + 1 per file.
        "read": co.c13 * sum(ceil_div(b, buf) + 1 for b in ax.B) if changed else 0,
    }
    # Fixed terms. Header and marker are replaced only by rename, so they are
    # read once without an end check.
    e["openat"] += (0 if ax.lock_fd_inherited else 1) + 1 + 1 + 1 + (1 if changed else 0)
    e["fstat"] += 1 + 1 + 1
    e["flock"] = 1
    e["read"] += 2
    e["write"] = 1 + (ceil_div(snapshot_bytes, buf) if changed else 0)
    e["fsync"] = 0  # boot-scoped runtime files are not fsynced (spec 3 state file rule)
    e["renameat"] = 2 if changed else 1
    e["unlinkat"] = 0
    return e


HelperStage = Literal["unchanged", "publish", "collect", "failure-last-good", "failure-recover"]
# Linux read(2)/write(2) transfer at most MAX_RW_COUNT bytes per call. Outside
# collection metering the release helper reads and writes each store file in
# one call of its full length (read_exact_len, write_fd), plus one EOF read.
MAX_RW_COUNT = 0x7FFF_F000

# Calls of one product operation in the release refresh helper on Linux glibc,
# in classify.helper_kind's vocabulary. Each entry names the code that makes
# them. Walk entries are per path name or per descriptor, so axes multiply them.
PRIMITIVES: dict[str, dict[str, int]] = {
    # helper::run before NSS: the watchdog thread (helper_limits::start) and
    # detach's chdir("/") and umask(077).
    "start": {"exec": 1, "thread": 1, "cwd": 1, "umask": 1},
    "stack_guard": {},  # overridden by the architecture/libc startup table
    # SystemClock::observe: boot_id open, fd statx, fstatfs, read and EOF read;
    # /proc/self, ns and timens_offsets opens with fstatfs, statx on the file;
    # readlinkat of time and time_for_children.
    "clock": {"openat": 4, "fstat": 2, "statfs": 4, "read": 2, "readlink": 2},
    # sys::passwd_entry through glibc: two nscd connects, nsswitch.conf and "/"
    # stats, nsswitch.conf open with an fd stat before and after its reads,
    # then /etc/passwd open, fd stat and rewind. Both files' buffered reads
    # are axes.
    "passwd": {"network": 4, "fstat": 5, "openat": 2, "seek": 1},
    # runtime_root::open_chain: an O_PATH open and fd_facts per folder, "/" too.
    "chain_folder": {"openat": 1, "fstat": 1},
    # Chain::revalidate: fd_facts per folder and at_stamp per name.
    "chain_recheck_folder": {"fstat": 1},
    "chain_recheck_name": {"fstat": 1},
    # source_path::Resolved::open: "/" open, fd stat and metadata; per name a
    # no-follow lstat, open, metadata and fd stat. A link costs a second lstat
    # and a readlinkat and is not opened; a missing last name is one lstat.
    "resolved_root": {"openat": 1, "fstat": 2},
    "resolved_name": {"openat": 1, "fstat": 3},
    "resolved_link": {"fstat": 2, "readlink": 1},
    "resolved_missing": {"fstat": 1},
    # Resolved::revalidate (and revalidate_bindings): metadata and fd stat per
    # descriptor, lstat per name, readlinkat per link.
    "resolved_recheck_fd": {"fstat": 2},
    "resolved_recheck_name": {"fstat": 1},
    "resolved_recheck_link": {"readlink": 1},
    # File::metadata or Path::symlink_metadata: one statx.
    "metadata": {"fstat": 1},
    # sys::fd_is_local: one fstatfs.
    "fd_is_local": {"statfs": 1},
    # snapshot_store::check_data: fd_facts, metadata and fd_is_local.
    "check_data": {"fstat": 2, "statfs": 1},
    # same_name: file_stamp of the fd and at_stamp of the name.
    "same_name": {"fstat": 2},
    # trust_record::check_record: fd_facts and metadata.
    "check_record": {"fstat": 2},
    # CheckedContextFd::under_runtime per component: open, fd_facts, fd_is_local;
    # mkdirat first when creating.
    "context_component": {"openat": 1, "fstat": 1, "statfs": 1},
    "context_mkdir": {"mkdir": 1},
    # File::try_clone.
    "dup": {"dup": 1},
    # sys::open_lock_at on an existing lock: the O_EXCL create attempt, then open.
    "open_lock": {"openat": 2},
    "flock": {"flock": 1},
    # LockedStore::remove_slot of an absent stage slot: one open.
    "absent_slot": {"openat": 1},
    # LockedStore::read of an absent file: one open.
    "absent_file": {"openat": 1},
    "open": {"openat": 1},
    # sys::create_file_at: O_EXCL open and fchmod.
    "create": {"openat": 1, "chmod": 1},
    "rewind": {"seek": 1},
    "rename": {"renameat": 1},
    "pread": {"read": 1},
    # helper_limits::install: /proc/self/statm open, metadata, read and EOF read.
    "statm": {"openat": 1, "fstat": 1, "read": 2},
    # snapshot_store::check_directory: fd_facts and fd_is_local.
    "check_directory": {"fstat": 1, "statfs": 1},
    # collection_gc and CollectionStore walks below the runtime root, per
    # folder: open, fd_facts, fd_is_local, metadata, at_stamp of the name.
    "collection_folder": {"openat": 1, "fstat": 3, "statfs": 1},
    # collector::spawn: the /proc/self/fd listing that closes inherited fds
    # (open, fd stat, one filled read and the EOF read), then the child's two
    # /dev/null opens and chdir("/") before its exec, and the supervisor thread.
    "fd_listing": {"openat": 1, "fstat": 1, "getdents": 2},
    "spawn": {"spawn": 1, "openat": 2, "cwd": 1, "thread": 1},
    # DirectoryCursor::open on a held folder: "." open, fd stat, flag query,
    # FD_CLOEXEC; its reads are one filled read and the EOF read.
    "directory_cursor": {"openat": 1, "fstat": 1, "fd_query": 1, "fd_flags": 1, "getdents": 2},
}

# musl differs only in its libc wrappers: open(O_CLOEXEC), fopen("e"),
# opendir and fcntl(F_DUPFD_CLOEXEC) add an F_SETFD of the new fd (musl's
# fallback for kernels without those flags), and its NSS reads /etc/passwd
# with stdio and no nscd or nsswitch.conf. Entries replace PRIMITIVES ones;
# observed on aarch64 musl release builds (fixtures/helper-stage-traces.md).
MUSL_PRIMITIVES: dict[str, dict[str, int]] = {
    "passwd": {"openat": 1, "fd_flags": 2},
    "dup": {"dup": 1, "fd_flags": 1},
    "statm": {"openat": 1, "fstat": 1, "read": 2, "fd_flags": 1},
    # musl's opendir does not stat the folder.
    "fd_listing": {"openat": 1, "getdents": 2, "fd_flags": 1},
}

# Rust std main-thread stack guard via glibc pthread_getattr_np. In the
# x86_64 CI capture, /proc/self/maps stdio teardown calls lseek(SEEK_CUR)
# then lseek(SEEK_SET). Neither call is a loader exemption. The preceding
# open/stat/reads retain the existing prologue rules; no new ignores here.
# aarch64 glibc captures have maps reads but no seeks. Rust std's
# install_main_guard_linux_musl returns None on both architectures, so that
# startup path has neither maps reads nor seeks (also seen in aarch64 musl).
STARTUP_PRIMITIVES = {
    ("x86_64", "gnu"): {"stack_guard": {"seek": 2}},
    ("aarch64", "gnu"): {"stack_guard": {}},
    ("x86_64", "musl"): {"stack_guard": {}},
    ("aarch64", "musl"): {"stack_guard": {}},
}


@dataclass
class HelperPlan:
    """One traced refresh helper run and the fixture facts it depends on.

    `stages` is one of ("unchanged",), ("publish",), ("failure-last-good",)
    or ("failure-recover",), with
    "collect" added when the screen selects collection. `ax` describes the
    config sources; the product shape covered here is one config.toml with
    conf.d and config.local.toml absent, no extends, links or approval record.
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


def _add(total: dict, name: str, times: int = 1) -> None:
    if times < 0:
        raise ValueError(name)
    for kind, n in _primitives.get(name, PRIMITIVES[name]).items():
        total[kind] = total.get(kind, 0) + n * times


def _resolved_open(e: dict, names: int, *, links: int = 0, missing: bool = False) -> None:
    _add(e, "resolved_root")
    _add(e, "resolved_name", names - int(missing))
    _add(e, "resolved_missing", int(missing))
    _add(e, "resolved_link", links)


def _resolved_recheck(e: dict, fds: int, names: int, links: int = 0) -> None:
    _add(e, "resolved_recheck_fd", fds)
    _add(e, "resolved_recheck_name", names)
    _add(e, "resolved_recheck_link", links)


def _open_chain(e: dict, names: int) -> None:
    _add(e, "chain_folder", names + 1)


def _chain_recheck(e: dict, names: int) -> None:
    _add(e, "chain_recheck_folder", names + 1)
    _add(e, "chain_recheck_name", names)


def _ensure_root(e: dict, names: int) -> None:
    # runtime_root::ensure_root: chain, locality of its last folder, recheck.
    _open_chain(e, names)
    _add(e, "fd_is_local")
    _chain_recheck(e, names)


def _context(e: dict, p: HelperPlan, *, create: bool) -> None:
    # CheckedContextFd::open: open_runtime_root (ensure_root shape plus the
    # pinned identity metadata), then each context component; two try_clone.
    _ensure_root(e, p.runtime_components)
    _add(e, "metadata")
    _add(e, "context_component", p.context_components)
    _add(e, "context_mkdir", p.context_components if create else 0)
    _add(e, "dup", 2)


def _verify_lock(e: dict) -> None:
    _add(e, "check_data")
    _add(e, "same_name")


def _recover(e: dict) -> None:
    # LockedStore::recover: lock check, then the four absent stage slots.
    _verify_lock(e)
    _add(e, "absent_slot", 4)


def _store_read(e: dict, size: int, buf: int) -> None:
    # LockedStore::read of a present file: open_data's check, stamp, check,
    # the exact-length read, stamp and name identity. These files are replaced
    # only by rename, so there is no end-check read (spec 8 read-count rule).
    _add(e, "open")
    _add(e, "check_data")
    _add(e, "metadata")
    _add(e, "check_data")
    e["read"] = e.get("read", 0) + ceil_div(size, buf)
    _add(e, "metadata")
    _add(e, "same_name")


def _stage(e: dict, size: int, buf: int) -> None:
    # snapshot_store::stage_verified: exclusive create, write, check, rewind,
    # exact readback with EOF read, name identity and stamp.
    _add(e, "create")
    e["write"] = e.get("write", 0) + ceil_div(size, buf)
    _add(e, "check_data")
    _add(e, "rewind")
    e["read"] = e.get("read", 0) + ceil_div(size, buf) + 1
    _add(e, "same_name")
    _add(e, "metadata")


def _install(e: dict, *, small: bool) -> None:
    # LockedStore::install: lock check, Staged::verify (check, stamp, name),
    # a pread of the retained bytes for Sequence and Marker, then the rename.
    _verify_lock(e)
    _add(e, "check_data")
    _add(e, "metadata")
    _add(e, "same_name")
    _add(e, "pread", int(small))
    _add(e, "rename")


def _selection_lock(e: dict, names: int) -> None:
    # SelectionLock::try_lock: state chain, lock open, record check and empty
    # length, flock, then verify: chain recheck, record check, stamp pair, length.
    _open_chain(e, names)
    _add(e, "open_lock")
    _add(e, "check_record")
    _add(e, "metadata")
    _add(e, "flock")
    _chain_recheck(e, names)
    _add(e, "check_record")
    _add(e, "metadata")
    _add(e, "chain_recheck_name")  # at_stamp of selection.lock
    _add(e, "metadata")


def _loader_revalidate(e: dict, k: int) -> None:
    # Loader::revalidate: the observed config.toml walk, each absence (stat and
    # parent walk), the config root evidence and the held executable file.
    _resolved_open(e, k + 1)
    for _ in range(2):
        _add(e, "metadata")
        _resolved_open(e, k)
    _resolved_recheck(e, k + 1, k)
    _resolved_recheck(e, k + 2, k + 1)


def _check_plan(p: HelperPlan) -> None:
    if (p.arch, p.libc) not in STARTUP_PRIMITIVES:
        raise ValueError("unreviewed helper architecture/libc")
    ax = p.ax
    base = [s for s in p.stages if s != "collect"]
    if (len(base) != 1 or base[0] not in {"unchanged", "publish", "failure-last-good", "failure-recover"}
            or len(p.stages) != len(set(p.stages)) or not set(p.stages) <= set(HelperStage.__args__)):
        raise ValueError("stages: one non-collect stage, optionally collect")
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


def _close_only_lock(e: dict, *, create: bool) -> None:
    # collection_store::close_only_lock: open_lock_at when creating, the data
    # open, check, name identity, flock and name identity again.
    _add(e, "open_lock", int(create))
    _add(e, "open")
    _add(e, "check_data")
    _add(e, "same_name")
    _add(e, "flock")
    _add(e, "same_name")


def _read_checked(e: dict, size: int) -> None:
    # collection_store::read_checked: open, stamp, check, 16 KiB metered reads
    # without an EOF read, check, stamp and name identity.
    _add(e, "open")
    _add(e, "metadata")
    _add(e, "check_data")
    e["read"] = e.get("read", 0) + ceil_div(size, 16_384)
    _add(e, "check_data")
    _add(e, "metadata")
    _add(e, "same_name")


def _metered_stage(e: dict, size: int) -> None:
    # stage_verified under the collection meter: the readback is 16 KiB reads
    # plus the EOF read.
    _add(e, "create")
    e["write"] = e.get("write", 0) + 1
    _add(e, "check_data")
    _add(e, "rewind")
    e["read"] = e.get("read", 0) + ceil_div(size, 16_384) + 1
    _add(e, "same_name")
    _add(e, "metadata")


def _staged_verify(e: dict) -> None:
    # Staged::verify: check, stamp, name identity.
    _add(e, "check_data")
    _add(e, "metadata")
    _add(e, "same_name")


def _catalog_commit(e: dict, size: int) -> None:
    # collection_gc catalog write: the absent stage slot, the staged record,
    # the current catalog's check and name, the stage's check, then rename.
    _add(e, "absent_slot")
    _metered_stage(e, size)
    _add(e, "open")
    _add(e, "check_data")
    _add(e, "same_name")
    _staged_verify(e)
    _add(e, "rename")


def _store_verify(e: dict, names: int) -> None:
    # CollectionStore::verify: both folders and the name of each collection
    # edge, then the collection lock's check and name.
    _add(e, "check_directory", 2 * names)
    _add(e, "same_name", names)
    _add(e, "check_data")
    _add(e, "same_name")


def _read_response(e: dict, size: int) -> None:
    _read_checked(e, size)
    _add(e, "metadata")


def _registration_open(e: dict, catalog: int, *, check_runtime: bool = True) -> None:
    # collection_gc::Registration::open: runtime folder check, GC lock,
    # catalog read, runtime metadata.
    _add(e, "check_directory", int(check_runtime))
    _close_only_lock(e, create=True)
    _read_checked(e, catalog)
    _add(e, "metadata")


def _reserve_walk(e: dict, folders: int) -> None:
    # Registration::reserve*: the runtime clone, each folder to the entry and
    # the entry's metadata.
    _add(e, "dup")
    _add(e, "collection_folder", folders)
    _add(e, "metadata")


def _breaker_read(e: dict, size: int) -> None:
    # collection_breaker::read: open, stamp, check, 1 KiB reads, stamp, name.
    _add(e, "open")
    _add(e, "metadata")
    _add(e, "check_data")
    e["read"] = e.get("read", 0) + ceil_div(size, 1_024)
    _add(e, "metadata")
    _add(e, "same_name")


def _ticket_verify(e: dict) -> None:
    # Ticket::verify: the runtime folder, then each session folder and name.
    _add(e, "check_directory", 4)
    _add(e, "same_name", 3)


def _breaker_save(e: dict, p: HelperPlan) -> None:
    # collection_breaker::save: stage slot removal, the old record's check,
    # reserve_breaker_write (GC lock, catalog, session walk, catalog commit),
    # stage create and 1 KiB writes, its check and name, read back of the stage
    # and the old record, then the rename between name checks.
    _add(e, "absent_slot")
    _add(e, "open")
    _add(e, "check_data")
    _add(e, "same_name")
    _registration_open(e, p.catalog_bytes, check_runtime=False)
    _add(e, "metadata")  # the session folder
    _reserve_walk(e, 3)
    _catalog_commit(e, p.catalog_bytes)
    _add(e, "create")
    e["write"] = e.get("write", 0) + ceil_div(p.breaker_bytes, 1_024)
    _add(e, "check_data")
    _add(e, "same_name")
    _breaker_read(e, p.breaker_bytes)
    _breaker_read(e, p.breaker_bytes)
    _add(e, "same_name")
    _add(e, "rename")
    _add(e, "same_name")


def _collect_prefix(e: dict, p: HelperPlan) -> None:
    """Deterministic collection admission, breaker begin, pin and spawn."""
    t, ctx, edges = p.collector_components, p.context_components, 3
    _add(e, "absent_file", 3)  # git_global::attach: three absent global inputs
    _add(e, "dup")  # the runtime descriptor kept for GC
    # PinnedCollector::verify: chain, open, facts, metadata, locality, the
    # build check (metadata, preads), stamp, then executable()'s recheck.
    _open_chain(e, t)
    _add(e, "open")
    _add(e, "metadata", 2)
    e["fstat"] += 1  # fd_facts
    _add(e, "fd_is_local")
    e["read"] = e.get("read", 0) + verify_build_reads(p.collector_bytes)
    _add(e, "metadata")
    _chain_recheck(e, t)
    _add(e, "metadata")
    e["fstat"] += 1  # fd_facts
    _add(e, "chain_recheck_name")
    # CollectionStore::admit: Registration::open (runtime check, GC lock,
    # catalog), reserve (context and collection walk, catalog commit), the
    # collection folders, the collection lock, attach (catalog commit), then
    # verify, both responses and stage recovery.
    _registration_open(e, p.catalog_bytes)
    _reserve_walk(e, ctx + edges)
    _catalog_commit(e, p.catalog_bytes)
    _add(e, "dup")
    _add(e, "context_mkdir", edges)
    _add(e, "open", edges)
    _add(e, "check_directory", edges)
    _add(e, "same_name", edges)
    _close_only_lock(e, create=True)
    _add(e, "metadata")
    _catalog_commit(e, p.catalog_bytes)
    _store_verify(e, edges)
    _read_response(e, p.response_bytes)
    _read_response(e, p.previous_bytes)
    _store_verify(e, edges)
    _add(e, "absent_slot", 2)
    # collection_breaker::begin with a newer sequence: registration and the
    # session's reserve walk (not fresh: no catalog write), the session chain,
    # its lock, the record, ticket checks and the record save.
    _registration_open(e, p.catalog_bytes)
    _reserve_walk(e, 3)
    _add(e, "dup")
    _add(e, "collection_folder", 3)
    _close_only_lock(e, create=True)
    _breaker_read(e, p.breaker_bytes)
    _ticket_verify(e)
    _add(e, "same_name")
    _breaker_save(e, p)
    # worker_lock, collector::spawn: executable() recheck, the lock handed to
    # the child, inherited fd listing, spawn, child setup and supervisor.
    _add(e, "dup")
    _chain_recheck(e, t)
    _add(e, "metadata")
    e["fstat"] += 1
    _add(e, "chain_recheck_name")
    _add(e, "dup")
    _add(e, "fd_listing")
    _add(e, "spawn")


def _collect_tail(e: dict, p: HelperPlan) -> None:
    # Supervisor thread: completion clock, then CollectionStore::publish with
    # both responses present (rotate current into previous, install stage).
    _add(e, "clock")
    _publish(e, p)
    _breaker_finish_and_gc(e, p)


def _publish(e: dict, p: HelperPlan) -> None:
    edges = 3
    _store_verify(e, edges)
    _read_response(e, p.response_bytes)
    _read_response(e, p.previous_bytes)
    _store_verify(e, edges)
    _add(e, "absent_slot", 2)
    _metered_stage(e, p.response_bytes)
    _store_verify(e, edges)
    _staged_verify(e)
    _staged_verify(e)
    for _ in range(2):  # current and previous unchanged since read
        _add(e, "metadata")
        _add(e, "check_data")
        _add(e, "same_name")
    _add(e, "rename")
    _store_verify(e, edges)
    _staged_verify(e)
    _add(e, "rename")


def _breaker_finish_and_gc(e: dict, p: HelperPlan) -> None:
    ctx, edges = p.context_components, 3
    # Ticket::finish after supervision: clock, session lock, checks around the
    # record update, then save.
    _add(e, "clock")
    _close_only_lock(e, create=False)
    _ticket_verify(e)
    _breaker_read(e, p.breaker_bytes)
    _ticket_verify(e)
    _add(e, "same_name")
    _breaker_save(e, p)
    # collection_gc::reclaim after the refresh: clock, catalog probe open,
    # runtime check, GC lock, catalog, the walk to the one store (no name
    # check on its last folder), its lock, a listing of response, previous and
    # the lock, the two absent stage names (stat and open), catalog commit.
    _add(e, "clock")
    _add(e, "open")
    _add(e, "check_directory")
    _close_only_lock(e, create=True)
    _read_checked(e, p.catalog_bytes)
    _add(e, "metadata")
    _add(e, "dup")
    _add(e, "collection_folder", ctx + edges)
    e["fstat"] -= 1
    _close_only_lock(e, create=False)
    _add(e, "directory_cursor")
    _read_checked(e, p.response_bytes)
    _read_checked(e, p.previous_bytes)
    _read_checked(e, 0)
    for _ in range(2):
        _add(e, "chain_recheck_name")
        _add(e, "absent_slot")
    # The session folder: walk, its lock, a listing of the lock and record.
    _reserve_walk(e, 3)
    _close_only_lock(e, create=False)
    _add(e, "directory_cursor")
    _breaker_read(e, 0)
    _breaker_read(e, p.breaker_bytes)
    _catalog_commit(e, p.catalog_bytes)


def helper_stage_expected(plan: HelperPlan) -> dict[str, int]:
    """Full-path helper-role calls of one release refresh helper run (spec 8 stage
    table): runtime/context walks and lock, unchanged revalidation, change
    publication and the failure path. Boot-scoped runtime files are never
    fsynced; renew is absent because the fixture has no approval record.
    For collect this is the complete prefix + tail sum; live checks use
    helper_collect_expected to apply exact/le separately."""
    _check_plan(plan)
    global _primitives
    _primitives = {**PRIMITIVES, **_LIBC[plan.libc], **STARTUP_PRIMITIVES[plan.arch, plan.libc]}
    try:
        return _helper_stage_expected(plan)
    finally:
        _primitives = PRIMITIVES


def helper_collect_expected(plan: HelperPlan, *, deadline: bool = False) -> dict[str, dict[str, int]]:
    """Collect prefix exact; each time-bound tail part is an independent cap.

    The prefix contains every unchanged-refresh primitive (including the final
    snapshot.lock unlock), admission, breaker begin, pin verification, spawn
    and child setup. The supervisor runs concurrently: its completion clock
    and publication are tail even before the main thread finishes refresh.
    After that unlock the main thread's Ticket::finish and GC are tail too.
    These are bounded by the 50 ms collector deadline / 20 ms GC budget, so
    they may stop early. No measured count chooses a formula coefficient.
    Exit 75 cannot publish, but still observes the supervisor completion clock.
    """
    _check_plan(plan)
    if "collect" not in plan.stages:
        raise ValueError("collect plan required")
    global _primitives
    _primitives = {**PRIMITIVES, **_LIBC[plan.libc], **STARTUP_PRIMITIVES[plan.arch, plan.libc]}
    try:
        prefix = _helper_stage_expected(replace(plan, stages=("unchanged",)))
        _collect_prefix(prefix, plan)
        supervisor: dict[str, int] = {}
        _add(supervisor, "clock")
        if not deadline:
            _publish(supervisor, plan)
        finish_gc: dict[str, int] = {}
        _breaker_finish_and_gc(finish_gc, plan)
        return {"prefix": prefix, "supervisor": supervisor, "finish_gc": finish_gc}
    finally:
        _primitives = PRIMITIVES


def _helper_stage_expected(plan: HelperPlan) -> dict[str, int]:
    p, k = plan, plan.ax.P
    stage = next(s for s in p.stages if s != "collect")
    e: dict[str, int] = {}
    _add(e, "start")
    _add(e, "stack_guard")
    _add(e, "passwd")
    e["read"] = e.get("read", 0) + p.nsswitch_reads + p.passwd_reads
    # build_identity::read: Resolved walk of the pinned link and its target,
    # target metadata, then revalidate_bindings over every descriptor and name.
    a, t = p.exe_link_components, p.exe_components
    _resolved_open(e, a + t + 1, links=1)
    _add(e, "metadata")
    _resolved_recheck(e, a + t + 2, a + t + 2, links=1)
    # Clock observations: process start, refresh start and each Budget::check
    # (two more around the snapshot encode and stage when publishing; a run
    # stopped at the snapshot read has made four).
    _add(e, "clock", {"publish": 16, "failure-recover": 4}.get(stage, 14))
    _context(e, p, create=True)
    _add(e, "open_lock")
    _add(e, "check_data")
    _add(e, "flock")
    _verify_lock(e)
    _recover(e)
    _ensure_root(e, p.state_components)
    _selection_lock(e, p.state_components)
    _open_chain(e, p.state_components)  # read_session: no config-use record
    _add(e, "absent_file")
    _add(e, "flock")  # selection lock dropped
    # ConfigRootPin::reopen: Resolved folder walk and its revalidation.
    _resolved_open(e, k)
    _resolved_recheck(e, k + 1, k)
    if stage == "failure-recover":
        # open_data's check refuses the snapshot's mode: Err(Unsafe) ends run();
        # the LockedStore drop reclaims the slots and releases the lock.
        _add(e, "open")
        _add(e, "check_data")
        _recover(e)
        _add(e, "flock")
        e.setdefault("fsync", 0)
        return dict(sorted(e.items()))
    if stage == "failure-last-good":
        _add(e, "absent_file")  # no current snapshot
    else:
        _store_read(e, p.snapshot_bytes, p.buf)
    _store_read(e, p.sequence_bytes, p.buf)
    # Loader::roots: conf.d missing and its absence, config.toml stat and
    # check, config.local.toml stat and absence. Then the read: check,
    # rewind, read_to_end and revalidation of the opened file.
    _resolved_open(e, k + 1, missing=True)
    _resolved_open(e, k)
    _add(e, "metadata")
    _resolved_open(e, k + 1)
    _add(e, "metadata")
    _resolved_open(e, k)
    _resolved_open(e, k + 1)
    _add(e, "rewind")
    e["read"] = e.get("read", 0) + read_to_end_calls(p.ax.B[0])
    _resolved_recheck(e, k + 2, k + 1)
    # revalidate() before the decision and again inside verified().
    _loader_revalidate(e, k)
    _loader_revalidate(e, k)
    _stage(e, p.sequence_bytes, p.buf)
    _install(e, small=True)
    if stage == "publish":
        _stage(e, p.snapshot_bytes, p.buf)
        _stage(e, p.snapshot_bytes, p.buf)  # last-good: the previous snapshot, same length here
    _stage(e, p.marker_bytes, p.buf)
    if stage == "failure-last-good":
        _store_read(e, p.snapshot_bytes, p.buf)  # last-good fallback for the display
    _add(e, "statm")
    # After the broker: selection lock again, the final revalidation, the
    # selection check, the context reopened without creation, same folder,
    # lock and snapshot stamp checks.
    _selection_lock(e, p.state_components)
    _loader_revalidate(e, k)
    _chain_recheck(e, p.state_components)
    _add(e, "check_record")
    _add(e, "metadata")
    _add(e, "chain_recheck_name", 2)  # selection.lock stamp, absent record
    _add(e, "metadata")
    _context(e, p, create=False)
    e["fstat"] = e.get("fstat", 0) + 2  # same_directory: fd_facts of both folders
    _verify_lock(e)
    _add(e, "chain_recheck_name")  # verify_snapshot: at_stamp of snapshot
    if stage == "publish":
        _install(e, small=False)
        _install(e, small=False)
    _install(e, small=True)
    _add(e, "flock")  # selection lock dropped
    _recover(e)  # LockedStore drop
    _add(e, "flock")
    if "collect" in p.stages:
        _collect_prefix(e, p)
        _collect_tail(e, p)
    e.setdefault("fsync", 0)
    return dict(sorted(e.items()))


def front_expected(C: int, section_bytes: int, session_bytes: int, buf: int) -> dict[str, int]:
    return {
        "openat": C + 3,
        "fstat": C + 3,
        "read": ceil_div(section_bytes, buf) + 1 + 1 + ceil_div(session_bytes, buf),
    }


def collection_expected(components: int, body_bytes: int, previous: bool, staged: bool) -> dict[str, int]:
    """Helper supervisor publication, after admission; Linux local-filesystem fixture.

    `components` counts held collection directory edges (normally three).
    `previous` means a current response is rotated into an absent previous slot;
    `staged` means a safe abandoned stage is removed first. Both complete records
    have the fixture's body length. Reads/writes complete their requested buffer
    in one call; the shared helper engine includes an EOF read on readback.

    Four chain/lock validations: (16*C+16) stat, (8*C+4) statfs.
    Stage write/readback and three install checks: 20 stat, 4 statfs.
    Two destination probes: 2 stat. Existing current: 13 stat, 3 statfs,
    1 header + ceil(body/16384) reads, 1 rename. Abandoned stage: 4 stat, 1 statfs, 1 unlink.
    The exact five opens are current, previous, stage recovery, legacy request
    recovery, and exclusive stage creation. No process is spawned here.

    Admission/catalog and GC operations are separate helper phases, never
    charged to the worker. Front header/body reads (16 KiB) are a separate phase.
    """
    if not 0 <= components <= 3300 or not 0 <= body_bytes <= 262_144 - 64:
        raise ValueError("collection publication axes exceed their bounds")
    p, s = int(previous), int(staged)
    return {
        "openat": 5,
        "fstat": 16 * components + 38 + 13 * p + 4 * s,
        "statfs": 8 * components + 8 + 3 * p + s,
        "read": 2 + (1 + ceil_div(body_bytes, 16_384)) * p,
        "write": 1,
        "renameat": 1 + p,
        "unlinkat": s,
        "flock": 0,
        "fsync": 0,
    }


def collection_front_expected(directories: int, file_sizes: tuple[int | None, ...],
                              body_bytes: tuple[int, ...], *, absent: bool = False) -> dict[str, int]:
    """Front increment only: O_PATH directories, immutable data and 16 KiB reads.

    `directories` counts successfully inspected private collection directories;
    a failed directory open contributes one attempt and no facts. None file sizes
    mean ENOENT slots. Body sizes name only records whose header was accepted.
    A normal two-slot fixture has directories=3 and two file sizes; a missing
    namespace has absent=True and no successful directory/file observations.
    """
    if not 0 <= directories <= 3 or len(file_sizes) > 2 or any(n is not None and n < 0 for n in file_sizes):
        raise ValueError("invalid collection prefetch axes")
    if directories < 3 and file_sizes or len(body_bytes) > 2 or any(not 0 <= n <= 262_144 - 64 for n in body_bytes):
        raise ValueError("invalid collection read axes")
    if absent and (directories or file_sizes or body_bytes):
        raise ValueError("absent namespace has no facts or reads")
    files = sum(n is not None for n in file_sizes)
    opens = 1 if absent else directories + (1 if directories < 3 else len(file_sizes))
    facts = directories + files
    return {"openat": opens, "fstat": facts, "fstatfs": facts,
            "fgetxattr": facts, "getxattr": directories,
            "read": sum(1 + ceil_div(n, 16_384) for n in body_bytes)}


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
             else collection_front_expected(3, (64 + body_bytes, 64 + previous_bytes),
                                            (body_bytes, previous_bytes)))
    publishes = case in {"fixture", "partial", "malformed-flood", "long-cwd", "legacy-gc"}
    if case == "ready-failure":
        # Admission created all three directories before startup failed. Both
        # file slots are still absent, so there are five opens and no reads.
        front = collection_front_expected(3, (None, None), ())
    publication = collection_expected(3, body_bytes, False, False) if publishes else {}
    # collector-effects is the expected ceiling, not evidence. Linux failure
    # traces supply measured counts; untraced cases are labelled in the ledger.
    return {"front-prefetch": front, "helper-publication": publication,
            "helper-gc": {"getdents": 2 * gc_directories, "unlinkat": gc_files,
                          "fsync": 0},
            "collector-effects": {"spawn": 0, "network": 0, "write": 0,
                                  "renameat": 0, "unlinkat": 0, "fsync": 0}}


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
        # U2: use held ancestor descriptors only. Each directory has its own
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
