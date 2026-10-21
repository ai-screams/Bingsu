"""Budget formulas (spec section 8 "filesystem call budget formula").

Coefficient values and per-axis caps are M3; M1 evaluates the shape with
caller-provided coefficients (all 1 for the synthetic program)."""
from dataclasses import dataclass, field


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


def helper_expected(ax: HelperAxes, co: Coeffs, changed: bool, buf: int, snapshot_bytes: int) -> dict[str, int]:
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
