"""Collection and collector-product formulas."""
from .common import ceil_div


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
    a failed directory open contributes one attempt and no facts. With all
    three, the prefetch opens three files: the collection response, the
    previous response and the command response (opened with
    them before the filter, read only when the snapshot draws a command
    segment). None file sizes mean ENOENT slots. Body sizes name only records
    whose header was accepted and that were read (a command response the
    snapshot does not draw is closed unread). A missing namespace has
    absent=True and no successful directory/file observations.
    """
    if not 0 <= directories <= 3 or any(n is not None and n < 0 for n in file_sizes):
        raise ValueError("invalid collection prefetch axes")
    if directories == 3 and len(file_sizes) != 3 or directories < 3 and file_sizes:
        raise ValueError("invalid collection prefetch axes")
    if len(body_bytes) > 3 or any(not 0 <= n <= 505_370 - 64 for n in body_bytes):
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
