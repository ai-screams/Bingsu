"""The M1 synthetic helper: spec coefficients over the helper axes."""
from dataclasses import dataclass, field
from .common import ceil_div


@dataclass
class HelperAxes:
    F: int  # unique config source files
    P: int  # path components walked
    L: int  # symlinks walked
    R: int  # references and candidates tried
    D: int  # source folders listed (conf.d)
    # Directory entries per folder. An axis with its own cap (M3) but no term
    # in any call formula: recorded per fixture.
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
    e["fsync"] = 0  # boot-scoped runtime files are not fsynced
    e["renameat"] = 2 if changed else 1
    e["unlinkat"] = 0
    return e
