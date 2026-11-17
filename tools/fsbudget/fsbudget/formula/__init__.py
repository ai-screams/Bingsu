"""Filesystem-call budget formulas.

Coefficient values and per-axis caps are M3; M1 evaluates the shape with
caller-provided coefficients (all 1 for the synthetic program).

The formulas live in the modules of this package; every name other code uses is
re-exported here, so `fsbudget.formula` keeps its import path."""

from .collection import (
    collection_expected as collection_expected,
    collection_front_expected as collection_front_expected,
)
from .collector import (
    CollectorAxes as CollectorAxes,
    collector_product_expected as collector_product_expected,
    collector_repository_expected as collector_repository_expected,
    collector_success_expected as collector_success_expected,
    git_collection_limits as git_collection_limits,
)
from .common import (
    ceil_div as ceil_div,
)
from .front import (
    FrontAttempt as FrontAttempt,
    front_attempts_expected as front_attempts_expected,
    front_body_bytes as front_body_bytes,
    front_expected as front_expected,
    front_read_bytes as front_read_bytes,
)
from .helper import (
    helper_collect_expected as helper_collect_expected,
    helper_command_expected as helper_command_expected,
    helper_stage_expected as helper_stage_expected,
)
from .helper_builtin import (
    helper_builtin_expected as helper_builtin_expected,
)
from .helper_collect import (
    EXAMINE_MAX as EXAMINE_MAX,
    PID_LINE_MAX as PID_LINE_MAX,
    PREAD_CHUNK as PREAD_CHUNK,
    PROCS_MAX as PROCS_MAX,
    PROCS_PREADS as PROCS_PREADS,
    RECLAIM_MAX as RECLAIM_MAX,
)
from .helper_plan import (
    HelperPlan as HelperPlan,
    read_to_end_calls as read_to_end_calls,
    verify_build_reads as verify_build_reads,
)
from .supervisor import (
    SUPERVISOR_SPAWNS_MAX as SUPERVISOR_SPAWNS_MAX,
    supervisor_expected as supervisor_expected,
)
from .synthetic import (
    Coeffs as Coeffs,
    HelperAxes as HelperAxes,
    synthetic_helper_expected as synthetic_helper_expected,
)
from .tables import (
    BUILTIN_BIN_LINKS_MAX as BUILTIN_BIN_LINKS_MAX,
    BUILTIN_PATH_FOLDERS_MAX as BUILTIN_PATH_FOLDERS_MAX,
    BUILTIN_SHIM_HOMES_MAX as BUILTIN_SHIM_HOMES_MAX,
    BUILTIN_STAGES as BUILTIN_STAGES,
    BUILTIN_WALK_NAMES_MAX as BUILTIN_WALK_NAMES_MAX,
    COMMAND_STAGES as COMMAND_STAGES,
    ENV_PIPE_PRIMITIVES as ENV_PIPE_PRIMITIVES,
    HelperStage as HelperStage,
    MAX_RW_COUNT as MAX_RW_COUNT,
    MUSL_PRIMITIVES as MUSL_PRIMITIVES,
    POSIX_SPAWN_PRIMITIVES as POSIX_SPAWN_PRIMITIVES,
    PRIMITIVES as PRIMITIVES,
    STARTUP_PRIMITIVES as STARTUP_PRIMITIVES,
)
