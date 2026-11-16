"""The collector supervisor formula."""
from .plan import _LIBC, _add, _use_primitives
from .tables import PRIMITIVES, STARTUP_PRIMITIVES


# One round spawns at most this many: config units (plan::CONFIG_MAX) and
# builtin probes (plan::PROBE_MAX).
SUPERVISOR_SPAWNS_MAX = 8 + 4


def supervisor_expected(spawns: int, *, atomic: bool, arch: str, libc: str, idle: bool = False) -> dict[str, int]:
    """The command supervisor's calls in one round that spawns `spawns`
    relays, every one approved and run to its end: exact. `atomic` is the
    cgroup path (the session's cgroup parent opened); without it every
    cgroup term is 0. The start adds the platform's stack guard seeks
    (STARTUP_PRIMITIVES, x86_64 glibc). The aarch64 glibc and musl captures
    agree term for term; x86_64 musl shares aarch64 musl's startup table.
    The relay and the target command are their own roles and are only
    counted (plan "decisive gates", 1382)."""
    # A builtin fast round starts the supervisor before the collection's
    # answer decides there is nothing to run (D3a Q-C): it marks the session
    # lock close-on-exec, sees the grant pipe's EOF and exits. Only that
    # stage asks for it (`idle`); a unit round never spawns none.
    if idle != (spawns == 0) or not 0 <= spawns <= SUPERVISOR_SPAWNS_MAX:
        raise ValueError("supervisor spawns: 1 to 12 a round, 0 only idle")
    _use_primitives({**PRIMITIVES, **_LIBC[libc], **STARTUP_PRIMITIVES[arch, libc]})
    try:
        e: dict[str, int] = {}
        _add(e, "supervisor_idle" if idle else "supervisor_start")
        _add(e, "stack_guard")
        _add(e, "clock", spawns)
        _add(e, "supervisor_spawn", spawns)
        _add(e, "supervisor_unit_cgroup" if atomic else "supervisor_own_group", spawns)
        return dict(sorted(e.items()))
    finally:
        _use_primitives(PRIMITIVES)
