"""The builtin language rounds (D3a) of the helper."""
from dataclasses import replace
from .collect import _breaker_finish, _collect_prefix, _collection_gc, _publish
from .command import _command_lookup, _command_session
from .helper import _helper_stage_expected
from .plan import HelperPlan, _LIBC, _add, _check_plan, _use_primitives
from .steps import _catalog_commit, _close_only_lock, _metered_stage, _read_checked, _read_response, _registration_open, _reserve_walk, _staged_verify, _store_verify
from .tables import BUILTIN_STAGES, PRIMITIVES, STARTUP_PRIMITIVES


def _builtin_round(e: dict, p: HelperPlan, stage: str) -> None:
    """After the collection's snapshot unlock, on the helper's main thread,
    through the command response's install (probe) or the decision (fast):
    exact. The order the trace shows: the breaker's finish, the grant (the
    shell folder's identity and repository scan, the round's one PATH
    lookup, the language's decision), the probe's admission and publication,
    Round::end's reclaim of the session parent."""
    _breaker_finish(e, p)
    e["fstat"] = e.get("fstat", 0) + 1
    _add(e, "folder_root")
    _add(e, "folder_name", p.shell_names)
    e["fstat"] += p.shell_names + 1
    # exec_path::lookup_open_in: every PATH folder's walk, the found
    # folder's walk again and the file, then its canonical path.
    _add(e, "folder_root", p.path_folders + 1)
    _add(e, "folder_name", p.path_names + p.target_names)
    _add(e, "target_file")
    e["readlink"] = e.get("readlink", 0) + p.target_names + 1
    if stage == "builtin_fast":
        _add(e, "builtin_pyenv_classify")
        _add(e, "manager_install")
        _add(e, "manager_link", p.bin_links)
        if p.cgroup_parent:
            _add(e, "cgroup_listing")  # no unit ran: nothing to reclaim
        return
    _add(e, "builtin_found_classify")
    e["fstat"] += p.manager_homes
    _add(e, "builtin_found_identity")
    # publish_entries -> admit_commands into the store the collection
    # admitted: its response and previous are read, not probed absent.
    edges = 3
    _registration_open(e, p.catalog_bytes)
    _reserve_walk(e, p.context_components + edges)
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
    _add(e, "absent_slot", 2)  # .response.stage, .stage-request
    # publish_commands, as command_miss's.
    _store_verify(e, edges)
    _read_response(e, p.command_bytes)
    _add(e, "absent_slot")
    _metered_stage(e, p.command_bytes)
    _store_verify(e, edges)
    _add(e, "metadata")
    _add(e, "same_name")
    _staged_verify(e)
    _add(e, "rename")
    if p.cgroup_parent:
        _add(e, "cgroup_listing")
        _add(e, "cgroup_unit")


def helper_builtin_expected(plan: HelperPlan, *, deadline: bool = False) -> dict[str, dict[str, int]]:
    """A builtin language round. `prefix` (the main thread until the
    collection's snapshot unlock, and the pre-exec setup of the collector
    and the command supervisor) is exact: the unchanged revalidation, the
    collection's admission, breaker begin and spawn, the command lookup,
    session and prepare (neutral folder, supervisor spawn). `supervisor` (the
    collection's supervisor thread) is an upper bound as in collect.
    `builtin` (after the unlock until the GC's first clock) is exact; `gc`
    (the collection GC over the store, its command response included) is an
    upper bound (its 20 ms budget)."""
    _check_plan(plan)
    stage = next((s for s in plan.stages if s in BUILTIN_STAGES), None)
    if stage is None:
        raise ValueError("builtin plan required")
    _use_primitives({**PRIMITIVES, **_LIBC[plan.libc], **STARTUP_PRIMITIVES[plan.arch, plan.libc]})
    try:
        prefix = _helper_stage_expected(replace(plan, stages=("unchanged",)))
        _collect_prefix(prefix, plan)
        _command_lookup(prefix, plan)
        _command_session(prefix, plan)
        _add(prefix, "neutral")
        _add(prefix, "dup")
        _add(prefix, "dup", 1 + int(plan.cgroup_parent))
        _add(prefix, "fd_listing")
        _add(prefix, "command_spawn")
        _add(prefix, "dup", 3)
        supervisor: dict[str, int] = {}
        _add(supervisor, "clock")
        builtin: dict[str, int] = {}
        _builtin_round(builtin, plan, stage)
        gc: dict[str, int] = {}
        _collection_gc(gc, plan)
        _read_checked(gc, plan.command_bytes)
        if deadline:
            # No verified answer: the supervisor stores nothing, and the rest
            # of the main thread is bounded by the full round's.
            tail = dict(builtin)
            for kind, n in gc.items():
                tail[kind] = tail.get(kind, 0) + n
            return {phase: dict(sorted(v.items())) for phase, v in
                    (("prefix", prefix), ("supervisor", supervisor), ("tail", tail))}
        _publish(supervisor, plan)
        return {phase: dict(sorted(v.items())) for phase, v in
                (("prefix", prefix), ("supervisor", supervisor), ("builtin", builtin), ("gc", gc))}
    finally:
        _use_primitives(PRIMITIVES)
