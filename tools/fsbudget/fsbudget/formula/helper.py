"""Helper formulas by stage: command, stage, collect and the shared stage builder."""
from dataclasses import replace
from .collect import _breaker_finish_and_gc, _collect_prefix, _collect_tail, _publish
from .command import _command_gc, _command_prefix
from .plan import HelperPlan, _LIBC, _add, _check_plan, _use_primitives, read_to_end_calls
from .steps import _chain_recheck, _context, _ensure_root, _install, _loader_revalidate, _open_chain, _recover, _resolved_open, _resolved_recheck, _selection_lock, _stage, _store_read, _verify_lock
from .tables import COMMAND_STAGES, PRIMITIVES, STARTUP_PRIMITIVES


def helper_command_expected(plan: HelperPlan) -> dict[str, dict[str, int]]:
    """command_miss: the prefix through the command response's install is
    exact; the GC after it is an upper bound (its 20 ms budget)."""
    _check_plan(plan)
    if "command_miss" not in plan.stages:
        raise ValueError("command_miss plan required")
    _use_primitives({**PRIMITIVES, **_LIBC[plan.libc], **STARTUP_PRIMITIVES[plan.arch, plan.libc]})
    try:
        prefix = _helper_stage_expected(replace(plan, stages=("unchanged",)))
        _command_prefix(prefix, plan, "command_miss")
        gc: dict[str, int] = {}
        _command_gc(gc, plan)
        return {"prefix": dict(sorted(prefix.items())), "gc": dict(sorted(gc.items()))}
    finally:
        _use_primitives(PRIMITIVES)


def helper_stage_expected(plan: HelperPlan) -> dict[str, int]:
    """Full-path helper-role calls of one release refresh helper run:
    runtime/context walks and lock, unchanged revalidation, change
    publication and the failure path. Boot-scoped runtime files are never
    fsynced; renew is absent because the fixture has no approval record.
    For collect this is the complete prefix + tail sum; live checks use
    helper_collect_expected to apply exact/le separately."""
    _check_plan(plan)
    _use_primitives({**PRIMITIVES, **_LIBC[plan.libc], **STARTUP_PRIMITIVES[plan.arch, plan.libc]})
    try:
        return _helper_stage_expected(plan)
    finally:
        _use_primitives(PRIMITIVES)


def helper_collect_expected(plan: HelperPlan, *, deadline: bool = False) -> dict[str, dict[str, int]]:
    """Collect prefix exact; each time-bound tail part is an independent cap.

    The prefix contains every unchanged-refresh primitive (including the final
    snapshot.lock unlock), admission, breaker begin, pin verification, spawn
    and child setup. The supervisor runs concurrently: its completion clock
    and publication are tail even before the main thread finishes refresh.
    After that unlock the main thread's Ticket::finish and GC are tail too.
    These are bounded by the 50 ms collector deadline / 20 ms GC budget, so
    they may stop early. No measured count chooses a formula coefficient.
    deadline=True is exit 75 without publication: the supervisor still
    observes its completion clock. An exit-75 attempt that stored a Deadline
    partial is judged by the publication formula (gate.check_collect).
    """
    _check_plan(plan)
    if "collect" not in plan.stages:
        raise ValueError("collect plan required")
    _use_primitives({**PRIMITIVES, **_LIBC[plan.libc], **STARTUP_PRIMITIVES[plan.arch, plan.libc]})
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
        _use_primitives(PRIMITIVES)


def _helper_stage_expected(plan: HelperPlan) -> dict[str, int]:
    p, k = plan, plan.ax.P
    stage = next(s for s in p.stages if s != "collect" and s not in COMMAND_STAGES)
    e: dict[str, int] = {}
    _add(e, "start")
    _add(e, "stack_guard")
    _add(e, "passwd")
    e["read"] = e.get("read", 0) + p.nsswitch_reads + p.passwd_reads
    e["seek"] = e.get("seek", 0) + p.passwd_seeks
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
    # Loader::roots: conf.d missing and its absence; config.toml and
    # config.json stat, config.json's absence and config.toml's check;
    # config.local.toml and config.local.json stat and both absences. Then
    # the read: check, rewind, read_to_end and revalidation of the opened file.
    _resolved_open(e, k + 1, missing=True)
    _resolved_open(e, k)
    _add(e, "metadata", 2)
    _resolved_open(e, k)
    _resolved_open(e, k + 1)
    _add(e, "metadata", 2)
    _resolved_open(e, k)
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
    for command in (s for s in p.stages if s in COMMAND_STAGES):
        _command_prefix(e, p, command)
        if command == "command_miss":
            _command_gc(e, p)
    e.setdefault("fsync", 0)
    return dict(sorted(e.items()))
