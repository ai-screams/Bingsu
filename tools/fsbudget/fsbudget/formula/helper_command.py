"""The command stages of a helper round: session, lookup, prefix, GC."""
from .primitives import _add
from .helper_collect import _session_sweep
from .helper_plan import HelperPlan
from .helper_steps import _catalog_commit, _close_only_lock, _metered_stage, _read_checked, _read_response, _registration_open, _reserve_walk, _staged_verify, _store_verify


def _command_session(e: dict, p: HelperPlan) -> None:
    """command_grant's session lock and session::session_reclaim:
    every round of a config with command units takes them, even with nothing
    to run."""
    _close_only_lock(e, create=True)
    e["fstat"] = e.get("fstat", 0) + 1  # fd_facts of the runtime root (the parent's name)
    _add(e, "cgroup_probe")
    e["read"] = e.get("read", 0) + 2  # cgroup.procs: one filled pread and the EOF one
    if p.cgroup_parent:
        _add(e, "cgroup_parent")
        _add(e, "cgroup_listing")  # the empty parent: nothing to reclaim


def _command_lookup(e: dict, p: HelperPlan) -> None:
    # collection_store::read_commands: the context clone, the three collection
    # folders, then the response read without the lock (a cache lookup).
    _add(e, "dup")
    _add(e, "context_component", 3)
    _read_checked(e, p.command_bytes)


def _command_prefix(e: dict, p: HelperPlan, stage: str) -> None:
    """The command round up to and including its publication: exact."""
    if stage != "command_not_run":
        _command_lookup(e, p)
    _command_session(e, p)
    if stage != "command_miss":
        return
    # prepare: the neutral folder, the supervisor (the lock it inherits, the
    # cgroup parent on the atomic path, the inherited fd census, the spawn),
    # then the round's context clone (two folders) and the runtime clone the
    # GC uses after publication (C4a review H1).
    _add(e, "neutral")
    _add(e, "dup")
    _add(e, "dup", 1 + int(p.cgroup_parent))
    _add(e, "fd_listing")
    _add(e, "command_spawn")
    _add(e, "dup", 3)
    # Round::grant -> units: the shell folder's identity (statx), the
    # repository scan (a no-follow walk of the shell's folder, then one
    # lstat of `.git` in "/" and in each folder of it), the PATH folder's
    # walk, the target folder's walk and the target.
    e["fstat"] = e.get("fstat", 0) + 1
    _add(e, "folder_root")
    _add(e, "folder_name", p.shell_names)
    e["fstat"] += p.shell_names + 1
    _add(e, "folder_root", 2)
    _add(e, "folder_name", p.path_names + p.target_names)
    _add(e, "target_file")
    _add(e, "resolved_link", p.target_links)
    # publish_entries -> CollectionStore::admit_commands: as collection
    # admission, with no collection response in the store.
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
    _add(e, "absent_file", 2)  # response, previous
    _store_verify(e, edges)
    _add(e, "absent_slot", 2)  # .response.stage, .stage-request
    # publish_commands: verify, the current response read again under the
    # lock, the stale stage's removal, the staged merge (same length here),
    # verify, the read file's stamp and name, the stage's check, rename.
    _store_verify(e, edges)
    _read_response(e, p.command_bytes)
    _add(e, "absent_slot")
    _metered_stage(e, p.command_bytes)
    _store_verify(e, edges)
    _add(e, "metadata")
    _add(e, "same_name")
    _staged_verify(e)
    _add(e, "rename")
    # Round::end on the atomic path: the reaped supervisor's one unit cgroup.
    if p.cgroup_parent:
        _add(e, "cgroup_listing")
        _add(e, "cgroup_unit")


def _command_gc(e: dict, p: HelperPlan) -> None:
    """collection_gc::reclaim after a publishing command round, run to
    completion over the one store: clock, catalog probe, runtime check, GC
    lock, catalog, the walk to the store (no name check on its last folder),
    its lock, the listing's command response and lock, the three stage
    names, catalog commit. Its budget may stop it earlier (an upper bound)."""
    edges = 3
    _add(e, "clock")
    _add(e, "open")
    _add(e, "check_directory")
    _close_only_lock(e, create=True)
    _read_checked(e, p.catalog_bytes)
    _add(e, "metadata")
    _add(e, "dup")
    _add(e, "collection_folder", p.context_components + edges)
    e["fstat"] -= 1
    _close_only_lock(e, create=False)
    _add(e, "directory_cursor")
    _read_checked(e, p.command_bytes)
    _read_checked(e, 0)
    for _ in range(3):  # .response.stage, .stage-request, .command.stage
        _add(e, "chain_recheck_name")
        _add(e, "absent_slot")
    _session_sweep(e, p)
    _catalog_commit(e, p.catalog_bytes)
