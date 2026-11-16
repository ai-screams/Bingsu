"""The collect stage of a helper round: publication, breaker finish, GC, session sweep."""
from .plan import HelperPlan, _add, verify_build_reads
from .steps import _breaker_read, _breaker_save, _catalog_commit, _chain_recheck, _close_only_lock, _metered_stage, _open_chain, _read_checked, _read_response, _registration_open, _reserve_walk, _staged_verify, _store_verify, _ticket_verify


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
    _breaker_finish(e, p)
    _collection_gc(e, p)


def _breaker_finish(e: dict, p: HelperPlan) -> None:
    # Ticket::finish after supervision: clock, session lock, checks around the
    # record update, then save.
    _add(e, "clock")
    _close_only_lock(e, create=False)
    _ticket_verify(e)
    _breaker_read(e, p.breaker_bytes)
    _ticket_verify(e)
    _add(e, "same_name")
    _breaker_save(e, p)


def _collection_gc(e: dict, p: HelperPlan) -> None:
    ctx, edges = p.context_components, 3
    # collection_gc::reclaim after the refresh: clock, catalog probe open,
    # runtime check, GC lock, catalog, the walk to the one store (no name
    # check on its last folder), its lock, a listing of response, previous and
    # the lock, the three absent stage names (stat and open: .response.stage,
    # .stage-request, .command.stage), catalog commit.
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
    for _ in range(3):
        _add(e, "chain_recheck_name")
        _add(e, "absent_slot")
    # The session folder: walk, its lock, a listing of the lock and record.
    _reserve_walk(e, 3)
    _close_only_lock(e, create=False)
    _add(e, "directory_cursor")
    _breaker_read(e, 0)
    _breaker_read(e, p.breaker_bytes)
    _session_sweep(e, p)
    _catalog_commit(e, p.catalog_bytes)


def _session_sweep(e: dict, p: HelperPlan) -> None:
    # command_sessions::reclaim_stale after the stores'
    # own work: the runtime root's listing, one block and the block that ends
    # it (each: open ".", seek, getdents, the next position), and a stat of
    # each session lock's name, at most EXAMINE_MAX. The fixtures have none
    # older than a day, so no lock is taken and the GC's own cgroup is never
    # looked up (that happens only after a stale lock is taken).
    _add(e, "session_listing", 2)
    e["fstat"] = e.get("fstat", 0) + min(p.session_locks, EXAMINE_MAX)
    if p.stale_locks > p.session_locks:
        raise ValueError("stale locks are session locks")
    # The runtime root's stamp, once a run, for this session's own digest:
    # read for the first lock past the age check, this session's own stale
    # lock too, which `stale_locks` leaves out; counted whenever there is a
    # lock at all.
    if p.session_locks:
        e["fstat"] += 1
    # Each stale lock opened and locked (a held one too: it does not count
    # against RECLAIM_MAX); at most RECLAIM_MAX taken, each counted whether
    # its reclaim then succeeds or fails; the own-cgroup lookup once.
    stale = min(p.stale_locks, EXAMINE_MAX)
    if stale:
        _add(e, "stale_lock_open", stale)
        _add(e, "stale_lock_taken", min(stale, RECLAIM_MAX))
        _add(e, "gc_own_cgroup")
        e["read"] += PROCS_PREADS


# command_sessions::EXAMINE_MAX and RECLAIM_MAX: names one GC run looks at,
# locks it takes.
EXAMINE_MAX = 32


RECLAIM_MAX = 4


# command_cgroup::read_bounded on cgroup.procs: 4 KiB preads until EOF or
# past core cgroup::PROCS_MAX (64 KiB). The kernel's seq_file stops a read
# short only before a record that does not fit, and a record is one pid line
# (pid_max is at most 2^22: 7 digits and the newline), so every read but
# the last returns at least 4096 - 7 bytes: 64 KiB take ceil(65536 / 4089)
# reads, and one more ends them (EOF, or the read past the cap).
PROCS_MAX, PREAD_CHUNK, PID_LINE_MAX = 65_536, 4096, 8


PROCS_PREADS = -(-PROCS_MAX // (PREAD_CHUNK - PID_LINE_MAX + 1)) + 1
