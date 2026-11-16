"""Building blocks of a helper round: path walk, lock, staging, catalog, breaker."""
from .common import ceil_div
from .plan import HelperPlan, _add


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
    # only by rename, so there is no end-check read.
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
    # parent walk: conf.d, config.json, config.local.toml, config.local.json),
    # the config root evidence and the held executable file.
    _resolved_open(e, k + 1)
    for _ in range(4):
        _add(e, "metadata")
        _resolved_open(e, k)
    _resolved_recheck(e, k + 1, k)
    _resolved_recheck(e, k + 2, k + 1)


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
