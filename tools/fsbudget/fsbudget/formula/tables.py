"""Primitive-call tables and axis caps shared by the helper formulas."""
from typing import Literal


HelperStage = Literal["unchanged", "publish", "collect", "failure-last-good", "failure-recover",
                      "command_not_run", "command_hit", "command_miss", "builtin_probe", "builtin_fast"]


COMMAND_STAGES = ("command_not_run", "command_hit", "command_miss")


# Builtin language rounds (D3a): a screen with dir and git and one language
# segment, no config unit. The probe runs the language's command found on
# PATH; the fast path decides pyenv's selected version without running.
BUILTIN_STAGES = ("builtin_probe", "builtin_fast")


# The product's bounds on the builtin axes (each pinned to its source by
# test_builtin_axis_caps_match_the_product): version_manager::BIN_LINKS_MAX,
# the entries of version_manager::unsupported, exec_path::DEPTH_MAX less one
# (the folders one walk holds, "/" among them: the names below it), and
# env_frame::FRAME_MAX over the shortest PATH entry ("/" and its ":").
BUILTIN_BIN_LINKS_MAX = 4


BUILTIN_SHIM_HOMES_MAX = 8


BUILTIN_WALK_NAMES_MAX = 256 - 1


BUILTIN_PATH_FOLDERS_MAX = 65_536 // 2


# Linux read(2)/write(2) transfer at most MAX_RW_COUNT bytes per call. Outside
# collection metering the release helper reads and writes each store file in
# one call of its full length (read_exact_len, write_fd), plus one EOF read.
MAX_RW_COUNT = 0x7FFF_F000


# Calls of one product operation in the release refresh helper on Linux glibc,
# in classify.helper_kind's vocabulary. Each entry names the code that makes
# them. Walk entries are per path name or per descriptor, so axes multiply them.
PRIMITIVES: dict[str, dict[str, int]] = {
    # helper::run before NSS: the watchdog thread (helper_limits::start) and
    # detach's chdir("/") and umask(077).
    "start": {"exec": 1, "thread": 1, "cwd": 1, "umask": 1},
    "stack_guard": {},  # overridden by the architecture/libc startup table
    # SystemClock::observe: boot_id open, fd statx, fstatfs, read and EOF read;
    # /proc/self, ns and timens_offsets opens with fstatfs, statx on the file;
    # readlinkat of time and time_for_children.
    "clock": {"openat": 4, "fstat": 2, "statfs": 4, "read": 2, "readlink": 2},
    # sys::passwd_entry through glibc: two nscd connects, nsswitch.conf and "/"
    # stats, nsswitch.conf open with an fd stat before and after its reads,
    # then /etc/passwd open, fd stat and rewind. Both files' buffered reads
    # are axes.
    "passwd": {"network": 4, "fstat": 5, "openat": 2, "seek": 1},
    # runtime_root::open_chain: an O_PATH open and fd_facts per folder, "/" too.
    "chain_folder": {"openat": 1, "fstat": 1},
    # Chain::revalidate: fd_facts per folder and at_stamp per name.
    "chain_recheck_folder": {"fstat": 1},
    "chain_recheck_name": {"fstat": 1},
    # source_path::Resolved::open: "/" open, fd stat and metadata; per name a
    # no-follow lstat, open, metadata and fd stat. A link costs a second lstat
    # and a readlinkat and is not opened; a missing last name is one lstat.
    "resolved_root": {"openat": 1, "fstat": 2},
    "resolved_name": {"openat": 1, "fstat": 3},
    "resolved_link": {"fstat": 2, "readlink": 1},
    "resolved_missing": {"fstat": 1},
    # Resolved::revalidate (and revalidate_bindings): metadata and fd stat per
    # descriptor, lstat per name, readlinkat per link.
    "resolved_recheck_fd": {"fstat": 2},
    "resolved_recheck_name": {"fstat": 1},
    "resolved_recheck_link": {"readlink": 1},
    # File::metadata or Path::symlink_metadata: one statx.
    "metadata": {"fstat": 1},
    # sys::fd_is_local: one fstatfs.
    "fd_is_local": {"statfs": 1},
    # snapshot_store::check_data: fd_facts, metadata and fd_is_local.
    "check_data": {"fstat": 2, "statfs": 1},
    # same_name: file_stamp of the fd and at_stamp of the name.
    "same_name": {"fstat": 2},
    # trust_record::check_record: fd_facts and metadata.
    "check_record": {"fstat": 2},
    # CheckedContextFd::under_runtime per component: open, fd_facts, fd_is_local;
    # mkdirat first when creating.
    "context_component": {"openat": 1, "fstat": 1, "statfs": 1},
    "context_mkdir": {"mkdir": 1},
    # File::try_clone.
    "dup": {"dup": 1},
    # sys::open_lock_at on an existing lock: the O_EXCL create attempt, then open.
    "open_lock": {"openat": 2},
    "flock": {"flock": 1},
    # LockedStore::remove_slot of an absent stage slot: one open.
    "absent_slot": {"openat": 1},
    # LockedStore::read of an absent file: one open.
    "absent_file": {"openat": 1},
    "open": {"openat": 1},
    # sys::create_file_at: O_EXCL open and fchmod.
    "create": {"openat": 1, "chmod": 1},
    "rewind": {"seek": 1},
    "rename": {"renameat": 1},
    "pread": {"read": 1},
    # helper_limits::install: /proc/self/statm open, metadata, read and EOF read.
    "statm": {"openat": 1, "fstat": 1, "read": 2},
    # snapshot_store::check_directory: fd_facts and fd_is_local.
    "check_directory": {"fstat": 1, "statfs": 1},
    # collection_gc and CollectionStore walks below the runtime root, per
    # folder: open, fd_facts, fd_is_local, metadata, at_stamp of the name.
    "collection_folder": {"openat": 1, "fstat": 3, "statfs": 1},
    # collector::spawn: the /proc/self/fd listing that closes inherited fds
    # (open, fd stat, one filled read and the EOF read), then the child's two
    # /dev/null opens and chdir("/") before its exec, and the supervisor thread.
    "fd_listing": {"openat": 1, "fstat": 1, "getdents": 2},
    "spawn": {"spawn": 1, "openat": 2, "cwd": 1, "thread": 1},
    # DirectoryCursor::open on a held folder: "." open, fd stat, flag query,
    # FD_CLOEXEC; its reads are one filled read and the EOF read.
    "directory_cursor": {"openat": 1, "fstat": 1, "fd_query": 1, "fd_flags": 1, "getdents": 2},
    # sys::directory_batch of the runtime root, one 8 KiB block.
    "session_listing": {"openat": 1, "seek": 2, "getdents": 1},
    # command_sessions::reclaim_one for a stale lock (m6-C4a7, observed in a
    # release probe under strace): its open, check_data's fd stat, metadata
    # stat and fstatfs, and the non-blocking flock; once taken, the stamp
    # check, the parent's rmdir and the lock's unlink.
    "stale_lock_open": {"openat": 1, "fstat": 2, "statfs": 1, "flock": 1},
    "stale_lock_taken": {"fstat": 1, "unlinkat": 2},
    # The GC's own-cgroup lookup, once a run (command_cgroup::fs::open_own):
    # /proc/self/cgroup opened and read (2), the own folder opened and its
    # fstatfs, cgroup.procs opened; its preads are PROCS_PREADS.
    "gc_own_cgroup": {"openat": 3, "read": 2, "statfs": 1},
    # command_cgroup::fs::open_session up to the session parent's open (Linux,
    # C3): uname (the 5.14 check, kernel_release), /proc/self/cgroup
    # through libc::open and read to its end, the own cgroup folder through
    # libc::open and its fstatfs, the cgroup.procs open (its preads are an
    # axis), the parent's mkdirat and open. A best-effort host stops at that
    # open (mkdir refused, nothing to open).
    "cgroup_probe": {"kernel_release": 1, "openat": 4, "read": 2, "statfs": 1, "mkdir": 1},
    # The opened parent: fd_facts and the mount ids of the own cgroup and the
    # parent; then the reclaim's listing of the parent (lseek, one filled
    # getdents64 and the EOF one).
    "cgroup_parent": {"fstat": 3},
    "cgroup_listing": {"seek": 1, "getdents": 2},
    # One unit cgroup reclaimed after its round: open and both mount ids,
    # cgroup.kill open, the mount ids of the folder and the file (the file
    # must be on the folder's mount, m6-C3b) and its write, cgroup.events
    # open and one pread, the unit's own listing, then rmdir.
    "cgroup_unit": {"openat": 3, "fstat": 4, "write": 1, "read": 1, "seek": 1, "getdents": 2, "unlinkat": 1},
    # builtin_probe::plan after exec_path::lookup_open_in: the found file's
    # canonical path (one readlinkat per name of the target folder and the
    # file), version_manager::classify (statx of the folder the lookup
    # stopped in and of the file's canonical folder; each shim home of the
    # managers bingsu knows that is absent, `manager_homes`), and for a run
    # the checked file's own metadata.
    "builtin_found_classify": {"fstat": 2},
    "builtin_found_identity": {"fstat": 1},
    # The same for pyenv's shim folder: the lookup's folder, the canonical
    # folder and PYENV_ROOT/shims are one folder, each stat once.
    "builtin_pyenv_classify": {"fstat": 3},
    # version_manager::choose -> pyenv installed: PYENV_ROOT opened by its
    # path, then versions, <v> and bin no-follow (each with its fstat), the
    # executable's no-follow open and its fstat and statx; each link inside
    # bin (`bin_links`) is an ELOOP open and its readlinkat.
    "manager_install": {"openat": 5, "fstat": 6},
    "manager_link": {"openat": 1, "readlink": 1},
    # The command supervisor (GATE-CMD-FSBUDGET), after its loader prologue:
    # its exec, then close-on-exec on the session lock (fd 5) and on fd 6,
    # the session's cgroup parent (EBADF on the best-effort path, still an
    # attempt). Each spawn (a config unit or a builtin probe) observes the
    # clock (`clock`) and opens /dev/null for the relay's stdin; the relay's
    # child chdir("/") is the spawn's. The atomic path makes the unit
    # cgroup, opens it and its cgroup.kill, spawns with clone3 into it and
    # writes the kill when the unit ends; the best-effort path's posix_spawn
    # puts the relay in its own process group instead. The session parent,
    # its listing, the unit's rmdir and the reclaim of earlier rounds are
    # the helper's (cgroup_probe, cgroup_parent, cgroup_listing, cgroup_unit).
    "supervisor_start": {"exec": 1, "fd_flags": 2},
    "supervisor_idle": {"exec": 1, "fd_flags": 1},
    "supervisor_spawn": {"spawn": 1, "openat": 1, "cwd": 1},
    # The mount ids of the parent, the new unit folder and its cgroup.kill:
    # the folder must be on the parent's mount and the file on the folder's
    # (m6-C3b).
    "supervisor_unit_cgroup": {"mkdir": 1, "openat": 2, "fstat": 3, "write": 1},
    "supervisor_own_group": {"pgroup": 1},
    # command_grant::session::neutral: the 0500 folder's mkdirat (EEXIST once made),
    # open and fd_facts, then its emptiness check through a cursor on a
    # duplicate (the dup itself is the "dup" primitive).
    "neutral": {"mkdir": 1, "openat": 1, "fstat": 2, "fd_query": 1, "fd_flags": 1, "seek": 1, "getdents": 2},
    # command_process::spawn_supervisor's posix_spawn: the child opens
    # /dev/null for fds 0-2 and chdir("/") before its exec.
    "command_spawn": {"spawn": 1, "openat": 3, "cwd": 1},
    # exec_path's no-follow walk of a folder: "/" open and fd stat, then per
    # name an lstat, open and fd stat (`folder_name`).
    "folder_root": {"openat": 1, "fstat": 1},
    "folder_name": {"openat": 1, "fstat": 2},
    # exec_path::lookup_open's target: lstat, open, statx and fd stat, the
    # file-capability query (a readable target, so on its descriptor)
    # and the 256-byte header pread.
    "target_file": {"fstat": 3, "openat": 1, "caps": 1, "read": 1},
}


# musl differs only in its libc wrappers: open(O_CLOEXEC), fopen("e"),
# opendir and fcntl(F_DUPFD_CLOEXEC) add an F_SETFD of the new fd (musl's
# fallback for kernels without those flags), and its NSS reads /etc/passwd
# with stdio and no nscd or nsswitch.conf. Entries replace PRIMITIVES ones;
# observed on aarch64 musl release builds (fixtures/helper-stage-traces.md).
MUSL_PRIMITIVES: dict[str, dict[str, int]] = {
    "passwd": {"openat": 1, "fd_flags": 2},
    "dup": {"dup": 1, "fd_flags": 1},
    "statm": {"openat": 1, "fstat": 1, "read": 2, "fd_flags": 1},
    # Its two libc open(O_CLOEXEC) calls (/proc/self/cgroup, the own folder).
    "gc_own_cgroup": {"openat": 3, "read": 2, "statfs": 1, "fd_flags": 2},
    # musl's opendir does not stat the folder.
    "fd_listing": {"openat": 1, "getdents": 2, "fd_flags": 1},
    # libc::open(O_CLOEXEC) of /proc/self/cgroup and of the own cgroup folder.
    "cgroup_probe": {"kernel_release": 1, "openat": 4, "read": 2, "statfs": 1, "mkdir": 1, "fd_flags": 2},
    # libc::open(O_CLOEXEC) of PYENV_ROOT by its path.
    "manager_install": {"openat": 5, "fstat": 6, "fd_flags": 1},
}


# Parent-side successful posix_spawn exec-error channel, per libc.
# A2 keep-musl/unchanged.strace, front PID 1838: one CLOEXEC pipe,
# close writer, read an int (EOF on exec success), close reader.
# A2 helper accounting excludes supervision pipes; it has no exact table.
POSIX_SPAWN_PRIMITIVES: dict[str, dict[str, int]] = {
    "gnu": {},
    "musl": {"pipe2": 1, "read": 1, "close": 2},
}


# The front's command environment frame before its helper spawn, every libc:
# pipe2(O_CLOEXEC|O_NONBLOCK), one write of the whole frame, close of the
# write end after it and of the read end after the spawn. These are the
# counts of a normal prompt, which every gate fixture is; an oversize
# environment skips the write (test_oversize_env_block_means_no_env checks that
# path on its own). The helper's fd 4 read and close are pipe calls, outside
# the helper stage kinds; GATE-FDS.1 pins them.
ENV_PIPE_PRIMITIVES: dict[str, int] = {"pipe2": 1, "write": 1, "close": 2}


# Rust std main-thread stack guard via glibc pthread_getattr_np. In the
# x86_64 CI capture, /proc/self/maps stdio teardown calls lseek(SEEK_CUR)
# then lseek(SEEK_SET). Neither call is a loader exemption. The preceding
# open/stat/reads retain the existing prologue rules; no new ignores here.
# aarch64 glibc captures have maps reads but no seeks. Rust std's
# install_main_guard_linux_musl returns None on both architectures, so that
# startup path has neither maps reads nor seeks (also seen in aarch64 musl).
# Front startup opens/reads are exact too. These entries are used only by
# the front gate; helper prologue accounting remains unchanged. glibc loads
# cache, libgcc and libc, then Rust reads maps three times for its stack guard.
# x86_64 glibc also preads the libc ELF program headers twice; aarch64
# headers fit the initial read. Static musl builds only list inherited fds,
# as do the glibc builds.
STARTUP_PRIMITIVES = {
    ("x86_64", "gnu"): {
        "stack_guard": {"seek": 2},
        "front_fds": {"openat": 1},
        "front_cache": {"openat": 1},
        "front_libgcc": {"openat": 1, "read": 1},
        "front_libc": {"openat": 1, "read": 1, "pread64": 2},
        "front_maps": {"openat": 1, "read": 3},
    },
    ("aarch64", "gnu"): {
        "stack_guard": {},
        "front_fds": {"openat": 1},
        "front_cache": {"openat": 1},
        "front_libgcc": {"openat": 1, "read": 1},
        "front_libc": {"openat": 1, "read": 1},
        "front_maps": {"openat": 1, "read": 3},
    },
    ("x86_64", "musl"): {"stack_guard": {}, "front_fds": {"openat": 1}},
    ("aarch64", "musl"): {"stack_guard": {}, "front_fds": {"openat": 1}},
}
