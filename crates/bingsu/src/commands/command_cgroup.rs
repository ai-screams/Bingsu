//! Reclaiming a shell session's command cgroups. Only the refresh helper that holds the
//! session lock reclaims: while it holds the lock no supervisor of the
//! session is alive (the supervisor holds a copy), so everything under the
//! session's parent folder is left over from one that is gone.
//!
//! One reclaim lists the parent in `getdents64` order, kills every unit
//! cgroup it may visit, then for each one whose `cgroup.events` reads
//! `populated 0` removes the subtree in post-order and then the unit folder.
//! A unit still populated after the kill and its retries (a descendant held
//! in the kernel, for one) stays for a later reclaim. Limits: 64 folders
//! visited in all (units and subtree folders), subtree depth 4, 20 ms.
use bingsu_core::command::cgroup::{
    self, POPULATED_RETRIES, RECLAIM_DEPTH, RECLAIM_NS, RECLAIM_VISITS,
};
use std::io;

/// Wait for `cgroup.events` to change after a kill, per retry.
const POPULATED_WAIT_MS: i32 = 1;

/// The operations a reclaim makes on the cgroup tree; tests replace them.
pub(crate) trait Tree {
    type Dir;
    /// Names of the folders right under `dir`, in listing order, at most `max`.
    fn subdirs(&mut self, dir: &mut Self::Dir, max: usize) -> io::Result<Vec<Vec<u8>>>;
    /// The folder `name` under `dir`, never following a symlink.
    fn open(&mut self, dir: &Self::Dir, name: &[u8]) -> io::Result<Self::Dir>;
    /// `1` into the folder's `cgroup.kill`.
    fn kill(&mut self, dir: &Self::Dir) -> io::Result<()>;
    /// The folder's `populated` value, after waiting up to `wait_ms` for
    /// `cgroup.events` to change when it is above 0.
    fn populated(&mut self, dir: &mut Self::Dir, wait_ms: i32) -> io::Result<Option<bool>>;
    /// Removes the empty folder `name` under `dir`.
    fn rmdir(&mut self, dir: &Self::Dir, name: &[u8]) -> io::Result<()>;
    fn now(&mut self) -> u64;
}

/// What one reclaim did, for the helper's log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reclaim {
    /// Unit folders opened and killed (the kill pass).
    pub kills: usize,
    /// Units and subtree folders the cleanup pass took (its window).
    pub visits: usize,
    /// Unit folders removed.
    pub removed: usize,
    /// Unit folders still populated after the kill: left for later.
    pub stuck: usize,
    /// Unit folders kept because their subtree goes below depth 4.
    pub deep: usize,
    /// The visit window or the time ran out with entries left.
    pub capped: bool,
    /// The parent held more names than one reclaim reads.
    pub truncated: bool,
    /// Calls that failed (the entry stays).
    pub failed: usize,
    /// Time from start to end.
    pub elapsed_ns: u64,
}

impl Reclaim {
    /// The diagnostic lines this reclaim leaves in the helper's log.
    pub(crate) fn messages(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.deep > 0 {
            out.push("command reclaim: a unit cgroup deeper than 4 levels stays");
        }
        if self.capped {
            out.push("command reclaim: limit reached, the rest waits for the next reclaim");
        }
        if self.truncated {
            out.push("command reclaim: the session's cgroup folder holds more names than one reclaim reads");
        }
        out
    }
}

/// Unit folders one reclaim kills. The kill pass opens a unit folder and its
/// `cgroup.kill` only, never a subtree, so it has its own budget: units that
/// stay (stuck, too deep) never keep the ones after them from their kill.
const KILL_MAX: usize = RECLAIM_VISITS;
/// Names one reclaim reads under the parent. Names outside the unit grammar
/// cost no visit; past this many the rest of the listing is not seen.
const LIST_MAX: usize = 4 * RECLAIM_VISITS;

/// Whether the reclaim's time is up; set `capped` when it is.
fn over<T: Tree>(t: &mut T, end: u64, r: &mut Reclaim) -> bool {
    let over = t.now() >= end;
    r.capped |= over;
    over
}

/// One reclaim of the session parent `parent`.
pub(crate) fn reclaim<T: Tree>(t: &mut T, parent: &mut T::Dir) -> Reclaim {
    let start = t.now();
    let end = start.saturating_add(RECLAIM_NS);
    let mut r = Reclaim::default();
    let mut names = match t.subdirs(parent, LIST_MAX + 1) {
        Ok(names) => names,
        Err(_) => {
            r.failed += 1;
            r.elapsed_ns = t.now().saturating_sub(start);
            return r;
        }
    };
    if names.len() > LIST_MAX {
        names.truncate(LIST_MAX);
        r.truncated = true;
    }
    // Every unit is killed before any is checked, so their deaths overlap.
    let mut units = Vec::new();
    for name in names.into_iter().filter(|n| cgroup::is_unit_name(n)) {
        if r.kills >= KILL_MAX {
            r.capped = true;
            break;
        }
        if over(t, end, &mut r) {
            break;
        }
        let Ok(dir) = t.open(parent, &name) else {
            r.failed += 1;
            continue;
        };
        r.kills += 1;
        if over(t, end, &mut r) {
            break;
        }
        if t.kill(&dir).is_err() {
            r.failed += 1;
        }
        units.push((name, dir));
    }
    // The cleanup pass has the visit window: each unit and each subtree folder.
    for (name, mut dir) in units {
        if r.visits >= RECLAIM_VISITS {
            r.capped = true;
            break;
        }
        if over(t, end, &mut r) {
            break;
        }
        r.visits += 1;
        let mut empty = t.populated(&mut dir, 0).ok().flatten() == Some(false);
        for _ in 0..POPULATED_RETRIES {
            if empty {
                break;
            }
            // Never wait past the reclaim's own end.
            let left = end.saturating_sub(t.now()) / 1_000_000;
            let wait = POPULATED_WAIT_MS.min(i32::try_from(left).unwrap_or(i32::MAX));
            if wait == 0 {
                r.capped = true;
                break;
            }
            empty = t.populated(&mut dir, wait).ok().flatten() == Some(false);
        }
        if !empty {
            r.stuck += 1;
            continue;
        }
        let mut deep = false;
        if !clear(t, &mut dir, 1, end, &mut r, &mut deep) {
            r.deep += usize::from(deep);
            continue;
        }
        drop(dir);
        if over(t, end, &mut r) {
            break;
        }
        match t.rmdir(parent, &name) {
            Ok(()) => r.removed += 1,
            Err(_) => r.failed += 1,
        }
    }
    r.elapsed_ns = t.now().saturating_sub(start);
    r
}

/// Removes every folder under `dir` in post-order; `depth` is the level of
/// its children. True when `dir` is left without children. The time is
/// checked before every listing and every removal.
fn clear<T: Tree>(
    t: &mut T,
    dir: &mut T::Dir,
    depth: usize,
    end: u64,
    r: &mut Reclaim,
    deep: &mut bool,
) -> bool {
    if over(t, end, r) {
        return false;
    }
    let room = RECLAIM_VISITS.saturating_sub(r.visits) + 1;
    let Ok(kids) = t.subdirs(dir, room) else {
        r.failed += 1;
        return false;
    };
    if kids.is_empty() {
        return true;
    }
    if depth > RECLAIM_DEPTH {
        *deep = true;
        return false;
    }
    let mut all = true;
    for name in kids {
        if r.visits >= RECLAIM_VISITS {
            r.capped = true;
            return false;
        }
        if over(t, end, r) {
            return false;
        }
        let Ok(mut child) = t.open(dir, &name) else {
            r.failed += 1;
            all = false;
            continue;
        };
        r.visits += 1;
        let cleared = clear(t, &mut child, depth + 1, end, r, deep);
        drop(child);
        if !cleared {
            all = false;
        } else if over(t, end, r) {
            return false;
        } else if t.rmdir(dir, &name).is_err() {
            r.failed += 1;
            all = false;
        }
    }
    all
}

/// A whole small file through `read(buf, offset)`, chunk after chunk until
/// end of file. `None` past `max` bytes: a list cut there could end in a
/// partial line that names another value, so it is not read at all.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux reads cgroup.procs")
)]
pub(crate) fn read_bounded(
    read: &mut dyn FnMut(&mut [u8], u64) -> io::Result<usize>,
    max: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = read(&mut chunk, out.len() as u64).ok()?;
        if n == 0 {
            return Some(out);
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > max {
            return None;
        }
    }
}

/// The cgroup file system itself (Linux).
#[cfg(target_os = "linux")]
pub(crate) mod fs {
    use super::super::sys;
    use bingsu_core::command::cgroup;
    use std::{
        ffi::OsStr,
        fs::File,
        io,
        os::{
            fd::{AsFd, AsRawFd},
            unix::ffi::OsStrExt,
        },
    };

    pub(crate) struct Fs;

    /// A cgroup folder and, once read, its `cgroup.events`.
    pub(crate) struct Dir {
        pub folder: File,
        events: Option<File>,
    }

    impl Dir {
        pub(crate) fn new(folder: File) -> Self {
            Self {
                folder,
                events: None,
            }
        }
    }

    /// The mount id of an open folder (`statx` `STATX_MNT_ID`, Linux 5.8);
    /// `None` when the kernel does not report it, which is no atomic path.
    pub(crate) fn mount_id(fd: &File) -> Option<u64> {
        const STATX_MNT_ID: u32 = 0x1000;
        // struct statx: stx_mask (u32) at 0, stx_mnt_id (u64) at 0x90; 256 bytes.
        let mut buf = [0u64; 32];
        // SAFETY: an open descriptor, an empty NUL-terminated name with
        // AT_EMPTY_PATH, and a writable buffer of statx's size.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                STATX_MNT_ID,
                buf.as_mut_ptr(),
            )
        };
        // stx_mask is the u32 at offset 0, whatever the byte order.
        let mask = u32::from_ne_bytes(buf[0].to_ne_bytes()[..4].try_into().unwrap_or([0; 4]));
        (rc == 0 && mask & STATX_MNT_ID != 0).then_some(buf[18])
    }

    fn open_at(dir: &File, name: &[u8], flags: i32) -> io::Result<File> {
        let c = std::ffi::CString::new(name)?;
        // SAFETY: `dir` is open and `c` is NUL-terminated; the result is owned once.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        use std::os::fd::FromRawFd;
        // SAFETY: a fresh descriptor nothing else owns.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// `1` into `cgroup.kill` of `folder`: every process of the subtree gets
    /// SIGKILL, forks in progress included. The file must sit on the
    /// folder's own mount: a `cgroup.kill` of another cgroup bind-mounted
    /// over this one's name would kill that cgroup instead.
    pub(crate) fn kill_file(folder: &File) -> io::Result<File> {
        let kill = open_at(folder, b"cgroup.kill", libc::O_WRONLY)?;
        kill_on(kill, mount_id(folder))
    }

    /// `kill_file` for a folder whose mount id the caller already has.
    pub(crate) fn kill_file_on(folder: &File, mount: u64) -> io::Result<File> {
        kill_on(
            open_at(folder, b"cgroup.kill", libc::O_WRONLY)?,
            Some(mount),
        )
    }

    fn kill_on(kill: File, folder: Option<u64>) -> io::Result<File> {
        // Fails without it: test_kill_file_refuses_a_file_bind_mounted_over_it.
        match (folder, mount_id(&kill)) {
            (Some(a), Some(b)) if a == b => Ok(kill),
            _ => Err(io::Error::other("cgroup.kill on another mount")),
        }
    }

    /// The mount id of `folder` when it is on `parent`'s mount, else `None`:
    /// a cgroup folder bind-mounted over a name below the parent is not one
    /// of its children (the supervisor's unit, as the reclaim's `open`).
    pub(crate) fn on_parent_mount(parent: &File, folder: &File) -> Option<u64> {
        let parent = mount_id(parent)?;
        // Fails without it: test_a_folder_bound_below_the_parent_is_not_its_child.
        (mount_id(folder)? == parent).then_some(parent)
    }

    pub(crate) fn write_kill(kill: &File) -> io::Result<()> {
        match sys::write_fd(kill.as_raw_fd(), b"1") {
            sys::WriteOutcome::Done => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn read_small(path: &std::ffi::CStr, max: usize) -> io::Result<Vec<u8>> {
        // Inside the collection GC every call is charged (open and its close,
        // then each read); outside it the meter is empty and charges nothing.
        sys::collection_ops(2)?;
        // SAFETY: fixed NUL-terminated path; the descriptor is owned below.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        use std::os::fd::FromRawFd;
        // SAFETY: a fresh descriptor nothing else owns.
        let file = unsafe { File::from_raw_fd(fd) };
        let mut out = vec![0u8; max + 1];
        let mut len = 0;
        while len < out.len() {
            sys::collection_ops(1)?;
            // SAFETY: writable tail of `out`.
            let n = unsafe {
                libc::read(
                    file.as_raw_fd(),
                    out[len..].as_mut_ptr().cast(),
                    out.len() - len,
                )
            };
            match usize::try_from(n) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(_) => return Err(io::Error::last_os_error()),
            }
        }
        out.truncate(len);
        Ok(out)
    }

    /// Who asks for the session's cgroup parent.
    pub(crate) struct Who<'a> {
        pub session: &'a [u8],
        /// `(dev, ino)` of the runtime root, where the session lock lives.
        pub runtime: (u64, u64),
        pub me: u32,
        /// This process: it must be in the cgroup the path names.
        pub pid: u32,
    }

    fn cgroup2(fd: &File) -> bool {
        // SAFETY: zeroed writable statfs.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: open descriptor and writable statfs.
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut st) } != 0 {
            return false;
        }
        #[allow(
            clippy::unnecessary_cast,
            reason = "f_type's type differs between libcs"
        )]
        let magic = st.f_type as i64 == libc::CGROUP2_SUPER_MAGIC as i64;
        magic
    }

    /// The atomic path's capability (the
    /// X-04 method): Linux 5.14 or later; the process's
    /// `0::` cgroup on the cgroup v2 mount at `/sys/fs/cgroup`, which must
    /// hold this process (a cgroup namespace whose mount was not redone
    /// names another folder); and the session parent `bingsu-cmd-<digest>`
    /// under it, made here when missing, owned by `me` and on the same mount
    /// as the process's own cgroup. On cgroup v2 from 5.14 every non-root cgroup has `cgroup.kill`,
    /// and the parent is never the root. `None` on any miss: the round takes
    /// the best-effort path. Called only by a helper holding the session
    /// lock, in a round with command units.
    pub(crate) fn open_session(who: &Who<'_>) -> Option<Dir> {
        // SAFETY: zeroed writable utsname.
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: writable utsname.
        if unsafe { libc::uname(&mut u) } != 0 {
            return None;
        }
        // SAFETY: uname wrote a NUL-terminated release.
        let release = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) };
        let text = read_small(c"/proc/self/cgroup", cgroup::PROC_CGROUP_MAX).ok()?;
        open_session_at(b"/sys/fs/cgroup", release.to_bytes(), &text, who)
    }

    /// The process's own cgroup folder on the cgroup v2 mount, holding this
    /// process (the round's check, for the collection GC). `Absent` only when
    /// `/proc/self/cgroup` has no cgroup v2 line (`0::`): no round makes a
    /// parent then (`open_session` needs that line). Any other miss is
    /// `Unknown`: a parent may be there out of sight (m6-C4a7).
    pub(crate) fn open_own() -> super::super::command_sessions::OwnCgroup {
        use super::super::command_sessions::OwnCgroup;
        let Ok(text) = read_small(c"/proc/self/cgroup", cgroup::PROC_CGROUP_MAX) else {
            return OwnCgroup::Unknown;
        };
        own_or_why(b"/sys/fs/cgroup", &text)
    }

    /// [`open_own`] from its inputs.
    pub(crate) fn own_or_why(
        mount: &[u8],
        proc_self_cgroup: &[u8],
    ) -> super::super::command_sessions::OwnCgroup {
        use super::super::command_sessions::OwnCgroup;
        // 이것을 실패시키는 것: v2 줄 없음 대신 찾기 실패를 없음으로 보는 것, v2 줄이 없는데 모름으로 보는 것
        // (gc_lookup_failure_is_not_absence).
        if !proc_self_cgroup
            .split(|&b| b == b'\n')
            .any(|l| l.starts_with(b"0::"))
        {
            return OwnCgroup::Absent;
        }
        match open_own_member_at(mount, proc_self_cgroup) {
            Some(own) => OwnCgroup::Folder(own),
            None => OwnCgroup::Unknown,
        }
    }

    /// [`open_own`] from its inputs, for this process.
    pub(crate) fn open_own_member_at(mount: &[u8], proc_self_cgroup: &[u8]) -> Option<File> {
        open_member_at(mount, proc_self_cgroup, std::process::id())
    }

    /// The folder `proc_self_cgroup` names on `mount` when its
    /// `cgroup.procs` lists `pid`: a cgroup namespace whose mount was not
    /// redone names another folder.
    fn open_member_at(mount: &[u8], proc_self_cgroup: &[u8], pid: u32) -> Option<File> {
        let own = open_own_at(mount, proc_self_cgroup)?;
        sys::collection_ops(2).ok()?;
        let procs = open_at(&own, b"cgroup.procs", libc::O_RDONLY).ok()?;
        let text = super::read_bounded(
            &mut |buf, at| {
                sys::collection_ops(1)?;
                let at = libc::off_t::try_from(at).map_err(|_| io::Error::other("offset"))?;
                // SAFETY: writable buffer of its length.
                let n = unsafe {
                    libc::pread(procs.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), at)
                };
                usize::try_from(n).map_err(|_| io::Error::last_os_error())
            },
            cgroup::PROCS_MAX,
        )?;
        // 이것을 실패시키는 것: 이 소속 확인을 지우는 것(회차: test_capability_needs_its_own_cgroup,
        // GC: test_gc_own_cgroup_needs_its_own_cgroup).
        cgroup::procs_contains(&text, pid).then_some(own)
    }

    /// [`open_own`] from its inputs: the cgroup v2 mount and
    /// `/proc/self/cgroup`.
    pub(crate) fn open_own_at(mount: &[u8], proc_self_cgroup: &[u8]) -> Option<File> {
        let own = cgroup::own_path(proc_self_cgroup)?;
        let own = std::ffi::CString::new([mount, own].concat()).ok()?;
        // The open and its close, then the fstatfs.
        sys::collection_ops(3).ok()?;
        // SAFETY: NUL-terminated path; the descriptor is owned below.
        let fd = unsafe {
            libc::open(
                own.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        use std::os::fd::FromRawFd;
        // SAFETY: a fresh descriptor nothing else owns.
        let own = unsafe { File::from_raw_fd(fd) };
        cgroup2(&own).then_some(own)
    }

    /// [`open_session`] from its inputs: the cgroup v2 mount, `uname -r`
    /// and `/proc/self/cgroup`.
    pub(crate) fn open_session_at(
        mount: &[u8],
        release: &[u8],
        proc_self_cgroup: &[u8],
        who: &Who<'_>,
    ) -> Option<Dir> {
        if !cgroup::kernel_has_kill(release) {
            return None;
        }
        let own = open_member_at(mount, proc_self_cgroup, who.pid)?;
        let name = cgroup::parent_name(who.session, who.runtime);
        let name = OsStr::new(&name);
        // A failed mkdir (read-only, not delegated) leaves nothing to open.
        let _ = sys::mkdir_at(own.as_fd(), name, 0o700);
        let parent = sys::open_dir_at_nofollow(own.as_fd(), name).ok()?;
        if sys::fd_facts(parent.as_fd()).ok()?.uid != who.me {
            return None;
        }
        // The parent on the same mount as the process's own cgroup (so on
        // cgroup v2 too): a folder mounted over the name, a plain one or
        // another session's parent, is not it.
        let mount = mount_id(&own)?;
        if mount_id(&parent)? != mount {
            return None;
        }
        Some(Dir::new(parent))
    }

    impl super::Tree for Fs {
        type Dir = Dir;

        fn subdirs(&mut self, dir: &mut Dir, max: usize) -> io::Result<Vec<Vec<u8>>> {
            let fd = dir.folder.as_raw_fd();
            // SAFETY: own descriptor; a parent listed twice starts again.
            if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut names = Vec::new();
            let mut buf = [0u8; 4096];
            while names.len() < max {
                // SAFETY: getdents64 writes at most the buffer's length.
                let n =
                    unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
                let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
                if n == 0 {
                    break;
                }
                let mut at = 0;
                // linux_dirent64: ino u64, off i64, reclen u16, type u8, name.
                while at + 19 <= n && names.len() < max {
                    let reclen = usize::from(u16::from_ne_bytes([buf[at + 16], buf[at + 17]]));
                    if reclen < 19 || at + reclen > n {
                        return Err(io::Error::other("getdents64 record"));
                    }
                    let kind = buf[at + 18];
                    let name = &buf[at + 19..at + reclen];
                    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                    if kind == libc::DT_DIR && name != b"." && name != b".." {
                        names.push(name.to_vec());
                    }
                    at += reclen;
                }
            }
            Ok(names)
        }

        fn open(&mut self, dir: &Dir, name: &[u8]) -> io::Result<Dir> {
            let child = open_at(&dir.folder, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            // A folder mounted over a name below the parent (another cgroup)
            // is never killed or removed.
            match (mount_id(&dir.folder), mount_id(&child)) {
                (Some(a), Some(b)) if a == b => Ok(Dir::new(child)),
                _ => Err(io::Error::other("cgroup folder on another mount")),
            }
        }

        fn kill(&mut self, dir: &Dir) -> io::Result<()> {
            write_kill(&kill_file(&dir.folder)?)
        }

        fn populated(&mut self, dir: &mut Dir, wait_ms: i32) -> io::Result<Option<bool>> {
            if dir.events.is_none() {
                dir.events = Some(open_at(&dir.folder, b"cgroup.events", libc::O_RDONLY)?);
            }
            let events = dir.events.as_ref().map_or(-1, |f| f.as_raw_fd());
            if wait_ms > 0 {
                // kernfs reports a change of cgroup.events as POLLPRI.
                let mut fds = [libc::pollfd {
                    fd: events,
                    events: libc::POLLPRI,
                    revents: 0,
                }];
                // SAFETY: one valid pollfd.
                unsafe { libc::poll(fds.as_mut_ptr(), 1, wait_ms) };
            }
            let mut buf = [0u8; 256];
            // SAFETY: writable buffer of its length; kernfs files reread from 0.
            let n = unsafe { libc::pread(events, buf.as_mut_ptr().cast(), buf.len(), 0) };
            let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
            Ok(cgroup::populated(&buf[..n]))
        }

        fn rmdir(&mut self, dir: &Dir, name: &[u8]) -> io::Result<()> {
            sys::remove_dir_at(dir.folder.as_fd(), OsStr::from_bytes(name))
        }

        fn now(&mut self) -> u64 {
            super::super::collector_process::now_ns().unwrap_or(u64::MAX)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

/// On a delegated cgroup v2 tree (the privileged container cell): run with
/// `--ignored`. Each test makes its own parent under the test's cgroup.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod cell;
