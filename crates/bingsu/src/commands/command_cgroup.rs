//! Reclaiming a shell session's command cgroups (spec section 4, stop order
//! step 4; U-15 Q1, U-9d, U-9j). Only the refresh helper that holds the
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

    /// The atomic path's capability (spec section 4 stop order step 4, the
    /// X-04 method; U-14 F0, C3 rulings): Linux 5.14 or later; the process's
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
    /// redone names another folder (U-14 F0).
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
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A cgroup tree in memory: each folder has children in listing order,
    /// a populated value that a kill clears unless the folder is stuck, and
    /// a log of every call. Every call advances the clock by `tick`.
    #[derive(Default)]
    pub(crate) struct Fake {
        pub folders: BTreeMap<Vec<u8>, Folder>,
        pub log: Vec<String>,
        pub clock: u64,
        pub tick: u64,
        /// The clock when each call started.
        pub starts: Vec<u64>,
        /// The longest wait a populated read asked for.
        pub waited: i32,
    }
    #[derive(Default, Clone)]
    pub(crate) struct Folder {
        pub children: Vec<Vec<u8>>,
        pub populated: bool,
        /// `cgroup.kill` does not empty it (a descendant held in the kernel).
        pub stuck: bool,
        /// Reads before a kill takes effect.
        pub dying: usize,
    }

    impl Fake {
        pub(crate) fn add(&mut self, path: &str) {
            let mut parent = String::new();
            for part in path.split('/') {
                let me = if parent.is_empty() {
                    part.to_owned()
                } else {
                    format!("{parent}/{part}")
                };
                if !self.folders.contains_key(me.as_bytes()) {
                    self.folders
                        .insert(me.clone().into_bytes(), Folder::default());
                    if let Some(p) = self.folders.get_mut(parent.as_bytes()) {
                        p.children.push(part.as_bytes().to_vec());
                    }
                }
                parent = me;
            }
        }
        pub(crate) fn get(&mut self, path: &str) -> &mut Folder {
            self.folders.get_mut(path.as_bytes()).unwrap()
        }
        fn step(&mut self) {
            self.starts.push(self.clock);
            self.clock += self.tick;
        }
        /// Unit folders still under `parent`.
        pub(crate) fn left(&self, parent: &str) -> Vec<String> {
            self.folders[parent.as_bytes()]
                .children
                .iter()
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect()
        }
        fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
            [dir, b"/", name].concat()
        }
    }

    impl Tree for Fake {
        type Dir = Vec<u8>;
        fn subdirs(&mut self, dir: &mut Vec<u8>, max: usize) -> io::Result<Vec<Vec<u8>>> {
            self.step();
            let kids = &self.folders[dir.as_slice()].children;
            Ok(kids.iter().take(max).cloned().collect())
        }
        fn open(&mut self, dir: &Vec<u8>, name: &[u8]) -> io::Result<Vec<u8>> {
            self.step();
            let path = Self::join(dir, name);
            self.log
                .push(format!("open {}", String::from_utf8_lossy(&path)));
            self.folders
                .contains_key(&path)
                .then_some(path)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
        }
        fn kill(&mut self, dir: &Vec<u8>) -> io::Result<()> {
            self.step();
            self.log
                .push(format!("kill {}", String::from_utf8_lossy(dir)));
            // A kill reaches the whole subtree.
            let prefix = [dir.as_slice(), b"/"].concat();
            for (path, f) in self.folders.iter_mut() {
                if (path == dir || path.starts_with(&prefix)) && !f.stuck {
                    f.dying = f.dying.max(usize::from(f.populated));
                }
            }
            Ok(())
        }
        fn populated(&mut self, dir: &mut Vec<u8>, wait_ms: i32) -> io::Result<Option<bool>> {
            self.step();
            self.waited = self.waited.max(wait_ms);
            self.clock += u64::try_from(wait_ms).unwrap_or(0) * 1_000_000;
            let prefix = [dir.as_slice(), b"/"].concat();
            let mut any = false;
            for (path, f) in self.folders.iter_mut() {
                if path == dir || path.starts_with(&prefix) {
                    if f.populated && !f.stuck && f.dying > 0 {
                        f.dying -= 1;
                        if f.dying == 0 {
                            f.populated = false;
                        }
                    }
                    any |= f.populated;
                }
            }
            self.log.push(format!(
                "populated {} {}",
                String::from_utf8_lossy(dir),
                u8::from(any)
            ));
            Ok(Some(any))
        }
        fn rmdir(&mut self, dir: &Vec<u8>, name: &[u8]) -> io::Result<()> {
            self.step();
            let path = Self::join(dir, name);
            self.log
                .push(format!("rmdir {}", String::from_utf8_lossy(&path)));
            let f = &self.folders[&path];
            if !f.children.is_empty() || f.populated {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            self.folders.remove(&path);
            self.folders
                .get_mut(dir.as_slice())
                .unwrap()
                .children
                .retain(|c| c != name);
            Ok(())
        }
        fn now(&mut self) -> u64 {
            self.clock
        }
    }

    fn unit(i: u64) -> String {
        cgroup::unit_name(i)
    }

    /// The deep unit (a chain six levels down) first, a unit exactly four
    /// levels deep, 30 empty units, then one unit holding 40 cgroups three
    /// levels deep: 81 visits in all,
    /// more than one reclaim may make.
    fn caps_fixture(tick: u64) -> Fake {
        let mut f = Fake {
            tick,
            ..Fake::default()
        };
        f.add(&format!("p/{}/a/b/c/d/e/f", unit(0)));
        // Exactly four levels: still removed.
        f.add(&format!("p/{}/a/b/c/d", unit(50)));
        for i in 1..=30 {
            f.add(&format!("p/{}", unit(i)));
        }
        let wide = unit(99);
        for a in 0..4 {
            for b in 0..3 {
                for c in 0..2 {
                    f.add(&format!("p/{wide}/a{a}/b{b}/c{c}"));
                }
            }
        }
        f
    }

    // 상한: 한 회수의 방문 ≤ 64, 작업 시간 ≤ 20 ms, 두 회수 안에 깊이 3 트리는 모두 제거, 깊이 6 트리의 단위
    // 폴더는 남고 진단 1줄. 이것을 실패시키는 것: 방문 상한(`r.visits >= RECLAIM_VISITS`) 두 곳을 지우는 것
    // (첫 회수가 64곳을 넘게 방문), 시간 상한(`t.now() >= end`)을 지우는 것(느린 시계에서 20 ms를 넘김), 깊이 상한을
    // 지우는 것(깊이 6 단위가 제거되고 진단이 없음), 빈 폴더의 조기 true를 지우는 것(깊이 정확히 4인 단위가 남음),
    // `!cleared` 분기를 지우는 것(남은 하위 트리 위 폴더에 rmdir을 시도해 failed가 생김).
    #[test]
    fn test_reclaim_depth_and_count_caps() {
        let mut f = caps_fixture(1_000);
        let mut parent = b"p".to_vec();
        let first = reclaim(&mut f, &mut parent);
        assert!(first.visits <= RECLAIM_VISITS, "{first:?}");
        assert!(first.capped, "{first:?}");
        let second = reclaim(&mut f, &mut parent);
        assert!(second.visits <= RECLAIM_VISITS, "{second:?}");
        assert_eq!(f.left("p"), [unit(0)]);
        assert!(
            f.folders
                .contains_key(format!("p/{}/a/b/c/d", unit(0)).as_bytes())
        );
        assert_eq!(second.deep, 1, "{second:?}");
        // No rmdir is tried on a folder whose subtree stayed.
        assert_eq!(first.failed + second.failed, 0, "{first:?} {second:?}");
        assert_eq!(
            second.messages(),
            ["command reclaim: a unit cgroup deeper than 4 levels stays"]
        );
        // A slow tree: every call takes 1 ms, so the clock, not the window,
        // ends it: while killing units, and inside one wide subtree.
        let mut slow = caps_fixture(1_000_000);
        let r = reclaim(&mut slow, &mut parent);
        assert!(r.capped, "{r:?}");
        assert!(r.elapsed_ns <= RECLAIM_NS + 2 * slow.tick, "{r:?}");
        let mut wide = Fake {
            tick: 1_000_000,
            ..Fake::default()
        };
        for a in 0..40 {
            wide.add(&format!("p/{}/a{a}", unit(7)));
        }
        let r = reclaim(&mut wide, &mut parent);
        assert!(r.capped, "{r:?}");
        assert!(r.elapsed_ns <= RECLAIM_NS + 2 * wide.tick, "{r:?}");
        // More units than the kill pass may take: it stops at 64.
        let mut many = Fake::default();
        for i in 0..70 {
            many.add(&format!("p/{}", unit(i)));
        }
        let r = reclaim(&mut many, &mut parent);
        assert_eq!((r.kills, r.removed), (KILL_MAX, KILL_MAX), "{r:?}");
        assert!(r.capped);
    }

    // 남는 항목은 건너뛰고 빈 항목은 그 회수에 모두 제거. 이것을 실패시키는 것: populated 뒤의
    // `if !empty { stuck; continue }`를 지우는 것(남는 항목 셋에 rmdir을 시도해 stuck 0, failed 3).
    #[test]
    fn test_reclaim_skips_stuck_entries() {
        let mut f = Fake::default();
        for i in 0..8 {
            f.add(&format!("p/{}", unit(i)));
        }
        for i in [0, 3, 6] {
            let u = f.get(&format!("p/{}", unit(i)));
            u.populated = true;
            u.stuck = true;
        }
        let mut parent = b"p".to_vec();
        let r = reclaim(&mut f, &mut parent);
        assert_eq!((r.removed, r.stuck, r.failed), (5, 3, 0), "{r:?}");
        assert_eq!(f.left("p"), [unit(0), unit(3), unit(6)]);
    }

    // rmdir은 그 단위의 populated=0 관측 뒤에만. 이것을 실패시키는 것: populated 확인을 건너뛰는 것
    // (`let mut empty = true`), kill 직후 첫 rmdir이 populated 기록보다 앞선다.
    #[test]
    fn test_populated_checked_before_rmdir() {
        let mut f = Fake::default();
        f.add(&format!("p/{}/x", unit(1)));
        let u = f.get(&format!("p/{}", unit(1)));
        // The kill takes two reads to empty it.
        u.populated = true;
        u.dying = 2;
        let x = f.get(&format!("p/{}/x", unit(1)));
        x.populated = true;
        x.dying = 2;
        let mut parent = b"p".to_vec();
        let r = reclaim(&mut f, &mut parent);
        assert_eq!(r.removed, 1, "{r:?} {:?}", f.log);
        let zero = f
            .log
            .iter()
            .position(|l| l == &format!("populated p/{} 0", unit(1)))
            .expect("populated 0 observed");
        let first_rmdir = f.log.iter().position(|l| l.starts_with("rmdir")).unwrap();
        assert!(zero < first_rmdir, "{:?}", f.log);
    }

    // 문법 밖 이름은 열지도 죽이지도 않는다. 이것을 실패시키는 것: is_unit_name 거르기를 지우는 것.
    #[test]
    fn reclaim_touches_only_unit_names() {
        let mut f = Fake::default();
        f.add("p/other");
        f.add(&format!("p/{}", unit(2)));
        let mut parent = b"p".to_vec();
        let r = reclaim(&mut f, &mut parent);
        assert_eq!(r.removed, 1);
        assert_eq!(f.left("p"), ["other"]);
        assert!(!f.log.iter().any(|l| l.contains("other")), "{:?}", f.log);
    }

    fn chunks(data: &'static [u8], size: usize) -> impl FnMut(&mut [u8], u64) -> io::Result<usize> {
        move |buf, at| {
            let at = usize::try_from(at).unwrap().min(data.len());
            let n = data[at..].len().min(size).min(buf.len());
            buf[..n].copy_from_slice(&data[at..at + n]);
            Ok(n)
        }
    }

    // cgroup.procs는 EOF까지 여러 번 읽는다(첫 청크 뒤의 pid도 찾음). 누적이 상한을 넘으면 None. 이것을
    // 실패시키는 것: 첫 읽기 하나로 끝내는 것(둘째 청크의 4242를 놓침), 상한 검사를 지우는 것(상한을 넘는 목록을
    // 그대로 돌려줌).
    #[test]
    fn read_bounded_reads_every_chunk_up_to_its_cap() {
        let list = b"1\n2\n3\n4242\n";
        let got = read_bounded(&mut chunks(list, 4), 64).unwrap();
        assert!(cgroup::procs_contains(&got, 4242), "{got:?}");
        assert_eq!(read_bounded(&mut chunks(list, 4), 8), None);
        assert_eq!(read_bounded(&mut chunks(b"", 4), 8), Some(Vec::new()));
    }

    // kill 단계와 정리 단계의 예산이 따로라, 하위 폴더 하나씩 가진 빈 단위 64개도 한 회수에 일부가 제거된다.
    // 이것을 실패시키는 것: kill 단계가 정리 단계의 방문 창을 쓰는 것(kill마다 visits를 늘림: 64개를 kill하면
    // 하위 폴더를 볼 방문이 없어 제거 0), 정리 단계의 단위마다 하는 창 검사를 지우는 것(방문이 64를 넘음).
    #[test]
    fn test_reclaim_leaves_room_for_subtrees() {
        let mut f = Fake::default();
        for i in 0..64 {
            f.add(&format!("p/{}/x", unit(i)));
        }
        let mut parent = b"p".to_vec();
        let r = reclaim(&mut f, &mut parent);
        assert!(r.removed > 0, "{r:?}");
        assert!(r.visits <= RECLAIM_VISITS, "{r:?}");
    }

    // 문법 밖 이름은 방문을 쓰지 않으므로 그 뒤의 단위도 회수된다. 한 회수가 읽는 이름 수를 넘으면 잘림 진단을
    // 남긴다. 이것을 실패시키는 것: 목록 상한을 RECLAIM_VISITS + 1로 되돌리는 것(문법 밖 65개 뒤 단위가
    // 보이지 않음), 잘림 표시를 지우는 것(진단 없음).
    #[test]
    fn test_reclaim_reads_past_foreign_names() {
        let mut f = Fake::default();
        for i in 0..65 {
            f.add(&format!("p/other{i:03}"));
        }
        f.add(&format!("p/{}", unit(1)));
        let mut parent = b"p".to_vec();
        let r = reclaim(&mut f, &mut parent);
        assert_eq!(r.removed, 1, "{r:?}");
        assert!(!r.truncated);
        let mut f = Fake::default();
        for i in 0..LIST_MAX {
            f.add(&format!("p/other{i:04}"));
        }
        f.add(&format!("p/{}", unit(1)));
        let r = reclaim(&mut f, &mut parent);
        assert_eq!(r.removed, 0, "{r:?}");
        assert!(r.truncated, "{r:?}");
        assert!(r.messages().contains(
            &"command reclaim: the session's cgroup folder holds more names than one reclaim reads"
        ));
    }

    // 마감이 지나면 목록 읽기·rmdir·대기를 새로 시작하지 않는다: 깊이 4 체인의 재귀가 돌아오는 중에 예산이
    // 끝나는 경우와, 남는 항목의 재시도 대기가 남은 예산보다 길어지는 경우. 이것을 실패시키는 것: clear의 rmdir
    // 앞 마감 확인을 지우는 것, 목록 읽기 앞 확인을 지우는 것, 부모 rmdir 앞 확인을 지우는 것, 재시도 대기를
    // 남은 예산으로 자르지 않는 것.
    #[test]
    fn test_reclaim_stops_at_its_deadline() {
        let mut parent = b"p".to_vec();
        for tick in (1_000_000..4_000_000).step_by(100_000) {
            let mut f = Fake {
                tick,
                ..Fake::default()
            };
            f.add(&format!("p/{}/a/b/c/d", unit(1)));
            let r = reclaim(&mut f, &mut parent);
            let late: Vec<u64> = f
                .starts
                .iter()
                .copied()
                .filter(|&at| at >= RECLAIM_NS)
                .collect();
            assert!(
                late.is_empty(),
                "tick {tick}: calls after the deadline {late:?} {r:?}"
            );
        }
        // A stuck unit whose first read leaves less than 1 ms: no further wait.
        let mut f = Fake {
            tick: 4_875_000,
            ..Fake::default()
        };
        f.add(&format!("p/{}", unit(2)));
        let u = f.get(&format!("p/{}", unit(2)));
        u.populated = true;
        u.stuck = true;
        let r = reclaim(&mut f, &mut parent);
        let left = RECLAIM_NS - f.starts[3] - f.tick;
        assert!(left > 0 && left < 1_000_000, "first read leaves {left} ns");
        assert_eq!(f.waited, 0, "{r:?}");
        assert!(f.starts.iter().all(|&at| at < RECLAIM_NS), "{:?}", f.starts);
        // The open ends at the deadline: no kill follows it.
        let mut f = Fake {
            tick: 10_000_000,
            ..Fake::default()
        };
        f.add(&format!("p/{}", unit(3)));
        let r = reclaim(&mut f, &mut parent);
        assert!(
            !f.log.iter().any(|l| l.starts_with("kill")),
            "{:?} {r:?}",
            f.log
        );
    }

    // 제거할 수 없는 단위(깊이 제한으로 남는 트리 32개)가 앞에 있어도 뒤의 단위는 kill을 받는다: 실행 중인 고아가
    // 끝난다. 이것을 실패시키는 것: KILL_MAX를 방문 창의 절반(32)으로 되돌리는 것(뒤의 단위가 kill되지 않음).
    #[test]
    fn test_reclaim_kills_past_units_that_stay() {
        let mut f = Fake::default();
        for i in 0..32 {
            f.add(&format!("p/{}/a/b/c/d/e/f", unit(i)));
        }
        let orphan = format!("p/{}", unit(40));
        f.add(&orphan);
        f.get(&orphan).populated = true;
        let mut parent = b"p".to_vec();
        let r = reclaim(&mut f, &mut parent);
        assert!(f.log.contains(&format!("kill {orphan}")), "{r:?}");
        assert!(
            !f.folders[orphan.as_bytes()].populated || f.folders[orphan.as_bytes()].dying > 0,
            "{r:?}"
        );
    }
}

/// On a delegated cgroup v2 tree (the privileged container cell): run with
/// `--ignored`. Each test makes its own parent under the test's cgroup.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod cell {
    use super::fs::{self, Dir, Fs};
    use super::*;
    use std::{fs::File, os::unix::fs::DirBuilderExt, path::PathBuf, process::Command};

    /// The test process's own cgroup folder.
    pub(crate) fn own_cgroup() -> PathBuf {
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let path = cgroup::own_path(&text).expect("cgroup v2");
        PathBuf::from(format!("/sys/fs/cgroup{}", String::from_utf8_lossy(path)))
    }

    /// A fresh parent folder `bingsu-cmd-<tag>` under the test's cgroup.
    pub(crate) fn parent(tag: &str) -> (PathBuf, Dir) {
        let p = own_cgroup().join(format!("bingsu-cmd-test-{tag}-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o755).create(&p).unwrap();
        let dir = Dir::new(File::open(&p).unwrap());
        (p, dir)
    }

    /// Whether this run is the privileged cell; atomic-path tests return
    /// at once elsewhere (CI checks each one PASSED in that cell).
    pub(crate) fn privileged() -> bool {
        #[expect(clippy::disallowed_methods, reason = "test-only cell name")]
        let cell = std::env::var("BINGSU_CGROUP_CELL");
        cell.is_ok_and(|c| c == "priv")
    }

    /// Unit folders under a session parent.
    pub(crate) fn units(parent: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| cgroup::is_unit_name(n.as_bytes()))
            .collect();
        v.sort();
        v
    }

    pub(crate) fn alive(pid: i32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
            !s.rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z')
        })
    }

    /// The cell this run is in: `BINGSU_CGROUP_CELL=priv|plain`.
    pub(crate) fn cell() -> String {
        #[expect(clippy::disallowed_methods, reason = "test-only cell name")]
        std::env::var("BINGSU_CGROUP_CELL").expect("BINGSU_CGROUP_CELL=priv|plain")
    }

    fn release() -> Vec<u8> {
        std::fs::read("/proc/sys/kernel/osrelease").unwrap()
    }

    fn who(session: &str) -> (Vec<u8>, (u64, u64), u32) {
        use std::os::unix::fs::MetadataExt;
        let root = std::fs::metadata(std::env::temp_dir()).unwrap();
        (
            session.as_bytes().to_vec(),
            (root.dev(), root.ino()),
            super::super::sys::current_uid(),
        )
    }

    fn open_at(mount: &[u8], release: &[u8], text: &[u8], session: &str) -> Option<Dir> {
        let (session, runtime, me) = who(session);
        fs::open_session_at(
            mount,
            release,
            text,
            &fs::Who {
                session: &session,
                runtime,
                me,
                pid: std::process::id(),
            },
        )
    }

    fn parent_path(session: &str) -> PathBuf {
        let (session, runtime, _) = who(session);
        own_cgroup().join(cgroup::parent_name(&session, runtime))
    }

    // 특권 셀은 원자 경로, 기본 셀은 최선 노력(X-04 음성 대조: 하위 폴더 생성 EROFS). 두 번째 판정은 같은
    // 부모 폴더를 다시 연다. 이것을 실패시키는 것: 부모를 열지 못하면 자기 cgroup 폴더를 대신 쓰는 것(기본
    // 셀에서 Some), open_session_at의 커널 조건을 지우는 것(5.13 입력이 Some).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_capability_matches_the_cell() {
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let session = format!("cell-{}", std::process::id());
        let release = release();
        let first = open_at(b"/sys/fs/cgroup", &release, &text, &session);
        match cell().as_str() {
            "plain" => assert!(first.is_none()),
            "priv" => {
                use std::os::unix::fs::MetadataExt;
                let a = first.expect("atomic path in the privileged cell");
                let b = open_at(b"/sys/fs/cgroup", &release, &text, &session).unwrap();
                assert_eq!(
                    a.folder.metadata().unwrap().ino(),
                    b.folder.metadata().unwrap().ino()
                );
                assert!(open_at(b"/sys/fs/cgroup", b"5.13.19\n", &text, &session).is_none());
                std::fs::remove_dir(parent_path(&session)).unwrap();
            }
            other => panic!("unknown cell {other}"),
        }
    }

    // cgroup v2가 아닌 곳(일반 파일 시스템)은 원자 경로가 아니다. 이것을 실패시키는 것: 자기 cgroup 폴더의
    // fstatfs CGROUP2_SUPER_MAGIC 비교를 지우는 것(임시 폴더 아래에 부모를 만들고 Some).
    #[test]
    fn test_capability_needs_cgroup2() {
        let root = std::env::temp_dir().join(format!("bingsu-cg-v1-{}", std::process::id()));
        std::fs::create_dir_all(root.join("user.slice")).unwrap();
        std::fs::write(
            root.join("user.slice/cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        let mount = root.as_os_str().as_encoded_bytes().to_vec();
        let got = open_at(&mount, b"6.8.0", b"0::/user.slice\n", "s");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(got.is_none());
    }

    // 남이 만든 부모 폴더는 쓰지 않는다. 이것을 실패시키는 것: 소유자 비교를 지우는 것.
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_capability_refuses_a_foreign_parent() {
        if !privileged() {
            return;
        }
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let session = format!("foreign-{}", std::process::id());
        let path = parent_path(&session);
        std::fs::create_dir(&path).unwrap();
        std::os::unix::fs::chown(&path, Some(4242), None).unwrap();
        let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
        std::fs::remove_dir(&path).unwrap();
        assert!(got.is_none());
    }

    // `0::` 경로가 이 프로세스를 담지 않은 cgroup을 가리키면(namespace를 만들고 다시 마운트하지 않은 경우의
    // 모양) 원자 경로가 아니다. 이것을 실패시키는 것: 자기 cgroup의 cgroup.procs 확인을 지우는 것(남의 cgroup
    // 아래에 부모를 만들고 Some).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_capability_needs_its_own_cgroup() {
        if !privileged() {
            return;
        }
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let own = cgroup::own_path(&text).unwrap();
        let other = format!("bingsu-other-{}", std::process::id());
        let fake = format!(
            "0::{}/{other}\n",
            String::from_utf8_lossy(own).trim_end_matches('/')
        );
        std::fs::create_dir(own_cgroup().join(&other)).unwrap();
        let session = format!("other-{}", std::process::id());
        let got = open_at(b"/sys/fs/cgroup", &release(), fake.as_bytes(), &session);
        let made = own_cgroup()
            .join(&other)
            .join(cgroup::parent_name(&who(&session).0, who(&session).1));
        let _ = std::fs::remove_dir(&made);
        std::fs::remove_dir(own_cgroup().join(&other)).unwrap();
        assert!(got.is_none());
    }

    // GC의 자기 cgroup도 회차와 같이 이 프로세스를 담은 cgroup이어야 한다(m6-C4a7). 양성 대조: 실제
    // `/proc/self/cgroup`은 연다. 이것을 실패시키는 것: GC가 cgroup.procs 확인 없이 폴더를 여는 것(남의
    // cgroup에서 빈 부모를 지울 수 있음).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_gc_own_cgroup_needs_its_own_cgroup() {
        if !privileged() {
            return;
        }
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        assert!(fs::open_own_member_at(b"/sys/fs/cgroup", &text).is_some());
        let own = cgroup::own_path(&text).unwrap();
        let other = format!("bingsu-gc-other-{}", std::process::id());
        let fake = format!(
            "0::{}/{other}\n",
            String::from_utf8_lossy(own).trim_end_matches('/')
        );
        std::fs::create_dir(own_cgroup().join(&other)).unwrap();
        let got = fs::open_own_member_at(b"/sys/fs/cgroup", fake.as_bytes());
        std::fs::remove_dir(own_cgroup().join(&other)).unwrap();
        assert!(got.is_none());
    }

    // 실제 cgroup namespace를 만들고 다시 마운트하지 않은 프로세스(자식 시험)는 원자 경로를 고르지 않는다.
    // 이것을 실패시키는 것: 위와 같은 cgroup.procs 확인 삭제(namespace 뿌리로 보이는 마운트 뿌리 아래에 부모를
    // 만들고 Some).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_capability_refuses_an_unremounted_namespace() {
        if !privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let inner = own_cgroup().join(format!("bingsu-ns-{}", std::process::id()));
        std::fs::create_dir(&inner).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::command_cgroup::cell::unremounted_namespace_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BINGSU_NS_CGROUP", &inner)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let _ = std::fs::remove_dir(&inner);
        assert!(
            text.contains("NS-CHILD atomic=false"),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Child of the test above: moves itself into `BINGSU_NS_CGROUP`, makes a
    /// cgroup namespace there without remounting `/sys/fs/cgroup`, and
    /// reports the capability.
    #[test]
    #[ignore = "child: an unremounted cgroup namespace"]
    fn unremounted_namespace_child() {
        #[expect(clippy::disallowed_methods, reason = "test-only child input")]
        let Ok(inner) = std::env::var("BINGSU_NS_CGROUP") else {
            return;
        };
        std::fs::write(
            format!("{inner}/cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        // SAFETY: plain namespace call on this test thread.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWCGROUP) }, 0);
        // Read from this thread: the path is relative to its new namespace.
        let text = std::fs::read("/proc/thread-self/cgroup").unwrap();
        let session = format!("ns-{}", std::process::id());
        let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
        if got.is_some() {
            let (s, r, _) = who(&session);
            let line = String::from_utf8_lossy(&text).into_owned();
            let rel = line
                .trim()
                .trim_start_matches("0::")
                .trim_end_matches('/')
                .to_owned();
            let _ = std::fs::remove_dir(format!(
                "/sys/fs/cgroup{rel}/{}",
                cgroup::parent_name(&s, r)
            ));
        }
        // Back out of the folder so the parent test can remove it.
        let _ = std::fs::write(
            "/sys/fs/cgroup/cgroup.procs",
            std::process::id().to_string(),
        );
        println!("NS-CHILD atomic={}", got.is_some());
    }

    // 부모 자리에만 일반 폴더를 bind mount하면 원자 경로가 아니다. 같은 mount면 같은 cgroup v2이므로 부모 fd의
    // mount id 비교가 이것을 맡는다. 이것을 실패시키는 것: 부모 fd의 mount id 비교를 지우는 것.
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_capability_refuses_a_bind_mounted_parent() {
        if !privileged() {
            return;
        }
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let session = format!("bind-{}", std::process::id());
        let path = parent_path(&session);
        let plain = std::env::temp_dir().join(format!("bingsu-bind-{}", std::process::id()));
        std::fs::create_dir(&plain).unwrap();
        std::fs::create_dir(&path).unwrap();
        let c =
            |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: NUL-terminated paths; a bind mount in this container only.
        let rc = unsafe {
            libc::mount(
                c(&plain).as_ptr(),
                c(&path).as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
        let ok = got.is_none();
        drop(got);
        // SAFETY: the mount made above.
        unsafe { libc::umount2(c(&path).as_ptr(), libc::MNT_DETACH) };
        std::fs::remove_dir(&path).unwrap();
        std::fs::remove_dir(&plain).unwrap();
        assert!(ok);
    }

    fn bind(from: &std::path::Path, onto: &std::path::Path) {
        let c =
            |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: NUL-terminated paths; a bind mount in this container only.
        let rc = unsafe {
            libc::mount(
                c(from).as_ptr(),
                c(onto).as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    }

    fn unbind(at: &std::path::Path) {
        let c = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the mount made by bind().
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }

    // 다른 세션의 실제 cgroup v2 부모를 내 부모 이름 자리에 bind mount하면(소유자·cgroup2 검사는 통과) 자기
    // cgroup 폴더와 mount id가 달라 원자 경로가 아니다. 이것을 실패시키는 것: 부모 fd의 mount id 비교를 지우는 것.
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_capability_refuses_a_foreign_parent_mounted_over_its_name() {
        if !privileged() {
            return;
        }
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let session = format!("over-{}", std::process::id());
        let mine = parent_path(&session);
        let other = parent_path(&format!("other-session-{}", std::process::id()));
        std::fs::create_dir(&mine).unwrap();
        std::fs::create_dir(&other).unwrap();
        bind(&other, &mine);
        let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
        let refused = got.is_none();
        drop(got);
        unbind(&mine);
        std::fs::remove_dir(&mine).unwrap();
        std::fs::remove_dir(&other).unwrap();
        assert!(refused);
    }

    // 부모 아래 단위 이름 자리에 다른 cgroup을 bind mount해도 회수는 그 cgroup을 kill하거나 지우지 않는다. 이것을
    // 실패시키는 것: Fs::open의 mount id 비교를 지우는 것(남의 cgroup의 프로세스가 죽음).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_reclaim_never_enters_a_cgroup_mounted_below() {
        if !privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (p, mut dir) = parent("below");
        let victim = own_cgroup().join(format!("bingsu-victim-{}", std::process::id()));
        std::fs::create_dir(&victim).unwrap();
        let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
        std::fs::write(victim.join("cgroup.procs"), sleep.id().to_string()).unwrap();
        let unit = p.join(cgroup::unit_name(9));
        std::fs::create_dir(&unit).unwrap();
        bind(&victim, &unit);
        let r = reclaim(&mut Fs, &mut dir);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let survived = alive(sleep.id() as i32);
        unbind(&unit);
        let _ = sleep.kill();
        let _ = sleep.wait();
        let _ = std::fs::remove_dir(&unit);
        let _ = std::fs::remove_dir(&p);
        while std::fs::remove_dir(&victim).is_err() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(survived, "{r:?}");
    }

    // 부모 아래 단위 이름 자리에 다른 cgroup 폴더를 bind mount하면, 그 폴더는 부모와 mount가 달라 감독의 단위로
    // 받지 않는다(mkdirat와 열기 사이에 bind하는 경쟁을 막는 비교; 경쟁 창 없이 비교 함수를 직접 본다). 이것을
    // 실패시키는 것: on_parent_mount의 비교를 지우는 것.
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_a_folder_bound_below_the_parent_is_not_its_child() {
        if !privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (p, _dir) = parent("unitbind");
        let parent_fd = File::open(&p).unwrap();
        let own = p.join(cgroup::unit_name(1));
        std::fs::create_dir(&own).unwrap();
        let mine = File::open(&own).unwrap();
        assert!(fs::on_parent_mount(&parent_fd, &mine).is_some());
        let victim = own_cgroup().join(format!("bingsu-unitvictim-{}", std::process::id()));
        std::fs::create_dir(&victim).unwrap();
        let unit = p.join(cgroup::unit_name(9));
        std::fs::create_dir(&unit).unwrap();
        bind(&victim, &unit);
        let bound = File::open(&unit).unwrap();
        let refused = fs::on_parent_mount(&parent_fd, &bound).is_none();
        drop(bound);
        unbind(&unit);
        drop(mine);
        let _ = std::fs::remove_dir(&unit);
        let _ = std::fs::remove_dir(&own);
        let _ = std::fs::remove_dir(&victim);
        let _ = std::fs::remove_dir(&p);
        assert!(refused);
    }

    // 단위 폴더의 cgroup.kill 자리에 다른 cgroup의 cgroup.kill을 파일 bind mount하면, 그 파일은 단위 폴더와
    // mount id가 달라 열기를 거부한다. 거부하지 않으면 그 쓰기가 남의 cgroup을 죽인다. 이것을 실패시키는 것:
    // kill_file의 mount id 비교를 지우는 것(victim의 sleep이 죽음).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_kill_file_refuses_a_file_bind_mounted_over_it() {
        if !privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (p, _dir) = parent("killbind");
        let victim = own_cgroup().join(format!("bingsu-killvictim-{}", std::process::id()));
        std::fs::create_dir(&victim).unwrap();
        let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
        std::fs::write(victim.join("cgroup.procs"), sleep.id().to_string()).unwrap();
        let unit = p.join(cgroup::unit_name(9));
        std::fs::create_dir(&unit).unwrap();
        // Unbound, the unit's own cgroup.kill opens.
        let folder = File::open(&unit).unwrap();
        assert!(fs::kill_file(&folder).is_ok());
        bind(&victim.join("cgroup.kill"), &unit.join("cgroup.kill"));
        let refused = fs::kill_file(&folder).map(|kill| fs::write_kill(&kill));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let survived = alive(sleep.id() as i32);
        unbind(&unit.join("cgroup.kill"));
        let _ = sleep.kill();
        let _ = sleep.wait();
        drop(folder);
        let _ = std::fs::remove_dir(&unit);
        let _ = std::fs::remove_dir(&p);
        while std::fs::remove_dir(&victim).is_err() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(refused.is_err() && survived, "{refused:?} {survived}");
    }

    // 실제 cgroupfs에서 kill → populated 0 → 후위 rmdir. 대상 프로세스는 단위 아래 깊이 2 폴더에 있다.
    // 이것을 실패시키는 것: Fs::kill이 cgroup.kill을 쓰지 않는 것(populated가 1로 남아 단위가 남음).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn fs_reclaim_kills_and_removes_a_nested_tree() {
        if !privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (p, mut dir) = parent("nested");
        let unit = p.join(cgroup::unit_name(1));
        std::fs::create_dir_all(unit.join("a/b")).unwrap();
        std::fs::create_dir_all(unit.join("c")).unwrap();
        let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
        std::fs::write(unit.join("a/b/cgroup.procs"), sleep.id().to_string()).unwrap();
        let r = reclaim(&mut Fs, &mut dir);
        let _ = sleep.wait();
        assert!(!alive(sleep.id() as i32));
        assert_eq!((r.removed, r.stuck, r.failed), (1, 0, 0), "{r:?}");
        assert!(!unit.exists());
        std::fs::remove_dir(&p).unwrap();
    }
}
