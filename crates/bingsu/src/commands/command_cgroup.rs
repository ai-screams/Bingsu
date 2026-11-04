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
    /// Folders opened: unit folders and subtree folders.
    pub visits: usize,
    /// Unit folders removed.
    pub removed: usize,
    /// Unit folders still populated after the kill: left for later.
    pub stuck: usize,
    /// Unit folders kept because their subtree goes below depth 4.
    pub deep: usize,
    /// The visit window or the time ran out with entries left.
    pub capped: bool,
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
        out
    }
}

/// One reclaim of the session parent `parent`.
pub(crate) fn reclaim<T: Tree>(t: &mut T, parent: &mut T::Dir) -> Reclaim {
    let start = t.now();
    let end = start.saturating_add(RECLAIM_NS);
    let mut r = Reclaim::default();
    let names = match t.subdirs(parent, RECLAIM_VISITS + 1) {
        Ok(names) => names,
        Err(_) => {
            r.failed += 1;
            r.elapsed_ns = t.now().saturating_sub(start);
            return r;
        }
    };
    // Every unit is killed before any is checked, so their deaths overlap.
    let mut units = Vec::new();
    for name in names.into_iter().filter(|n| cgroup::is_unit_name(n)) {
        if r.visits >= RECLAIM_VISITS || t.now() >= end {
            r.capped = true;
            break;
        }
        let Ok(dir) = t.open(parent, &name) else {
            r.failed += 1;
            continue;
        };
        r.visits += 1;
        if t.kill(&dir).is_err() {
            r.failed += 1;
        }
        units.push((name, dir));
    }
    for (name, mut dir) in units {
        if t.now() >= end {
            r.capped = true;
            break;
        }
        let mut empty = t.populated(&mut dir, 0).ok().flatten() == Some(false);
        for _ in 0..POPULATED_RETRIES {
            if empty || t.now() >= end {
                break;
            }
            empty = t.populated(&mut dir, POPULATED_WAIT_MS).ok().flatten() == Some(false);
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
        match t.rmdir(parent, &name) {
            Ok(()) => r.removed += 1,
            Err(_) => r.failed += 1,
        }
    }
    r.elapsed_ns = t.now().saturating_sub(start);
    r
}

/// Removes every folder under `dir` in post-order; `depth` is the level of
/// its children. True when `dir` is left without children.
fn clear<T: Tree>(
    t: &mut T,
    dir: &mut T::Dir,
    depth: usize,
    end: u64,
    r: &mut Reclaim,
    deep: &mut bool,
) -> bool {
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
        if r.visits >= RECLAIM_VISITS || t.now() >= end {
            r.capped = true;
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
        } else if t.rmdir(dir, &name).is_err() {
            r.failed += 1;
            all = false;
        }
    }
    all
}

/// The cgroup file system itself (Linux).
#[cfg(target_os = "linux")]
pub(crate) mod fs {
    use super::super::sys;
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
    /// SIGKILL, forks in progress included.
    pub(crate) fn kill_file(folder: &File) -> io::Result<File> {
        open_at(folder, b"cgroup.kill", libc::O_WRONLY)
    }

    pub(crate) fn write_kill(kill: &File) -> io::Result<()> {
        match sys::write_fd(kill.as_raw_fd(), b"1") {
            sys::WriteOutcome::Done => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
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
            open_at(&dir.folder, name, libc::O_RDONLY | libc::O_DIRECTORY).map(Dir::new)
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
            Ok(bingsu_core::command::cgroup::populated(&buf[..n]))
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
        fn populated(&mut self, dir: &mut Vec<u8>, _wait_ms: i32) -> io::Result<Option<bool>> {
            self.step();
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
        // More units than the window: the kill pass stops at 64.
        let mut many = Fake::default();
        for i in 0..70 {
            many.add(&format!("p/{}", unit(i)));
        }
        let r = reclaim(&mut many, &mut parent);
        assert_eq!(
            (r.visits, r.removed),
            (RECLAIM_VISITS, RECLAIM_VISITS),
            "{r:?}"
        );
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
}

/// On a delegated cgroup v2 tree (the privileged container cell): run with
/// `--ignored`. Each test makes its own parent under the test's cgroup.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod cell {
    use super::fs::{Dir, Fs};
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

    fn alive(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
            !s.rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z')
        })
    }

    // 실제 cgroupfs에서 kill → populated 0 → 후위 rmdir. 대상 프로세스는 단위 아래 깊이 2 폴더에 있다.
    // 이것을 실패시키는 것: Fs::kill이 cgroup.kill을 쓰지 않는 것(populated가 1로 남아 단위가 남음).
    #[test]
    #[ignore = "needs a delegated cgroup v2 tree (privileged cell)"]
    fn fs_reclaim_kills_and_removes_a_nested_tree() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (p, mut dir) = parent("nested");
        let unit = p.join(cgroup::unit_name(1));
        std::fs::create_dir_all(unit.join("a/b")).unwrap();
        std::fs::create_dir_all(unit.join("c")).unwrap();
        let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
        std::fs::write(unit.join("a/b/cgroup.procs"), sleep.id().to_string()).unwrap();
        let r = reclaim(&mut Fs, &mut dir);
        let _ = sleep.wait();
        assert!(!alive(sleep.id()));
        assert_eq!((r.removed, r.stuck, r.failed), (1, 0, 0), "{r:?}");
        assert!(!unit.exists());
        std::fs::remove_dir(&p).unwrap();
    }
}
