//! N4 pre-filter TCB. Only `prepare` is callable from the prompt adapter, once
//! immediately before confinement. `Prepared::respond` has no path effects:
//! pending core opens/inspections consume already-held fds and cached facts.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use bingsu_core::front::staged::{self, Effect, FdFacts, Observation, Operation, Slot, Step};
use bingsu_core::fs_trust::{self, AclFacts, Facts};
use bingsu_core::snapshot::{Clock, ClockError};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

struct Held {
    fd: OwnedFd,
    facts: FdFacts,
}
struct Prepared {
    plan: staged::ReadPlan,
    step: Step,
    slots: [Option<Held>; 3],
    files: [Option<Held>; 3],
    sources: Option<staged::Prefetch>,
    clock: ClockPins,
}

/// The closure owns every descriptor, including clock evidence. Dropping it on
/// a refused filter closes them; unwinding has the same ownership discipline.
pub fn prepare(raw: &[&[u8]]) -> impl FnOnce() -> Vec<u8> + use<> {
    let p = prepare_state(raw);
    move || p.respond()
}

fn prepare_state(raw: &[&[u8]]) -> Prepared {
    prepare_with_clock(raw, ClockPins::prepare)
}

fn prepare_with_clock(raw: &[&[u8]], clock: fn() -> ClockPins) -> Prepared {
    let mut p = Prepared {
        plan: staged::prepare(raw),
        step: Step::Done(staged::Observed::default()),
        slots: [None, None, None],
        files: [None, None, None],
        sources: None,
        clock: ClockPins::default(),
    };
    let mut previous = None;
    loop {
        let step = staged::next(&mut p.plan, previous.take());
        let Step::Read(effect) = step else {
            p.step = step;
            break;
        };
        if let Some(sources) = p.plan.prefetch(&effect) {
            if let Some(parent) = &p.slots[sources.parent().index()] {
                for (i, name) in sources.names().into_iter().enumerate() {
                    p.files[i] = CString::new(name)
                        .ok()
                        .and_then(|name| open(parent.fd.as_raw_fd(), &name, DATA_FLAGS).ok())
                        .and_then(|fd| held(fd).ok())
                        .filter(|h| sources.accepts(i, h.facts));
                }
            }
            p.sources = Some(sources);
            p.step = Step::Read(effect);
            break;
        }
        previous = Some(p.before(&effect, clock));
    }
    p
}

impl Prepared {
    fn before(&mut self, effect: &Effect, clock: fn() -> ClockPins) -> Observation {
        match effect.operation() {
            // SAFETY: getuid has no preconditions and cannot fail.
            Operation::Uid => Observation::Uid(unsafe { libc::getuid() }),
            Operation::Clock => {
                self.clock = clock();
                Observation::Clock(self.clock.observe().ok())
            }
            Operation::OpenDirectory { parent, name, into } => {
                let base = match parent {
                    Some(slot) => match self.slots[slot.index()].as_ref() {
                        Some(h) => h.fd.as_raw_fd(),
                        None => return Observation::Failed,
                    },
                    None => libc::AT_FDCWD,
                };
                let h = CString::new(name.as_slice())
                    .ok()
                    .and_then(|name| open(base, &name, DIRECTORY_FLAGS).ok())
                    .and_then(|fd| held(fd).ok());
                if self.slots[into.index()].is_some() {
                    return Observation::Failed;
                }
                self.slots[into.index()] = h;
                if self.slots[into.index()].is_some() {
                    Observation::Opened
                } else {
                    Observation::Failed
                }
            }
            Operation::Inspect(slot) => self.inspect(*slot),
            Operation::Close(slot) => self.close(*slot),
            // No snapshot contents are consumed in the pre-filter stage.
            _ => Observation::Failed,
        }
    }
    fn inspect(&self, slot: Slot) -> Observation {
        self.slots[slot.index()]
            .as_ref()
            .map_or(Observation::Failed, |h| Observation::Facts(h.facts))
    }
    fn close(&mut self, slot: Slot) -> Observation {
        // OwnedFd closes once, without retrying a potentially recycled fd.
        if self.slots[slot.index()].take().is_some() {
            Observation::Closed
        } else {
            Observation::Failed
        }
    }
    fn after(&mut self, effect: &Effect) -> Observation {
        match effect.operation() {
            Operation::OpenFile { into, .. } => {
                if self.slots[into.index()].is_some() {
                    return Observation::Failed;
                }
                let Some(i) = self.sources.as_ref().and_then(|s| s.index(effect)) else {
                    return Observation::Failed;
                };
                self.slots[into.index()] = self.files[i].take();
                if self.slots[into.index()].is_some() {
                    Observation::Opened
                } else {
                    Observation::Failed
                }
            }
            Operation::Inspect(slot) => self.inspect(*slot),
            Operation::Read { slot, len } => {
                let Some(h) = self.slots[slot.index()].as_ref() else {
                    return Observation::Failed;
                };
                // The continuation alone determines sequential offsets and lengths.
                let mut bytes = vec![0; *len];
                // SAFETY: held descriptor and writable initialized buffer of len bytes.
                let n =
                    unsafe { libc::read(h.fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
                match usize::try_from(n) {
                    Ok(n) if n <= bytes.len() => {
                        bytes.truncate(n);
                        Observation::Bytes(bytes)
                    }
                    _ => Observation::Failed,
                }
            }
            Operation::Close(slot) => self.close(*slot),
            Operation::Clock => Observation::Clock(self.clock.observe().ok()),
            // No UID query, directory open, stat, ACL or pathname call after the filter.
            _ => Observation::Failed,
        }
    }
    fn respond(mut self) -> Vec<u8> {
        loop {
            match self.step {
                Step::Done(observed) => {
                    return staged::finish(
                        self.plan,
                        observed,
                        bingsu_core::color::palette::Mode::Dark,
                    )
                    .record;
                }
                Step::Read(_) => {
                    // Move the effect out before mutably borrowing the executor.
                    let Step::Read(effect) =
                        std::mem::replace(&mut self.step, Step::Done(staged::Observed::default()))
                    else {
                        unreachable!()
                    };
                    let observation = self.after(&effect);
                    self.step = staged::next(&mut self.plan, Some(observation));
                }
            }
        }
    }
}

const DATA_FLAGS: i32 =
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY;
#[cfg(target_os = "linux")]
const DIRECTORY_FLAGS: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
#[cfg(target_os = "macos")]
const DIRECTORY_FLAGS: i32 =
    libc::O_SEARCH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

fn open(base: i32, name: &CStr, flags: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: base is held or AT_FDCWD for '/', name is terminated, no O_CREAT.
    let fd = unsafe { libc::openat(base, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat returned unique ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[allow(
    clippy::unnecessary_cast,
    clippy::useless_conversion,
    reason = "stat fields differ across Linux libc and macOS"
)]
fn held(fd: OwnedFd) -> std::io::Result<Held> {
    // SAFETY: zeroed structs are valid output storage.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: zeroed structs are valid output storage.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: owned descriptor and valid output pointers.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: owned descriptor and valid output pointer.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut fs) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    let (ownership, local) = (
        true,
        fs_trust::linux_fs_is_local(fs.f_type as u64 & 0xffff_ffff),
    );
    #[cfg(target_os = "macos")]
    let (ownership, local) = (
        fs_trust::macos_ownership_enforced(fs.f_flags),
        fs_trust::macos_fs_is_local(fs.f_flags),
    );
    let facts = FdFacts {
        entry: Facts {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            uid: st.st_uid,
            gid: st.st_gid,
            mode: u32::from(st.st_mode),
            ownership: Some(ownership),
            acl: acl(fd.as_raw_fd()),
        },
        local: Some(local),
        nlink: st.st_nlink as u64,
        size: u64::try_from(st.st_size).map_err(|_| std::io::Error::other("negative file size"))?,
    };
    Ok(Held { fd, facts })
}

#[derive(Default)]
struct ClockPins {
    identity: Option<Clock>,
    // Keep the kernel observations alive across the filter and both clock samples.
    #[cfg(target_os = "linux")]
    fds: Vec<OwnedFd>,
}
impl ClockPins {
    fn observe(&self) -> Result<Clock, ClockError> {
        let mut clock = self.identity.ok_or(ClockError::Boot)?;
        clock.now = crate::prompt_io::monotonic_ns()?;
        Ok(clock)
    }
    #[cfg(target_os = "macos")]
    fn prepare() -> Self {
        Self {
            identity: crate::prompt_io::observe_clock().ok(),
        }
    }
    #[cfg(target_os = "linux")]
    fn prepare() -> Self {
        let mut p = Self::default();
        p.identity = p.linux().ok();
        p
    }
    #[cfg(target_os = "linux")]
    fn kernel(&mut self, base: i32, name: &CStr, flags: i32, magic: u64) -> Result<FdFacts, i32> {
        let fd =
            open(base, name, flags | libc::O_CLOEXEC).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        // SAFETY: writable statfs output storage.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: live descriptor and writable output storage.
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut fs) } != 0 {
            return Err(libc::EIO);
        }
        let h = held(fd).map_err(|_| libc::EIO)?;
        let facts = h.facts;
        #[allow(clippy::unnecessary_cast, reason = "glibc/musl fsword types differ")]
        let actual = fs.f_type as u64 & 0xffff_ffff;
        if !kernel_entry(facts, flags & libc::O_DIRECTORY != 0, actual, magic) {
            return Err(libc::EIO);
        }
        self.fds.push(h.fd);
        Ok(facts)
    }
    #[cfg(target_os = "linux")]
    fn last(&self) -> i32 {
        self.fds.last().expect("kernel retained fd").as_raw_fd()
    }
    #[cfg(target_os = "linux")]
    fn linux(&mut self) -> Result<Clock, ClockError> {
        let dir = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY;
        let file = libc::O_RDONLY | libc::O_NOFOLLOW;
        let procfs = 0x9fa0;
        let root =
            held(open(libc::AT_FDCWD, c"/", DIRECTORY_FLAGS).map_err(|_| ClockError::Domain)?)
                .map_err(|_| ClockError::Domain)?;
        self.kernel(root.fd.as_raw_fd(), c"proc", dir, procfs)
            .map_err(|_| ClockError::Domain)?;
        let proc = self.last();
        // /proc/self is a symlink. Its numeric spelling identifies only this
        // process, so the walk never follows it (the only follows are nsfs below).
        // SAFETY: getpid has no preconditions and runs before the filter.
        let pid =
            CString::new(unsafe { libc::getpid() }.to_string()).map_err(|_| ClockError::Domain)?;
        self.kernel(proc, &pid, dir, procfs)
            .map_err(|_| ClockError::Domain)?;
        let process = self.last();
        self.kernel(process, c"ns", dir, procfs)
            .map_err(|_| ClockError::Domain)?;
        let ns = self.last();
        let time = self.kernel(ns, c"time", libc::O_RDONLY, 0x6e736673);
        let child = self.kernel(ns, c"time_for_children", libc::O_RDONLY, 0x6e736673);
        let offsets = self.kernel(process, c"timens_offsets", file, procfs);
        let domain = time_domain(time, child, offsets)?;
        let mut base = proc;
        for name in [c"sys", c"kernel", c"random"] {
            self.kernel(base, name, dir, procfs)
                .map_err(|_| ClockError::Boot)?;
            base = self.last();
        }
        let facts = self
            .kernel(base, c"boot_id", file, procfs)
            .map_err(|_| ClockError::Boot)?;
        if !boot_file(facts) {
            return Err(ClockError::Boot);
        }
        let mut bytes = [0; 38];
        let mut n = 0;
        while n < bytes.len() {
            // SAFETY: retained boot fd and initialized writable suffix.
            let got =
                unsafe { libc::read(self.last(), bytes[n..].as_mut_ptr().cast(), bytes.len() - n) };
            let got = usize::try_from(got).map_err(|_| ClockError::Boot)?;
            if got == 0 {
                break;
            }
            n += got;
        }
        Ok(Clock {
            boot: boot_bytes(&bytes[..n])?,
            domain,
            now: 0,
            kind: 1,
            resume: 0,
        })
    }
}

// The native observations are judged separately so error/absence and filesystem
// substitutions can be exercised even when the host sandbox denies boot identity.
#[cfg(any(test, target_os = "linux"))]
fn kernel_entry(f: FdFacts, directory: bool, actual: u64, expected: u64) -> bool {
    let kind = if directory { 0o040000 } else { 0o100000 };
    actual == expected
        && f.entry.mode & 0o170000 == kind
        && matches!(
            f.entry.acl,
            AclFacts::None | AclFacts::DenyOnly | AclFacts::PosixExtended
        )
}
#[cfg(any(test, target_os = "linux"))]
fn time_domain(
    time: Result<FdFacts, i32>,
    child: Result<FdFacts, i32>,
    offsets: Result<FdFacts, i32>,
) -> Result<[u8; 16], ClockError> {
    let missing = [
        time == Err(libc::ENOENT),
        child == Err(libc::ENOENT),
        offsets == Err(libc::ENOENT),
    ];
    match time {
        Ok(f) => {
            if child.is_err() || offsets.is_err() {
                return Err(ClockError::Domain);
            }
            bingsu_core::snapshot::namespace_domain(Some((f.entry.dev, f.entry.ino)), true, missing)
        }
        Err(_) => bingsu_core::snapshot::namespace_domain(None, true, missing),
    }
}
#[cfg(any(test, target_os = "linux"))]
fn boot_file(f: FdFacts) -> bool {
    f.entry.uid == 0 && f.entry.mode & 0o170022 == 0o100000
}
#[cfg(any(test, target_os = "linux"))]
fn boot_bytes(bytes: &[u8]) -> Result<[u8; 16], ClockError> {
    if bytes.len() != 37 || bytes[36] != b'\n' {
        return Err(ClockError::Boot);
    }
    crate::prompt_io::uuid(&bytes[..36])
}

#[cfg(target_os = "macos")]
mod macos_acl {
    unsafe extern "C" {
        pub fn acl_get_entry(
            acl: *mut libc::c_void,
            id: libc::c_int,
            e: *mut *mut libc::c_void,
        ) -> libc::c_int;
        pub fn acl_get_tag_type(e: *mut libc::c_void, t: *mut libc::c_int) -> libc::c_int;
        pub fn acl_get_permset(e: *mut libc::c_void, p: *mut *mut libc::c_void) -> libc::c_int;
        pub fn acl_get_perm_np(p: *mut libc::c_void, perm: libc::c_int) -> libc::c_int;
        pub fn acl_free(o: *mut libc::c_void) -> libc::c_int;
    }
    // <sys/acl.h>, verified against the SDK on 2026-10-04.
    pub const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    pub const ACL_FIRST_ENTRY: libc::c_int = 0;
    pub const ACL_NEXT_ENTRY: libc::c_int = -1;
    pub const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    pub const ACL_EXTENDED_DENY: libc::c_int = 2;
    pub const WRITE_CLASS: [libc::c_int; 8] = [
        1 << 2,
        1 << 4,
        1 << 5,
        1 << 6,
        1 << 8,
        1 << 10,
        1 << 12,
        1 << 13,
    ];
}

/// Folds and frees an ACL returned by `acl_get_link_np` or `acl_get_fd_np`.
#[cfg(target_os = "macos")]
fn acl_entries(acl: *mut libc::c_void) -> AclFacts {
    use macos_acl::*;
    if acl.is_null() {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return if e == libc::ENOENT || e == 0 {
            AclFacts::None
        } else {
            AclFacts::Unknown
        };
    }
    let mut entries: Vec<Result<fs_trust::AclEntry, ()>> = Vec::new();
    let mut id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: returns this thread's errno pointer.
        let errno = unsafe { libc::__error() };
        // SAFETY: this thread owns the writable errno slot.
        unsafe { *errno = 0 };
        // SAFETY: `acl` is a live ACL; `entry` receives a pointer into it.
        if unsafe { acl_get_entry(acl, id, &mut entry) } != 0 {
            // EINVAL means "no more entries" (acl_get_entry(3)); any other
            // error leaves the ACL unread.
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
                entries.push(Err(()));
            }
            break;
        }
        id = ACL_NEXT_ENTRY;
        let mut tag = 0;
        let mut perms = std::ptr::null_mut();
        // SAFETY: `entry` is valid until the ACL is freed.
        let t = unsafe { acl_get_tag_type(entry, &mut tag) };
        // SAFETY: as above.
        let q = unsafe { acl_get_permset(entry, &mut perms) };
        let item = if t != 0 || q != 0 {
            Err(())
        } else if tag == ACL_EXTENDED_ALLOW {
            let mut writes = Ok(false);
            for &w in &WRITE_CLASS {
                // SAFETY: `perms` belongs to `entry`.
                match unsafe { acl_get_perm_np(perms, w) } {
                    1 => writes = writes.map(|_| true),
                    0 => {}
                    _ => writes = Err(()),
                }
            }
            writes.map(|writes| fs_trust::AclEntry::Allow { writes })
        } else if tag == ACL_EXTENDED_DENY {
            Ok(fs_trust::AclEntry::Deny)
        } else {
            Err(())
        };
        let failed = item.is_err();
        entries.push(item);
        if failed {
            break;
        }
    }
    let facts = fs_trust::fold_acl(entries);
    // SAFETY: `acl` was returned by acl_get_link_np and is freed once.
    unsafe { acl_free(acl) };
    facts
}

#[cfg(target_os = "macos")]
fn acl(fd: i32) -> AclFacts {
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, ty: libc::c_int) -> *mut libc::c_void;
    }
    // SAFETY: held descriptor, fixed extended ACL kind; returned object freed by acl_entries.
    acl_entries(unsafe { acl_get_fd_np(fd, macos_acl::ACL_TYPE_EXTENDED) })
}
#[cfg(target_os = "linux")]
fn acl(fd: i32) -> AclFacts {
    // SAFETY: held descriptor, terminated name; length-only query.
    let mut n = unsafe {
        libc::fgetxattr(
            fd,
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
        // R1's sole O_PATH ACL fallback names this owned descriptor, never argv.
        let Ok(path) = CString::new(format!("/proc/self/fd/{fd}")) else {
            return AclFacts::Unknown;
        };
        // SAFETY: terminated names; length-only query on the held fd alias.
        n = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
    }
    if n > 0 {
        return AclFacts::PosixExtended;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    if n == 0 || matches!(errno, Some(libc::ENODATA | libc::ENOTSUP)) {
        AclFacts::None
    } else {
        AclFacts::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::{
        color::palette::Mode,
        config::{
            compile::BUILTIN_TOML,
            source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
        },
        snapshot::{self, Identity, Marker, Snapshot},
    };
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
    };
    struct NoFiles;
    impl Resolver for NoFiles {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("no source files")
        }
    }
    // macOS sandbox may deny kern.bootsessionuuid. Only the tests inject the
    // boot identity; production always uses ClockPins::prepare.
    fn fixed_clock() -> ClockPins {
        let kind = if cfg!(target_os = "linux") { 1 } else { 2 };
        ClockPins {
            identity: Some(Clock {
                boot: [1; 16],
                domain: [0; 16],
                now: 0,
                kind,
                resume: 0,
            }),
            #[cfg(target_os = "linux")]
            fds: Vec::new(),
        }
    }
    fn released(fd: i32, old: FdFacts) {
        // Other tests may reuse this process-global number. A reused descriptor
        // is fine; only the exact unique fixture inode would indicate a leak.
        // SAFETY: writable output storage; fstat on a closed fd simply fails.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: writable output storage, no ownership transferred.
        let rc = unsafe { libc::fstat(fd, &mut st) };
        #[allow(clippy::unnecessary_cast, reason = "platform stat types")]
        if rc == 0 {
            assert_ne!(
                (st.st_dev as u64, st.st_ino as u64),
                (old.entry.dev, old.entry.ino)
            );
        }
    }
    struct Fx {
        base: PathBuf,
        store: PathBuf,
        args: Vec<Vec<u8>>,
        wire: Vec<u8>,
    }
    impl Fx {
        fn new() -> Self {
            static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let base = std::env::temp_dir().join(format!(
                "bingsu-n4-read-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&base).unwrap();
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
            let base = fs::canonicalize(base).unwrap();
            let m = fs::metadata(&base).unwrap();
            let mut store = base.clone();
            for part in snapshot::context_components(b"/c", b"/s").unwrap() {
                store.push(part);
                fs::create_dir(&store).unwrap();
                fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let clock = fixed_clock().observe().unwrap();
            let roots: Vec<_> = [
                BUILTIN_TOML,
                "icons='ascii'\n[layout.line2]\nleft=['char']\n",
            ]
            .iter()
            .enumerate()
            .map(|(i, text)| Opened {
                key: FileKey {
                    dev: 1,
                    ino: i as u64,
                },
                bytes: text.as_bytes().to_vec(),
                trust: Trust::Executable,
                display: vec![i as u8],
            })
            .collect();
            let config =
                bingsu_core::config::report::report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
                    .snapshot
                    .unwrap();
            let snapshot = Snapshot {
                id: Identity {
                    boot: clock.boot,
                    context: snapshot::context_crc(b"/c", b"/s").unwrap(),
                    epoch: [3; 16],
                    generation: 1,
                    source: [4; 4],
                },
                config,
                metadata: snapshot::encode_metadata(b"metadata stays unread").unwrap(),
            };
            let marker = Marker {
                id: snapshot.id,
                seq: 1,
                verified_at: clock.now,
                kind: clock.kind,
                domain: clock.domain,
                resume: clock.resume,
                invalid: false,
            };
            let wire = snapshot.encode(clock.kind, clock.resume).unwrap();
            for (name, bytes) in [
                ("snapshot", wire.as_slice()),
                ("last-good", wire.as_slice()),
                ("marker", marker.encode().as_slice()),
            ] {
                let path = store.join(name);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let mut args: Vec<_> = [
                "--ctx",
                "1",
                "--record",
                "B1",
                "--shell",
                "bash",
                "--width",
                "80",
                "--config-root=/c",
                "--state-root=/s",
            ]
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect();
            args.push(
                format!("--runtime-root={}:{}:{}", m.dev(), m.ino(), base.display()).into_bytes(),
            );
            Self {
                base,
                store,
                args,
                wire,
            }
        }
        fn prepared(&self) -> Prepared {
            prepare_with_clock(
                &self.args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                fixed_clock,
            )
        }
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    // 이것을 실패시키는 것: 사전 준비 중 내용 읽기, 셋 중 일부만 열기, 필터 뒤 경로 재열기.
    #[test]
    fn holds_all_sources_before_reading_and_survives_replacement() {
        let f = Fx::new();
        let p = f.prepared();
        let mut fds = Vec::new();
        for h in &p.files {
            let fd = h.as_ref().expect("all three checked files").fd.as_raw_fd();
            fds.push((fd, h.as_ref().unwrap().facts));
            // SAFETY: live descriptor; read-only test query before confinement.
            assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 0);
            // SAFETY: live descriptor and a no-argument fcntl query.
            assert_ne!(
                // SAFETY: live descriptor, no-argument query.
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            // SAFETY: held descriptor, read-only flag query.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert_ne!(flags & libc::O_NONBLOCK, 0);
            // SAFETY: live descriptor and no-argument fcntl query.
            assert_eq!(
                // SAFETY: live descriptor, no-argument query.
                unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE,
                libc::O_RDONLY
            );
        }
        fs::rename(f.store.join("snapshot"), f.store.join("saved")).unwrap();
        fs::write(f.store.join("snapshot"), b"replacement").unwrap();
        // Run with actual seccomp on Linux. The child fixture below isolates it.
        let record = text(p.respond());
        assert!(record.contains("ok:none"), "{record:?}");
        assert!(!record.contains('!'));
        for (fd, facts) in fds {
            released(fd, facts);
        }
    }
    // 이것을 실패시키는 것: 손상된 current에서 last-good 선택·notice·실제 compiled 렌더 연결 누락.
    #[test]
    fn fallback_and_marker_revocation_reach_the_record() {
        let f = Fx::new();
        let mut bad = f.wire.clone();
        bad[0] ^= 1;
        fs::write(f.store.join("snapshot"), bad).unwrap();
        let record = text(f.prepared().respond());
        assert!(
            record.contains("error:config-last-good") && record.contains('!'),
            "{record:?}"
        );
        fs::write(f.store.join("snapshot"), &f.wire).unwrap();
        let mut marker = Marker::decode(&fs::read(f.store.join("marker")).unwrap()).unwrap();
        marker.invalid = true;
        fs::write(f.store.join("marker"), marker.encode()).unwrap();
        let record = text(f.prepared().respond());
        assert!(
            record.contains("degraded:trust-invalid") && record.contains('!'),
            "{record:?}"
        );
    }
    // 이것을 실패시키는 것: regular/mode/nlink 검사 또는 NOFOLLOW를 빼고 위험한 FD를 보유하는 것.
    #[test]
    fn prefilter_rejects_symlink_hardlink_mode_and_fifo() {
        let f = Fx::new();
        let path = f.store.join("snapshot");
        fs::remove_file(&path).unwrap();
        symlink("last-good", &path).unwrap();
        assert!(f.prepared().files[0].is_none());
        fs::remove_file(&path).unwrap();
        fs::hard_link(f.store.join("last-good"), &path).unwrap();
        let p = f.prepared();
        assert!(p.files[0].is_none() && p.files[1].is_none());
        drop(p);
        fs::remove_file(&path).unwrap();
        fs::write(&path, &f.wire).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.prepared().files[0].is_none());
        fs::remove_file(&path).unwrap();
        let c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: terminated path for a private test FIFO, before confinement.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(f.prepared().files[0].is_none());
    }
    // 이것을 실패시키는 것: init dev/ino pin을 빼거나 디렉터리 symlink를 따라가는 것.
    #[test]
    fn pin_and_directory_symlink_stop_before_file_preparation() {
        let mut f = Fx::new();
        let root = f.args.last_mut().unwrap();
        *root = format!("--runtime-root=0:0:{}", f.base.display()).into_bytes();
        assert!(f.prepared().sources.is_none());
        let m = fs::metadata(&f.base).unwrap();
        *f.args.last_mut().unwrap() = format!(
            "--runtime-root={}:{}:{}",
            m.dev(),
            m.ino(),
            f.base.display()
        )
        .into_bytes();
        fs::rename(f.base.join("contexts-v2"), f.base.join("elsewhere")).unwrap();
        symlink("elsewhere", f.base.join("contexts-v2")).unwrap();
        assert!(f.prepared().sources.is_none());
    }
    // 이것을 실패시키는 것: 잘못된 봉투에서 UID·clock·파일 관찰을 시작하는 것.
    #[test]
    fn invalid_envelope_opens_nothing() {
        let p = prepare_state(&[b"--ctx", b"2", b"--record", b"B1"]);
        assert!(p.sources.is_none() && p.clock.identity.is_none());
        assert!(p.slots.iter().all(Option::is_none) && p.files.iter().all(Option::is_none));
        assert!(text(p.respond()).contains("error:bad-args"));
    }
    // 이것을 실패시키는 것: procfs/nsfs·fd 종류·ACL·부재/실패·boot 소유/형식 조건 누락.
    #[test]
    fn held_clock_evidence_is_strict() {
        let f = FdFacts {
            entry: Facts {
                dev: 1,
                ino: 9,
                uid: 0,
                gid: 0,
                mode: 0o100444,
                acl: AclFacts::None,
                ownership: Some(true),
            },
            local: Some(false),
            nlink: 1,
            size: 0,
        };
        assert!(kernel_entry(f, false, 0x9fa0, 0x9fa0));
        assert!(kernel_entry(f, false, 0x6e736673, 0x6e736673));
        assert!(!kernel_entry(f, false, 0x9fa0, 0x6e736673));
        assert!(!kernel_entry(f, true, 0x9fa0, 0x9fa0));
        let mut dir = f;
        dir.entry.mode = 0o040555;
        assert!(kernel_entry(dir, true, 0x9fa0, 0x9fa0));
        for acl in [AclFacts::Unknown, AclFacts::AllowsWrite] {
            let mut bad = f;
            bad.entry.acl = acl;
            assert!(!kernel_entry(bad, false, 0x9fa0, 0x9fa0));
        }
        assert!(time_domain(Ok(f), Ok(f), Ok(f)).is_ok());
        assert!(time_domain(Err(libc::ENOENT), Err(libc::ENOENT), Err(libc::ENOENT)).is_ok());
        for i in 0..3 {
            let mut observed = [Err(libc::ENOENT); 3];
            observed[i] = Err(libc::EACCES);
            assert!(time_domain(observed[0], observed[1], observed[2]).is_err());
        }
        assert!(time_domain(Ok(f), Err(libc::ENOENT), Ok(f)).is_err());
        assert!(time_domain(Ok(f), Ok(f), Err(libc::EACCES)).is_err());
        assert!(boot_file(f));
        for (uid, mode) in [(501, 0o100444), (0, 0o100446), (0, 0o040444)] {
            let mut bad = f;
            bad.entry.uid = uid;
            bad.entry.mode = mode;
            assert!(!boot_file(bad));
        }
        let uuid = b"00112233-4455-6677-8899-aabbccddeeff\n";
        assert!(boot_bytes(uuid).is_ok());
        for bytes in [
            &uuid[..36],
            b"00112233-4455-6677-8899-aabbccddeeff ",
            b"00112233-4455-6677-8899-aabbccddeeff\nextra",
            b"00000000-0000-0000-0000-000000000000\n".as_slice(),
        ] {
            assert!(boot_bytes(bytes).is_err());
        }
    }
    // 이것을 실패시키는 것: 저장 시각 반환, 현재 관찰 생략, identity 실패를 성공으로 바꾸는 것.
    #[test]
    fn fresh_clock_is_monotonic_and_missing_identity_fails() {
        let before = crate::prompt_io::monotonic_ns().unwrap();
        let mut pins = fixed_clock();
        let observed = pins.observe().unwrap();
        let after = crate::prompt_io::monotonic_ns().unwrap();
        assert!(before > 0 && before <= observed.now && observed.now <= after);
        pins.identity = None;
        assert!(pins.observe().is_err());
    }
    // 이것을 실패시키는 것: 필터 뒤 UID/path 준비 재실행을 허용하는 것.
    #[test]
    fn postfilter_refuses_preparation_effects() {
        let f = Fx::new();
        let mut held = f.prepared();
        let raw: Vec<_> = f.args.iter().map(Vec::as_slice).collect();
        let mut plan = staged::prepare(&raw);
        let Step::Read(uid) = staged::next(&mut plan, None) else {
            panic!("uid")
        };
        assert!(matches!(held.after(&uid), Observation::Failed));
        // SAFETY: identity observation for the test's separate pure plan.
        let Step::Read(_) =
            staged::next(&mut plan, Some(Observation::Uid(unsafe { libc::getuid() })))
        else {
            panic!("clock")
        };
        let Step::Read(directory) = staged::next(
            &mut plan,
            Some(Observation::Clock(fixed_clock().observe().ok())),
        ) else {
            panic!("directory")
        };
        assert!(matches!(held.after(&directory), Observation::Failed));
    }
    // 이것을 실패시키는 것: closure를 버릴 때 보유 FD가 남는 것(차단된 sandbox 경로).
    #[test]
    fn dropping_prepared_closes_every_source() {
        let f = Fx::new();
        let p = f.prepared();
        let fds: Vec<_> = p
            .files
            .iter()
            .flatten()
            .map(|h| (h.fd.as_raw_fd(), h.facts))
            .collect();
        assert_eq!(fds.len(), 3);
        drop(p);
        for (fd, facts) in fds {
            released(fd, facts);
        }
    }
    // 이것을 실패시키는 것: 필터 뒤 syscall을 추가하거나 vDSO fallback을 예산에서 빠뜨리는 것.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child: installs the real seccomp filter"]
    fn confined_child() {
        let f = Fx::new();
        let p = f.prepared();
        assert_eq!(
            crate::sandbox::enter(),
            bingsu_core::front::Sandbox::Installed
        );
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid output pointer; direct syscall deliberately bypasses vDSO.
        assert_eq!(
            // SAFETY: writable timespec; this test bypasses the vDSO explicitly.
            unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_BOOTTIME, &mut ts) },
            0
        );
        assert!(ts.tv_sec > 0);
        assert!(text(p.respond()).contains("ok:none"));
        // SAFETY: child exit avoids libtest/path cleanup under the filter.
        unsafe { libc::_exit(0) }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn held_reader_under_real_seccomp() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "prompt_read::tests::confined_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
}
