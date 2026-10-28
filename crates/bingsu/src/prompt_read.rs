//! N4 pre-filter TCB. Only `prepare` is callable from the prompt adapter, once
//! immediately before confinement. `Prepared::respond` has no path effects:
//! pending core opens/inspections consume already-held fds and cached facts.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use crate::prompt_io::check_deadline;
use bingsu_core::front::output::Deadline;
use bingsu_core::front::staged::{self, Effect, FdFacts, Observation, Operation, Slot, Step};
use bingsu_core::fs_trust::{self, AclFacts, Facts};
use bingsu_core::snapshot::{Clock, ClockError};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

// std's debug OwnedFd drop probes F_GETFD, which the prompt filter forbids.
// All exits (including unwind and unused prefetches) use exactly one close.
struct PromptFd(Option<OwnedFd>);
impl AsRawFd for PromptFd {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_ref().expect("owned prompt fd").as_raw_fd()
    }
}
impl Drop for PromptFd {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            // SAFETY: into_raw_fd transfers unique ownership, suppressing Drop.
            // Never retry close: the descriptor may already have been recycled.
            unsafe { libc::close(fd.into_raw_fd()) };
        }
    }
}

struct Held {
    fd: PromptFd,
    facts: FdFacts,
    #[cfg(target_os = "linux")]
    magic: u64,
}
struct Prepared {
    deadline: Option<Deadline>,
    plan: staged::ReadPlan,
    step: Step,
    slots: [Option<Held>; 3],
    files: [Option<Held>; 3],
    collections: [Option<Held>; 2],
    sources: Option<staged::Prefetch>,
    clock: ClockPins,
}

/// The closure owns every descriptor, including clock evidence. Dropping it on
/// a refused filter closes them; unwinding has the same ownership discipline.
pub fn prepare(raw: &[&[u8]], deadline: Deadline) -> impl FnOnce() -> Vec<u8> + use<> {
    let p = prepare_state(raw, Some(deadline));
    move || p.respond()
}

fn prepare_state(raw: &[&[u8]], deadline: Option<Deadline>) -> Prepared {
    prepare_with_clock(raw, ClockPins::prepare, deadline)
}

fn prepare_with_clock(
    raw: &[&[u8]],
    clock: fn(Option<Deadline>) -> ClockPins,
    deadline: Option<Deadline>,
) -> Prepared {
    check_deadline(deadline);
    let plan = staged::prepare(raw).with_build_id(bingsu_identity::build_id());
    let plan = if let Some(d) = deadline {
        plan.with_deadline(d)
    } else {
        plan
    };
    let mut p = Prepared {
        deadline,
        plan,
        step: Step::Done(staged::Observed::default()),
        slots: [None, None, None],
        files: [None, None, None],
        collections: [None, None],
        sources: None,
        clock: ClockPins::default(),
    };
    let mut previous = None;
    loop {
        check_deadline(deadline);
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
                        .and_then(|name| {
                            open(parent.fd.as_raw_fd(), &name, DATA_FLAGS, deadline).ok()
                        })
                        .and_then(|fd| held(fd, deadline).ok())
                        .filter(|h| sources.accepts(i, h.facts));
                }
                p.collections = prefetch_collections(parent.fd.as_raw_fd(), &sources, deadline);
            }
            p.sources = Some(sources);
            p.step = Step::Read(effect);
            break;
        }
        let observation = p.before(&effect, clock);
        if let (Some(deadline), Observation::Clock(Some(observed))) = (deadline, &observation) {
            if let Some(entry) = crate::prompt_io::entry_clock(deadline, *observed) {
                p.plan = p.plan.with_entry(entry);
            }
        }
        previous = Some(observation);
    }
    p
}

fn prefetch_collections(
    base: i32,
    sources: &staged::Prefetch,
    deadline: Option<Deadline>,
) -> [Option<Held>; 2] {
    let Some(components) = sources.collection_components() else {
        return [None, None];
    };
    let mut directory: Option<Held> = None;
    for component in components {
        let parent = directory.as_ref().map_or(base, |h| h.fd.as_raw_fd());
        let next = CString::new(component)
            .ok()
            .and_then(|name| open(parent, &name, DIRECTORY_FLAGS, deadline).ok())
            .and_then(|fd| held(fd, deadline).ok())
            .filter(|h| sources.accepts_collection_directory(h.facts));
        if next.is_none() {
            return [None, None];
        }
        directory = next;
    }
    let Some(directory) = directory else {
        return [None, None];
    };
    [
        staged::CollectionCopy::Current,
        staged::CollectionCopy::Previous,
    ]
    .map(|copy| {
        CString::new(copy.name())
            .ok()
            .and_then(|name| open(directory.fd.as_raw_fd(), &name, DATA_FLAGS, deadline).ok())
            .and_then(|fd| held(fd, deadline).ok())
            .filter(|h| sources.accepts_collection(h.facts))
    })
}

impl Prepared {
    fn before(&mut self, effect: &Effect, clock: fn(Option<Deadline>) -> ClockPins) -> Observation {
        check_deadline(self.deadline);
        match effect.operation() {
            // SAFETY: getuid has no preconditions and cannot fail.
            Operation::Uid => Observation::Uid(unsafe { libc::getuid() }),
            Operation::Clock => {
                self.clock = clock(self.deadline);
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
                    .and_then(|name| open(base, &name, DIRECTORY_FLAGS, self.deadline).ok())
                    .and_then(|fd| held(fd, self.deadline).ok());
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
        // PromptFd closes once, without std's post-filter debug fcntl probe.
        if self.slots[slot.index()].take().is_some() {
            Observation::Closed
        } else {
            Observation::Failed
        }
    }
    fn after(&mut self, effect: &Effect) -> Observation {
        check_deadline(self.deadline);
        match effect.operation() {
            Operation::OpenCollection(copy) => {
                if self.slots[Slot::File.index()].is_some() {
                    return Observation::Failed;
                }
                self.slots[Slot::File.index()] = self.collections[copy.index()].take();
                if self.slots[Slot::File.index()].is_some() {
                    Observation::Opened
                } else {
                    Observation::Failed
                }
            }
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
                check_deadline(self.deadline);
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
            check_deadline(self.deadline);
            match self.step {
                Step::Done(observed) => {
                    return staged::finish(self.plan, observed).record;
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

fn open(
    base: i32,
    name: &CStr,
    flags: i32,
    deadline: Option<Deadline>,
) -> std::io::Result<PromptFd> {
    check_deadline(deadline);
    // SAFETY: base is held or AT_FDCWD for '/', name is terminated, no O_CREAT.
    let fd = unsafe { libc::openat(base, name.as_ptr(), flags) };
    #[cfg(test)]
    tests::record_open(base, name, flags, fd);
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat returned unique ownership.
    Ok(PromptFd(Some(unsafe { OwnedFd::from_raw_fd(fd) })))
}

#[allow(
    clippy::unnecessary_cast,
    clippy::useless_conversion,
    reason = "stat fields differ across Linux libc and macOS"
)]
fn held(fd: PromptFd, deadline: Option<Deadline>) -> std::io::Result<Held> {
    #[cfg(test)]
    tests::record_facts(fd.as_raw_fd());
    // SAFETY: zeroed structs are valid output storage.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: zeroed structs are valid output storage.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    check_deadline(deadline);
    // SAFETY: owned descriptor and valid output pointers.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    check_deadline(deadline);
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
            acl: acl(fd.as_raw_fd(), deadline),
        },
        local: Some(local),
        nlink: st.st_nlink as u64,
        size: u64::try_from(st.st_size).map_err(|_| std::io::Error::other("negative file size"))?,
    };
    Ok(Held {
        fd,
        facts,
        #[cfg(target_os = "linux")]
        magic: fs.f_type as u64 & 0xffff_ffff,
    })
}

#[derive(Default)]
struct ClockPins {
    deadline: Option<Deadline>,
    identity: Option<Clock>,
    #[cfg(test)]
    fixed_now: Option<u64>,
    // Keep ordinary kernel files alive across the filter and both samples.
    // Namespace links are observed before the filter and retain no target fd.
    #[cfg(target_os = "linux")]
    fds: Vec<Held>,
}
impl ClockPins {
    fn observe(&self) -> Result<Clock, ClockError> {
        check_deadline(self.deadline);
        let mut clock = self.identity.ok_or(ClockError::Boot)?;
        #[cfg(test)]
        if let Some(now) = self.fixed_now {
            clock.now = now;
            return Ok(clock);
        }
        clock.now = crate::prompt_io::monotonic_ns()?;
        Ok(clock)
    }
    #[cfg(target_os = "macos")]
    fn prepare(deadline: Option<Deadline>) -> Self {
        check_deadline(deadline);
        Self {
            deadline,
            identity: crate::prompt_io::observe_clock_until(deadline).ok(),
            #[cfg(test)]
            fixed_now: None,
        }
    }
    #[cfg(target_os = "linux")]
    fn prepare(deadline: Option<Deadline>) -> Self {
        check_deadline(deadline);
        let mut p = Self {
            deadline,
            ..Self::default()
        };
        p.identity = p.linux().ok();
        // Walk directories have served their purpose. Keep only the identity
        // files alive for the two samples; a failed identity needs no pins.
        p.fds
            .retain(|h| p.identity.is_some() && h.facts.entry.mode & 0o170000 != 0o040000);
        p
    }
    #[cfg(target_os = "linux")]
    fn kernel(&mut self, base: i32, name: &CStr, flags: i32, magic: u64) -> Result<FdFacts, i32> {
        let fd = open(base, name, flags | libc::O_CLOEXEC, self.deadline)
            .map_err(|e| e.raw_os_error().unwrap_or(0))?;
        let h = held(fd, self.deadline).map_err(|_| libc::EIO)?;
        let facts = h.facts;
        if !kernel_entry(facts, flags & libc::O_DIRECTORY != 0, h.magic, magic) {
            return Err(libc::EIO);
        }
        self.fds.push(h);
        Ok(facts)
    }
    #[cfg(target_os = "linux")]
    fn last(&self) -> i32 {
        self.fds.last().expect("kernel retained fd").fd.as_raw_fd()
    }
    #[cfg(target_os = "linux")]
    fn linux(&mut self) -> Result<Clock, ClockError> {
        let dir = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY;
        let file = libc::O_RDONLY | libc::O_NOFOLLOW;
        let procfs = 0x9fa0;
        let root = held(
            open(libc::AT_FDCWD, c"/", DIRECTORY_FLAGS, self.deadline)
                .map_err(|_| ClockError::Domain)?,
            self.deadline,
        )
        .map_err(|_| ClockError::Domain)?;
        self.kernel(root.fd.as_raw_fd(), c"proc", dir, procfs)
            .map_err(|_| ClockError::Domain)?;
        let proc = self.last();
        // The mounted procfs may belong to an ancestor PID namespace. Its
        // kernel-owned self link, not getpid(), names us in that mount.
        // Read a bounded numeric component; keep O_NOFOLLOW on the walk.
        let pid = proc_self_name(proc, self.deadline)?;
        self.kernel(proc, &pid, dir, procfs)
            .map_err(|_| ClockError::Domain)?;
        let process = self.last();
        self.kernel(process, c"ns", dir, procfs)
            .map_err(|_| ClockError::Domain)?;
        let ns = self.last();
        let offsets = self.kernel(process, c"timens_offsets", file, procfs);
        check_deadline(self.deadline);
        let domain =
            crate::prompt_io::time_namespace_domain_until(ns, offsets.map(|_| ()), self.deadline)?;
        let mut base = proc;
        for name in [c"sys", c"kernel", c"random"] {
            self.kernel(base, name, dir, procfs)
                .map_err(|_| ClockError::Boot)?;
            base = self.last();
        }
        let facts = self
            .kernel(base, c"boot_id", file, procfs)
            .map_err(|_| ClockError::Boot)?;
        if !crate::prompt_io::boot_file(facts.entry, procfs) {
            return Err(ClockError::Boot);
        }
        let mut bytes = [0; 38];
        let mut n = 0;
        while n < bytes.len() {
            check_deadline(self.deadline);
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
            boot: crate::prompt_io::boot_bytes(&bytes[..n])?,
            domain,
            now: 0,
            kind: 1,
            resume: 0,
        })
    }
}

#[cfg(any(test, target_os = "linux"))]
fn proc_self_name(proc: i32, deadline: Option<Deadline>) -> Result<CString, ClockError> {
    check_deadline(deadline);
    // A positive pid_t is at most ten decimal digits; reserve a truncation byte.
    let mut bytes = [0u8; 11];
    // SAFETY: held proc directory and initialized writable buffer; no link is followed.
    let n = unsafe {
        libc::readlinkat(
            proc,
            c"self".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    let n = usize::try_from(n).map_err(|_| ClockError::Domain)?;
    proc_self_component(&bytes[..n])
}

#[cfg(any(test, target_os = "linux"))]
fn proc_self_component(bytes: &[u8]) -> Result<CString, ClockError> {
    if bytes.is_empty() || bytes.len() >= 11 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ClockError::Domain);
    }
    CString::new(bytes).map_err(|_| ClockError::Domain)
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
fn acl(fd: i32, deadline: Option<Deadline>) -> AclFacts {
    check_deadline(deadline);
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, ty: libc::c_int) -> *mut libc::c_void;
    }
    // SAFETY: held descriptor, fixed extended ACL kind; returned object freed by acl_entries.
    acl_entries(unsafe { acl_get_fd_np(fd, macos_acl::ACL_TYPE_EXTENDED) })
}
#[cfg(target_os = "linux")]
fn acl(fd: i32, deadline: Option<Deadline>) -> AclFacts {
    check_deadline(deadline);
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
        check_deadline(deadline);
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
pub(crate) mod tests {
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

    #[derive(Clone, Debug)]
    enum Event {
        Open(i32, Vec<u8>, i32, i32),
        Facts(i32),
    }
    std::thread_local! { static EVENTS: std::cell::RefCell<Vec<Event>> = const { std::cell::RefCell::new(Vec::new()) }; }
    pub(super) fn record_open(base: i32, name: &CStr, flags: i32, fd: i32) {
        EVENTS.with_borrow_mut(|events| {
            events.push(Event::Open(base, name.to_bytes().to_vec(), flags, fd))
        });
    }
    pub(super) fn record_facts(fd: i32) {
        EVENTS.with_borrow_mut(|events| events.push(Event::Facts(fd)));
    }
    fn take_events() -> Vec<Event> {
        EVENTS.with_borrow_mut(std::mem::take)
    }
    fn collection_events() -> Vec<Event> {
        let events = take_events();
        let at = events
            .iter()
            .position(|e| matches!(e, Event::Open(_, name, _, _) if name == b"collections-v1"))
            .expect("collection root attempted");
        events[at..].to_vec()
    }
    use bingsu_core::collection::{
        response::Completed,
        selection::Catalog,
        wire::{Binding, EndReason, M3B_REQUEST_ID, Update},
    };
    use bingsu_core::field::{Field, FieldDecl, FieldType, SegmentDecl, Value};
    const TEST_MASK: u32 = 1 << 31;
    static COLLECTION_CATALOG: [SegmentDecl; 32] = {
        let ids = [
            "a00", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10", "a11",
            "a12", "a13", "a14", "a15", "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23",
            "a24", "a25", "a26", "a27", "a28", "a29", "a30", "fixture",
        ];
        let mut c = [const {
            SegmentDecl {
                id: "unused",
                role: "fg",
                fields: &[],
            }
        }; 32];
        let mut i = 0;
        while i < 32 {
            c[i] = SegmentDecl {
                id: ids[i],
                role: "fg",
                fields: &[],
            };
            i += 1;
        }
        c[31] = SegmentDecl {
            id: "fixture",
            role: "fg",
            fields: &[FieldDecl {
                name: "text",
                ty: FieldType::Text { max_cells: 4096 },
            }],
        };
        c
    };
    fn fixture_config(f: &Fx) -> bingsu_core::config::compile::CompiledConfig {
        let mut s = Snapshot::decode(&f.wire).unwrap();
        s.config.bands.clear();
        s.config.band_order.clear();
        s.config.collect_mask = TEST_MASK;
        s.config.variants = vec![
            bingsu_core::template::compile::compile("{fixture}", &COLLECTION_CATALOG).unwrap(),
        ];
        s.config
    }
    fn collection_fixture(cwd: &[u8]) -> (Fx, Binding, PathBuf) {
        let mut f = Fx::new();
        f.args.extend([b"--pwd".to_vec(), cwd.to_vec()]);
        let c = fixed_clock(None).observe().unwrap();
        let b = Binding {
            path_query: Default::default(),
            build_id: bingsu_identity::build_id(),
            snapshot: Marker::decode(&fs::read(f.store.join("marker")).unwrap())
                .unwrap()
                .id,
            clock_kind: c.kind,
            domain: c.domain,
            resume: c.resume,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            cwd: cwd.to_vec(),
            mask: TEST_MASK,
        };
        let path = b
            .components()
            .into_iter()
            .fold(f.store.clone(), |p, n| p.join(n));
        (f, b, path)
    }
    fn publish_fixture(f: &Fx, b: &Binding, at: u64, text: &[u8]) {
        use crate::commands::{
            collection_gc, collection_store::CollectionStore, snapshot_store::CheckedContextFd, sys,
        };
        let runtime = fs::File::open(&f.base).unwrap();
        let context = CheckedContextFd::under_runtime(
            &runtime,
            &b.config,
            &b.state,
            sys::current_uid(),
            false,
        )
        .unwrap();
        let now = fixed_clock(None).observe().unwrap();
        for _ in 0..8 {
            let report =
                collection_gc::fixture_reclaim(&context, now, 4096, &COLLECTION_CATALOG).unwrap();
            if !report.incomplete {
                break;
            }
        }
        let mut store =
            CollectionStore::fixture(&context, b, now, &COLLECTION_CATALOG, None).unwrap();
        let r = Completed {
            progress: Default::default(),
            request_id: M3B_REQUEST_ID,
            binding: b.clone(),
            completed_at_ns: at,
            reason: EndReason::Deadline,
            updates: vec![Update {
                facts: None,
                segment: 31,
                value: Some(Value::new(
                    text,
                    vec![Field::text(
                        text,
                        4096,
                        bingsu_core::width::WidthProfile::DEFAULT,
                    )],
                )),
            }],
        };
        store.publish(&r).unwrap();
    }
    fn fixture_prepared(f: &Fx, entry: u64) -> Prepared {
        let mut p = f.prepared();
        p.plan = p
            .plan
            .with_entry(Clock {
                now: entry,
                ..fixed_clock(None).observe().unwrap()
            })
            .with_catalog(
                Catalog {
                    segments: &COLLECTION_CATALOG,
                    workers: TEST_MASK,
                },
                fixture_config(f),
            );
        p
    }

    // 이것을 실패시키는 것: 어댑터가 deadline.start 대신 StartClock을 완료 cutoff로 쓰는 것.
    #[test]
    fn adapter_uses_deadline_entry_before_the_start_clock_observation() {
        fn delayed_clock(deadline: Option<Deadline>) -> ClockPins {
            ClockPins {
                fixed_now: Some(deadline.unwrap().start() + 2),
                ..fixed_clock(deadline)
            }
        }
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (f, b, _) = collection_fixture(b"/cwd");
        let entry = crate::prompt_io::monotonic_ns().unwrap();
        publish_fixture(&f, &b, entry - 1, b"PREVIOUS");
        publish_fixture(&f, &b, entry + 1, b"CURRENT");
        for (start, want, refused) in [
            (entry, "PREVIOUS", "CURRENT"),
            (entry + 2, "CURRENT", "PREVIOUS"),
        ] {
            let deadline = Deadline::from_entry(start, 60_000_000_000).unwrap();
            let mut p = prepare_with_clock(
                &f.args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                delayed_clock,
                Some(deadline),
            );
            assert!(p.collections.iter().all(Option::is_some));
            // Supply only the test worker catalog, never override the entry
            // chosen by the adapter under test.
            p.plan = p.plan.with_catalog(
                Catalog {
                    segments: &COLLECTION_CATALOG,
                    workers: TEST_MASK,
                },
                fixture_config(&f),
            );
            let record = text(p.respond());
            assert!(
                record.contains(want) && !record.contains(refused),
                "{record}"
            );
        }
    }

    // 이것을 실패시키는 것: collections-v1 실패 뒤 추가 open 또는 facts를 수행하는 것.
    #[test]
    fn missing_collections_stops_after_one_enoent() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        for n in [1, 3841, 65_536] {
            let mut cwd = vec![b'a'; n];
            cwd[0] = b'/';
            let (f, _, _) = collection_fixture(&cwd);
            let p = f.prepared();
            let events = collection_events();
            assert!(
                matches!(events.as_slice(), [Event::Open(_, name, flags, -1)] if name == b"collections-v1" && *flags == DIRECTORY_FLAGS),
                "{events:?}"
            );
            assert!(p.collections.iter().all(Option::is_none));
            let ordinary = p.respond();
            assert_eq!(ordinary, f.prepared().respond());
        }
    }

    // 이것을 실패시키는 것: cwd 길이에 따라 open 수를 늘리거나 descriptor 검증·NOFOLLOW를 빼는 것.
    #[test]
    fn collection_prefetch_has_five_fixed_path_opens() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        for cwd in [
            b"/".to_vec(),
            b"/prefix/\xff".to_vec(),
            [b"/".as_slice(), &vec![b'a'; 65_535]].concat(),
        ] {
            let (f, b, path) = collection_fixture(&cwd);
            publish_fixture(&f, &b, 98, b"PREVIOUS");
            publish_fixture(&f, &b, 99, b"CURRENT");
            let p = fixture_prepared(&f, 100);
            let events = collection_events();
            let opens: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    Event::Open(base, n, flags, fd) => Some((*base, n, *flags, *fd)),
                    _ => None,
                })
                .collect();
            assert_eq!(opens.len(), 5, "{events:?}");
            let names = [
                b"collections-v1".to_vec(),
                b.components()[1].as_bytes().to_vec(),
                b"store".to_vec(),
                b"response".to_vec(),
                b"previous".to_vec(),
            ];
            for (i, (base, name, flags, fd)) in opens.iter().enumerate() {
                assert_eq!(**name, names[i]);
                assert!(*base >= 0 && *fd >= 0);
                assert_eq!(*flags, if i < 3 { DIRECTORY_FLAGS } else { DATA_FLAGS });
                if i > 0 {
                    assert_eq!(*base, opens[if i == 4 { 2 } else { i - 1 }].3);
                }
                assert!(matches!(&events[i*2+1], Event::Facts(n) if n == fd));
            }
            assert!(p.collections.iter().all(Option::is_some));
            for h in p.collections.iter().flatten() {
                // SAFETY: live descriptor; read-only query before confinement.
                assert_eq!(
                    // SAFETY: this fixture retains the descriptor before confinement.
                    unsafe { libc::lseek(h.fd.as_raw_fd(), 0, libc::SEEK_CUR) },
                    0
                );
            }
            fs::rename(path.join("response"), path.join("saved")).unwrap();
            fs::write(path.join("response"), b"torn replacement").unwrap();
            assert!(text(p.respond()).contains("CURRENT"));
            assert!(text(fixture_prepared(&f, 100).respond()).contains("PREVIOUS"));
        }
    }

    // 이것을 실패시키는 것: 원본 cwd 접근·unsafe directory 통과·구 경로 fallback을 추가하는 것.
    #[test]
    fn prefetch_uses_only_validated_context_and_cwd_address() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (f, b, path) = collection_fixture(b"/never-open-this-cwd");
        publish_fixture(&f, &b, 99, b"SAFE");
        for depth in 0..3 {
            let directory = b.components()[..=depth]
                .iter()
                .fold(f.store.clone(), |p, n| p.join(n));
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
            let p = fixture_prepared(&f, 100);
            let events = collection_events();
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e, Event::Open(..)))
                    .count(),
                depth + 1
            );
            assert!(p.collections.iter().all(Option::is_none));
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::rename(&path, path.with_file_name("elsewhere")).unwrap();
        symlink("elsewhere", &path).unwrap();
        assert!(f.prepared().collections.iter().all(Option::is_none));
        let events = collection_events();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Open(..)))
                .count(),
            3
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::Open(_,n,_,_) if n == &b.cwd))
        );
    }

    // 이것을 실패시키는 것: current 부재·decode 실패를 오류로 만들거나 다른 binding의 응답을 재사용하는 것.
    #[test]
    fn published_fixture_previous_and_unknown_reach_render() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (f, b, path) = collection_fixture(b"/cwd");
        publish_fixture(&f, &b, 99, b"PREVIOUS");
        publish_fixture(&f, &b, 101, b"CURRENT");
        assert!(text(fixture_prepared(&f, 100).respond()).contains("PREVIOUS"));
        assert!(text(fixture_prepared(&f, 102).respond()).contains("CURRENT"));
        fs::remove_file(path.join("response")).unwrap();
        assert!(text(fixture_prepared(&f, 100).respond()).contains("PREVIOUS"));
        fs::write(path.join("previous"), b"undecodable").unwrap();
        let record = text(fixture_prepared(&f, 100).respond());
        assert!(
            record.contains('?') && record.contains("ok:none"),
            "{record}"
        );
    }

    // 이것을 실패시키는 것: 새 수집의 완료 또는 lock 해제를 현재 prompt가 기다리는 것.
    #[test]
    fn new_completion_never_blocks_the_current_prompt() {
        // Share the guard with every child-spawning test in this binary,
        // from fixture publication until the worker has dropped its store.
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        use crate::commands::{
            collection_store::CollectionStore, snapshot_store::CheckedContextFd, sys,
        };
        let (f, b, _) = collection_fixture(b"/cwd");
        publish_fixture(&f, &b, 99, b"PREVIOUS");
        let runtime = fs::File::open(&f.base).unwrap();
        let context = CheckedContextFd::under_runtime(
            &runtime,
            &b.config,
            &b.state,
            sys::current_uid(),
            false,
        )
        .unwrap();
        let mut store = CollectionStore::fixture(
            &context,
            &b,
            fixed_clock(None).observe().unwrap(),
            &COLLECTION_CATALOG,
            None,
        )
        .unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let released = release_rx.recv_timeout(std::time::Duration::from_secs(10));
            if released.is_ok() {
                store
                    .publish(&Completed {
                        progress: Default::default(),
                        request_id: M3B_REQUEST_ID,
                        binding: b,
                        completed_at_ns: 101,
                        reason: EndReason::Complete,
                        updates: vec![Update {
                            facts: None,
                            segment: 31,
                            value: Some(Value::new(
                                b"CURRENT",
                                vec![Field::text(
                                    b"CURRENT",
                                    4096,
                                    bingsu_core::width::WidthProfile::DEFAULT,
                                )],
                            )),
                        }],
                    })
                    .unwrap();
            }
        });
        ready_rx.recv().unwrap();
        let begin = std::time::Instant::now();
        let record = text(fixture_prepared(&f, 100).respond());
        assert!(
            begin.elapsed() < std::time::Duration::from_secs(2),
            "prompt waited for stalled collection"
        );
        assert!(record.contains("PREVIOUS") && !record.contains("CURRENT"));
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(text(fixture_prepared(&f, 102).respond()).contains("CURRENT"));
    }

    // Called only by the harness=false test target, on the process main thread.
    #[allow(
        dead_code,
        reason = "entry for the separate collection_reader test target"
    )]
    pub(crate) fn collection_trace_child() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        use std::io::Read;
        #[cfg(target_os = "linux")]
        // SAFETY: these identity queries have no pointer arguments.
        assert_eq!(unsafe { libc::gettid() }, unsafe { libc::getpid() });
        #[cfg(target_os = "macos")]
        // SAFETY: pthread_main_np has no arguments and reports the current thread.
        assert_eq!(unsafe { libc::pthread_main_np() }, 1);
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let mut input = input.split('\0');
        let mode = input.next().filter(|s| !s.is_empty()).unwrap_or("current");
        let length: usize = input.next().and_then(|n| n.parse().ok()).unwrap_or(4);
        let shell = input.next().unwrap_or("bash");
        let payload = input.next().unwrap_or("CURRENT");
        let mut cwd = vec![b'a'; length];
        cwd[0] = b'/';
        if length > 1 {
            cwd[length - 1] = 0xff;
        }
        let (mut f, b, path) = collection_fixture(&cwd);
        f.args[5] = shell.as_bytes().to_vec();
        f.args[7] = b"400".to_vec();
        if mode != "absent" {
            publish_fixture(&f, &b, 98, b"PREVIOUS");
            publish_fixture(&f, &b, 99, payload.as_bytes());
            if mode == "previous" {
                fs::remove_file(path.join("response")).unwrap();
            }
            if mode == "corrupt" {
                fs::write(path.join("response"), vec![0; 64]).unwrap();
            }
        }
        // Marker writes delimit fixture preparation from the actual reader.
        let begin = b"C3-BEGIN\n";
        // SAFETY: initialized bytes and the test child's stdout.
        assert_eq!(
            // SAFETY: initialized bytes and the isolated child stdout.
            unsafe { libc::write(1, begin.as_ptr().cast(), begin.len()) },
            begin.len() as isize
        );
        let p = fixture_prepared(&f, 100);
        let prepared = b"C3-PREPARED\n";
        // SAFETY: initialized bytes and stdout, before installing the filter.
        assert_eq!(
            // SAFETY: initialized bytes and the isolated child stdout.
            unsafe { libc::write(1, prepared.as_ptr().cast(), prepared.len()) },
            prepared.len() as isize
        );
        let sandbox = crate::sandbox::enter();
        assert!(bingsu_core::front::runs_core(sandbox));
        #[cfg(target_os = "linux")]
        assert_eq!(sandbox, bingsu_core::front::Sandbox::Installed);
        let record = p.respond();
        // SAFETY: initialized B1 bytes and stdout; no file/metadata effects.
        assert_eq!(
            // SAFETY: initialized bytes and the isolated child stdout.
            unsafe { libc::write(1, record.as_ptr().cast(), record.len()) },
            record.len() as isize
        );
        // SAFETY: isolated child; no fixture path cleanup after confinement.
        unsafe { libc::_exit(0) }
    }

    // 이것을 실패시키는 것: collection 파일의 NOFOLLOW/종류/0600/nlink/크기 검사를 생략하는 것.
    #[test]
    fn collection_files_reject_unsafe_metadata_without_blocking() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (f, b, path) = collection_fixture(b"/cwd");
        publish_fixture(&f, &b, 98, b"PREVIOUS");
        publish_fixture(&f, &b, 99, b"CURRENT");
        let current = path.join("response");
        let saved = fs::read(&current).unwrap();
        for case in 0..6 {
            fs::remove_file(&current).unwrap();
            match case {
                0 => symlink("previous", &current).unwrap(),
                1 => {
                    fs::write(&current, &saved).unwrap();
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o644)).unwrap();
                }
                2 => fs::hard_link(path.join("previous"), &current).unwrap(),
                3 => {
                    let c = CString::new(current.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: terminated fixture path, created before confinement.
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }
                4 => {
                    fs::write(&current, []).unwrap();
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => {
                    fs::write(&current, vec![0; 262145]).unwrap();
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            let p = fixture_prepared(&f, 100);
            assert!(p.collections[0].is_none(), "case {case}");
            let record = text(p.respond());
            assert!(!record.contains("CURRENT"));
            assert!(
                record.contains(if case == 2 { "?" } else { "PREVIOUS" }),
                "case {case}: {record}"
            );
        }
    }

    // 이것을 실패시키는 것: 해시 주소가 같다는 이유로 파일 속 다른 cwd를 수용하는 것.
    #[test]
    fn stored_cwd_bytes_override_no_address_authority() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (f, b, path) = collection_fixture(b"/cwd");
        publish_fixture(&f, &b, 99, b"COLLISION");
        let mut r = Completed::decode_with_catalog(
            &fs::read(path.join("response")).unwrap(),
            &COLLECTION_CATALOG,
        )
        .unwrap();
        r.binding.cwd = b"/another-cwd".to_vec();
        fs::write(
            path.join("response"),
            r.encode_with_catalog(&COLLECTION_CATALOG).unwrap(),
        )
        .unwrap();
        let record = text(fixture_prepared(&f, 100).respond());
        assert!(record.contains('?') && !record.contains("COLLISION"));
    }

    #[test]
    #[ignore = "200 warm observations per case; latency evidence, not a timing assertion"]
    fn collection_read_latency() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        for mode in ["absent", "current", "previous"] {
            let (f, b, _) = collection_fixture(b"/cwd");
            if mode != "absent" {
                publish_fixture(&f, &b, 98, b"PREVIOUS");
                publish_fixture(
                    &f,
                    &b,
                    if mode == "previous" { 101 } else { 99 },
                    b"CURRENT",
                );
            }
            let mut samples = Vec::new();
            for i in 0..201 {
                let mut p = fixture_prepared(&f, 100);
                let mut start = None;
                let mut elapsed = None;
                let record = loop {
                    match std::mem::replace(&mut p.step, Step::Done(staged::Observed::default())) {
                        Step::Done(observed) => break staged::finish(p.plan, observed).record,
                        Step::Read(effect) => {
                            if matches!(effect.operation(), Operation::OpenCollection(_))
                                && start.is_none()
                            {
                                start = Some(crate::prompt_io::monotonic_ns().unwrap());
                            }
                            if matches!(effect.operation(), Operation::Clock) {
                                elapsed =
                                    start.map(|at| crate::prompt_io::monotonic_ns().unwrap() - at);
                            }
                            let observation = p.after(&effect);
                            p.step = staged::next(&mut p.plan, Some(observation));
                        }
                    }
                };
                let elapsed = elapsed.expect("collection read window executed");
                assert!(record.starts_with(b"B1"));
                if i > 0 {
                    samples.push(elapsed);
                }
            }
            samples.sort_unstable();
            assert_eq!(samples.len(), 200);
            println!(
                "collection-read {mode}: n=200 p50_ns={} p95_ns={}",
                samples[100], samples[189]
            );
        }
    }
    // 이것을 실패시키는 것: procfs의 self 대신 현재 namespace의 getpid 숫자를 사용하는 것.
    #[test]
    fn proc_self_uses_the_mounted_namespace() {
        let base = std::env::temp_dir().join(format!("bingsu-proc-self-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let dir = fs::File::open(&base).unwrap();
        let other_pid = (u64::from(std::process::id()) + 1).to_string();
        symlink(&other_pid, base.join("self")).unwrap();
        assert_eq!(
            proc_self_name(dir.as_raw_fd(), None).unwrap().to_bytes(),
            other_pid.as_bytes()
        );
        fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: readlink 오류·잘린 결과·숫자 아닌 경로를 PID 구간으로 사용하는 것.
    #[test]
    fn proc_self_rejects_errors_truncation_and_paths() {
        assert!(proc_self_component(b"").is_err());
        let base = std::env::temp_dir().join(format!("bingsu-proc-bad-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let dir = fs::File::open(&base).unwrap();
        assert!(proc_self_name(dir.as_raw_fd(), None).is_err());
        for target in ["12345678901", "../123", "/123", "12x"] {
            symlink(target, base.join("self")).unwrap();
            assert!(proc_self_name(dir.as_raw_fd(), None).is_err(), "{target}");
            fs::remove_file(base.join("self")).unwrap();
        }
        fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: 실제 clock 준비가 self 이름 대신 getpid 이름을 다시 사용하는 것.
    // test_prompt_proc.py runs this with a different visible getpid value.
    #[cfg(target_os = "linux")]
    #[test]
    fn mounted_proc_clock_matches_publisher() {
        let mut publisher = crate::prompt_io::observe_clock().expect("native procfs clock");
        publisher.now = 0; // Identity preparation deliberately does not sample time.
        assert_eq!(ClockPins::prepare(None).identity, Some(publisher));
    }

    struct NoFiles;
    impl Resolver for NoFiles {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("no source files")
        }
    }
    // macOS sandbox may deny kern.bootsessionuuid. Only the tests inject the
    // boot identity; production always uses ClockPins::prepare.
    fn fixed_clock(deadline: Option<Deadline>) -> ClockPins {
        let kind = if cfg!(target_os = "linux") { 1 } else { 2 };
        ClockPins {
            deadline,
            identity: Some(Clock {
                boot: [1; 16],
                domain: [0; 16],
                now: 0,
                kind,
                resume: 0,
            }),
            fixed_now: None,
            #[cfg(target_os = "linux")]
            fds: Vec::new(),
        }
    }
    std::thread_local! { static PUBLISHER_CLOCK: std::cell::Cell<Option<Clock>> = const { std::cell::Cell::new(None) }; }
    fn publisher_clock(deadline: Option<Deadline>) -> ClockPins {
        let at = PUBLISHER_CLOCK.get().expect("publisher clock");
        ClockPins {
            deadline,
            identity: Some(at),
            fixed_now: Some(at.now),
            #[cfg(target_os = "linux")]
            fds: Vec::new(),
        }
    }
    /// The front's whole response from a real read of a store the refresh
    /// tests published, observing the publisher's own clock at `at`.
    pub(crate) fn published_response(
        runtime: &std::path::Path,
        config: &[u8],
        state: &[u8],
        at: Clock,
    ) -> staged::Response {
        let m = fs::metadata(runtime).unwrap();
        let mut args: Vec<Vec<u8>> = [
            "--ctx", "1", "--record", "B1", "--shell", "bash", "--width", "80",
        ]
        .iter()
        .map(|a| a.as_bytes().to_vec())
        .collect();
        args.push([b"--config-root=".as_slice(), config].concat());
        args.push([b"--state-root=".as_slice(), state].concat());
        args.push(
            format!(
                "--runtime-root={}:{}:{}",
                m.dev(),
                m.ino(),
                runtime.display()
            )
            .into_bytes(),
        );
        PUBLISHER_CLOCK.set(Some(at));
        let mut p = prepare_with_clock(
            &args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            publisher_clock,
            None,
        );
        loop {
            match std::mem::replace(&mut p.step, Step::Done(staged::Observed::default())) {
                Step::Done(observed) => break staged::finish(p.plan, observed),
                Step::Read(effect) => {
                    let observation = p.after(&effect);
                    p.step = staged::next(&mut p.plan, Some(observation));
                }
            }
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
            Self::at(base, fixed_clock(None).observe().unwrap(), false)
        }
        /// A store published under `clock`; `boundary` uses the 4096-band
        /// forest of the N1 boundary fixture (crates/bingsu/examples/n7_front_cost.rs).
        fn at(base: PathBuf, clock: Clock, boundary: bool) -> Self {
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
            let mut config =
                bingsu_core::config::report::report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
                    .snapshot
                    .unwrap();
            if boundary {
                let n = bingsu_core::bands::MAX_BANDS;
                config.bands = (0..n)
                    .map(|i| bingsu_core::bands::Band {
                        min_cols: Some(i as u16),
                        max_cols: Some(10000),
                        order: None,
                    })
                    .collect();
                config.band_names = (0..n).map(|i| format!("b{i}")).collect();
                config.band_order = (0..n).rev().collect();
                config.variants = vec![config.variants[0].clone(); n + 1];
                config.widths.clear();
            }
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
            take_events();
            prepare_with_clock(
                &self.args.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                fixed_clock,
                None,
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
        let p = prepare_state(&[b"--ctx", b"2", b"--record", b"B1"], None);
        assert!(p.sources.is_none() && p.clock.identity.is_none());
        assert!(p.slots.iter().all(Option::is_none) && p.files.iter().all(Option::is_none));
        assert!(text(p.respond()).contains("error:bad-args"));
    }
    // 이것을 실패시키는 것: procfs/nsfs·fd 종류·ACL·부재/실패 조건 누락.
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
    }

    // 이것을 실패시키는 것: 저장 시각 반환, 현재 관찰 생략, identity 실패를 성공으로 바꾸는 것.
    #[test]
    fn fresh_clock_is_monotonic_and_missing_identity_fails() {
        let before = crate::prompt_io::monotonic_ns().unwrap();
        let mut pins = fixed_clock(None);
        let observed = pins.observe().unwrap();
        let after = crate::prompt_io::monotonic_ns().unwrap();
        assert!(before > 0 && before <= observed.now && observed.now <= after);
        pins.identity = None;
        assert!(pins.observe().is_err());
    }
    // The same probe also runs under unshare -U/rootless containers: uid 65534
    // must not make the reader disagree with the publisher.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_publisher_reader_identity_agrees_and_walk_fds_are_closed() {
        let reader = ClockPins::prepare(None);
        let publisher = crate::prompt_io::observe_clock().expect("publisher clock observation");
        let identity = |c: Clock| (c.boot, c.domain, c.kind, c.resume);
        assert_eq!(
            identity(reader.identity.expect("reader clock observation")),
            identity(publisher)
        );
        assert!(
            reader
                .fds
                .iter()
                .all(|h| h.facts.entry.mode & 0o170000 == 0o100000)
        );
    }
    #[test]
    fn colorfgbg_reaches_snapshot_and_default_rendering() {
        let mut f = Fx::new();
        let dark = f.prepared().respond();
        f.args.extend([b"--colorfgbg".to_vec(), b"0;15".to_vec()]);
        let light = f.prepared().respond();
        assert_ne!(dark, light);
        for name in ["snapshot", "last-good"] {
            fs::write(f.store.join(name), b"broken").unwrap();
        }
        let light_default = f.prepared().respond();
        f.args.pop();
        f.args.push(b"15;0".to_vec());
        assert_ne!(light_default, f.prepared().respond());
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
            Some(Observation::Clock(fixed_clock(None).observe().ok())),
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
        let mut p = f.prepared();
        // Exercise real clock-pin destruction as well as all snapshot slots.
        p.clock.fds = ClockPins::prepare(None).fds;
        // Production denies fcntl with EPERM, which std's debug probe ignores.
        // This test-only filter kills it so a reintroduced probe turns us red.
        let op = |code: u32, jt, jf, k| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let mut filter = [
            op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            op(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                1,
                libc::SYS_fcntl as u32,
            ),
            op(
                libc::BPF_RET | libc::BPF_K,
                0,
                0,
                libc::SECCOMP_RET_KILL_PROCESS,
            ),
            op(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: only this child is confined; the filter/program buffers live through prctl.
        assert_eq!(
            // SAFETY: no pointers; affects only this child process.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        // SAFETY: valid BPF program and no_new_privs is set above.
        assert_eq!(
            // SAFETY: program and its filter buffer remain live through this call.
            unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
            0
        );
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
    #[test]
    #[ignore = "child: expires before prefilter preparation"]
    fn expired_preparation_child() {
        prepare_state(&[], Deadline::from_entry(0, 1));
        // SAFETY: child-only sentinel; production must have exited first.
        unsafe { libc::_exit(88) }
    }

    #[test]
    #[ignore = "child: expires between held-fd reads"]
    fn expired_read_child() {
        let f = Fx::new();
        let mut p = f.prepared();
        drop(f); // Unlink the fixture now: retained descriptors still own the bytes.
        loop {
            let Step::Read(effect) =
                std::mem::replace(&mut p.step, Step::Done(staged::Observed::default()))
            else {
                panic!("expected a snapshot read");
            };
            if matches!(effect.operation(), Operation::Read { .. }) {
                p.deadline = Deadline::from_entry(0, 1);
                p.after(&effect);
                // SAFETY: child-only sentinel: no read is allowed after expiry.
                unsafe { libc::_exit(88) }
            }
            let observed = p.after(&effect);
            p.step = staged::next(&mut p.plan, Some(observed));
        }
    }

    // 이것을 실패시키는 것: 준비·각 스냅샷 읽기 전에 절대 마감을 검사하지 않는 것.
    #[test]
    fn expired_preparation_and_read_start_no_new_io() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        for name in ["expired_preparation_child", "expired_read_child"] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    &format!("prompt_read::tests::{name}"),
                    "--test-threads=1",
                    "--nocapture",
                    "-q",
                ])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(0), "{name}: {:?}", out.stderr);
            assert!(out.stderr.is_empty());
            assert!(!out.stdout.windows(3).any(|bytes| bytes == b"B1\x1f"));
        }
    }

    // Segment budget row "front snapshot read" (spec section 8): the window opens when
    // clock preparation returns, immediately before the first runtime-root
    // directory open, and closes when the read continuation is done, after the
    // snapshot, marker and collection reads and the final clock that the pair
    // and freshness checks of `staged::finish` consume. `finish` is timed next to
    // it. Delays exist only in this test loop; the shipped `respond` is unchanged.
    std::thread_local! { static BOUNDARY_START: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
    fn boundary_stamp() {
        if BOUNDARY_START.get().is_none() {
            BOUNDARY_START.set(Some(crate::prompt_io::monotonic_ns().unwrap()));
        }
    }
    fn boundary_native_clock(deadline: Option<Deadline>) -> ClockPins {
        let pins = ClockPins::prepare(deadline);
        boundary_stamp();
        pins
    }
    fn boundary_fixed_clock(deadline: Option<Deadline>) -> ClockPins {
        let pins = fixed_clock(deadline);
        boundary_stamp();
        pins
    }
    #[derive(Clone, Copy, Default)]
    struct Delays {
        marker_read: u64,
        final_clock: u64,
    }
    struct Boundary {
        boundary_ns: u64,
        read_decode_ns: u64,
        finish_ns: u64,
        record: Vec<u8>,
    }
    fn boundary_sample(
        args: &[Vec<u8>],
        clock: fn(Option<Deadline>) -> ClockPins,
        deadline: Option<Deadline>,
        confine: bool,
        delays: Delays,
    ) -> Boundary {
        #[derive(Clone, Copy, PartialEq)]
        enum Reading {
            Nothing,
            Snapshot,
            Marker,
        }
        let now = || crate::prompt_io::monotonic_ns().unwrap();
        let pause = |ns: u64| {
            if ns > 0 {
                std::thread::sleep(std::time::Duration::from_nanos(ns));
            }
        };
        BOUNDARY_START.set(None);
        let raw = args.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut p = prepare_with_clock(&raw, clock, deadline);
        if confine {
            assert!(bingsu_core::front::runs_core(crate::sandbox::enter()));
        }
        let mut reading = Reading::Nothing;
        let (mut read_start, mut read_end) = (None, None);
        loop {
            match std::mem::replace(&mut p.step, Step::Done(staged::Observed::default())) {
                Step::Done(observed) => {
                    let end = now();
                    let record = staged::finish(p.plan, observed).record;
                    let finish_ns = now() - end;
                    let start = BOUNDARY_START.get().expect("clock preparation ran");
                    return Boundary {
                        boundary_ns: end - start,
                        read_decode_ns: read_end.zip(read_start).map_or(0, |(e, s)| e - s),
                        finish_ns,
                        record,
                    };
                }
                Step::Read(effect) => {
                    match effect.operation() {
                        Operation::OpenFile { name, .. } => {
                            reading = match *name {
                                b"marker" => Reading::Marker,
                                b"snapshot" | b"last-good" => Reading::Snapshot,
                                _ => Reading::Nothing,
                            }
                        }
                        Operation::Read { .. } if reading == Reading::Marker => {
                            pause(delays.marker_read)
                        }
                        Operation::Read { .. } if reading == Reading::Snapshot => {
                            read_start.get_or_insert_with(now);
                        }
                        // The decode ran in the `next` that asked for this close.
                        Operation::Close(Slot::File) => {
                            if reading == Reading::Snapshot && read_end.is_none() {
                                read_end = Some(now());
                            }
                            reading = Reading::Nothing;
                        }
                        Operation::Clock => pause(delays.final_clock),
                        _ => {}
                    }
                    let observation = p.after(&effect);
                    p.step = staged::next(&mut p.plan, Some(observation));
                }
            }
        }
    }

    // 이것을 실패시키는 것: 끝 시각을 마지막 시계 관찰 전(표식을 닫은 직후)으로 당기는 것,
    // 표식 읽기 지연을 스냅샷 읽기에도 넣는 것.
    #[test]
    fn snapshot_boundary_grows_with_injected_marker_delay() {
        const DELAY: u64 = 20_000_000;
        let f = Fx::new();
        let median = |delays: Delays| {
            let mut rows: Vec<_> = (0..3)
                .map(|_| {
                    let b = boundary_sample(&f.args, boundary_fixed_clock, None, false, delays);
                    assert!(text(b.record).contains("ok:none"));
                    (b.boundary_ns, b.read_decode_ns)
                })
                .collect();
            rows.sort_unstable();
            let boundary = rows[1].0;
            rows.sort_unstable_by_key(|r| r.1);
            (boundary, rows[1].1)
        };
        let base = median(Delays::default());
        assert!(
            base.0 < DELAY / 2 && base.1 > 0 && base.1 <= base.0,
            "{base:?}"
        );
        for delays in [
            Delays {
                marker_read: DELAY,
                ..Delays::default()
            },
            Delays {
                final_clock: DELAY,
                ..Delays::default()
            },
        ] {
            let (boundary, read_decode) = median(delays);
            assert!(boundary >= DELAY, "boundary {boundary}");
            assert!(read_decode < DELAY / 2, "read/decode {read_decode}");
        }
    }

    /// bench/n7_measure.py runs one child per sample from a private working
    /// folder named after its fixture (`normal` or `4096-band`). The store is
    /// published with the native clock, the reader runs the shipped clock pins,
    /// deadline and (Linux) seccomp filter, and the result leaves by `write`.
    #[test]
    #[ignore = "child: one confined snapshot-boundary sample for bench/n7_measure.py"]
    fn n7_snapshot_boundary_child() {
        let dir = std::env::current_dir().unwrap();
        let boundary = match dir.file_name().and_then(|n| n.to_str()) {
            Some("normal") => false,
            Some("4096-band") => true,
            // SAFETY: child-only exit before any measurement.
            _ => unsafe { libc::_exit(3) },
        };
        let out = match crate::prompt_io::observe_clock() {
            Err(_) => "N7_BOUNDARY_NA native boot observation denied\n".to_owned(),
            Ok(clock) => {
                let f = Fx::at(dir.join(std::process::id().to_string()), clock, boundary);
                let b = boundary_sample(
                    &f.args,
                    boundary_native_clock,
                    crate::prompt_io::entry_deadline(),
                    true,
                    Delays::default(),
                );
                std::mem::forget(f); // Confined: the parent removes the folder.
                format!(
                    "N7_BOUNDARY {{\"snapshot_boundary_ns\":{},\"snapshot_read_decode_ns\":{},\"finish_ns\":{},\"normal_record\":{}}}\n",
                    b.boundary_ns,
                    b.read_decode_ns,
                    b.finish_ns,
                    b.record.ends_with(b"ok:none\x1e")
                )
            }
        };
        // SAFETY: a valid buffer of out.len() bytes.
        unsafe { libc::write(1, out.as_ptr().cast(), out.len()) };
        // SAFETY: child exit avoids libtest output under the filter.
        unsafe { libc::_exit(0) }
    }
}
