//! Descriptor capabilities for hostile repository input. Not wired into the
//! product worker until its repository sandbox is installed.
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use crate::meter::{Lease, Meter, Op, Phase, READ_CHUNK};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
mod walk;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    Missing,
    Denied,
    Escape,
    Symlink,
    Special,
    Changed,
    Limit,
    Deadline,
    StageAOnly,
    Io(i32),
}

impl ReadError {
    pub(super) fn errno(errno: i32) -> Self {
        match errno {
            libc::ENOENT | libc::ENOTDIR => Self::Missing,
            libc::EACCES | libc::EPERM => Self::Denied,
            libc::EXDEV => Self::Escape,
            #[cfg(target_os = "macos")]
            libc::ENOTCAPABLE => Self::Escape,
            libc::ELOOP => Self::Symlink,
            libc::EAGAIN => Self::Changed,
            libc::ENOMEM | libc::EMFILE | libc::ENFILE => Self::Limit,
            _ => Self::Io(errno),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolver {
    Openat2,
    DarwinBeneath,
    Stepwise,
}

/// Evidence of kernel confinement, never inferred from inode/ctime samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guarantee {
    Openat2,
    LandlockReadLayer,
    DarwinBeneath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadScope {
    StageAOnly,
    AllStages(Guarantee),
}

/// Thread-local authority. B3 may upgrade only after restrict_reads succeeds.
/// A public Resolver value by itself never grants permission to read content.
pub struct Access {
    backend: Resolver,
    guarantee: Option<Guarantee>,
    #[cfg(target_os = "macos")]
    darwin: macos::DarwinCaps,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Access {
    pub fn stage_a_only() -> Self {
        Self {
            backend: Resolver::Stepwise,
            guarantee: None,
            #[cfg(target_os = "macos")]
            darwin: macos::DarwinCaps::default(),
            _thread: std::marker::PhantomData,
        }
    }

    pub fn probe(meter: &mut Meter) -> Result<Self, ReadError> {
        let mut access = Self::stage_a_only();
        access.backend = resolver(meter)?;
        if access.backend == Resolver::Openat2 {
            access.guarantee = Some(Guarantee::Openat2);
        }
        // Darwin requires B2's validated fixture fd; absent means stage A only.
        Ok(access)
    }

    pub fn guarantee(&self) -> Option<Guarantee> {
        self.guarantee
    }

    pub fn scope(&self) -> ReadScope {
        self.guarantee
            .map_or(ReadScope::StageAOnly, ReadScope::AllStages)
    }

    fn full(&self) -> Result<(), ReadError> {
        self.guarantee.ok_or(ReadError::StageAOnly).map(|_| ())
    }

    /// B3 hook; false by default, no environment/config switch can enable it.
    ///
    /// # Safety
    /// The calling thread must have successfully installed READ_FILE|READ_DIR
    /// Landlock rules for exactly the selected roots, before content opens.
    /// Do not call on ABI detection, write-only rules, or a failed installation.
    #[cfg(target_os = "linux")]
    pub unsafe fn landlock_reads_installed(&mut self) {
        if self.guarantee.is_none() {
            self.guarantee = Some(Guarantee::LandlockReadLayer);
        }
    }
}

/// Closed read set for discovery and stage A. No caller-supplied path, ref,
/// config, object, index, listing or worktree data can pass this capability.
#[derive(Clone, Copy, Debug)]
pub enum StageAFile {
    GitPointer,
    CommonDir,
    Head,
    MergeHead,
    CherryPickHead,
    RevertHead,
    BisectLog,
    RebaseMergeHeadName,
    RebaseApplyHeadName,
}

impl StageAFile {
    fn path(self) -> &'static [u8] {
        match self {
            Self::GitPointer => b".git",
            Self::CommonDir => b"commondir",
            Self::Head => b"HEAD",
            Self::MergeHead => b"MERGE_HEAD",
            Self::CherryPickHead => b"CHERRY_PICK_HEAD",
            Self::RevertHead => b"REVERT_HEAD",
            Self::BisectLog => b"BISECT_LOG",
            Self::RebaseMergeHeadName => b"rebase-merge/head-name",
            Self::RebaseApplyHeadName => b"rebase-apply/head-name",
        }
    }
}

pub fn read_stage_a(
    root: &Root,
    file: StageAFile,
    access: &Access,
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    read_inner(
        root,
        file.path(),
        ReadCap {
            bytes: 65_536,
            single_link: true,
        },
        access,
        meter,
    )
}

/// Fixed discovery/operation directories; the returned Root grants no listing
/// or arbitrary reads without a separate full Access.
#[derive(Clone, Copy, Debug)]
pub enum StageADirectory {
    Git,
    RebaseMerge,
    RebaseApply,
}

pub fn directory_stage_a(
    root: &Root,
    dir: StageADirectory,
    access: &Access,
    meter: &mut Meter,
) -> Result<Root, ReadError> {
    let path: &[u8] = match dir {
        StageADirectory::Git => b".git",
        StageADirectory::RebaseMerge => b"rebase-merge",
        StageADirectory::RebaseApply => b"rebase-apply",
    };
    let Opened { fd, identity, .. } = resolve(root, path, access, true, false, meter)?;
    Ok(Root { fd, identity })
}

/// Selected once, before repository acquisition. An individual denied open
/// never changes this choice. B3 calls this only under the installed protection.
pub fn resolver(meter: &mut Meter) -> Result<Resolver, ReadError> {
    static SELECTED: ResolverChoice = ResolverChoice(std::sync::OnceLock::new());
    SELECTED.get(meter)
}

#[derive(Default)]
pub struct ResolverChoice(std::sync::OnceLock<Result<Resolver, ReadError>>);

impl ResolverChoice {
    pub fn get(&self, meter: &mut Meter) -> Result<Resolver, ReadError> {
        #[cfg(target_os = "linux")]
        {
            *self.0.get_or_init(|| linux::probe(meter))
        }
        #[cfg(not(target_os = "linux"))]
        {
            meter.check()?;
            *self.0.get_or_init(|| Ok(Resolver::Stepwise))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadCap {
    pub bytes: u64,
    pub single_link: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DiscoveryQuery {
    pub home_component: Option<u16>,
    pub unique: bool,
}

pub struct Discovery {
    pub cwd: Root,
    /// Oldest to newest, at most 32; never reopen ".." for discovery.
    pub ancestors: Vec<Root>,
    pub logical: bool,
    pub query: DiscoveryQuery,
}

struct Fd {
    fd: OwnedFd,
    _lease: Lease,
}
impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mount: [u64; 2],
}

pub struct Root {
    fd: Fd,
    identity: Identity,
}
impl Root {
    pub fn device(&self) -> u64 {
        self.identity.device
    }

    /// B3 ruleset installer only; do not use as an ambient IO adapter.
    #[cfg(target_os = "linux")]
    pub(crate) fn read_rule_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.fd.fd.as_fd()
    }
}
pub struct Directory {
    root: Root,
}
pub struct ReadFile {
    fd: Fd,
    metadata: libc::stat,
}
struct Opened {
    fd: Fd,
    metadata: libc::stat,
    identity: Identity,
}
fn inspect(fd: Fd, meter: &mut Meter) -> Result<Opened, ReadError> {
    let metadata = stat(fd.as_raw_fd(), meter)?;
    let identity = identity_from(fd.as_raw_fd(), &metadata, meter)?;
    Ok(Opened {
        fd,
        metadata,
        identity,
    })
}
pub struct Listing {
    pub names: Vec<Vec<u8>>,
    pub complete: bool,
}

pub fn acquire(
    cwd: &[u8],
    query: DiscoveryQuery,
    meter: &mut Meter,
) -> Result<Discovery, ReadError> {
    let previous = meter.phase;
    meter.phase = Phase::Acquisition;
    let result = walk::acquire(cwd, query, meter);
    meter.phase = previous;
    result
}

pub fn resolve_with(
    root: &Root,
    path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<ReadFile, ReadError> {
    access.full()?;
    resolve_file(root, path, access, false, meter)
}

fn resolve_file(
    root: &Root,
    path: &[u8],
    access: &Access,
    single_link: bool,
    meter: &mut Meter,
) -> Result<ReadFile, ReadError> {
    let Opened { fd, metadata, .. } = resolve(root, path, access, false, single_link, meter)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(ReadError::Special);
    }
    Ok(ReadFile { fd, metadata })
}

fn resolve(
    root: &Root,
    path: &[u8],
    access: &Access,
    is_dir: bool,
    single_link: bool,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    relative(path)?;
    let fd = match access.backend {
        #[cfg(target_os = "linux")]
        Resolver::Openat2 => inspect(linux::open(root, path, is_dir, meter)?, meter)?,
        Resolver::Stepwise | Resolver::DarwinBeneath => {
            walk::resolve(root, path, is_dir, access, single_link, meter)?
        }
        #[cfg(not(target_os = "linux"))]
        Resolver::Openat2 => return Err(ReadError::Denied),
    };
    let found = fd.identity;
    if found.mount != root.identity.mount || found.device != root.identity.device {
        return Err(ReadError::Escape);
    }
    Ok(fd)
}

pub fn read(
    root: &Root,
    relative: &[u8],
    cap: ReadCap,
    access: &Access,
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    read_with(root, relative, cap, access, meter)
}

pub fn read_with(
    root: &Root,
    relative: &[u8],
    cap: ReadCap,
    access: &Access,
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    access.full()?;
    read_inner(root, relative, cap, access, meter)
}

fn read_inner(
    root: &Root,
    relative: &[u8],
    cap: ReadCap,
    access: &Access,
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    let capacity = usize::try_from(cap.bytes.checked_add(1).ok_or(ReadError::Limit)?)
        .map_err(|_| ReadError::Limit)?;
    // Reject impossible requests before path allocation or filesystem access.
    if capacity as u64 > meter.byte_limit || capacity as u64 > meter.allocation_limit {
        return Err(ReadError::Limit);
    }
    let file = resolve_file(root, relative, access, cap.single_link, meter)?;
    file.read(cap, meter)
}

impl ReadFile {
    pub fn read(self, cap: ReadCap, meter: &mut Meter) -> Result<Vec<u8>, ReadError> {
        if cap.single_link && self.metadata.st_nlink != 1 {
            return Err(ReadError::Special);
        }
        let capacity = usize::try_from(cap.bytes.checked_add(1).ok_or(ReadError::Limit)?)
            .map_err(|_| ReadError::Limit)?;
        if self.metadata.st_size < 0 || self.metadata.st_size as u64 > cap.bytes {
            return Err(ReadError::Limit);
        }
        meter.read_capacity(capacity)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ReadError::Limit)?;
        bytes.resize(capacity, 0);
        let mut used = 0;
        while used < capacity {
            let size = (capacity - used).min(READ_CHUNK);
            meter.event("before_read");
            let count = retry(meter, Op::Read, || {
                // SAFETY: owned readable fd and a writable in-bounds slice.
                unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        bytes[used..used + size].as_mut_ptr().cast(),
                        size,
                    )
                }
            })? as usize;
            meter.returned_bytes(count);
            used += count;
            if count == 0 {
                break;
            }
        }
        if used as u64 > cap.bytes {
            return Err(ReadError::Limit);
        }
        bytes.truncate(used);
        Ok(bytes)
    }
}

pub fn directory(
    root: &Root,
    relative: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<Directory, ReadError> {
    directory_with(root, relative, access, meter)
}

pub fn directory_with(
    root: &Root,
    relative: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<Directory, ReadError> {
    access.full()?;
    let Opened { fd, identity, .. } = resolve(root, relative, access, true, false, meter)?;
    Ok(Directory {
        root: Root { fd, identity },
    })
}

/// Raw backend differential fixtures only. Never compiled into the worker.
#[cfg(test)]
pub fn unchecked_backend_for_test(backend: Resolver) -> Access {
    let mut access = Access::stage_a_only();
    access.backend = backend;
    access.guarantee = Some(Guarantee::Openat2);
    access
}

pub fn entries(dir: &Directory, raw_limit: u32, meter: &mut Meter) -> Result<Listing, ReadError> {
    #[cfg(target_os = "linux")]
    {
        linux::entries(dir, raw_limit, meter)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir, raw_limit, meter);
        Err(ReadError::Denied)
    }
}

fn relative(path: &[u8]) -> Result<(), ReadError> {
    if path.starts_with(b"/") || path.contains(&0) {
        return Err(ReadError::Escape);
    }
    if path.is_empty() {
        return Err(ReadError::Missing);
    }
    if path.len() > 65_536 {
        return Err(ReadError::Limit);
    }
    Ok(())
}

fn cstring(path: &[u8], meter: &mut Meter) -> Result<CString, ReadError> {
    meter.allocation(path.len().checked_add(1).ok_or(ReadError::Limit)?)?;
    CString::new(path).map_err(|_| ReadError::Escape)
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn retry(meter: &mut Meter, op: Op, mut call: impl FnMut() -> isize) -> Result<isize, ReadError> {
    for attempt in 0..=8 {
        meter.charge(op)?;
        let result = call();
        if result >= 0 {
            return Ok(result);
        }
        let error = errno();
        if error != libc::EINTR {
            return Err(ReadError::errno(error));
        }
        if attempt == 8 {
            return Err(ReadError::Changed);
        }
        meter.charge(Op::Retry)?;
    }
    unreachable!()
}

fn openat(
    parent: RawFd,
    name: &std::ffi::CStr,
    flags: i32,
    meter: &mut Meter,
) -> Result<Fd, ReadError> {
    let lease = meter.lease()?;
    let fd = retry(meter, Op::Open, || {
        // SAFETY: valid C string; no create flags, and parent stays alive.
        unsafe { libc::openat(parent, name.as_ptr(), flags) as isize }
    })? as RawFd;
    Ok(Fd {
        // SAFETY: successful open yields a fresh, uniquely owned descriptor.
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        _lease: lease,
    })
}

fn stat(fd: RawFd, meter: &mut Meter) -> Result<libc::stat, ReadError> {
    // SAFETY: stat is a plain C output record.
    let mut out = unsafe { std::mem::zeroed() };
    retry(meter, Op::Stat, || {
        // SAFETY: live descriptor and writable output record.
        unsafe { libc::fstat(fd, &mut out) as isize }
    })?;
    Ok(out)
}

fn identity(fd: RawFd, meter: &mut Meter) -> Result<Identity, ReadError> {
    let metadata = stat(fd, meter)?;
    identity_from(fd, &metadata, meter)
}

fn identity_from(
    fd: RawFd,
    metadata: &libc::stat,
    meter: &mut Meter,
) -> Result<Identity, ReadError> {
    #[cfg(target_os = "linux")]
    let mount = linux::mount(fd, meter)?;
    #[cfg(not(target_os = "linux"))]
    let mount = {
        // B2 adds separately probed Darwin flags; the shared fallback never
        // assumes that a BENEATH flag enforces mount identity.
        // SAFETY: fstatfs is a plain C output record.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        retry(meter, Op::Filesystem, || {
            // SAFETY: live descriptor and writable output record.
            unsafe { libc::fstatfs(fd, &mut fs) as isize }
        })?;
        // SAFETY: Darwin fsid_t is the UAPI's two i32 words; libc keeps
        // these fields private. Transmute also checks the exact size.
        let words: [i32; 2] = unsafe { std::mem::transmute(fs.f_fsid) };
        [words[0] as u32 as u64, words[1] as u32 as u64]
    };
    #[cfg(target_os = "linux")]
    let device = metadata.st_dev;
    #[cfg(not(target_os = "linux"))]
    let device = metadata.st_dev as u64;
    Ok(Identity {
        device,
        inode: metadata.st_ino,
        mount,
    })
}

#[cfg(all(test, target_os = "linux"))]
pub fn probe_for_test(meter: &mut Meter) -> Result<Resolver, ReadError> {
    linux::probe_for_test(meter)
}
