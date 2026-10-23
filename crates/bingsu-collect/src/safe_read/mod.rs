//! Descriptor capabilities for hostile repository input. Not wired into the
//! product worker until its repository sandbox is installed.
//!
//! Without kernel confinement, stage A opens only fixed, single components
//! with O_NOFOLLOW from held, typed directories. Symlink means unknown, never
//! a general walk. This reduced mode is NOT race-free: a held directory can
//! move before its next fixed child is opened. Zero outside reads under rename
//! races is an acceptance criterion only when a kernel guarantee exists.
//! Discovery ancestors grant listing only; content roots require selection.
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use crate::meter::{Lease, Meter, Op, PathAllocation, Phase, READ_CHUNK};
// Compatibility spelling for B1 callers; the wire query is now the sole type.
pub use bingsu_core::collection::path_facts::PathQuery as DiscoveryQuery;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
mod walk;
mod worktree;
pub use worktree::WorktreeStats;
#[cfg(target_os = "macos")]
mod bulk;

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
        Self::probe_with(&SELECTED, meter)
    }

    pub fn probe_with(choice: &ResolverChoice, meter: &mut Meter) -> Result<Self, ReadError> {
        let mut access = Self::stage_a_only();
        access.backend = choice.get(meter)?;
        if access.backend == Resolver::Openat2 {
            access.guarantee = Some(Guarantee::Openat2);
        }
        // Darwin requires B2's validated fixture fd; absent means stage A only.
        Ok(access)
    }

    /// Called after stage A and names-only discovery. Consuming Discovery in
    /// root selection has already closed every unselected ancestor. C5 supplies
    /// the selected worktree/gitdir/commondir, or cwd alone outside a repository.
    #[cfg(target_os = "linux")]
    pub fn restrict_to(&mut self, roots: &[&Root], meter: &mut Meter) -> Result<(), ReadError> {
        meter.check()?;
        // Never let the process-wide probe first run after read confinement.
        resolver(meter)?;
        let fds: Vec<_> = roots.iter().map(|root| root.read_rule_fd()).collect();
        let proof = crate::landlock::restrict_reads(&fds)
            .map_err(|error| ReadError::errno(error.raw_os_error().unwrap_or(libc::EACCES)))?;
        self.landlock_reads_installed(proof);
        Ok(())
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

    /// B3 hook; only landlock's successful read-layer installer can mint proof.
    /// Both proof and Access stay on the installing thread. Default is false.
    #[cfg(target_os = "linux")]
    pub fn landlock_reads_installed(&mut self, _proof: crate::landlock::ReadLayerInstalled) {
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
    let operation = match file {
        StageAFile::RebaseMergeHeadName => Some(StageADirectory::RebaseMerge),
        StageAFile::RebaseApplyHeadName => Some(StageADirectory::RebaseApply),
        _ => None,
    };
    if access.guarantee().is_none() {
        if let Some(dir) = operation {
            return directory_stage_a(root, dir, access, meter)?.read(file, access, meter);
        }
        return read_stage_a_component(root, file.path(), meter);
    }
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

fn read_stage_a_component(
    root: &Root,
    name: &[u8],
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    let Opened { fd, metadata, .. } = walk::one_component(root, name, false, meter)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(ReadError::Special);
    }
    ReadFile { fd, metadata }.read(
        ReadCap {
            bytes: 65_536,
            single_link: true,
        },
        meter,
    )
}

/// Fixed discovery/operation directories. These cannot become content Roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageADirectory {
    Git,
    RebaseMerge,
    RebaseApply,
}

pub struct StageADir<'a> {
    root: Root,
    selected: &'a Root,
    kind: StageADirectory,
}

impl StageADir<'_> {
    pub fn read(
        &self,
        file: StageAFile,
        access: &Access,
        meter: &mut Meter,
    ) -> Result<Vec<u8>, ReadError> {
        if access.guarantee().is_some() {
            // A moved held child must never become a new confinement root.
            let prefix = match (self.kind, file) {
                (StageADirectory::Git, _) => b".git/".as_slice(),
                (StageADirectory::RebaseMerge, StageAFile::RebaseMergeHeadName)
                | (StageADirectory::RebaseApply, StageAFile::RebaseApplyHeadName) => b"".as_slice(),
                _ => return Err(ReadError::Denied),
            };
            let size = prefix.len() + file.path().len();
            meter.allocation(size)?;
            let mut path = Vec::new();
            path.try_reserve_exact(size).map_err(|_| ReadError::Limit)?;
            path.extend_from_slice(prefix);
            path.extend_from_slice(file.path());
            return read_inner(
                self.selected,
                &path,
                ReadCap {
                    bytes: 65_536,
                    single_link: true,
                },
                access,
                meter,
            );
        }
        let name = match (self.kind, file) {
            (StageADirectory::RebaseMerge, StageAFile::RebaseMergeHeadName)
            | (StageADirectory::RebaseApply, StageAFile::RebaseApplyHeadName) => {
                b"head-name".as_slice()
            }
            (StageADirectory::Git, _) => return read_stage_a(&self.root, file, access, meter),
            _ => return Err(ReadError::Denied),
        };
        read_stage_a_component(&self.root, name, meter)
    }
}

pub fn directory_stage_a<'a>(
    root: &'a Root,
    dir: StageADirectory,
    access: &Access,
    meter: &mut Meter,
) -> Result<StageADir<'a>, ReadError> {
    let path: &[u8] = match dir {
        StageADirectory::Git => b".git",
        StageADirectory::RebaseMerge => b"rebase-merge",
        StageADirectory::RebaseApply => b"rebase-apply",
    };
    let Opened { fd, identity, .. } = if access.guarantee().is_none() {
        walk::one_component(root, path, true, meter)?
    } else {
        resolve(root, path, access, true, false, meter)?
    };
    Ok(StageADir {
        root: Root { fd, identity },
        selected: root,
        kind: dir,
    })
}

/// Selected once, before repository acquisition. An individual denied open
/// never changes this choice. B3 calls this only under the installed protection.
pub fn resolver(meter: &mut Meter) -> Result<Resolver, ReadError> {
    SELECTED.get(meter)
}

static SELECTED: ResolverChoice = ResolverChoice(std::sync::OnceLock::new());

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

pub struct Discovery {
    cwd: Root,
    /// Oldest to newest, at most 32; never reopen ".." for discovery.
    ancestors: Vec<AncestorDir>,
    logical: bool,
    query: DiscoveryQuery,
    slash: Identity,
}

/// Names only: no conversion, raw fd, stage-A or content-read API.
pub struct AncestorDir {
    root: Root,
}

impl AncestorDir {
    pub fn entries(&self, raw_limit: u32, meter: &mut Meter) -> Result<Listing, ReadError> {
        entries_root(&self.root, raw_limit.min(256), meter)
    }
}

impl Discovery {
    pub fn ancestors(&self) -> &[AncestorDir] {
        &self.ancestors
    }
    pub fn logical(&self) -> bool {
        self.logical
    }
    pub fn query(&self) -> DiscoveryQuery {
        self.query
    }

    fn validate(&self, root: &Root) -> Result<(), ReadError> {
        if root.identity == self.slash {
            return Err(ReadError::Escape);
        }
        Ok(())
    }

    /// The request's cwd is the only content root outside a repository.
    pub fn select_cwd(self) -> Result<Root, ReadError> {
        self.validate(&self.cwd)?;
        Ok(self.cwd)
    }

    /// Select an already-held repository ancestor, never an arbitrary read
    /// root. C5 still parses a gitfile and applies repository trust policy.
    pub fn select_worktree(
        mut self,
        levels: usize,
        access: &Access,
        meter: &mut Meter,
    ) -> Result<Root, ReadError> {
        let root = if levels == 0 {
            &self.cwd
        } else {
            &self
                .ancestors
                .get(
                    self.ancestors
                        .len()
                        .checked_sub(levels)
                        .ok_or(ReadError::Escape)?,
                )
                .ok_or(ReadError::Escape)?
                .root
        };
        self.validate(root)?;
        same_mount(root.identity, self.cwd.identity)?;
        let marker = if access.guarantee().is_none() {
            walk::one_component(root, b".git", false, meter)?
        } else {
            match resolve(root, b".git", access, true, false, meter) {
                Ok(dir) => dir,
                Err(ReadError::Missing) => resolve(root, b".git", access, false, true, meter)?,
                Err(error) => return Err(error),
            }
        };
        let kind = marker.metadata.st_mode & libc::S_IFMT;
        if kind != libc::S_IFDIR && (kind != libc::S_IFREG || marker.metadata.st_nlink != 1) {
            return Err(ReadError::Special);
        }
        if levels == 0 {
            Ok(self.cwd)
        } else {
            Ok(self
                .ancestors
                .swap_remove(self.ancestors.len() - levels)
                .root)
        }
    }

    /// For an absolute gitdir/commondir pointer acquired separately by C5.
    /// Only this directory, never its parents, becomes a content capability.
    pub fn select_metadata(self, anchor: &Root, meter: &mut Meter) -> Result<Root, ReadError> {
        self.validate(&self.cwd)?;
        same_mount(self.cwd.identity, anchor.identity)?;
        let metadata = stat(self.cwd.fd.as_raw_fd(), meter)?;
        // SAFETY: reads the current process identity only.
        if metadata.st_uid != unsafe { libc::geteuid() } {
            return Err(ReadError::Denied);
        }
        Ok(self.cwd)
    }

    #[cfg(test)]
    pub fn unchecked_cwd_for_test(self) -> Root {
        self.cwd
    }
}

fn same_mount(found: Identity, root: Identity) -> Result<(), ReadError> {
    if found.device != root.device || found.mount != root.mount {
        return Err(ReadError::Escape);
    }
    Ok(())
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
    /// Observation only. No access(2) fallback if the exact query is unavailable.
    #[cfg(target_os = "linux")]
    pub fn readonly(&self, meter: &mut Meter) -> Result<Option<bool>, ReadError> {
        meter.charge(Op::Readonly)?;
        // SAFETY: held directory and fixed relative dot; no object is created.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        readonly_status(if rc == 0 { Ok(()) } else { Err(errno()) })
    }

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

/// One-shot worktree observation. Bulk callers use WorktreeStats and finish
/// the directory validation before publishing any observations.
pub fn worktree_metadata(
    root: &Root,
    path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<libc::stat, ReadError> {
    let mut stats = WorktreeStats::default();
    let metadata = stats.metadata(root, path, access, meter)?;
    stats.finish(root, access, meter)?;
    Ok(metadata)
}

/// No-follow regular-file open for raw worktree hashing. The final root-based
/// open remains atomic on the fast backends; stepwise needs Landlock as before.
pub fn resolve_nofollow(
    root: &Root,
    path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<ReadFile, ReadError> {
    let opened = resolve_worktree(root, path, false, access, meter)?;
    if opened.metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(ReadError::Special);
    }
    Ok(ReadFile {
        fd: opened.fd,
        metadata: opened.metadata,
    })
}

/// Index paths must never resolve through any symlink, even within the root.
/// General repository reads continue to use `resolve` and allow confined links.
fn resolve_worktree(
    root: &Root,
    path: &[u8],
    is_dir: bool,
    access: &Access,
    meter: &mut Meter,
) -> Result<Opened, ReadError> {
    access.full()?;
    relative(path)?;
    if path.split(|b| *b == b'/').any(|p| p == b"..") {
        return Err(ReadError::Escape);
    }
    let opened = match access.backend {
        #[cfg(target_os = "linux")]
        Resolver::Openat2 => {
            linux::open_nofollow(root, path, is_dir, meter).and_then(|fd| inspect(fd, meter))
        }
        Resolver::Stepwise | Resolver::DarwinBeneath => {
            walk::resolve_nofollow(root, path, is_dir, access, meter)
        }
        #[cfg(not(target_os = "linux"))]
        Resolver::Openat2 => Err(ReadError::Denied),
    }
    .map_err(|error| match error {
        ReadError::Symlink => ReadError::Missing,
        other => other,
    })?;
    same_mount(opened.identity, root.identity)?;
    Ok(opened)
}

#[cfg(target_os = "macos")]
fn worktree_directory(
    root: &Root,
    path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<Directory, ReadError> {
    let Opened { fd, identity, .. } = resolve_worktree(root, path, true, access, meter)?;
    Ok(Directory {
        root: Root { fd, identity },
    })
}

/// Identity and content-change check, using full-width kernel fields. This is
/// not an ancestry guarantee; that comes from Access and the resolver.
pub fn same_worktree_stat(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
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
    /// Metadata of the already validated, held regular file; never reopens a path.
    pub fn metadata(&self) -> libc::stat {
        self.metadata
    }

    pub fn read(self, cap: ReadCap, meter: &mut Meter) -> Result<Vec<u8>, ReadError> {
        self.read_with_charge(cap, meter, |capacity, meter| meter.read_capacity(capacity))
    }

    pub(crate) fn read_worktree(
        self,
        cap: ReadCap,
        meter: &mut Meter,
    ) -> Result<Vec<u8>, ReadError> {
        let size = usize::try_from(cap.bytes).map_err(|_| ReadError::Limit)?;
        if self.metadata.st_size < 0 || self.metadata.st_size as u64 != cap.bytes {
            return Err(ReadError::Changed);
        }
        // Caller reserved size bytes of live scratch and WorktreeReadBytes.
        // The growth probe is a stack byte, allowing an exact OBJECT_ALLOC blob.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| ReadError::Limit)?;
        bytes.resize(size, 0);
        let mut used = 0;
        while used < size {
            meter.event("before_read");
            let chunk = (size - used).min(READ_CHUNK);
            let n = retry(meter, Op::Read, || {
                // SAFETY: validated readable fd and bounded writable slice.
                unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        bytes[used..used + chunk].as_mut_ptr().cast(),
                        chunk,
                    )
                }
            })? as usize;
            meter.returned_bytes(n);
            if n == 0 {
                return Err(ReadError::Changed);
            }
            used += n;
        }
        let mut probe = 0u8;
        meter.event("before_read");
        let n = retry(meter, Op::Read, || {
            // SAFETY: held fd, one writable stack byte.
            unsafe { libc::read(self.fd.as_raw_fd(), (&mut probe as *mut u8).cast(), 1) }
        })?;
        meter.returned_bytes(n as usize);
        if n != 0 {
            return Err(ReadError::Limit);
        }
        if !same_worktree_stat(&self.metadata, &stat(self.fd.as_raw_fd(), meter)?) {
            return Err(ReadError::Changed);
        }
        Ok(bytes)
    }

    /// The repository adapter has checked the same-fd size against its file
    /// cap and charged its own axis before reaching this allocation. The extra
    /// byte detects growth; it is not worktree content or another file byte.
    pub(crate) fn read_reserved(
        self,
        cap: ReadCap,
        meter: &mut Meter,
    ) -> Result<Vec<u8>, ReadError> {
        self.read_with_charge(cap, meter, |capacity, meter| {
            meter.check()?;
            meter.record_allocation(capacity);
            Ok(())
        })
    }

    fn read_with_charge(
        &self,
        cap: ReadCap,
        meter: &mut Meter,
        charge: impl FnOnce(usize, &mut Meter) -> Result<(), ReadError>,
    ) -> Result<Vec<u8>, ReadError> {
        if cap.single_link && self.metadata.st_nlink != 1 {
            return Err(ReadError::Special);
        }
        let capacity = usize::try_from(cap.bytes.checked_add(1).ok_or(ReadError::Limit)?)
            .map_err(|_| ReadError::Limit)?;
        if self.metadata.st_size < 0 || self.metadata.st_size as u64 > cap.bytes {
            return Err(ReadError::Limit);
        }
        charge(capacity, meter)?;
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

/// Count every raw dirent (including `.` and `..`) against the cap before allocating names.
/// Names omit those two entries regardless of order; complete requires observing EOF
/// before the cap is reached, so an exact-cap listing remains incomplete.
pub fn entries(dir: &Directory, raw_limit: u32, meter: &mut Meter) -> Result<Listing, ReadError> {
    entries_root(&dir.root, raw_limit, meter)
}

fn entries_root(root: &Root, raw_limit: u32, meter: &mut Meter) -> Result<Listing, ReadError> {
    #[cfg(target_os = "linux")]
    {
        linux::entries(root, raw_limit, meter)
    }
    #[cfg(target_os = "macos")]
    {
        macos::entries(root, raw_limit, meter)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (root, raw_limit, meter);
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

struct PathCString {
    value: CString,
    _allocation: PathAllocation,
}
impl std::ops::Deref for PathCString {
    type Target = std::ffi::CStr;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
fn cstring(path: &[u8], meter: &mut Meter) -> Result<PathCString, ReadError> {
    let mut allocation = meter.path_allocation();
    allocation.reserve(path.len().checked_add(1).ok_or(ReadError::Limit)?, meter)?;
    Ok(PathCString {
        value: CString::new(path).map_err(|_| ReadError::Escape)?,
        _allocation: allocation,
    })
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn retry(meter: &mut Meter, op: Op, mut call: impl FnMut() -> isize) -> Result<isize, ReadError> {
    for attempt in 0..=8 {
        meter.charge(op)?;
        meter.event("before_safe_syscall");
        let result = call();
        let saved_errno = errno();
        meter.event("after_safe_syscall");
        if result >= 0 {
            return Ok(result);
        }
        let error = saved_errno;
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

#[cfg(any(test, target_os = "linux"))]
fn readonly_status(result: Result<(), i32>) -> Result<Option<bool>, ReadError> {
    match result {
        Ok(()) => Ok(Some(false)),
        Err(libc::ENOSYS | libc::EPERM) => Ok(None),
        Err(libc::EACCES | libc::EROFS) => Ok(Some(true)),
        Err(error) => Err(ReadError::errno(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: CString의 선예약 또는 drop 시 live 예약 반환을 생략하는 것.
    #[test]
    fn path_cstring_reservation_is_live_and_precharged() {
        let mut meter = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
        meter.allocation(17).unwrap();
        let baseline = meter.live_allocated();
        meter.allocation_limit = baseline + 5;
        for _ in 0..4096 {
            let name = cstring(b"name", &mut meter).unwrap();
            assert_eq!(name.to_bytes(), b"name");
            assert_eq!(meter.live_allocated(), baseline + 5);
            assert_eq!(cstring(b"x", &mut meter).err(), Some(ReadError::Limit));
            drop(name);
            assert_eq!(meter.live_allocated(), baseline);
        }
        assert_eq!(cstring(b"bad\0", &mut meter).err(), Some(ReadError::Escape));
        assert_eq!(meter.live_allocated(), baseline);
    }

    // 이것을 실패시키는 것: 미지원 readonly를 true/false로 만들거나 권한 거부를 쓰기 가능으로 보고하는 것.
    #[test]
    fn readonly_observation_preserves_unknown_and_errors() {
        assert_eq!(readonly_status(Ok(())), Ok(Some(false)));
        for error in [libc::ENOSYS, libc::EPERM] {
            assert_eq!(readonly_status(Err(error)), Ok(None));
        }
        for error in [libc::EACCES, libc::EROFS] {
            assert_eq!(readonly_status(Err(error)), Ok(Some(true)));
        }
        assert_eq!(readonly_status(Err(libc::ENOENT)), Err(ReadError::Missing));
        assert_eq!(
            readonly_status(Err(libc::EIO)),
            Err(ReadError::Io(libc::EIO))
        );
    }
}
