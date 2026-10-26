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
    rc::Rc,
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
    /// Reciprocal linked-worktree registration, used only during discovery.
    WorktreePointer,
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
            Self::WorktreePointer => b"gitdir",
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
    resolve_with(root, file.path(), access, meter)?.read_metadata(65_536, meter)
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
    ReadFile { fd, metadata }.read_metadata(65_536, meter)
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
            let mut scratch = meter.path_allocation();
            scratch.reserve(size, meter)?;
            let mut path = Vec::new();
            path.try_reserve_exact(size).map_err(|_| ReadError::Limit)?;
            path.extend_from_slice(prefix);
            path.extend_from_slice(file.path());
            return resolve_with(self.selected, &path, access, meter)?.read_metadata(65_536, meter);
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
    cwd: Rc<Root>,
    components: usize,
    repo_level: Option<usize>,
    in_repo: Option<bool>,
    /// Oldest to newest, at most 32; never reopen ".." for discovery.
    ancestors: Vec<AncestorDir>,
    logical: bool,
    query: DiscoveryQuery,
    slash: Identity,
    _allocation: PathAllocation,
}

/// Names only: no conversion, raw fd, stage-A or content-read API.
pub struct AncestorDir {
    root: Rc<Root>,
    listed: std::cell::Cell<bool>,
}

impl AncestorDir {
    pub fn entries(&self, raw_limit: u32, meter: &mut Meter) -> Result<Listing, ReadError> {
        if self.listed.replace(true) {
            return Err(ReadError::Changed);
        }
        entries_root(&self.root, raw_limit.min(256), meter)
    }
}

impl AncestorDir {
    pub(crate) fn siblings(&self, bytes: usize, meter: &mut Meter) -> Result<Listing, ReadError> {
        if self.listed.replace(true) {
            return Err(ReadError::Changed);
        }
        entries_bounded(&self.root, 256, Some(bytes), meter)
    }
}

impl Discovery {
    pub(crate) fn path_binding(&self) -> (usize, Option<usize>, Option<bool>) {
        (self.components, self.repo_level, self.in_repo)
    }

    pub(crate) fn discard_names(&mut self) {
        self.ancestors.clear();
    }

    /// Names are optional; selected cwd/worktree capabilities remain shared.
    /// Missing ancestor sets make PathFacts partial and use abbrev, without
    /// moving enumeration before stage A or increasing the descriptor budget.
    pub(crate) fn spare_fds(&mut self, needed: u32, meter: &mut Meter) {
        if meter.live_fds() > crate::meter::LIVE_FDS.saturating_sub(needed) {
            self.discard_names();
            meter.event("names_discarded_for_fds");
        }
    }

    pub(crate) fn readonly(&self, meter: &mut Meter) -> Result<Option<bool>, ReadError> {
        self.cwd.readonly(meter)
    }

    /// Reacquiring an ancestor for gitfile proof must not reset the selected
    /// worktree's mount boundary before the ordinary bounded marker walk.
    pub(crate) fn ancestor_repository(
        self,
        anchor: &Root,
        max_levels: usize,
        meter: &mut Meter,
    ) -> Result<(Root, Option<usize>), ReadError> {
        same_mount(self.cwd.identity, anchor.identity)?;
        self.repository(max_levels, meter)
    }

    /// Inspect only the fixed marker on held ancestors. A failed/unsafe marker
    /// is not absence. Consume discovery before any read ruleset is installed.
    pub(crate) fn repository(
        mut self,
        max_levels: usize,
        meter: &mut Meter,
    ) -> Result<(Root, Option<usize>), ReadError> {
        let (root, level) = self.retain_repository(max_levels, meter)?;
        drop(self);
        Ok((Rc::try_unwrap(root).map_err(|_| ReadError::Changed)?, level))
    }

    /// Select once, retaining names-only ancestors through the Path stage.
    /// Rc shares the already-held descriptor: no dup, open or repeated stat.
    pub(crate) fn retain_repository(
        &mut self,
        max_levels: usize,
        meter: &mut Meter,
    ) -> Result<(Rc<Root>, Option<usize>), ReadError> {
        for level in 0..=max_levels.min(32).min(self.ancestors.len()) {
            let root = if level == 0 {
                &self.cwd
            } else {
                &self.ancestors[self.ancestors.len() - level].root
            };
            if self.validate(root).is_err() {
                break;
            }
            same_mount(root.identity, self.cwd.identity)?;
            meter.event("discovery_candidate");
            let marker = match walk::one_component(root, b".git", false, meter) {
                Ok(marker) => marker,
                Err(ReadError::Missing) => continue,
                Err(error) => return Err(error),
            };
            let kind = marker.metadata.st_mode & libc::S_IFMT;
            if kind != libc::S_IFDIR && (kind != libc::S_IFREG || marker.metadata.st_nlink != 1) {
                return Err(ReadError::Special);
            }
            self.repo_level = Some(level);
            self.in_repo = Some(true);
            return Ok((Rc::clone(root), Some(level)));
        }
        self.validate(&self.cwd)?;
        // A depth cutoff or an unproved logical boundary is not absence.
        let needed = self.query.home_component.map_or(self.components, |home| {
            self.components.saturating_sub(usize::from(home) + 1)
        });
        self.in_repo = (self.logical && needed <= max_levels.min(32)).then_some(false);
        Ok((Rc::clone(&self.cwd), None))
    }

    /// External metadata pointers must be canonical, owned directories BEFORE
    /// selection. No symlink in a pointer path may redirect a shape check.
    pub(crate) fn pointer_is_logical(&self) -> bool {
        self.logical
    }

    /// No general content authority escapes while C5 verifies the reciprocal
    /// gitfile/commondir shape. The selected root is still unpublished.
    pub(crate) fn metadata_pointer(
        &self,
        file: StageAFile,
        anchor: &Root,
        meter: &mut Meter,
    ) -> Result<Vec<u8>, ReadError> {
        if !matches!(file, StageAFile::CommonDir | StageAFile::WorktreePointer) {
            return Err(ReadError::Denied);
        }
        self.validate(&self.cwd)?;
        same_mount(self.cwd.identity, anchor.identity)?;
        if !self.logical || !self.cwd.owned(meter)? {
            return Err(ReadError::Denied);
        }
        read_stage_a(&self.cwd, file, &Access::stage_a_only(), meter)
    }

    /// Shape validation may inspect only this fixed config before publishing
    /// a metadata root. The owner decision precedes both bytes and gix parsing;
    /// config needs the same kernel guarantee as every other general read.
    pub(crate) fn metadata_config(
        &self,
        anchor: &Root,
        access: &Access,
        meter: &mut Meter,
    ) -> Result<Vec<u8>, ReadError> {
        self.validate(&self.cwd)?;
        same_mount(self.cwd.identity, anchor.identity)?;
        if !self.logical || !self.cwd.owned(meter)? {
            return Err(ReadError::Denied);
        }
        resolve_with(&self.cwd, b"config", access, meter)?
            .read_metadata(bingsu_core::collection::budget::CONFIG_BYTES, meter)
    }

    /// A reciprocal worktree registration alone cannot authorize an arbitrary
    /// common directory. Probe fixed metadata markers, never object payloads.
    pub(crate) fn metadata_signature(
        &self,
        anchor: &Root,
        meter: &mut Meter,
    ) -> Result<(), ReadError> {
        self.validate(&self.cwd)?;
        same_mount(self.cwd.identity, anchor.identity)?;
        if !self.logical || !self.cwd.owned(meter)? {
            return Err(ReadError::Denied);
        }
        read_stage_a(&self.cwd, StageAFile::Head, &Access::stage_a_only(), meter)?;
        for name in [b"objects".as_slice(), b"refs"] {
            walk::one_component(&self.cwd, name, true, meter)?;
        }
        Ok(())
    }
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
        Rc::try_unwrap(self.cwd).map_err(|_| ReadError::Changed)
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
            Rc::try_unwrap(self.cwd).map_err(|_| ReadError::Changed)
        } else {
            Rc::try_unwrap(
                self.ancestors
                    .swap_remove(self.ancestors.len() - levels)
                    .root,
            )
            .map_err(|_| ReadError::Changed)
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
        Rc::try_unwrap(self.cwd).map_err(|_| ReadError::Changed)
    }

    #[cfg(test)]
    pub fn unchecked_cwd_for_test(self) -> Root {
        Rc::try_unwrap(self.cwd).ok().expect("exclusive test cwd")
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
    pub(crate) fn owned(&self, meter: &mut Meter) -> Result<bool, ReadError> {
        let metadata = stat(self.fd.as_raw_fd(), meter)?;
        // SAFETY: reads only the process identity; never NSS or environment.
        let owned = metadata.st_uid == unsafe { libc::geteuid() };
        meter.event(if owned {
            "owner_owned"
        } else {
            "owner_foreign"
        });
        Ok(owned)
    }

    /// Only the fixed .git child can become an in-worktree metadata root.
    /// Unlike external pointers, foreign ownership is allowed for HEAD only.
    pub(crate) fn git_directory(&self, meter: &mut Meter) -> Result<Self, ReadError> {
        let Opened { fd, identity, .. } = walk::one_component(self, b".git", true, meter)?;
        Ok(Self { fd, identity })
    }
    /// Effective-user observation on the held cwd only; never create a file.
    pub fn readonly(&self, meter: &mut Meter) -> Result<Option<bool>, ReadError> {
        meter.charge(Op::Readonly)?;
        // SAFETY: held directory and fixed relative dot; no symlink traversal.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: same held directory and fixed relative dot.
        let rc = unsafe {
            libc::faccessat(
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        let access = readonly_status(if rc == 0 { Ok(()) } else { Err(errno()) });
        meter.charge(Op::Filesystem)?;
        // SAFETY: live fd and fully writable statfs output; no pathname lookup.
        #[cfg(target_os = "linux")]
        let mut fs = unsafe { std::mem::zeroed::<libc::statfs64>() };
        #[cfg(target_os = "macos")]
        // SAFETY: statfs is a C output structure; zero is a valid initialization.
        let mut fs = unsafe { std::mem::zeroed::<libc::statfs>() };
        // fstatfs64 is the same fstatfs syscall on our 64-bit Linux targets;
        // unlike libc's GNU statfs binding, it exposes the UAPI f_flags field.
        // SAFETY: matching output layout and the same live directory fd.
        #[cfg(target_os = "linux")]
        let rc = unsafe { libc::fstatfs64(self.fd.as_raw_fd(), &mut fs) };
        #[cfg(target_os = "macos")]
        // SAFETY: matching writable output and held directory fd.
        let rc = unsafe { libc::fstatfs(self.fd.as_raw_fd(), &mut fs) };
        // Linux ST_RDONLY and Darwin MNT_RDONLY both use bit 0.
        readonly_observation(access, (rc == 0).then_some(fs.f_flags & 1 != 0))
    }

    pub fn device(&self) -> u64 {
        self.identity.device
    }

    /// The kernel's stored spelling of this held directory, without a path
    /// lookup. Darwin volumes may ignore case and Unicode normalization, so a
    /// cwd and git's recorded paths can spell one directory differently.
    #[cfg(target_os = "macos")]
    pub(crate) fn stored_path(&self, meter: &mut Meter) -> Result<Option<Vec<u8>>, ReadError> {
        let mut path = [0u8; libc::PATH_MAX as usize];
        retry(meter, Op::Stat, || {
            // SAFETY: descriptor-only query with a PATH_MAX writable buffer.
            unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) as isize }
        })?;
        let end = path.iter().position(|b| *b == 0).ok_or(ReadError::Denied)?;
        Ok(Some(path[..end].to_vec()))
    }

    /// Other kernels compare names bytewise: there is no second spelling.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn stored_path(&self, _meter: &mut Meter) -> Result<Option<Vec<u8>>, ReadError> {
        Ok(None)
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
    _allocation: Option<PathAllocation>,
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

/// Pointer acquisition rejects every symlink and checks the leaf's owner
/// before opening that directory. This is not a general content-read API.
pub(crate) fn acquire_metadata(path: &[u8], meter: &mut Meter) -> Result<Discovery, ReadError> {
    let previous = meter.phase;
    meter.phase = Phase::Acquisition;
    let result = walk::acquire_metadata(path, meter).map(|mut discovery| {
        // Pointer validation never walks these ancestors. In particular, do
        // not retain a fresh 33-fd stack at every nested submodule level.
        discovery.ancestors.clear();
        discovery
    });
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
    #[cfg(test)]
    meter.event(&format!("resolve:{}", String::from_utf8_lossy(path)));
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
    /// A bounded chunk on the already confined fd. The repository stream owns
    /// the byte reservation and never exposes this fd to a parser.
    pub(crate) fn stream_chunk(
        &self,
        bytes: &mut [u8],
        meter: &mut Meter,
    ) -> Result<usize, ReadError> {
        if bytes.is_empty() || bytes.len() > READ_CHUNK || self.metadata.st_nlink != 1 {
            return Err(ReadError::Special);
        }
        meter.event("before_read");
        let n = retry(meter, Op::Read, || {
            // SAFETY: held readable regular fd and bounded writable slice.
            unsafe { libc::read(self.fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) }
        })? as usize;
        meter.returned_bytes(n);
        Ok(n)
    }

    pub(crate) fn verify_stream(&self, meter: &mut Meter) -> Result<(), ReadError> {
        let now = stat(self.fd.as_raw_fd(), meter)?;
        if now.st_nlink != 1 || !same_worktree_stat(&self.metadata, &now) {
            return Err(ReadError::Changed);
        }
        Ok(())
    }

    /// Metadata has its own file cap and a live read reservation. It never
    /// spends the worktree content budget. Use the same inspected fd and size;
    /// the extra byte detects growth without reserving 64 KiB for every HEAD.
    pub(crate) fn read_metadata(self, cap: u64, meter: &mut Meter) -> Result<Vec<u8>, ReadError> {
        let size = u64::try_from(self.metadata.st_size).map_err(|_| ReadError::Limit)?;
        if size > cap {
            return Err(ReadError::Limit);
        }
        let capacity = usize::try_from(size.checked_add(1).ok_or(ReadError::Limit)?)
            .map_err(|_| ReadError::Limit)?;
        let mut scratch = meter.path_allocation();
        scratch.reserve(capacity, meter)?;
        let bytes = self.read_reserved(
            ReadCap {
                bytes: size,
                single_link: true,
            },
            meter,
        )?;
        if bytes.len() as u64 != size {
            return Err(ReadError::Changed);
        }
        Ok(bytes)
    }

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

/// Observe a directory entry without following its leaf. In particular, a
/// dangling symlink is present. Only the confined parent directory is opened.
pub(crate) fn has_entry(
    root: &Root,
    relative: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<bool, ReadError> {
    access.full()?;
    let split = relative
        .iter()
        .rposition(|b| *b == b'/')
        .ok_or(ReadError::Escape)?;
    let (parent, name) = (&relative[..split], &relative[split + 1..]);
    if matches!(name, b"" | b"." | b"..") {
        return Err(ReadError::Escape);
    }
    let dir = match directory(root, parent, access, meter) {
        Ok(dir) => dir,
        Err(ReadError::Missing) => return Ok(false),
        Err(error) => return Err(error),
    };
    let name = cstring(name, meter)?;
    match walk::lstat(dir.root.fd.as_raw_fd(), &name, meter) {
        Ok(_) => Ok(true),
        Err(ReadError::Missing) => Ok(false),
        Err(error) => Err(error),
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
    entries_bounded(root, raw_limit, None, meter)
}

fn entries_bounded(
    root: &Root,
    raw_limit: u32,
    bytes: Option<usize>,
    meter: &mut Meter,
) -> Result<Listing, ReadError> {
    #[cfg(target_os = "linux")]
    {
        linux::entries(root, raw_limit, bytes, meter)
    }
    #[cfg(target_os = "macos")]
    {
        macos::entries(root, raw_limit, bytes, meter)
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
    #[cfg(test)]
    meter.event(&format!("openat:{}", name.to_string_lossy()));
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

fn readonly_observation(
    access: Result<Option<bool>, ReadError>,
    mount: Option<bool>,
) -> Result<Option<bool>, ReadError> {
    match mount {
        Some(true) => Ok(Some(true)),
        Some(false) => access,
        None => Ok(None),
    }
}

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
    // 이것을 실패시키는 것: ancestor 재획득이 원래 worktree의 device/mount 경계를 초기화.
    #[test]
    fn ancestor_repository_preserves_mount_boundary() {
        use std::os::unix::ffi::OsStrExt;
        let path =
            std::env::temp_dir().join(format!("bingsu-ancestor-mount-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let path = std::fs::canonicalize(path).unwrap();
        let mut meter = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
        for device in [true, false] {
            let query = acquire(
                path.as_os_str().as_bytes(),
                DiscoveryQuery::default(),
                &mut meter,
            )
            .unwrap();
            let mut anchor = acquire(
                path.as_os_str().as_bytes(),
                DiscoveryQuery::default(),
                &mut meter,
            )
            .unwrap()
            .select_cwd()
            .unwrap();
            if device {
                anchor.identity.device ^= 1;
            } else {
                anchor.identity.mount[0] ^= 1;
            }
            let before = meter.operations();
            assert!(matches!(
                query.ancestor_repository(&anchor, 0, &mut meter),
                Err(ReadError::Escape)
            ));
            assert_eq!(meter.operations(), before);
        }
        std::fs::remove_dir(path).unwrap();
    }

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

struct Names {
    listing: Listing,
    left: Option<usize>,
}
impl Names {
    fn new(bytes: Option<usize>, meter: &Meter) -> Self {
        Self {
            listing: Listing {
                names: Vec::new(),
                complete: false,
                _allocation: bytes.map(|_| meter.path_allocation()),
            },
            left: bytes.map(|n| n.min(bingsu_core::shorten::SIBLING_STEP_MAX)),
        }
    }
    fn entry(
        &mut self,
        name: &[u8],
        live: bool,
        kind: u8,
        meter: &mut Meter,
    ) -> Result<bool, ReadError> {
        meter.raw_entry()?;
        if !live || name == b"." || name == b".." {
            return Ok(true);
        }
        if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
            return Err(ReadError::Io(libc::EIO));
        }
        // Only the names-only sibling port filters known non-directories.
        // DT_UNKNOWN is conservative evidence; never stat or follow a link.
        if self.left.is_some() && kind != libc::DT_DIR && kind != libc::DT_UNKNOWN {
            return Ok(true);
        }
        self.push(name, meter)
    }
    fn push(&mut self, name: &[u8], meter: &mut Meter) -> Result<bool, ReadError> {
        if let Some(left) = &mut self.left {
            if name.len() > bingsu_core::shorten::SIBLING_NAME_MAX || name.len() > *left {
                return Ok(false);
            }
            *left -= name.len();
        }
        let bytes = name.len() + std::mem::size_of::<Vec<u8>>();
        if let Some(allocation) = &mut self.listing._allocation {
            allocation.reserve(bytes, meter)?;
        } else {
            // Preserve the general directory API's existing accounting. E1
            // releases only its bounded, names-only per-folder scratch.
            meter.allocation(bytes)?;
        }
        self.listing
            .names
            .try_reserve_exact(1)
            .map_err(|_| ReadError::Limit)?;
        self.listing.names.push(name.to_vec());
        Ok(true)
    }
    fn finish(mut self, complete: bool) -> Listing {
        self.listing.complete = complete;
        self.listing
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;
    fn meter() -> Meter {
        Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(60))
    }
    // Fails if name/step caps happen after allocation, or scratch accumulates.
    #[test]
    fn sibling_name_and_step_limits_precede_allocation() {
        let mut m = meter();
        for _ in 0..4096 {
            let mut names = Names::new(Some(16_384), &m);
            for _ in 0..8 {
                assert!(names.push(&[b'x'; 1024], &mut m).unwrap());
            }
            let baseline = m.live_allocated();
            assert!(!names.push(b"x", &mut m).unwrap());
            assert_eq!(m.live_allocated(), baseline);
            drop(names);
            assert_eq!(m.live_allocated(), 0);
        }
        let mut names = Names::new(Some(8192), &m);
        assert!(!names.push(&[b'x'; 1025], &mut m).unwrap());
        assert_eq!(m.live_allocated(), 0);
        assert!(names.push(&[b'x'; 1023], &mut m).unwrap());
        assert!(names.push(&[b'x'; 1024], &mut m).unwrap());
        let mut names = Names::new(Some(1023), &m);
        assert!(!names.push(&[b'x'; 1024], &mut m).unwrap());
        m.allocation_limit = 0;
        assert_eq!(names.push(b"x", &mut m), Err(ReadError::Limit));
    }
    // Mount and effective access are independent observations; failure is unknown.
    #[test]
    fn readonly_mount_and_failed_observations_stay_conservative() {
        for access in [
            Ok(None),
            Ok(Some(false)),
            Ok(Some(true)),
            Err(ReadError::Denied),
        ] {
            assert_eq!(readonly_observation(access, Some(true)), Ok(Some(true)));
            assert_eq!(readonly_observation(access, None), Ok(None));
            assert_eq!(readonly_observation(access, Some(false)), access);
        }
        #[cfg(target_os = "linux")]
        assert_eq!(libc::ST_RDONLY, 1);
        #[cfg(target_os = "macos")]
        assert_eq!(libc::MNT_RDONLY, 1);
    }
}

#[cfg(test)]
mod raw_name_tests {
    use super::*;
    // A deleted slot, dot entries, files, links and unknown types all spend raw budget.
    #[test]
    fn raw_deleted_and_nonfolder_entries_count_before_filtering() {
        let mut m = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let mut names = Names::new(Some(8192), &m);
        for (name, live) in [(b".".as_slice(), true), (b"..", true), (b"", false)] {
            assert!(names.entry(name, live, libc::DT_DIR, &mut m).unwrap());
        }
        for _ in 3..256 {
            assert!(
                names
                    .entry(b"file-or-unknown", true, libc::DT_UNKNOWN, &mut m)
                    .unwrap()
            );
        }
        assert_eq!(m.counts[Phase::Content as usize].raw_entries, 256);
        for kind in [libc::DT_REG, libc::DT_LNK, libc::DT_FIFO, libc::DT_SOCK] {
            assert!(names.entry(b"not-a-folder", true, kind, &mut m).unwrap());
        }
        assert_eq!(m.counts[Phase::Content as usize].raw_entries, 260);
        assert_eq!(names.finish(false).names.len(), 253);
        let mut names = Names::new(Some(8192), &m);
        assert_eq!(
            names.entry(b"bad/name", true, libc::DT_UNKNOWN, &mut m),
            Err(ReadError::Io(libc::EIO))
        );
    }
}
