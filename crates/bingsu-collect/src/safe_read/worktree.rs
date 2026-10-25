//! Shared verified directory stack for one index-order walk. Each edge is
//! opened and mount-checked once, reused by its files and descendants, and
//! revalidated against its held parent when popped. Fds are bounded by depth.
use super::*;

struct Step {
    directory: Root,
    name: PathCString,
    listed: bool,
}

/// Observations are provisional until finish succeeds. Edge identity checks
/// detect replacement, not ABA or atomic ancestry. Content opens retain the
/// original-root atomic backend (or the Linux Landlock read layer).
#[derive(Default)]
pub struct WorktreeStats {
    stack: Vec<Step>,
    // Sorted raw prefixes whose directory open returned Missing (including
    // ENOTDIR and refused symlinks). Absence is a request-local observation;
    // later leaves and descendants must not retry it or disturb a live listing.
    missing: Vec<PathCString>,
    allocation: Option<PathAllocation>,
    root_listing: Option<Directory>,
    failed: Option<ReadError>,
}

impl WorktreeStats {
    fn held<'a>(&'a self, root: &'a Root) -> &'a Root {
        self.stack.last().map_or(root, |s| &s.directory)
    }

    // dev_t/ino_t widths differ across the supported Unix targets.
    #[allow(clippy::unnecessary_cast)]
    fn pop(&mut self, root: &Root, meter: &mut Meter) -> Result<(), ReadError> {
        let step = self.stack.pop().expect("nonempty stack");
        meter.event("before_worktree_directory_check");
        let current =
            walk::lstat(self.held(root).fd.as_raw_fd(), &step.name, meter).map_err(|e| {
                if e == ReadError::Missing {
                    ReadError::Changed
                } else {
                    e
                }
            })?;
        if current.st_dev as u64 != step.directory.identity.device
            || current.st_ino as u64 != step.directory.identity.inode
            || current.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(ReadError::Changed);
        }
        Ok(())
    }

    fn parent(
        &mut self,
        root: &Root,
        path: &[u8],
        access: &Access,
        meter: &mut Meter,
    ) -> Result<(), ReadError> {
        access.full()?;
        if let Some(error) = self.failed {
            return Err(error);
        }
        if !path.is_empty() {
            canonical(path)?;
        }
        if !self.missing.is_empty() {
            for end in path
                .iter()
                .enumerate()
                .filter_map(|(i, &b)| (b == b'/').then_some(i))
                .chain(std::iter::once(path.len()))
            {
                if self
                    .missing
                    .binary_search_by(|name| name.to_bytes().cmp(&path[..end]))
                    .is_ok()
                {
                    return Err(ReadError::Missing);
                }
            }
        }
        let common = path
            .split(|&b| b == b'/')
            .zip(&self.stack)
            .take_while(|(name, step)| *name == step.name.to_bytes())
            .count();
        while self.stack.len() > common {
            if let Err(error) = self.pop(root, meter) {
                self.failed = Some(error);
                return Err(error);
            }
        }
        for part in path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .skip(common)
        {
            meter.charge_axis(bingsu_core::collection::budget::Axis::Directories, 1)?;
            let name = cstring(part, meter)?;
            let opened = match walk::worktree_component(self.held(root), &name, true, access, meter)
            {
                Ok(opened) => opened,
                Err(ReadError::Missing | ReadError::Symlink) => {
                    let end = self
                        .stack
                        .iter()
                        .map(|step| step.name.to_bytes().len() + 1)
                        .sum::<usize>()
                        + part.len();
                    let missing = cstring(&path[..end], meter)?;
                    self.allocation
                        .get_or_insert_with(|| meter.path_allocation())
                        .reserve(std::mem::size_of::<PathCString>(), meter)?;
                    self.missing
                        .try_reserve_exact(1)
                        .map_err(|_| ReadError::Limit)?;
                    let at = self
                        .missing
                        .partition_point(|name| name.to_bytes() < missing.to_bytes());
                    self.missing.insert(at, missing);
                    return Err(ReadError::Missing);
                }
                Err(error) => return Err(error),
            };
            if self.stack.len() == self.stack.capacity() {
                self.allocation
                    .get_or_insert_with(|| meter.path_allocation())
                    .reserve(std::mem::size_of::<Step>(), meter)?;
                self.stack
                    .try_reserve_exact(1)
                    .map_err(|_| ReadError::Limit)?;
            }
            self.stack.push(Step {
                directory: Root {
                    fd: opened.fd,
                    identity: opened.identity,
                },
                name,
                listed: false,
            });
        }
        Ok(())
    }

    pub fn metadata(
        &mut self,
        root: &Root,
        path: &[u8],
        access: &Access,
        meter: &mut Meter,
    ) -> Result<libc::stat, ReadError> {
        access.full()?;
        let (parent, leaf) = split(path)?;
        self.parent(root, parent, access, meter)?;
        let held = self.held(root);
        // Reuse a bounded stack buffer: the kernel's component limit is much
        // smaller, but a hostile long name must still fail without truncation.
        if leaf.len() > 4096 {
            return Err(ReadError::Limit);
        }
        let mut name = [0u8; 4097];
        name[..leaf.len()].copy_from_slice(leaf);
        let name = std::ffi::CStr::from_bytes_with_nul(&name[..leaf.len() + 1])
            .map_err(|_| ReadError::Escape)?;
        // SAFETY: stat is a plain C output record.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        meter.event("before_worktree_stat");
        retry(meter, Op::Stat, || {
            // SAFETY: live verified dirfd, one terminated component, writable
            // record. A replacement symlink is observed, never followed.
            unsafe {
                libc::fstatat(
                    held.fd.as_raw_fd(),
                    name.as_ptr(),
                    &mut metadata,
                    libc::AT_SYMLINK_NOFOLLOW,
                ) as isize
            }
        })?;
        #[cfg(test)]
        if let Some(device) = meter.worktree_device {
            metadata.st_dev = device as _;
        }
        if metadata.st_dev as u64 != held.identity.device {
            // Return the observation so comparison can report modified; both
            // compare and worktree_hash reject it before any content open.
            return Ok(metadata);
        }
        match metadata.st_mode & libc::S_IFMT {
            libc::S_IFREG | libc::S_IFLNK | libc::S_IFDIR => Ok(metadata),
            _ => Err(ReadError::Special),
        }
    }

    /// Read only a leaf link's bytes from its verified parent. Targets are
    /// opaque blob data: never resolve, open, or interpret them as paths.
    #[allow(clippy::too_many_arguments)]
    // dev_t is u64 on Linux and narrower on Darwin.
    #[allow(clippy::unnecessary_cast)]
    pub(crate) fn read_link(
        &mut self,
        root: &Root,
        path: &[u8],
        expected: &libc::stat,
        buffer: &mut [u8],
        access: &Access,
        meter: &mut Meter,
    ) -> Result<usize, ReadError> {
        access.full()?;
        let (parent, leaf) = split(path)?;
        self.parent(root, parent, access, meter)?;
        let held = self.held(root);
        let name = cstring(leaf, meter)?;
        let verify = |meter: &mut Meter| {
            let now = walk::lstat(held.fd.as_raw_fd(), &name, meter)?;
            if now.st_mode & libc::S_IFMT != libc::S_IFLNK
                || now.st_dev as u64 != held.identity.device
                || !same_worktree_stat(expected, &now)
            {
                return Err(ReadError::Changed);
            }
            Ok(())
        };
        verify(meter)?;
        meter.event("before_worktree_readlink");
        let size = retry(meter, Op::Readlink, || {
            // SAFETY: held verified parent, one terminated leaf, writable
            // precharged bounded slice. readlinkat never follows the target.
            unsafe {
                libc::readlinkat(
                    held.fd.as_raw_fd(),
                    name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            }
        })? as usize;
        meter.returned_bytes(size);
        meter.event("after_worktree_readlink");
        verify(meter)?;
        if size == buffer.len() || size as i64 != expected.st_size {
            return Err(ReadError::Changed);
        }
        Ok(size)
    }

    /// Hash opens share verified ancestors, but retain atomic root confinement
    /// on fast backends. Stepwise content is confined by the Landlock layer.
    pub fn open_file(
        &mut self,
        root: &Root,
        path: &[u8],
        access: &Access,
        meter: &mut Meter,
    ) -> Result<ReadFile, ReadError> {
        access.full()?;
        let (parent, leaf) = split(path)?;
        self.parent(root, parent, access, meter)?;
        let opened = match access.backend {
            #[cfg(target_os = "linux")]
            Resolver::Openat2 => inspect(linux::open_nofollow(root, path, false, meter)?, meter)?,
            #[cfg(target_os = "macos")]
            Resolver::DarwinBeneath => {
                meter.event("before_beneath_open");
                macos::open(root, path, false, false, access.darwin, meter)?
            }
            _ => {
                let name = cstring(leaf, meter)?;
                walk::worktree_component(self.held(root), &name, false, access, meter)?
            }
        };
        same_mount(opened.identity, root.identity)?;
        if opened.metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(ReadError::Special);
        }
        Ok(ReadFile {
            fd: opened.fd,
            metadata: opened.metadata,
        })
    }

    /// Compatibility entry point for the tracked-only caller.
    #[cfg(target_os = "macos")]
    pub fn directory(
        &mut self,
        root: &Root,
        parent: &[u8],
        access: &Access,
        meter: &mut Meter,
        mut visitor: impl FnMut(&[u8], Result<&libc::stat, ReadError>) -> Result<(), ReadError>,
    ) -> Result<bool, ReadError> {
        match self.parent(root, parent, access, meter) {
            Ok(()) => {}
            Err(ReadError::Missing) => return Ok(false),
            Err(error) => return Err(error),
        }
        let mut first = true;
        while self.visit_batch(root, parent, access, meter, first, |name, stat, _| {
            visitor(name, stat)
        })? {
            first = false;
        }
        Ok(true)
    }

    /// Resume one listing on the same private OFD, one bounded kernel batch
    /// at a time. False means EOF. Returning to a held parent preserves its
    /// offset; starting a second listing on it is forbidden.
    #[allow(clippy::too_many_arguments)]
    pub fn visit_batch(
        &mut self,
        root: &Root,
        parent: &[u8],
        access: &Access,
        meter: &mut Meter,
        first: bool,
        visitor: impl FnMut(&[u8], Result<&libc::stat, ReadError>, &mut Meter) -> Result<(), ReadError>,
    ) -> Result<bool, ReadError> {
        match self.parent(root, parent, access, meter) {
            Ok(()) => {}
            Err(ReadError::Missing) => return Ok(false),
            Err(error) => return Err(error),
        }
        let held = if let Some(step) = self.stack.last_mut() {
            if step.listed == first {
                return Err(ReadError::Denied);
            }
            step.listed = true;
            &step.directory
        } else {
            if self.root_listing.is_some() == first {
                return Err(ReadError::Denied);
            }
            if first {
                meter.charge_axis(bingsu_core::collection::budget::Axis::Directories, 1)?;
                // A fresh root OFD isolates bulk offsets from other list callers.
                let Opened { fd, identity, .. } =
                    resolve_worktree(root, b".", true, access, meter)?;
                self.root_listing = Some(Directory {
                    root: Root { fd, identity },
                });
            }
            &self.root_listing.as_ref().expect("root listing").root
        };
        #[cfg(target_os = "macos")]
        return bulk::visit_batch(held, meter, visitor);
        #[cfg(target_os = "linux")]
        return visit_linux_batch(held, meter, visitor);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (held, meter, visitor);
            return Err(ReadError::Denied);
        }
    }

    /// A narrow marker probe on the already-listed directory. No recursive
    /// listing, HEAD read, or gitfile target resolution is permitted here.
    #[allow(clippy::unnecessary_cast)]
    pub(crate) fn embedded_repository(
        &self,
        access: &Access,
        meter: &mut Meter,
    ) -> Result<bool, ReadError> {
        access.full()?;
        if let Some(error) = self.failed {
            return Err(error);
        }
        let held = match self.stack.last() {
            Some(step) if step.listed => &step.directory,
            None => &self.root_listing.as_ref().ok_or(ReadError::Denied)?.root,
            _ => return Err(ReadError::Denied),
        };
        let marker = match walk::lstat(held.fd.as_raw_fd(), c".git", meter) {
            Ok(metadata) => metadata,
            Err(ReadError::Missing) => return Ok(false),
            Err(error) => return Err(error),
        };
        let kind = marker.st_mode & libc::S_IFMT;
        if !matches!(kind, libc::S_IFREG | libc::S_IFDIR) {
            return Ok(false);
        }
        if marker.st_dev as u64 != held.identity.device {
            return Err(ReadError::Escape);
        }
        if kind == libc::S_IFDIR {
            meter.charge_axis(bingsu_core::collection::budget::Axis::Directories, 1)?;
        }
        // A separate, no-follow capability prevents an intermediate .git
        // symlink from escaping via a multi-component fstatat lookup.
        let opened = resolve_worktree(held, b".git", kind == libc::S_IFDIR, access, meter)?;
        if !same_worktree_stat(&marker, &opened.metadata) {
            return Err(ReadError::Changed);
        }
        let valid = if kind == libc::S_IFDIR {
            let mut valid = true;
            for (name, expected) in [
                (c"HEAD", libc::S_IFREG),
                (c"objects", libc::S_IFDIR),
                (c"refs", libc::S_IFDIR),
            ] {
                match walk::lstat(opened.fd.as_raw_fd(), name, meter) {
                    Ok(metadata) => {
                        if metadata.st_dev as u64 != held.identity.device {
                            return Err(ReadError::Escape);
                        }
                        valid &= metadata.st_mode & libc::S_IFMT == expected;
                    }
                    Err(ReadError::Missing) => valid = false,
                    Err(error) => return Err(error),
                }
            }
            valid
        } else {
            let file = ReadFile {
                fd: opened.fd,
                metadata: opened.metadata,
            };
            let mut prefix = [0u8; 8];
            // Pointer metadata uses the existing repository-byte axis. Only
            // this fixed prefix is read, regardless of hostile file size.
            meter.charge_axis(
                bingsu_core::collection::budget::Axis::RefBytes,
                prefix.len() as u64,
            )?;
            let mut used = 0;
            while used < prefix.len() {
                let n = file.stream_chunk(&mut prefix[used..], meter)?;
                if n == 0 {
                    break;
                }
                used += n;
            }
            file.verify_stream(meter)?;
            used == prefix.len() && &prefix == b"gitdir: "
        };
        if !same_worktree_stat(&marker, &walk::lstat(held.fd.as_raw_fd(), c".git", meter)?) {
            return Err(ReadError::Changed);
        }
        Ok(valid)
    }

    pub fn finish(
        &mut self,
        root: &Root,
        _access: &Access,
        meter: &mut Meter,
    ) -> Result<(), ReadError> {
        let result = (|| {
            if let Some(error) = self.failed {
                return Err(error);
            }
            while !self.stack.is_empty() {
                self.pop(root, meter)?;
            }
            Ok(())
        })();
        self.stack = Vec::new();
        self.missing = Vec::new();
        self.allocation = None;
        self.root_listing = None;
        self.failed = result.err();
        result
    }
}

/// Stream getdents64 once on the verified OFD, then stat each raw leaf without
/// following links. Dot entries count toward the raw budget, but are not visited.
#[cfg(target_os = "linux")]
fn visit_linux_batch(
    root: &Root,
    meter: &mut Meter,
    mut visitor: impl FnMut(&[u8], Result<&libc::stat, ReadError>, &mut Meter) -> Result<(), ReadError>,
) -> Result<bool, ReadError> {
    let mut buffer = [0u8; crate::meter::DIRENT_CHUNK];
    meter.event("before_worktree_bulk");
    let size = retry(meter, Op::List, || {
        // SAFETY: owned verified directory fd and bounded writable buffer.
        unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                root.fd.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            ) as isize
        }
    })? as usize;
    meter.event("after_worktree_bulk");
    if size == 0 {
        return Ok(false);
    }
    let mut offset = 0;
    while offset < size {
        let record = &buffer[offset..size];
        if record.len() < 20 {
            return Err(ReadError::Io(libc::EIO));
        }
        let length = u16::from_ne_bytes([record[16], record[17]]) as usize;
        if length < 20 || length > record.len() {
            return Err(ReadError::Io(libc::EIO));
        }
        meter.raw_entry()?;
        let name = std::ffi::CStr::from_bytes_until_nul(&record[19..length])
            .map_err(|_| ReadError::Io(libc::EIO))?;
        let raw = name.to_bytes();
        if raw != b"." && raw != b".." {
            if raw.is_empty() || raw.contains(&b'/') {
                return Err(ReadError::Io(libc::EIO));
            }
            meter.event("before_worktree_stat");
            let metadata = match walk::lstat(root.fd.as_raw_fd(), name, meter) {
                Err(error @ (ReadError::Limit | ReadError::Deadline)) => return Err(error),
                result => result,
            };
            #[cfg(test)]
            let metadata = metadata.map(|mut s| {
                if let Some(device) = meter.worktree_device {
                    s.st_dev = device as _;
                }
                s
            });
            visitor(raw, metadata.as_ref().map_err(|e| *e), meter)?;
        }
        offset += length;
    }
    Ok(true)
}

fn canonical(path: &[u8]) -> Result<(), ReadError> {
    relative(path)?;
    if path
        .split(|&b| b == b'/')
        .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(ReadError::Escape);
    }
    if path.split(|&b| b == b'/').count() > 4096 {
        return Err(ReadError::Limit);
    }
    Ok(())
}

fn split(path: &[u8]) -> Result<(&[u8], &[u8]), ReadError> {
    canonical(path)?;
    Ok(path
        .iter()
        .rposition(|&b| b == b'/')
        .map_or((&b""[..], path), |at| (&path[..at], &path[at + 1..])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };

    // 이것을 실패시키는 것: 공유 중간 fd의 mount/device 대조 또는 lstat/fstat 정체 대조 제거.
    #[test]
    fn cached_component_checks_mount_device_and_identity() {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        for fault in ["mount", "device", "identity"] {
            let path = std::env::temp_dir().join(format!(
                "bingsu-cache-edge-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir_all(path.join("a/b")).unwrap();
            let path = fs::canonicalize(path).unwrap();
            let mut meter = Meter::new(Instant::now() + Duration::from_secs(30));
            let root = acquire(
                path.as_os_str().as_bytes(),
                DiscoveryQuery::default(),
                &mut meter,
            )
            .unwrap()
            .select_cwd()
            .unwrap();
            let access = unchecked_backend_for_test(Resolver::Stepwise);
            let mut scan = WorktreeStats::default();
            scan.parent(&root, b"a", &access, &mut meter).unwrap();
            match fault {
                "mount" => scan.stack[0].directory.identity.mount[0] ^= 1,
                "device" => scan.stack[0].directory.identity.device ^= 1,
                _ => {
                    let path = path.clone();
                    meter.hook = Some(Box::new(move |event| {
                        if event == "before_open_component" {
                            fs::rename(path.join("a/b"), path.join("a/old")).unwrap();
                            fs::create_dir(path.join("a/b")).unwrap();
                        }
                    }));
                }
            }
            assert_eq!(
                scan.parent(&root, b"a/b", &access, &mut meter),
                Err(if fault == "identity" {
                    ReadError::Changed
                } else {
                    ReadError::Escape
                })
            );
            assert_eq!(meter.counts[Phase::Content as usize].read, 0);
            fs::remove_dir_all(path).unwrap();
        }
    }
}
