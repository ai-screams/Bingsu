//! Shared verified directory stack for one index-order walk. Each edge is
//! opened and mount-checked once, reused by its files and descendants, and
//! revalidated against its held parent when popped. Fds are bounded by depth.
use super::*;

struct Step {
    directory: Root,
    name: PathCString,
    #[cfg(target_os = "macos")]
    listed: bool,
}

/// Observations are provisional until finish succeeds. Edge identity checks
/// detect replacement, not ABA or atomic ancestry. Content opens retain the
/// original-root atomic backend (or the Linux Landlock read layer).
#[derive(Default)]
pub struct WorktreeStats {
    stack: Vec<Step>,
    allocation: Option<PathAllocation>,
    #[cfg(target_os = "macos")]
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
            let opened = walk::worktree_component(self.held(root), &name, true, access, meter)
                .map_err(|e| {
                    if e == ReadError::Symlink {
                        ReadError::Missing
                    } else {
                        e
                    }
                })?;
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
                #[cfg(target_os = "macos")]
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
            libc::S_IFREG => Ok(metadata),
            libc::S_IFLNK => Err(ReadError::Missing),
            _ => Err(ReadError::Special),
        }
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

    /// Each directory's OFD is private to this walk and listed at most once.
    /// D1 must reuse these observations for untracked matching as well.
    #[cfg(target_os = "macos")]
    pub fn directory(
        &mut self,
        root: &Root,
        parent: &[u8],
        access: &Access,
        meter: &mut Meter,
        visitor: impl FnMut(&[u8], Result<&libc::stat, ReadError>) -> Result<(), ReadError>,
    ) -> Result<bool, ReadError> {
        match self.parent(root, parent, access, meter) {
            Ok(()) => {}
            Err(ReadError::Missing) => return Ok(false),
            Err(error) => return Err(error),
        }
        let held = if let Some(step) = self.stack.last_mut() {
            if step.listed {
                return Err(ReadError::Denied);
            }
            step.listed = true;
            &step.directory
        } else {
            if self.root_listing.is_some() {
                return Err(ReadError::Denied);
            }
            meter.charge_axis(bingsu_core::collection::budget::Axis::Directories, 1)?;
            // A fresh root OFD isolates bulk offsets from other list callers.
            self.root_listing = Some(worktree_directory(root, b".", access, meter)?);
            &self.root_listing.as_ref().expect("root listing").root
        };
        bulk::visit(held, meter, visitor)?;
        Ok(true)
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
        self.allocation = None;
        #[cfg(target_os = "macos")]
        {
            self.root_listing = None;
        }
        self.failed = result.err();
        result
    }
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
