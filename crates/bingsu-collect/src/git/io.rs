//! The only filesystem port available to git parsers.
use crate::{
    meter::Meter,
    safe_read::{self, Access, Listing, ReadCap, ReadError, Root},
};
use bingsu_core::collection::budget::Axis;
use std::{cell::RefCell, time::Instant};

pub const UNSUPPORTED: ReadError = ReadError::Io(libc::ENOTSUP);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootId {
    Worktree,
    GitDir,
    CommonDir,
}

pub struct RepoPath {
    pub root: RootId,
    pub relative: Vec<u8>,
}
impl RepoPath {
    pub fn new(root: RootId, relative: &[u8]) -> Self {
        Self {
            root,
            relative: relative.to_vec(),
        }
    }
}

/// Only capabilities, never paths. C5 validates repository shape, owner and
/// mount before constructing this bundle; identical roots may share a borrow.
pub struct RepoRoots<'a> {
    pub worktree: &'a Root,
    pub gitdir: &'a Root,
    pub commondir: &'a Root,
}

pub struct RepoIo<'a> {
    roots: RepoRoots<'a>,
    access: &'a Access,
    meter: &'a RefCell<Meter>,
}

// Move the ONE meter out for a syscall sequence, releasing the RefCell borrow.
// The expired placeholder rejects reentry, including from test callbacks.
// Unwinding restores the real counters/deadline/leases, just like normal return.
struct MeterLoan<'a> {
    slot: &'a RefCell<Meter>,
    value: Option<Meter>,
}
impl Drop for MeterLoan<'_> {
    fn drop(&mut self) {
        self.slot.replace(self.value.take().expect("owned meter"));
    }
}

impl<'a> RepoIo<'a> {
    pub fn new(roots: RepoRoots<'a>, access: &'a Access, meter: &'a RefCell<Meter>) -> Self {
        Self {
            roots,
            access,
            meter,
        }
    }

    fn root(&self, id: RootId) -> &Root {
        match id {
            RootId::Worktree => self.roots.worktree,
            RootId::GitDir => self.roots.gitdir,
            RootId::CommonDir => self.roots.commondir,
        }
    }

    pub(super) fn metered<T>(
        &self,
        operation: impl FnOnce(&mut Meter) -> Result<T, ReadError>,
    ) -> Result<T, ReadError> {
        let value = {
            let mut slot = self.meter.try_borrow_mut().map_err(|_| ReadError::Denied)?;
            slot.check()?;
            std::mem::replace(&mut *slot, Meter::new(Instant::now()))
        };
        let mut loan = MeterLoan {
            slot: self.meter,
            value: Some(value),
        };
        operation(loan.value.as_mut().expect("owned meter"))
    }

    pub fn read(&self, path: RepoPath, cap: ReadCap) -> Result<Vec<u8>, ReadError> {
        self.metered(|meter| {
            safe_read::read(
                self.root(path.root),
                &path.relative,
                cap,
                self.access,
                meter,
            )
        })
    }

    /// Reserve the inspected size before reading from that same fd. Growth is
    /// an error (cap+1 probe), never an uncharged extension of the reservation.
    pub(super) fn read_ref(&self, path: RepoPath, cap: u64) -> Result<Vec<u8>, ReadError> {
        self.metered(|meter| {
            // Exhaustion forbids even another path lookup.
            if meter.budget.used(Axis::RefBytes) == Axis::RefBytes.limit() {
                return Err(ReadError::Limit);
            }
            let file =
                safe_read::resolve_with(self.root(path.root), &path.relative, self.access, meter)?;
            let metadata = file.metadata();
            let size = u64::try_from(metadata.st_size).map_err(|_| ReadError::Limit)?;
            if size > cap {
                return Err(ReadError::Limit);
            }
            meter.charge_axis(Axis::RefBytes, size)?;
            file.read(
                ReadCap {
                    bytes: size,
                    single_link: true,
                },
                meter,
            )
        })
    }

    /// A same-fd regular-file snapshot, not ambient stat or a worktree lstat.
    /// C4 supplies the no-follow worktree-stat operation separately.
    pub fn metadata(&self, path: RepoPath) -> Result<libc::stat, ReadError> {
        self.metered(|meter| {
            Ok(
                safe_read::resolve_with(self.root(path.root), &path.relative, self.access, meter)?
                    .metadata(),
            )
        })
    }

    pub fn list(&self, path: RepoPath, raw_limit: u32) -> Result<Listing, ReadError> {
        self.metered(|meter| {
            let dir =
                safe_read::directory(self.root(path.root), &path.relative, self.access, meter)?;
            safe_read::entries(&dir, raw_limit, meter)
        })
    }

    /// C3 will implement bounded read-only maps. Unconnected means unsupported,
    /// not an empty successful map and not a filesystem fallback.
    pub fn map(&self, _path: RepoPath, _cap: u64) -> Result<Vec<u8>, ReadError> {
        Err(UNSUPPORTED)
    }
}
