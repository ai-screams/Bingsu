//! OS-side budget port. Pure collection counters are connected in the next stage.
use std::{cell::Cell, rc::Rc, time::Instant};

use crate::safe_read::ReadError;

pub const READ_CHUNK: usize = 16_384;
pub const DIRENT_CHUNK: usize = 8_192;
pub const LIVE_FDS: u32 = 56;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    Probe,
    Acquisition,
    #[default]
    Content,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub open: u64,
    pub stat: u64,
    pub mount: u64,
    pub filesystem: u64,
    pub readlink: u64,
    pub read: u64,
    pub list: u64,
    pub components: u64,
    pub read_bytes: u64,
    pub raw_entries: u64,
    pub allocated: u64,
    pub retries: u64,
}

#[derive(Clone, Copy)]
pub enum Op {
    Open,
    Stat,
    Mount,
    Filesystem,
    Readlink,
    Read,
    List,
    Component,
    Retry,
}

#[cfg(test)]
type Hook = Box<dyn FnMut(&str)>;

pub struct Meter {
    deadline: Instant,
    pub phase: Phase,
    pub counts: [Counters; 3],
    pub byte_limit: u64,
    pub allocation_limit: u64,
    operations: u64,
    bytes: u64,
    allocated: u64,
    live: Rc<Cell<u32>>,
    pub peak_fds: u32,
    #[cfg(test)]
    pub hook: Option<Hook>,
    #[cfg(test)]
    pub mount_fault: Option<i32>,
    #[cfg(test)]
    pub openat2_errors: std::collections::VecDeque<i32>,
}

pub struct Lease(Rc<Cell<u32>>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

impl Meter {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            phase: Phase::Content,
            counts: [Counters::default(); 3],
            byte_limit: 8_388_608,
            allocation_limit: 8_388_608,
            operations: 0,
            bytes: 0,
            allocated: 0,
            live: Rc::new(Cell::new(0)),
            peak_fds: 0,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            mount_fault: None,
            #[cfg(test)]
            openat2_errors: Default::default(),
        }
    }

    pub fn check(&self) -> Result<(), ReadError> {
        if Instant::now() >= self.deadline {
            Err(ReadError::Deadline)
        } else {
            Ok(())
        }
    }

    pub fn charge(&mut self, op: Op) -> Result<(), ReadError> {
        self.check()?;
        if self.operations >= 100_000 {
            return Err(ReadError::Limit);
        }
        self.operations += 1;
        let count = &mut self.counts[self.phase as usize];
        let axis = match op {
            Op::Open => &mut count.open,
            Op::Stat => &mut count.stat,
            Op::Mount => &mut count.mount,
            Op::Filesystem => &mut count.filesystem,
            Op::Readlink => &mut count.readlink,
            Op::Read => &mut count.read,
            Op::List => &mut count.list,
            Op::Component => &mut count.components,
            Op::Retry => &mut count.retries,
        };
        *axis += 1;
        Ok(())
    }

    pub fn allocation(&mut self, bytes: usize) -> Result<(), ReadError> {
        self.check()?;
        let next = self
            .allocated
            .checked_add(bytes as u64)
            .ok_or(ReadError::Limit)?;
        if next > self.allocation_limit {
            return Err(ReadError::Limit);
        }
        self.allocated = next;
        self.counts[self.phase as usize].allocated += bytes as u64;
        Ok(())
    }

    /// Reserve the entire cap+1 before allocating or issuing a content read.
    pub fn read_capacity(&mut self, bytes: usize) -> Result<(), ReadError> {
        self.check()?;
        let next = self
            .bytes
            .checked_add(bytes as u64)
            .ok_or(ReadError::Limit)?;
        if next > self.byte_limit {
            return Err(ReadError::Limit);
        }
        self.allocation(bytes)?;
        self.bytes = next;
        Ok(())
    }

    pub fn returned_bytes(&mut self, bytes: usize) {
        self.counts[self.phase as usize].read_bytes += bytes as u64;
    }

    pub fn raw_entry(&mut self) -> Result<(), ReadError> {
        self.check()?;
        let counter = &mut self.counts[self.phase as usize].raw_entries;
        if *counter >= 65_536 {
            return Err(ReadError::Limit);
        }
        *counter += 1;
        Ok(())
    }

    pub fn lease(&mut self) -> Result<Lease, ReadError> {
        self.check()?;
        let next = self.live.get() + 1;
        if next > LIVE_FDS {
            return Err(ReadError::Limit);
        }
        self.live.set(next);
        self.peak_fds = self.peak_fds.max(next);
        Ok(Lease(Rc::clone(&self.live)))
    }

    pub fn event(&mut self, _event: &str) {
        #[cfg(test)]
        if let Some(hook) = self.hook.as_mut() {
            hook(_event);
        }
    }
}
