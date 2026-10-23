//! OS deadlines and syscall observations around the shared pure budget counters.
use std::{cell::Cell, rc::Rc, time::Instant};

use crate::safe_read::ReadError;
use bingsu_core::collection::budget::{self, Axis, BudgetCounters};

pub const READ_CHUNK: usize = budget::READ_CHUNK as usize;
pub const DIRENT_CHUNK: usize = budget::DIRENT_CHUNK as usize;
pub const LIVE_FDS: u32 = budget::LIVE_FDS as u32;

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
    pub readonly: u64,
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
    Readonly,
}

#[cfg(test)]
type Hook = Box<dyn FnMut(&str)>;

pub struct Meter {
    deadline: Instant,
    pub budget: BudgetCounters,
    pub phase: Phase,
    pub counts: [Counters; 3],
    pub byte_limit: u64,
    pub allocation_limit: u64,
    operations: u64,
    bytes: u64,
    allocated: Rc<Cell<u64>>,
    live: Rc<Cell<u32>>,
    pub peak_fds: u32,
    #[cfg(test)]
    pub hook: Option<Hook>,
    #[cfg(test)]
    pub mount_fault: Option<i32>,
    #[cfg(test)]
    pub worktree_device: Option<u64>,
    #[cfg(test)]
    pub openat2_errors: std::collections::VecDeque<i32>,
}

pub struct Lease(Rc<Cell<u32>>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

/// A single object's live scratch reservation. The caller keeps this through
/// the returned buffer's use, then releases it on the next find or adapter drop.
#[derive(Debug)]
pub struct ObjectAllocation {
    live: Rc<Cell<u64>>,
    bytes: u64,
}
impl ObjectAllocation {
    pub fn reserve(&mut self, bytes: usize, meter: &mut Meter) -> Result<(), ReadError> {
        let next = self
            .bytes
            .checked_add(bytes as u64)
            .ok_or(ReadError::Limit)?;
        if next > budget::OBJECT_ALLOC {
            return Err(ReadError::Limit);
        }
        meter.allocation(bytes)?;
        self.bytes = next;
        Ok(())
    }
}
impl Drop for ObjectAllocation {
    fn drop(&mut self) {
        self.live.set(self.live.get() - self.bytes);
    }
}

/// Path scratch lives only as long as its resolution or cached directory.
/// Unlike object buffers it has no per-object cap; it shares the live limit.
pub struct PathAllocation {
    live: Rc<Cell<u64>>,
    bytes: u64,
}
impl PathAllocation {
    pub fn reserve(&mut self, bytes: usize, meter: &mut Meter) -> Result<(), ReadError> {
        let next = self
            .bytes
            .checked_add(bytes as u64)
            .ok_or(ReadError::Limit)?;
        meter.allocation(bytes)?;
        self.bytes = next;
        Ok(())
    }
}
impl Drop for PathAllocation {
    fn drop(&mut self) {
        self.live.set(self.live.get() - self.bytes);
    }
}

impl Meter {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            budget: BudgetCounters::default(),
            phase: Phase::Content,
            counts: [Counters::default(); 3],
            byte_limit: 8_388_608,
            allocation_limit: 8_388_608,
            operations: 0,
            bytes: 0,
            allocated: Rc::new(Cell::new(0)),
            live: Rc::new(Cell::new(0)),
            peak_fds: 0,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            mount_fault: None,
            #[cfg(test)]
            worktree_device: None,
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

    /// Reentry sentinel for RepoIo's loan. Sharing the live counters avoids
    /// two heap allocations per leaf; its expired deadline rejects all work.
    pub(crate) fn expired_placeholder(&self) -> Self {
        Self {
            deadline: Instant::now(),
            budget: BudgetCounters::default(),
            phase: self.phase,
            counts: [Counters::default(); 3],
            byte_limit: 0,
            allocation_limit: 0,
            operations: 0,
            bytes: 0,
            allocated: Rc::clone(&self.allocated),
            live: Rc::clone(&self.live),
            peak_fds: 0,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            mount_fault: None,
            #[cfg(test)]
            worktree_device: None,
            #[cfg(test)]
            openat2_errors: Default::default(),
        }
    }

    pub fn charge_axis(&mut self, axis: Axis, amount: u64) -> Result<(), ReadError> {
        self.check()?;
        self.budget
            .charge(axis, amount)
            .map_err(|_| ReadError::Limit)
    }

    pub fn charge(&mut self, op: Op) -> Result<(), ReadError> {
        self.check()?;
        if self.operations >= 100_000 {
            return Err(ReadError::Limit);
        }
        if matches!(op, Op::Stat) {
            self.budget
                .charge(Axis::Stats, 1)
                .map_err(|_| ReadError::Limit)?;
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
            Op::Readonly => &mut count.readonly,
        };
        *axis += 1;
        Ok(())
    }

    pub fn allocation(&mut self, bytes: usize) -> Result<(), ReadError> {
        self.check()?;
        let next = self
            .allocated
            .get()
            .checked_add(bytes as u64)
            .ok_or(ReadError::Limit)?;
        if next > self.allocation_limit {
            return Err(ReadError::Limit);
        }
        self.allocated.set(next);
        self.record_allocation(bytes);
        Ok(())
    }

    pub fn object_allocation(&self) -> ObjectAllocation {
        ObjectAllocation {
            live: Rc::clone(&self.allocated),
            bytes: 0,
        }
    }

    pub fn path_allocation(&self) -> PathAllocation {
        PathAllocation {
            live: Rc::clone(&self.allocated),
            bytes: 0,
        }
    }

    #[cfg(test)]
    pub fn operations(&self) -> u64 {
        self.operations
    }

    #[cfg(test)]
    pub fn live_allocated(&self) -> u64 {
        self.allocated.get()
    }

    /// Observation only: repository snapshots have already reserved their own
    /// file/axis budget, independently of the generic worktree allocation cap.
    pub(crate) fn record_allocation(&mut self, bytes: usize) {
        self.counts[self.phase as usize].allocated += bytes as u64;
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
        self.charge_axis(Axis::WorktreeReadBytes, bytes as u64)?;
        self.allocation(bytes)?;
        self.bytes = next;
        Ok(())
    }

    pub fn returned_bytes(&mut self, bytes: usize) {
        self.counts[self.phase as usize].read_bytes += bytes as u64;
    }

    pub fn raw_entry(&mut self) -> Result<(), ReadError> {
        self.raw_entries(1)
    }

    pub fn raw_entries(&mut self, amount: u64) -> Result<(), ReadError> {
        self.check()?;
        self.budget
            .charge(Axis::WorktreeEntries, amount)
            .map_err(|_| ReadError::Limit)?;
        let counter = &mut self.counts[self.phase as usize].raw_entries;
        let next = counter.checked_add(amount).ok_or(ReadError::Limit)?;
        if next > 65_536 {
            return Err(ReadError::Limit);
        }
        *counter = next;
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

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 객체 예약의 drop 반환 또는 객체별 OBJECT_ALLOC 검사를 제거하는 것.
    #[test]
    fn object_reservations_are_live_and_individually_bounded() {
        let mut m = Meter::new(Instant::now() + std::time::Duration::from_secs(30));
        for _ in 0..4096 {
            let mut reservation = m.object_allocation();
            reservation
                .reserve(budget::OBJECT_ALLOC as usize, &mut m)
                .unwrap();
            assert_eq!(m.allocated.get(), budget::OBJECT_ALLOC);
            assert_eq!(reservation.reserve(1, &mut m), Err(ReadError::Limit));
            drop(reservation);
            assert_eq!(m.allocated.get(), 0);
        }
        assert_eq!(m.budget.used(Axis::DecompressedBytes), 0);
    }

    // 이것을 실패시키는 것: OS port에서 core 사전 charge를 빼거나 phase마다 예산을 초기화하는 것.
    #[test]
    fn pure_budget_precedes_io_across_phases() {
        let mut m = Meter::new(Instant::now() + std::time::Duration::from_secs(30));
        m.budget.charge(Axis::Stats, budget::STATS).unwrap();
        assert_eq!(m.charge(Op::Stat), Err(ReadError::Limit));
        assert_eq!(m.counts[Phase::Content as usize].stat, 0);
        m.budget
            .charge(Axis::WorktreeReadBytes, budget::WORKTREE_READ_BYTES)
            .unwrap();
        assert_eq!(m.read_capacity(1), Err(ReadError::Limit));
        assert_eq!(m.allocated.get(), 0);
        m.budget
            .charge(Axis::WorktreeEntries, budget::WORKTREE_ENTRIES - 1)
            .unwrap();
        m.phase = Phase::Acquisition;
        m.raw_entry().unwrap();
        m.phase = Phase::Content;
        assert_eq!(m.raw_entry(), Err(ReadError::Limit));
        assert_eq!(m.counts[Phase::Content as usize].raw_entries, 0);
    }
}
