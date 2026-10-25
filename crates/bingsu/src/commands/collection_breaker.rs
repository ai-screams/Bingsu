//! Helper-only breaker records. No repository opens and no prompt-side calls.
use super::{
    collection_gc, collection_store,
    snapshot_store::{self, StoreError},
    sys,
};
use bingsu_core::{
    collection::{
        breaker::{Admission, Breaker, Error as BreakerError, Key, MAX_BYTES},
        wire::{EndReason, Progress},
    },
    snapshot::Clock,
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsFd,
};

pub(crate) const ROOT: &str = "collection-control-v1";
pub(crate) const RECORD: &str = "breaker";
pub(crate) const STAGE: &str = ".breaker.stage";
pub(crate) const LOCK: &str = "breaker.lock";
pub(crate) const FILES: [&str; 3] = [RECORD, STAGE, LOCK];
pub(crate) const MAX_RESERVATION: u64 = 2 * MAX_BYTES as u64;
pub(crate) const ACCOUNTING_UNIT: u64 = 4_096;
pub(crate) const CHUNK: usize = 1_024;

pub(crate) fn rounded_size(len: usize) -> u64 {
    (len as u64).div_ceil(ACCOUNTING_UNIT) * ACCOUNTING_UNIT
}

#[cfg(test)]
type IoHook = (usize, Box<dyn FnOnce()>);
#[cfg(test)]
thread_local! {
    static BEFORE_IO: std::cell::RefCell<Option<IoHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
#[allow(dead_code, reason = "deterministic concurrent admission fixture")]
pub(crate) fn fixture_before_io(skip: usize, hook: impl FnOnce() + 'static) {
    BEFORE_IO.with(|slot| *slot.borrow_mut() = Some((skip, Box::new(hook))));
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IoCounts {
    pub reads: u64,
    pub writes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub max_read: usize,
    pub max_write: usize,
}
#[cfg(test)]
thread_local! { static IO: std::cell::Cell<IoCounts> = const { std::cell::Cell::new(IoCounts { reads:0, writes:0, read_bytes:0, write_bytes:0, max_read:0, max_write:0 }) }; }
#[cfg(test)]
#[allow(dead_code, reason = "native breaker I/O measurement")]
pub(crate) fn fixture_io() -> IoCounts {
    IO.with(std::cell::Cell::take)
}

pub(crate) enum Decision {
    Run(Option<Ticket>),
    Blocked,
    Deferred,
}
pub(crate) struct Ticket {
    chain: Vec<File>,
    session: String,
    key: Key,
    sequence: u64,
}

pub(crate) fn session_valid(session: &[u8]) -> bool {
    session.len() == 32
        && session
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
pub(crate) fn path(session: &str) -> Vec<String> {
    vec![ROOT.into(), "sessions".into(), session.into()]
}
pub(crate) fn location(path: &[String]) -> bool {
    path.len() == 3
        && path[0] == ROOT
        && path[1] == "sessions"
        && session_valid(
            path[2]
                .strip_prefix('.')
                .and_then(|s| s.strip_suffix(".gc"))
                .unwrap_or(&path[2])
                .as_bytes(),
        )
}
pub(crate) fn tombstone(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(".gc")
}

/// Any I/O/codec failure disables only this optional mechanism. Busy or stale
/// sessions do not wait. A returned ticket proves its lease was persisted.
pub(crate) fn begin(
    runtime: &File,
    session: Option<&[u8]>,
    sequence: Option<u64>,
    cwd: &[u8],
    now: Clock,
) -> Decision {
    decision(begin_checked(runtime, session, sequence, cwd, now, || {
        collection_gc::GcBudget::default().start()
    }))
}
fn decision(result: Result<Decision, StoreError>) -> Decision {
    match result {
        Ok(decision) => decision,
        Err(StoreError::Busy) => Decision::Deferred,
        Err(_) => Decision::Run(None),
    }
}

#[cfg(test)]
#[allow(dead_code, reason = "native breaker integration target")]
pub(crate) fn fixture_begin(
    runtime: &File,
    session: Option<&[u8]>,
    sequence: Option<u64>,
    cwd: &[u8],
    now: Clock,
) -> Decision {
    decision(begin_checked(runtime, session, sequence, cwd, now, || {
        sys::CollectionMeter::fixture_operations(4096)
    }))
}

fn begin_checked(
    runtime: &File,
    session: Option<&[u8]>,
    sequence: Option<u64>,
    cwd: &[u8],
    now: Clock,
    start_meter: impl FnOnce() -> sys::CollectionMeter,
) -> Result<Decision, StoreError> {
    let (Some(session), Some(sequence)) = (session, sequence) else {
        return Ok(Decision::Run(None));
    };
    if !session_valid(session) {
        return Err(StoreError::Unsafe);
    }
    let key = Key::cwd(cwd).map_err(|_| StoreError::Unsafe)?;
    let session = std::str::from_utf8(session)
        .map_err(|_| StoreError::Unsafe)?
        .to_owned();
    let me = sys::current_uid();
    let mut registration = match collection_gc::Registration::open(
        runtime,
        me,
        now,
        bingsu_core::field::BUILTIN,
        start_meter,
    )? {
        Ok(registration) => registration,
        Err(_) => return Ok(Decision::Deferred),
    };
    let fresh = match registration.reserve_breaker(&session, now) {
        Ok(fresh) => fresh,
        Err(StoreError::Busy) => return Ok(Decision::Run(None)),
        Err(error) => return Err(error),
    };
    let mut chain = vec![runtime.try_clone()?];
    let mut created = 0;
    for name in path(&session) {
        let parent = chain.last().unwrap();
        if fresh {
            created += u64::from(sys::mkdir_at(parent.as_fd(), OsStr::new(&name), 0o700)?);
        }
        let child = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(&name))?;
        snapshot_store::check_directory(&child, me)?;
        snapshot_store::same_name(&child, parent.as_fd(), &name)?;
        chain.push(child);
    }
    let ticket = Ticket {
        chain,
        session,
        key,
        sequence,
    };
    let dir = ticket.chain.last().unwrap();
    let _lock = collection_store::close_only_lock(dir, LOCK, me, true)?;
    if fresh {
        registration.attach(dir, created)?;
    }
    // The session lock protects the record; payload I/O must not retain GC_LOCK.
    drop(registration);
    let mut breaker = load(dir, me)?.unwrap_or_else(|| Breaker::new(now));
    let admission = match breaker.reserve(&ticket.key, sequence, now) {
        Ok(admission) => admission,
        // Cached init output can give independent shells the same session.
        // A stale sequence disables tracking only for an unblocked key.
        Err(BreakerError::Sequence) => {
            return Ok(
                match breaker.admit_after_sequence_rejection(&ticket.key, now) {
                    Admission::Blocked | Admission::Probe => Decision::Blocked,
                    Admission::Allowed | Admission::Disabled => Decision::Run(None),
                },
            );
        }
        Err(_) => return Err(StoreError::Unsafe),
    };
    if admission == Admission::Blocked {
        return Ok(Decision::Blocked);
    }
    ticket.verify()?;
    snapshot_store::same_name(&_lock, dir.as_fd(), LOCK)?;
    save(&ticket, &breaker, me)?;
    Ok(Decision::Run(Some(ticket)))
}
impl Ticket {
    fn verify(&self) -> Result<(), StoreError> {
        let me = sys::current_uid();
        snapshot_store::check_directory(&self.chain[0], me)?;
        for (i, name) in path(&self.session).iter().enumerate() {
            snapshot_store::check_directory(&self.chain[i + 1], me)?;
            snapshot_store::same_name(&self.chain[i + 1], self.chain[i].as_fd(), name)?;
        }
        Ok(())
    }
    pub(crate) fn finish(
        self,
        progress: Progress,
        reason: EndReason,
        now: Clock,
    ) -> Result<(), StoreError> {
        let me = sys::current_uid();
        let dir = self.chain.last().unwrap();
        let _lock = collection_store::close_only_lock(dir, LOCK, me, false)?;
        self.verify()?;
        let mut breaker = load(dir, me)?.ok_or(StoreError::Unsafe)?;
        breaker
            .observe(self.key.clone(), self.sequence, progress, reason, now)
            .map_err(|_| StoreError::Unsafe)?;
        self.verify()?;
        snapshot_store::same_name(&_lock, dir.as_fd(), LOCK)?;
        save(&self, &breaker, me)
    }
}

/// Immutable same-fd, checked-length reads, in 1 KiB units with no EOF probe.
pub(crate) fn read(dir: &File, name: &str, me: u32) -> Result<Option<Vec<u8>>, StoreError> {
    #[cfg(test)]
    BEFORE_IO.with(|slot| {
        let mut pending = slot.borrow_mut();
        if let Some((skip, _)) = pending.as_mut() {
            if *skip > 0 {
                *skip -= 1;
                return;
            }
        }
        let hook = pending.take();
        drop(pending);
        if let Some((_, hook)) = hook {
            hook();
        }
    });
    let mut file = match sys::open_data_at_nofollow(dir.as_fd(), OsStr::new(name)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let before = sys::file_stamp(&file)?;
    let len = snapshot_store::check_data(&file, if name == LOCK { 0 } else { MAX_BYTES }, me)?;
    let mut bytes = vec![0; len];
    let mut offset = 0;
    while offset < len {
        sys::collection_ops(1)?;
        let end = (offset + CHUNK).min(len);
        let n = file.read(&mut bytes[offset..end])?;
        #[cfg(test)]
        IO.with(|slot| {
            let mut count = slot.get();
            count.reads += 1;
            count.read_bytes += n as u64;
            count.max_read = count.max_read.max(end - offset);
            slot.set(count);
        });
        if n == 0 {
            return Err(StoreError::Unsafe);
        }
        offset += n;
    }
    if before != sys::file_stamp(&file)? {
        return Err(StoreError::Unsafe);
    }
    snapshot_store::same_name(&file, dir.as_fd(), name)?;
    Ok(Some(bytes))
}
pub(crate) fn load(dir: &File, me: u32) -> Result<Option<Breaker>, StoreError> {
    read(dir, RECORD, me)?
        .map(|bytes| Breaker::decode(&bytes).map_err(|_| StoreError::Unsafe))
        .transpose()
}
/// GC holds the session lock; account for every allowed occupant in 4 KiB
/// units. A damaged payload remains reclaimable.
pub(crate) fn inventory(dir: &File, me: u32) -> Result<(Option<Breaker>, u64), StoreError> {
    let mut record = None;
    let mut size = 0;
    let mut stream = sys::DirectoryCursor::open(dir.as_fd())?;
    while let Some(name) = stream.next()? {
        if name == "." || name == ".." {
            continue;
        }
        let name = name.to_str().ok_or(StoreError::Unsafe)?;
        if !FILES.contains(&name) {
            return Err(StoreError::Unsafe);
        }
        let bytes = read(dir, name, me)?.ok_or(StoreError::Unsafe)?;
        size += rounded_size(bytes.len());
        if name == RECORD {
            record = Breaker::decode(&bytes).ok();
        }
    }
    Ok((record, size))
}
fn save(ticket: &Ticket, breaker: &Breaker, me: u32) -> Result<(), StoreError> {
    let dir = ticket.chain.last().unwrap();
    let bytes = breaker.encode().map_err(|_| StoreError::Unsafe)?;
    collection_store::remove_checked(dir, STAGE, MAX_BYTES, me)?;
    // Both old and staging files coexist until rename. Compute their actual
    // sizes under the session lock and reserve before the first write. The
    // short catalog transaction releases GC_LOCK before any payload I/O.
    let old_size = match sys::open_data_at_nofollow(dir.as_fd(), OsStr::new(RECORD)) {
        Ok(file) => {
            let len = snapshot_store::check_data(&file, MAX_BYTES, me)?;
            snapshot_store::same_name(&file, dir.as_fd(), RECORD)?;
            rounded_size(len)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.into()),
    };
    collection_gc::reserve_breaker_write(
        &ticket.chain[0],
        dir,
        &ticket.session,
        old_size + rounded_size(bytes.len()),
        breaker.used(),
        me,
    )
    .map_err(|error| match error {
        // Capacity or GC contention while persisting disables tracking only.
        StoreError::Busy => StoreError::Unsafe,
        error => error,
    })?;
    let mut file = sys::create_file_at(dir.as_fd(), OsStr::new(STAGE), 0o600)?;
    let mut offset = 0;
    while offset < bytes.len() {
        sys::collection_ops(1)?;
        let end = (offset + CHUNK).min(bytes.len());
        let n = file.write(&bytes[offset..end])?;
        #[cfg(test)]
        IO.with(|slot| {
            let mut count = slot.get();
            count.writes += 1;
            count.write_bytes += n as u64;
            count.max_write = count.max_write.max(end - offset);
            slot.set(count);
        });
        if n == 0 {
            return Err(StoreError::Unsafe);
        }
        offset += n;
    }
    snapshot_store::check_data(&file, MAX_BYTES, me)?;
    snapshot_store::same_name(&file, dir.as_fd(), STAGE)?;
    if read(dir, STAGE, me)?.as_deref() != Some(&bytes) {
        return Err(StoreError::Unsafe);
    }
    // Replacement checks metadata even if the old payload was damaged.
    if let Some(old) = read(dir, RECORD, me)? {
        Breaker::decode(&old).map_err(|_| StoreError::Unsafe)?;
    }
    snapshot_store::same_name(&file, dir.as_fd(), STAGE)?;
    sys::rename_at(dir.as_fd(), OsStr::new(STAGE), OsStr::new(RECORD))?;
    snapshot_store::same_name(&file, dir.as_fd(), RECORD)?;
    Ok(())
}
