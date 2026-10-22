//! Bounded pipe exchange. Only validated final values cross the publication gate.
use super::{
    collector_process::{self, OwnedChild, SignalChild, now_ns},
    helper_limits::{CollectorRegistration, Watchdog},
    snapshot_store::StoreError,
};
use bingsu_core::{
    collection::{
        response::Completed,
        selection::PRODUCT,
        wire::{self, EndReason, Frame, Kind, Request, Transcript},
    },
    field::SegmentDecl,
    snapshot::ClockSource,
};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
    time::Duration,
};

const READY_NS: u64 = 100_000_000;
const LIFE_NS: u64 = 1_000_000_000;
const REQUEST_MS: u32 = 50;
#[cfg(test)]
pub(crate) static POLL_INTERRUPTS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

type Publisher = Box<dyn FnOnce(Completed) -> Result<(), StoreError> + Send>;

pub(crate) struct CollectorJob {
    child: OwnedChild,
    request: Request,
    input: File,
    output: File,
    _lock: File,
    registration: CollectorRegistration,
    started_ns: u64,
    lifecycle: Lifecycle,
    publication_clock: Option<Arc<std::sync::atomic::AtomicU64>>,
    life_ns: u64,
    helper_ns: u64,
    catalog: &'static [SegmentDecl],
    #[cfg(test)]
    fixture_clock: bool,
    #[cfg(test)]
    ready_ns: Option<u64>,
}

/// Helper-local monotonic observations, never timestamps subtracted across processes.
/// Missing events stay None on failure; observation cannot admit work or extend a deadline.
#[derive(Debug, Default, Clone)]
#[allow(dead_code, reason = "M3b lifecycle measurement report")]
pub(crate) struct Lifecycle {
    pub verify_start: Option<u64>,
    pub verify_end: Option<u64>,
    pub spawn_enter: Option<u64>,
    pub spawn_return: Option<u64>,
    pub ready: Option<u64>,
    pub request_sent: Option<u64>,
    pub completed: Option<u64>,
    pub response_renamed: Option<u64>,
    pub lock_acquired: Option<u64>,
    pub lock_closed: Option<u64>,
    pub request_deadline: Option<u64>,
    pub landlock_abi: Option<u32>,
    pub as_baseline: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct SupervisionReport {
    pub reason: EndReason,
    pub bytes: u32,
    pub frames: u16,
    pub kill_requested: bool,
    pub reaped: bool,
    pub published: bool,
    pub lifecycle: Lifecycle,
    #[cfg(test)]
    pub unconfined_reads: u32,
    #[cfg(test)]
    pub unconfined_decodes: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Permission {
    Pending,
    Confined,
    Cancelled,
}
struct Barrier {
    state: Mutex<Permission>,
    changed: Condvar,
}
pub(crate) struct SupervisorHandle {
    thread: Option<JoinHandle<SupervisionReport>>,
    barrier: Arc<Barrier>,
    signal: SignalChild,
}

impl CollectorJob {
    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "Linux native integration fixes the pidfd before TSYNC"
    )]
    pub fn child_pidfd(&self) -> Option<std::os::fd::RawFd> {
        self.child.pidfd()
    }

    #[cfg(test)]
    #[allow(dead_code, reason = "native integration observes queued Ready bytes")]
    pub(crate) fn fixture_input(&self) -> io::Result<File> {
        self.input.try_clone()
    }

    #[cfg(test)]
    #[allow(dead_code, reason = "used by the native integration target")]
    pub(crate) fn fixture(
        exe: &std::ffi::OsStr,
        mode: &std::ffi::OsStr,
        request: Request,
        lock: File,
        watchdog: &Watchdog,
        catalog: &'static [SegmentDecl],
    ) -> io::Result<Self> {
        let mut job = Self::launch(
            request,
            lock,
            watchdog,
            now_ns()?,
            catalog,
            |read, write, lock, deadline| {
                collector_process::spawn_args(exe, &[mode], read, write, lock, deadline)
            },
        )?;
        job.fixture_clock = true;
        Ok(job)
    }

    pub(crate) fn new(
        exe: &std::ffi::OsStr,
        request: Request,
        lock: File,
        watchdog: &Watchdog,
        started_ns: u64,
    ) -> io::Result<Self> {
        Self::launch(
            request,
            lock,
            watchdog,
            started_ns,
            PRODUCT.segments,
            |read, write, lock, deadline| {
                collector_process::spawn(exe, read, write, lock, deadline)
            },
        )
    }

    fn launch(
        request: Request,
        lock: File,
        watchdog: &Watchdog,
        started_ns: u64,
        catalog: &'static [SegmentDecl],
        spawn: impl FnOnce(&File, &File, &File, u64) -> io::Result<OwnedChild>,
    ) -> io::Result<Self> {
        let (ready_ns, life_ns) = deadlines(started_ns, watchdog.expires_ns());
        if now_ns()? >= life_ns {
            return Err(io::Error::other("collector lifetime"));
        }
        let (input, response) = collector_process::pipe()?;
        let (request_read, output) = collector_process::pipe()?;
        collector_process::nonblocking(&input)?;
        collector_process::nonblocking(&output)?;
        if now_ns()? >= ready_ns {
            return Err(io::Error::other("collector startup deadline"));
        }
        let child = spawn(&request_read, &response, &lock, watchdog.expires_ns())?;
        let registration = watchdog.register_collector(&child, ready_ns)?;
        let lifecycle = Lifecycle {
            spawn_enter: child.spawn_enter,
            spawn_return: child.spawn_return,
            ..Lifecycle::default()
        };
        Ok(Self {
            child,
            request,
            input,
            output,
            _lock: lock,
            registration,
            started_ns,
            lifecycle,
            publication_clock: None,
            life_ns,
            helper_ns: watchdog.expires_ns(),
            catalog,
            #[cfg(test)]
            fixture_clock: false,
            #[cfg(test)]
            ready_ns: None,
        })
    }

    pub(crate) fn observations(
        mut self,
        verify_start: Option<u64>,
        verify_end: Option<u64>,
        lock_acquired: Option<u64>,
        publication_clock: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.lifecycle.verify_start = verify_start;
        self.lifecycle.verify_end = verify_end;
        self.lifecycle.lock_acquired = lock_acquired;
        self.publication_clock = Some(publication_clock);
        self
    }

    pub fn start(self, publish: Publisher) -> io::Result<SupervisorHandle> {
        let signal = self.child.signal_copy()?;
        let barrier = Arc::new(Barrier {
            state: Mutex::new(Permission::Pending),
            changed: Condvar::new(),
        });
        let gate = barrier.clone();
        let thread = std::thread::Builder::new()
            .name("collect-supervisor".into())
            .stack_size(512 * 1024)
            .spawn(move || self.run(publish, gate))?;
        Ok(SupervisorHandle {
            thread: Some(thread),
            barrier,
            signal,
        })
    }

    fn run(mut self, publish: Publisher, barrier: Arc<Barrier>) -> SupervisionReport {
        let mut report = SupervisionReport {
            reason: EndReason::Resource,
            bytes: 0,
            frames: 0,
            kill_requested: false,
            reaped: false,
            published: false,
            lifecycle: self.lifecycle.clone(),
            #[cfg(test)]
            unconfined_reads: 0,
            #[cfg(test)]
            unconfined_decodes: 0,
        };
        let result = Transcript::with_catalog(&self.request, self.catalog);
        if let Ok(mut transcript) = result {
            report.reason = self.exchange(&mut transcript, &mut report, &barrier);
            if report.reason != EndReason::Complete {
                report.reason = self.registration.reason().unwrap_or(report.reason);
            }
            if report.reason != EndReason::Complete {
                let _ = self.child.signal(libc::SIGKILL);
            }
            // Cancellation also gates publication. No snapshot lock is owned
            // here, and a stalled publisher cannot block the watchdog.
            let clock = super::clock::SystemClock.observe();
            #[cfg(test)]
            let clock = if self.fixture_clock {
                fixture_clock()
            } else {
                clock
            };
            let completed = clock
                .ok()
                .and_then(|clock| transcript.finish(report.reason, clock).ok().flatten());
            if let Some(completed) = completed {
                let mut permission = barrier.state.lock().unwrap_or_else(|e| e.into_inner());
                while *permission == Permission::Pending {
                    let remaining = self.helper_ns.saturating_sub(now_ns().unwrap_or(u64::MAX));
                    if remaining == 0 {
                        break;
                    }
                    permission = barrier
                        .changed
                        .wait_timeout(permission, Duration::from_nanos(remaining))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                if *permission == Permission::Confined
                    && now_ns().is_ok_and(|now| now < self.helper_ns)
                {
                    // Serialize cancellation with the publication admission.
                    drop(permission);
                    report.published = publish(completed).is_ok();
                    report.lifecycle.response_renamed =
                        self.publication_clock.as_ref().and_then(|stamp| {
                            let value = stamp.load(std::sync::atomic::Ordering::Acquire);
                            (value != 0).then_some(value)
                        });
                }
            }
            // EOF is not proof of process death. Complete workers that keep
            // running remain registered until the request's absolute deadline.
            loop {
                match self.child.reap() {
                    Ok(true) => {
                        report.reaped = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
                if now_ns().map_or(true, |n| n >= self.helper_ns) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        report.kill_requested = self.child.kill_requested();
        drop(self._lock);
        report.lifecycle.lock_closed = now_ns().ok();
        #[cfg(test)]
        if self.fixture_clock {
            eprintln!(
                "lifecycle: spawn_to_ready_ns={:?}, spawn_to_lock_close_ns={}, ready_deadline_ns={}, life_deadline_ns={}, reason={:?}",
                self.ready_ns
                    .map(|ready| ready.saturating_sub(self.started_ns)),
                now_ns().unwrap().saturating_sub(self.started_ns),
                deadlines(self.started_ns, self.helper_ns).0,
                self.life_ns,
                report.reason
            );
        }
        report
    }

    fn exchange(
        &mut self,
        transcript: &mut Transcript,
        report: &mut SupervisionReport,
        barrier: &Barrier,
    ) -> EndReason {
        // The supervisor thread must exist before TSYNC, but cannot touch the
        // hostile pipe until both limits and the synchronized filter are live.
        // Waiting consumes the original spawn-to-Ready budget.
        let mut deadline = deadlines(self.started_ns, self.helper_ns).0;
        let mut permission = barrier.state.lock().unwrap_or_else(|e| e.into_inner());
        while *permission == Permission::Pending {
            let Ok(now) = now_ns() else {
                return EndReason::Resource;
            };
            let remaining = deadline.saturating_sub(now);
            if remaining == 0 {
                return EndReason::Deadline;
            }
            permission = barrier
                .changed
                .wait_timeout(permission, Duration::from_nanos(remaining))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        if *permission != Permission::Confined {
            return EndReason::Resource;
        }
        drop(permission);
        let mut buffer = Box::new([0u8; wire::FRAME_MAX]);
        let mut have = 0;
        let mut want = wire::HEADER;
        let mut outgoing = Vec::new();
        let mut sent = 0;
        let mut ready = false;
        let mut complete = false;
        loop {
            let Ok(now) = now_ns() else {
                return EndReason::Resource;
            };
            if now >= deadline {
                return EndReason::Deadline;
            }
            if *barrier.state.lock().unwrap_or_else(|e| e.into_inner()) == Permission::Cancelled {
                return EndReason::Resource;
            }
            if sent < outgoing.len() {
                match self.output.write(&outgoing[sent..]) {
                    Ok(0) => return EndReason::WorkerExit,
                    Ok(n) => {
                        sent += n;
                        if sent == outgoing.len() {
                            if transcript.request_sent().is_err() {
                                return EndReason::Protocol;
                            }
                            report.lifecycle.request_sent = now_ns().ok();
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return EndReason::WorkerExit,
                }
                if now_ns().map_or(true, |now| now >= deadline) {
                    return EndReason::Deadline;
                }
            }
            #[cfg(test)]
            if *barrier.state.lock().unwrap_or_else(|e| e.into_inner()) == Permission::Pending {
                report.unconfined_reads += 1;
            }
            match self.input.read(&mut buffer[have..want]) {
                Ok(0) => {
                    return if transcript.accept_bytes(&buffer[..have]).is_ok() && complete {
                        EndReason::Complete
                    } else {
                        EndReason::Protocol
                    };
                }
                Ok(n) => {
                    report.bytes += n as u32;
                    if report.bytes as usize > wire::STREAM_MAX {
                        return EndReason::Protocol;
                    }
                    if complete {
                        return EndReason::Protocol;
                    }
                    have += n;
                    if now_ns().map_or(true, |now| now >= deadline) {
                        return EndReason::Deadline;
                    }
                    if have == wire::HEADER {
                        let Ok(length) = wire::frame_len(&buffer[..have]) else {
                            return EndReason::Protocol;
                        };
                        want = length;
                    }
                    if have == want {
                        #[cfg(test)]
                        if *barrier.state.lock().unwrap_or_else(|e| e.into_inner())
                            == Permission::Pending
                        {
                            report.unconfined_decodes += 1;
                        }
                        let Ok(frame) = wire::decode_frame(&buffer[..have]) else {
                            return EndReason::Protocol;
                        };
                        report.frames += 1;
                        // The codec is transactional, not latched: the adapter
                        // must return at its FIRST rejection.
                        if transcript.accept(frame).is_err() {
                            return EndReason::Protocol;
                        }
                        complete = frame.kind == Kind::Complete;
                        if complete {
                            report.lifecycle.completed = now_ns().ok();
                        }
                        if !ready {
                            ready = true;
                            let Ok(start) = now_ns() else {
                                return EndReason::Resource;
                            };
                            #[cfg(test)]
                            {
                                self.ready_ns = Some(start);
                            }
                            report.lifecycle.ready = Some(start);
                            report.lifecycle.landlock_abi = Some(u32::from_le_bytes(
                                frame.payload[12..16].try_into().unwrap(),
                            ));
                            report.lifecycle.as_baseline = Some(u64::from_le_bytes(
                                frame.payload[16..24].try_into().unwrap(),
                            ));
                            let budget =
                                request_budget(self.life_ns, start, self.request.budget_ms);
                            if budget == 0 {
                                return EndReason::Deadline;
                            }
                            self.request.budget_ms = budget;
                            deadline = start
                                .saturating_add(u64::from(budget) * 1_000_000)
                                .min(self.life_ns);
                            // The watchdog starts with Ready's tighter bound;
                            // after Ready its bound becomes the request end.
                            self.registration.set_deadline(deadline);
                            report.lifecycle.request_deadline = Some(deadline);
                            let Ok(bytes) = request_bytes(&self.request, &mut buffer) else {
                                return EndReason::Protocol;
                            };
                            outgoing = bytes;
                        }
                        have = 0;
                        want = if complete { 1 } else { wire::HEADER };
                    }
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return EndReason::WorkerExit,
            }
            let Ok(now) = now_ns() else {
                return EndReason::Resource;
            };
            if now >= deadline {
                return EndReason::Deadline;
            }
            let mut fds = [
                libc::pollfd {
                    fd: self.input.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if sent < outgoing.len() {
                        self.output.as_raw_fd()
                    } else {
                        -1
                    },
                    events: libc::POLLOUT,
                    revents: 0,
                },
            ];
            let timeout = (deadline.saturating_sub(now).div_ceil(1_000_000)).min(2) as i32;
            // SAFETY: two initialized pollfd records and bounded nonnegative timeout.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            if rc < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return EndReason::Resource;
                }
                #[cfg(test)]
                POLL_INTERRUPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

fn deadlines(started_ns: u64, helper_ns: u64) -> (u64, u64) {
    let life_ns = started_ns.saturating_add(LIFE_NS).min(helper_ns);
    (started_ns.saturating_add(READY_NS).min(life_ns), life_ns)
}

fn request_budget(life_ns: u64, start_ns: u64, requested_ms: u32) -> u32 {
    (life_ns.saturating_sub(start_ns) / 1_000_000).min(u64::from(requested_ms.min(REQUEST_MS)))
        as u32
}

#[cfg(test)]
pub(crate) fn fixture_clock()
-> Result<bingsu_core::snapshot::Clock, bingsu_core::snapshot::ClockError> {
    Ok(bingsu_core::snapshot::Clock {
        boot: [1; 16],
        kind: 1,
        domain: [0; 16],
        resume: 0,
        now: now_ns().map_err(|_| bingsu_core::snapshot::ClockError::Time)?,
    })
}

fn request_bytes(
    request: &Request,
    buffer: &mut [u8; wire::FRAME_MAX],
) -> Result<Vec<u8>, wire::ProtocolError> {
    let body = request.encode_body()?;
    let mut bytes = Vec::new();
    let mut append = |kind, payload: &[u8]| {
        let n = wire::encode_frame(
            Frame {
                kind,
                build_id: request.binding.build_id,
                request_id: request.request_id,
                payload,
            },
            buffer,
        )?;
        if bytes.len() + n > wire::STREAM_MAX {
            return Err(wire::ProtocolError::Budget);
        }
        bytes.extend_from_slice(&buffer[..n]);
        Ok(())
    };
    let mut begin = Vec::from((body.len() as u32).to_le_bytes());
    begin.extend_from_slice(&wire::FEATURES.to_le_bytes());
    append(Kind::RequestBegin, &begin)?;
    let mut offset = 0u32;
    for part in body.chunks(wire::PAYLOAD_MAX - 4) {
        let mut payload = Vec::from(offset.to_le_bytes());
        payload.extend_from_slice(part);
        append(Kind::RequestChunk, &payload)?;
        offset += part.len() as u32;
    }
    append(Kind::RequestEnd, &bingsu_core::snapshot::crc32c(&[&body]))?;
    Ok(bytes)
}

impl SupervisorHandle {
    pub fn child_pidfd(&self) -> Option<std::os::fd::RawFd> {
        self.signal.pidfd()
    }

    #[cfg(test)]
    #[allow(dead_code, reason = "native integration observes confinement timeout")]
    pub(crate) fn fixture_finished(&self) -> bool {
        self.thread.as_ref().unwrap().is_finished()
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "native integration test interrupts the live poll thread"
    )]
    pub(crate) fn fixture_interrupt(&self) {
        use std::os::unix::thread::JoinHandleExt;
        let thread = self.thread.as_ref().unwrap().as_pthread_t();
        // libc models musl's pthread_t as a pointer; std exposes its raw word.
        #[cfg(target_env = "musl")]
        let thread = thread as libc::pthread_t;
        // SAFETY: this handle owns a live or exited-but-unjoined thread. The
        // isolated test installs a handler before delivering this signal.
        let rc = unsafe { libc::pthread_kill(thread, libc::SIGUSR1) };
        assert!(rc == 0 || rc == libc::ESRCH);
    }
    /// Call only after helper limits and the TSYNC filter have both succeeded.
    pub fn confirm_confinement(&self) -> io::Result<()> {
        let mut state = self.barrier.state.lock().unwrap_or_else(|e| e.into_inner());
        if *state != Permission::Pending {
            return Err(io::Error::other("confinement gate"));
        }
        *state = Permission::Confined;
        self.barrier.changed.notify_all();
        Ok(())
    }
    pub fn finish(mut self) -> SupervisionReport {
        {
            let mut permission = self.barrier.state.lock().unwrap_or_else(|e| e.into_inner());
            if *permission == Permission::Pending {
                *permission = Permission::Cancelled;
                self.barrier.changed.notify_all();
                let _ = self.signal.signal(libc::SIGKILL);
            }
        }
        self.thread
            .take()
            .unwrap()
            .join()
            .unwrap_or_else(|_| SupervisionReport {
                reason: EndReason::Resource,
                bytes: 0,
                frames: 0,
                kill_requested: self.signal.signal(libc::SIGKILL).is_ok(),
                reaped: self.signal.reaped(),
                published: false,
                lifecycle: Lifecycle::default(),
                #[cfg(test)]
                unconfined_reads: 0,
                #[cfg(test)]
                unconfined_decodes: 0,
            })
    }
}
impl Drop for SupervisorHandle {
    fn drop(&mut self) {
        if self.thread.is_some() {
            *self.barrier.state.lock().unwrap_or_else(|e| e.into_inner()) = Permission::Cancelled;
            self.barrier.changed.notify_all();
            let _ = self.signal.signal(libc::SIGKILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 100ms/1s 상한이나 helper 잔여 수명으로의 재제한을 없애는 것.
    #[test]
    fn helper_remaining_lifetime_bounds_every_phase() {
        for (started, helper, ready, life) in [
            (0, 2_000_000_000, 100_000_000, 1_000_000_000),
            (0, 70_000_000, 70_000_000, 70_000_000),
            (1_000_000_000, 2_000_000_000, 1_100_000_000, 2_000_000_000),
            (1_999_500_000, 2_000_000_000, 2_000_000_000, 2_000_000_000),
        ] {
            assert_eq!(deadlines(started, helper), (ready, life));
        }
        assert_eq!(request_budget(2_000_000_000, 1_999_500_000, 50), 0);
    }

    // 이것을 실패시키는 것: 남은 밀리초를 올림하거나 50ms/호출자 예산 상한을 없애는 것.
    #[test]
    fn absolute_budget_rounds_down_and_never_exceeds_lifetime() {
        for (life, start, requested, expected) in [
            (10, 11, 50, 0),
            (999_999, 0, 50, 0),
            (1_000_000, 0, 50, 1),
            (1_999_999, 0, 50, 1),
            (2_000_000, 0, 1, 1),
            (1_000_000_000, 0, 51, 50),
            (1_000_000_000, 999_500_000, 50, 0),
        ] {
            assert_eq!(request_budget(life, start, requested), expected);
        }
    }
}
