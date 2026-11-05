//! Command supervisor `bingsu __command-v1` (spec section 4, process row
//! "command supervisor"; U-1 C+, U-15 Q1). The refresh helper spawns it
//! before its own filter with an empty environment and exactly descriptors
//! 0 to 2 (`/dev/null`), 3 the grant pipe's read end, 4 the result pipe's
//! write end and 5 a close-only copy of the session lock. It waits for the
//! one grant; end of file before one runs nothing. For each unit it repeats
//! the approval right before that unit's relay spawn, then supervises every
//! relay in one `poll` loop with the grant pipe (done or end of file: the
//! helper is gone, so every child is ended), the result pipe's partial
//! writes, each child's stdout (4 KB, never parsed) and status, and the next
//! deadline. Every decision is `bingsu_core::command`; this file makes the
//! system calls.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use super::{collector_process::OwnedChild, command_process};
use bingsu_core::{
    command::{
        deadline::Budget,
        grant::{self, Refusal},
        plan,
        wire::{self, Grant, Message, Outcome, Policy, Reason, STDOUT_MAX},
    },
    handoff::{self, Cwd, ExecFrame, Origin, RELAY_INPUT_MAX},
    snapshot::Clock,
};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    process::ExitCode,
};

pub(crate) const ENTRY: &str = "__command-v1";
pub(crate) const GRANT_FD: i32 = 3;
pub(crate) const RESULT_FD: i32 = 4;
pub(crate) const LOCK_FD: i32 = 5;
/// The session's cgroup parent, open only on the atomic path (C3 ruling R2).
#[cfg(target_os = "linux")]
pub(crate) const CGROUP_FD: i32 = 6;
/// U-9d: the round ends 100 ms before the helper's deadline, and a unit
/// with less than 10 ms left is not spawned.
pub(crate) const BUDGET: Budget = Budget {
    reserve: 100_000_000,
    min_run: 10_000_000,
};
/// Relay refusal codes (`relay.rs`), read from its status pipe.
const RELAY_INPUT: u8 = 120;
const RELAY_EXPIRED: u8 = 121;
const RELAY_TARGET: u8 = 122;
/// How often macOS, which has no pidfd, looks for an exited child.
#[cfg(not(target_os = "linux"))]
const REAP_TICK_NS: u64 = 2_000_000;

pub(crate) fn run(argv0: &OsStr) -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    let Ok(relay) = CString::new(argv0.as_bytes()) else {
        return ExitCode::from(1);
    };
    // Nothing the supervisor holds crosses a spawn; 3 and 4 never block it.
    for fd in [GRANT_FD, RESULT_FD, LOCK_FD] {
        if set_fd(fd, libc::FD_CLOEXEC).is_err() {
            return ExitCode::from(1);
        }
    }
    // The helper lives at most LIFETIME; a grant later than that (plus a
    // second) comes from no live helper.
    let until = super::collector_process::now_ns().ok().and_then(|now| {
        let life = super::helper_limits::LIFETIME + std::time::Duration::from_secs(1);
        now.checked_add(u64::try_from(life.as_nanos()).ok()?)
    });
    let Some((grant, rest)) = until.and_then(|until| wait_grant(GRANT_FD, until)) else {
        return ExitCode::SUCCESS;
    };
    let relay = Relay {
        exe: relay,
        prefix: Vec::new(),
    };
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut, reason = "Linux cgroups"))]
    let mut s = Supervisor::new(grant, rest, relay, GRANT_FD, RESULT_FD);
    #[cfg(target_os = "linux")]
    // Descriptor 6 is there only on the atomic path; nothing else crosses a spawn.
    if set_fd(CGROUP_FD, libc::FD_CLOEXEC).is_ok() {
        use std::os::fd::FromRawFd;
        // SAFETY: an open descriptor the helper placed for this process alone.
        s = s.with_cgroup(unsafe { File::from_raw_fd(CGROUP_FD) });
    }
    s.run(true);
    ExitCode::SUCCESS
}

/// How the supervisor starts a relay: `exe`, then `prefix`, then the relay
/// arguments. The product passes its own binary and no prefix (`bingsu
/// __exec-v2 …`); tests name a child test before the relay arguments.
pub(crate) struct Relay {
    pub exe: CString,
    pub prefix: Vec<Vec<u8>>,
}

fn set_fd(fd: i32, flags: i32) -> Result<(), ()> {
    // SAFETY: F_SETFD changes only this number's descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

fn nonblocking(fd: i32) -> Result<(), ()> {
    // SAFETY: plain descriptor flag query and update.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(());
    }
    Ok(())
}

fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> bool {
    // SAFETY: `fds` is a valid, writable array of its length.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    rc >= 0 || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
}

/// Reads `fd` into `buf`; `Some(0)` is end of file, `None` would block.
fn read_some(fd: i32, buf: &mut [u8]) -> Result<Option<usize>, ()> {
    // SAFETY: `buf` is writable for its length.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if let Ok(n) = usize::try_from(n) {
        return Ok(Some(n));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR) => Ok(None),
        _ => Err(()),
    }
}

/// The grant, and any bytes read after it (a done frame), or `None` when the
/// pipe ends or carries anything but one valid grant first.
pub(crate) fn wait_grant(fd: i32, until_ns: u64) -> Option<(Grant, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; wire::FRAME_MAX];
    loop {
        if buf.len() >= wire::HEADER {
            let total = wire::frame_len(&buf[..wire::HEADER]).ok()?;
            if buf.len() >= total {
                let Message::Grant(g) = wire::decode(&buf[..total]).ok()? else {
                    return None;
                };
                return Some((g, buf.split_off(total)));
            }
        }
        let mut fds = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        // Its own deadline too: a helper stopped (not killed) never ends the pipe.
        let now = super::collector_process::now_ns().ok()?;
        if now >= until_ns {
            return None;
        }
        let wait = i32::try_from((until_ns - now).div_ceil(1_000_000)).unwrap_or(i32::MAX);
        if !poll(&mut fds, wait) {
            return None;
        }
        if fds[0].revents == 0 {
            continue;
        }
        match read_some(fd, &mut chunk).ok()? {
            Some(0) => return None,
            Some(n) => buf.extend_from_slice(&chunk[..n]),
            None => {}
        }
    }
}

/// A builtin probe's fixed arguments and run time (spec: argv and
/// environment come from the profile table, never from the grant). The
/// table is D3's; until then no profile exists and a probe is refused.
struct Profile {
    args: &'static [&'static [u8]],
    timeout: u64,
}
fn profile(id: u8) -> Option<Profile> {
    #[cfg(test)]
    if id == tests::TEST_PROFILE {
        return Some(Profile {
            args: &[b"--version"],
            timeout: plan::TIMEOUT_DEFAULT,
        });
    }
    let _ = id;
    None
}

/// One spawned relay and what it has said so far.
struct Run {
    origin: Origin,
    index: u8,
    approved_at: u64,
    deadline: u64,
    child: OwnedChild,
    /// `cgroup.kill` of the unit's cgroup (atomic path), until written.
    kill: Option<File>,
    stdout: Option<File>,
    status: Option<File>,
    out: Vec<u8>,
    /// The relay's refusal code, when it wrote one.
    code: Option<u8>,
    /// The status pipe ended without a code: the target was executed.
    executed: bool,
    timed_out: bool,
    reaped: bool,
    reported: bool,
}

impl Run {
    /// Ends the target and everything it forked: SIGKILL to the relay's
    /// pidfd, and on the atomic path `1` into the unit's `cgroup.kill`
    /// (once; the descriptor is closed after it). On the best-effort path
    /// the relay's process group goes at its reap (OwnedChild::reap).
    fn end(&mut self) {
        let _ = self.child.signal(libc::SIGKILL);
        #[cfg(target_os = "linux")]
        if let Some(kill) = self.kill.take() {
            let _ = super::command_cgroup::fs::write_kill(&kill);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = &self.kill;
    }
    fn finished(&self) -> bool {
        self.reaped && self.status.is_none()
    }
    fn reason(&self) -> Reason {
        if self.timed_out {
            return Reason::Timeout;
        }
        match (self.code, self.executed) {
            (None, true) => self
                .child
                .wait_status()
                .map_or(Reason::SpawnFailed, Reason::Exited),
            // The relay's fresh clock was past a deadline.
            (Some(RELAY_EXPIRED), _) => Reason::Refused(match self.origin {
                Origin::Config => Refusal::Trust,
                Origin::Builtin => Refusal::Budget,
            }),
            (Some(RELAY_TARGET), _) => Reason::Refused(Refusal::Policy),
            (Some(RELAY_INPUT), _) => Reason::Refused(Refusal::Limit),
            _ => Reason::SpawnFailed,
        }
    }
}

pub(crate) struct Supervisor {
    grant: Grant,
    /// Bytes read from the grant pipe after the grant.
    tail: Vec<u8>,
    relay: Relay,
    grant_fd: Option<i32>,
    result_fd: i32,
    runs: Vec<Run>,
    /// Encoded results not yet written.
    pending: Vec<u8>,
    /// The helper is gone or done: every child is ended and nothing more is written.
    stopped: bool,
    /// The atomic path: the session's cgroup parent and the last unit name.
    #[cfg(target_os = "linux")]
    cgroup: Option<Cgroups>,
    #[cfg(test)]
    pub eagain: u32,
    /// Runs once the filter is installed (tests only).
    #[cfg(test)]
    pub confined: Option<Box<dyn FnOnce()>>,
}

impl Supervisor {
    pub(crate) fn new(
        grant: Grant,
        tail: Vec<u8>,
        relay: Relay,
        grant_fd: i32,
        result_fd: i32,
    ) -> Self {
        // Neither pipe may block the loop: a helper that stops reading
        // results must not keep the supervisor from seeing it is gone.
        // No test for the failure: fcntl(F_SETFL) on an open pipe end cannot
        // be made to fail from a test; it stops the round (fail closed), the
        // same class as the C1 macOS fcntl branch (user decision).
        let blocked = nonblocking(grant_fd).and(nonblocking(result_fd)).is_err();
        Self {
            stopped: blocked,
            grant,
            tail,
            relay,
            grant_fd: Some(grant_fd),
            result_fd,
            runs: Vec::new(),
            pending: Vec::new(),
            #[cfg(target_os = "linux")]
            cgroup: None,
            #[cfg(test)]
            eagain: 0,
            #[cfg(test)]
            confined: None,
        }
    }

    /// The atomic path, with the session's cgroup parent (descriptor 6).
    #[cfg(target_os = "linux")]
    pub(crate) fn with_cgroup(mut self, parent: File) -> Self {
        self.cgroup = Some(Cgroups { parent, seq: None });
        self
    }

    fn report(&mut self, origin: Origin, index: usize, reason: Reason, approved_at: u64) {
        let ended_at = super::collector_process::now_ns().unwrap_or(approved_at);
        self.push(Outcome {
            origin,
            index: u8::try_from(index).unwrap_or(u8::MAX),
            reason,
            approved_at,
            ended_at: ended_at.max(approved_at),
            stdout: Vec::new(),
        });
    }

    fn push(&mut self, o: Outcome) {
        if let Ok(frame) = wire::encode(&Message::Result(o)) {
            self.pending.extend_from_slice(&frame);
        }
    }

    /// Every unit, then every probe: approved right before its spawn.
    fn spawn_all(&mut self) {
        let units = self.grant.units.len();
        for index in 0..units {
            self.spawn_unit(index);
        }
        for index in 0..self.grant.probes.len() {
            self.spawn_probe(index);
        }
    }

    fn spawn_unit(&mut self, index: usize) {
        let now = clock();
        let at = now.map_or(0, |c| c.now);
        if index >= plan::CONFIG_MAX {
            return self.report(Origin::Config, index, Reason::Refused(Refusal::Limit), at);
        }
        let approved = now
            .map_err(|()| Refusal::Clock)
            .and_then(|now| grant::approve_unit(now, &self.grant, index, BUDGET));
        let deadline = match approved {
            Ok(e) => e,
            Err(r) => return self.report(Origin::Config, index, Reason::Refused(r), at),
        };
        let unit = &self.grant.units[index];
        let argv = match &unit.policy {
            Policy::Argv { argv } => plan::with_dir(argv, &self.grant.cwd),
            Policy::UnsafeShell { script } => vec![b"sh".to_vec(), b"-c".to_vec(), script.clone()],
        };
        let frame = ExecFrame {
            origin: Origin::Config,
            run_deadline: deadline,
            environment: unit.environment.clone(),
            pin: unit.pin,
            interpreter: unit.interpreter.clone(),
            cwd: Vec::new(),
        };
        let folder = match unit.cwd {
            Cwd::Neutral => self.grant.neutral.clone(),
            Cwd::UntrustedCurrent => self.grant.cwd.clone(),
        };
        let executable = unit.executable.clone();
        let cwd = unit.cwd;
        self.start(
            Origin::Config,
            index,
            at,
            deadline,
            &frame,
            &executable,
            cwd,
            &folder,
            &argv,
        );
    }

    fn spawn_probe(&mut self, index: usize) {
        let now = clock();
        let at = now.map_or(0, |c| c.now);
        if index >= plan::PROBE_MAX {
            return self.report(Origin::Builtin, index, Reason::Refused(Refusal::Limit), at);
        }
        let probe = &self.grant.probes[index];
        let Some(profile) = profile(probe.profile) else {
            return self.report(Origin::Builtin, index, Reason::Refused(Refusal::Policy), at);
        };
        let approved = now
            .map_err(|()| Refusal::Clock)
            .and_then(|now| grant::approve_probe(now, &self.grant, index, profile.timeout, BUDGET));
        let deadline = match approved {
            Ok(e) => e,
            Err(r) => return self.report(Origin::Builtin, index, Reason::Refused(r), at),
        };
        let name = probe
            .executable
            .rsplit(|&b| b == b'/')
            .next()
            .unwrap_or_default()
            .to_vec();
        let argv: Vec<Vec<u8>> = std::iter::once(name)
            .chain(profile.args.iter().map(|a| a.to_vec()))
            .collect();
        let frame = ExecFrame {
            origin: Origin::Builtin,
            run_deadline: deadline,
            environment: Vec::new(),
            pin: probe.pin,
            interpreter: None,
            cwd: Vec::new(),
        };
        let executable = probe.executable.clone();
        let folder = self.grant.neutral.clone();
        self.start(
            Origin::Builtin,
            index,
            at,
            deadline,
            &frame,
            &executable,
            Cwd::Neutral,
            &folder,
            &argv,
        );
    }

    #[allow(clippy::too_many_arguments, reason = "one spawn's fixed inputs")]
    fn start(
        &mut self,
        origin: Origin,
        index: usize,
        approved_at: u64,
        deadline: u64,
        frame: &ExecFrame,
        executable: &[u8],
        cwd: Cwd,
        folder: &[u8],
        argv: &[Vec<u8>],
    ) {
        // The relay enters the folder; the spawn itself happens in "/", so
        // a folder on a stopped mount never holds the supervisor.
        let frame = ExecFrame {
            cwd: folder.to_vec(),
            ..frame.clone()
        };
        // Over the relay's input cap: the unit's environment is too large.
        let Ok(input) = handoff::relay_input(self.grant.permit, &frame, RELAY_INPUT_MAX) else {
            return self.report(origin, index, Reason::Refused(Refusal::Limit), approved_at);
        };
        let words: Vec<&[u8]> = argv.iter().map(Vec::as_slice).collect();
        let Ok(relay_args) = handoff::relay_args(executable, cwd, &words) else {
            return self.report(origin, index, Reason::Refused(Refusal::Policy), approved_at);
        };
        let args: Vec<Vec<u8>> = std::iter::once(self.relay.exe.as_bytes().to_vec())
            .chain(self.relay.prefix.iter().cloned())
            .chain(relay_args.into_iter().map(<[u8]>::to_vec))
            .collect();
        // Checked right before posix_spawn, after every preparation step
        // (pipes, input, descriptors, actions). A poll and a spawn cannot be
        // one step, so the guarantee is: once the helper's death is observed
        // no new spawn follows, and a unit spawned before that is ended at the
        // loop's next poll of the grant pipe.
        let (fd, stopped) = (self.grant_fd, self.stopped);
        let go = move || !stopped && fd.is_some_and(|fd| !readable(fd));
        #[cfg(target_os = "linux")]
        let unit = match self.cgroup.as_mut().map(Cgroups::unit) {
            Some(Ok(u)) => Some(u),
            // A unit cgroup that cannot be made (or a name already taken)
            // runs nothing: never an old folder, never outside one.
            Some(Err(())) => {
                return self.report(origin, index, Reason::SpawnFailed, approved_at);
            }
            None => None,
        };
        #[cfg(target_os = "linux")]
        use std::os::fd::AsFd;
        #[cfg(target_os = "linux")]
        let mut spawned = command_process::spawn(
            &self.relay.exe,
            &args,
            &input,
            self.grant.helper_deadline,
            &go,
            unit.as_ref().map(|u| u.folder.as_fd()),
        );
        #[cfg(not(target_os = "linux"))]
        let spawned = command_process::spawn(
            &self.relay.exe,
            &args,
            &input,
            self.grant.helper_deadline,
            &go,
            None,
        );
        #[cfg(target_os = "linux")]
        let kill = match (unit, &spawned) {
            (Some(u), Ok(_)) => Some(u.kill),
            (Some(u), Err(e)) => {
                // ENOSYS or EPERM: no clone3 here; ENOENT or EACCES: the cgroup
                // cannot be entered (a namespace view the mount does not
                // match, no write access to its common ancestor).
                let clone3_missing = matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS | libc::EPERM | libc::ENOENT | libc::EACCES)
                );
                if let Some(c) = &self.cgroup {
                    c.remove(&u.name);
                }
                // clone3 refused before any unit ran in a cgroup: the whole
                // round takes the best-effort path (C3 rulings).
                if clone3_missing && !self.runs.iter().any(|r| r.kill.is_some()) {
                    self.cgroup = None;
                    spawned = command_process::spawn(
                        &self.relay.exe,
                        &args,
                        &input,
                        self.grant.helper_deadline,
                        &go,
                        None,
                    );
                }
                None
            }
            (None, _) => None,
        };
        #[cfg(not(target_os = "linux"))]
        let kill = None;
        if matches!(&spawned, Err(e) if e.kind() == std::io::ErrorKind::Interrupted) {
            return self.stop();
        }
        let Ok(s) = spawned else {
            return self.report(origin, index, Reason::SpawnFailed, approved_at);
        };
        self.runs.push(Run {
            origin,
            index: u8::try_from(index).unwrap_or(u8::MAX),
            approved_at,
            deadline,
            child: s.child,
            kill,
            stdout: Some(s.stdout),
            status: Some(s.status),
            out: Vec::new(),
            code: None,
            executed: false,
            timed_out: false,
            reaped: false,
            reported: false,
        });
    }

    /// Spawns, confines itself, then supervises until every result is
    /// written, the helper is gone or the helper's deadline passes.
    pub(crate) fn run(mut self, confine: bool) -> Self {
        // A done frame read with the grant stops the round before any spawn.
        let tail = std::mem::take(&mut self.tail);
        self.grant_bytes(&tail);
        self.spawn_all();
        if confine && self.confine().is_err() {
            // Without the filter nothing more may run: end the children.
            self.stop();
        }
        #[cfg(test)]
        if let Some(confined) = self.confined.take() {
            confined();
        }
        while !self.over() {
            self.step();
        }
        self.stop();
        self
    }

    fn over(&self) -> bool {
        let now = super::collector_process::now_ns().unwrap_or(u64::MAX);
        self.stopped
            || now >= self.grant.helper_deadline
            || self.runs.iter().all(Run::finished) && self.pending.is_empty()
    }

    fn stop(&mut self) {
        self.stopped = true;
        for run in &mut self.runs {
            // Without a cgroup the relay's process group goes when this exit
            // is reaped (OwnedChild::reap of a group leader), in a later step
            // or in the drop when the supervisor ends first (best effort: a
            // descendant that called setsid stays).
            run.end();
        }
    }

    /// Bytes after the grant: a done frame stops the round; anything else
    /// is not from a working helper either.
    fn grant_bytes(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.stop();
        }
    }

    fn step(&mut self) {
        let now = super::collector_process::now_ns().unwrap_or(u64::MAX);
        let mut next = self.grant.helper_deadline;
        for run in self.runs.iter_mut().filter(|r| !r.reaped) {
            if now >= run.deadline && !run.timed_out {
                run.timed_out = true;
                run.end();
            }
            if !run.timed_out {
                next = next.min(run.deadline);
            }
        }
        #[cfg(not(target_os = "linux"))]
        if self.runs.iter().any(|r| !r.reaped) {
            next = next.min(now.saturating_add(REAP_TICK_NS));
        }
        let mut fds = Vec::new();
        if let Some(fd) = self.grant_fd {
            fds.push(pollfd(fd, libc::POLLIN));
        }
        if !self.pending.is_empty() {
            fds.push(pollfd(self.result_fd, libc::POLLOUT));
        }
        for run in &self.runs {
            if let Some(f) = &run.stdout {
                fds.push(pollfd(f.as_raw_fd(), libc::POLLIN));
            }
            if let Some(f) = &run.status {
                fds.push(pollfd(f.as_raw_fd(), libc::POLLIN));
            }
            #[cfg(target_os = "linux")]
            if !run.reaped
                && let Some(fd) = run.child.pidfd()
            {
                fds.push(pollfd(fd, libc::POLLIN));
            }
        }
        let wait = next.saturating_sub(now).div_ceil(1_000_000);
        if !poll(&mut fds, i32::try_from(wait).unwrap_or(i32::MAX)) {
            return self.stop();
        }
        self.read_grant_pipe();
        self.write_results();
        let mut done = Vec::new();
        for run in &mut self.runs {
            read_stdout(run);
            read_status(run);
            if !run.reaped {
                run.reaped = run.child.reap().unwrap_or(true);
                if run.reaped {
                    // What the target left running (setsid or not) ends with it.
                    run.end();
                    // The relay is gone: what its pipes hold now is all it wrote.
                    read_status(run);
                    read_stdout(run);
                }
            }
            if run.finished() && !run.reported {
                run.reported = true;
                done.push(Outcome {
                    origin: run.origin,
                    index: run.index,
                    reason: run.reason(),
                    approved_at: run.approved_at,
                    ended_at: super::collector_process::now_ns()
                        .unwrap_or(run.approved_at)
                        .max(run.approved_at),
                    stdout: std::mem::take(&mut run.out),
                });
            }
        }
        for o in done {
            self.push(o);
        }
    }

    fn read_grant_pipe(&mut self) {
        let Some(fd) = self.grant_fd else { return };
        let mut buf = [0u8; 64];
        match read_some(fd, &mut buf) {
            Ok(None) => {}
            // End of file, a done frame or any other byte: the helper is
            // gone or finished, so nothing it would read is still wanted.
            Ok(Some(_)) | Err(()) => {
                self.grant_fd = None;
                self.stop();
            }
        }
    }

    fn write_results(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        // SAFETY: `pending` is readable for its length.
        let n = unsafe {
            libc::write(
                self.result_fd,
                self.pending.as_ptr().cast(),
                self.pending.len(),
            )
        };
        match usize::try_from(n) {
            Ok(n) => {
                self.pending.drain(..n);
            }
            Err(_) if std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) => {
                #[cfg(test)]
                {
                    self.eagain += 1;
                }
            }
            // The helper closed its end: nobody reads results any more. No
            // test: the helper closes its read end only after done or at its
            // own exit, which the grant pipe reports first; EPIPE here ends the
            // round (fail closed), the same class as the C1 macOS fcntl branch.
            Err(_) => self.stop(),
        }
    }
}

/// The session's cgroup parent and the names this supervisor made in it.
#[cfg(target_os = "linux")]
struct Cgroups {
    parent: File,
    seq: Option<u64>,
}

/// One unit's cgroup, made right before its spawn.
#[cfg(target_os = "linux")]
struct UnitCgroup {
    name: String,
    folder: File,
    kill: File,
}

#[cfg(target_os = "linux")]
impl Cgroups {
    /// A new unit cgroup with a name never used in this boot: `mkdirat`
    /// fails on a name that exists, and nothing reuses it then.
    fn unit(&mut self) -> Result<UnitCgroup, ()> {
        use std::os::fd::AsFd;
        let now = super::collector_process::now_ns().map_err(|_| ())?;
        let seq = bingsu_core::command::cgroup::next_seq(self.seq, now);
        self.seq = Some(seq);
        let name = bingsu_core::command::cgroup::unit_name(seq);
        let os = OsStr::new(&name);
        if !super::sys::mkdir_at(self.parent.as_fd(), os, 0o755).map_err(|_| ())? {
            return Err(());
        }
        let made = (|| {
            let folder = super::sys::open_dir_at_nofollow(self.parent.as_fd(), os).ok()?;
            let kill = super::command_cgroup::fs::kill_file(&folder).ok()?;
            Some((folder, kill))
        })();
        // No test for the None arm: a folder this call just made opens, and
        // every cgroup v2 folder from 5.14 has cgroup.kill; it runs nothing
        // (fail closed), the same class as the C1 fcntl branch.
        match made {
            Some((folder, kill)) => Ok(UnitCgroup { name, folder, kill }),
            None => {
                self.remove(&name);
                Err(())
            }
        }
    }

    /// Removes an empty unit folder (before the filter: no process ran in it).
    fn remove(&self, name: &str) {
        use std::os::fd::AsFd;
        let _ = super::sys::remove_dir_at(self.parent.as_fd(), OsStr::new(name));
    }
}

/// Whether anything is readable on the grant pipe now: a done frame or end
/// of file, either way the helper is gone or done.
fn readable(fd: i32) -> bool {
    let mut fds = [pollfd(fd, libc::POLLIN)];
    !poll(&mut fds, 0) || fds[0].revents != 0
}

fn pollfd(fd: i32, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// What the pipe holds now: the first `STDOUT_MAX` bytes are kept, the
/// rest is read and dropped. The pipe stays open, so a target that writes
/// more is not ended by EPIPE and keeps its own exit status; one that never
/// stops is ended by its run deadline. At most `DRAIN_CHUNKS` reads per
/// call, so an endless writer cannot hold the loop; after the reap the call
/// takes what was written before the exit.
fn read_stdout(run: &mut Run) {
    let mut buf = [0u8; STDOUT_MAX];
    for _ in 0..DRAIN_CHUNKS {
        let Some(f) = &run.stdout else { return };
        match read_some(f.as_raw_fd(), &mut buf) {
            Ok(None) => return,
            Ok(Some(0)) | Err(()) => run.stdout = None,
            Ok(Some(n)) => {
                let room = STDOUT_MAX - run.out.len();
                run.out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
}
/// 16 reads of 4 KB per loop turn.
const DRAIN_CHUNKS: usize = 16;

fn read_status(run: &mut Run) {
    let Some(f) = &mut run.status else { return };
    let mut b = [0u8; 1];
    match f.read(&mut b) {
        Ok(0) => {
            run.executed = run.code.is_none();
            run.status = None;
        }
        Ok(_) => run.code = Some(b[0]),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(_) => run.status = None,
    }
}

fn clock() -> Result<Clock, ()> {
    crate::prompt_io::observe_clock().map_err(|_| ())
}

impl Supervisor {
    /// After the last spawn (spec: the supervisor's own filter): no exec,
    /// no new process, no new descriptor, and signals only through the
    /// pidfds of the children it holds now (Linux).
    fn confine(&self) -> std::io::Result<()> {
        let pidfds: Vec<std::os::fd::RawFd> =
            self.runs.iter().filter_map(|r| r.child.pidfd()).collect();
        let groups: Vec<libc::pid_t> = self
            .runs
            .iter()
            .filter(|r| r.child.group())
            .map(|r| r.child.pid)
            .collect();
        super::helper_filter::install_supervisor(&pidfds, &groups)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bingsu_core::{
        command::wire::{Probe, Unit, policy_digest},
        handoff::Permit,
    };
    use std::os::fd::{FromRawFd, OwnedFd};

    pub(crate) const TEST_PROFILE: u8 = 255;
    const MS: u64 = 1_000_000;
    const STUB: &str = "commands::command_supervisor::tests::stub_relay";

    /// Stands in for the relay: libtest runs it with the relay arguments as
    /// extra filters after `--`. Its target argv[0] picks what it does; it
    /// says "executed" by closing fd 2 (the status pipe) like a relay whose
    /// execveat succeeded, or writes a refusal code there.
    #[test]
    #[ignore = "child: one stub relay"]
    fn stub_relay() {
        let args: Vec<Vec<u8>> = std::env::args_os().map(|a| a.as_bytes().to_vec()).collect();
        let at = args.iter().position(|a| a == b"__exec-v2").unwrap();
        let target = &args[at + 6..];
        let behaviour = target[0].clone();
        let say = |b: &[u8]| {
            // SAFETY: readable bytes; fd 1 is the stdout pipe.
            unsafe { libc::write(1, b.as_ptr().cast(), b.len()) };
        };
        if behaviour != b"noread" {
            let mut input = Vec::new();
            // SAFETY: fd 3 is this child's input pipe, owned here.
            let mut f = unsafe { File::from_raw_fd(3) };
            f.read_to_end(&mut input).unwrap();
            // As the relay: enter the frame's folder.
            let (_, frame) = handoff::read_relay_input(&input, RELAY_INPUT_MAX).unwrap();
            std::env::set_current_dir(std::ffi::OsStr::from_bytes(&frame.cwd)).unwrap();
        }
        let executed = || {
            // SAFETY: fd 2 is the status pipe; closing it is "executed".
            unsafe { libc::close(2) };
        };
        match behaviour.as_slice() {
            b"refuse" => {
                // SAFETY: one byte to the status pipe.
                unsafe { libc::write(2, [RELAY_TARGET].as_ptr().cast(), 1) };
                // SAFETY: plain exit of the child.
                unsafe { libc::_exit(i32::from(RELAY_TARGET)) }
            }
            b"sleep" | b"noread" => {
                executed();
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            b"split" => {
                // Two writes, then exit at once: the second can land after the
                // supervisor's read and before its reap.
                say(b"a");
                executed();
                say(b"b\n");
            }
            b"late" => {
                // Writes its canary after 300 ms, unless it is ended first.
                executed();
                std::thread::sleep(std::time::Duration::from_millis(300));
                std::fs::write(std::ffi::OsStr::from_bytes(&target[1]), b"x").unwrap();
            }
            b"big" => {
                // 256 KB, more than a pipe holds, then a normal exit. SIGPIPE
                // to its default, as in a C program (Rust ignores it).
                // SAFETY: plain disposition change.
                unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
                executed();
                for _ in 0..64 {
                    say(&[b'x'; 4096]);
                }
            }
            b"setsid" | b"setsid-exit" => {
                // A grandchild in its own session that outlives the target
                // (which waits, or with `-exit` ends at once):
                // only the unit's cgroup reaches it. Its pid goes to argv[1].
                // SAFETY: the child runs only async-signal-safe calls.
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    // SAFETY: in the forked child.
                    unsafe { libc::setsid() };
                    // SAFETY: as above.
                    unsafe { libc::sleep(60) };
                    // SAFETY: as above.
                    unsafe { libc::_exit(0) }
                }
                std::fs::write(std::ffi::OsStr::from_bytes(&target[1]), pid.to_string()).unwrap();
                executed();
                if behaviour == b"setsid" {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
            b"fork" | b"fork-exit" => {
                // A grandchild in the target's own process group (no new
                // session); with `-exit` the target ends at once.
                // SAFETY: the child runs only async-signal-safe calls.
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    // SAFETY: in the forked child.
                    unsafe { libc::sleep(60) };
                    // SAFETY: as above.
                    unsafe { libc::_exit(0) }
                }
                std::fs::write(std::ffi::OsStr::from_bytes(&target[1]), pid.to_string()).unwrap();
                executed();
                if behaviour == b"fork" {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
            b"nest" => {
                // Two nested cgroups below the unit's (depth 2) and one beside,
                // with a process moved into the deepest; argv[1] is told when.
                let text = std::fs::read("/proc/self/cgroup").unwrap();
                let own = bingsu_core::command::cgroup::own_path(&text).unwrap();
                let own = format!("/sys/fs/cgroup{}", String::from_utf8_lossy(own));
                std::fs::create_dir_all(format!("{own}/a/b")).unwrap();
                std::fs::create_dir_all(format!("{own}/c")).unwrap();
                // SAFETY: the child runs only async-signal-safe calls.
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    // SAFETY: in the forked child.
                    unsafe { libc::sleep(60) };
                    // SAFETY: as above.
                    unsafe { libc::_exit(0) }
                }
                std::fs::write(format!("{own}/a/b/cgroup.procs"), pid.to_string()).unwrap();
                std::fs::write(std::ffi::OsStr::from_bytes(&target[1]), b"ok").unwrap();
                executed();
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            b"yes" => {
                executed();
                loop {
                    // SAFETY: readable bytes; EPIPE ends the loop.
                    if unsafe { libc::write(1, b"y\n".as_ptr().cast(), 2) } < 0 {
                        break;
                    }
                }
            }
            _ => {
                executed();
                say(b"\nSTUB:");
                say(&target.join(&b' '));
                say(b":CWD:");
                say(std::env::current_dir().unwrap().as_os_str().as_bytes());
            }
        }
        // SAFETY: child exit without the harness's work.
        unsafe { libc::_exit(0) }
    }

    fn stub() -> Relay {
        Relay {
            exe: CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap(),
            prefix: [
                "--exact",
                STUB,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
                "--",
            ]
            .iter()
            .map(|w| w.as_bytes().to_vec())
            .collect(),
        }
    }

    fn permit(now: Clock, deadline: u64) -> Permit {
        Permit {
            kind: now.kind,
            deadline,
            boot: now.boot,
            resume: now.resume,
            domain: now.domain,
        }
    }

    pub(crate) fn unit(word: &str, timeout: u64) -> Unit {
        let policy = Policy::Argv {
            argv: vec![word.as_bytes().to_vec(), b"{dir}".to_vec()],
        };
        Unit {
            id: format!("custom/{word}"),
            digest: policy_digest(&policy, Cwd::Neutral, timeout, &[]),
            policy,
            cwd: Cwd::Neutral,
            environment: b"HOME=/h\0".to_vec(),
            timeout,
            env_allow: Vec::new(),
            executable: b"/bin/true".to_vec(),
            pin: None,
            interpreter: None,
        }
    }

    pub(crate) fn grant(units: Vec<Unit>, trust: u64) -> Grant {
        let now = clock().unwrap();
        Grant {
            permit: permit(now, now.now + trust),
            helper_deadline: now.now + 2_000 * MS,
            cwd: b"/a b;$(x)\n".to_vec(),
            neutral: std::env::temp_dir().as_os_str().as_bytes().to_vec(),
            units,
            probes: Vec::new(),
        }
    }

    /// A pipe; the read end is non-blocking.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let (r, w) = crate::commands::collector_process::pipe().unwrap();
        crate::commands::collector_process::nonblocking(&r).unwrap();
        (r.into(), w.into())
    }

    /// Runs one round in this process (no filter) with the helper alive
    /// (the grant pipe's write end open) and returns the results and how
    /// long it took.
    fn round(g: Grant) -> (Vec<Outcome>, std::time::Duration) {
        let (grant_read, grant_write) = pipe();
        let (result_read, result_write) = pipe();
        let started = std::time::Instant::now();
        let s = Supervisor::new(
            g,
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        let took = started.elapsed();
        drop(s);
        drop((grant_write, result_write));
        (results(result_read), took)
    }

    fn results(fd: OwnedFd) -> Vec<Outcome> {
        let mut bytes = Vec::new();
        File::from(fd).read_to_end(&mut bytes).unwrap_or_default();
        let mut out = Vec::new();
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            let n = wire::frame_len(rest).unwrap();
            let Message::Result(o) = wire::decode(&rest[..n]).unwrap() else {
                panic!("not a result")
            };
            out.push(o);
            rest = &rest[n..];
        }
        out.sort_by_key(|o| (o.origin.tag(), o.index));
        out
    }

    fn spawned(o: &Outcome) -> bool {
        !matches!(o.reason, Reason::Refused(_) | Reason::SpawnFailed)
    }

    // 허가 없이 파이프가 닫히면(도우미 SIGKILL, 발행 실패로 버림) 아무것도 실행하지 않는다. 이것을
    // 실패시키는 것: wait_grant가 EOF에서 None 대신 빈 허가를 돌려주는 것, 허가 아닌 프레임(done)을 허가로
    // 받는 것, 잘린 허가를 받아들이는 것.
    #[test]
    fn test_no_grant_means_no_exec() {
        let frame = wire::encode(&Message::Grant(grant(vec![unit("ok", MS)], MS))).unwrap();
        let done = wire::encode(&Message::Done).unwrap();
        for bytes in [&b""[..], &done, &frame[..frame.len() - 1]] {
            let (read, write) = pipe();
            assert!(matches!(
                super::super::sys::write_fd(write.as_raw_fd(), bytes),
                super::super::sys::WriteOutcome::Done
            ));
            drop(write);
            assert!(
                wait_grant(read.as_raw_fd(), u64::MAX).is_none(),
                "{} bytes",
                bytes.len()
            );
        }
        let (read, write) = pipe();
        let both = [frame.as_slice(), &done].concat();
        assert!(matches!(
            super::super::sys::write_fd(write.as_raw_fd(), &both),
            super::super::sys::WriteOutcome::Done
        ));
        let (g, rest) = wait_grant(read.as_raw_fd(), u64::MAX).unwrap();
        assert_eq!(g.units.len(), 1);
        assert_eq!(rest, done);
    }

    // 도우미가 멈춰(죽지 않고) 허가도 EOF도 오지 않으면 감독은 자기 마감에 끝난다. 이것을 실패시키는 것:
    // wait_grant의 마감 검사를 지우는 것(poll이 영원히 기다림).
    #[test]
    fn test_wait_grant_ends_at_its_deadline() {
        let (read, _write) = pipe();
        let started = std::time::Instant::now();
        let until = super::super::collector_process::now_ns().unwrap() + 50 * MS;
        assert!(wait_grant(read.as_raw_fd(), until).is_none());
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }

    // 도우미가 허가를 쓰고 곧 죽었으면(쓰기 쪽 닫힘) 감독은 하나도 생성하지 않는다. 이것을 실패시키는 것:
    // spawn_with의 posix_spawn 직전 `go()` 검사를 지우는 것.
    #[test]
    fn test_dead_helper_gets_no_spawn() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (grant_read, grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        drop(grant_write);
        let s = Supervisor::new(
            grant(vec![unit("ok", 200 * MS), unit("ok", 200 * MS)], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        assert!(s.runs.is_empty(), "{} spawned", s.runs.len());
    }

    // 생성 준비(파이프·입력·descriptor·actions) 도중에 도우미가 죽어도 그 생성은 일어나지 않는다. 이것을
    // 실패시키는 것: 도우미 확인을 posix_spawn 직전이 아니라 준비 앞(start의 command_process::spawn 호출 앞)에
    // 두는 것.
    #[test]
    fn test_helper_death_during_preparation_spawns_nothing() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (grant_read, grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        let mut writer = Some(grant_write);
        command_process::PREPARE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || drop(writer.take())));
        });
        let s = Supervisor::new(
            grant(vec![unit("ok", 200 * MS)], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        command_process::PREPARE.with(|hook| hook.borrow_mut().take());
        assert!(s.runs.is_empty(), "{} spawned", s.runs.len());
    }

    // 허가와 함께 읽힌 done은 생성 전에 회차를 멈춘다. 이것을 실패시키는 것: run에서 tail 처리를 spawn_all
    // 뒤로 옮기는 것.
    #[test]
    fn test_done_with_the_grant_spawns_nothing() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (grant_read, _grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        let done = wire::encode(&Message::Done).unwrap();
        let s = Supervisor::new(
            grant(vec![unit("ok", 200 * MS)], 1_000 * MS),
            done,
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        assert!(s.runs.is_empty());
    }

    // GATE-CMD-GRANT.1(감독 승인 표), GATE-TRUST-REVOKE.3(철회된 단위의 결정 시각 기록). 이것을 실패시키는
    // 것: spawn_unit에서 approve_unit 호출을 지우는 것(중계는 그대로 생성): 신뢰 마감이 지났거나 시계가 다르거나
    // 요약값이 다른 단위도 생성된다. 거부 결과에 승인 시각 대신 0을 적는 것.
    #[test]
    fn test_supervisor_approval_deadline_table() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let ok = unit("ok", 200 * MS);
        let mut tampered = unit("ok", 200 * MS);
        tampered.policy = Policy::Argv {
            argv: vec![b"rm".to_vec(), b"-rf".to_vec()],
        };
        let mut cases: Vec<(&str, Grant, bool)> = vec![
            ("live", grant(vec![ok.clone()], 1_000 * MS), true),
            ("expired", grant(vec![ok.clone()], 0), false),
            ("policy", grant(vec![tampered], 1_000 * MS), false),
        ];
        for field in ["boot", "domain", "resume"] {
            let mut g = grant(vec![ok.clone()], 1_000 * MS);
            match field {
                "boot" => g.permit.boot[0] ^= 1,
                "domain" => g.permit.domain[0] ^= 1,
                _ => g.permit.resume += 1,
            }
            cases.push((field, g, false));
        }
        // Expired while it waited: the trust deadline passes before approval.
        let late = grant(vec![ok], 30 * MS);
        std::thread::sleep(std::time::Duration::from_millis(40));
        cases.push(("waited", late, false));
        for (name, g, want) in cases {
            let (got, _) = round(g);
            assert_eq!(got.len(), 1, "{name}");
            assert_eq!(spawned(&got[0]), want, "{name}: {got:?}");
            // GATE-TRUST-REVOKE.3: a revoked unit's result records the refusal
            // and when it was decided.
            if matches!(name, "expired" | "waited") {
                assert_eq!(got[0].reason, Reason::Refused(Refusal::Trust), "{name}");
                assert!(got[0].approved_at > 0 && got[0].approved_at <= got[0].ended_at);
            }
        }
    }

    // 양성 대조와 `{dir}`·작업 폴더: 치환한 값은 원소 하나, 중립 단위는 중립 폴더에서 돈다.
    // 이것을 실패시키는 것: spawn_unit에서 with_dir 대신 정책 argv를 그대로 넘기는 것, 작업 폴더를
    // cwd 종류와 무관하게 셸 폴더로 하는 것.
    #[test]
    fn test_unit_runs_with_dir_word_in_neutral_folder() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let g = grant(vec![unit("ok", 200 * MS)], 1_000 * MS);
        let neutral = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let (got, _) = round(g);
        assert!(matches!(got[0].reason, Reason::Exited(0)), "{got:?}");
        let out = String::from_utf8_lossy(&got[0].stdout).into_owned();
        let tail = out.rsplit("\nSTUB:").next().unwrap();
        assert_eq!(
            tail,
            format!("ok /a b;$(x)\n:CWD:{}", neutral.display()),
            "{out:?}"
        );
    }

    // 이것을 실패시키는 것: Run::reason이 상태 파이프의 거부 코드를 보지 않는 것(중계가 거부한 단위가
    // 대상 종료 코드 122로 보고됨).
    #[test]
    fn test_relay_refusal_is_not_an_exit() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (got, _) = round(grant(vec![unit("refuse", 200 * MS)], 1_000 * MS));
        assert_eq!(got[0].reason, Reason::Refused(Refusal::Policy), "{got:?}");
    }

    // 이것을 실패시키는 것: 결과 파이프 대신 다른 곳을 생존 신호로 보는 것, 허가 파이프 EOF에서 자식을
    // 끝내지 않는 것(stop 호출 삭제): 출력 없는 대상이 5초 동안 남고 감독도 그때까지 끝나지 않는다.
    #[test]
    fn test_supervisor_detects_helper_death_without_output() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (grant_read, grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        let g = grant(vec![unit("sleep", 1_000 * MS)], 1_000 * MS);
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            drop(grant_write);
            std::time::Instant::now()
        });
        let s = Supervisor::new(
            g,
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        let pid = s.runs[0].child.pid;
        drop(s);
        let gone = killer.join().unwrap();
        // Well before the unit's own 1 s deadline.
        assert!(gone.elapsed() < std::time::Duration::from_millis(500));
        // SAFETY: signal 0 only asks whether the pid still exists.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "the target must be gone");
    }

    // 대상이 나눠 쓰고 곧바로 끝나도 마지막 조각까지 결과에 담긴다. reap 뒤 비우기를 지운 변이는 Linux
    // 2,000회·macOS 200회에서 잃은 회차가 0이라 이 시험으로 잡히지 않는다. 이것을 실패시키는 것: 읽은
    // stdout을 결과에 옮기지 않는 것(Outcome의 stdout을 비우는 것).
    #[test]
    fn test_split_output_is_kept_whole() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let mut lost = 0;
        for _ in 0..SPLIT_ROUNDS {
            let (got, _) = round(grant(vec![unit("split", 200 * MS)], 1_000 * MS));
            if !got[0].stdout.ends_with(b"ab\n") {
                lost += 1;
            }
        }
        assert_eq!(lost, 0, "{lost} of {SPLIT_ROUNDS} rounds lost output");
    }
    const SPLIT_ROUNDS: usize = 50;

    /// The test process's resident set, in KB (Linux).
    #[cfg(target_os = "linux")]
    fn rss_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    // 끝없이 쓰는 대상: 결과는 4 KB, 나머지는 읽어서 버리고 마감에 끝낸다. 이것을 실패시키는 것:
    // read_stdout의 room 자르기를 지우는 것(4 KB 넘는 결과는 encode가 거부해 결과가 사라짐).
    // Linux는 감독(이 시험 프로세스) RSS 증가가 1 MB 미만인지도 본다.
    #[test]
    fn test_gigabyte_output_is_cut_at_4k() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        #[cfg(target_os = "linux")]
        let before = rss_kb();
        let (got, _) = round(grant(vec![unit("yes", 300 * MS)], 1_000 * MS));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].reason, Reason::Timeout);
        assert_eq!(got[0].stdout.len(), STDOUT_MAX);
        #[cfg(target_os = "linux")]
        assert!(rss_kb() < before + 1024, "{} KB -> {} KB", before, rss_kb());
    }

    // K1: 4 KB를 넘게 쓰고 끝나는 정상 명령은 SIGPIPE 없이 자기 종료 상태를 남긴다. 이것을 실패시키는 것:
    // 4 KB에서 stdout을 닫는 것(대상이 SIGPIPE로 끝남).
    #[test]
    fn test_long_output_keeps_exit_status() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (got, _) = round(grant(vec![unit("big", 300 * MS)], 1_000 * MS));
        assert_eq!(got[0].reason, Reason::Exited(0), "{:?}", got[0].reason);
        assert_eq!(got[0].stdout.len(), STDOUT_MAX);
    }

    // 이것을 실패시키는 것: 중계 입력을 생성 뒤에 쓰는 것(읽지 않는 중계에 막힘), 마감에 끝내지 않는 것.
    #[test]
    fn test_relay_never_reads_does_not_block() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let g = grant(
            vec![unit("noread", 100 * MS), unit("ok", 200 * MS)],
            1_000 * MS,
        );
        let (got, took) = round(g);
        assert_eq!(got[0].reason, Reason::Timeout, "{got:?}");
        assert!(matches!(got[1].reason, Reason::Exited(0)), "{got:?}");
        assert!(took < std::time::Duration::from_millis(1_000), "{took:?}");
    }

    // 결과 파이프가 가득 차도(도우미가 읽지 않음) 감독은 허가 파이프 EOF를 보고 모든 대상을 끝낸다.
    // 이것을 실패시키는 것: 결과 쓰기를 차단 모드로 하는 것(EAGAIN 대신 write에 막혀 EOF를 못 봄),
    // poll 집합에서 허가 파이프를 빼는 것(Linux만. macOS는 REAP_TICK 때문에 이 변이를 잡지 못한다).
    #[test]
    fn test_result_backpressure_then_helper_death() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (grant_read, grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        // The helper reads nothing: its pipe is already full.
        let w = result_write.as_raw_fd();
        nonblocking(w).unwrap();
        let fill = [0u8; 4096];
        // SAFETY: `fill` is readable; the end is non-blocking, so this stops at EAGAIN.
        while unsafe { libc::write(w, fill.as_ptr().cast(), fill.len()) } > 0 {}
        // Blocking again, as the helper hands it over: the supervisor sets its own mode.
        // SAFETY: plain flag change on the test's own descriptor.
        unsafe { libc::fcntl(w, libc::F_SETFL, 0) };
        let mut units: Vec<Unit> = (0..7).map(|_| unit("yes", 1_000 * MS)).collect();
        units.push(unit("sleep", 1_000 * MS));
        let mut g = grant(units, 1_000 * MS);
        for _ in 0..4 {
            g.probes.push(Probe {
                profile: TEST_PROFILE,
                executable: b"/usr/bin/probe".to_vec(),
                pin: None,
            });
        }
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(grant_write);
        });
        let started = std::time::Instant::now();
        let s = Supervisor::new(
            g,
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        let took = started.elapsed();
        let pids: Vec<libc::pid_t> = s.runs.iter().map(|r| r.child.pid).collect();
        let eagain = s.eagain;
        drop(s);
        killer.join().unwrap();
        assert!(eagain >= 1, "the full pipe must have refused a write");
        assert!(took < std::time::Duration::from_millis(800), "{took:?}");
        for pid in pids {
            // SAFETY: signal 0 only asks whether the pid still exists.
            assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "{pid} still runs");
        }
    }

    // 이것을 실패시키는 것: relay_input의 16 KB 상한을 지우거나 그 거부를 생성으로 바꾸는 것.
    #[test]
    fn test_oversize_exec_frame_refused() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let mut big = unit("ok", 200 * MS);
        big.environment = [b"X=".as_slice(), &vec![b'x'; 20 * 1024], b"\0"].concat();
        big.env_allow = vec![b"X".to_vec()];
        big.digest = policy_digest(&big.policy, big.cwd, big.timeout, &big.env_allow);
        let (got, _) = round(grant(vec![big, unit("ok", 200 * MS)], 1_000 * MS));
        assert_eq!(got[0].reason, Reason::Refused(Refusal::Limit), "{got:?}");
        assert!(matches!(got[1].reason, Reason::Exited(0)), "{got:?}");
    }

    // 이것을 실패시키는 것: spawn_unit의 CONFIG_MAX 검사를 지우는 것(아홉째 단위도 생성됨).
    #[test]
    fn test_ninth_config_unit_refused() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let units = (0..9).map(|_| unit("ok", 200 * MS)).collect();
        let (got, _) = round(grant(units, 1_000 * MS));
        assert_eq!(got.iter().filter(|o| spawned(o)).count(), 8, "{got:?}");
        assert_eq!(got[8].reason, Reason::Refused(Refusal::Limit));
    }

    /// One confined round in its own process, then an `execve` attempt:
    /// exit 42 for EPERM (the filter refused it), 1 for anything else.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child: one confined supervisor round"]
    fn filter_child() {
        let (grant_read, _grant_write) = pipe();
        let (result_read, result_write) = pipe();
        // A process the supervisor does not supervise, and a pidfd of it taken
        // before the filter.
        // Never waited for: the child exits with _exit below and init reaps it.
        #[expect(
            clippy::zombie_processes,
            reason = "the test child exits without waiting"
        )]
        let other = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let pid = other.id() as libc::pid_t;
        // SAFETY: pidfd_open of our own child.
        let other_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        assert!(other_pidfd >= 0);
        let s = Supervisor::new(
            grant(vec![unit("ok", 200 * MS)], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(true);
        let held: Vec<i32> = s.runs.iter().filter_map(|r| r.child.pidfd()).collect();
        drop(s);
        // Positive: the confined loop finished the round and wrote its result.
        let mut buf = vec![0u8; 65_536];
        // SAFETY: writable buffer; non-blocking read end.
        let n = unsafe { libc::read(result_read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        let finished = usize::try_from(n).ok().is_some_and(|n| {
            matches!(wire::decode(&buf[..n]), Ok(Message::Result(o)) if o.reason == Reason::Exited(0))
        });
        let eperm = |rc: libc::c_long| {
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        };
        let argv = [c"/bin/false".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        let proc = std::ffi::CString::new(format!("/proc/{pid}/stat")).unwrap();
        let checks = [
            // SAFETY: NUL-terminated arrays of NUL-terminated strings.
            eperm(unsafe { libc::execve(argv[0], argv.as_ptr(), envp.as_ptr()) } as libc::c_long),
            // SAFETY: plain syscalls with integer or NUL-terminated arguments.
            eperm(unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    other_pidfd,
                    libc::SIGKILL,
                    0,
                    0,
                )
            }),
            // SAFETY: as above.
            eperm(unsafe { libc::kill(pid, libc::SIGKILL) } as libc::c_long),
            // SAFETY: as above.
            eperm(unsafe { libc::open(proc.as_ptr(), libc::O_RDONLY) } as libc::c_long),
            // SAFETY: as above.
            eperm(unsafe { libc::dup(0) } as libc::c_long),
            // SAFETY: as above.
            eperm(unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 10) } as libc::c_long),
            // SAFETY: as above.
            eperm(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) } as libc::c_long),
            // SAFETY: a null header is never read: the filter answers first.
            eperm(unsafe { libc::recvmsg(0, std::ptr::null_mut(), 0) } as libc::c_long),
        ];
        // A held number, now closed, names nobody: the signal finds no descriptor.
        let ebadf = held.iter().all(|&fd| {
            // SAFETY: plain syscall with integer arguments.
            let rc = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, libc::SIGKILL, 0, 0) };
            rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
        });
        // SAFETY: zeroed siginfo is a valid output buffer; WNOHANG|WNOWAIT only looks.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let alive = unsafe {
            libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
        } == 0
            // SAFETY: waitid filled the event fields.
            && unsafe { info.si_pid() } == 0;
        let all = checks.iter().all(|&c| c) && finished && !held.is_empty() && ebadf && alive;
        let code = if all { 42 } else { 1 };
        // SAFETY: plain exit of the child (the stray sleep ends on its own).
        unsafe { libc::_exit(code) }
    }

    // 필터 뒤에도 감독은 회차를 끝까지 마치고(양성), exec·무관한 자식 신호·open·dup·fcntl·socket·recvmsg는
    // EPERM이며, 닫힌 pidfd 번호로 보낸 신호는 아무에게도 닿지 않는다. 이것을 실패시키는 것: run에서 confine
    // 호출을 지우는 것(execve가 됨), 기본 거부를 허용으로 바꾸는 것(socket·recvmsg가 됨), 허용 목록에서 루프의
    // 호출을 빼는 것(회차가 끝나지 않음), pidfd 집합 비교를 지우는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_supervisor_filter_denies_exec_after_spawn() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::command_supervisor::tests::filter_child",
                "--ignored",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(42));
    }

    /// A confined round with one unit that runs past a SIGSTOP and SIGCONT
    /// of this process: exit 42 when the round still ends with its result.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child: a confined supervisor stopped and continued"]
    fn stopcont_child() {
        let (grant_read, _grant_write) = pipe();
        let (result_read, result_write) = pipe();
        let mut s = Supervisor::new(
            grant(vec![unit("sleep", 500 * MS)], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        );
        // Tells the parent the filter is in: one byte on stdout (write is allowed).
        s.confined = Some(Box::new(|| {
            // SAFETY: one readable byte to this child's stdout.
            unsafe { libc::write(1, b"R".as_ptr().cast(), 1) };
        }));
        let s = s.run(true);
        drop(s);
        let mut buf = vec![0u8; 65_536];
        // SAFETY: writable buffer; non-blocking read end.
        let n = unsafe { libc::read(result_read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        let ok = usize::try_from(n).ok().is_some_and(|n| {
            matches!(wire::decode(&buf[..n]), Ok(Message::Result(o)) if o.reason == Reason::Timeout)
        });
        // SAFETY: plain exit of the child.
        unsafe { libc::_exit(if ok { 42 } else { 1 }) }
    }

    // 필터 뒤 poll이 SIGSTOP·SIGCONT로 멈췄다 재개되어도 회차가 끝까지 간다. x86_64의 poll은 restart_syscall로
    // 이어진다. 이것을 실패시키는 것(x86_64): 허용 목록에서 restart_syscall을 빼는 것(재개된 poll이 EPERM으로
    // 회차를 끝내 결과가 없음). aarch64의 ppoll은 같은 호출로 다시 시작해 이 변이를 잡지 못하고, 그 칸은 BPF
    // 시험(supervisor_filter_denies_by_default)이 잡는다.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_confined_supervisor_survives_stop_and_continue() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::command_supervisor::tests::stopcont_child",
                "--ignored",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        // libtest prints its own lines first; the byte after them is ours.
        let mut out = child.stdout.take().unwrap();
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !got.ends_with(b"R") {
            assert_eq!(std::io::Read::read(&mut out, &mut b).unwrap(), 1, "{got:?}");
            got.push(b[0]);
        }
        // Stopped only once a confined thread waits in poll, continued only
        // once it is stopped.
        let tasks = || -> Vec<String> {
            std::fs::read_dir(format!("/proc/{pid}/task"))
                .map(|d| {
                    d.filter_map(|e| e.ok())
                        .map(|e| e.path().display().to_string())
                        .collect()
                })
                .unwrap_or_default()
        };
        #[cfg(target_arch = "x86_64")]
        let polls = [libc::SYS_poll, libc::SYS_ppoll];
        #[cfg(target_arch = "aarch64")]
        let polls = [libc::SYS_ppoll];
        let in_poll = || {
            tasks().iter().any(|t| {
                let status = std::fs::read_to_string(format!("{t}/status")).unwrap_or_default();
                let call = std::fs::read_to_string(format!("{t}/syscall")).unwrap_or_default();
                let nr = call
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<i64>().ok());
                status.contains("Seccomp:\t2") && nr.is_some_and(|n| polls.contains(&n))
            })
        };
        let until = |what: &dyn Fn() -> bool| {
            // An upper bound only: a loaded host starts the child slowly.
            let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !what() && std::time::Instant::now() < end {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            what()
        };
        let seen = || {
            tasks()
                .iter()
                .map(|t| {
                    let status = std::fs::read_to_string(format!("{t}/status")).unwrap_or_default();
                    let seccomp = status
                        .lines()
                        .find(|l| l.starts_with("Seccomp:"))
                        .unwrap_or("")
                        .to_owned();
                    (
                        t.clone(),
                        seccomp,
                        std::fs::read_to_string(format!("{t}/syscall")).map_err(|e| e.to_string()),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert!(
            until(&in_poll),
            "the confined supervisor never waited in poll: {:?}",
            seen()
        );
        // SAFETY: signals to the test's own child.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let stopped = || {
            std::fs::read_to_string(format!("/proc/{pid}/status"))
                .is_ok_and(|s| s.lines().any(|l| l.starts_with("State:\tT")))
        };
        assert!(until(&stopped), "the child never stopped");
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        let _ = std::io::Read::read_to_end(&mut out, &mut Vec::new());
        assert_eq!(child.wait().unwrap().code(), Some(42));
    }

    /// A confined round where the supervisor's own filter cannot be installed
    /// (a filter in front answers seccomp with EPERM): exit 42 when the late
    /// unit's canary never appears.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child: a supervisor whose filter fails"]
    fn filter_failure_child() {
        let deny = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::SYS_seccomp as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let prog = libc::sock_fprog {
            len: deny.len() as u16,
            filter: deny.as_ptr().cast_mut(),
        };
        // SAFETY: plain prctl with integer arguments.
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        assert_eq!(nnp, 0);
        // SAFETY: `prog` outlives the call.
        let rc = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) };
        assert_eq!(rc, 0);
        let canary = std::env::temp_dir().join(format!("bingsu-c2-late-{}", std::process::id()));
        let _ = std::fs::remove_file(&canary);
        let (grant_read, _grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        let mut late = unit("late", 1_000 * MS);
        late.policy = Policy::Argv {
            argv: vec![b"late".to_vec(), canary.as_os_str().as_bytes().to_vec()],
        };
        late.digest = policy_digest(&late.policy, late.cwd, late.timeout, &late.env_allow);
        let s = Supervisor::new(
            grant(vec![late], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(true);
        drop(s);
        std::thread::sleep(std::time::Duration::from_millis(600));
        let code = if canary.exists() { 1 } else { 42 };
        let _ = std::fs::remove_file(&canary);
        // SAFETY: plain exit of the child.
        unsafe { libc::_exit(code) }
    }

    // 자기 필터를 걸지 못하면 이미 띄운 자식을 끝내고 아무것도 더 실행하지 않는다. 이것을 실패시키는 것:
    // run에서 confine 실패 분기(stop)를 지우는 것(늦게 쓰는 대상이 카나리를 남김).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_filter_failure_ends_the_round() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::command_supervisor::tests::filter_failure_child",
                "--ignored",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(42));
    }

    /// A round whose second unit works in a folder on a stopped mount (the
    /// last argument names it; run by hand in a FUSE container): the first
    /// unit is still ended at its deadline and the helper's death is still
    /// seen, because the supervisor spawns in "/" and only that one relay
    /// waits on the mount. Exit 42 on success.
    #[test]
    #[ignore = "child: needs a stopped FUSE mount, path as the last argument"]
    fn blocked_cwd_round() {
        let folder = std::env::args_os().last().unwrap();
        let (grant_read, grant_write) = pipe();
        let (result_read, result_write) = pipe();
        let mut stuck = unit("ok", 1_000 * MS);
        stuck.cwd = Cwd::UntrustedCurrent;
        stuck.digest = policy_digest(&stuck.policy, stuck.cwd, stuck.timeout, &stuck.env_allow);
        let mut g = grant(vec![unit("sleep", 300 * MS), stuck], 1_000 * MS);
        g.cwd = folder.as_bytes().to_vec();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(600));
            drop(grant_write);
        });
        let started = std::time::Instant::now();
        let s = Supervisor::new(
            g,
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(false);
        let took = started.elapsed();
        drop(s);
        drop(result_write);
        killer.join().unwrap();
        let got = results(result_read);
        let ok = took < std::time::Duration::from_millis(900)
            && got
                .first()
                .is_some_and(|o| o.index == 0 && o.reason == Reason::Timeout);
        eprintln!("took {took:?}: {got:?}");
        // SAFETY: plain exit of the child.
        unsafe { libc::_exit(if ok { 42 } else { 1 }) }
    }

    // 무효 표식 회차(permit deadline 0)에서도 내장 조사는 돈다. 이것을 실패시키는 것: 내장 조사를 permit
    // 신뢰 검사 안으로 넣는 것(approve_probe 대신 approve_unit 규칙).
    #[test]
    fn test_builtin_runs_under_invalid_marker() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let mut g = grant(vec![unit("ok", 200 * MS)], 0);
        g.permit.deadline = 0;
        g.probes.push(Probe {
            profile: TEST_PROFILE,
            executable: b"/usr/bin/probe".to_vec(),
            pin: None,
        });
        let (got, _) = round(g);
        assert_eq!(got[0].reason, Reason::Refused(Refusal::Trust), "{got:?}");
        assert!(matches!(got[1].reason, Reason::Exited(0)), "{got:?}");
    }

    /// A round in this process with the session's cgroup parent `parent`
    /// (the atomic path), the helper alive throughout.
    #[cfg(target_os = "linux")]
    fn cgroup_round(g: Grant, parent: &std::path::Path) -> Vec<Outcome> {
        let (grant_read, grant_write) = pipe();
        let (result_read, result_write) = pipe();
        let s = Supervisor::new(
            g,
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .with_cgroup(File::open(parent).unwrap())
        .run(false);
        drop(s);
        drop((grant_write, result_write));
        results(result_read)
    }

    #[cfg(target_os = "linux")]
    fn read_pid(path: &std::path::Path) -> i32 {
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn gone_within(pid: i32, ms: u64) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < end {
            if !super::super::command_cgroup::cell::alive(pid) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        !super::super::command_cgroup::cell::alive(pid)
    }

    #[cfg(target_os = "linux")]
    fn finish(path: &std::path::Path) {
        use super::super::command_cgroup::{fs, reclaim};
        let mut dir = fs::Dir::new(File::open(path).unwrap());
        reclaim(&mut fs::Fs, &mut dir);
        let _ = std::fs::remove_dir(path);
    }

    // 원자 경로: 마감에 cgroup.kill이 setsid한 손자까지 끝낸다. 이것을 실패시키는 것: Run::end의
    // write_kill을 지우는 것(주 pid만 SIGKILL, 손자가 남음 — 결정적 대조).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_setsid_descendant_killed_with_cgroup() {
        use super::super::command_cgroup::cell;
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("setsid");
        let pidfile = std::env::temp_dir().join(format!("bingsu-gc-{}", std::process::id()));
        let mut g = grant(vec![unit("setsid", 300 * MS)], 1_000 * MS);
        g.cwd = pidfile.as_os_str().as_bytes().to_vec();
        let out = cgroup_round(g, &path);
        assert!(matches!(out[0].reason, Reason::Timeout), "{out:?}");
        let grandchild = read_pid(&pidfile);
        let gone = gone_within(grandchild, 1_000);
        if !gone {
            // SAFETY: plain signal to the test's own leftover.
            unsafe { libc::kill(grandchild, libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(&pidfile);
        finish(&path);
        assert!(gone, "the setsid grandchild outlived the unit");
    }

    // 대상이 단위 cgroup 아래 깊이 2의 하위 cgroup을 만들어도 그 회차의 정리(감독 뒤 도우미의 회수) 뒤
    // 단위 폴더 0. 이것을 실패시키는 것: 회수의 후위 순회를 단위 폴더 rmdir 하나로 바꾸는 것(clear 결과를
    // true로: EBUSY로 남음).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_nested_cgroup_removed_postorder() {
        use super::super::command_cgroup::{cell, fs, reclaim};
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("nested-round");
        let flag = std::env::temp_dir().join(format!("bingsu-nest-{}", std::process::id()));
        let mut g = grant(vec![unit("nest", 300 * MS)], 1_000 * MS);
        g.cwd = flag.as_os_str().as_bytes().to_vec();
        let out = cgroup_round(g, &path);
        assert!(flag.exists(), "the target made no nested cgroup: {out:?}");
        let _ = std::fs::remove_file(&flag);
        let mut dir = fs::Dir::new(File::open(&path).unwrap());
        let r = reclaim(&mut fs::Fs, &mut dir);
        let left = cell::units(&path);
        finish(&path);
        assert_eq!(left, Vec::<String>::new(), "{r:?}");
        assert_eq!(r.removed, 1, "{r:?}");
    }

    // 같은 세션의 100 단위(8개씩 13회차, 회차마다 새 감독)는 이름이 모두 다르다. 이것을 실패시키는 것:
    // 단위 이름을 회차 안 순번으로 만드는 것(next_seq 대신 0부터 세기: 회차마다 같은 이름이 다시 쓰임).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_cgroup_names_never_reused() {
        use super::super::command_cgroup::cell;
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("names");
        let mut seen = Vec::new();
        while seen.len() < 100 {
            let units = (0..plan::CONFIG_MAX)
                .map(|_| unit("echo", 500 * MS))
                .collect();
            let out = cgroup_round(grant(units, 2_000 * MS), &path);
            assert!(out.iter().all(spawned), "{out:?}");
            let names = cell::units(&path);
            assert_eq!(names.len(), plan::CONFIG_MAX);
            seen.extend(names);
            let mut dir = super::super::command_cgroup::fs::Dir::new(File::open(&path).unwrap());
            super::super::command_cgroup::reclaim(
                &mut super::super::command_cgroup::fs::Fs,
                &mut dir,
            );
        }
        finish(&path);
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), seen.len(), "a unit cgroup name came back");
    }

    // 위임 셀: 출력 없는 대상의 도우미가 죽으면 1 s 안에 그 단위 cgroup이 빈다(setsid 손자까지). 이것을
    // 실패시키는 것: stop()이 Run::end 대신 pidfd SIGKILL만 보내는 것(손자가 남아 populated 1).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_supervisor_detects_helper_death_without_output_in_cgroup() {
        use super::super::command_cgroup::cell;
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("death");
        let pidfile = std::env::temp_dir().join(format!("bingsu-death-{}", std::process::id()));
        let (grant_read, grant_write) = pipe();
        let (_result_read, result_write) = pipe();
        let mut g = grant(vec![unit("setsid", 1_000 * MS)], 1_000 * MS);
        g.cwd = pidfile.as_os_str().as_bytes().to_vec();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            drop(grant_write);
            std::time::Instant::now()
        });
        let s = Supervisor::new(
            g,
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .with_cgroup(File::open(&path).unwrap())
        .run(false);
        drop(s);
        let died = killer.join().unwrap();
        let unit = path.join(&cell::units(&path)[0]);
        let empty = loop {
            let events = std::fs::read(unit.join("cgroup.events")).unwrap();
            let empty = bingsu_core::command::cgroup::populated(&events) == Some(false);
            if empty || died.elapsed() > std::time::Duration::from_secs(1) {
                break empty;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        if !empty {
            // SAFETY: plain signal to the test's own leftover.
            unsafe { libc::kill(read_pid(&pidfile), libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(&pidfile);
        finish(&path);
        assert!(
            empty,
            "the unit cgroup was not empty 1 s after the helper died"
        );
    }

    // 바로 끝난 대상이 남긴 setsid 손자도 그 단위가 끝날 때(relay reap) cgroup.kill로 끝난다. 둘째 단위가 회차를
    // 1초 동안 붙잡고 있으므로, 손자는 회차가 끝나기 전에 사라져야 한다. 이것을 실패시키는 것: reap 분기의
    // run.end()를 지우는 것(손자가 회차 끝의 stop까지 남음).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_setsid_descendant_of_an_exited_target_killed() {
        use super::super::command_cgroup::cell;
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("setsid-exit");
        let pidfile = std::env::temp_dir().join(format!("bingsu-gcx-{}", std::process::id()));
        let mut g = grant(
            vec![unit("setsid-exit", 1_000 * MS), unit("sleep", 1_000 * MS)],
            2_000 * MS,
        );
        g.cwd = pidfile.as_os_str().as_bytes().to_vec();
        let round = {
            let path = path.clone();
            std::thread::spawn(move || cgroup_round(g, &path))
        };
        let start = std::time::Instant::now();
        while std::fs::read_to_string(&pidfile).map_or(true, |t| t.trim().is_empty())
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let grandchild = read_pid(&pidfile);
        let gone = gone_within(grandchild, 500);
        let during = !round.is_finished();
        let out = round.join().unwrap();
        if !gone {
            // SAFETY: plain signal to the test's own leftover.
            unsafe { libc::kill(grandchild, libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(&pidfile);
        finish(&path);
        assert!(matches!(out[0].reason, Reason::Exited(0)), "{out:?}");
        assert!(
            gone && during,
            "the exited target's setsid grandchild outlived its unit: {gone} {during}"
        );
    }

    // 이미 있는 이름의 단위 폴더는 다시 쓰지 않는다: 그 단위는 생성 0, SpawnFailed. 이것을 실패시키는 것:
    // Cgroups::unit의 `mkdir_at`이 false(EEXIST)일 때의 거부를 지우는 것(남의 폴더 안에서 실행됨).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_existing_unit_name_is_never_reused() {
        use super::super::command_cgroup::cell;
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("taken");
        let taken = u64::MAX - 10;
        std::fs::create_dir(path.join(bingsu_core::command::cgroup::unit_name(taken + 1))).unwrap();
        let (grant_read, grant_write) = pipe();
        let (result_read, result_write) = pipe();
        let mut s = Supervisor::new(
            grant(vec![unit("echo", 500 * MS)], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .with_cgroup(File::open(&path).unwrap());
        if let Some(c) = s.cgroup.as_mut() {
            c.seq = Some(taken);
        }
        drop(s.run(false));
        drop((grant_write, result_write));
        let out = results(result_read);
        finish(&path);
        assert!(matches!(out[0].reason, Reason::SpawnFailed), "{out:?}");
    }

    // clone3이 ENOSYS면 그 회차는 처음부터 최선 노력(posix_spawn)으로 돌고 빈 단위 폴더는 남지 않는다. 첫
    // 단위가 cgroup 안에서 돈 뒤의 실패는 섞지 않고 그 단위만 SpawnFailed. 이것을 실패시키는 것: 대체 경로를
    // 지우는 것(첫 회차 단위가 SpawnFailed), 빈 폴더 제거를 지우는 것(단위 폴더가 남음), "아직 cgroup 단위
    // 없음" 조건을 지우는 것(둘째 회차의 둘째 단위가 최선 노력으로 섞여 실행됨), ENOSYS·EPERM 판별을 모든
    // 오류로 넓히는 것(EINVAL 단위가 최선 노력으로 실행됨), 판별에서 ENOENT나 EACCES를 빼는 것(그 단위가
    // SpawnFailed).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_clone3_refusal_takes_the_best_effort_path() {
        use super::super::command_cgroup::cell;
        use super::super::command_process::CLONE3_ERRORS;
        if !cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (path, _dir) = cell::parent("enosys");
        CLONE3_ERRORS.with(|q| *q.borrow_mut() = [Some(libc::ENOSYS)].into());
        let out = cgroup_round(
            grant(
                vec![unit("echo", 500 * MS), unit("echo", 500 * MS)],
                1_000 * MS,
            ),
            &path,
        );
        let left = cell::units(&path);
        CLONE3_ERRORS.with(|q| *q.borrow_mut() = [None, Some(libc::ENOSYS)].into());
        let mixed = cgroup_round(
            grant(
                vec![unit("echo", 500 * MS), unit("echo", 500 * MS)],
                1_000 * MS,
            ),
            &path,
        );
        let mut entered = Vec::new();
        for errno in [libc::ENOENT, libc::EACCES] {
            CLONE3_ERRORS.with(|q| *q.borrow_mut() = [Some(errno)].into());
            entered.push(cgroup_round(
                grant(vec![unit("echo", 500 * MS)], 1_000 * MS),
                &path,
            ));
        }
        CLONE3_ERRORS.with(|q| *q.borrow_mut() = [Some(libc::EINVAL)].into());
        let other = cgroup_round(grant(vec![unit("echo", 500 * MS)], 1_000 * MS), &path);
        CLONE3_ERRORS.with(|q| q.borrow_mut().clear());
        finish(&path);
        assert!(
            out.iter().all(|o| matches!(o.reason, Reason::Exited(0))),
            "{out:?}"
        );
        assert_eq!(left, Vec::<String>::new());
        assert!(matches!(mixed[0].reason, Reason::Exited(0)), "{mixed:?}");
        assert!(matches!(mixed[1].reason, Reason::SpawnFailed), "{mixed:?}");
        // A cgroup that cannot be entered (ENOENT, EACCES) is no atomic path either.
        for out in &entered {
            assert!(matches!(out[0].reason, Reason::Exited(0)), "{out:?}");
        }
        // Any other clone3 error is that unit's spawn failure, not a path switch.
        assert!(matches!(other[0].reason, Reason::SpawnFailed), "{other:?}");
    }

    // 최선 노력 경로(cgroup 없음): 중계는 자기 프로세스 그룹을 이끌고, 그 종료를 회수하기 직전(마감 뒤, 또는
    // 대상이 스스로 끝난 뒤) OwnedChild::reap이 그룹 전체에 SIGKILL을 보낸다. setsid하지 않은 손자는 남지
    // 않는다. 이것을 실패시키는 것: spawn의 own_group을 끄는 것(그룹이 없어 손자가 남음), reap의 killpg를
    // 지우는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_group_kill_ends_a_same_group_descendant() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        for (word, timeout) in [("fork", 300 * MS), ("fork-exit", 1_000 * MS)] {
            let pidfile =
                std::env::temp_dir().join(format!("bingsu-grp-{word}-{}", std::process::id()));
            let mut g = grant(vec![unit(word, timeout)], 1_000 * MS);
            g.cwd = pidfile.as_os_str().as_bytes().to_vec();
            let (out, _) = round(g);
            assert!(spawned(&out[0]), "{out:?}");
            let grandchild = read_pid(&pidfile);
            let gone = gone_within(grandchild, 1_000);
            if !gone {
                // SAFETY: plain signal to the test's own leftover.
                unsafe { libc::kill(grandchild, libc::SIGKILL) };
            }
            let _ = std::fs::remove_file(&pidfile);
            assert!(gone, "{word}: a same-group grandchild outlived its unit");
        }
    }

    // clone3 자식의 exec 실패 코드는 relay의 어떤 상태 코드와도 겹치지 않고, 감독은 그것을 SpawnFailed로
    // 읽는다(relay가 쓴 거부 코드로 읽히지 않음). 이것을 실패시키는 것: SPAWN_FAILED를 122(RELAY_TARGET)로
    // 바꾸는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_failed_code_is_not_a_relay_code() {
        let relay = include_str!("../relay.rs").replace("\r\n", "\n");
        let codes: Vec<u8> = relay
            .lines()
            .filter_map(|l| l.strip_prefix("pub(crate) const RELAY_"))
            .filter_map(|l| l.split(": u8 = ").nth(1)?.strip_suffix(';')?.parse().ok())
            .collect();
        assert_eq!(codes, [RELAY_INPUT, RELAY_EXPIRED, RELAY_TARGET, 123]);
        assert!(!codes.contains(&command_process::SPAWN_FAILED));
        assert!(
            ![RELAY_INPUT, RELAY_EXPIRED, RELAY_TARGET].contains(&command_process::SPAWN_FAILED)
        );
    }
}
