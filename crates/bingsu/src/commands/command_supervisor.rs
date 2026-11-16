//! Command supervisor `bingsu __command-v1`. The refresh helper spawns it
//! before its own filter with an empty environment and exactly descriptors
//! 0 to 2 (`/dev/null`), 3 the grant channel's read end, 4 the result
//! channel's write end (pipes, Unix stream socket pairs on macOS:
//! `command_process::channel`) and 5 a close-only copy of the session lock.
//! It waits for the one grant; end of file before one runs nothing. For each
//! unit it repeats the approval right before that unit's relay spawn, then
//! supervises every relay in one `poll` loop with the grant channel (done or
//! end of file: the helper is gone, so every child is ended), the result
//! channel's partial writes, each child's stdout (4 KB, never parsed) and
//! status, and the next deadline. Every decision is `bingsu_core::command`;
//! this file makes the system calls.
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
/// The session's cgroup parent, open only on the atomic path.
#[cfg(target_os = "linux")]
pub(crate) const CGROUP_FD: i32 = 6;
/// the round ends 100 ms before the helper's deadline, and a unit
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

/// A builtin probe's fixed arguments, run time and environment (spec: argv
/// and environment come from the profile table, never from the grant; the
/// grant's toolchain is a grammar-checked name the table puts in one fixed
/// variable). `home` is the neutral folder the probe runs in.
fn profile(
    id: u8,
    toolchain: Option<&[u8]>,
    home: &[u8],
) -> Option<(bingsu_core::command::profile::Profile, Vec<u8>)> {
    #[cfg(test)]
    if id == tests::TEST_PROFILE {
        return Some((
            bingsu_core::command::profile::Profile {
                args: &[b"--version"],
                timeout: plan::TIMEOUT_DEFAULT,
            },
            Vec::new(),
        ));
    }
    Some((
        bingsu_core::command::profile::profile(id)?,
        bingsu_core::command::profile::environment(id, toolchain, home)?,
    ))
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
        // same class as the C1 macOS fcntl branch.
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
        // Fails without it: test_builtin_profiles_fix_argv_and_environment
        // (an unknown profile or a toolchain it does not take runs nothing).
        let Some((profile, environment)) = profile(
            probe.profile,
            probe.toolchain.as_deref(),
            &self.grant.neutral,
        ) else {
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
            environment,
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
        // (channels, input, descriptors, actions). A poll and a spawn cannot be
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
                // round takes the best-effort path.
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
            use super::command_cgroup::fs;
            let folder = super::sys::open_dir_at_nofollow(self.parent.as_fd(), os).ok()?;
            // A cgroup folder bound over the new name between mkdirat and the
            // open is on another mount: not this unit (m6-C3b).
            let mount = fs::on_parent_mount(&self.parent, &folder)?;
            let kill = fs::kill_file_on(&folder, mount).ok()?;
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
pub(crate) mod tests;
