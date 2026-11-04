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
    let Some((grant, rest)) = wait_grant(GRANT_FD) else {
        return ExitCode::SUCCESS;
    };
    let relay = Relay {
        exe: relay,
        prefix: Vec::new(),
    };
    Supervisor::new(grant, rest, relay, GRANT_FD, RESULT_FD).run(true);
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
pub(crate) fn wait_grant(fd: i32) -> Option<(Grant, Vec<u8>)> {
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
        if !poll(&mut fds, -1) {
            return None;
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
    #[cfg(test)]
    pub eagain: u32,
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
            #[cfg(test)]
            eagain: 0,
        }
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
        // Over the relay's input cap: the unit's environment is too large.
        let Ok(input) = handoff::relay_input(self.grant.permit, frame, RELAY_INPUT_MAX) else {
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
        let (Ok(folder), true) = (CString::new(folder), folder.first() == Some(&b'/')) else {
            return self.report(origin, index, Reason::Refused(Refusal::Policy), approved_at);
        };
        let spawned = command_process::spawn(
            &self.relay.exe,
            &args,
            &input,
            &folder,
            self.grant.helper_deadline,
        );
        let Ok(s) = spawned else {
            return self.report(origin, index, Reason::SpawnFailed, approved_at);
        };
        self.runs.push(Run {
            origin,
            index: u8::try_from(index).unwrap_or(u8::MAX),
            approved_at,
            deadline,
            child: s.child,
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
        self.spawn_all();
        if confine && confine_self().is_err() {
            // Without the filter nothing more may run: end the children.
            self.stop();
        }
        let tail = std::mem::take(&mut self.tail);
        self.grant_bytes(&tail);
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
        for run in &self.runs {
            let _ = run.child.signal(libc::SIGKILL);
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
                let _ = run.child.signal(libc::SIGKILL);
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

/// After the last spawn (spec: the supervisor's own filter): no exec, no
/// new process, signals only through the pidfds it holds (Linux).
fn confine_self() -> std::io::Result<()> {
    super::helper_filter::install_supervisor()
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
                wait_grant(read.as_raw_fd()).is_none(),
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
        let (g, rest) = wait_grant(read.as_raw_fd()).unwrap();
        assert_eq!(g.units.len(), 1);
        assert_eq!(rest, done);
    }

    // GATE-CMD-GRANT(감독 승인 표). 이것을 실패시키는 것: spawn_unit에서 approve_unit 호출을 지우는 것
    // (중계는 그대로 생성): 신뢰 마감이 지났거나 시계가 다르거나 요약값이 다른 단위도 생성된다.
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
        let (_result_read, result_write) = pipe();
        let s = Supervisor::new(
            grant(vec![unit("ok", 200 * MS)], 1_000 * MS),
            Vec::new(),
            stub(),
            grant_read.as_raw_fd(),
            result_write.as_raw_fd(),
        )
        .run(true);
        drop(s);
        let argv = [c"/bin/false".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        // SAFETY: NUL-terminated arrays of NUL-terminated strings.
        unsafe { libc::execve(argv[0], argv.as_ptr(), envp.as_ptr()) };
        let code = if std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
            42
        } else {
            1
        };
        // SAFETY: plain exit of the child.
        unsafe { libc::_exit(code) }
    }

    // 이것을 실패시키는 것: run에서 confine_self 호출을 지우는 것(마지막 생성 뒤에도 execve가 됨).
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
}
