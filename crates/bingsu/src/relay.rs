//! Trusted relay, Linux native executables (`bingsu __exec-v2`, spec section 4
//! "the place of the pre-exec check"). The command supervisor spawns it with
//! an empty environment and the permit and exec frame on fd 3; the relay checks
//! the target through one open descriptor, takes a fresh clock as its last
//! step and runs the target with `execveat` on that descriptor. Every decision
//! is `bingsu_core::handoff` or `bingsu_core::fs_trust`; this file reads fd 3,
//! makes the system calls and refuses with a fixed exit code. It is pinned in
//! scripts/check_cli_prompt_forbid.py (TCB_SHA256).
// The relay starts with an empty environment and never reads one: the
// clippy.toml rules (environment reads, std::process::exit, write_all) are
// forbidden here, and forbid cannot be switched off with #[allow].
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use bingsu_core::fs_trust::{AclFacts, Facts, RefuseGroupWrite, Verdict, entry_verdict};
use bingsu_core::handoff::{PERMIT_FD, parse_relay_args, read_relay_input};
use std::ffi::{CString, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

/// Largest permit plus exec frame the relay reads from fd 3 (U-9d, 16 KB):
/// the supervisor writes both into an empty pipe in one write.
pub(crate) const INPUT_CAP: usize = 16 * 1024;
/// Fixed exit codes; the target was not executed. Argv or fd 3 input.
pub(crate) const RELAY_INPUT: u8 = 120;
/// The fresh clock is past a deadline or is not the permit's clock.
pub(crate) const RELAY_EXPIRED: u8 = 121;
/// The executable failed to open or a check on its descriptor.
pub(crate) const RELAY_TARGET: u8 = 122;
/// Descriptor setup or `execveat` failed.
pub(crate) const RELAY_EXEC: u8 = 123;

pub(crate) fn run(args: &[OsString]) -> ExitCode {
    ExitCode::from(relay(args))
}

/// Returns only when the target was not executed.
fn relay(args: &[OsString]) -> u8 {
    match prepare(args) {
        Ok(target) => target.exec(),
        Err(code) => code,
    }
}

/// A checked target, ready for `execveat`. The pointer arrays point into
/// `argv` and `envp`, whose heap buffers do not move with the struct.
pub(crate) struct Target {
    fd: OwnedFd,
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    envp_ptrs: Vec<*const libc::c_char>,
}

/// Spec order: signals, fd 3 read and closed, the executable opened and
/// checked, descriptors past 2 marked close-on-exec, then the fresh clock.
/// The relay never changes folder: the supervisor spawns it in the unit's
/// working folder (the neutral folder, or the shell's folder for
/// `untrusted-current`), and the target inherits that folder.
pub(crate) fn prepare(args: &[OsString]) -> Result<Target, u8> {
    reset_signals();
    let input = read_fd3();
    // SAFETY: fd 3 is the relay's own input; nothing else holds it.
    unsafe { libc::close(i32::from(PERMIT_FD)) };
    let input = input.ok_or(RELAY_INPUT)?;
    let words: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let parsed = parse_relay_args(&words).map_err(|_| RELAY_INPUT)?;
    let (permit, frame) = read_relay_input(&input, INPUT_CAP).map_err(|_| RELAY_INPUT)?;
    let fd = open_target(parsed.executable)?;
    let argv = parsed
        .argv
        .iter()
        .map(|w| CString::new(*w).map_err(|_| RELAY_INPUT))
        .collect::<Result<Vec<_>, _>>()?;
    let envp = environment(&frame.environment)?;
    let argv_ptrs = pointers(&argv);
    let envp_ptrs = pointers(&envp);
    // The target gets 0, 1 and 2 only; the executable's fd is close-on-exec.
    if !cloexec_from_3(close_range_cloexec()) {
        return Err(RELAY_EXEC);
    }
    // Last before exec: a fresh clock. Config units need the trust deadline
    // and E, builtin probes E only, both on the permit's boot, resume and domain.
    let now = crate::prompt_io::observe_clock().map_err(|_| RELAY_EXPIRED)?;
    if !frame.allows(permit, now) {
        return Err(RELAY_EXPIRED);
    }
    Ok(Target {
        fd,
        _argv: argv,
        _envp: envp,
        argv_ptrs,
        envp_ptrs,
    })
}

impl Target {
    fn exec(self) -> u8 {
        // SAFETY: the fd is open; both arrays are NULL-terminated and point
        // at NUL-terminated strings owned by `self`, alive for the call.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.fd.as_raw_fd(),
                c"".as_ptr(),
                self.argv_ptrs.as_ptr(),
                self.envp_ptrs.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        RELAY_EXEC
    }
}

/// Every signal to its default disposition and an empty mask: `exec` keeps
/// ignored signals and the mask, and Rust's runtime ignores SIGPIPE before
/// `main`. The kernel calls are made directly because the C library refuses
/// its reserved signals (32 and up), which an ignoring parent can still leave
/// ignored; the kernel refuses only SIGKILL and SIGSTOP, already default.
fn reset_signals() {
    // The kernel's sigaction (handler, flags, restorer, 64-bit mask) and the
    // 64-bit sigset: all zero is SIG_DFL, no flags, nothing blocked.
    let zero = [0u64; 4];
    for signal in 1..=64 {
        // SAFETY: `zero` is readable for the kernel struct; no old action is requested.
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                signal,
                zero.as_ptr(),
                std::ptr::null_mut::<u64>(),
                8usize,
            )
        };
    }
    // SAFETY: `zero` is readable for an 8-byte sigset; no old mask is requested.
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            zero.as_ptr(),
            std::ptr::null_mut::<u64>(),
            8usize,
        )
    };
}

/// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, or its errno.
fn close_range_cloexec() -> Result<(), i32> {
    // SAFETY: plain syscall; CLOSE_RANGE_CLOEXEC changes flags, closes nothing.
    let r = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// Most descriptors the fallback walks; a larger soft limit fails closed.
const FALLBACK_FD_CAP: u64 = 65_536;

/// Every descriptor from 3 up is close-on-exec. Kernels before 5.11 have no
/// close_range (ENOSYS; the spec supports 5.7 and later): then each number
/// below the RLIMIT_NOFILE soft limit gets FD_CLOEXEC. Any other error, or a
/// limit we cannot read or above `FALLBACK_FD_CAP`, fails closed.
fn cloexec_from_3(close_range: Result<(), i32>) -> bool {
    match close_range {
        Ok(()) => true,
        Err(libc::ENOSYS) => {
            // SAFETY: an all-zero rlimit is a valid out-parameter value.
            let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
            // SAFETY: `lim` is writable.
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
                return false;
            }
            cloexec_below(lim.rlim_cur)
        }
        Err(_) => false,
    }
}

/// FD_CLOEXEC on 3..limit (closed numbers answer EBADF, which is fine).
fn cloexec_below(limit: u64) -> bool {
    if limit > FALLBACK_FD_CAP {
        return false;
    }
    for fd in 3..limit as i32 {
        // SAFETY: F_SETFD only changes this number's descriptor flags.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    true
}

/// All of fd 3 up to end of file; `None` past `INPUT_CAP` or on an error.
fn read_fd3() -> Option<Vec<u8>> {
    let mut buf = vec![0u8; INPUT_CAP + 1];
    let mut len = 0;
    while len < buf.len() {
        let rest = &mut buf[len..];
        // SAFETY: `rest` is writable for its length.
        let n = unsafe { libc::read(i32::from(PERMIT_FD), rest.as_mut_ptr().cast(), rest.len()) };
        if n == 0 {
            buf.truncate(len);
            return Some(buf);
        }
        // No handler is installed, so a signal never interrupts this read.
        len += usize::try_from(n).ok()?;
    }
    None
}

/// Opens the executable without following a final symlink and without
/// waiting on a FIFO, then checks the descriptor: a regular file that only
/// root or the user can change (group write refused: the relay has no group
/// answer), and not a script (the sealed memfd path comes later). An
/// execute-only file opens with `O_PATH`, which cannot be read, so it is run
/// as a native executable only (spec section 4 "native executable").
fn open_target(path: &[u8]) -> Result<OwnedFd, u8> {
    // A relative path would name a file in the inherited working folder.
    if !path.starts_with(b"/") {
        return Err(RELAY_TARGET);
    }
    let path = CString::new(path).map_err(|_| RELAY_INPUT)?;
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    // SAFETY: `path` is NUL-terminated; no O_CREAT.
    let mut raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | flags) };
    let readable = raw >= 0;
    if !readable && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES) {
        // SAFETY: as above.
        raw = unsafe { libc::open(path.as_ptr(), libc::O_PATH | flags) };
    }
    if raw < 0 {
        return Err(RELAY_TARGET);
    }
    // SAFETY: a successful open returns a descriptor nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open and `st` is writable.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(RELAY_TARGET);
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(RELAY_TARGET);
    }
    let facts = Facts {
        dev: st.st_dev,
        ino: st.st_ino,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode,
        // Linux file systems enforce ownership. An ACL matters only under
        // group write (its mask), which RefuseGroupWrite refuses already.
        acl: AclFacts::None,
        ownership: Some(true),
    };
    // SAFETY: getuid cannot fail.
    let me = unsafe { libc::getuid() };
    if entry_verdict(&facts, me, false, &mut RefuseGroupWrite) != Verdict::Safe {
        return Err(RELAY_TARGET);
    }
    if readable {
        let mut head = [0u8; 2];
        // SAFETY: `head` is writable for 2 bytes; `fd` is open for reading.
        let n = unsafe { libc::pread(fd.as_raw_fd(), head.as_mut_ptr().cast(), 2, 0) };
        if n == 2 && head == *b"#!" {
            return Err(RELAY_TARGET);
        }
    }
    Ok(fd)
}

/// The exec frame's `NAME=VALUE\0` entries as the target's envp.
fn environment(bytes: &[u8]) -> Result<Vec<CString>, u8> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let body = bytes.strip_suffix(b"\0").unwrap_or(bytes);
    body.split(|&b| b == 0)
        .map(|entry| CString::new(entry).map_err(|_| RELAY_INPUT))
        .collect()
}

fn pointers(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::handoff::{Cwd, ExecFrame, Origin, Permit, relay_args, relay_input};
    use bingsu_core::snapshot::Clock;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    const SECOND: i64 = 1_000_000_000;
    const ECHO: &[u8] = b"bingsu-relay-echo\n";
    const CLOCK_TAG: &str = "RELAY-CLOCK-READS";

    /// Deadlines relative to a clock just read: the permit's trust deadline and
    /// the frame's E, in nanoseconds from `clock.now`.
    struct Times {
        trust: i64,
        run: i64,
        resume_shift: u64,
    }
    const LIVE: Times = Times {
        trust: SECOND,
        run: SECOND,
        resume_shift: 0,
    };

    fn input_at(clock: Clock, origin: Origin, t: Times, environment: &[u8]) -> (Permit, Vec<u8>) {
        let permit = Permit {
            kind: clock.kind,
            deadline: clock.now.checked_add_signed(t.trust).unwrap(),
            boot: clock.boot,
            resume: clock.resume + t.resume_shift,
            domain: clock.domain,
        };
        let frame = ExecFrame {
            origin,
            run_deadline: clock.now.checked_add_signed(t.run).unwrap(),
            environment: environment.to_vec(),
        };
        (permit, relay_input(permit, &frame, INPUT_CAP).unwrap())
    }

    fn input(origin: Origin, t: Times, environment: &[u8]) -> (Permit, Vec<u8>) {
        input_at(
            crate::prompt_io::observe_clock().unwrap(),
            origin,
            t,
            environment,
        )
    }

    fn args(exe: &Path, argv: &[&[u8]]) -> Vec<Vec<u8>> {
        relay_args(exe.as_os_str().as_bytes(), Cwd::Neutral, argv)
            .unwrap()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn cat() -> PathBuf {
        std::fs::canonicalize("/bin/cat").unwrap()
    }

    /// A pipe whose ends sit at 100 or above and are close-on-exec, so the
    /// child's dup2 onto 3, 4 and 5 never overwrites another of them.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` is writable for two descriptors.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let high = |fd: i32| {
            // SAFETY: `fd` is open; the duplicate is close-on-exec.
            let h = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) };
            assert!(h >= 100);
            // SAFETY: `fd` was returned by pipe2 above and is closed once.
            unsafe { libc::close(fd) };
            // SAFETY: `h` is a fresh descriptor nothing else owns.
            unsafe { OwnedFd::from_raw_fd(h) }
        };
        (high(fds[0]), high(fds[1]))
    }

    fn put(fd: &OwnedFd, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            // SAFETY: `bytes` is readable for its length; `fd` is open.
            let n = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            bytes = &bytes[usize::try_from(n).unwrap()..];
        }
    }

    fn read_all(fd: i32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: `buf` is writable for its length.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            match usize::try_from(n).unwrap() {
                0 => return out,
                n => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// The supervisor's side for one relay: fd 3 holds `input`, fd 4 the
    /// relay argv (NUL-terminated words, read by `relay_child`), fd 5 a pipe
    /// end left open without close-on-exec (an fd the relay must not pass on).
    /// SIGUSR1 is ignored and SIGUSR2 blocked, which the relay must undo.
    /// `relay_env` is the relay's own envp; the supervisor passes none.
    fn spawn_relay(input: &[u8], args: &[Vec<u8>], relay_env: &[(&str, &Path)]) -> Child {
        let (r3, w3) = pipe();
        put(&w3, input);
        drop(w3);
        let (r4, w4) = pipe();
        for word in args {
            put(&w4, word);
            put(&w4, b"\0");
        }
        drop(w4);
        let (r5, _w5) = pipe();
        let (r3, r4, r5) = (r3.as_raw_fd(), r4.as_raw_fd(), r5.as_raw_fd());
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "relay::tests::relay_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
        for (k, v) in relay_env {
            cmd.env(k, v);
        }
        // Runs in the forked child: only async-signal-safe calls (dup2, signal,
        // sigemptyset, sigaddset, pthread_sigmask) on descriptors open there.
        let setup = move || {
            for (from, to) in [(r3, 3), (r4, 4), (r5, 5)] {
                // SAFETY: both descriptors are valid; dup2 clears close-on-exec on `to`.
                if unsafe { libc::dup2(from, to) } != to {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // SAFETY: plain disposition change.
            unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) };
            // SAFETY: an all-zero sigset_t is a valid buffer for sigemptyset.
            let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
            // SAFETY: `set` is writable.
            unsafe { libc::sigemptyset(&mut set) };
            // SAFETY: `set` is initialized.
            unsafe { libc::sigaddset(&mut set, libc::SIGUSR2) };
            // SAFETY: `set` is initialized; the old mask is not requested.
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
            Ok(())
        };
        // SAFETY: `setup` is async-signal-safe (above).
        unsafe { cmd.pre_exec(setup) };
        cmd.spawn().unwrap()
    }

    #[derive(Debug)]
    struct Seen {
        exe: PathBuf,
        fds: Vec<i32>,
        sig_ign: String,
        sig_blk: String,
        environ: Vec<u8>,
        cmdline: Vec<u8>,
    }
    #[derive(Debug)]
    enum Outcome {
        /// The relay exited with this code; the target never ran.
        Refused(i32),
        Ran(Seen),
    }

    /// The target is `cat`: it echoes a line once its exec has finished. A
    /// relay that refuses exits and closes stdout without the echo.
    fn echo(mut child: Child) -> Result<Child, i32> {
        let mut stdout = child.stdout.take().unwrap();
        // A refusing relay may already be gone (EPIPE): the read below decides.
        let _ = child.stdin.as_ref().unwrap().write(ECHO);
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.ends_with(ECHO) {
            let n = stdout.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        if got.ends_with(ECHO) {
            Ok(child)
        } else {
            Err(child.wait().unwrap().code().unwrap_or(-1))
        }
    }

    /// Ends a running target by closing its stdin.
    fn finish(mut child: Child) {
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    /// The running target's /proc entries, read while it waits on stdin.
    fn outcome(child: Child) -> Outcome {
        let child = match echo(child) {
            Ok(child) => child,
            Err(code) => return Outcome::Refused(code),
        };
        let proc = PathBuf::from(format!("/proc/{}", child.id()));
        let status = std::fs::read_to_string(proc.join("status")).unwrap();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap()
                .trim()
                .to_owned()
        };
        let mut fds: Vec<i32> = std::fs::read_dir(proc.join("fd"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        fds.sort_unstable();
        let seen = Seen {
            exe: std::fs::read_link(proc.join("exe")).unwrap(),
            fds,
            sig_ign: field("SigIgn:"),
            sig_blk: field("SigBlk:"),
            environ: std::fs::read(proc.join("environ")).unwrap(),
            cmdline: std::fs::read(proc.join("cmdline")).unwrap(),
        };
        finish(child);
        Outcome::Ran(seen)
    }

    fn relay_cat(origin: Origin, t: Times, environment: &[u8]) -> Outcome {
        let (_, bytes) = input(origin, t, environment);
        outcome(spawn_relay(&bytes, &args(&cat(), &[b"cat"]), &[]))
    }

    fn ran(o: Outcome) -> Seen {
        match o {
            Outcome::Ran(seen) => seen,
            other => panic!("target did not run: {other:?}"),
        }
    }

    /// The relay process: reads its argv from fd 4 and runs the relay.
    #[test]
    #[ignore = "child: one relay run"]
    fn relay_child() {
        let words = read_all(4);
        // SAFETY: fd 4 is this child's argv pipe, read to the end above.
        unsafe { libc::close(4) };
        let args: Vec<OsString> = words
            .strip_suffix(b"\0")
            .unwrap()
            .split(|&b| b == 0)
            .map(|w| OsString::from_vec(w.to_vec()))
            .collect();
        let code = relay(&args);
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(i32::from(code)) }
    }

    // N-076. 이것을 실패시키는 것: prepare의 새 시계 확인(`frame.allows`)을 지우는 것.
    #[test]
    fn test_relay_refuses_after_deadline() {
        let t = Times { trust: -1, ..LIVE };
        assert!(matches!(
            relay_cat(Origin::Config, t, b""),
            Outcome::Refused(c) if c == i32::from(RELAY_EXPIRED)
        ));
    }

    // 양성 대조: 두 마감이 1초 남은 같은 입력은 대상을 실행한다.
    #[test]
    fn test_relay_runs_before_deadline() {
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.exe, cat());
    }

    // 이것을 실패시키는 것: ExecFrame::allows에서 `now < run_deadline`을 지우는 것.
    #[test]
    fn test_relay_config_refuses_after_e() {
        let t = Times { run: -1, ..LIVE };
        assert!(matches!(
            relay_cat(Origin::Config, t, b""),
            Outcome::Refused(c) if c == i32::from(RELAY_EXPIRED)
        ));
    }

    // 이것을 실패시키는 것: ExecFrame::allows의 내장 분기에서 E 검사를 지우는 것
    // (`now < run_deadline`을 `origin == Config`일 때만 보게 하는 것).
    #[test]
    fn test_relay_builtin_refuses_after_e() {
        let t = Times { run: -1, ..LIVE };
        assert!(matches!(
            relay_cat(Origin::Builtin, t, b""),
            Outcome::Refused(c) if c == i32::from(RELAY_EXPIRED)
        ));
    }

    // 이것을 실패시키는 것: 내장에도 신뢰 마감을 확인하는 것(ExecFrame::allows의
    // `origin == Builtin ||`를 지우는 것).
    #[test]
    fn test_relay_builtin_ignores_trust() {
        let t = Times { trust: -1, ..LIVE };
        ran(relay_cat(Origin::Builtin, t, b""));
    }

    // N-077. 이것을 실패시키는 것: prepare의 close_range(CLOSE_RANGE_CLOEXEC)를 지우는 것
    // (중계가 물려받은 fd 5가 대상에 남는다).
    #[test]
    fn test_relay_target_fds() {
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.fds, [0, 1, 2]);
    }

    // N-078. 이것을 실패시키는 것: 중계가 마감이나 permit을 대상 envp·argv에 넣는 것.
    #[test]
    fn test_relay_no_deadline_env() {
        let (permit, bytes) = input(Origin::Config, LIVE, b"A=1\0");
        let seen = ran(outcome(spawn_relay(&bytes, &args(&cat(), &[b"cat"]), &[])));
        let (_, frame) = read_relay_input(&bytes, INPUT_CAP).unwrap();
        let mut needles: Vec<Vec<u8>> = vec![
            permit.encode().to_vec(),
            b"BNGEXC02".to_vec(),
            b"BNGEXF01".to_vec(),
        ];
        for value in [permit.deadline, frame.run_deadline] {
            needles.push(value.to_string().into_bytes());
            needles.push(value.to_le_bytes().to_vec());
            needles.push(format!("{value:x}").into_bytes());
        }
        for hay in [&seen.environ, &seen.cmdline] {
            for needle in &needles {
                assert!(
                    !hay.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "{needle:?} in {hay:?}"
                );
            }
        }
        assert_eq!(seen.cmdline, b"cat\0");
    }

    // 이것을 실패시키는 것: Permit::same_clock의 resume 비교를 지우는 것(깨어난 뒤의 시계로 실행).
    #[test]
    fn test_relay_refuses_after_resume() {
        for origin in [Origin::Config, Origin::Builtin] {
            let t = Times {
                resume_shift: 1,
                ..LIVE
            };
            assert!(matches!(
                relay_cat(origin, t, b""),
                Outcome::Refused(c) if c == i32::from(RELAY_EXPIRED)
            ));
        }
    }

    // 이것을 실패시키는 것: reset_signals의 sigaction 초기화를 지우는 것(SIGPIPE·SIGUSR1이
    // 무시된 채 남음), 또는 마스크 비우기를 지우는 것(SIGUSR2가 막힌 채 남음).
    #[test]
    fn test_relay_resets_sigpipe() {
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.sig_ign, "0000000000000000");
        assert_eq!(seen.sig_blk, "0000000000000000");
    }

    /// A shared object whose constructor appends `/proc/self/exe` to `hits`.
    #[cfg(target_env = "gnu")]
    fn canary(dir: &Path) -> PathBuf {
        let hits = dir.join("hits");
        let source = dir.join("canary.c");
        std::fs::write(
            &source,
            format!(
                "#include <fcntl.h>\n#include <unistd.h>\n\
                 __attribute__((constructor)) static void canary(void) {{\n\
                 char p[4096]; ssize_t n = readlink(\"/proc/self/exe\", p, sizeof p - 1);\n\
                 if (n <= 0) return; p[n++] = '\\n';\n\
                 int fd = open(\"{}\", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);\n\
                 if (fd < 0) return; (void)!write(fd, p, n); close(fd); }}\n",
                hits.display()
            ),
        )
        .unwrap();
        let so = dir.join("canary.so");
        let status = Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success());
        so
    }

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bingsu-relay-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    // 이것을 실패시키는 것: 감독(이 시험의 spawn_relay)이 대상 환경을 실행 프레임 대신 중계의
    // envp로 넘기는 것. 양성 대조: 같은 .so를 envp로 받은 같은 중계 바이너리는 기록을 남긴다.
    #[cfg(target_env = "gnu")]
    #[test]
    fn test_relay_loader_never_sees_target_env() {
        let dir = fresh_dir("loader");
        let so = canary(&dir);
        let hits = dir.join("hits");
        let relay_exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let mut env = b"LD_PRELOAD=".to_vec();
        env.extend_from_slice(so.as_os_str().as_bytes());
        env.push(0);
        ran(relay_cat(Origin::Config, LIVE, &env));
        let lines = std::fs::read_to_string(&hits).unwrap();
        assert_eq!(lines, format!("{}\n", cat().display()));
        // Positive control: the relay's loader records itself when its envp has it.
        std::fs::remove_file(&hits).unwrap();
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        ran(outcome(spawn_relay(
            &bytes,
            &args(&cat(), &[b"cat"]),
            &[("LD_PRELOAD", &so)],
        )));
        let lines = std::fs::read_to_string(&hits).unwrap();
        assert_eq!(lines, format!("{}\n", relay_exe.display()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: environment()가 항목 하나를 버리거나, 끝의 NUL 뒤나 빈 프레임에서
    // 빈 항목을 더하는 것.
    #[test]
    fn test_target_env_equals_frame() {
        let seen = ran(relay_cat(Origin::Config, LIVE, b"A=1\0B=2\0"));
        assert_eq!(seen.environ, b"A=1\0B=2\0");
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.environ, b"");
    }

    // 이것을 실패시키는 것: open_target의 entry_verdict 확인을 지우는 것(남이 쓸 수 있는 파일 실행),
    // shebang 거부를 지우는 것(종료 코드가 RELAY_EXEC로 바뀜), O_NONBLOCK을 지우는 것(FIFO에서
    // 멈춤), S_IFREG 비교를 지우는 것(FIFO가 RELAY_EXEC로 끝남).
    #[test]
    fn test_relay_refuses_unsafe_targets() {
        let dir = fresh_dir("unsafe");
        let writable = dir.join("writable");
        std::fs::copy(cat(), &writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o757)).unwrap();
        let script = dir.join("script");
        std::fs::write(&script, "#!/bin/sh\nexec cat\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fifo = dir.join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o755) }, 0);
        for exe in [&writable, &script, &fifo, &dir.join("missing")] {
            let (_, bytes) = input(Origin::Config, LIVE, b"");
            let got = outcome(spawn_relay(&bytes, &args(exe, &[b"cat"]), &[]));
            assert!(
                matches!(got, Outcome::Refused(c) if c == i32::from(RELAY_TARGET)),
                "{exe:?}: {got:?}"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: open_target의 절대 경로 검사를 지우는 것(작업 폴더 기준 상대 경로로
    // 실제 cat에 닿는 경로가 실행된다).
    #[test]
    fn test_relay_refuses_relative_executable() {
        let depth = std::env::current_dir().unwrap().components().count() - 1;
        let relative = PathBuf::from("../".repeat(depth)).join(cat().strip_prefix("/").unwrap());
        assert!(std::fs::metadata(&relative).is_ok(), "{relative:?}");
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        let got = outcome(spawn_relay(&bytes, &args(&relative, &[b"cat"]), &[]));
        assert!(
            matches!(got, Outcome::Refused(c) if c == i32::from(RELAY_TARGET)),
            "{got:?}"
        );
    }

    /// The close_range fallback, in a child because it changes every
    /// descriptor's flags: ENOSYS walks the soft limit, other errors and a
    /// limit above the cap fail closed.
    #[test]
    #[ignore = "child: changes this process's descriptor flags"]
    fn cloexec_child() {
        // SAFETY: fd 0 is open; the duplicate is not close-on-exec.
        let fd = unsafe { libc::dup(0) };
        let cloexec = |fd| {
            // SAFETY: F_GETFD only reads flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            flags & libc::FD_CLOEXEC != 0
        };
        let before = cloexec(fd);
        let enosys = cloexec_from_3(Err(libc::ENOSYS));
        let after = cloexec(fd);
        let einval = cloexec_from_3(Err(libc::EINVAL));
        let over = cloexec_below(FALLBACK_FD_CAP + 1);
        let line = format!("{CLOCK_TAG} {before} {enosys} {after} {einval} {over}\n");
        put(
            // SAFETY: fd 1 is the parent's capture pipe; ManuallyDrop keeps it open.
            &std::mem::ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(1) }),
            line.as_bytes(),
        );
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(0) }
    }

    // 이것을 실패시키는 것: cloexec_from_3의 ENOSYS 분기를 지우는 것(5.11 미만 커널에서 실행 불가),
    // 대체 루프를 지우는 것(fd가 close-on-exec가 아님), 다른 오류를 통과시키는 것, 상한 검사를
    // 지우는 것.
    #[test]
    fn test_relay_close_range_fallback() {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "relay::tests::cloexec_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| l.starts_with(CLOCK_TAG)).collect();
        assert_eq!(
            lines,
            [format!("{CLOCK_TAG} false true true false false")],
            "{text}"
        );
    }

    // 이것을 실패시키는 것: open_target의 O_PATH 재시도를 지우는 것(실행 권한만 있는 파일을
    // 거부). root는 읽기 권한을 무시하므로 이 시험은 root가 아닌 사용자로 돌려야 뜻이 있다.
    #[test]
    fn test_relay_runs_execute_only_target() {
        let dir = fresh_dir("xonly");
        let exe = dir.join("cat");
        std::fs::copy(cat(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o111)).unwrap();
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        // An unreadable executable makes the process non-dumpable, so its /proc
        // entries are closed to us; the echo is the evidence that it ran.
        let child = echo(spawn_relay(&bytes, &args(&exe, &[b"cat"]), &[])).unwrap();
        finish(child);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// GATE-CLOCK-READS.4 child: runs `prepare` (everything before execveat)
    /// for three units and prints, per unit, its result, the clock reads it
    /// executed by use and whether fd 3 is closed afterwards.
    #[test]
    #[ignore = "child: counts the relay's pre-exec clock reads"]
    fn clock_child() {
        let clock = crate::prompt_io::observe_clock().unwrap();
        let cat = cat();
        let missing = PathBuf::from("/nonexistent/bingsu-relay-target");
        let expired = || Times { trust: -1, ..LIVE };
        let cases = [
            ("live", LIVE, &cat),
            ("expired", expired(), &cat),
            ("missing", expired(), &missing),
        ];
        let mut out = String::new();
        for (name, t, exe) in cases {
            let (_, bytes) = input_at(clock, Origin::Config, t, b"");
            let (r, w) = pipe();
            put(&w, &bytes);
            drop(w);
            // SAFETY: both descriptors are valid; fd 3 is free in this child.
            assert_eq!(unsafe { libc::dup2(r.as_raw_fd(), 3) }, 3);
            drop(r);
            let words: Vec<OsString> = args(exe, &[b"cat"])
                .into_iter()
                .map(OsString::from_vec)
                .collect();
            let before = crate::prompt_io::clock_reads();
            let code = match prepare(&words) {
                Ok(_) => 0,
                Err(c) => c,
            };
            let after = crate::prompt_io::clock_reads();
            // SAFETY: F_GETFD only reads flags; -1 means fd 3 is closed.
            let closed = unsafe { libc::fcntl(3, libc::F_GETFD) } == -1;
            let reads: Vec<String> = (0..4).map(|i| (after[i] - before[i]).to_string()).collect();
            out.push_str(&format!(
                "{CLOCK_TAG} {name} {code} {} {closed}\n",
                reads.join(",")
            ));
        }
        put(
            // SAFETY: fd 1 is the parent's capture pipe; ManuallyDrop keeps it open.
            &std::mem::ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(1) }),
            out.as_bytes(),
        );
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(0) }
    }

    // GATE-CLOCK-READS.4. 실행 단위마다 exec 전 시계 읽기는 Identity 한 번이고, 실행 파일 확인이
    // 실패한 단위는 시계를 읽지 않는다(시계가 마지막). 이것을 실패시키는 것: prepare에 시계 읽기를
    // 하나 더하거나 지우는 것, 시계 읽기를 open_target 앞으로 옮기는 것(missing이 RELAY_EXPIRED와
    // 읽기 1로 바뀜), fd 3 close를 지우는 것(close_range는 close-on-exec만 켠다).
    #[test]
    fn test_relay_pre_exec_clock_reads() {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "relay::tests::clock_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| l.starts_with(CLOCK_TAG)).collect();
        assert_eq!(
            lines,
            [
                format!("{CLOCK_TAG} live 0 0,0,0,1 true"),
                format!("{CLOCK_TAG} expired {RELAY_EXPIRED} 0,0,0,1 true"),
                format!("{CLOCK_TAG} missing {RELAY_TARGET} 0,0,0,0 true"),
            ],
            "{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
