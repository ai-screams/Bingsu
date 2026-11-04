//! One relay spawn for the command supervisor (spec section 4 "user command
//! execution model", row input and output). The relay's permit and exec frame
//! are written into an empty pipe before the spawn, so a relay that never
//! reads cannot hold the supervisor. The relay always gets descriptors 0, 1
//! and 2 from the spawn actions, whatever the supervisor holds there: 0 is
//! `/dev/null`, 1 the stdout pipe, 2 the status pipe, 3 its input; nothing
//! else crosses (the supervisor's own descriptors are close-on-exec, and
//! macOS spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT`). The environment is empty
//! and the spawn happens in "/"; the relay enters the unit's folder.
use super::collector_process::{OwnedChild, now_ns, pipe};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
};

/// A running relay and the supervisor's ends of its pipes.
pub(crate) struct Spawned {
    pub child: OwnedChild,
    /// Non-blocking read end of the relay's (then the target's) stdout.
    pub stdout: File,
    /// Non-blocking read end of the relay's status pipe: a byte is the
    /// relay's refusal code, end of file without one means the target was
    /// executed (the write end is close-on-exec in the relay).
    pub status: File,
}

fn check(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

/// Spawns `exe` with `args` (argv[0] included) in "/", `input` on
/// descriptor 3. `input` must fit one write into an empty pipe; a shorter
/// write is an error and nothing is spawned. The relay enters the unit's
/// folder itself: a chdir here would run in the spawn and hold the
/// supervisor on a stopped mount.
pub(crate) fn spawn(
    exe: &CStr,
    args: &[Vec<u8>],
    input: &[u8],
    expires_ns: u64,
    go: &dyn Fn() -> bool,
) -> io::Result<Spawned> {
    #[cfg(test)]
    PREPARE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
    let (input_read, input_write) = pipe()?;
    super::collector_process::nonblocking(&input_write)?;
    // SAFETY: `input` is readable for its length; the pipe is empty.
    let n = unsafe { libc::write(input_write.as_raw_fd(), input.as_ptr().cast(), input.len()) };
    if usize::try_from(n).ok() != Some(input.len()) {
        return Err(io::Error::other("relay input did not fit the pipe"));
    }
    drop(input_write);
    let (stdout, stdout_write) = pipe()?;
    let (status, status_write) = pipe()?;
    super::collector_process::nonblocking(&stdout)?;
    super::collector_process::nonblocking(&status)?;
    // The supervisor's own descriptors are close-on-exec, so nothing but
    // these crosses.
    let (child, _) = spawn_with(
        exe,
        args,
        &[(0, libc::O_RDONLY)],
        &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
        c"/",
        false,
        expires_ns,
        go,
    )?;
    Ok(Spawned {
        child,
        stdout,
        status,
    })
}

/// The supervisor itself, from the helper (`args`: the binary and
/// `__command-v1`): 0 to 2 `/dev/null`, then the grant pipe's read end, the
/// result pipe's write end and the lock copy at 3, 4 and 5, in folder "/".
/// Every other helper descriptor is closed.
pub(crate) fn spawn_supervisor(
    exe: &CStr,
    args: &[Vec<u8>],
    grant: &File,
    results: &File,
    lock: &File,
    expires_ns: u64,
) -> io::Result<OwnedChild> {
    spawn_with(
        exe,
        args,
        &[
            (0, libc::O_RDONLY),
            (1, libc::O_WRONLY),
            (2, libc::O_WRONLY),
        ],
        &[(grant, 3), (results, 4), (lock, 5)],
        c"/",
        true,
        expires_ns,
        &|| true,
    )
    .map(|(child, _)| child)
}

#[cfg(test)]
thread_local! {
    /// Runs at the start of a relay spawn's preparation (tests only).
    pub(crate) static PREPARE: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// One `posix_spawn` with an empty environment and default signals: `nulls`
/// open `/dev/null` at a number, `dups` move a source to a number (sources
/// are first moved above every target), the child starts in `cwd`. With
/// `close_rest` (Linux) every other open descriptor is closed in the child;
/// macOS always spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT`.
#[allow(clippy::too_many_arguments, reason = "one spawn's fixed inputs")]
fn spawn_with(
    exe: &CStr,
    args: &[Vec<u8>],
    nulls: &[(i32, i32)],
    dups: &[(&File, i32)],
    cwd: &CStr,
    close_rest: bool,
    expires_ns: u64,
    go: &dyn Fn() -> bool,
) -> io::Result<(OwnedChild, Option<u64>)> {
    let words = args
        .iter()
        .map(|w| CString::new(w.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv: Vec<_> = words.iter().map(|w| w.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let mut copies = Vec::new();
    for (file, _) in dups {
        // SAFETY: duplicates a live source above every target number.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh duplicate nothing else owns.
        copies.push(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    }
    // SAFETY: C objects initialized by the corresponding APIs below.
    let mut actions = unsafe { std::mem::zeroed() };
    // SAFETY: writable action storage.
    check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
    // SAFETY: writable attribute storage.
    let mut attr = unsafe { std::mem::zeroed() };
    // SAFETY: writable attribute storage.
    if let Err(e) = check(unsafe { libc::posix_spawnattr_init(&mut attr) }) {
        // SAFETY: initialized actions, no longer used.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
        return Err(e);
    }
    let result = (|| {
        // SAFETY: writable mask storage.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: writable mask.
        if unsafe { libc::sigemptyset(&mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized empty mask resets inherited blocked signals.
        check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr, &mask) })?;
        // SAFETY: writable mask.
        if unsafe { libc::sigfillset(&mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every signal to its default in the child.
        check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr, &mask) })?;
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
        #[cfg(target_os = "macos")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // SAFETY: supported child-only flags.
        check(unsafe { libc::posix_spawnattr_setflags(&mut attr, flags as libc::c_short) })?;
        for &(fd, mode) in nulls {
            // SAFETY: fixed path and initialized actions.
            check(unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    fd,
                    c"/dev/null".as_ptr(),
                    mode,
                    0,
                )
            })?;
        }
        for (source, (_, target)) in copies.iter().zip(dups) {
            // SAFETY: sources sit above every target, so no dup2 overwrites one.
            check(unsafe {
                libc::posix_spawn_file_actions_adddup2(&mut actions, source.as_raw_fd(), *target)
            })?;
        }
        #[cfg(target_os = "linux")]
        if close_rest {
            let keep = nulls
                .len()
                .max(dups.iter().map(|d| d.1 as usize + 1).max().unwrap_or(0));
            for entry in std::fs::read_dir("/proc/self/fd")? {
                let fd: i32 = entry?
                    .file_name()
                    .to_str()
                    .ok_or_else(|| io::Error::other("fd census"))?
                    .parse()
                    .map_err(io::Error::other)?;
                if fd >= keep as i32 {
                    // SAFETY: kernel-observed descriptor and initialized actions.
                    check(unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, fd) })?;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = close_rest;
        // SAFETY: NUL-terminated folder, applied in the child before exec.
        check(unsafe { libc::posix_spawn_file_actions_addchdir_np(&mut actions, cwd.as_ptr()) })?;
        // The caller's last word, after every preparation step: false (the
        // helper is gone) spawns nothing.
        if !go() {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let mut pid = 0;
        let spawn_enter = now_ns().ok();
        // SAFETY: initialized objects and live NUL-terminated arrays; empty environment.
        check(unsafe {
            libc::posix_spawn(
                &mut pid,
                exe.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                [std::ptr::null_mut()].as_ptr(),
            )
        })?;
        Ok((OwnedChild::attach(pid, expires_ns)?, spawn_enter))
    })();
    // SAFETY: initialized actions, no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn fds(pid: libc::pid_t) -> Vec<i32> {
        let mut v: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        v.sort_unstable();
        v
    }

    // GATE-CMD-FDS(감독 칸): 감독은 정확히 {0,1,2,3,4,5}이고 envp가 비어 있다. 도우미가 close-on-exec 없이
    // 쥔 fd도 넘어가지 않는다. 이것을 실패시키는 것: spawn_with의 close_rest 훑기를 지우는 것.
    #[test]
    fn test_supervisor_gets_exactly_six_fds() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let mut raw = [0; 2];
        // SAFETY: writable storage; deliberately without O_CLOEXEC.
        assert_eq!(unsafe { libc::pipe(raw.as_mut_ptr()) }, 0);
        // Above every target number, so no dup2 hides them.
        let raw = raw.map(|fd| {
            // SAFETY: `fd` is open; F_DUPFD leaves the copy inheritable.
            let high = unsafe { libc::fcntl(fd, libc::F_DUPFD, 50) };
            // SAFETY: the low number is closed once.
            unsafe { libc::close(fd) };
            high
        });
        let (a, b) = pipe().unwrap();
        let (c, _d) = pipe().unwrap();
        let sleep = c"/bin/sleep";
        let args = [b"sleep".to_vec(), b"5".to_vec()];
        let mut child = spawn_supervisor(sleep, &args, &a, &b, &c, u64::MAX).unwrap();
        // The spawn is synchronous; give exec a moment to settle the table.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let seen = fds(child.pid);
        let environ = std::fs::read(format!("/proc/{}/environ", child.pid)).unwrap();
        let _ = child.signal(libc::SIGKILL);
        while !child.reap().unwrap() {}
        for fd in raw {
            // SAFETY: closes the test's own pipe ends once.
            unsafe { libc::close(fd) };
        }
        assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
        assert!(environ.is_empty());
    }
}

/// C2 timings with the real binaries (Linux): `BINGSU_BIN` names a built
/// `bingsu`. Run with `--ignored --nocapture`; it prints, never asserts.
#[cfg(all(test, target_os = "linux"))]
mod timing {
    use super::*;
    use bingsu_core::command::wire::{self, Grant, Message, Policy, Unit, policy_digest};
    use bingsu_core::handoff::{Cwd, Permit};

    fn now() -> u64 {
        crate::prompt_io::observe_clock().unwrap().now
    }

    fn grant(units: usize) -> Grant {
        let c = crate::prompt_io::observe_clock().unwrap();
        let policy = Policy::Argv {
            argv: vec![b"true".to_vec()],
        };
        let tmp = std::env::temp_dir().into_os_string().into_encoded_bytes();
        Grant {
            permit: Permit {
                kind: c.kind,
                deadline: c.now + 10_000_000_000,
                boot: c.boot,
                resume: c.resume,
                domain: c.domain,
            },
            helper_deadline: c.now + 2_000_000_000,
            cwd: tmp.clone(),
            neutral: tmp,
            units: (0..units)
                .map(|i| Unit {
                    id: format!("custom/t{i}"),
                    digest: policy_digest(&policy, Cwd::Neutral, 200_000_000, &[]),
                    policy: policy.clone(),
                    cwd: Cwd::Neutral,
                    environment: b"PATH=/usr/bin\0".to_vec(),
                    timeout: 200_000_000,
                    env_allow: Vec::new(),
                    executable: std::fs::canonicalize("/bin/true")
                        .unwrap()
                        .into_os_string()
                        .into_encoded_bytes(),
                    pin: None,
                    interpreter: None,
                })
                .collect(),
            probes: Vec::new(),
        }
    }

    /// Spawns the real supervisor; with `early` the grant is in the pipe
    /// before the spawn. Returns (spawned at, grant written at, results).
    fn round(exe: &CStr, units: usize, early: bool) -> (u64, u64, Vec<wire::Outcome>) {
        let (grant_read, grant_write) = pipe().unwrap();
        let (results_read, results_write) = pipe().unwrap();
        let (lock, _keep) = pipe().unwrap();
        let frame = wire::encode(&Message::Grant(grant(units))).unwrap();
        let write = |at: &mut u64| {
            *at = now();
            assert!(matches!(
                crate::commands::sys::write_fd(grant_write.as_raw_fd(), &frame),
                crate::commands::sys::WriteOutcome::Done
            ));
        };
        let mut granted = 0;
        if early {
            write(&mut granted);
        }
        let args = [exe.to_bytes().to_vec(), b"__command-v1".to_vec()];
        let spawned = now();
        let mut child =
            spawn_supervisor(exe, &args, &grant_read, &results_write, &lock, u64::MAX).unwrap();
        drop((grant_read, results_write));
        if !early {
            std::thread::sleep(std::time::Duration::from_millis(50));
            write(&mut granted);
        }
        let mut bytes = Vec::new();
        let mut buf = vec![0u8; 65_536];
        let mut out = Vec::new();
        while out.len() < units {
            // SAFETY: writable buffer; blocking read end.
            let n =
                unsafe { libc::read(results_read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            let n = usize::try_from(n).unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            while bytes.len() >= wire::HEADER {
                let total = wire::frame_len(&bytes).unwrap();
                if bytes.len() < total {
                    break;
                }
                if let Message::Result(o) = wire::decode(&bytes[..total]).unwrap() {
                    out.push(o);
                }
                bytes.drain(..total);
            }
        }
        drop(grant_write);
        while !child.reap().unwrap() {}
        (spawned, granted, out)
    }

    fn show(name: &str, mut v: Vec<u64>) {
        v.sort_unstable();
        let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)] as f64 / 1e6;
        println!(
            "{name}: n={} p50={:.3} ms p95={:.3} ms max={:.3} ms",
            v.len(),
            p(0.5),
            p(0.95),
            p(1.0)
        );
    }

    #[test]
    #[ignore = "timing: needs BINGSU_BIN"]
    fn c2_timings() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        #[expect(clippy::disallowed_methods, reason = "test-only timing input")]
        let exe = CString::new(std::env::var("BINGSU_BIN").unwrap()).unwrap();
        let rounds: usize = 30;
        let (mut ready, mut first, mut approve) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..rounds {
            // Grant already waiting: spawn -> first approval is start-up and grant read.
            let (spawned, _, out) = round(&exe, 1, true);
            ready.push(out[0].approved_at - spawned);
            // Supervisor idle on its pipe: grant -> first approval, and approval -> end.
            let (_, granted, out) = round(&exe, 8, false);
            first.push(out.iter().map(|o| o.approved_at).min().unwrap() - granted);
            for o in &out {
                assert!(matches!(o.reason, wire::Reason::Exited(0)), "{o:?}");
                approve.push(o.ended_at - o.approved_at);
            }
        }
        show(
            "supervisor_ready_ns (spawn -> first approval, grant waiting)",
            ready,
        );
        show("go_to_first_approval_ns (grant -> first approval)", first);
        show(
            "approve_to_end_ns (approval -> /bin/true reaped, 8 units)",
            approve,
        );
    }
}
