//! Pre-filter TCB: one fixed helper, no PATH lookup, no inherited environment,
//! no wait. The caller's argv0 is the absolute binary path pinned by init.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;

pub fn bootstrap(
    exe: &OsStr,
    raw: &[&[u8]],
    deadline: Option<bingsu_core::front::output::Deadline>,
) {
    let _ = spawn_until(exe, raw, deadline);
}
fn spawn_until(
    exe: &OsStr,
    raw: &[&[u8]],
    deadline: Option<bingsu_core::front::output::Deadline>,
) -> Result<(), ()> {
    crate::prompt_io::check_deadline(deadline);
    if !exe.as_bytes().starts_with(b"/") {
        return Err(());
    }
    let words = bingsu_core::helper::words(raw).map_err(|_| ())?;
    let path = CString::new(exe.as_bytes()).map_err(|_| ())?;
    let mut strings = vec![path.clone(), CString::new("__refresh-v1").map_err(|_| ())?];
    for word in words {
        strings.push(CString::new(word).map_err(|_| ())?);
    }
    let mut argv: Vec<_> = strings.iter().map(|s| s.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let env = [std::ptr::null_mut()];
    // SAFETY: zeroed storage is initialized by the corresponding init functions.
    let mut actions = unsafe { std::mem::zeroed() };
    // SAFETY: actions is writable storage for a spawn action object.
    check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
    // SAFETY: zeroed storage is initialized below.
    let mut attr = unsafe { std::mem::zeroed() };
    // SAFETY: attr is writable storage for a spawn attribute object.
    if check(unsafe { libc::posix_spawnattr_init(&mut attr) }).is_err() {
        // SAFETY: actions was initialized above.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
        return Err(());
    }
    let result = (|| {
        // SAFETY: zero is valid storage for sigaction; mask initialized below.
        let mut reap: libc::sigaction = unsafe { std::mem::zeroed() };
        reap.sa_sigaction = libc::SIG_IGN;
        reap.sa_flags = libc::SA_NOCLDWAIT;
        // SAFETY: writable signal set.
        check(unsafe { libc::sigemptyset(&mut reap.sa_mask) })?;
        // SAFETY: valid signal and initialized action, no previous action requested.
        check(unsafe { libc::sigaction(libc::SIGCHLD, &reap, std::ptr::null_mut()) })?;
        // SAFETY: initialized below using signal-set functions.
        let mut mask = unsafe { std::mem::zeroed() };
        // SAFETY: valid writable signal set.
        check(unsafe { libc::sigemptyset(&mut mask) })?;
        // SAFETY: initialized objects.
        check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr, &mask) })?;
        // SAFETY: valid writable signal set.
        check(unsafe { libc::sigfillset(&mut mask) })?;
        // SAFETY: initialized objects; reset inherited ignores in child only.
        check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr, &mask) })?;
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
        #[cfg(target_os = "macos")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // SAFETY: attr is initialized; flags are supported spawn flags.
        check(unsafe { libc::posix_spawnattr_setflags(&mut attr, flags as libc::c_short) })?;
        for fd in 0..3 {
            // SAFETY: initialized actions, fixed NUL-terminated path; only child's fds change.
            check(unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    fd,
                    c"/dev/null".as_ptr(),
                    libc::O_RDWR,
                    0,
                )
            })?;
        }
        #[cfg(target_os = "linux")]
        {
            // Single-threaded front end. Enumerate the complete fd table, not
            // RLIMIT_NOFILE (which can be lowered below an already open fd).
            // Uses POSIX actions on both glibc and musl, including old releases.
            crate::prompt_io::check_deadline(deadline);
            let mut entries = std::fs::read_dir("/proc/self/fd").map_err(|_| ())?;
            loop {
                crate::prompt_io::check_deadline(deadline);
                let Some(entry) = entries.next() else { break };
                let entry = entry.map_err(|_| ())?;
                let fd: i32 = entry
                    .file_name()
                    .to_str()
                    .ok_or(())?
                    .parse()
                    .map_err(|_| ())?;
                if fd >= 3 {
                    // SAFETY: initialized action; the integer came from the kernel fd table.
                    check(unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, fd) })?;
                }
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(());
        crate::prompt_io::check_deadline(deadline);
        let mut pid = 0;
        // SAFETY: all strings, pointer arrays, initialized objects outlive spawn;
        // env and argv are NUL terminated. No function pointer or PATH lookup.
        check(unsafe {
            libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                env.as_ptr(),
            )
        })
    })();
    // SAFETY: initialized actions, now no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, now no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}
fn check(rc: i32) -> Result<(), ()> {
    if rc == 0 { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    fn spawn(exe: &std::ffi::OsStr, raw: &[&[u8]]) -> Result<(), ()> {
        super::spawn_until(exe, raw, None)
    }
    use super::*;
    use std::{
        fs,
        process::Command,
        time::{Duration, Instant},
    };
    // 이것을 실패시키는 것: 높은 fd 상속·셸 stdout 유지·signal/env 상속·wait·자동 회수 누락.
    #[test]
    #[ignore = "isolates signal disposition and inherited fds"]
    fn spawn_child() {
        let (base, exe) = crate::commands::n3_test::probe("spawn");
        let file = fs::File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        // SAFETY: initialized below, writable limit storage.
        let mut limit = unsafe { std::mem::zeroed() };
        // SAFETY: valid resource and output pointer.
        assert_eq!(
            // SAFETY: valid resource and writable limit storage.
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit.rlim_cur = 4608.min(limit.rlim_max);
        // SAFETY: child-only limit change within inherited hard.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        // SAFETY: live fd; deliberately non-CLOEXEC high descriptor.
        let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 1025) };
        assert!(high >= 1025);
        let home = format!("--home={}", base.display());
        let raw: Vec<&[u8]> = vec![
            b"--runtime-root=1:2:/r",
            b"--config-root=/c",
            b"--config-root-written=/c",
            b"--state-root=/s",
            home.as_bytes(),
            b"--log-level=info",
        ];
        let start = Instant::now();
        spawn(exe.as_os_str(), &raw).unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        let report = crate::commands::n3_test::wait_report(&base.join("probe"));
        assert_eq!(&report[..5], &[3, 0, 0, 1, 1]);
        // The slow helper is alive, but the test parent has never waited for it.
        // SAFETY: zero signal only tests the known child's existence.
        assert_eq!(unsafe { libc::kill(report[5], 0) }, 0);
        // SAFETY: terminate the test fixture, which is not the product helper.
        unsafe { libc::kill(report[5], libc::SIGKILL) };
        let mut fast = raw.clone();
        *fast.last_mut().unwrap() = b"--log-level=debug";
        for _ in 0..16 {
            fs::remove_file(base.join("probe")).unwrap();
            spawn(exe.as_os_str(), &fast).unwrap();
            let report = crate::commands::n3_test::wait_report(&base.join("probe"));
            assert_eq!(&report[..5], &[3, 0, 0, 1, 1]);
        }
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            // SAFETY: test-only nonblocking reap query and valid status pointer.
            let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            assert_ne!(rc, report[5], "zombie instead of automatic reap");
            if rc == -1 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD)
                );
                break;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(spawn(OsStr::new("relative"), &raw).is_err());
        assert!(spawn(OsStr::new("/missing-bingsu"), &raw).is_err());
        // SAFETY: closing the duplicate created above, no Rust owner.
        unsafe { libc::close(high) };
        fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: 고정 생성의 fd 정리·자동 회수·실패 반환이 망가지는 것.
    #[test]
    fn fixed_spawn_fd_hygiene_and_reaping() {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "prompt_spawn::tests::spawn_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BINGSU_ATTACK", "yes")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
