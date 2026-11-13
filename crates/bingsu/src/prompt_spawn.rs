//! Pre-filter TCB: one fixed helper, no PATH lookup, no inherited environment,
//! no wait. The caller's argv0 is the absolute binary path pinned by init.
//! The shell's environment reaches the helper only as bytes: one framed
//! write into a Unix stream socket pair whose read end becomes the helper's
//! fd 4 (`bingsu_core::command::env_frame`); the helper's envp stays empty.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

/// Starts the refresh helper (unless the shell asked for a redraw) and
/// returns the shell's environment frame: the one pass over environ serves
/// the helper's fd 4 and the prompt's command display (C4b ruling Q6).
/// `None` for an environment over the frame cap, as the helper sees it.
/// The helper is the hook's `--helper-exe=` word, else `fallback`
/// (`front::helper_exe`): argv0 for `bingsu prompt`, none for `bingsu-prompt`.
pub fn bootstrap(
    fallback: Option<&OsString>,
    raw: &[&[u8]],
    deadline: Option<bingsu_core::front::output::Deadline>,
) -> Option<Vec<u8>> {
    let frame = bingsu_core::command::env_frame::encode(environ_entries());
    if bingsu_core::front::spawns_helper(raw)
        && let Some(exe) = bingsu_core::front::helper_exe(raw, fallback.map(|exe| exe.as_bytes()))
    {
        let _ = spawn_until(OsStr::from_bytes(exe), raw, frame.as_deref(), deadline);
    }
    frame
}
#[cfg(test)]
pub(crate) fn spawn_for_test(exe: &OsStr, raw: &[&[u8]]) -> Result<(), ()> {
    let frame = bingsu_core::command::env_frame::encode(environ_entries());
    spawn_until(exe, raw, frame.as_deref(), None)
}
fn spawn_until(
    exe: &OsStr,
    raw: &[&[u8]],
    frame: Option<&[u8]>,
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
    let mut env_read = None;
    let env_read = &mut env_read;
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
        #[cfg(target_os = "linux")]
        {
            // Single-threaded front end. Enumerate the complete fd table, not
            // RLIMIT_NOFILE (which can be lowered below an already open fd).
            // Mark descriptors close-on-exec in this single-threaded process.
            // addclose rejects fds above a lowered NOFILE limit on glibc;
            // F_SETFD still works, even after the hard limit was lowered.
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
                    // SAFETY: the integer came from the live kernel fd table.
                    // This changes descriptor flags, not the shared open-file flags.
                    check(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
                }
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(());
        crate::prompt_io::check_deadline(deadline);
        // Made after the fd walk above, so the walk neither lists nor marks it.
        *env_read = env_socket(frame);
        if let Some(read) = *env_read {
            // First, so a read end at 0-2 is copied before those are replaced.
            // A read end that already is fd 4 has its close-on-exec flag
            // cleared by this action (POSIX adddup2 with equal descriptors).
            // SAFETY: initialized actions; the read end is open until after spawn.
            check(unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions, read, ENV_FD) })?;
        }
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
    if let Some(read) = *env_read {
        // SAFETY: the read end made by env_socket; the helper holds its own copy.
        unsafe { libc::close(read) };
    }
    // SAFETY: initialized actions, now no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, now no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}
fn check(rc: i32) -> Result<(), ()> {
    if rc == 0 { Ok(()) } else { Err(()) }
}

const ENV_FD: i32 = bingsu_core::command::env_frame::FD;

/// Send buffer of the frame's socket: one whole frame
/// (`env_frame::FRAME_MAX`), which one non-blocking write then takes
/// (`max_env_frame_fits_one_write`). A pipe cannot promise that room: macOS
/// starts every pipe at 512 bytes and grows it only while pipe kernel memory
/// is under a system-wide cap, and Linux gives 4 KiB pipes to a user past
/// pipe-user-pages-soft. A socket buffer draws on socket memory instead. A
/// system whose limit is lower takes less: the write is then short, the
/// helper reports the frame cut and runs no command unit, and the prompt
/// does not wait.
const SEND_BUFFER: libc::c_int = bingsu_core::command::env_frame::FRAME_MAX as libc::c_int;

/// The read end of a new socket pair holding `frame`, its write end already
/// closed. `None` when no pair could be made; the helper then starts without
/// fd 4, which it reads as no environment.
fn env_socket(frame: Option<&[u8]>) -> Option<i32> {
    let [read, write] = env_socket_ends()?;
    let _ = write_frame(write, frame);
    // SAFETY: the write end made above, closed exactly once.
    unsafe { libc::close(write) };
    Some(read)
}

/// `[read, write]` of a Unix stream socket pair, the write end non-blocking
/// (on Linux both ends, from the socketpair flags) with its send buffer set
/// to `SEND_BUFFER`. A refused size is left as the kernel's: a frame that
/// does not fit is cut, never waited for. Nothing but this process and the
/// helper holds either end; the write end is closed before the spawn, so the
/// helper's fd 4 has no peer to send to.
fn env_socket_ends() -> Option<[i32; 2]> {
    let mut fds = [-1; 2];
    // SAFETY: two writable ints for the new descriptors.
    #[cfg(target_os = "linux")]
    let made = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fds.as_mut_ptr(),
        )
    } == 0;
    // macOS has no socket flags. Spawn closes every other fd (POSIX_SPAWN_CLOEXEC_DEFAULT).
    // SAFETY: two writable ints for the new descriptors.
    #[cfg(target_os = "macos")]
    let made =
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } == 0;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let made = false;
    if !made {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        // A blocking write could wait on the helper: without the flag, no socket.
        // No test: F_SETFL fails only on an invalid fd, which a test cannot
        // produce here. Kept by user decision (2026-11-04).
        // SAFETY: the write end made above; changes only its status flags.
        if unsafe { libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
            // SAFETY: both ends made above, closed exactly once.
            unsafe { libc::close(fds[0]) };
            // SAFETY: as above.
            unsafe { libc::close(fds[1]) };
            return None;
        }
    }
    // SAFETY: the write end made above; reads `SEND_BUFFER` for its size.
    let _ = unsafe {
        libc::setsockopt(
            fds[1],
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&SEND_BUFFER as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    Some(fds)
}

/// One non-blocking write of the frame; the bytes accepted. `EAGAIN`, a short
/// write or an oversize environment (no frame, no write) leaves less than a
/// whole frame, which the helper reads as no environment. Never retried:
/// nobody reads the socket until the helper runs.
fn write_frame(write: i32, frame: Option<&[u8]>) -> isize {
    let Some(frame) = frame else {
        return 0;
    };
    // SAFETY: initialized frame bytes, valid for frame.len() bytes.
    unsafe { libc::write(write, frame.as_ptr().cast(), frame.len()) }
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    static environ: *const *const libc::c_char;
}

/// The entries of this process's environment as the shell passed them,
/// each with its NUL. Nothing is split or decoded. The front is single
/// threaded and never changes its environment, so the array stays put.
fn environ_entries() -> impl Iterator<Item = &'static [u8]> {
    // SAFETY: the C runtime's environment pointer, read once.
    #[cfg(target_os = "linux")]
    let mut at = unsafe { environ };
    // SAFETY: libSystem's accessor for the same pointer; never null.
    #[cfg(target_os = "macos")]
    let slot = unsafe { libc::_NSGetEnviron() };
    // SAFETY: the accessor's slot holds the environment pointer.
    #[cfg(target_os = "macos")]
    let mut at = unsafe { *slot }.cast_const().cast::<*const libc::c_char>();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let mut at: *const *const libc::c_char = std::ptr::null();
    std::iter::from_fn(move || {
        if at.is_null() {
            return None;
        }
        // SAFETY: a NULL-terminated array of entries; `at` is inside it.
        let entry = unsafe { *at };
        if entry.is_null() {
            return None;
        }
        // SAFETY: the next slot exists, since this one was not the terminator.
        at = unsafe { at.add(1) };
        // SAFETY: each entry is a NUL-terminated string that lives as long as the process.
        Some(unsafe { std::ffi::CStr::from_ptr(entry) }.to_bytes_with_nul())
    })
}

#[cfg(test)]
mod tests {
    fn spawn(exe: &std::ffi::OsStr, raw: &[&[u8]]) -> Result<(), ()> {
        let frame = bingsu_core::command::env_frame::encode(super::environ_entries());
        super::spawn_until(exe, raw, frame.as_deref(), None)
    }
    /// The frame of these entries, as `bootstrap` makes it.
    fn frame_of(entries: &[&[u8]]) -> Option<Vec<u8>> {
        bingsu_core::command::env_frame::encode(entries.iter().copied())
    }
    /// The length of the frame `spawn` hands over: this process's environment.
    fn env_frame_len() -> i32 {
        let frame = bingsu_core::command::env_frame::encode(super::environ_entries()).unwrap();
        i32::try_from(frame.len()).unwrap()
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
        spawn_fixture(false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child: irreversibly lowers NOFILE after opening a high fd"]
    fn lowered_nofile_child() {
        spawn_fixture(true);
    }

    fn spawn_fixture(lower_limit: bool) {
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
        if lower_limit {
            limit.rlim_cur = 32;
            limit.rlim_max = 32;
            // SAFETY: isolated fixture process; high remains open above both limits.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        }
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
        // fds 0-2 and the environment socket at 4, nothing else.
        assert_eq!(&report[..5], &[4, 0, 0, 1, 1]);
        // The parent's BINGSU_ATTACK reaches the helper only as frame bytes (report[4]: not in envp).
        // 이것을 실패시키는 것: adddup2를 빼는 것(fd 4가 없어 -1), 쓰기를 빼는 것(0바이트), 프레임 일부만
        // 넘기는 것(파이프로 되돌리면 파이프 메모리가 모자란 macOS에서 512바이트만 간다).
        assert_eq!(
            (report[8], report[9]),
            (env_frame_len(), 1),
            "the whole frame on fd 4: {report:?}"
        );
        // 이것을 실패시키는 것: fd 0–2 중 하나의 addopen을 지우는 것(시험 부모의 stdout·stderr가 남는다).
        assert_eq!(report[7], 3, "fds 0-2 must be the spawn's own /dev/null");
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
            assert_eq!(&report[..5], &[4, 0, 0, 1, 1]);
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("spawn_child");
    }

    // 이것을 실패시키는 것: 낮춘 NOFILE 위의 fd를 addclose에 넣거나 exec에 상속시키는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn lowered_nofile_still_spawns_without_leaking_fds() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("lowered_nofile_child");
    }

    // 이것을 실패시키는 것: env_socket_ends의 `if !made` 조기 반환을 지우는 것(Linux: [-1, -1]을 돌려줘
    // 첫 단언이 실패한다. macOS에서는 뒤따르는 F_SETFL 실패 분기가 같은 경우를 닫아 이 변이가 산다).
    // musl의 posix_spawn은 자기 오류 파이프에 fd 둘이 필요해 같은 한도에서 생성이
    // 실패하므로 musl에서는 돌리지 않는다.
    #[cfg(not(target_env = "musl"))]
    #[test]
    fn env_socket_failure_still_spawns_without_fd_4() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("env_socket_failure_child");
    }

    #[cfg(not(target_env = "musl"))]
    #[test]
    #[ignore = "child: fills its fd table so only one descriptor is free"]
    fn env_socket_failure_child() {
        use std::os::fd::IntoRawFd;
        const LIMIT: i32 = 32;
        let (base, exe) = crate::commands::n3_test::probe("env-emfile");
        let null = fs::File::open("/dev/null").unwrap().into_raw_fd();
        assert!(null < LIMIT - 1);
        for fd in 3..LIMIT - 1 {
            // SAFETY: isolated child; only probes whether the slot is open.
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                // SAFETY: live source fd; fills a free slot in this child only.
                assert_eq!(unsafe { libc::dup2(null, fd) }, fd);
            }
        }
        // SAFETY: isolated child; leaves exactly the last slot under the limit free.
        unsafe { libc::close(LIMIT - 1) };
        // SAFETY: initialized below, writable limit storage.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: valid resource and writable limit storage.
        let got = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        assert_eq!(got, 0);
        let saved = limit;
        limit.rlim_cur = LIMIT as libc::rlim_t;
        // SAFETY: lowers only the soft limit of this child.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        // One free slot: the fd walk (Linux) still opens its folder, a socket pair cannot.
        assert!(
            super::env_socket_ends().is_none(),
            "the fixture must make socketpair fail"
        );
        let home = format!("--home={}", base.display());
        let raw: Vec<&[u8]> = vec![
            b"--runtime-root=1:2:/r",
            b"--config-root=/c",
            b"--config-root-written=/c",
            b"--state-root=/s",
            home.as_bytes(),
            b"--log-level=debug",
        ];
        let spawned = spawn(exe.as_os_str(), &raw);
        // SAFETY: restores the soft limit saved above (within the unchanged hard limit).
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) }, 0);
        spawned.expect("the helper spawns without an environment socket");
        let report = crate::commands::n3_test::wait_report(&base.join("probe"));
        // fds 0-2 only, envp empty, and no fd 4: the helper reads that as no environment.
        assert_eq!(&report[..5], &[3, 0, 0, 1, 1], "{report:?}");
        assert_eq!(report[8], -1, "no fd 4: {report:?}");
        fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: 읽는 쪽이 이미 fd 4일 때 adddup2를 건너뛰는 것(Linux는 SOCK_CLOEXEC로,
    // macOS는 POSIX_SPAWN_CLOEXEC_DEFAULT로 exec 때 닫혀 도우미에 fd 4가 없다).
    #[test]
    fn env_read_end_already_at_fd_4() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("env_read_end_at_fd_4_child");
    }

    #[test]
    #[ignore = "child: arranges its fd table so the socket's read end is fd 4"]
    fn env_read_end_at_fd_4_child() {
        let (base, exe) = crate::commands::n3_test::probe("env-fd4");
        // Isolated child process: fd 3 open, 4 and 5 free, so the pair gets [4, 5].
        use std::os::fd::IntoRawFd;
        let null = fs::File::open("/dev/null").unwrap().into_raw_fd();
        if null != 3 {
            // SAFETY: live source fd; replaces whatever fd 3 was in this child only.
            assert_eq!(unsafe { libc::dup2(null, 3) }, 3);
            // SAFETY: the raw fd taken above, closed once.
            unsafe { libc::close(null) };
        }
        for fd in [4, 5] {
            // SAFETY: isolated child; frees the slots the fixture needs.
            unsafe { libc::close(fd) };
        }
        let [read, write] = super::env_socket_ends().unwrap();
        assert_eq!(
            (read, write),
            (4, 5),
            "fixture must put the read end at fd 4"
        );
        for fd in [read, write] {
            // SAFETY: both ends made just above, closed once.
            unsafe { libc::close(fd) };
        }
        let home = format!("--home={}", base.display());
        let raw: Vec<&[u8]> = vec![
            b"--runtime-root=1:2:/r",
            b"--config-root=/c",
            b"--config-root-written=/c",
            b"--state-root=/s",
            home.as_bytes(),
            b"--log-level=debug",
        ];
        spawn(exe.as_os_str(), &raw).unwrap();
        let report = crate::commands::n3_test::wait_report(&base.join("probe"));
        assert_eq!(&report[..5], &[4, 0, 0, 1, 1], "{report:?}");
        assert_eq!(
            (report[8], report[9]),
            (env_frame_len(), 1),
            "the whole frame on fd 4: {report:?}"
        );
        fs::remove_dir_all(base).unwrap();
    }

    fn entry(total: usize) -> Vec<u8> {
        let mut e = b"BIG=".to_vec();
        e.resize(total - 1, b'x');
        e.push(0);
        e
    }

    fn read_all(fd: i32) -> Vec<u8> {
        let mut out = vec![0u8; 80_000];
        let mut got = 0;
        loop {
            // SAFETY: writable bytes from got to the end of out.
            let n = unsafe { libc::read(fd, out[got..].as_mut_ptr().cast(), out.len() - got) };
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        // SAFETY: test-owned read end, closed once.
        unsafe { libc::close(fd) };
        out.truncate(got);
        out
    }

    // 이것을 실패시키는 것: 상한을 본문 기준 65,536으로 두는 것(머리를 빼지 않음). 1바이트 큰 환경이
    // 65,537바이트 프레임이 되어 쓰기가 일부만 받아들이고, 도우미 쪽에 바이트가 남는다. 소켓 대신 파이프로
    // 되돌리는 것(파이프 커널 메모리가 상한에 닿은 macOS는 새 파이프가 512바이트에서 늘지 않는다), 보내기
    // 버퍼를 넓히지 않는 것(macOS의 Unix stream 기본값은 8 KiB).
    // The two checks below hold whatever the machine's pipe state: the read
    // end is a socket, and the write end's send buffer takes a whole frame.
    // 이것을 실패시키는 것: 파이프로 되돌리는 것(S_ISSOCK 아님, getsockopt 실패), 보내기 버퍼를 넓히지 않는 것
    // (macOS 기본 8 KiB; Linux 기본값은 한 프레임보다 커서 이 단언만으로는 잡히지 않는다).
    #[test]
    fn max_env_frame_fits_one_write() {
        use bingsu_core::command::env_frame::{BODY_MAX, FRAME_MAX};
        let max = entry(BODY_MAX);
        let [read, write] = super::env_socket_ends().unwrap();
        // SAFETY: all-zero storage for the stat fstat writes.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `read` is open and `st` is writable.
        assert_eq!(unsafe { libc::fstat(read, &mut st) }, 0);
        assert_eq!(
            st.st_mode & libc::S_IFMT,
            libc::S_IFSOCK,
            "the read end is a socket"
        );
        let mut size: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `write` is open; `size` and `len` are writable and sized for an int.
        let rc = unsafe {
            libc::getsockopt(
                write,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&mut size as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        assert!(size as usize >= FRAME_MAX, "send buffer {size}");
        assert_eq!(
            super::write_frame(write, frame_of(&[max.as_slice()]).as_deref()),
            FRAME_MAX as isize
        );
        // SAFETY: test-owned write end, closed once.
        unsafe { libc::close(write) };
        assert_eq!(
            crate::commands::helper::read_env(read).as_deref(),
            Some(max.as_slice())
        );
        let over = entry(BODY_MAX + 1);
        let read = super::env_socket(frame_of(&[over.as_slice()]).as_deref()).unwrap();
        assert_eq!(
            read_all(read),
            b"",
            "an oversize environment writes nothing"
        );
    }

    // 이것을 실패시키는 것: 도우미 쪽 프레임 길이 검사를 지우는 것(중간 EOF 프레임에서 slice panic),
    // 쓰기를 재시도하는 것(가득 찬 소켓에서 이 시험이 멈춘다).
    #[test]
    fn partial_env_frame_discarded() {
        let body = entry(5_000);
        let frame = bingsu_core::command::env_frame::encode([body.as_slice()]).unwrap();
        // End of file in the middle of the body.
        let [read, write] = super::env_socket_ends().unwrap();
        // SAFETY: initialized bytes, half the frame.
        let n = unsafe { libc::write(write, frame.as_ptr().cast(), frame.len() / 2) };
        assert_eq!(n as usize, frame.len() / 2);
        // SAFETY: test-owned write end, closed once.
        unsafe { libc::close(write) };
        assert_eq!(crate::commands::helper::read_env(read), None);
        // EAGAIN or a short write into a socket that is full.
        let [read, write] = super::env_socket_ends().unwrap();
        let chunk = vec![0u8; 4096];
        let mut filled = 0usize;
        loop {
            // SAFETY: initialized bytes, valid for the chunk's length.
            let n = unsafe { libc::write(write, chunk.as_ptr().cast(), chunk.len()) };
            if n < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN)
                );
                break;
            }
            filled += n as usize;
            assert!(filled < 64 * bingsu_core::command::env_frame::FRAME_MAX);
        }
        let accepted = super::write_frame(write, frame_of(&[body.as_slice()]).as_deref());
        assert!(
            accepted < frame.len() as isize,
            "the fixture must refuse part of the frame"
        );
        // SAFETY: test-owned write end, closed once.
        unsafe { libc::close(write) };
        let mut drained = vec![0u8; filled];
        let mut got = 0;
        while got < drained.len() {
            // SAFETY: writable bytes from got on.
            let n = unsafe {
                libc::read(
                    read,
                    drained[got..].as_mut_ptr().cast(),
                    drained.len() - got,
                )
            };
            assert!(n > 0);
            got += n as usize;
        }
        assert_eq!(crate::commands::helper::read_env(read), None);
    }

    fn child(name: &str) {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("prompt_spawn::tests::{name}"),
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
