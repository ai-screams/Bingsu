//! Trusted relay, native executables and scripts on Linux and macOS
//! (`bingsu __exec-v2`). The command
//! supervisor spawns it with an empty environment and the permit and exec
//! frame on fd 3 (fd 2 is its status pipe); the relay checks the target
//! through one open descriptor, checks that its name is still that file,
//! takes a fresh clock and runs it by name. Linux runs it with
//! `execveat(folder, name, AT_SYMLINK_NOFOLLOW)` and a script as its checked
//! interpreter with a sealed memfd copy of the script. macOS has neither
//! `execveat` nor `fexecve`: it rechecks the whole canonical path with
//! `AT_SYMLINK_NOFOLLOW_ANY` and runs `execve` on it, and a script arrives
//! as the helper's private copy (`exec_path::ScriptCopies`). Every decision
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
use bingsu_core::command::path::{ExecPin, Head, SHEBANG_MAX, Shebang, head};
use bingsu_core::fs_trust::{AclFacts, Facts, PinnedGroupWrite, Verdict, entry_verdict};
use bingsu_core::handoff::{ExecFrame, PERMIT_FD, Permit, parse_relay_args, read_relay_input};
use std::ffi::{CString, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

/// Largest permit plus exec frame the relay reads from fd 3.
pub(crate) const INPUT_CAP: usize = bingsu_core::handoff::RELAY_INPUT_MAX;
/// Fixed exit codes; the target was not executed. Argv or fd 3 input.
pub(crate) const RELAY_INPUT: u8 = 120;
/// The fresh clock is past a deadline or is not the permit's clock.
pub(crate) const RELAY_EXPIRED: u8 = 121;
/// The executable failed to open or a check on its descriptor.
pub(crate) const RELAY_TARGET: u8 = 122;
/// Descriptor setup or `execveat` failed.
pub(crate) const RELAY_EXEC: u8 = 123;
/// Largest script the relay copies into its memfd (spec: 64 KB).
pub(crate) const SCRIPT_MAX: usize = 64 * 1024;
/// macOS `fstatat` flag (sys/fcntl.h, not in the libc crate): no symlink
/// anywhere on the path. A macOS without it answers EINVAL, and the name
/// check then refuses.
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW_ANY: i32 = 0x0800;
/// The seals of the script copy: its bytes and size are fixed, and nobody
/// can lift a seal.
#[cfg(target_os = "linux")]
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

pub(crate) fn run(args: &[OsString]) -> ExitCode {
    ExitCode::from(relay(args))
}

/// Returns only when the target was not executed. The supervisor learns
/// which happened from the status pipe it passes as fd 2: the refusal code
/// as one byte, or end of file without one when `execveat` closed it.
fn relay(args: &[OsString]) -> u8 {
    let (status, code) = match take_status() {
        Ok(status) => {
            let code = match prepare(args) {
                Ok(target) => target.exec(),
                Err(code) => code,
            };
            (status, code)
        }
        Err(status) => (status, RELAY_EXEC),
    };
    if let Some(fd) = status {
        // SAFETY: one readable byte to the relay's own descriptor.
        unsafe { libc::write(fd.as_raw_fd(), [code].as_ptr().cast(), 1) };
    }
    code
}

/// Moves fd 2 (the status pipe) to 4 or above, where the close-on-exec pass
/// of `prepare` marks it like every descriptor from 3 up, and puts
/// `/dev/null` at 2 for the target (spec: stderr `/dev/null`). Without a
/// fd 2 there is no status pipe, and 2 still gets `/dev/null`. `Err` (fd 2
/// could not be replaced, so the target would inherit the pipe) refuses.
fn take_status() -> Result<Option<OwnedFd>, Option<OwnedFd>> {
    // Above 3 even when fd 3 is missing: the input must never be read from
    // (or closed under) the status pipe. Fails without it: cli_smoke's
    // exec_entry_reaches_the_relay, whose fd 3 is closed (the relay aborted).
    // SAFETY: duplicates fd 2 when it is open; -1 (EBADF) when it is not.
    let moved = unsafe { libc::fcntl(2, libc::F_DUPFD, 4) };
    // SAFETY: a successful F_DUPFD returns a descriptor nothing else owns.
    let status = (moved >= 0).then(|| unsafe { OwnedFd::from_raw_fd(moved) });
    // SAFETY: fixed NUL-terminated path, no O_CREAT.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    // No test: opening /dev/null or the dup2 below cannot be made to fail
    // from a test without also failing the relay's other opens; either way
    // the relay refuses (fail closed). An untested fail-closed branch is a
    // deliberate exception here, like the macOS `F_SETFL` branch of
    // `prompt_spawn`.
    if null < 0 {
        return Err(status);
    }
    // Rust's runtime opens `/dev/null` on any of 0 to 2 that is closed
    // before `main`, so fd 2 is open here and `null` is above it.
    // SAFETY: both descriptors are open; dup2 clears close-on-exec on 2.
    let ok = unsafe { libc::dup2(null, 2) } == 2;
    // SAFETY: `null` was opened above and is closed once.
    unsafe { libc::close(null) };
    if ok { Ok(status) } else { Err(status) }
}

/// A checked target, ready for the clock check and `execveat`. The pointer
/// arrays point into `argv` and `envp`, whose heap buffers do not move with
/// the struct. `frame` keeps only its deadline and origin (its environment is
/// moved into `envp`), so dropping it frees nothing.
pub(crate) struct Target {
    permit: Permit,
    frame: ExecFrame,
    exe: Exe,
    /// A script's sealed copy: the one descriptor past 2 the target keeps.
    _script: Option<OwnedFd>,
    /// macOS: the helper's script copy the interpreter will open by path,
    /// rechecked by name with the interpreter right before the exec.
    #[cfg(target_os = "macos")]
    copy: Option<Exe>,
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    envp_ptrs: Vec<*const libc::c_char>,
}

/// Spec order: signals, fd 3 read and closed, the executable opened and
/// checked, descriptors past 2 marked close-on-exec. Every buffer of this
/// stage is freed when it returns; the fresh clock comes after, in `exec`.
/// The relay enters the unit's working folder (the frame's `cwd`: the
/// neutral folder, or the shell's folder for `untrusted-current`) after its
/// checks, and the target inherits it. The supervisor spawns every relay in
/// "/", so a folder on a stopped mount holds only this relay, which the
/// supervisor ends at its deadline.
pub(crate) fn prepare(args: &[OsString]) -> Result<Target, u8> {
    reset_signals();
    let input = read_fd3();
    // SAFETY: fd 3 is the relay's own input; nothing else holds it.
    unsafe { libc::close(i32::from(PERMIT_FD)) };
    let input = input.ok_or(RELAY_INPUT)?;
    let words: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let parsed = parse_relay_args(&words).map_err(|_| RELAY_INPUT)?;
    let (permit, mut frame) = read_relay_input(&input, INPUT_CAP).map_err(|_| RELAY_INPUT)?;
    #[cfg(target_os = "macos")]
    let mut copy = None;
    let (exe, script, argv) = match open_target(parsed.executable, frame.pin)? {
        // A frame that names an interpreter was made for a script.
        Opened::Native(_) if frame.interpreter.is_some() => return Err(RELAY_TARGET),
        Opened::Native(exe) => (exe, None, c_strings(parsed.argv)?),
        Opened::Script(exe, body) => {
            let run = script(&exe, &body, &frame, parsed.executable, parsed.argv)?;
            #[cfg(target_os = "macos")]
            {
                copy = Some(exe);
            }
            run
        }
    };
    let envp = environment(&std::mem::take(&mut frame.environment))?;
    let argv_ptrs = pointers(&argv);
    let envp_ptrs = pointers(&envp);
    // The target gets 0, 1 and 2 only; the executable's fd is close-on-exec.
    if !cloexec_all() {
        return Err(RELAY_EXEC);
    }
    // A Linux script's copy alone stays open across exec, so the interpreter
    // can open `/proc/self/fd/N`; this comes after the close-on-exec pass,
    // which would mark it again.
    if let Some(copy) = &script
        && set_fd_flags(copy.as_raw_fd(), 0).is_err()
    {
        return Err(RELAY_EXEC);
    }
    let folder = CString::new(std::mem::take(&mut frame.cwd)).map_err(|_| RELAY_INPUT)?;
    // SAFETY: NUL-terminated absolute path (the frame refuses any other).
    if unsafe { libc::chdir(folder.as_ptr()) } != 0 {
        return Err(RELAY_EXEC);
    }
    // A target that would run with other rights gains nothing; the
    // flag stays for every descendant. Set-id files are refused before this
    // on every system (`allowed`), and file capabilities are refused by
    // the helper's lookup; this flag still holds for a capability set after
    // that check. Last of the checks, so `exec` keeps the clock read right
    // before execveat.
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(RELAY_EXEC);
    }
    Ok(Target {
        permit,
        frame,
        exe,
        _script: script,
        #[cfg(target_os = "macos")]
        copy,
        _argv: argv,
        _envp: envp,
        argv_ptrs,
        envp_ptrs,
    })
}

impl Target {
    /// The fresh clock. Config units need the trust deadline and E, builtin
    /// probes E only, both on the permit's boot, resume and domain.
    fn clock_allows(&self) -> bool {
        crate::prompt_io::observe_clock().is_ok_and(|now| self.frame.allows(self.permit, now))
    }

    /// The name check, the clock check and the exec back to back: nothing
    /// is built or freed between them (`self` drops only after a failed
    /// exec). The target runs by its name: a program that tells its
    /// role from the executed name (uutils' multicall coreutils reads
    /// AT_EXECFN) refuses a `/dev/fd/N`. Right before, the name must still
    /// be the checked file: same device, inode and ctime, and not a symlink.
    /// Linux runs the name in the folder the walk held. macOS has neither
    /// `execveat` nor `fexecve`, so it runs the canonical path, which only
    /// root, the user or a cleared group can change; the window between the
    /// check and the exec there is an accepted OS limit.
    fn exec(self) -> u8 {
        // The name check first: on NFS or FUSE it can take long, and the
        // clock read must be the last step before execveat.
        if !self.exe.still_named() {
            return RELAY_TARGET;
        }
        // macOS: the script copy too, by its path. After the exec the
        // interpreter opens that path itself; in between only the user can
        // change the copy, the user's 0600 file in a 0700 folder (fails
        // without it: test_macos_copy_swapped_before_the_exec_is_refused).
        #[cfg(target_os = "macos")]
        if !self.copy.as_ref().is_none_or(Exe::still_named) {
            return RELAY_TARGET;
        }
        if !self.clock_allows() {
            return RELAY_EXPIRED;
        }
        #[cfg(test)]
        hook::at(hook::Stage::BeforeExec);
        #[cfg(target_os = "macos")]
        // SAFETY: NUL-terminated path; both arrays are NULL-terminated and
        // point at NUL-terminated strings owned by `self`, alive for the call.
        unsafe {
            libc::execve(
                self.exe.path.as_ptr(),
                self.argv_ptrs.as_ptr(),
                self.envp_ptrs.as_ptr(),
            )
        };
        #[cfg(target_os = "linux")]
        // SAFETY: the folder fd is open, the name is NUL-terminated; both
        // arrays are NULL-terminated and point at NUL-terminated strings
        // owned by `self`, alive for the call.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.exe.dir.as_raw_fd(),
                self.exe.name.as_ptr(),
                self.argv_ptrs.as_ptr(),
                self.envp_ptrs.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
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
#[cfg(target_os = "linux")]
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

/// macOS: every signal below NSIG (32) to its default and an empty mask; the
/// C library's sigaction is the kernel's, and it refuses only SIGKILL and
/// SIGSTOP, already default.
#[cfg(target_os = "macos")]
fn reset_signals() {
    for signal in 1..32 {
        // SAFETY: an all-zero sigaction is SIG_DFL, no flags, empty mask.
        let action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `action` is readable; no old action is requested.
        unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
    }
    // SAFETY: an all-zero sigset_t is the empty set.
    let empty: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `empty` is readable; no old mask is requested.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) };
}

/// Every descriptor from 3 up is close-on-exec, or false.
#[cfg(target_os = "linux")]
fn cloexec_all() -> bool {
    cloexec_from_3(close_range_cloexec())
}

/// macOS has no close_range: every open descriptor above 2 that the kernel
/// lists for this process gets FD_CLOEXEC. A listing that fails or may be
/// cut short refuses.
#[cfg(target_os = "macos")]
fn cloexec_all() -> bool {
    cloexec_listed(open_fds(), set_cloexec)
}

/// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, or its errno.
#[cfg(target_os = "linux")]
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

/// Every descriptor from 3 up is close-on-exec. Without close_range (ENOSYS
/// before 5.9) or without its CLOEXEC flag (EINVAL on 5.9 and 5.10; the spec
/// supports 5.7 and later) every open descriptor listed in /proc/self/fd gets
/// FD_CLOEXEC. Any other error, an unreadable listing or a failed fcntl
/// fails closed.
#[cfg(target_os = "linux")]
fn cloexec_from_3(close_range: Result<(), i32>) -> bool {
    match close_range {
        Ok(()) => true,
        Err(libc::ENOSYS | libc::EINVAL) => cloexec_listed(open_fds(), set_cloexec),
        Err(_) => false,
    }
}

/// The numbers in /proc/self/fd, or `None` when the listing fails.
#[cfg(target_os = "linux")]
fn open_fds() -> Option<Vec<i32>> {
    std::fs::read_dir("/proc/self/fd")
        .ok()?
        .map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect()
}

/// The descriptors `proc_pidinfo(PROC_PIDLISTFDS)` lists, or `None` when
/// the call fails or fills the whole buffer (the list may be cut).
#[cfg(target_os = "macos")]
fn open_fds() -> Option<Vec<i32>> {
    let one = std::mem::size_of::<libc::proc_fdinfo>();
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    // SAFETY: a null buffer asks only for the size.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let room = usize::try_from(need).ok()? / one + 16;
    // SAFETY: an all-zero proc_fdinfo is a valid value.
    let mut list = vec![unsafe { std::mem::zeroed::<libc::proc_fdinfo>() }; room];
    let bytes = i32::try_from(room * one).ok()?;
    // SAFETY: `list` is writable for `bytes` bytes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            list.as_mut_ptr().cast(),
            bytes,
        )
    };
    // No test: both refusals need the kernel's answer to change under a
    // single-threaded relay (a failed call, or 16 more descriptors between
    // the two calls); either refuses (fail closed).
    let got = usize::try_from(got)
        .ok()
        .filter(|&g| g > 0 && g < room * one)?
        / one;
    Some(list[..got].iter().map(|f| f.proc_fd).collect())
}

fn set_cloexec(fd: i32) -> Result<(), i32> {
    set_fd_flags(fd, libc::FD_CLOEXEC)
}

fn set_fd_flags(fd: i32, flags: i32) -> Result<(), i32> {
    // SAFETY: F_SETFD only changes this number's descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `set` on every listed number above 2. EBADF is the listing's own
/// descriptor, closed once the listing ends; any other error fails closed.
fn cloexec_listed(fds: Option<Vec<i32>>, mut set: impl FnMut(i32) -> Result<(), i32>) -> bool {
    let Some(fds) = fds else {
        return false;
    };
    for fd in fds.into_iter().filter(|&fd| fd > 2) {
        match set(fd) {
            Ok(()) | Err(libc::EBADF) => {}
            Err(_) => return false,
        }
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

/// `openat(dir, name, flags | O_NOFOLLOW | O_CLOEXEC)` as an owned fd.
fn open_at(dir: i32, name: &[u8], flags: i32) -> Result<OwnedFd, i32> {
    let name = CString::new(name).map_err(|_| libc::EINVAL)?;
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `dir` is open (or AT_FDCWD with an absolute name); `name` is
    // NUL-terminated; no O_CREAT.
    let raw = unsafe { libc::openat(dir, name.as_ptr(), flags) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: a successful openat returns a descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Opens the executable one name at a time from "/" without following any
/// symlink and without waiting on a FIFO, then checks the descriptor. The
/// supervisor passes the canonical path the helper resolved (symlinks
/// owned by root or the user already followed there), so a symlink on the
/// way now means the path changed: refused. Every folder is opened
/// `O_PATH | O_DIRECTORY | O_NOFOLLOW` (macOS: `O_SEARCH | O_NOFOLLOW`), so
/// a symlink in a folder's place fails with ENOTDIR or ELOOP; ".", ".." and
/// empty names are refused.
///
/// The file must be regular and pass `allowed`. It is opened `O_PATH` first
/// and checked; then that descriptor is opened for reading through
/// `/proc/self/fd`, the same inode, and its first bytes say whether it is a
/// script (`read_script`). An execute-only file cannot be opened for reading (EACCES), and
/// without `/proc` there is no such path; then the `O_PATH` descriptor runs,
/// as a native executable only: its
/// `#!` line, if any, is never read, and the kernel's own script loader
/// cannot open the folder descriptor it would hand the interpreter: the
/// name runs as `/dev/fd/<folder>/<name>`, and the folder is close-on-exec
/// (BINPRM_FLAGS_PATH_INACCESSIBLE, `test_execute_only_script_is_not_loaded`).
///
/// macOS has no `O_PATH`: the last name's type is read first (`fstatat`,
/// no follow), then the regular file is opened for reading, and its
/// descriptor must be the same inode. An execute-only file cannot be read
/// and is refused: run by path, the kernel's own script loader would start
/// whatever interpreter its `#!` line names, unchecked. A
/// set-id file is refused (`allowed`), and so is one on a mount that
/// is not local or ignores ownership.
fn open_target(path: &[u8], pin: Option<ExecPin>) -> Result<Opened, u8> {
    // A relative path would name a file in the inherited working folder.
    let Some(rest) = path.strip_prefix(b"/") else {
        return Err(RELAY_TARGET);
    };
    let names: Vec<&[u8]> = rest.split(|&b| b == b'/').collect();
    let (last, folders) = names.split_last().ok_or(RELAY_TARGET)?;
    if names
        .iter()
        .any(|n| n.is_empty() || *n == b"." || *n == b"..")
    {
        return Err(RELAY_TARGET);
    }
    #[cfg(target_os = "linux")]
    let search = libc::O_PATH | libc::O_DIRECTORY;
    #[cfg(target_os = "macos")]
    let search = libc::O_SEARCH;
    let mut dir = open_at(libc::AT_FDCWD, b"/", search).map_err(|_| RELAY_TARGET)?;
    for name in folders {
        dir = open_at(dir.as_raw_fd(), name, search).map_err(|_| RELAY_TARGET)?;
    }
    let name = CString::new(*last).map_err(|_| RELAY_TARGET)?;
    #[cfg(target_os = "linux")]
    let (exe, readable) = {
        // The last name opens path-only first, so a device or FIFO put there is
        // never opened for reading before its type is known.
        let path_fd = open_at(dir.as_raw_fd(), last, libc::O_PATH).map_err(|_| RELAY_TARGET)?;
        let st = stat(&path_fd)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || !allowed(&st, pin, Some(true))? {
            return Err(RELAY_TARGET);
        }
        let (fd, readable) = match reopen(&path_fd).map_err(native_only) {
            Ok(fd) => (fd, true),
            Err(Some(())) => (path_fd, false),
            Err(None) => return Err(RELAY_TARGET),
        };
        // No target or interpreter with file capabilities, also when
        // the pin cannot tell (a setcap in the same coarse timestamp tick as
        // the lookup leaves the ctime unchanged).
        // 이것을 실패시키는 것: 이 확인을 지우는 것(root test_relay_refuses_a_capability_target,
        // test_relay_refuses_capabilities_set_in_the_lookups_tick).
        if !capability_free(&fd) {
            return Err(RELAY_TARGET);
        }
        (Exe { fd, dir, name, st }, readable)
    };
    #[cfg(target_os = "macos")]
    let (exe, readable) = {
        // A device or FIFO put there is never opened (fails without it:
        // test_macos_relay_never_opens_a_fifo). The descriptor is not
        // compared with this stat again: no test can tell a swap between the
        // two from a swap before them. Whatever is opened is what the checks
        // below run on (owner, mode, pin); swapping the name needs root, the
        // user or a cleared group; a FIFO then fails its first pread, and
        // execve refuses any file that is not regular.
        if stat_at(&dir, &name)?.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(RELAY_TARGET);
        }
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;
        let fd = open_at(dir.as_raw_fd(), last, flags).map_err(|_| RELAY_TARGET)?;
        let st = stat(&fd)?;
        if !allowed(&st, pin, local_ownership(&fd))? {
            return Err(RELAY_TARGET);
        }
        let path = CString::new(path).map_err(|_| RELAY_TARGET)?;
        (Exe { fd, path, st }, true)
    };
    if !readable {
        return Ok(Opened::Native(exe));
    }
    Ok(match read_script(&exe.fd)? {
        Some(body) => Opened::Script(exe, body),
        None => Opened::Native(exe),
    })
}

/// A checked executable: its descriptor and the stat the checks ran on,
/// with the folder it was found in and its last name there (Linux) or its
/// canonical path (macOS).
pub(crate) struct Exe {
    fd: OwnedFd,
    #[cfg(target_os = "linux")]
    dir: OwnedFd,
    #[cfg(target_os = "linux")]
    name: CString,
    #[cfg(target_os = "macos")]
    path: CString,
    st: libc::stat,
}

impl Exe {
    /// Whether the name is still the checked file (not a symlink, same
    /// device, inode and ctime). Linux asks the held folder; macOS asks the
    /// whole path, as `execve` will resolve it, with no symlink anywhere on
    /// it (EINVAL on a macOS without that flag refuses).
    fn still_named(&self) -> bool {
        #[cfg(test)]
        hook::at(hook::Stage::Recheck);
        // SAFETY: an all-zero stat is a valid out-parameter value.
        let mut now: libc::stat = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "linux")]
        // SAFETY: open folder fd, NUL-terminated name, writable `now`.
        let rc = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                &mut now,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: NUL-terminated absolute path, writable `now`.
        let rc = unsafe {
            libc::fstatat(
                libc::AT_FDCWD,
                self.path.as_ptr(),
                &mut now,
                AT_SYMLINK_NOFOLLOW_ANY,
            )
        };
        rc == 0
            && (now.st_dev, now.st_ino, now.st_ctime, now.st_ctime_nsec)
                == (
                    self.st.st_dev,
                    self.st.st_ino,
                    self.st.st_ctime,
                    self.st.st_ctime_nsec,
                )
    }
}

/// A checked executable: a native one, or a script with its body, read once.
enum Opened {
    Native(Exe),
    Script(Exe, Vec<u8>),
}

/// The bytes every script decision uses, read in one pass from offset 0:
/// the first `SHEBANG_MAX` bytes, and when they start with `#!` the rest of
/// the body, refused past `SCRIPT_MAX`. `None` for a native file. Nothing
/// reads the file again: the line compared with the frame, the argv and the
/// memfd copy all come from this buffer.
fn read_script(fd: &OwnedFd) -> Result<Option<Vec<u8>>, u8> {
    read_script_with(|buf, at| read_at(fd, buf, at))
}

/// `read_script` over `read(buf, offset)`. Only a read of 0 bytes is the
/// end: a short read of the first bytes is followed by more reads.
fn read_script_with(
    mut read: impl FnMut(&mut [u8], usize) -> Result<usize, i32>,
) -> Result<Option<Vec<u8>>, u8> {
    let mut first = [0u8; SHEBANG_MAX];
    let mut n = 0;
    while n < SHEBANG_MAX {
        let got = read(&mut first[n..], n).map_err(|_| RELAY_TARGET)?;
        if got == 0 {
            break;
        }
        n += got;
    }
    if !first[..n].starts_with(b"#!") {
        return Ok(None);
    }
    let mut body = vec![0u8; SCRIPT_MAX + 1];
    body[..n].copy_from_slice(&first[..n]);
    let mut len = n;
    while len < body.len() {
        let n = read(&mut body[len..], len).map_err(|_| RELAY_TARGET)?;
        if n == 0 {
            break;
        }
        len += n;
    }
    if len > SCRIPT_MAX {
        return Err(RELAY_TARGET);
    }
    body.truncate(len);
    Ok(Some(body))
}

/// One `pread`; a signal never interrupts it (no handler is installed).
fn read_at(fd: &OwnedFd, buf: &mut [u8], at: usize) -> Result<usize, i32> {
    let at = libc::off_t::try_from(at).map_err(|_| libc::EINVAL)?;
    // SAFETY: `buf` is writable for its length; `fd` is open for reading.
    let n = unsafe { libc::pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), at) };
    usize::try_from(n).map_err(|_| errno())
}

/// The script rule, on the body `read_script` read once:
/// its whole `#!` line must be the line the helper resolved, the kernel must
/// let the user execute the file (`may_execute`), and the interpreter must
/// pass the same checks, be a native executable (no nested `#!`) and not be
/// `/usr/bin/env`. The body goes into a sealed memfd; then the script's
/// descriptor must still be the file `checked` describes (same identity,
/// owner, mode and status change time). The interpreter's descriptor runs
/// with argv `[line interpreter, line argument, /proc/self/fd/N, argv[1..]]`,
/// the order the kernel's script loader uses.
///
/// macOS: the target is the helper's private copy of the script
/// (`exec_path::ScriptCopies`, made from the descriptor the helper checked:
/// the helper refused a `noexec` mount, asked faccessat(X_OK, AT_EACCESS) on
/// the original's path and compared its stat after copying): it must be the
/// user's and exactly 0600, and the interpreter gets its path in place of
/// `/proc/self/fd/N`. Nothing stays open across exec.
fn script(
    script: &Exe,
    body: &[u8],
    frame: &ExecFrame,
    executable: &[u8],
    argv: &[&[u8]],
) -> Result<(Exe, Option<OwnedFd>, Vec<CString>), u8> {
    let Head::Script(line) = head(&body[..body.len().min(SHEBANG_MAX)]) else {
        return Err(RELAY_TARGET);
    };
    let interpreter = frame
        .interpreter
        .as_ref()
        .filter(|i| i.line == line.line && i.path != b"/usr/bin/env")
        .ok_or(RELAY_TARGET)?;
    #[cfg(target_os = "linux")]
    {
        let _ = executable;
        let (fd, checked) = (&script.fd, &script.st);
        if !may_execute(fd) {
            return Err(RELAY_TARGET);
        }
        let Opened::Native(interpreter_exe) = open_target(&interpreter.path, interpreter.pin)?
        else {
            return Err(RELAY_TARGET);
        };
        let copy = sealed_copy(body, memfd_create, write_fd)?;
        if !unchanged(checked, &stat(fd)?) {
            return Err(RELAY_TARGET);
        }
        let name = format!("/proc/self/fd/{}", copy.as_raw_fd()).into_bytes();
        let argv = c_strings(&script_argv(line, name, argv))?;
        Ok((interpreter_exe, Some(copy), argv))
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: getuid cannot fail.
        let me = unsafe { libc::getuid() };
        // Fails without it: test_script_copy_must_be_private (0644 copy).
        if script.st.st_uid != me || script.st.st_mode & 0o7777 != 0o600 {
            return Err(RELAY_TARGET);
        }
        let Opened::Native(interpreter_exe) = open_target(&interpreter.path, interpreter.pin)?
        else {
            return Err(RELAY_TARGET);
        };
        let argv = c_strings(&script_argv(line, executable.to_vec(), argv))?;
        Ok((interpreter_exe, None, argv))
    }
}

#[cfg(target_os = "linux")]
/// The kernel's own answer whether this user may execute the script's
/// file: permission bits, ACL and a `noexec` mount, as `execve` would judge
/// a native file. Asked through `/proc/self/fd/N`, so it is the checked
/// inode on its own mount, with the faccessat2 system call itself (a C
/// library may answer AT_EACCESS from the mode bits). Before Linux 5.8
/// (ENOSYS) the answer is `may_execute_old`; any other error refuses.
fn may_execute(fd: &OwnedFd) -> bool {
    let Ok(name) = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
        return false;
    };
    execute_verdict(|| faccessat2(&name), || may_execute_old(&name))
}

#[cfg(target_os = "linux")]
/// `new` answers; only its ENOSYS asks `old`, once. Any other error refuses.
fn execute_verdict(new: impl FnOnce() -> Result<(), i32>, old: impl FnOnce() -> bool) -> bool {
    match new() {
        Ok(()) => true,
        Err(libc::ENOSYS) => old(),
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn faccessat2(name: &CString) -> Result<(), i32> {
    // SAFETY: `name` is NUL-terminated; no pointer is written.
    let r = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            name.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    if r == 0 { Ok(()) } else { Err(errno()) }
}

#[cfg(target_os = "linux")]
/// Without faccessat2 (before Linux 5.8): the three-argument faccessat
/// system call, which the kernel judges (bits, ACL, `noexec` mount) for the
/// real ids. The relay is never set-uid, so they are its effective ids; were
/// it set-uid, the real ids would be the stricter answer.
fn may_execute_old(name: &CString) -> bool {
    // SAFETY: `name` is NUL-terminated; no pointer is written.
    unsafe {
        libc::syscall(
            libc::SYS_faccessat,
            libc::AT_FDCWD,
            name.as_ptr(),
            libc::X_OK,
        ) == 0
    }
}

#[cfg(target_os = "linux")]
/// Whether `now` is still the file `before` describes: a write, chmod,
/// chown or ACL change moves the status change time. A rewrite within one
/// timestamp tick keeps the ctime and is not caught; only trusted parties
/// (the owner, root, a pinned group) can write the file.
fn unchanged(before: &libc::stat, now: &libc::stat) -> bool {
    let key = |s: &libc::stat| {
        (
            s.st_dev,
            s.st_ino,
            s.st_mode,
            s.st_uid,
            s.st_gid,
            s.st_ctime,
            s.st_ctime_nsec,
        )
    };
    key(before) == key(now)
}

fn script_argv<'a>(line: Shebang<'a>, script: Vec<u8>, argv: &[&'a [u8]]) -> Vec<Vec<u8>> {
    let mut out = vec![line.interpreter.to_vec()];
    out.extend(line.arg.map(<[u8]>::to_vec));
    out.push(script);
    // parse_relay_args refuses an empty argv; argv[0] is the script's name.
    out.extend(argv.iter().skip(1).map(|w| w.to_vec()));
    out
}

#[cfg(target_os = "linux")]
/// `body` in a memfd from `create` (through `memfd`), written with `write`
/// and sealed with `SEALS`.
fn sealed_copy(
    body: &[u8],
    create: impl FnMut(libc::c_uint) -> Result<OwnedFd, i32>,
    mut write: impl FnMut(&OwnedFd, &[u8]) -> isize,
) -> Result<OwnedFd, u8> {
    let copy = memfd(create).map_err(|_| RELAY_EXEC)?;
    let mut rest = body;
    while !rest.is_empty() {
        // A write that takes nothing would loop forever.
        let n = usize::try_from(write(&copy, rest))
            .ok()
            .filter(|&n| n > 0)
            .ok_or(RELAY_EXEC)?;
        rest = &rest[n..];
    }
    // SAFETY: F_ADD_SEALS only changes the memfd's seals.
    if unsafe { libc::fcntl(copy.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err(RELAY_EXEC);
    }
    Ok(copy)
}

#[cfg(target_os = "linux")]
fn write_fd(fd: &OwnedFd, bytes: &[u8]) -> isize {
    // SAFETY: `bytes` is readable for its length; `fd` is open for writing.
    unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) }
}

#[cfg(target_os = "linux")]
/// A close-on-exec, sealable memfd that can never be executed
/// (`MFD_NOEXEC_SEAL`, Linux 6.3). Before 6.3 the kernel does not know that
/// flag and answers EINVAL: then once more without it. Any other error
/// (EMFILE, ENOMEM, EACCES) stays an error.
fn memfd(mut create: impl FnMut(libc::c_uint) -> Result<OwnedFd, i32>) -> Result<OwnedFd, i32> {
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    match create(base | libc::MFD_NOEXEC_SEAL) {
        Err(libc::EINVAL) => create(base),
        other => other,
    }
}

#[cfg(target_os = "linux")]
fn memfd_create(flags: libc::c_uint) -> Result<OwnedFd, i32> {
    // SAFETY: the name is NUL-terminated.
    let raw = unsafe { libc::memfd_create(c"bingsu-script".as_ptr(), flags) };
    if raw < 0 {
        return Err(errno());
    }
    // SAFETY: a successful memfd_create returns a descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn c_strings<W: AsRef<[u8]>>(words: &[W]) -> Result<Vec<CString>, u8> {
    words
        .iter()
        .map(|w| CString::new(w.as_ref()).map_err(|_| RELAY_INPUT))
        .collect()
}

/// macOS: whether `fd`'s mount enforces ownership, `None` (undecidable) when
/// fstatfs fails or the mount is not local (a network file system's
/// executable is refused).
#[cfg(target_os = "macos")]
fn local_ownership(fd: &OwnedFd) -> Option<bool> {
    // SAFETY: an all-zero statfs is a valid out-parameter value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // No test: fstatfs on a descriptor the relay just opened cannot be made
    // to fail from a test; `None` refuses (fail closed).
    // SAFETY: `fd` is open and `fs` is writable.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut fs) } != 0 {
        return None;
    }
    mount_ownership(fs.f_flags)
}

/// macOS mount flags to ownership, by the helper's own rules: `None` unless
/// local (fails without it: mount_flags_decide_ownership and
/// test_macos_target_on_a_volume_ignoring_owners_refused).
#[cfg(target_os = "macos")]
fn mount_ownership(flags: u32) -> Option<bool> {
    use bingsu_core::fs_trust::{macos_fs_is_local, macos_ownership_enforced};
    macos_fs_is_local(flags).then_some(macos_ownership_enforced(flags))
}

/// macOS: `fstatat(dir, name)` without following a symlink.
#[cfg(target_os = "macos")]
fn stat_at(dir: &OwnedFd, name: &CString) -> Result<libc::stat, u8> {
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: open folder fd, NUL-terminated name, writable `st`.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(RELAY_TARGET);
    }
    Ok(st)
}

fn stat(fd: &OwnedFd) -> Result<libc::stat, u8> {
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open and `st` is writable.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(RELAY_TARGET);
    }
    Ok(st)
}

#[cfg(target_os = "linux")]
/// The checked file for reading, through its own descriptor: opening
/// `/proc/self/fd/N` reaches the inode `N` holds, never a name someone may
/// have swapped since.
fn reopen(path_fd: &OwnedFd) -> Result<OwnedFd, i32> {
    let name = format!("/proc/self/fd/{}", path_fd.as_raw_fd());
    let name = CString::new(name).map_err(|_| libc::EINVAL)?;
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: `name` is NUL-terminated; no O_CREAT.
    let raw = unsafe { libc::open(name.as_ptr(), flags) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: a successful open returns a descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(target_os = "linux")]
/// A failed reopen that still lets the `O_PATH` descriptor run as a native
/// executable (`Some`): EACCES (execute-only file) and no `/proc` (ENOENT),
/// as the close-on-exec fallback treats a missing listing. Anything else
/// refuses (`None`).
fn native_only(errno: i32) -> Option<()> {
    matches!(errno, libc::EACCES | libc::ENOENT).then_some(())
}

/// Linux: whether the opened target is known to carry no file capabilities,
/// by the helper's rule (`sys::capability_free`): only ENODATA and EOPNOTSUPP
/// mean none; an attribute of any length or another answer refuses. A
/// path-only descriptor asks through `/proc/self/fd/N`.
#[cfg(target_os = "linux")]
fn capability_free(fd: &OwnedFd) -> bool {
    let name = c"security.capability";
    // SAFETY: `fd` is open; size 0 asks only for the length.
    let mut n = unsafe { libc::fgetxattr(fd.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
        let Ok(p) = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
            return false;
        };
        // SAFETY: names are NUL-terminated; size 0 asks only for the length.
        n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    }
    capability_answer(n, std::io::Error::last_os_error().raw_os_error())
}

/// The helper's mapping (`sys::capability_answer`), kept here so the relay
/// links nothing of the helper; `test_relay_capability_rule_is_the_helpers`
/// holds the two equal.
#[cfg(target_os = "linux")]
fn capability_answer(n: libc::ssize_t, errno: Option<i32>) -> bool {
    n < 0 && matches!(errno, Some(libc::ENODATA | libc::EOPNOTSUPP))
}

/// Only root or the user may change the file. Group write passes only with
/// a pin, and a pin must name this file unchanged: same device, inode,
/// group, mode and status change time as when the helper's group check
/// cleared it (rewriting, chmod, chown and ACL changes move the ctime).
/// `ownership`: whether the file's mount enforces ownership (Linux file
/// systems do; macOS asks `local_ownership`).
fn allowed(st: &libc::stat, pin: Option<ExecPin>, ownership: Option<bool>) -> Result<bool, u8> {
    // No setuid or setgid target, on any system (the helper refuses
    // them too; this holds for a bit set after its check). 이것을 실패시키는
    // 것: 이 조건을 지우는 것, 두 비트 가운데 하나만 보는 것
    // (test_relay_refuses_set_id_targets, macOS test_set_id_targets_are_refused).
    if st.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0 {
        return Ok(false);
    }
    let facts = Facts {
        #[cfg(target_os = "linux")]
        dev: st.st_dev,
        // The helper's facts take the same sign-extending cast (sys::fd_facts).
        #[cfg(target_os = "macos")]
        dev: st.st_dev as u64,
        ino: st.st_ino,
        uid: st.st_uid,
        gid: st.st_gid,
        #[cfg(target_os = "linux")]
        mode: st.st_mode,
        #[cfg(target_os = "macos")]
        mode: u32::from(st.st_mode),
        // The ACL is not read here: the helper read it before it made the
        // pin (an extended ACL under group write is undecided there and gets
        // no pin), and after that only the file's owner (root or the user,
        // checked below) or a holder of CAP_FOWNER can change it, both
        // trusted (on macOS only the owner or root).
        acl: AclFacts::None,
        ownership,
    };
    let ctime = (
        st.st_ctime,
        u32::try_from(st.st_ctime_nsec).map_err(|_| RELAY_TARGET)?,
    );
    let cleared = match pin {
        Some(p) if !p.matches(&facts, ctime) => return Ok(false),
        Some(p) => vec![p.group],
        None => Vec::new(),
    };
    // SAFETY: getuid cannot fail.
    let me = unsafe { libc::getuid() };
    Ok(entry_verdict(&facts, me, false, &mut PinnedGroupWrite(&cleared)) == Verdict::Safe)
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

/// Where a test may act inside `exec`, on either platform.
#[cfg(test)]
mod hook {
    /// Before the name check's fstatat, or after the name and clock checks,
    /// right before the exec.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Stage {
        Recheck,
        BeforeExec,
    }
    type Hook = Option<Box<dyn FnMut(Stage)>>;
    thread_local! {
        pub(super) static HOOK: std::cell::RefCell<Hook> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn at(stage: Stage) {
        HOOK.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(stage);
            }
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

/// macOS relay runs: the test binary is the relay (`relay_child`) and, for
/// the checks that need to see the target, the target too (`probe_child`).
#[cfg(all(test, target_os = "macos"))]
mod macos_tests;
