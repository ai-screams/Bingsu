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
    // the relay refuses (fail closed).
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
    /// Linux runs the name in the folder the walk held; macOS runs the
    /// canonical path, which only root, the user or a cleared group can
    /// change (an OS limit on macOS).
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
mod tests {
    use super::*;
    use bingsu_core::fs_trust::GroupPin;
    use bingsu_core::handoff::{Cwd, ExecFrame, Origin, Permit, relay_args, relay_input};
    use bingsu_core::snapshot::Clock;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    const SECOND: i64 = 1_000_000_000;

    use super::hook::{HOOK, Stage};
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
        pinned_at(clock, origin, t, environment, None)
    }

    fn pinned_at(
        clock: Clock,
        origin: Origin,
        t: Times,
        environment: &[u8],
        pin: Option<ExecPin>,
    ) -> (Permit, Vec<u8>) {
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
            pin,
            interpreter: None,
            cwd: b"/".to_vec(),
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

    fn pinned(pin: Option<ExecPin>) -> Vec<u8> {
        let clock = crate::prompt_io::observe_clock().unwrap();
        pinned_at(clock, Origin::Config, LIVE, b"", pin).1
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
        spawn_relay_with(input, args, relay_env, Spawn::default())
    }

    /// How `spawn_relay_with` starts the relay beyond its input and argv.
    #[derive(Default)]
    struct Spawn {
        /// Run as this user (root only).
        uid: Option<u32>,
        /// Start under a filter that answers PR_SET_NO_NEW_PRIVS with EPERM.
        deny_nnp: bool,
        /// fd 2 of the relay (its status pipe); the test's stderr otherwise.
        status: Option<OwnedFd>,
        /// Start the relay with fd 2 closed.
        close_stderr: bool,
    }

    /// `spawn_relay`, as the user `uid` when given (root only).
    fn spawn_relay_with(
        input: &[u8],
        args: &[Vec<u8>],
        relay_env: &[(&str, &Path)],
        how: Spawn,
    ) -> Child {
        let Spawn {
            uid,
            deny_nnp,
            status,
            close_stderr,
        } = how;
        // With `deny_nnp` the relay starts under a filter that answers
        // prctl(PR_SET_NO_NEW_PRIVS) with EPERM (installing it needs the
        // flag first). Built before the fork: the child may not allocate.
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |k, jt, jf| libc::sock_filter {
            code: 0x15,
            jt,
            jf,
            k,
        };
        let deny = [
            stmt(0x20, 0),
            jump(libc::SYS_prctl as u32, 0, 3),
            stmt(0x20, 16),
            jump(libc::PR_SET_NO_NEW_PRIVS as u32, 0, 1),
            stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
            stmt(0x06, libc::SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: deny.len() as u16,
            filter: deny.as_ptr().cast_mut(),
        };
        let program = std::ptr::addr_of!(program) as usize;
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
        .stderr(status.map_or_else(Stdio::inherit, Stdio::from));
        for (k, v) in relay_env {
            cmd.env(k, v);
        }
        if let Some(uid) = uid {
            cmd.uid(uid).gid(uid);
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
            if close_stderr {
                // SAFETY: closes the child's own fd 2.
                unsafe { libc::close(2) };
            }
            if deny_nnp {
                // SAFETY: plain prctl with integer arguments.
                if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: `program` points at the filter above, alive until spawn returns.
                let rc = unsafe {
                    libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, program)
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
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
        no_new_privs: String,
        cwd: PathBuf,
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
            // A script target prints its script after the echo.
            child.stdout = Some(stdout);
            Ok(child)
        } else {
            Err(child.wait().unwrap().code().unwrap_or(-1))
        }
    }

    /// Ends a running target by closing its stdin; what it prints after
    /// that (a script target prints its script) is drained so it never
    /// blocks on a full pipe.
    fn finish(mut child: Child) {
        drop(child.stdin.take());
        if let Some(mut out) = child.stdout.take() {
            out.read_to_end(&mut Vec::new()).unwrap();
        }
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
            no_new_privs: field("NoNewPrivs:"),
            cwd: std::fs::read_link(proc.join("cwd")).unwrap(),
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

    /// Stands for the relay's own pid in a word of its argv: `/proc/self` is
    /// a symlink, which the relay refuses.
    const OWN_PID: &[u8] = b"@relay-pid@";

    /// The relay process: reads its argv from fd 4 and runs the relay.
    #[test]
    #[ignore = "child: one relay run"]
    fn relay_child() {
        let words = read_all(4);
        // SAFETY: fd 4 is this child's argv pipe, read to the end above.
        unsafe { libc::close(4) };
        let pid = std::process::id().to_string();
        let args: Vec<OsString> = words
            .strip_suffix(b"\0")
            .unwrap()
            .split(|&b| b == 0)
            .map(|w| {
                match w
                    .strip_prefix(b"/proc/")
                    .and_then(|r| r.strip_prefix(OWN_PID))
                {
                    Some(rest) => OsString::from_vec([b"/proc/", pid.as_bytes(), rest].concat()),
                    None => OsString::from_vec(w.to_vec()),
                }
            })
            .collect();
        let code = relay(&args);
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(i32::from(code)) }
    }

    // 마감이 지난 permit으로는 대상을 실행하지 않는다. 이것을 실패시키는 것: prepare의 새 시계 확인(`frame.allows`)을
    // 지우는 것.
    #[test]
    fn test_relay_refuses_after_deadline() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let t = Times { trust: -1, ..LIVE };
        assert!(matches!(
            relay_cat(Origin::Config, t, b""),
            Outcome::Refused(c) if c == i32::from(RELAY_EXPIRED)
        ));
    }

    // 양성 대조: 두 마감이 1초 남은 같은 입력은 대상을 실행한다.
    #[test]
    fn test_relay_runs_before_deadline() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.exe, cat());
    }

    // 이것을 실패시키는 것: ExecFrame::allows에서 `now < run_deadline`을 지우는 것.
    #[test]
    fn test_relay_config_refuses_after_e() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let t = Times { trust: -1, ..LIVE };
        ran(relay_cat(Origin::Builtin, t, b""));
    }

    // 대상은 fd 0–2만 받는다. 이것을 실패시키는 것: prepare의 close_range(CLOSE_RANGE_CLOEXEC)를 지우는 것
    // (중계가 물려받은 fd 5가 대상에 남는다).
    #[test]
    fn test_relay_target_fds() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.fds, [0, 1, 2]);
    }

    /// A pipe for the relay's fd 2: (supervisor's read end, relay's write end).
    fn status_pipe() -> (OwnedFd, OwnedFd) {
        pipe()
    }

    /// Everything in the status pipe once every writer is gone.
    fn status_bytes(read: OwnedFd) -> Vec<u8> {
        read_all(read.as_raw_fd())
    }

    // 감독이 exec 성공과 중계 거부를 대상 종료 코드와 따로 안다. 이것을 실패시키는 것: relay()의
    // 상태 바이트 쓰기를 지우는 것(거부가 빈 EOF, 곧 "실행됨"으로 보임).
    #[test]
    fn test_relay_writes_refusal_to_status() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (read, write) = status_pipe();
        let (_, bytes) = input(Origin::Config, Times { trust: -1, ..LIVE }, b"");
        let got = outcome(spawn_relay_with(
            &bytes,
            &args(&cat(), &[b"cat"]),
            &[],
            Spawn {
                status: Some(write),
                ..Spawn::default()
            },
        ));
        assert!(refused_with(&got, RELAY_EXPIRED), "{got:?}");
        assert_eq!(status_bytes(read), [RELAY_EXPIRED]);
    }

    // 이것을 실패시키는 것: take_status가 fd 2에 /dev/null을 놓지 않는 것(대상 fd 2가 상태 파이프라 EOF가
    // 대상 종료까지 늦어짐).
    #[test]
    fn test_relay_status_ends_at_exec() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (read, write) = status_pipe();
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        let child = echo(spawn_relay_with(
            &bytes,
            &args(&cat(), &[b"cat"]),
            &[],
            Spawn {
                status: Some(write),
                ..Spawn::default()
            },
        ))
        .unwrap();
        // The target runs: the pipe already ended, with no byte.
        // SAFETY: flag change on the test's own read end.
        unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        let mut b = [0u8; 1];
        // SAFETY: `b` is writable; the read end is non-blocking.
        let n = unsafe { libc::read(read.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        let fd2 = std::fs::read_link(format!("/proc/{}/fd/2", child.id())).unwrap();
        finish(child);
        assert_eq!(n, 0, "end of file while the target still runs");
        assert_eq!(fd2, Path::new("/dev/null"));
    }

    // 수용 조건: fd 2 없이 떠도 대상은 fd 2에 /dev/null을 받는다(memfd나 열린 파일이 2를 받지
    // 않음). 이 성질은 Rust 런타임이 main 전에 닫힌 0–2에 /dev/null을 여는 데서 온다(take_status의 dup2를
    // 지워도 통과함을 확인했다). 이것을 실패시키는 것: 그 정리를 하지 않는 런타임·대상으로 중계를 빌드하는 것.
    #[test]
    fn test_relay_without_fd2_gives_target_dev_null() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        let child = echo(spawn_relay_with(
            &bytes,
            &args(&cat(), &[b"cat"]),
            &[],
            Spawn {
                close_stderr: true,
                ..Spawn::default()
            },
        ))
        .unwrap();
        let fd2 = std::fs::read_link(format!("/proc/{}/fd/2", child.id()));
        finish(child);
        assert_eq!(fd2.unwrap(), Path::new("/dev/null"));
    }

    // 작업 폴더는 중계가 exec 직전에 들어간다(감독은 "/"에서 생성). 이것을 실패시키는 것: prepare의 chdir를
    // 지우는 것(대상이 중계의 "/"에 남음), 없는 폴더의 chdir 실패를 무시하는 것.
    #[test]
    fn test_relay_enters_the_frame_folder() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("cwd")).unwrap();
        let clock = crate::prompt_io::observe_clock().unwrap();
        let (permit, _) = input_at(clock, Origin::Config, LIVE, b"");
        let mut frame = read_relay_input(&input_at(clock, Origin::Config, LIVE, b"").1, INPUT_CAP)
            .unwrap()
            .1;
        frame.cwd = dir.as_os_str().as_bytes().to_vec();
        let bytes = relay_input(permit, &frame, INPUT_CAP).unwrap();
        let seen = ran(outcome(spawn_relay(&bytes, &args(&cat(), &[b"cat"]), &[])));
        assert_eq!(seen.cwd, dir);
        frame.cwd = dir.join("missing").into_os_string().into_vec();
        let bytes = relay_input(permit, &frame, INPUT_CAP).unwrap();
        let got = outcome(spawn_relay(&bytes, &args(&cat(), &[b"cat"]), &[]));
        assert!(refused_with(&got, RELAY_EXEC), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 대상은 no_new_privs로 돈다. 이것을 실패시키는 것: prepare의 PR_SET_NO_NEW_PRIVS를 지우는 것(대상의
    // NoNewPrivs가 0).
    #[test]
    fn test_relay_target_has_no_new_privs() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let own = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(
            own.lines().any(|l| l == "NoNewPrivs:\t0"),
            "the test process must not have the flag already"
        );
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.no_new_privs, "1");
    }

    // no_new_privs 플래그를 걸 수 없으면 대상을 실행하지 않는다. 이것을 실패시키는 것: prepare에서 prctl의
    // 실패 분기(`!= 0` → RELAY_EXEC)를 지우는 것(EPERM을 무시하고 대상이 실행됨).
    #[test]
    fn test_relay_refuses_without_no_new_privs() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        let got = outcome(spawn_relay_with(
            &bytes,
            &args(&cat(), &[b"cat"]),
            &[],
            Spawn {
                deny_nnp: true,
                ..Spawn::default()
            },
        ));
        assert!(refused_with(&got, RELAY_EXEC), "{got:?}");
    }

    // setuid·setgid 비트가 있는 대상은 거부한다. 양성 대조: 같은 사본 0755는 돈다. 이것을 실패시키는
    // 것: allowed의 set-id 조건을 지우는 것, 또는 두 비트 가운데 하나만 보는 것.
    #[test]
    fn test_relay_refuses_set_id_targets() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("set-id")).unwrap();
        for (mode, refuse) in [(0o755, false), (0o4755, true), (0o2755, true)] {
            let exe = dir.join(format!("cat-{mode:o}"));
            cat_copy(&exe, mode);
            assert_eq!(pin_of(&exe).group.mode & 0o7777, mode, "{mode:o}");
            assert_eq!(refused(&exe, None), refuse, "{mode:o}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What the helper's lookup gives for `name` in `dir`: every
    /// target that would run carries its pin.
    fn looked_up(dir: &Path, name: &[u8]) -> Option<ExecPin> {
        crate::commands::exec_path::lookup(
            name,
            &[dir.to_path_buf()],
            &[],
            crate::commands::sys::current_uid(),
            &mut bingsu_core::fs_trust::RefuseGroupWrite,
        )
        .unwrap()
        .pin
    }

    // 조회한 뒤 대상이 바뀌면(이름 위로 다른 실행 파일을 옮김, chmod) relay가 조회의 pin으로 거부한다. 양성
    // 대조: 바뀌지 않은 대상은 실행된다. 이것을 실패시키는 것: helper가 그룹 쓰기를 비운 대상에만 pin을 주는 것.
    #[test]
    fn test_relay_refuses_a_target_changed_after_its_lookup() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("after-lookup")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("cat");
        cat_copy(&exe, 0o755);
        let pin = looked_up(&dir, b"cat");
        assert!(!refused(&exe, pin), "unchanged");
        cat_copy(&dir.join("other"), 0o755);
        std::fs::rename(dir.join("other"), &exe).unwrap();
        assert!(refused(&exe, pin), "replaced");
        let pin = looked_up(&dir, b"cat");
        assert!(!refused(&exe, pin), "looked up again");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(refused(&exe, pin), "chmod");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // root 시험: 조회한 뒤 file capability를 붙인 대상은 relay가 거부한다(relay는 capability를 읽지 않고, setcap이
    // 바꾼 ctime으로 잡는다). CI가 sudo로 --ignored로 돌린다. 이것을 실패시키는 것: helper가 그룹 쓰기를 비운
    // 대상에만 pin을 주는 것.
    #[test]
    #[ignore = "root: writing security.capability needs CAP_SETFCAP"]
    fn test_relay_refuses_capabilities_set_after_the_lookup() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        assert_eq!(crate::commands::sys::current_uid(), 0, "run as root");
        let dir = std::fs::canonicalize(fresh_dir("caps-after-lookup")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("cat");
        cat_copy(&exe, 0o755);
        let pin = looked_up(&dir, b"cat");
        assert!(!refused(&exe, pin), "unchanged");
        // Past the kernel's coarse timestamp tick, so setcap moves the ctime.
        std::thread::sleep(std::time::Duration::from_millis(50));
        crate::commands::sys::test_set_file_capability(&exe, true);
        assert!(refused(&exe, pin), "setcap");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // relay의 capability 판정은 helper와 같다. 이것을 실패시키는 것: relay의 답 매핑을 helper와 다르게 바꾸는
    // 것(다른 errno를 없음으로 봄, 길이 0을 없음으로 봄 등).
    #[test]
    fn test_relay_capability_rule_is_the_helpers() {
        for n in [-1, 0, 20] {
            for errno in [
                None,
                Some(libc::ENODATA),
                Some(libc::EOPNOTSUPP),
                Some(libc::EACCES),
                Some(libc::EIO),
                Some(libc::EBADF),
                Some(libc::ERANGE),
            ] {
                assert_eq!(
                    capability_answer(n, errno),
                    crate::commands::sys::capability_answer(n, errno),
                    "n={n} errno={errno:?}"
                );
            }
        }
    }

    // root 시험: file capability가 있는 대상은 pin 없이도 relay가 거부한다. 양성 대조: 속성을 지우면 돈다. CI가
    // sudo로 --ignored로 돌린다. 이것을 실패시키는 것: relay의 capability 확인을 지우는 것.
    #[test]
    #[ignore = "root: writing security.capability needs CAP_SETFCAP"]
    fn test_relay_refuses_a_capability_target() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        assert_eq!(crate::commands::sys::current_uid(), 0, "run as root");
        let dir = std::fs::canonicalize(fresh_dir("caps-target")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("cat");
        cat_copy(&exe, 0o755);
        crate::commands::sys::test_set_file_capability(&exe, true);
        assert!(refused(&exe, None), "capabilities");
        crate::commands::sys::test_set_file_capability(&exe, false);
        assert!(!refused(&exe, None), "removed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // root 시험: 조회와 같은 시각 tick 안에서 붙인 capability는 pin이 그대로 맞아 pin으로는 가리지 못한다. setcap 뒤
    // 그 파일의 지금 stamp로 pin을 만들어 넘기면 정확히 그 상태가 되고, relay의 capability 확인만 거부할 수 있다.
    // 이것을 실패시키는 것: relay의 capability 확인을 지우는 것.
    #[test]
    #[ignore = "root: writing security.capability needs CAP_SETFCAP"]
    fn test_relay_refuses_capabilities_set_in_the_lookups_tick() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        assert_eq!(crate::commands::sys::current_uid(), 0, "run as root");
        let dir = std::fs::canonicalize(fresh_dir("caps-same-tick")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("cat");
        cat_copy(&exe, 0o755);
        crate::commands::sys::test_set_file_capability(&exe, true);
        // The pin a lookup in the same tick would have made.
        let pin = pin_of(&exe);
        assert!(refused(&exe, Some(pin)), "setcap the pin cannot see");
        crate::commands::sys::test_set_file_capability(&exe, false);
        assert!(!refused(&exe, Some(pin_of(&exe))), "removed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 대상의 envp·argv에는 마감도 permit도 없다. 이것을 실패시키는 것: 중계가 마감이나 permit을 대상 envp·argv에
    // 넣는 것.
    #[test]
    fn test_relay_no_deadline_env() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let seen = ran(relay_cat(Origin::Config, LIVE, b"A=1\0B=2\0"));
        assert_eq!(seen.environ, b"A=1\0B=2\0");
        let seen = ran(relay_cat(Origin::Config, LIVE, b""));
        assert_eq!(seen.environ, b"");
    }

    // 이것을 실패시키는 것: allowed의 entry_verdict 확인을 지우는 것(남이 쓸 수 있는 파일 실행),
    // 프레임에 인터프리터가 없는 스크립트를 거부하지 않는 것, 첫 바이트 pread 실패를 네이티브로 보는 것
    // (/proc/<중계 pid>/mem이 RELAY_EXEC로 끝남). S_IFREG 비교는 test_relay_never_opens_a_fifo_for_reading이
    // 잡는다(지우면 FIFO를 읽기로 연다).
    #[test]
    fn test_relay_refuses_unsafe_targets() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        // The relay's /proc/<pid>/mem is a regular 0600 file of its own user
        // whose read at offset 0 fails (EIO): the shebang check cannot answer.
        let mut unreadable = b"/proc/".to_vec();
        unreadable.extend_from_slice(OWN_PID);
        unreadable.extend_from_slice(b"/mem");
        let unreadable = PathBuf::from(OsString::from_vec(unreadable));
        for exe in [&writable, &script, &fifo, &dir.join("missing"), &unreadable] {
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
    /// descriptor's flags. fd 200 sits above a soft RLIMIT_NOFILE of 64, which
    /// a walk up to the limit would miss.
    #[test]
    #[ignore = "child: changes this process's descriptor flags"]
    fn cloexec_child() {
        // SAFETY: fd 0 is open; the duplicates are not close-on-exec.
        let low = unsafe { libc::dup(0) };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::dup2(0, 200) }, 200);
        let lim = libc::rlimit {
            rlim_cur: 64,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: `lim` is initialized; lowering the soft limit leaves fd 200 open.
        let mut lowered = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } == 0;
        if !lowered {
            let hard = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 4096,
            };
            // SAFETY: as above, for a finite hard limit.
            lowered = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &hard) } == 0;
        }
        let cloexec = |fd| {
            // SAFETY: F_GETFD only reads flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            flags & libc::FD_CLOEXEC != 0
        };
        let clear = || {
            for fd in [low, 200] {
                // SAFETY: F_SETFD only changes this descriptor's flags.
                unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
            }
        };
        let marked = || cloexec(low) && cloexec(200) && ![0, 1, 2].into_iter().any(cloexec);
        let mut got = vec![lowered, !cloexec(low) && !cloexec(200)];
        for errno in [libc::ENOSYS, libc::EINVAL] {
            clear();
            got.push(cloexec_from_3(Err(errno)));
            got.push(marked());
        }
        got.push(cloexec_from_3(Err(libc::EPERM)));
        got.push(cloexec_listed(None, |_| Ok(())));
        got.push(cloexec_listed(Some(vec![5]), |_| Err(libc::EPERM)));
        got.push(cloexec_listed(Some(vec![5]), |_| Err(libc::EBADF)));
        got.push(cloexec_listed(Some(vec![0, 1, 2]), |_| Err(libc::EPERM)));
        let words: Vec<String> = got.iter().map(bool::to_string).collect();
        let line = format!("{CLOCK_TAG} {}\n", words.join(" "));
        put(
            // SAFETY: fd 1 is the parent's capture pipe; ManuallyDrop keeps it open.
            &std::mem::ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(1) }),
            line.as_bytes(),
        );
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(0) }
    }

    // 이것을 실패시키는 것: 대체 경로에서 ENOSYS나 EINVAL 분기를 지우는 것(5.11 미만 커널에서
    // 실행 불가), /proc/self/fd 열거 대신 소프트 상한까지만 도는 것(fd 200을 놓침), fcntl 오류를
    // 무시하거나 EBADF까지 거부하는 것, 열거 실패를 통과시키는 것, 0·1·2를 건드리는 것, 그 밖의
    // close_range 오류를 통과시키는 것.
    #[test]
    fn test_relay_close_range_fallback() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
            [format!(
                "{CLOCK_TAG} true true true true true true false false false true true"
            )],
            "{text}"
        );
    }

    // 이것을 실패시키는 것: open_target의 O_PATH 재시도를 지우는 것(실행 권한만 있는 파일을
    // 거부). root는 읽기 권한을 무시하므로 이 시험은 root가 아닌 사용자로 돌려야 뜻이 있다.
    #[test]
    fn test_relay_runs_execute_only_target() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
            // SAFETY: fd 0 is open; the duplicate is not close-on-exec.
            let leak = unsafe { libc::dup(0) };
            let before = crate::prompt_io::clock_reads();
            let prepared = prepare(&words);
            let mid = crate::prompt_io::clock_reads();
            // fd 3 is no longer the input pipe: closed, or reused by the
            // executable's descriptor (the lowest free number after the close).
            // SAFETY: an all-zero stat is a valid out-parameter value.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `st` is writable; a closed fd 3 answers -1.
            let closed = unsafe { libc::fstat(3, &mut st) } != 0
                || st.st_mode & libc::S_IFMT != libc::S_IFIFO;
            // SAFETY: F_GETFD only reads flags.
            let marked = unsafe { libc::fcntl(leak, libc::F_GETFD) } & libc::FD_CLOEXEC != 0;
            let code = match prepared {
                Ok(target) if target.clock_allows() => 0,
                Ok(_) => RELAY_EXPIRED,
                Err(c) => c,
            };
            let after = crate::prompt_io::clock_reads();
            let delta = |a: [u32; 4], b: [u32; 4]| {
                (0..4)
                    .map(|i| (b[i] - a[i]).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            out.push_str(&format!(
                "{CLOCK_TAG} {name} {code} {} {} {closed} {marked}\n",
                delta(before, mid),
                delta(mid, after)
            ));
            // SAFETY: `leak` is this loop's duplicate, closed once.
            unsafe { libc::close(leak) };
        }
        put(
            // SAFETY: fd 1 is the parent's capture pipe; ManuallyDrop keeps it open.
            &std::mem::ManuallyDrop::new(unsafe { OwnedFd::from_raw_fd(1) }),
            out.as_bytes(),
        );
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(0) }
    }

    // GATE-CLOCK-READS.4. 실행 단위마다 exec 전 시계 읽기는 Identity 한 번이고, prepare(fd 3 닫기,
    // 실행 파일 확인, close-on-exec)는 시계를 읽지 않으며, 실행 파일 확인이 실패한 단위는 시계를
    // 읽지 않는다(시계가 마지막). 이것을 실패시키는 것: 시계 읽기를 하나 더하거나 지우는 것, 시계
    // 확인을 prepare 안(open_target 앞이나 close-on-exec 앞)으로 옮기는 것, fd 3 close를 지우는
    // 것(close_range는 close-on-exec만 켠다), close-on-exec 처리를 지우는 것.
    #[test]
    fn test_relay_pre_exec_clock_reads() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
                format!("{CLOCK_TAG} live 0 0,0,0,0 0,0,0,1 true true"),
                format!("{CLOCK_TAG} expired {RELAY_EXPIRED} 0,0,0,0 0,0,0,1 true true"),
                format!("{CLOCK_TAG} missing {RELAY_TARGET} 0,0,0,0 0,0,0,0 true false"),
            ],
            "{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The pin of what sits at `path` now.
    fn pin_of(path: &Path) -> ExecPin {
        let file = std::fs::File::open(path).unwrap();
        // SAFETY: an all-zero stat is a valid out-parameter value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the file is open and `st` is writable.
        assert_eq!(unsafe { libc::fstat(file.as_raw_fd(), &mut st) }, 0);
        ExecPin {
            group: GroupPin {
                dev: st.st_dev,
                ino: st.st_ino,
                gid: st.st_gid,
                mode: st.st_mode,
            },
            ctime_sec: st.st_ctime,
            ctime_nsec: u32::try_from(st.st_ctime_nsec).unwrap(),
        }
    }

    /// A copy of `cat` at `path` with `mode`, and the pin of what landed there.
    fn cat_copy(path: &Path, mode: u32) -> ExecPin {
        std::fs::copy(cat(), path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        pin_of(path)
    }

    fn refused(exe: &Path, pin: Option<ExecPin>) -> bool {
        let got = outcome(spawn_relay(&pinned(pin), &args(exe, &[b"cat"]), &[]));
        matches!(got, Outcome::Refused(c) if c == i32::from(RELAY_TARGET))
    }

    // 이것을 실패시키는 것: open_target이 폴더를 한 이름씩 O_NOFOLLOW로 열지 않고 전체 경로를 한 번에 여는
    // 것(중간 symlink를 따라감), 또는 "."·".."·빈 이름 거부를 지우는 것.
    #[test]
    fn test_relay_refuses_middle_symlink() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("middle");
        let dir = std::fs::canonicalize(&dir).unwrap();
        std::fs::create_dir(dir.join("real")).unwrap();
        cat_copy(&dir.join("real/cat"), 0o755);
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        // Positive control: the canonical path runs.
        ran(outcome(spawn_relay(
            &pinned(None),
            &args(&dir.join("real/cat"), &[b"cat"]),
            &[],
        )));
        assert!(refused(&dir.join("link/cat"), None));
        let mut dotted = dir.join("real").into_os_string();
        dotted.push("/../real/cat");
        assert!(refused(Path::new(&dotted), None));
        let mut doubled = dir.join("real").into_os_string();
        doubled.push("//cat");
        assert!(refused(Path::new(&doubled), None));
        let mut dot = dir.join("real").into_os_string();
        dot.push("/./cat");
        assert!(refused(Path::new(&dot), None));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 그룹 쓰기 대상은 그 파일·그룹·mode·ctime의 pin이 있을 때만 실행된다. 이것을 실패시키는 것: allowed가
    // pin을 무시하고 그룹 쓰기를 늘 거부하는 것(양성 대조가 깨짐), pin이 있기만 하면 통과시키는 것(다른
    // ino·mode·gid pin이 실행됨), matches의 ctime 비교를 지우는 것(그 자리에서 고쳐 쓴 파일이 옛 pin으로
    // 실행됨), 그룹 쓰기 판정을 지우는 것(pin 없이 실행됨).
    #[test]
    fn test_relay_group_write_needs_matching_pin() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("pin");
        let exe = dir.join("cat");
        let pin = cat_copy(&exe, 0o775);
        ran(outcome(spawn_relay(
            &pinned(Some(pin)),
            &args(&exe, &[b"cat"]),
            &[],
        )));
        assert!(refused(&exe, None));
        let g = pin.group;
        let with = |group: GroupPin| ExecPin { group, ..pin };
        let wrong = [
            with(GroupPin {
                ino: g.ino + 1,
                ..g
            }),
            with(GroupPin {
                dev: g.dev + 1,
                ..g
            }),
            with(GroupPin {
                gid: g.gid + 1,
                ..g
            }),
            with(GroupPin {
                mode: g.mode & !0o020,
                ..g
            }),
            ExecPin {
                ctime_sec: pin.ctime_sec - 1,
                ..pin
            },
            ExecPin {
                ctime_nsec: (pin.ctime_nsec + 1) % 1_000_000_000,
                ..pin
            },
        ];
        for w in wrong {
            assert!(refused(&exe, Some(w)), "{w:?}");
        }
        // Rewriting the same inode in place moves its ctime: the old pin no
        // longer runs it, a fresh one does.
        let bytes = std::fs::read(&exe).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&exe, &bytes).unwrap();
        assert_eq!(pin_of(&exe).group, pin.group);
        assert!(refused(&exe, Some(pin)));
        ran(outcome(spawn_relay(
            &pinned(Some(pin_of(&exe))),
            &args(&exe, &[b"cat"]),
            &[],
        )));
        // A pin does not open other write.
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o777)).unwrap();
        let now = pin_of(&exe);
        assert!(refused(&exe, Some(now)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Prepares a relay run of `exe` (a copy of `true`), then puts something
    /// else at that name (fd 4: the folder, NUL, `rename` for a copy of
    /// `false` renamed over it or `symlink` for a symlink to it), then
    /// executes: the exit code says what happened.
    #[test]
    #[ignore = "child: replaces itself with the target"]
    fn swap_child() {
        let words = read_all(4);
        // SAFETY: fd 4 is this child's argument pipe, read to the end above.
        unsafe { libc::close(4) };
        let mut parts = words.split(|&b| b == 0);
        let dir = PathBuf::from(OsString::from_vec(parts.next().unwrap().to_vec()));
        let mode = parts.next().unwrap().to_vec();
        let exe = dir.join("x");
        let words: Vec<OsString> = args(&exe, &[b"x"])
            .into_iter()
            .map(OsString::from_vec)
            .collect();
        let (r, w) = pipe();
        let clock = crate::prompt_io::observe_clock().unwrap();
        let short = Times {
            trust: SECOND,
            run: 100_000_000,
            resume_shift: 0,
        };
        let times = if mode == b"late" { short } else { LIVE };
        put(&w, &pinned_at(clock, Origin::Config, times, b"", None).1);
        drop(w);
        // SAFETY: both descriptors are valid; fd 3 is free in this child.
        assert_eq!(unsafe { libc::dup2(r.as_raw_fd(), 3) }, 3);
        drop(r);
        let target = prepare(&words).unwrap();
        let link = {
            let (exe, dir) = (exe.clone(), dir.clone());
            move || {
                std::fs::remove_file(&exe).unwrap();
                std::os::unix::fs::symlink(dir.join("false"), &exe).unwrap();
            }
        };
        match mode.as_slice() {
            b"rename" => std::fs::rename(dir.join("false"), &exe).unwrap(),
            b"symlink" => link(),
            // A symlink put at the name after the name and clock checks passed.
            b"symlink-late" => HOOK.with(|h| {
                let mut link = Some(link);
                *h.borrow_mut() = Some(Box::new(move |stage| {
                    if stage == Stage::BeforeExec
                        && let Some(link) = link.take()
                    {
                        link();
                    }
                }));
            }),
            // The deadline passes while the name check runs.
            _ => HOOK.with(|h| {
                *h.borrow_mut() = Some(Box::new(|stage| {
                    if stage == Stage::Recheck {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }));
            }),
        }
        let code = target.exec();
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(100 + i32::from(code)) }
    }

    fn swapped(mode: &str) -> Option<i32> {
        let dir = std::fs::canonicalize(fresh_dir(&format!("swap-{mode}"))).unwrap();
        let copy = |from: &str, to: &str| {
            std::fs::copy(std::fs::canonicalize(from).unwrap(), dir.join(to)).unwrap();
        };
        copy("/bin/true", "x");
        copy("/bin/false", "false");
        let (r4, w4) = pipe();
        put(
            &w4,
            &[dir.as_os_str().as_bytes(), b"\0", mode.as_bytes()].concat(),
        );
        drop(w4);
        let r4 = r4.as_raw_fd();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "relay::tests::swap_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null());
        let setup = move || {
            // SAFETY: `r4` is valid in the child; dup2 clears close-on-exec on 4.
            if unsafe { libc::dup2(r4, 4) } != 4 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: dup2 is async-signal-safe.
        unsafe { cmd.pre_exec(setup) };
        let status = cmd.status().unwrap();
        // Positive control: what now sits at the name is `false` (`late`
        // leaves `true` there).
        let want = if mode == "late" { 0 } else { 1 };
        assert_eq!(
            Command::new(dir.join("x")).status().unwrap().code(),
            Some(want)
        );
        std::fs::remove_dir_all(&dir).unwrap();
        status.code()
    }

    // 중계는 이름으로 실행하되, 바로 앞에서 그 이름이 검사한 파일(장치·inode·ctime)인지 다시 본다.
    // 검사 뒤 같은 이름에 다른 파일을 넣으면 실행하지 않는다(RELAY_TARGET). 이것을 실패시키는 것: exec의
    // still_named 재확인을 지우는 것(바꿔치기한 false가 실행되어 종료 코드 1).
    #[test]
    fn test_swap_after_check_is_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        assert_eq!(swapped("rename"), Some(100 + i32::from(RELAY_TARGET)));
    }

    // 시계는 이름 재확인 다음, execveat 바로 앞에서 읽는다. 재확인(fstatat)이 오래 걸려 그 사이 마감이
    // 지나면 실행하지 않는다(RELAY_EXPIRED). 이것을 실패시키는 것: exec에서 시계 확인을 재확인 앞으로 되돌리는 것
    // (확인 뒤 지난 마감에도 true가 실행되어 종료 코드 0).
    #[test]
    fn test_deadline_passing_during_the_name_check_is_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        assert_eq!(swapped("late"), Some(100 + i32::from(RELAY_EXPIRED)));
    }

    // 재확인과 시계가 통과한 뒤 이름이 symlink로 바뀌어도 execveat의 AT_SYMLINK_NOFOLLOW가 따라가지
    // 않는다(ELOOP, RELAY_EXEC). 이것을 실패시키는 것: execveat의 AT_SYMLINK_NOFOLLOW만 지우는 것(링크를 따라
    // false가 실행됨).
    #[test]
    fn test_symlink_after_the_checks_is_not_followed() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        assert_eq!(swapped("symlink-late"), Some(100 + i32::from(RELAY_EXEC)));
    }

    // 검사 뒤 이름을 symlink로 바꾸면 따라가지 않는다. 재확인은 링크 자체를 보아 거부하고(RELAY_TARGET),
    // 재확인이 없어도 execveat의 AT_SYMLINK_NOFOLLOW가 ELOOP로 막는다(RELAY_EXEC). 이것을 실패시키는 것:
    // 재확인과 NOFOLLOW를 함께 지우는 것(링크를 따라 false가 실행됨). NOFOLLOW만 지운 변이는 위
    // test_symlink_after_the_checks_is_not_followed가 잡는다.
    #[test]
    fn test_symlink_after_check_is_not_followed() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let code = swapped("symlink");
        assert!(
            code == Some(100 + i32::from(RELAY_TARGET))
                || code == Some(100 + i32::from(RELAY_EXEC)),
            "{code:?}"
        );
    }

    // Ubuntu 사용자 전용 그룹(umask 0002) 실행 파일: 도우미 쪽 해석(SystemGroups)이 pin을 만들고 중계가
    // 그 pin으로 실행한다. 사용자 전용 기본 그룹이 있는 비root 사용자로 Linux 컨테이너에서 --ignored로
    // 돌린다. 이것을 실패시키는 것: resolve가 pin을 비우는 것(양성이 거부됨), 중계가 pin을 무시하는 것.
    #[test]
    #[ignore = "needs a user-private primary group; run in the Linux container as that user"]
    fn test_private_group_target_runs_with_pin() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        // SAFETY: umask only changes this process's file creation mask.
        unsafe { libc::umask(0o002) };
        let dir = fresh_dir("private-group");
        let exe = std::fs::canonicalize(&dir).unwrap().join("cat");
        std::fs::copy(cat(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o775)).unwrap();
        let found = crate::commands::exec_path::resolve_for_user(&exe, None).unwrap();
        assert_eq!(found.executable, exe);
        let pin = found.pin.expect("the private group is cleared");
        ran(outcome(spawn_relay(
            &pinned(Some(pin)),
            &args(&exe, &[b"cat"]),
            &[],
        )));
        assert!(refused(&exe, None));
        assert!(refused(
            &exe,
            Some(ExecPin {
                ctime_sec: pin.ctime_sec + 1,
                ..pin
            })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: native_only에서 EACCES나 ENOENT를 지우는 것(실행 전용 파일, /proc 없는 환경이
    // 거부됨), 또는 그 밖의 오류도 O_PATH 실행으로 넘기는 것.
    #[test]
    fn reopen_failures_that_still_run_native() {
        assert_eq!(native_only(libc::EACCES), Some(()));
        assert_eq!(native_only(libc::ENOENT), Some(()));
        for e in [libc::EPERM, libc::EMFILE, libc::ELOOP, libc::ENXIO] {
            assert_eq!(native_only(e), None, "{e}");
        }
    }

    // 종류를 확인하기 전에는 읽기로 열지 않는다. 막혀 있는 FIFO 쓰기 쪽은 누군가 읽기로 열면 풀린다.
    // 이것을 실패시키는 것: open_target이 마지막 이름을 O_PATH가 아니라 O_RDONLY로 먼저 여는 것.
    #[test]
    fn test_relay_never_opens_a_fifo_for_reading() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("fifo-open");
        let fifo = dir.join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o755) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        let writer = std::thread::spawn(move || {
            // SAFETY: gettid has no preconditions.
            tid_tx.send(unsafe { libc::gettid() }).unwrap();
            // Blocks in openat until a reader opens the FIFO. Called directly,
            // so the waiting system call is openat on every architecture and
            // C library (std's open may use SYS_open on x86_64 musl).
            let c = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: `c` is NUL-terminated; no O_CREAT.
            let w = unsafe {
                libc::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC)
            };
            assert!(w >= 0);
            tx.send(()).unwrap();
            // SAFETY: `w` was opened above and is closed once.
            unsafe { libc::close(w) };
        });
        // The writer must be waiting inside openat before the relay runs, or a
        // late writer would hide a relay that opened the FIFO.
        let syscall = format!("/proc/self/task/{}/syscall", tid_rx.recv().unwrap());
        let blocked = (0..400).any(|_| {
            let now = std::fs::read_to_string(&syscall).unwrap_or_default();
            let first = now.split_whitespace().next().unwrap_or("");
            if first == libc::SYS_openat.to_string() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            false
        });
        assert!(blocked, "the writer never blocked in openat");
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(refused(&fifo, None));
        let opened = rx
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_ok();
        // Release a writer still waiting; non-blocking, because a writer the
        // relay already released is gone and a blocking open would wait for
        // another one.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        writer.join().unwrap();
        drop(reader);
        assert!(!opened, "the relay opened the FIFO for reading");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The `#!` line (after `#!`) of `cat_script`.
    fn cat_line() -> Vec<u8> {
        format!("{} -", cat().display()).into_bytes()
    }

    /// The relay input for a script whose whole `#!` line is `line`, resolved
    /// by the helper to `path` (with `pin` for a group-writable interpreter).
    fn script_input(line: &[u8], path: &Path, pin: Option<ExecPin>) -> Vec<u8> {
        let clock = crate::prompt_io::observe_clock().unwrap();
        let (permit, _) = input_at(clock, Origin::Config, LIVE, b"");
        let frame = ExecFrame {
            origin: Origin::Config,
            run_deadline: clock.now.checked_add_signed(LIVE.run).unwrap(),
            environment: Vec::new(),
            pin: None,
            interpreter: Some(bingsu_core::handoff::Interpreter {
                line: line.to_vec(),
                path: path.as_os_str().as_bytes().to_vec(),
                pin,
            }),
            cwd: b"/".to_vec(),
        };
        relay_input(permit, &frame, INPUT_CAP).unwrap()
    }

    /// An executable file at `path` with `bytes`.
    fn executable(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// `#!<cat> -` and a body: `cat` reads stdin (the echo) before it prints
    /// the script it was handed, so it waits with exactly the descriptors the
    /// relay left it.
    fn cat_script(len: usize) -> Vec<u8> {
        let mut s = format!("#!{} -\n", cat().display()).into_bytes();
        while s.len() < len {
            s.extend_from_slice(b"# bingsu script body line\n");
        }
        s.truncate(len);
        s
    }

    fn script_outcome(script: &Path, input: &[u8], argv: &[&[u8]]) -> Outcome {
        outcome(spawn_relay(input, &args(script, argv), &[]))
    }

    fn refused_with(o: &Outcome, code: u8) -> bool {
        matches!(o, Outcome::Refused(c) if *c == i32::from(code))
    }

    /// The memfd number from `/proc/self/fd/N` in a script target's argv.
    fn copy_fd(cmdline: &[u8]) -> i32 {
        let words: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
        let word = std::str::from_utf8(words[2]).unwrap();
        word.strip_prefix("/proc/self/fd/")
            .unwrap()
            .parse()
            .unwrap()
    }

    // 실행 중인 대상의 memfd에 쓰기·늘이기·줄이기가 막히고 봉인 집합이 정확히 SEALS(6.3 이상이면 +
    // F_SEAL_EXEC)이며, 대상이 읽는 내용이 스크립트 그대로다. 이것을 실패시키는 것: SEALS에서
    // F_SEAL_WRITE(쓰기 성공)·GROW·SHRINK·SEAL 하나를 빼는 것, F_ADD_SEALS 호출을 지우는 것, 복사를
    // 빠뜨리거나 자르는 것(cat이 내보내는 내용이 다름).
    #[test]
    fn test_script_runs_through_sealed_memfd() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("sealed")).unwrap();
        let script = dir.join("s");
        let body = cat_script(300);
        executable(&script, &body, 0o755);
        let input = script_input(&cat_line(), &cat(), None);
        let child = echo(spawn_relay(&input, &args(&script, &[b"s"]), &[])).unwrap();
        let proc = PathBuf::from(format!("/proc/{}", child.id()));
        let n = copy_fd(&std::fs::read(proc.join("cmdline")).unwrap());
        let copy = std::fs::OpenOptions::new()
            .write(true)
            .open(proc.join(format!("fd/{n}")))
            .unwrap();
        // SAFETY: F_GET_SEALS only reads the memfd's seals.
        let seals = unsafe { libc::fcntl(copy.as_raw_fd(), libc::F_GET_SEALS) };
        let want = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(seals & !libc::F_SEAL_EXEC, want, "{seals:#x}");
        // F_SEAL_EXEC (0x20) is there when MFD_NOEXEC_SEAL was accepted.
        eprintln!("relay script seals {seals:#x}");
        let write = (&copy).write(b"x").unwrap_err();
        assert_eq!(write.raw_os_error(), Some(libc::EPERM));
        for len in [0, 1 << 20] {
            let e = copy.set_len(len).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{len}");
        }
        drop(copy);
        let mut child = child;
        drop(child.stdin.take());
        let mut rest = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut rest).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(rest, body);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 대상의 fd는 정확히 {0,1,2,N}이고 N이 argv의 /proc/self/fd/N이며, argv는 커널 순서(#! 줄의
    // 인터프리터, 줄 인자, 스크립트, 원래 argv[1..])다. 이것을 실패시키는 것: close-on-exec 끄기를 모든
    // fd에 하는 것(인터프리터 fd와 물려받은 fd 5가 남음), 끄기를 close_range 앞으로 옮기는 것(N이 닫혀
    // cat이 스크립트를 열지 못함), 끄기를 지우는 것, argv[0]을 버리지 않거나 줄 인자를 버리는 것.
    #[test]
    fn test_script_fd_set() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("script-fds")).unwrap();
        let script = dir.join("s");
        let body = cat_script(200);
        executable(&script, &body, 0o755);
        let line = cat();
        let input = script_input(&cat_line(), &cat(), None);
        let child = echo(spawn_relay(&input, &args(&script, &[b"s", b"-"]), &[])).unwrap();
        let proc = PathBuf::from(format!("/proc/{}", child.id()));
        let cmdline = std::fs::read(proc.join("cmdline")).unwrap();
        let n = copy_fd(&cmdline);
        let mut fds: Vec<i32> = std::fs::read_dir(proc.join("fd"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        fds.sort_unstable();
        assert_eq!(fds, [0, 1, 2, n]);
        assert!(n > 2);
        assert_eq!(std::fs::read_link(proc.join("exe")).unwrap(), cat());
        assert_eq!(
            cmdline,
            format!("{}\0-\0/proc/self/fd/{n}\0-\0", line.display()).into_bytes()
        );
        let mut child = child;
        drop(child.stdin.take());
        let mut rest = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut rest).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(rest, body);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: head의 `/usr/bin/env` 거부를 지우는 것(도우미가 거르지 못한 env 줄을 중계가
    // 그대로 실행). 감독이 env를 인터프리터로 실어 보내도 중계가 RELAY_TARGET으로 거부한다.
    #[test]
    fn test_env_shebang_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("env-shebang");
        let script = dir.join("s");
        executable(&script, b"#!/usr/bin/env sh\nexec cat\n", 0o755);
        let env = std::fs::canonicalize("/usr/bin/env").unwrap();
        let input = script_input(b"/usr/bin/env sh", &env, None);
        let got = script_outcome(&script, &input, &[b"s"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: script()에서 인터프리터가 Opened::Native인지 보는 검사를 지우는 것(커널이
    // close-on-exec 인터프리터 fd 위의 스크립트를 ENOENT로 막아 RELAY_EXEC로 끝남).
    #[test]
    fn test_nested_shebang_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("nested")).unwrap();
        let interpreter = dir.join("i");
        executable(&interpreter, cat_script(64).as_slice(), 0o755);
        let script = dir.join("s");
        let line = format!("#!{}\n", interpreter.display());
        executable(&script, line.as_bytes(), 0o755);
        let input = script_input(interpreter.as_os_str().as_bytes(), &interpreter, None);
        let got = script_outcome(&script, &input, &[b"s"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 양성 대조: 정확히 65,536바이트는 실행된다. 이것을 실패시키는 것: sealed_copy의 크기 검사를 지우는
    // 것(65,537바이트가 잘리거나 통째로 실행됨), 상한을 하나 줄이는 것.
    #[test]
    fn test_script_over_64k_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("64k")).unwrap();
        let script = dir.join("s");
        let input = script_input(&cat_line(), &cat(), None);
        let body = cat_script(SCRIPT_MAX);
        assert_eq!(body.len(), 65_536);
        executable(&script, &body, 0o755);
        let mut child = echo(spawn_relay(&input, &args(&script, &[b"s"]), &[])).unwrap();
        drop(child.stdin.take());
        let mut rest = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut rest).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(rest, body);
        let body = cat_script(SCRIPT_MAX + 1);
        assert_eq!(body.len(), 65_537);
        executable(&script, &body, 0o755);
        let got = script_outcome(&script, &input, &[b"s"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 중계는 자기가 읽은 #! 줄이 도우미가 해석한 인터프리터와 같을 때만, 그 인터프리터를 같은 검사와 pin으로
    // 열어 실행한다. 이것을 실패시키는 것: script()의 줄 비교를 지우는 것(프레임의 다른 인터프리터가
    // 실행됨), 프레임에 인터프리터가 없을 때 거부하지 않는 것, 인터프리터를 열 때 그 pin 대신 None을
    // 넘기는 것(양성 대조가 깨짐)이나 pin 없이 그룹 쓰기를 통과시키는 것.
    #[test]
    fn test_script_interpreter_matches_line_and_pin() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("interp")).unwrap();
        let interpreter = dir.join("cat");
        let pin = cat_copy(&interpreter, 0o775);
        let script = dir.join("s");
        executable(
            &script,
            format!("#!{} -\n", interpreter.display()).as_bytes(),
            0o755,
        );
        let line = format!("{} -", interpreter.display()).into_bytes();
        let line = line.as_slice();
        finish(
            echo(spawn_relay(
                &script_input(line, &interpreter, Some(pin)),
                &args(&script, &[b"s"]),
                &[],
            ))
            .unwrap(),
        );
        for input in [
            script_input(line, &interpreter, None),
            script_input(b"/bin/true", &interpreter, Some(pin)),
            pinned(None),
        ] {
            let got = script_outcome(&script, &input, &[b"s"]);
            assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: memfd가 EINVAL 밖의 오류(EMFILE·ENOMEM·EACCES·EPERM)에도 다시 부르는 것,
    // EINVAL에서 다시 부르지 않는 것(6.3 미만 커널에서 스크립트 실행 불가), 다시 부를 때 MFD_NOEXEC_SEAL 밖의
    // 플래그(CLOEXEC·ALLOW_SEALING)까지 빼는 것.
    #[test]
    fn memfd_retries_once_without_noexec_on_einval() {
        let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
        // Each call answers from `answers` in turn; a call past them fails the test.
        let calls = |answers: &[Result<(), i32>]| {
            let mut seen = Vec::new();
            let got = memfd(|flags| {
                seen.push(flags);
                match answers[seen.len() - 1] {
                    Ok(()) => Ok(std::fs::File::open("/dev/null").unwrap().into()),
                    Err(e) => Err(e),
                }
            });
            (got.is_ok(), seen)
        };
        let both = vec![base | libc::MFD_NOEXEC_SEAL, base];
        assert_eq!(
            calls(&[Err(libc::EINVAL), Err(libc::EMFILE)]),
            (false, both.clone())
        );
        assert_eq!(
            calls(&[Err(libc::EINVAL), Err(libc::EINVAL)]),
            (false, both.clone())
        );
        assert_eq!(calls(&[Err(libc::EINVAL), Ok(())]), (true, both));
        assert_eq!(calls(&[Ok(())]), (true, vec![base | libc::MFD_NOEXEC_SEAL]));
        for e in [libc::EMFILE, libc::ENOMEM, libc::EACCES, libc::EPERM] {
            assert_eq!(
                calls(&[Err(e)]),
                (false, vec![base | libc::MFD_NOEXEC_SEAL]),
                "{e}"
            );
        }
    }

    // 이것을 실패시키는 것: sealed_copy가 0바이트 write를 진행으로 보는 것(끝나지 않는 고리, 시험은
    // 시간 초과로 죽음)이나 음수를 받아들이는 것, 짧은 write 뒤 나머지를 쓰지 않는 것.
    #[test]
    fn sealed_copy_needs_writes_that_progress() {
        for stuck in [0, -1] {
            let got = sealed_copy(b"#!/bin/sh\n", memfd_create, |_, _| stuck);
            assert_eq!(got.err(), Some(RELAY_EXEC), "{stuck}");
        }
        let body = b"#!/bin/sh\necho one byte at a time\n";
        let copy = sealed_copy(body, memfd_create, |fd, b| write_fd(fd, &b[..1])).unwrap();
        let mut back = vec![0u8; body.len() + 1];
        let n = read_at(&copy, &mut back, 0).unwrap();
        assert_eq!(&back[..n], body);
    }

    fn open_read(path: &Path) -> Exe {
        let fd: OwnedFd = std::fs::File::open(path).unwrap().into();
        let st = stat(&fd).unwrap();
        let dir: OwnedFd = std::fs::File::open(path.parent().unwrap()).unwrap().into();
        let name = CString::new(path.file_name().unwrap().as_bytes()).unwrap();
        Exe { fd, dir, name, st }
    }

    fn script_frame(line: &[u8], path: &Path) -> ExecFrame {
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        let mut frame = read_relay_input(&bytes, INPUT_CAP).unwrap().1;
        frame.interpreter = Some(bingsu_core::handoff::Interpreter {
            line: line.to_vec(),
            path: path.as_os_str().as_bytes().to_vec(),
            pin: None,
        });
        frame
    }

    // 중계가 판정한 바이트가 곧 복사한 바이트다. 파일에는 다른 본문을 두고 script()에 버퍼를 넘긴다.
    // 이것을 실패시키는 것: script()나 sealed_copy가 파일을 다시 읽는 것(memfd에 파일 쪽 본문이 들어감),
    // 줄 비교를 버퍼 대신 파일에서 하는 것, 복사 뒤 fstat 재확인을 지우는 것(검사 뒤 고쳐 쓴 파일이 통과).
    #[test]
    fn script_uses_the_checked_buffer() {
        let dir = std::fs::canonicalize(fresh_dir("buffer")).unwrap();
        let file = dir.join("s");
        executable(
            &file,
            format!("#!{} -\n# on disk\n", cat().display()).as_bytes(),
            0o755,
        );
        let body = format!("#!{} -\n# checked\n", cat().display()).into_bytes();
        let frame = script_frame(&cat_line(), &cat());
        let exe = open_read(&file);
        let (_, copy, argv) = script(&exe, &body, &frame, b"/s", &[b"s"]).unwrap();
        let copy = copy.unwrap();
        let mut back = vec![0u8; SCRIPT_MAX];
        let n = read_at(&copy, &mut back, 0).unwrap();
        assert_eq!(&back[..n], body.as_slice());
        assert_eq!(argv[0].as_bytes(), cat().as_os_str().as_bytes());
        // The file's own line would match another frame; the buffer's decides.
        let other = format!("#!{}\n", cat().display()).into_bytes();
        assert_eq!(
            script(&exe, &other, &frame, b"/s", &[b"s"]).err(),
            Some(RELAY_TARGET)
        );
        // Rewritten after the checks (same bytes, new ctime): refused.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&file, std::fs::read(&file).unwrap()).unwrap();
        assert_ne!(stat(&exe.fd).unwrap().st_ctime_nsec, exe.st.st_ctime_nsec);
        assert_eq!(
            script(&exe, &body, &frame, b"/s", &[b"s"]).err(),
            Some(RELAY_TARGET)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 선택 인자까지 줄 전체를 비교한다. 이것을 실패시키는 것: script()가 줄 전체(line.line) 대신 인터프리터
    // 단어만 비교하는 것.
    #[test]
    fn test_script_line_compares_the_argument() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("line-arg")).unwrap();
        let script = dir.join("s");
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        for (on_disk, framed) in [
            (&b"/bin/sh -n"[..], &b"/bin/sh"[..]),
            (b"/bin/sh", b"/bin/sh -n"),
        ] {
            let mut body = b"#!".to_vec();
            body.extend_from_slice(on_disk);
            body.extend_from_slice(b"\nexec cat\n");
            executable(&script, &body, 0o755);
            let got = script_outcome(&script, &script_input(framed, &sh, None), &[b"s"]);
            assert!(refused_with(&got, RELAY_TARGET), "{on_disk:?} {got:?}");
        }
        // Positive control: the same line runs.
        executable(&script, b"#!/bin/sh\nexec cat\n", 0o755);
        finish(
            echo(spawn_relay(
                &script_input(b"/bin/sh", &sh, None),
                &args(&script, &[b"s"]),
                &[],
            ))
            .unwrap(),
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 원본 스크립트의 실행 권한은 커널이 판정한다(네이티브는 execveat가 했다). 이것을 실패시키는 것: script()의
    // may_execute 확인을 지우는 것(읽기만 되는 0644 스크립트가 실행됨).
    #[test]
    fn test_script_needs_execute_permission() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("noexec-bits")).unwrap();
        let script = dir.join("s");
        executable(&script, &cat_script(64), 0o644);
        let input = script_input(&cat_line(), &cat(), None);
        let got = script_outcome(&script, &input, &[b"s"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 다른 사용자에게 읽기만 허락한 root 소유 0744 스크립트는 그 사용자에게 실행되지 않는다(소유자 비트만 보는
    // 검사로는 통과). root로 Linux 컨테이너에서 --ignored로 돌린다(중계는 nobody로 뜬다). 시험 바이너리는
    // nobody가 실행할 수 있는 곳에 있어야 한다. 이것을 실패시키는 것: may_execute를 mode 비트의 아무 x
    // 비트 검사로 바꾸는 것, may_execute를 지우는 것.
    #[test]
    #[ignore = "root in the Linux container; the relay runs as nobody"]
    fn test_root_script_others_may_only_read() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        // SAFETY: getuid cannot fail.
        assert_eq!(unsafe { libc::getuid() }, 0, "run as root");
        let dir = std::fs::canonicalize(fresh_dir("root-0744")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = dir.join("s");
        let input = script_input(&cat_line(), &cat(), None);
        executable(&script, &cat_script(64), 0o744);
        let got = outcome(spawn_relay_with(
            &input,
            &args(&script, &[b"s"]),
            &[],
            Spawn {
                uid: Some(65_534),
                ..Spawn::default()
            },
        ));
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        // Positive control: with execute for others it runs as nobody.
        executable(&script, &cat_script(64), 0o755);
        finish(
            echo(spawn_relay_with(
                &input,
                &args(&script, &[b"s"]),
                &[],
                Spawn {
                    uid: Some(65_534),
                    ..Spawn::default()
                },
            ))
            .unwrap(),
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // noexec 마운트 위의 스크립트는 실행되지 않는다. 특권 Linux 컨테이너에서 root로 --ignored로 돌린다(tmpfs를
    // 직접 마운트한다). 이것을 실패시키는 것: may_execute를 지우거나 mode 비트만 보는 검사로 바꾸는 것.
    #[test]
    #[ignore = "privileged Linux container, root: mounts a noexec tmpfs"]
    fn test_script_on_noexec_mount_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("noexec-mount")).unwrap();
        let target = CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: all strings are NUL-terminated; no data argument.
        let mounted = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOEXEC,
                std::ptr::null(),
            )
        } == 0;
        assert!(mounted, "BLOCKED: mount needs a privileged container");
        let script = dir.join("s");
        executable(&script, &cat_script(64), 0o755);
        let input = script_input(&cat_line(), &cat(), None);
        let got = script_outcome(&script, &input, &[b"s"]);
        // SAFETY: `target` is NUL-terminated.
        unsafe { libc::umount(target.as_ptr()) };
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 인터프리터를 실은 프레임은 스크립트용이다. 이것을 실패시키는 것: prepare의 "Native인데 인터프리터가 있으면
    // 거부" 분기를 지우는 것(네이티브 cat이 실행됨, O_PATH 갈래 포함).
    #[test]
    fn test_interpreter_frame_on_native_target_refused() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("native-with-interp");
        let xonly = dir.join("cat");
        std::fs::copy(cat(), &xonly).unwrap();
        std::fs::set_permissions(&xonly, std::fs::Permissions::from_mode(0o111)).unwrap();
        let input = script_input(&cat_line(), &cat(), None);
        for exe in [cat(), xonly] {
            let got = script_outcome(&exe, &input, &[b"cat"]);
            assert!(refused_with(&got, RELAY_TARGET), "{exe:?} {got:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 정규 경로가 /usr/bin/env인 인터프리터는 중계도 거부한다(줄의 원문은 다른 이름). 이것을 실패시키는 것:
    // script()의 `i.path != b"/usr/bin/env"`를 지우는 것(env가 sh를 찾아 스크립트를 실행).
    #[test]
    fn test_relay_refuses_env_by_canonical_path() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("env-alias")).unwrap();
        let env = std::fs::canonicalize("/usr/bin/env").unwrap();
        assert_eq!(env, Path::new("/usr/bin/env"));
        std::os::unix::fs::symlink(&env, dir.join("env")).unwrap();
        let script = dir.join("s");
        let line = format!("{} sh", dir.join("env").display()).into_bytes();
        let mut body = b"#!".to_vec();
        body.extend_from_slice(&line);
        body.extend_from_slice(b"\nexec cat\n");
        executable(&script, &body, 0o755);
        let got = script_outcome(&script, &script_input(&line, &env, None), &[b"s"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 도우미 해석에서 중계 실행까지: `#!/bin/cat -`는 merged-/usr에서 `/bin -> usr/bin`을 지나므로, 중계는 줄의
    // 원문이 아니라 도우미가 푼 정규 경로를 연다. 이것을 실패시키는 것: script()가 interpreter.path 대신
    // interpreter.line을 여는 것(merged-/usr에서 중간 symlink로 거부), argv[0]에 정규 경로를 쓰는 것.
    #[test]
    fn test_resolved_script_runs() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("resolved")).unwrap();
        let script = dir.join("s");
        executable(&script, b"#!/bin/cat -\n", 0o755);
        let found = crate::commands::exec_path::resolve_for_user(&script, None).unwrap();
        let interpreter = found.interpreter.unwrap();
        assert_eq!(interpreter.line, b"/bin/cat -");
        let path = PathBuf::from(OsString::from_vec(interpreter.path.clone()));
        assert_eq!(path, cat());
        let input = script_input(&interpreter.line, &path, interpreter.pin);
        let child = echo(spawn_relay(&input, &args(&script, &[b"s"]), &[])).unwrap();
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", child.id())).unwrap();
        assert!(
            cmdline.starts_with(b"/bin/cat\0-\0/proc/self/fd/"),
            "{cmdline:?}"
        );
        finish(child);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 처음 256바이트는 0바이트 읽기만 끝으로 본다. 이것을 실패시키는 것: read_script_with가 첫 읽기 한 번의
    // 결과로 판정하는 것(1바이트 "#"만 보고 네이티브로 봄), 본문 읽기에서 짧은 읽기 뒤 멈추는 것.
    #[test]
    fn read_script_keeps_reading_short_reads() {
        let one_at_a_time = |source: &[u8]| {
            let source = source.to_vec();
            read_script_with(move |buf, at| {
                let n = source.len().saturating_sub(at).min(1).min(buf.len());
                buf[..n].copy_from_slice(&source[at..at + n]);
                Ok(n)
            })
        };
        let script = cat_script(300);
        assert_eq!(one_at_a_time(&script), Ok(Some(script)));
        assert_eq!(one_at_a_time(b"\x7fELF\x02\x01\x01"), Ok(None));
        assert_eq!(one_at_a_time(b""), Ok(None));
    }

    // 실행 권한만 있는 대상은 O_PATH fd로 열리고, 그 갈래에서도 인터프리터를 실은 프레임은 거부된다. root가 아닌
    // 사용자로 Linux 컨테이너에서 --ignored로 돌린다(root는 읽기 권한을 무시해 O_PATH 갈래를 지나지 않는다).
    // 이것을 실패시키는 것: prepare의 "Native인데 인터프리터가 있으면 거부" 분기를 지우는 것, open_target의
    // O_PATH 재시도를 지우는 것(열기 자체가 실패).
    #[test]
    fn test_execute_only_target_runs_path_only() {
        // Root reads any file, so the case needs another user (CI's Linux
        // cells; BINGSU_REQUIRE_NONROOT_TESTS=1 turns a root run into a failure).
        if crate::commands::exec_path::test_skip_as_root() {
            return;
        }
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("xonly-path");
        let exe = dir.join("cat");
        std::fs::copy(cat(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o111)).unwrap();
        let Opened::Native(opened) = open_target(exe.as_os_str().as_bytes(), None).unwrap() else {
            panic!("an execute-only file is not a script here");
        };
        // SAFETY: F_GETFL only reads the descriptor's status flags.
        let flags = unsafe { libc::fcntl(opened.fd.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_PATH, 0, "{flags:#x}");
        drop(opened);
        let got = script_outcome(&exe, &script_input(&cat_line(), &cat(), None), &[b"cat"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: execute_verdict의 ENOSYS 조건을 지우는 것(모든 오류에서 대체 호출), ENOSYS에서
    // 대체 호출을 하지 않거나 그 답을 버리는 것, 성공을 거부하는 것.
    // 이름으로 실행해도 실행 전용 `#!` 스크립트는 커널이 싣지 않는다. 이름 실행의 경로가 `/dev/fd/<폴더>/<이름>`이고
    // 그 폴더 fd가 close-on-exec라 binfmt_script가 ENOENT를 낸다(BINPRM_FLAGS_PATH_INACCESSIBLE). 그래서 줄이
    // 이름 붙인 인터프리터(검사하지 않은 `touch`)는 돌지 않고 결과는 RELAY_EXEC다. 이것을 실패시키는 것: exec 직전에
    // 폴더 fd의 FD_CLOEXEC를 끄는 것(touch가 돌아 카나리가 생기고 종료 코드가 touch의 것). 폴더를 O_CLOEXEC 없이
    // 여는 것만으로는 실패하지 않는다: prepare의 close-on-exec 단계가 3 이상 모든 fd에 다시 건다.
    #[test]
    fn test_execute_only_script_is_not_loaded() {
        // Root reads any file, so the case needs another user (CI's Linux
        // cells; BINGSU_REQUIRE_NONROOT_TESTS=1 turns a root run into a failure).
        if crate::commands::exec_path::test_skip_as_root() {
            return;
        }
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = fresh_dir("xonly-script");
        let canary = dir.join("ran");
        let exe = dir.join("tool");
        let line = format!("#!/usr/bin/touch {}\n", canary.display());
        executable(&exe, line.as_bytes(), 0o111);
        let (_, bytes) = input(Origin::Config, LIVE, b"");
        let got = script_outcome(&exe, &bytes, &[b"tool"]);
        assert!(refused_with(&got, RELAY_EXEC), "{got:?}");
        assert!(
            !canary.exists(),
            "the kernel ran the script's own interpreter"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn execute_check_falls_back_only_on_enosys() {
        let run = |new: Result<(), i32>, old: bool| {
            let mut calls = 0;
            let verdict = execute_verdict(
                || new,
                || {
                    calls += 1;
                    old
                },
            );
            (verdict, calls)
        };
        assert_eq!(run(Ok(()), false), (true, 0));
        assert_eq!(run(Err(libc::ENOSYS), true), (true, 1));
        assert_eq!(run(Err(libc::ENOSYS), false), (false, 1));
        for e in [libc::EPERM, libc::EACCES, libc::EINVAL, libc::EIO] {
            assert_eq!(run(Err(e), true), (false, 0), "{e}");
        }
    }
}

/// macOS relay runs: the test binary is the relay (`relay_child`) and, for
/// the checks that need to see the target, the target too (`probe_child`).
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::hook::{HOOK, Stage};
    use super::*;
    use bingsu_core::handoff::{Cwd, Interpreter, Origin, relay_args, relay_input};
    use std::io::Read;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const SECOND: i64 = 1_000_000_000;

    /// A pipe whose ends sit at 100 or above and are close-on-exec, so the
    /// child's dup2 onto 3 and 5 never overwrites another of them.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` is writable for two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let high = |fd: i32| {
            // SAFETY: `fd` is open; the duplicate is close-on-exec.
            let h = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) };
            assert!(h >= 100);
            // SAFETY: `fd` was returned by pipe above and is closed once.
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

    fn scratch(tag: &str) -> PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = base.join(format!("bingsu-relay-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn copy_mode(from: &Path, to: &Path, mode: u32) {
        std::fs::copy(from, to).unwrap();
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn frame_input(run_ns: i64, interpreter: Option<Interpreter>) -> Vec<u8> {
        frame_input_pinned(run_ns, interpreter, None)
    }

    fn frame_input_pinned(
        run_ns: i64,
        interpreter: Option<Interpreter>,
        pin: Option<ExecPin>,
    ) -> Vec<u8> {
        let clock = crate::prompt_io::observe_clock().unwrap();
        let permit = Permit {
            kind: clock.kind,
            // Far: the first run of a fresh copy of this binary can take
            // seconds on macOS (its code is checked on first exec).
            deadline: clock.now.checked_add_signed(60 * SECOND).unwrap(),
            boot: clock.boot,
            resume: clock.resume,
            domain: clock.domain,
        };
        let frame = ExecFrame {
            origin: Origin::Config,
            run_deadline: clock.now.checked_add_signed(run_ns).unwrap(),
            environment: Vec::new(),
            pin,
            interpreter,
            cwd: b"/".to_vec(),
        };
        relay_input(permit, &frame, INPUT_CAP).unwrap()
    }

    fn live() -> Vec<u8> {
        frame_input(60 * SECOND, None)
    }

    /// What one relay run left: its exit code, the bytes on its status pipe
    /// and the target's stdout.
    #[derive(Debug)]
    struct Run {
        code: i32,
        status: Vec<u8>,
        stdout: Vec<u8>,
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

    /// A `relay_child` hook: its mode, the path it acts on and the other one.
    type Swap<'a> = Option<(&'a str, &'a Path, &'a Path)>;

    /// The supervisor's side for one relay: fd 3 holds `input`, fd 2 the
    /// status pipe, fd 4 the `relay_child` hook and the relay argv as
    /// NUL-terminated words, fd 5 a pipe end left open without close-on-exec
    /// (an fd the relay must not pass on). SIGUSR1 is ignored and SIGUSR2
    /// blocked, which the relay must undo.
    fn run_relay(input: &[u8], exe: &Path, argv: &[&[u8]], swap: Swap<'_>) -> Run {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let words: Vec<Vec<u8>> = relay_args(exe.as_os_str().as_bytes(), Cwd::Neutral, argv)
            .unwrap()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        let (r3, w3) = pipe();
        put(&w3, input);
        drop(w3);
        let (r4, w4) = pipe();
        let (mode, target, with) = swap.unwrap_or(("", Path::new(""), Path::new("")));
        let hook = [
            mode.as_bytes(),
            target.as_os_str().as_bytes(),
            with.as_os_str().as_bytes(),
        ];
        for word in hook.into_iter().chain(words.iter().map(Vec::as_slice)) {
            put(&w4, word);
            put(&w4, b"\0");
        }
        drop(w4);
        let (status_r, status_w) = pipe();
        let (r5, _w5) = pipe();
        let (r3n, r4n, r5n) = (r3.as_raw_fd(), r4.as_raw_fd(), r5.as_raw_fd());
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "relay::macos_tests::relay_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(status_w));
        // Runs in the forked child: only async-signal-safe calls.
        let setup = move || {
            for (from, to) in [(r3n, 3), (r4n, 4), (r5n, 5)] {
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
        let mut child = cmd.spawn().unwrap();
        drop((r3, r4, r5));
        let mut stdout = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        let code = child.wait().unwrap().code().unwrap_or(-1);
        drop(cmd);
        let mut status = Vec::new();
        std::fs::File::from(status_r)
            .read_to_end(&mut status)
            .unwrap();
        Run {
            code,
            status,
            stdout,
        }
    }

    /// The relay process: reads its hook and argv from fd 4 (the relay
    /// reads no environment, so neither does this), then runs the relay.
    #[test]
    #[ignore = "child: one relay run"]
    fn relay_child() {
        let words = read_all(4);
        // SAFETY: fd 4 is this child's argument pipe, read to the end above.
        unsafe { libc::close(4) };
        let mut words: Vec<OsString> = words
            .strip_suffix(b"\0")
            .unwrap()
            .split(|&b| b == 0)
            .map(|w| OsString::from_vec(w.to_vec()))
            .collect();
        let args = words.split_off(3);
        let [mode, target, with] = <[OsString; 3]>::try_from(words).unwrap();
        let (target, with) = (PathBuf::from(target), PathBuf::from(with));
        let mode = mode.into_string().unwrap();
        if !mode.is_empty() {
            // Once: a script run checks two names.
            let mut once = Some(mode);
            HOOK.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |stage| {
                    if stage != Stage::Recheck {
                        return;
                    }
                    let Some(mode) = once.take() else { return };
                    match mode.as_str() {
                        // Another file under the checked name.
                        "rename" => std::fs::rename(&with, &target).unwrap(),
                        // The checked folder moved to `with`, a symlink in
                        // its place: the same inode through a link.
                        "folder-link" => {
                            std::fs::rename(&target, &with).unwrap();
                            std::os::unix::fs::symlink(&with, &target).unwrap();
                        }
                        // The name check takes long: the deadline passes.
                        "late" => std::thread::sleep(std::time::Duration::from_millis(400)),
                        other => panic!("{other}"),
                    }
                }));
            });
        }
        let code = relay(&args);
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(i32::from(code)) }
    }

    /// The target side: prints what it was started with on one line.
    #[test]
    #[ignore = "child: the relay's target"]
    fn probe_child() {
        let fds: Vec<i32> = open_fds().unwrap().into_iter().collect();
        // SAFETY: an all-zero sigset_t is a valid out-parameter value.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: only reads this thread's mask into `mask`.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) };
        // SAFETY: an all-zero sigaction is a valid out-parameter value.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: only reads SIGUSR1's action into `old`.
        unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
        let cwd = std::env::current_dir().unwrap();
        let argv0 = std::env::args_os().next().unwrap();
        println!(
            "SEEN fds={fds:?} mask={mask} usr1={} cwd={} argv0={}",
            old.sa_sigaction,
            cwd.display(),
            argv0.to_string_lossy()
        );
    }

    fn me_exe() -> PathBuf {
        std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
    }

    /// The probe target as `exe` (a path to this test binary or a copy).
    fn probe(exe: &Path, input: &[u8]) -> Run {
        let argv: [&[u8]; 6] = [
            b"probe-word",
            b"relay::macos_tests::probe_child",
            b"--exact",
            b"--ignored",
            b"--nocapture",
            b"-q",
        ];
        run_relay(input, exe, &argv, None)
    }

    fn seen(run: &Run) -> String {
        let out = String::from_utf8_lossy(&run.stdout);
        out.lines()
            .find_map(|l| l.strip_prefix("SEEN "))
            .unwrap_or_else(|| panic!("the target did not run: {run:?}"))
            .to_owned()
    }

    // 양성 대조와 계약: 대상은 fd {0,1,2}만, 빈 신호 마스크와 기본 처리, frame의 작업 폴더, 사용자가 쓴 argv[0]으로
    // 돈다. 상태 파이프는 exec에서 닫혀 0바이트다. 이것을 실패시키는 것: cloexec_all을 늘 참으로(fd 5와 상태
    // 파이프가 남음), reset_signals를 지우는 것.
    #[test]
    fn test_macos_relay_runs_the_target_clean() {
        let run = probe(&me_exe(), &live());
        let line = seen(&run);
        assert_eq!(run.code, 0, "{run:?}");
        assert!(run.status.is_empty(), "{run:?}");
        assert!(line.contains("fds=[0, 1, 2] "), "{line}");
        assert!(line.contains(" mask=0 usr1=0 "), "{line}");
        assert!(line.contains(" cwd=/ "), "{line}");
        assert!(line.ends_with(" argv0=probe-word"), "{line}");
    }

    // 거부하면 상태 파이프에 코드 1바이트를 쓰고 대상은 돌지 않는다. 이것을 실패시키는 것: relay의 상태 쓰기를
    // 지우는 것, prepare의 시계 확인을 지우는 것(만료 frame이 돈다).
    #[test]
    fn test_macos_relay_refuses_an_expired_frame() {
        let run = probe(&me_exe(), &frame_input(-1, None));
        assert_eq!(run.code, i32::from(RELAY_EXPIRED), "{run:?}");
        assert_eq!(run.status, [RELAY_EXPIRED]);
        assert!(!String::from_utf8_lossy(&run.stdout).contains("SEEN "));
    }

    // macOS: setuid·setgid 비트가 있는 대상은 거부한다. 양성 대조: 같은 사본 0755는 돈다. 이것을
    // 실패시키는 것: allowed의 set-id 조건을 지우는 것, 또는 두 비트 가운데 하나만 보는 것.
    #[test]
    fn test_set_id_targets_are_refused() {
        let dir = scratch("set-id");
        for (mode, code) in [(0o755, 0), (0o4755, RELAY_TARGET), (0o2755, RELAY_TARGET)] {
            let exe = dir.join(format!("probe-{mode:o}"));
            copy_mode(&me_exe(), &exe, mode);
            let run = probe(&exe, &live());
            assert_eq!(run.code, i32::from(code), "{mode:o}: {run:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // macOS: 조회한 뒤 대상이 바뀌면(이름 위로 다른 사본을 옮김, chmod) relay가 조회의 pin으로 거부한다.
    // 양성 대조: 바뀌지 않은 대상은 돈다. 이것을 실패시키는 것: helper가 그룹 쓰기를 비운 대상에만 pin을 주는 것.
    #[test]
    fn test_relay_refuses_a_target_changed_after_its_lookup() {
        let dir = scratch("after-lookup");
        let exe = dir.join("probe");
        copy_mode(&me_exe(), &exe, 0o755);
        let look = || {
            crate::commands::exec_path::lookup(
                b"probe",
                std::slice::from_ref(&dir),
                &[],
                crate::commands::sys::current_uid(),
                &mut bingsu_core::fs_trust::RefuseGroupWrite,
            )
            .unwrap()
            .pin
        };
        let run = |pin| probe(&exe, &frame_input_pinned(60 * SECOND, None, pin)).code;
        let pin = look();
        assert_eq!(run(pin), 0, "unchanged");
        copy_mode(&me_exe(), &dir.join("other"), 0o755);
        std::fs::rename(dir.join("other"), &exe).unwrap();
        assert_eq!(run(pin), i32::from(RELAY_TARGET), "replaced");
        let pin = look();
        assert_eq!(run(pin), 0, "looked up again");
        std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        assert_eq!(run(pin), i32::from(RELAY_TARGET), "chmod");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 읽을 수 없는 실행 전용 대상은 거부한다(경로 execve면 커널이 그 `#!` 줄의 인터프리터를 검사 없이
    // 띄운다). 양성 대조: 같은 사본 0711(소유자가 읽음)은 돈다. 이것을 실패시키는 것: 읽기 열기의 EACCES에서
    // O_EXEC로 다시 열어 네이티브로 실행하는 대체 경로.
    #[test]
    fn test_macos_execute_only_target_refused() {
        let dir = scratch("xonly");
        for (mode, code) in [(0o711, 0), (0o111, RELAY_TARGET)] {
            let exe = dir.join(format!("probe-{mode:o}"));
            copy_mode(&me_exe(), &exe, mode);
            let run = probe(&exe, &live());
            assert_eq!(run.code, i32::from(code), "{mode:o}: {run:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn swapped(mode: &str, input: &[u8]) -> Run {
        let dir = scratch(&format!("swap-{mode}"));
        let folder = dir.join("bin");
        std::fs::create_dir(&folder).unwrap();
        let exe = folder.join("probe");
        copy_mode(&me_exe(), &exe, 0o755);
        // The first exec of a fresh copy is slow (its code is checked): done
        // here, so the short deadline of "late" measures the name check alone.
        assert!(
            Command::new(&exe)
                .arg("--list")
                .output()
                .unwrap()
                .status
                .success()
        );
        let (target, with) = match mode {
            "rename" => {
                let other = folder.join("other");
                copy_mode(&me_exe(), &other, 0o755);
                (exe.clone(), other)
            }
            "folder-link" => (folder.clone(), dir.join("moved")),
            _ => (exe.clone(), exe.clone()),
        };
        let argv: [&[u8]; 6] = [
            b"probe-word",
            b"relay::macos_tests::probe_child",
            b"--exact",
            b"--ignored",
            b"--nocapture",
            b"-q",
        ];
        let run = run_relay(input, &exe, &argv, Some((mode, &target, &with)));
        std::fs::remove_dir_all(&dir).unwrap();
        run
    }

    // 재확인 바로 앞에 이름 자리에 다른 파일이 오면 거부한다. 이것을 실패시키는 것: still_named를 늘 참으로.
    #[test]
    fn test_macos_swap_before_the_name_check_is_refused() {
        let run = swapped("rename", &live());
        assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
    }

    // 검사한 폴더를 옮기고 그 자리에 링크를 두면 같은 inode·ctime이라도 거부한다(execve는 경로 전체를
    // 다시 해석한다). 이것을 실패시키는 것: 재확인의 AT_SYMLINK_NOFOLLOW_ANY를 AT_SYMLINK_NOFOLLOW로 바꾸는 것.
    #[test]
    fn test_macos_link_on_the_way_is_refused() {
        let run = swapped("folder-link", &live());
        assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
    }

    // 재확인이 늦어 마감이 지나면 실행하지 않는다(시계는 재확인 뒤). 이것을 실패시키는 것: exec의
    // 시계 확인을 still_named 앞으로 옮기는 것.
    #[test]
    fn test_macos_deadline_passing_during_the_name_check_is_refused() {
        let run = swapped("late", &frame_input(300_000_000, None));
        assert_eq!(run.code, i32::from(RELAY_EXPIRED), "{run:?}");
    }

    // 이름 자리의 FIFO는 열지 않는다(열면 기다리던 쓰는 쪽이 풀린다). macOS에는 쓰는 쪽이 open 안에서 기다리는지
    // 볼 /proc이 없어 200 ms를 먼저 기다린다(늦은 쓰는 쪽은 통과로 보일 수 있을 뿐 거짓 실패는 없다). 이것을
    // 실패시키는 것: open_target의 열기 전 형식 검사(stat_at)를 지우는 것.
    #[test]
    fn test_macos_relay_never_opens_a_fifo() {
        let dir = scratch("fifo");
        let fifo = dir.join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o755) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            // SAFETY: `c` is NUL-terminated; no O_CREAT. Blocks until a reader opens it.
            let w = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            assert!(w >= 0);
            tx.send(()).unwrap();
            // SAFETY: `w` was opened above and is closed once.
            unsafe { libc::close(w) };
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        let run = probe(&fifo, &live());
        let opened = rx
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_ok();
        // Release a writer still waiting, without waiting for one.
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated; no O_CREAT.
        let r = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        writer.join().unwrap();
        // SAFETY: `r` was opened above and is closed once.
        unsafe { libc::close(r) };
        assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
        assert!(!opened, "the relay opened the FIFO for reading");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn sh() -> PathBuf {
        std::fs::canonicalize("/bin/sh").unwrap()
    }

    fn interpreter(line: &str) -> Option<Interpreter> {
        Some(Interpreter {
            line: line.as_bytes().to_vec(),
            path: sh().as_os_str().as_bytes().to_vec(),
            pin: None,
        })
    }

    /// A script copy as the helper makes one (the user's, 0600 unless
    /// `mode` says otherwise) that prints its argv.
    fn script_copy(dir: &Path, mode: u32) -> PathBuf {
        let copy = dir.join("copy");
        std::fs::write(&copy, b"#!/bin/sh\necho \"SEEN $0 $*\"\n").unwrap();
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap();
        copy
    }

    // 스크립트 복사본은 검사한 인터프리터로 돌고, 인터프리터는 복사본 경로를 인자로 받는다. 이것을 실패시키는 것:
    // script_argv에 복사본 경로 대신 다른 값을 넣는 것.
    #[test]
    fn test_macos_script_copy_runs_through_its_interpreter() {
        let dir = scratch("script");
        let copy = script_copy(&dir, 0o600);
        let run = run_relay(
            &frame_input(60 * SECOND, interpreter("/bin/sh")),
            &copy,
            &[b"tool", b"x"],
            None,
        );
        assert_eq!(run.code, 0, "{run:?}");
        assert_eq!(seen(&run), format!("{} x", copy.display()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 복사본은 사용자의 0600 파일이어야 한다. 이것을 실패시키는 것: script()의 private 조건을 지우는 것.
    #[test]
    fn test_script_copy_must_be_private() {
        let dir = scratch("script-0644");
        let copy = script_copy(&dir, 0o644);
        let run = run_relay(
            &frame_input(60 * SECOND, interpreter("/bin/sh")),
            &copy,
            &[b"tool"],
            None,
        );
        assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // frame의 줄과 다른 `#!` 줄, 그리고 인터프리터가 다시 스크립트인 경우는 거부한다. 이것을 실패시키는 것:
    // script()의 줄 비교를 지우는 것, 인터프리터의 Opened::Native 요구를 지우는 것.
    #[test]
    fn test_macos_script_line_and_nesting_refused() {
        let dir = scratch("script-refused");
        let copy = script_copy(&dir, 0o600);
        let other = run_relay(
            &frame_input(60 * SECOND, interpreter("/bin/zsh")),
            &copy,
            &[b"tool"],
            None,
        );
        assert_eq!(other.code, i32::from(RELAY_TARGET), "{other:?}");
        let nested = dir.join("nested");
        std::fs::write(&nested, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut frame = interpreter("/bin/sh");
        if let Some(i) = frame.as_mut() {
            i.path = nested.as_os_str().as_bytes().to_vec();
        }
        let copy2 = dir.join("copy2");
        std::fs::write(&copy2, format!("#!{}\n", nested.display())).unwrap();
        std::fs::set_permissions(&copy2, std::fs::Permissions::from_mode(0o600)).unwrap();
        if let Some(i) = frame.as_mut() {
            i.line = nested.as_os_str().as_bytes().to_vec();
        }
        let run = run_relay(&frame_input(60 * SECOND, frame), &copy2, &[b"tool"], None);
        assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 최종 재확인은 스크립트 사본도 본다. 인터프리터 재확인 때 사본 자리에 다른 0600 스크립트가
    // 오면 거부한다. 양성 대조: test_macos_script_copy_runs_through_its_interpreter. 이것을 실패시키는 것: exec의
    // 사본 still_named 검사를 지우는 것(바뀐 사본이 돈다).
    #[test]
    fn test_macos_copy_swapped_before_the_exec_is_refused() {
        let dir = scratch("copy-swap");
        let copy = script_copy(&dir, 0o600);
        let other = dir.join("other");
        std::fs::write(&other, b"#!/bin/sh\necho \"SEEN swapped\"\n").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        let run = run_relay(
            &frame_input(60 * SECOND, interpreter("/bin/sh")),
            &copy,
            &[b"tool"],
            Some(("rename", &copy, &other)),
        );
        assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 소유권을 무시하는 볼륨(`hdiutil attach -owners off`) 위의 대상은 거부한다(그 볼륨에서는 모든
    // 파일이 지금 사용자 소유로 보인다). 양성 대조: 같은 dmg를 소유권을 지키게 붙이면 돈다. 이것을 실패시키는 것:
    // mount_ownership이 MNT_IGNORE_OWNERSHIP을 보지 않는 것.
    #[test]
    fn test_macos_target_on_a_volume_ignoring_owners_refused() {
        for (owners, code) in [(true, 0), (false, RELAY_TARGET)] {
            let dir = scratch(if owners { "owners-on" } else { "owners-off" });
            let volume = crate::commands::sys::TestVolume::new(&dir, owners, false);
            // A small target: the image holds 4 MB.
            let exe = volume.mount.join("true");
            copy_mode(Path::new("/usr/bin/true"), &exe, 0o755);
            let run = run_relay(&live(), &exe, &[b"true"], None);
            assert_eq!(run.code, i32::from(code), "owners {owners}: {run:?}");
            drop(volume);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    // 로컬이 아닌 마운트는 판정 불가(None), 소유권을 무시하는 로컬 마운트는 false다. 이것을 실패시키는 것:
    // mount_ownership의 MNT_LOCAL 조건이나 MNT_IGNORE_OWNERSHIP 조건을 지우는 것.
    #[test]
    fn mount_flags_decide_ownership() {
        let local = libc::MNT_LOCAL as u32;
        let ignore = libc::MNT_IGNORE_OWNERSHIP as u32;
        assert_eq!(mount_ownership(local), Some(true));
        assert_eq!(mount_ownership(local | ignore), Some(false));
        assert_eq!(mount_ownership(0), None);
        assert_eq!(mount_ownership(ignore), None);
    }
}
