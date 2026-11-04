//! Trusted relay, Linux native executables and scripts (`bingsu __exec-v2`,
//! spec section 4 "the place of the pre-exec check", rows native executable
//! and script). The command supervisor spawns it with an empty environment
//! and the permit and exec frame on fd 3 (fd 2 is its status pipe); the relay checks the target through
//! one open descriptor, takes a fresh clock as its last step and runs the
//! target with `execveat` on that descriptor. A script runs as its checked
//! interpreter's descriptor with a sealed memfd copy of the script. Every decision
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
/// The seals of the script copy: its bytes and size are fixed, and nobody
/// can lift a seal.
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

/// Moves fd 2 (the status pipe) above fd 3, where the close-on-exec pass
/// of `prepare` marks it like every descriptor from 3 up, and puts
/// `/dev/null` at 2 for the target (spec: stderr `/dev/null`). Without a
/// fd 2 there is no status pipe, and 2 still gets `/dev/null`. `Err` (fd 2
/// could not be replaced, so the target would inherit the pipe) refuses.
fn take_status() -> Result<Option<OwnedFd>, Option<OwnedFd>> {
    // SAFETY: duplicates fd 2 when it is open; -1 (EBADF) when it is not.
    let moved = unsafe { libc::fcntl(2, libc::F_DUPFD, 3) };
    // SAFETY: a successful F_DUPFD returns a descriptor nothing else owns.
    let status = (moved >= 0).then(|| unsafe { OwnedFd::from_raw_fd(moved) });
    // SAFETY: fixed NUL-terminated path, no O_CREAT.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
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
    fd: OwnedFd,
    /// A script's sealed copy: the one descriptor past 2 the target keeps.
    _script: Option<OwnedFd>,
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    envp_ptrs: Vec<*const libc::c_char>,
}

/// Spec order: signals, fd 3 read and closed, the executable opened and
/// checked, descriptors past 2 marked close-on-exec. Every buffer of this
/// stage is freed when it returns; the fresh clock comes after, in `exec`.
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
    let (permit, mut frame) = read_relay_input(&input, INPUT_CAP).map_err(|_| RELAY_INPUT)?;
    let (fd, script, argv) = match open_target(parsed.executable, frame.pin)? {
        // A frame that names an interpreter was made for a script.
        Opened::Native(_) if frame.interpreter.is_some() => return Err(RELAY_TARGET),
        Opened::Native(fd) => (fd, None, c_strings(parsed.argv)?),
        Opened::Script(fd, checked, body) => {
            let (interpreter, copy, argv) = script(&fd, &checked, &body, &frame, parsed.argv)?;
            (interpreter, Some(copy), argv)
        }
    };
    let envp = environment(&std::mem::take(&mut frame.environment))?;
    let argv_ptrs = pointers(&argv);
    let envp_ptrs = pointers(&envp);
    // The target gets 0, 1 and 2 only; the executable's fd is close-on-exec.
    if !cloexec_from_3(close_range_cloexec()) {
        return Err(RELAY_EXEC);
    }
    // A script's copy alone stays open across exec, so the interpreter can
    // open `/proc/self/fd/N`; this comes after the close-on-exec pass, which
    // would mark it again.
    if let Some(copy) = &script
        && set_fd_flags(copy.as_raw_fd(), 0).is_err()
    {
        return Err(RELAY_EXEC);
    }
    // U-17: a setuid, setgid or file-capability target runs, but without
    // gaining anything; the flag stays for every descendant. Last of the
    // checks, so `exec` keeps the clock read right before execveat.
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(RELAY_EXEC);
    }
    Ok(Target {
        permit,
        frame,
        fd,
        _script: script,
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

    /// The clock check and `execveat` back to back: nothing is built or
    /// freed between them (`self` drops only after a failed exec).
    fn exec(self) -> u8 {
        if !self.clock_allows() {
            return RELAY_EXPIRED;
        }
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

/// Every descriptor from 3 up is close-on-exec. Without close_range (ENOSYS
/// before 5.9) or without its CLOEXEC flag (EINVAL on 5.9 and 5.10; the spec
/// supports 5.7 and later) every open descriptor listed in /proc/self/fd gets
/// FD_CLOEXEC. Any other error, an unreadable listing or a failed fcntl
/// fails closed.
fn cloexec_from_3(close_range: Result<(), i32>) -> bool {
    match close_range {
        Ok(()) => true,
        Err(libc::ENOSYS | libc::EINVAL) => cloexec_listed(open_fds(), set_cloexec),
        Err(_) => false,
    }
}

/// The numbers in /proc/self/fd, or `None` when the listing fails.
fn open_fds() -> Option<Vec<i32>> {
    std::fs::read_dir("/proc/self/fd")
        .ok()?
        .map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect()
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
/// `O_PATH | O_DIRECTORY | O_NOFOLLOW`, so a symlink in a folder's place
/// fails with ENOTDIR or ELOOP; ".", ".." and empty names are refused.
///
/// The file must be regular and pass `allowed`. It is opened `O_PATH` first
/// and checked; then that descriptor is opened for reading through
/// `/proc/self/fd`, the same inode, and its first bytes say whether it is a
/// script (`read_script`). An execute-only file cannot be opened for reading (EACCES), and
/// without `/proc` there is no such path; then the `O_PATH` descriptor runs,
/// as a native executable only (spec section 4 "native executable"): its
/// `#!` line, if any, is never read, and the kernel's own script loader
/// cannot open the close-on-exec descriptor it would hand the interpreter.
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
    let search = libc::O_PATH | libc::O_DIRECTORY;
    let mut dir = open_at(libc::AT_FDCWD, b"/", search).map_err(|_| RELAY_TARGET)?;
    for name in folders {
        dir = open_at(dir.as_raw_fd(), name, search).map_err(|_| RELAY_TARGET)?;
    }
    // The last name opens path-only first, so a device or FIFO put there is
    // never opened for reading before its type is known.
    let path_fd = open_at(dir.as_raw_fd(), last, libc::O_PATH).map_err(|_| RELAY_TARGET)?;
    let st = stat(&path_fd)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || !allowed(&st, pin)? {
        return Err(RELAY_TARGET);
    }
    drop(dir);
    let (fd, readable) = match reopen(&path_fd).map_err(native_only) {
        Ok(fd) => (fd, true),
        Err(Some(())) => (path_fd, false),
        Err(None) => return Err(RELAY_TARGET),
    };
    if !readable {
        return Ok(Opened::Native(fd));
    }
    Ok(match read_script(&fd)? {
        Some(body) => Opened::Script(fd, st, body),
        None => Opened::Native(fd),
    })
}

/// A checked executable: a native one, or a script with the stat its checks
/// ran on and its body, read once.
enum Opened {
    Native(OwnedFd),
    Script(OwnedFd, libc::stat, Vec<u8>),
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

/// The script row of spec section 4, on the body `read_script` read once:
/// its whole `#!` line must be the line the helper resolved, the kernel must
/// let the user execute the file (`may_execute`), and the interpreter must
/// pass the same checks, be a native executable (no nested `#!`) and not be
/// `/usr/bin/env`. The body goes into a sealed memfd; then the script's
/// descriptor must still be the file `checked` describes (same identity,
/// owner, mode and status change time). The interpreter's descriptor runs
/// with argv `[line interpreter, line argument, /proc/self/fd/N, argv[1..]]`,
/// the order the kernel's script loader uses.
fn script(
    fd: &OwnedFd,
    checked: &libc::stat,
    body: &[u8],
    frame: &ExecFrame,
    argv: &[&[u8]],
) -> Result<(OwnedFd, OwnedFd, Vec<CString>), u8> {
    let Head::Script(line) = head(&body[..body.len().min(SHEBANG_MAX)]) else {
        return Err(RELAY_TARGET);
    };
    let interpreter = frame
        .interpreter
        .as_ref()
        .filter(|i| i.line == line.line && i.path != b"/usr/bin/env")
        .ok_or(RELAY_TARGET)?;
    if !may_execute(fd) {
        return Err(RELAY_TARGET);
    }
    let Opened::Native(interpreter_fd) = open_target(&interpreter.path, interpreter.pin)? else {
        return Err(RELAY_TARGET);
    };
    let copy = sealed_copy(body, memfd_create, write_fd)?;
    if !unchanged(checked, &stat(fd)?) {
        return Err(RELAY_TARGET);
    }
    let argv = c_strings(&script_argv(line, copy.as_raw_fd(), argv))?;
    Ok((interpreter_fd, copy, argv))
}

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

/// `new` answers; only its ENOSYS asks `old`, once. Any other error refuses.
fn execute_verdict(new: impl FnOnce() -> Result<(), i32>, old: impl FnOnce() -> bool) -> bool {
    match new() {
        Ok(()) => true,
        Err(libc::ENOSYS) => old(),
        Err(_) => false,
    }
}

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

/// Whether `now` is still the file `before` describes: a write, chmod,
/// chown or ACL change moves the status change time. A rewrite within one
/// timestamp tick keeps the ctime and is not caught; only trusted parties
/// (the owner, root, a pinned group) can write the file (m6-B2a).
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

fn script_argv<'a>(line: Shebang<'a>, copy: i32, argv: &[&'a [u8]]) -> Vec<Vec<u8>> {
    let mut out = vec![line.interpreter.to_vec()];
    out.extend(line.arg.map(<[u8]>::to_vec));
    out.push(format!("/proc/self/fd/{copy}").into_bytes());
    // parse_relay_args refuses an empty argv; argv[0] is the script's name.
    out.extend(argv.iter().skip(1).map(|w| w.to_vec()));
    out
}

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

fn write_fd(fd: &OwnedFd, bytes: &[u8]) -> isize {
    // SAFETY: `bytes` is readable for its length; `fd` is open for writing.
    unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) }
}

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

fn stat(fd: &OwnedFd) -> Result<libc::stat, u8> {
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open and `st` is writable.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(RELAY_TARGET);
    }
    Ok(st)
}

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

/// A failed reopen that still lets the `O_PATH` descriptor run as a native
/// executable (`Some`): EACCES (execute-only file) and no `/proc` (ENOENT),
/// as the close-on-exec fallback treats a missing listing. Anything else
/// refuses (`None`).
fn native_only(errno: i32) -> Option<()> {
    matches!(errno, libc::EACCES | libc::ENOENT).then_some(())
}

/// Only root or the user may change the file. Group write passes only with
/// a pin, and a pin must name this file unchanged: same device, inode,
/// group, mode and status change time as when the helper's group check
/// cleared it (spec section 2 safety row; rewriting, chmod, chown and ACL
/// changes move the ctime).
fn allowed(st: &libc::stat, pin: Option<ExecPin>) -> Result<bool, u8> {
    let facts = Facts {
        dev: st.st_dev,
        ino: st.st_ino,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode,
        // Linux file systems enforce ownership. The ACL is not read here: the
        // helper read it before it made the pin (an extended ACL under group
        // write is undecided there and gets no pin), and after that only the
        // file's owner (root or the user, checked below) or a holder of
        // CAP_FOWNER can change it, both trusted (B2 ruling A-1).
        acl: AclFacts::None,
        ownership: Some(true),
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

#[cfg(test)]
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
            // SAFETY: plain prctl calls; `program` points at the filter above,
            // alive until spawn returns.
            if deny_nnp
                && unsafe {
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, program)
                            != 0
                }
            {
                return Err(std::io::Error::last_os_error());
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

    // N-076. 이것을 실패시키는 것: prepare의 새 시계 확인(`frame.allows`)을 지우는 것.
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

    // N-077. 이것을 실패시키는 것: prepare의 close_range(CLOSE_RANGE_CLOEXEC)를 지우는 것
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

    // 감독이 exec 성공과 중계 거부를 대상 종료 코드와 따로 안다(B1 판정). 이것을 실패시키는 것: relay()의
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

    // C2 수용 조건(B3 리뷰): fd 2 없이 떠도 대상은 fd 2에 /dev/null을 받는다(memfd나 열린 파일이 2를 받지
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

    // U-17. 이것을 실패시키는 것: prepare의 PR_SET_NO_NEW_PRIVS를 지우는 것(대상의 NoNewPrivs가 0).
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

    // U-17: 플래그를 걸 수 없으면 대상을 실행하지 않는다. 이것을 실패시키는 것: prepare에서 prctl의
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

    // U-17: setuid 대상은 실행되지만 권한을 얻지 못한다. Linux 컨테이너에서 root로 --ignored로 돌린다
    // (root 소유 04755 사본을 nobody가 실행). 이것을 실패시키는 것: prepare의 PR_SET_NO_NEW_PRIVS를
    // 지우는 것(대상의 유효 uid가 0이 됨).
    #[test]
    #[ignore = "root in the Linux container; the relay runs as nobody"]
    fn test_setuid_target_gains_nothing() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        // SAFETY: getuid cannot fail.
        assert_eq!(unsafe { libc::getuid() }, 0, "run as root");
        let dir = std::fs::canonicalize(fresh_dir("setuid")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("cat");
        cat_copy(&exe, 0o4755);
        assert_eq!(pin_of(&exe).group.mode & 0o7777, 0o4755);
        let (_, input) = input(Origin::Config, LIVE, b"");
        let child = echo(spawn_relay_with(
            &input,
            &args(&exe, &[b"cat"]),
            &[],
            Spawn {
                uid: Some(65_534),
                ..Spawn::default()
            },
        ))
        .unwrap();
        // Only the status file: another user's /proc/<pid>/exe needs ptrace access.
        let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
        finish(child);
        assert!(
            status
                .lines()
                .any(|l| l == "Uid:\t65534\t65534\t65534\t65534"),
            "{status}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // N-078. 이것을 실패시키는 것: 중계가 마감이나 permit을 대상 envp·argv에 넣는 것.
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

    /// Prepares a relay run of `exe` (a copy of `true`), then renames a copy
    /// of `false` over that name, then executes: the exit code says which
    /// file ran.
    #[test]
    #[ignore = "child: replaces itself with the target"]
    fn swap_child() {
        let dir = PathBuf::from(OsString::from_vec(read_all(4)));
        // SAFETY: fd 4 is this child's argument pipe, read to the end above.
        unsafe { libc::close(4) };
        let exe = dir.join("x");
        let words: Vec<OsString> = args(&exe, &[b"x"])
            .into_iter()
            .map(OsString::from_vec)
            .collect();
        let (r, w) = pipe();
        put(&w, &pinned(None));
        drop(w);
        // SAFETY: both descriptors are valid; fd 3 is free in this child.
        assert_eq!(unsafe { libc::dup2(r.as_raw_fd(), 3) }, 3);
        drop(r);
        let target = prepare(&words).unwrap();
        std::fs::rename(dir.join("false"), &exe).unwrap();
        let code = target.exec();
        // SAFETY: child exit without the harness's atexit work.
        unsafe { libc::_exit(100 + i32::from(code)) }
    }

    // 이것을 실패시키는 것: 중계가 검사한 fd 대신 경로로 실행하는 것(execveat(fd) 대신 execve(path)):
    // 검사 뒤 바꿔치기한 false가 실행되어 종료 코드 1이 된다.
    #[test]
    fn test_swap_after_check_runs_checked_file() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let dir = std::fs::canonicalize(fresh_dir("swap")).unwrap();
        let copy = |from: &str, to: &str| {
            std::fs::copy(std::fs::canonicalize(from).unwrap(), dir.join(to)).unwrap();
        };
        copy("/bin/true", "x");
        copy("/bin/false", "false");
        let (r4, w4) = pipe();
        put(&w4, dir.as_os_str().as_bytes());
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
        assert_eq!(status.code(), Some(0), "{status:?}");
        // Positive control: what now sits at the name is `false`.
        assert_eq!(
            Command::new(dir.join("x")).status().unwrap().code(),
            Some(1)
        );
        std::fs::remove_dir_all(&dir).unwrap();
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

    fn open_read(path: &Path) -> (OwnedFd, libc::stat) {
        let fd: OwnedFd = std::fs::File::open(path).unwrap().into();
        let st = stat(&fd).unwrap();
        (fd, st)
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
        let (fd, st) = open_read(&file);
        let (_, copy, argv) = script(&fd, &st, &body, &frame, &[b"s"]).unwrap();
        let mut back = vec![0u8; SCRIPT_MAX];
        let n = read_at(&copy, &mut back, 0).unwrap();
        assert_eq!(&back[..n], body.as_slice());
        assert_eq!(argv[0].as_bytes(), cat().as_os_str().as_bytes());
        // The file's own line would match another frame; the buffer's decides.
        let other = format!("#!{}\n", cat().display()).into_bytes();
        assert_eq!(
            script(&fd, &st, &other, &frame, &[b"s"]).err(),
            Some(RELAY_TARGET)
        );
        // Rewritten after the checks (same bytes, new ctime): refused.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&file, std::fs::read(&file).unwrap()).unwrap();
        assert_ne!(stat(&fd).unwrap().st_ctime_nsec, st.st_ctime_nsec);
        assert_eq!(
            script(&fd, &st, &body, &frame, &[b"s"]).err(),
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
    #[ignore = "non-root user in the Linux container"]
    fn test_execute_only_target_runs_path_only() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        // SAFETY: getuid cannot fail.
        let me = unsafe { libc::getuid() };
        assert_ne!(me, 0, "run as a user other than root");
        let dir = fresh_dir("xonly-path");
        let exe = dir.join("cat");
        std::fs::copy(cat(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o111)).unwrap();
        let Opened::Native(fd) = open_target(exe.as_os_str().as_bytes(), None).unwrap() else {
            panic!("an execute-only file is not a script here");
        };
        // SAFETY: F_GETFL only reads the descriptor's status flags.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_PATH, 0, "{flags:#x}");
        drop(fd);
        let got = script_outcome(&exe, &script_input(&cat_line(), &cat(), None), &[b"cat"]);
        assert!(refused_with(&got, RELAY_TARGET), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // 이것을 실패시키는 것: execute_verdict의 ENOSYS 조건을 지우는 것(모든 오류에서 대체 호출), ENOSYS에서
    // 대체 호출을 하지 않거나 그 답을 버리는 것, 성공을 거부하는 것.
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
