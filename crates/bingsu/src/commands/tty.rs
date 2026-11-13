//! The user's terminal, `/dev/tty` (not stdin or stdout, which may be
//! pipes): lines to ask a question, and the background color query
//! `OSC 11 ; ?` (`bingsu setup`; `doctor` asks the same question). Not on any
//! prompt path.
//!
//! The query needs the terminal in a mode where the answer is not echoed and
//! is read without a newline. The terminal is put back on these ways out: the
//! answer arrived, the time ran out, Ctrl-C (read as the byte 0x03 because
//! `ISIG` is off), SIGTERM, SIGHUP or SIGINT from outside (a handler sets a
//! flag and `select` returns early), and a panic (the guard's `Drop`). Other
//! fatal signals (SIGQUIT, SIGKILL, SIGSEGV...) are not handled: they leave
//! the terminal raw until `stty sane` or `reset`.
//!
//! A reply that comes after the time limit would otherwise land on the shell's
//! command line as typed text. So when no reply came, the terminal is read for
//! a little longer before it is restored. Restoring is `tcsetattr(TCSANOW)`
//! first, then `tcflush(TCIFLUSH)` for what is still queued: `TCSAFLUSH`
//! would wait for the output to drain, which never ends when the output is
//! stopped (Ctrl-S) and `ISIG` is off.
use super::sys;
use bingsu_core::color::osc11::{REPLY_MAX, find_reply};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long the terminal gets to answer. A hypothesis (200 ms): the setup
/// measurement of the answer time per terminal sets the final value.
pub const REPLY_TIMEOUT: Duration = Duration::from_millis(200);

/// How long a silent terminal is read after the time limit, so a late reply
/// is thrown away instead of reaching the command line. A starting value
/// (50 ms), to be set again from the same measurement.
pub const LATE_REPLY_DRAIN: Duration = Duration::from_millis(50);

/// Typed input read before the reply, kept only to look for the reply in.
const INPUT_CAP: usize = 4 * REPLY_MAX;

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// The bytes of the terminal's answer, `ESC ] 11 ; … ST`. Not parsed.
    Bytes(Vec<u8>),
    /// No answer in time, or one that was too long to be an answer.
    Silent,
    /// Ctrl-C, or a termination signal.
    Cancelled,
}

pub struct Tty {
    file: File,
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The terminal as found, and the signal handlers it replaced. Putting both
/// back is `Drop`.
struct Raw {
    fd: RawFd,
    saved: libc::termios,
    old: [libc::sigaction; 3],
}

impl Raw {
    /// Switches `fd` to a mode with no echo, no line editing and no signal
    /// keys, where a read returns at once with what is there.
    fn enter(fd: RawFd) -> std::io::Result<Self> {
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is an open descriptor and `saved` is writable memory
        // of the type tcgetattr fills.
        if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: tcgetattr returned 0, so it wrote the whole structure.
        let saved = unsafe { saved.assume_init() };
        let mut raw = saved;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        STOP.store(false, Ordering::SeqCst);
        // SAFETY: an all-zero `sigaction` is a valid starting value.
        let mut old: [libc::sigaction; 3] = unsafe { std::mem::zeroed() };
        for (slot, sig) in old.iter_mut().zip(SIGNALS) {
            // SAFETY: an all-zero `sigaction` is a valid starting value.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            // No SA_RESTART: `select` must return early (EINTR).
            act.sa_flags = 0;
            // SAFETY: `act.sa_mask` is a valid signal set to empty.
            unsafe { libc::sigemptyset(&mut act.sa_mask) };
            // SAFETY: `act` is initialised and `slot` receives the old action.
            unsafe { libc::sigaction(sig, &act, slot) };
        }
        let this = Self { fd, saved, old };
        // SAFETY: `fd` is open and `raw` is the structure tcgetattr filled.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(this)
    }
}

/// How often an interrupted call is tried again.
const RESTORE_TRIES: usize = 8;

/// Puts the saved settings back with `set`. A signal can interrupt the call
/// (EINTR), so it is tried again. `true`: restored.
fn restore_with(mut set: impl FnMut() -> std::io::Result<()>) -> bool {
    for _ in 0..RESTORE_TRIES {
        match set() {
            Ok(()) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    false
}

/// The answer to give once the wait and the discard are over: a stop request
/// wins over everything, an answer included.
fn settle(result: Reply, stop: bool) -> Reply {
    if stop { Reply::Cancelled } else { result }
}

impl Drop for Raw {
    fn drop(&mut self) {
        let (fd, saved) = (self.fd, &self.saved);
        // TCSANOW, not TCSAFLUSH: that one waits for the output to drain.
        restore_with(|| {
            // SAFETY: `fd` is the open terminal this was made for; `saved`
            // came from tcgetattr.
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, saved) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
        for _ in 0..RESTORE_TRIES {
            // SAFETY: as above. A second discard of what arrived meanwhile.
            if unsafe { libc::tcflush(fd, libc::TCIFLUSH) } == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
        // The handlers go back after the terminal does.
        for (old, sig) in self.old.iter().zip(SIGNALS) {
            // SAFETY: `old` is the action `sigaction` returned for `sig`.
            unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) };
        }
    }
}

/// Writes all of `buf` through `write`. A write that a signal interrupted
/// (EINTR) is not simply tried again: if the signal asked to stop, `false`.
fn write_checked(
    mut write: impl FnMut(&[u8]) -> std::io::Result<usize>,
    mut buf: &[u8],
) -> std::io::Result<bool> {
    while !buf.is_empty() {
        match write(buf) {
            Ok(0) => return Err(std::io::Error::other("the terminal took no bytes")),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if STOP.load(Ordering::SeqCst) {
                    return Ok(false);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Waits until `fd` can be read or `until` passes. `false`: time ran out or
/// a signal asked to stop (only when `stoppable`). `select`, not `poll`: macOS
/// `poll` does not support `/dev/tty` (it reports the descriptor invalid at
/// once).
#[allow(
    clippy::unnecessary_fallible_conversions,
    reason = "`tv_usec` is 32 bits on macOS and 64 on Linux; one spelling for both"
)]
fn readable(fd: RawFd, stoppable: bool) -> impl Fn(Instant) -> bool {
    move |until| loop {
        if stoppable && STOP.load(Ordering::SeqCst) {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let mut tv = libc::timeval {
            tv_sec: left.as_secs().try_into().unwrap_or(0),
            tv_usec: left.subsec_micros().try_into().unwrap_or(0),
        };
        let mut set = std::mem::MaybeUninit::<libc::fd_set>::uninit();
        // SAFETY: `set` is writable memory; FD_ZERO initialises all of it.
        unsafe { libc::FD_ZERO(set.as_mut_ptr()) };
        // SAFETY: FD_ZERO above initialised `set`.
        let mut set = unsafe { set.assume_init() };
        // SAFETY: `Tty::open` refuses a descriptor at or above FD_SETSIZE, so
        // `fd` fits the set, and `set` is initialised.
        unsafe { libc::FD_SET(fd, &mut set) };
        // SAFETY: `set` and `tv` are valid for the call; no write or error sets.
        let n = unsafe {
            libc::select(
                fd + 1,
                &mut set,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut tv,
            )
        };
        if n > 0 {
            return true;
        }
        if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

/// Reads what the terminal sends until a reply is complete. `ready()` waits
/// for something to read (`false`: time ran out, or a stop was asked for);
/// `read` reads it.
fn read_reply(
    mut ready: impl FnMut() -> bool,
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
) -> Reply {
    let mut seen: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        if !ready() {
            return if STOP.load(Ordering::SeqCst) {
                Reply::Cancelled
            } else {
                Reply::Silent
            };
        }
        let n = match read(&mut chunk) {
            // Readable but nothing to read: the terminal went away.
            Ok(0) => return Reply::Silent,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Reply::Silent,
        };
        if chunk[..n].contains(&0x03) {
            return Reply::Cancelled;
        }
        if seen.len() + n > INPUT_CAP {
            return Reply::Silent;
        }
        seen.extend_from_slice(&chunk[..n]);
        if let Some(reply) = find_reply(&seen) {
            return Reply::Bytes(reply.to_vec());
        }
    }
}

impl Tty {
    /// `None`: there is no controlling terminal (a pipe, CI, `setsid`).
    pub fn open() -> Option<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/tty")
            .ok()?;
        // `select` cannot take a descriptor at or above FD_SETSIZE (it would
        // abort with the terminal raw): such a terminal is not used.
        if file.as_raw_fd() >= RawFd::try_from(libc::FD_SETSIZE).unwrap_or(RawFd::MAX) {
            return None;
        }
        // A device that is not a terminal (or a stale node) is no terminal.
        let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the descriptor is open and `t` is writable memory.
        if unsafe { libc::tcgetattr(file.as_raw_fd(), t.as_mut_ptr()) } != 0 {
            return None;
        }
        // Only the foreground job may change the terminal or read from it. A
        // background job that ignores SIGTTOU could change the mode under the
        // foreground shell, and restoring would throw away what the user typed.
        // SAFETY: the descriptor is open; the call reads the terminal's group.
        let foreground = unsafe { libc::tcgetpgrp(file.as_raw_fd()) };
        // SAFETY: getpgrp takes no arguments and cannot fail.
        let own = unsafe { libc::getpgrp() };
        (foreground == own).then_some(Self { file })
    }

    pub fn say(&self, text: &str) {
        let _ = sys::write_fd(self.file.as_raw_fd(), text.as_bytes());
    }

    /// One line typed by the user, lower-cased and trimmed, at most 64
    /// bytes. `None` at end of input (Ctrl-D) or an error.
    pub fn line(&self) -> Option<String> {
        let mut f = &self.file;
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        loop {
            match f.read(&mut b) {
                Ok(1) if b[0] == b'\n' => break,
                Ok(1) => {
                    if out.len() < 64 {
                        out.push(b[0]);
                    }
                }
                _ => return None,
            }
        }
        Some(String::from_utf8_lossy(&out).trim().to_lowercase())
    }

    /// Sends `OSC 11 ; ?` and waits up to `REPLY_TIMEOUT` for the answer.
    /// After anything but an answer the terminal is read for
    /// `LATE_REPLY_DRAIN` more and what comes is thrown away, whether the
    /// wait ended in silence or in a cancel; a cancel that arrives during
    /// that time still counts.
    pub fn ask_background(&self) -> std::io::Result<Reply> {
        let fd = self.file.as_raw_fd();
        let guard = Raw::enter(fd)?;
        let mut f = &self.file;
        let wait = readable(fd, true);
        // The time limit counts from before the query is written, so a late
        // start of this process after the write (a busy machine) cannot make
        // an answer count that came later than the limit after the query.
        let until = Instant::now() + REPLY_TIMEOUT;
        let sent = write_checked(
            |b| {
                // SAFETY: `fd` is open and `b` is a valid slice.
                let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
                usize::try_from(n).map_err(|_| std::io::Error::last_os_error())
            },
            b"\x1b]11;?\x1b\\",
        )?;
        let mut chunk = [0u8; 64];
        let mut result = if sent {
            read_reply(|| wait(until), |b| f.read(b))
        } else {
            Reply::Cancelled
        };
        if !matches!(result, Reply::Bytes(_)) {
            // A reply may still be on its way: read and drop it. The wait
            // here ignores the stop flag so that a cancel still reads it all.
            let drain = readable(fd, false);
            let until = Instant::now() + LATE_REPLY_DRAIN;
            while drain(until) {
                match f.read(&mut chunk) {
                    Ok(n) if n > 0 => {
                        if chunk[..n].contains(&0x03) {
                            result = Reply::Cancelled;
                        }
                    }
                    _ => break,
                }
            }
        }
        let result = settle(result, STOP.load(Ordering::SeqCst));
        drop(guard);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    // 이것을 실패시키는 것: `tcsetattr`가 EINTR로 끊겼을 때 다시 시도하지 않는 것(터미널이 raw로 남음), 다른
    // 오류에서 계속 시도하는 것, 계속 끊기면 끝없이 시도하는 것, 성공을 실패로 알리는 것.
    #[test]
    fn restoring_retries_an_interrupted_call() {
        let mut n = 0;
        assert!(restore_with(|| {
            n += 1;
            if n < 3 {
                Err(Error::from(ErrorKind::Interrupted))
            } else {
                Ok(())
            }
        }));
        assert_eq!(n, 3);
        let mut n = 0;
        assert!(!restore_with(|| {
            n += 1;
            Err(Error::from_raw_os_error(libc::EINVAL))
        }));
        assert_eq!(n, 1);
        let mut n = 0;
        assert!(!restore_with(|| {
            n += 1;
            Err(Error::from(ErrorKind::Interrupted))
        }));
        assert_eq!(n, RESTORE_TRIES);
    }

    // 이것을 실패시키는 것: 응답을 받은 뒤에 온 정지 요청(신호)을 무시하고 응답을 쓰는 것.
    #[test]
    fn a_stop_request_wins_over_an_answer() {
        let answer = || Reply::Bytes(b"x".to_vec());
        assert_eq!(settle(answer(), true), Reply::Cancelled);
        assert_eq!(settle(Reply::Silent, true), Reply::Cancelled);
        assert_eq!(settle(answer(), false), answer());
        assert_eq!(settle(Reply::Silent, false), Reply::Silent);
    }

    // 이것을 실패시키는 것: 읽을 수 있다는데 0바이트(끊긴 터미널)를 끝으로 보지 않고 마감까지 되풀이하는 것,
    // 응답 앞에 친 글자 속에서 응답을 못 찾는 것, 0x03을 취소로 치지 않는 것, 입력 상한을 넘겨도 계속 읽는 것.
    #[test]
    fn reading_a_reply_ends_on_hang_up_cancel_answer_and_flood() {
        // A hung-up terminal is readable and gives nothing: one read, then silence.
        let mut reads = 0;
        let mut waits = 0;
        let got = read_reply(
            || {
                waits += 1;
                waits < 6
            },
            |_| {
                reads += 1;
                Ok(0)
            },
        );
        assert_eq!(got, Reply::Silent);
        assert_eq!(reads, 1);
        // Typed-ahead input, then the answer in two pieces.
        let mut pieces: Vec<&[u8]> = vec![b"ls\r\x1b]11;rgb:00", b"00/0000/0000\x07"];
        let got = read_reply(
            || true,
            |b| {
                let p = pieces.remove(0);
                b[..p.len()].copy_from_slice(p);
                Ok(p.len())
            },
        );
        assert_eq!(
            got,
            Reply::Bytes(b"\x1b]11;rgb:0000/0000/0000\x07".to_vec())
        );
        // Ctrl-C.
        let got = read_reply(
            || true,
            |b| {
                b[0] = 0x03;
                Ok(1)
            },
        );
        assert_eq!(got, Reply::Cancelled);
        // Input that never makes an answer stops at the cap.
        let mut total = 0;
        let got = read_reply(
            || true,
            |b| {
                b.fill(b'x');
                total += b.len();
                // Bounded, so that a loop without the cap ends in an error.
                if total > 100 * INPUT_CAP {
                    return Err(Error::from_raw_os_error(libc::EIO));
                }
                Ok(b.len())
            },
        );
        assert_eq!(got, Reply::Silent);
        assert!(total <= INPUT_CAP + 64, "{total}");
        // Time ran out.
        assert_eq!(read_reply(|| false, |_| Ok(0)), Reply::Silent);
    }

    // 이것을 실패시키는 것: EINTR을 받고 정지 표시를 보지 않고 막힌 쓰기를 다시 하는 것, 부분 쓰기 뒤 나머지를
    // 쓰지 않는 것, 정지 표시가 없는데 EINTR에서 그만두는 것.
    #[test]
    fn an_interrupted_write_checks_the_stop_flag() {
        // The flag is process-wide: this test is the only one that sets it.
        STOP.store(false, Ordering::SeqCst);
        let mut calls = 0;
        let got = write_checked(
            |b| {
                calls += 1;
                match calls {
                    1 => Ok(b.len() - 2),
                    2 => Err(Error::from(ErrorKind::Interrupted)),
                    _ => {
                        assert_eq!(b.len(), 2, "only the rest is written");
                        Ok(b.len())
                    }
                }
            },
            b"abcdef",
        );
        assert!(matches!(got, Ok(true)));
        assert_eq!(calls, 3);
        // A stop request during an interrupted write ends it.
        let mut calls = 0;
        let got = write_checked(
            |_| {
                calls += 1;
                STOP.store(true, Ordering::SeqCst);
                // Bounded, so that a loop that ignores the flag ends in an error.
                if calls > 3 {
                    return Err(Error::from_raw_os_error(libc::EIO));
                }
                Err(Error::from(ErrorKind::Interrupted))
            },
            b"abc",
        );
        STOP.store(false, Ordering::SeqCst);
        assert!(matches!(got, Ok(false)));
        assert_eq!(calls, 1);
        assert!(write_checked(|_| Err(Error::from_raw_os_error(libc::EIO)), b"x").is_err());
    }
}
