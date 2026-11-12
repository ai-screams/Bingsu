//! The user's terminal, `/dev/tty` (not stdin or stdout, which may be
//! pipes): lines to ask a question, and the background color query
//! `OSC 11 ; ?` (`bingsu setup`; `doctor` asks the same question). Not on any
//! prompt path.
//!
//! The query needs the terminal in a mode where the answer is not echoed and
//! is read without a newline. The terminal is left as it was found on every
//! way out: the answer arrived, the time ran out, Ctrl-C (read as the byte
//! 0x03 because `ISIG` is off), SIGTERM, SIGHUP or SIGINT from outside (a
//! handler sets a flag and `select` returns early), and a panic (the guard's
//! `Drop`). SIGKILL cannot be caught: it leaves the terminal raw until
//! `stty sane` or `reset`.
//!
//! A reply that comes after the time limit would otherwise land on the shell's
//! command line as typed text. So when no reply came, the terminal is read for
//! a little longer before it is restored, and restoring discards what is still
//! queued (`tcsetattr(TCSAFLUSH)`, then `tcflush(TCIFLUSH)`).
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

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: `fd` is the open terminal this was made for; `saved` came
        // from tcgetattr. TCSAFLUSH also discards input not yet read.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
        // SAFETY: as above. A second discard of what arrived meanwhile.
        unsafe { libc::tcflush(self.fd, libc::TCIFLUSH) };
        for (old, sig) in self.old.iter().zip(SIGNALS) {
            // SAFETY: `old` is the action `sigaction` returned for `sig`.
            unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) };
        }
    }
}

/// Waits until `fd` can be read or `until` passes. `false`: time ran out or
/// a signal asked to stop. `select`, not `select`: macOS `select` does not
/// support `/dev/tty` (it reports the descriptor invalid at once).
fn readable(fd: RawFd) -> impl Fn(Instant) -> bool {
    move |until| loop {
        if STOP.load(Ordering::SeqCst) {
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
        // SAFETY: `fd` is a small open descriptor below FD_SETSIZE (the
        // terminal opened right after start-up) and `set` is initialised.
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

impl Tty {
    /// `None`: there is no controlling terminal (a pipe, CI, `setsid`).
    pub fn open() -> Option<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/tty")
            .ok()?;
        // A device that is not a terminal (or a stale node) is no terminal.
        let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the descriptor is open and `t` is writable memory.
        (unsafe { libc::tcgetattr(file.as_raw_fd(), t.as_mut_ptr()) } == 0).then_some(Self { file })
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
    pub fn ask_background(&self) -> std::io::Result<Reply> {
        let fd = self.file.as_raw_fd();
        let guard = Raw::enter(fd)?;
        let mut f = &self.file;
        if sys::write_fd(fd, b"\x1b]11;?\x1b\\") != sys::WriteOutcome::Done {
            return Err(std::io::Error::other("the terminal did not take the query"));
        }
        let wait = readable(fd);
        let until = Instant::now() + REPLY_TIMEOUT;
        let mut seen: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 64];
        let result = loop {
            if !wait(until) {
                break if STOP.load(Ordering::SeqCst) {
                    Reply::Cancelled
                } else {
                    Reply::Silent
                };
            }
            let n = match f.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break Reply::Silent,
            };
            if chunk[..n].contains(&0x03) {
                break Reply::Cancelled;
            }
            if seen.len() + n > INPUT_CAP {
                break Reply::Silent;
            }
            seen.extend_from_slice(&chunk[..n]);
            if let Some(reply) = find_reply(&seen) {
                break Reply::Bytes(reply.to_vec());
            }
        };
        if result != Reply::Cancelled && !matches!(result, Reply::Bytes(_)) {
            // A reply may still be on its way: read and drop it.
            let until = Instant::now() + LATE_REPLY_DRAIN;
            while wait(until) {
                if !matches!(f.read(&mut chunk), Ok(n) if n > 0) {
                    break;
                }
            }
        }
        drop(guard);
        Ok(result)
    }
}
