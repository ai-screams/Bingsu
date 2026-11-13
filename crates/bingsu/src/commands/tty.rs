//! The user's terminal, `/dev/tty` (not stdin or stdout, which may be
//! pipes): lines to ask a question, and queries the terminal answers itself,
//! such as the background color `OSC 11 ; ?` (`bingsu setup`) or the cursor
//! position `CSI 6 n` (`bingsu doctor`). Not on any prompt path.
//!
//! A query needs the terminal in a mode where the answer is not echoed and
//! is read without a newline: `Tty::raw` gives a guard ([`RawGuard`]) that
//! asks one or more queries ([`Terminal`]). The terminal is put back on these
//! ways out: the guard ends, Ctrl-C (read as the byte 0x03 because `ISIG` is
//! off), SIGTERM, SIGHUP or SIGINT from outside (a handler sets a flag and
//! `select` returns early), and a panic (the guard's `Drop`). Other fatal
//! signals (SIGQUIT, SIGKILL, SIGSEGV...) are not handled: they leave the
//! terminal raw until `stty sane` or `reset`. One guard at a time in a
//! process: the flag and the handlers are process-wide. Raw mode also turns
//! output flow control (IXON) off, so Ctrl-S cannot hold a query's write.
//!
//! Replies carry no query number, so a reply must not be read as the answer
//! to another query. Before each query the input queue is discarded; once a
//! query ends silent or cancelled, the guard asks nothing more. A reply that
//! comes after the time limit would otherwise land on the shell's command
//! line as typed text, so when no reply came the terminal is read for a
//! little longer before the query returns. Restoring is `tcsetattr(TCSANOW)`
//! first, then `tcflush(TCIFLUSH)` for what is still queued: `TCSAFLUSH`
//! would wait for the output to drain, which never ends when the output is
//! stopped (Ctrl-S) and `ISIG` is off.
use super::sys;
use bingsu_core::color::osc11::REPLY_MAX;
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

/// The longest control sequence reply kept. A cursor position report is at
/// most 14 bytes (`ESC [`, two numbers of up to five digits, `;`, `R`).
const CSI_REPLY_MAX: usize = 32;

/// Which reply counts, and where it ends. Other input before it (typed keys,
/// an arrow key's `ESC [ A`, a reply to something else) is skipped, within a
/// cap. Only 7-bit forms: the 8-bit introducers would match bytes of typed
/// UTF-8 text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyEnd {
    /// `ESC ] <prefix> ... (BEL | ESC \)`, for example `Osc(b"11;")`. At
    /// most `REPLY_MAX` (64) bytes.
    Osc(&'static [u8]),
    /// `ESC [`, parameter bytes (0x30-0x3f), intermediate bytes (0x20-0x2f)
    /// and the final byte given, for example `Csi(b'R')` for a cursor
    /// position report. At most `CSI_REPLY_MAX` (32) bytes.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "bingsu doctor's terminal measurement asks it")
    )]
    Csi(u8),
}

impl ReplyEnd {
    /// The longest reply of this kind.
    fn reply_cap(self) -> usize {
        match self {
            Self::Osc(_) => REPLY_MAX,
            Self::Csi(_) => CSI_REPLY_MAX,
        }
    }

    /// Input read while waiting for the reply, kept only to look for it in.
    fn input_cap(self) -> usize {
        4 * self.reply_cap()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// From ESC through the end. Not parsed.
    Reply(Vec<u8>),
    /// No reply by the deadline, a reply over its cap, the terminal went
    /// away, or an earlier query on this guard was silent.
    Silent,
    /// 0x03, or SIGINT, SIGTERM or SIGHUP, now or in an earlier query on
    /// this guard.
    Cancelled,
}

/// A terminal that answers queries. `bingsu doctor`'s measurements run on
/// this, so a fake terminal can test them.
pub trait Terminal {
    /// Discards queued input (`tcflush(TCIFLUSH)`), writes `request` and reads
    /// one reply until `deadline`. On `Silent` or `Cancelled` it reads and
    /// drops input for `LATE_REPLY_DRAIN` more before it returns, and every
    /// later query returns the same without asking.
    fn query(
        &mut self,
        request: &[u8],
        end: ReplyEnd,
        deadline: Instant,
    ) -> std::io::Result<Answer>;
    /// Writes without asking (probe characters, `\r`, `ESC [ K`), also after
    /// a silent or cancelled query. `ErrorKind::Interrupted` when a signal
    /// cut the write short.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "bingsu doctor's terminal measurement writes")
    )]
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Columns from `TIOCGWINSZ`; `None` when unknown or 0.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "bingsu doctor's terminal measurement reads it")
    )]
    fn columns(&self) -> Option<u16>;
}

/// The first complete reply of kind `end` in `buf`, which may start with
/// other input. `None` while it has not arrived whole.
fn find_answer(buf: &[u8], end: ReplyEnd) -> Option<&[u8]> {
    match end {
        ReplyEnd::Osc(prefix) => find_osc(buf, prefix),
        ReplyEnd::Csi(last) => find_csi(buf, last),
    }
}

/// From the first `ESC ] <prefix>` through the first BEL or `ESC \` after it.
fn find_osc<'a>(buf: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let start = 2 + prefix.len();
    let from = buf
        .windows(start)
        .position(|w| w[..2] == *b"\x1b]" && w[2..] == *prefix)?;
    let rest = &buf[from..];
    let end = rest
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(i, &b)| match b {
            0x07 => Some(i + 1),
            b'\\' if rest[i - 1] == 0x1b => Some(i + 1),
            _ => None,
        })?;
    Some(&rest[..end])
}

/// The first `ESC [ P* I* F` whose final byte F is `last` (ECMA-48 5.4).
/// A sequence with another final byte is skipped.
fn find_csi(buf: &[u8], last: u8) -> Option<&[u8]> {
    let mut from = 0;
    while let Some(at) = buf[from..].windows(2).position(|w| w == b"\x1b[") {
        let start = from + at;
        let mut i = start + 2;
        while i < buf.len() && (0x30..=0x3f).contains(&buf[i]) {
            i += 1;
        }
        while i < buf.len() && (0x20..=0x2f).contains(&buf[i]) {
            i += 1;
        }
        if i == buf.len() {
            // Not ended yet: the rest may still come.
            return None;
        }
        if buf[i] == last {
            return Some(&buf[start..=i]);
        }
        from = start + 1;
    }
    None
}

pub struct Tty {
    file: File,
}

static STOP: AtomicBool = AtomicBool::new(false);

/// A guard is alive: `Tty::raw` makes no second one.
static IN_RAW: AtomicBool = AtomicBool::new(false);

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
    /// Switches `fd` to a mode with no echo, no line editing, no signal keys
    /// and no output flow control, where a read returns at once with what is
    /// there.
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
        // Ctrl-S would stop the output, and on Linux a write then waits until
        // Ctrl-Q, past any deadline (Ctrl-C cannot end it: ISIG is off). With
        // IXON off the key is input that the next query discards, and Linux
        // restarts output that was stopped before. macOS keeps such output
        // stopped; small writes still return, so the query ends silent.
        raw.c_iflag &= !libc::IXON;
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
fn settle(result: Answer, stop: bool) -> Answer {
    if stop { Answer::Cancelled } else { result }
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
        IN_RAW.store(false, Ordering::SeqCst);
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

/// Reads what the terminal sends until a reply of kind `end` is complete.
/// `ready()` waits for something to read (`false`: time ran out, or a stop
/// was asked for); `read` reads it.
fn read_reply(
    end: ReplyEnd,
    mut ready: impl FnMut() -> bool,
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
) -> Answer {
    let mut seen: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        if !ready() {
            return if STOP.load(Ordering::SeqCst) {
                Answer::Cancelled
            } else {
                Answer::Silent
            };
        }
        let n = match read(&mut chunk) {
            // Readable but nothing to read: the terminal went away.
            Ok(0) => return Answer::Silent,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Answer::Silent,
        };
        if chunk[..n].contains(&0x03) {
            return Answer::Cancelled;
        }
        if seen.len() + n > end.input_cap() {
            return Answer::Silent;
        }
        seen.extend_from_slice(&chunk[..n]);
        if let Some(reply) = find_answer(&seen, end) {
            return if reply.len() > end.reply_cap() {
                Answer::Silent
            } else {
                Answer::Reply(reply.to_vec())
            };
        }
    }
}

/// Discards what the terminal has sent and nobody read yet. A signal can
/// interrupt the call (EINTR), so it is tried again.
fn flush_input(fd: RawFd) -> std::io::Result<()> {
    for _ in 0..RESTORE_TRIES {
        // SAFETY: `fd` is the open terminal; the call only drops queued input.
        if unsafe { libc::tcflush(fd, libc::TCIFLUSH) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
}

/// One `write(2)` on `fd`: the bytes taken.
fn write_once(fd: RawFd, b: &[u8]) -> std::io::Result<usize> {
    // SAFETY: `fd` is open and `b` is a valid slice.
    let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
    usize::try_from(n).map_err(|_| std::io::Error::last_os_error())
}

/// How a guard's earlier query ended, when it ended without a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spent {
    Silent,
    Cancelled,
}

/// The terminal in raw mode, from `Tty::raw` until it is dropped.
pub struct RawGuard<'a> {
    tty: &'a Tty,
    _raw: Raw,
    spent: Option<Spent>,
}

impl RawGuard<'_> {
    /// Reads and drops what comes for `LATE_REPLY_DRAIN`, so a late reply
    /// does not stay behind. The wait ignores the stop flag so that a cancel
    /// still reads it all; a 0x03 in it turns `result` into a cancel.
    fn drain(&self, mut result: Answer) -> Answer {
        let fd = self.tty.file.as_raw_fd();
        let mut f = &self.tty.file;
        let mut chunk = [0u8; 64];
        let wait = readable(fd, false);
        let until = Instant::now() + LATE_REPLY_DRAIN;
        while wait(until) {
            match f.read(&mut chunk) {
                Ok(n) if n > 0 => {
                    if chunk[..n].contains(&0x03) {
                        result = Answer::Cancelled;
                    }
                }
                _ => break,
            }
        }
        result
    }
}

impl Terminal for RawGuard<'_> {
    fn query(
        &mut self,
        request: &[u8],
        end: ReplyEnd,
        deadline: Instant,
    ) -> std::io::Result<Answer> {
        match self.spent {
            Some(Spent::Silent) => return Ok(Answer::Silent),
            Some(Spent::Cancelled) => return Ok(Answer::Cancelled),
            None => {}
        }
        let fd = self.tty.file.as_raw_fd();
        // What came before this query (typed keys, a late reply to an
        // earlier one) is not its answer.
        flush_input(fd)?;
        let mut result = if write_checked(|b| write_once(fd, b), request)? {
            let wait = readable(fd, true);
            let mut f = &self.tty.file;
            read_reply(end, || wait(deadline), |b| f.read(b))
        } else {
            Answer::Cancelled
        };
        if !matches!(result, Answer::Reply(_)) {
            result = self.drain(result);
        }
        let result = settle(result, STOP.load(Ordering::SeqCst));
        self.spent = match result {
            Answer::Reply(_) => None,
            Answer::Silent => Some(Spent::Silent),
            Answer::Cancelled => Some(Spent::Cancelled),
        };
        Ok(result)
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let fd = self.tty.file.as_raw_fd();
        if write_checked(|b| write_once(fd, b), bytes)? {
            Ok(())
        } else {
            self.spent = Some(Spent::Cancelled);
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        }
    }

    fn columns(&self) -> Option<u16> {
        // SAFETY: an all-zero `winsize` is a valid value for the call to fill.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is open and `size` is writable memory of the
        // type TIOCGWINSZ fills.
        let rc = unsafe { libc::ioctl(self.tty.file.as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
        (rc == 0 && size.ws_col > 0).then_some(size.ws_col)
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

    /// The terminal in raw mode until the guard is dropped. An error when
    /// the mode cannot be set, or while another guard in this process is
    /// alive (the signal flag and handlers are process-wide).
    pub fn raw(&self) -> std::io::Result<RawGuard<'_>> {
        if IN_RAW.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("the terminal is already in raw mode"));
        }
        let raw = Raw::enter(self.file.as_raw_fd())?;
        IN_RAW.store(true, Ordering::SeqCst);
        Ok(RawGuard {
            tty: self,
            _raw: raw,
            spent: None,
        })
    }

    /// Sends `OSC 11 ; ?` and waits up to `REPLY_TIMEOUT` for the answer.
    /// After anything but an answer the terminal is read for
    /// `LATE_REPLY_DRAIN` more and what comes is thrown away, whether the
    /// wait ended in silence or in a cancel; a cancel that arrives during
    /// that time still counts.
    pub fn ask_background(&self) -> std::io::Result<Answer> {
        let mut guard = self.raw()?;
        // The time limit counts from before the query is written, so a late
        // start of this process after the write (a busy machine) cannot make
        // an answer count that came later than the limit after the query.
        let until = Instant::now() + REPLY_TIMEOUT;
        guard.query(b"\x1b]11;?\x1b\\", ReplyEnd::Osc(b"11;"), until)
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
        let answer = || Answer::Reply(b"x".to_vec());
        assert_eq!(settle(answer(), true), Answer::Cancelled);
        assert_eq!(settle(Answer::Silent, true), Answer::Cancelled);
        assert_eq!(settle(answer(), false), answer());
        assert_eq!(settle(Answer::Silent, false), Answer::Silent);
    }

    // 이것을 실패시키는 것: 읽을 수 있다는데 0바이트(끊긴 터미널)를 끝으로 보지 않고 마감까지 되풀이하는 것,
    // 응답 앞에 친 글자 속에서 응답을 못 찾는 것, 0x03을 취소로 치지 않는 것, 입력 상한을 넘겨도 계속 읽는 것.
    #[test]
    fn reading_a_reply_ends_on_hang_up_cancel_answer_and_flood() {
        // A hung-up terminal is readable and gives nothing: one read, then silence.
        let mut reads = 0;
        let mut waits = 0;
        let got = read_reply(
            ReplyEnd::Osc(b"11;"),
            || {
                waits += 1;
                waits < 6
            },
            |_| {
                reads += 1;
                Ok(0)
            },
        );
        assert_eq!(got, Answer::Silent);
        assert_eq!(reads, 1);
        // Typed-ahead input, then the answer in two pieces.
        let mut pieces: Vec<&[u8]> = vec![b"ls\r\x1b]11;rgb:00", b"00/0000/0000\x07"];
        let got = read_reply(
            ReplyEnd::Osc(b"11;"),
            || true,
            |b| {
                let p = pieces.remove(0);
                b[..p.len()].copy_from_slice(p);
                Ok(p.len())
            },
        );
        assert_eq!(
            got,
            Answer::Reply(b"\x1b]11;rgb:0000/0000/0000\x07".to_vec())
        );
        // Ctrl-C.
        let got = read_reply(
            ReplyEnd::Osc(b"11;"),
            || true,
            |b| {
                b[0] = 0x03;
                Ok(1)
            },
        );
        assert_eq!(got, Answer::Cancelled);
        // Input that never makes an answer stops at the cap.
        let mut total = 0;
        let got = read_reply(
            ReplyEnd::Osc(b"11;"),
            || true,
            |b| {
                b.fill(b'x');
                total += b.len();
                // Bounded, so that a loop without the cap ends in an error.
                if total > 100 * ReplyEnd::Osc(b"11;").input_cap() {
                    return Err(Error::from_raw_os_error(libc::EIO));
                }
                Ok(b.len())
            },
        );
        assert_eq!(got, Answer::Silent);
        assert!(total <= ReplyEnd::Osc(b"11;").input_cap() + 64, "{total}");
        // Time ran out.
        assert_eq!(
            read_reply(ReplyEnd::Osc(b"11;"), || false, |_| Ok(0)),
            Answer::Silent
        );
    }

    // OSC 11 replies found as `osc11::find_reply` finds them: the generic
    // finder replaced it for `bingsu setup`.
    // 이것을 실패시키는 것: 앞 글자를 건너뛰지 않는 것, BEL이나 ESC \ 하나만 끝으로 보는 것, 첫 도입부가 아닌
    // 곳부터 읽는 것, 끝나지 않은 응답을 돌려주는 것.
    #[test]
    fn the_osc_finder_agrees_with_the_osc_11_finder() {
        let cases: &[&[u8]] = &[
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\",
            b"ls\r\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\tail",
            b"\x1b]11;rgb:00",
            b"\x1b]11;\x1b]11;rgb:1/2/3\x07",
            b"\x1b]10;rgb:1/2/3\x07\x1b]11;rgb:4/5/6\x07",
            b"\x1b]11;\\x\x07",
            b"\x1b]11;\x1b\x07",
            b"\x1b]1",
            b"",
            b"\x9d11;rgb:1/2/3\x9c",
        ];
        for &case in cases {
            assert_eq!(
                find_answer(case, ReplyEnd::Osc(b"11;")),
                bingsu_core::color::osc11::find_reply(case),
                "{case:?}"
            );
        }
    }

    // 이것을 실패시키는 것: 다른 최종 바이트의 CSI(화살표 키 ESC [ A)를 응답으로 받는 것, 앞의 다른 OSC를
    // 받는 것(접두를 보지 않음), 끝나지 않은 CSI를 돌려주는 것, 8비트 CSI(0x9b)를 받는 것.
    #[test]
    fn finders_skip_other_sequences() {
        let csi = ReplyEnd::Csi(b'R');
        assert_eq!(find_answer(b"\x1b[12;40R", csi), Some(&b"\x1b[12;40R"[..]));
        assert_eq!(
            find_answer(b"\x1b[Ax\x1b[1;5D\x1b[3;7R", csi),
            Some(&b"\x1b[3;7R"[..])
        );
        assert_eq!(find_answer(b"\x1b[12;4", csi), None);
        assert_eq!(find_answer(b"\x1b[\x1b[2;2R", csi), Some(&b"\x1b[2;2R"[..]));
        assert_eq!(find_answer(b"\x9b2;2R", csi), None);
        assert_eq!(find_answer(b"\x1b[ R", csi), Some(&b"\x1b[ R"[..]));
        let osc = ReplyEnd::Osc(b"11;");
        assert_eq!(
            find_answer(b"\x1b[5;1R\x1b]10;rgb:1/1/1\x07\x1b]11;rgb:2/2/2\x07", osc),
            Some(&b"\x1b]11;rgb:2/2/2\x07"[..])
        );
    }

    // 이것을 실패시키는 것: 응답 길이 상한을 보지 않는 것, 두 종류의 상한을 바꿔 쓰는 것.
    #[test]
    fn a_reply_over_its_cap_is_no_reply() {
        let mut long_csi = b"\x1b[".to_vec();
        long_csi.resize(CSI_REPLY_MAX - 1, b'1');
        long_csi.push(b'R');
        let mut too_long_csi = long_csi.clone();
        too_long_csi.insert(2, b'1');
        let mut long_osc = b"\x1b]11;".to_vec();
        long_osc.resize(REPLY_MAX - 1, b'0');
        long_osc.push(0x07);
        let mut too_long_osc = long_osc.clone();
        too_long_osc.insert(5, b'0');
        for (end, reply, fits) in [
            (ReplyEnd::Csi(b'R'), &long_csi, true),
            (ReplyEnd::Csi(b'R'), &too_long_csi, false),
            (ReplyEnd::Osc(b"11;"), &long_osc, true),
            (ReplyEnd::Osc(b"11;"), &too_long_osc, false),
        ] {
            let mut sent = 0;
            let got = read_reply(
                end,
                || true,
                |b| {
                    let n = (reply.len() - sent).min(b.len());
                    b[..n].copy_from_slice(&reply[sent..sent + n]);
                    sent += n;
                    Ok(n)
                },
            );
            let want = if fits {
                Answer::Reply(reply.clone())
            } else {
                Answer::Silent
            };
            assert_eq!(got, want, "{end:?} {}", reply.len());
        }
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

    /// Real pseudo-terminals: a parent test plays the terminal on the master
    /// side, and an ignored child test (`tty::tests::<name>`) takes the slave
    /// as its controlling terminal and asks through `Tty`. The child prints
    /// `ANSWER ...` lines, which the parent compares.
    mod pty {
        use super::super::*;
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::process::{Child, Command, Stdio};

        const CPR: &[u8] = b"\x1b[6n";
        const OSC11: &[u8] = b"\x1b]11;?\x1b\\";
        const WAIT: Duration = Duration::from_secs(5);

        pub(super) struct Pty {
            /// Other spawning tests wait, so no other child inherits this
            /// terminal's descriptors (held until `finish` reaps the child).
            _spawns: std::sync::MutexGuard<'static, ()>,
            master: Option<File>,
            child: Child,
            /// What the child wrote and `expect` has not matched yet.
            unread: Vec<u8>,
            /// Everything the child wrote.
            all: Vec<u8>,
        }

        /// Starts the child test `name` on a new pseudo-terminal of `cols`
        /// columns (0: unknown).
        #[allow(
            clippy::unnecessary_mut_passed,
            reason = "openpty takes the window size as *mut on macOS and *const on Linux"
        )]
        pub(super) fn start(name: &str, cols: u16) -> Pty {
            let spawns = crate::commands::sys::test_inherited_fd_lock();
            let (mut master, mut slave) = (-1, -1);
            // SAFETY: an all-zero `winsize` is valid; the columns are set below.
            let mut size: libc::winsize = unsafe { std::mem::zeroed() };
            size.ws_col = cols;
            size.ws_row = 24;
            assert_eq!(
                // SAFETY: two writable descriptor outputs; default termios.
                unsafe {
                    libc::openpty(
                        &mut master,
                        &mut slave,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut size,
                    )
                },
                0
            );
            // openpty sets no close-on-exec: without it the child would hold
            // the master too, and closing it here would not hang up.
            for fd in [master, slave] {
                // SAFETY: the descriptors openpty just made.
                let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                assert_eq!(rc, 0);
            }
            // SAFETY: a new descriptor, owned once from here on.
            let master = unsafe { File::from_raw_fd(master) };
            // SAFETY: as above.
            let slave = unsafe { OwnedFd::from_raw_fd(slave) };
            assert_eq!(
                // SAFETY: the test owns the master's description.
                unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
                0
            );
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("commands::tty::tests::pty::{name}"),
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .stdin(Stdio::from(slave))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            Pty {
                _spawns: spawns,
                master: Some(master),
                child,
                unread: Vec::new(),
                all: Vec::new(),
            }
        }

        impl Pty {
            /// Reads what the child wrote for up to `d`; `true` once `stop`
            /// says so of what is unread.
            fn pump(&mut self, d: Duration, stop: impl Fn(&[u8]) -> bool) -> bool {
                let until = Instant::now() + d;
                let mut buf = [0u8; 256];
                loop {
                    if stop(&self.unread) {
                        return true;
                    }
                    let Some(mut m) = self.master.as_ref() else {
                        return false;
                    };
                    match m.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            self.unread.extend_from_slice(&buf[..n]);
                            self.all.extend_from_slice(&buf[..n]);
                            continue;
                        }
                        // EAGAIN while the child runs, EIO once it is gone.
                        _ => {}
                    }
                    if Instant::now() >= until {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }

            /// Waits until the child wrote `want`, and forgets what came up
            /// to its end.
            pub(super) fn expect(&mut self, want: &[u8]) {
                let found = |b: &[u8]| b.windows(want.len()).any(|w| w == want);
                assert!(
                    self.pump(WAIT, found),
                    "no {:?} in {:?}",
                    want.escape_ascii().to_string(),
                    self.all.escape_ascii().to_string()
                );
                let at = self
                    .unread
                    .windows(want.len())
                    .position(|w| w == want)
                    .unwrap();
                self.unread.drain(..at + want.len());
            }

            /// Writes as the terminal would: typed keys, replies.
            pub(super) fn send(&mut self, bytes: &[u8]) {
                let fd = self.master.as_ref().unwrap().as_raw_fd();
                // SAFETY: the master is open and `bytes` is a valid slice.
                let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
                assert_eq!(usize::try_from(n).ok(), Some(bytes.len()));
            }

            /// Reads for `d` without answering.
            pub(super) fn idle(&mut self, d: Duration) {
                self.pump(d, |_| false);
            }

            /// Closes the master: the terminal goes away.
            pub(super) fn hang_up(&mut self) {
                self.master = None;
            }

            /// Waits for the child, which must pass. Its `ANSWER` lines, and
            /// everything it wrote to the terminal.
            pub(super) fn finish(mut self) -> (Vec<String>, Vec<u8>) {
                let until = Instant::now() + WAIT;
                let status = loop {
                    if let Some(status) = self.child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= until {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        panic!(
                            "the child did not end: {:?}",
                            self.all.escape_ascii().to_string()
                        );
                    }
                    self.idle(Duration::from_millis(5));
                };
                self.idle(Duration::ZERO);
                let mut out = String::new();
                let mut err = String::new();
                self.child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut out)
                    .unwrap();
                self.child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut err)
                    .unwrap();
                assert!(status.success(), "{out}\n{err}");
                let lines = out
                    .lines()
                    // libtest's "test ... " has no newline before the test's output.
                    .filter_map(|l| l.split_once("ANSWER "))
                    .map(|(_, a)| a.to_owned())
                    .collect();
                (lines, self.all)
            }
        }

        /// In the child: makes stdin (the slave) this process's controlling
        /// terminal, so `/dev/tty` is it.
        #[allow(
            clippy::useless_conversion,
            reason = "TIOCSCTTY is c_uint on macOS and the ioctl request type elsewhere"
        )]
        fn take_terminal() -> Tty {
            // SAFETY: setsid takes no arguments; a test process is no group leader.
            assert!(unsafe { libc::setsid() } >= 0);
            // SAFETY: fd 0 is the slave this process holds.
            assert_eq!(unsafe { libc::ioctl(0, libc::TIOCSCTTY.into(), 0) }, 0);
            Tty::open().expect("the pseudo-terminal is the controlling terminal")
        }

        fn mode() -> Vec<u8> {
            // SAFETY: all-zero storage for tcgetattr to fill.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: fd 0 is the terminal; `t` is writable.
            assert_eq!(unsafe { libc::tcgetattr(0, &mut t) }, 0);
            // SAFETY: a plain C structure read as its bytes.
            unsafe {
                std::slice::from_raw_parts(
                    (&t as *const libc::termios).cast::<u8>(),
                    size_of::<libc::termios>(),
                )
            }
            .to_vec()
        }

        /// Output flow control is on: the pseudo-terminal's default, which
        /// raw mode turns off and the guard puts back.
        fn ixon() -> bool {
            // SAFETY: all-zero storage for tcgetattr to fill.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: fd 0 is the terminal; `t` is writable.
            assert_eq!(unsafe { libc::tcgetattr(0, &mut t) }, 0);
            t.c_iflag & libc::IXON != 0
        }

        fn show(a: std::io::Result<Answer>) -> String {
            match a {
                Ok(Answer::Reply(r)) => format!("reply {}", r.escape_ascii()),
                Ok(Answer::Silent) => "silent".to_owned(),
                Ok(Answer::Cancelled) => "cancelled".to_owned(),
                Err(e) => format!("error {e}"),
            }
        }

        /// A query the test answers: a long deadline, so a slow machine
        /// does not turn the answer into silence.
        fn ask(g: &mut RawGuard<'_>, request: &[u8], end: ReplyEnd) -> String {
            show(g.query(request, end, Instant::now() + WAIT))
        }

        /// A query that is meant to stay unanswered: the real deadline.
        fn ask_unanswered(g: &mut RawGuard<'_>, request: &[u8], end: ReplyEnd) -> String {
            show(g.query(request, end, Instant::now() + REPLY_TIMEOUT))
        }

        fn say(line: &str) {
            println!("ANSWER {line}");
        }

        // 이것을 실패시키는 것: 응답 뒤 다음 질의를 막는 것, 화살표 키(ESC [ A)를 위치 보고로 받는 것(최종 바이트를
        // 보지 않음), OSC 10 응답을 OSC 11 답으로 받는 것(접두를 보지 않음), 끝난 뒤 터미널 설정을 되돌리지 않는 것.
        #[test]
        fn several_queries_in_one_guard() {
            let mut t = start("several_queries_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[3;1R");
            t.expect(CPR);
            t.send(b"\x1b[A\x1b[3;5R");
            t.expect(OSC11);
            t.send(b"\x1b]10;rgb:ffff/ffff/ffff\x07\x1b]11;rgb:0000/0000/0000\x1b\\");
            let (lines, _) = t.finish();
            assert_eq!(
                lines,
                [
                    "ixon before true",
                    r"reply \x1b[3;1R",
                    r"reply \x1b[3;5R",
                    r"reply \x1b]11;rgb:0000/0000/0000\x1b\\",
                    "restored true",
                ]
            );
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn several_queries_child() {
            let tty = take_terminal();
            let before = mode();
            say(&format!("ixon before {}", ixon()));
            {
                let mut g = tty.raw().unwrap();
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
                say(&ask(&mut g, OSC11, ReplyEnd::Osc(b"11;")));
            }
            say(&format!("restored {}", mode() == before));
        }

        // 이것을 실패시키는 것: 침묵 뒤에도 같은 guard로 다시 묻는 것(터미널이 세 번째 요청을 본다).
        #[test]
        fn silence_ends_the_guard_s_queries() {
            let mut t = start("silence_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[3;1R");
            t.expect(CPR);
            let (lines, all) = t.finish();
            assert_eq!(
                lines,
                [
                    r"reply \x1b[3;1R",
                    "silent",
                    "silent",
                    "silent at once true",
                    "restored true"
                ]
            );
            assert_eq!(all.windows(CPR.len()).filter(|w| *w == CPR).count(), 2);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn silence_child() {
            let tty = take_terminal();
            let before = mode();
            {
                let mut g = tty.raw().unwrap();
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
                say(&ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R')));
                let start = Instant::now();
                let third = ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R'));
                say(&third);
                say(&format!(
                    "silent at once {}",
                    start.elapsed() < LATE_REPLY_DRAIN
                ));
            }
            say(&format!("restored {}", mode() == before));
        }

        // 이것을 실패시키는 것: 취소 뒤에도 같은 guard로 다시 묻는 것, 취소 뒤 쓰기를 막는 것(시험 글자를 지우지
        // 못함), 끝난 뒤 터미널 설정을 되돌리지 않는 것.
        #[test]
        fn ctrl_c_ends_the_guard_s_queries_but_not_its_writes() {
            let mut t = start("ctrl_c_child", 80);
            t.expect(CPR);
            t.send(b"\x03");
            t.expect(b"\r\x1b[K");
            let (lines, all) = t.finish();
            assert_eq!(
                lines,
                ["cancelled", "cancelled", "write ok", "restored true"]
            );
            assert_eq!(all.windows(CPR.len()).filter(|w| *w == CPR).count(), 1);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn ctrl_c_child() {
            let tty = take_terminal();
            let before = mode();
            {
                let mut g = tty.raw().unwrap();
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
                say(&format!(
                    "write {}",
                    if g.write(b"\r\x1b[K").is_ok() {
                        "ok"
                    } else {
                        "refused"
                    }
                ));
            }
            say(&format!("restored {}", mode() == before));
        }

        // 이것을 실패시키는 것: 질의 전에 입력을 비우지 않는 것(앞 질의 뒤에 온 위치 보고를 다음 질의의 답으로 읽음).
        #[test]
        fn a_reply_queued_before_a_query_is_not_its_answer() {
            let mut t = start("stale_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[3;1R");
            t.idle(Duration::from_millis(100));
            t.send(b"\x1b[3;9R");
            t.expect(CPR);
            t.send(b"\x1b[4;1R");
            let (lines, _) = t.finish();
            assert_eq!(lines, [r"reply \x1b[3;1R", r"reply \x1b[4;1R"]);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn stale_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            // Waits until the stale report is queued, so the next query
            // starts with it in the input.
            let until = Instant::now() + WAIT;
            loop {
                let mut queued: libc::c_int = 0;
                // SAFETY: fd 0 is the terminal; `queued` is a writable int.
                assert_eq!(unsafe { libc::ioctl(0, libc::FIONREAD, &mut queued) }, 0);
                if queued > 0 {
                    break;
                }
                assert!(Instant::now() < until, "the stale report never came");
                std::thread::sleep(Duration::from_millis(2));
            }
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
        }

        // 이것을 실패시키는 것: 끊긴 터미널에서 마감까지 기다리거나 panic하는 것.
        #[test]
        fn a_hang_up_ends_the_query() {
            let mut t = start("hang_up_child", 80);
            t.expect(CPR);
            t.hang_up();
            let (lines, _) = t.finish();
            assert!(
                lines == ["cancelled", "ended true"] || lines == ["silent", "ended true"],
                "{lines:?}"
            );
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn hang_up_child() {
            // The hang-up's SIGHUP can come after the guard put the old
            // handler back; ignored, it does not end this process before it
            // reports. During the guard the guard's own handler takes it.
            // SAFETY: sets this process's SIGHUP disposition to ignore.
            unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
            let tty = take_terminal();
            let start = Instant::now();
            {
                let mut g = tty.raw().unwrap();
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            }
            say(&format!(
                "ended {}",
                start.elapsed() < Duration::from_secs(2)
            ));
        }

        // 이것을 실패시키는 것: guard가 살아 있는데 둘째 guard를 만드는 것, guard가 끝난 뒤 새 guard를 막는 것,
        // 새 guard에서 앞 guard의 정지 표시를 지우지 않는 것(SIGINT 뒤 새 guard의 질의가 바로 취소됨).
        #[test]
        fn one_guard_at_a_time_and_a_new_one_starts_clean() {
            let mut t = start("guards_child", 80);
            t.expect(CPR);
            t.expect(CPR);
            t.send(b"\x1b[5;1R");
            let (lines, _) = t.finish();
            assert_eq!(lines, ["second refused", "cancelled", r"reply \x1b[5;1R"]);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn guards_child() {
            let tty = take_terminal();
            let other = Tty::open().unwrap();
            {
                let mut g = tty.raw().unwrap();
                say(if other.raw().is_err() {
                    "second refused"
                } else {
                    "second made"
                });
                // SAFETY: raises SIGINT in this process; the guard's handler takes it.
                unsafe { libc::raise(libc::SIGINT) };
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            }
            let mut g = other.raw().unwrap();
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
        }

        // Ctrl-S before the guard stops the output. 이것을 실패시키는 것: raw 모드에서 IXON을 끄지 않는 것
        // (Linux: 질의의 쓰기가 Ctrl-Q까지 멈춰, 시험이 1.5초 뒤 Ctrl-Q를 보낼 때까지 걸림). macOS에서는 이 변이가
        // 살아남는다: 작은 쓰기는 멈춘 출력 큐에 들어가 돌아오고 질의는 마감에 silent로 끝나며, IXON을 꺼도
        // macOS는 이미 멈춘 출력을 다시 열지 않는다(Linux는 다시 열어 답이 온다).
        #[test]
        fn ctrl_s_before_the_guard_does_not_hold_a_query() {
            let mut t = start("ctrl_s_child", 80);
            t.send(b"\x13");
            if t.pump(Duration::from_secs(1), |b| {
                b.windows(CPR.len()).any(|w| w == CPR)
            }) {
                t.send(b"\x1b[2;2R");
            }
            t.idle(Duration::from_millis(500));
            if t.child.try_wait().unwrap().is_none() {
                // Ctrl-Q: lets a held write, or the child's exit (macOS waits
                // for stopped output on the last close), go on.
                t.send(b"\x11");
            }
            let (lines, _) = t.finish();
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(
                lines[0] == r"reply \x1b[2;2R" || lines[0] == "silent",
                "{lines:?}"
            );
            assert_eq!(lines[1], "within the deadline true", "{lines:?}");
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn ctrl_s_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            let start = Instant::now();
            say(&ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R')));
            say(&format!(
                "within the deadline {}",
                start.elapsed() < REPLY_TIMEOUT + LATE_REPLY_DRAIN + Duration::from_millis(700)
            ));
        }

        // 이것을 실패시키는 것: guard의 Drop이 터미널 설정을 되돌리지 않는 것(panic으로 끝난 질의 뒤 raw로 남음).
        #[test]
        fn a_panic_with_a_guard_alive_restores_the_terminal() {
            let t = start("panic_child", 80);
            let (lines, _) = t.finish();
            assert_eq!(lines, ["panicked true", "restored true"]);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn panic_child() {
            let tty = take_terminal();
            let before = mode();
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _g = tty.raw().unwrap();
                panic!("inside the guard");
            }));
            say(&format!("panicked {}", caught.is_err()));
            say(&format!("restored {}", mode() == before));
        }

        // 이것을 실패시키는 것: 0칸(모름)을 Some(0)으로 알리는 것, 다른 값을 읽는 것.
        #[test]
        fn columns_come_from_the_window_size() {
            for (cols, want) in [(132, "columns Some(132)"), (0, "columns None")] {
                let t = start("columns_child", cols);
                let (lines, _) = t.finish();
                assert_eq!(lines, [want]);
            }
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn columns_child() {
            let tty = take_terminal();
            let g = tty.raw().unwrap();
            say(&format!("columns {:?}", g.columns()));
        }
    }
}
