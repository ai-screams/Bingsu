//! The user's terminal, `/dev/tty` (not stdin or stdout, which may be
//! pipes): lines to ask a question, and queries the terminal answers itself,
//! such as the background color `OSC 11 ; ?` (`bingsu setup`) or the cursor
//! position `CSI 6 n` (`bingsu doctor`). Not on any prompt path.
//!
//! A query needs the terminal in a mode where the answer is not echoed and
//! is read without a newline: `Tty::raw` gives a guard ([`RawGuard`]) that
//! asks one or more queries ([`Terminal`]), only while this process is the
//! terminal's foreground job. The terminal is put back on these ways out:
//! the guard ends, Ctrl-C (read as the byte 0x03 because `ISIG` is off),
//! SIGTERM, SIGHUP or SIGINT from outside (a handler sets a flag and `select`
//! returns early), and a panic (the guard's `Drop`). Such a signal is raised
//! again once the old handlers are back, so by default the process still
//! ends with it; a signal the process ignores (SIGHUP under `nohup`) is left
//! ignored. Other fatal signals (SIGQUIT, SIGKILL, SIGSEGV...) are not
//! handled: they leave the terminal raw until `stty sane` or `reset`. One
//! guard at a time in a process: the flag and the handlers are process-wide.
//!
//! Nothing waits past a deadline. Raw mode turns output flow control (IXON)
//! off, so Ctrl-S cannot stop the output under a query, and writes are
//! non-blocking: a terminal that takes no output (its queue full) ends the
//! write at the deadline, and what is still queued is dropped
//! (`tcflush(TCOFLUSH)`) so half a request never reaches it later. The
//! flush cannot take back what the terminal (or, on Linux, the
//! pseudo-terminal's reading side) already holds, so a request that was
//! cut short, at the deadline, by a stop or by a write error, is followed by
//! bytes that end the sequence (`CANCEL`), which may take up to
//! `CANCEL_WAIT` (50 ms) past the deadline. One exception to the deadlines
//! follows: those three bytes stay queued for a terminal that stopped
//! reading, and when this process is the terminal's session leader (the
//! terminal ran `bingsu` itself) its exit waits until the terminal reads
//! them; a process started from a shell ends at once (macOS, measured).
//!
//! Replies carry no query number, so a reply must not be read as the answer
//! to another query. Before each query the input queue is discarded (a
//! Ctrl-C in it is kept as a cancel); once a query ends silent or cancelled,
//! the guard asks nothing more. A reply that
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
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long the terminal gets to answer. A hypothesis (200 ms): the setup
/// measurement of the answer time per terminal sets the final value.
pub const REPLY_TIMEOUT: Duration = Duration::from_millis(200);

/// How long a silent terminal is read after the time limit, so a late reply
/// is thrown away instead of reaching the command line. A starting value
/// (50 ms), to be set again from the same measurement.
pub const LATE_REPLY_DRAIN: Duration = Duration::from_millis(50);

/// How long one `Terminal::write` may wait for the terminal to take its
/// bytes, as a query waits for its reply.
pub const WRITE_TIMEOUT: Duration = REPLY_TIMEOUT;

/// Input typed between two queries that is looked through for a Ctrl-C (a
/// few keys at most; more is dropped unread by the query's flush).
const TYPED_CAP: usize = 256;

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
    /// Discards queued input (`tcflush(TCIFLUSH)`; a Ctrl-C in it, or a
    /// signal already taken, cancels without writing), writes `request` and
    /// reads one reply, both until `deadline`. On `Silent` or `Cancelled` it
    /// reads and drops input for `LATE_REPLY_DRAIN` more before it returns,
    /// and every later query returns the same without asking.
    fn query(
        &mut self,
        request: &[u8],
        end: ReplyEnd,
        deadline: Instant,
    ) -> std::io::Result<Answer>;
    /// Writes without asking (probe characters, `\r`, `ESC [ K`), also after
    /// a silent or cancelled query. `ErrorKind::Interrupted` when a signal
    /// cut the write short (later queries are cancelled), and
    /// `ErrorKind::TimedOut` when the terminal took nothing more for
    /// `WRITE_TIMEOUT` (what was queued is dropped, later queries are silent).
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Columns from `TIOCGWINSZ`; `None` when unknown or 0.
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

/// The one guard's place in this process. Taking it is one atomic step, so
/// two threads cannot both take it (a second guard would save the first
/// one's raw mode as the mode to restore); dropping it, with the guard or
/// after a failed `Tty::raw`, gives it back.
struct Slot;

impl Slot {
    fn take() -> std::io::Result<Self> {
        IN_RAW
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| Self)
            .map_err(|_| std::io::Error::other("the terminal is already in raw mode"))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        IN_RAW.store(false, Ordering::SeqCst);
    }
}

/// The signals the guard's handler took, one bit each (`1 << sig`): raised
/// again once the handlers they replaced are back.
static CAUGHT: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    CAUGHT.fetch_or(1u64 << (sig & 63), Ordering::SeqCst);
    STOP.store(true, Ordering::SeqCst);
}

const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The terminal as found (its mode and this descriptor's status flags), and
/// the signal handlers it replaced (`None`: the signal was ignored and is
/// left so, as under `nohup`). Putting them back is `Drop`.
struct Raw {
    fd: RawFd,
    saved: libc::termios,
    flags: libc::c_int,
    old: [Option<libc::sigaction>; 3],
}

/// Whether this process is the terminal's foreground job. Only that job may
/// change the terminal or read from it: a background job that ignores
/// SIGTTOU could change the mode under the foreground shell, and restoring
/// would throw away what the user typed.
fn foreground(fd: RawFd) -> bool {
    // SAFETY: `fd` is open; the call reads the terminal's group.
    let foreground = unsafe { libc::tcgetpgrp(fd) };
    // SAFETY: getpgrp takes no arguments and cannot fail.
    let own = unsafe { libc::getpgrp() };
    foreground == own
}

impl Raw {
    /// Switches `fd` to a mode with no echo, no line editing, no signal keys
    /// and no output flow control, where a read returns at once with what is
    /// there, and makes its writes non-blocking.
    fn enter(fd: RawFd) -> std::io::Result<Self> {
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is an open descriptor and `saved` is writable memory
        // of the type tcgetattr fills.
        if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: tcgetattr returned 0, so it wrote the whole structure.
        let saved = unsafe { saved.assume_init() };
        // SAFETY: `fd` is open; F_GETFL only reads its status flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
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
        let mut old: [Option<libc::sigaction>; 3] = [None; 3];
        for (slot, sig) in old.iter_mut().zip(SIGNALS) {
            // SAFETY: an all-zero `sigaction` is a valid starting value.
            let mut was: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a null new action only reads the current one into `was`.
            unsafe { libc::sigaction(sig, std::ptr::null(), &mut was) };
            if was.sa_sigaction == libc::SIG_IGN {
                continue;
            }
            // SAFETY: an all-zero `sigaction` is a valid starting value.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            // No SA_RESTART: `select` must return early (EINTR).
            act.sa_flags = 0;
            // SAFETY: `act.sa_mask` is a valid signal set to empty.
            unsafe { libc::sigemptyset(&mut act.sa_mask) };
            // SAFETY: `act` is initialised and `was` receives the old action.
            unsafe { libc::sigaction(sig, &act, &mut was) };
            *slot = Some(was);
        }
        let this = Self {
            fd,
            saved,
            flags,
            old,
        };
        // SAFETY: `fd` is open and `raw` is the structure tcgetattr filled.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // A terminal whose reader stopped taking output (a full queue) would
        // hold a blocking write past any deadline. `fd` is this process's own
        // open of /dev/tty, so the flag does not reach the shell's
        // descriptors, which share no open file description with it.
        // SAFETY: `fd` is open; F_SETFL changes only its status flags.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
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
        // Blocking again, for `Tty::line` and `Tty::say`.
        // SAFETY: as above; F_SETFL puts back the flags F_GETFL read.
        unsafe { libc::fcntl(fd, libc::F_SETFL, self.flags) };
        // The handlers go back after the terminal does.
        for (old, sig) in self.old.iter().zip(SIGNALS) {
            if let Some(old) = old {
                // SAFETY: `old` is the action `sigaction` returned for `sig`.
                unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) };
            }
        }
        // A signal the guard took now reaches the handler it was meant for:
        // by default the process ends with it (status 128 + the signal).
        let caught = CAUGHT.swap(0, Ordering::SeqCst);
        for sig in SIGNALS {
            if caught & (1u64 << sig) != 0 {
                // SAFETY: raises a signal in this process; its handler is the
                // one this process had before the guard.
                unsafe { libc::raise(sig) };
            }
        }
    }
}

/// How a write ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    All,
    /// A signal asked to stop. `partial`: the terminal took the first bytes.
    Stopped {
        partial: bool,
    },
    /// The terminal took no more before the deadline. `partial`: it took
    /// the first bytes.
    TimedOut {
        partial: bool,
    },
}

/// A write that failed. `partial`: the terminal took the first bytes.
#[derive(Debug)]
struct Failed {
    error: std::io::Error,
    partial: bool,
}

/// Writes all of `buf` through `write`, a non-blocking write. When the
/// terminal takes nothing now (`WouldBlock`), `wait()` waits until it can
/// (`false`: the deadline passed, or a stop was asked for). A write that a
/// signal interrupted (EINTR) is not simply tried again: if the signal asked
/// to stop, `Stopped`.
fn write_checked(
    mut write: impl FnMut(&[u8]) -> std::io::Result<usize>,
    mut wait: impl FnMut() -> bool,
    mut buf: &[u8],
) -> Result<Sent, Failed> {
    let stopped = || STOP.load(Ordering::SeqCst);
    let whole = buf.len();
    while !buf.is_empty() {
        let partial = buf.len() < whole;
        let failed = |error| Failed { error, partial };
        match write(buf) {
            Ok(0) => return Err(failed(std::io::Error::other("the terminal took no bytes"))),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if stopped() {
                    return Ok(Sent::Stopped { partial });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !wait() {
                    return Ok(if stopped() {
                        Sent::Stopped { partial }
                    } else {
                        Sent::TimedOut { partial }
                    });
                }
            }
            Err(e) => return Err(failed(e)),
        }
    }
    Ok(Sent::All)
}

/// Waits until `fd` can be read or `until` passes. `false`: time ran out or
/// a signal asked to stop (only when `stoppable`).
fn readable(fd: RawFd, stoppable: bool) -> impl Fn(Instant) -> bool {
    ready(fd, stoppable, false)
}

/// Waits until `fd` can be written (stoppable), as `readable`.
fn writable(fd: RawFd) -> impl Fn(Instant) -> bool {
    ready(fd, true, true)
}

/// Waits until `fd` can be written (`write`) or read, or `until` passes.
/// `select`, not `poll`: macOS `poll` does not support `/dev/tty` (it reports
/// the descriptor invalid at once).
#[allow(
    clippy::unnecessary_fallible_conversions,
    reason = "`tv_usec` is 32 bits on macOS and 64 on Linux; one spelling for both"
)]
fn ready(fd: RawFd, stoppable: bool, write: bool) -> impl Fn(Instant) -> bool {
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
        let (reads, writes): (*mut libc::fd_set, *mut libc::fd_set) = if write {
            (std::ptr::null_mut(), &mut set)
        } else {
            (&mut set, std::ptr::null_mut())
        };
        // SAFETY: `set` and `tv` are valid for the call; one set, no error set.
        let n = unsafe { libc::select(fd + 1, reads, writes, std::ptr::null_mut(), &mut tv) };
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

/// Drops what was written to the terminal and not sent yet: a request cut
/// short (half an escape sequence), or a whole one whose reply would later
/// land on the command line as typed text. The terminal's queue is shared,
/// so other output still waiting in it goes too.
fn discard_output(fd: RawFd) {
    for _ in 0..RESTORE_TRIES {
        // SAFETY: `fd` is the open terminal; the call only drops queued output.
        if unsafe { libc::tcflush(fd, libc::TCOFLUSH) } == 0
            || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return;
        }
    }
}

/// What ends an escape sequence the terminal began to read: CAN, then ST
/// (`ESC \`). xterm, VTE, Windows Terminal and ghostty drop a CSI or OSC
/// sequence in progress on CAN, and the ST that follows ends nothing. kitty
/// drops a CSI on CAN but ends an OSC only on BEL or ST: there the ST ends
/// it with a value that is no query (`?` and CAN; an OSC 11 value that is
/// no color puts the default background back). alacritty and wezterm end an
/// OSC on CAN and carry it out: when exactly `ESC ] 11 ; ?` had reached
/// them, that is a query whose reply comes late. BEL is no choice (it rings
/// outside a sequence), and neither is ST alone (every parser would carry
/// out the half OSC).
const CANCEL: &[u8] = b"\x18\x1b\\";

/// How long the bytes of `CANCEL` may wait for room in the terminal's queue.
const CANCEL_WAIT: Duration = Duration::from_millis(50);

/// After a request was cut short (the terminal took its first bytes, then
/// nothing more: a deadline, a stop or a write error), the terminal's parser
/// is inside an escape sequence and would read later output (a table, the
/// next question) as the rest of it. What is still queued is dropped first
/// (`discard_output`); what the terminal already holds stays, so `CANCEL` is
/// queued behind it, for the terminal to read next. The flush leaves room
/// for its three bytes (Linux and macOS took them at once right after
/// flushing a full queue), but another writer of the same terminal can fill
/// the queue again in between and leave room for only `CAN ESC`, and a
/// lone ESC would start a new sequence: the rest is written as room comes,
/// for at most `CANCEL_WAIT`; the wait for room ignores the stop flag (a
/// write that a signal interrupts while a stop is asked for still ends it).
/// Past that it is given up.
fn cancel_half_escape(fd: RawFd) {
    discard_output(fd);
    let wait = ready(fd, false, true);
    let until = Instant::now() + CANCEL_WAIT;
    #[cfg(test)]
    let takes = std::cell::Cell::new(test_terminal::CANCEL_TAKES.with(std::cell::Cell::take));
    let _ = write_checked(
        |b| {
            #[cfg(test)]
            if let Some(r) = test_terminal::cancel_write(&takes, b, |b| write_once(fd, b)) {
                return r;
            }
            write_once(fd, b)
        },
        || wait(until),
        CANCEL,
    );
}

/// A terminal that takes only part of a write, for tests: `send` and
/// `cancel_half_escape` consult these before each write and wait.
#[cfg(test)]
mod test_terminal {
    use super::STOP;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    /// What the terminal does once it took its bytes of a request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Then {
        /// Takes nothing more; the write waits to its deadline.
        Stall,
        /// The next write fails (EIO).
        Fail,
        /// Takes nothing more; the write tells `STOPPER` and waits until a
        /// signal asks to stop.
        Stop,
    }

    thread_local! {
        /// How many bytes of the next request the terminal takes, then what.
        pub(super) static ROOM: Cell<Option<(usize, Then)>> = const { Cell::new(None) };
        /// How many bytes of the next cancel the terminal takes in its first
        /// write; it then reports itself full once.
        pub(super) static CANCEL_TAKES: Cell<Option<usize>> = const { Cell::new(None) };
        /// Told once a request ending in `Then::Stop` took its bytes.
        pub(super) static STOPPER: RefCell<Option<std::sync::mpsc::Sender<()>>> =
            const { RefCell::new(None) };
    }

    /// A request write on `fd` under `room`: `None` writes as usual. Once
    /// the terminal took its bytes, this waits until the test's terminal
    /// says it read them (`read_by_the_terminal`), so the flush that follows
    /// cannot take them back (as a terminal that read the start of a request
    /// and then stopped).
    pub(super) fn write(
        room: &Cell<Option<(usize, Then)>>,
        fd: std::os::fd::RawFd,
        b: &[u8],
    ) -> Option<std::io::Result<usize>> {
        let (left, then) = room.get()?;
        Some(match (left, then) {
            (0, Then::Fail) => Err(std::io::Error::from_raw_os_error(libc::EIO)),
            (0, _) => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            _ => {
                let n = super::write_once(fd, &b[..b.len().min(left)]);
                if let Ok(n) = n {
                    room.set(Some((left - n, then)));
                    if n == left {
                        read_by_the_terminal(fd);
                    }
                }
                n
            }
        })
    }

    /// What the test's terminal sends once it read the start of a request.
    pub(super) const READ: u8 = b'!';

    /// Waits (at most 5 s) until the test's terminal sends `READ`, and reads
    /// it. Asking the pseudo-terminal does not do: on Linux written bytes
    /// leave its output queue at once, but a flush right after still drops
    /// those its reading side has not taken in yet.
    fn read_by_the_terminal(fd: std::os::fd::RawFd) {
        if super::ready(fd, false, false)(Instant::now() + Duration::from_secs(5)) {
            let mut byte = 0u8;
            // SAFETY: `fd` is the open terminal; one writable byte.
            let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            assert_eq!((n, byte), (1, READ), "the terminal said it read the start");
        }
    }

    /// A request's wait under `room`: `None` waits as usual.
    pub(super) fn wait(room: &Cell<Option<(usize, Then)>>, deadline: Instant) -> Option<bool> {
        match room.get()? {
            (0, Then::Stall) => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                Some(false)
            }
            (0, Then::Stop) => {
                if let Some(tell) = STOPPER.with(|s| s.borrow_mut().take()) {
                    let _ = tell.send(());
                }
                let until = Instant::now() + Duration::from_secs(5);
                while !STOP.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Some(false)
            }
            _ => None,
        }
    }

    /// A cancel write under `takes`: the first write takes that many bytes,
    /// the next finds no room; `None` writes as usual.
    pub(super) fn cancel_write(
        takes: &Cell<Option<usize>>,
        b: &[u8],
        mut write: impl FnMut(&[u8]) -> std::io::Result<usize>,
    ) -> Option<std::io::Result<usize>> {
        match takes.get()? {
            0 => {
                takes.set(None);
                Some(Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)))
            }
            n => {
                takes.set(Some(0));
                Some(write(&b[..b.len().min(n)]))
            }
        }
    }
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
    /// After `_raw`: the place is given back once the terminal is restored.
    _slot: Slot,
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

    /// Whether the input waiting now holds a Ctrl-C (0x03). Reads at most
    /// `TYPED_CAP` bytes without waiting; the query's flush drops the rest.
    fn typed_cancel(&self) -> bool {
        let mut f = &self.tty.file;
        let mut chunk = [0u8; 64];
        let mut read = 0;
        while read < TYPED_CAP {
            match f.read(&mut chunk) {
                Ok(n) if n > 0 => {
                    if chunk[..n].contains(&0x03) {
                        return true;
                    }
                    read += n;
                }
                _ => return false,
            }
        }
        false
    }

    /// Writes `bytes` until `deadline`. On a timeout what is still queued is
    /// dropped (`discard_output`). When the terminal took the first bytes and
    /// the write ended at the deadline, a stop or an error, the sequence it
    /// began is cancelled (`cancel_half_escape`) before the result returns.
    fn send(&self, bytes: &[u8], deadline: Instant) -> std::io::Result<Sent> {
        let fd = self.tty.file.as_raw_fd();
        let wait = writable(fd);
        #[cfg(test)]
        let room = std::cell::Cell::new(test_terminal::ROOM.with(std::cell::Cell::take));
        let written = write_checked(
            |b| {
                #[cfg(test)]
                if let Some(r) = test_terminal::write(&room, fd, b) {
                    return r;
                }
                write_once(fd, b)
            },
            || {
                #[cfg(test)]
                if let Some(go_on) = test_terminal::wait(&room, deadline) {
                    return go_on;
                }
                wait(deadline)
            },
            bytes,
        );
        let sent = match written {
            Ok(sent) => sent,
            Err(Failed { error, partial }) => {
                if partial {
                    cancel_half_escape(fd);
                }
                return Err(error);
            }
        };
        match sent {
            Sent::TimedOut { partial: true } | Sent::Stopped { partial: true } => {
                cancel_half_escape(fd);
            }
            Sent::TimedOut { partial: false } => discard_output(fd),
            Sent::All | Sent::Stopped { partial: false } => {}
        }
        Ok(sent)
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
        // A Ctrl-C typed since the last query is a cancel, not input to throw
        // away; and once a stop is recorded no request goes out, so no reply
        // can come after the terminal is restored.
        let mut result = if STOP.load(Ordering::SeqCst) || self.typed_cancel() {
            Answer::Cancelled
        } else {
            // What came before this query (typed keys, a late reply to an
            // earlier one) is not its answer.
            flush_input(fd)?;
            match self.send(request, deadline)? {
                Sent::All => {
                    let wait = readable(fd, true);
                    let mut f = &self.tty.file;
                    read_reply(end, || wait(deadline), |b| f.read(b))
                }
                Sent::Stopped { .. } => Answer::Cancelled,
                Sent::TimedOut { .. } => Answer::Silent,
            }
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
        match self.send(bytes, Instant::now() + WRITE_TIMEOUT)? {
            Sent::All => Ok(()),
            Sent::Stopped { .. } => {
                self.spent = Some(Spent::Cancelled);
                Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
            }
            Sent::TimedOut { .. } => {
                self.spent = Some(Spent::Silent);
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
        }
    }

    fn columns(&self) -> Option<u16> {
        columns_of(self.tty.file.as_fd())
    }
}

/// Columns of the terminal behind `fd` from `TIOCGWINSZ`; `None` when `fd`
/// is not a terminal (a pipe or a file: the call fails) or the terminal
/// reports 0. Asks nothing and changes no mode, so any descriptor will do,
/// standard output included (`bingsu explain`).
pub fn columns_of(fd: BorrowedFd<'_>) -> Option<u16> {
    // SAFETY: an all-zero `winsize` is a valid value for the call to fill.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is borrowed open for the call and `size` is
    // writable memory of the type TIOCGWINSZ fills.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
    // 이것을 실패시키는 것: 0칸을 받는 것(columns_come_from_the_window_size의 0칸 터미널).
    (rc == 0 && size.ws_col > 0).then_some(size.ws_col)
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
        foreground(file.as_raw_fd()).then_some(Self { file })
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
    /// this process is no longer the foreground job (it may have been moved
    /// to the background after `open`), when the mode cannot be set, or
    /// while another guard in this process is alive (the signal flag and
    /// handlers are process-wide).
    pub fn raw(&self) -> std::io::Result<RawGuard<'_>> {
        if !foreground(self.file.as_raw_fd()) {
            return Err(std::io::Error::other("not the terminal's foreground job"));
        }
        let slot = Slot::take()?;
        let raw = Raw::enter(self.file.as_raw_fd())?;
        Ok(RawGuard {
            tty: self,
            _raw: raw,
            _slot: slot,
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
            || true,
            b"abcdef",
        );
        assert!(matches!(got, Ok(Sent::All)));
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
            || true,
            b"abc",
        );
        STOP.store(false, Ordering::SeqCst);
        assert!(matches!(got, Ok(Sent::Stopped { partial: false })));
        assert_eq!(calls, 1);
        // 이것을 실패시키는 것: 일부를 쓴 뒤의 오류(Ok(0), EIO)를 partial false로 알리는 것(반쪽 escape를 끊지
        // 않음), 아무것도 못 쓴 오류를 true로 알리는 것.
        let got = write_checked(|_| Err(Error::from_raw_os_error(libc::EIO)), || true, b"x");
        assert!(matches!(got, Err(Failed { partial: false, .. })), "{got:?}");
        for after in [Ok(0), Err(Error::from_raw_os_error(libc::EIO))] {
            let mut after = Some(after);
            let mut calls = 0;
            let got = write_checked(
                |b| {
                    calls += 1;
                    if calls == 1 {
                        Ok(b.len() - 4)
                    } else {
                        after.take().unwrap()
                    }
                },
                || true,
                b"\x1b]11;?\x1b\\",
            );
            assert!(matches!(got, Err(Failed { partial: true, .. })), "{got:?}");
        }
        // 이것을 실패시키는 것: 터미널이 지금 받지 않을 때(WouldBlock) 기다리지 않고 오류로 끝내는 것, 기다림이
        // 마감으로 끝났는데 계속 쓰는 것, 마감과 정지 요청을 바꿔 알리는 것.
        let (mut calls, mut waits) = (0, 0);
        let got = write_checked(
            |b| {
                calls += 1;
                if calls == 1 {
                    Err(Error::from(ErrorKind::WouldBlock))
                } else {
                    Ok(b.len())
                }
            },
            || {
                waits += 1;
                true
            },
            b"abc",
        );
        assert!(matches!(got, Ok(Sent::All)));
        assert_eq!((calls, waits), (2, 1));
        for stop in [false, true] {
            let mut calls = 0;
            let got = write_checked(
                |_| {
                    calls += 1;
                    // Bounded, so that a loop that ignores the deadline ends in an error.
                    if calls > 3 {
                        return Err(Error::from_raw_os_error(libc::EIO));
                    }
                    Err(Error::from(ErrorKind::WouldBlock))
                },
                || {
                    STOP.store(stop, Ordering::SeqCst);
                    false
                },
                b"abc",
            );
            STOP.store(false, Ordering::SeqCst);
            let want = if stop {
                Sent::Stopped { partial: false }
            } else {
                Sent::TimedOut { partial: false }
            };
            assert!(matches!(got, Ok(s) if s == want), "{got:?}");
            assert_eq!(calls, 1);
        }
        // 이것을 실패시키는 것: 일부를 쓴 뒤 마감·정지로 끝났는데 partial을 false로 알리는 것(반쪽 escape를 끊지
        // 않음), 아무것도 쓰지 못했는데 true로 알리는 것(쓰지 않은 요청 뒤에 CAN을 보냄; 바로 위의 false 칸).
        for (stop, interrupted) in [(false, false), (true, false), (true, true)] {
            let mut calls = 0;
            let got = write_checked(
                |b| {
                    calls += 1;
                    match calls {
                        1 => Ok(b.len() - 4),
                        2 if interrupted => {
                            STOP.store(true, Ordering::SeqCst);
                            Err(Error::from(ErrorKind::Interrupted))
                        }
                        2 => Err(Error::from(ErrorKind::WouldBlock)),
                        _ => Err(Error::from_raw_os_error(libc::EIO)),
                    }
                },
                || {
                    STOP.store(stop, Ordering::SeqCst);
                    false
                },
                b"\x1b]11;?\x1b\\",
            );
            STOP.store(false, Ordering::SeqCst);
            let want = if stop {
                Sent::Stopped { partial: true }
            } else {
                Sent::TimedOut { partial: true }
            };
            assert!(matches!(got, Ok(s) if s == want), "{got:?}");
            assert_eq!(calls, 2);
        }
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
            /// The test's own copy of the slave: the terminal's mode stays
            /// readable after the child ends (a last close would reset it).
            /// macOS revokes the slave when the child, the session's
            /// controlling process, ends; there the master reads the same
            /// mode.
            slave: OwnedFd,
            /// The slave's mode before the child started.
            mode_before: Vec<u8>,
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
            let keep = slave.try_clone().unwrap();
            let mode_before = mode_of(if cfg!(target_os = "macos") {
                master.as_raw_fd()
            } else {
                keep.as_raw_fd()
            });
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
                slave: keep,
                mode_before,
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

            /// Waits up to `limit` for the child to end without reading the
            /// master, as a terminal that stopped taking output. `true`: it
            /// ended.
            pub(super) fn wait_unread(&mut self, limit: Duration) -> bool {
                let until = Instant::now() + limit;
                while Instant::now() < until {
                    if self.child.try_wait().unwrap().is_some() {
                        return true;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                false
            }

            /// Closes the master: the terminal goes away.
            pub(super) fn hang_up(&mut self) {
                self.master = None;
            }

            /// Waits for the child, which must pass. Its `ANSWER` lines, and
            /// everything it wrote to the terminal.
            pub(super) fn finish(mut self) -> (Vec<String>, Vec<u8>) {
                let (lines, status, out, err) = self.end();
                assert!(status.success(), "{lines:?} {out}\n{err}");
                (lines, self.all)
            }

            /// Whether the terminal's mode now is the one from before the
            /// child started.
            pub(super) fn mode_restored(&self) -> bool {
                let fd = if cfg!(target_os = "macos") {
                    self.master.as_ref().unwrap().as_raw_fd()
                } else {
                    self.slave.as_raw_fd()
                };
                mode_of(fd) == self.mode_before
            }

            /// Waits for the child. Its `ANSWER` lines, how it ended, and its
            /// whole output and error output.
            pub(super) fn end(
                &mut self,
            ) -> (Vec<String>, std::process::ExitStatus, String, String) {
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
                let lines = out
                    .lines()
                    // libtest's "test ... " has no newline before the test's output.
                    .filter_map(|l| l.split_once("ANSWER "))
                    .map(|(_, a)| a.to_owned())
                    .collect();
                (lines, status, out, err)
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
            mode_of(0)
        }

        /// The terminal mode on `fd`, as bytes.
        fn mode_of(fd: RawFd) -> Vec<u8> {
            // SAFETY: all-zero storage for tcgetattr to fill.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `fd` is a terminal; `t` is writable.
            assert_eq!(unsafe { libc::tcgetattr(fd, &mut t) }, 0);
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

        // More queued input than the Ctrl-C check reads (`TYPED_CAP`), then a
        // stale report. 이것을 실패시키는 것: 질의 전에 입력을 비우지 않는 것(남은 입력과 앞 질의 뒤에 온 위치 보고를
        // 다음 질의가 읽음).
        #[test]
        fn a_reply_queued_before_a_query_is_not_its_answer() {
            let mut t = start("stale_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[3;1R");
            t.idle(Duration::from_millis(100));
            t.send(&[b'z'; 2 * TYPED_CAP]);
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
            wait_queued(2 * TYPED_CAP + b"\x1b[3;9R".len());
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
        // 새 guard에서 앞 guard의 정지 표시를 지우지 않는 것(SIGINT 뒤 새 guard의 질의가 바로 취소됨), 정지가
        // 기록된 뒤에도 요청을 쓰는 것(터미널이 요청을 둘 봄), 받은 신호를 원래 처리기로 다시 올리지 않는 것,
        // 원래 처리기를 되돌리지 않는 것(다시 올린 신호가 guard의 처리기로 감).
        #[test]
        fn one_guard_at_a_time_and_a_new_one_starts_clean() {
            let mut t = start("guards_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[5;1R");
            let (lines, all) = t.finish();
            assert_eq!(
                lines,
                [
                    "second refused",
                    "cancelled",
                    "the old handler ran 1",
                    r"reply \x1b[5;1R"
                ]
            );
            assert_eq!(all.windows(CPR.len()).filter(|w| *w == CPR).count(), 1);
        }

        static OLD_HANDLER_RAN: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);

        extern "C" fn count_signal(_: libc::c_int) {
            OLD_HANDLER_RAN.fetch_add(1, Ordering::SeqCst);
        }

        /// Gives `sig` this test's own handler, as an application would have.
        fn hook(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
            // SAFETY: an all-zero `sigaction` is a valid starting value.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = handler as usize;
            // SAFETY: `act` is initialised; the old action is not wanted.
            let rc = unsafe { libc::sigaction(sig, &act, std::ptr::null_mut()) };
            assert_eq!(rc, 0);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn guards_child() {
            hook(libc::SIGINT, count_signal);
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
            say(&format!(
                "the old handler ran {}",
                OLD_HANDLER_RAN.load(Ordering::SeqCst)
            ));
            let mut g = other.raw().unwrap();
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
        }

        // A signal the guard took ends the process the way it would have,
        // after the terminal is back. 이것을 실패시키는 것: 신호를 다시 올리지 않는 것(정상 종료), 터미널을
        // 되돌리기 전에 다시 올리는 것(raw인 채 죽음).
        #[test]
        fn a_signal_ends_the_process_after_the_terminal_is_restored() {
            use std::os::unix::process::ExitStatusExt;
            let mut t = start("signal_child", 80);
            let (lines, status, out, err) = t.end();
            assert_eq!(status.signal(), Some(libc::SIGTERM), "{out}\n{err}");
            assert_eq!(lines, ["cancelled"]);
            assert!(t.mode_restored());
            assert!(
                !t.all.windows(CPR.len()).any(|w| w == CPR),
                "no request after the stop"
            );
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn signal_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            // SAFETY: raises SIGTERM in this process; the guard's handler takes it.
            unsafe { libc::raise(libc::SIGTERM) };
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            drop(g);
            say("still running");
        }

        /// The handler `sig` has now.
        fn disposition(sig: libc::c_int) -> libc::sighandler_t {
            // SAFETY: an all-zero `sigaction` is a valid value to fill.
            let mut was: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a null new action only reads the current one.
            let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &mut was) };
            assert_eq!(rc, 0);
            was.sa_sigaction
        }

        // A signal the process ignores (SIGHUP under nohup) stays ignored.
        // 이것을 실패시키는 것: 무시하던 신호에도 guard의 처리기를 거는 것(그 신호로 질의가 취소되고, guard
        // 동안 처리기가 바뀜).
        #[test]
        fn an_ignored_signal_stays_ignored() {
            let mut t = start("ignored_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[6;1R");
            let (lines, _) = t.finish();
            assert_eq!(
                lines,
                [
                    "ignored during true",
                    r"reply \x1b[6;1R",
                    "ignored after true"
                ]
            );
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn ignored_child() {
            // SAFETY: sets this process's SIGHUP disposition to ignore.
            unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
            let tty = take_terminal();
            {
                let mut g = tty.raw().unwrap();
                say(&format!(
                    "ignored during {}",
                    disposition(libc::SIGHUP) == libc::SIG_IGN
                ));
                // SAFETY: raises SIGHUP in this process, which ignores it.
                unsafe { libc::raise(libc::SIGHUP) };
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            }
            say(&format!(
                "ignored after {}",
                disposition(libc::SIGHUP) == libc::SIG_IGN
            ));
        }

        // 이것을 실패시키는 것: 다음 질의의 입력 비우기가 질의 사이에 누른 Ctrl-C를 버리는 것(사용자의 취소가
        // 사라지고 요청이 또 나감).
        #[test]
        fn ctrl_c_between_queries_cancels_the_next() {
            let mut t = start("ctrl_c_between_child", 80);
            t.expect(CPR);
            t.send(b"\x1b[3;1R");
            t.idle(Duration::from_millis(100));
            t.send(b"\x03");
            let (lines, all) = t.finish();
            assert_eq!(lines, [r"reply \x1b[3;1R", "cancelled"]);
            assert_eq!(all.windows(CPR.len()).filter(|w| *w == CPR).count(), 1);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn ctrl_c_between_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            wait_queued(1);
            say(&ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R')));
        }

        /// Waits until the terminal has `bytes` of input queued for this
        /// process.
        fn wait_queued(bytes: usize) {
            let until = Instant::now() + WAIT;
            loop {
                let mut queued: libc::c_int = 0;
                // SAFETY: fd 0 is the terminal; `queued` is a writable int.
                assert_eq!(unsafe { libc::ioctl(0, libc::FIONREAD, &mut queued) }, 0);
                if usize::try_from(queued).unwrap_or(0) >= bytes {
                    return;
                }
                assert!(Instant::now() < until, "nothing came");
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        // A job moved to the background after it opened the terminal.
        // 이것을 실패시키는 것: raw()에서 전경 작업인지 다시 보지 않는 것(SIGTTOU를 무시하는 배경 작업이 남의
        // 터미널을 raw로 바꿈).
        #[test]
        fn a_background_job_gets_no_guard() {
            let t = start("background_child", 80);
            let (lines, _) = t.finish();
            assert_eq!(lines, ["background refused true"]);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn background_child() {
            use std::os::unix::process::CommandExt;
            let tty = take_terminal();
            // SAFETY: sets this process's SIGTTOU disposition to ignore.
            unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
            let mut other = Command::new("sleep")
                .arg("30")
                .process_group(0)
                .stdin(Stdio::null())
                .spawn()
                .unwrap();
            let group = libc::pid_t::try_from(other.id()).unwrap();
            // SAFETY: fd 0 is this session's terminal; `group` is a group in it.
            assert_eq!(unsafe { libc::tcsetpgrp(0, group) }, 0);
            say(&format!("background refused {}", tty.raw().is_err()));
            // SAFETY: getpgrp takes no arguments and cannot fail.
            let own = unsafe { libc::getpgrp() };
            // SAFETY: as above, back to this process's own group.
            assert_eq!(unsafe { libc::tcsetpgrp(0, own) }, 0);
            other.kill().unwrap();
            other.wait().unwrap();
        }

        // Ctrl-S before the guard stops the output. 이것을 실패시키는 것: raw 모드에서 IXON을 끄지 않는 것
        // (Linux: 출력이 다시 열리지 않아 쓰기가 마감에 걸리고 답이 오지 않음). macOS에서는 이 변이가 살아남는다:
        // IXON을 꺼도 macOS는 이미 멈춘 출력을 다시 열지 않아 두 경우 모두 마감에 silent로 끝난다. 마감을 넘지
        // 않는 것은 non-blocking 쓰기가 지킨다.
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
            if cfg!(target_os = "linux") {
                assert_eq!(lines, [r"reply \x1b[2;2R"]);
            } else {
                assert_eq!(lines, ["silent", "within the deadline true"]);
            }
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn ctrl_s_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            if cfg!(target_os = "linux") {
                // Output starts again with IXON off, so the reply comes.
                say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
            } else {
                let start = Instant::now();
                say(&ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R')));
                say(&format!(
                    "within the deadline {}",
                    start.elapsed() < REPLY_TIMEOUT + LATE_REPLY_DRAIN + Duration::from_millis(700)
                ));
            }
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

        /// Fills the terminal's output queue through a second, non-blocking
        /// open of /dev/tty, as a terminal that stopped reading would leave
        /// it. The bytes written. Full means the terminal took nothing for
        /// `FULL_QUIET`, not the first EAGAIN: a Linux pseudo-terminal moves
        /// written bytes on between its two buffers afterwards, and room came
        /// back for about 1.8 KB after a first EAGAIN at 10,240 bytes (arm64).
        /// 이것을 실패시키는 것: 첫 EAGAIN에서 멈추는 것(나중에 난 자리로 질의의 요청이 나가, 큐 시험이 가끔
        /// 실패함: arm64 컨테이너 40번 중 4번).
        fn fill_output() -> usize {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let filler = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open("/dev/tty")
                .unwrap();
            let chunk = [b'x'; 4096];
            let mut filled = 0;
            let mut quiet = Instant::now();
            loop {
                let mut took = 0;
                for size in [chunk.len(), 512, 1] {
                    loop {
                        match (&filler).write(&chunk[..size]) {
                            Ok(n) => took += n,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => panic!("{e}"),
                        }
                        assert!(filled + took < 64 << 20, "the queue never filled");
                    }
                }
                filled += took;
                if took > 0 {
                    quiet = Instant::now();
                } else if quiet.elapsed() >= FULL_QUIET {
                    return filled;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        /// How long the terminal must take nothing before the queue counts as
        /// full.
        const FULL_QUIET: Duration = Duration::from_millis(200);

        /// The status flags the guard changes (`O_NONBLOCK`). The rest are not
        /// compared: macOS adds a "written" bit (0x10000) to `F_GETFL` once
        /// the descriptor took a write.
        fn changed_flags(fd: RawFd) -> libc::c_int {
            // SAFETY: `fd` is open; F_GETFL only reads its status flags.
            unsafe { libc::fcntl(fd, libc::F_GETFL) & libc::O_NONBLOCK }
        }

        fn nonblocking(fd: RawFd) -> bool {
            // SAFETY: `fd` is open; F_GETFL only reads its status flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            flags & libc::O_NONBLOCK != 0
        }

        // A terminal that stopped taking output. 이것을 실패시키는 것: raw 모드에서 쓰기를 non-blocking으로
        // 두지 않는 것(질의의 쓰기가 터미널이 큐를 비울 때까지 멈춤: 시험이 3초 뒤 master를 읽을 때까지 걸림),
        // 마감에 남은 출력을 버리지 않는 것(터미널이 나중에 채운 바이트를 모두 받음), 셸과 같은 open file
        // description을 쓰는 것(셸의 표준 입력에 O_NONBLOCK이 샘), guard가 끝난 뒤 상태 플래그를 되돌리지 않는 것.
        #[test]
        fn a_full_output_queue_does_not_hold_a_query() {
            let mut t = start("full_queue_query_child", 80);
            let ended = t.wait_unread(Duration::from_secs(3));
            let (lines, all) = t.finish();
            assert!(ended, "{lines:?}");
            assert_eq!(lines.len(), 5, "{lines:?}");
            assert_eq!(
                &lines[1..],
                [
                    "silent within the deadline true",
                    "stdin nonblocking false",
                    "flags restored true",
                    "restored true"
                ]
            );
            let filled: usize = lines[0].strip_prefix("filled ").unwrap().parse().unwrap();
            assert!(
                all.len() < filled,
                "{} of {filled} reached the terminal",
                all.len()
            );
            assert!(!all.contains(&0x1b), "no request reached the terminal");
            // 이것을 실패시키는 것: 요청을 한 바이트도 못 썼는데 CANCEL을 보내는 것.
            assert!(!all.contains(&CANCEL[0]), "a cancel without a request");
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn full_queue_query_child() {
            let tty = take_terminal();
            let before = mode();
            let flags = changed_flags(tty.file.as_raw_fd());
            {
                let mut g = tty.raw().unwrap();
                say(&format!("filled {}", fill_output()));
                let start = Instant::now();
                let answer = ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R'));
                say(&format!(
                    "{answer} within the deadline {}",
                    start.elapsed() < REPLY_TIMEOUT + LATE_REPLY_DRAIN + Duration::from_millis(700)
                ));
                say(&format!("stdin nonblocking {}", nonblocking(0)));
            }
            say(&format!(
                "flags restored {}",
                changed_flags(tty.file.as_raw_fd()) == flags
            ));
            say(&format!("restored {}", mode() == before));
        }

        // A terminal that is slow, not stuck: the query waits for room and
        // gets through. 이것을 실패시키는 것: 쓸 자리를 읽을 수 있음으로 기다리는 것(select의 읽기 집합; 요청이
        // 끝내 나가지 않아 마감에 silent).
        #[test]
        fn a_queue_that_drains_in_time_lets_the_query_through() {
            let mut t = start("draining_queue_child", 80);
            assert!(!t.wait_unread(Duration::from_millis(300)));
            t.expect(CPR);
            t.send(b"\x1b[7;1R");
            let (lines, _) = t.finish();
            assert_eq!(lines, [r"reply \x1b[7;1R"]);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn draining_queue_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            fill_output();
            say(&ask(&mut g, CPR, ReplyEnd::Csi(b'R')));
        }

        // 터미널이 요청의 앞 3바이트(`ESC ] 1`)만 읽고 출력을 받지 않으면, 마감 뒤에 CANCEL(`CAN ESC \`)이 따라와
        // 터미널이 읽은 바이트의 끝이 되고, 요청의 나머지는 오지 않는다. 이것을 실패시키는 것: CANCEL을 보내지 않는 것
        // (터미널은 OSC 문자열 안에 남음), 앞부분이 나간 시간 초과에서 cancel_half_escape를 부르지 않는 것.
        #[test]
        fn a_request_cut_short_is_cancelled() {
            let mut t = start("cut_request_child", 80);
            t.expect(&OSC11[..3]);
            t.send(&[test_terminal::READ]);
            t.expect(CANCEL);
            let (lines, all) = t.finish();
            assert_eq!(lines, ["silent"]);
            assert!(all.ends_with(CANCEL), "{}", all.escape_ascii());
            assert!(
                !all.windows(2).any(|w| w == b";?"),
                "{}",
                all.escape_ascii()
            );
        }

        // 쓰기가 오류로 끝나도 같다: 터미널이 앞부분을 받은 뒤 쓰기가 EIO로 끝나면, 오류를 돌려주기 전에 CANCEL을
        // 보낸다. 질의(OSC 11)와 Terminal::write 둘 다. 이것을 실패시키는 것: 일부를 쓴 뒤 오류로 끝난 쓰기에서
        // cancel_half_escape를 부르지 않는 것(`?`로 바로 돌아감).
        #[test]
        fn a_write_that_fails_after_its_start_is_cancelled() {
            let mut t = start("cut_by_error_child", 80);
            t.expect(&OSC11[..3]);
            t.send(&[test_terminal::READ]);
            t.expect(CANCEL);
            t.expect(b"\x1b[31");
            t.send(&[test_terminal::READ]);
            t.expect(CANCEL);
            let (lines, all) = t.finish();
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(lines[0].starts_with("error "), "{lines:?}");
            assert_eq!(lines[1], "write failed true");
            assert!(all.ends_with(CANCEL), "{}", all.escape_ascii());
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn cut_by_error_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            test_terminal::ROOM.with(|r| r.set(Some((3, test_terminal::Then::Fail))));
            say(&ask_unanswered(&mut g, OSC11, ReplyEnd::Osc(b"11;")));
            test_terminal::ROOM.with(|r| r.set(Some((4, test_terminal::Then::Fail))));
            say(&format!(
                "write failed {}",
                g.write(b"\x1b[31mred").is_err()
            ));
        }

        // CANCEL의 쓰기가 짧아도(다른 writer가 flush 뒤 큐를 다시 채워 `CAN ESC`만 들어감) 자리가 나면 나머지를
        // 마저 써, 터미널이 읽은 바이트가 `CAN ESC \`로 끝난다(ESC 하나가 매달리지 않음). 이것을 실패시키는 것:
        // CANCEL을 write 한 번으로만 쓰는 것.
        #[test]
        fn a_short_cancel_is_finished() {
            let mut t = start("short_cancel_child", 80);
            t.expect(&OSC11[..3]);
            t.send(&[test_terminal::READ]);
            t.expect(CANCEL);
            let (lines, all) = t.finish();
            assert_eq!(lines, ["silent"]);
            assert!(all.ends_with(CANCEL), "{}", all.escape_ascii());
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn short_cancel_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            test_terminal::ROOM.with(|r| r.set(Some((3, test_terminal::Then::Stall))));
            test_terminal::CANCEL_TAKES.with(|c| c.set(Some(2)));
            say(&ask_unanswered(&mut g, OSC11, ReplyEnd::Osc(b"11;")));
        }

        // 신호로 멈춘 쓰기도 같다: 터미널이 앞 3바이트를 받은 뒤 SIGTERM이 오면 CANCEL이 따라오고, 프로세스는 터미널을
        // 되돌린 뒤 그 신호로 끝난다. 신호는 hook이 "앞부분을 썼다"고 알린 뒤에 보내고, 쓰기는 시간이 아니라 정지를
        // 기다리므로 늘 Stopped로 끝난다. 이것을 실패시키는 것: 쓰기가 Stopped로 끝났을 때 cancel_half_escape를
        // 부르지 않는 것.
        #[test]
        fn a_request_cut_short_by_a_signal_is_cancelled() {
            use std::os::unix::process::ExitStatusExt;
            let mut t = start("cut_by_signal_child", 80);
            t.expect(&OSC11[..3]);
            t.send(&[test_terminal::READ]);
            t.expect(CANCEL);
            let (lines, status, out, err) = t.end();
            assert_eq!(status.signal(), Some(libc::SIGTERM), "{out}\n{err}");
            assert_eq!(lines, ["cancelled"]);
            assert!(t.all.ends_with(CANCEL), "{}", t.all.escape_ascii());
            assert!(t.mode_restored());
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn cut_by_signal_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            // The stop comes once the terminal took the first 3 bytes, while
            // the write waits for room (it waits for the stop, not for time).
            let (tell, told) = std::sync::mpsc::channel();
            test_terminal::STOPPER.with(|s| *s.borrow_mut() = Some(tell));
            test_terminal::ROOM.with(|r| r.set(Some((3, test_terminal::Then::Stop))));
            let stop = std::thread::spawn(move || {
                told.recv().unwrap();
                // SAFETY: getpid takes no arguments and cannot fail.
                let me = unsafe { libc::getpid() };
                // SAFETY: sends SIGTERM to this process; the guard's handler takes it.
                unsafe { libc::kill(me, libc::SIGTERM) };
            });
            say(&ask_unanswered(&mut g, OSC11, ReplyEnd::Osc(b"11;")));
            stop.join().unwrap();
            drop(g);
            say("still running");
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn cut_request_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            test_terminal::ROOM.with(|r| r.set(Some((3, test_terminal::Then::Stall))));
            say(&ask_unanswered(&mut g, OSC11, ReplyEnd::Osc(b"11;")));
        }

        // 이것을 실패시키는 것: Terminal::write가 마감 없이 막히는 것, 마감에 걸린 쓰기 뒤에도 질의하는 것(터미널이
        // 받지 않는 요청을 또 씀).
        #[test]
        fn a_full_output_queue_does_not_hold_a_write() {
            let mut t = start("full_queue_write_child", 80);
            let ended = t.wait_unread(Duration::from_secs(3));
            let (lines, _) = t.finish();
            assert!(ended, "{lines:?}");
            assert_eq!(
                lines,
                ["timed out within the deadline true", "silent at once true"]
            );
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn full_queue_write_child() {
            let tty = take_terminal();
            let mut g = tty.raw().unwrap();
            fill_output();
            let start = Instant::now();
            let kind = g.write(b"abc").err().map(|e| e.kind());
            say(&format!(
                "{} within the deadline {}",
                if kind == Some(std::io::ErrorKind::TimedOut) {
                    "timed out"
                } else {
                    "written"
                },
                start.elapsed() < WRITE_TIMEOUT + Duration::from_millis(700)
            ));
            let start = Instant::now();
            let answer = ask_unanswered(&mut g, CPR, ReplyEnd::Csi(b'R'));
            say(&format!(
                "{answer} at once {}",
                start.elapsed() < LATE_REPLY_DRAIN
            ));
        }

        // Two threads ask for a guard at the same moment, many times: one
        // gets it. 이것을 실패시키는 것: 자리 잡기를 읽기와 쓰기 둘로 나누는 것(두 스레드가 함께 비어 있음을
        // 보고 둘 다 guard를 얻음; 확률적으로 잡히며, 측정은 PR 본문).
        #[test]
        fn two_threads_get_one_guard() {
            let t = start("two_threads_child", 80);
            let (lines, _) = t.finish();
            assert_eq!(lines, ["rounds 200, not exactly one guard 0"]);
        }

        #[test]
        #[ignore = "child: asks on a pseudo-terminal"]
        fn two_threads_child() {
            let tty = take_terminal();
            let mut bad = 0;
            for _ in 0..200 {
                let start = std::sync::Barrier::new(2);
                let tried = std::sync::Barrier::new(2);
                let got = std::thread::scope(|s| {
                    let one = || {
                        start.wait();
                        let guard = tty.raw();
                        // Both hold what they got until both have tried.
                        tried.wait();
                        guard.is_ok()
                    };
                    let a = s.spawn(one);
                    let b = s.spawn(one);
                    [a.join().unwrap(), b.join().unwrap()]
                });
                if got.iter().filter(|ok| **ok).count() != 1 {
                    bad += 1;
                }
            }
            say(&format!("rounds 200, not exactly one guard {bad}"));
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
