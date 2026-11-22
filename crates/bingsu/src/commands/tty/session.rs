//! A full-screen session on the user's terminal, for `bingsu setup`'s
//! editor. Not on any prompt path.
//!
//! [`Tty::full_screen`] takes the query guard's raw mode (no echo, no line
//! editing, no signal keys, no output flow control, non-blocking writes;
//! `ICRNL` stays, so Enter comes as `\n`, or `\r` where the mode has no
//! `ICRNL`) and then turns the alternate screen on (`CSI ? 1049 h`), hides
//! the cursor (`CSI ? 25 l`), turns bracketed paste on (`CSI ? 2004 h`) and
//! turns off mouse reports another program left on (`CSI ? 1000 l`, 1002,
//! 1003, 1005, 1006, 1015; nothing of them is put back on the way out). The
//! caller then loops on [`Session::wait`], which returns one [`Event`]:
//!
//! - `Input(bytes)`: what one read gave (keys, pasted text, late replies),
//!   not parsed. Ctrl-C (0x03) and Ctrl-Z (0x1a) come as bytes: the caller
//!   ends on the first and calls [`Session::suspend`] on the second.
//! - `Writable`: asked for with `write = true` while the caller still has
//!   bytes of a frame; [`Session::write_some`] takes the rest.
//! - `Resized(size)`: the window size changed (SIGWINCH). Draw everything
//!   again.
//! - `Resumed(size)`: the session came back after a stop (Ctrl-Z, SIGTSTP,
//!   SIGSTOP) or a continue. The screen and the mode were taken again,
//!   input typed meanwhile was dropped and a frame cut by the stop was
//!   ended: drop pending output and key parser state, draw everything again.
//! - `Signal(sig)`: SIGINT, SIGTERM or SIGHUP came. End: dropping the
//!   session restores the terminal, and the process then ends with that
//!   signal (status 130, 143 or 129 in a shell). A signal the process
//!   ignored (SIGHUP under `nohup`) stays ignored.
//! - `Hangup`: the terminal went away (a read gave 0 or EIO, or the
//!   terminal is gone while the session waits in the background), or it did
//!   not take the modes when the session took it again after a stop (what
//!   went out was put back). End without saving. A caught SIGINT, SIGTERM
//!   or SIGHUP is reported as `Signal` first.
//! - `Timeout`: `until` passed, for the caller's timers. Never while the
//!   session is in the background: nothing can be drawn then, and
//!   `Resumed` follows.
//!
//! Frames. `write_some(rest)` is one non-blocking write of the rest of the
//! frame being written: it returns how much the terminal took. It returns
//! 0 when the terminal takes nothing now, and also, writing nothing, when
//! the session does not own the terminal at that moment (it gave it back,
//! a continue waits to be handled, or it is no longer the foreground job);
//! the caller then calls `wait` before it writes again (a loop of writes
//! alone would spin). A frame the terminal took only in part is cut: a
//! stop or the end drops what is still queued and ends the escape sequence
//! the terminal is in (`CAN ESC \`) before anything else. A frame that
//! uses synchronized output calls `mark_synced(true)` before it writes
//! `CSI ? 2026 h` and `mark_synced(false)` once its `CSI ? 2026 l` was
//! taken, so the end turns it off when a frame was cut inside it.
//!
//! Stop and continue. The handlers of SIGTSTP, SIGCONT and SIGWINCH are in
//! from before the raw switch to after the mode is back. Ctrl-Z (`suspend`)
//! and SIGTSTP put the terminal back (as on the way out, below) and stop:
//! Ctrl-Z stops the whole process group, as the terminal's own Ctrl-Z would;
//! a SIGTSTP from outside stops this process. An exit signal or a SIGCONT
//! that came while the terminal was put back goes first: nothing stops (a
//! SIGCONT drops a SIGTSTP not taken yet, as the kernel drops a pending
//! stop). An exit sent while stopped ends the session when it goes on,
//! without taking the terminal again. When the process goes on (`fg`, `bg`,
//! or at once in an orphaned process group, where the kernel drops the
//! stop), it looks whether it is the terminal's foreground job. If so it
//! takes the terminal again (reading its mode anew), drops the input typed
//! meanwhile, turns the modes on and, once they are on, reports `Resumed`.
//! If not (`bg`) it touches nothing (no read, no write, no mode change: a
//! background job would get SIGTTIN or, with `tostop`, SIGTTOU) and waits
//! for the next SIGCONT or SIGWINCH, looking once a second whether the
//! terminal is still there. A continue without a stop of the session's own
//! (SIGSTOP, a stray SIGCONT) is taken the same way: the terminal is put
//! back first and then taken again. SIGTSTP ignored when the session began
//! stays ignored, and `suspend` then does nothing; so does a SIGTSTP blocked
//! in the signal mask of the thread that opens the session. The other
//! signals reach the session only while that thread does not block them:
//! one blocked stays pending until it is let through.
//!
//! The way out (drop, after `Signal`, `Hangup` or the caller's end), with
//! what was turned on only, each mode recorded as on before its bytes are
//! written (a reset of a mode never set is harmless): the cut escape is
//! ended, then one write of `CSI ? 2026 l`, `CSI 0 m`, `CSI ? 2004 l`,
//! `CSI ? 25 h` and `CSI ? 1049 l` that waits at most [`LEAVE_WAIT`], and
//! then the terminal mode, whatever became of those bytes
//! (`tcsetattr(TCSANOW)`, `tcflush(TCIFLUSH)`, the descriptor flags). A
//! terminal that takes no output or hung up may keep the alternate screen:
//! putting the screen back is bounded best effort; the mode is always put
//! back while the session is the foreground job, and never touched from the
//! background. Signals not handled here (SIGQUIT, SIGKILL, SIGSEGV...) leave
//! the terminal raw on the alternate screen until `reset` or `stty sane`.
//!
//! Waking. Signal handlers set a flag and write one byte to a non-blocking
//! pipe; the wait selects on the terminal and that pipe together, so a
//! signal that comes between the flag check and the wait is not lost. The
//! pipe is made once per process and never closed. SIGTSTP, SIGCONT and
//! SIGWINCH have flags of their own: they never cancel a query.
//!
//! No file is read or written while a session waits: only the terminal
//! and the wake pipe. One guard at a time per process ([`Tty::raw`] or a
//! session): the flags and handlers are process-wide.
//!
//! What the caller must keep to (the editor that opens a session):
//!
//! - The sizes of `Resized` and `Resumed` are TIOCGWINSZ's raw `u16`s: 0,
//!   or 65535 by 65535, are possible (any process of the user can set
//!   them). Bound columns and rows before making a cell grid.
//! - `Input` is raw bytes (pastes, late replies): never written back to the
//!   screen unsanitized.
//! - No `std::process::exit` (or `_exit`) while a session lives: its drop
//!   puts the terminal back. Drop it before any way out that exits, a
//!   command deadline's watchdog included.
//! - No descriptor closed or `dup2`ed by number, and no closefrom-like
//!   call, in a process that opened a session: the wake pipe stays open
//!   for the rest of the process.
//! - No child started on another thread while a session is open: a group
//!   stop ignores SIGTSTP for a moment, and on macOS the wake pipe's ends
//!   are made close-on-exec only after `pipe`.
//!
//! One thread takes the signals. While a session is alive no other thread
//! may take SIGINT, SIGTERM, SIGHUP, SIGTSTP, SIGCONT or SIGWINCH: block
//! them in any thread started meanwhile, or start none (`bingsu setup`
//! starts none; arm a command deadline, whose watchdog is a thread, only
//! after the session is dropped). A process-directed signal goes to any
//! thread that does not block it, and the handlers on two threads run in
//! no fixed order: the session could see the SIGCONT that ended a stop
//! before the SIGTERM sent while stopped, and take the terminal again; or
//! see that SIGCONT only after it took the terminal, and take it a second
//! time. On the session's own thread the kernel runs the handlers of the
//! signals pending at a continue before the stopped call returns.
use super::{
    CAUGHT, Raw, RawGuard, SIGNALS, STOP, Size, Tty, WAKE, WRITE_TIMEOUT, cancel_half_escape,
    fits_select, flush_input, foreground, ready, window_size, write_once,
};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long putting the modes back may wait for the terminal to take the
/// bytes.
pub const LEAVE_WAIT: Duration = Duration::from_millis(500);

/// How often a session in the background looks whether the terminal is
/// still there: a background job gets no signal when the terminal's session
/// ends (a shell that does not hang up its jobs).
const BACKGROUND_CHECK: Duration = Duration::from_secs(1);

/// `BACKGROUND_CHECK`, or a test's own.
fn background_check() -> Duration {
    #[cfg(test)]
    if let Some(d) = test_session::BACKGROUND_CHECK.get() {
        return d;
    }
    BACKGROUND_CHECK
}

/// The longest time one `select` waits.
const LONGEST_SELECT: Duration = Duration::from_secs(24 * 60 * 60);

/// The most one read takes.
const INPUT_CHUNK: usize = 1024;

/// Modes the session turns on, one bit each.
const ALT: u8 = 1;
const HIDDEN: u8 = 2;
const PASTE: u8 = 4;
const SYNC: u8 = 8;

/// Turning the modes on, in order.
const ENTER: [(u8, &[u8]); 4] = [
    (ALT, b"\x1b[?1049h"),
    (HIDDEN, b"\x1b[?25l"),
    (PASTE, b"\x1b[?2004h"),
    // Mouse reports another program may have left on (X10 and normal
    // tracking, button and any motion, the UTF-8, SGR and urxvt
    // coordinates), so none reach the key parser: 1005's UTF-8 coordinates
    // would read as keys. Nothing to put back: the session never turns
    // them on.
    // 이것을 실패시키는 것: 이 단계를 빼는 것(entering_and_leaving_put_every_mode_back_in_order의 진입 열).
    (
        0,
        b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l",
    ),
];

/// What puts back the modes in `modes`, in the order of the way out: the
/// end of synchronized output first (a terminal holds the screen until
/// then), the alternate screen last.
fn leave_bytes(modes: u8) -> Vec<u8> {
    let mut out = Vec::new();
    if modes & SYNC != 0 {
        out.extend_from_slice(b"\x1b[?2026l");
    }
    if modes != 0 {
        out.extend_from_slice(b"\x1b[0m");
    }
    if modes & PASTE != 0 {
        out.extend_from_slice(b"\x1b[?2004l");
    }
    if modes & HIDDEN != 0 {
        out.extend_from_slice(b"\x1b[?25h");
    }
    if modes & ALT != 0 {
        out.extend_from_slice(b"\x1b[?1049l");
    }
    out
}

/// How turning the modes on ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entered {
    Done,
    /// An exit signal came.
    Signal,
    /// No longer the terminal's foreground job.
    Lost,
    /// A continue is to be handled first (a SIGSTOP and `fg` while the
    /// modes went out): the next `wait` puts back what went out and takes
    /// the terminal again.
    Resume,
    /// The terminal did not take the bytes in time, or the write failed.
    Failed,
}

/// What `Session::wait` saw.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    Input(&'a [u8]),
    Writable,
    Resized(Size),
    Resumed(Size),
    Signal(libc::c_int),
    Hangup,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The foreground job, with the terminal taken.
    Running,
    /// Continued without the terminal (`bg`), or not given it back yet.
    Background,
    /// The terminal went away.
    Gone,
}

static TSTP_SEEN: AtomicBool = AtomicBool::new(false);
static CONT_SEEN: AtomicBool = AtomicBool::new(false);
static WINCH_SEEN: AtomicBool = AtomicBool::new(false);

/// The job control signals the session handles, in the order of
/// `Session::old`.
const JOB_SIGNALS: [libc::c_int; 3] = [libc::SIGTSTP, libc::SIGCONT, libc::SIGWINCH];

extern "C" fn on_job_signal(sig: libc::c_int) {
    let seen = match sig {
        libc::SIGTSTP => &TSTP_SEEN,
        libc::SIGCONT => {
            // A continue drops a stop not taken yet, as the kernel drops a
            // pending SIGTSTP when SIGCONT is sent. Cleared before the
            // continue is set: a SIGTSTP whose handler runs in between (the
            // handlers can nest) is then kept, not lost.
            // 이것을 실패시키는 것: 지우지 않는 것(재개 뒤 남은 SIGTSTP로 한 번 더 멈춤; a_continue_during_the_way_out_cancels_the_stop).
            TSTP_SEEN.store(false, Ordering::SeqCst);
            &CONT_SEEN
        }
        _ => &WINCH_SEEN,
    };
    seen.store(true, Ordering::SeqCst);
    super::wake();
}

/// The action that sends `sig` to `on_job_signal`. SA_RESTART: the session
/// wakes on the pipe, so other calls need not end early.
fn job_action() -> libc::sigaction {
    // SAFETY: an all-zero `sigaction` is a valid starting value.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = on_job_signal as extern "C" fn(libc::c_int) as usize;
    act.sa_flags = libc::SA_RESTART;
    // SAFETY: `act.sa_mask` is a valid signal set to empty.
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    act
}

/// Sets `sig`'s action to `act`; the one it replaced, `None` when the call
/// failed and nothing changed.
fn set_action(sig: libc::c_int, act: &libc::sigaction) -> Option<libc::sigaction> {
    // SAFETY: an all-zero `sigaction` is a valid value for the call to fill.
    let mut was: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: `act` is initialised and `was` receives the old action.
    (unsafe { libc::sigaction(sig, act, &mut was) } == 0).then_some(was)
}

/// Whether `sig` is blocked in this thread's signal mask.
fn blocked(sig: libc::c_int) -> bool {
    // SAFETY: an all-zero `sigset_t` is valid storage for the call to fill.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: a null new set only reads this thread's mask into `mask`.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) };
    // SAFETY: `mask` was filled by pthread_sigmask (or is still all zero).
    rc == 0 && unsafe { libc::sigismember(&mask, sig) } == 1
}

/// `sig`'s action now.
fn action(sig: libc::c_int) -> libc::sigaction {
    // SAFETY: an all-zero `sigaction` is a valid value for the call to fill.
    let mut was: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a null new action only reads the current one into `was`.
    unsafe { libc::sigaction(sig, std::ptr::null(), &mut was) };
    was
}

/// The default action.
fn default_action() -> libc::sigaction {
    plain_action(libc::SIG_DFL)
}

/// Ignoring the signal.
fn ignore_action() -> libc::sigaction {
    plain_action(libc::SIG_IGN)
}

fn plain_action(handler: libc::sighandler_t) -> libc::sigaction {
    // SAFETY: an all-zero `sigaction` is SIG_DFL with no flags.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler;
    // SAFETY: `act.sa_mask` is a valid signal set to empty.
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    act
}

/// The session's handlers of SIGTSTP, SIGCONT and SIGWINCH, from before the
/// terminal mode changes until after it is back: a SIGTSTP in between is
/// the session's to handle, so it never stops the process with the
/// terminal raw. Putting the old actions back is `Drop`.
struct JobSignals {
    /// The actions they had, in `JOB_SIGNALS` order (`None`: not replaced;
    /// SIGTSTP is left alone when it was ignored).
    old: [Option<libc::sigaction>; 3],
}

impl JobSignals {
    fn install() -> Self {
        // A signal an earlier session took and never handled; cleared before
        // the handlers go in, so one that comes after is kept.
        // 이것을 실패시키는 것: 이 깃발을 지우지 않는 것(앞 세션 끝에 온 SIGTSTP로 새 세션이 멈춤; a_new_session_starts_with_no_signal_seen).
        for seen in [&TSTP_SEEN, &CONT_SEEN, &WINCH_SEEN] {
            seen.store(false, Ordering::SeqCst);
        }
        let ours = job_action();
        let mut old = [None; 3];
        for (slot, sig) in old.iter_mut().zip(JOB_SIGNALS) {
            // An ignored SIGTSTP stays so. A blocked one (in the mask this
            // thread came with) counts as ignored too: the raise of a stop
            // would only stay pending, after the rest of the process group
            // stopped, and the session would take the terminal again at once.
            // 이것을 실패시키는 것: 무시하던 SIGTSTP에도 처리기를 거는 것(an_ignored_stop_stays_ignored),
            // 막아 둔 SIGTSTP를 보지 않는 것(a_blocked_stop_counts_as_ignored).
            if sig == libc::SIGTSTP && (action(sig).sa_sigaction == libc::SIG_IGN || blocked(sig)) {
                continue;
            }
            *slot = set_action(sig, &ours);
        }
        Self { old }
    }

    /// Whether SIGTSTP is the session's (it was not ignored).
    fn stops(&self) -> bool {
        self.old[0].is_some()
    }
}

impl Drop for JobSignals {
    fn drop(&mut self) {
        // 이것을 실패시키는 것: 처리기를 되돌리지 않는 것(entering_and_leaving_put_every_mode_back_in_order의 handlers back,
        // a_failed_raw_switch_puts_the_handlers_back).
        for (old, sig) in self.old.iter().zip(JOB_SIGNALS) {
            if let Some(old) = old {
                set_action(sig, old);
            }
        }
    }
}

/// The wake pipe (read end, write end), made once per process and never
/// closed, so a handler that loaded the write end's number never writes
/// into a file that took the number over. Its write end is in `WAKE` from
/// then on: signals in a later query write there too, and the next wait
/// drains them.
static PIPE: Mutex<Option<(RawFd, RawFd)>> = Mutex::new(None);

/// The wake pipe's read end, made on the first call.
fn wake_pipe() -> std::io::Result<RawFd> {
    let mut pipe = PIPE.lock().unwrap_or_else(|e| e.into_inner());
    // 이것을 실패시키는 것: 부를 때마다 새로 만드는 것(the_wake_pipe_is_non_blocking_closed_on_exec_and_made_once).
    if let Some((read, _)) = *pipe {
        return Ok(read);
    }
    let (read, write) = super::sys::nonblocking_pipe()?;
    // 이것을 실패시키는 것: 이 검사를 빼거나 한 끝만 보는 것(FD_SETSIZE에 걸친 pipe를 select에 넣음;
    // a_wake_pipe_above_fd_setsize_is_refused는 읽는 끝 1023, 쓰는 끝 1024).
    if ![&read, &write]
        .iter()
        .all(|end| fits_select(end.as_raw_fd()))
    {
        return Err(std::io::Error::other(
            "the wake pipe's descriptors do not fit select",
        ));
    }
    let ends = (read.into_raw_fd(), write.into_raw_fd());
    *pipe = Some(ends);
    WAKE.store(ends.1, Ordering::SeqCst);
    Ok(ends.0)
}

/// Reads and drops what the wake pipe holds (it is non-blocking).
fn drain(fd: RawFd) {
    let mut chunk = [0u8; 64];
    for _ in 0..64 {
        // SAFETY: `fd` is the wake pipe's read end; `chunk` is writable.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n <= 0 {
            break;
        }
    }
}

/// The session's end: a caught exit signal goes first, then `Hangup`.
fn ended() -> Event<'static> {
    // 이것을 실패시키는 것: 받은 종료 신호보다 Hangup을 먼저 알리는 것(a_failed_reentry_ends_the_session의 TERM 칸).
    caught().map_or(Event::Hangup, Event::Signal)
}

/// The first of SIGINT, SIGTERM and SIGHUP a handler took.
fn caught() -> Option<libc::c_int> {
    let bits = CAUGHT.load(Ordering::SeqCst);
    SIGNALS.into_iter().find(|&sig| bits & (1u64 << sig) != 0)
}

/// Writes all of `buf` to `fd`, waiting for room until `until`; signals do
/// not end it (it puts things back on the way out). The bytes taken.
fn write_bounded(fd: RawFd, mut buf: &[u8], until: Instant) -> usize {
    let whole = buf.len();
    let wait = ready(fd, false, true);
    while !buf.is_empty() {
        match write_once(fd, buf) {
            Ok(0) => break,
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if Instant::now() >= until {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !wait(until) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    whole - buf.len()
}

/// What `select` reported.
struct Ready {
    input: bool,
    output: bool,
    wake: bool,
}

/// Waits until `tty` can be read (or written, with `write`), `wake` can be
/// read, or `until` passes. `None`: the call failed (other than EINTR,
/// which reports nothing ready).
#[allow(
    clippy::unnecessary_fallible_conversions,
    reason = "`tv_usec` is 32 bits on macOS and 64 on Linux; one spelling for both"
)]
fn select(tty: Option<RawFd>, wake: RawFd, write: bool, until: Option<Instant>) -> Option<Ready> {
    #[cfg(test)]
    if test_session::FAIL_SELECT.take() {
        return None;
    }
    let mut tv = until.map(|until| {
        // At most a day per call; the callers wait again until `until`.
        // macOS refuses a time over 1e8 s (EINVAL), which would end the
        // session as if the terminal were gone.
        // 이것을 실패시키는 것: 남은 시간을 줄이지 않는 것(macOS: 먼 마감이 Hangup; a_wait_with_a_far_time_limit_goes_on).
        let left = until
            .saturating_duration_since(Instant::now())
            .min(LONGEST_SELECT);
        libc::timeval {
            tv_sec: left.as_secs().try_into().unwrap_or(0),
            tv_usec: left.subsec_micros().try_into().unwrap_or(0),
        }
    });
    let mut reads = std::mem::MaybeUninit::<libc::fd_set>::uninit();
    let mut writes = std::mem::MaybeUninit::<libc::fd_set>::uninit();
    // SAFETY: `reads` is writable memory; FD_ZERO initialises all of it.
    unsafe { libc::FD_ZERO(reads.as_mut_ptr()) };
    // SAFETY: as above.
    unsafe { libc::FD_ZERO(writes.as_mut_ptr()) };
    // SAFETY: FD_ZERO above initialised both sets.
    let mut reads = unsafe { reads.assume_init() };
    // SAFETY: as above.
    let mut writes = unsafe { writes.assume_init() };
    // SAFETY: the wake pipe fits the set (`wake_pipe` checked it).
    unsafe { libc::FD_SET(wake, &mut reads) };
    let mut top = wake;
    if let Some(tty) = tty {
        // SAFETY: `Tty::open` refused a terminal that does not fit the set.
        unsafe { libc::FD_SET(tty, &mut reads) };
        if write {
            // SAFETY: as above.
            unsafe { libc::FD_SET(tty, &mut writes) };
        }
        top = top.max(tty);
    }
    let timeout = tv
        .as_mut()
        .map_or(std::ptr::null_mut(), |tv| tv as *mut libc::timeval);
    // SAFETY: the sets and the time are valid for the call; no error set.
    let n = unsafe {
        libc::select(
            top + 1,
            &mut reads,
            &mut writes,
            std::ptr::null_mut(),
            timeout,
        )
    };
    if n < 0 {
        return (std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted)
            .then_some(Ready {
                input: false,
                output: false,
                wake: true,
            });
    }
    // SAFETY: `reads` was filled by select; `wake` is in range.
    let wake = unsafe { libc::FD_ISSET(wake, &reads) };
    let (input, output) = match tty {
        Some(tty) => (
            // SAFETY: as above.
            unsafe { libc::FD_ISSET(tty, &reads) },
            // SAFETY: as above.
            write && unsafe { libc::FD_ISSET(tty, &writes) },
        ),
        None => (false, false),
    };
    Some(Ready {
        input,
        output,
        wake,
    })
}

/// The terminal in full-screen use, from `Tty::full_screen` until it is
/// dropped. See the module comment.
pub struct Session<'a> {
    /// Dropped after `Session::drop` and before `guard`: the job control
    /// handlers go back once the terminal is, and before the one guard's
    /// place is given back.
    jobs: JobSignals,
    /// Dropped after `jobs`: the handlers of SIGINT, SIGTERM and SIGHUP go
    /// back, a signal taken is raised again, then the place is given back.
    guard: RawGuard<'a>,
    fd: RawFd,
    /// The wake pipe's read end.
    wake: RawFd,
    state: State,
    /// Turned on and not put back yet (recorded before each write).
    modes: u8,
    /// The terminal took part of a frame and not the rest.
    cut: bool,
    /// `Resumed` is due.
    resumed: bool,
    size: Size,
    input: [u8; INPUT_CHUNK],
}

impl Tty {
    /// The terminal in full-screen use until the session is dropped. An
    /// error when `Tty::raw` refuses (not the foreground job, another guard
    /// alive), when the wake pipe cannot be made, or when the modes could
    /// not all be turned on in time (a terminal that takes no output) or a
    /// signal came meanwhile: then what was turned on is put back, and a
    /// signal taken ends the process.
    pub fn full_screen(&self) -> std::io::Result<Session<'_>> {
        // First, so that a failure leaves the terminal alone.
        let wake = wake_pipe()?;
        let fd = self.file.as_raw_fd();
        // The place first (the handlers are process-wide), then the job
        // control handlers, then the mode. An early return drops them in
        // the other order: the handlers go back before the place does.
        let slot = self.claim()?;
        // 이것을 실패시키는 것: 처리기를 raw 전환 뒤에 거는 것(그 사이 SIGTSTP가 raw인 채 멈춤; a_stop_right_after_the_raw_switch_puts_the_terminal_back).
        let jobs = JobSignals::install();
        #[cfg(test)]
        if test_session::FAIL_RAW.take() {
            return Err(std::io::Error::other("the test's raw switch failed"));
        }
        let raw = Raw::enter(fd)?;
        #[cfg(test)]
        test_session::after_raw();
        let mut session = Session {
            jobs,
            guard: RawGuard {
                tty: self,
                raw,
                _slot: slot,
                spent: None,
            },
            fd,
            wake,
            state: State::Running,
            modes: 0,
            cut: false,
            resumed: false,
            size: Size::default(),
            input: [0; INPUT_CHUNK],
        };
        match session.enter() {
            Entered::Done => {}
            Entered::Signal => return Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
            Entered::Lost => {
                return Err(std::io::Error::other("not the terminal's foreground job"));
            }
            Entered::Failed => return Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            Entered::Resume => {}
        }
        session.size = window_size(self.file.as_fd()).unwrap_or_default();
        Ok(session)
    }
}

impl Session<'_> {
    /// The window size when the session began or last changed (0 when the
    /// terminal does not know).
    pub fn size(&self) -> Size {
        self.size
    }

    /// Waits for the next event; see the module comment. `write`: the
    /// caller has bytes of a frame left and wants `Writable`. `until`: when
    /// to give `Timeout` (`None`: no time limit).
    pub fn wait(&mut self, write: bool, until: Option<Instant>) -> Event<'_> {
        loop {
            // The pipe before the flags: a signal after the flag check
            // leaves its byte for the select below.
            // 이것을 실패시키는 것: 깃발을 본 뒤에 pipe를 비우는 것(그 사이 신호의 바이트를 지워 select가 깨어나지 않음).
            drain(self.wake);
            if let Some(sig) = caught() {
                return Event::Signal(sig);
            }
            if TSTP_SEEN.load(Ordering::SeqCst) {
                self.stop(false);
            }
            let winch = WINCH_SEEN.swap(false, Ordering::SeqCst);
            // 이것을 실패시키는 것: SIGCONT 뒤 전경 작업인지 다시 보지 않는 것(bg로 이어 간 작업이 터미널을 다시 잡음).
            if CONT_SEEN.swap(false, Ordering::SeqCst) || (winch && self.state == State::Background)
            {
                self.check();
            }
            match self.state {
                State::Gone => return ended(),
                State::Background => {
                    // Nothing of the terminal: the pipe only.
                    // 이것을 실패시키는 것: 배경에서 터미널을 기다리고 읽는 것(SIGTTIN으로 멈춤; stop_bg_and_fg_under_a_job_control_shell).
                    let until = Instant::now() + background_check();
                    match select(None, self.wake, false, Some(until)) {
                        Some(r) if r.wake => {}
                        // A quiet second: is the terminal back, or gone?
                        Some(_) => self.check(),
                        // The wait itself failed: waiting again would spin.
                        // 이것을 실패시키는 것: 이때도 check하고 다시 기다리는 것(끝나지 않음;
                        // a_failed_wait_in_the_background_ends_the_session).
                        None => self.state = State::Gone,
                    }
                    continue;
                }
                State::Running => {}
            }
            if std::mem::take(&mut self.resumed) {
                return Event::Resumed(self.size);
            }
            if winch {
                let now = window_size(self.guard.tty.file.as_fd()).unwrap_or(self.size);
                if now != self.size {
                    self.size = now;
                    return Event::Resized(now);
                }
            }
            #[cfg(test)]
            test_session::before_select();
            let Some(ready) = select(Some(self.fd), self.wake, write, until) else {
                self.state = State::Gone;
                return ended();
            };
            if ready.wake {
                continue;
            }
            if ready.input {
                // Not read when the terminal is no longer this job's: a
                // background job's read stops it (SIGTTIN).
                // 이것을 실패시키는 것: 읽기 전에 소유를 보지 않는 것(배경에서 읽어 SIGTTIN으로 멈춤; a_session_that_lost_the_terminal_reads_nothing).
                if !self.owns() {
                    continue;
                }
                #[cfg(test)]
                test_session::steal_input(self.fd);
                // SAFETY: `fd` is the open terminal; `input` is writable.
                let n = unsafe {
                    libc::read(self.fd, self.input.as_mut_ptr().cast(), self.input.len())
                };
                match usize::try_from(n) {
                    // Nothing is no end by itself: with VMIN and VTIME 0 a
                    // read gives 0 when another reader of the foreground
                    // group took the bytes since the select. A write of no
                    // bytes tells: it fails (EIO) on a terminal that hung up,
                    // on Linux and macOS alike.
                    // 이것을 실패시키는 것: 0바이트 읽기를 늘 끝으로 보는 것(a_read_of_nothing_is_no_hang_up), 끊긴
                    // 터미널을 보지 않는 것(a_hang_up_ends_the_session의 SIGHUP 무시 칸).
                    Ok(0) => {
                        if write_once(self.fd, &[]).is_err() {
                            self.state = State::Gone;
                            return ended();
                        }
                        #[cfg(test)]
                        test_session::read_nothing();
                        continue;
                    }
                    Ok(n) => return Event::Input(&self.input[..n]),
                    Err(_) => {
                        let kind = std::io::Error::last_os_error().kind();
                        if !matches!(
                            kind,
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) {
                            self.state = State::Gone;
                            return ended();
                        }
                        continue;
                    }
                }
            }
            if ready.output {
                return Event::Writable;
            }
            if until.is_some_and(|until| Instant::now() >= until) {
                return Event::Timeout;
            }
        }
    }

    /// One non-blocking write of `rest`, the part of the frame being
    /// written that the terminal has not taken yet: the bytes taken (0 when
    /// it takes nothing now, and always 0 outside the foreground). An error
    /// means the terminal went away.
    pub fn write_some(&mut self, rest: &[u8]) -> std::io::Result<usize> {
        // 이것을 실패시키는 것: 쓰기 전에 소유를 보지 않는 것(a_write_after_a_stop_and_bg_writes_nothing).
        if rest.is_empty() || !self.owns() {
            return Ok(0);
        }
        match self.write_once(rest) {
            Ok(n) => {
                // 이것을 실패시키는 것: 일부만 받은 쓰기를 끊김으로 치지 않는 것(쓰다 만 단계의 CANCEL이 빠짐).
                self.cut = n < rest.len();
                Ok(n)
            }
            // Nothing taken: the frame is as cut as it was.
            // 이것을 실패시키는 것: 받지 않은 쓰기를 끊김으로 치는 것(a_frame_the_terminal_took_nothing_of_is_not_cancelled).
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(0)
            }
            Err(e) => {
                self.state = State::Gone;
                Err(e)
            }
        }
    }

    /// One `write(2)` of `rest`; in tests, a terminal that takes only part
    /// of it can stand in (`test_terminal::ROOM`).
    fn write_once(&self, rest: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        if let Some(r) =
            super::test_terminal::ROOM.with(|room| super::test_terminal::write(room, self.fd, rest))
        {
            return r;
        }
        write_once(self.fd, rest)
    }

    /// Whether the session may use the terminal now: it took it and did not
    /// give it back (a stop that an exit cancelled gives it back), no
    /// continue waits to be handled (SIGSTOP and `fg` or `bg` since the
    /// last wait), and it is still the foreground job (a shell can take the
    /// terminal back without a stop; the session is then in the
    /// background). The next `wait` takes it from there. Between this check
    /// and the call that follows, a SIGSTOP and `bg` can still come: with
    /// `tostop` the kernel stops the job then (SIGTTOU), and without it a
    /// write reaches the screen. In a process with more threads the
    /// continue's handler can run on another one a moment after this one
    /// goes on, so a continue can still be missed here then; in the
    /// foreground the write lands before `Resumed` redraws.
    fn owns(&mut self) -> bool {
        // 이것을 실패시키는 것: 되돌린 터미널을 제 것으로 보는 것(a_terminate_during_the_way_out_ends_without_a_stop의 AFTER),
        // 처리하지 않은 재개를 보지 않는 것(a_write_after_a_stop_and_fg_waits_for_the_resume).
        if self.state != State::Running || !self.guard.raw.on || CONT_SEEN.load(Ordering::SeqCst) {
            return false;
        }
        // 이것을 실패시키는 것: 전경인지 보지 않는 것(a_write_after_the_terminal_was_taken_writes_nothing).
        if !foreground(self.fd) {
            self.state = State::Background;
            return false;
        }
        true
    }

    /// A frame with synchronized output begins (`true`, before its
    /// `CSI ? 2026 h` is written) or its end was taken (`false`).
    pub fn mark_synced(&mut self, on: bool) {
        if on {
            self.modes |= SYNC;
        } else {
            self.modes &= !SYNC;
        }
    }

    /// Ctrl-Z: puts the terminal back and stops the process group, as the
    /// terminal's own Ctrl-Z would. Returns once the process goes on; the
    /// next `wait` gives `Resumed` (or waits in the background first).
    /// Nothing when SIGTSTP was ignored when the session began.
    pub fn suspend(&mut self) {
        // 이것을 실패시키는 것: 무시하던 SIGTSTP인데도 멈추는 것(an_ignored_stop_stays_ignored).
        if self.jobs.stops() && self.state == State::Running {
            self.stop(true);
        }
    }

    /// `write_bounded` on the terminal; in tests, a terminal that takes only
    /// part of the bytes can stand in (`test_terminal::ROOM`).
    fn put(&self, bytes: &[u8], until: Instant) -> usize {
        #[cfg(test)]
        if let Some(taken) = test_session::hooked_write(self.fd, bytes, until) {
            return taken;
        }
        write_bounded(self.fd, bytes, until)
    }

    /// One mode's bytes for `enter`, written only while the session owns the
    /// terminal: before every write, also the first and each one after a
    /// wait for room, it must still be the foreground job with no continue
    /// to handle (a SIGSTOP and `bg` or `fg` can come while it waits). The
    /// bytes taken, and how it ended when not all of them were.
    fn put_owned(&self, bytes: &[u8], until: Instant) -> (usize, Option<Entered>) {
        #[cfg(test)]
        let hooked = super::test_terminal::ROOM.get().is_some();
        let mut taken = 0;
        let ended = loop {
            if taken == bytes.len() {
                break None;
            }
            // 이것을 실패시키는 것: 쓰기 전에 전경인지 보지 않는 것(배경에서 모드를 씀: tostop과 SIGTTOU로 멈춤;
            // an_entry_whose_terminal_was_taken_writes_no_more, an_entry_cut_when_the_shell_takes_the_terminal_writes_no_more).
            if !foreground(self.fd) {
                break Some(Entered::Lost);
            }
            // The next `wait` takes the terminal again from the start.
            // 이것을 실패시키는 것: 쓰기 전에 처리하지 않은 재개를 보지 않는 것(an_entry_cut_by_sigstop_and_fg_starts_again).
            if CONT_SEEN.load(Ordering::SeqCst) {
                break Some(Entered::Resume);
            }
            match self.write_once(&bytes[taken..]) {
                Ok(0) => break Some(Entered::Failed),
                Ok(n) => taken += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    if Instant::now() >= until {
                        break Some(Entered::Failed);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if !self.wait_for_room(until) {
                        break Some(Entered::Failed);
                    }
                }
                Err(_) => break Some(Entered::Failed),
            }
        };
        #[cfg(test)]
        if hooked {
            super::test_terminal::ROOM.set(None);
        }
        (taken, ended)
    }

    /// Waits until the terminal takes output or `until` passes.
    fn wait_for_room(&self, until: Instant) -> bool {
        #[cfg(test)]
        if let Some(room) = test_session::wait_for_room(self.fd, until) {
            return room;
        }
        ready(self.fd, false, true)(until)
    }

    /// Turns the modes on, each recorded before its bytes are written and
    /// each written only while this is the foreground job.
    fn enter(&mut self) -> Entered {
        for (step, (mode, bytes)) in ENTER.into_iter().enumerate() {
            // 이것을 실패시키는 것: 쓴 뒤에 기록하는 것(반쯤 나간 1049h를 되돌리지 않음; an_entry_the_terminal_stopped_taking_is_put_back).
            self.modes |= mode;
            let (taken, ended) = self.put_owned(bytes, Instant::now() + WRITE_TIMEOUT);
            if let Some(ended) = ended {
                // The terminal is in the escape sequence the bytes began.
                self.cut = taken > 0;
                return ended;
            }
            #[cfg(test)]
            test_session::entered(step);
            #[cfg(not(test))]
            let _ = step;
            // 이것을 실패시키는 것: 들어가는 동안 온 종료 신호를 보지 않는 것(나머지 모드를 켠 뒤에야 끝남).
            if STOP.load(Ordering::SeqCst) {
                return Entered::Signal;
            }
        }
        Entered::Done
    }

    /// Puts the terminal back as it was found: the cut escape ends, the
    /// modes go off (at most `LEAVE_WAIT`), then the mode, whatever became
    /// of those bytes. `false`: not the terminal's foreground job, so
    /// nothing was touched.
    fn leave(&mut self) -> bool {
        // 이것을 실패시키는 것: 전경 작업이 아닌데 터미널을 건드리는 것(배경에서 tcsetattr: SIGTTOU로 멈춤).
        if !foreground(self.fd) {
            return false;
        }
        if self.cut {
            cancel_half_escape(self.fd);
            self.cut = false;
        }
        let bytes = leave_bytes(self.modes);
        if !bytes.is_empty() {
            let taken = self.put(&bytes, Instant::now() + LEAVE_WAIT);
            #[cfg(test)]
            test_session::during_leave();
            // 이것을 실패시키는 것: 반쯤 나간 복구 열을 끊지 않는 것(터미널이 escape 안에 남음; a_way_out_the_terminal_stopped_taking_is_ended).
            if taken > 0 && taken < bytes.len() {
                cancel_half_escape(self.fd);
            }
        }
        self.modes = 0;
        // Whatever became of the bytes above.
        self.guard.raw.restore_terminal();
        true
    }

    /// Puts the terminal back and stops: the process group (`whole_group`,
    /// Ctrl-Z) or this process (a SIGTSTP from outside). Then `check`.
    fn stop(&mut self, whole_group: bool) {
        TSTP_SEEN.store(false, Ordering::SeqCst);
        CONT_SEEN.store(false, Ordering::SeqCst);
        let left = self.state == State::Running && self.leave();
        // Putting the terminal back can take a while (a terminal slow to
        // take output). What came meanwhile goes first, before anything of
        // the process group stops: an exit (`wait` reports it, and nothing
        // is taken again), or a continue (the stop is dropped).
        // 이것을 실패시키는 것: 종료 요청을 보지 않고 멈추는 것(a_terminate_during_the_way_out_ends_without_a_stop).
        if caught().is_some() {
            return;
        }
        // 이것을 실패시키는 것: 재개를 보지 않고 멈추는 것(a_continue_during_the_way_out_cancels_the_stop).
        if CONT_SEEN.swap(false, Ordering::SeqCst) {
            self.check();
            return;
        }
        // A session that lost the terminal (the shell took it without a
        // stop) stops alone: its process group is no longer the foreground
        // job, and the terminal's Ctrl-Z would not reach it either.
        // 이것을 실패시키는 것: 이때도 그룹에 보내는 것(같은 작업의 다른 프로세스가 멈춤;
        // a_suspend_without_the_terminal_stops_only_the_session).
        if whole_group && left {
            // The rest of the process group stops as on the terminal's own
            // Ctrl-Z. This process's copy is ignored, so dropped when sent:
            // otherwise it reaches the session's handler (at once, or later
            // on another thread) and stops the session a second time.
            // 이것을 실패시키는 것: 그룹에 보내지 않는 것(같은 그룹의 다른 프로세스가 멈추지 않음), 제 몫을 무시하지 않고
            // 보내는 것(나중에 받은 제 몫으로 한 번 더 멈춤; ctrl_z_puts_the_terminal_back_and_takes_it_again).
            set_action(libc::SIGTSTP, &ignore_action());
            // SAFETY: sends SIGTSTP to this process group.
            unsafe { libc::kill(0, libc::SIGTSTP) };
        }
        // A signal raised for this thread is taken before the call returns:
        // the default action stops the process here. In an orphaned process
        // group the kernel drops the stop, and the call returns at once.
        set_action(libc::SIGTSTP, &default_action());
        // SAFETY: raises SIGTSTP in this thread.
        unsafe { libc::raise(libc::SIGTSTP) };
        set_action(libc::SIGTSTP, &job_action());
        // On this thread the SIGCONT that ended the stop, and an exit sent
        // while stopped, were handled before `raise` returned (the module
        // comment says why no other thread takes them).
        // This continue is the one `check` handles now.
        CONT_SEEN.store(false, Ordering::SeqCst);
        // An exit sent while the process was stopped comes with the
        // continue: the terminal is not taken again.
        // 이것을 실패시키는 것: 멈춘 사이 온 종료 요청을 보지 않고 다시 잡는 것(a_terminate_while_stopped_ends_without_taking_the_terminal).
        if caught().is_some() {
            return;
        }
        self.check();
    }

    /// After a continue (or a window change, or a quiet second, in the
    /// background): whether the terminal is there and this is its
    /// foreground job. If so the terminal is taken again (from the mode it
    /// has now), input typed meanwhile is dropped, the modes go on and
    /// `Resumed` is due.
    fn check(&mut self) {
        // SAFETY: `fd` is open; the call reads the terminal's group.
        let owner = unsafe { libc::tcgetpgrp(self.fd) };
        // SAFETY: getpgrp takes no arguments and cannot fail.
        let own = unsafe { libc::getpgrp() };
        if owner < 0 {
            self.state = State::Gone;
            return;
        }
        if owner != own {
            self.state = State::Background;
            return;
        }
        // A continue without a stop of ours (SIGSTOP, a stray SIGCONT):
        // the terminal is put back first, so it is taken from its own mode.
        if self.guard.raw.on || self.modes != 0 {
            self.leave();
        }
        // 이것을 실패시키는 것: 다시 들어갈 때 모드를 새로 읽지 않는 것(멈춘 사이 바꾼 stty가 나갈 때 사라짐; stop_bg_and_fg_under_a_job_control_shell).
        if self.guard.raw.reenter().is_err() {
            self.state = State::Gone;
            return;
        }
        // 이것을 실패시키는 것: 멈춘 사이 친 글자를 버리지 않는 것(재개 뒤 키로 읽힘).
        let _ = flush_input(self.fd);
        self.state = State::Running;
        #[cfg(test)]
        test_session::arm_reentry();
        // `Resumed` only once the modes are on again.
        // 이것을 실패시키는 것: 다시 들어가기에 실패해도 Resumed를 알리는 것(a_failed_reentry_ends_the_session).
        match self.enter() {
            Entered::Done => {
                self.size = window_size(self.guard.tty.file.as_fd()).unwrap_or(self.size);
                self.resumed = true;
            }
            // An exit came: `wait` reports it next, and the drop puts back
            // what is on. A continue came: the next `wait` checks again.
            Entered::Signal | Entered::Resume => {}
            // Taken away again meanwhile: the next continue takes it. (The
            // SIGCONT of a `bg` that took it is pending then and would move
            // the session to the background at the next `wait` as well, and
            // `owns` refuses the terminal to a session that lost it; no test
            // tells this line from those.)
            Entered::Lost => self.state = State::Background,
            // The terminal did not take the modes: what went out is put
            // back, and the session ends (`Hangup`, or a caught exit first).
            // 이것을 실패시키는 것: 되돌리지 않는 것, 끝내지 않는 것(a_failed_reentry_ends_the_session).
            Entered::Failed => {
                self.leave();
                self.state = State::Gone;
            }
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // Not the foreground job (in the background, or the terminal gone):
        // the terminal is not touched, neither here nor by the guard after.
        // 이것을 실패시키는 것: 그때 guard의 복구를 막지 않는 것(배경에서 tcsetattr: SIGTTOU로 멈춤; a_session_that_lost_the_terminal_does_not_touch_it).
        if !self.leave() {
            self.guard.raw.on = false;
        }
        // `jobs`, then `guard`, drop next.
    }
}

/// Signals at chosen stages, for tests.
#[cfg(test)]
mod test_session {
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Pause {
        Stop,
        Taken,
    }

    thread_local! {
        /// Raised once the given step of `enter` wrote its bytes.
        pub(super) static AFTER_STEP: Cell<Option<(usize, libc::c_int)>> = const { Cell::new(None) };
        /// Raised once, just before `wait` selects (after it read the flags).
        pub(super) static BEFORE_SELECT: Cell<Option<libc::c_int>> = const { Cell::new(None) };
        /// How often the background session looks at the terminal.
        pub(super) static BACKGROUND_CHECK: Cell<Option<std::time::Duration>> = const { Cell::new(None) };
        /// `full_screen` fails once its job control handlers are in, before
        /// the raw switch.
        pub(super) static FAIL_RAW: Cell<bool> = const { Cell::new(false) };
        /// Waits for room in the entry's writes, counted.
        pub(super) static ROOM_WAITS: Cell<usize> = const { Cell::new(0) };
        /// What happens during the next wait for room of the entry.
        pub(super) static PAUSE: Cell<Option<Pause>> = const { Cell::new(None) };
        /// The next `select` fails.
        pub(super) static FAIL_SELECT: Cell<bool> = const { Cell::new(false) };
        /// The waiting input is read away once, as another reader of the
        /// foreground group would between the select and the read.
        pub(super) static STEAL: Cell<bool> = const { Cell::new(false) };
        /// Raised once, right after the raw switch.
        pub(super) static AFTER_RAW: Cell<Option<libc::c_int>> = const { Cell::new(None) };
        /// Raised once, in order, once `leave` wrote the way out (0: none).
        pub(super) static DURING_LEAVE: Cell<[libc::c_int; 2]> = const { Cell::new([0; 2]) };
        /// Moved into `ROOM`, `AFTER_STEP` and `DURING_LEAVE` right before
        /// `check` turns the modes on again, so the stop's own way out does
        /// not use them up.
        pub(super) static REENTRY_ROOM: Cell<Option<(usize, super::super::test_terminal::Then)>> = const { Cell::new(None) };
        pub(super) static REENTRY_STEP: Cell<Option<(usize, libc::c_int)>> = const { Cell::new(None) };
        pub(super) static REENTRY_LEAVE: Cell<[libc::c_int; 2]> = const { Cell::new([0; 2]) };
    }

    pub(super) fn arm_reentry() {
        if let Some(room) = REENTRY_ROOM.take() {
            super::super::test_terminal::ROOM.set(Some(room));
        }
        if let Some(step) = REENTRY_STEP.take() {
            AFTER_STEP.set(Some(step));
        }
        let leave = REENTRY_LEAVE.take();
        if leave != [0; 2] {
            DURING_LEAVE.set(leave);
        }
    }

    pub(super) fn during_leave() {
        for sig in DURING_LEAVE.take() {
            if sig != 0 {
                raise(sig);
            }
        }
    }

    /// A wait for room of the entry: counted (`ROOM_WAITS`), done as
    /// `PAUSE` says once, or as `test_terminal::ROOM` says (a stall sleeps
    /// to the limit). `None`: the real wait.
    pub(super) fn wait_for_room(fd: std::os::fd::RawFd, until: std::time::Instant) -> Option<bool> {
        use super::super::test_terminal;
        ROOM_WAITS.set(ROOM_WAITS.get() + 1);
        if let Some(pause) = PAUSE.take() {
            match pause {
                // Stopped meanwhile, as by a SIGSTOP from outside.
                Pause::Stop => raise(libc::SIGSTOP),
                // The shell takes the terminal meanwhile, without a stop.
                Pause::Taken => {
                    println!("ANSWER job: paused");
                    // SAFETY: getpgrp takes no arguments and cannot fail.
                    let own = unsafe { libc::getpgrp() };
                    let limit = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    // SAFETY: `fd` is the terminal; the call reads its group.
                    while unsafe { libc::tcgetpgrp(fd) } == own && std::time::Instant::now() < limit
                    {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
            }
            // Room again from here on.
            test_terminal::ROOM.set(None);
            return Some(true);
        }
        test_terminal::ROOM.with(|room| test_terminal::wait(room, until))
    }

    pub(super) fn steal_input(fd: std::os::fd::RawFd) {
        if STEAL.take() {
            let mut chunk = [0u8; 64];
            // SAFETY: `fd` is the open terminal; `chunk` is writable.
            while unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) } > 0 {}
        }
    }

    /// Said from the branch of a read that gave 0 and was no hang-up, on
    /// the standard error (not the terminal): the parent test waits for it.
    pub(super) fn read_nothing() {
        eprintln!("READ NOTHING");
    }

    pub(super) fn after_raw() {
        if let Some(sig) = AFTER_RAW.take() {
            raise(sig);
        }
    }

    /// One of `put`'s writes on a terminal that takes only part of it
    /// (`test_terminal::ROOM`, which it then clears): the bytes taken.
    /// `None`: no such terminal.
    pub(super) fn hooked_write(
        fd: std::os::fd::RawFd,
        mut buf: &[u8],
        until: std::time::Instant,
    ) -> Option<usize> {
        use super::super::test_terminal;
        let whole = buf.len();
        test_terminal::ROOM.with(|room| {
            room.get()?;
            while !buf.is_empty() {
                match test_terminal::write(room, fd, buf) {
                    Some(Ok(n)) => buf = &buf[n..],
                    _ => {
                        let _ = test_terminal::wait(room, until);
                        break;
                    }
                }
            }
            room.set(None);
            Some(whole - buf.len())
        })
    }

    fn raise(sig: libc::c_int) {
        // SAFETY: raises `sig` in this thread; its handler runs before the
        // call returns.
        unsafe { libc::raise(sig) };
    }

    pub(super) fn entered(step: usize) {
        if let Some((at, sig)) = AFTER_STEP.get() {
            if at == step {
                AFTER_STEP.set(None);
                raise(sig);
            }
        }
    }

    pub(super) fn before_select() {
        if let Some(sig) = BEFORE_SELECT.take() {
            raise(sig);
        }
    }
}

#[cfg(test)]
mod tests;
