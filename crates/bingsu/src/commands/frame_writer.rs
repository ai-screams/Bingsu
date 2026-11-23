//! The editor's frames on their way to the terminal (`bingsu setup`). Not
//! on any prompt path.
//!
//! A frame is built whole from the latest editor state and then written
//! through a [`Sink`] in non-blocking pieces: what the terminal does not
//! take now stays pending, and the event loop goes on reading keys and
//! signals meanwhile. Nothing here waits.
//!
//! - One frame at a time. A new frame starts only once the last byte of the
//!   one before was taken, so half a frame is never followed by another.
//!   Changes meanwhile only mark that a frame is due ([`FrameWriter::request`]):
//!   however many came, the next frame is one, built from the state at that
//!   moment ([`FrameWriter::wants_frame`]). A frame that draws only what
//!   changed is built against the screen the last frame left, which is why
//!   a pending frame is never replaced by a newer one.
//! - Each frame is wrapped in synchronized output (`CSI ? 2026 h` ...
//!   `CSI ? 2026 l`; a terminal without it ignores both), and the sink is
//!   told before the first byte and once the last was taken
//!   ([`Sink::mark_synced`]), so leaving the screen mid-frame can end it.
//! - `rest` handed to the sink is always all that is left of the frame, so
//!   the sink can tell a frame the terminal took in part (and must cut).
//! - A frame is at most [`FRAME_MAX`] bytes; a larger one is refused (a
//!   fault of the frame's builder, not of the terminal).
//! - At most [`WRITES_PER_FLUSH`] writes per call, so a terminal that takes
//!   a byte at a time cannot hold the loop.
//! - [`STALL`]: when the terminal takes not one byte of a pending frame for
//!   2 s, [`Flushed::Stalled`] tells the caller to end (and put the terminal
//!   back). The time runs from the last byte taken or the frame's start;
//!   [`FrameWriter::deadline`] gives it as a limit for the loop's wait.
//! - After a stop and a resume the frame in progress is gone with the
//!   screen it was drawn for: [`FrameWriter::discard`], then a whole frame.
//!   A resize alone does not cut a frame: it finishes, then the whole
//!   screen is drawn again.
//!
//! The sink is a trait, so tests inject partial writes, `EAGAIN`, errors
//! and a terminal that takes nothing. The full-screen session implements it
//! with its own `write_some` (0 when the terminal takes nothing now) and
//! `mark_synced`.
use std::io::ErrorKind;
use std::time::{Duration, Instant};

/// How long a pending frame may go without the terminal taking a byte.
pub const STALL: Duration = Duration::from_secs(2);

/// The largest frame, without the synchronized-output wrapper.
pub const FRAME_MAX: usize = 1 << 20;

/// Writes per `flush` call at most.
pub const WRITES_PER_FLUSH: usize = 16;

const SYNC_BEGIN: &[u8] = b"\x1b[?2026h";
const SYNC_END: &[u8] = b"\x1b[?2026l";

/// Where frames go: the terminal, or a test's stand-in.
pub trait Sink {
    /// One non-blocking write of `rest`, all that is left of the frame:
    /// the bytes taken, 0 when the terminal takes nothing now. An
    /// `ErrorKind::WouldBlock` or `Interrupted` error counts as 0; any
    /// other error means the terminal went away.
    fn write_some(&mut self, rest: &[u8]) -> std::io::Result<usize>;
    /// A frame with synchronized output begins (`true`, before its first
    /// byte is written) or its last byte was taken (`false`).
    fn mark_synced(&mut self, on: bool);
}

/// The full-screen session takes the frames, through its own methods.
impl Sink for super::tty::session::Session<'_> {
    fn write_some(&mut self, rest: &[u8]) -> std::io::Result<usize> {
        super::tty::session::Session::write_some(self, rest)
    }
    fn mark_synced(&mut self, on: bool) {
        super::tty::session::Session::mark_synced(self, on);
    }
}

/// How a `flush` ended.
#[derive(Debug)]
pub enum Flushed {
    /// No frame pending: the last one was taken whole.
    Done,
    /// Bytes are left; wait until the terminal can take more (or the
    /// deadline).
    Pending,
    /// The terminal took nothing for `STALL`. The frame stays pending.
    Stalled,
    /// The write failed: the terminal went away. The frame is dropped.
    Gone(std::io::Error),
}

/// Why `begin` refused a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// A frame is still pending.
    Busy,
    /// Over `FRAME_MAX`.
    TooBig,
}

#[derive(Debug, Default)]
pub struct FrameWriter {
    /// The frame being written, wrapped; empty when none.
    frame: Vec<u8>,
    /// Its bytes the terminal took.
    taken: usize,
    /// The sink was told the frame began.
    marked: bool,
    /// When the terminal last took a byte of it (or it began).
    progress: Option<Instant>,
    /// A frame is due.
    due: bool,
}

impl FrameWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The editor's state changed: a frame is due.
    pub fn request(&mut self) {
        self.due = true;
    }

    /// No frame pending.
    pub fn idle(&self) -> bool {
        self.frame.is_empty()
    }

    /// A frame is due and none is pending: build one now, from the latest
    /// state, and `begin` it.
    pub fn wants_frame(&self) -> bool {
        self.due && self.idle()
    }

    /// Bytes are pending: the loop's wait should report when the terminal
    /// can take more.
    pub fn wants_write(&self) -> bool {
        !self.idle()
    }

    /// Starts writing `frame` (built whole) at `now`. Nothing is written
    /// until `flush`.
    pub fn begin(&mut self, frame: &[u8], now: Instant) -> Result<(), Refused> {
        // 이것을 실패시키는 것: 쓰는 중인 프레임 뒤에 새 프레임을 받는 것(반쪽 프레임 뒤에 다른 프레임이 끼어듦),
        // 크기 상한을 보지 않거나 하나 어긋나게 보는 것.
        if !self.idle() {
            return Err(Refused::Busy);
        }
        if frame.len() > FRAME_MAX {
            return Err(Refused::TooBig);
        }
        self.frame.extend_from_slice(SYNC_BEGIN);
        self.frame.extend_from_slice(frame);
        self.frame.extend_from_slice(SYNC_END);
        self.taken = 0;
        self.marked = false;
        self.progress = Some(now);
        self.due = false;
        Ok(())
    }

    /// Writes what is pending until the terminal takes no more now, at most
    /// `WRITES_PER_FLUSH` writes. Call it after `begin` and whenever the
    /// terminal can take more.
    pub fn flush(&mut self, sink: &mut impl Sink, now: Instant) -> Flushed {
        if self.idle() {
            return Flushed::Done;
        }
        // 이것을 실패시키는 것: 첫 바이트 전에 알리지 않는 것(첫 쓰기에서 끊긴 프레임의 2026이 남음), 두 번 알리는 것.
        if !self.marked {
            sink.mark_synced(true);
            self.marked = true;
        }
        for _ in 0..WRITES_PER_FLUSH {
            let rest = self.frame.get(self.taken..).unwrap_or(&[]);
            match sink.write_some(rest) {
                Ok(0) => break,
                Ok(n) => {
                    // 이것을 실패시키는 것: 받은 만큼 진행 시각을 새로 하지 않는 것(조금씩이라도 받는 터미널을 정체로 봄).
                    self.taken = self.taken.saturating_add(n);
                    self.progress = Some(now);
                    if self.taken >= self.frame.len() {
                        // 이것을 실패시키는 것: 마지막 바이트를 받은 뒤 알리지 않는 것(끝난 프레임인데 나갈 때 2026 l을 또 보냄),
                        // 끝난 프레임을 비우지 않는 것(다음 프레임을 받지 않음).
                        self.clear();
                        sink.mark_synced(false);
                        return Flushed::Done;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                    break;
                }
                Err(e) => {
                    self.clear();
                    return Flushed::Gone(e);
                }
            }
        }
        if self.stalled(now) {
            Flushed::Stalled
        } else {
            Flushed::Pending
        }
    }

    /// A frame is pending and the terminal took nothing of it for `STALL`.
    pub fn stalled(&self, now: Instant) -> bool {
        // 이것을 실패시키는 것: 비교를 `>`로 바꾸는 것(정확히 2 s에 정체로 보지 않음), 대기 중인 프레임이 없는데도
        // 정체로 보는 것.
        self.deadline().is_some_and(|d| now >= d)
    }

    /// When a pending frame counts as stalled; `None` when none is pending.
    pub fn deadline(&self) -> Option<Instant> {
        // `progress` is set from `begin` until the frame is done or dropped.
        self.progress.and_then(|p| p.checked_add(STALL))
    }

    /// Drops the frame in progress (the terminal was given back and taken
    /// again; the screen it was drawn for is gone) and makes a frame due:
    /// draw the whole screen.
    pub fn discard(&mut self) {
        self.clear();
        self.due = true;
    }

    fn clear(&mut self) {
        self.frame.clear();
        self.taken = 0;
        self.marked = false;
        self.progress = None;
    }
}

#[cfg(test)]
mod tests;
