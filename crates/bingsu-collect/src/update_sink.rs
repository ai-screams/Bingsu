//! Immediate, bounded response writes. The receiver's codec is also the
//! sender's policy: no separate ordering, frame, stream or storage counters.
use std::io;
use std::{cell::Cell, time::Instant};

use bingsu_core::{
    collection::{
        language::LanguageResult,
        wire::{self, Frame, Kind, Progress, Request, Transcript, Update},
    },
    field::SegmentDecl,
};

#[allow(
    dead_code,
    reason = "product collection stays disabled until stage integration"
)]
pub(crate) trait UpdateSink {
    fn stage_deadline(&mut self, _deadline: Instant) {}
    fn update(&mut self, value: Update) -> io::Result<()>;
    fn progress(&mut self, value: Progress) -> io::Result<()>;
    /// One language's detection result (D1). A sink for a request without
    /// languages never receives one.
    fn language(&mut self, _value: LanguageResult) -> io::Result<()> {
        Err(io::Error::other("this sink takes no language result"))
    }
}

/// A language result past the stage deadline: nothing was written and the
/// response goes on (security review S-M for D1). The stage stops sending
/// languages; later frames and Complete are unaffected.
#[derive(Debug)]
pub(crate) struct LateLanguage;

impl std::fmt::Display for LateLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("language result past the stage deadline")
    }
}

impl std::error::Error for LateLanguage {}

pub(crate) fn late_language() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, LateLanguage)
}

pub(crate) fn is_late_language(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<LateLanguage>())
}

pub(crate) struct WireSink<'a> {
    request: &'a Request,
    transcript: Transcript,
    buffer: &'a mut [u8; wire::FRAME_MAX],
    write: &'a mut dyn FnMut(&[u8]) -> io::Result<()>,
    stopped: bool,
    deadline: Option<Instant>,
    write_deadline: Option<&'a Cell<Instant>>,
}

impl<'a> WireSink<'a> {
    /// Ready has already been written successfully and the one request decoded.
    /// Account for that exact Ready, including its frame and byte costs.
    pub(crate) fn new(
        request: &'a Request,
        catalog: &[SegmentDecl],
        ready_payload: &[u8],
        buffer: &'a mut [u8; wire::FRAME_MAX],
        write: &'a mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<Self> {
        let mut transcript = Transcript::with_catalog(request, catalog).map_err(protocol)?;
        transcript
            .accept(Frame {
                kind: Kind::Ready,
                build_id: request.binding.build_id,
                request_id: request.request_id,
                payload: ready_payload,
            })
            .map_err(protocol)?;
        transcript.request_sent().map_err(protocol)?;
        Ok(Self {
            request,
            transcript,
            buffer,
            write,
            stopped: false,
            deadline: None,
            write_deadline: None,
        })
    }

    /// The worker's short-write loop observes the same stage boundary. The
    /// request deadline remains a separate, immutable upper bound there.
    #[allow(
        dead_code,
        reason = "codec-only integration targets omit worker pipe IO"
    )]
    pub(crate) fn attach_write_deadline(&mut self, deadline: &'a Cell<Instant>) {
        self.write_deadline = Some(deadline);
    }

    /// Only the exchange owner completes a successful callback. A callback
    /// that swallows a sink error still cannot send Complete or any later frame.
    pub(crate) fn complete(&mut self) -> io::Result<()> {
        self.send(Kind::Complete, &[])
    }

    fn active(&self) -> io::Result<()> {
        if self.stopped {
            Err(io::Error::other("worker response stopped"))
        } else {
            Ok(())
        }
    }

    fn send(&mut self, kind: Kind, payload: &[u8]) -> io::Result<()> {
        self.active()?;
        // Latch before encoding, validation or writing. The core transcript
        // intentionally stays reusable after rejection; this I/O adapter must not.
        self.stopped = true;
        let frame = Frame {
            kind,
            build_id: self.request.binding.build_id,
            request_id: self.request.request_id,
            payload,
        };
        let n = wire::encode_frame(frame, self.buffer).map_err(protocol)?;
        self.transcript.accept(frame).map_err(protocol)?;
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        (self.write)(&self.buffer[..n])?;
        self.stopped = kind == Kind::Complete;
        Ok(())
    }

    /// Preserve the pre-existing test-only segment-31 fixture codec. Product
    /// callers can only submit typed builtin Updates; both paths use send().
    #[cfg(test)]
    pub(super) fn fixture_update(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send(Kind::Update, payload)
    }
}

impl UpdateSink for WireSink<'_> {
    fn stage_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
        if let Some(write_deadline) = self.write_deadline {
            write_deadline.set(deadline);
        }
    }
    fn update(&mut self, value: Update) -> io::Result<()> {
        self.active()?;
        self.stopped = true;
        let payload = value.encode(&self.request.binding).map_err(protocol)?;
        self.stopped = false;
        self.send(Kind::Update, &payload)
    }

    fn progress(&mut self, value: Progress) -> io::Result<()> {
        self.send(Kind::Progress, &value.encode())
    }

    fn language(&mut self, value: LanguageResult) -> io::Result<()> {
        // Before the transcript and the latch: a late result is not sent and
        // stops nothing. Fails without it: late_language_leaves_the_stream_open.
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(late_language());
        }
        self.send(Kind::Language, &value.encode())
    }
}

fn protocol(error: wire::ProtocolError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("worker protocol: {error:?}"),
    )
}
