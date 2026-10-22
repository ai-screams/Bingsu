//! Immediate, bounded response writes. The receiver's codec is also the
//! sender's policy: no separate ordering, frame, stream or storage counters.
use std::io;

use bingsu_core::{
    collection::wire::{self, Frame, Kind, Progress, Request, Transcript, Update},
    field::SegmentDecl,
};

#[allow(
    dead_code,
    reason = "product collection stays disabled until stage integration"
)]
pub(crate) trait UpdateSink {
    fn update(&mut self, value: Update) -> io::Result<()>;
    fn progress(&mut self, value: Progress) -> io::Result<()>;
}

pub(crate) struct WireSink<'a> {
    request: &'a Request,
    transcript: Transcript,
    buffer: &'a mut [u8; wire::FRAME_MAX],
    write: &'a mut dyn FnMut(&[u8]) -> io::Result<()>,
    stopped: bool,
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
        })
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
}

fn protocol(error: wire::ProtocolError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("worker protocol: {error:?}"),
    )
}
