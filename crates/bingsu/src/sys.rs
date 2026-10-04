//! The only module in this crate allowed to use `unsafe` (the allow is on
//! `mod sys;` in main.rs). Every block carries a SAFETY comment (workspace lint).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Done,
    /// EPIPE or another error: the shell will see a truncated record and
    /// fall back to its minimal prompt. We stay silent (spec section 6).
    /// EAGAIN is not retried and ends as `Failed`: on a non-blocking fd the
    /// record may be cut short and the shell falls back to its minimal prompt.
    Failed,
}

/// Hand-written write(2) loop. `write_all` retries EINTR on its own, which
/// a timer could not interrupt (spec section 4 "output rules"). M3a adds
/// the deadline-flag check on EINTR; M1 has no timer yet.
pub fn write_fd(fd: i32, mut buf: &[u8]) -> WriteOutcome {
    while !buf.is_empty() {
        // SAFETY: `buf` is an initialized slice valid for `buf.len()` bytes.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return WriteOutcome::Failed;
        }
        let n = usize::try_from(n).unwrap_or(0);
        // A zero return on a non-empty buffer means no progress on an
        // ordinary fd; retrying would spin and the prompt must never block.
        // Not reproducible from a test, so no mutation was run for this arm.
        if n == 0 {
            return WriteOutcome::Failed;
        }
        buf = &buf[n.min(buf.len())..];
    }
    WriteOutcome::Done
}

/// `_exit` without atexit handlers (spec section 4, `std::process::exit`
/// is rejected).
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit never returns and takes no pointers.
    unsafe { libc::_exit(code) }
}
