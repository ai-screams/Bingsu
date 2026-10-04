//! `bingsu prompt`: envelope -> status -> one record on fd 1, exit 0.
//! M1 has no renderer (M2), so accepted envelopes yield the minimal record.
use crate::envelope::{self, EnvelopeError};
use crate::sys;
use bingsu_core::record::write_minimal_b1;
use bingsu_core::status::Status;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};

static PANICKED: AtomicBool = AtomicBool::new(false);

fn build(args: &[&[u8]], out: &mut Vec<u8>) {
    match envelope::parse(args) {
        Err(EnvelopeError::NoSupportedRecordVersion) => {}
        Err(EnvelopeError::BadArgs(_)) => write_minimal_b1(Status::ERROR_BAD_ARGS, out),
        Ok(env) => {
            let status = if env.runtime_root.is_none() {
                Status::DEGRADED_RUNTIME_ROOT
            } else {
                Status::OK_NONE
            };
            write_minimal_b1(status, out);
        }
    }
}

pub fn run(args: &[OsString]) -> ! {
    // The default hook writes to stderr before unwinding (spec section 6
    // rule 1). This one only records in memory.
    std::panic::set_hook(Box::new(|_| PANICKED.store(true, Ordering::Relaxed)));
    let raw: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    let mut out = Vec::with_capacity(256);
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(&raw, &mut out)));
    if built.is_err() || PANICKED.load(Ordering::Relaxed) {
        out.clear();
        if raw.windows(2).any(|w| w[0] == b"--record" && w[1] == b"B1") {
            write_minimal_b1(Status::ERROR_INTERNAL, &mut out);
        }
    }
    let _ = sys::write_fd(1, &out);
    sys::exit_now(0)
}
