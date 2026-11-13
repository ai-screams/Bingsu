//! Waiting for an interactive child (the editor of `config edit`) the way
//! `git commit` waits for its editor. Ctrl-C and Ctrl-\ at the terminal go
//! to the whole foreground process group: the editor gets them and decides
//! what they mean, while bingsu ignores SIGINT and SIGQUIT until the editor
//! has ended and then puts its previous handling back. A SIGINT or SIGQUIT
//! sent to bingsu with `kill` during the wait is ignored the same way.
//!
//! Order. The child is started first and the signals are ignored after it.
//! An ignored signal stays ignored across exec (only caught ones go back to
//! the default), and std resets only SIGPIPE in a child, so ignoring first
//! would hand the editor SIG_IGN for Ctrl-C. In the short gap between the
//! start and the ignore a Ctrl-C still ends bingsu (and the editor with it);
//! nothing has been applied by then, so the settings stay as they were.
//!
//! The allow for `unsafe` is on `mod signal_guard;` in commands/mod.rs; each
//! block is one operation with a SAFETY comment.
// The clippy.toml rules are forbidden here, as in sys.rs.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use std::io;
use std::process::{Command, ExitStatus};

/// The signals the terminal sends to the foreground group for Ctrl-C and
/// Ctrl-\.
const IGNORED: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];

/// Starts `cmd` and waits for it with SIGINT and SIGQUIT ignored in this
/// process; the previous handling is back when it returns, also on error.
/// The child starts with the handling this process had (the default, unless
/// a caller ignored them), in this process group, so Ctrl-C reaches it. The
/// caller reads the status: an editor ended by Ctrl-C has
/// `ExitStatusExt::signal() == Some(SIGINT)`.
pub fn run_ignoring_interrupts(cmd: &mut Command) -> io::Result<ExitStatus> {
    let mut child = cmd.spawn()?;
    let _ignored = Ignored::new();
    child.wait()
}

/// SIGINT and SIGQUIT ignored while it lives. Private: built only after
/// the child has started (see the module comment).
struct Ignored {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Ignored {
    fn new() -> Ignored {
        let mut previous = Vec::with_capacity(IGNORED.len());
        for sig in IGNORED {
            if let Some(old) = ignore(sig) {
                previous.push((sig, old));
            }
        }
        Ignored { previous }
    }
}

impl Drop for Ignored {
    fn drop(&mut self) {
        for (sig, old) in self.previous.iter().rev() {
            // SAFETY: `old` is the action sigaction returned for `sig`; no
            // old action is requested.
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
    }
}

/// Sets `sig` to SIG_IGN; the previous action, or `None` when sigaction
/// failed and nothing changed (then there is nothing to put back). It fails
/// only for an invalid signal number, which a test cannot reach, so no
/// mutation was run for that arm.
fn ignore(sig: libc::c_int) -> Option<libc::sigaction> {
    // SAFETY: an all-zero sigaction is SIG_DFL with no flags and an empty
    // mask; the disposition is set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_IGN;
    // SAFETY: as above, storage for the previous action.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: both actions are valid for the call.
    if unsafe { libc::sigaction(sig, &action, &mut old) } != 0 {
        return None;
    }
    Some(old)
}

#[cfg(test)]
mod tests;
