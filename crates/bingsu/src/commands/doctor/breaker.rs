//! The collection-breaker row: whether this shell session has switched off
//! collection for the folder it is in. It never looks at the folder itself: a
//! stopped mount is when the breaker is on, and a stat of it would stop doctor too.
use super::*;

// ---- the collection breaker -------------------------------------------------------

/// What reading this session's breaker gave: `Err` when it could not be read
/// safely.
pub(super) fn judge_breaker(read: Result<Peek, ()>) -> Finding {
    match read {
        Ok(Peek::Blocked) => finding(
            Status::Warn,
            "collection is switched off for this folder in this shell session for a while (the same mount missed its deadline three times in a row); the prompt still draws",
            Some(codes::COLLECTION_BREAKER_ON),
        ),
        Ok(Peek::NoRecord) => finding(
            Status::Ok,
            "this session has no breaker record for this folder: collection is not switched off",
            None,
        ),
        Ok(Peek::Allowed) => finding(Status::Ok, "collection is on for this folder", None),
        Ok(Peek::Probe) => finding(
            Status::Ok,
            "the wait is over: the next prompt tries collection in this folder again",
            None,
        ),
        Ok(Peek::Disabled) => finding(
            Status::Unknown,
            "the breaker record is from another boot or clock, so it says nothing about now",
            None,
        ),
        Err(()) => finding(
            Status::Unknown,
            "the breaker record could not be read safely; the pinned folders check says whether the runtime folder is safe",
            None,
        ),
    }
}

/// A breaker row that cannot be confirmed, with the reason.
fn breaker_unknown(why: &str) -> Finding {
    finding(
        Status::Unknown,
        format!("the collection breaker is not confirmed: {why}"),
        None,
    )
}

/// The folder key the prompt used: the shell's `PWD`, as the prompt's own
/// envelope rule takes it (an absolute path of a bounded length). The string is
/// the key as it is: the helper keys the breaker by the `$PWD` the shell passed,
/// and the folder is never looked at here, since a stopped mount is exactly
/// when the breaker is on and a look at it would stop this command too.
pub(super) fn shell_pwd(pwd: Option<&OsStr>) -> Result<Vec<u8>, &'static str> {
    let Some(pwd) = pwd else {
        return Err(
            "the shell does not export PWD to its commands, so the folder the prompt used is not known",
        );
    };
    // `--width` is a required word of the envelope; its value does not matter here.
    let argv: [&[u8]; 8] = [
        b"--ctx",
        b"1",
        b"--record",
        b"B1",
        b"--width",
        b"80",
        b"--pwd",
        pwd.as_bytes(),
    ];
    match bingsu_core::envelope::parse(&argv) {
        Ok(e) => e.pwd.ok_or(
            "PWD is not an absolute path the prompt accepts, so the folder it used is not known",
        ),
        Err(_) => Err("PWD could not be read as the prompt reads it"),
    }
}

pub(super) fn run_breaker(c: &Ctx) -> Finding {
    let session = match doctor_evidence::session_of(&c.evidence) {
        Ok(s) => s,
        Err(f) => return f,
    };
    // The runtime folder is the one init pinned in this shell and nothing else:
    // a pin that no longer holds (the folder was made again) must not let the
    // folder in its place stand in for it, since an empty folder has no record.
    let Some(value) = TrustedEnv::pinned_roots() else {
        return breaker_unknown(
            "init has not pinned the folders in this shell (see the pinned folders check)",
        );
    };
    let Some(runtime) = pinned::open_runtime(
        value.as_bytes(),
        c.user.me,
        &c.user.pw.name,
        &c.user.pw.home,
    ) else {
        return breaker_unknown(
            "the folders init pinned do not hold now (see the pinned folders check)",
        );
    };
    let (_, pwd) = TrustedEnv::shell();
    let cwd = match shell_pwd(pwd.as_deref()) {
        Ok(cwd) => cwd,
        Err(why) => return breaker_unknown(why),
    };
    let Ok(now) = crate::prompt_io::observe_clock() else {
        return judge_breaker(Err(()));
    };
    judge_breaker(collection_breaker::peek(&runtime, &session, &cwd, now).map_err(|_| ()))
}
