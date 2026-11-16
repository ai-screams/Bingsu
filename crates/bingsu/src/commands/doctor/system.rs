//! The seccomp row (what the kernel supports) and the settings row (what `config
//! check` finds).
use super::*;

// ---- seccomp -------------------------------------------------------------------

pub(super) fn judge_seccomp(k: SeccompKernel) -> Finding {
    match k {
        SeccompKernel::Supported => finding(Status::Ok, "the kernel supports seccomp", None),
        SeccompKernel::Absent => finding(
            Status::Warn,
            "the kernel has no seccomp; the prompt runs without its system call filter",
            Some(codes::NO_KERNEL_SECCOMP),
        ),
        SeccompKernel::NotApplicable => {
            finding(Status::Skipped, "this platform has no seccomp", None)
        }
        SeccompKernel::Failed(errno) => finding(
            Status::Unknown,
            format!("the kernel's answer could not be read (error {errno})"),
            None,
        ),
    }
}

pub(super) fn run_seccomp(_: &Ctx) -> Finding {
    judge_seccomp(sys::seccomp_kernel())
}

// ---- settings --------------------------------------------------------------------

pub(super) fn judge_settings(code: u8, errors: usize, warnings: usize) -> Finding {
    match code {
        0 => finding(
            Status::Ok,
            format!("the settings check out ({warnings} warning(s))"),
            None,
        ),
        EXIT_FAILED => finding(
            Status::Fail,
            format!("the settings have {errors} error(s); the prompt keeps the last good ones"),
            Some(codes::SETTINGS_INVALID),
        ),
        _ => finding(
            Status::Unknown,
            "the settings could not be read to the end",
            None,
        ),
    }
}

/// The settings could not be opened at all: a confirmed refusal (a folder
/// that fails its checks, a missing one) is a failure, as `config check`
/// exits 1 for it; anything else is not known.
pub(super) fn judge_settings_unread(code: u8, text: &str) -> Finding {
    if code == EXIT_FAILED {
        finding(Status::Fail, text, Some(codes::SETTINGS_INVALID))
    } else {
        finding(Status::Unknown, text, None)
    }
}

fn judge_inspection(i: &Inspection) -> Finding {
    let count = |s: Severity| {
        i.report
            .diagnostics
            .iter()
            .filter(|d| d.severity() == s)
            .count()
    };
    judge_settings(
        exit_for(i),
        count(Severity::Error),
        count(Severity::Warning),
    )
}

pub(super) fn run_settings(c: &Ctx) -> Finding {
    match inspect_config(&c.user, &c.env) {
        Ok(i) => judge_inspection(&i),
        Err((text, code)) => judge_settings_unread(code, &text),
    }
}
