//! What the prompt draws from a command response (C4b): a unit's value only
//! when every part of the response that ran it matches this prompt. The
//! prompt reads the response the helper published for its context and cwd,
//! and draws an entry when
//! - the response's binding is the one this prompt expects (build, boot,
//!   epoch, context, clock, roots, cwd) and its clock is this prompt's;
//! - the entry completed before this prompt began;
//! - the unit runs now (no `not_run`) and its policy digest is the one the
//!   entry ran with;
//! - this shell's original environment digest (the keep list, `LC_*` and
//!   the unit's `env_allow`) is the one the entry ran with;
//! - the entry succeeded (a failure shows nothing) and carries no `match`
//!   pattern (the prompt does not apply patterns; C4b ruling Q4);
//! - for a config unit, the marker makes the snapshot's units eligible for
//!   display (the security review's C4b condition). A builtin probe has no
//!   such condition (D3 ruling Q3).
//!
//! The value is sanitized text (`response` refuses anything else); the
//! renderer cuts it to the segment's cells.
use super::{
    plan::{self, Environ},
    response::{Binding, Response, Status},
    wire::policy_digest,
};
use crate::{config::compile::ExecUnit, handoff::Origin, snapshot::Clock};

/// This prompt's side of the comparison.
pub struct Prompt<'a> {
    /// The binding this prompt would publish under.
    pub expected: &'a Binding,
    /// This prompt's entry clock.
    pub entry: Clock,
    /// This shell's environment, as the prompt hands it to the helper.
    pub vars: &'a Environ<'a>,
    /// Whether the marker makes the snapshot's config units eligible.
    pub eligible: bool,
}

/// The value `unit` shows under `origin`, or `None`.
pub fn value<'r>(
    response: &'r Response,
    prompt: &Prompt<'_>,
    unit: &ExecUnit,
    origin: Origin,
) -> Option<&'r str> {
    if origin == Origin::Config && !prompt.eligible {
        return None;
    }
    if !response.eligible(prompt.expected, prompt.entry) {
        return None;
    }
    let runnable = plan::runnable(unit)?;
    let entry = response.entry(origin, &unit.id)?;
    let policy = policy_digest(
        &runnable.policy,
        runnable.cwd,
        runnable.timeout,
        &runnable.env_allow,
    );
    (entry.status == Status::Ok
        && entry.pattern == [0; 32]
        && entry.completed_at < prompt.entry.now
        && entry.policy == policy
        && entry.environment == plan::env_digest(prompt.vars, &runnable.env_allow))
    .then_some(entry.value.as_str())
}

#[cfg(test)]
mod tests;
