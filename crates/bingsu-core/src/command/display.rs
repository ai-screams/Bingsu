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
//! - the entry succeeded (a failure shows nothing) and its pattern digest
//!   is the one of the unit's `match` in this snapshot (all zeros without
//!   one): the helper applied that pattern, and the prompt never runs one
//!   (U-9c). An entry matched under an older `match` shows nothing until the
//!   helper applies the new one;
//! - for a config unit, the marker makes the snapshot's units eligible for
//!   display (the security review's C4b condition). A builtin probe has no
//!   such condition (D3 ruling Q3).
//!
//! A builtin language's version (`builtin_value`, D3b rulings Q1–Q3) needs
//! the same binding, clock, completion and success, and this shell's
//! environment digest over the language's variables
//! (`builtin::Language::env_digest`), so a shell whose `PATH`, `HOME` or
//! manager variables differ does not see another shell's version in the same
//! folder. Its policy digest is not checked here: it binds facts only the
//! helper sees (the executable's identity, the toolchain, the selection
//! file), and the response is the helper's own file under the runtime root.
//! The value must also be a version name (`collection::language::version_ok`),
//! and this shell's environment must have been read whole: a frame with an
//! entry left out (malformed, or a name given twice) shows no builtin value,
//! as the helper decides none from it (`builtin_probe::whole`). Otherwise a
//! shell whose only difference is a variable given twice would digest like
//! one without it.
//!
//! The value is sanitized text (`response` refuses anything else); the
//! renderer cuts it to the segment's cells.
use super::{
    builtin::Language,
    plan::{self, Environ},
    response::{Binding, Response, Status},
    wire::{pattern_digest, policy_digest},
};
use crate::{config::compile::ExecUnit, handoff::Origin, snapshot::Clock};
use alloc::vec::Vec;

/// This prompt's side of the comparison, bound to the response it reads.
pub struct Prompt<'a> {
    response: &'a Response,
    entry: Clock,
    vars: &'a Environ<'a>,
    /// Whether the marker makes the snapshot's config units eligible.
    eligible: bool,
    /// The environment digest per `env_allow` list already computed: units
    /// that allow the same names share one digest of this shell.
    digests: Vec<(Vec<Vec<u8>>, [u8; 32])>,
}

impl<'a> Prompt<'a> {
    /// `None` when `response` may not be used by this prompt at all: another
    /// binding than `expected` (build, boot, epoch, context, roots, cwd) or
    /// another clock than `entry`. Checked once for every unit.
    pub fn new(
        response: &'a Response,
        expected: &Binding,
        entry: Clock,
        vars: &'a Environ<'a>,
        eligible: bool,
    ) -> Option<Self> {
        response.eligible(expected, entry).then(|| Self {
            response,
            entry,
            vars,
            eligible,
            digests: Vec::new(),
        })
    }

    /// `plan::env_digest` of this shell for `env_allow`, once per list.
    fn env_digest(&mut self, env_allow: &[Vec<u8>]) -> [u8; 32] {
        if let Some((_, d)) = self.digests.iter().find(|(k, _)| k == env_allow) {
            return *d;
        }
        let d = plan::env_digest(self.vars, env_allow);
        self.digests.push((env_allow.to_vec(), d));
        d
    }
}

/// The value `unit` shows under `origin`, or `None`.
pub fn value<'r>(prompt: &mut Prompt<'r>, unit: &ExecUnit, origin: Origin) -> Option<&'r str> {
    if origin == Origin::Config && !prompt.eligible {
        return None;
    }
    let runnable = plan::runnable(unit)?;
    let entry = prompt.response.entry(origin, &unit.id)?;
    let policy = policy_digest(
        &runnable.policy,
        runnable.cwd,
        runnable.timeout,
        &runnable.env_allow,
    );
    (entry.status == Status::Ok
        && entry.pattern == pattern_digest(unit.pattern.as_deref())
        && entry.completed_at < prompt.entry.now
        && entry.policy == policy
        && entry.environment == prompt.env_digest(&runnable.env_allow))
    .then_some(entry.value.as_str())
}

/// The version `language` shows, or `None`.
pub fn builtin_value<'r>(prompt: &Prompt<'r>, language: &Language) -> Option<&'r str> {
    let entry = prompt.response.entry(Origin::Builtin, language.id)?;
    let whole = prompt.vars.dropped.malformed + prompt.vars.dropped.duplicate == 0;
    (whole
        && entry.status == Status::Ok
        && entry.pattern == [0; 32]
        && entry.completed_at < prompt.entry.now
        && entry.environment == language.env_digest(prompt.vars)
        && crate::collection::language::version_ok(entry.value.as_bytes()))
    .then_some(entry.value.as_str())
}

#[cfg(test)]
mod tests;
