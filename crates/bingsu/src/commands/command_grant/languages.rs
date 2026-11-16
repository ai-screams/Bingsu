//! The round's language answers: which user-defined and builtin languages ran where, and
//! where a language's files were found.
use super::*;

/// This round's language answers, by the asked language's id: what
/// the collector found for each version selection file. Empty when the
/// collection did not run or did not finish.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Languages {
    pub(super) answers: Vec<(Vec<u8>, bingsu_core::collection::language::Version)>,
    /// Whether each answered language's marker files were found.
    pub(super) found: Vec<(Vec<u8>, bool)>,
    /// What the folder facts say of the repository (D3a review H1).
    pub(super) root: Root,
}

/// The repository the folder facts found for the shell's folder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Root {
    /// No facts, or facts that could not settle it: an alias folder path,
    /// a search cut at its depth limit. Builtin languages are not decided.
    #[default]
    Unknown,
    /// Confirmed outside any repository.
    Outside,
    /// Inside, the root at this component of the shell's folder.
    Repo(u16),
}

impl Root {
    /// From one round's folder facts (re-review H1: `in_repo` unknown, or
    /// in a repository whose root component is not known, is unknown).
    pub(crate) fn of(facts: &bingsu_core::collection::path_facts::PathFactInput) -> Self {
        // Fails without each: roots_stay_unknown_unless_settled.
        match (facts.in_repo, facts.repo_component) {
            (Some(false), _) => Self::Outside,
            (Some(true), Some(component)) => Self::Repo(component),
            _ => Self::Unknown,
        }
    }
}

impl Languages {
    /// The answers of a finished collection, by the asked language's id.
    pub(crate) fn from_result(c: &bingsu_core::collection::response::Completed) -> Self {
        let answers = c
            .languages
            .iter()
            .filter_map(|l| {
                let q = c.language_queries.get(usize::from(l.index))?;
                Some((q.id.clone(), l.version.clone()))
            })
            .collect();
        let found = c
            .languages
            .iter()
            .filter_map(|l| {
                let q = c.language_queries.get(usize::from(l.index))?;
                Some((q.id.clone(), l.marker.is_some()))
            })
            .collect();
        let root = c
            .updates
            .iter()
            .find_map(|u| u.facts.as_ref())
            .map_or(Root::Unknown, Root::of);
        Self {
            answers,
            found,
            root,
        }
    }

    /// Whether the builtin languages may be decided this round: the
    /// collection answered them, and its folder facts name the same
    /// repository the round searches with (`repo`). Without the facts the
    /// shell's folder would stand for the repository, and an executable
    /// inside the real one could run (D3a review H1).
    pub(crate) fn ready(&self, repo: Option<u16>) -> bool {
        // Fails without each: a_round_with_nothing_to_decide_searches_nothing,
        // and test_builtin_probe_never_runs_from_the_repository (no facts).
        !self.answers.is_empty()
            && match self.root {
                Root::Unknown => false,
                Root::Outside => repo.is_none(),
                Root::Repo(component) => repo == Some(component),
            }
    }

    /// Whether a user-defined language's marker files were found this
    /// round: `None` when the collection did not answer
    /// it or its folder facts do not settle the repository the round
    /// searches with (`ready`), so the language is not decided either way.
    pub(crate) fn detected(&self, id: &[u8], repo: Option<u16>) -> Option<bool> {
        if !self.ready(repo) {
            return None;
        }
        self.found.iter().find(|(a, _)| a == id).map(|(_, f)| *f)
    }

    /// Answers and a root as a collection would give them (tests).
    #[cfg(test)]
    pub(crate) fn of(
        answers: Vec<(Vec<u8>, bingsu_core::collection::language::Version)>,
        root: Root,
    ) -> Self {
        Self {
            answers,
            found: Vec::new(),
            root,
        }
    }

    /// What the folder facts say of the repository.
    pub(crate) fn root(&self) -> Root {
        self.root
    }

    /// The answer for language `id`, if the collection gave one.
    pub(crate) fn get(&self, id: &[u8]) -> Option<&bingsu_core::collection::language::Version> {
        self.answers.iter().find(|(a, _)| a == id).map(|(_, v)| v)
    }
}

/// The language units this round does not run (`skip`: their marker files
/// were not found, or the collection did not settle it) and, of those, the
/// ones whose files it looked for and did not find (`hide`).
pub(super) fn gate_languages(
    units: &[String],
    languages: &Languages,
    repo: Option<u16>,
) -> (Vec<String>, Vec<String>) {
    let mut skip = Vec::new();
    let mut hide = Vec::new();
    for id in units {
        match languages.detected(id.as_bytes(), repo) {
            Some(true) => {}
            Some(false) => {
                skip.push(id.clone());
                hide.push(id.clone());
            }
            None => skip.push(id.clone()),
        }
    }
    (skip, hide)
}

/// A language unit's entry: the version word of the first line it printed
/// (`profile::any_version`); a line with none is a failed
/// entry with no value.
pub(super) fn language_entry(mut e: response::Entry) -> response::Entry {
    if e.status == response::Status::Ok {
        // Fails without it: a_language_entry_keeps_only_its_version.
        match bingsu_core::command::profile::any_version(&e.raw) {
            Some(v) => e.value = v.to_owned(),
            None => {
                e.status = response::Status::Failed;
                e.value.clear();
                e.raw.clear();
            }
        }
    }
    e
}

/// The policy digest of a language unit hidden because its marker files
/// were not found: no running unit has it.
pub(super) fn undetected(id: &str) -> [u8; 32] {
    bingsu_core::collection::cwd_hash::sha256(
        &[b"bingsu-language-undetected\0".as_slice(), id.as_bytes()].concat(),
    )
}
