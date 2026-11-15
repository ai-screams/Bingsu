//! A round's results as command-response entries, and publishing them.
use super::*;

impl Publish {
    /// The `match` of runnable unit `id`.
    pub(super) fn pattern(&self, id: &str) -> Option<&str> {
        self.patterns
            .iter()
            .find(|(u, _)| u == id)
            .and_then(|(_, p)| p.as_deref())
    }

    /// Publishes the re-matched entries of a round where nothing runs.
    pub(crate) fn publish_reapplied(&self) -> Result<response::Response, StoreError> {
        self.publish_entries(&self.reapplied)
    }

    /// Publishes `entries` into the command response of this context and
    /// cwd: the store of the collection response, under its lock. A store another round holds is no publication: the
    /// next round
    /// runs those units again.
    pub(super) fn publish_entries(
        &self,
        entries: &[response::Entry],
    ) -> Result<response::Response, StoreError> {
        let p = self;
        let now = bingsu_core::snapshot::Clock {
            now: now_ns().map_err(StoreError::Io)?,
            ..p.clock
        };
        match super::super::collection_store::CollectionStore::admit_commands(
            &p.context, &p.binding, now,
        )? {
            super::super::collection_store::Admission::Admitted(mut store) => {
                store.publish_commands(&p.binding, entries)
            }
            super::super::collection_store::Admission::Deferred(_) => Err(StoreError::Busy),
        }
    }
}

/// A builtin entry decided without running anything, at `now`.
pub(super) fn decided(
    p: &Planned,
    now: u64,
    status: response::Status,
    value: String,
) -> response::Entry {
    response::Entry {
        origin: Origin::Builtin,
        id: p.language.id.to_owned(),
        policy: p.policy,
        environment: p.environment,
        pattern: [0; 32],
        attempted_at: now,
        completed_at: now,
        status,
        raw: value.clone(),
        value,
    }
}

impl Round {
    /// The builtin languages of this round (D3a): each decided without
    /// running (shown or hidden), or a probe added to the grant unless its
    /// cached result stands. A language the collection did not answer
    /// (it did not run or did not finish) is left as it was.
    /// Returns how many times the shell's folder was made canonical.
    pub(super) fn plan_builtins(
        &mut self,
        languages: &Languages,
        found: &Search,
        me: u32,
        groups: &mut SystemGroups,
    ) -> u32 {
        if self.builtins.is_empty() {
            return 0;
        }
        let environment = self.environment.clone();
        let vars = Environ::parse(&environment);
        let shell_folder = self.grant.cwd.clone();
        let resolved = std::cell::Cell::new(0);
        let c = builtin_probe::Context {
            vars: builtin_probe::whole(&vars),
            folders: &found.folders,
            repo: &found.repo,
            cwd: &shell_folder,
            me,
            xcode_link: Path::new(builtin_probe::XCODE_SELECT_LINK),
            command_line_tools: Path::new(builtin_probe::COMMAND_LINE_TOOLS),
            resolved: &resolved,
        };
        let now = now_ns().unwrap_or(self.publish.clock.now);
        for language in self.builtins.clone() {
            let Some(version) = languages.get(language.id.as_bytes()) else {
                continue;
            };
            let p = builtin_probe::plan(language, version, &c, groups);
            let current = self
                .current
                .as_ref()
                .and_then(|r| r.entry(Origin::Builtin, language.id))
                .cloned();
            let current = current.as_ref();
            let (status, value) = match &p.action {
                Action::Show(value) => (response::Status::Ok, value.clone()),
                Action::Hide(why) => {
                    self.hidden.push(why);
                    (response::Status::Failed, String::new())
                }
                Action::Run(probe) => {
                    self.run_probe(&p, probe.clone(), current);
                    continue;
                }
            };
            // The same decision already published is not written again: a
            // fast or hidden value costs a store write only when it changes.
            // Fails without it: test_builtin_fast_value_is_written_once.
            let same = current.is_some_and(|e| {
                e.policy == p.policy
                    && e.environment == p.environment
                    && e.status == status
                    && e.value == value
            });
            if !same {
                self.decided.push(decided(&p, now, status, value));
            }
        }
        resolved.get()
    }

    /// Adds `probe` to the grant unless its cached result stands or it does
    /// not fit the grant frame.
    pub(super) fn run_probe(
        &mut self,
        p: &Planned,
        probe: wire::Probe,
        current: Option<&response::Entry>,
    ) {
        if !self.probes_allowed {
            self.hidden.push(NEUTRAL_REFUSED);
            return;
        }
        {
            // Fails without it: test_builtin_probe_runs_once_and_is_cached.
            let hit = current.is_some_and(|e| {
                e.hit(
                    &p.policy,
                    &p.environment,
                    self.publish.clock.now,
                    builtin_probe::PROBE_CACHE_NS,
                )
            });
            if hit {
                return;
            }
            if !fits(&self.grant, &probe) {
                self.hidden
                    .push("a builtin probe does not fit the grant frame");
                return;
            }
            self.grant.probes.push(probe);
            self.probes.push(p.clone());
        }
    }

    /// Publishes the round's results and, as failed attempts at this time,
    /// the units that could not run (C4a review M2: not resolved, or over
    /// the relay input cap).
    pub(super) fn publish_results(&self, report: &mut Report, unresolved: &[String]) {
        let mut entries = self.entries(&report.results);
        entries.extend(self.decided.iter().cloned());
        entries.extend(self.publish.reapplied.iter().cloned());
        if let Ok(now) = now_ns() {
            entries.extend(
                unresolved
                    .iter()
                    .filter_map(|id| self.unresolved_entry(id, now)),
            );
        }
        if !entries.is_empty() {
            match self.publish.publish_entries(&entries) {
                Ok(published) => report.published = Some(published),
                Err(_) => report.publish_failed = true,
            }
        }
    }

    /// The hidden entry of language unit `id` whose marker files this round
    /// did not find, when the response still holds another entry for it;
    /// `None` when it holds none or already this one (written only when it
    /// changes). Its policy digest is no unit's, so once the files are back
    /// the unit runs at once.
    pub(super) fn undetected_entry(&self, id: &str, now: u64) -> Option<response::Entry> {
        let policy = undetected(id);
        let current = self.current.as_ref()?.entry(Origin::Config, id)?;
        // Fails without it: test_user_language_only_layout_draws_its_version_where_its_files_are.
        if current.policy == policy {
            return None;
        }
        let env = self.publish.environments.iter().find(|(u, _)| u == id)?.1;
        Some(response::Entry {
            origin: Origin::Config,
            id: id.to_owned(),
            policy,
            environment: env,
            pattern: [0; 32],
            attempted_at: now,
            completed_at: now,
            status: response::Status::Failed,
            value: String::new(),
            raw: String::new(),
        })
    }

    /// A failed entry for unit `id`, attempted and ended at `now`: the
    /// failure cache keeps it 10 s, then it is the unit tried longest ago.
    pub(super) fn unresolved_entry(&self, id: &str, now: u64) -> Option<response::Entry> {
        let (_, r) = self.runnable.iter().find(|(u, _)| u == id)?;
        let env = self.publish.environments.iter().find(|(u, _)| u == id)?.1;
        let failed = Outcome {
            origin: Origin::Config,
            index: 0,
            reason: wire::Reason::SpawnFailed,
            approved_at: now,
            ended_at: now,
            stdout: Vec::new(),
        };
        // A failed entry shows nothing and is never re-matched, so its
        // pattern digest stays all zeros.
        response::entry_for(id.to_owned(), plan::entry_digest(r), env, now, &failed)
    }

    /// The response entries of this round's config results (builtin probes
    /// are D3's): each bound to the unit's policy digest and the original
    /// environment digest it ran with.
    pub(super) fn entries(&self, results: &[Outcome]) -> Vec<response::Entry> {
        let probes = results
            .iter()
            .filter(|o| o.origin == Origin::Builtin)
            .filter_map(|o| self.probe_entry(o));
        results
            .iter()
            .filter(|o| o.origin == Origin::Config)
            .filter_map(|o| {
                let unit = self.grant.units.get(usize::from(o.index))?;
                let env = self
                    .publish
                    .environments
                    .iter()
                    .find(|(id, _)| *id == unit.id)?
                    .1;
                // The entry's digest: the grant's, and a language unit's
                // `detect_files` too (`plan::entry_digest`).
                let policy = self
                    .runnable
                    .iter()
                    .find(|(id, _)| *id == unit.id)
                    .map_or(unit.digest, |(_, r)| plan::entry_digest(r));
                let e =
                    response::entry_for(unit.id.clone(), policy, env, self.publish.clock.now, o)?;
                // A language has no `match` (the key is for commands), so
                // its pattern is none and its value the version word.
                let e = self.publish.budget.bind(e, self.publish.pattern(&unit.id));
                Some(if self.language_units.contains(&unit.id) {
                    language_entry(e)
                } else {
                    e
                })
            })
            .chain(probes)
            .collect()
    }

    /// A probe's entry: its version cut from the first line it printed
    /// (`Python 3.12.1` shows `3.12.1`); a line with no version is a failed
    /// probe with no value.
    pub(super) fn probe_entry(&self, o: &Outcome) -> Option<response::Entry> {
        let p = self.probes.get(usize::from(o.index))?;
        let mut e = response::entry_for(
            p.language.id.to_owned(),
            p.policy,
            p.environment,
            self.publish.clock.now,
            o,
        )?;
        if e.status == response::Status::Ok {
            // Fails without it: test_builtin_probe_publishes_only_a_version.
            match bingsu_core::command::profile::version(p.language.profile, &e.raw) {
                Some(v) => e.value = v.to_owned(),
                None => {
                    e.status = response::Status::Failed;
                    e.value.clear();
                    e.raw.clear();
                }
            }
        }
        Some(e)
    }
}
