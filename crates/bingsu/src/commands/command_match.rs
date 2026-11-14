//! A command segment's `match` in the CLI: the regex
//! lives here, never in core and never on the prompt path. One check decides
//! for every report the CLI makes (publication, `config check`): a pattern
//! that does not compile or passes the size limit is an E203 error and turns
//! only that unit off. The helper applies a unit's pattern to the sanitized
//! first line before it publishes the entry, and binds the entry to the
//! pattern digest the prompt compares.
use bingsu_core::command::response::{Entry, Status};
use bingsu_core::command::wire::pattern_digest;
use bingsu_core::config::compile::NotRun;
use bingsu_core::config::report::ConfigReport;
use bingsu_core::diag::{Diagnostic, Place};
use bingsu_core::diag_codes as codes;

/// Checks every unit's `match` in `report`'s snapshot: one that does not
/// compile under `bingsu_match::SIZE_LIMIT` gets `NotRun::MatchInvalid`
/// (unless something else already keeps it off) and an E203 at its key.
pub(crate) fn check(report: &mut ConfigReport) {
    let Some(c) = report.snapshot.as_mut() else {
        return;
    };
    let mut found = Vec::new();
    for u in &mut c.exec_units {
        let Some(pattern) = &u.pattern else {
            continue;
        };
        let Err(e) = bingsu_match::Matcher::new(pattern) else {
            continue;
        };
        let at = u
            .origins
            .iter()
            .find(|(k, _)| k == "match")
            .map_or(Place::Builtin, |(_, o)| Place::Source {
                id: o.source,
                span: o.span,
            });
        let why = e.0.lines().last().unwrap_or_default().trim().to_owned();
        found.push(
            Diagnostic::new(codes::BAD_VALUE, at)
                .arg("key", format!("segment.\"{}\".match", u.id))
                .arg("found", format!("\"{pattern}\" ({why})"))
                .arg(
                    "expected",
                    "a regular expression within the size limit; this segment is turned off",
                ),
        );
        // Fails without it: the unit runs with a pattern the helper cannot apply.
        u.not_run.get_or_insert(NotRun::MatchInvalid);
    }
    report.add_diagnostics(found);
}

/// `e` bound to `pattern`: its pattern digest, and for a success the value
/// `pattern` picks from the raw line, or without a pattern the raw line
/// itself, cut to what the prompt reads. So an entry matched under a pattern
/// the config then drops goes back to the whole line. A pattern that does
/// not compile (a unit `check` kept running cannot have one) publishes no
/// value.
pub(crate) fn bind(mut e: Entry, pattern: Option<&str>) -> Entry {
    e.pattern = pattern_digest(pattern);
    if e.status == Status::Ok {
        let picked = match pattern {
            Some(p) => bingsu_match::Matcher::new(p).map_or("", |m| m.value(&e.raw)),
            None => e.raw.as_str(),
        };
        e.value =
            bingsu_core::field::Clean::read_prefix(picked, bingsu_core::field::CUSTOM_TEXT_CELLS)
                .into();
    }
    e
}

/// The entry `current` would be under `pattern` without running anything
/// again: a success matched under another pattern, re-matched on its
/// stored raw line. Its completion moves one nanosecond, so the publication
/// replaces the older entry (only a newer completion does), and its cache
/// still ends where the run's did.
pub(crate) fn reapplied(current: &Entry, pattern: Option<&str>) -> Option<Entry> {
    // Fails without it: test_match_only_change_reapplies_without_exec.
    if current.status != Status::Ok || current.pattern == pattern_digest(pattern) {
        return None;
    }
    let mut e = bind(current.clone(), pattern);
    e.completed_at = e.completed_at.saturating_add(1);
    Some(e)
}

/// Time one round may spend matching. A search cannot stop halfway,
/// so the budget is checked between units: a round spends at most this plus
/// one unit's search.
pub(crate) const ROUND_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// The match time a round has spent, across its re-matched cache hits and
/// its results.
pub(crate) struct Budget {
    spent: std::cell::Cell<std::time::Duration>,
    now: Box<dyn Fn() -> std::time::Instant>,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Self::with_clock(Box::new(std::time::Instant::now))
    }

    fn with_clock(now: Box<dyn Fn() -> std::time::Instant>) -> Self {
        Self {
            spent: std::cell::Cell::new(std::time::Duration::ZERO),
            now,
        }
    }

    fn timed<T>(&self, f: impl FnOnce() -> T) -> T {
        let start = (self.now)();
        let out = f();
        let took = (self.now)().saturating_duration_since(start);
        self.spent.set(self.spent.get() + took);
        out
    }

    fn over(&self) -> bool {
        // Fails without it: a_round_past_its_budget_fails_the_rest.
        self.spent.get() >= ROUND_BUDGET
    }

    /// `bind`, within the round's budget: once it is spent, a success that
    /// needs its pattern is published as a failure (shown as nothing, run
    /// again after the 10 s failure cache) instead of matched.
    pub(crate) fn bind(&self, mut e: Entry, pattern: Option<&str>) -> Entry {
        if pattern.is_some() && e.status == Status::Ok && self.over() {
            e.status = Status::Failed;
            e.value.clear();
            e.raw.clear();
            e.pattern = pattern_digest(pattern);
            return e;
        }
        self.timed(|| bind(e, pattern))
    }

    /// `reapplied`, within the round's budget: once it is spent, the stale
    /// entry stays (hidden by its digest) for a later round to re-match.
    pub(crate) fn reapplied(&self, current: &Entry, pattern: Option<&str>) -> Option<Entry> {
        if self.over() {
            return None;
        }
        self.timed(|| reapplied(current, pattern))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::color::palette::Mode;
    use bingsu_core::command::response::Entry;
    use bingsu_core::config::compile::BUILTIN_TOML;
    use bingsu_core::config::report;
    use bingsu_core::config::source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust};
    use bingsu_core::handoff::Origin;

    struct NoFiles;
    impl Resolver for NoFiles {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("no source files")
        }
    }

    fn report_of(user: &str) -> ConfigReport {
        let roots: Vec<_> = [BUILTIN_TOML, user]
            .iter()
            .enumerate()
            .map(|(i, text)| Opened {
                key: FileKey {
                    dev: 1,
                    ino: i as u64,
                },
                bytes: text.as_bytes().to_vec(),
                trust: Trust::Executable,
                display: vec![b'a' + i as u8],
            })
            .collect();
        report::report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
    }

    fn two(first: &str, second: &str) -> String {
        format!(
            "[segment.\"custom/a\"]\nkind = 'command'\ncommand = ['a']\nmatch = '{first}'\n\
             [segment.\"custom/b\"]\nkind = 'command'\ncommand = ['b']\nmatch = '{second}'\n\
             [layout.line1]\nleft = ['custom/a', 'custom/b', 'char']\n"
        )
    }

    // 문법 오류·크기 상한 초과는 그 단위만 끄고(MatchInvalid) E203을 그 키 자리에 낸다. 맞는 패턴의 단위는 그대로
    // 돈다. 이것을 실패시키는 것: 꺼짐 표시를 지우는 것, 진단을 지우는 것, 맞는
    // 단위까지 끄는 것, 이미 다른 이유로 꺼진 단위의 이유를 덮는 것.
    #[test]
    fn test_match_over_limit_disables_segment_only() {
        let many = "(a)".repeat(1500);
        for bad in [r"\w{50}", "(unclosed", many.as_str()] {
            let mut r = report_of(&two(r"([^/]+)$", bad));
            check(&mut r);
            let units = &r.snapshot.as_ref().unwrap().exec_units;
            assert_eq!(units[0].not_run, None, "{bad}");
            assert_eq!(units[1].not_run, Some(NotRun::MatchInvalid), "{bad}");
            let d: Vec<_> = r
                .diagnostics
                .iter()
                .filter(|d| d.code == codes::BAD_VALUE)
                .collect();
            assert_eq!(d.len(), 1, "{bad}: {:?}", r.diagnostics);
            assert!(matches!(d[0].at, Place::Source { .. }));
        }
        let mut r = report_of(
            &two(r"\w{50}", r"(.*)")
                .replace("command = ['a']\n", "command = ['a']\nenabled = false\n"),
        );
        check(&mut r);
        assert_eq!(
            r.snapshot.as_ref().unwrap().exec_units[0].not_run,
            Some(NotRun::Disabled)
        );
    }

    fn entry(raw: &str, status: Status) -> Entry {
        Entry {
            origin: Origin::Config,
            id: "custom/a".into(),
            policy: [1; 32],
            environment: [2; 32],
            pattern: [0; 32],
            attempted_at: 5,
            completed_at: 10,
            status,
            value: raw.into(),
            raw: raw.into(),
        }
    }

    // 도우미의 적용: 성공 항목은 패턴이 고른 값(읽기 상한으로 자른 것)과 패턴 요약값을 갖고, 패턴이 없으면 값은
    // 그대로에 요약값 0이다. 실패 항목도 요약값을 받는다. 이것을 실패시키는 것: 요약값을 붙이지 않는 것, 값을
    // 원문 그대로 두는 것, 값을 자르지 않는 것.
    #[test]
    fn bind_picks_the_value_and_the_digest() {
        let e = bind(
            entry("go version go1.23.1 darwin", Status::Ok),
            Some("go([0-9.]+)"),
        );
        assert_eq!(e.value, "1.23.1");
        assert_eq!(e.pattern, pattern_digest(Some("go([0-9.]+)")));
        let e = bind(entry("plain", Status::Ok), None);
        assert_eq!((e.value.as_str(), e.pattern), ("plain", [0; 32]));
        let long = "x".repeat(4000);
        let e = bind(entry(&long, Status::Ok), Some("(x+)"));
        assert_eq!(
            e.value.len(),
            bingsu_core::field::Clean::read_prefix(&long, bingsu_core::field::CUSTOM_TEXT_CELLS)
                .len()
        );
        let e = bind(entry("", Status::Failed), Some("(x)"));
        assert_eq!(e.pattern, pattern_digest(Some("(x)")));
    }

    // `match`만 바뀐 성공 항목은 저장한 원문에 새 패턴을 다시 맞추고 완료 시각을 1 ns만 옮긴다(발행 병합이 더 새로운
    // 완료만 받으므로). 같은 패턴이거나 실패 항목은 다시 맞추지 않는다. 이것을 실패시키는 것: 같은 패턴에도 다시
    // 맞추는 것(회차마다 발행), 완료 시각을 옮기지 않는 것(병합이 버림), 실패 항목에 값을 만드는 것, `match`를 지운
    // 항목에 옛 추출값을 남기는 것(요약값 0으로 옛 값이 그려짐).
    #[test]
    fn test_match_only_change_reapplies_without_exec() {
        let old = bind(entry("a/b/kube-ctx", Status::Ok), Some("(.*)"));
        let new = reapplied(&old, Some("([^/]+)$")).unwrap();
        assert_eq!(new.value, "kube-ctx");
        assert_eq!(new.completed_at, old.completed_at + 1);
        assert_eq!(new.pattern, pattern_digest(Some("([^/]+)$")));
        assert_eq!(reapplied(&old, Some("(.*)")), None);
        // Dropping `match` goes back to the whole line, also after a pattern
        // that matched nothing (its value was empty, hidden).
        let back = reapplied(&new, None).unwrap();
        assert_eq!(
            (back.value.as_str(), back.pattern),
            ("a/b/kube-ctx", [0; 32])
        );
        let missed = bind(entry("a/b/kube-ctx", Status::Ok), Some("zzz"));
        assert_eq!(missed.value, "");
        assert_eq!(reapplied(&missed, None).unwrap().value, "a/b/kube-ctx");
        assert!(reapplied(&bind(entry("x", Status::Failed), None), Some("(x)")).is_none());
    }

    // 회차 예산: 매칭에 쓴 시간이 예산(250 ms)에 닿으면 남은 성공 항목은 그 회차에 Failed로 발행되고(값 없음),
    // 패턴이 없는 항목과 이미 실패한 항목은 그대로다. 다시 맞추기는 예산이 다하면 미룬다. 확인은 단위 사이에서만
    // 한다. 이것을 실패시키는 것: 예산 확인을 지우는 것, 경계를 넘김(>)으로 바꾸는 것, 매칭 시간을 쌓지 않는 것,
    // 패턴 없는 항목까지 실패로 만드는 것, 다시 맞추기에 예산을 걸지 않는 것.
    #[test]
    fn a_round_past_its_budget_fails_the_rest() {
        // Reads go 0, 125, 125, 250, …: one bind (two reads) spends 125 ms.
        let tick = std::cell::Cell::new(0u64);
        let base = std::time::Instant::now();
        let clock = move || {
            tick.set(tick.get() + 1);
            base + std::time::Duration::from_millis(125 * (tick.get() / 2))
        };
        let budget = Budget::with_clock(Box::new(clock));
        let p = Some("go([0-9.]+)");
        let first = budget.bind(entry("go version go1.2", Status::Ok), p);
        assert_eq!((first.status, first.value.as_str()), (Status::Ok, "1.2"));
        let second = budget.bind(entry("go version go1.3", Status::Ok), p);
        assert_eq!(second.status, Status::Ok, "spent {:?}", budget.spent.get());
        // 250 ms spent: the rest of the round does not match.
        assert_eq!(budget.spent.get(), ROUND_BUDGET);
        let late = budget.bind(entry("go version go1.4", Status::Ok), p);
        assert_eq!(
            (late.status, late.value.as_str(), late.raw.as_str()),
            (Status::Failed, "", "")
        );
        assert_eq!(late.pattern, pattern_digest(p));
        let plain = budget.bind(entry("plain", Status::Ok), None);
        assert_eq!((plain.status, plain.value.as_str()), (Status::Ok, "plain"));
        let old = bind(entry("a/b/c", Status::Ok), Some("(.*)"));
        assert_eq!(budget.reapplied(&old, Some("([^/]+)$")), None);
    }

    // 다시 맞추기에 쓴 시간도 같은 예산에 쌓인다: 캐시된 "a/b"를 새 패턴으로 다시 맞추는 데 125 ms, 다른 결과에
    // 125 ms를 쓰면 다음 패턴 성공은 실패로 발행된다. prepare가 만든 예산은 Publish로 옮겨져 결과 매칭에 이어진다
    // (같은 값을 옮김, 새로 만들지 않음). 이것을 실패시키는 것: 다시 맞추기를 `timed`로 감싸지 않는 것.
    #[test]
    fn re_matching_spends_the_same_budget() {
        let tick = std::cell::Cell::new(0u64);
        let base = std::time::Instant::now();
        let clock = move || {
            tick.set(tick.get() + 1);
            base + std::time::Duration::from_millis(125 * (tick.get() / 2))
        };
        let budget = Budget::with_clock(Box::new(clock));
        let cached = bind(entry("a/b", Status::Ok), Some("(.*)"));
        let again = budget.reapplied(&cached, Some("([^/]+)$")).unwrap();
        assert_eq!(again.value, "b");
        let other = budget.bind(entry("go version go1.2", Status::Ok), Some("go([0-9.]+)"));
        assert_eq!(other.status, Status::Ok);
        let late = budget.bind(entry("go version go1.3", Status::Ok), Some("go([0-9.]+)"));
        assert_eq!(late.status, Status::Failed);
    }
}
