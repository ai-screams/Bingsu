//! In-memory policy only: configuration never supplies a filesystem authority.
use super::super::config::Config;
use super::{RepoIo, RepoPath};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::collection::budget::Axis;
use gix_attributes::{StateRef, search::MetadataCollection};
use gix_index::entry::stat::Options;
use gix_object::bstr::ByteSlice;
use std::{borrow::Cow, path::Path};

#[path = "policy/pattern_caps.rs"]
mod pattern_caps;
use pattern_caps::{
    attribute_names, attribute_part_bytes, attribute_parts, class_bytes, is_comment,
    name_table_bytes, over_caps, quoted, star_runs, weight,
};

const INVALID: ReadError = ReadError::Io(libc::EINVAL);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionPolicy {
    RawHash,
    /// No conversion, driver or content read. Both equal and unequal metadata
    /// are approximations, so the caller must set filtered AND partial.
    MetadataApproximation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatPolicy {
    pub check_stat: bool,
    pub trust_ctime: bool,
    pub use_nsec: bool,
    pub use_stdev: bool,
}
impl Default for StatPolicy {
    fn default() -> Self {
        Self {
            check_stat: true,
            trust_ctime: true,
            use_nsec: cfg!(target_os = "macos"),
            use_stdev: false,
        }
    }
}
impl StatPolicy {
    pub fn options(self) -> Options {
        Options {
            check_stat: self.check_stat,
            trust_ctime: self.trust_ctime,
            use_nsec: self.use_nsec,
            use_stdev: self.use_stdev,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NamePolicy {
    pub ignore_case: bool,
    pub precompose_unicode: bool,
}
impl NamePolicy {
    /// Git only compensates for decomposed filesystem names on macOS. A
    /// copied repository's config must not change Linux byte comparisons.
    pub(crate) fn precompose(self) -> bool {
        cfg!(target_os = "macos") && self.precompose_unicode
    }

    /// A comparison key only. Never pass it to RepoIo. Non-UTF-8 names remain
    /// raw bytes; Git's ignoreCase folds ASCII, not Unicode case mappings.
    pub(crate) fn key(self, raw: &[u8]) -> Cow<'_, [u8]> {
        let mut key = Cow::Borrowed(raw);
        if self.precompose()
            && !raw.is_ascii()
            && let Ok(text) = std::str::from_utf8(raw)
            && let Cow::Owned(text) = gix_utils::str::precompose(Cow::Borrowed(text))
        {
            key = Cow::Owned(text.into_bytes());
        }
        if self.ignore_case && key.iter().any(u8::is_ascii_uppercase) {
            key.to_mut().make_ascii_lowercase();
        }
        key
    }

    /// Equality only: the caller still owns and opens the raw name. Multiple
    /// raw names comparing equal must become Partial in the D1 walker.
    pub fn same(self, left: &[u8], right: &[u8], meter: &mut Meter) -> Result<bool, ReadError> {
        if left.len() > 65_536 || right.len() > 65_536 {
            return Err(ReadError::Limit);
        }
        meter.check()?;
        let mut scratch = meter.object_allocation();
        scratch.reserve(
            (left.len() + right.len())
                .checked_mul(33)
                .ok_or(ReadError::Limit)?,
            meter,
        )?;
        let same = self.key(left) == self.key(right);
        meter.check()?;
        Ok(same)
    }

    fn case(self) -> gix_ignore::glob::pattern::Case {
        if self.ignore_case {
            gix_ignore::glob::pattern::Case::Fold
        } else {
            gix_ignore::glob::pattern::Case::Sensitive
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policies {
    pub stat: StatPolicy,
    pub names: NamePolicy,
    pub conversion: ConversionPolicy,
    pub filemode: bool,
    pub symlinks: bool,
}
impl Policies {
    pub fn from_config(config: &Config) -> Result<Self, ReadError> {
        let active = boolean(
            config
                .common()
                .and_then(|f| f.value("extensions.worktreeconfig")),
            false,
        )?;
        let value = |key: &str| {
            (if active {
                config.worktree().and_then(|f| f.value(key))
            } else {
                None
            })
            .or_else(|| config.common().and_then(|f| f.value(key)))
        };
        let check_stat = match value("core.checkstat") {
            None => true,
            Some(Some(v)) if v.eq_ignore_ascii_case(b"default") => true,
            Some(Some(v)) if v.eq_ignore_ascii_case(b"minimal") => false,
            _ => return Err(INVALID),
        };
        let autocrlf = match value("core.autocrlf") {
            Some(Some(v)) if v.eq_ignore_ascii_case(b"input") => true,
            v => boolean(v, false)?,
        };
        let eol = match value("core.eol") {
            None => false,
            Some(Some(v))
                if [b"lf".as_slice(), b"crlf", b"native"]
                    .iter()
                    .any(|x| v.eq_ignore_ascii_case(x)) =>
            {
                true
            }
            _ => return Err(INVALID),
        };
        Ok(Self {
            stat: StatPolicy {
                check_stat,
                trust_ctime: boolean(value("core.trustctime"), true)?,
                ..StatPolicy::default()
            },
            names: NamePolicy {
                ignore_case: boolean(value("core.ignorecase"), false)?,
                precompose_unicode: cfg!(target_os = "macos")
                    && boolean(value("core.precomposeunicode"), false)?,
            },
            conversion: if autocrlf || eol {
                ConversionPolicy::MetadataApproximation
            } else {
                ConversionPolicy::RawHash
            },
            filemode: boolean(value("core.filemode"), true)?,
            symlinks: boolean(value("core.symlinks"), true)?,
        })
    }
}

fn boolean(value: Option<Option<&[u8]>>, default: bool) -> Result<bool, ReadError> {
    match value {
        None => Ok(default),
        Some(None) => Ok(true),
        Some(Some(v))
            if [b"true".as_slice(), b"yes", b"on", b"1"]
                .iter()
                .any(|s| v.eq_ignore_ascii_case(s)) =>
        {
            Ok(true)
        }
        Some(Some(v))
            if [b"false".as_slice(), b"no", b"off", b"0", b""]
                .iter()
                .any(|s| v.eq_ignore_ascii_case(s)) =>
        {
            Ok(false)
        }
        _ => Err(INVALID),
    }
}

#[derive(Clone, Copy)]
pub enum PatternKind {
    Ignore,
    Attributes,
}

/// Per pattern line: at most this many `*` runs of two or more, and this many
/// `*` runs in all. One wildmatch call cannot be interrupted; its cost grows
/// about 2^n with n `**` runs, with the other `*` runs and linearly with the
/// path length (release: `**/` x16 took 47 ms on a 511-byte path). Paths
/// reach about 240 KB: the walker reserves 34 bytes per path byte and the
/// attribute matcher 8, under the 8 MiB live and 2 MiB object limits. There
/// the slowest measured line at these caps took 4.6 ms, so the deadline
/// checks below land within that of each other; one more `**` run roughly
/// doubles it. Real files use far less: at most 2 `**` and 4 `*` runs per
/// pattern were seen in surveyed ignore and attribute files. Escaped stars
/// and attribute values count too; `#` lines do not.
pub(crate) const GLOBSTAR_RUNS: usize = 3;
pub(crate) const STAR_RUNS: usize = 8;
/// Per pattern line: at most this many bytes inside bracket classes, brackets
/// included. wildmatch scans a class at every position it retries, so class
/// bytes multiply the cost above. On a 240 KB path the slowest measured shape
/// (`**/*C*/**/*C*/**/*Cx`) took 9.3 ms with 9 class bytes, 11.4 ms with 21
/// and 13.2 ms with 27, about 12 ms at this cap; it grows without bound past
/// it (15,000 class bytes took seconds). Surveyed real files had at most 20
/// (`report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json`).
pub(crate) const CLASS_BYTES: usize = 24;
/// Estimated matching work between deadline checks: path plus pattern bytes
/// times the pattern's weight, (`*` runs + 1) << `**` runs. The slowest
/// measured shapes cost under 1 ns per unit, so checks are at most about
/// 0.07 ms apart plus one pattern (or attribute part); a short path checks
/// every few hundred patterns.
const MATCH_CHECK_UNITS: usize = 65_536;
/// The match loops below follow these releases' search order. The cap costs
/// above were measured one release earlier, with the same matching code.
pub(crate) const GIX_MATCH_VERSIONS: [(&str, &str); 3] = [
    ("gix-glob", "0.29.1"),
    ("gix-ignore", "0.24.1"),
    ("gix-attributes", "0.37.1"),
];

/// Lines of one attribute file matched by one call, and its weight.
struct AttributePart {
    search: gix_attributes::Search,
    weight: usize,
    fixed: usize,
}

/// Buffer matchers, with no ambient sources or filesystem stack. D1 supplies
/// traversal/order. A failure invalidates this matcher; it cannot return clean.
#[derive(Default)]
pub struct Patterns {
    ignore: gix_ignore::Search,
    /// Match weight of each ignore pattern, list for list (at most 504).
    ignore_weights: Vec<Vec<u16>>,
    /// Parts of attribute files in file and line order.
    attributes: Vec<AttributePart>,
    info_attributes: Vec<AttributePart>,
    metadata: MetadataCollection,
    words: usize,
    retained_bytes: usize,
    /// Most names, and their bytes, the shared name table was charged for.
    names: usize,
    name_bytes: usize,
    failure: Option<ReadError>,
    allocation: Option<crate::meter::PathAllocation>,
}
impl Patterns {
    /// Fuzz and seed replay only: one file's bytes, charged like a read file,
    /// under the source path the caller picks (the label add_buffer branches on).
    /// collector_fuzz is set by fuzz/collector's build script, never a feature.
    #[cfg(any(test, collector_fuzz))]
    pub(crate) fn fuzz_bytes(
        &mut self,
        bytes: &[u8],
        kind: PatternKind,
        source: std::path::PathBuf,
        meter: &mut Meter,
    ) -> Result<(), ReadError> {
        let (files, size, patterns) = match kind {
            PatternKind::Ignore => (Axis::IgnoreFiles, Axis::IgnoreBytes, Axis::IgnorePatterns),
            PatternKind::Attributes => (
                Axis::AttributeFiles,
                Axis::AttributeBytes,
                Axis::AttributePatterns,
            ),
        };
        meter.charge_axis(files, 1)?;
        meter.charge_axis(size, bytes.len() as u64)?;
        self.add_buffer(bytes, source, kind, patterns, meter)
    }

    /// Call before info/exclude and per-directory .gitignore. Only helper
    /// bytes cross this boundary; the label is never opened as a path.
    pub(crate) fn add_global(&mut self, io: &RepoIo<'_>, bytes: &[u8]) -> Result<(), ReadError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let result = io.metered(|meter| {
            if bytes.len() > bingsu_core::collection::wire::GLOBAL_EXCLUDES_MAX {
                return Err(ReadError::Limit);
            }
            meter.charge_axis(Axis::IgnoreFiles, 1)?;
            meter.charge_axis(Axis::IgnoreBytes, bytes.len() as u64)?;
            self.add_buffer(
                bytes,
                "<global-excludes>".into(),
                PatternKind::Ignore,
                Axis::IgnorePatterns,
                meter,
            )
        });
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    pub fn add(
        &mut self,
        io: &RepoIo<'_>,
        path: RepoPath,
        kind: PatternKind,
    ) -> Result<(), ReadError> {
        self.add_with_names(io, path, kind, NamePolicy::default())
    }

    pub(crate) fn add_with_names(
        &mut self,
        io: &RepoIo<'_>,
        path: RepoPath,
        kind: PatternKind,
        names: NamePolicy,
    ) -> Result<(), ReadError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.add_inner(io, path, kind, names);
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    fn add_inner(
        &mut self,
        io: &RepoIo<'_>,
        path: RepoPath,
        kind: PatternKind,
        names: NamePolicy,
    ) -> Result<(), ReadError> {
        let (files, bytes_axis, patterns) = match kind {
            PatternKind::Ignore => (Axis::IgnoreFiles, Axis::IgnoreBytes, Axis::IgnorePatterns),
            PatternKind::Attributes => (
                Axis::AttributeFiles,
                Axis::AttributeBytes,
                Axis::AttributePatterns,
            ),
        };
        // Resolve missing candidates without counting them as read files.
        // Successful files reserve both axes before the first byte read.
        let _source = io.account(|m| {
            if path.relative.len() > 65_536 {
                return Err(ReadError::Limit);
            }
            let mut scratch = m.path_allocation();
            scratch.reserve(path.relative.len() * 34, m)?;
            Ok(scratch)
        })?;
        // Normalize only the matcher source/base; open the observed raw path.
        let key = names.key(&path.relative);
        let source = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&key));
        let worktree = path.root == super::RootId::Worktree;
        let bytes = match io.read_patterns(path, files, bytes_axis) {
            Ok(bytes) => bytes,
            Err(ReadError::Missing) => return Ok(()),
            Err(ReadError::Symlink) if worktree => return Ok(()),
            Err(error) => return Err(error),
        };
        io.metered(|m| self.add_buffer(&bytes, source, kind, patterns, m))
    }

    fn add_buffer(
        &mut self,
        bytes: &[u8],
        source: std::path::PathBuf,
        kind: PatternKind,
        axis: Axis,
        meter: &mut Meter,
    ) -> Result<(), ReadError> {
        let (mut lines, mut words) = (0usize, 0usize);
        let mut wild = false;
        for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            lines += 1;
            // Comments count toward neither cap: both gix parsers skip them
            // before building anything, so they cost only the byte scan, and
            // that time and memory stay bounded by the file's byte cap (256
            // KiB), which parser_reservation charges at 8 bytes per byte.
            // 이것을 실패시키는 것: 주석 줄도 단어로 세는 것(1,205줄 형태 시험과
            // comments-past-word-cap seed가 Limit이 된다).
            if is_comment(line, kind) {
                continue;
            }
            words += line
                .split(u8::is_ascii_whitespace)
                .filter(|w| !w.is_empty())
                .count();
            let (runs, globstars) = star_runs(line);
            // 이것을 실패시키는 것: 두 비교 중 하나를 지우거나 `>`를 `>=`로 바꾸는 것
            // (cap/cap+1 seed와 policy 시험의 고정 판정이 바뀐다).
            wild |= runs > STAR_RUNS || globstars > GLOBSTAR_RUNS;
            // 이것을 실패시키는 것: 이 비교를 지우거나 `>=`로 바꾸는 것(class-bytes
            // 24/25 seed의 판정이 바뀐다).
            wild |= class_bytes(line) > CLASS_BYTES;
        }
        if bytes.contains(&0) || words > 2048 || wild {
            return Err(ReadError::Limit);
        }
        meter.charge_axis(axis, lines as u64)?;
        let input_bytes = bytes
            .len()
            .checked_add(source.as_os_str().len())
            .ok_or(ReadError::Limit)?;
        // Plus two weight bytes per ignore pattern and its list's slot. No test
        // fails without it: parser_reservation's margin covers it today.
        let reserve = parser_reservation(input_bytes, words)?
            .checked_add(2 * lines + 96)
            .ok_or(ReadError::Limit)?;
        self.allocation
            .get_or_insert_with(|| meter.path_allocation())
            .reserve(reserve, meter)?;
        meter.event("before_pattern_parse");
        if matches!(kind, PatternKind::Attributes) {
            // The lower parser is deliberately lenient; do not silently drop
            // malformed policy. Custom macros are deferred, explicitly Partial,
            // to avoid unbounded recursive expansion from hostile definitions.
            // Caps and weights also apply to the pattern gix builds when it
            // unquotes one (`"\052\052/a"` matches as `**/a`). Unquoted patterns
            // only lose bytes, so their raw line already weighs at least as much
            // (attribute_unquoted_text_never_outweighs_its_line pins it).
            let any_quote = bytes.contains(&b'"');
            let line_count = if any_quote {
                bytes.split(|b| *b == b'\n').count()
            } else {
                0
            };
            let mut scratch = meter.path_allocation();
            scratch.reserve(2 * line_count, meter)?;
            let mut parsed = vec![0u16; line_count];
            let mut lines_left = bytes.split(|b| *b == b'\n').enumerate();
            for item in gix_attributes::parse(bytes) {
                let (pattern, assignments, line) = item.map_err(|_| INVALID)?;
                let gix_attributes::parse::Kind::Pattern(pattern) = pattern else {
                    return Err(super::UNSUPPORTED);
                };
                for assignment in assignments {
                    assignment.map_err(|_| INVALID)?;
                }
                if !any_quote {
                    continue;
                }
                let index = line.wrapping_sub(1);
                let raw = lines_left
                    .find(|(i, _)| *i == index)
                    .map_or(&[][..], |(_, l)| l);
                // 이것을 실패시키는 것: 따옴표 판정을 끄거나 뒤집는 것(따옴표 seed가
                // Limit 대신 Ok가 되거나 interval 시험의 검사 횟수가 바뀐다).
                if !quoted(raw, index) {
                    continue;
                }
                // 이것을 실패시키는 것: 이 검사를 지우는 것(따옴표 seed가 Limit 대신
                // Ok가 된다).
                if over_caps(&pattern.text) {
                    return Err(ReadError::Limit);
                }
                if let Some(slot) = parsed.get_mut(index) {
                    *slot = weight(&pattern.text) as u16;
                }
            }
            let info = source == Path::new("info/attributes");
            // The shared name table holds the names already there plus at most
            // this file's distinct names; it grows from what earlier files
            // charged.
            let (new_names, new_bytes) = attribute_names(bytes, words, &mut scratch, meter)?;
            let held = self.metadata.iter().count();
            let names = held.checked_add(new_names).ok_or(ReadError::Limit)?;
            let name_bytes = self
                .name_bytes
                .checked_add(new_bytes)
                .ok_or(ReadError::Limit)?;
            let names = names.max(self.names);
            let part_bytes = attribute_part_bytes(bytes, &parsed, source.as_os_str().len())
                .and_then(|parts| {
                    let grown = name_table_bytes(names, name_bytes)?
                        .checked_sub(name_table_bytes(self.names, self.name_bytes)?)?;
                    parts.checked_add(grown)
                })
                .ok_or(ReadError::Limit)?;
            self.allocation
                .get_or_insert_with(|| meter.path_allocation())
                .reserve(part_bytes, meter)?;
            (self.names, self.name_bytes) = (names, name_bytes);
            let list = if info {
                &mut self.info_attributes
            } else {
                &mut self.attributes
            };
            let mut start = 0usize;
            for (end, weight, fixed) in attribute_parts(bytes, &parsed) {
                // A later part starts at the previous line's `\n`: gix-attributes
                // strips a byte-order mark at a buffer's start, and a line that
                // only begins like one must stay an ordinary line.
                // 이것을 실패시키는 것: `start - 1` 대신 `start`부터 자르는 것
                // (part 첫 줄의 `+/v8`을 BOM으로 떼어 차등 시험이 갈린다).
                let from = start.saturating_sub(1);
                let mut search = gix_attributes::Search::default();
                // 이것을 실패시키는 것: 이 오류를 버리는 것(부모 없는 source 시험이
                // 빈 Search를 Ok로 받아들인다).
                search
                    .add_patterns_buffer(
                        &bytes[from..end],
                        source.clone(),
                        if info { None } else { Some(Path::new("")) },
                        &mut self.metadata,
                        false,
                    )
                    .map_err(|_| INVALID)?;
                list.push(AttributePart {
                    search,
                    weight,
                    fixed,
                });
                start = end;
            }
            self.words = self.words.checked_add(words).ok_or(ReadError::Limit)?;
            self.retained_bytes = self
                .retained_bytes
                .checked_add(input_bytes)
                .ok_or(ReadError::Limit)?;
        } else {
            let info =
                source == Path::new("info/exclude") || source == Path::new("<global-excludes>");
            // On failure nothing is pushed, so `last()` below would weigh the
            // previous file's list.
            // 이것을 실패시키는 것: 이 오류를 버리는 것(부모 없는 source 시험이 Ok를
            // 받는다).
            self.ignore
                .add_patterns_buffer(
                    bytes,
                    source,
                    if info { None } else { Some(Path::new("")) },
                    gix_ignore::search::Ignore {
                        support_precious: false,
                    },
                )
                .map_err(|_| INVALID)?;
            let list = self.ignore.patterns.last().map_or(&[][..], |l| &l.patterns);
            // gix-ignore only drops bytes (a leading `!`, a `\` before `!`, `#`
            // or `$`, a leading `/`, a trailing `/`, unescaped trailing spaces)
            // and never unquotes, so its text never weighs more than the raw
            // line the caps checked; ignore_text_never_outweighs_its_line pins it.
            self.ignore_weights.push(
                list.iter()
                    .map(|m| weight(&m.pattern.text) as u16)
                    .collect(),
            );
        }
        Ok(())
    }

    pub fn ignored(
        &self,
        io: &RepoIo<'_>,
        relative: &[u8],
        is_dir: bool,
        names: NamePolicy,
    ) -> Result<bool, ReadError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        io.metered(|m| self.ignored_in(m, relative, is_dir, names))
    }

    /// The matcher itself, without the port; shared with the fuzz corpus.
    pub(crate) fn ignored_in(
        &self,
        m: &mut Meter,
        relative: &[u8],
        is_dir: bool,
        names: NamePolicy,
    ) -> Result<bool, ReadError> {
        m.check()?;
        let mut scratch = m.path_allocation();
        if names.precompose() && !relative.is_ascii() {
            scratch.reserve(relative.len() * 33, m)?;
        }
        let name = NamePolicy {
            ignore_case: false,
            ..names
        }
        .key(relative);
        // gix_ignore::Search::pattern_matching_relative_path, pattern by
        // pattern so the deadline holds inside one call: last list first,
        // last pattern first, and the first match decides.
        let path = name.as_bstr();
        let case = names.case();
        let basename = path.rfind_byte(b'/').map(|p| p + 1);
        let mut work = 0usize;
        for (list, weights) in self
            .ignore
            .patterns
            .iter()
            .rev()
            .zip(self.ignore_weights.iter().rev())
        {
            let Some((relative, basename)) =
                list.strip_base_handle_recompute_basename_pos(path, basename, case)
            else {
                continue;
            };
            for (mapping, weight) in list.patterns.iter().rev().zip(weights.iter().rev()) {
                let pattern = &mapping.pattern;
                work += (path.len() + pattern.text.len()) * usize::from(*weight);
                // 이것을 실패시키는 것: 이 검사를 지우는 것(경로가 긴 cap 모양 패턴
                // 512개 시험이 Deadline 대신 수 초 뒤 Ok로 끝난다).
                if work >= MATCH_CHECK_UNITS {
                    m.event("ignore_match_check");
                    m.check()?;
                    work = 0;
                }
                if pattern.matches_repo_relative_path(
                    relative,
                    basename,
                    Some(is_dir),
                    case,
                    gix_ignore::glob::wildmatch::Mode::NO_MATCH_SLASH_LITERAL,
                ) {
                    return Ok(!pattern.is_negative());
                }
            }
        }
        Ok(false)
    }

    pub fn conversion(
        &self,
        io: &RepoIo<'_>,
        relative: &[u8],
        policies: Policies,
    ) -> Result<ConversionPolicy, ReadError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.words == 0 {
            // No matching, allocation or I/O. The status loops check their
            // per-entry deadline before requesting this already-known policy.
            return Ok(policies.conversion);
        }
        io.account(|m| self.conversion_in(m, relative, policies))
    }

    /// The attribute matcher itself, without the port; shared with the fuzz corpus.
    pub(crate) fn conversion_in(
        &self,
        m: &mut Meter,
        relative: &[u8],
        policies: Policies,
    ) -> Result<ConversionPolicy, ReadError> {
        if self.words == 0 {
            // Same as conversion(): no matching, allocation or deadline check.
            return Ok(policies.conversion);
        }
        let mut scratch = m.object_allocation();
        scratch.reserve(
            parser_reservation(
                relative
                    .len()
                    .checked_add(self.retained_bytes)
                    .ok_or(ReadError::Limit)?,
                self.words,
            )?,
            m,
        )?;
        let mut normalization = m.path_allocation();
        if policies.names.precompose() && !relative.is_ascii() {
            normalization.reserve(relative.len() * 33, m)?;
        }
        let name = NamePolicy {
            ignore_case: false,
            ..policies.names
        }
        .key(relative);
        let mut out = gix_attributes::search::Outcome::default();
        out.initialize_with_selection(
            &self.metadata,
            ["filter", "text", "eol", "ident", "working-tree-encoding"],
        );
        self.match_attributes(m, name.as_bstr(), policies.names.case(), &mut out)?;
        // Conservatively approximate every active conversion attribute,
        // including text=auto and unknown values. Explicit unset/unspecified
        // do not activate a conversion. A global conversion stays conservative.
        let conversion = out
            .iter_selected()
            .any(|a| matches!(a.assignment.state, StateRef::Set | StateRef::Value(_)));
        Ok(if conversion {
            ConversionPolicy::MetadataApproximation
        } else {
            policies.conversion
        })
    }

    /// gix_attributes::Search::pattern_matching_relative_path over each
    /// file's parts, last part first, so the deadline holds between parts.
    /// Info parts come first; matching stops once `out` is filled.
    fn match_attributes(
        &self,
        m: &mut Meter,
        name: &gix_object::bstr::BStr,
        case: gix_ignore::glob::pattern::Case,
        out: &mut gix_attributes::search::Outcome,
    ) -> Result<(), ReadError> {
        let mut work = 0usize;
        for part in self
            .info_attributes
            .iter()
            .rev()
            .chain(self.attributes.iter().rev())
        {
            if out.is_done() {
                break;
            }
            work += name.len() * part.weight + part.fixed;
            // 이것을 실패시키는 것: 이 검사를 지우는 것(48 KB 경로 cap 모양 시험이
            // Deadline 대신 수 초 뒤 결과를 낸다).
            if work >= MATCH_CHECK_UNITS {
                m.event("attribute_match_check");
                m.check()?;
                work = 0;
            }
            part.search
                .pattern_matching_relative_path(name, case, Some(false), out);
        }
        Ok(())
    }
}

pub(crate) fn parser_reservation(bytes: usize, words: usize) -> Result<usize, ReadError> {
    bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(words.checked_mul(512)?))
        .and_then(|n| n.checked_add(4096))
        .ok_or(ReadError::Limit)
}

use std::os::unix::ffi::OsStrExt;

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
