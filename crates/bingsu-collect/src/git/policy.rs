//! In-memory policy only: configuration never supplies a filesystem authority.
use super::super::config::Config;
use super::{RepoIo, RepoPath};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::collection::budget::Axis;
use gix_attributes::{StateRef, search::MetadataCollection};
use gix_index::entry::stat::Options;
use gix_object::bstr::ByteSlice;
use std::{borrow::Cow, path::Path};

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
/// The match loops below follow these releases' search order, and the cap
/// costs above were measured on them.
pub(crate) const GIX_MATCH_VERSIONS: [(&str, &str); 3] = [
    ("gix-glob", "0.28.0"),
    ("gix-ignore", "0.23.0"),
    ("gix-attributes", "0.36.0"),
];

/// Whether gix skips `line` as a comment: `#` as the first byte of an ignore
/// line, or the first after blanks (space, tab, CR) of an attribute line.
/// `\#` is a pattern in both. A comment right after a byte-order mark on the
/// first line still counts, which only over-counts.
/// 이것을 실패시키는 것: 두 종류에 같은 규칙을 쓰는 것(앞 공백 `#` seed의
/// 종류별 판정이 바뀐다).
fn is_comment(line: &[u8], kind: PatternKind) -> bool {
    let first = match kind {
        PatternKind::Ignore => line.first(),
        PatternKind::Attributes => line.iter().find(|b| !b" \t\r".contains(b)),
    };
    first == Some(&b'#')
}

/// Whether gix-attributes unquotes this line's pattern: after blanks (space,
/// tab, CR) it starts with `"`. On the first line a byte-order mark comes
/// off first, so there any `"` counts.
fn quoted(line: &[u8], index: usize) -> bool {
    if index == 0 {
        return line.contains(&b'"');
    }
    line.iter().find(|b| !b" \t\r".contains(b)) == Some(&b'"')
}

/// Whether one line or pattern passes any shape cap.
fn over_caps(text: &[u8]) -> bool {
    let (runs, globstars) = star_runs(text);
    runs > STAR_RUNS || globstars > GLOBSTAR_RUNS || class_bytes(text) > CLASS_BYTES
}

/// (`*` runs, runs of two or more) in one line.
fn star_runs(line: &[u8]) -> (usize, usize) {
    // A shortcut with the same result, so no mutation fails a test; it cuts
    // the parse cost increase from +65% to +45%.
    if !line.contains(&b'*') {
        return (0, 0);
    }
    let (mut runs, mut globstars, mut run) = (0, 0, 0usize);
    for &b in line.iter().chain(std::iter::once(&0)) {
        if b == b'*' {
            run += 1;
            continue;
        }
        if run > 0 {
            runs += 1;
            globstars += usize::from(run > 1);
        }
        run = 0;
    }
    (runs, globstars)
}

/// Most pattern weight one attribute part takes before it is closed; a part
/// is matched by one gix-attributes call, so the deadline is checked between
/// parts. One heavier line (at most 504) is a part of its own. At 64 the
/// slowest part took 7.5 ms on a 240 KB path and matching a large ordinary
/// file cost 9% more than one whole-file call; at 128 the extra cost was 5%
/// but one part took 18.6 ms.
const PART_WEIGHT: usize = 64;

/// The match weight of one pattern line: (`*` runs + 1) << `**` runs, times
/// (1 + class bytes / 4). At the caps it is at most 72 * 7 = 504.
fn weight(line: &[u8]) -> usize {
    let (runs, globstars) = star_runs(line);
    ((runs + 1) << globstars) * (1 + class_bytes(line) / 4)
}

/// Bytes of a line inside bracket classes, brackets included, following
/// gix-glob's class grammar: `\` escapes one byte, a leading `!` or `^` and
/// then a leading `]` are members, and `[:name:]` runs to its `:]`. An
/// unclosed class counts to the line's end, so doubt counts more.
fn class_bytes(line: &[u8]) -> usize {
    // A shortcut with the same result, so no mutation fails a test; it cuts
    // the parse cost increase from +65% to +45%.
    if !line.contains(&b'[') {
        return 0;
    }
    let (mut total, mut i) = (0, 0);
    while i < line.len() {
        match line[i] {
            b'\\' => i += 2,
            b'[' => {
                let mut j = i + 1;
                if matches!(line.get(j), Some(b'!' | b'^')) {
                    j += 1;
                }
                if line.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < line.len() && line[j] != b']' {
                    match line[j] {
                        b'\\' => j += 2,
                        b'[' if line.get(j + 1) == Some(&b':') => {
                            j += 2;
                            while j < line.len() && !line[j..].starts_with(b":]") {
                                j += 1;
                            }
                            j += 2;
                        }
                        _ => j += 1,
                    }
                }
                total += j.min(line.len() - 1) + 1 - i;
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    total
}

/// Splits an attribute file at line ends into parts of at most PART_WEIGHT,
/// as (end, weight, line bytes times weight).
/// `parsed` holds each line's weight from the pattern gix built (unquoted),
/// by line index; a line weighs the larger of that and its raw bytes' weight.
fn attribute_parts<'a>(
    bytes: &'a [u8],
    parsed: &'a [u16],
) -> impl Iterator<Item = (usize, usize, usize)> + 'a {
    let mut index = 0;
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= bytes.len() {
            return None;
        }
        let (mut end, mut total, mut fixed) = (start, 0usize, 0usize);
        while end < bytes.len() {
            let line_end = bytes[end..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |i| end + i + 1);
            let line = &bytes[end..line_end];
            let raw = if line.trim_ascii().is_empty() {
                0
            } else {
                weight(line)
            };
            // 이것을 실패시키는 것: parsed 가중치를 빼고 원시 줄만 쓰는 것(따옴표로
            // 감싼 `\052\052/` 줄이 가중치 1이 되어 interval 시험이 갈린다).
            let w = raw.max(parsed.get(index).map_or(0, |w| usize::from(*w)));
            if end > start && total + w > PART_WEIGHT {
                break;
            }
            // Only a line taken into this part advances; the next part starts
            // with the line that did not fit.
            index += 1;
            total += w;
            fixed += line.len() * w;
            end = line_end;
        }
        let part = (end, total, fixed);
        start = end;
        Some(part)
    })
}

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
    failure: Option<ReadError>,
    allocation: Option<crate::meter::PathAllocation>,
}
impl Patterns {
    /// Fuzz and seed replay only: one file's bytes, charged like a read file.
    /// collector_fuzz is set by fuzz/collector's build script, never a feature.
    #[cfg(any(test, collector_fuzz))]
    pub(crate) fn fuzz_bytes(
        &mut self,
        bytes: &[u8],
        kind: PatternKind,
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
        self.add_buffer(bytes, "fuzz".into(), kind, patterns, meter)
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
            // Each part repeats the source path and its base in its own list.
            // As above, parser_reservation's margin hides this from the tests.
            let parts = attribute_parts(bytes, &parsed).count();
            let part_bytes = source
                .as_os_str()
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(256))
                .and_then(|n| n.checked_mul(parts))
                .ok_or(ReadError::Limit)?;
            self.allocation
                .get_or_insert_with(|| meter.path_allocation())
                .reserve(part_bytes, meter)?;
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
                search.add_patterns_buffer(
                    &bytes[from..end],
                    source.clone(),
                    if info { None } else { Some(Path::new("")) },
                    &mut self.metadata,
                    false,
                );
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
            self.ignore.add_patterns_buffer(
                bytes,
                source,
                if info { None } else { Some(Path::new("")) },
                gix_ignore::search::Ignore {
                    support_precious: false,
                },
            );
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
mod tests {
    use super::*;
    use gix_attributes::search::MetadataCollection;
    use std::time::{Duration, Instant};

    fn add(p: &mut Patterns, bytes: &[u8], source: &str, m: &mut Meter) {
        p.add_buffer(
            bytes,
            source.into(),
            PatternKind::Ignore,
            Axis::IgnorePatterns,
            m,
        )
        .unwrap();
    }

    // 이것을 실패시키는 것: class_bytes에서 escape 건너뛰기, 앞 `!`·`^`·`]` 처리,
    // `[:name:]` 처리, 닫히지 않은 클래스를 줄 끝까지 세기 중 하나를 빼는 것.
    #[test]
    fn class_bytes_follow_the_glob_grammar() {
        for (line, bytes) in [
            (&b"*.py[cod]"[..], 5),
            (b"[Bb]in/", 4),
            (b"report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json", 20),
            (b"[]a]", 4),
            (b"[!]a]x", 5),
            (b"[^a]", 4),
            (b"[[:alpha:]]x", 11),
            (b"[a[:x:]]", 8),
            (b"\\[a]", 0),
            (b"[a\\]]", 5),
            (b"x[ab", 3),
            (b"[", 1),
        ] {
            assert_eq!(class_bytes(line), bytes, "{:?}", line.as_bstr());
        }
    }

    // 이것을 실패시키는 것: gix-ignore가 패턴 텍스트를 원시 줄보다 무겁게 만드는
    // 것(예: 따옴표 해제를 하는 버전으로 올리는 것). 무작위 줄과 앞 `\!`,
    // 뒤 공백, `\ ` 같은 변형 줄에서 텍스트의 런·클래스 수가 줄의 것 이하인지 본다.
    #[test]
    fn ignore_text_never_outweighs_its_line() {
        const PARTS: [&str; 16] = [
            "*", "**", "/", "[a]", "[", "]", "\\", "\\ ", " ", "!", "#", "$", "\"", "\\052", "a",
            "[!a]",
        ];
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for _ in 0..20_000 {
            let mut line = String::new();
            for _ in 0..(rng.0 % 12 + 1) {
                line.push_str(rng.pick(&PARTS));
            }
            for (pattern, _, _) in gix_ignore::parse(line.as_bytes(), false) {
                let text = &pattern.text;
                let (runs, globstars) = star_runs(text);
                let (line_runs, line_globstars) = star_runs(line.as_bytes());
                assert!(runs <= line_runs && globstars <= line_globstars, "{line:?}");
                assert!(
                    class_bytes(text) <= class_bytes(line.as_bytes()),
                    "{line:?}"
                );
                assert!(weight(text) <= weight(line.as_bytes()), "{line:?}");
            }
        }
    }

    // 이것을 실패시키는 것: gix-attributes가 따옴표 없는 패턴도 무겁게 만드는
    // 것(예: escape를 푸는 버전으로 올리는 것). 따옴표로 시작하지 않는 무작위
    // 줄(앞 공백, `\!`, 클래스, escape, 속성 포함)에서 텍스트가 줄 이하인지 본다.
    #[test]
    fn attribute_unquoted_text_never_outweighs_its_line() {
        const PARTS: [&str; 18] = [
            "*", "**", "/", "[a]", "[", "]", "\\", "\\ ", " ", "\t", "\\!", "#", "a", "[!a]",
            "\\052", " text", " -diff", "\"",
        ];
        let mut rng = Rng(0x5851_f42d_4c95_7f2d);
        let mut seen = 0;
        for _ in 0..20_000 {
            let mut line = String::new();
            for _ in 0..(rng.0 % 12 + 1) {
                line.push_str(rng.pick(&PARTS));
            }
            if quoted(line.as_bytes(), 1) {
                continue;
            }
            // A leading line keeps it off the first line, as gix numbers them.
            let text = format!("x\n{line}\n");
            for item in gix_attributes::parse(text.as_bytes()).flatten() {
                let (gix_attributes::parse::Kind::Pattern(pattern), _, 2) = item else {
                    continue;
                };
                let raw = line.as_bytes();
                let (runs, globstars) = star_runs(&pattern.text);
                let (line_runs, line_globstars) = star_runs(raw);
                assert!(runs <= line_runs && globstars <= line_globstars, "{line:?}");
                assert!(class_bytes(&pattern.text) <= class_bytes(raw), "{line:?}");
                assert!(weight(&pattern.text) <= weight(raw), "{line:?}");
                seen += 1;
            }
        }
        assert!(seen > 10_000, "{seen}");
    }

    // The shape of a real 1,205-line .gitignore (names replaced): 430 comment
    // lines (3,440 words here, 2,060 in the real file), 460 one-word patterns
    // and 315 blank lines.
    // 이것을 실패시키는 것: 주석 줄의 단어를 단어 상한에 세는 것.
    #[test]
    fn long_commented_ignore_file_is_accepted() {
        // Kinds spread over the file by a stride coprime with 1,205.
        let mut text = String::new();
        for i in 0..1205 {
            let k = i * 7 % 1205;
            match k {
                0..430 => text.push_str(&format!("# section {k} keeps generated files of tool\n")),
                430..890 if k % 3 == 0 => text.push_str(&format!("/out-{k}/\n")),
                430..890 if k % 3 == 1 => text.push_str(&format!("**/cache-{k}\n")),
                430..890 => text.push_str(&format!("*.ext{k}\n")),
                _ => text.push('\n'),
            }
        }
        let lines = |f: fn(&str) -> bool| text.lines().filter(|l| f(l)).count();
        assert_eq!(lines(|l| l.starts_with('#')), 430);
        assert_eq!(lines(|l| !l.is_empty() && !l.starts_with('#')), 460);
        let all: usize = text.split_ascii_whitespace().count();
        assert!(all > 2048, "{all}");
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut patterns = Patterns::default();
        add(&mut patterns, text.as_bytes(), ".gitignore", &mut m);
        assert_eq!(
            patterns.ignored_in(&mut m, b"src/a.ext431", false, NamePolicy::default()),
            Ok(true)
        );
    }

    // 이것을 실패시키는 것: ignored_in에서 list나 pattern 순회의 `.rev()`를 지우는
    // 것, base를 떼지 않은 경로로 맞추는 것, 부정 판정을 뒤집는 것, case를
    // Sensitive로 고정하는 것. 모두 gix_ignore::Search와 판정이 갈린다.
    #[test]
    fn ignore_loop_matches_gix_search() {
        let files: [(&str, &[u8]); 3] = [
            ("info/exclude", b"*.log\n!keep.log\nbuild/\n"),
            (".gitignore", b"!*.log\n/root.txt\nDocs/**/*.md\n"),
            (
                "sub/.gitignore",
                b"*.tmp\n!important.tmp\n/anchored\nnested/\n",
            ),
        ];
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut ours = Patterns::default();
        let mut gix = gix_ignore::Search::default();
        for (source, bytes) in files {
            add(&mut ours, bytes, source, &mut m);
            let root = (source != "info/exclude").then_some(Path::new(""));
            let parse = gix_ignore::search::Ignore {
                support_precious: false,
            };
            gix.add_patterns_buffer(bytes, source, root, parse);
        }
        for path in [
            "a.log",
            "keep.log",
            "sub/a.log",
            "x.tmp",
            "sub/x.tmp",
            "sub/important.tmp",
            "SUB/X.TMP",
            "anchored",
            "sub/anchored",
            "sub/deep/anchored",
            "build",
            "sub/build",
            "sub/nested",
            "root.txt",
            "sub/root.txt",
            "Docs/a/b.md",
            "docs/a/b.md",
        ] {
            for is_dir in [false, true] {
                for ignore_case in [false, true] {
                    let names = NamePolicy {
                        ignore_case,
                        precompose_unicode: false,
                    };
                    let want = gix
                        .pattern_matching_relative_path(path.into(), Some(is_dir), names.case())
                        .is_some_and(|found| !found.pattern.is_negative());
                    assert_eq!(
                        ours.ignored_in(&mut m, path.as_bytes(), is_dir, names),
                        Ok(want),
                        "{path} dir={is_dir} ignore_case={ignore_case}"
                    );
                }
            }
        }
    }

    // 이것을 실패시키는 것: 가중치를 (`*` 런 + 1) << `**` 런이 아닌 값(예: 1)으로
    // 두거나, 클래스 바이트 계수를 빼거나, 작업량에서 패턴 바이트를 빼거나,
    // MATCH_CHECK_UNITS를 바꾸는 것.
    // 검사 횟수가 고정값에서 벗어난다.
    #[test]
    fn ignore_check_interval_follows_the_pattern_weight() {
        let checks = |line: &str, path: &str| {
            let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
            let mut patterns = Patterns::default();
            add(
                &mut patterns,
                line.repeat(512).as_bytes(),
                ".gitignore",
                &mut m,
            );
            let count = std::rc::Rc::new(std::cell::Cell::new(0));
            let seen = count.clone();
            m.hook = Some(Box::new(move |event| {
                if event == "ignore_match_check" {
                    seen.set(seen.get() + 1);
                }
            }));
            assert_eq!(
                patterns.ignored_in(&mut m, path.as_bytes(), false, NamePolicy::default()),
                Ok(false)
            );
            count.get()
        };
        let long = "a/".repeat(500) + "z";
        // (1001 + 20) * 72 units per pattern: one check before each.
        assert_eq!(checks("**/*a*/**/*a*/**/*ax\n", &long), 512);
        // (1001 + 5) * 2 units: one check per 33 patterns.
        assert_eq!(checks("*.log\n", &long), 15);
        // (7 + 5) * 2 units: the 512 patterns fit in one interval.
        assert_eq!(checks("*.log\n", "src/a.c"), 0);
        // (7 + 205) * 2 units: the pattern's own bytes count too.
        let named = "a".repeat(200) + "*.log\n";
        assert_eq!(checks(&named, "src/a.c"), 3);
        // (1001 + 9) * 2 * (1 + 5 / 4) units: class bytes raise the weight.
        assert_eq!(checks("*.py[cod]\n", &long), 30);
    }

    // 이것을 실패시키는 것: ignored_in 루프의 MATCH_CHECK_UNITS 검사를 지우는 것.
    // 첫 m.check()는 마감 전이라 통과하고, 그 뒤에는 cap 모양 패턴 512개를 다
    // 맞춰 수 초 뒤에 Ok(false)를 낸다.
    #[test]
    fn ignore_matching_checks_the_deadline_between_patterns() {
        let line = "**/*a*/**/*a*/**/*ax\n";
        assert_eq!(
            star_runs(line.trim_end().as_bytes()),
            (STAR_RUNS, GLOBSTAR_RUNS)
        );
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut patterns = Patterns::default();
        add(
            &mut patterns,
            line.repeat(512).as_bytes(),
            ".gitignore",
            &mut m,
        );
        let path = vec!["aa"; 16_384].join("/");
        let mut m = Meter::new(Instant::now() + Duration::from_millis(20));
        let start = Instant::now();
        assert_eq!(
            patterns.ignored_in(&mut m, path.as_bytes(), false, NamePolicy::default()),
            Err(ReadError::Deadline)
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    fn add_attributes(p: &mut Patterns, bytes: &[u8], source: &str, m: &mut Meter) {
        p.add_buffer(
            bytes,
            source.into(),
            PatternKind::Attributes,
            Axis::AttributePatterns,
            m,
        )
        .unwrap();
    }

    /// Matches of one outcome, without line numbers (each part counts its own).
    fn matches(out: &gix_attributes::search::Outcome, selected: bool) -> Vec<String> {
        let show = |a: gix_attributes::search::Match<'_>| {
            format!(
                "{:?} {:?} {:?} {:?}",
                a.assignment, a.pattern.text, a.kind, a.location.source
            )
        };
        if selected {
            out.iter_selected().map(show).collect()
        } else {
            out.iter().map(show).collect()
        }
    }

    struct Rng(u64);
    impl Rng {
        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            items[(self.0 % items.len() as u64) as usize]
        }
    }

    // 이것을 실패시키는 것: match_attributes에서 part 순회의 `.rev()`를 지우는 것,
    // info와 일반 part 순서를 바꾸는 것, part를 `start - 1`이 아닌 `start`부터
    // 자르는 것, part 경계에서 줄을 빠뜨리거나 겹치는 것. 모두 gix 원 Search와
    // 선택 결과 또는 전체 결과(우선순위, 값, 매치한 패턴)가 갈린다.
    #[test]
    fn attribute_parts_match_gix_search() {
        const PATTERNS: [&str; 15] = [
            "\"\\052.c\"",
            "\"q\\040p\"",
            "*.c",
            "a/**/b",
            "**/x",
            "/root",
            "sub/*",
            "\"q p\"",
            "sub/neg",
            "x",
            "*",
            "docs/**",
            "+/v8",
            "\u{feff}bom",
            "A*.C",
        ];
        const ATTRS: [&str; 13] = [
            "text",
            "-text",
            "!text",
            "text=auto",
            "eol=lf",
            "eol=crlf",
            "filter=lfs",
            "binary",
            "diff",
            "ident",
            "working-tree-encoding=UTF-16",
            "linguist-vendored",
            "-diff",
        ];
        const PATHS: [&str; 15] = [
            "a.c",
            "sub/a.c",
            "sub/x",
            "root",
            "sub/root",
            "a/b",
            "a/x/b",
            "docs/q p",
            "q p",
            "+/v8",
            "bom",
            "x",
            "sub/neg",
            "A.C",
            "docs/deep/x",
        ];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        // A fixed boundary case: PART_WEIGHT / 2 lines of weight 2 fill a part, so the
        // `+/v8` line starts the next one.
        let mut fixed = "*.c eol=lf\n".repeat(PART_WEIGHT / 2);
        fixed.push_str("+/v8 text\n");
        let mut refused = 0;
        'round: for round in 0..400 {
            let mut files = Vec::new();
            for source in ["info/attributes", ".gitattributes", "sub/.gitattributes"] {
                let mut text = if round == 0 && source == ".gitattributes" {
                    fixed.clone()
                } else {
                    String::new()
                };
                for _ in 0..(round % 90) {
                    let mut line = rng.pick(&["", "", "", "# c *", " "]).to_owned();
                    if line.is_empty() {
                        line.push_str(rng.pick(&PATTERNS));
                        for _ in 0..(rng.0 % 3 + 1) {
                            line.push(' ');
                            line.push_str(rng.pick(&ATTRS));
                        }
                    }
                    line.push_str(rng.pick(&["\n", "\n", "\r\n"]));
                    text.push_str(&line);
                }
                files.push((source, text));
            }
            let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
            let mut ours = Patterns::default();
            let (mut info, mut rest) = (
                gix_attributes::Search::default(),
                gix_attributes::Search::default(),
            );
            let mut metadata = MetadataCollection::default();
            for (source, text) in &files {
                let added = ours.add_buffer(
                    text.as_bytes(),
                    (*source).into(),
                    PatternKind::Attributes,
                    Axis::AttributePatterns,
                    &mut m,
                );
                // Only gix parse errors are refused, e.g. a file-start `+/v8`
                // mark leaving a negated pattern.
                if added.is_err() {
                    assert!(
                        gix_attributes::parse(text.as_bytes()).any(|line| line.is_err()),
                        "{text:?}"
                    );
                    refused += 1;
                    continue 'round;
                }
                let root = (*source != "info/attributes").then_some(Path::new(""));
                let search = if root.is_none() { &mut info } else { &mut rest };
                search.add_patterns_buffer(
                    text.as_bytes(),
                    source.into(),
                    root,
                    &mut metadata,
                    false,
                );
            }
            for path in PATHS {
                for case in [
                    gix_ignore::glob::pattern::Case::Sensitive,
                    gix_ignore::glob::pattern::Case::Fold,
                ] {
                    for selected in [true, false] {
                        let init =
                            |out: &mut gix_attributes::search::Outcome,
                             metadata: &MetadataCollection| {
                                if selected {
                                    out.initialize_with_selection(
                                        metadata,
                                        ["filter", "text", "eol", "ident", "working-tree-encoding"],
                                    );
                                } else {
                                    out.initialize(metadata);
                                }
                            };
                        let mut want = gix_attributes::search::Outcome::default();
                        init(&mut want, &metadata);
                        let path = path.into();
                        info.pattern_matching_relative_path(path, case, Some(false), &mut want);
                        if !want.is_done() {
                            rest.pattern_matching_relative_path(path, case, Some(false), &mut want);
                        }
                        let mut got = gix_attributes::search::Outcome::default();
                        init(&mut got, &ours.metadata);
                        ours.match_attributes(&mut m, path, case, &mut got).unwrap();
                        assert_eq!(
                            matches(&got, selected),
                            matches(&want, selected),
                            "round {round} {path} {case:?} selected={selected}\n{files:?}"
                        );
                    }
                }
            }
        }
        assert!(refused < 100, "{refused} of 400 rounds refused");
    }

    // 이것을 실패시키는 것: match_attributes의 MATCH_CHECK_UNITS 검사를 지우는 것.
    #[test]
    fn attribute_matching_checks_the_deadline_between_parts() {
        let line = "**/*a*/**/*a*/**/*ax text\n";
        assert_eq!(
            star_runs(line.trim_end().as_bytes()),
            (STAR_RUNS, GLOBSTAR_RUNS)
        );
        let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
        let mut patterns = Patterns::default();
        add_attributes(
            &mut patterns,
            line.repeat(1024).as_bytes(),
            ".gitattributes",
            &mut m,
        );
        let path = vec!["aa"; 16_384].join("/");
        let policies = Policies::from_config(&Config::default()).unwrap();
        let mut m = Meter::new(Instant::now() + Duration::from_millis(20));
        let start = Instant::now();
        assert_eq!(
            patterns.conversion_in(&mut m, path.as_bytes(), policies),
            Err(ReadError::Deadline)
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    // 이것을 실패시키는 것: part 가중치를 줄 가중치의 합이 아닌 값으로 두거나
    // 줄 바이트 항을 빼는 것, PART_WEIGHT·MATCH_CHECK_UNITS를 바꾸는 것, 또는
    // 선택이 다 찬 뒤에도 남은
    // part를 도는 것(마지막 시험의 검사 횟수가 0에서 벗어난다).
    #[test]
    fn attribute_check_interval_follows_the_part_weight() {
        let checks = |text: &str, path: &str| {
            let mut m = Meter::new(Instant::now() + Duration::from_secs(30));
            let mut patterns = Patterns::default();
            add_attributes(&mut patterns, text.as_bytes(), ".gitattributes", &mut m);
            let count = std::rc::Rc::new(std::cell::Cell::new(0));
            let seen = count.clone();
            m.hook = Some(Box::new(move |event| {
                if event == "attribute_match_check" {
                    seen.set(seen.get() + 1);
                }
            }));
            let policies = Policies::from_config(&Config::default()).unwrap();
            patterns
                .conversion_in(&mut m, path.as_bytes(), policies)
                .unwrap();
            count.get()
        };
        let long = "a/".repeat(500) + "z";
        // Weight 72 per line, a part each: (1001 * 72 + 26 * 72) units.
        assert_eq!(
            checks(&"**/*a*/**/*a*/**/*ax text\n".repeat(512), &long),
            512
        );
        // Weight 2, 32 lines a part: 1001 * 64 + 32 * 22 units per part.
        assert_eq!(checks(&"*.log text\n".repeat(512), &long), 8);
        assert_eq!(checks(&"*.log text\n".repeat(512), "src/a.c"), 0);
        // 7 * 64 + 32 * 422 units per part: the lines' own bytes count too.
        let named = "a".repeat(200) + "*.log text\n";
        assert_eq!(checks(&named.repeat(512), "src/a.c"), 3);
        // A quoted line weighs as gix's unquoted `**/*a/c`: (2 + 1) << 1 = 6,
        // 10 lines a part, 1001 * 60 + 10 * 23 * 6 units per part.
        let quoted = "\"\\052\\052/\\052a/c\" text\n";
        assert_eq!(checks(&quoted.repeat(512), &long), 26);
        // The last line fills every selected attribute; nothing else is visited.
        let mut filled = "**/*a*/**/*a*/**/*ax text\n".repeat(512);
        filled.push_str("* text eol=lf filter=x ident working-tree-encoding=x\n");
        assert_eq!(checks(&filled, &long), 0);
    }

    // The match loops copy gix-ignore 0.23 and gix-attributes 0.36 search order
    // over gix-glob 0.28 wildmatch; the cap costs were measured on these.
    // 이것을 실패시키는 것: Cargo.lock의 셋 중 하나를 GIX_MATCH_VERSIONS와 다른
    // 버전으로 올리는 것.
    #[test]
    fn match_loops_are_pinned_to_gix_versions() {
        let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
            .replace("\r\n", "\n");
        for (name, version) in GIX_MATCH_VERSIONS {
            let found: Vec<_> = lock
                .split("\n[[package]]\n")
                .filter(|block| block.starts_with(&format!("name = \"{name}\"\n")))
                .map(|block| block.lines().nth(1).unwrap_or_default())
                .collect();
            assert_eq!(found, [format!("version = \"{version}\"")], "{name}");
        }
    }
}
