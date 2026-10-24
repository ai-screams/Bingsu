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

/// Buffer matchers, with no ambient sources or filesystem stack. D1 supplies
/// traversal/order. A failure invalidates this matcher; it cannot return clean.
#[derive(Default)]
pub struct Patterns {
    ignore: gix_ignore::Search,
    attributes: gix_attributes::Search,
    info_attributes: gix_attributes::Search,
    metadata: MetadataCollection,
    words: usize,
    retained_bytes: usize,
    failure: Option<ReadError>,
    allocation: Option<crate::meter::PathAllocation>,
}
impl Patterns {
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
        let lines = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .count();
        let words = bytes
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty())
            .count();
        if bytes.contains(&0) || words > 2048 {
            return Err(ReadError::Limit);
        }
        meter.charge_axis(axis, lines as u64)?;
        let input_bytes = bytes
            .len()
            .checked_add(source.as_os_str().len())
            .ok_or(ReadError::Limit)?;
        let reserve = parser_reservation(input_bytes, words)?;
        self.allocation
            .get_or_insert_with(|| meter.path_allocation())
            .reserve(reserve, meter)?;
        meter.event("before_pattern_parse");
        if matches!(kind, PatternKind::Attributes) {
            // The lower parser is deliberately lenient; do not silently drop
            // malformed policy. Custom macros are deferred, explicitly Partial,
            // to avoid unbounded recursive expansion from hostile definitions.
            for item in gix_attributes::parse(bytes) {
                let (pattern, assignments, _) = item.map_err(|_| INVALID)?;
                if matches!(pattern, gix_attributes::parse::Kind::Macro(_)) {
                    return Err(super::UNSUPPORTED);
                }
                for assignment in assignments {
                    assignment.map_err(|_| INVALID)?;
                }
            }
            let info = source == Path::new("info/attributes");
            let search = if info {
                &mut self.info_attributes
            } else {
                &mut self.attributes
            };
            search.add_patterns_buffer(
                bytes,
                source,
                if info { None } else { Some(Path::new("")) },
                &mut self.metadata,
                false,
            );
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
        io.metered(|m| {
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
            Ok(self
                .ignore
                .pattern_matching_relative_path(name.as_bstr(), Some(is_dir), names.case())
                .is_some_and(|found| !found.pattern.is_negative()))
        })
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
            return io.account(|m| {
                m.check()?;
                Ok(policies.conversion)
            });
        }
        io.account(|m| {
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
            self.info_attributes.pattern_matching_relative_path(
                name.as_bstr(),
                policies.names.case(),
                Some(false),
                &mut out,
            );
            self.attributes.pattern_matching_relative_path(
                name.as_bstr(),
                policies.names.case(),
                Some(false),
                &mut out,
            );
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
        })
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
