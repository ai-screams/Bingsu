//! Isolated config: repository bytes only; include directives remain inert data.
use super::io::{RepoIo, RepoPath, RootId};
use crate::{
    meter::{Meter, ObjectAllocation},
    safe_read::{Access, Discovery, ReadCap, ReadError, Root},
};
use bingsu_core::collection::budget::{CONFIG_BYTES, OBJECT_ALLOC};

// The 64 KiB config row is a byte cap, not a parser allocation cap. Keep
// structural amplification below one 2 MiB object allocation, leaving room in
// the shared 8 MiB meter for two configs, refs and subsequent stages.
// SECTION_LIMIT and WORD_LIMIT count only the '[' and name runs that can
// make gix events: outside values, and for words outside headers too.
pub const SECTION_LIMIT: usize = 256;
pub const LINE_LIMIT: usize = 1024;
pub const WORD_LIMIT: usize = 4096;
// gix-config 0.61.0 (lossy) keeps the events of the current section, or of the
// front matter, in one 56 B-per-event Vec that starts at 256 and doubles. Peak
// is that capacity plus one copy: drain(..).collect() of a section at the next
// header, or the SmallVec collect of front matter (rounded to a power of two).
// Kept events are at most 2 per key name (name, value) plus 2 per line
// (separator, continuation), so scan's own counts bound them; at the scan
// limits that is 10,240 events and 16,384 slots per term. The second per-line
// event is needed: `a=\` followed by 1,021 lines of `\` keeps 2W + L + 1
// events and overruns a 2W + L reservation.
// Key names are counted as words outside values and headers. In gix's
// parse/from_bytes, section_header() turns a header into one SectionHeader
// event that Events::from_bytes keeps in SectionData, not in a body or the
// front matter, so header and subsection words add no event; the section's
// own cost is the H term and its quoted bytes the Q term below. In it,
// value() owns everything after a key's `=` up to the line end: an unquoted
// `;`/`#` starts a comment, quotes hide those, any `\` escapes the next byte,
// and a `\` before LF or CRLF carries the value onto the next line. Scan
// follows the same rules, so words and `[` in a value, on every line it
// continues to, make no name or header; it only ends a value early (then
// counts more), never late. Outside a header, `#` and `;` start a comment()
// that runs to the line end. A `=` inside a header, including a quoted
// subsection with its `\` escapes, is not a separator, and keys may follow the
// closing `]` on the same line. Any other `=` either ends in a parse error or
// sits in a comment, so skipping the rest of its line never undercounts.
// Beyond events: the backing copy holds the input again, and the lookup
// tree's copies of header names plus extracted values together hold at most
// the input once more (2 * len); a header name of nearly the whole input
// (`[aaa…]`, `[a.bbb…]`) needs both, since neither W nor Q counts it. Per section, File keeps a sections-map
// bucket (SectionData, about 105 B), a lookup-tree bucket (about 100 B), an id
// Vec and, for a subsection, its own small map, while Events' 80 B SectionData
// Vec is still alive; hashbrown growth briefly keeps old and new tables. 768 B
// per power-of-two section slot covers that (counted: at most 567 B).
// A quoted subsection with an escape is decoded into a Vec copied from the
// raw prefix and grown by push: up to 2q kept plus q old during a doubling,
// then File's lookup tree copies it once more (to_owned, q). Q, every raw byte
// inside a header's quotes (escapes included), bounds the sum of q, so 4Q
// covers them. A 3Q (or 2Q) mutation survives the corpus: those bytes are also
// inside the 2 * len term, which only a mixed values-and-subsection worst case
// would exhaust; the counted subsection peak is about 3.8 * len in total.
// Inputs whose reservation passes one object allocation are refused before
// parsing (ObjectAllocation::reserve). Git accepts at most one key per line
// and scan counts no word on continued value lines, so any config git reads
// (W <= L, even with every byte quoted) stays within it (const assert); only
// several implicit keys per line can be refused.
// git_parser_charges_cover_counted_peak guards these with an allocator, and
// git_config_derivation_is_pinned ties them to the locked gix-config version.
pub const GIX_CONFIG_VERSION: &str = "0.61.0";
const EVENT_BYTES: usize = 56;
const EVENT_SCRATCH: usize = 256;
const SECTION_BYTES: usize = 768;
const fn reservation(
    headers: usize,
    lines: usize,
    words: usize,
    len: usize,
    quoted_bytes: usize,
) -> usize {
    let events = (2 * words + 2 * lines).next_power_of_two();
    let scratch = if events > EVENT_SCRATCH {
        events
    } else {
        EVENT_SCRATCH
    };
    EVENT_BYTES * (scratch + events)
        + 2 * len
        + 4 * quoted_bytes
        + SECTION_BYTES * (headers + 1).next_power_of_two()
}
pub const PARSER_ALLOCATION: usize = OBJECT_ALLOC as usize;
const _: () = assert!(
    reservation(
        SECTION_LIMIT,
        LINE_LIMIT,
        LINE_LIMIT,
        CONFIG_BYTES as usize,
        CONFIG_BYTES as usize
    ) <= PARSER_ALLOCATION
);

// Only C3-C5 policy facts survive parsing. core.worktree is retained solely for
// reciprocal submodule validation; no external path/driver/include is followed.
// A missing key, implicit value and explicit empty
// value remain distinct; later policy code must validate the value it consumes.
const KEYS: [&str; 15] = [
    "core.worktree",
    "core.repositoryformatversion",
    "core.bare",
    "core.filemode",
    "core.symlinks",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.checkstat",
    "core.trustctime",
    "core.autocrlf",
    "core.eol",
    "extensions.worktreeconfig",
    "extensions.refstorage",
    "extensions.objectformat",
    "index.sparse",
];

#[derive(Debug, Default)]
pub struct Facts {
    core_worktree: bool,
    use_replace_refs: bool,
    unknown_extension: bool,
    values: [Option<Option<Vec<u8>>>; KEYS.len()],
    allocation: Option<ObjectAllocation>,
}

impl Facts {
    pub fn value(&self, key: &str) -> Option<Option<&[u8]>> {
        let index = KEYS.iter().position(|k| k.eq_ignore_ascii_case(key))?;
        self.values[index].as_ref().map(|v| v.as_deref())
    }

    fn unsupported(&self) -> bool {
        // Fail closed for unknown/implicit formats too. In particular version
        // 1 + objectFormat=sha256 must never reach the SHA-1 readers.
        self.unknown_extension
            || self
                .value("core.repositoryformatversion")
                .is_some_and(|v| !matches!(v, Some(b"0" | b"1")))
            || self
                .value("extensions.refstorage")
                .is_some_and(|v| v != Some(b"files"))
            || self
                .value("extensions.objectformat")
                .is_some_and(|v| v != Some(b"sha1"))
    }
}

#[derive(Debug, Default)]
pub struct Config {
    common: Option<Facts>,
    worktree: Option<Facts>,
}

impl Config {
    pub fn load(io: &RepoIo<'_>) -> Result<Self, ReadError> {
        // Inspect even inactive config.worktree for unsafe policy/format facts.
        Ok(Self {
            common: read(io, RootId::CommonDir, b"config")?,
            worktree: read(io, RootId::GitDir, b"config.worktree")?,
        })
    }

    pub fn common(&self) -> Option<&Facts> {
        self.common.as_ref()
    }
    pub fn worktree(&self) -> Option<&Facts> {
        self.worktree.as_ref()
    }

    pub fn has_core_worktree(&self) -> bool {
        [&self.common, &self.worktree]
            .into_iter()
            .flatten()
            .any(|f| f.core_worktree)
    }

    pub(super) fn risky_worktree(&self, roots: &super::discover::RepoRoots) -> bool {
        [&self.common, &self.worktree]
            .into_iter()
            .flatten()
            .filter(|facts| facts.core_worktree)
            .any(|facts| {
                !facts
                    .value("core.worktree")
                    .flatten()
                    .is_some_and(|value| roots.matches_worktree(value))
            })
    }

    /// Presence alone is unsafe, including implicit, empty and false values.
    pub fn has_use_replace_refs(&self) -> bool {
        [&self.common, &self.worktree]
            .into_iter()
            .flatten()
            .any(|f| f.use_replace_refs)
    }

    pub fn ensure_supported(&self, io: &RepoIo<'_>) -> Result<(), ReadError> {
        if [&self.common, &self.worktree]
            .into_iter()
            .flatten()
            .any(Facts::unsupported)
        {
            return Err(ReadError::StageAOnly);
        }
        for root in [RootId::GitDir, RootId::CommonDir] {
            if io.has_directory(RepoPath::new(root, b"reftable"))? {
                return Err(ReadError::StageAOnly);
            }
        }
        Ok(())
    }
}

fn read(io: &RepoIo<'_>, root: RootId, name: &[u8]) -> Result<Option<Facts>, ReadError> {
    let bytes = match io.read(
        RepoPath::new(root, name),
        ReadCap {
            bytes: CONFIG_BYTES,
            single_link: true,
        },
    ) {
        Ok(bytes) => bytes,
        Err(ReadError::Missing) => return Ok(None),
        Err(error) => return Err(error),
    };
    io.metered(|meter| parse(&bytes, meter).map(Some))
}

/// Discovery's fixed, owner-checked config read uses the same bounded isolated
/// parser as preflight. This does not create a general metadata capability.
pub(super) fn submodule_worktree(
    candidate: &Discovery,
    anchor: &Root,
    access: &Access,
    meter: &mut Meter,
) -> Result<Vec<u8>, ReadError> {
    let bytes = candidate.metadata_config(anchor, access, meter)?;
    let facts = parse(&bytes, meter)?;
    facts
        .value("core.worktree")
        .flatten()
        .map(<[u8]>::to_vec)
        .ok_or(ReadError::Escape)
}

pub(crate) fn parse(bytes: &[u8], meter: &mut Meter) -> Result<Facts, ReadError> {
    let (file, _scratch) = isolated(bytes, meter)?;
    let mut facts = Facts::default();
    for section in file.sections() {
        meter.check()?;
        let header = section.header();
        if header.subsection_name().is_some() {
            continue;
        }
        if header.name().eq_ignore_ascii_case(b"core") {
            facts.core_worktree |= section.contains_value_name("worktree");
            facts.use_replace_refs |= section.contains_value_name("useReplaceRefs");
        }
        if header.name().eq_ignore_ascii_case(b"extensions") {
            for name in section.value_names() {
                if !["worktreeconfig", "refstorage", "objectformat", "noop"]
                    .iter()
                    .any(|key| name.eq_ignore_ascii_case(key))
                {
                    facts.unknown_extension = true;
                }
            }
        }
        for (index, key) in KEYS.iter().enumerate() {
            let (group, name) = key.split_once('.').expect("fixed key");
            if header.name().eq_ignore_ascii_case(group.as_bytes()) {
                if let Some(value) = section.value_implicit(name) {
                    facts.values[index] = Some(value.map(Into::into));
                }
            }
        }
    }
    // Only extracted values survive this parse, not the parser envelope.
    let mut allocation = meter.object_allocation();
    allocation.reserve(
        facts
            .values
            .iter()
            .flatten()
            .flatten()
            .map(Vec::capacity)
            .sum(),
        meter,
    )?;
    facts.allocation = Some(allocation);
    Ok(facts)
}

/// Shared bounded bytes constructor for policy and history configuration.
/// The reservation must outlive the parser and any extraction scratch.
pub(super) fn isolated(
    bytes: &[u8],
    meter: &mut Meter,
) -> Result<(gix_config::File, ObjectAllocation), ReadError> {
    meter.check()?;
    let reserve = parser_allocation(bytes)?;
    let mut scratch = meter.object_allocation();
    scratch.reserve(reserve, meter)?;
    meter.event("before_config_parse");
    let file = gix_config::File::from_bytes_no_includes(
        bytes,
        gix_config::file::Metadata::from(gix_config::Source::Local),
        gix_config::file::init::Options {
            lossy: true,
            ..Default::default()
        },
    )
    .map_err(|_| ReadError::Io(libc::EINVAL))?;
    Ok((file, scratch))
}

/// Parser reservation from scan's structural counts. A sum above one object
/// allocation (PARSER_ALLOCATION) is refused by ObjectAllocation before parsing.
pub(crate) fn parser_allocation(bytes: &[u8]) -> Result<usize, ReadError> {
    if bytes.len() > CONFIG_BYTES as usize {
        return Err(ReadError::Limit);
    }
    const KEY: u8 = 0;
    const HEADER: u8 = 1;
    const QUOTED: u8 = 2;
    const ESCAPE: u8 = 3;
    const VALUE: u8 = 4;
    const COMMENT: u8 = 5;
    let (mut headers, mut lines, mut words) = (0, usize::from(!bytes.is_empty()), 0);
    let (mut in_word, mut state, mut quoted_bytes) = (false, KEY, 0);
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if state == VALUE || state == COMMENT {
            // Nothing in a value or comment is counted. Mirror gix value(): a
            // `\` before LF or CRLF continues the value onto the next line,
            // any other `\` escapes one byte, quotes hide `;`/`#`, and an
            // unquoted `;`/`#` starts a comment that never continues.
            in_word = false;
            let (mut value, mut quoted) = (state == VALUE, false);
            while let Some(&byte) = bytes.get(i) {
                match byte {
                    b'\n' => break,
                    b'"' if value => quoted = !quoted,
                    b';' | b'#' if value && !quoted => value = false,
                    b'\\' if value => {
                        let crlf =
                            bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n');
                        if crlf || bytes.get(i + 1) == Some(&b'\n') {
                            i += 1 + usize::from(crlf);
                            lines += usize::from(i + 1 < bytes.len());
                        } else {
                            i += 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            // The line end itself runs through the counting below.
            state = KEY;
            continue;
        }
        // Conservative upper bounds, not another config parser: outside values
        // and comments, '[' counts even in subsections, and so do name runs
        // outside headers, including several implicit keys on one line.
        headers += usize::from(byte == b'[');
        lines += usize::from(byte == b'\n' && i + 1 < bytes.len());
        let word = state == KEY && (byte.is_ascii_alphanumeric() || byte == b'-');
        words += usize::from(word && !in_word);
        in_word = word;
        quoted_bytes += usize::from(state == QUOTED || state == ESCAPE);
        state = match (state, byte) {
            (_, b'\n') => KEY,
            (KEY, b'[') => HEADER,
            (KEY, b'=') => VALUE,
            (KEY, b'#' | b';') => COMMENT,
            (HEADER, b']') => KEY,
            (HEADER, b'"') => QUOTED,
            (QUOTED, b'"') => HEADER,
            (QUOTED, b'\\') => ESCAPE,
            (ESCAPE, _) => QUOTED,
            (state, _) => state,
        };
        if headers > SECTION_LIMIT || lines > LINE_LIMIT || words > WORD_LIMIT {
            return Err(ReadError::Limit);
        }
        i += 1;
    }
    // A value continued to EOF counted its lines without the loop's check.
    if lines > LINE_LIMIT {
        return Err(ReadError::Limit);
    }
    Ok(reservation(
        headers,
        lines,
        words,
        bytes.len(),
        quoted_bytes,
    ))
}
