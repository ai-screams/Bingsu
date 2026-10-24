//! Isolated config: repository bytes only; include directives remain inert data.
use super::io::{RepoIo, RepoPath, RootId};
use crate::{
    meter::{Meter, ObjectAllocation},
    safe_read::{Access, Discovery, ReadCap, ReadError, Root},
};
use bingsu_core::collection::budget::CONFIG_BYTES;

// The 64 KiB config row is a byte cap, not a parser allocation cap. Keep
// structural amplification below one 2 MiB object allocation, leaving room in
// the shared 8 MiB meter for two configs, refs and subsequent stages.
pub const SECTION_LIMIT: usize = 256;
pub const LINE_LIMIT: usize = 1024;
pub const WORD_LIMIT: usize = 4096;
// gix-config 0.61.0: bounded corpus peak 708,656 B (10.82 * 64 KiB),
// including extraction and overlapping realloc buffers. Round to 11 * 64 KiB.
// Reserve the envelope even for tiny inputs: per-byte amplification is largest
// there. git_parser_charges_cover_counted_peak guards upgrades with an allocator.
pub const PARSER_ALLOCATION: usize = CONFIG_BYTES as usize * 11;

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
    scan(bytes)?;
    let mut scratch = meter.object_allocation();
    scratch.reserve(PARSER_ALLOCATION, meter)?;
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

fn scan(bytes: &[u8]) -> Result<(), ReadError> {
    if bytes.len() > CONFIG_BYTES as usize {
        return Err(ReadError::Limit);
    }
    let (mut headers, mut lines, mut words) = (0, usize::from(!bytes.is_empty()), 0);
    let mut in_word = false;
    for (i, &byte) in bytes.iter().enumerate() {
        // Conservative upper bounds, not another config parser: '[' in values
        // and comments counts too, including adjacent headers without newlines.
        headers += usize::from(byte == b'[');
        lines += usize::from(byte == b'\n' && i + 1 < bytes.len());
        // gix also accepts many implicit keys on ONE physical line ("a a a").
        // Bound ASCII name runs as well, including runs in comments/values.
        let word = byte.is_ascii_alphanumeric() || byte == b'-';
        words += usize::from(word && !in_word);
        in_word = word;
        if headers > SECTION_LIMIT || lines > LINE_LIMIT || words > WORD_LIMIT {
            return Err(ReadError::Limit);
        }
    }
    Ok(())
}
