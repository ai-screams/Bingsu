//! Language detection (plan D1): marker files and version selection files
//! from the shell's folder up to the repository root, read under the read
//! confinement already installed, through the same safe-read rules as every
//! repository read (no symlink at the leaf, regular files only, bounded
//! reads). The rules (grammar, formats, bounds) are
//! `bingsu_core::collection::language`; only grammar-checked strings leave.
use crate::{
    meter::Meter,
    safe_read::{self, Access, ReadCap, ReadError, Root, WorktreeStats},
};
use bingsu_core::collection::language::{
    self as rule, DETECT_LEVELS, LanguageQuery, LanguageResult, Version,
};

/// Stat and open calls one request's detection may make (the meter refuses
/// the next one where it counts them, so every folder opened and checked on
/// the way, and the stack's closing checks, count), and bytes it may read
/// (every byte the kernel returned, failed reads included).
pub const PROBES_MAX: u64 = 512;
pub const BYTES_MAX: u64 = 65_536;

const _: () = assert!(DETECT_LEVELS == safe_read::DISCOVERY_LEVELS);

/// The folders looked at, as paths relative to `root`: the shell's folder
/// first (`parts` are its components below `root`), then each parent up to
/// `root` itself, at most `DETECT_LEVELS` above the shell's.
pub fn levels(parts: &[&[u8]]) -> impl Iterator<Item = (u8, Vec<u8>)> {
    let top = parts.len().min(DETECT_LEVELS);
    // Fails without the inclusive bound: test_detect_depth_32 (a root 32 up).
    (0..=top).map(move |level| (level as u8, parts[..parts.len() - level].join(&b'/')))
}

fn join(folder: &[u8], name: &[u8]) -> Vec<u8> {
    if folder.is_empty() {
        name.to_vec()
    } else {
        [folder, b"/", name].concat()
    }
}

/// Bytes one request's detection has read, from the meter's own counters
/// (all phases) against their value when detection started.
struct Spend {
    bytes: u64,
}

fn bytes(meter: &Meter) -> u64 {
    meter.counts.iter().map(|c| c.read_bytes).sum()
}

impl Spend {
    fn new(meter: &Meter) -> Self {
        Self {
            bytes: bytes(meter),
        }
    }

    fn bytes_left(&self, meter: &Meter) -> u64 {
        BYTES_MAX.saturating_sub(bytes(meter) - self.bytes)
    }
}

/// A regular file at `path` (no symlink at the leaf), through the detection's
/// one folder stack: a parent already held is not opened again.
fn is_file(
    stats: &mut WorktreeStats,
    root: &Root,
    path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<bool, ReadError> {
    match stats.metadata(root, path, access, meter) {
        Ok(st) => Ok(st.st_mode & libc::S_IFMT == libc::S_IFREG),
        Err(ReadError::Missing | ReadError::Denied | ReadError::Special) => Ok(false),
        Err(error) => Err(error),
    }
}

/// One language: the nearest marker and the nearest version selection file
/// (within a folder, in the query's order), in one pass from the shell's
/// folder up, on one folder stack (each folder is opened once per language,
/// not once per probe). A file over its cap has no value (C2 ruling Q4 for
/// D1): `Refused` with an all-zero digest.
fn detect(
    index: u8,
    query: &LanguageQuery,
    root: &Root,
    parts: &[&[u8]],
    access: &Access,
    spend: &Spend,
    meter: &mut Meter,
) -> Result<LanguageResult, ReadError> {
    let mut stats = WorktreeStats::default();
    let found = find(&mut stats, query, root, parts, access, spend, meter);
    let finished = stats.finish(root, access, meter);
    let (marker, version) = found?;
    finished?;
    Ok(LanguageResult {
        index,
        marker,
        version,
    })
}

type Found = (Option<(u8, u8)>, Version);

fn find(
    stats: &mut WorktreeStats,
    query: &LanguageQuery,
    root: &Root,
    parts: &[&[u8]],
    access: &Access,
    spend: &Spend,
    meter: &mut Meter,
) -> Result<Found, ReadError> {
    let mut marker = None;
    let mut version = None;
    for (level, folder) in levels(parts) {
        if marker.is_none() {
            for (i, name) in query.markers.iter().enumerate() {
                if is_file(stats, root, &join(&folder, name), access, meter)? {
                    marker = Some((i as u8, level));
                    break;
                }
            }
        }
        if version.is_none() {
            for (i, file) in query.version_files.iter().enumerate() {
                let path = join(&folder, &file.name);
                if !is_file(stats, root, &path, access, meter)? {
                    continue;
                }
                version = read_version(file, i as u8, level, root, &path, access, spend, meter)?;
                if version.is_some() {
                    break;
                }
            }
        }
    }
    Ok((marker, version.unwrap_or(Version::None)))
}

#[allow(clippy::too_many_arguments, reason = "one version file's fixed inputs")]
fn read_version(
    file: &rule::VersionFile,
    i: u8,
    level: u8,
    root: &Root,
    path: &[u8],
    access: &Access,
    spend: &Spend,
    meter: &mut Meter,
) -> Result<Option<Version>, ReadError> {
    let left = spend.bytes_left(meter);
    if left == 0 {
        return Err(ReadError::Limit);
    }
    // Opened without following the leaf, a regular file only; the bytes come
    // from that descriptor. One that cannot be opened is absent, as before
    // the stat (the next file is looked at).
    let opened = match safe_read::resolve_nofollow(root, path, access, meter) {
        Ok(opened) => opened,
        Err(ReadError::Missing | ReadError::Denied | ReadError::Special) => return Ok(None),
        Err(error) => return Err(error),
    };
    let cap = file.format.cap().min(left);
    match opened.read(
        ReadCap {
            bytes: cap,
            single_link: true,
        },
        meter,
    ) {
        Ok(bytes) => Ok(Some(rule::version(&file.format, &bytes, i, level))),
        // Over the format's own cap: no value (C2 ruling Q4 for D1).
        // Over what the request may still read: stop (`Limit`).
        Err(ReadError::Limit) if cap == file.format.cap() => Ok(Some(Version::Refused {
            file: i,
            level,
            digest: [0; 16],
        })),
        Err(error) => Err(error),
    }
}

/// Every asked language, in order, each sent as soon as it is known. Over
/// the call or byte bound, or past the stage's time, the rest is not sent
/// (the reader sees no answer, not a wrong one). A file that cannot be read
/// safely (a hard link, a file replaced or changed while read, an I/O
/// error) leaves only that language without an answer. Nothing here fails
/// the round: only the sink's own error does.
pub fn detect_all(
    queries: &[LanguageQuery],
    root: &Root,
    parts: &[&[u8]],
    access: &Access,
    meter: &mut Meter,
    mut send: impl FnMut(LanguageResult) -> Result<(), crate::git::CollectError>,
) -> Result<(), crate::git::CollectError> {
    let spend = Spend::new(meter);
    // Restored by the stage (git::languages) on every way out, a panic too.
    meter.calls_limit = meter.calls().saturating_add(PROBES_MAX);
    for (index, query) in queries.iter().enumerate() {
        let result = detect(index as u8, query, root, parts, access, &spend, meter)
            .and_then(|result| meter.check().map(|()| result));
        match result {
            Ok(result) => send(result)?,
            // Fails without the stop: lang_ms_zero_keeps_the_round_complete
            // (a Deadline would be skipped language by language, each
            // reaching the next stat first).
            Err(ReadError::Limit | ReadError::Deadline) => {
                meter.event("languages_over_bound");
                return Ok(());
            }
            Err(_) => meter.event("language_unreadable"),
        }
    }
    Ok(())
}
