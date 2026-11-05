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

/// Calls one request's detection may make: every operation the meter
/// charges (stats, opens, reads, identity and mount checks, components,
/// retries), refused where the meter counts them, so every folder opened
/// and checked on the way, a version file's own walk and the stack's closing
/// checks count; and bytes it may read (every byte the kernel returned,
/// failed reads included).
/// 1,024 by user decision U-20 (was 512): with every call counted, 512 left
/// built-in languages without an answer from 15 folders down.
pub const PROBES_MAX: u64 = 1_024;
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

/// What is at `path` (the leaf never followed), through the detection's one
/// folder stack: a parent already held is not opened again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    Absent,
    Regular,
    /// Something by that name that is not a regular file it may read: a
    /// symlink, a folder, a device or FIFO, one it may not look at.
    Other,
}

fn entry(
    stats: &mut WorktreeStats,
    root: &Root,
    path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<Entry, ReadError> {
    match stats.metadata(root, path, access, meter) {
        Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFREG => Ok(Entry::Regular),
        Ok(_) | Err(ReadError::Denied | ReadError::Special) => Ok(Entry::Other),
        Err(ReadError::Missing) => Ok(Entry::Absent),
        Err(error) => Err(error),
    }
}

/// The answer for a version file that is there but cannot be read safely:
/// the managers read the nearest file, so the search stops here with no
/// value instead of taking one from farther up (D2 review M8).
fn unreadable(file: u8, level: u8) -> Version {
    Version::Refused {
        file,
        level,
        digest: [0; 16],
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
                if entry(stats, root, &join(&folder, name), access, meter)? == Entry::Regular {
                    marker = Some((i as u8, level));
                    break;
                }
            }
        }
        if version.is_none() {
            for (i, file) in query.version_files.iter().enumerate() {
                let path = join(&folder, &file.name);
                match entry(stats, root, &path, access, meter)? {
                    Entry::Absent => continue,
                    // Fails without it: a_nearer_unreadable_version_file_stops_the_search.
                    Entry::Other => version = Some(unreadable(i as u8, level)),
                    Entry::Regular => {
                        version = Some(read_version(
                            file, i as u8, level, root, &path, access, spend, meter,
                        )?);
                    }
                }
                break;
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
) -> Result<Version, ReadError> {
    let left = spend.bytes_left(meter);
    if left == 0 {
        return Err(ReadError::Limit);
    }
    // Opened without following the leaf, a regular file only; the bytes come
    // from that descriptor. The stat saw a regular file here, so one that
    // cannot be opened now (gone, replaced by a link, refused) is this
    // level's answer, never a reason to look farther up.
    let opened = match safe_read::resolve_nofollow(root, path, access, meter) {
        Ok(opened) => opened,
        Err(ReadError::Missing | ReadError::Denied | ReadError::Special) => {
            return Ok(unreadable(i, level));
        }
        Err(error) => return Err(error),
    };
    let cap = file.format.cap().min(left);
    let size = opened.metadata().st_size;
    let before = bytes(meter);
    match opened.read(
        ReadCap {
            bytes: cap,
            single_link: true,
        },
        meter,
    ) {
        Ok(bytes) => Ok(rule::version(&file.format, &bytes, i, level)),
        // The file over the format's own cap (by its size, or grown past it
        // while read): no value (C2 ruling Q4 for D1). Any other `Limit` (what
        // the request may still read, the meter's byte, allocation or call
        // bounds) stops. Fails without the file test:
        // meter_limits_stop_instead_of_refusing.
        Err(ReadError::Limit)
            if cap == file.format.cap()
                && (size < 0 || size as u64 > cap || bytes(meter) - before > cap) =>
        {
            Ok(unreadable(i, level))
        }
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
            Ok(result) => match send(result) {
                Ok(()) => {}
                // A result the sink found late (nothing written): stop, as
                // past the stage's time. Fails without it:
                // a_late_language_result_keeps_the_round_complete.
                Err(crate::git::CollectError::Read(ReadError::Deadline)) => {
                    meter.event("language_late");
                    return Ok(());
                }
                Err(error) => return Err(error),
            },
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
