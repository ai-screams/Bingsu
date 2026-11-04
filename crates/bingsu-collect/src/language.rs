//! Language detection (plan D1): marker files and version selection files
//! from the shell's folder up to the repository root, read under the read
//! confinement already installed, through the same safe-read rules as every
//! repository read (no symlink at the leaf, regular files only, bounded
//! reads). The rules (grammar, formats, bounds) are
//! `bingsu_core::collection::language`; only grammar-checked strings leave.
use crate::{
    meter::Meter,
    safe_read::{self, Access, ReadCap, ReadError, Root},
};
use bingsu_core::collection::language::{
    self as rule, DETECT_LEVELS, LanguageQuery, LanguageResult, Version,
};

/// Stats and reads one request's detection may make, and bytes it may read.
pub const PROBES_MAX: usize = 512;
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

/// What one request's detection may still spend.
struct Spend {
    probes: usize,
    bytes: u64,
}

impl Spend {
    fn probe(&mut self) -> Result<(), ReadError> {
        self.probes = self.probes.checked_add(1).ok_or(ReadError::Limit)?;
        // Fails without it: probe_bound_stops_further_languages.
        if self.probes > PROBES_MAX {
            return Err(ReadError::Limit);
        }
        Ok(())
    }
}

/// A regular file named `name` in `folder` (no symlink at the leaf).
fn is_file(
    root: &Root,
    path: &[u8],
    access: &Access,
    spend: &mut Spend,
    meter: &mut Meter,
) -> Result<bool, ReadError> {
    spend.probe()?;
    match safe_read::worktree_metadata(root, path, access, meter) {
        Ok(st) => Ok(st.st_mode & libc::S_IFMT == libc::S_IFREG),
        Err(ReadError::Missing | ReadError::Denied | ReadError::Special) => Ok(false),
        Err(error) => Err(error),
    }
}

/// One language: the nearest marker and the nearest version selection file
/// (within a folder, in the query's order). A file over its cap has no
/// value (C2 ruling Q4 for D1): `Refused` with an all-zero digest.
fn detect(
    index: u8,
    query: &LanguageQuery,
    root: &Root,
    parts: &[&[u8]],
    access: &Access,
    spend: &mut Spend,
    meter: &mut Meter,
) -> Result<LanguageResult, ReadError> {
    let mut marker = None;
    'markers: for (level, folder) in levels(parts) {
        for (i, name) in query.markers.iter().enumerate() {
            if is_file(root, &join(&folder, name), access, spend, meter)? {
                marker = Some((i as u8, level));
                break 'markers;
            }
        }
    }
    let mut version = Version::None;
    'files: for (level, folder) in levels(parts) {
        for (i, file) in query.version_files.iter().enumerate() {
            let path = join(&folder, &file.name);
            spend.probe()?;
            // Opened without following the leaf (a symlink is absent), a
            // regular file only; the bytes come from that descriptor.
            let opened = match safe_read::resolve_nofollow(root, &path, access, meter) {
                Ok(opened) => opened,
                Err(ReadError::Missing | ReadError::Denied | ReadError::Special) => continue,
                Err(error) => return Err(error),
            };
            let cap = file
                .format
                .cap()
                .min(BYTES_MAX - spend.bytes.min(BYTES_MAX));
            version = match opened.read(
                ReadCap {
                    bytes: cap,
                    single_link: true,
                },
                meter,
            ) {
                Ok(bytes) => {
                    // Fails without it: byte_bound_stops_further_languages.
                    spend.bytes += bytes.len() as u64;
                    rule::version(&file.format, &bytes, i as u8, level)
                }
                // Over the format's own cap: no value (C2 ruling Q4 for D1).
                // Over what the request may still read: stop (`Limit`).
                Err(ReadError::Limit) if cap == file.format.cap() => Version::Refused {
                    file: i as u8,
                    level,
                    digest: [0; 16],
                },
                Err(error) => return Err(error),
            };
            break 'files;
        }
    }
    Ok(LanguageResult {
        index,
        marker,
        version,
    })
}

/// Every asked language, in order, each sent as soon as it is known. Over
/// the probe or byte bound the rest is not sent (the reader sees no answer,
/// not a wrong one).
pub fn detect_all(
    queries: &[LanguageQuery],
    root: &Root,
    parts: &[&[u8]],
    access: &Access,
    meter: &mut Meter,
    mut send: impl FnMut(LanguageResult) -> Result<(), crate::git::CollectError>,
) -> Result<(), crate::git::CollectError> {
    use crate::git::CollectError;
    let mut spend = Spend {
        probes: 0,
        bytes: 0,
    };
    for (index, query) in queries.iter().enumerate() {
        match detect(index as u8, query, root, parts, access, &mut spend, meter) {
            Ok(result) => {
                meter.check().map_err(CollectError::Read)?;
                send(result)?;
            }
            Err(ReadError::Limit) => {
                meter.event("languages_over_bound");
                return Ok(());
            }
            Err(error) => return Err(CollectError::Read(error)),
        }
    }
    Ok(())
}
