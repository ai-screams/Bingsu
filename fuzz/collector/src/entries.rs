//! The ten in-memory fuzz entries. Each calls the collector's own bytes
//! parser (the same functions stage A–D call after a safe read), with a fresh
//! Meter. No path is opened and no process is started here: file-backed
//! classes (symref chains, gitdir ownership, reciprocal binding, safe-read
//! caps) run under the protected collector in a separate subprocess corpus.
//!
//! Shared verbatim by fuzz/collector's libFuzzer targets and the stable seed
//! replay (crates/bingsu-collect/tests/fuzz_seeds.rs).
//!
//! Input layout per target (F = one flag byte; bit 0 re-seals SHA-1 trailers):
//! - index, multi_pack_index: F + file bytes
//! - pack: F + pack length (u32 LE) + pack bytes + .idx bytes
//! - config, gitdir: file bytes
//! - attributes, ignore: F + file bytes; bits 0–1 pick the source label (0 the
//!   generic one, 1 a possibly nested .gitignore/.gitattributes, 2 info/exclude
//!   or info/attributes, 3 the global excludes or a nested attributes file),
//!   bits 2–3 the nesting depth
//! - refs: F + bytes; bit 0 clear = packed-refs, set = one loose ref
//! - commit_objects: F + bytes; bit 0 clear = commit body (framed, deflated
//!   and hashed here), set = a raw zlib stream under a non-matching id
//! - commondir: .git file bytes + NUL + commondir file bytes
use crate::{
    formats,
    git::{
        config::{self, Config},
        discover,
        io::{
            ReadMap, index,
            objects::{self, Pack},
            policy::{NamePolicy, PatternKind, Patterns, Policies},
        },
        refs::{self, Refs},
        stage_c,
    },
    meter::Meter,
    safe_read::ReadError,
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Target {
    Index,
    Pack,
    Config,
    Attributes,
    Ignore,
    Refs,
    CommitObjects,
    MultiPackIndex,
    Gitdir,
    Commondir,
}

impl Target {
    pub const ALL: [Self; 10] = [
        Self::Index,
        Self::Pack,
        Self::Config,
        Self::Attributes,
        Self::Ignore,
        Self::Refs,
        Self::CommitObjects,
        Self::MultiPackIndex,
        Self::Gitdir,
        Self::Commondir,
    ];

    /// Equals the fuzz_targets/<name>.rs file name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Pack => "pack",
            Self::Config => "config",
            Self::Attributes => "attributes",
            Self::Ignore => "ignore",
            Self::Refs => "refs",
            Self::CommitObjects => "commit_objects",
            Self::MultiPackIndex => "multi_pack_index",
            Self::Gitdir => "gitdir",
            Self::Commondir => "commondir",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Limit,
    Invalid,
    Unsupported,
    Escape,
    StageAOnly,
    Deadline,
    Other,
}

fn verdict(result: Result<(), ReadError>) -> Verdict {
    match result {
        Ok(()) => Verdict::Ok,
        Err(ReadError::Limit) => Verdict::Limit,
        Err(ReadError::Io(libc::EINVAL)) => Verdict::Invalid,
        Err(ReadError::Io(libc::ENOTSUP)) => Verdict::Unsupported,
        Err(ReadError::Escape) => Verdict::Escape,
        Err(ReadError::StageAOnly) => Verdict::StageAOnly,
        Err(ReadError::Deadline) => Verdict::Deadline,
        Err(_) => Verdict::Other,
    }
}

/// One input's request deadline. Every parser loop checks the Meter.
pub const DEADLINE: Duration = Duration::from_secs(2);
/// Joined pointer base for gitdir/commondir: the worktree's logical path.
pub const BASE: &[u8] = b"/fuzz/worktree";
/// Fixed relative paths the ignore/attributes matchers are driven over;
/// pattern cost is paid at match time as well as at parse time.
pub const PATHS: [&[u8]; 6] = [
    b"a",
    b"dir/file.txt",
    b"deep/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p",
    b"x.tmp",
    b"\xc3\xa9t\xc3\xa9/file",
    b"node_modules/pkg/index.js",
];

pub struct Outcome {
    pub verdict: Verdict,
    /// Bytes the Meter was asked to reserve (cumulative, Content phase).
    pub charged: u64,
    pub fds_after: u32,
    pub elapsed: Duration,
}

/// Work done before the measured parse: splits and optional seals. The
/// measured step borrows it, so nothing allocated here is freed inside.
/// Bit 0 of the flag byte re-seals SHA-1 trailers so mutations reach past
/// checksums; without it a damaged trailer is itself the input.
pub(crate) enum Prepared {
    Index(Vec<u8>),
    Pack(Vec<u8>, Vec<u8>),
    Config(Vec<u8>),
    Patterns(PatternKind, PathBuf, Vec<u8>),
    PackedRefs(Vec<u8>),
    LooseRef(Vec<u8>),
    Commit {
        compressed: Vec<u8>,
        id: formats::Oid,
    },
    Midx(Vec<u8>, Box<Pack>),
    Gitdir(Vec<u8>),
    Commondir(Vec<u8>, Vec<u8>),
}

fn split_flag(data: &[u8]) -> (u8, &[u8]) {
    match data.split_first() {
        Some((flag, rest)) => (*flag, rest),
        None => (0, data),
    }
}

/// The source label the product gives a pattern file, picked by the flag byte:
/// nested per-directory files, info/exclude, info/attributes and the global
/// excludes take different add_buffer branches (matcher base, info lists).
pub(crate) fn pattern_source(kind: PatternKind, flag: u8) -> PathBuf {
    let name = match kind {
        PatternKind::Ignore => ".gitignore",
        PatternKind::Attributes => ".gitattributes",
    };
    let nested = |depth: u8| {
        let mut path = PathBuf::new();
        for level in 0..depth {
            path.push(format!("d{level}"));
        }
        path.push(name);
        path
    };
    let depth = (flag >> 2) & 3;
    match (flag & 3, kind) {
        (1, _) => nested(depth),
        (2, PatternKind::Ignore) => "info/exclude".into(),
        (2, PatternKind::Attributes) => "info/attributes".into(),
        (3, PatternKind::Ignore) => "<global-excludes>".into(),
        (3, PatternKind::Attributes) => nested(depth + 1),
        _ => "fuzz".into(),
    }
}

pub(crate) fn prepare(target: Target, data: &[u8]) -> Prepared {
    let (flag, rest) = split_flag(data);
    match target {
        Target::Index => {
            let mut bytes = rest.to_vec();
            if flag & 1 != 0 {
                formats::reseal(&mut bytes);
            }
            Prepared::Index(bytes)
        }
        Target::Pack => {
            let length = rest.get(..4).map_or(0, |b| {
                u32::from_le_bytes(b.try_into().expect("4 bytes")) as usize
            });
            let body = rest.get(4..).unwrap_or_default();
            let (pack, idx) = body.split_at(length.min(body.len()));
            let (mut pack, mut idx) = (pack.to_vec(), idx.to_vec());
            if flag & 1 != 0 && pack.len() >= 20 && idx.len() >= 40 {
                formats::reseal(&mut pack);
                let trailer = pack[pack.len() - 20..].to_vec();
                let at = idx.len() - 40;
                idx[at..at + 20].copy_from_slice(&trailer);
                formats::reseal(&mut idx);
            }
            Prepared::Pack(pack, idx)
        }
        Target::Config => Prepared::Config(data.to_vec()),
        Target::Attributes => Prepared::Patterns(
            PatternKind::Attributes,
            pattern_source(PatternKind::Attributes, flag),
            rest.to_vec(),
        ),
        Target::Ignore => Prepared::Patterns(
            PatternKind::Ignore,
            pattern_source(PatternKind::Ignore, flag),
            rest.to_vec(),
        ),
        Target::Refs if flag & 1 == 0 => Prepared::PackedRefs(rest.to_vec()),
        Target::Refs => Prepared::LooseRef(rest.to_vec()),
        Target::CommitObjects if flag & 1 == 0 => {
            let raw = formats::loose_raw("commit", rest);
            Prepared::Commit {
                compressed: formats::deflate(&raw),
                id: formats::sha1(&raw),
            }
        }
        Target::CommitObjects => Prepared::Commit {
            compressed: rest.to_vec(),
            id: formats::sha1(rest),
        },
        Target::MultiPackIndex => {
            let mut bytes = rest.to_vec();
            if flag & 1 != 0 {
                formats::reseal(&mut bytes);
            }
            Prepared::Midx(bytes, Box::new(fixture_pack()))
        }
        Target::Gitdir => Prepared::Gitdir(data.to_vec()),
        Target::Commondir => {
            let at = data.iter().position(|b| *b == 0).unwrap_or(data.len());
            let common = data.get(at + 1..).unwrap_or_default();
            Prepared::Commondir(data[..at].to_vec(), common.to_vec())
        }
    }
}

/// The validated two-object pack every MIDX input is checked against.
pub struct FixturePack {
    pub data: Vec<u8>,
    pub index: Vec<u8>,
    pub objects: Vec<(formats::Oid, u64)>,
}

pub fn fixture_pack_bytes() -> FixturePack {
    let bodies: [&[u8]; 2] = [b"first\n", b"second\n"];
    let pack = formats::pack(
        &bodies
            .iter()
            .map(|body| formats::PackEntry::Base {
                kind: 3,
                body: body.to_vec(),
            })
            .collect::<Vec<_>>(),
    );
    let objects: Vec<_> = bodies
        .iter()
        .zip(&pack.offsets)
        .map(|(body, offset)| (formats::object_id("blob", body), *offset))
        .collect();
    let index = formats::pack_index(&objects, &pack.data);
    FixturePack {
        data: pack.data,
        index,
        objects,
    }
}

fn fixture_pack() -> Pack {
    let fixture = fixture_pack_bytes();
    let mut meter = Meter::new(Instant::now() + DEADLINE);
    Pack::from_bytes(
        formats::pack_name(&fixture.data),
        ReadMap::fuzz_bytes(&fixture.data),
        ReadMap::fuzz_bytes(&fixture.index),
        &mut meter,
    )
    .expect("fixture pack is valid")
}

/// gitdir/commondir oracle: an accepted pointer is absolute and normalized.
fn assert_normalized(path: &[u8]) {
    assert!(path.starts_with(b"/") && path.len() <= 65_536, "{path:?}");
    let parts: Vec<_> = path[1..].split(|b| *b == b'/').collect();
    assert!(parts.len() <= 4096, "component cap");
    assert!(
        parts
            .iter()
            .all(|p| !matches!(*p, b"" | b"." | b"..") && !p.contains(&0)),
        "unnormalized pointer {path:?}"
    );
}

fn parts(path: &[u8]) -> Vec<&[u8]> {
    path.split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect()
}

fn run_prepared(prepared: &mut Prepared, meter: &mut Meter) -> Result<(), ReadError> {
    match prepared {
        Prepared::Index(bytes) => {
            let parsed = index::parse(bytes, meter)?;
            assert_live(meter, "index");
            drop(parsed);
            Ok(())
        }
        Prepared::Pack(data, idx) => {
            // The product maps both files; these copies stand in for the maps.
            let (data, idx) = (ReadMap::fuzz_bytes(data), ReadMap::fuzz_bytes(idx));
            let pack = Pack::from_bytes(b"fuzz.idx".to_vec(), data, idx, meter)?;
            assert_live(meter, "pack");
            pack.fuzz_decode_all(meter)
        }
        Prepared::Config(bytes) => {
            // The heap oracle compares against what the Meter charged; for
            // config that must include the per-input parser_allocation(bytes).
            let before = meter.counts[2].allocated;
            let facts = config::parse(bytes, meter);
            if let (Ok(reservation), Ok(_)) = (config::parser_allocation(bytes), &facts) {
                // 이것을 실패시키는 것: isolated()가 parser_allocation보다 적게 예약하는 것.
                let charged = meter.counts[2].allocated - before;
                assert!(charged >= reservation as u64, "config reservation");
            }
            let facts = facts?;
            assert_live(meter, "config facts");
            let config = Config::fuzz_common(facts);
            let _ = (config.has_core_worktree(), config.has_use_replace_refs());
            Policies::from_config(&config).map(drop)
        }
        Prepared::Patterns(kind, source, bytes) => {
            let mut patterns = Patterns::default();
            patterns.fuzz_bytes(bytes, *kind, source.clone(), meter)?;
            assert_live(meter, "patterns");
            let policies = Policies::from_config(&Config::default())?;
            for names in [
                NamePolicy::default(),
                NamePolicy {
                    ignore_case: true,
                    precompose_unicode: true,
                },
            ] {
                let policies = Policies { names, ..policies };
                for path in PATHS {
                    match *kind {
                        PatternKind::Ignore => {
                            patterns.ignored_in(meter, path, false, names)?;
                            patterns.ignored_in(meter, path, true, names)?;
                        }
                        PatternKind::Attributes => {
                            patterns.conversion_in(meter, path, policies)?;
                        }
                    }
                }
            }
            assert_live(meter, "pattern matches");
            Ok(())
        }
        Prepared::PackedRefs(bytes) => {
            let refs = Refs::parse(bytes, meter)?;
            assert_live(meter, "packed refs");
            let _ = refs.contains_replace();
            Ok(())
        }
        Prepared::LooseRef(bytes) => {
            let parsed = refs::parse_loose(bytes)?;
            assert_live(meter, "loose ref");
            drop(parsed);
            Ok(())
        }
        Prepared::Commit { compressed, id } => {
            let id = gix_index::hash::ObjectId::from_bytes_or_panic(&id[..]);
            let mut buffer = Vec::new();
            let decoded = objects::loose(compressed, &id, &mut buffer, meter)?;
            assert_live(meter, "loose object");
            stage_c::checked_commit(&decoded, meter)?;
            gix_object::CommitRefIter::from_bytes(decoded.data, gix_index::hash::Kind::Sha1)
                .tree_id()
                .map(drop)
                .map_err(|_| ReadError::Io(libc::EINVAL))
        }
        Prepared::Midx(bytes, pack) => objects::validate_midx(
            ReadMap::fuzz_bytes(bytes),
            std::slice::from_ref(pack),
            meter,
        ),
        Prepared::Gitdir(bytes) => {
            let pointer = discover::gitfile_pointer(bytes)?;
            let discover::GitfileShape {
                scratch: _scratch,
                git_path,
                common,
            } = discover::gitfile_shape(BASE, pointer, meter)?;
            assert_live(meter, "gitfile");
            assert_normalized(&git_path);
            if let Some(common) = common {
                assert_normalized(&common);
                assert!(git_path.starts_with(&[&common[..], b"/worktrees/"].concat()));
            }
            let _ = discover::module_suffix(&git_path, b"/fuzz/worktree/.git");
            Ok(())
        }
        Prepared::Commondir(gitfile, common) => {
            let pointer = discover::gitfile_pointer(gitfile)?;
            let discover::GitfileShape {
                scratch: _scratch,
                git_path,
                common: expected,
            } = discover::gitfile_shape(BASE, pointer, meter)?;
            assert_live(meter, "commondir");
            let Some(expected) = expected else {
                // Not a linked worktree: the commondir file is never consulted.
                return Err(ReadError::Escape);
            };
            let target = discover::pointer_target(&git_path, common)?;
            if target != expected {
                return Err(ReadError::Escape);
            }
            assert_normalized(&target);
            assert!(git_path.starts_with(&[&target[..], b"/worktrees/"].concat()));
            Ok(())
        }
    }
}

/// Live-heap oracle, run while a parse result is still held: the heap alive
/// now must be covered by what the Meter holds reserved now (a released
/// reservation covers nothing) plus UNRESERVED. The cumulative charge cannot
/// see an allocation made after a release, and an allowance sized by the
/// input would hide an unreserved copy of it. Measured over every fixed seed
/// the largest excess of live over reserved was 63 B (a loose ref); the map
/// stand-ins of the pack and midx entries are covered by their reservations.
// 이것을 실패시키는 것: config::parse 첫 줄에 `std::mem::forget(bytes.to_vec())`
// 같은 입력 크기의 무예약 할당을 넣는 것("config facts"가 실패한다), 그리고
// assert_live_rejects_unreserved_heap 시험(fuzz_seeds.rs)에서 이 검사를 지우는 것.
pub(crate) fn assert_live(meter: &Meter, what: &str) {
    let live = crate::allocation::live();
    let reserved = usize::try_from(meter.live_allocated()).unwrap_or(usize::MAX);
    assert!(
        live <= reserved.saturating_add(UNRESERVED),
        "{what}: {live} live heap bytes above the {reserved} reserved now"
    );
}

/// The measured step. Callers bracket only this with their heap counter;
/// its own copies (standing in for maps) are freed before it returns.
pub(crate) fn execute(prepared: &mut Prepared) -> Outcome {
    let start = Instant::now();
    let mut meter = Meter::new(start + DEADLINE);
    let result = run_prepared(prepared, &mut meter);
    Outcome {
        verdict: verdict(result),
        charged: meter.counts[2].allocated,
        fds_after: meter.live_fds(),
        elapsed: start.elapsed(),
    }
}

/// Allowed unreserved heap: the Meter's own counters, error values and other
/// constant bookkeeping. Anything else must be reserved before it is used.
pub const UNRESERVED: usize = 4096;

/// Oracles shared by fuzzing and replay: no descriptor is held, the request
/// deadline bounds time, and the peak heap never passes what the parser
/// reserved through the Meter (cumulative, itself under the 8 MiB live cap)
/// plus two input-sized copies and UNRESERVED. The copies stand for those a
/// measured step makes itself (the pack and midx map stand-ins, one derived
/// value); prepare's own copies are made outside the measure and are not
/// counted. assert_live checks the stricter live bound at each stage.
pub fn assert_bounded(outcome: &Outcome, peak: usize, input: usize, slack: Duration) {
    assert_eq!(outcome.fds_after, 0, "descriptor lease leaked");
    assert!(
        outcome.elapsed <= DEADLINE + slack,
        "deadline ignored: {:?}",
        outcome.elapsed
    );
    let reserved = usize::try_from(outcome.charged).unwrap_or(usize::MAX);
    assert!(
        peak <= reserved.saturating_add(2 * input + UNRESERVED),
        "heap peak {peak} above the {reserved} reserved bytes"
    );
}
