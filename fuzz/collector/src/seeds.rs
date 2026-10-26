//! Fixed seed corpus with one pinned verdict per seed. Every target has the
//! classes in `Class::REQUIRED`; cap seeds derive from the collector's own
//! constants, so a removed or loosened check changes a verdict.
//!
//! What "cyclic" means per target (in memory; file-backed cycles run under
//! the protected collector in the subprocess corpus):
//! - index: split-index `link` to a shared index (self-reference) and a
//!   duplicated cache-tree child;
//! - pack: REF_DELTA -> OFS_DELTA -> the first entry again;
//! - config: include/includeIf naming the same file (inert data);
//! - attributes: a macro that expands to itself;
//! - ignore: patterns that negate each other back and forth;
//! - refs: a loose ref naming itself (resolution is file-backed) and a packed
//!   list repeating a name;
//! - commit_objects: duplicate parent lines (a real parent cycle cannot hash
//!   to its own id; the walk's cycle colour is pinned by git_history);
//! - multi_pack_index: two objects aliasing one pack offset;
//! - gitdir: a pointer to the worktree itself;
//! - commondir: a commondir naming the linked gitdir itself.
use crate::{
    entries::{self, Target, Verdict},
    formats::{self, IndexEntry, PackEntry},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    Valid,
    Damaged,
    Truncated,
    Cyclic,
    Oversize,
    CapMinusOne,
    AtCap,
    CapPlusOne,
}

impl Class {
    pub const REQUIRED: [Self; 8] = [
        Self::Valid,
        Self::Damaged,
        Self::Truncated,
        Self::Cyclic,
        Self::Oversize,
        Self::CapMinusOne,
        Self::AtCap,
        Self::CapPlusOne,
    ];
}

pub struct Seed {
    pub target: Target,
    pub name: &'static str,
    pub class: Class,
    pub data: Vec<u8>,
    pub expect: Verdict,
}

/// Larger seeds are replayed by the stable test but kept out of the
/// libFuzzer start corpus, whose mutations work on small inputs.
pub const CORPUS_MAX: usize = 1_048_576;

const SEAL: u8 = 1;

fn with_flag(flag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut data = vec![flag];
    data.extend_from_slice(bytes);
    data
}

pub fn all() -> Vec<Seed> {
    let mut seeds = Vec::new();
    index(&mut seeds);
    pack(&mut seeds);
    config(&mut seeds);
    patterns(&mut seeds, Target::Attributes);
    patterns(&mut seeds, Target::Ignore);
    refs(&mut seeds);
    commit_objects(&mut seeds);
    multi_pack_index(&mut seeds);
    gitdir(&mut seeds);
    commondir(&mut seeds);
    seeds
}

fn push(
    seeds: &mut Vec<Seed>,
    target: Target,
    name: &'static str,
    class: Class,
    data: Vec<u8>,
    expect: Verdict,
) {
    seeds.push(Seed {
        target,
        name,
        class,
        data,
        expect,
    });
}

fn blob_entry(path: &str) -> IndexEntry {
    IndexEntry {
        path: path.as_bytes().to_vec(),
        id: formats::object_id("blob", path.as_bytes()),
        mode: 0o100644,
        stage: 0,
    }
}

fn index_header(count: u32) -> Vec<u8> {
    let mut bytes = b"DIRC".to_vec();
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(count.to_be_bytes());
    bytes.extend([0u8; 20]);
    with_flag(SEAL, &bytes)
}

fn index(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::Index;
    let entries = [blob_entry("a"), blob_entry("dir/b")];
    let tree = {
        let mut tree = b"\x002 1\n".to_vec();
        tree.extend(formats::object_id("tree", b"root"));
        tree.extend(b"dir\x001 0\n");
        tree.extend(formats::object_id("tree", b"dir"));
        tree
    };
    let valid = formats::index(2, &entries, &[(*b"TREE", tree)]);
    push(seeds, t, "valid-with-tree", Valid, with_flag(0, &valid), Ok);
    let mut bad = valid.clone();
    *bad.last_mut().unwrap() ^= 1;
    push(seeds, t, "checksum", Damaged, with_flag(0, &bad), Invalid);
    let mut signature = valid.clone();
    signature[3] = b'X';
    push(
        seeds,
        t,
        "signature",
        Damaged,
        with_flag(SEAL, &signature),
        Invalid,
    );
    push(
        seeds,
        t,
        "half",
        Truncated,
        with_flag(SEAL, &valid[..valid.len() / 2]),
        Invalid,
    );
    push(
        seeds,
        t,
        "header-only",
        Truncated,
        with_flag(0, &valid[..12]),
        Invalid,
    );
    // Split index: link names a shared index; with bitmaps it can also claim
    // huge EWAH sizes. Both are refused before any bitmap or shared lookup.
    let mut link = vec![0u8; 20];
    push(
        seeds,
        t,
        "link-sharedindex-missing",
        Cyclic,
        with_flag(0, &formats::index(2, &entries, &[(*b"link", link.clone())])),
        Unsupported,
    );
    link.extend(u32::MAX.to_be_bytes());
    link.extend(u32::MAX.to_be_bytes());
    push(
        seeds,
        t,
        "link-bitmap-overflow",
        Damaged,
        with_flag(0, &formats::index(2, &entries, &[(*b"link", link)])),
        Unsupported,
    );
    let duplicate = {
        let mut tree = b"\x002 2\n".to_vec();
        tree.extend(formats::object_id("tree", b"root"));
        for _ in 0..2 {
            tree.extend(b"dir\x001 0\n");
            tree.extend(formats::object_id("tree", b"dir"));
        }
        tree
    };
    // A bad optional cache is discarded, never evidence of a clean stage.
    push(
        seeds,
        t,
        "tree-duplicate-child",
        Cyclic,
        with_flag(0, &formats::index(2, &entries, &[(*b"TREE", duplicate)])),
        Ok,
    );
    let mut huge = b"DIRC".to_vec();
    huge.extend(2u32.to_be_bytes());
    huge.extend(u32::MAX.to_be_bytes());
    huge.extend([0u8; 20]);
    push(
        seeds,
        t,
        "huge-count",
        Oversize,
        with_flag(SEAL, &huge),
        Limit,
    );
    let cap = bingsu_core::collection::budget::INDEX_BYTES as usize;
    let mut bytes = b"DIRC".to_vec();
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(1u32.to_be_bytes());
    bytes.resize(cap + 1, 0);
    push(
        seeds,
        t,
        "bytes-cap-plus-one",
        Oversize,
        with_flag(SEAL, &bytes),
        Limit,
    );
    bytes.truncate(cap);
    // Passes the size check, then an all-zero extension signature: not a Limit.
    push(
        seeds,
        t,
        "bytes-at-cap",
        AtCap,
        with_flag(SEAL, &bytes),
        Unsupported,
    );
    let entries_cap = bingsu_core::collection::budget::INDEX_ENTRIES as u32;
    push(
        seeds,
        t,
        "entries-cap-minus-one",
        CapMinusOne,
        index_header(entries_cap - 1),
        Invalid,
    );
    push(
        seeds,
        t,
        "entries-at-cap",
        AtCap,
        index_header(entries_cap),
        Invalid,
    );
    push(
        seeds,
        t,
        "entries-cap-plus-one",
        CapPlusOne,
        index_header(entries_cap + 1),
        Limit,
    );
}

/// A base blob and `depth` OFS_DELTA entries, each one byte longer.
fn delta_chain(depth: usize) -> Vec<u8> {
    let mut content = b"x".to_vec();
    let mut entries = vec![PackEntry::Base {
        kind: 3,
        body: content.clone(),
    }];
    let mut ids = vec![formats::object_id("blob", &content)];
    for k in 0..depth {
        let insert = [b'a' + (k % 26) as u8];
        entries.push(PackEntry::OfsDelta {
            back: 1,
            delta: formats::copy_insert_delta(content.len(), &insert),
        });
        content.push(insert[0]);
        ids.push(formats::object_id("blob", &content));
    }
    pack_input(entries, &ids)
}

fn pack_input(entries: Vec<PackEntry>, ids: &[formats::Oid]) -> Vec<u8> {
    let pack = formats::pack(&entries);
    let objects: Vec<_> = ids
        .iter()
        .copied()
        .zip(pack.offsets.iter().copied())
        .collect();
    let idx = formats::pack_index(&objects, &pack.data);
    let mut data = vec![0];
    data.extend((pack.data.len() as u32).to_le_bytes());
    data.extend(pack.data);
    data.extend(idx);
    data
}

fn pack(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::Pack;
    let valid = delta_chain(3);
    push(seeds, t, "delta-chain-3", Valid, valid.clone(), Ok);
    let mut bad = valid.clone();
    let at = 5 + u32::from_le_bytes(valid[1..5].try_into().unwrap()) as usize - 1;
    bad[at] ^= 1;
    push(seeds, t, "pack-checksum", Damaged, bad, Invalid);
    let pack_len = u32::from_le_bytes(valid[1..5].try_into().unwrap()) as usize;
    let half = pack_len / 2 + 20;
    let mut cut = vec![SEAL];
    cut.extend((half as u32).to_le_bytes());
    cut.extend_from_slice(&valid[5..5 + half]);
    cut.extend_from_slice(&valid[5 + pack_len..]);
    push(seeds, t, "pack-half", Truncated, cut, Invalid);
    // B is a REF_DELTA on A's id; A is an OFS_DELTA back onto B.
    let (a, b) = ([0x11; 20], [0x22; 20]);
    let cyclic = pack_input(
        vec![
            PackEntry::RefDelta {
                base: a,
                delta: formats::copy_insert_delta(1, b"b"),
            },
            PackEntry::OfsDelta {
                back: 1,
                delta: formats::copy_insert_delta(1, b"a"),
            },
        ],
        &[b, a],
    );
    push(seeds, t, "ref-ofs-delta-cycle", Cyclic, cyclic, Limit);
    // A delta claiming a 1 TiB result from a 1-byte base (delta bomb).
    let mut bomb = formats::varint(1);
    bomb.extend(formats::varint(1 << 40));
    bomb.extend([0x91, 0x00, 0x01]);
    let base = b"x".to_vec();
    let bomb = pack_input(
        vec![
            PackEntry::Base {
                kind: 3,
                body: base.clone(),
            },
            PackEntry::OfsDelta {
                back: 1,
                delta: bomb,
            },
        ],
        &[formats::object_id("blob", &base), [0x33; 20]],
    );
    push(seeds, t, "delta-bomb", Oversize, bomb, Limit);
    let depth = crate::git::io::objects::DELTA_DEPTH;
    push(
        seeds,
        t,
        "depth-cap-minus-one",
        CapMinusOne,
        delta_chain(depth - 1),
        Ok,
    );
    push(seeds, t, "depth-at-cap", AtCap, delta_chain(depth), Ok);
    push(
        seeds,
        t,
        "depth-cap-plus-one",
        CapPlusOne,
        delta_chain(depth + 1),
        Limit,
    );
}

fn config(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::Config;
    let s = |text: &str| text.as_bytes().to_vec();
    push(
        seeds,
        t,
        "core",
        Valid,
        s("[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
        Ok,
    );
    push(
        seeds,
        t,
        "checkstat-unknown",
        Damaged,
        s("[core]\n\tcheckStat = sometimes\n"),
        Invalid,
    );
    push(
        seeds,
        t,
        "boolean-unknown",
        Damaged,
        s("[core]\n\tfilemode = perhaps\n"),
        Invalid,
    );
    push(
        seeds,
        t,
        "unterminated-header",
        Truncated,
        s("[core\n\tbare = true\n"),
        Invalid,
    );
    push(
        seeds,
        t,
        "include-loop",
        Cyclic,
        s("[include]\n\tpath = config\n[includeIf \"gitdir:/\"]\n\tpath = ./config\n"),
        Ok,
    );
    let cap = bingsu_core::collection::budget::CONFIG_BYTES as usize;
    let comment = |n: usize| {
        let mut bytes = b"# ".to_vec();
        bytes.resize(n, b'x');
        bytes
    };
    push(
        seeds,
        t,
        "bytes-cap-plus-one",
        Oversize,
        comment(cap + 1),
        Limit,
    );
    push(seeds, t, "bytes-at-cap", AtCap, comment(cap), Ok);
    let sections = |n: usize| "[a]\n".repeat(n).into_bytes();
    let limit = crate::git::config::SECTION_LIMIT;
    push(
        seeds,
        t,
        "sections-cap-minus-one",
        CapMinusOne,
        sections(limit - 1),
        Ok,
    );
    push(seeds, t, "sections-at-cap", AtCap, sections(limit), Ok);
    push(
        seeds,
        t,
        "sections-cap-plus-one",
        CapPlusOne,
        sections(limit + 1),
        Limit,
    );
    // Header names are not key words (scan counts names outside headers).
    let words = |n: usize| {
        let mut text = "[a]\n".to_string();
        text.push_str(&"k ".repeat(n));
        text.into_bytes()
    };
    let limit = crate::git::config::WORD_LIMIT;
    push(seeds, t, "words-at-cap", AtCap, words(limit), Ok);
    push(
        seeds,
        t,
        "words-cap-plus-one",
        CapPlusOne,
        words(limit + 1),
        Limit,
    );
    // Fuzz findings: one long implicit-key line, then another header. gix
    // copies the whole section's event Vec at that header; a fixed envelope
    // undercounted these by about 27% before charging the scanned structure.
    let mut minimal = b"[a]\n".to_vec();
    minimal.extend(b" k".repeat(4000));
    minimal.extend(b"\n[a]\n");
    push(
        seeds,
        t,
        "finding-implicit-keys-then-header",
        Valid,
        minimal,
        Ok,
    );
    let found = include_bytes!("../seeds/config-two-sections-implicit-keys.bin");
    push(
        seeds,
        t,
        "finding-sections-around-key-line",
        Damaged,
        found.to_vec(),
        // Its trailing 0xff bytes fail the parse; the peak came before that error.
        Invalid,
    );
    // Front matter, then a section that doubles the event Vec: the front
    // SmallVec stays live beside it. One 2 * NPOT(all events) envelope
    // undercounted this by 33 KB before front matter was charged on its own.
    let found = include_bytes!("../seeds/config-front-matter-then-section.bin");
    push(
        seeds,
        t,
        "finding-front-matter-then-section",
        Valid,
        found.to_vec(),
        Ok,
    );
}

fn patterns(seeds: &mut Vec<Seed>, t: Target) {
    use Class::*;
    use Verdict::*;
    let attributes = t == Target::Attributes;
    let s = |text: &str| text.as_bytes().to_vec();
    if attributes {
        push(
            seeds,
            t,
            "text-eol",
            Valid,
            s("*.txt text eol=lf\n*.bin -text\n"),
            Ok,
        );
        push(
            seeds,
            t,
            "macro-self",
            Cyclic,
            s("[attr]loop loop\n* loop\n"),
            Unsupported,
        );
        push(
            seeds,
            t,
            "unterminated-quote",
            Truncated,
            s("\"*.txt text\n"),
            Ok,
        );
    } else {
        push(
            seeds,
            t,
            "tmp-and-negation",
            Valid,
            s("*.tmp\n!keep.tmp\nbuild/\n"),
            Ok,
        );
        push(
            seeds,
            t,
            "negation-ping-pong",
            Cyclic,
            s("*\n!*\n*\n!*\n"),
            Ok,
        );
        push(seeds, t, "trailing-escape", Truncated, s("dir/\\"), Ok);
    }
    push(seeds, t, "nul-byte", Damaged, s("*.c x\0y\n"), Limit);
    let explosion = "**/**/**/**/**/**/**/**/**/a*b*c*d*e* x\n".repeat(64);
    push(
        seeds,
        t,
        "glob-explosion",
        Valid,
        explosion.into_bytes(),
        Ok,
    );
    let cap = bingsu_core::collection::budget::IGNORE_BYTES as usize;
    debug_assert_eq!(
        cap,
        bingsu_core::collection::budget::ATTRIBUTE_BYTES as usize
    );
    push(
        seeds,
        t,
        "bytes-cap-plus-one",
        Oversize,
        vec![b' '; cap + 1],
        Limit,
    );
    push(seeds, t, "bytes-at-cap", AtCap, vec![b' '; cap], Ok);
    // add_buffer's word cap bounds both parse and per-path match work.
    let words = |n: usize| "a\n".repeat(n).into_bytes();
    push(
        seeds,
        t,
        "words-cap-minus-one",
        CapMinusOne,
        words(2047),
        Ok,
    );
    push(seeds, t, "words-at-cap", AtCap, words(2048), Ok);
    push(
        seeds,
        t,
        "words-cap-plus-one",
        CapPlusOne,
        words(2049),
        Limit,
    );
}

fn packed(names: impl Iterator<Item = String>) -> Vec<u8> {
    let mut text = "# pack-refs with: peeled fully-peeled sorted \n".to_string();
    for name in names {
        text.push_str(&format!("{} {name}\n", "1".repeat(40)));
    }
    with_flag(0, text.as_bytes())
}

fn refs(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::Refs;
    let names = |n: usize| (0..n).map(|k| format!("refs/heads/b{k:05}"));
    push(seeds, t, "packed-two", Valid, packed(names(2)), Ok);
    push(
        seeds,
        t,
        "loose-object",
        Valid,
        with_flag(1, "1".repeat(40).as_bytes()),
        Ok,
    );
    push(
        seeds,
        t,
        "packed-bad-hex",
        Damaged,
        with_flag(0, b"zz refs/heads/main\n"),
        Invalid,
    );
    push(
        seeds,
        t,
        "packed-outside-refs",
        Damaged,
        packed(["../../config".to_string()].into_iter()),
        Invalid,
    );
    push(
        seeds,
        t,
        "loose-short-id",
        Truncated,
        with_flag(1, b"1111"),
        Invalid,
    );
    push(
        seeds,
        t,
        "loose-self",
        Cyclic,
        with_flag(1, b"ref: refs/heads/main\n"),
        Ok,
    );
    push(
        seeds,
        t,
        "packed-repeated-name",
        Cyclic,
        packed(
            ["refs/heads/a", "refs/heads/a"]
                .map(String::from)
                .into_iter(),
        ),
        Invalid,
    );
    let cap = bingsu_core::collection::budget::REF_BYTES as usize;
    let mut big = b"# x".to_vec();
    big.resize(cap + 1, b'x');
    push(
        seeds,
        t,
        "packed-bytes-cap-plus-one",
        Oversize,
        with_flag(0, &big),
        Limit,
    );
    let small = bingsu_core::collection::budget::SMALL_FILE_BYTES as usize;
    push(
        seeds,
        t,
        "loose-bytes-cap-plus-one",
        Oversize,
        with_flag(1, &vec![b'1'; small + 1]),
        Limit,
    );
    let entries = bingsu_core::collection::budget::REF_ENTRIES as usize;
    push(
        seeds,
        t,
        "entries-cap-minus-one",
        CapMinusOne,
        packed(names(entries - 1)),
        Ok,
    );
    push(
        seeds,
        t,
        "entries-at-cap",
        AtCap,
        packed(names(entries)),
        Ok,
    );
    push(
        seeds,
        t,
        "entries-cap-plus-one",
        CapPlusOne,
        packed(names(entries + 1)),
        Limit,
    );
}

/// A commit whose compressed + inflated + probe bytes total exactly `sum`.
fn commit_of_total(sum: usize) -> Vec<u8> {
    let mut extra = sum.saturating_sub(4096);
    for _ in 0..64 {
        let body = formats::commit_body(formats::EMPTY_TREE, &[], &vec![b'x'; extra]);
        let raw = formats::loose_raw("commit", &body);
        let total = formats::deflate(&raw).len() + raw.len() + 1;
        if total == sum {
            return with_flag(0, &body);
        }
        extra = (extra as isize + sum as isize - total as isize) as usize;
    }
    panic!("no commit with total {sum}");
}

fn commit_objects(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::CommitObjects;
    let tree = formats::EMPTY_TREE;
    let parent = formats::hex(&formats::object_id("commit", b"parent"));
    push(
        seeds,
        t,
        "root",
        Valid,
        with_flag(0, &formats::commit_body(tree, &[], b"m\n")),
        Ok,
    );
    push(
        seeds,
        t,
        "with-parent",
        Valid,
        with_flag(
            0,
            &formats::commit_body(tree, std::slice::from_ref(&parent), b"m\n"),
        ),
        Ok,
    );
    push(
        seeds,
        t,
        "bad-tree-hex",
        Damaged,
        with_flag(0, b"tree zz\n\nm\n"),
        Invalid,
    );
    push(
        seeds,
        t,
        "no-message",
        Damaged,
        with_flag(0, format!("tree {tree}\n").as_bytes()),
        Invalid,
    );
    let stream = formats::deflate(&formats::loose_raw(
        "commit",
        &formats::commit_body(tree, &[], b"m\n"),
    ));
    push(
        seeds,
        t,
        "stream-half",
        Truncated,
        with_flag(1, &stream[..stream.len() / 2]),
        Invalid,
    );
    push(
        seeds,
        t,
        "duplicate-parents",
        Cyclic,
        with_flag(
            0,
            &formats::commit_body(tree, &[parent.clone(), parent], b"m\n"),
        ),
        Ok,
    );
    // Header claims 100 MB; inflating the first 64 bytes reveals it.
    let mut bomb = b"commit 100000000\0".to_vec();
    bomb.resize(65_536, 0);
    push(
        seeds,
        t,
        "zip-bomb",
        Oversize,
        with_flag(1, &formats::deflate(&bomb)),
        Limit,
    );
    let cap = crate::git::io::objects::OBJECT_BUFFER;
    push(
        seeds,
        t,
        "inflated-cap-minus-one",
        CapMinusOne,
        commit_of_total(cap - 1),
        Ok,
    );
    push(seeds, t, "inflated-at-cap", AtCap, commit_of_total(cap), Ok);
    push(
        seeds,
        t,
        "inflated-cap-plus-one",
        CapPlusOne,
        commit_of_total(cap + 1),
        Limit,
    );
    // The compressed snapshot itself: below OBJECT_BUFFER it reaches zlib.
    push(
        seeds,
        t,
        "compressed-below-cap",
        AtCap,
        with_flag(1, &vec![0x78; cap - 1]),
        Invalid,
    );
    push(
        seeds,
        t,
        "compressed-at-cap",
        CapPlusOne,
        with_flag(1, &vec![0x78; cap]),
        Limit,
    );
}

fn fixture_midx(
    packs: u32,
    objects: Option<Vec<(formats::Oid, u32, u32)>>,
    extra: Option<([u8; 4], Vec<u8>)>,
) -> Vec<u8> {
    let fixture = entries::fixture_pack_bytes();
    let objects = objects.unwrap_or_else(|| {
        fixture
            .objects
            .iter()
            .map(|(id, offset)| (*id, 0, *offset as u32))
            .collect()
    });
    formats::midx(&formats::MidxParts {
        packs,
        names: vec![formats::pack_name(&fixture.data)],
        objects,
        extra_chunk: extra,
    })
}

fn multi_pack_index(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::MultiPackIndex;
    let valid = fixture_midx(1, None, None);
    push(seeds, t, "one-pack", Valid, with_flag(0, &valid), Ok);
    let mut bad = valid.clone();
    *bad.last_mut().unwrap() ^= 1;
    push(seeds, t, "checksum", Damaged, with_flag(0, &bad), Invalid);
    push(
        seeds,
        t,
        "half",
        Truncated,
        with_flag(SEAL, &valid[..valid.len() / 2]),
        Invalid,
    );
    let fixture = entries::fixture_pack_bytes();
    let first = fixture.objects[0].1 as u32;
    let aliased = fixture
        .objects
        .iter()
        .map(|(id, _)| (*id, 0, first))
        .collect();
    push(
        seeds,
        t,
        "aliased-offsets",
        Cyclic,
        with_flag(0, &fixture_midx(1, Some(aliased), None)),
        Invalid,
    );
    let overflow = fixture
        .objects
        .iter()
        .map(|(id, _)| (*id, 0, 0x8000_0000 | 1))
        .collect();
    push(
        seeds,
        t,
        "offset-overflow",
        Oversize,
        with_flag(0, &fixture_midx(1, Some(overflow), None)),
        Invalid,
    );
    let loff = Some((*b"LOFF", vec![0xff; 8]));
    push(
        seeds,
        t,
        "large-offset-chunk",
        Oversize,
        with_flag(0, &fixture_midx(1, None, loff)),
        Unsupported,
    );
    let cap = bingsu_core::collection::budget::PACKS as u32;
    push(
        seeds,
        t,
        "packs-cap-minus-one",
        CapMinusOne,
        with_flag(0, &fixture_midx(cap - 1, None, None)),
        Invalid,
    );
    push(
        seeds,
        t,
        "packs-at-cap",
        AtCap,
        with_flag(0, &fixture_midx(cap, None, None)),
        Invalid,
    );
    push(
        seeds,
        t,
        "packs-cap-plus-one",
        CapPlusOne,
        with_flag(0, &fixture_midx(cap + 1, None, None)),
        Limit,
    );
}

fn relative(components: usize) -> Vec<u8> {
    let mut pointer = b"gitdir: ".to_vec();
    pointer.extend("a/".repeat(components).bytes());
    pointer.pop();
    pointer.push(b'\n');
    pointer
}

fn gitdir(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::Gitdir;
    let s = |text: &str| text.as_bytes().to_vec();
    push(
        seeds,
        t,
        "linked-worktree",
        Valid,
        s("gitdir: /repo/.git/worktrees/w\n"),
        Ok,
    );
    push(
        seeds,
        t,
        "submodule-relative",
        Valid,
        s("gitdir: ../.git/modules/sub\n"),
        Ok,
    );
    push(
        seeds,
        t,
        "missing-colon",
        Damaged,
        s("gitdir /repo/.git\n"),
        Escape,
    );
    push(
        seeds,
        t,
        "embedded-nul",
        Damaged,
        s("gitdir: /repo\0/.git\n"),
        Escape,
    );
    push(
        seeds,
        t,
        "two-lines",
        Damaged,
        s("gitdir: /a\ngitdir: /b\n"),
        Escape,
    );
    push(seeds, t, "empty-target", Truncated, s("gitdir: \n"), Escape);
    push(seeds, t, "self", Cyclic, s("gitdir: .\n"), Ok);
    push(
        seeds,
        t,
        "parent-escape",
        Damaged,
        s("gitdir: ../../../../etc\n"),
        Escape,
    );
    let mut long = b"gitdir: /".to_vec();
    long.resize(8 + 65_537, b'a');
    push(
        seeds,
        t,
        "length-cap-plus-one",
        Oversize,
        long.clone(),
        Escape,
    );
    long.truncate(8 + 65_536);
    push(seeds, t, "length-at-cap", AtCap, long, Ok);
    // BASE contributes two components; the cap counts the joined path.
    let base = entries::BASE
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .count();
    push(
        seeds,
        t,
        "components-cap-minus-one",
        CapMinusOne,
        relative(4095 - base),
        Ok,
    );
    push(
        seeds,
        t,
        "components-at-cap",
        AtCap,
        relative(4096 - base),
        Ok,
    );
    push(
        seeds,
        t,
        "components-cap-plus-one",
        CapPlusOne,
        relative(4097 - base),
        Limit,
    );
}

fn commondir(seeds: &mut Vec<Seed>) {
    use Class::*;
    use Verdict::*;
    let t = Target::Commondir;
    let pair = |common: &[u8]| {
        let mut data = b"gitdir: /r/.git/worktrees/w\n\0".to_vec();
        data.extend_from_slice(common);
        data
    };
    push(seeds, t, "relative-parent", Valid, pair(b"../..\n"), Ok);
    push(seeds, t, "absolute-common", Valid, pair(b"/r/.git\n"), Ok);
    push(seeds, t, "two-lines", Damaged, pair(b"../..\nx\n"), Escape);
    push(
        seeds,
        t,
        "not-linked",
        Damaged,
        b"gitdir: /r/.git\n\0../..\n".to_vec(),
        Escape,
    );
    push(seeds, t, "empty", Truncated, pair(b""), Escape);
    push(seeds, t, "self", Cyclic, pair(b".\n"), Escape);
    push(
        seeds,
        t,
        "other-worktree",
        Cyclic,
        pair(b"../../worktrees/w\n"),
        Escape,
    );
    push(
        seeds,
        t,
        "outside",
        Damaged,
        pair(b"../../../../../../outside\n"),
        Escape,
    );
    push(
        seeds,
        t,
        "absolute-elsewhere",
        Damaged,
        pair(b"/etc\n"),
        Escape,
    );
    let padded = |n: usize| {
        let mut common = b"../..".to_vec();
        common.resize(n, b'/');
        pair(&common)
    };
    let mut huge = b"gitdir: /r/.git/worktrees/w\n\0".to_vec();
    huge.resize(huge.len() + 1_048_576, b'.');
    push(seeds, t, "one-mebibyte-line", Oversize, huge, Escape);
    push(
        seeds,
        t,
        "length-cap-minus-one",
        CapMinusOne,
        padded(65_535),
        Ok,
    );
    push(seeds, t, "length-at-cap", AtCap, padded(65_536), Ok);
    push(
        seeds,
        t,
        "length-cap-plus-one",
        CapPlusOne,
        padded(65_537),
        Escape,
    );
}
