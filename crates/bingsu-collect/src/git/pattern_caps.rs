//! Line costs and heap estimates for ignore and attribute pattern files:
//! what one pattern line may cost to match, checked against the caps in
//! policy.rs, and the bytes a file's parsed attribute parts and names keep.
//! No I/O happens here; `Patterns::add_buffer` charges what these compute.
use super::{AttributePart, CLASS_BYTES, GLOBSTAR_RUNS, PatternKind, STAR_RUNS};
use crate::{meter::Meter, safe_read::ReadError};

/// Whether gix skips `line` as a comment: `#` as the first byte of an ignore
/// line, or the first after blanks (space, tab, CR) of an attribute line.
/// `\#` is a pattern in both. A comment right after a byte-order mark on the
/// first line still counts, which only over-counts.
/// 이것을 실패시키는 것: 두 종류에 같은 규칙을 쓰는 것(앞 공백 `#` seed의
/// 종류별 판정이 바뀐다).
pub(super) fn is_comment(line: &[u8], kind: PatternKind) -> bool {
    let first = match kind {
        PatternKind::Ignore => line.first(),
        PatternKind::Attributes => line.iter().find(|b| !b" \t\r".contains(b)),
    };
    first == Some(&b'#')
}

/// Whether gix-attributes unquotes this line's pattern: after blanks (space,
/// tab, CR) it starts with `"`. On the first line a byte-order mark comes
/// off first, so there any `"` counts.
pub(super) fn quoted(line: &[u8], index: usize) -> bool {
    if index == 0 {
        return line.contains(&b'"');
    }
    line.iter().find(|b| !b" \t\r".contains(b)) == Some(&b'"')
}

/// Whether one line or pattern passes any shape cap.
pub(super) fn over_caps(text: &[u8]) -> bool {
    let (runs, globstars) = star_runs(text);
    runs > STAR_RUNS || globstars > GLOBSTAR_RUNS || class_bytes(text) > CLASS_BYTES
}

/// (`*` runs, runs of two or more) in one line.
pub(super) fn star_runs(line: &[u8]) -> (usize, usize) {
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
pub(super) const PART_WEIGHT: usize = 64;

/// The match weight of one pattern line: (`*` runs + 1) << `**` runs, times
/// (1 + class bytes / 4). At the caps it is at most 72 * 7 = 504.
pub(super) fn weight(line: &[u8]) -> usize {
    let (runs, globstars) = star_runs(line);
    ((runs + 1) << globstars) * (1 + class_bytes(line) / 4)
}

/// Bytes of a line inside bracket classes, brackets included, following
/// gix-glob's class grammar: `\` escapes one byte, a leading `!` or `^` and
/// then a leading `]` are members, and `[:name:]` runs to its `:]`. An
/// unclosed class counts to the line's end, so doubt counts more.
pub(super) fn class_bytes(line: &[u8]) -> usize {
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
pub(super) fn attribute_parts<'a>(
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

type AttributeList =
    gix_attributes::glob::search::pattern::List<gix_attributes::search::Attributes>;
type AttributeMapping =
    gix_attributes::glob::search::pattern::Mapping<gix_attributes::search::Value>;

/// Heap bytes the parts of one attribute file keep, plus the largest
/// transient while one is built, following the releases in
/// GIX_MATCH_VERSIONS. Each part costs:
/// - its own Search, whose Vec<List> takes the minimum capacity of 4 on its
///   one push;
/// - the List's copy of the source path and its base, the source's parent
///   plus `/`, which `push_byte` regrows to twice the parent (at least 8);
///   the parent is shorter than the source, so 3 * source bounds both;
/// - one Mapping per pattern line, collected from an iterator without a size
///   hint: capacity 4, then doubling, so max(4, k.next_power_of_two()) slots;
/// - three AttributePart slots, which bound the shared Vec's doubling growth
///   with the old and new buffers live together.
///
/// The transient is the old Mapping and base buffers while the largest part
/// grows. Pattern text and each Mapping's assignments are left to
/// parser_reservation's byte and word terms; the attribute names that
/// MetadataCollection keeps across files are name_table_bytes.
pub(super) fn attribute_part_bytes(bytes: &[u8], parsed: &[u16], source: usize) -> Option<usize> {
    // 이것을 실패시키는 것: Search의 4칸을 빼는 것(파일을 되풀이하는 요청 형태).
    // The AttributePart slots fail no test alone (120 B a part).
    const FIXED: usize = 4 * size_of::<AttributeList>() + 3 * size_of::<AttributePart>() + 8;
    let mapping = size_of::<AttributeMapping>();
    let (mut total, mut transient, mut start) = (source, 0usize, 0usize);
    for (end, _, _) in attribute_parts(bytes, parsed) {
        // A pattern line is one gix may turn into a Mapping: not blank and
        // not a comment. Negative patterns and lines gix drops count too.
        let lines = bytes[start..end]
            .split(|b| *b == b'\n')
            .filter(|l| !l.trim_ascii().is_empty() && !is_comment(l, PatternKind::Attributes))
            .count();
        // 이것을 실패시키는 것: 패턴 줄이 없는 part에도 최소 4칸을 매기는 것
        // (주석 8,192줄 형태가 Limit이 된다), 또는 주석 줄도 패턴 줄로 세는 것.
        // No test fails without the 4-slot floor alone: for a one-line part
        // the word term's 512 B and the other part terms cover the 672 B.
        let slots = if lines == 0 {
            0
        } else {
            lines.next_power_of_two().max(4)
        };
        // 이것을 실패시키는 것: 3 * source를 source로 줄이는 것(깊은 폴더의
        // .gitattributes 형태의 peak가 계상을 넘는다).
        total = total.checked_add(
            slots
                .checked_mul(mapping)?
                .checked_add(source.checked_mul(3)?)?
                .checked_add(FIXED)?,
        )?;
        // No test fails without this either: the word term's margin covers it.
        if slots > 4 {
            transient = transient.max(slots / 2 * mapping);
        }
        start = end;
    }
    total.checked_add(transient)
}

/// Heap bytes of the MetadataCollection that all attribute files of one
/// request share, once it holds up to `names` names, following std's
/// hashbrown 0.17: a key is an Rc<str> (two counts, then the bytes, padded to
/// 8), and the HashMap<Name, Metadata> has 4, 8, 16... buckets, filled to
/// buckets - 1 below 16 and to 7/8 from there. One table is the entries
/// rounded up to 16, then a control byte per bucket and one 16-byte group.
/// When it grows the old table is still live, so the half-size table counts
/// too. gix-attributes uses std::collections::HashMap, so this hashbrown comes
/// with rustc, not Cargo.lock: GIX_MATCH_VERSIONS cannot notice it change, and
/// on a rustc update the name shapes of the allocator corpus are the only guard.
pub(super) fn name_table_bytes(names: usize, name_bytes: usize) -> Option<usize> {
    if names == 0 {
        return Some(0);
    }
    let entry = size_of::<(gix_attributes::Name, gix_attributes::search::Metadata)>();
    let mut buckets = 4usize;
    // 이것을 실패시키는 것: 이 함수의 몫을 통째로 빼거나 entry 크기를 0으로 두는 것
    // (이름 2,047개 줄 하나의 peak가 계상을 넘는다). The terms below are real
    // costs, but none fails a test alone (7/8 fill, old table, keys, and the
    // held and distinct counts that feed `names`): parser_reservation's 512 B
    // per word overlaps them. At the costliest moment, a rehash, the tables
    // take about 634 B a name; with the old table removed a fourth such file
    // is admitted and its rehash peaks at 5.3 MB, still under the 8 MB held.
    while names
        > if buckets < 16 {
            buckets - 1
        } else {
            buckets / 8 * 7
        }
    {
        buckets = buckets.checked_mul(2)?;
    }
    let table = |b: usize| Some(b.checked_mul(entry)?.checked_add(15)? / 16 * 16 + b + 16);
    let old = if buckets > 4 { table(buckets / 2)? } else { 0 };
    table(buckets)?
        .checked_add(old)?
        .checked_add(names.checked_mul(23)?)?
        .checked_add(name_bytes)
}

/// Distinct attribute names of one file and their bytes, split as gix does:
/// words at blanks (space, tab, CR), the pattern first, then a name after one
/// `-` or `!` and before `=`. A quoted pattern with blanks only adds names.
/// One case counts one name too few: gix ends a quoted pattern at its closing
/// quote, so a name glued to it (`"x"f0n0`) is a name there and part of the
/// skipped pattern here. That loses at most one name a line, and the line's
/// glued word still pays parser_reservation's 512 B, more than the name costs
/// (its 23 + len B key and its share of the table); the thinnest measured
/// margin, one file of glued lines, was 52,178 B.
/// `words` bounds their count: add_buffer counted words at ASCII whitespace,
/// which splits at least where blanks do, and gix already rejected names
/// with other whitespace. The sort scratch is charged to `scratch`.
pub(super) fn attribute_names(
    bytes: &[u8],
    words: usize,
    scratch: &mut crate::meter::PathAllocation,
    meter: &mut Meter,
) -> Result<(usize, usize), ReadError> {
    let blank = |b: &u8| b" \t\r".contains(b);
    let found = || {
        bytes
            .split(|b| *b == b'\n')
            .filter(|line| !is_comment(line, PatternKind::Attributes))
            .flat_map(move |line| line.split(blank).filter(|w| !w.is_empty()).skip(1))
            .map(|word| {
                let word = word
                    .strip_prefix(b"-")
                    .or_else(|| word.strip_prefix(b"!"))
                    .unwrap_or(word);
                word.split(|b| *b == b'=').next().unwrap_or(word)
            })
    };
    // Ordinary files repeat a few names: a short list on the stack finds
    // them without the sort, which cost 17% of an ordinary file's parse.
    // 이것을 실패시키는 것: 목록이 찼을 때 정렬로 넘어가지 않고 그대로 세는 것(이름
    // 2,047개 줄의 계상이 peak 아래로 내려간다).
    let mut few: [&[u8]; 16] = [&[]; 16];
    let mut held = 0;
    let fits = found().all(|name| {
        if few[..held].contains(&name) {
            return true;
        }
        let Some(slot) = few.get_mut(held) else {
            return false;
        };
        *slot = name;
        held += 1;
        true
    });
    if fits {
        return Ok((held, few[..held].iter().map(|n| n.len()).sum()));
    }
    scratch.reserve(words.saturating_mul(size_of::<&[u8]>()), meter)?;
    let mut names: Vec<&[u8]> = Vec::with_capacity(words);
    names.extend(found());
    names.sort_unstable();
    names.dedup();
    Ok((names.len(), names.iter().map(|n| n.len()).sum()))
}
