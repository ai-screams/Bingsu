//! Width measuring for line layout: the cells of runs and texts as a terminal
//! reads the joined text, and the join arithmetic at the borders between
//! items (`may_join`, `join_delta`). Free functions over text and a width
//! profile; no layout state.
use super::Run;
use crate::width::{WidthProfile, str_width};
use alloc::string::String;
use unicode_segmentation::UnicodeSegmentation;

/// Cells of `runs` printed one after another, measured on the joined text
/// as a terminal reads it.
pub fn runs_width(runs: &[Run], p: WidthProfile) -> u32 {
    match runs {
        [] => 0,
        [r] => str_width(&r.text, p),
        _ => {
            let joined: String = runs.iter().map(|r| r.text.as_str()).collect();
            str_width(&joined, p)
        }
    }
}

/// Byte length of the first grapheme of `s`.
pub(super) fn head_len(s: &str) -> usize {
    s.graphemes(true).next().map_or(0, |s| s.len())
}

/// Byte offset where the last grapheme of `s` starts.
pub(super) fn tail_at(s: &str) -> usize {
    s.grapheme_indices(true).next_back().map_or(0, |(i, _)| i)
}

/// `buf` cleared and at least `n` bytes long, allocated anew (never grown)
/// when it is shorter.
pub(super) fn scratch(buf: &mut String, n: usize) {
    buf.clear();
    if buf.capacity() < n {
        *buf = String::with_capacity(n);
    }
}

/// Do `x` then `y` make one grapheme on their own?
pub(super) fn pair_joins(x: char, y: char) -> bool {
    let mut buf = [0u8; 8];
    let n = x.encode_utf8(&mut buf).len();
    let m = y.encode_utf8(&mut buf[n..]).len();
    core::str::from_utf8(&buf[..n + m]).is_ok_and(|s| s.graphemes(true).nth(1).is_none())
}

/// Can a grapheme ending in `a` join one starting with `b`? When false,
/// any `t` ending in `a` and `h` starting with `b` measure w(t) + w(h).
/// Below U+0300 no code point joins anything (CR and LF never reach a
/// line). Otherwise the pair decides, except for two rules that look
/// further back, an emoji ZWJ sequence (GB11) and an Indic conjunct (GB9c):
/// both need an `a` that extends any base (a ZWJ, a linker, another mark),
/// as `A` then `a` tells. A "may" that does not join only costs a
/// measurement. A search over every code point on either side of the
/// border found no width change where this says no (report E3, round 1).
pub(super) fn may_join(a: char, b: char) -> bool {
    if u32::from(a) < 0x300 && u32::from(b) < 0x300 {
        return false;
    }
    if pair_joins(a, b) {
        return true;
    }
    pair_joins('A', a)
}

/// Cells gained (or lost) where `t`, the last grapheme drawn, meets `h`, the
/// first one after it: w(t + h) − w(t) − w(h); zero when they stay two
/// graphemes.
pub(super) fn join_delta(t: &str, h: &str, buf: &mut String, p: WidthProfile) -> i64 {
    let (Some(a), Some(b)) = (t.chars().next_back(), h.chars().next()) else {
        return 0;
    };
    if !may_join(a, b) {
        return 0;
    }
    measure_join(t, h, buf, p)
}

pub(super) fn measure_join(t: &str, h: &str, buf: &mut String, p: WidthProfile) -> i64 {
    scratch(buf, t.len() + h.len());
    buf.push_str(t);
    buf.push_str(h);
    let (wj, wt, wh) = (str_width(buf, p), str_width(t, p), str_width(h, p));
    i64::from(wj) - i64::from(wt) - i64::from(wh)
}

/// `may_join` for the few code point pairs a line repeats at its borders
/// (a separator glyph and a padding space), remembered per line.
pub(super) struct PairMemo(pub(super) [(char, char, bool); 32]);

impl PairMemo {
    pub(super) fn may_join(&mut self, a: char, b: char) -> bool {
        // Multiplicative hashing: a pair and its reverse (space then glyph,
        // glyph then space) land in different slots.
        let h = (u32::from(a).wrapping_mul(0x9E37_79B9) ^ u32::from(b)).wrapping_mul(0x85EB_CA6B);
        let slot = &mut self.0[(h >> 27) as usize];
        if slot.0 != a || slot.1 != b {
            *slot = (a, b, may_join(a, b));
        }
        slot.2
    }
}

/// Adds a signed join delta to a width (never below 0).
pub(super) fn add(w: u32, d: i64) -> u32 {
    u32::try_from((i64::from(w) + d).max(0)).unwrap_or(u32::MAX)
}

/// A segment's text measured alone and padded for a block.
#[derive(Clone, Copy, Default)]
pub(super) struct TextM {
    pub(super) width: u32,
    /// Width of `" " + text + " "`.
    pub(super) padded: u32,
    /// First grapheme's length and last grapheme's start.
    pub(super) head: usize,
    pub(super) tail: usize,
}

pub(super) fn text_m(t: &str, buf: &mut String, p: WidthProfile) -> TextM {
    let width = str_width(t, p);
    let (head, tail) = (head_len(t), tail_at(t));
    let dh = join_delta(" ", &t[..head], buf, p);
    let dt = join_delta(&t[tail..], " ", buf, p);
    TextM {
        width,
        padded: add(width.saturating_add(2), dh + dt),
        head,
        tail,
    }
}
