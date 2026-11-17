//! Writing a laid-out line as runs: the in-place `Sink`, the single-run and
//! cleared-line helpers, and the `Lay` methods that walk the drawn items into
//! runs. Split from `layout` so that file keeps the measuring-and-fitting
//! decisions.
use super::{Item, Kind, LaidLine, Lay, Run, SepKind, Shape, Src};
use crate::color::sgr::{DIM, Style};
use alloc::string::String;
use alloc::vec::Vec;

/// Output runs written in place: an existing run's String is reused when
/// it has room and otherwise allocated at its exact size, so writing never
/// grows a String or a Vec.
pub(super) struct Sink<'a> {
    runs: &'a mut Vec<Run>,
    n: usize,
}

impl<'a> Sink<'a> {
    pub(super) fn new(runs: &'a mut Vec<Run>, count: usize) -> Self {
        if runs.capacity() < count {
            *runs = Vec::with_capacity(count);
        }
        runs.truncate(count);
        Self { runs, n: 0 }
    }

    pub(super) fn start(&mut self, style: Style, bytes: usize) -> &mut String {
        if self.n < self.runs.len() {
            let r = &mut self.runs[self.n];
            r.style = style;
            r.text.clear();
            if r.text.capacity() < bytes {
                r.text = String::with_capacity(bytes);
            }
        } else {
            self.runs.push(Run {
                text: String::with_capacity(bytes),
                style,
            });
        }
        self.n += 1;
        &mut self.runs[self.n - 1].text
    }

    pub(super) fn finish(self) {
        self.runs.truncate(self.n);
    }
}

pub(super) fn one_run(runs: &mut Vec<Run>, text: &str, style: Style) {
    let mut sink = Sink::new(runs, 1);
    sink.start(style, text.len()).push_str(text);
    sink.finish();
}

pub(super) fn clear_line(out: &mut LaidLine, minimal: bool) {
    out.left.clear();
    out.right.clear();
    out.minimal = minimal;
}

impl Lay<'_, '_> {
    /// Number of pieces item `it` is drawn in.
    fn parts(&self, it: &Item) -> usize {
        match it.src {
            Src::Seg(s, _) => self.slots[s].short.as_ref().map_or(1, |sh| sh.ends.len()),
            _ => 1,
        }
    }

    /// Piece `j` of item `items[i]`: style and text as (before, text, after).
    fn part(&self, items: &[Item], i: usize, j: usize, right_side: bool) -> (Style, [&str; 3]) {
        let it = &items[i];
        match it.src {
            Src::Seg(s, padded) => {
                let t = self.seg_text(s);
                let (start, end, sh) = match &self.slots[s].short {
                    Some(short) => {
                        let start = j.checked_sub(1).map_or(0, |p| short.ends[p].0);
                        (start, short.ends[j].0, short.ends[j].1)
                    }
                    None => (0, t.len(), false),
                };
                let last = j + 1 == self.parts(it);
                let style = if sh {
                    Style {
                        attrs: it.style.attrs | DIM,
                        ..it.style
                    }
                } else {
                    it.style
                };
                let pad = |on| if padded && on { " " } else { "" };
                (style, [pad(j == 0), &t[start..end], pad(last)])
            }
            _ => (item_style(items, i, right_side), ["", self.text(it), ""]),
        }
    }

    /// The first non-empty piece at or after piece `j` of item `i`.
    fn next_part(
        &self,
        items: &[Item],
        mut i: usize,
        mut j: usize,
        right_side: bool,
    ) -> Option<(usize, usize)> {
        while i < items.len() {
            if j >= self.parts(&items[i]) {
                (i, j) = (i + 1, 0);
                continue;
            }
            if self
                .part(items, i, j, right_side)
                .1
                .iter()
                .any(|x| !x.is_empty())
            {
                return Some((i, j));
            }
            j += 1;
        }
        None
    }

    /// Writes the runs of cleaned items to `out` (or only counts them when
    /// `out` is None): neighbors of one style merge, and each run's String
    /// is opened at its exact size. Returns the run count.
    pub(super) fn runs(
        &self,
        items: &[Item],
        right_side: bool,
        mut out: Option<&mut Sink<'_>>,
    ) -> usize {
        let mut n = 0;
        let mut at = self.next_part(items, 0, 0, right_side);
        while let Some((i, j)) = at {
            let style = self.part(items, i, j, right_side).0;
            // The run ends at the first piece of another style.
            let (mut len, mut end) = (0usize, Some((i, j)));
            while let Some((a, c)) = end {
                let (st, t) = self.part(items, a, c, right_side);
                if st != style {
                    break;
                }
                len += t.iter().map(|x| x.len()).sum::<usize>();
                end = self.next_part(items, a, c + 1, right_side);
            }
            if let Some(sink) = out.as_deref_mut() {
                let text = sink.start(style, len);
                let mut q = Some((i, j));
                while q != end {
                    let Some((a, c)) = q else { break };
                    for x in self.part(items, a, c, right_side).1 {
                        text.push_str(x);
                    }
                    q = self.next_part(items, a, c + 1, right_side);
                }
            }
            n += 1;
            at = end;
        }
        n
    }
}

/// Style of cleaned item `i`. Separators take the colors of the blocks
/// next to them (design brief interlock rule): a left side separator `▶`
/// has the block before as text color and the block after as background, a
/// right side `◀` the reverse; a head takes the block after, a tail the
/// block before, on the default background; `flat` is a space on the
/// neighboring block's background.
fn item_style(items: &[Item], i: usize, right_side: bool) -> Style {
    let it = items[i];
    let Kind::Sep(kind, shape) = it.kind else {
        return it.style;
    };
    let block_at = |j: Option<usize>| match j.and_then(|j| items.get(j)) {
        Some(Item {
            kind: Kind::Content,
            block: Some(b),
            ..
        }) => Some(*b),
        _ => None,
    };
    let (prev, next) = (block_at(i.checked_sub(1)), block_at(Some(i + 1)));
    let (fg, bg) = match kind {
        SepKind::Head => (next, None),
        SepKind::Tail => (prev, None),
        SepKind::Sep if right_side => (next, prev),
        SepKind::Sep => (prev, next),
    };
    let (fg, bg) = if shape == Shape::Flat {
        (None, next.or(prev))
    } else {
        (fg, bg)
    };
    Style {
        fg: fg.unwrap_or_default(),
        bg: bg.unwrap_or_default(),
        attrs: 0,
    }
}
