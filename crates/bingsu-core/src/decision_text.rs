//! The text of `bingsu explain`: a `DecisionLog` (what the layout decided
//! for one width) in words. The log is made by the same layout call the
//! prompt makes (`front::render_selected_recorded`); this module only
//! formats it, so it adds no decision of its own. I/O-free: names come in
//! as arguments.
use crate::color::palette::Mode;
use crate::config::compile::CompiledConfig;
use crate::envelope::Envelope;
use crate::recorder::{DecisionLog, HideReason, Step};
use crate::shell_word::Shell;
use crate::shorten::Method;
use crate::status::Status;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// The decisions the prompt makes for `compiled` and `parsed` (the width is
/// `parsed.width`), and the record it would write. The layout is made by the
/// prompt's own render. The prompt picks the band before the layout (the
/// front hands the layout only the chosen variant, so the layout itself
/// sees no bands), so the band is filled in here with the same
/// `bands::select` call that `LayoutView::lines_at` makes.
pub fn decide(compiled: &CompiledConfig, parsed: &Envelope, mode: Mode) -> (DecisionLog, Vec<u8>) {
    let mut log = DecisionLog::default();
    let mut record = Vec::new();
    crate::front::render_selected_recorded(
        parsed,
        Shell::Zsh,
        Status::OK_NONE,
        Some(compiled),
        mode,
        &[],
        &mut log,
        &mut record,
    );
    log.band = crate::bands::select(&compiled.band_order, &compiled.bands, parsed.width);
    (log, record)
}

/// Names for the indexes a log holds. `segments` is in catalog order (the
/// built-ins, then the user segments); `methods[i]` is the shorten method
/// list of segment `i`.
pub struct Names<'a> {
    pub segments: &'a [&'a str],
    pub bands: &'a [String],
    pub methods: &'a [&'a [Method]],
}

/// Words for the overflow steps of the layout (spec "한 줄 조립과 넘칠 때").
pub const fn step_text(s: Step) -> &'static str {
    match s {
        Step::ShortenNames => "shortened names",
        Step::HideRightByPriority => "hid right-side segments by priority",
        Step::HideRight => "hid the whole right side",
        Step::TruncateLeft => "truncated the left side",
        Step::HideLeftOptional => "hid optional left-side segments",
        Step::DropDecoration => "dropped decoration",
        Step::Minimal => "kept only the prompt character",
    }
}

/// The stable word of a hide reason.
pub const fn reason_word(r: HideReason) -> &'static str {
    match r {
        HideReason::NoValue => "no-value",
        HideReason::Priority => "priority",
        HideReason::RightHidden => "right-hidden",
        HideReason::LeftOptional => "left-optional",
        HideReason::Minimal => "minimal",
        HideReason::EmptyGroup => "empty-group",
    }
}

const fn reason_text(r: HideReason) -> &'static str {
    match r {
        HideReason::NoValue => "the segment sent no value",
        HideReason::Priority => "step 2: lower priority than what fits",
        HideReason::RightHidden => "step 3: the right side did not fit",
        HideReason::LeftOptional => "step 5: optional segment on the left",
        HideReason::Minimal => "step 7: only the prompt character is left",
        HideReason::EmptyGroup => "its group is empty (all its fields are empty)",
    }
}

fn method_text(m: Option<&Method>, out: &mut String) {
    match m {
        None => out.push_str("(unknown method)"),
        Some(Method::None) => out.push_str("none"),
        Some(Method::Depth(n)) => {
            let _ = write!(out, "depth {n}");
        }
        Some(Method::Abbrev(n)) => {
            let _ = write!(out, "abbrev {n}");
        }
        Some(Method::Unique) => out.push_str("unique"),
        Some(Method::Repo) => out.push_str("repo"),
        Some(Method::Truncate { max, .. }) => {
            let _ = write!(out, "truncate {max}");
        }
    }
}

fn name<'a>(names: &Names<'a>, i: usize) -> &'a str {
    names
        .segments
        .get(i)
        .copied()
        .unwrap_or("(unknown segment)")
}

/// The decisions at `width`, one block per line. `only` keeps the hide and
/// shorten records of one segment (its catalog index).
pub fn render(log: &DecisionLog, names: &Names<'_>, width: u16, only: Option<usize>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "width: {width} cells");
    match log.band {
        Some(b) => {
            let n = names.bands.get(b).map_or("(unnamed)", |x| x.as_str());
            let _ = writeln!(out, "layout: band `{n}`");
        }
        None => out.push_str("layout: the default layout (no band matches)\n"),
    }
    let last = log
        .steps
        .iter()
        .map(|x| x.0)
        .chain(log.hidden.iter().map(|x| x.0))
        .chain(log.shortened.iter().map(|x| x.0))
        .max();
    let Some(last) = last else {
        out.push_str("overflow: none; every segment with a value fits\n");
        return out;
    };
    for line in 0..=last {
        let _ = writeln!(out, "line {}:", line + 1);
        let mut any = false;
        for (_, s) in log.steps.iter().filter(|x| x.0 == line) {
            any = true;
            let _ = writeln!(out, "  overflow step {}: {}", *s as u8, step_text(*s));
        }
        for (_, seg, r) in log.hidden.iter().filter(|x| x.0 == line) {
            if only.is_some_and(|o| o != *seg) {
                continue;
            }
            any = true;
            let _ = writeln!(
                out,
                "  hidden: {} [{}] ({})",
                name(names, *seg),
                reason_word(*r),
                reason_text(*r)
            );
        }
        for (_, seg, m) in log.shortened.iter().filter(|x| x.0 == line) {
            if only.is_some_and(|o| o != *seg) {
                continue;
            }
            any = true;
            let _ = write!(out, "  shortened: {} with ", name(names, *seg));
            method_text(names.methods.get(*seg).and_then(|l| l.get(*m)), &mut out);
            out.push('\n');
        }
        if !any {
            out.push_str("  nothing hidden or shortened\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn names<'a>(segs: &'a [&'a str], bands: &'a [String], m: &'a [&'a [Method]]) -> Names<'a> {
        Names {
            segments: segs,
            bands,
            methods: m,
        }
    }

    // 이것을 실패시키는 것: 줄 번호를 0부터 세는 것, 구간 이름과 기본 레이아웃의 구분을 잃는 것,
    // 숨김 이유 낱말을 바꾸는 것, 한 세그먼트로 거르는 `only`를 무시하는 것.
    #[test]
    fn a_log_reads_as_words() {
        let log = DecisionLog {
            band: Some(0),
            steps: vec![(0, Step::HideRightByPriority)],
            hidden: vec![(0, 1, HideReason::Priority), (0, 0, HideReason::NoValue)],
            shortened: vec![(0, 0, 1)],
        };
        let bands = vec![String::from("narrow")];
        let m: [&[Method]; 2] = [&[Method::None, Method::Depth(2)], &[]];
        let n = names(&["dir", "git"], &bands, &m);
        let all = render(&log, &n, 40, None);
        assert_eq!(
            all,
            "width: 40 cells\nlayout: band `narrow`\nline 1:\n  overflow step 2: hid right-side segments by priority\n  hidden: git [priority] (step 2: lower priority than what fits)\n  hidden: dir [no-value] (the segment sent no value)\n  shortened: dir with depth 2\n"
        );
        let git = render(&log, &n, 40, Some(1));
        assert!(
            git.contains("hidden: git") && !git.contains("dir ["),
            "{git}"
        );
        assert!(!git.contains("shortened"), "{git}");
        let none = render(&DecisionLog::default(), &n, 120, None);
        assert_eq!(
            none,
            "width: 120 cells\nlayout: the default layout (no band matches)\noverflow: none; every segment with a value fits\n"
        );
    }

    // 이것을 실패시키는 것: 목록 밖 인덱스에서 패닉하는 것(알 수 없는 세그먼트·구간·방법).
    #[test]
    fn unknown_indexes_do_not_panic() {
        let log = DecisionLog {
            band: Some(9),
            steps: vec![],
            hidden: vec![(1, 7, HideReason::Minimal)],
            shortened: vec![(1, 7, 3)],
        };
        let n = names(&[], &[], &[]);
        let t = render(&log, &n, 0, None);
        assert!(
            t.contains("band `(unnamed)`") && t.contains("(unknown segment)"),
            "{t}"
        );
        assert!(
            t.contains("line 2:") && t.contains("(unknown method)"),
            "{t}"
        );
    }
}
