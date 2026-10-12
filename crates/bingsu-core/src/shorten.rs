//! Shorteners (spec section 3 "긴 이름 줄이기"). Requests and results are
//! plain data; built-in methods are pure functions here; core validates
//! every result, so "a line never overflows" does not depend on whoever
//! made the result (a plugin method in sub-project 3).
use crate::field::{Field, FieldValue, VALUE_MAX_CELLS};
use crate::sanitize::is_removed;
use crate::width::{WidthProfile, ellipsis, fit_prefix, fit_suffix, str_width};
use alloc::string::String;
use alloc::vec::Vec;
use unicode_segmentation::UnicodeSegmentation;

/// Most path steps kept (PATH_MAX 4096 allows about 2048).
pub const MAX_STEPS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    Root,
    Home,
}

/// Path facts from the `dir` segment (spec section 4 `PathFacts`). Fields
/// are private: `PathFacts::new` sanitizes every name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathFacts {
    anchor: Anchor,
    steps: Vec<String>,
    /// Index of the repository root folder in `steps`.
    repo_root: Option<usize>,
    /// Sibling names per step for `unique`; None when not collected or when
    /// the folder had more than 256 raw entries.
    siblings: Vec<Option<Vec<String>>>,
}

impl PathFacts {
    /// Folder names are untrusted bytes: sanitized and cut to
    /// VALUE_MAX_CELLS each; a name that sanitizing empties becomes U+FFFD
    /// (an empty step would draw `//`); at most MAX_STEPS steps are kept
    /// (the last ones). A `repo_root` past the last step is dropped.
    pub fn new(
        anchor: Anchor,
        steps: &[&[u8]],
        repo_root: Option<usize>,
        siblings: &[Option<&[&[u8]]>],
    ) -> Self {
        let name = |s: &[u8]| match Field::text(s, VALUE_MAX_CELLS, WidthProfile::DEFAULT).value {
            FieldValue::Text(t) if !t.as_str().is_empty() => String::from(t.as_str()),
            _ => String::from("\u{FFFD}"),
        };
        let skip = steps.len().saturating_sub(MAX_STEPS);
        let steps: Vec<String> = steps[skip..].iter().map(|s| name(s)).collect();
        let repo_root = repo_root.and_then(|r| r.checked_sub(skip));
        let repo_root = repo_root.filter(|&r| r < steps.len());
        let siblings = siblings
            .iter()
            .skip(skip)
            .map(|o| o.map(|v| v.iter().map(|s| name(s)).collect()))
            .collect();
        Self {
            anchor,
            steps,
            repo_root,
            siblings,
        }
    }

    pub fn display(&self) -> String {
        let mut s = String::from(match self.anchor {
            Anchor::Root => "",
            Anchor::Home => "~",
        });
        for st in &self.steps {
            s.push('/');
            s.push_str(st);
        }
        if s.is_empty() {
            s.push('/');
        }
        s
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Source<'a> {
    Path(&'a PathFacts),
    Text(&'a str),
}

impl Source<'_> {
    fn original(&self) -> String {
        match self {
            Source::Path(p) => p.display(),
            Source::Text(t) => String::from(*t),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    Start,
    End,
}

/// Built-in methods (config shape `"repo"` or `{ kind = "depth", value = 3 }`;
/// key names in M3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    None,
    Depth(u16),
    Abbrev(u16),
    Unique,
    Repo,
    Truncate { max: u16, keep: Keep },
}

#[derive(Clone, Copy, Debug)]
pub struct ShortenRequest<'a> {
    pub source: Source<'a>,
    pub budget: u32,
    pub profile: WidthProfile,
    pub method: Method,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    pub text: String,
    /// Drawn dim so the shortening shows.
    pub shortened: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ShortenResult {
    pub pieces: Vec<Piece>,
}

impl ShortenResult {
    pub fn text(&self) -> String {
        self.pieces.iter().map(|p| p.text.as_str()).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    TooWide,
    ForeignChar,
    Malformed,
}

const ELLIPSIS: &str = "\u{2026}";

fn piece(text: impl Into<String>, shortened: bool) -> Piece {
    Piece {
        text: text.into(),
        shortened,
    }
}

fn first_graphemes(s: &str, n: usize) -> &str {
    let end = s.grapheme_indices(true).nth(n).map_or(s.len(), |(i, _)| i);
    &s[..end]
}

fn path_pieces(p: &PathFacts, step: impl Fn(usize, &str) -> (String, bool)) -> Vec<Piece> {
    let mut out = Vec::new();
    match p.anchor {
        Anchor::Root if p.steps.is_empty() => out.push(piece("/", false)),
        Anchor::Root => {}
        Anchor::Home => out.push(piece("~", false)),
    }
    for (i, s) in p.steps.iter().enumerate() {
        out.push(piece("/", false));
        let (t, cut) = step(i, s);
        out.push(piece(t, cut));
    }
    out
}

/// Runs a built-in method. None when the method does not apply (a path
/// method on text, `repo` outside a repository).
pub fn run_builtin(req: &ShortenRequest<'_>) -> Option<ShortenResult> {
    let last = |p: &PathFacts| p.steps.len().saturating_sub(1);
    let pieces = match (req.method, req.source) {
        (Method::None, s) => alloc::vec![piece(s.original(), false)],
        (Method::Depth(n), Source::Path(p)) => {
            let n = usize::from(n.max(1));
            if p.steps.len() <= n {
                path_pieces(p, |_, s| (s.into(), false))
            } else {
                let mut v = alloc::vec![piece(ELLIPSIS, true)];
                for s in &p.steps[p.steps.len() - n..] {
                    v.push(piece("/", false));
                    v.push(piece(s.as_str(), false));
                }
                v
            }
        }
        (Method::Abbrev(n), Source::Path(p)) => path_pieces(p, |i, s| {
            let t = first_graphemes(s, usize::from(n.max(1)));
            if i == last(p) || t.len() == s.len() {
                (s.into(), false)
            } else {
                (t.into(), true)
            }
        }),
        (Method::Unique, Source::Path(p)) => path_pieces(p, |i, s| {
            if i == last(p) {
                return (s.into(), false);
            }
            let total = s.graphemes(true).count();
            let k = match p.siblings.get(i).and_then(Option::as_ref) {
                Some(sib) => (1..=total)
                    .find(|&k| {
                        let pre = first_graphemes(s, k);
                        !sib.iter().any(|o| o != s && o.starts_with(pre))
                    })
                    .unwrap_or(total),
                None => 1,
            };
            let t = first_graphemes(s, k);
            (t.into(), t.len() != s.len())
        }),
        (Method::Repo, Source::Path(p)) => {
            let r = p.repo_root?;
            let mut v = Vec::new();
            for (j, s) in p.steps[r..].iter().enumerate() {
                if j > 0 {
                    v.push(piece("/", false));
                }
                v.push(piece(s.as_str(), false));
            }
            v
        }
        (Method::Truncate { max, keep }, s) => {
            let o = s.original();
            let max = u32::from(max).min(req.budget);
            if str_width(&o, req.profile) <= max {
                alloc::vec![piece(o, false)]
            } else {
                let e = ellipsis(req.profile, max);
                let room = max - str_width(e, req.profile);
                match keep {
                    Keep::End => {
                        let (start, _) = fit_suffix(&o, room, req.profile);
                        alloc::vec![piece(e, true), piece(&o[start..], false)]
                    }
                    Keep::Start => {
                        let (end, _) = fit_prefix(&o, room, req.profile);
                        alloc::vec![piece(&o[..end], false), piece(e, true)]
                    }
                }
            }
        }
        (_, Source::Text(_)) => return None,
    };
    Some(ShortenResult { pieces })
}

/// Checks a result from any method: width within the budget, no character
/// that is not in the original value (the ellipsis `…` and `.` excepted),
/// no empty piece, no removed character. Returns the width.
pub fn validate(req: &ShortenRequest<'_>, r: &ShortenResult) -> Result<u32, Reject> {
    if r.pieces.is_empty()
        || r.pieces
            .iter()
            .any(|p| p.text.is_empty() || p.text.chars().any(is_removed))
    {
        return Err(Reject::Malformed);
    }
    let mut seen: Vec<char> = req.source.original().chars().collect();
    seen.sort_unstable();
    for p in &r.pieces {
        for c in p.text.chars() {
            if c != '\u{2026}' && c != '.' && seen.binary_search(&c).is_err() {
                return Err(Reject::ForeignChar);
            }
        }
    }
    let w: u32 = r
        .pieces
        .iter()
        .map(|p| str_width(&p.text, req.profile))
        .sum();
    if w > req.budget {
        Err(Reject::TooWide)
    } else {
        Ok(w)
    }
}

/// Tries `methods` in order and returns the first valid result that fits,
/// with its index; if none fits, the narrowest valid one (layout step 4
/// cuts further). `None` when no method gives a valid result.
pub fn shorten(
    source: Source<'_>,
    methods: &[Method],
    budget: u32,
    profile: WidthProfile,
) -> Option<(ShortenResult, usize, u32)> {
    let mut best: Option<(ShortenResult, usize, u32)> = None;
    for (i, m) in methods.iter().enumerate() {
        let req = ShortenRequest {
            source,
            budget: u32::MAX,
            profile,
            method: *m,
        };
        let Some(r) = run_builtin(&req) else { continue };
        let Ok(w) = validate(&req, &r) else { continue };
        if w <= budget {
            return Some((r, i, w));
        }
        if best.as_ref().is_none_or(|b| w < b.2) {
            best = Some((r, i, w));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    const D: WidthProfile = WidthProfile::DEFAULT;

    const STEPS: [&[u8]; 5] = [b"Works", b"AiScream", b"themes", b"src", b"render"];

    fn facts() -> PathFacts {
        // Spec example: `~/Works` holds `AiScream` and `Apps`.
        PathFacts::new(
            Anchor::Home,
            &STEPS,
            Some(2),
            &[
                Some(&[b"Works", b"Desktop"]),
                Some(&[b"AiScream", b"Apps"]),
                None,
                None,
                None,
            ],
        )
    }
    fn run(m: Method) -> String {
        let f = facts();
        run_builtin(&ShortenRequest {
            source: Source::Path(&f),
            budget: 80,
            profile: D,
            method: m,
        })
        .unwrap()
        .text()
    }

    // 이것을 실패시키는 것: 스펙 3절 표의 예(`~/Works/AiScream/themes/src/render`)와 다른 결과.
    #[test]
    fn spec_table_examples() {
        assert_eq!(run(Method::None), "~/Works/AiScream/themes/src/render");
        assert_eq!(run(Method::Depth(2)), "\u{2026}/src/render");
        assert_eq!(run(Method::Abbrev(1)), "~/W/A/t/s/render");
        assert_eq!(run(Method::Unique), "~/W/Ai/t/s/render");
        assert_eq!(run(Method::Repo), "themes/src/render");
    }

    // 이것을 실패시키는 것: 같은 앞부분을 가진 형제를 무시하는 unique.
    #[test]
    fn unique_uses_siblings() {
        let f = PathFacts::new(
            Anchor::Home,
            &STEPS,
            Some(2),
            &[
                Some(&[b"Works", b"Desktop"]),
                Some(&[b"AiScream", b"Apps"]),
                None,
                Some(&[b"src", b"scripts"]),
                None,
            ],
        );
        let r = run_builtin(&ShortenRequest {
            source: Source::Path(&f),
            budget: 80,
            profile: D,
            method: Method::Unique,
        })
        .unwrap();
        assert_eq!(r.text(), "~/W/Ai/t/sr/render");
    }

    // 이것을 실패시키는 것: 폴더 이름을 정제하지 않는 것, 범위 밖 repo_root를 남기는 것.
    #[test]
    fn facts_are_sanitized() {
        let f = PathFacts::new(
            Anchor::Root,
            &[b"a\x1b[31m", b"b\xff", b"\x1b\x7f"],
            Some(9),
            &[],
        );
        assert_eq!(f.display(), "/a[31m/b\u{FFFD}/\u{FFFD}");
        assert!(
            run_builtin(&ShortenRequest {
                source: Source::Path(&f),
                budget: 80,
                profile: D,
                method: Method::Repo
            })
            .is_none()
        );
    }

    // 이것을 실패시키는 것: 칸 상한 초과·원래 없는 글자·빈 조각을 받는 검증.
    #[test]
    fn validation_rejects_bad_results() {
        let f = facts();
        let req = ShortenRequest {
            source: Source::Path(&f),
            budget: 10,
            profile: D,
            method: Method::None,
        };
        let wide = ShortenResult {
            pieces: vec![piece("~/Works/AiScream", false)],
        };
        assert_eq!(validate(&req, &wide), Err(Reject::TooWide));
        let foreign = ShortenResult {
            pieces: vec![piece("~/X", false)],
        };
        assert_eq!(validate(&req, &foreign), Err(Reject::ForeignChar));
        let empty = ShortenResult {
            pieces: vec![piece("", false)],
        };
        assert_eq!(validate(&req, &empty), Err(Reject::Malformed));
        let ctl = ShortenResult {
            pieces: vec![piece("~\u{1b}", false)],
        };
        assert_eq!(validate(&req, &ctl), Err(Reject::Malformed));
        let ok = ShortenResult {
            pieces: vec![piece("\u{2026}/render", true)],
        };
        assert_eq!(validate(&req, &ok), Ok(8));
    }

    // 이것을 실패시키는 것: 앞 방식이 맞는데 다음 방식으로 가거나, 다 넘칠 때 가장 좁은 것을 고르지 않는 것.
    #[test]
    fn chain_order() {
        let f = facts();
        let m = [Method::Repo, Method::Abbrev(1), Method::Depth(1)];
        let (r, i, w) = shorten(Source::Path(&f), &m, 20, D).unwrap();
        assert_eq!((r.text().as_str(), i, w), ("themes/src/render", 0, 17));
        let (r, i, _) = shorten(Source::Path(&f), &m, 16, D).unwrap();
        assert_eq!((r.text().as_str(), i), ("~/W/A/t/s/render", 1));
        let (r, i, w) = shorten(Source::Path(&f), &m, 3, D).unwrap();
        assert_eq!((r.text().as_str(), i, w), ("\u{2026}/render", 2, 8));
    }

    // 이것을 실패시키는 것: truncate가 grapheme을 자르거나, ambiguous=2에서 생략 기호 폭을 무시하는 것.
    #[test]
    fn truncate_text() {
        let p2 = WidthProfile::new(2, 2).unwrap();
        let t = |s: &str, max, keep, p| {
            run_builtin(&ShortenRequest {
                source: Source::Text(s),
                budget: 80,
                profile: p,
                method: Method::Truncate { max, keep },
            })
            .unwrap()
            .text()
        };
        assert_eq!(
            t("feature/very-long-branch", 10, Keep::Start, D),
            "feature/v\u{2026}"
        );
        assert_eq!(
            t("feature/very-long-branch", 10, Keep::End, D),
            "\u{2026}ng-branch"
        );
        assert_eq!(
            t("feature/very-long-branch", 10, Keep::Start, p2),
            "feature/\u{2026}"
        );
        assert_eq!(t("한글브랜치", 5, Keep::Start, D), "한글\u{2026}");
        assert_eq!(t("short", 10, Keep::Start, D), "short");
        assert!(
            run_builtin(&ShortenRequest {
                source: Source::Text("x"),
                budget: 9,
                profile: D,
                method: Method::Repo
            })
            .is_none()
        );
    }

    // 이것을 실패시키는 것: 깊은 경로(1,000단계·긴 이름)에서 결과가 칸 상한을 넘는 것.
    #[test]
    fn deep_long_paths_stay_within_budget() {
        let names: Vec<String> = (0..1000)
            .map(|i| alloc::format!("d{i}"))
            .chain([String::from("x").repeat(4096)])
            .collect();
        let steps: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
        let f = PathFacts::new(Anchor::Root, &steps, None, &[]);
        let m = [
            Method::Abbrev(1),
            Method::Depth(1),
            Method::Truncate {
                max: 40,
                keep: Keep::End,
            },
        ];
        let (r, i, w) = shorten(Source::Path(&f), &m, 40, D).unwrap();
        assert_eq!(i, 2);
        assert!(w <= 40 && r.text().ends_with("xxxx"));
    }
}
