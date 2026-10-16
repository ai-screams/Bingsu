//! "Did you mean" for unknown keys and segment names (spec section 6 "진단
//! 구조"): a near spelling among the known names, or the bingsu name of
//! another tool's segment. Only a suggestion: unknown names stay errors and
//! are never accepted as aliases.

/// Another tool's segment name and the bingsu segment for the same thing.
/// Only names read in that tool's documentation (2026-10-15): starship
/// <https://starship.rs/config/> table names, powerlevel10k
/// `config/p10k-classic.zsh` prompt elements.
pub const OTHER_TOOLS: [(&str, &str, &str); 13] = [
    ("powerlevel10k", "background_jobs", "jobs"),
    ("powerlevel10k", "command_execution_time", "duration"),
    ("powerlevel10k", "context", "host"),
    ("powerlevel10k", "vcs", "git"),
    ("powerlevel10k", "virtualenv", "venv"),
    ("starship", "character", "char"),
    ("starship", "cmd_duration", "duration"),
    ("starship", "directory", "dir"),
    ("starship", "git_branch", "git"),
    ("starship", "git_status", "git"),
    ("starship", "hostname", "host"),
    ("starship", "python", "venv"),
    ("starship", "username", "host"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suggestion<'a> {
    /// A known name one or two edits away.
    Spelling(&'a str),
    /// The name another tool uses for this bingsu segment.
    OtherTool {
        tool: &'static str,
        ours: &'static str,
    },
}

/// Edit distance with adjacent swaps, stopping early past `max`.
fn distance(a: &[u8], b: &[u8], max: usize) -> Option<usize> {
    if a.len().abs_diff(b.len()) > max || a.len() > 64 || b.len() > 64 {
        return None;
    }
    let w = b.len() + 1;
    let mut d = [[0usize; 65]; 65];
    for (i, row) in d.iter_mut().enumerate().take(a.len() + 1) {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate().take(w) {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..w {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    let r = d[a.len()][b.len()];
    (r <= max).then_some(r)
}

/// The closest of `known` to `word` (at most two edits, at most one for
/// words of four bytes or less; the first wins a tie), else another tool's
/// name when `segments` is set.
pub fn suggest<'a>(word: &str, known: &[&'a str], segments: bool) -> Option<Suggestion<'a>> {
    let max = if word.len() <= 4 { 1 } else { 2 };
    let near = known
        .iter()
        .filter_map(|k| distance(word.as_bytes(), k.as_bytes(), max).map(|d| (d, *k)))
        .min_by_key(|(d, _)| *d);
    if let Some((_, k)) = near {
        return Some(Suggestion::Spelling(k));
    }
    if segments {
        if let Some(&(tool, _, ours)) = OTHER_TOOLS.iter().find(|(_, name, _)| *name == word) {
            return Some(Suggestion::OtherTool { tool, ours });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: [&str; 5] = ["colors", "layout", "style", "width", "theme"];

    // 이것을 실패시키는 것: 오타 한두 글자(빠짐·더함·바뀜·자리 바꿈)를 못 찾거나, 먼 이름을 권하는 것.
    #[test]
    fn near_spellings() {
        assert_eq!(
            suggest("colrs", &KEYS, false),
            Some(Suggestion::Spelling("colors"))
        );
        assert_eq!(
            suggest("lyaout", &KEYS, false),
            Some(Suggestion::Spelling("layout"))
        );
        assert_eq!(
            suggest("styles", &KEYS, false),
            Some(Suggestion::Spelling("style"))
        );
        assert_eq!(suggest("palette", &KEYS, false), None);
        // a swap is one edit, so a short word still finds it.
        assert_eq!(
            suggest("tmie", &["time"], false),
            Some(Suggestion::Spelling("time"))
        );
        // short words: one edit only ("wdh" is two from "width").
        assert_eq!(suggest("wdh", &KEYS, false), None);
    }

    // 이것을 실패시키는 것: 다른 도구 이름 표를 세그먼트가 아닌 키에도 쓰거나, 표의 bingsu 이름이 내장 세그먼트가 아닌 것.
    #[test]
    fn other_tool_names_point_to_builtin_segments() {
        assert_eq!(
            suggest("directory", &["dir", "git"], true),
            Some(Suggestion::OtherTool {
                tool: "starship",
                ours: "dir"
            })
        );
        assert_eq!(suggest("directory", &KEYS, false), None);
        for (_, _, ours) in OTHER_TOOLS {
            assert!(crate::field::segment(ours).is_some(), "{ours}");
        }
    }

    // 이것을 실패시키는 것: 가장 가까운 이름·동점의 첫 이름·철자 우선순위·64바이트 상한을 바꾸는 것.
    #[test]
    fn closest_first_tie_and_bounded_names() {
        assert_eq!(
            suggest("colrs", &["colours", "colors"], false),
            Some(Suggestion::Spelling("colors"))
        );
        assert_eq!(
            suggest("cat", &["bat", "hat"], false),
            Some(Suggestion::Spelling("bat"))
        );
        assert_eq!(
            suggest("directory", &["directory"], true),
            Some(Suggestion::Spelling("directory"))
        );
        assert_eq!(
            suggest("colxxs", &["colors"], false),
            Some(Suggestion::Spelling("colors"))
        );
        let limit = "a".repeat(64);
        let over = "a".repeat(65);
        assert_eq!(
            suggest(&limit, &[&limit], false),
            Some(Suggestion::Spelling(&limit))
        );
        assert_eq!(suggest(&over, &[&over], false), None);
        assert_eq!(suggest(&limit, &[&over], false), None);
        assert_eq!(suggest("any", &[], true), None);
        for (tool, name, ours) in OTHER_TOOLS {
            assert_eq!(
                suggest(name, &[], true),
                Some(Suggestion::OtherTool { tool, ours })
            );
        }
    }
}
