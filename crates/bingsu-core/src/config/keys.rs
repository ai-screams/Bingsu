//! The key table (spec section 2): every config key, its type, whether it
//! is an execution key, whether a theme may set it, its level
//! (`x-bingsu-level`), its default and its description. The checker (S3b),
//! the JSON Schema (S5) and the execution-key rule all read this one table.
//!
//! Execution keys (spec section 2 "민감 키 원칙"): a key that turns execution
//! on, chooses what runs, sets its arguments or environment, or raises its
//! resource use. Only keys proven to change how the prompt looks are
//! `Shape`; every path not in this table classifies as `Exec` ("새 키는
//! 민감한 것으로 시작").
//!
//! Paths are dotted; `*` stands for one key chosen by the user (a segment
//! id, a band name, a color or token name). A segment key lists the kinds
//! it applies to; built-in segments have their own rows.
use crate::config::merge::{KeyClass, Slot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Basic,
    Advanced,
    Expert,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Ty {
    Bool,
    Int {
        min: i64,
        max: i64,
    },
    Float {
        min: f64,
        max: f64,
    },
    Str,
    /// A string drawn in the prompt: no control, bidi or invisible
    /// characters (`sanitize::is_removed`; ZWJ and variation selectors stay).
    Text,
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// A duration string: digits and `ms` or `s` (`"200ms"`, `"2s"`).
    Duration,
    /// A color: `oklch(...)`, `#rrggbb`, a 256-color number as a string, or
    /// a `term.ansi.N` name (`color::notation::parse_color`).
    Color,
    /// An array of strings.
    Strings,
    /// An array of segment ids (layout).
    Segments,
    /// An array of strings from a closed list.
    EnumList(&'static [&'static str]),
    /// A table whose keys are described by more rows.
    Table,
}

/// Segment kinds (spec section 2 "`kind`"): a closed list.
pub const KINDS: [&str; 4] = ["command", "text", "env", "language"];

#[derive(Clone, Copy, Debug)]
pub struct KeyDef {
    pub path: &'static str,
    pub ty: Ty,
    pub class: KeyClass,
    /// A theme may set it (theme schema, spec section 2 "테마 스키마").
    pub theme: bool,
    pub level: Level,
    /// The default as TOML text, when there is one.
    pub default: Option<&'static str>,
    /// An example value as TOML text (the default stands in when there is
    /// one and no example).
    pub example: Option<&'static str>,
    /// A key of a later milestone: accepted with a notice, no effect yet
    /// (the milestone name).
    pub planned: Option<&'static str>,
    /// For `segment.*.<key>`: the kinds it applies to (empty: all).
    pub kinds: &'static [&'static str],
    pub en: &'static str,
    pub ko: &'static str,
}

const fn key(
    path: &'static str,
    ty: Ty,
    level: Level,
    en: &'static str,
    ko: &'static str,
) -> KeyDef {
    KeyDef {
        path,
        ty,
        class: KeyClass::Shape,
        theme: true,
        level,
        default: None,
        example: None,
        planned: None,
        kinds: &[],
        en,
        ko,
    }
}

impl KeyDef {
    const fn exec(mut self) -> Self {
        self.class = KeyClass::Exec;
        self.theme = false;
        self
    }
    const fn not_in_theme(mut self) -> Self {
        self.theme = false;
        self
    }
    const fn default(mut self, toml: &'static str) -> Self {
        self.default = Some(toml);
        self
    }
    const fn kinds(mut self, k: &'static [&'static str]) -> Self {
        self.kinds = k;
        self
    }
    const fn example(mut self, toml: &'static str) -> Self {
        self.example = Some(toml);
        self
    }
    const fn planned(mut self, milestone: &'static str) -> Self {
        self.planned = Some(milestone);
        self
    }
}

use Level::{Advanced, Basic, Expert};

const PRESETS: &[&str] = &["lean", "triangle"];
const SHAPES: &[&str] = &["triangle", "round", "slant", "flat"];
const SHORTEN: &[&str] = &["none", "repo", "abbrev", "depth", "unique"];
const CMD: &[&str] = &["command"];
const CMD_LANG: &[&str] = &["command", "language"];

/// Every key, sorted by path.
pub const KEYS: &[KeyDef] = &[
    key("colors", Ty::Table, Basic, "Colors.", "색."),
    key(
        "colors.flavor",
        Ty::Enum(&["a"]),
        Basic,
        "Color flavor.",
        "색 flavor.",
    )
    .default("\"a\""),
    key(
        "colors.knobs",
        Ty::Table,
        Advanced,
        "Adjust the flavor.",
        "flavor 조절.",
    ),
    key(
        "colors.knobs.accent_c",
        Ty::Float {
            min: 0.0,
            max: 0.37,
        },
        Advanced,
        "Accent chroma.",
        "강조색 채도.",
    )
    .example("0.12"),
    key(
        "colors.knobs.accent_l",
        Ty::Float { min: 0.0, max: 1.0 },
        Advanced,
        "Accent lightness.",
        "강조색 밝기.",
    )
    .example("0.76"),
    key(
        "colors.knobs.hue",
        Ty::Float {
            min: 0.0,
            max: 360.0,
        },
        Advanced,
        "Accent hue in degrees.",
        "강조색 색상(도).",
    )
    .example("280"),
    key(
        "colors.mode",
        Ty::Enum(&["auto", "dark", "light"]),
        Basic,
        "Dark or light background.",
        "어두운 배경 또는 밝은 배경.",
    )
    .default("\"auto\""),
    key(
        "colors.override",
        Ty::Table,
        Expert,
        "Replace a palette color or token.",
        "팔레트 색이나 token을 바꿈.",
    ),
    key(
        "colors.override.*",
        Ty::Color,
        Expert,
        "The new color.",
        "새 색.",
    )
    .example("\"oklch(0.78 0.12 60)\""),
    key(
        "colors.roles",
        Ty::Table,
        Expert,
        "Point a token at a palette color.",
        "token이 가리킬 팔레트 색.",
    ),
    key(
        "colors.roles.*",
        Ty::Str,
        Expert,
        "A palette color name.",
        "팔레트 색 이름.",
    )
    .example("\"accent.blue\""),
    key(
        "icons",
        Ty::Enum(&["nerd", "light", "unicode", "ascii"]),
        Basic,
        "Icon set; falls back when a glyph does not fit.",
        "아이콘 집합. 글자가 맞지 않으면 다음 집합으로.",
    )
    .default("\"unicode\""),
    key("layout", Ty::Table, Basic, "Prompt lines.", "프롬프트 줄."),
    key(
        "layout.fill",
        Ty::Enum(&["space", "dot", "line"]),
        Advanced,
        "What fills the gap between left and right.",
        "왼쪽과 오른쪽 사이를 채우는 것.",
    )
    .default("\"space\""),
    key(
        "layout.frame",
        Ty::Enum(&["none", "line"]),
        Advanced,
        "Frame a two-line prompt with corner marks.",
        "두 줄 프롬프트를 모서리 표시로 묶음.",
    )
    .default("\"none\""),
    key(
        "layout.line1",
        Ty::Table,
        Basic,
        "The first line.",
        "첫 줄.",
    ),
    key(
        "layout.line1.enabled",
        Ty::Bool,
        Advanced,
        "Draw this line.",
        "이 줄을 그림.",
    )
    .default("true"),
    key(
        "layout.line1.left",
        Ty::Segments,
        Basic,
        "Segments on the left.",
        "왼쪽 세그먼트.",
    )
    .example("[\"dir\", \"git\"]"),
    key(
        "layout.line1.right",
        Ty::Segments,
        Basic,
        "Segments on the right.",
        "오른쪽 세그먼트.",
    )
    .example("[\"status\", \"duration\"]"),
    key(
        "layout.line2",
        Ty::Table,
        Basic,
        "The second line.",
        "둘째 줄.",
    ),
    key(
        "layout.line2.enabled",
        Ty::Bool,
        Advanced,
        "Draw this line.",
        "이 줄을 그림.",
    )
    .default("true"),
    key(
        "layout.line2.left",
        Ty::Segments,
        Basic,
        "Segments on the left.",
        "왼쪽 세그먼트.",
    )
    .example("[\"char\"]"),
    key(
        "layout.line2.right",
        Ty::Segments,
        Basic,
        "Segments on the right.",
        "오른쪽 세그먼트.",
    )
    .example("[]"),
    key(
        "layout.transient",
        Ty::Enum(&["none", "char"]),
        Advanced,
        "Shorten the prompts above the current one (M4 and M5).",
        "지나간 프롬프트를 짧게 그림(M4·M5).",
    )
    .example("\"char\"")
    .planned("M4"),
    key(
        "layout.use_last_column",
        Ty::Bool,
        Expert,
        "Draw in the last column.",
        "마지막 칸까지 그림.",
    )
    .default("false"),
    key(
        "layout.when",
        Ty::Table,
        Advanced,
        "Layouts for width bands.",
        "폭 구간별 레이아웃.",
    ),
    key(
        "layout.when.*",
        Ty::Table,
        Advanced,
        "One band.",
        "구간 하나.",
    ),
    key(
        "layout.when.*.line1",
        Ty::Table,
        Advanced,
        "The first line in this band.",
        "이 구간의 첫 줄.",
    ),
    key(
        "layout.when.*.line1.enabled",
        Ty::Bool,
        Advanced,
        "Draw this line.",
        "이 줄을 그림.",
    )
    .example("false"),
    key(
        "layout.when.*.line1.left",
        Ty::Segments,
        Advanced,
        "Segments on the left.",
        "왼쪽 세그먼트.",
    )
    .example("[\"dir\"]"),
    key(
        "layout.when.*.line1.right",
        Ty::Segments,
        Advanced,
        "Segments on the right.",
        "오른쪽 세그먼트.",
    )
    .example("[]"),
    key(
        "layout.when.*.line2",
        Ty::Table,
        Advanced,
        "The second line in this band.",
        "이 구간의 둘째 줄.",
    ),
    key(
        "layout.when.*.line2.enabled",
        Ty::Bool,
        Advanced,
        "Draw this line.",
        "이 줄을 그림.",
    )
    .example("true"),
    key(
        "layout.when.*.line2.left",
        Ty::Segments,
        Advanced,
        "Segments on the left.",
        "왼쪽 세그먼트.",
    )
    .example("[\"duration\", \"char\"]"),
    key(
        "layout.when.*.line2.right",
        Ty::Segments,
        Advanced,
        "Segments on the right.",
        "오른쪽 세그먼트.",
    )
    .example("[]"),
    key(
        "layout.when.*.max_cols",
        Ty::Int { min: 1, max: 65535 },
        Advanced,
        "Widest width of the band, inclusive.",
        "구간의 가장 넓은 폭(포함).",
    )
    .example("59"),
    key(
        "layout.when.*.min_cols",
        Ty::Int { min: 1, max: 65535 },
        Advanced,
        "Narrowest width of the band, inclusive.",
        "구간의 가장 좁은 폭(포함).",
    )
    .example("120"),
    key(
        "layout.when.*.order",
        Ty::Int {
            min: -1000,
            max: 1000,
        },
        Expert,
        "Which overlapping band wins.",
        "겹치는 구간 중 무엇이 이기나.",
    )
    .example("1"),
    key(
        "layout.when.*.style",
        Ty::Table,
        Advanced,
        "Style in this band.",
        "이 구간의 스타일.",
    ),
    key(
        "layout.when.*.style.preset",
        Ty::Enum(PRESETS),
        Advanced,
        "Style preset in this band.",
        "이 구간의 스타일 프리셋.",
    )
    .example("\"lean\""),
    key(
        "layout.when.*.style.template",
        Ty::Text,
        Expert,
        "Template text in this band; replaces preset and options.",
        "이 구간의 템플릿. 프리셋과 옵션을 대신함.",
    )
    .example("\"{dir} {char}\""),
    key(
        "segment",
        Ty::Table,
        Basic,
        "Segment settings.",
        "세그먼트 설정.",
    ),
    key(
        "segment.*",
        Ty::Table,
        Basic,
        "One segment.",
        "세그먼트 하나.",
    ),
    key(
        "segment.*.cache",
        Ty::Duration,
        Advanced,
        "Reuse the output this long.",
        "출력을 다시 쓰는 시간.",
    )
    .exec()
    .kinds(CMD_LANG)
    .example("\"30s\""),
    key(
        "segment.*.command",
        Ty::Strings,
        Basic,
        "The command as argv, no shell.",
        "실행할 명령(argv, 셸 없음).",
    )
    .exec()
    .kinds(CMD)
    .example("[\"kubectl\", \"config\", \"current-context\"]"),
    key(
        "segment.*.cwd",
        Ty::Str,
        Expert,
        "Folder to run in.",
        "실행할 폴더.",
    )
    .exec()
    .kinds(CMD)
    .example("\"~/work\""),
    key(
        "segment.*.enabled",
        Ty::Bool,
        Basic,
        "Turn the segment off with false.",
        "false면 세그먼트를 끔.",
    )
    .exec()
    .example("true"),
    key(
        "segment.*.env_allow",
        Ty::Strings,
        Expert,
        "Environment variables passed to the command.",
        "명령에 넘길 환경 변수.",
    )
    .exec()
    .kinds(CMD)
    .example("[\"KUBECONFIG\"]"),
    key(
        "segment.*.kind",
        Ty::Enum(&KINDS),
        Basic,
        "What the segment is.",
        "세그먼트의 종류.",
    )
    .example("\"command\"")
    .exec(),
    key(
        "segment.*.shell",
        Ty::Str,
        Expert,
        "Run through this shell (needs unsafe_shell).",
        "이 셸로 실행(unsafe_shell 필요).",
    )
    .exec()
    .kinds(CMD)
    .example("\"sh\""),
    key(
        "segment.*.text",
        Ty::Text,
        Basic,
        "The text to show.",
        "보일 글.",
    )
    .kinds(&["text"])
    .example("\"prod\""),
    key(
        "segment.*.timeout",
        Ty::Duration,
        Advanced,
        "Give up after this long.",
        "이 시간 뒤 포기.",
    )
    .exec()
    .kinds(CMD_LANG)
    .example("\"200ms\""),
    key(
        "segment.*.unsafe_shell",
        Ty::Bool,
        Expert,
        "Allow `shell`.",
        "`shell`을 허용.",
    )
    .exec()
    .kinds(CMD)
    .example("false"),
    key(
        "segment.*.var",
        Ty::Str,
        Advanced,
        "Environment variable to show.",
        "보일 환경 변수.",
    )
    .exec()
    .kinds(&["env"])
    .example("\"AWS_PROFILE\""),
    key(
        "segment.dir",
        Ty::Table,
        Basic,
        "The folder segment.",
        "폴더 세그먼트.",
    ),
    key(
        "segment.dir.shorten",
        Ty::EnumList(SHORTEN),
        Advanced,
        "Ways to shorten a long path, in order.",
        "긴 경로를 줄이는 방법, 순서대로.",
    )
    .default("[\"repo\", \"abbrev\", \"depth\"]"),
    key(
        "segment.dir.when",
        Ty::Enum(&["needed", "always"]),
        Advanced,
        "Shorten only when the line overflows, or always.",
        "줄이 넘칠 때만 줄일지, 항상 줄일지.",
    )
    .default("\"needed\""),
    key(
        "segment.duration",
        Ty::Table,
        Basic,
        "The duration segment.",
        "실행 시간 세그먼트.",
    ),
    key(
        "segment.duration.min",
        Ty::Duration,
        Basic,
        "Show from this duration.",
        "이 시간부터 보임.",
    )
    .default("\"2s\""),
    key("style", Ty::Table, Basic, "Style.", "스타일."),
    key(
        "style.preset",
        Ty::Enum(PRESETS),
        Basic,
        "Style preset.",
        "스타일 프리셋.",
    )
    .default("\"triangle\""),
    key(
        "style.separator",
        Ty::Enum(SHAPES),
        Advanced,
        "Separator shape between blocks.",
        "블록 사이 구분자 모양.",
    )
    .example("\"round\""),
    key(
        "style.template",
        Ty::Text,
        Expert,
        "Template text; replaces preset and options.",
        "템플릿. 프리셋과 옵션을 대신함.",
    )
    .example("\"{dir} {git}{@nl}{char}\""),
    key(
        "theme",
        Ty::Enum(&["bingsu-default"]),
        Basic,
        "Built-in theme name.",
        "내장 테마 이름.",
    )
    .not_in_theme()
    .default("\"bingsu-default\""),
    key(
        "width",
        Ty::Table,
        Advanced,
        "How wide characters are.",
        "글자 폭.",
    ),
    key(
        "width.ambiguous",
        Ty::Int { min: 1, max: 2 },
        Advanced,
        "Cells of East Asian Ambiguous characters (2 in most CJK setups).",
        "East Asian Ambiguous 글자의 칸 수(CJK 환경은 대개 2).",
    )
    .default("1"),
    key(
        "width.emoji",
        Ty::Int { min: 1, max: 2 },
        Advanced,
        "Cells of emoji.",
        "이모지의 칸 수.",
    )
    .default("2"),
];

fn matches(pattern: &str, path: &[&str]) -> bool {
    let mut p = pattern.split('.');
    let mut n = 0;
    for seg in path {
        match p.next() {
            Some("*") => {}
            Some(x) if x == *seg => {}
            _ => return false,
        }
        n += 1;
    }
    p.next().is_none() && n == path.len()
}

/// The row for `path`. A literal row wins over a `*` row (`segment.dir`
/// over `segment.*`).
pub fn lookup(path: &[&str]) -> Option<&'static KeyDef> {
    let mut best: Option<&'static KeyDef> = None;
    for k in KEYS {
        if matches(k.path, path) {
            let stars = |d: &KeyDef| d.path.matches('*').count();
            if best.is_none_or(|b| stars(k) < stars(b)) {
                best = Some(k);
            }
        }
    }
    best
}

/// What a shape-only file may put at `path` (`merge`).
pub fn slot(path: &[&str]) -> Slot {
    match lookup(path) {
        Some(k) if k.class == KeyClass::Exec => Slot::Exec,
        Some(k) if k.ty == Ty::Table => Slot::Table,
        Some(_) => Slot::Shape,
        None => Slot::Exec,
    }
}

/// Execution key or not; an unknown path is an execution key.
pub fn classify(path: &[&str]) -> KeyClass {
    lookup(path).map_or(KeyClass::Exec, |k| k.class)
}

/// Keys a table at `path` may hold, by name (`*` rows left out).
pub fn children(path: &[&str]) -> alloc::vec::Vec<&'static str> {
    KEYS.iter()
        .filter_map(|k| {
            let (parent, last) = k.path.rsplit_once('.').unwrap_or(("", k.path));
            let same = if path.is_empty() {
                parent.is_empty()
            } else {
                matches(parent, path)
            };
            (same && last != "*").then_some(last)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // 이것을 실패시키는 것: 표에 없는 키를 모양 키로 다루는 것("새 키는 민감한 것으로 시작"),
    // 스펙이 이름으로 든 실행 키 하나를 모양 키로 두는 것.
    #[test]
    fn execution_keys_are_the_default() {
        assert_eq!(
            classify(&["segment", "custom/k", "brand_new_key"]),
            KeyClass::Exec
        );
        assert_eq!(classify(&["nonsense"]), KeyClass::Exec);
        for k in [
            "kind",
            "enabled",
            "command",
            "shell",
            "unsafe_shell",
            "cwd",
            "env_allow",
            "timeout",
            "cache",
        ] {
            assert_eq!(classify(&["segment", "custom/k", k]), KeyClass::Exec, "{k}");
        }
        assert_eq!(classify(&["segment", "dir", "enabled"]), KeyClass::Exec);
        assert_eq!(classify(&["colors", "mode"]), KeyClass::Shape);
        assert_eq!(
            classify(&["layout", "when", "narrow", "line2", "left"]),
            KeyClass::Shape
        );
    }

    // 이것을 실패시키는 것: 테마가 실행 키나 `extends`·`theme`을 쓸 수 있게 두는 것.
    #[test]
    fn themes_set_no_execution_key() {
        for k in KEYS {
            if k.class == KeyClass::Exec {
                assert!(!k.theme, "{}", k.path);
            }
        }
        assert!(!lookup(&["theme"]).unwrap().theme);
    }

    // 이것을 실패시키는 것: 표가 정렬되지 않거나 같은 경로가 둘이거나, 상위 표 없는 키가 있는 것
    // (스키마가 그 키를 못 그림).
    #[test]
    fn the_table_is_sorted_and_closed() {
        assert!(
            KEYS.windows(2).all(|w| w[0].path < w[1].path),
            "sorted, unique"
        );
        for k in KEYS {
            if let Some((parent, _)) = k.path.rsplit_once('.') {
                let p = KEYS.iter().find(|d| d.path == parent);
                assert!(
                    p.is_some_and(|d| d.ty == Ty::Table),
                    "{} has no table parent",
                    k.path
                );
            }
        }
        let top: Vec<&str> = children(&[]);
        assert_eq!(
            top,
            [
                "colors", "icons", "layout", "segment", "style", "theme", "width"
            ]
        );
    }

    // 모양 키(실행 키가 아닌 값 키)의 전수 목록. 표에서 키를 지우거나 분류를 바꾸면 이 목록과 달라지고,
    // 실패 메시지가 그 키 이름을 보인다. 새 모양 키는 근거와 함께 여기에 더한다.
    // 이것을 실패시키는 것: 모양 키 하나를 표에서 지우는 것(그 키는 실행 키로 다뤄짐), 실행 키를 모양 키로 바꾸는 것.
    #[test]
    fn shape_keys_are_pinned() {
        let got: Vec<&str> = KEYS
            .iter()
            .filter(|k| k.class == KeyClass::Shape && k.ty != Ty::Table)
            .map(|k| k.path)
            .collect();
        let want = [
            "colors.flavor",
            "colors.knobs.accent_c",
            "colors.knobs.accent_l",
            "colors.knobs.hue",
            "colors.mode",
            "colors.override.*",
            "colors.roles.*",
            "icons",
            "layout.fill",
            "layout.frame",
            "layout.line1.enabled",
            "layout.line1.left",
            "layout.line1.right",
            "layout.line2.enabled",
            "layout.line2.left",
            "layout.line2.right",
            "layout.transient",
            "layout.use_last_column",
            "layout.when.*.line1.enabled",
            "layout.when.*.line1.left",
            "layout.when.*.line1.right",
            "layout.when.*.line2.enabled",
            "layout.when.*.line2.left",
            "layout.when.*.line2.right",
            "layout.when.*.max_cols",
            "layout.when.*.min_cols",
            "layout.when.*.order",
            "layout.when.*.style.preset",
            "layout.when.*.style.template",
            "segment.*.text",
            "segment.dir.shorten",
            "segment.dir.when",
            "segment.duration.min",
            "style.preset",
            "style.separator",
            "style.template",
            "theme",
            "width.ambiguous",
            "width.emoji",
        ];
        let missing: Vec<&&str> = want.iter().filter(|w| !got.contains(w)).collect();
        let extra: Vec<&&str> = got.iter().filter(|g| !want.contains(g)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "missing {missing:?}, extra {extra:?}"
        );
    }

    // 이것을 실패시키는 것: `*`보다 글자 그대로의 행을 먼저 고르지 않는 것.
    #[test]
    fn literal_rows_win() {
        assert_eq!(
            lookup(&["segment", "dir", "shorten"]).unwrap().path,
            "segment.dir.shorten"
        );
        assert_eq!(lookup(&["segment", "dir"]).unwrap().path, "segment.dir");
        assert_eq!(lookup(&["segment", "custom/k"]).unwrap().path, "segment.*");
        assert!(
            lookup(&["segment", "dir", "command"]).is_some(),
            "segment.* keys still match"
        );
    }
}
