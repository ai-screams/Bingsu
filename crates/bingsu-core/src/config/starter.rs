//! The starter settings file `bingsu setup` writes, and the comparison it prints instead when a file is already
//! there. Pure: the text is built from two fixed choices, so no user
//! string is ever put into the file. `colors.mode` is written here and in
//! no other file.
use crate::config::tree::{self, Table, Value};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The schema of the published config, for editors (`#:schema`).
pub const SCHEMA_URL: &str = "https://raw.githubusercontent.com/ai-screams/Bingsu/main/crates/bingsu-core/schema/config-v1.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icons {
    Nerd,
    Unicode,
}

impl Icons {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "nerd" => Some(Self::Nerd),
            "unicode" => Some(Self::Unicode),
            _ => None,
        }
    }
    pub const fn word(self) -> &'static str {
        match self {
            Self::Nerd => "nerd",
            Self::Unicode => "unicode",
        }
    }
    /// Without Nerd Font glyphs the plainer `lean` preset reads better
    /// (decision Q10).
    pub const fn preset(self) -> &'static str {
        match self {
            Self::Nerd => "triangle",
            Self::Unicode => "lean",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Dark,
    Light,
}

impl Mode {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "auto" => Some(Self::Auto),
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            _ => None,
        }
    }
    pub const fn word(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choices {
    pub icons: Icons,
    pub mode: Mode,
}

/// The file text for `c`.
pub fn starter(c: Choices) -> String {
    format!(
        "#:schema {SCHEMA_URL}\n\
         # bingsu settings. Every line is optional: delete one to get the default.\n\
         # Check this file with `bingsu config check`; `bingsu list` shows the names.\n\
         \n\
         # \"nerd\" draws Nerd Font glyphs; \"unicode\" needs no special font.\n\
         icons = \"{icons}\"\n\
         \n\
         [style]\n\
         # See `bingsu list presets --preview`.\n\
         preset = \"{preset}\"\n\
         \n\
         [colors]\n\
         # \"auto\" follows the terminal; \"dark\" or \"light\" fixes it.\n\
         mode = \"{mode}\"\n",
        icons = c.icons.word(),
        preset = c.icons.preset(),
        mode = c.mode.word(),
    )
}

fn text<'a>(t: &'a Table, path: &[&str]) -> Option<&'a str> {
    let (last, parents) = path.split_last()?;
    let mut table = t;
    for key in parents {
        match &table.get(key)?.node.value {
            Value::Table(inner) => table = inner,
            _ => return None,
        }
    }
    match &table.get(last)?.node.value {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

/// A value from the file as the terminal will show it: quoted, without
/// control, bidi or invisible characters (`sanitize`), at most 64
/// characters.
fn shown(value: &str) -> String {
    let clean = crate::sanitize::sanitize(value.as_bytes());
    let mut out = String::from("\"");
    out.extend(clean.chars().take(64));
    if clean.chars().count() > 64 {
        out.push('\u{2026}');
    }
    out.push('"');
    out
}

/// What differs between the file `existing`, written in `format`, and the
/// starter for `c`, one line per key: `icons: "unicode" now, "nerd"
/// suggested`. Empty when the three keys already match. `None` when the file
/// does not parse. Values from the file go through `shown`.
pub fn differences(format: tree::Format, existing: &[u8], c: Choices) -> Option<Vec<String>> {
    let tree = tree::parse_as(format, existing).ok()?;
    let want = [
        ("icons", &["icons"][..], c.icons.word()),
        ("style.preset", &["style", "preset"], c.icons.preset()),
        ("colors.mode", &["colors", "mode"], c.mode.word()),
    ];
    let mut out = Vec::new();
    for (name, path, suggested) in want {
        let now = text(&tree, path);
        if now != Some(suggested) {
            let now = match now {
                Some(v) => shown(v),
                None => "not set".to_string(),
            };
            out.push(format!("{name}: {now} now, {} suggested", shown(suggested)));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Choices; 6] = {
        const fn c(icons: Icons, mode: Mode) -> Choices {
            Choices { icons, mode }
        }
        [
            c(Icons::Nerd, Mode::Auto),
            c(Icons::Nerd, Mode::Dark),
            c(Icons::Nerd, Mode::Light),
            c(Icons::Unicode, Mode::Auto),
            c(Icons::Unicode, Mode::Dark),
            c(Icons::Unicode, Mode::Light),
        ]
    };

    // 이것을 실패시키는 것: 시작 설정이 TOML로 읽히지 않는 것, `colors.mode`가 한 번이 아닌 것,
    // `#:schema` 줄이 첫 줄이 아닌 것, 고른 값이 파일에 없거나 `unicode`에 `lean`이 따라가지 않는 것.
    #[test]
    fn the_starter_parses_and_writes_each_choice_once() {
        for c in ALL {
            let s = starter(c);
            assert!(s.starts_with("#:schema https://"), "{s}");
            let t = tree::parse(s.as_bytes()).unwrap();
            assert_eq!(text(&t, &["icons"]), Some(c.icons.word()));
            assert_eq!(text(&t, &["style", "preset"]), Some(c.icons.preset()));
            assert_eq!(text(&t, &["colors", "mode"]), Some(c.mode.word()));
            assert_eq!(s.matches("mode = ").count(), 1, "{s}");
            assert_eq!(s.matches("\nicons = ").count(), 1, "{s}");
            assert!(starter(c).is_ascii());
            // The starter agrees with itself: no differences.
            assert_eq!(
                differences(tree::Format::Toml, s.as_bytes(), c),
                Some(Vec::new()),
                "{s}"
            );
        }
        assert_eq!(Icons::Unicode.preset(), "lean");
    }

    // 이것을 실패시키는 것: 다른 값·없는 키를 차이로 알리지 않는 것, 같은 값을 차이로 알리는 것,
    // 파싱 안 되는 파일에 `None`이 아닌 것, 파일의 제어·bidi 글자를 그대로 내보내는 것, 긴 값을 자르지 않는 것.
    #[test]
    fn differences_name_only_what_differs() {
        let c = Choices {
            icons: Icons::Nerd,
            mode: Mode::Dark,
        };
        let d = differences(
            tree::Format::Toml,
            b"icons = \"unicode\"\n[colors]\nmode = \"dark\"\n",
            c,
        )
        .unwrap();
        assert_eq!(
            d,
            [
                "icons: \"unicode\" now, \"nerd\" suggested",
                "style.preset: not set now, \"triangle\" suggested"
            ]
        );
        assert_eq!(differences(tree::Format::Toml, b"icons = [", c), None);
        let d = differences(tree::Format::Toml, b"icons = \"a\\u001b[31m\\u202eb\"\n", c).unwrap();
        assert_eq!(d[0], "icons: \"a[31mb\" now, \"nerd\" suggested");
        let long = format!("icons = \"{}\"\n", "x".repeat(100));
        let d = differences(tree::Format::Toml, long.as_bytes(), c).unwrap();
        assert_eq!(
            d[0],
            format!(
                "icons: \"{}\u{2026}\" now, \"nerd\" suggested",
                "x".repeat(64)
            )
        );
    }
}
