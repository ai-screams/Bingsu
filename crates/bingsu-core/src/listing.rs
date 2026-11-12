//! The rows of `bingsu list` (plan D2): the names the settings accept. Each
//! kind is read from the table the schema, the renderer or the palette
//! reads (`config::keys`, `style::PRESETS`, `field::BUILTIN`,
//! `color::palette::TOKENS`, `icons::ICONS`), so a list cannot drift from
//! what a settings file may say.
use crate::color::palette::TOKENS;
use crate::config::keys::enum_values;
use crate::field::BUILTIN;
use crate::icons::{ICONS, IconSet};
use crate::style::PRESETS;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What `list` can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    Presets,
    Segments,
    Flavors,
    Roles,
    Shorteners,
    Icons,
}

impl What {
    pub const ALL: [What; 6] = [
        Self::Presets,
        Self::Segments,
        Self::Flavors,
        Self::Roles,
        Self::Shorteners,
        Self::Icons,
    ];

    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|w| w.word() == word)
    }

    pub const fn word(self) -> &'static str {
        match self {
            Self::Presets => "presets",
            Self::Segments => "segments",
            Self::Flavors => "flavors",
            Self::Roles => "roles",
            Self::Shorteners => "shorteners",
            Self::Icons => "icons",
        }
    }
}

fn names(path: &[&str]) -> Vec<String> {
    enum_values(path)
        .unwrap_or_default()
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// The rows of `what`, one string each, columns split by a tab.
pub fn rows(what: What) -> Vec<String> {
    match what {
        What::Presets => PRESETS.iter().map(|p| p.name.to_string()).collect(),
        What::Segments => BUILTIN
            .iter()
            .map(|d| format!("{}\t{}", d.id, d.role))
            .collect(),
        What::Flavors => names(&["colors", "flavor"]),
        What::Roles => TOKENS
            .iter()
            .map(|t| format!("{}\t{}\t{}", t.name, t.dark, t.light))
            .collect(),
        What::Shorteners => names(&["segment", "dir", "shorten"]),
        What::Icons => ICONS
            .iter()
            .map(|i| {
                let g = |s| i.glyph(s);
                format!(
                    "{}\t{}\t{}\t{}\t{}",
                    i.name(),
                    g(IconSet::Nerd),
                    g(IconSet::Light),
                    g(IconSet::Unicode),
                    g(IconSet::Ascii)
                )
            })
            .collect(),
    }
}
