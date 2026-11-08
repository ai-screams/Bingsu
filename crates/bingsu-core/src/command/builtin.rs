//! The builtin languages (plan D3): for each, the response entry's id, its
//! probe profile, the command its version comes from, the version manager
//! bingsu resolves for it and the shell variables its value depends on. The
//! helper decides and publishes a language's entry from this table, and the
//! prompt checks the entry's environment digest against the same names, so
//! the two sides cannot disagree on which variables bind a value.
use super::{
    plan::{self, Environ},
    profile,
};
use crate::collection::manager::Manager;
use alloc::vec::Vec;

/// One builtin language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Language {
    /// The collector's query id, the response entry's id and the segment id.
    pub id: &'static str,
    pub profile: u8,
    /// The command the version comes from, looked up on `PATH`.
    pub word: &'static [u8],
    pub manager: Option<Manager>,
    /// The shell variables its answer depends on beyond the keep list
    /// (`PATH`, `HOME`, ...).
    pub variables: &'static [&'static [u8]],
}

/// Shell variables that name the folders of managers without a resolver
/// (asdf, mise, volta, nodenv, goenv): they change whether the command is
/// such a shim, so they bind every language's value.
pub const UNSUPPORTED: [&[u8]; 8] = [
    b"ASDF_DATA_DIR",
    b"ASDF_DIR",
    b"MISE_DATA_DIR",
    b"MISE_SHIMS_DIR",
    b"XDG_DATA_HOME",
    b"VOLTA_HOME",
    b"NODENV_ROOT",
    b"GOENV_ROOT",
];

pub const LANGUAGES: [Language; 4] = [
    Language {
        id: "node",
        profile: profile::NODE,
        word: b"node",
        manager: None,
        variables: &[],
    },
    Language {
        id: "python",
        profile: profile::PYTHON,
        word: b"python3",
        manager: Some(Manager::Pyenv),
        variables: &[
            b"PYENV_ROOT",
            b"PYENV_VERSION",
            b"PYENV_DIR",
            b"PYENV_HOOK_PATH",
            // macOS: it picks the developer tools' python3 (D3a review M4).
            b"DEVELOPER_DIR",
        ],
    },
    Language {
        id: "rust",
        profile: profile::RUST,
        word: b"rustc",
        manager: Some(Manager::Rustup),
        variables: &[b"RUSTUP_HOME", b"CARGO_HOME", b"RUSTUP_TOOLCHAIN"],
    },
    Language {
        id: "go",
        profile: profile::GO,
        word: b"go",
        manager: None,
        variables: &[],
    },
];

/// Kept names a built-in language's digest leaves out (F1-b ruling).
pub const BUILTIN_DIGEST_SKIP: [&[u8]; 2] = [b"TERM", b"TZ"];

/// The language of a query or entry id.
pub fn language(id: &[u8]) -> Option<&'static Language> {
    LANGUAGES.iter().find(|l| l.id.as_bytes() == id)
}

impl Language {
    /// The environment digest of this language's entry: `plan::env_digest`
    /// over its own variables and `UNSUPPORTED`, without `TERM` or `TZ`
    /// (still passed): a version does not depend on the terminal or the time
    /// zone (F1-b ruling), so shells that differ only there share it.
    pub fn env_digest(&self, vars: &Environ<'_>) -> [u8; 32] {
        let names: Vec<Vec<u8>> = self
            .variables
            .iter()
            .chain(UNSUPPORTED.iter())
            .map(|n| n.to_vec())
            .collect();
        plan::digest_without(vars, &names, &BUILTIN_DIGEST_SKIP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 내장 언어 요약값은 TERM·TZ를 보지 않고(값을 함께 씀), 다른 남기기 이름(PATH)과 언어 변수는 본다. 이것을
    // 실패시키는 것: TERM이나 TZ를 다시 요약하는 것(터미널·시간대가 다른 셸이 서로의 버전을 숨김), 건너뛰는
    // 목록이 PATH나 언어 변수까지 빼는 것.
    #[test]
    fn builtin_digest_leaves_out_term_and_tz_only() {
        let python = language(b"python").unwrap();
        let d = |frame: &[u8]| python.env_digest(&Environ::parse(frame));
        let base = d(b"HOME=/h\0PATH=/bin\0PYENV_VERSION=3.12\0");
        assert_eq!(
            base,
            d(b"HOME=/h\0PATH=/bin\0PYENV_VERSION=3.12\0TERM=tmux\0TZ=Asia/Seoul\0")
        );
        assert_ne!(base, d(b"HOME=/h\0PATH=/usr/bin\0PYENV_VERSION=3.12\0"));
        assert_ne!(base, d(b"HOME=/h\0PATH=/bin\0PYENV_VERSION=3.13\0"));
        // A config unit keeps TZ in its digest.
        let unit = |frame: &[u8]| plan::env_digest(&Environ::parse(frame), &[]);
        assert_ne!(unit(b"TZ=UTC\0"), unit(b"TZ=Asia/Seoul\0"));
    }

    // 언어 표는 수집 질의 표(collection::language::BUILTIN)와 내장 segment 표(field::BUILTIN)와 같은 id를 쓰고,
    // segment마다 version 칸이 있다. 프로필 id는 서로 다르다. 이것을 실패시키는 것: 한 표에서만 id를 바꾸는 것,
    // 두 언어에 같은 프로필을 주는 것.
    #[test]
    fn languages_match_the_query_and_segment_tables() {
        assert_eq!(LANGUAGES.len(), crate::collection::language::BUILTIN.len());
        for (i, l) in LANGUAGES.iter().enumerate() {
            assert!(
                crate::collection::language::BUILTIN
                    .iter()
                    .any(|b| b.id == l.id.as_bytes()),
                "{}",
                l.id
            );
            let decl = crate::field::BUILTIN
                .iter()
                .find(|d| d.id == l.id)
                .unwrap_or_else(|| panic!("{}", l.id));
            assert!(decl.field_index("version").is_some(), "{}", l.id);
            assert_eq!(language(l.id.as_bytes()), Some(l));
            assert!(LANGUAGES[..i].iter().all(|o| o.profile != l.profile));
        }
        assert_eq!(language(b"ruby"), None);
    }
}
