//! Fixed user-facing messages, looked up by id. One English table today.
//! Adding a language: write a table with every id (the test below checks
//! completeness), and let `init` pick the table once from the locale it sees
//! at that trusted moment; the chosen text is embedded in the hook, so the
//! prompt never reads the locale.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgId {
    UnsupportedShell,
    NoHome,
    NoExePath,
    Tamperable,
    TamperUnknown,
    NoRuntimeRoot,
    UnconfirmedRoot,
    BashTooOld,
    LateHookZsh,
    LateHookBash,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the completeness list for message tables; only tests read it in M1"
    )
)]
pub const ALL: [MsgId; 10] = [
    MsgId::UnsupportedShell,
    MsgId::NoHome,
    MsgId::NoExePath,
    MsgId::Tamperable,
    MsgId::TamperUnknown,
    MsgId::NoRuntimeRoot,
    MsgId::UnconfirmedRoot,
    MsgId::BashTooOld,
    MsgId::LateHookZsh,
    MsgId::LateHookBash,
];

const EN: [(MsgId, &str); 10] = [
    (
        MsgId::UnsupportedShell,
        "bingsu: unsupported shell. Supported: zsh, bash, fish",
    ),
    (
        MsgId::NoHome,
        "bingsu: cannot read the account home folder; prompt not installed",
    ),
    (
        MsgId::NoExePath,
        "bingsu: could not find the path you ran bingsu from; using the resolved executable path. Run: bingsu doctor",
    ),
    (
        MsgId::Tamperable,
        "bingsu: the bingsu executable or a folder above it can be changed by another user. Run: bingsu doctor",
    ),
    (
        MsgId::TamperUnknown,
        "bingsu: could not confirm that the bingsu executable and the folders above it are safe from other users. Run: bingsu doctor",
    ),
    (
        MsgId::NoRuntimeRoot,
        "bingsu: no usable runtime folder; the prompt runs without saved state. Run: bingsu doctor",
    ),
    (
        MsgId::UnconfirmedRoot,
        "bingsu: a settings, state or log folder path could not be confirmed; that folder is not used. Run: bingsu doctor",
    ),
    (
        MsgId::BashTooOld,
        "bingsu: bash 5.1 or newer is required; this shell keeps its own prompt. Run: bingsu doctor",
    ),
    (
        MsgId::LateHookZsh,
        "bingsu: another prompt hook runs after bingsu; put the bingsu init line last in your .zshrc",
    ),
    (
        MsgId::LateHookBash,
        "bingsu: another prompt hook runs after bingsu; put the bingsu init line last in your .bashrc",
    ),
];

pub fn en(id: MsgId) -> &'static str {
    EN.iter()
        .find(|(i, _)| *i == id)
        .map_or("bingsu: message missing", |(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: id가 표에 없거나 두 번 있는 것, 여러 줄·제어 문자·작은따옴표·접두사 없는 문구.
    #[test]
    fn messages_cover_every_id() {
        for id in ALL {
            assert_eq!(EN.iter().filter(|(i, _)| *i == id).count(), 1, "{id:?}");
            let t = en(id);
            assert!(t.starts_with("bingsu: "), "{id:?}");
            assert!(
                t.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'\''),
                "{id:?}: {t}"
            );
        }
        assert_eq!(EN.len(), ALL.len());
    }
}
