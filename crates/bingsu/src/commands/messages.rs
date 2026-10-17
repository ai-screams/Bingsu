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
    ShapeOnlyConfigRoot,
    BashTooOld,
    LateHookZsh,
    LateHookBash,
    NoSandbox,
    TrustInvalid,
    TrustMismatch,
    TrustClock,
    ColdInitUnfinished,
    ColdInitInvalid,
    ReloadInvalid,
    ReloadBusy,
    ReloadIncomplete,
    DeadlineReached,
    UseSavedUnfinished,
    UseSavedInvalid,
    RootsFromEnvironment,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the completeness list for message tables; only tests read it in M1"
    )
)]
pub const ALL: [MsgId; 24] = [
    MsgId::UnsupportedShell,
    MsgId::NoHome,
    MsgId::NoExePath,
    MsgId::Tamperable,
    MsgId::TamperUnknown,
    MsgId::NoRuntimeRoot,
    MsgId::UnconfirmedRoot,
    MsgId::ShapeOnlyConfigRoot,
    MsgId::BashTooOld,
    MsgId::LateHookZsh,
    MsgId::LateHookBash,
    MsgId::NoSandbox,
    MsgId::TrustInvalid,
    MsgId::TrustMismatch,
    MsgId::TrustClock,
    MsgId::ColdInitUnfinished,
    MsgId::ColdInitInvalid,
    MsgId::ReloadInvalid,
    MsgId::ReloadBusy,
    MsgId::ReloadIncomplete,
    MsgId::DeadlineReached,
    MsgId::UseSavedUnfinished,
    MsgId::UseSavedInvalid,
    MsgId::RootsFromEnvironment,
];

const EN: [(MsgId, &str); 24] = [
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
        MsgId::ShapeOnlyConfigRoot,
        "bingsu: could not confirm that the settings folder and the folders above it are safe from other users; its colors and layout apply, but nothing in it runs",
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
    (
        MsgId::TrustInvalid,
        "bingsu: settings verification failed; configured commands are paused. Run: bingsu doctor",
    ),
    (
        MsgId::TrustMismatch,
        "bingsu: saved settings and their verification do not match; configured commands are paused. Run: bingsu doctor",
    ),
    (
        MsgId::TrustClock,
        "bingsu: settings verification time could not be confirmed; configured commands are paused. Run: bingsu doctor",
    ),
    (
        MsgId::NoSandbox,
        "bingsu: the prompt could not start its system call filter, so it draws a minimal prompt. Run: bingsu doctor",
    ),
    (
        MsgId::ColdInitUnfinished,
        "bingsu: reading your settings did not finish in time; the prompt starts with the built-in look and takes your settings when they are ready",
    ),
    (
        MsgId::ColdInitInvalid,
        "bingsu: your settings are not valid, so the prompt starts with the built-in look. Run: bingsu config check",
    ),
    (
        MsgId::ReloadInvalid,
        "bingsu: the settings are not valid, so nothing changed and the prompt keeps the last good settings. Run: bingsu config check",
    ),
    (
        MsgId::ReloadBusy,
        "bingsu: another refresh is running, so nothing changed. Try again in a moment",
    ),
    (
        MsgId::ReloadIncomplete,
        "bingsu: the settings could not be read to the end, so nothing changed. Run: bingsu config check",
    ),
    (
        MsgId::DeadlineReached,
        "bingsu: did not finish in time; nothing more was changed",
    ),
    (
        MsgId::UseSavedUnfinished,
        "bingsu: your choice was saved, but applying it is not finished; the next prompt applies it, or run: bingsu reload",
    ),
    (
        MsgId::UseSavedInvalid,
        "bingsu: your choice was saved, but the settings it gives are not valid and the prompt keeps the last good settings. Run: bingsu config check",
    ),
    (
        MsgId::RootsFromEnvironment,
        "bingsu: the folders were found from the environment now, not from what init pinned in this shell, so they may differ from the ones your prompt uses. Run: eval \"$(bingsu init <shell>)\" again",
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
