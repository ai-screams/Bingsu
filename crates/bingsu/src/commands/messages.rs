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
    ReloadOverCap,
    DeadlineReached,
    UseSavedUnfinished,
    UseSavedInvalid,
    RootsFromEnvironment,
    UseShapeOnlyRoot,
    NoticeBadArgs,
    NoticeInternal,
    NoticeRuntimeRoot,
    NoticeOversize,
    NoticeTrustUnverified,
    NoticeTrustExpired,
    NoticeConfigLastGood,
    NoticeConfigDefault,
    NoticeGeneric,
    NoRecord,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the completeness list for message tables; only tests read it in M1"
    )
)]
pub const ALL: [MsgId; 36] = [
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
    MsgId::ReloadOverCap,
    MsgId::DeadlineReached,
    MsgId::UseSavedUnfinished,
    MsgId::UseSavedInvalid,
    MsgId::RootsFromEnvironment,
    MsgId::UseShapeOnlyRoot,
    MsgId::NoticeBadArgs,
    MsgId::NoticeInternal,
    MsgId::NoticeRuntimeRoot,
    MsgId::NoticeOversize,
    MsgId::NoticeTrustUnverified,
    MsgId::NoticeTrustExpired,
    MsgId::NoticeConfigLastGood,
    MsgId::NoticeConfigDefault,
    MsgId::NoticeGeneric,
    MsgId::NoRecord,
];

const EN: [(MsgId, &str); 36] = [
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
        "bingsu: could not find the path you ran bingsu from; using the resolved executable path. Run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::Tamperable,
        "bingsu: the bingsu executable or a folder above it can be changed by another user. Check its ownership and write permissions and run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::TamperUnknown,
        "bingsu: could not confirm that the bingsu executable and the folders above it are safe from other users. Check their ownership, write permissions and access lists and run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::NoRuntimeRoot,
        "bingsu: no usable runtime folder; the prompt runs without saved state. Check your runtime or cache folder permissions and run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::UnconfirmedRoot,
        "bingsu: a settings, state or log folder path could not be confirmed; that folder is not used. Run: bingsu doctor, check the path and its permissions, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::ShapeOnlyConfigRoot,
        "bingsu: could not confirm that the settings folder and the folders above it are safe from other users; its colors and layout apply, but nothing in it runs",
    ),
    (
        MsgId::BashTooOld,
        "bingsu: bash 5.1 or newer is required; this shell keeps its own prompt. Upgrade bash, then open a new bash",
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
        "bingsu: settings verification failed; configured commands are paused. Run: bingsu config check, then bingsu reload",
    ),
    (
        MsgId::TrustMismatch,
        "bingsu: saved settings and their verification do not match; configured commands are paused. Run: bingsu config check, then bingsu reload",
    ),
    (
        MsgId::TrustClock,
        "bingsu: settings verification time could not be confirmed; configured commands are paused. Run: bingsu reload",
    ),
    (
        MsgId::NoSandbox,
        "bingsu: the prompt could not start its system call filter, so it draws a minimal prompt. Run: bingsu doctor, which checks whether the kernel supports the filter, then open a new shell",
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
        MsgId::ReloadOverCap,
        "bingsu: the settings need more file reads than one refresh may make, so nothing is published. Use fewer entries in conf.d or extends",
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
    (
        MsgId::UseShapeOnlyRoot,
        "bingsu: not using {path}: it is inside the settings folder, which could not be confirmed safe, so nothing in it runs. Run: bingsu config check",
    ),
    (
        MsgId::NoticeBadArgs,
        "bingsu: the shell hook and the bingsu program do not match, so a minimal prompt is drawn. Run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::NoticeInternal,
        "bingsu: the prompt hit an internal error, so a minimal prompt is drawn. Run: bingsu doctor, then open a new shell",
    ),
    (
        MsgId::NoticeRuntimeRoot,
        "bingsu: the runtime folder changed, so the prompt runs without saved state. Run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
    ),
    (
        MsgId::NoticeOversize,
        "bingsu: the prompt grew too large, so a minimal prompt is drawn. Use a shorter layout",
    ),
    (
        MsgId::NoticeTrustUnverified,
        "bingsu: settings are not verified yet; configured commands are paused. Run: bingsu reload",
    ),
    (
        MsgId::NoticeTrustExpired,
        "bingsu: settings verification is out of date; configured commands are paused. Run: bingsu reload",
    ),
    (
        MsgId::NoticeConfigLastGood,
        "bingsu: your settings are not valid, so the prompt keeps the last good settings. Run: bingsu config check",
    ),
    (
        MsgId::NoticeConfigDefault,
        "bingsu: your settings are not valid, so the prompt uses the built-in look. Run: bingsu config check",
    ),
    (
        MsgId::NoticeGeneric,
        "bingsu: this bingsu does not know the prompt status it got, so a notice cannot be shown. The hook and the program may be from different versions: run bingsu doctor",
    ),
    (
        MsgId::NoRecord,
        "bingsu: the prompt gave no answer in time, so a minimal prompt is drawn. If this keeps happening, run: bingsu doctor",
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

    /// The words the user sees, id by id, in full. A change of a message
    /// is made here too, on purpose: the other tests read the table itself.
    const PINNED: [(MsgId, &str); 36] = [
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
            "bingsu: could not find the path you ran bingsu from; using the resolved executable path. Run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::Tamperable,
            "bingsu: the bingsu executable or a folder above it can be changed by another user. Check its ownership and write permissions and run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::TamperUnknown,
            "bingsu: could not confirm that the bingsu executable and the folders above it are safe from other users. Check their ownership, write permissions and access lists and run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::NoRuntimeRoot,
            "bingsu: no usable runtime folder; the prompt runs without saved state. Check your runtime or cache folder permissions and run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::UnconfirmedRoot,
            "bingsu: a settings, state or log folder path could not be confirmed; that folder is not used. Run: bingsu doctor, check the path and its permissions, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::ShapeOnlyConfigRoot,
            "bingsu: could not confirm that the settings folder and the folders above it are safe from other users; its colors and layout apply, but nothing in it runs",
        ),
        (
            MsgId::BashTooOld,
            "bingsu: bash 5.1 or newer is required; this shell keeps its own prompt. Upgrade bash, then open a new bash",
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
            "bingsu: settings verification failed; configured commands are paused. Run: bingsu config check, then bingsu reload",
        ),
        (
            MsgId::TrustMismatch,
            "bingsu: saved settings and their verification do not match; configured commands are paused. Run: bingsu config check, then bingsu reload",
        ),
        (
            MsgId::TrustClock,
            "bingsu: settings verification time could not be confirmed; configured commands are paused. Run: bingsu reload",
        ),
        (
            MsgId::NoSandbox,
            "bingsu: the prompt could not start its system call filter, so it draws a minimal prompt. Run: bingsu doctor, which checks whether the kernel supports the filter, then open a new shell",
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
            MsgId::ReloadOverCap,
            "bingsu: the settings need more file reads than one refresh may make, so nothing is published. Use fewer entries in conf.d or extends",
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
        (
            MsgId::UseShapeOnlyRoot,
            "bingsu: not using {path}: it is inside the settings folder, which could not be confirmed safe, so nothing in it runs. Run: bingsu config check",
        ),
        (
            MsgId::NoticeBadArgs,
            "bingsu: the shell hook and the bingsu program do not match, so a minimal prompt is drawn. Run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::NoticeInternal,
            "bingsu: the prompt hit an internal error, so a minimal prompt is drawn. Run: bingsu doctor, then open a new shell",
        ),
        (
            MsgId::NoticeRuntimeRoot,
            "bingsu: the runtime folder changed, so the prompt runs without saved state. Run: bingsu doctor, then open a new shell or evaluate your bingsu init line again",
        ),
        (
            MsgId::NoticeOversize,
            "bingsu: the prompt grew too large, so a minimal prompt is drawn. Use a shorter layout",
        ),
        (
            MsgId::NoticeTrustUnverified,
            "bingsu: settings are not verified yet; configured commands are paused. Run: bingsu reload",
        ),
        (
            MsgId::NoticeTrustExpired,
            "bingsu: settings verification is out of date; configured commands are paused. Run: bingsu reload",
        ),
        (
            MsgId::NoticeConfigLastGood,
            "bingsu: your settings are not valid, so the prompt keeps the last good settings. Run: bingsu config check",
        ),
        (
            MsgId::NoticeConfigDefault,
            "bingsu: your settings are not valid, so the prompt uses the built-in look. Run: bingsu config check",
        ),
        (
            MsgId::NoticeGeneric,
            "bingsu: this bingsu does not know the prompt status it got, so a notice cannot be shown. The hook and the program may be from different versions: run bingsu doctor",
        ),
        (
            MsgId::NoRecord,
            "bingsu: the prompt gave no answer in time, so a minimal prompt is drawn. If this keeps happening, run: bingsu doctor",
        ),
    ];

    // 이것을 실패시키는 것: 표의 문구를 이 표 밖에서 몰래 바꾸는 것(사용자에게 보이는 글이 우연히 바뀜), 표가 이
    // 표와 한 id라도 다른 것.
    #[test]
    fn every_message_is_pinned_in_full() {
        assert_eq!(PINNED.len(), ALL.len());
        for (id, text) in PINNED {
            assert_eq!(en(id), text, "{id:?}");
        }
        for id in ALL {
            assert!(PINNED.iter().any(|(i, _)| *i == id), "{id:?} is not pinned");
        }
    }

    // `bingsu doctor` answers environment and installation questions only: the lines that name it are these,
    // and no other line sends the user there. 이것을 실패시키는 것: 설정 문제 줄에 `doctor`가 끼거나, 환경 문제 줄에서 빠지는 것.
    #[test]
    fn only_environment_messages_point_to_doctor() {
        use MsgId::*;
        let want = [
            NoExePath,
            Tamperable,
            TamperUnknown,
            NoRuntimeRoot,
            UnconfirmedRoot,
            NoSandbox,
            NoticeBadArgs,
            NoticeInternal,
            NoticeRuntimeRoot,
            NoticeGeneric,
            NoRecord,
        ];
        let got: Vec<MsgId> = ALL
            .into_iter()
            .filter(|id| en(*id).contains("bingsu doctor"))
            .collect();
        assert_eq!(got, want);
        // The command exists: the words after "Run: " or "run " name `bingsu doctor` exactly.
        for id in got {
            let t = en(id);
            assert!(
                t.contains("Run: bingsu doctor")
                    || t.contains("run bingsu doctor")
                    || t.contains("run: bingsu doctor"),
                "{id:?}: {t}"
            );
        }
    }

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
