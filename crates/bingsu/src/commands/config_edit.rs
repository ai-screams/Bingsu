//! `bingsu config edit`: open the settings file in the user's editor, then
//! check what was saved the way `config check` does and publish it the way
//! `reload` does. The file is edited in place: its owner, mode, links and `extends` paths stay as they are. A
//! save that is not valid is not applied: the prompt keeps the previous
//! settings, and the commands of the file stop running until a valid save,
//! as for any invalid file on disk.
//!
//! The editor is `$VISUAL`, else `$EDITOR`, started without a shell
//! (`editor.rs`) with the environment as it is. Nothing in a settings file
//! can name it. Exit codes: 0 applied or unchanged, 1 refused or invalid or
//! the editor failed, 2 usage, 3 not finished (busy, deadline).
use super::{
    clock::SystemClock,
    config_inspect::{Selection, check_report, inspect_config},
    config_load::{TwoNames, name_present, pick_name, root_names},
    ctx::{self, EXIT_FAILED, EXIT_UNFINISHED, User},
    editor::{self, EditorError},
    init::trusted_env::TrustedEnv,
    messages::{MsgId, en},
    reload, signal_guard,
};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn editor_problem(e: &EditorError) -> String {
    match e {
        EditorError::NotSet => "bingsu: set $VISUAL or $EDITOR to the editor to use, for example\n  export EDITOR=\"code -w\"\n  export EDITOR=nano".to_owned(),
        EditorError::ShellSyntax(c) => format!(
            "bingsu: the editor value has a shell character ({c}), and no shell is run. Put the command in a script and point $VISUAL or $EDITOR at it"
        ),
        EditorError::Unfinished => "bingsu: the editor value has a quote or backslash that is not finished".to_owned(),
        EditorError::Empty => "bingsu: the editor value has no program".to_owned(),
        EditorError::RelativeProgram => "bingsu: the editor program is a relative path; use an absolute path or a name found in PATH".to_owned(),
        EditorError::NotFound => "bingsu: the editor program was not found (only absolute PATH entries are searched)".to_owned(),
        EditorError::NotText => "bingsu: the editor value is not text".to_owned(),
    }
}

/// Whether what the editor did can be applied: `Ok` only for an editor that
/// ended with success. The error is the text to show.
///
/// An error from the wait is not only "could not start": a process that
/// ignores SIGCHLD has its child collected for it on some systems, and the
/// wait then fails after the editor has ended. Whether it saved is not known,
/// so nothing is applied.
fn editor_outcome(result: std::io::Result<std::process::ExitStatus>) -> Result<(), String> {
    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!(
            "bingsu: the editor ended with {status}, so nothing was applied. If you saved changes, bingsu reload applies them"
        )),
        Err(e) => Err(format!(
            "bingsu: could not tell how the editor ended ({e}), so nothing was applied. If you saved changes, bingsu reload applies them"
        )),
    }
}

/// Which settings file stands in the one place `config.toml` / `config.json`
/// of the settings folder, by the reader's own rule (`config_load::pick_name`):
/// one name present is the file, two present are an error (E308), none
/// present is the default name, which the caller finds missing.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Place {
    One(PathBuf),
    Both(PathBuf, PathBuf),
}

pub(super) fn place(root: &std::path::Path, present: impl Fn(&std::path::Path) -> bool) -> Place {
    let [toml, json] = root_names(root);
    match pick_name([&toml, &json], present) {
        TwoNames::Both => Place::Both(toml, json),
        TwoNames::Second => Place::One(json),
        TwoNames::First | TwoNames::Neither => Place::One(toml),
    }
}

/// The file to open: the file `config use` chose when there is one, else the
/// file of the settings place.
fn target(selection: &Selection, written_root: &std::path::Path) -> Place {
    match selection {
        Selection::Chosen(r) => Place::One(r.path.clone()),
        _ => place(written_root, name_present),
    }
}

pub fn run(exe: &OsStr) -> ExitCode {
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    let env = TrustedEnv::capture();
    let inspected = match inspect_config(&user, &env) {
        Ok(i) => i,
        Err((text, code)) => {
            eprintln!("{text}");
            return ctx::code(code);
        }
    };
    if matches!(inspected.selection, Selection::Incomplete) {
        eprintln!(
            "bingsu: the settings choice could not be read, so no file is opened. Run: bingsu config path"
        );
        return ctx::code(EXIT_UNFINISHED);
    }
    let file = match target(&inspected.selection, &inspected.root_written) {
        Place::One(f) => f,
        Place::Both(a, b) => {
            eprintln!(
                "bingsu: {} and {} are both here, so no file is opened. Keep one of them (bingsu help E308)",
                ctx::show(&a),
                ctx::show(&b)
            );
            return ctx::code(EXIT_FAILED);
        }
    };
    if let Selection::Unusable(why) = &inspected.selection {
        eprintln!(
            "bingsu: the file chosen with `config use` cannot be used ({why}); opening {}",
            ctx::show(&file)
        );
    }
    // The file must be there as a plain file: a link that leads nowhere would
    // make the editor's save create a file at its target, maybe outside the
    // settings folder.
    if !std::fs::metadata(&file).is_ok_and(|m| m.is_file()) {
        eprintln!(
            "bingsu: there is no settings file at {}; run bingsu setup to make one",
            ctx::show(&file)
        );
        return ctx::code(EXIT_FAILED);
    }

    let (visual, editor_var, path) = TrustedEnv::editor();
    let words = match editor::pick(visual.as_deref(), editor_var.as_deref())
        .and_then(|v| editor::words(&v))
    {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{}", editor_problem(&e));
            return ctx::code(EXIT_FAILED);
        }
    };
    let program = match editor::find_program(&words[0], path.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", editor_problem(&e));
            return ctx::code(EXIT_FAILED);
        }
    };
    let mut cmd = Command::new(&program);
    cmd.args(&words[1..]).arg(&file);
    // Ctrl-C and Ctrl-\ belong to the editor while it runs (it is in the
    // foreground group and gets them); this process ignores them until the
    // editor has ended.
    if let Err(text) = editor_outcome(signal_guard::run_ignoring_interrupts(&mut cmd)) {
        eprintln!("{text}");
        return ctx::code(EXIT_FAILED);
    }

    // From here the 3 s command limit counts, not while the editor ran.
    let Some(started) = ctx::start() else {
        eprintln!("{}", en(MsgId::ReloadIncomplete));
        return ctx::code(EXIT_UNFINISHED);
    };
    let _deadline = match ctx::arm_deadline(
        ctx::COMMAND_LIMIT,
        format!("{}\n", en(MsgId::DeadlineReached)),
    ) {
        Ok(d) => d,
        Err(code) => return ctx::code(code),
    };
    // The same report as `config check`, and its code: the edit ends with it
    // when the check fails. The publication still runs: for an invalid save it
    // is what revokes the previous settings' right to run commands.
    let check_code = match check_report(&user, &TrustedEnv::capture()) {
        Ok((shown, code)) => {
            if !ctx::print(&shown) {
                return ctx::code(EXIT_FAILED);
            }
            if code != 0 {
                eprintln!(
                    "bingsu: the saved settings are not valid, so they were not applied; the prompt keeps the previous settings"
                );
            }
            code
        }
        Err((text, code)) => {
            eprintln!("{text}");
            return ctx::code(code);
        }
    };
    let roots = match ctx::roots_for_publishing(&user) {
        Ok(r) => r,
        Err((text, code)) => {
            eprintln!("{text}");
            return ctx::code(code);
        }
    };
    let applied = ctx::apply(
        std::path::Path::new(exe),
        &roots,
        &user,
        started,
        &mut SystemClock,
    );
    match reload::report(&applied, "edited") {
        Ok(text) => {
            if !ctx::print(&text) {
                return ctx::code(EXIT_FAILED);
            }
            ctx::code(check_code)
        }
        Err((text, code)) => {
            eprintln!("{text}");
            ctx::code(if check_code != 0 { check_code } else { code })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    // 이것을 실패시키는 것: 기다림 오류(ECHILD: 편집기가 자동 회수됨)를 편집기의 정상 종료로 읽고 적용하는 것,
    // 신호로 끝났거나 0이 아닌 상태를 적용하는 것, 오류 문구에서 "nothing was applied"를 빼는 것.
    // 이것을 실패시키는 것: json만 있을 때 `config.toml`을 고르는 것, 둘 다 있을 때 하나를 고르는 것, 둘 다 없을 때
    // 기본 이름을 `config.toml`이 아닌 것으로 하는 것.
    #[test]
    fn the_place_is_picked_by_the_readers_rule() {
        let root = std::path::Path::new("/c");
        let has = |names: &'static [&'static str]| {
            move |p: &std::path::Path| names.iter().any(|n| p == root.join(n))
        };
        let (t, j) = (root.join("config.toml"), root.join("config.json"));
        assert_eq!(place(root, has(&["config.toml"])), Place::One(t.clone()));
        assert_eq!(place(root, has(&["config.json"])), Place::One(j.clone()));
        assert_eq!(
            place(root, has(&["config.toml", "config.json"])),
            Place::Both(t.clone(), j)
        );
        assert_eq!(place(root, has(&[])), Place::One(t));
    }

    #[test]
    fn only_a_successful_end_can_be_applied() {
        assert_eq!(editor_outcome(Ok(ExitStatus::from_raw(0))), Ok(()));
        let failed = editor_outcome(Ok(ExitStatus::from_raw(3 << 8))).unwrap_err();
        assert!(
            failed.contains("exit status: 3") && failed.contains("nothing was applied"),
            "{failed}"
        );
        let signalled = editor_outcome(Ok(ExitStatus::from_raw(libc::SIGTERM))).unwrap_err();
        assert!(
            signalled.contains("signal") && signalled.contains("nothing was applied"),
            "{signalled}"
        );
        let unknown =
            editor_outcome(Err(std::io::Error::from_raw_os_error(libc::ECHILD))).unwrap_err();
        assert!(
            unknown.contains("could not tell how the editor ended"),
            "{unknown}"
        );
        assert!(unknown.contains("nothing was applied"), "{unknown}");
    }
}
