//! `bingsu config edit`: open the settings file in the user's editor, then
//! check what was saved the way `config check` does and publish it the way
//! `reload` does. The file is edited in place (spec section 4 "설정 편집
//! 루프"): its owner, mode, links and `extends` paths stay as they are. A
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
    config_inspect::{Selection, exit_for, inspect_config, render_check},
    ctx::{self, EXIT_FAILED, EXIT_UNFINISHED, User},
    editor::{self, EditorError},
    init::trusted_env::TrustedEnv,
    messages::{MsgId, en},
    reload,
};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus};

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

/// Waits for the editor. Ctrl-C belongs to the editor while it runs; the
/// interrupt guard (`run_ignoring_interrupts`) takes this place when it is
/// merged.
fn wait_for_editor(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    cmd.status()
}

/// The file to open: the file `config use` chose when there is one, else
/// `config.toml` in the settings folder.
fn target(selection: &Selection, written_root: &std::path::Path) -> PathBuf {
    match selection {
        Selection::Chosen(r) => r.path.clone(),
        _ => written_root.join("config.toml"),
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
    let file = target(&inspected.selection, &inspected.root_written);
    if let Selection::Unusable(why) = &inspected.selection {
        eprintln!(
            "bingsu: the file chosen with `config use` cannot be used ({why}); opening {}",
            ctx::show(&file)
        );
    }
    if std::fs::symlink_metadata(&file).is_err() {
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
    match wait_for_editor(&mut cmd) {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!(
                "bingsu: the editor ended with {status}, so nothing was applied. If you saved changes, bingsu reload applies them"
            );
            return ctx::code(EXIT_FAILED);
        }
        Err(e) => {
            eprintln!("bingsu: the editor could not be started ({e})");
            return ctx::code(EXIT_FAILED);
        }
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
    match inspect_config(&user, &TrustedEnv::capture()) {
        Ok(after) => {
            let shown = render_check(&after);
            if !ctx::print(&shown) {
                return ctx::code(EXIT_FAILED);
            }
            if exit_for(&after) != 0 {
                eprintln!(
                    "bingsu: the saved settings are not valid, so they were not applied; the prompt keeps the previous settings"
                );
            }
        }
        Err((text, code)) => {
            eprintln!("{text}");
            return ctx::code(code);
        }
    }
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
            if ctx::print(&text) {
                ExitCode::SUCCESS
            } else {
                ctx::code(EXIT_FAILED)
            }
        }
        Err((text, code)) => {
            eprintln!("{text}");
            ctx::code(code)
        }
    }
}
