//! `bingsu init <shell>`: stdout carries only the connection script;
//! diagnostics go to stderr (spec section 5 "init output").
pub(crate) mod exe_path;
mod render;
pub(super) mod roots;
pub(super) mod trusted_env;

use crate::commands::sys;
use bingsu_core::shell_word::Shell;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use crate::commands::messages::{MsgId, en};

fn hex16(b: [u8; 16]) -> [u8; 32] {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, v) in b.iter().enumerate() {
        out[2 * i] = H[usize::from(v >> 4)];
        out[2 * i + 1] = H[usize::from(v & 0xf)];
    }
    out
}

/// An empty or relative `pw_dir` would make every root relative to the
/// working folder; treat it like a failed lookup.
fn home_is_usable(home: &std::path::Path) -> bool {
    home.is_absolute()
}

/// Init's stderr lines about the roots, in order.
fn root_warnings(roots: &roots::Roots) -> Vec<String> {
    let mut out = Vec::new();
    if roots.config.is_none() || roots.state.is_none() || roots.log.is_none() {
        out.push(en(MsgId::UnconfirmedRoot).to_owned());
    }
    if let Some(lines) = roots.config.as_ref().and_then(|c| c.shape_only_notice()) {
        out.extend(lines);
    }
    if roots.runtime.is_none() {
        out.push(en(MsgId::NoRuntimeRoot).to_owned());
    }
    out
}

/// The values of the config root words: canonical path, written path and
/// whether the shape-only mark follows them.
fn config_root_words(p: &roots::ConfigRootPin) -> (&[u8], &[u8], bool) {
    (
        p.path.as_os_str().as_bytes(),
        p.written.as_os_str().as_bytes(),
        p.shape_only,
    )
}

pub fn run(argv0: &OsStr, args: &[OsString]) -> ExitCode {
    let shell = match args {
        [one] => Shell::parse(one.as_bytes()),
        _ => None,
    };
    let Some(shell) = shell else {
        eprintln!("{}", en(MsgId::UnsupportedShell));
        return ExitCode::from(2);
    };
    let env = trusted_env::TrustedEnv::capture();
    let uid = sys::current_uid();
    let Some(pw) = sys::passwd_entry(uid).filter(|pw| home_is_usable(&pw.home)) else {
        eprintln!("{}", en(MsgId::NoHome));
        return ExitCode::from(1);
    };
    let found = std::env::current_dir()
        .ok()
        .and_then(|cwd| exe_path::invocation_path(argv0, env.path.as_deref(), &cwd));
    let exe = match found {
        Some(p) => p,
        None => {
            eprintln!("{}", en(MsgId::NoExePath));
            match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return ExitCode::from(1),
            }
        }
    };
    match exe_path::check_path(&exe, uid, &pw.name) {
        exe_path::Verdict::Safe => {}
        exe_path::Verdict::Unknown => eprintln!("{}", en(MsgId::TamperUnknown)),
        exe_path::Verdict::Tamperable => eprintln!("{}", en(MsgId::Tamperable)),
    }
    let roots = roots::resolve(&env, &pw.home, &pw.name);
    for line in root_warnings(&roots) {
        eprintln!("{line}");
    }
    let Some(random) = sys::random_bytes16() else {
        return ExitCode::from(1);
    };
    let session = hex16(random);
    let inputs = render::ScriptInputs {
        shell,
        exe: exe.as_os_str().as_bytes(),
        runtime_root: roots
            .runtime
            .as_ref()
            .map(|r| (r.dev, r.ino, r.path.as_os_str().as_bytes())),
        config_root: roots.config.as_ref().map(config_root_words),
        state_root: roots.state.as_ref().map(|p| p.as_os_str().as_bytes()),
        log_root: roots.log.as_ref().map(|p| p.as_os_str().as_bytes()),
        session_hex: &session,
        home: pw.home.as_os_str().as_bytes(),
    };
    let mut out = Vec::with_capacity(16 * 1024);
    render::render(&inputs, &mut out);
    match sys::write_fd(1, &out) {
        sys::WriteOutcome::Done => ExitCode::SUCCESS,
        sys::WriteOutcome::Failed => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 모양 전용 뿌리(Undecided)도 두 경로와 표식을 넘기고, stderr 안내 두 줄을 내며 "쓰지 않는 폴더" 경고는 내지 않는다.
    // 보통 뿌리에는 표식이 없다.
    // 이것을 실패시키는 것: init이 pin의 모양 전용 상한을 단어로 넘기지 않는 것(`false` 고정), 안내 줄을 빼는 것,
    // 모양 전용 뿌리를 버린 뿌리처럼 경고하는 것.
    #[test]
    fn shape_only_pin_reaches_the_root_words() {
        use bingsu_core::fs_trust::{Facts, Group, GroupOracle};
        use std::os::unix::fs::PermissionsExt;
        struct Unknown;
        impl GroupOracle for Unknown {
            fn group_write(&mut self, _: &Facts) -> Group {
                Group::Unknown
            }
        }
        let d = std::env::temp_dir().join(format!("bingsu-init-words-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let root = std::fs::canonicalize(std::fs::create_dir_all(&d).map(|()| &d).unwrap())
            .unwrap()
            .join("bingsu");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o775)).unwrap();
        let me = sys::current_uid();
        let pin = roots::ConfigRootPin::check(&root, me, &mut Unknown).unwrap();
        let words = config_root_words(&pin);
        assert_eq!(words.0, root.as_os_str().as_bytes());
        assert!(words.2);
        let notice = pin.shape_only_notice().unwrap();
        let warned = root_warnings(&roots::Roots {
            runtime: None,
            config: Some(pin),
            state: Some(d.clone()),
            log: Some(d.clone()),
        });
        assert_eq!(
            warned,
            [
                notice[0].clone(),
                notice[1].clone(),
                en(MsgId::NoRuntimeRoot).to_owned()
            ]
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pin = roots::ConfigRootPin::check(&root, me, &mut Unknown).unwrap();
        assert!(!config_root_words(&pin).2);
        std::fs::remove_dir_all(&d).unwrap();
    }

    // 이것을 실패시키는 것: 빈·상대 pw_dir를 홈으로 받아 뿌리를 cwd 기준으로 만드는 것.
    #[test]
    fn home_must_be_absolute() {
        assert!(!home_is_usable(std::path::Path::new("")));
        assert!(!home_is_usable(std::path::Path::new("home/u")));
        assert!(home_is_usable(std::path::Path::new("/home/u")));
    }
}
