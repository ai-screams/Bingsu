//! `bingsu init <shell>`: stdout carries only the connection script;
//! diagnostics go to stderr (spec section 5 "init output").
pub(crate) mod exe_path;
mod render;
mod roots;
mod trusted_env;

use crate::sys;
use bingsu_core::shell_word::Shell;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use crate::messages::{MsgId, en};

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
    let roots = roots::resolve(&env, &pw.home);
    if roots.config.is_none() || roots.state.is_none() || roots.log.is_none() {
        eprintln!("{}", en(MsgId::UnconfirmedRoot));
    }
    if roots.runtime.is_none() {
        eprintln!("{}", en(MsgId::NoRuntimeRoot));
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
        config_root: roots.config.as_ref().map(|p| p.as_os_str().as_bytes()),
        state_root: roots.state.as_ref().map(|p| p.as_os_str().as_bytes()),
        log_root: roots.log.as_ref().map(|p| p.as_os_str().as_bytes()),
        session_hex: &session,
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

    // 이것을 실패시키는 것: 빈·상대 pw_dir를 홈으로 받아 뿌리를 cwd 기준으로 만드는 것.
    #[test]
    fn home_must_be_absolute() {
        assert!(!home_is_usable(std::path::Path::new("")));
        assert!(!home_is_usable(std::path::Path::new("home/u")));
        assert!(home_is_usable(std::path::Path::new("/home/u")));
    }
}
