//! `bingsu init <shell>`: stdout carries only the connection script;
//! diagnostics go to stderr (spec section 5 "init output").
pub(crate) mod exe_path;
pub(super) mod pinned;
pub(super) mod prime;
mod render;
pub(super) mod roots;
pub(super) mod trusted_env;

use crate::commands::{ctx, sys};
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
pub(in crate::commands) fn home_is_usable(home: &std::path::Path) -> bool {
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

/// Warm init starts nothing. A missing root leaves nothing to start (init
/// already said so on stderr), so the script goes out alone.
fn prime_cold(
    roots: &roots::Roots,
    user: &ctx::User,
    started: bingsu_core::snapshot::Clock,
    exe: &std::path::Path,
) -> prime::PrimeResult {
    let Ok(request) = ctx::request(exe, roots, user, started) else {
        return prime::PrimeResult::Unavailable;
    };
    let mut spawn = || {
        if let Some(words) = prime::helper_words(roots, &user.pw.home) {
            let raw: Vec<&[u8]> = words.iter().map(Vec::as_slice).collect();
            crate::prompt_spawn::bootstrap(exe.as_os_str(), &raw, None);
        }
    };
    prime::prime_with_deadline(
        &request,
        started.boot,
        std::time::Instant::now() + prime::INIT_LIMIT,
        &mut spawn,
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
    let started = ctx::start();
    let env = trusted_env::TrustedEnv::capture();
    let Some(user) = ctx::User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ExitCode::from(1);
    };
    let (uid, pw) = (user.me, &user.pw);
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
    let exe_safe = match exe_path::check_path(&exe, uid, &pw.name) {
        exe_path::Verdict::Safe => true,
        exe_path::Verdict::Unknown => {
            eprintln!("{}", en(MsgId::TamperUnknown));
            false
        }
        exe_path::Verdict::Tamperable => {
            eprintln!("{}", en(MsgId::Tamperable));
            false
        }
    };
    let collector = if exe_safe {
        exe_path::collector_sibling(
            &exe,
            uid,
            &mut crate::commands::group_policy::SystemGroups::new(&pw.name),
        )
    } else {
        None
    };
    let roots = roots::resolve(&env, &pw.home, &pw.name);
    for line in root_warnings(&roots) {
        eprintln!("{line}");
    }
    // A snapshot of this boot and context means no work. Otherwise one
    // independent helper reads the settings while init waits for it at most
    // INIT_LIMIT; the connection script is printed either way.
    // A binary init just warned about is not started here; the first
    // prompt's helper does the work.
    if let (Some(started), true) = (started, exe_safe) {
        match prime_cold(&roots, &user, started, &exe) {
            prime::PrimeResult::AlreadyReady
            | prime::PrimeResult::Published
            | prime::PrimeResult::Unavailable => {}
            prime::PrimeResult::Invalid => eprintln!("{}", en(MsgId::ColdInitInvalid)),
            prime::PrimeResult::TimedOut => eprintln!("{}", en(MsgId::ColdInitUnfinished)),
        }
    }
    let Some(random) = sys::random_bytes16() else {
        return ExitCode::from(1);
    };
    let session = hex16(random);
    let roots_var = pinned::encode(&roots, &pw.home);
    let inputs = render::ScriptInputs {
        shell,
        exe: exe.as_os_str().as_bytes(),
        collector_exe: collector.as_ref().map(|p| p.as_os_str().as_bytes()),
        runtime_groups: roots
            .runtime
            .as_ref()
            .map_or(&[], |r| r.group_ok.as_slice()),
        runtime_root: roots
            .runtime
            .as_ref()
            .map(|r| (r.dev, r.ino, r.path.as_os_str().as_bytes())),
        config_root: roots.config.as_ref().map(config_root_words),
        state_root: roots.state.as_ref().map(|p| p.as_os_str().as_bytes()),
        log_root: roots.log.as_ref().map(|p| p.as_os_str().as_bytes()),
        roots_var: roots_var.as_deref(),
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

    // Test-only producer consumed by test_init_words.py. The real resolver
    // gets an Unknown oracle; no production environment switch is added.
    // 이것을 실패시키는 것: Undecided pin의 두 경로 또는 shape-only 표식을 셸 렌더에서 잃는 것.
    #[test]
    #[ignore = "fixture producer for the three real shell round trips"]
    #[expect(
        clippy::disallowed_methods,
        reason = "test-only fixture destination, never production input"
    )]
    fn write_shape_only_shell_fixture() {
        use bingsu_core::fs_trust::{Facts, Group, GroupOracle};
        use std::os::unix::fs::{PermissionsExt, symlink};
        struct Unknown;
        impl GroupOracle for Unknown {
            fn group_write(&mut self, _: &Facts) -> Group {
                Group::Unknown
            }
        }
        let base = std::path::PathBuf::from(std::env::var_os("M3A_FIXTURE_DIR").unwrap());
        let base = std::fs::canonicalize(base).unwrap();
        let root = base.join("canonical ' space");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o775)).unwrap();
        let written = base.join("written ' space");
        symlink(root.file_name().unwrap(), &written).unwrap();
        let mut pin =
            roots::ConfigRootPin::check(&written, sys::current_uid(), &mut Unknown).unwrap();
        assert!(pin.shape_only);
        assert_ne!(pin.path, pin.written);
        // The host checks the real paths above; render their spellings at
        // the consumer's mount point (/w in the minimum-shell containers).
        let embedded = std::path::PathBuf::from(std::env::var_os("M3A_FIXTURE_ROOT").unwrap());
        pin.path = embedded.join(pin.path.strip_prefix(&base).unwrap());
        pin.written = embedded.join(pin.written.strip_prefix(&base).unwrap());
        let exe = embedded.join("probe");
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let mut out = Vec::new();
            render::render(
                &render::ScriptInputs {
                    shell,
                    exe: exe.as_os_str().as_bytes(),
                    collector_exe: None,
                    runtime_groups: &[],
                    runtime_root: None,
                    config_root: Some(config_root_words(&pin)),
                    state_root: None,
                    log_root: None,
                    roots_var: None,
                    session_hex: &[b'0'; 32],
                    home: b"/h",
                },
                &mut out,
            );
            let name = match shell {
                Shell::Bash => "bash",
                Shell::Zsh => "zsh",
                Shell::Fish => "fish",
            };
            std::fs::write(base.join(format!("init.{name}")), out).unwrap();
        }
    }

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
