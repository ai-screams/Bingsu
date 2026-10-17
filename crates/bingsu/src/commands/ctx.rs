//! What the user commands (`init`, `reload`, `config …`) share: who the user
//! is, the request the N2 publication engine takes, and how a command ends.
//! Exit codes: 0 success, 1 a confirmed settings or trust failure, 2 usage,
//! 3 not finished (busy, deadline, resources, I/O).
use super::{
    clock::SystemClock,
    init::{
        home_is_usable, pinned,
        roots::{self, Roots},
        trusted_env::TrustedEnv,
    },
    messages::{MsgId, en},
    refresh::{self, RefreshRequest, RefreshResult},
    runtime_root::Pinned,
    sys,
};
use bingsu_core::snapshot::{Clock, ClockSource};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

pub const EXIT_FAILED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_UNFINISHED: u8 = 3;

/// A command that changes things may not run longer than the publication
/// engine's own life (2 s) plus the time it needs to unwind.
pub const COMMAND_LIMIT: Duration = Duration::from_secs(3);

pub fn code(n: u8) -> ExitCode {
    ExitCode::from(n)
}

pub struct User {
    pub me: u32,
    pub pw: sys::Passwd,
}

impl User {
    /// `None`: the account or its home folder cannot be read.
    pub fn current() -> Option<Self> {
        let me = sys::current_uid();
        let pw = sys::passwd_entry(me).filter(|pw| home_is_usable(&pw.home))?;
        Some(Self { me, pw })
    }
}

pub fn version() -> [u32; 3] {
    parse_version(bingsu_core::VERSION)
}

fn parse_version(text: &str) -> [u32; 3] {
    let mut parts = text.split('.').map(|n| n.parse().unwrap_or(0));
    let mut next = || parts.next().unwrap_or(0);
    [next(), next(), next()]
}

/// A path for a message: control bytes and escapes cannot reach the terminal.
pub fn show(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    bingsu_core::sanitize::sanitize(p.as_os_str().as_bytes())
}

/// One write of the command's product to stdout.
pub fn print(text: &str) -> bool {
    sys::write_fd(1, text.as_bytes()) == sys::WriteOutcome::Done
}

/// The roots init pinned in this shell (`BINGSU_ROOTS`), re-checked now.
/// `None`, after one stderr line, when the variable is absent, garbled,
/// forged or no longer matches: the caller then resolves from the
/// environment, as init does.
pub fn pinned_roots(user: &User) -> Option<Roots> {
    use std::os::unix::ffi::OsStrExt;
    let found = TrustedEnv::pinned_roots()
        .and_then(|v| pinned::decode(v.as_bytes(), user.me, &user.pw.name, &user.pw.home));
    if found.is_none() {
        eprintln!("{}", en(MsgId::RootsFromEnvironment));
    }
    found
}

/// Every root a command that publishes needs.
pub fn roots_for_publishing(user: &User) -> Roots {
    pinned_roots(user)
        .unwrap_or_else(|| roots::resolve(&TrustedEnv::capture(), &user.pw.home, &user.pw.name))
}

/// What the engine needs, or the fixed message for what is missing.
pub fn request(roots: &Roots, user: &User, started: Clock) -> Result<RefreshRequest, MsgId> {
    let runtime = roots.runtime.as_ref().ok_or(MsgId::NoRuntimeRoot)?;
    let (Some(config), Some(state)) = (roots.config.as_ref(), roots.state.as_ref()) else {
        return Err(MsgId::UnconfirmedRoot);
    };
    Ok(RefreshRequest {
        runtime: Pinned {
            dev: runtime.dev,
            ino: runtime.ino,
            path: runtime.path.clone(),
        },
        config_written: config.written.clone(),
        config_canonical: config.path.clone(),
        config_root_shape_only: config.shape_only,
        state_root: state.clone(),
        home: user.pw.home.clone(),
        me: user.me,
        user: user.pw.name.clone(),
        version: version(),
        process_started: started,
    })
}

/// How an application of the settings ended, in the words users see.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    Published {
        generation: u64,
        left_out: Vec<PathBuf>,
    },
    Unchanged {
        generation: u64,
    },
    Invalid,
    Busy,
    Incomplete,
    Unavailable(MsgId),
}

/// The one way a command publishes: the N2 engine, same locks, same
/// source evidence, same deadline as the refresh helper.
pub fn apply(roots: &Roots, user: &User, started: Clock, clock: &mut dyn ClockSource) -> Applied {
    match request(roots, user, started) {
        Ok(r) => match refresh::refresh(r, clock) {
            RefreshResult::Published {
                generation,
                left_out,
            } => Applied::Published {
                generation,
                left_out,
            },
            RefreshResult::Revalidated { generation } => Applied::Unchanged { generation },
            RefreshResult::Invalid => Applied::Invalid,
            RefreshResult::Busy => Applied::Busy,
            RefreshResult::Incomplete => Applied::Incomplete,
        },
        Err(m) => Applied::Unavailable(m),
    }
}

/// Observes the clock at command entry, before any root or NSS lookup.
pub fn start() -> Option<Clock> {
    SystemClock.observe().ok()
}

/// A hard stop: the engine's budget is cooperative, so a source on a
/// stalled mount could keep a command in the kernel. Past `limit` the
/// process says so and ends with "not finished".
pub fn arm_deadline(limit: Duration, text: String) {
    let _ = std::thread::Builder::new()
        .name("deadline".into())
        .spawn(move || {
            std::thread::sleep(limit);
            let _ = sys::write_fd(2, text.as_bytes());
            sys::exit_now(i32::from(EXIT_UNFINISHED));
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    // The child half of `deadline_ends_the_process_with_3`: it arms a short deadline and then stays busy.
    #[test]
    #[ignore = "runs inside the child process of deadline_ends_the_process_with_3"]
    fn deadline_child() {
        arm_deadline(Duration::from_millis(50), "bingsu: test deadline\n".into());
        std::thread::sleep(Duration::from_secs(20));
    }

    // 이것을 실패시키는 것: 한도가 지나도 프로세스를 끝내지 않는 것(막힌 원본에서 명령이 멈춤), 종료 코드를 3이 아니게 내는 것, 문구를 빼는 것.
    #[test]
    fn deadline_ends_the_process_with_3() {
        let t = std::time::Instant::now();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::ctx::tests::deadline_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("bingsu: test deadline\n"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(t.elapsed() < Duration::from_secs(15));
    }

    // 이것을 실패시키는 것: 버전을 세 숫자로 읽지 못해 요청의 version이 0.0.0이 되는 것, 숫자가 모자란 버전에서 어긋나는 것.
    #[test]
    fn version_text_is_three_numbers() {
        assert_eq!(parse_version("1.22.333"), [1, 22, 333]);
        assert_eq!(parse_version("0.3"), [0, 3, 0]);
        assert_eq!(parse_version("1.2.3-rc.4"), [1, 2, 0]);
        assert_eq!(version(), parse_version(env!("CARGO_PKG_VERSION")));
    }
}
