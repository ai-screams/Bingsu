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

/// The roots init pinned in this shell, re-checked now. Only absence may
/// fall back to current XDG; a present but unusable pin must stop all writes.
pub fn pinned_roots(user: &User) -> Result<Option<Roots>, (String, u8)> {
    use std::os::unix::ffi::OsStrExt;
    let Some(value) = TrustedEnv::pinned_roots() else {
        eprintln!("{}", en(MsgId::RootsFromEnvironment));
        return Ok(None);
    };
    pinned::decode(value.as_bytes(), user.me, &user.pw.name, &user.pw.home)
        .map(Some)
        .ok_or_else(|| ("bingsu: the folders pinned in BINGSU_ROOTS no longer match; run bingsu init <shell> again".into(), EXIT_UNFINISHED))
}

/// Every root a command that publishes needs.
pub fn roots_for_publishing(user: &User) -> Result<Roots, (String, u8)> {
    Ok(pinned_roots(user)?
        .unwrap_or_else(|| roots::resolve(&TrustedEnv::capture(), &user.pw.home, &user.pw.name)))
}

/// System errors with an errno are incomplete unless they confirm a path or
/// access failure. Semantic checks use errors without an errno.
pub fn io_exit(e: &std::io::Error) -> u8 {
    match e.raw_os_error() {
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::EACCES | libc::EPERM) | None => {
            EXIT_FAILED
        }
        Some(_) => EXIT_UNFINISHED,
    }
}

/// What the engine needs, or the fixed message for what is missing.
pub fn request(
    exe: &Path,
    roots: &Roots,
    user: &User,
    started: Clock,
) -> Result<RefreshRequest, MsgId> {
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
        build: super::build_identity::read(exe),
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
pub fn apply(
    exe: &Path,
    roots: &Roots,
    user: &User,
    started: Clock,
    clock: &mut dyn ClockSource,
) -> Applied {
    match request(exe, roots, user, started) {
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
pub struct Deadline(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Deadline {
    pub fn selection_saved(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

fn deadline_text(saved: bool, text: &str) -> &str {
    if saved {
        "bingsu: your choice was saved; applying it did not finish before the deadline\n"
    } else {
        text
    }
}

fn require_watchdog<T>(result: std::io::Result<T>) -> Result<T, u8> {
    result.map_err(|_| {
        sys::write_deadline_notice(
            b"bingsu: cannot start the deadline watchdog; nothing was changed\n",
        );
        EXIT_UNFINISHED
    })
}

pub fn arm_deadline(limit: Duration, text: String) -> Result<Deadline, u8> {
    let saved = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stage = saved.clone();
    let end = std::time::Instant::now() + limit;
    require_watchdog(
        std::thread::Builder::new()
            .name("deadline".into())
            .spawn(move || {
                std::thread::sleep(end.saturating_duration_since(std::time::Instant::now()));
                let text = deadline_text(stage.load(std::sync::atomic::Ordering::Acquire), &text);
                sys::write_deadline_notice(text.as_bytes());
                sys::exit_now(i32::from(EXIT_UNFINISHED));
            }),
    )?;
    Ok(Deadline(saved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_creation_failure_stops_the_command() {
        assert_eq!(
            require_watchdog::<()>(Err(std::io::Error::from_raw_os_error(libc::EAGAIN))),
            Err(3)
        );
    }

    #[test]
    fn selection_saved_stage_changes_deadline_message() {
        let d = Deadline(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false,
        )));
        assert_eq!(
            deadline_text(d.0.load(std::sync::atomic::Ordering::Acquire), "generic"),
            "generic"
        );
        d.selection_saved();
        let text = deadline_text(d.0.load(std::sync::atomic::Ordering::Acquire), "generic");
        assert!(text.contains("choice was saved"));
        assert!(text.contains("applying it did not finish"));
    }

    #[test]
    fn io_failures_are_not_configuration_failures() {
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::EIO,
            libc::ENOMEM,
            libc::ENOSPC,
        ] {
            assert_eq!(io_exit(&std::io::Error::from_raw_os_error(errno)), 3);
        }
        for errno in [libc::ENOENT, libc::ENOTDIR, libc::ELOOP, libc::EACCES] {
            assert_eq!(io_exit(&std::io::Error::from_raw_os_error(errno)), 1);
        }
    }

    #[test]
    fn deadline_exits_even_when_stderr_is_full() {
        use std::io::Write;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let (_reader, mut writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        while writer.write(&[b'x'; 4096]).is_ok() {}
        writer.set_nonblocking(false).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::ctx::tests::deadline_child",
                "--ignored",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(OwnedFd::from(writer)))
            .spawn()
            .unwrap();
        let end = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(3));
                break;
            }
            if std::time::Instant::now() >= end {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("deadline blocked on full stderr");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // The child half of `deadline_ends_the_process_with_3`: it arms a short deadline and then stays busy.
    #[test]
    #[ignore = "runs inside the child process of deadline_ends_the_process_with_3"]
    fn deadline_child() {
        arm_deadline(Duration::from_millis(50), "bingsu: test deadline\n".into()).unwrap();
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
