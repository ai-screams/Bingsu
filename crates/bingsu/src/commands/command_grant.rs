//! The refresh helper's side of a command round (U-1 C+, U-15 Q1): whether
//! this round has config units to run, the session lock, the grant built in
//! memory from the compiled config the helper holds (never by decoding the
//! published snapshot again), the supervisor spawned before the helper's
//! filter, and, once the marker is installed, the one grant, the results
//! and the done frame. The helper keeps the grant pipe's write end until it
//! has every result, so its end of file tells the supervisor the helper is
//! gone. Results are checked and dropped here; publishing them is C4.
use super::{
    collection_store::close_only_lock,
    collector_process::{OwnedChild, now_ns, pipe},
    command_process, exec_path,
    group_policy::SystemGroups,
    helper::NoEnv,
    snapshot_store::StoreError,
    sys,
};
use bingsu_core::{
    collection::cwd_hash::sha256,
    command::{
        plan::{self, Environ},
        wire::{self, Grant, Message, Outcome, Policy, Unit, policy_digest},
    },
    config::compile::CompiledConfig,
    handoff::{self, Cwd, ExecFrame, Origin, Permit},
    snapshot::{Marker, T_NS},
};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

/// The shell to run an `unsafe_shell` script with: a fixed path, resolved
/// by the same rules as any executable, never looked up in `PATH`.
const SHELL: &[u8] = b"/bin/sh";
/// The neutral working folder in the runtime root (spec: empty).
const NEUTRAL: &str = "neutral";
pub(crate) const NEUTRAL_REFUSED: &str =
    "command round: the neutral folder is not empty, the user's and 0500; its units do not run";

/// What the helper knows before it decides on a round.
pub(crate) struct Inputs<'a> {
    pub config: &'a CompiledConfig,
    pub session: Option<&'a [u8]>,
    pub pwd: Option<&'a [u8]>,
    pub environment: &'a Result<Vec<u8>, NoEnv>,
    pub runtime: &'a File,
    pub runtime_path: &'a Path,
    pub exe: &'a OsStr,
    pub me: u32,
    pub helper_deadline: u64,
}

/// Why a round runs no supervisor, for the helper's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Skip {
    /// No config unit may run (none, or all with a `not_run` reason).
    NoUnits,
    NoEnvironment(NoEnv),
    /// No session value or no shell folder in the envelope.
    NoSession,
    /// Another supervisor of this session holds the lock.
    Busy,
    /// No trusted relay on this platform yet (macOS, C2 ruling J3).
    NoRelay,
    /// Every unit runs in the neutral folder, which is not empty, the
    /// user's and 0500.
    Neutral,
    Failed,
}
impl Skip {
    pub(crate) fn message(self) -> Option<&'static str> {
        Some(match self {
            Self::NoUnits => return None,
            Self::NoSession => "command round skipped: no session value from the shell",
            Self::NoRelay => "command round skipped: no trusted relay on this platform",
            Self::Neutral => NEUTRAL_REFUSED,
            Self::NoEnvironment(why) => why.message(),
            Self::Busy => "command round busy: the session's supervisor is still running",
            Self::Failed => "command round failed: supervisor not started",
        })
    }
}

/// A started supervisor waiting for its grant. The grant's units are
/// resolved only after publication: walking the sanitized `PATH` and the
/// shell's folder can block on a stopped mount, which must never hold the
/// marker back.
pub(crate) struct Round {
    child: OwnedChild,
    /// Everything but the units and the permit.
    grant: Grant,
    runnable: Vec<(String, plan::Runnable)>,
    environment: Vec<u8>,
    grant_pipe: File,
    results: File,
    /// The session lock; the supervisor holds its own copy.
    _lock: File,
    /// Units left out because the neutral folder failed its check.
    pub neutral_refused: usize,
}

/// `command-<first 16 bytes of sha256(session), hex>.lock`: a fixed-length
/// name, never the raw session value.
fn lock_name(session: &[u8]) -> String {
    let d = sha256(session);
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("command-{hex}.lock")
}

/// The neutral folder (spec: an empty private folder): made 0500 when
/// missing, so read and search work and nothing can be written in it, by
/// a unit either. One that is there must be empty, the user's and exactly
/// 0500; otherwise `neutral` units do not run this round. It is never
/// repaired or emptied.
fn neutral(runtime: &File, me: u32) -> Result<bool, StoreError> {
    let name = OsStr::new(NEUTRAL);
    let made = sys::mkdir_at(runtime.as_fd(), name, 0o500)?;
    let dir = sys::open_dir_at_nofollow(runtime.as_fd(), name)?;
    // Only a folder this call made is set (a umask can take bits from it).
    if made {
        use std::os::unix::fs::PermissionsExt;
        dir.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    }
    let facts = sys::fd_facts(dir.as_fd())?;
    Ok(facts.uid == me
        && facts.mode & 0o7777 == 0o500
        && sys::directory_names(dir.as_fd())?.is_empty())
}

/// Decides the round and, when it has units, takes the session lock and
/// spawns the supervisor. Only the runtime root is touched here, before the
/// marker; the units are resolved in `Round::grant`, after it.
pub(crate) fn prepare(i: &Inputs<'_>) -> Result<Round, Skip> {
    let runnable: Vec<_> = i
        .config
        .exec_units
        .iter()
        .filter_map(|u| plan::runnable(u).map(|r| (u.id.as_str(), r)))
        .collect();
    if runnable.is_empty() {
        return Err(Skip::NoUnits);
    }
    if cfg!(not(target_os = "linux")) {
        return Err(Skip::NoRelay);
    }
    let body = i
        .environment
        .as_ref()
        .map_err(|why| Skip::NoEnvironment(*why))?;
    let (Some(session), Some(pwd)) = (i.session, i.pwd) else {
        return Err(Skip::NoSession);
    };
    let lock =
        close_only_lock(i.runtime, &lock_name(session), i.me, true).map_err(|e| match e {
            StoreError::Busy => Skip::Busy,
            _ => Skip::Failed,
        })?;
    let mut runnable = runnable;
    let mut neutral_refused = 0;
    if !neutral(i.runtime, i.me).map_err(|_| Skip::Failed)? {
        let before = runnable.len();
        runnable.retain(|(_, r)| r.cwd != Cwd::Neutral);
        neutral_refused = before - runnable.len();
        if runnable.is_empty() {
            return Err(Skip::Neutral);
        }
    }
    let grant = Grant {
        permit: Permit {
            kind: 0,
            deadline: 0,
            boot: [0; 16],
            resume: 0,
            domain: [0; 16],
        },
        helper_deadline: i.helper_deadline,
        cwd: pwd.to_vec(),
        neutral: i
            .runtime_path
            .join(NEUTRAL)
            .into_os_string()
            .into_encoded_bytes(),
        units: Vec::new(),
        probes: Vec::new(),
    };
    let (grant_read, grant_pipe) = pipe().map_err(|_| Skip::Failed)?;
    let (results, results_write) = pipe().map_err(|_| Skip::Failed)?;
    super::collector_process::nonblocking(&grant_pipe).map_err(|_| Skip::Failed)?;
    super::collector_process::nonblocking(&results).map_err(|_| Skip::Failed)?;
    let exe = CString::new(i.exe.as_bytes()).map_err(|_| Skip::Failed)?;
    let args = [
        i.exe.as_bytes().to_vec(),
        super::command_supervisor::ENTRY.as_bytes().to_vec(),
    ];
    let child = command_process::spawn_supervisor(
        &exe,
        &args,
        &grant_read,
        &results_write,
        &lock,
        i.helper_deadline,
    )
    .map_err(|_| Skip::Failed)?;
    Ok(Round {
        child,
        grant,
        runnable: runnable
            .into_iter()
            .map(|(id, r)| (id.to_owned(), r))
            .collect(),
        environment: body.clone(),
        grant_pipe,
        results,
        _lock: lock,
        neutral_refused,
    })
}

/// The grant's units and what was left out.
#[derive(Debug, Default)]
struct Resolved {
    units: Vec<Unit>,
    /// Executable not found or failed the checks.
    unresolved: usize,
    /// Over the relay's input cap, or past the grant frame's room.
    oversize: usize,
    /// No collected repository root: the shell's folder stood for it.
    repo_fallback: bool,
    dropped: plan::Dropped,
}

/// The grant's units: at most `CONFIG_MAX` runnable units whose executable
/// resolves from the sanitized `PATH` (or `/bin/sh` for a script), each with
/// its target environment and the digest of its policy before `{dir}`. A
/// unit whose relay input would pass `RELAY_INPUT_MAX`, or that would push
/// the grant past one frame, is left out alone; the others still run.
fn units(
    runnable: &[(String, plan::Runnable)],
    environment: &[u8],
    base: &Grant,
    collected: Option<u16>,
    me: u32,
    groups: &mut SystemGroups,
) -> Result<Resolved, Skip> {
    let mut out = Resolved {
        repo_fallback: collected.is_none(),
        ..Resolved::default()
    };
    // The repository the shell is in, by identity, for the PATH and
    // executable rules (C2 ruling J9): the root this round's collection
    // reported, else the shell's own folder (one statx, command rounds
    // only). A folder that cannot be read refuses the round.
    let folder = plan::repo_folder(&base.cwd, collected);
    let repo = exec_path::repo_id(Some(Path::new(OsStr::from_bytes(&folder))))
        .map_err(|_| Skip::Failed)?;
    let vars = Environ::parse(environment);
    out.dropped = vars.dropped;
    let folders = exec_path::sanitize(vars.get(b"PATH").unwrap_or_default(), repo, me, groups);
    let path = exec_path::path_value(&folders);
    let attempts: Vec<(&str, Option<u64>)> =
        runnable.iter().map(|(id, _)| (id.as_str(), None)).collect();
    let mut trial = base.clone();
    for at in plan::pick(&attempts, plan::CONFIG_MAX) {
        let (id, r) = &runnable[at];
        let word = match &r.policy {
            Policy::Argv { argv } => argv[0].as_slice(),
            Policy::UnsafeShell { .. } => SHELL,
        };
        let Ok(found) = exec_path::lookup(word, &folders, repo, me, groups) else {
            out.unresolved += 1;
            continue;
        };
        let unit = Unit {
            id: id.clone(),
            digest: policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow),
            policy: r.policy.clone(),
            cwd: r.cwd,
            environment: plan::target_environment(&vars, &r.env_allow, &path),
            timeout: r.timeout,
            env_allow: r.env_allow.clone(),
            executable: found.executable.into_os_string().into_encoded_bytes(),
            pin: found.pin,
            interpreter: found.interpreter,
        };
        let frame = ExecFrame {
            origin: Origin::Config,
            run_deadline: 0,
            environment: unit.environment.clone(),
            pin: unit.pin,
            interpreter: unit.interpreter.clone(),
            cwd: match unit.cwd {
                Cwd::Neutral => base.neutral.clone(),
                Cwd::UntrustedCurrent => base.cwd.clone(),
            },
        };
        if handoff::relay_input(base.permit, &frame, handoff::RELAY_INPUT_MAX).is_err() {
            out.oversize += 1;
            continue;
        }
        trial.units.push(unit);
        if wire::encode(&Message::Grant(trial.clone())).is_err() {
            trial.units.pop();
            out.oversize += 1;
        }
    }
    out.units = trial.units;
    Ok(out)
}

/// Writes all of `bytes` to the non-blocking `fd` by `until_ns`, waiting in
/// `poll` when the pipe is full: the supervisor reads the grant while it
/// arrives, and a pipe can be smaller than the frame (pipe-user-pages-soft
/// leaves 4 KB pipes, m6-C1a).
fn send(fd: i32, bytes: &[u8], until_ns: u64) -> bool {
    send_with(
        bytes,
        until_ns,
        &mut || now_ns().ok(),
        &mut |b: &[u8]| {
            // SAFETY: `b` is readable for its length.
            let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
            usize::try_from(n)
                .map_err(|_| std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        },
        &mut |wait_ms| {
            let mut fds = [libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            }];
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(fds.as_mut_ptr(), 1, wait_ms) };
        },
    )
}

/// `send` with its clock, write and wait passed in (tests replace them).
fn send_with(
    mut bytes: &[u8],
    until_ns: u64,
    now: &mut dyn FnMut() -> Option<u64>,
    write: &mut dyn FnMut(&[u8]) -> Result<usize, i32>,
    wait: &mut dyn FnMut(i32),
) -> bool {
    while !bytes.is_empty() {
        // Before the first write and every retry: a late grant is no grant.
        let Some(at) = now().filter(|&at| at < until_ns) else {
            return false;
        };
        match write(bytes) {
            Ok(n) => {
                bytes = &bytes[n..];
                continue;
            }
            Err(libc::EAGAIN | libc::EINTR) => {}
            Err(_) => return false,
        }
        wait(i32::try_from((until_ns - at).div_ceil(1_000_000)).unwrap_or(i32::MAX));
    }
    true
}

/// The permit of the marker this round installed: its clock and trust
/// deadline `verified_at + T`, or deadline 0 for an invalid marker (config
/// units are then refused; builtin probes still run).
pub(crate) fn permit(marker: &Marker) -> Permit {
    Permit {
        kind: marker.kind,
        deadline: if marker.invalid {
            0
        } else {
            marker.verified_at.saturating_add(T_NS)
        },
        boot: marker.id.boot,
        resume: marker.resume,
        domain: marker.domain,
    }
}

/// What came back from one round.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub results: Vec<Outcome>,
    /// Frames that did not decode or did not name a place in the grant.
    pub rejected: usize,
    /// Units left out because their executable was not found or failed the checks.
    pub unresolved: usize,
    /// The shell's folder could not be read: no grant.
    pub failed: bool,
    /// Units over the relay input cap or past the grant frame's room.
    pub oversize: usize,
    /// No collected repository root; the shell's folder stood for it.
    pub repo_fallback: bool,
    /// Environment entries left out (`=` missing, empty, duplicate names).
    pub dropped: plan::Dropped,
    /// The grant could not be written in time: nothing ran.
    pub send_failed: bool,
}

impl Round {
    /// Without publication: no grant. Closing the pipe tells the supervisor
    /// to run nothing; it is then waited for until the helper's deadline.
    pub(crate) fn abandon(self) {
        let deadline = self.grant.helper_deadline;
        let Self {
            mut child,
            grant_pipe,
            ..
        } = self;
        drop(grant_pipe);
        wait(&mut child, deadline);
    }

    /// Sends the grant under `permit`, reads every result until the helper's
    /// deadline less the reserve, then writes done and closes the pipe.
    /// `repo`: the repository component this round's collection reported
    /// for the shell's folder, if it ran (C2 ruling J9).
    pub(crate) fn grant(
        mut self,
        permit: Permit,
        repo: Option<u16>,
        me: u32,
        groups: &mut SystemGroups,
    ) -> Report {
        self.grant.permit = permit;
        let mut report = Report::default();
        match units(
            &self.runnable,
            &self.environment,
            &self.grant,
            repo,
            me,
            groups,
        ) {
            Ok(resolved) => {
                report.unresolved = resolved.unresolved;
                report.oversize = resolved.oversize;
                report.repo_fallback = resolved.repo_fallback;
                report.dropped = resolved.dropped;
                self.grant.units = resolved.units;
                if self.grant.units.is_empty() {
                    self.abandon();
                    return report;
                }
            }
            Err(_) => {
                report.failed = true;
                self.abandon();
                return report;
            }
        }
        let end = self
            .grant
            .helper_deadline
            .saturating_sub(super::command_supervisor::BUDGET.reserve / 2);
        // units() kept the grant within one frame, so this encodes.
        let Ok(frame) = wire::encode(&Message::Grant(self.grant.clone())) else {
            report.send_failed = true;
            self.abandon();
            return report;
        };
        // A short grant is a cut one, which the supervisor refuses whole.
        if !send(self.grant_pipe.as_raw_fd(), &frame, end) {
            report.send_failed = true;
            self.abandon();
            return report;
        }
        let want = self.grant.units.len() + self.grant.probes.len();
        let mut bytes = Vec::new();
        let mut chunk = vec![0u8; wire::FRAME_MAX];
        while report.results.len() + report.rejected < want {
            let Ok(now) = now_ns() else { break };
            if now >= end {
                break;
            }
            let mut fds = [libc::pollfd {
                fd: self.results.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let wait = i32::try_from((end - now).div_ceil(1_000_000)).unwrap_or(i32::MAX);
            // SAFETY: one valid pollfd.
            if unsafe { libc::poll(fds.as_mut_ptr(), 1, wait) } < 0 {
                break;
            }
            // SAFETY: `chunk` is writable for its length.
            let n = unsafe {
                libc::read(
                    self.results.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            match usize::try_from(n) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                Err(_) => continue,
            }
            while bytes.len() >= wire::HEADER {
                let Ok(total) = wire::frame_len(&bytes[..wire::HEADER]) else {
                    report.rejected = want;
                    break;
                };
                if bytes.len() < total {
                    break;
                }
                match wire::decode(&bytes[..total]) {
                    Ok(Message::Result(o)) if plan::result_fits(&self.grant, &o) => {
                        report.results.push(o)
                    }
                    _ => report.rejected += 1,
                }
                bytes.drain(..total);
            }
        }
        if let Ok(done) = wire::encode(&Message::Done) {
            let _ = sys::write_fd(self.grant_pipe.as_raw_fd(), &done);
        }
        self.abandon();
        report
    }
}

/// Waits for the supervisor to exit (it ends its children first) until the
/// helper's deadline; the drop then kills and reaps whatever is left.
fn wait(child: &mut OwnedChild, deadline: u64) {
    while matches!(child.reap(), Ok(false)) && now_ns().is_ok_and(|now| now < deadline) {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::snapshot::Identity;

    fn runnable(id: &str, env_allow: &[&str]) -> (String, plan::Runnable) {
        (
            id.to_owned(),
            plan::Runnable {
                policy: Policy::Argv {
                    argv: vec![b"/usr/bin/true".to_vec()],
                },
                cwd: Cwd::Neutral,
                timeout: plan::TIMEOUT_DEFAULT,
                env_allow: env_allow.iter().map(|n| n.as_bytes().to_vec()).collect(),
            },
        )
    }
    fn base() -> Grant {
        Grant {
            permit: Permit {
                kind: 1,
                deadline: 9,
                boot: [1; 16],
                resume: 0,
                domain: [2; 16],
            },
            helper_deadline: 9,
            // A folder of its own stands for the repository (no collected root).
            cwd: std::env::temp_dir().into_os_string().into_encoded_bytes(),
            neutral: b"/tmp".to_vec(),
            units: Vec::new(),
            probes: Vec::new(),
        }
    }
    fn groups() -> SystemGroups {
        SystemGroups::new(&sys::passwd_entry(sys::current_uid()).unwrap().name)
    }

    // M4·M-2: 상한을 넘는 단위만 빠지고 나머지는 돈다. 이것을 실패시키는 것: units()의 relay 입력 상한 검사를
    // 지우는 것(20 KB 환경 단위가 허가에 남음), 허가 전체 encode 검사를 지우는 것(여덟 단위 × 15 KB가 한 프레임을
    // 넘어 회차 전체가 실패함).
    #[test]
    fn oversize_units_are_left_out_alone() {
        let big = |n: usize| {
            [
                b"PATH=/usr/bin:/bin\0BIG=".as_slice(),
                &vec![b'x'; n],
                b"\0",
            ]
            .concat()
        };
        let units20 = vec![
            runnable("custom/big", &["BIG"]),
            runnable("custom/small", &[]),
        ];
        let got = units(
            &units20,
            &big(20 * 1024),
            &base(),
            None,
            sys::current_uid(),
            &mut groups(),
        )
        .unwrap();
        assert_eq!((got.units.len(), got.oversize), (1, 1));
        assert_eq!(got.units[0].id, "custom/small");
        let eight: Vec<_> = (0..8)
            .map(|i| runnable(&format!("custom/u{i}"), &["BIG"]))
            .collect();
        let got = units(
            &eight,
            &big(15 * 1024),
            &base(),
            None,
            sys::current_uid(),
            &mut groups(),
        )
        .unwrap();
        assert!(
            got.oversize > 0 && !got.units.is_empty(),
            "{} {}",
            got.units.len(),
            got.oversize
        );
        let mut g = base();
        g.units = got.units;
        assert!(wire::encode(&Message::Grant(g)).is_ok());
    }

    // J9·L5: 수집 루트가 없으면 대체를 알리고, 버린 환경 항목 수를 센다. 이것을 실패시키는 것: repo_fallback을
    // 늘 false로 두는 것, dropped를 옮기지 않는 것.
    #[test]
    fn units_report_the_fallback_and_dropped_entries() {
        let env = b"PATH=/usr/bin:/bin\0NOEQ\0X=1\0X=2\0";
        let got = units(
            &[runnable("custom/a", &[])],
            env,
            &base(),
            None,
            sys::current_uid(),
            &mut groups(),
        )
        .unwrap();
        assert!(got.repo_fallback);
        assert_eq!(
            got.dropped,
            plan::Dropped {
                malformed: 1,
                duplicate: 1
            }
        );
        let got = units(
            &[runnable("custom/a", &[])],
            env,
            &base(),
            Some(0),
            sys::current_uid(),
            &mut groups(),
        )
        .unwrap();
        assert!(!got.repo_fallback);
    }

    // M4: 허가는 4 KB 파이프에서도 감독이 읽는 동안 이어 써서 끝까지 간다. 읽는 쪽이 없으면 마감에 실패한다.
    // 이것을 실패시키는 것: send가 EAGAIN이나 부분 쓰기에서 멈추는 것(write 한 번만).
    #[cfg(target_os = "linux")]
    #[test]
    fn grant_send_waits_for_a_small_pipe() {
        let (read, write) = pipe().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        // SAFETY: F_SETPIPE_SZ on the test's own pipe.
        assert!(unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } >= 4096);
        let frame = vec![7u8; 40 * 1024];
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut got = Vec::new();
            let mut read = read;
            let mut buf = [0u8; 1024];
            while let Ok(n) = read.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            got.len()
        });
        let until = now_ns().unwrap() + 2_000_000_000;
        assert!(send(write.as_raw_fd(), &frame, until));
        drop(write);
        assert_eq!(reader.join().unwrap(), frame.len());
        // Nobody reads: the deadline ends it.
        let (_read, write) = pipe().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        // SAFETY: as above.
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
        let until = now_ns().unwrap() + 50_000_000;
        assert!(!send(write.as_raw_fd(), &frame, until));
    }

    // 첫 부분 쓰기 뒤에 마감이 지나면 다음 write를 하지 않는다(시계·write 주입). 이것을 실패시키는 것:
    // send_with의 쓰기 전 마감 검사를 지우는 것(둘째 write가 일어남).
    #[test]
    fn grant_send_stops_writing_once_its_deadline_passes() {
        let mut calls = 0;
        let mut clock = [10, 200, 300].into_iter();
        let mut writes = 0;
        let sent = send_with(
            b"0123456789",
            100,
            &mut || {
                calls += 1;
                clock.next()
            },
            &mut |b: &[u8]| {
                writes += 1;
                Ok(3.min(b.len()))
            },
            &mut |_| {},
        );
        assert!(!sent);
        assert_eq!(writes, 1, "the partial write, then the deadline");
        assert_eq!(calls, 2);
    }

    // 마감이 지난 뒤에는 빈 파이프라도 쓰지 않는다. 이것을 실패시키는 것: send의 쓰기 전 마감 검사를 지우는 것.
    #[test]
    fn grant_send_writes_nothing_past_its_deadline() {
        let (read, write) = pipe().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        super::super::collector_process::nonblocking(&read).unwrap();
        let past = now_ns().unwrap() - 1;
        assert!(!send(write.as_raw_fd(), b"grant", past));
        let mut b = [0u8; 8];
        // SAFETY: writable buffer; non-blocking read end.
        let n = unsafe { libc::read(read.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) };
        assert!(n < 0, "nothing was written");
    }

    // 무효 표식 회차의 permit은 deadline 0이라 설정 단위가 모두 거부된다(내장 조사만). 이것을 실패시키는
    // 것: permit()의 `marker.invalid` 분기를 지우는 것, T를 더하지 않는 것.
    #[test]
    fn permit_follows_the_installed_marker() {
        let marker = Marker {
            id: Identity {
                boot: [7; 16],
                epoch: [0; 16],
                context: [0; 4],
                generation: 3,
                source: [0; 4],
            },
            seq: 1,
            verified_at: 1_000,
            kind: 1,
            domain: [9; 16],
            resume: 2,
            invalid: false,
        };
        assert_eq!(
            permit(&marker),
            Permit {
                kind: 1,
                deadline: 1_000 + T_NS,
                boot: [7; 16],
                resume: 2,
                domain: [9; 16],
            }
        );
        let invalid = Marker {
            invalid: true,
            ..marker
        };
        assert_eq!(permit(&invalid).deadline, 0);
    }

    // 파일 이름에는 세션 값이 아니라 고정 길이 요약값만. 이것을 실패시키는 것: lock_name이 세션 값을
    // 그대로 쓰는 것.
    #[test]
    fn lock_name_is_a_digest() {
        let name = lock_name(b"0123456789abcdef0123456789abcdef");
        assert_eq!(name.len(), "command-".len() + 32 + ".lock".len());
        assert!(!name.contains("0123456789abcdef"));
        assert_ne!(name, lock_name(b"fedcba9876543210fedcba9876543210"));
    }
}
