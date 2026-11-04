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
    fs_trust::{Last, NextOwner, RefuseGroupWrite, final_verdict},
    handoff::Permit,
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
/// The neutral working folder in the runtime root (spec: empty, 0700).
const NEUTRAL: &str = "neutral";

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
    /// No unit's executable could be resolved.
    Unresolved,
    /// No trusted relay on this platform yet (macOS, C2 ruling J3).
    NoRelay,
    Failed,
}
impl Skip {
    pub(crate) fn message(self) -> Option<&'static str> {
        Some(match self {
            Self::NoUnits | Self::NoSession | Self::NoRelay => return None,
            Self::NoEnvironment(why) => why.message(),
            Self::Busy => "command round busy: the session's supervisor is still running",
            Self::Unresolved => "command round skipped: no unit's executable passed the checks",
            Self::Failed => "command round failed: supervisor not started",
        })
    }
}

/// A started supervisor waiting for its grant.
pub(crate) struct Round {
    child: OwnedChild,
    grant: Grant,
    grant_pipe: File,
    results: File,
    /// The session lock; the supervisor holds its own copy.
    _lock: File,
    /// Units left out because their executable failed the checks.
    pub unresolved: usize,
}

/// `command-<first 16 bytes of sha256(session), hex>.lock`: a fixed-length
/// name, never the raw session value.
fn lock_name(session: &[u8]) -> String {
    let d = sha256(session);
    let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("command-{hex}.lock")
}

/// The neutral folder: made 0700 when missing; one that is there must be
/// the user's, exactly 0700 and allow no other writer.
fn neutral(runtime: &File, me: u32) -> Result<(), StoreError> {
    let name = OsStr::new(NEUTRAL);
    let made = sys::mkdir_at(runtime.as_fd(), name, 0o700)?;
    let dir = sys::open_dir_at_nofollow(runtime.as_fd(), name)?;
    if made {
        use std::os::unix::fs::PermissionsExt;
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    let facts = sys::fd_facts(dir.as_fd())?;
    let local = sys::fd_is_local(dir.as_raw_fd());
    final_verdict(
        &facts,
        me,
        0,
        NextOwner::Any,
        Last::PrivateFolder,
        local,
        &mut RefuseGroupWrite,
    )
    .map_err(|_| StoreError::Unsafe)?;
    Ok(())
}

/// Decides the round and, when it has units, takes the session lock,
/// builds the grant (its permit comes later) and spawns the supervisor.
pub(crate) fn prepare(i: &Inputs<'_>, groups: &mut SystemGroups) -> Result<Round, Skip> {
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
    neutral(i.runtime, i.me).map_err(|_| Skip::Failed)?;
    // The repository the shell is in, by identity, for the PATH and
    // executable rules. Until it has a source (C2 ruling J9) the shell's own
    // folder stands for it; a folder that cannot be read refuses the round.
    let repo =
        exec_path::repo_id(Some(Path::new(OsStr::from_bytes(pwd)))).map_err(|_| Skip::Failed)?;
    let vars = Environ::parse(body);
    let folders = exec_path::sanitize(vars.get(b"PATH").unwrap_or_default(), repo, i.me, groups);
    let path = exec_path::path_value(&folders);
    let attempts: Vec<(&str, Option<u64>)> = runnable.iter().map(|(id, _)| (*id, None)).collect();
    let mut units = Vec::new();
    let mut unresolved = 0;
    for at in plan::pick(&attempts, plan::CONFIG_MAX) {
        let (id, r) = &runnable[at];
        let word = match &r.policy {
            Policy::Argv { argv } => argv[0].as_slice(),
            Policy::UnsafeShell { .. } => SHELL,
        };
        let Ok(found) = exec_path::lookup(word, &folders, repo, i.me, groups) else {
            unresolved += 1;
            continue;
        };
        units.push(Unit {
            id: (*id).to_owned(),
            digest: policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow),
            policy: r.policy.clone(),
            cwd: r.cwd,
            environment: plan::target_environment(&vars, &r.env_allow, &path),
            timeout: r.timeout,
            env_allow: r.env_allow.clone(),
            executable: found.executable.into_os_string().into_encoded_bytes(),
            pin: found.pin,
            interpreter: found.interpreter,
        });
    }
    if units.is_empty() {
        return Err(Skip::Unresolved);
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
        units,
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
        grant_pipe,
        results,
        _lock: lock,
        unresolved,
    })
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
    pub(crate) fn grant(mut self, permit: Permit) -> Report {
        self.grant.permit = permit;
        let mut report = Report::default();
        let Ok(frame) = wire::encode(&Message::Grant(self.grant.clone())) else {
            self.abandon();
            return report;
        };
        // One write into the empty pipe; a short one is a cut grant, which
        // the supervisor refuses as a whole.
        if !matches!(
            sys::write_fd(self.grant_pipe.as_raw_fd(), &frame),
            sys::WriteOutcome::Done
        ) {
            self.abandon();
            return report;
        }
        let want = self.grant.units.len() + self.grant.probes.len();
        let end = self
            .grant
            .helper_deadline
            .saturating_sub(super::command_supervisor::BUDGET.reserve / 2);
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
