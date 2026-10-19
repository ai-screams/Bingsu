//! Warm and cold `init` (spec section 5 "init output", plan N5 Step 2). A
//! snapshot of the same boot and settings context needs no work: `init`
//! compiles nothing, and a marker that grew old is the first prompt's helper
//! to renew. Without one, `init` asks the same fixed helper the prompt uses
//! (an independent process, no wait inside it) and polls the store for at
//! most `INIT_LIMIT`. Whatever happens, the connection script is printed.
use super::roots::Roots;
use crate::commands::{
    group_policy::SystemGroups,
    refresh::RefreshRequest,
    snapshot_store::{CheckedContextFd, DataFile},
};
use bingsu_core::root_arg::{
    CONFIG_ROOT_PREFIX, CONFIG_ROOT_SHAPE_ONLY, CONFIG_ROOT_WRITTEN_PREFIX, HOME_PREFIX,
    LOG_ROOT_PREFIX, RUNTIME_ROOT_PREFIX, STATE_ROOT_PREFIX,
};
use bingsu_core::snapshot::{self, Snapshot};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// The longest `init` waits for a first compile.
pub const INIT_LIMIT: Duration = Duration::from_millis(500);
const POLL: Duration = Duration::from_millis(5);

#[derive(Debug, PartialEq, Eq)]
pub enum PrimeResult {
    /// A snapshot of this boot and context was there; nothing was started.
    AlreadyReady,
    /// The helper published one inside the limit.
    Published,
    /// The helper decided (an invalid marker) and there is no snapshot.
    Invalid,
    /// The limit passed first; the helper may still finish.
    TimedOut,
    /// A root is missing, so there is no helper to ask (init said so).
    Unavailable,
}

/// What the store shows about this context.
#[derive(Debug, PartialEq, Eq)]
pub struct State {
    pub snapshot_ready: bool,
    pub marker: Option<Vec<u8>>,
}

/// Read-only store view. A healthy marker may have arrived just after the
/// first snapshot read; retry the snapshot rather than calling it invalid.
fn read_state(
    boot: [u8; 16],
    context: [u8; 4],
    read: &mut dyn FnMut(DataFile) -> Option<Vec<u8>>,
) -> State {
    let ready = |bytes: Option<Vec<u8>>| {
        bytes
            .and_then(|b| Snapshot::decode(&b).ok())
            .is_some_and(|s| snapshot::same_boot(s.id, Some(boot), context))
    };
    let mut snapshot_ready = ready(read(DataFile::Snapshot));
    let marker = read(DataFile::Marker);
    if !snapshot_ready
        && marker
            .as_deref()
            .and_then(|b| snapshot::Marker::decode(b).ok())
            .is_some_and(|m| snapshot::same_boot(m.id, Some(boot), context) && !m.invalid)
    {
        snapshot_ready = ready(read(DataFile::Snapshot));
    }
    State {
        snapshot_ready,
        marker,
    }
}

#[cfg(test)]
fn state_of(req: &RefreshRequest, boot: [u8; 16]) -> State {
    store_reader(req.clone(), boot)()
}

/// Initialization and every read happen inside the worker. Keep the checked
/// runtime descriptor and SystemGroups once, even before context folders exist.
fn store_reader(req: RefreshRequest, boot: [u8; 16]) -> impl FnMut() -> State + Send {
    let mut initialized = false;
    let mut runtime = None;
    let mut dir = None;
    move || {
        let config = req.config_canonical.as_os_str().as_bytes();
        let state = req.state_root.as_os_str().as_bytes();
        if !initialized {
            initialized = true;
            runtime = crate::commands::runtime_root::open_runtime_root(
                &req.runtime,
                req.me,
                &mut SystemGroups::new(&req.user),
            )
            .ok();
        }
        if dir.is_none()
            && let Some(runtime) = &runtime
        {
            dir = CheckedContextFd::under_runtime(runtime, config, state, req.me, false).ok();
        }
        read_state(
            boot,
            snapshot::context_crc(config, state).unwrap_or([0; 4]),
            &mut |name| dir.as_ref()?.read(name).ok(),
        )
    }
}

enum Event {
    Spawn,
    Done(PrimeResult),
}

/// A detached worker may remain blocked in NSS or filesystem I/O. The parent
/// only receives with the absolute deadline and never joins that worker.
fn prime_reader_with_deadline(
    boot: [u8; 16],
    context: [u8; 4],
    end: Instant,
    spawn: &mut dyn FnMut(),
    mut read: impl FnMut() -> State + Send + 'static,
) -> PrimeResult {
    let (tx, rx) = std::sync::mpsc::channel();
    let (ack, proceed) = std::sync::mpsc::channel();
    if std::thread::Builder::new()
        .name("init-poll".into())
        .spawn(move || {
            let before = read();
            if before.snapshot_ready {
                let _ = tx.send(Event::Done(PrimeResult::AlreadyReady));
                return;
            }
            if tx.send(Event::Spawn).is_err() || proceed.recv().is_err() {
                return;
            }
            while Instant::now() < end {
                let now = read();
                let result = if now.snapshot_ready {
                    Some(PrimeResult::Published)
                } else if now.marker != before.marker
                    && now
                        .marker
                        .as_deref()
                        .and_then(|b| snapshot::Marker::decode(b).ok())
                        .is_some_and(|m| {
                            snapshot::same_boot(m.id, Some(boot), context) && m.invalid
                        })
                {
                    Some(PrimeResult::Invalid)
                } else {
                    None
                };
                if let Some(result) = result {
                    let _ = tx.send(Event::Done(result));
                    return;
                }
                std::thread::sleep(POLL.min(end.saturating_duration_since(Instant::now())));
            }
        })
        .is_err()
    {
        return PrimeResult::TimedOut;
    }
    loop {
        match rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok(Event::Spawn) => {
                spawn();
                let _ = ack.send(());
            }
            Ok(Event::Done(result)) => return result,
            Err(_) => return PrimeResult::TimedOut,
        }
    }
}

/// `spawn` starts the independent helper once; store reads cannot hold the
/// caller past `end`, including the initial warm check.
pub fn prime_with_deadline(
    req: &RefreshRequest,
    boot: [u8; 16],
    end: Instant,
    spawn: &mut dyn FnMut(),
) -> PrimeResult {
    let context = snapshot::context_crc(
        req.config_canonical.as_os_str().as_bytes(),
        req.state_root.as_os_str().as_bytes(),
    )
    .unwrap_or([0; 4]);
    prime_reader_with_deadline(boot, context, end, spawn, store_reader(req.clone(), boot))
}

/// The words the shell hook hands the helper, as raw arguments for
/// `bingsu_core::helper::words`.
pub fn helper_words(roots: &Roots, home: &Path) -> Option<Vec<Vec<u8>>> {
    let runtime = roots.runtime.as_ref()?;
    let config = roots.config.as_ref()?;
    let state = roots.state.as_ref()?;
    let join = |prefix: &[u8], v: &[u8]| [prefix, v].concat();
    let mut out = vec![
        join(
            RUNTIME_ROOT_PREFIX,
            &[
                format!("{}:{}:", runtime.dev, runtime.ino).as_bytes(),
                runtime.path.as_os_str().as_bytes(),
            ]
            .concat(),
        ),
        join(
            b"--runtime-groups=",
            bingsu_core::helper::encode_groups(&runtime.group_ok).as_bytes(),
        ),
        join(CONFIG_ROOT_PREFIX, config.path.as_os_str().as_bytes()),
        join(
            CONFIG_ROOT_WRITTEN_PREFIX,
            config.written.as_os_str().as_bytes(),
        ),
    ];
    if config.shape_only {
        out.push(CONFIG_ROOT_SHAPE_ONLY.to_vec());
    }
    out.push(join(STATE_ROOT_PREFIX, state.as_os_str().as_bytes()));
    if let Some(log) = &roots.log {
        out.push(join(LOG_ROOT_PREFIX, log.as_os_str().as_bytes()));
    }
    out.push(join(HOME_PREFIX, home.as_os_str().as_bytes()));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{refresh, refresh::RefreshResult, runtime_root::Pinned, sys};
    use bingsu_core::snapshot::{Clock, ClockError, ClockSource};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    const BOOT: [u8; 16] = [4; 16];

    struct Fixed;
    impl ClockSource for Fixed {
        fn observe(&mut self) -> Result<Clock, ClockError> {
            Ok(Clock {
                kind: 1,
                domain: [3; 16],
                resume: 0,
                boot: BOOT,
                now: 10_000_000_000,
            })
        }
    }

    struct Fx {
        base: PathBuf,
        request: RefreshRequest,
    }
    impl Fx {
        fn new(tag: &str, config: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("bingsu-n5-prime-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir(&base).unwrap();
            let mode = |p: &Path| {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap()
            };
            mode(&base);
            let base = std::fs::canonicalize(base).unwrap();
            for n in ["runtime", "config", "state"] {
                std::fs::create_dir(base.join(n)).unwrap();
                mode(&base.join(n));
            }
            let md = std::fs::metadata(base.join("runtime")).unwrap();
            let me = sys::current_uid();
            let f = Self {
                request: RefreshRequest {
                    runtime: Pinned {
                        dev: md.dev(),
                        ino: md.ino(),
                        path: base.join("runtime"),
                    },
                    config_written: base.join("config"),
                    config_canonical: base.join("config"),
                    config_root_shape_only: false,
                    state_root: base.join("state"),
                    home: base.clone(),
                    me,
                    user: sys::passwd_entry(me).unwrap().name,
                    version: [0, 3, 0],
                    build: Some([1; 40]),
                    process_started: Fixed.observe().unwrap(),
                },
                base,
            };
            f.config(config);
            f
        }
        fn config(&self, text: &str) {
            let p = self.base.join("config/config.toml");
            let _ = std::fs::remove_file(&p);
            std::fs::write(&p, text).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn helper(&self) -> RefreshResult {
            refresh::refresh(self.request.clone(), &mut Fixed)
        }
        fn prime(&self, boot: [u8; 16], limit: Duration, spawn: &mut dyn FnMut()) -> PrimeResult {
            prime_with_deadline(&self.request, boot, Instant::now() + limit, spawn)
        }
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn blocked_initial_or_later_store_read_cannot_hold_parent() {
        for blocked_at in [0, 1] {
            let (release, gate) = std::sync::mpsc::channel();
            let mut calls = 0;
            let t = Instant::now();
            let mut spawned = 0;
            let result = prime_reader_with_deadline(
                BOOT,
                [0; 4],
                t + Duration::from_millis(80),
                &mut || spawned += 1,
                move || {
                    if calls == blocked_at {
                        let _ = gate.recv_timeout(Duration::from_secs(5));
                    }
                    calls += 1;
                    State {
                        snapshot_ready: false,
                        marker: None,
                    }
                },
            );
            let elapsed = t.elapsed();
            let _ = release.send(());
            assert_eq!(result, PrimeResult::TimedOut);
            assert_eq!(spawned, blocked_at);
            assert!(elapsed >= Duration::from_millis(70));
            assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        }
    }

    #[test]
    fn store_reader_keeps_the_checked_runtime_instead_of_walking_again() {
        let f = Fx::new("retained-runtime", "icons = \"ascii\"\n");
        let mut read = store_reader(f.request.clone(), BOOT);
        assert!(!read().snapshot_ready);
        assert!(matches!(f.helper(), RefreshResult::Published { .. }));
        std::fs::rename(f.base.join("runtime"), f.base.join("old-runtime")).unwrap();
        assert!(read().snapshot_ready);
    }

    #[test]
    fn healthy_marker_race_rechecks_snapshot() {
        let f = Fx::new("marker-race", "icons = \"ascii\"\n");
        assert!(matches!(f.helper(), RefreshResult::Published { .. }));
        let context = snapshot::context_crc(
            f.request.config_canonical.as_os_str().as_bytes(),
            f.request.state_root.as_os_str().as_bytes(),
        )
        .unwrap();
        let dir = CheckedContextFd::open(
            &f.request.runtime,
            f.request.config_canonical.as_os_str().as_bytes(),
            f.request.state_root.as_os_str().as_bytes(),
            f.request.me,
            &mut SystemGroups::new(&f.request.user),
            false,
        )
        .unwrap();
        let mut first = true;
        let state = read_state(BOOT, context, &mut |name| {
            if matches!(name, DataFile::Snapshot) && first {
                first = false;
                None
            } else {
                dir.read(name).ok()
            }
        });
        assert!(state.snapshot_ready);
        // A marker for a different boot/context must never finish an invalid read.
        let mut marker = snapshot::Marker::decode(state.marker.as_ref().unwrap()).unwrap();
        marker.invalid = true;
        for variant in 0..3 {
            let mut m = marker;
            match variant {
                0 => m.invalid = false,
                1 => m.id.boot = [9; 16],
                _ => m.id.context = [9; 4],
            }
            let mut first = true;
            let r = prime_reader_with_deadline(
                BOOT,
                context,
                Instant::now() + Duration::from_millis(40),
                &mut || {},
                move || {
                    let bytes = if first {
                        None
                    } else {
                        Some(m.encode().to_vec())
                    };
                    first = false;
                    State {
                        snapshot_ready: false,
                        marker: bytes,
                    }
                },
            );
            assert_eq!(r, PrimeResult::TimedOut);
        }
    }

    // A snapshot of this boot and context means init starts nothing; another boot (a reboot) or no snapshot
    // does. 이것을 실패시키는 것: 준비된 snapshot이 있는데 helper를 띄우는 것(warm init이 컴파일), 부팅 정체를 보지 않는 것,
    // 읽기 쪽 확인이 폴더를 만드는 것.
    #[test]
    fn warm_init_starts_nothing() {
        let f = Fx::new("warm", "icons = \"ascii\"\n");
        let mut spawned = 0;
        assert!(matches!(f.helper(), RefreshResult::Published { .. }));
        let first = f.prime(BOOT, Duration::from_secs(5), &mut || spawned += 1);
        assert_eq!((first, spawned), (PrimeResult::AlreadyReady, 0));
        // Not ready for another boot: the helper is asked once, and nothing publishes for it here.
        let other = f.prime([5; 16], Duration::from_millis(30), &mut || spawned += 1);
        assert_eq!((other, spawned), (PrimeResult::TimedOut, 1));
        // The store was only read.
        let empty = Fx::new("warm-empty", "icons = \"ascii\"\n");
        let before = std::fs::read_dir(empty.base.join("runtime"))
            .unwrap()
            .count();
        assert!(!state_of(&empty.request, BOOT).snapshot_ready);
        assert_eq!(
            std::fs::read_dir(empty.base.join("runtime"))
                .unwrap()
                .count(),
            before
        );
    }

    // No snapshot and a helper that never answers: init gives up at the limit, after asking exactly once.
    // 이것을 실패시키는 것: 도우미 종료까지 무한히 기다리는 것(한도 무시), 한도보다 훨씬 일찍 포기하는 것, 두 번 띄우는 것.
    #[test]
    fn cold_init_stall_ends_at_the_limit() {
        let f = Fx::new("stall", "icons = \"ascii\"\n");
        let mut spawned = 0;
        let t = Instant::now();
        let r = f.prime(BOOT, Duration::from_millis(120), &mut || spawned += 1);
        let took = t.elapsed();
        assert_eq!((r, spawned), (PrimeResult::TimedOut, 1));
        assert!(took >= Duration::from_millis(115), "{took:?}");
        assert!(took < Duration::from_millis(1500), "{took:?}");
    }

    // The helper publishes while init waits: init sees it and returns at once; an invalid first read ends the wait
    // with the "invalid" answer instead of running to the limit.
    // 이것을 실패시키는 것: 발행을 보고도 한도까지 기다리는 것, 표식 변화(무효 판정)를 보지 않아 한도까지 기다리는 것.
    #[test]
    fn cold_init_sees_the_helper_decide() {
        let f = Fx::new("decide", "icons = \"ascii\"\n");
        let t = Instant::now();
        let r = f.prime(BOOT, Duration::from_secs(30), &mut || {
            assert!(matches!(f.helper(), RefreshResult::Published { .. }));
        });
        assert_eq!(r, PrimeResult::Published);
        assert!(t.elapsed() < Duration::from_secs(10));
        let bad = Fx::new("decide-bad", "colr = 1\n");
        let t = Instant::now();
        let r = bad.prime(BOOT, Duration::from_secs(30), &mut || {
            assert_eq!(bad.helper(), RefreshResult::Invalid);
        });
        assert_eq!(r, PrimeResult::Invalid);
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    // The helper gets the roots init pinned, as the hook words, shape-only mark and log root included.
    // 이것을 실패시키는 것: 모양 전용 표식·그룹 기록·로그 뿌리·home 중 하나를 도우미 인자에서 빼는 것, 뿌리가 없는데 인자를 만드는 것.
    #[test]
    fn helper_words_carry_every_pinned_root() {
        use super::super::roots::{ConfigRootPin, RuntimeRootPin};
        use bingsu_core::fs_trust::{Facts, Group, GroupOracle};
        struct Unknown;
        impl GroupOracle for Unknown {
            fn group_write(&mut self, _: &Facts) -> Group {
                Group::Unknown
            }
        }
        let f = Fx::new("words", "icons = \"ascii\"\n");
        let root = f.base.join("shape");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o775)).unwrap();
        let config = ConfigRootPin::check(&root, f.request.me, &mut Unknown).unwrap();
        assert!(config.shape_only);
        let md = std::fs::metadata(f.base.join("runtime")).unwrap();
        let roots = Roots {
            runtime: Some(RuntimeRootPin {
                dev: md.dev(),
                ino: md.ino(),
                path: f.base.join("runtime"),
                group_ok: Vec::new(),
            }),
            config: Some(config),
            state: Some(f.base.join("state")),
            log: Some(f.base.join("state/log")),
        };
        let words = helper_words(&roots, &f.base).unwrap();
        let raw: Vec<&[u8]> = words.iter().map(Vec::as_slice).collect();
        let e = bingsu_core::helper::validate(&bingsu_core::helper::words(&raw).unwrap()).unwrap();
        let bytes = |p: &Path| p.as_os_str().as_bytes().to_vec();
        assert_eq!(e.config_root, Some(bytes(&root)));
        assert!(e.config_root_shape_only);
        assert_eq!(e.state_root, Some(bytes(&f.base.join("state"))));
        assert_eq!(e.log_root, Some(bytes(&f.base.join("state/log"))));
        assert_eq!(e.home, Some(bytes(&f.base)));
        let r = e.runtime_root.unwrap();
        assert_eq!((r.dev, r.ino), (md.dev(), md.ino()));
        let none = Roots {
            runtime: None,
            ..roots
        };
        assert!(helper_words(&none, &f.base).is_none());
    }
}
