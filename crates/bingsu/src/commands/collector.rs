//! Fixed M3b broker boundary. M3a's worker validates the immutable request and
//! releases its lock; collecting git values and publishing results belong to M3b.
use super::{
    log::checked,
    snapshot_store::{CheckedContextFd, StoreError},
    sys,
};
use bingsu_core::{
    collection::Request,
    fs_trust::{Last, RefuseGroupWrite, walk_verdict},
};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::Read,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

/// Held evidence for the canonical dedicated executable. This does not select
/// a worker from PATH, nor authorize any configured command. C1 consumes it
/// immediately before spawning; the legacy broker below remains disconnected.
pub struct PinnedCollector {
    path: std::path::PathBuf,
    chain: super::runtime_root::Chain,
    executable: File,
    stamp: sys::Stamp,
    facts: bingsu_core::fs_trust::Facts,
}
impl PinnedCollector {
    pub fn verify(
        exe: &OsStr,
        me: u32,
        groups: &mut dyn bingsu_core::fs_trust::GroupOracle,
    ) -> Result<Self, StoreError> {
        use bingsu_core::fs_trust::{NextOwner, ancestor_verdict};
        let path = std::path::Path::new(exe);
        if path.file_name() != Some(OsStr::new("bingsu-collect")) {
            return Err(StoreError::Unsafe);
        }
        let parent = path.parent().ok_or(StoreError::Unsafe)?;
        let chain = super::runtime_root::open_chain(parent).map_err(StoreError::Root)?;
        let mut next = NextOwner::Any;
        for (at, facts) in chain.facts.iter().enumerate() {
            next = ancestor_verdict(facts, me, at, next, groups).map_err(|_| StoreError::Unsafe)?;
        }
        let executable =
            sys::open_data_at_nofollow(chain.last().as_fd(), OsStr::new("bingsu-collect"))?;
        let facts = sys::fd_facts(executable.as_fd())?;
        ancestor_verdict(&facts, me, chain.facts.len(), next, groups)
            .map_err(|_| StoreError::Unsafe)?;
        let md = executable.metadata()?;
        if !md.is_file()
            || !executable_mode(md.mode())
            || sys::fd_is_local(executable.as_raw_fd()) != Some(true)
        {
            return Err(StoreError::Unsafe);
        }
        verify_build(&executable)?;
        let pin = Self {
            path: path.to_path_buf(),
            chain,
            stamp: sys::file_stamp(&executable)?,
            executable,
            facts,
        };
        pin.executable()?;
        Ok(pin)
    }
    /// Recheck retained descriptors and parent/name bindings without a new
    /// executable lookup. Replaced parents or targets invalidate this handle.
    pub fn executable(&self) -> Result<&OsStr, StoreError> {
        self.chain.revalidate()?;
        if sys::file_stamp(&self.executable)? != self.stamp
            || sys::fd_facts(self.executable.as_fd())? != self.facts
            || sys::at_stamp(self.chain.last().as_fd(), OsStr::new("bingsu-collect"))? != self.stamp
        {
            return Err(StoreError::Unsafe);
        }
        Ok(self.path.as_os_str())
    }
}
fn executable_mode(mode: u32) -> bool {
    mode & 0o111 != 0 && mode & 0o6000 == 0
}
fn verify_build(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::FileExt;
    let size = file.metadata()?.len();
    if size > 64 * 1024 * 1024 {
        return Err(StoreError::Unsafe);
    }
    let mut buffer = [0u8; 65_536];
    let expected = bingsu_collect::build_id();
    let mut found = 0;
    let mut offset = 0;
    let mut overlap = 0;
    while offset < size {
        let n = file.read_at(&mut buffer[overlap..], offset)?;
        if n == 0 {
            return Err(StoreError::Unsafe);
        }
        let length = overlap + n;
        for window in buffer[..length].windows(48) {
            if window[..16] == bingsu_collect::manifest_tag()[..16] {
                if window[16..] != expected.0 {
                    return Err(StoreError::Unsafe);
                }
                found += 1;
            }
        }
        overlap = length.min(47);
        buffer.copy_within(length - overlap..length, 0);
        offset += n as u64;
    }
    if found != 1 {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

pub fn spawn(
    exe: &OsStr,
    context: &CheckedContextFd,
    request: &Request,
    me: u32,
) -> Result<(), StoreError> {
    let mut dir = context.dir.try_clone()?;
    for name in request.components() {
        sys::mkdir_at(dir.as_fd(), OsStr::new(&name), 0o700)?;
        dir = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new(&name))?;
        walk_verdict(
            &[sys::fd_facts(dir.as_fd())?],
            me,
            Last::PrivateFolder,
            sys::fd_is_local(dir.as_raw_fd()),
            &mut RefuseGroupWrite,
        )
        .map_err(|_| StoreError::Unsafe)?;
    }
    let lock = sys::open_lock_at(dir.as_fd(), OsStr::new("collection.lock"))?;
    checked(&lock, 0, me)?;
    // Hold through request staging and spawn; errors explicitly unlock.
    let lock = match sys::try_lock(lock) {
        Ok(held) => held,
        Err(e) if matches!(e.raw_os_error(), Some(libc::EWOULDBLOCK)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let staging = OsStr::new(".stage-request");
    match sys::open_data_at_nofollow(dir.as_fd(), staging) {
        Ok(old) => {
            checked(&old, bingsu_core::collection::REQUEST_MAX, me)?;
            sys::unlink_at(dir.as_fd(), staging)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let writable = sys::create_file_at(dir.as_fd(), staging, 0o600)?;
    let bytes = request.encode()?;
    if !matches!(
        sys::write_fd(writable.as_raw_fd(), &bytes),
        sys::WriteOutcome::Done
    ) {
        return Err(StoreError::Unsafe);
    }
    let readonly = sys::open_data_at_nofollow(dir.as_fd(), staging)?;
    checked(&readonly, bingsu_core::collection::REQUEST_MAX, me)?;
    if sys::file_stamp(&writable)? != sys::file_stamp(&readonly)? {
        return Err(StoreError::Unsafe);
    }
    drop(writable);
    sys::unlink_at(dir.as_fd(), staging)?;
    #[cfg(test)]
    super::n3_test::observe_lock_scope();
    spawn_fds(exe, [&readonly, &dir, &lock])?;
    // Only a successful spawn transfers unlock responsibility to the child.
    drop(lock.into_inherited_file());
    Ok(())
}
fn spawn_fds(exe: &OsStr, files: [&File; 3]) -> Result<(), StoreError> {
    if !exe.as_bytes().starts_with(b"/") {
        return Err(StoreError::Unsafe);
    }
    let path = CString::new(exe.as_bytes()).map_err(|_| StoreError::Unsafe)?;
    let argv = [
        path.as_ptr().cast_mut(),
        c"__collect-v1".as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];
    let env = [std::ptr::null_mut()];
    let mut copies = Vec::new();
    for f in files {
        // SAFETY: live fd; new copies are above all destination slots.
        let fd = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 6) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fcntl returned a new owned fd.
        copies.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    // SAFETY: initialized by the spawn API below.
    let mut actions = unsafe { std::mem::zeroed() };
    // SAFETY: writable action storage.
    spawn_check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
    // SAFETY: initialized below.
    let mut attr = unsafe { std::mem::zeroed() };
    // SAFETY: writable attribute storage.
    if let Err(e) = spawn_check(unsafe { libc::posix_spawnattr_init(&mut attr) }) {
        // SAFETY: initialized actions.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
        return Err(e);
    }
    let result = (|| {
        // SAFETY: integer-only signal action, mask initialized next.
        let mut reap: libc::sigaction = unsafe { std::mem::zeroed() };
        reap.sa_sigaction = libc::SIG_IGN;
        reap.sa_flags = libc::SA_NOCLDWAIT;
        // SAFETY: writable mask.
        spawn_check(unsafe { libc::sigemptyset(&mut reap.sa_mask) })?;
        // SAFETY: helper process only, initialized action.
        spawn_check(unsafe { libc::sigaction(libc::SIGCHLD, &reap, std::ptr::null_mut()) })?;
        // SAFETY: valid storage, initialized by sigemptyset below.
        let mut mask = unsafe { std::mem::zeroed() };
        // SAFETY: writable mask.
        spawn_check(unsafe { libc::sigemptyset(&mut mask) })?;
        // SAFETY: initialized mask and attr.
        spawn_check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr, &mask) })?;
        // SAFETY: writable mask.
        spawn_check(unsafe { libc::sigfillset(&mut mask) })?;
        // SAFETY: initialized mask and attr.
        spawn_check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr, &mask) })?;
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
        #[cfg(target_os = "macos")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // SAFETY: initialized attr and supported flags.
        spawn_check(unsafe { libc::posix_spawnattr_setflags(&mut attr, flags as libc::c_short) })?;
        for fd in 0..3 {
            // SAFETY: fixed path, initialized actions.
            spawn_check(unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    fd,
                    c"/dev/null".as_ptr(),
                    libc::O_RDWR,
                    0,
                )
            })?;
        }
        for (i, fd) in copies.iter().enumerate() {
            // SAFETY: all sources are distinct and >=6; destinations are 3,4,5.
            spawn_check(unsafe {
                libc::posix_spawn_file_actions_adddup2(&mut actions, fd.as_raw_fd(), 3 + i as i32)
            })?;
        }
        #[cfg(target_os = "linux")]
        for entry in std::fs::read_dir("/proc/self/fd")? {
            let fd: i32 = entry?
                .file_name()
                .to_str()
                .ok_or(StoreError::Unsafe)?
                .parse()
                .map_err(|_| StoreError::Unsafe)?;
            if fd >= 6 {
                // SAFETY: initialized action and kernel fd. Watchdog opens no Linux fds.
                spawn_check(unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, fd) })?;
            }
        }
        let mut pid = 0;
        // SAFETY: initialized objects and live NUL-terminated pointer arrays.
        spawn_check(unsafe {
            libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                env.as_ptr(),
            )
        })
    })();
    // SAFETY: initialized objects, no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized object, no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}
fn spawn_check(rc: i32) -> Result<(), StoreError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(rc).into())
    }
}

pub fn run() -> std::process::ExitCode {
    let started = std::time::Instant::now();
    std::panic::set_hook(Box::new(|_| {}));
    if super::helper::detach().is_err() {
        return std::process::ExitCode::from(1);
    }
    let Ok(watchdog) = super::helper_limits::start(started) else {
        return std::process::ExitCode::from(1);
    };
    // M3a stub budget, owned by this process. M3b can choose collection
    // limits without inheriting an irreversible helper CPU/AS ceiling.
    if super::helper_limits::install(&watchdog).is_err() {
        return std::process::ExitCode::from(1);
    }
    let _ = stub();
    std::process::ExitCode::SUCCESS
}
fn stub() -> Result<(), StoreError> {
    // SAFETY: this internal entry owns the three reserved descriptors. Check
    // they are open first so direct malformed invocations never own invalid fds.
    for fd in 3..6 {
        // SAFETY: read-only fd query.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(StoreError::Unsafe);
        }
    }
    // SAFETY: checked open fd, transferred once to File.
    let request = unsafe { File::from_raw_fd(3) };
    // SAFETY: checked open fd, transferred once to File.
    let dir = unsafe { File::from_raw_fd(4) };
    // SAFETY: checked open fd, transferred once to File.
    let lock = unsafe { File::from_raw_fd(5) };
    stub_files(request, dir, lock)
}
fn stub_files(request: File, dir: File, lock: File) -> Result<(), StoreError> {
    // Re-locking the inherited open-file description adopts the parent's lock.
    // Keep the guard even on validation errors, so inherited copies cannot
    // extend this worker's critical section after it returns.
    let lock = sys::try_lock(lock).map_err(super::snapshot_store::lock_error)?;
    let me = sys::current_uid();
    let md = request.metadata()?;
    // SAFETY: read-only flag query on live request fd.
    let flags = unsafe { libc::fcntl(request.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY || md.nlink() != 0 {
        return Err(StoreError::Unsafe);
    }
    super::snapshot_store::data_verdict(
        sys::fd_facts(request.as_fd())?,
        md.is_file(),
        1,
        md.len(),
        bingsu_core::collection::REQUEST_MAX,
        sys::fd_is_local(request.as_raw_fd()),
        me,
    )?;
    walk_verdict(
        &[sys::fd_facts(dir.as_fd())?],
        me,
        Last::PrivateFolder,
        sys::fd_is_local(dir.as_raw_fd()),
        &mut RefuseGroupWrite,
    )
    .map_err(|_| StoreError::Unsafe)?;
    checked(&lock, 0, me)?;
    if sys::at_stamp(dir.as_fd(), OsStr::new("collection.lock"))? != sys::file_stamp(&lock)? {
        return Err(StoreError::Unsafe);
    }
    let mut bytes = Vec::new();
    request
        .take((bingsu_core::collection::REQUEST_MAX + 1) as u64)
        .read_to_end(&mut bytes)?;
    Request::decode(&bytes)?;
    // M3b implements collection and atomic result publication here. No git or
    // user command is executed by the M3a stub, and no fake complete result.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 실행 비트를 요구하지 않거나 setuid/setgid를 허용하는 것.
    #[test]
    fn collector_executable_mode_rejects_special_bits() {
        assert!(executable_mode(0o100700));
        for mode in [0o100600, 0o104700, 0o102700, 0o106700] {
            assert!(!executable_mode(mode), "mode {mode:o}");
        }
    }

    // 이것을 실패시키는 것: 고정 실행 파일의 manifest·권한·부모 교체 검사를 생략하는 것.
    #[test]
    fn collector_path_never_uses_prompt_environment() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("bingsu-worker-pin-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let base = std::fs::canonicalize(base).unwrap();
        let directory = base.join("install");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("bingsu-collect");
        let me = sys::current_uid();
        let check = || PinnedCollector::verify(path.as_os_str(), me, &mut RefuseGroupWrite);
        assert!(check().is_err());
        std::fs::write(&path, bingsu_collect::manifest_tag()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin = check().unwrap();
        assert_eq!(pin.executable().unwrap(), path.as_os_str());
        assert!(
            PinnedCollector::verify(
                directory.join("other").as_os_str(),
                me,
                &mut RefuseGroupWrite
            )
            .is_err()
        );
        // Some macOS hosts silently clear special bits on chmod. The pure
        // predicate above always covers them; Linux also checks actual files.
        let modes: &[u32] = if cfg!(target_os = "linux") {
            &[0o600, 0o4700, 0o2700]
        } else {
            &[0o600]
        };
        for &mode in modes {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, mode);
            assert!(check().is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o702)).unwrap();
        assert!(check().is_err());
        assert!(pin.executable().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin = check().unwrap();
        let old = base.join("old");
        std::fs::rename(&directory, &old).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(old.join("bingsu-collect"), &path).unwrap();
        assert!(pin.executable().is_err());
        assert!(check().is_ok());
        std::fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: 같은 wire 버전의 다른 build-id나 중복 tag를 받는 것.
    #[test]
    fn sibling_build_id_is_exact() {
        let path = std::env::temp_dir().join(format!("bingsu-worker-build-{}", std::process::id()));
        let valid = bingsu_collect::manifest_tag();
        for offset in 16..48 {
            let mut bad = *valid;
            bad[offset] ^= 1;
            std::fs::write(&path, bad).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_err());
        }
        for prefix in [0, 65_520, 65_535, 65_536] {
            let mut bytes = vec![0; prefix];
            bytes.extend(valid);
            std::fs::write(&path, &bytes).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_ok());
            bytes.extend(valid);
            std::fs::write(&path, bytes).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_err());
        }
        std::fs::remove_file(path).unwrap();
    }
    // 이것을 실패시키는 것: fd 3/4/5·읽기 전용/분리된 request·고정 verb·fd 정리·lock 승계를 깨는 것.
    #[test]
    #[ignore = "isolates collector signal disposition"]
    fn collector_child() {
        let (base, exe) = super::super::n3_test::probe("collector");
        use bingsu_core::snapshot::{self, Clock, Identity};
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = base.join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let md = std::fs::metadata(&runtime).unwrap();
        let pin = super::super::runtime_root::Pinned {
            path: runtime.clone(),
            dev: md.dev(),
            ino: md.ino(),
        };
        let context = CheckedContextFd::open(
            &pin,
            b"/c",
            b"/s",
            sys::current_uid(),
            &mut RefuseGroupWrite,
            true,
        )
        .unwrap();
        let id = Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            source: [3; 4],
            context: snapshot::context_crc(b"/c", b"/s").unwrap(),
        };
        let now = Clock {
            boot: id.boot,
            kind: 1,
            domain: [0; 16],
            resume: 0,
            now: 1,
        };
        // Explicit legacy wire input keeps the fd contract tested while the
        // product request constructor is disabled.
        let request = Request {
            id,
            kind: now.kind,
            domain: now.domain,
            resume: now.resume,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            cwd: b"/repo".to_vec(),
            mask: 1 << 3,
        };
        let path = snapshot::context_components(b"/c", b"/s")
            .unwrap()
            .iter()
            .chain(request.components().iter())
            .fold(runtime, |p, n| p.join(n));
        // SAFETY: initialized writable limit storage.
        let mut limit = unsafe { std::mem::zeroed() };
        // SAFETY: valid resource and output pointer.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        assert_eq!(rc, 0);
        limit.rlim_cur = 4608.min(limit.rlim_max);
        // SAFETY: isolated child's soft limit within inherited hard.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        assert_eq!(rc, 0);
        // SAFETY: duplicate live fd, deliberately without CLOEXEC.
        let high = unsafe { libc::fcntl(context.dir.as_raw_fd(), libc::F_DUPFD, 1025) };
        assert!(high >= 1025);
        // A failed spawn must unlock even if another child inherited the fd.
        let inherited = std::rc::Rc::new(std::cell::RefCell::new(None));
        let child = inherited.clone();
        let lock_path = path.join("collection.lock");
        super::super::n3_test::on_lock_scope(move || {
            *child.borrow_mut() = Some(sys::PausedFork::new());
            assert!(matches!(
                sys::try_lock(File::open(lock_path).unwrap()),
                Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK)
            ));
        });
        assert!(
            spawn(
                base.join("missing-executable").as_os_str(),
                &context,
                &request,
                sys::current_uid()
            )
            .is_err()
        );
        assert!(inherited.borrow().is_some());
        drop(sys::try_lock(File::open(path.join("collection.lock")).unwrap()).unwrap());
        // SAFETY: isolated test process; let PausedFork reap its own child.
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
        drop(inherited);

        // The real worker must explicitly unlock both success and error paths,
        // including when a duplicated description remains open elsewhere.
        let request_path = path.join("worker-request");
        std::fs::write(&request_path, request.encode().unwrap()).unwrap();
        std::fs::set_permissions(&request_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let readonly = File::open(&request_path).unwrap();
        std::fs::remove_file(&request_path).unwrap();
        for request_file in [readonly, File::open(&exe).unwrap()] {
            let lock = sys::try_lock(File::open(path.join("collection.lock")).unwrap()).unwrap();
            let inherited = lock.try_clone().unwrap();
            let valid = request_file.metadata().unwrap().nlink() == 0;
            assert_eq!(
                stub_files(
                    request_file,
                    File::open(&path).unwrap(),
                    lock.into_inherited_file()
                )
                .is_ok(),
                valid
            );
            drop(sys::try_lock(File::open(path.join("collection.lock")).unwrap()).unwrap());
            drop(inherited);
        }
        spawn(exe.as_os_str(), &context, &request, sys::current_uid()).unwrap();
        let report = super::super::n3_test::wait_report(&path.join("probe"));
        assert_eq!(&report[..5], &[6, 0, libc::O_RDONLY, 1, 1]);
        assert_eq!(report[6], 0);
        assert!(!path.join(".stage-request").exists());
        let lock = File::open(path.join("collection.lock")).unwrap();
        assert!(matches!(
            sys::try_lock(lock),
            Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK)
        ));
        // Busy must not replace the request or create another collector.
        spawn(exe.as_os_str(), &context, &request, sys::current_uid()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert_eq!(
            super::super::n3_test::wait_report(&path.join("probe")),
            report
        );
        // SAFETY: known test fixture process only.
        unsafe { libc::kill(report[5], libc::SIGKILL) };
        // SAFETY: high duplicate created above, no Rust owner.
        unsafe { libc::close(high) };
        std::fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: collection spawn의 fd 계약·신호 기본값·빈 환경을 제거하는 것.
    #[test]
    fn collector_fd_contract() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::collector::tests::collector_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
