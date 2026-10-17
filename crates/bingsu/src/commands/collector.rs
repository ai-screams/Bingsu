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
    match sys::try_lock(&lock) {
        Ok(()) => {}
        Err(e) if matches!(e.raw_os_error(), Some(libc::EWOULDBLOCK)) => return Ok(()),
        Err(e) => return Err(e.into()),
    }
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
    spawn_fds(exe, [&readonly, &dir, &lock])?;
    // Close local lock copy, never LOCK_UN: the child owns the same description.
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
    std::panic::set_hook(Box::new(|_| {}));
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
        let request = Request::new(id, now, b"/c", b"/s", b"/repo", u32::MAX)
            .unwrap()
            .unwrap();
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
        spawn(exe.as_os_str(), &context, &request, sys::current_uid()).unwrap();
        let report = super::super::n3_test::wait_report(&path.join("probe"));
        assert_eq!(&report[..5], &[6, 0, libc::O_RDONLY, 1, 1]);
        assert_eq!(report[6], 0);
        assert!(!path.join(".stage-request").exists());
        let lock = File::open(path.join("collection.lock")).unwrap();
        assert_eq!(
            sys::try_lock(&lock).unwrap_err().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
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
