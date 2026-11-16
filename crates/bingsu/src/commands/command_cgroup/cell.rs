use super::fs::{self, Dir, Fs};
use super::*;
use std::{fs::File, os::unix::fs::DirBuilderExt, path::PathBuf, process::Command};

/// The test process's own cgroup folder.
pub(crate) fn own_cgroup() -> PathBuf {
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    let path = cgroup::own_path(&text).expect("cgroup v2");
    PathBuf::from(format!("/sys/fs/cgroup{}", String::from_utf8_lossy(path)))
}

/// A fresh parent folder `bingsu-cmd-<tag>` under the test's cgroup.
pub(crate) fn parent(tag: &str) -> (PathBuf, Dir) {
    let p = own_cgroup().join(format!("bingsu-cmd-test-{tag}-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o755).create(&p).unwrap();
    let dir = Dir::new(File::open(&p).unwrap());
    (p, dir)
}

/// Whether this run is the privileged cell; atomic-path tests return
/// at once elsewhere (CI checks each one PASSED in that cell).
pub(crate) fn privileged() -> bool {
    #[expect(clippy::disallowed_methods, reason = "test-only cell name")]
    let cell = std::env::var("BINGSU_CGROUP_CELL");
    cell.is_ok_and(|c| c == "priv")
}

/// Unit folders under a session parent.
pub(crate) fn units(parent: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(parent)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| cgroup::is_unit_name(n.as_bytes()))
        .collect();
    v.sort();
    v
}

pub(crate) fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        !s.rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with('Z')
    })
}

/// The cell this run is in: `BINGSU_CGROUP_CELL=priv|plain`.
pub(crate) fn cell() -> String {
    #[expect(clippy::disallowed_methods, reason = "test-only cell name")]
    std::env::var("BINGSU_CGROUP_CELL").expect("BINGSU_CGROUP_CELL=priv|plain")
}

fn release() -> Vec<u8> {
    std::fs::read("/proc/sys/kernel/osrelease").unwrap()
}

fn who(session: &str) -> (Vec<u8>, (u64, u64), u32) {
    use std::os::unix::fs::MetadataExt;
    let root = std::fs::metadata(std::env::temp_dir()).unwrap();
    (
        session.as_bytes().to_vec(),
        (root.dev(), root.ino()),
        super::super::sys::current_uid(),
    )
}

fn open_at(mount: &[u8], release: &[u8], text: &[u8], session: &str) -> Option<Dir> {
    let (session, runtime, me) = who(session);
    fs::open_session_at(
        mount,
        release,
        text,
        &fs::Who {
            session: &session,
            runtime,
            me,
            pid: std::process::id(),
        },
    )
}

fn parent_path(session: &str) -> PathBuf {
    let (session, runtime, _) = who(session);
    own_cgroup().join(cgroup::parent_name(&session, runtime))
}

// 특권 셀은 원자 경로, 기본 셀은 최선 노력(X-04 음성 대조: 하위 폴더 생성 EROFS). 두 번째 판정은 같은
// 부모 폴더를 다시 연다. 이것을 실패시키는 것: 부모를 열지 못하면 자기 cgroup 폴더를 대신 쓰는 것(기본
// 셀에서 Some), open_session_at의 커널 조건을 지우는 것(5.13 입력이 Some).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_capability_matches_the_cell() {
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    let session = format!("cell-{}", std::process::id());
    let release = release();
    let first = open_at(b"/sys/fs/cgroup", &release, &text, &session);
    match cell().as_str() {
        "plain" => assert!(first.is_none()),
        "priv" => {
            use std::os::unix::fs::MetadataExt;
            let a = first.expect("atomic path in the privileged cell");
            let b = open_at(b"/sys/fs/cgroup", &release, &text, &session).unwrap();
            assert_eq!(
                a.folder.metadata().unwrap().ino(),
                b.folder.metadata().unwrap().ino()
            );
            assert!(open_at(b"/sys/fs/cgroup", b"5.13.19\n", &text, &session).is_none());
            std::fs::remove_dir(parent_path(&session)).unwrap();
        }
        other => panic!("unknown cell {other}"),
    }
}

// cgroup v2가 아닌 곳(일반 파일 시스템)은 원자 경로가 아니다. 이것을 실패시키는 것: 자기 cgroup 폴더의
// fstatfs CGROUP2_SUPER_MAGIC 비교를 지우는 것(임시 폴더 아래에 부모를 만들고 Some).
#[test]
fn test_capability_needs_cgroup2() {
    let root = std::env::temp_dir().join(format!("bingsu-cg-v1-{}", std::process::id()));
    std::fs::create_dir_all(root.join("user.slice")).unwrap();
    std::fs::write(
        root.join("user.slice/cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    let mount = root.as_os_str().as_encoded_bytes().to_vec();
    let got = open_at(&mount, b"6.8.0", b"0::/user.slice\n", "s");
    std::fs::remove_dir_all(&root).unwrap();
    assert!(got.is_none());
}

// 남이 만든 부모 폴더는 쓰지 않는다. 이것을 실패시키는 것: 소유자 비교를 지우는 것.
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_capability_refuses_a_foreign_parent() {
    if !privileged() {
        return;
    }
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    let session = format!("foreign-{}", std::process::id());
    let path = parent_path(&session);
    std::fs::create_dir(&path).unwrap();
    std::os::unix::fs::chown(&path, Some(4242), None).unwrap();
    let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
    std::fs::remove_dir(&path).unwrap();
    assert!(got.is_none());
}

// `0::` 경로가 이 프로세스를 담지 않은 cgroup을 가리키면(namespace를 만들고 다시 마운트하지 않은 경우의
// 모양) 원자 경로가 아니다. 이것을 실패시키는 것: 자기 cgroup의 cgroup.procs 확인을 지우는 것(남의 cgroup
// 아래에 부모를 만들고 Some).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_capability_needs_its_own_cgroup() {
    if !privileged() {
        return;
    }
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    let own = cgroup::own_path(&text).unwrap();
    let other = format!("bingsu-other-{}", std::process::id());
    let fake = format!(
        "0::{}/{other}\n",
        String::from_utf8_lossy(own).trim_end_matches('/')
    );
    std::fs::create_dir(own_cgroup().join(&other)).unwrap();
    let session = format!("other-{}", std::process::id());
    let got = open_at(b"/sys/fs/cgroup", &release(), fake.as_bytes(), &session);
    let made = own_cgroup()
        .join(&other)
        .join(cgroup::parent_name(&who(&session).0, who(&session).1));
    let _ = std::fs::remove_dir(&made);
    std::fs::remove_dir(own_cgroup().join(&other)).unwrap();
    assert!(got.is_none());
}

// GC의 자기 cgroup도 회차와 같이 이 프로세스를 담은 cgroup이어야 한다(m6-C4a7). 양성 대조: 실제
// `/proc/self/cgroup`은 연다. 이것을 실패시키는 것: GC가 cgroup.procs 확인 없이 폴더를 여는 것(남의
// cgroup에서 빈 부모를 지울 수 있음).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_gc_own_cgroup_needs_its_own_cgroup() {
    if !privileged() {
        return;
    }
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    assert!(fs::open_own_member_at(b"/sys/fs/cgroup", &text).is_some());
    let own = cgroup::own_path(&text).unwrap();
    let other = format!("bingsu-gc-other-{}", std::process::id());
    let fake = format!(
        "0::{}/{other}\n",
        String::from_utf8_lossy(own).trim_end_matches('/')
    );
    std::fs::create_dir(own_cgroup().join(&other)).unwrap();
    let got = fs::open_own_member_at(b"/sys/fs/cgroup", fake.as_bytes());
    std::fs::remove_dir(own_cgroup().join(&other)).unwrap();
    assert!(got.is_none());
}

// 실제 cgroup namespace를 만들고 다시 마운트하지 않은 프로세스(자식 시험)는 원자 경로를 고르지 않는다.
// 이것을 실패시키는 것: 위와 같은 cgroup.procs 확인 삭제(namespace 뿌리로 보이는 마운트 뿌리 아래에 부모를
// 만들고 Some).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_capability_refuses_an_unremounted_namespace() {
    if !privileged() {
        return;
    }
    let _inherited_fds = super::super::sys::test_inherited_fd_lock();
    let inner = own_cgroup().join(format!("bingsu-ns-{}", std::process::id()));
    std::fs::create_dir(&inner).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::command_cgroup::cell::unremounted_namespace_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BINGSU_NS_CGROUP", &inner)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = std::fs::remove_dir(&inner);
    assert!(
        text.contains("NS-CHILD atomic=false"),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Child of the test above: moves itself into `BINGSU_NS_CGROUP`, makes a
/// cgroup namespace there without remounting `/sys/fs/cgroup`, and
/// reports the capability.
#[test]
#[ignore = "child: an unremounted cgroup namespace"]
fn unremounted_namespace_child() {
    #[expect(clippy::disallowed_methods, reason = "test-only child input")]
    let Ok(inner) = std::env::var("BINGSU_NS_CGROUP") else {
        return;
    };
    std::fs::write(
        format!("{inner}/cgroup.procs"),
        std::process::id().to_string(),
    )
    .unwrap();
    // SAFETY: plain namespace call on this test thread.
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWCGROUP) }, 0);
    // Read from this thread: the path is relative to its new namespace.
    let text = std::fs::read("/proc/thread-self/cgroup").unwrap();
    let session = format!("ns-{}", std::process::id());
    let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
    if got.is_some() {
        let (s, r, _) = who(&session);
        let line = String::from_utf8_lossy(&text).into_owned();
        let rel = line
            .trim()
            .trim_start_matches("0::")
            .trim_end_matches('/')
            .to_owned();
        let _ = std::fs::remove_dir(format!(
            "/sys/fs/cgroup{rel}/{}",
            cgroup::parent_name(&s, r)
        ));
    }
    // Back out of the folder so the parent test can remove it.
    let _ = std::fs::write(
        "/sys/fs/cgroup/cgroup.procs",
        std::process::id().to_string(),
    );
    println!("NS-CHILD atomic={}", got.is_some());
}

// 부모 자리에만 일반 폴더를 bind mount하면 원자 경로가 아니다. 같은 mount면 같은 cgroup v2이므로 부모 fd의
// mount id 비교가 이것을 맡는다. 이것을 실패시키는 것: 부모 fd의 mount id 비교를 지우는 것.
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_capability_refuses_a_bind_mounted_parent() {
    if !privileged() {
        return;
    }
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    let session = format!("bind-{}", std::process::id());
    let path = parent_path(&session);
    let plain = std::env::temp_dir().join(format!("bingsu-bind-{}", std::process::id()));
    std::fs::create_dir(&plain).unwrap();
    std::fs::create_dir(&path).unwrap();
    let c = |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: NUL-terminated paths; a bind mount in this container only.
    let rc = unsafe {
        libc::mount(
            c(&plain).as_ptr(),
            c(&path).as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
    let ok = got.is_none();
    drop(got);
    // SAFETY: the mount made above.
    unsafe { libc::umount2(c(&path).as_ptr(), libc::MNT_DETACH) };
    std::fs::remove_dir(&path).unwrap();
    std::fs::remove_dir(&plain).unwrap();
    assert!(ok);
}

fn bind(from: &std::path::Path, onto: &std::path::Path) {
    let c = |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: NUL-terminated paths; a bind mount in this container only.
    let rc = unsafe {
        libc::mount(
            c(from).as_ptr(),
            c(onto).as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
}

fn unbind(at: &std::path::Path) {
    let c = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the mount made by bind().
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
}

// 다른 세션의 실제 cgroup v2 부모를 내 부모 이름 자리에 bind mount하면(소유자·cgroup2 검사는 통과) 자기
// cgroup 폴더와 mount id가 달라 원자 경로가 아니다. 이것을 실패시키는 것: 부모 fd의 mount id 비교를 지우는 것.
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_capability_refuses_a_foreign_parent_mounted_over_its_name() {
    if !privileged() {
        return;
    }
    let text = std::fs::read("/proc/self/cgroup").unwrap();
    let session = format!("over-{}", std::process::id());
    let mine = parent_path(&session);
    let other = parent_path(&format!("other-session-{}", std::process::id()));
    std::fs::create_dir(&mine).unwrap();
    std::fs::create_dir(&other).unwrap();
    bind(&other, &mine);
    let got = open_at(b"/sys/fs/cgroup", &release(), &text, &session);
    let refused = got.is_none();
    drop(got);
    unbind(&mine);
    std::fs::remove_dir(&mine).unwrap();
    std::fs::remove_dir(&other).unwrap();
    assert!(refused);
}

// 부모 아래 단위 이름 자리에 다른 cgroup을 bind mount해도 회수는 그 cgroup을 kill하거나 지우지 않는다. 이것을
// 실패시키는 것: Fs::open의 mount id 비교를 지우는 것(남의 cgroup의 프로세스가 죽음).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_reclaim_never_enters_a_cgroup_mounted_below() {
    if !privileged() {
        return;
    }
    let _inherited_fds = super::super::sys::test_inherited_fd_lock();
    let (p, mut dir) = parent("below");
    let victim = own_cgroup().join(format!("bingsu-victim-{}", std::process::id()));
    std::fs::create_dir(&victim).unwrap();
    let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
    std::fs::write(victim.join("cgroup.procs"), sleep.id().to_string()).unwrap();
    let unit = p.join(cgroup::unit_name(9));
    std::fs::create_dir(&unit).unwrap();
    bind(&victim, &unit);
    let r = reclaim(&mut Fs, &mut dir);
    std::thread::sleep(std::time::Duration::from_millis(50));
    let survived = alive(sleep.id() as i32);
    unbind(&unit);
    let _ = sleep.kill();
    let _ = sleep.wait();
    let _ = std::fs::remove_dir(&unit);
    let _ = std::fs::remove_dir(&p);
    while std::fs::remove_dir(&victim).is_err() {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(survived, "{r:?}");
}

// 부모 아래 단위 이름 자리에 다른 cgroup 폴더를 bind mount하면, 그 폴더는 부모와 mount가 달라 감독의 단위로
// 받지 않는다(mkdirat와 열기 사이에 bind하는 경쟁을 막는 비교; 경쟁 창 없이 비교 함수를 직접 본다). 이것을
// 실패시키는 것: on_parent_mount의 비교를 지우는 것.
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_a_folder_bound_below_the_parent_is_not_its_child() {
    if !privileged() {
        return;
    }
    let _inherited_fds = super::super::sys::test_inherited_fd_lock();
    let (p, _dir) = parent("unitbind");
    let parent_fd = File::open(&p).unwrap();
    let own = p.join(cgroup::unit_name(1));
    std::fs::create_dir(&own).unwrap();
    let mine = File::open(&own).unwrap();
    assert!(fs::on_parent_mount(&parent_fd, &mine).is_some());
    let victim = own_cgroup().join(format!("bingsu-unitvictim-{}", std::process::id()));
    std::fs::create_dir(&victim).unwrap();
    let unit = p.join(cgroup::unit_name(9));
    std::fs::create_dir(&unit).unwrap();
    bind(&victim, &unit);
    let bound = File::open(&unit).unwrap();
    let refused = fs::on_parent_mount(&parent_fd, &bound).is_none();
    drop(bound);
    unbind(&unit);
    drop(mine);
    let _ = std::fs::remove_dir(&unit);
    let _ = std::fs::remove_dir(&own);
    let _ = std::fs::remove_dir(&victim);
    let _ = std::fs::remove_dir(&p);
    assert!(refused);
}

// 단위 폴더의 cgroup.kill 자리에 다른 cgroup의 cgroup.kill을 파일 bind mount하면, 그 파일은 단위 폴더와
// mount id가 달라 열기를 거부한다. 거부하지 않으면 그 쓰기가 남의 cgroup을 죽인다. 이것을 실패시키는 것:
// kill_file의 mount id 비교를 지우는 것(victim의 sleep이 죽음).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn test_kill_file_refuses_a_file_bind_mounted_over_it() {
    if !privileged() {
        return;
    }
    let _inherited_fds = super::super::sys::test_inherited_fd_lock();
    let (p, _dir) = parent("killbind");
    let victim = own_cgroup().join(format!("bingsu-killvictim-{}", std::process::id()));
    std::fs::create_dir(&victim).unwrap();
    let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
    std::fs::write(victim.join("cgroup.procs"), sleep.id().to_string()).unwrap();
    let unit = p.join(cgroup::unit_name(9));
    std::fs::create_dir(&unit).unwrap();
    // Unbound, the unit's own cgroup.kill opens.
    let folder = File::open(&unit).unwrap();
    assert!(fs::kill_file(&folder).is_ok());
    bind(&victim.join("cgroup.kill"), &unit.join("cgroup.kill"));
    let refused = fs::kill_file(&folder).map(|kill| fs::write_kill(&kill));
    std::thread::sleep(std::time::Duration::from_millis(50));
    let survived = alive(sleep.id() as i32);
    unbind(&unit.join("cgroup.kill"));
    let _ = sleep.kill();
    let _ = sleep.wait();
    drop(folder);
    let _ = std::fs::remove_dir(&unit);
    let _ = std::fs::remove_dir(&p);
    while std::fs::remove_dir(&victim).is_err() {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(refused.is_err() && survived, "{refused:?} {survived}");
}

// 실제 cgroupfs에서 kill → populated 0 → 후위 rmdir. 대상 프로세스는 단위 아래 깊이 2 폴더에 있다.
// 이것을 실패시키는 것: Fs::kill이 cgroup.kill을 쓰지 않는 것(populated가 1로 남아 단위가 남음).
#[test]
#[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
fn fs_reclaim_kills_and_removes_a_nested_tree() {
    if !privileged() {
        return;
    }
    let _inherited_fds = super::super::sys::test_inherited_fd_lock();
    let (p, mut dir) = parent("nested");
    let unit = p.join(cgroup::unit_name(1));
    std::fs::create_dir_all(unit.join("a/b")).unwrap();
    std::fs::create_dir_all(unit.join("c")).unwrap();
    let mut sleep = Command::new("sleep").arg("60").spawn().unwrap();
    std::fs::write(unit.join("a/b/cgroup.procs"), sleep.id().to_string()).unwrap();
    let r = reclaim(&mut Fs, &mut dir);
    let _ = sleep.wait();
    assert!(!alive(sleep.id() as i32));
    assert_eq!((r.removed, r.stuck, r.failed), (1, 0, 0), "{r:?}");
    assert!(!unit.exists());
    std::fs::remove_dir(&p).unwrap();
}
