//! Linux-only container acceptance. Run each ignored parent separately with
//! --exact --ignored --nocapture --test-threads=1. Landlock is irreversible.
//! Two-uid parent needs root (SETUID/SETGID/CHOWN); no privileged mount required.
#![cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/landlock.rs"]
mod landlock;
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
use meter::{Meter, Phase};
use safe_read::{Access, DiscoveryQuery, Guarantee, ReadCap, ReadError as E};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(30))
}
fn cap() -> ReadCap {
    ReadCap {
        bytes: 64,
        single_link: false,
    }
}
fn fixture(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("bingsu-b1-{label}-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::create_dir_all(path.join("root/a/b")).unwrap();
    fs::write(path.join("canary"), b"EXTERNAL").unwrap();
    fs::write(path.join("root/HEAD"), b"inside").unwrap();
    path
}
fn root(path: &std::path::Path, meter: &mut Meter) -> safe_read::Root {
    safe_read::acquire(
        path.as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        meter,
    )
    .unwrap()
    .select_cwd()
    .unwrap()
}
fn helper(path: &std::path::Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "linux_attacker_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BINGSU_ATTACK_PATH", path)
        .env("BINGSU_ATTACK_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    command
}
fn ack(reader: &mut impl BufRead, expected: &str) {
    loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "attacker exited before {expected}"
        );
        if line.trim_end().ends_with(expected) {
            break;
        }
    }
}

// 이것을 실패시키는 것: read layer 설치를 빼거나 성공 전 B3 권한 승격을 허용하는 것.
#[test]
#[ignore = "Linux-only isolated Landlock acceptance; unavailable kernel is BLOCKED"]
fn linux_landlock_backstop_blocks_held_fd_after_coarse_rename() {
    let path = fixture("landlock");
    let mut attacker = helper(&path, "rename").spawn().unwrap();
    let mut reader = BufReader::new(attacker.stdout.take().unwrap());
    let mut writer = attacker.stdin.take().unwrap();
    ack(&mut reader, "READY");
    let mut budget = meter();
    let root = root(&path.join("root"), &mut budget);
    let mut access = Access::stage_a_only();
    assert_eq!(access.guarantee(), None);
    let proof = install_read_layer(&root);
    access.landlock_reads_installed(proof);
    assert_eq!(access.guarantee(), Some(Guarantee::LandlockReadLayer));
    // 이것을 실패시키는 것: READ_DIR handled right를 누락하는 것.
    assert_eq!(
        fs::read_dir(&path).unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
    assert!(fs::read_dir(path.join("root")).is_ok());
    assert_eq!(
        safe_read::read(&root, b"HEAD", cap(), &access, &mut budget).unwrap(),
        b"inside"
    );
    let before = budget.counts[Phase::Content as usize].read_bytes;
    let mut visits = 0;
    budget.hook = Some(Box::new(move |event| {
        if event == "after_open_component" {
            visits += 1;
            if visits == 2 {
                writeln!(writer, "MOVE").unwrap();
                writer.flush().unwrap();
                ack(&mut reader, "MOVED");
            }
        }
    }));
    let result = safe_read::read(&root, b"a/b/value", cap(), &access, &mut budget);
    println!(
        "LANDLOCK result={result:?} outside_bytes={}",
        budget.counts[Phase::Content as usize].read_bytes - before
    );
    assert_eq!(
        result,
        Err(E::Denied),
        "held b outside root must fail open with EACCES"
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, before);
    budget.hook = None;
    assert!(attacker.wait().unwrap().success());
    // The unconfined child cleans up; this thread cannot list outside root.
}

fn install_read_layer(root: &safe_read::Root) -> landlock::ReadLayerInstalled {
    assert_eq!(
        // SAFETY: monotonically removes privilege from this disposable child.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    landlock::restrict_reads(&[root.read_rule_fd()]).expect("BLOCKED: Landlock read layer required")
}

// 이것을 실패시키는 것: root가 아닌 이동한 fd에서 openat2를 호출하거나 BENEATH를 생략하는 것.
#[test]
fn linux_openat2_coarse_rename_reads_zero_external_bytes() {
    let path = fixture("openat2");
    let mut budget = meter();
    let root = root(&path.join("root"), &mut budget);
    let access = Access::probe(&mut budget).unwrap();
    assert_eq!(
        access.guarantee(),
        Some(Guarantee::Openat2),
        "BLOCKED: native openat2 required"
    );
    let moved = path.clone();
    budget.hook = Some(Box::new(move |event| {
        if event == "before_openat2" {
            fs::rename(moved.join("root/a"), moved.join("moved-a")).unwrap();
            fs::rename(moved.join("canary"), moved.join("moved-a/b/value")).unwrap();
            std::os::unix::fs::symlink("../moved-a", moved.join("root/a")).unwrap();
        }
    }));
    assert_eq!(
        safe_read::read(&root, b"a/b/value", cap(), &access, &mut budget),
        Err(E::Escape)
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
    fs::remove_dir_all(path).unwrap();
}

// 이것을 실패시키는 것: victim 파일을 attacker 소유로 바꾸거나 0700/sticky 보호를 제거해 rename/hardlink를 허용하는 것.
#[test]
#[ignore = "Linux-only two-uid container test: root with SETUID/SETGID/CHOWN required"]
fn linux_two_uid_victim_canaries_are_unreadable() {
    assert_eq!(
        // SAFETY: identity query only.
        unsafe { libc::geteuid() },
        0,
        "BLOCKED: run as container root"
    );
    let path = fixture("two-uid");
    fs::create_dir(path.join("private")).unwrap();
    fs::create_dir(path.join("sticky")).unwrap();
    for dir in ["private", "sticky"] {
        fs::write(path.join(dir).join("canary"), b"VICTIM").unwrap();
        fs::set_permissions(
            path.join(dir).join("canary"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        chown(&path.join(dir).join("canary"), 21001);
    }
    chown(&path.join("private"), 21001);
    fs::set_permissions(path.join("private"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(path.join("sticky"), fs::Permissions::from_mode(0o1777)).unwrap();
    chown(&path.join("root"), 21002);
    let mut command = helper(&path, "two-uid");
    let drop_credentials = || {
        // SAFETY: async-signal-safe syscall in child; clears inherited groups.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: dedicated attacker group in the disposable test child.
        if unsafe { libc::setgid(21002) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: irreversible privilege drop in the disposable test child.
        if unsafe { libc::setuid(21002) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: closure uses only async-signal-safe credential syscalls.
    unsafe { command.pre_exec(drop_credentials) };
    let output = command.output().unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(output.status.success());
    let mut budget = meter();
    let root = root(&path.join("root"), &mut budget);
    let access = Access::probe(&mut budget).unwrap();
    assert_eq!(access.guarantee(), Some(Guarantee::Openat2));
    // 이것을 실패시키는 것: 외부 metadata root의 동일 uid 조건을 제거하는 것.
    assert!(matches!(
        safe_read::acquire(
            path.join("private").as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut budget
        )
        .unwrap()
        .select_metadata(&root, &mut budget),
        Err(E::Denied)
    ));
    for dir in ["private", "sticky"] {
        for suffix in ["rename", "hard"] {
            assert_eq!(
                safe_read::read(
                    &root,
                    format!("{dir}-{suffix}").as_bytes(),
                    cap(),
                    &access,
                    &mut budget
                ),
                Err(E::Missing)
            );
        }
        assert_eq!(
            safe_read::read(
                &root,
                format!("{dir}-symlink").as_bytes(),
                cap(),
                &access,
                &mut budget
            ),
            Err(E::Escape)
        );
    }
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
    fs::remove_dir_all(path).unwrap();
}
fn chown(path: &std::path::Path, uid: u32) {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: fixture-owned terminated path and dedicated test uid/gid.
    assert_eq!(unsafe { libc::chown(path.as_ptr(), uid, uid) }, 0);
}

// 이것을 실패시키는 것: 부모 barrier 전에 공격하거나 권한 거부 결과를 무시하는 것(부모가 자식 실패를 검사).
#[test]
#[ignore = "internal attacker child, started before Landlock or with attacker uid"]
fn linux_attacker_child() {
    let path = PathBuf::from(std::env::var_os("BINGSU_ATTACK_PATH").unwrap());
    if std::env::var("BINGSU_ATTACK_MODE").unwrap() == "rename" {
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "MOVE");
        fs::rename(path.join("root/a"), path.join("moved-a")).unwrap();
        fs::rename(path.join("canary"), path.join("moved-a/b/value")).unwrap();
        // a can be restored only while b remains outside: never root->a->b->value.
        fs::rename(path.join("moved-a/b"), path.join("moved-b")).unwrap();
        fs::rename(path.join("moved-a"), path.join("root/a")).unwrap();
        println!("MOVED");
        std::io::stdout().flush().unwrap();
        line.clear();
        assert_eq!(std::io::stdin().read_line(&mut line).unwrap(), 0);
        fs::remove_dir_all(path).unwrap();
    } else {
        for dir in ["private", "sticky"] {
            for (suffix, result) in [
                (
                    "rename",
                    fs::rename(
                        path.join(dir).join("canary"),
                        path.join("root").join(format!("{dir}-rename")),
                    ),
                ),
                (
                    "hard",
                    fs::hard_link(
                        path.join(dir).join("canary"),
                        path.join("root").join(format!("{dir}-hard")),
                    ),
                ),
            ] {
                let errno = result.unwrap_err().raw_os_error().unwrap();
                println!("TWO_UID {dir} {suffix} errno={errno}");
                assert!(errno == libc::EACCES || errno == libc::EPERM);
            }
            std::os::unix::fs::symlink(
                format!("../{dir}/canary"),
                path.join("root").join(format!("{dir}-symlink")),
            )
            .unwrap();
        }
    }
}

// 이것을 실패시키는 것: read-layer rule 추가 실패를 무시하고 성공 증거를 발급하는 것.
#[test]
fn linux_read_layer_failure_cannot_grant_access() {
    use std::os::fd::AsFd;
    let file = fs::File::open("/dev/null").unwrap();
    // READ_DIR on a non-directory must fail before restrict_self; no NNP or
    // irreversible restriction is needed for this error-path test.
    let result = landlock::restrict_reads(&[file.as_fd()]);
    let error = match result {
        Ok(_) => panic!("failed rule must never mint installation evidence"),
        Err(error) => error,
    };
    assert_eq!(
        error.raw_os_error(),
        Some(libc::EINVAL),
        "BLOCKED if Landlock unavailable"
    );
    assert_eq!(Access::stage_a_only().guarantee(), None);
}
