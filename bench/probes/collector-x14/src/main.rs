//! Trusted-fixture experiment only. Product repository handling belongs to a
//! later milestone. No external filters, submodules, or index writes are used.
#[cfg(not(target_os = "linux"))]
compile_error!("X-14 requires a native Linux kernel");
#[allow(dead_code)]
#[path = "../../../../crates/bingsu-collect/src/filter.rs"]
mod filter;
#[path = "../../../../crates/bingsu-collect/src/landlock.rs"]
mod landlock;
#[allow(dead_code)]
#[path = "../../../../crates/bingsu-collect/src/limits.rs"]
mod limits;
use std::{
    path::Path,
    process::{Command, Stdio},
};

fn git(path: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}
fn prepare(path: &Path) {
    std::fs::create_dir(path).unwrap();
    git(path, &["init", "--quiet", "--template="]);
    std::fs::write(path.join(".git/config"), b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = true\n[status]\n\tshowUntrackedFiles = all\n").unwrap();
    std::fs::write(path.join("tracked"), b"original\n").unwrap();
    git(path, &["add", "--", "tracked"]);
    std::fs::write(path.join("tracked"), b"changed and longer\n").unwrap();
    std::fs::write(path.join("untracked"), b"new\n").unwrap();
    assert!(!path.join(".gitmodules").exists());
    assert!(!path.join(".gitattributes").exists());
}
fn denied_processes() {
    // SAFETY: the product filter must reject this; unexpected children exit.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: exit an unexpected child immediately.
        unsafe { libc::_exit(91) };
    }
    assert_eq!(pid, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    // SAFETY: invalid clone3 pointer/length; the filter must return ENOSYS.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_clone3, 0usize, 0usize) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOSYS)
    );
    #[cfg(target_arch = "x86_64")]
    for n in [libc::SYS_fork, libc::SYS_vfork] {
        // SAFETY: raw process creation must be refused before touching arguments.
        assert_eq!(unsafe { libc::syscall(n) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
}
fn probe(path: &Path) {
    // Trusted fixture snapshot before protection, for an independent byte oracle.
    let index = std::fs::read(path.join(".git/index")).unwrap();
    limits::install_base().unwrap();
    limits::drop_capabilities().unwrap();
    // SAFETY: integer-only privilege restriction.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    let state = landlock::install_read_only().unwrap();
    if std::env::var_os("BINGSU_REQUIRE_LANDLOCK").is_some() {
        assert!(matches!(state, landlock::LandlockState::Installed { .. }));
    }
    filter::install_bootstrap().unwrap();
    let memory = limits::lower_as_under_filter().unwrap();
    filter::seal_limits().unwrap();
    denied_processes();
    assert_eq!(
        std::thread::spawn(|| {
            denied_processes();
            42
        })
        .join()
        .unwrap(),
        42
    );
    // API reference: https://docs.rs/gix/0.83.0/gix/status/index_worktree/struct.Iter.html
    // gix's parallel feature is disabled; this fixture never has >2 worker threads.
    let repo = gix::open(path).unwrap();
    let mut changes = repo
        .status(gix::progress::Discard)
        .unwrap()
        .into_index_worktree_iter(std::iter::empty::<gix::bstr::BString>())
        .unwrap();
    let mut count = 0;
    for change in changes.by_ref() {
        change.unwrap();
        count += 1;
    }
    assert!(
        count >= 2,
        "both tracked and untracked changes must be observed"
    );
    assert!(changes.into_outcome().is_some(), "status did not complete");
    // Outcome::write_changes is intentionally never called.
    assert_eq!(std::fs::read(path.join(".git/index")).unwrap(), index);
    println!(
        "X-14 status PASS changes={count} index_unchanged=1 baseline={} limit={}",
        memory.baseline_bytes, memory.memory_limit_bytes
    );
}
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 4 && args[0] == "--case" && args[1] == "child" && args[2] == "--repo" {
        probe(Path::new(&args[3]));
        return;
    }
    assert!(args == ["--case", "all"], "usage: collector-x14 --case all");
    let dir = std::env::temp_dir().join(format!("collector-x14-{}", std::process::id()));
    prepare(&dir);
    let index = std::fs::read(dir.join(".git/index")).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--case", "child", "--repo"])
        .arg(&dir)
        .env_clear();
    if std::env::var_os("BINGSU_REQUIRE_LANDLOCK").is_some() {
        command.env("BINGSU_REQUIRE_LANDLOCK", "1");
    }
    let out = command.output().unwrap();
    assert_eq!(std::fs::read(dir.join(".git/index")).unwrap(), index);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        text.lines()
            .filter(|s| s.starts_with("X-14 status PASS "))
            .count(),
        1,
        "{text}"
    );
    print!("{text}");
    println!("X-14 PASS");
}
