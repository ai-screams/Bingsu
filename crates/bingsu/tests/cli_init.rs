//! `bingsu init` contract (spec section 5 "connection" and "init output",
//! section 4 "runtime root"). Install dirs live under CARGO_TARGET_TMPDIR,
//! not /tmp, so no world-writable ancestor triggers the tamper warning.
#![cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cli_init")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn install(base: &Path, dir_name: &[u8]) -> PathBuf {
    let dir = base.join(std::ffi::OsStr::from_bytes(dir_name));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = dir.join("bingsu");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_bingsu"), &exe).unwrap();
    exe
}

fn init(exe: &Path, shell: &str, base: &Path) -> Output {
    Command::new(exe)
        .args(["init", shell])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", base.join("run"))
        .env("XDG_CONFIG_HOME", base.join("cfg"))
        .env("XDG_STATE_HOME", base.join("state"))
        .env("XDG_CACHE_HOME", base.join("cache"))
        .output()
        .unwrap()
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// 이것을 실패시키는 것: 지원하지 않는 셸에서 stdout에 무엇이든 쓰는 것(eval되는 날 글자).
#[test]
fn unsupported_shell_prints_nothing_on_stdout() {
    for args in [&["init", "tcsh"][..], &["init"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_bingsu"))
            .args(args)
            .output()
            .unwrap();
        assert!(out.stdout.is_empty(), "{args:?}");
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(
            out.stderr,
            b"bingsu: unsupported shell. Supported: zsh, bash, fish\n"
        );
    }
}

#[test]
fn init_embeds_invoked_symlink_path_not_target() {
    let base = scratch("symlink");
    let exe = install(&base, b"bin");
    let out = init(&exe, "zsh", &base);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut want = b"'".to_vec();
    want.extend_from_slice(exe.as_os_str().as_bytes());
    want.extend_from_slice(b"' prompt");
    assert!(has(&out.stdout, &want));
    let target = std::fs::canonicalize(env!("CARGO_BIN_EXE_bingsu")).unwrap();
    assert!(!has(&out.stdout, target.as_os_str().as_bytes()));
}

#[test]
fn init_finds_bare_argv0_on_path_without_resolving_it() {
    let base = scratch("argv0");
    let exe = install(&base, b"bin");
    let out = Command::new("bingsu")
        .args(["init", "bash"])
        .env_clear()
        .env("PATH", exe.parent().unwrap())
        .env("XDG_RUNTIME_DIR", base.join("run"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(has(&out.stdout, exe.as_os_str().as_bytes()));
}

#[test]
fn init_pins_runtime_root_and_roots() {
    let base = scratch("roots");
    let exe = install(&base, b"bin");
    let out = init(&exe, "zsh", &base);
    let run = std::fs::canonicalize(base.join("run/bingsu")).unwrap();
    let md = std::fs::metadata(&run).unwrap();
    assert_eq!(md.mode() & 0o777, 0o700);
    let word = format!(
        "'--runtime-root={}:{}:{}'",
        md.dev(),
        md.ino(),
        run.display()
    );
    assert!(has(&out.stdout, word.as_bytes()), "missing {word}");
    for (flag, p) in [
        ("--config-root=", "cfg/bingsu"),
        ("--state-root=", "state/bingsu"),
        ("--log-root=", "state/bingsu/log"),
    ] {
        let w = format!("'{flag}{}'", base.join(p).display());
        assert!(has(&out.stdout, w.as_bytes()), "missing {w}");
    }
}

// 이것을 실패시키는 것: 설정 뿌리를 정규화하지 않고 symlink 경로 그대로 박는 것.
#[test]
fn config_root_is_canonical() {
    let base = scratch("canonical");
    let exe = install(&base, b"bin");
    std::fs::create_dir_all(base.join("real-cfg")).unwrap();
    std::os::unix::fs::symlink(base.join("real-cfg"), base.join("cfg")).unwrap();
    let out = init(&exe, "zsh", &base);
    let want = format!(
        "'--config-root={}'",
        std::fs::canonicalize(base.join("real-cfg"))
            .unwrap()
            .join("bingsu")
            .display()
    );
    assert!(has(&out.stdout, want.as_bytes()), "missing {want}");
}

// 이것을 실패시키는 것: 상대 경로 XDG_RUNTIME_DIR를 받아 주는 것.
#[test]
fn relative_xdg_runtime_dir_falls_back_to_cache() {
    let base = scratch("relative");
    let exe = install(&base, b"bin");
    let out = Command::new(&exe)
        .args(["init", "zsh"])
        .env_clear()
        .env("XDG_RUNTIME_DIR", "relative/run")
        .env("XDG_CACHE_HOME", base.join("cache"))
        .output()
        .unwrap();
    let run = std::fs::canonicalize(base.join("cache/bingsu/run")).unwrap();
    assert!(has(&out.stdout, run.as_os_str().as_bytes()));
}

#[test]
fn unusable_runtime_root_drops_the_word_and_says_why() {
    let base = scratch("unusable");
    let exe = install(&base, b"bin");
    std::fs::write(base.join("run"), b"not a dir").unwrap();
    let out = init(&exe, "zsh", &base);
    assert_eq!(out.status.code(), Some(0));
    assert!(!has(&out.stdout, b"--runtime-root="));
    assert_eq!(
        out.stderr,
        b"bingsu: no usable runtime folder; the prompt runs without saved state. Run: bingsu doctor\n"
    );
}

// 이것을 실패시키는 것: 틀 표식을 값에 넣은 뒤 다시 훑는 치환(값 안의 표식이 바뀜).
#[test]
fn template_markers_inside_paths_are_not_substituted() {
    let base = scratch("marker");
    let exe = install(&base, b"@CONFIG_ROOT@ dir");
    let out = init(&exe, "zsh", &base);
    assert!(has(&out.stdout, b"/@CONFIG_ROOT@ dir/bingsu' prompt"));
    for t in [
        "@BIN@",
        "@RECORD@",
        "@SESSION@",
        "@RUNTIME_ROOT@",
        "@STATE_ROOT@",
        "@LOG_ROOT@",
        "@KNOWN_CODES@",
        "@MSG_BASH_TOO_OLD@",
        "@MSG_LATE_HOOK_ZSH@",
        "@MSG_LATE_HOOK_BASH@",
    ] {
        assert!(!has(&out.stdout, t.as_bytes()), "unreplaced {t}");
    }
}

// Decision 2 checks, one row per inspected place. 이것을 실패시키는 것: 링크·대상·상위 폴더 중 하나를 빼고 보는 것.
#[test]
fn tamper_rows_warn_on_stderr_only() {
    const TAMPER: &[u8] = b"bingsu: the bingsu executable or a folder above it can be changed by another user. Run: bingsu doctor\n";
    // (row, setup on (base, exe), expected stderr)
    type Setup = fn(&Path, &Path);
    let rows: &[(&str, Setup, &[u8])] = &[
        ("clean install", |_, _| {}, b""),
        (
            "install dir other-writable",
            |_, exe| chmod(exe.parent().unwrap(), 0o777),
            TAMPER,
        ),
        (
            "ancestor other-writable",
            |base, _| chmod(base, 0o777),
            TAMPER,
        ),
        (
            "target dir other-writable",
            |base, _| chmod(&base.join("target"), 0o777),
            TAMPER,
        ),
    ];
    for (row, setup, want) in rows {
        let base = scratch(&format!("tamper-{}", row.replace(' ', "-")));
        let target_dir = base.join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        chmod(&target_dir, 0o755);
        let target = target_dir.join("bingsu-real");
        std::fs::copy(env!("CARGO_BIN_EXE_bingsu"), &target).unwrap();
        let dir = base.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        chmod(&dir, 0o755);
        let exe = dir.join("bingsu");
        std::os::unix::fs::symlink(&target, &exe).unwrap();
        setup(&base, &exe);
        let out = init(&exe, "fish", &base);
        chmod(&base, 0o755);
        assert_eq!(out.status.code(), Some(0), "{row}");
        assert!(!out.stdout.is_empty(), "{row}");
        assert_eq!(
            out.stderr,
            *want,
            "{row}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

// Fail closed. 이것을 실패시키는 것: 조회 실패를 안전으로 보는 것.
#[test]
fn uninspectable_target_warns_unknown() {
    if is_root() {
        eprintln!("skip: root reads a 0000 folder, so nothing is uninspectable");
        return;
    }
    let base = scratch("unknown");
    let hidden = base.join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let target = hidden.join("bingsu-real");
    std::fs::copy(env!("CARGO_BIN_EXE_bingsu"), &target).unwrap();
    let exe_dir = base.join("bin");
    std::fs::create_dir_all(&exe_dir).unwrap();
    chmod(&exe_dir, 0o755);
    let exe = exe_dir.join("bingsu");
    std::os::unix::fs::symlink(&target, &exe).unwrap();
    // Run a copy outside `hidden`, with argv0 = the link, then make the
    // link's target folder unreadable so canonicalize() fails.
    let copy = base.join("bingsu-copy");
    std::fs::copy(&target, &copy).unwrap();
    chmod(&hidden, 0o000);
    let out = Command::new(&copy)
        .args(["init", "zsh"])
        .arg0(exe.as_os_str())
        .env_clear()
        .env("XDG_RUNTIME_DIR", base.join("run"))
        .output()
        .unwrap();
    chmod(&hidden, 0o755);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        out.stderr,
        b"bingsu: could not confirm that the bingsu executable and the folders above it are safe from other users. Run: bingsu doctor\n"
    );
}

// macOS ACL rows. 이것을 실패시키는 것: ACL을 보지 않거나, deny 항목을 위험으로 보는 것.
#[cfg(target_os = "macos")]
#[test]
fn macos_acl_rows() {
    for (row, entry, want_warn) in [
        ("allow write", "everyone allow write", true),
        ("deny delete", "everyone deny delete", false),
    ] {
        let base = scratch(&format!("acl-{}", row.replace(' ', "-")));
        let exe = install(&base, b"bin");
        let st = Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(exe.parent().unwrap())
            .status()
            .unwrap();
        assert!(st.success(), "{row}: chmod +a");
        let out = init(&exe, "zsh", &base);
        let _ = Command::new("/bin/chmod")
            .args(["-N"])
            .arg(exe.parent().unwrap())
            .status();
        assert_eq!(
            !out.stderr.is_empty(),
            want_warn,
            "{row}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn bash_script_is_wrapped_in_version_guard() {
    let base = scratch("bashguard");
    let exe = install(&base, b"bin");
    let out = init(&exe, "bash", &base);
    assert!(
        out.stdout
            .starts_with(b"if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )); then\n")
    );
    assert!(has(&out.stdout, b"bingsu: bash 5.1 or newer is required"));
}

// Review Focus 4. 이것을 실패시키는 것: 경로를 String으로 바꾸며 깨뜨리는 것(to_string_lossy 등).
#[cfg(target_os = "linux")]
#[test]
fn init_embeds_non_utf8_install_path() {
    let base = scratch("nonutf8");
    let exe = install(&base, b"bin-\xff\xfe");
    let out = init(&exe, "bash", &base);
    assert_eq!(out.status.code(), Some(0));
    assert!(has(&out.stdout, b"/bin-\xff\xfe/bingsu' prompt"));
}

// Review Focus 5. 이것을 실패시키는 것: 런타임 폴더 생성에서 EEXIST를 실패로 보는 것.
#[test]
fn concurrent_init_pins_same_runtime_root() {
    let base = scratch("concurrent");
    let exe = install(&base, b"bin");
    let outs: Vec<Output> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|_| s.spawn(|| init(&exe, "zsh", &base)))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let word = |o: &Output| -> Vec<u8> {
        let i = o
            .stdout
            .windows(15)
            .position(|w| w == b"--runtime-root=")
            .expect("runtime root word");
        o.stdout[i..]
            .split(|&b| b == b'\'')
            .next()
            .unwrap()
            .to_vec()
    };
    let first = word(&outs[0]);
    for o in &outs {
        assert!(
            o.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert_eq!(word(o), first);
    }
}

// Spec section 4: the symlink, its target and every ancestor folder. An
// intermediate hop (`bin/bingsu -> ../hop/x -> ../real/bingsu`, the shape of
// /etc/alternatives) is a target too, and its folder is an ancestor.
// 이것을 실패시키는 것: 실행 경로와 최종 정규 대상만 보고 사슬 중간 hop과 그 폴더를 건너뛰는 것.
#[test]
fn symlink_chain_hops_are_checked() {
    const TAMPER: &[u8] = b"bingsu: the bingsu executable or a folder above it can be changed by another user. Run: bingsu doctor\n";
    for (row, hop_mode, want) in [
        ("clean chain", 0o755, &b""[..]),
        ("hop dir other-writable", 0o777, TAMPER),
    ] {
        let base = scratch(&format!("chain-{}", row.replace(' ', "-")));
        for d in ["bin", "hop", "real"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
            chmod(&base.join(d), 0o755);
        }
        std::fs::copy(env!("CARGO_BIN_EXE_bingsu"), base.join("real/bingsu")).unwrap();
        std::os::unix::fs::symlink("../real/bingsu", base.join("hop/x")).unwrap();
        std::os::unix::fs::symlink("../hop/x", base.join("bin/bingsu")).unwrap();
        chmod(&base.join("hop"), hop_mode);
        let out = init(&base.join("bin/bingsu"), "zsh", &base);
        chmod(&base.join("hop"), 0o755);
        assert_eq!(out.status.code(), Some(0), "{row}");
        assert_eq!(
            out.stderr,
            want,
            "{row}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// A chain longer than 40 hops cannot be confirmed: warn, do not loop.
// 이것을 실패시키는 것: hop 상한을 없애거나 41보다 크게 잡는 것.
#[test]
fn symlink_chain_over_40_hops_warns_unknown() {
    let base = scratch("chain-long");
    let chain = base.join("chain");
    std::fs::create_dir_all(&chain).unwrap();
    chmod(&chain, 0o755);
    let real = base.join("bingsu-real");
    std::fs::copy(env!("CARGO_BIN_EXE_bingsu"), &real).unwrap();
    std::os::unix::fs::symlink(&real, chain.join("l41")).unwrap();
    for i in (0..41).rev() {
        std::os::unix::fs::symlink(format!("l{}", i + 1), chain.join(format!("l{i}"))).unwrap();
    }
    // The kernel refuses to exec through this many links, so run the real
    // file with argv0 = the head of the chain.
    let out = Command::new(&real)
        .args(["init", "zsh"])
        .arg0(chain.join("l0").as_os_str())
        .env_clear()
        .env("XDG_RUNTIME_DIR", base.join("run"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        out.stderr,
        b"bingsu: could not confirm that the bingsu executable and the folders above it are safe from other users. Run: bingsu doctor\n"
    );
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

const TAMPER_LINE: &[u8] = b"bingsu: the bingsu executable or a folder above it can be changed by another user. Run: bingsu doctor\n";

// macOS computes the members of `everyone` (nobody, daemon, ...); the group
// lists none. Also the path that read the member array unaligned.
// 이것을 실패시키는 것: 시스템 판정을 빼고 gr_mem·기본 gid만 보는 것(경고 없음),
// gr_mem을 정렬 가정으로 읽는 것(debug 패닉, 종료 코드 101·134).
#[cfg(target_os = "macos")]
#[test]
fn macos_everyone_group_writable_warns() {
    let base = scratch("group-everyone");
    let exe = install(&base, b"bin");
    let dir = exe.parent().unwrap();
    std::os::unix::fs::chown(dir, None, Some(12)).unwrap();
    chmod(dir, 0o775);
    let out = init(&exe, "zsh", &base);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stderr,
        TAMPER_LINE,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Every local account the system counts as a member of `group`, asked
/// through dsmemberutil (independent of the code under test). `None` if any
/// oracle command fails or answers something else: a partial list would
/// make the skip decision wrong.
#[cfg(target_os = "macos")]
fn ds_members(group: &str) -> Option<Vec<String>> {
    let users = Command::new("/usr/bin/dscl")
        .args([".", "list", "/Users"])
        .output()
        .ok()?;
    if !users.status.success() {
        return None;
    }
    let mut out = Vec::new();
    for u in String::from_utf8(users.stdout).ok()?.lines() {
        let r = Command::new("/usr/bin/dsmemberutil")
            .args(["checkmembership", "-U", u, "-G", group])
            .output()
            .ok()?;
        if !r.status.success() {
            return None;
        }
        if r.stdout.starts_with(b"user is a member") {
            out.push(u.to_owned());
        } else if !r.stdout.starts_with(b"user is not a member") {
            return None;
        }
    }
    Some(out)
}

// Homebrew rule: a group-writable folder whose group holds only root and
// the current user is safe (`admin` on a one-person Mac).
// 이것을 실패시키는 것: 계산 그룹 판정이 root·현재 사용자도 남으로 세는 것.
#[cfg(target_os = "macos")]
#[test]
fn macos_admin_group_with_only_root_and_me_is_safe() {
    let me = String::from_utf8(
        Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let me = me.trim();
    let Some(mut members) = ds_members("admin") else {
        eprintln!("skip: the dscl/dsmemberutil oracle failed for some account");
        return;
    };
    members.sort();
    let mut want = vec!["root".to_owned(), me.to_owned()];
    want.sort();
    if members != want {
        eprintln!("skip: admin members are {members:?}, not exactly root and {me}");
        return;
    }
    let base = scratch("group-admin");
    let exe = install(&base, b"bin");
    let dir = exe.parent().unwrap();
    std::os::unix::fs::chown(dir, None, Some(80)).unwrap();
    chmod(dir, 0o775);
    let out = init(&exe, "zsh", &base);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// The creation mode is masked by umask; init must still end at 0700.
// 이것을 실패시키는 것: 만든 뒤 0700으로 맞추지 않는 것(umask 0177이면 0600).
#[test]
fn runtime_root_is_0700_under_any_umask() {
    for mask in ["077", "022", "0177"] {
        let base = scratch(&format!("umask-{mask}"));
        let exe = install(&base, b"bin");
        std::fs::create_dir_all(base.join("run")).unwrap();
        chmod(&base.join("run"), 0o755);
        let out = Command::new("/bin/sh")
            .args(["-c", &format!("umask {mask}; exec \"$0\" init zsh")])
            .arg(&exe)
            .env_clear()
            .env("XDG_RUNTIME_DIR", base.join("run"))
            .env("XDG_STATE_HOME", base.join("state"))
            .env("XDG_CONFIG_HOME", base.join("cfg"))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "umask {mask}");
        assert!(
            out.stderr.is_empty(),
            "umask {mask}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let md = std::fs::metadata(base.join("run/bingsu")).unwrap();
        assert_eq!(md.mode() & 0o7777, 0o700, "umask {mask}");
    }
}

// `..` after a symlinked folder goes to the link target's parent, not the
// parent spelled in the path: `bin/bingsu -> ../lnk/../real/bingsu` with
// `lnk -> deep/a/b` runs `deep/a/real/bingsu`; `real/bingsu` is a decoy.
// 이것을 실패시키는 것: `..`를 글자 그대로(어휘적으로) 푸는 것(미끼 폴더를 검사함).
#[test]
fn dotdot_after_symlinked_folder_follows_the_kernel() {
    for (row, true_mode, decoy_mode, want) in [
        ("true dir writable", 0o777, 0o755, TAMPER_LINE),
        ("decoy dir writable", 0o755, 0o777, &b""[..]),
    ] {
        let base = scratch(&format!("dotdot-{}", row.replace(' ', "-")));
        for d in ["bin", "deep", "deep/a", "deep/a/b", "deep/a/real", "real"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
            chmod(&base.join(d), 0o755);
        }
        std::fs::copy(
            env!("CARGO_BIN_EXE_bingsu"),
            base.join("deep/a/real/bingsu"),
        )
        .unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_bingsu"), base.join("real/bingsu")).unwrap();
        std::os::unix::fs::symlink("deep/a/b", base.join("lnk")).unwrap();
        std::os::unix::fs::symlink("../lnk/../real/bingsu", base.join("bin/bingsu")).unwrap();
        chmod(&base.join("deep/a/real"), true_mode);
        chmod(&base.join("real"), decoy_mode);
        let out = init(&base.join("bin/bingsu"), "zsh", &base);
        chmod(&base.join("deep/a/real"), 0o755);
        chmod(&base.join("real"), 0o755);
        assert_eq!(out.status.code(), Some(0), "{row}");
        assert_eq!(
            out.stderr,
            want,
            "{row}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// A relative PATH entry before the match was searched from the shell's
// working folder, which init cannot see.
// 이것을 실패시키는 것: 상대 PATH 항목을 건너뛰고 뒤의 절대 항목에서 찾은 다른 실행 파일을 박는 것.
#[test]
fn relative_path_entry_falls_back_to_resolved_executable() {
    let base = scratch("path-relative");
    let exe = install(&base, b"bin");
    let other = install(&base, b"other");
    let out = Command::new("bingsu")
        .args(["init", "zsh"])
        .current_dir(other.parent().unwrap())
        .env_clear()
        .env("PATH", format!(".:{}", exe.parent().unwrap().display()))
        .env("XDG_RUNTIME_DIR", base.join("run"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        out.stderr,
        b"bingsu: could not find the path you ran bingsu from; using the resolved executable path. Run: bingsu doctor\n"
    );
    assert!(!has(&out.stdout, exe.as_os_str().as_bytes()));
}

const NO_RUNTIME: &[u8] =
    b"bingsu: no usable runtime folder; the prompt runs without saved state. Run: bingsu doctor\n";

// The last runtime folder must be opened without following a symlink:
// `run/bingsu -> victim` is refused, and victim keeps its mode.
// 이것을 실패시키는 것: 마지막 이름을 따라가 여는 것(victim이 0700이 되고 뿌리로 박힘).
#[test]
fn runtime_root_symlink_is_refused_not_followed() {
    let base = scratch("runtime-symlink");
    let exe = install(&base, b"bin");
    for d in ["run", "victim"] {
        std::fs::create_dir_all(base.join(d)).unwrap();
        chmod(&base.join(d), 0o755);
    }
    std::os::unix::fs::symlink(base.join("victim"), base.join("run/bingsu")).unwrap();
    let out = init(&exe, "zsh", &base);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        out.stderr,
        NO_RUNTIME,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!has(&out.stdout, b"--runtime-root="));
    let md = std::fs::metadata(base.join("victim")).unwrap();
    assert_eq!(md.mode() & 0o7777, 0o755);
}

// Missing folders above the runtime folder are made 0700 too; under umask
// 0177 a plain mkdir would leave them 0600 and block the next level.
// 이것을 실패시키는 것: 중간 폴더를 0700으로 맞추지 않는 것(0600 중간 폴더 때문에 뿌리 없음).
#[test]
fn missing_parents_of_runtime_root_are_0700_under_umask_0177() {
    let base = scratch("umask-parents");
    let exe = install(&base, b"bin");
    let out = Command::new("/bin/sh")
        .args(["-c", "umask 0177; exec \"$0\" init zsh"])
        .arg(&exe)
        .env_clear()
        .env("XDG_RUNTIME_DIR", base.join("run"))
        .env("XDG_STATE_HOME", base.join("state"))
        .env("XDG_CONFIG_HOME", base.join("cfg"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for d in ["run", "run/bingsu"] {
        let md = std::fs::metadata(base.join(d)).unwrap();
        assert_eq!(md.mode() & 0o7777, 0o700, "{d}");
    }
}

// A ".." after a name that does not exist yet cannot be resolved ahead of
// the kernel: the state and log words are left out and init warns. The
// same path without ".." is pinned as is (control row).
// 이것을 실패시키는 것: 없는 구간의 `..`를 어휘적으로 접어 추측한 경로를 박는 것.
#[test]
fn state_root_with_dotdot_after_missing_name_is_not_pinned() {
    let base = scratch("state-dotdot");
    let exe = install(&base, b"bin");
    std::fs::create_dir_all(base.join("cl/deep/a/b")).unwrap();
    std::os::unix::fs::symlink(base.join("cl/deep/a/b"), base.join("cl/lnk")).unwrap();
    let run = |state: &str| {
        Command::new(&exe)
            .args(["init", "zsh"])
            .env_clear()
            .env("XDG_RUNTIME_DIR", base.join("run"))
            .env("XDG_CONFIG_HOME", base.join("cfg"))
            .env("XDG_STATE_HOME", base.join(state))
            .output()
            .unwrap()
    };
    let out = run("cl/missing/../lnk/../x");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        out.stderr,
        b"bingsu: a settings, state or log folder path could not be confirmed; that folder is not used. Run: bingsu doctor\n"
    );
    assert!(!has(&out.stdout, b"--state-root="));
    assert!(!has(&out.stdout, b"--log-root="));
    assert!(has(&out.stdout, b"--config-root="));
    let out = run("cl/missing/x");
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let want = format!(
        "'--state-root={}'",
        std::fs::canonicalize(base.join("cl"))
            .unwrap()
            .join("missing/x/bingsu")
            .display()
    );
    assert!(has(&out.stdout, want.as_bytes()), "missing {want}");
}
