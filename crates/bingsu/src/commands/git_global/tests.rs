use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
    time::Instant,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bingsu-global-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let f = Self(fs::canonicalize(dir).unwrap());
        fs::create_dir_all(f.0.join("repo")).unwrap();
        f.git(&["init", "-q"]);
        f
    }
    fn bytes(&self) -> &[u8] {
        self.0.as_os_str().as_bytes()
    }
    fn write(&self, path: &str, data: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    fn input(&self) -> Input {
        load(Some(self.bytes()), None)
    }
    fn git(&self, args: &[&str]) -> Vec<u8> {
        self.git_home(args, &self.0)
    }
    fn git_home(&self, args: &[&str], home: &Path) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.0.join("repo"))
            .args(args)
            .env_clear()
            .env(
                "PATH",
                crate::commands::init::trusted_env::TrustedEnv::capture()
                    .path
                    .unwrap(),
            )
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .expect("git oracle required");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// 이것을 실패시키는 것: XDG 기본값·두 전역 설정의 순서·틸드 확장 중 하나를 바꾸거나 repository config를 읽는 것.
#[test]
fn global_sources_match_git_with_fixture_home() {
    let f = Fixture::new();
    f.write(".config/git/ignore", b".DS_Store\n");
    f.write("repo/.DS_Store", b"ignored");
    f.write("repo/visible", b"visible");
    assert_eq!(
        f.input(),
        Input {
            bytes: b".DS_Store\n".to_vec(),
            reason: Reason::Loaded
        }
    );
    assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? visible\n");
    f.write("xdg/git/ignore", b"visible\n");
    let xdg = f.0.join("xdg");
    assert_eq!(
        load(Some(f.bytes()), Some(xdg.as_os_str().as_bytes())).bytes,
        b"visible\n"
    );
    assert_eq!(load(Some(f.bytes()), Some(b"")).bytes, b".DS_Store\n");
    f.write("xdg/git/config", b"[core]\n excludesFile = ~/xdg-rules\n");
    f.write("xdg-rules", b"xdg\n");
    assert_eq!(
        load(Some(f.bytes()), Some(xdg.as_os_str().as_bytes())).bytes,
        b"xdg\n"
    );
    f.write(".config/git/config", b"[core]\n excludesFile = ~/low\n");
    f.write("low", b"visible\n");
    f.write("rules # one", b".DS_Store\n");
    f.write(
        ".gitconfig",
        b"[CoRe]\n EXCLUDESfile = \"~/rules # one\" ; comment\n",
    );
    let path = f.git(&["config", "--global", "--path", "--get", "core.excludesFile"]);
    assert_eq!(
        path.strip_suffix(b"\n").unwrap(),
        f.0.join("rules # one").as_os_str().as_bytes()
    );
    assert_eq!(f.input().bytes, b".DS_Store\n");
    f.write(".gitconfig", b"[core]\nexcludesFile=\"~//rules # one\"\n");
    assert_eq!(f.input().bytes, b".DS_Store\n");
    assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? visible\n");
    assert_eq!(
        load(Some(f.bytes()), Some(xdg.as_os_str().as_bytes())).bytes,
        b".DS_Store\n"
    );
    assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? visible\n");
    // A local override intentionally differs from unmodified Git. The oracle
    // pins the trusted global value explicitly when testing that policy.
    f.write("hostile", b"visible\n");
    f.git(&[
        "config",
        "core.excludesFile",
        f.0.join("hostile").to_str().unwrap(),
    ]);
    assert_eq!(f.input().bytes, b".DS_Store\n");
    assert_eq!(
        f.git(&[
            "-c",
            &format!("core.excludesFile={}", f.0.join("rules # one").display()),
            "status",
            "--porcelain=v2"
        ]),
        b"? visible\n"
    );
    assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? .DS_Store\n");
}

// 이것을 실패시키는 것: regular·owner·cap 검사를 없애거나 실패 때 기본 파일로 바꾸는 것.
#[test]
fn empty_inputs_have_specific_failure_reasons() {
    let f = Fixture::new();
    assert_eq!(f.input().reason, Reason::Missing);
    f.write(".config/git/ignore", vec![b'x'; GLOBAL_EXCLUDES_MAX]);
    assert_eq!(f.input().bytes.len(), GLOBAL_EXCLUDES_MAX);
    f.write(".config/git/ignore", vec![b'x'; GLOBAL_EXCLUDES_MAX + 1]);
    assert_eq!(
        f.input(),
        Input {
            bytes: vec![],
            reason: Reason::TooLarge
        }
    );
    f.write(".config/git/ignore", b"fallback\n");
    f.write(".gitconfig", b"[core]\n excludesFile = ~/absent\n");
    assert_eq!(f.input().reason, Reason::Missing);
    f.write(".gitconfig", b"[core]\n excludesFile = ~/.config\n");
    assert_eq!(f.input().reason, Reason::Special);
    f.write("unreadable", b"hidden\n");
    fs::set_permissions(f.0.join("unreadable"), fs::Permissions::from_mode(0o0)).unwrap();
    f.write(".gitconfig", b"[core]\n excludesFile = ~/unreadable\n");
    if sys::current_uid() != 0 {
        assert_eq!(f.input().reason, Reason::Unreadable);
    }
    fs::remove_file(f.0.join(".gitconfig")).unwrap();
    f.write(".gitconfig", vec![b'#'; GLOBAL_EXCLUDES_MAX + 1]);
    assert_eq!(f.input().reason, Reason::TooLarge);
    for path in [
        b"relative".as_slice(),
        b"~other/ignore",
        b"%(prefix)/ignore",
    ] {
        let mut config = b"[core]\n excludesFile = ".to_vec();
        config.extend(path);
        f.write(".gitconfig", config);
        assert_eq!(f.input().reason, Reason::UnsupportedPath);
    }
    assert_eq!(load(Some(b"relative"), None).reason, Reason::UnsafePath);
    assert_eq!(load(Some(b""), None).reason, Reason::Missing);
}

// 이것을 실패시키는 것: Git의 quote/escape/last-value/subsection 문법을 다르게 해석하는 것.
#[test]
fn bounded_config_lexer_matches_git() {
    fn excludes_value(bytes: &[u8]) -> Result<Option<Vec<u8>>, Reason> {
        let mut selected = None;
        parse_config(bytes, |entry| {
            if let Entry::Excludes(value) = entry {
                selected = Some(value);
            }
            Ok(())
        })?;
        Ok(selected)
    }
    let f = Fixture::new();
    for config in [
        b"[core]\n excludesFile = ~/first\n excludesFile = ~/second\n".as_slice(),
        b"[core] excludesfile=\" ~/space \"\n",
        b"[core]\n excludesfile = ~/one\\\n two\n",
        b"[core]\r\n excludesfile=~/one\\\r\n two\r\n",
        b"\xef\xbb\xbf[CORE]\n excludesfile = ~/one\\t\\\"\\\\file # end\n",
        b"[core \"sub\\\"section\"]\n excludesfile=wrong\n[core]\n excludesfile = ~/right\n",
        b"[core]\n excludesfile=\n",
        b"[other]\n boolean\n[core]\n excludesfile = ~/a   b\n",
    ] {
        f.write(".gitconfig", config);
        let raw = f.git(&["config", "--global", "--get", "core.excludesFile"]);
        assert_eq!(
            excludes_value(config).unwrap().unwrap(),
            raw.strip_suffix(b"\n").unwrap(),
            "{config:?}"
        );
    }
    for config in [
        b"[core]\nexcludesFile=\\q".as_slice(),
        b"[core]\nexcludesFile=\"unterminated",
        b"[core]\nexcludesFile",
        b"[core\n",
        b"[core]\nx=\0",
    ] {
        assert_eq!(excludes_value(config), Err(Reason::InvalidConfig));
    }
}

#[test]
fn attaches_bytes_without_disabling_collection_on_request_budget() {
    let f = Fixture::new();
    f.write(".config/git/ignore", vec![b'x'; GLOBAL_EXCLUDES_MAX]);
    let e = bingsu_core::envelope::Envelope {
        home: Some(f.bytes().to_vec()),
        ..Default::default()
    };
    let binding = bingsu_core::collection::wire::Binding {
        path_query: Default::default(),
        build_id: bingsu_core::collection::wire::BuildId([0; 32]),
        snapshot: bingsu_core::snapshot::Identity {
            boot: [0; 16],
            epoch: [0; 16],
            generation: 0,
            source: [0; 4],
            context: bingsu_core::snapshot::context_crc(b"/c", b"/s").unwrap(),
        },
        clock_kind: 1,
        domain: [0; 16],
        resume: 0,
        config: b"/c".to_vec(),
        state: b"/s".to_vec(),
        cwd: b"/w".to_vec(),
        mask: 1 << 3,
    };
    let mut request = Request {
        request_id: bingsu_core::collection::wire::M3B_REQUEST_ID,
        binding,
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
    };
    assert_eq!(attach(&mut request, &e), Reason::Loaded);
    assert!(request.global_excludes_known);
    // Old hook + new binary: absent global words use only the pinned --home.
    // Mutation: remove the fallback, or ignore an explicit new home pin.
    assert_eq!(request.global_excludes, vec![b'x'; GLOBAL_EXCLUDES_MAX]);
    let new_pin = bingsu_core::envelope::Envelope {
        home: Some(b"/unused-display-home".to_vec()),
        git_global_home: e.home.clone(),
        git_global_xdg: Some(vec![]),
        ..Default::default()
    };
    assert_eq!(attach(&mut request, &new_pin), Reason::Loaded);
    assert_eq!(request.global_excludes, vec![b'x'; GLOBAL_EXCLUDES_MAX]);
    // Mutation: treat an explicitly empty (including over-cap) observation
    // as absent and silently revive the pinned HOME.
    let blank = bingsu_core::envelope::Envelope {
        git_global_home: Some(vec![]),
        git_global_xdg: Some(vec![]),
        home: Some(f.bytes().to_vec()),
        ..Default::default()
    };
    assert_eq!(attach(&mut request, &blank), Reason::Missing);
    assert!(request.global_excludes_known);
    assert!(request.global_excludes.is_empty());
    assert_eq!(attach(&mut request, &e), Reason::Loaded);
    assert!(request.global_excludes_known);
    // Mutations: treat a skipped source as known-empty, retain old bytes, or
    // let an explicitly empty XDG suppress HOME/.config fallback.
    let empty_xdg = bingsu_core::envelope::Envelope {
        git_global_home: e.home.clone(),
        git_global_xdg: Some(vec![]),
        ..Default::default()
    };
    assert_eq!(attach(&mut request, &empty_xdg), Reason::Loaded);
    assert!(request.global_excludes_known);
    for (config, reason) in [
        (
            b"[core]\n excludesFile = relative\n".as_slice(),
            Reason::UnsupportedPath,
        ),
        (
            b"[includeIf \"gitdir:/never/\"]\n path = conditional\n",
            Reason::ConditionalConfig,
        ),
    ] {
        f.write(".gitconfig", config);
        f.write("conditional", b"[core]\n excludesFile = /different\n");
        assert_eq!(attach(&mut request, &e), reason);
        assert!(!request.global_excludes_known);
        assert!(request.global_excludes.is_empty());
        let decoded = Request::decode_body(
            request.binding.build_id,
            request.request_id,
            &request.encode_body().unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, request);
    }
    fs::remove_file(f.0.join(".gitconfig")).unwrap();
    fs::remove_file(f.0.join(".config/git/ignore")).unwrap();
    assert_eq!(attach(&mut request, &e), Reason::Missing);
    assert!(request.global_excludes_known);
    assert!(request.global_excludes.is_empty());
    let decoded = Request::decode_body(
        request.binding.build_id,
        request.request_id,
        &request.encode_body().unwrap(),
    )
    .unwrap();
    assert_eq!(decoded, request);
    f.write(".config/git/ignore", vec![b'x'; GLOBAL_EXCLUDES_MAX]);
    assert_eq!(attach(&mut request, &e), Reason::Loaded);
    let encoded = request.encode_body().unwrap();
    assert_eq!(
        Request::decode_body(request.binding.build_id, request.request_id, &encoded).unwrap(),
        request
    );
    for p in [
        &mut request.binding.config,
        &mut request.binding.state,
        &mut request.binding.cwd,
    ] {
        p.resize(65_536, b'a');
    }
    request.binding.snapshot.context =
        bingsu_core::snapshot::context_crc(&request.binding.config, &request.binding.state)
            .unwrap();
    assert_eq!(attach(&mut request, &e), Reason::RequestBudget);
    assert!(!request.global_excludes_known);
    assert!(request.global_excludes.is_empty());
    request.encode_body().unwrap();
    request.binding.mask = 0;
    assert_eq!(attach(&mut request, &e), Reason::Missing);
}

// Explicit observation, no timing assertion: helper is outside request 50 ms,
// still inside the existing 2 s watchdog. Run release warm samples separately.
#[test]
#[ignore = "release measurement over 200 warm runs"]
fn measure_global_inputs() {
    let f = Fixture::new();
    for label in [
        "missing",
        "default",
        "global-tilde",
        "global-absolute",
        "64k",
        "oversize",
        "config-64k",
        "symlink",
        "hardlink",
        "include",
        "includeif-unrelated",
        "includeif-conflict",
        "include-depth10",
        "include-total-cap",
    ] {
        let _ = fs::remove_file(f.0.join(".gitconfig"));
        let _ = fs::remove_file(f.0.join(".config/git/ignore"));
        if label != "missing" {
            f.write(".config/git/ignore", b".DS_Store\n");
        }
        match label {
            "global-tilde" => f.write(".gitconfig", b"[core]\nexcludesFile=~/.config/git/ignore\n"),
            "global-absolute" => f.write(
                ".gitconfig",
                format!(
                    "[core]\nexcludesFile={}\n",
                    f.0.join(".config/git/ignore").display()
                ),
            ),
            "64k" => f.write(".config/git/ignore", vec![b'#'; GLOBAL_EXCLUDES_MAX]),
            "oversize" => f.write(".config/git/ignore", vec![b'#'; GLOBAL_EXCLUDES_MAX + 1]),
            "config-64k" => f.write(".gitconfig", vec![b'#'; GLOBAL_EXCLUDES_MAX]),
            "symlink" | "hardlink" => {
                f.write("rules", b".DS_Store\n");
                fs::remove_file(f.0.join(".config/git/ignore")).unwrap();
                if label == "symlink" {
                    symlink("../../rules", f.0.join(".config/git/ignore")).unwrap();
                } else {
                    fs::hard_link(f.0.join("rules"), f.0.join(".config/git/ignore")).unwrap();
                }
            }
            "include" | "includeif-unrelated" | "includeif-conflict" => {
                let section = if label == "include" {
                    "include"
                } else {
                    "includeIf \"gitdir:~/repo/\""
                };
                f.write(".gitconfig", format!("[{section}]\npath=extra\n"));
                f.write(
                    "extra",
                    if label == "includeif-unrelated" {
                        b"[user]\nemail=test@example.invalid\n".as_slice()
                    } else {
                        b"[core]\nexcludesFile=~/rules\n"
                    },
                );
                f.write("rules", b".DS_Store\n");
            }
            "include-depth10" => {
                f.write(".gitconfig", b"[include]\npath=c1\n");
                for depth in 1..10 {
                    f.write(
                        &format!("c{depth}"),
                        format!("[include]\npath=c{}\n", depth + 1),
                    );
                }
                f.write("c10", b"[core]\nexcludesFile=~/rules\n");
                f.write("rules", b".DS_Store\n");
            }
            "include-total-cap" => {
                f.write(
                    ".gitconfig",
                    b"[include]\npath=big\npath=big\npath=big\npath=big\n",
                );
                f.write("big", vec![b'#'; GLOBAL_EXCLUDES_MAX]);
            }
            _ => {}
        }
        let cold = Instant::now();
        std::hint::black_box(f.input());
        let cold = cold.elapsed().as_nanos();
        let mut ns = Vec::new();
        for _ in 0..200 {
            let t = Instant::now();
            std::hint::black_box(f.input());
            ns.push(t.elapsed().as_nanos());
        }
        let mean = ns.iter().sum::<u128>() as f64 / 200.0;
        let variance = ns.iter().map(|n| (*n as f64 - mean).powi(2)).sum::<f64>() / 200.0;
        ns.sort_unstable();
        eprintln!(
            "D1C_HELPER {label} runs=200 cold_ns={cold} p50_ns={} p95_ns={} variance_ns2={variance} samples_ns={ns:?}",
            ns[99], ns[189]
        );
    }
}

// Mutations: compare only length, skip same-fd evidence, or allow parent hops.
#[test]
fn same_fd_changes_parent_hops_and_fifos_are_refused() {
    let f = Fixture::new();
    f.write("rules", b"old\n");
    let path = f.0.join("rules");
    // A mode change is timestamp-resolution independent on Linux too.
    assert_eq!(
        read_with(&path, |file| file
            .set_permissions(fs::Permissions::from_mode(0o400))
            .unwrap()),
        Err(Reason::Changed)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_with(&path, |_| fs::write(&path, b"different length\n").unwrap()),
        Err(Reason::Changed)
    );
    assert_eq!(
        absolute(f.0.join("repo/../rules").as_os_str().as_bytes()),
        Err(Reason::UnsafePath)
    );
    let fifo = f.0.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: a NUL-terminated path in this test's private fixture directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert_eq!(read(&fifo), Err(Reason::Special));
}

// Mutations: restore O_NOFOLLOW (leaf or HOME ancestor), nlink == 1,
// or reject symlinked global config/include files. Git applies each source.
#[test]
fn symlinks_and_hardlinks_match_git() {
    let f = Fixture::new();
    f.write("rules", b".DS_Store\n");
    f.write("repo/.DS_Store", b"ignored");
    f.write("repo/visible", b"visible");
    fs::create_dir_all(f.0.join(".config/git")).unwrap();
    symlink("../../rules", f.0.join(".config/git/ignore")).unwrap();
    let check = || {
        assert_eq!(
            f.input(),
            Input {
                bytes: b".DS_Store\n".to_vec(),
                reason: Reason::Loaded
            }
        );
        assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? visible\n");
    };
    check();
    symlink(".", f.0.join("home-link")).unwrap();
    let home = f.0.join("home-link");
    assert_eq!(load(Some(home.as_os_str().as_bytes()), None), f.input());
    // Git's HOME is independently set to the symlink in this oracle run.
    assert_eq!(
        f.git_home(&["status", "--porcelain=v2"], &home),
        b"? visible\n"
    );
    fs::remove_file(f.0.join(".config/git/ignore")).unwrap();
    fs::hard_link(f.0.join("rules"), f.0.join(".config/git/ignore")).unwrap();
    check();
    f.write("actual-config", b"[include]\npath = nested/include\n");
    f.write("included", b"[core]\nexcludesFile = ~/rules\n");
    fs::create_dir(f.0.join("nested")).unwrap();
    symlink("../included", f.0.join("nested/include")).unwrap();
    symlink("actual-config", f.0.join(".gitconfig")).unwrap();
    check();
}

// Mutations: treat every include as unsupported, ignore all include targets,
// lose source order, or assume an unknown condition is true/false from cwd.
#[test]
fn includes_only_change_excludes_when_relevant() {
    let f = Fixture::new();
    f.write(".config/git/ignore", b".DS_Store\n");
    f.write("repo/.DS_Store", b"ignored");
    f.write("repo/visible", b"visible");
    f.write("extra", b"[user]\nemail = test@example.invalid\n");
    for condition in ["gitdir:~/repo/", "gitdir/i:~/REPO/", "onbranch:other"] {
        f.write(
            ".gitconfig",
            format!("[includeIf \"{condition}\"]\npath=extra\n"),
        );
        assert_eq!(f.input().bytes, b".DS_Store\n");
        assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? visible\n");
    }
    f.write("extra", b"[core]\nexcludesFile=~/rules\n");
    f.write("rules", b"visible\n");
    f.write(".gitconfig", b"[include]\npath=extra\n");
    assert_eq!(f.input().bytes, b"visible\n");
    assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? .DS_Store\n");
    for condition in ["gitdir:~/repo/", "gitdir/i:~/REPO/"] {
        f.write(
            ".gitconfig",
            format!("[includeIf \"{condition}\"]\npath=extra\n"),
        );
        // Git discovers .git, but our request has only cwd. Deliberately
        // unknown rather than returning a falsely confident global input.
        assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? .DS_Store\n");
        assert_eq!(
            f.input(),
            Input {
                bytes: vec![],
                reason: Reason::ConditionalConfig
            }
        );
        // Same value in every possible branch is determinate.
        f.write(
            ".gitconfig",
            format!("[core]\nexcludesFile=~/rules\n[includeIf \"{condition}\"]\npath=extra\n"),
        );
        assert_eq!(f.input().bytes, b"visible\n");
        // Later unconditional values override earlier conditional values.
        f.write(".gitconfig", format!("[includeIf \"{condition}\"]\npath=extra\n[core]\nexcludesFile=~/.config/git/ignore\n"));
        assert_eq!(f.input().bytes, b".DS_Store\n");
        assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? visible\n");
    }
    // A later conditional include cannot erase an earlier possible value.
    f.write("same", b"[core]\nexcludesFile=~/.config/git/ignore\n");
    f.write(
        ".gitconfig",
        b"[includeIf \"onbranch:other\"]\npath=extra\npath=same\n",
    );
    assert_eq!(f.input().reason, Reason::ConditionalConfig);
    // Relative paths are relative to the including file, including ../.
    f.write(".gitconfig", b"[include]\npath=nested/inner\n");
    f.write("nested/inner", b"[include]\npath=../extra\n");
    assert_eq!(f.input().bytes, b"visible\n");
    assert_eq!(f.git(&["status", "--porcelain=v2"]), b"? .DS_Store\n");
}

// Mutations: return early on a failed config, or let unrelated config mask a
// failure when no source actually supplies core.excludesFile.
#[test]
fn one_failed_global_config_does_not_hide_the_other_answer() {
    let f = Fixture::new();
    f.write("rules", b"kept\n");
    for (bad, good) in [
        (".config/git/config", ".gitconfig"),
        (".gitconfig", ".config/git/config"),
    ] {
        f.write(bad, vec![b'#'; GLOBAL_EXCLUDES_MAX + 1]);
        f.write(good, b"[core]\nexcludesFile=~/rules\n");
        assert_eq!(f.input().bytes, b"kept\n");
        f.write(good, b"[user]\nemail=test@example.invalid\n");
        assert_eq!(
            f.input(),
            Input {
                bytes: vec![],
                reason: Reason::TooLarge
            }
        );
    }
}

// Mutations: remove depth or aggregate-byte cap, weaken 64 KiB per-config
// cap, or silently return the default ignore after an include is skipped.
#[test]
fn includes_have_depth_and_total_byte_limits() {
    let f = Fixture::new();
    f.write(".config/git/ignore", b"fallback\n");
    f.write(".gitconfig", b"[include]\npath=c1\n");
    for depth in 1..10 {
        f.write(
            &format!("c{depth}"),
            format!("[include]\npath=c{}\n", depth + 1),
        );
    }
    f.write("c10", b"[user]\nemail=test@example.invalid\n");
    assert_eq!(f.input().bytes, b"fallback\n");
    f.write("c10", b"[include]\npath=c11\n");
    f.write("c11", b"[user]\nemail=test@example.invalid\n");
    assert_eq!(
        f.input(),
        Input {
            bytes: vec![],
            reason: Reason::IncludeDepth
        }
    );
    f.write(".gitconfig", b"[include]\npath=big\n");
    f.write("big", vec![b'#'; GLOBAL_EXCLUDES_MAX]);
    assert_eq!(f.input().bytes, b"fallback\n");
    f.write("big", vec![b'#'; GLOBAL_EXCLUDES_MAX + 1]);
    assert_eq!(f.input().reason, Reason::TooLarge);
    // Re-reading a file still spends bytes. Exactly 256 KiB is allowed.
    let config = b"[include]\npath=big\npath=big\npath=big\npath=tail\n";
    f.write(".gitconfig", config);
    f.write("big", vec![b'#'; GLOBAL_EXCLUDES_MAX]);
    f.write("tail", vec![b'#'; GLOBAL_EXCLUDES_MAX - config.len()]);
    assert_eq!(f.input().bytes, b"fallback\n");
    f.write("tail", vec![b'#'; GLOBAL_EXCLUDES_MAX - config.len() + 1]);
    assert_eq!(
        f.input(),
        Input {
            bytes: vec![],
            reason: Reason::ConfigBudget
        }
    );
}

// Mutations: read before checking metadata size, omit NONBLOCK/CLOEXEC,
// remove owner enforcement, or log skip reasons at DebugLog again.
#[test]
fn global_read_guards_and_info_diagnostics() {
    use std::os::fd::AsRawFd;
    let f = Fixture::new();
    f.write("rules", b"rule\n");
    // Independently exercise effective uid and root (Nix store) acceptance;
    // the privileged test below covers a real foreign-owned inode.
    let file = fs::File::open(f.0.join("rules")).unwrap();
    let mut stamp = sys::file_stamp(&file).unwrap();
    for (owner, expected) in [
        (1234, Ok(())),
        (0, Ok(())),
        (1235, Err(Reason::ForeignOwner)),
    ] {
        stamp.uid = owner;
        assert_eq!(check_metadata(&stamp, 1234, GLOBAL_EXCLUDES_MAX), expected);
    }
    read_with(&f.0.join("rules"), |file| {
        assert_ne!(
            // SAFETY: fcntl queries a live descriptor; no pointer argument.
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            // SAFETY: fcntl queries a live descriptor; no pointer argument.
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    })
    .unwrap();
    f.write("rules", vec![b'#'; GLOBAL_EXCLUDES_MAX + 1]);
    let read_ran = std::cell::Cell::new(false);
    assert_eq!(
        read_with(&f.0.join("rules"), |_| read_ran.set(true)),
        Err(Reason::TooLarge)
    );
    assert!(
        !read_ran.get(),
        "oversize must be rejected before reading/allocating"
    );
    for reason in [
        Reason::Missing,
        Reason::Unreadable,
        Reason::UnsafePath,
        Reason::Special,
        Reason::ForeignOwner,
        Reason::TooLarge,
        Reason::Changed,
        Reason::InvalidConfig,
        Reason::ConditionalConfig,
        Reason::IncludeDepth,
        Reason::ConfigBudget,
        Reason::UnsupportedPath,
        Reason::RequestBudget,
    ] {
        assert_eq!(reason.log_level(), bingsu_core::envelope::LogLevel::Info);
        assert!(reason.message().contains("using empty input"));
    }
}

// Mutation: remove the final-file owner check. Requires real second uid;
// run explicitly, and report unavailable chown privilege as BLOCKED.
#[test]
#[ignore = "requires chown to another non-root uid"]
fn foreign_owned_source_is_rejected() {
    let f = Fixture::new();
    f.write(".config/git/ignore", b"foreign\n");
    let path =
        std::ffi::CString::new(f.0.join(".config/git/ignore").as_os_str().as_bytes()).unwrap();
    let uid = if effective_uid() == 65534 {
        65533
    } else {
        65534
    };
    assert_eq!(
        // SAFETY: NUL-terminated fixture path, gid -1 leaves group unchanged.
        unsafe { libc::chown(path.as_ptr(), uid, !0) },
        0,
        "BLOCKED: chown: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        f.input(),
        Input {
            bytes: vec![],
            reason: Reason::ForeignOwner
        }
    );
}

// Mutation: classify any non-Missing skip as known, or Missing/Loaded as unknown.
#[test]
fn global_input_knowledge_is_explicit_for_every_reason() {
    for reason in [Reason::Loaded, Reason::Missing] {
        assert!(reason.known(), "{reason:?}");
    }
    for reason in [
        Reason::Unreadable,
        Reason::UnsafePath,
        Reason::Special,
        Reason::ForeignOwner,
        Reason::TooLarge,
        Reason::Changed,
        Reason::InvalidConfig,
        Reason::ConditionalConfig,
        Reason::IncludeDepth,
        Reason::ConfigBudget,
        Reason::UnsupportedPath,
        Reason::RequestBudget,
    ] {
        assert!(!reason.known(), "{reason:?}");
    }
}
