//! D1 language detection through the product collection pipeline: marker
//! and version selection files from the shell's folder up to the repository
//! root, read after the read confinement, grammar-checked in the worker.
#![cfg(unix)]
#[allow(dead_code)]
#[path = "../src/git/mod.rs"]
mod git;
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
#[allow(dead_code)]
#[path = "../src/update_sink.rs"]
mod update_sink;

use bingsu_core::{
    collection::{
        language::{BUILTIN, LanguageQuery, LanguageResult, Version},
        path_facts::PathQuery,
        wire::{self, Binding, BuildId, Progress, Request, Update},
    },
    snapshot::{self, Identity},
};
use meter::Meter;
use safe_read::Access;
use std::{
    cell::RefCell,
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
    time::{Duration, Instant},
};

fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(60))
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base =
            std::env::var_os("BINGSU_D1_ROOT").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let path = base.join(format!(
            "bingsu-d1-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }
    fn repo(&self, name: &str) -> PathBuf {
        let path = self.dir(name);
        fs::create_dir(path.join(".git")).unwrap();
        fs::write(
            path.join(".git/HEAD"),
            b"0123456789012345678901234567890123456789\n",
        )
        .unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(cwd: &Path, home: &Path, languages: Vec<LanguageQuery>) -> Request {
    let cwd = cwd.as_os_str().as_bytes().to_vec();
    Request {
        languages,
        request_id: wire::M3B_REQUEST_ID,
        binding: Binding {
            build_id: BuildId([7; 32]),
            snapshot: Identity {
                boot: [1; 16],
                epoch: [2; 16],
                generation: 3,
                source: [4; 4],
                context: snapshot::context_crc(b"/c", b"/s").unwrap(),
            },
            clock_kind: 1,
            domain: [5; 16],
            resume: 0,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            path_query: PathQuery::for_path(&cwd, Some(home.as_os_str().as_bytes()), false),
            cwd,
            mask: 1 << 1,
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
    }
}

/// Runs case `k` of `name` (for every `k` below `cases`) alone in a fresh
/// child, one collection round per child: the round installs the read
/// confinement (on Linux a Landlock layer, after no_new_privs), which must
/// not reach another round or test. In the child it returns the case.
fn case(name: &str, cases: usize) -> Option<usize> {
    if std::env::var("BINGSU_D1_CHILD").ok().as_deref() == Some(name) {
        #[cfg(target_os = "linux")]
        assert_eq!(
            // SAFETY: irreversible prerequisite only in a disposable child.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        return std::env::var("BINGSU_D1_CASE").ok()?.parse().ok();
    }
    for k in 0..cases {
        let f = Fixture::new();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("BINGSU_D1_CHILD", name)
            .env("BINGSU_D1_CASE", k.to_string())
            .env("BINGSU_D1_ROOT", &f.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {k}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
    None
}

#[derive(Default)]
struct Sink {
    updates: Vec<Update>,
    progress: Vec<Progress>,
    languages: Vec<LanguageResult>,
}
impl update_sink::UpdateSink for Sink {
    fn update(&mut self, value: Update) -> std::io::Result<()> {
        self.updates.push(value);
        Ok(())
    }
    fn progress(&mut self, value: Progress) -> std::io::Result<()> {
        self.progress.push(value);
        Ok(())
    }
    fn language(&mut self, value: LanguageResult) -> std::io::Result<()> {
        self.languages.push(value);
        Ok(())
    }
}

fn deadlines() -> git::StageDeadlines {
    git::StageDeadlines {
        a_ms: 60_000,
        path_ms: 60_000,
        lang_ms: 60_000,
        b_ms: 60_000,
        c_ms: 60_000,
        d_ms: 60_000,
    }
}

fn full_access() -> Access {
    #[cfg(target_os = "linux")]
    let access = Access::probe(&mut meter()).unwrap();
    #[cfg(target_os = "macos")]
    let access = {
        use std::os::fd::AsFd;
        // The probe validates the kernel's beneath resolution on this tree.
        let f = Fixture::new();
        f.dir("dir");
        fs::write(f.0.join("value"), b"inside").unwrap();
        fs::write(f.0.join("dir/file"), b"inside").unwrap();
        fs::write(f.0.join("hard"), b"linked").unwrap();
        fs::hard_link(f.0.join("hard"), f.0.join("hard2")).unwrap();
        for (target, name) in [
            ("../value", "dir/inner"),
            ("dir", "linkdir"),
            ("/", "absolute"),
            ("../outside", "escape"),
            ("../../outside", "dir/up"),
        ] {
            symlink(target, f.0.join(name)).unwrap();
        }
        let fd = fs::File::open(&f.0).unwrap();
        safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap()
    };
    assert!(access.guarantee().is_some(), "kernel guarantee required");
    access
}

/// One collection round in this process; its language results and events.
fn round(r: &Request) -> (Vec<LanguageResult>, Vec<String>) {
    round_with(r, deadlines(), |_| {})
}

/// A round with these stage deadlines; `also` sees every meter event first.
/// The round must end complete (the collector would send Complete).
fn round_with(
    r: &Request,
    stages: git::StageDeadlines,
    mut also: impl FnMut(&str) + 'static,
) -> (Vec<LanguageResult>, Vec<String>) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        also(event);
        output.borrow_mut().push(event.to_owned())
    }));
    let mut sink = Sink::default();
    git::collect_with_deadlines(r, &mut sink, m, full_access(), stages).unwrap();
    let events = events.borrow().clone();
    (sink.languages, events)
}

fn calls(events: &[String]) -> u64 {
    events
        .iter()
        .find_map(|e| e.strip_prefix("languages calls="))
        .expect("language stage ran")
        .parse()
        .unwrap()
}

fn directories(events: &[String]) -> u64 {
    events
        .iter()
        .find_map(|e| e.strip_prefix("languages directories="))
        .expect("language stage ran")
        .parse()
        .unwrap()
}

fn python() -> LanguageQuery {
    BUILTIN[1].query()
}

fn python_version(cwd: &Path, home: &Path) -> Version {
    let (results, _) = round(&request(cwd, home, vec![python()]));
    assert_eq!(results.len(), 1, "{results:?}");
    results[0].version.clone()
}

// 버전 문자열 문법은 수집 작업 프로세스 안에서 확인한다. `.python-version`의 `../x`와 `x/y`는 응답에 버전이
// 없다(파일은 있으나 값 거부). 양성 대조: `3.12.1`. 이것을 실패시키는 것: 허용 글자에 `/`를 더하는 것(`x/y`가
// 통과. `../x`는 `..` 금지로도 막혀서 이 변이만으로는 통과하지 않는다).
#[test]
fn test_version_grammar() {
    let cases: [(&[u8], Option<&[u8]>); 4] = [
        (b"3.12.1\n", Some(b"3.12.1")),
        (b"../x\n", None),
        (b"x/y\n", None),
        (b"-x\n", None),
    ];
    let Some(k) = case("test_version_grammar", cases.len()) else {
        return;
    };
    let (body, found) = cases[k];
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join(".python-version"), body).unwrap();
    match (python_version(&repo, &f.0), found) {
        (Version::Found { value, .. }, Some(want)) => assert_eq!(value, want),
        (
            Version::Refused {
                file: 0, level: 0, ..
            },
            None,
        ) => {}
        (other, _) => panic!("{:?}: {other:?}", String::from_utf8_lossy(body)),
    }
}

// 버전 문자열은 32자까지다. 이것을 실패시키는 것: 32자 상한을 지우는 것(33자가 통과).
#[test]
fn test_version_length() {
    let Some(k) = case("test_version_length", 2) else {
        return;
    };
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join(".python-version"), "a".repeat(32 + k)).unwrap();
    let version = python_version(&repo, &f.0);
    if k == 0 {
        assert!(matches!(version, Version::Found { .. }), "{version:?}");
    } else {
        assert!(matches!(version, Version::Refused { .. }), "{version:?}");
    }
}

// 저장소 루트가 32단 위면 루트의 표시 파일까지 본다. 33단 위의 루트는 탐색이 찾지 못해 저장소
// 밖이므로 shell 폴더만 본다. 이것을 실패시키는 것: levels의 상한을 `..=`에서 `..`로 바꾸는 것(32단 위 루트를
// 빠뜨림), DETECT_LEVELS를 31로 낮추는 것(그러면 discovery 상한과 같다는 단언이 컴파일에서 막는다).
#[test]
fn test_detect_depth_32() {
    let cases = [(32, Some((0, 32))), (33, None)];
    let Some(k) = case("test_detect_depth_32", cases.len()) else {
        return;
    };
    let (levels, marker) = cases[k];
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join("pyproject.toml"), b"").unwrap();
    let cwd = repo.join(vec!["a"; levels].join("/"));
    fs::create_dir_all(&cwd).unwrap();
    let (results, _) = round(&request(&cwd, &f.0, vec![python()]));
    assert_eq!(results.len(), 1, "{levels}: {results:?}");
    assert_eq!(results[0].marker, marker, "{levels}");
}

// 가까운 폴더가 이긴다. shell 폴더와 루트에 모두 버전 파일이 있으면 shell 폴더 것을 쓴다. 이것을 실패시키는
// 것: levels를 루트부터 도는 것.
#[test]
fn nearest_folder_wins() {
    if case("nearest_folder_wins", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let sub = repo.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(repo.join(".python-version"), b"3.11\n").unwrap();
    fs::write(sub.join(".python-version"), b"3.12\n").unwrap();
    match python_version(&sub, &f.0) {
        Version::Found { value, level, .. } => {
            assert_eq!((value.as_slice(), level), (&b"3.12"[..], 0))
        }
        other => panic!("{other:?}"),
    }
}

// 안전 읽기 규칙: 끝 이름이 symlink인 표시 파일·버전 파일은 쓰지 않는다(링크가 저장소 안의 일반 파일을 가리켜도).
// 이것을 실패시키는 것: is_file이 링크를 따라가는 해석(resolve_with)을 쓰는 것, 버전 파일을 resolve_nofollow 대신
// 따라가는 읽기로 여는 것.
#[test]
fn symlinked_files_are_not_used() {
    if case("symlinked_files_are_not_used", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let real = repo.join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("pyproject.toml"), b"").unwrap();
    fs::write(real.join("pv"), b"3.12\n").unwrap();
    symlink("real/pyproject.toml", repo.join("pyproject.toml")).unwrap();
    symlink("real/pv", repo.join(".python-version")).unwrap();
    let (results, _) = round(&request(&repo, &f.0, vec![python()]));
    assert_eq!(results[0].marker, None);
    // The version file is there but a link: no value from it (D2 review M8).
    assert!(
        matches!(
            results[0].version,
            Version::Refused {
                file: 0,
                level: 0,
                ..
            }
        ),
        "{results:?}"
    );
}

// 셸 폴더에 더 가까운 버전 파일을 안전하게 읽을 수 없으면(링크, FIFO, 읽기 거부) 위쪽
// 파일의 값을 쓰지 않는다. pyenv와 rustup은 가까운 파일을 읽기 때문이다. 폴더는 두 관리자 모두 건너뛰므로 없는
// 것으로 보고 위로 간다(루트의 3.11.9). 이것을 실패시키는 것: Entry::Other를 건너뛰고 위로 가는 것, 폴더를 Other로
// 보는 것(폴더 칸이 Refused), read_version이 open 거부를 그 언어의 오류로 올리는 것.
#[test]
fn a_nearer_unreadable_version_file_stops_the_search() {
    let Some(k) = case("a_nearer_unreadable_version_file_stops_the_search", 4) else {
        return;
    };
    let f = Fixture::new();
    let repo = f.repo("repo");
    let sub = repo.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(repo.join(".python-version"), b"3.11.9\n").unwrap();
    let near = sub.join(".python-version");
    match k {
        0 => symlink("../.python-version", &near).unwrap(),
        1 => fs::create_dir(&near).unwrap(),
        // A regular file the stat sees but the open may not read.
        3 => {
            // SAFETY: plain query.
            if unsafe { libc::geteuid() } == 0 {
                return;
            }
            fs::write(&near, b"3.12.1\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&near, fs::Permissions::from_mode(0o000)).unwrap();
        }
        _ => {
            let c = std::ffi::CString::new(near.as_os_str().as_bytes()).unwrap();
            // SAFETY: a terminated path, read only during the call.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        }
    }
    match (k, python_version(&sub, &f.0)) {
        (
            1,
            Version::Found {
                file: 0,
                level: 1,
                value,
                ..
            },
        ) => assert_eq!(value, b"3.11.9"),
        (
            0 | 2 | 3,
            Version::Refused {
                file: 0, level: 0, ..
            },
        ) => {}
        (_, other) => panic!("case {k}: {other:?}"),
    }
}

// 같은 레벨에서 rust-toolchain이 폴더이면 rustup은 그것을 건너뛰고 rust-toolchain.toml을 읽는다.
// path 키가 든 toml이면 Path다. 이것을 실패시키는 것: 폴더를 Other로 보는 것(Refused file 0이 됨).
#[test]
fn a_folder_lets_the_next_file_of_its_level_answer() {
    let Some(k) = case("a_folder_lets_the_next_file_of_its_level_answer", 2) else {
        return;
    };
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::create_dir(repo.join("rust-toolchain")).unwrap();
    let toml: &[u8] = if k == 0 {
        b"[toolchain]\nchannel = \"1.80.0\"\n"
    } else {
        b"[toolchain]\npath = \"/opt/rust\"\n"
    };
    fs::write(repo.join("rust-toolchain.toml"), toml).unwrap();
    let (results, _) = round(&request(&repo, &f.0, vec![BUILTIN[2].query()]));
    match (k, &results[0].version) {
        (
            0,
            Version::Found {
                file: 1,
                level: 0,
                value,
                ..
            },
        ) => assert_eq!(value, b"1.80.0"),
        (1, Version::Path { file: 1, level: 0 }) => {}
        (_, other) => panic!("case {k}: {other:?}"),
    }
}

// stat 뒤 open 전에 버전 파일이 바뀌는 경우. 사라졌으면 다음 파일(같은 레벨의 rust-toolchain.toml,
// 그것이 없으면 위쪽 3.11.9), FIFO나 링크로 바뀌었으면 그 레벨의 Refused. 이것을 실패시키는 것: open의 Missing을
// 다시 보지 않고 사라짐으로 보는 것(링크 칸이 위쪽 3.11.9가 됨), Missing을 늘 Refused로 보는 것, Special을
// 건너뛰는 것, 사라진 파일 뒤에 같은 레벨의 나머지 파일을 보지 않는 것.
#[test]
fn version_file_changed_after_its_stat() {
    let Some(k) = case("version_file_changed_after_its_stat", 4) else {
        return;
    };
    if k == 2 {
        let f = Fixture::new();
        let repo = f.repo("repo");
        let legacy = repo.join("rust-toolchain");
        fs::write(&legacy, b"1.79.0\n").unwrap();
        fs::write(
            repo.join("rust-toolchain.toml"),
            b"[toolchain]\nchannel = \"1.80.0\"\n",
        )
        .unwrap();
        let mut done = false;
        let gone = move |event: &str| {
            if event == "before_language_open" && !done {
                done = true;
                fs::remove_file(&legacy).unwrap();
            }
        };
        let (results, _) = round_with(
            &request(&repo, &f.0, vec![BUILTIN[2].query()]),
            deadlines(),
            gone,
        );
        match &results[0].version {
            Version::Found {
                file: 1,
                level: 0,
                value,
                ..
            } => assert_eq!(value, b"1.80.0"),
            other => panic!("{other:?}"),
        }
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let sub = repo.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(repo.join(".python-version"), b"3.11.9\n").unwrap();
    let near = sub.join(".python-version");
    fs::write(&near, b"3.12.1\n").unwrap();
    let mut done = false;
    let change = move |event: &str| {
        if event == "before_language_open" && !done {
            done = true;
            fs::remove_file(&near).unwrap();
            if k == 1 {
                let c = std::ffi::CString::new(near.as_os_str().as_bytes()).unwrap();
                // SAFETY: a terminated path, read only during the call.
                assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            }
            if k == 3 {
                symlink("../.python-version", &near).unwrap();
            }
        }
    };
    let (results, _) = round_with(&request(&sub, &f.0, vec![python()]), deadlines(), change);
    match (k, &results[0].version) {
        (
            0,
            Version::Found {
                level: 1, value, ..
            },
        ) => assert_eq!(value, b"3.11.9"),
        (
            1 | 3,
            Version::Refused {
                file: 0, level: 0, ..
            },
        ) => {}
        (_, other) => panic!("case {k}: {other:?}"),
    }
}

// 저장소 밖이면 shell 폴더만 본다(읽기 제한의 root가 cwd 하나다). 부모의 표시 파일은 보이지 않는다. 이것을
// 실패시키는 것: Outside에서 부모 폴더까지 levels를 넘기는 것.
#[test]
fn outside_a_repository_only_the_folder_counts() {
    let Some(k) = case("outside_a_repository_only_the_folder_counts", 2) else {
        return;
    };
    let f = Fixture::new();
    let parent = f.dir("plain");
    let cwd = f.dir("plain/child");
    fs::write(parent.join("pyproject.toml"), b"").unwrap();
    if k == 1 {
        fs::write(cwd.join("pyproject.toml"), b"").unwrap();
    }
    let (results, _) = round(&request(&cwd, &f.0, vec![python()]));
    assert_eq!(results[0].marker, (k == 1).then_some((0, 0)));
}

// 3단계 사용자 정의 detect_files(표시 파일만)도 같은 경로를 지난다. 이것을 실패시키는 것: detect가 내장
// 형식이 있는 언어만 보는 것.
#[test]
fn user_detect_files_take_the_same_path() {
    if case("user_detect_files_take_the_same_path", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join("deno.json"), b"{}").unwrap();
    let query = LanguageQuery {
        id: b"custom/deno".to_vec(),
        markers: vec![b"deno.jsonc".to_vec(), b"deno.json".to_vec()],
        version_files: vec![],
    };
    let (results, _) = round(&request(&repo.join(""), &f.0, vec![query]));
    assert_eq!(results[0].marker, Some((1, 0)));
    assert_eq!(results[0].version, Version::None);
}

// 언어 요청이 없는 회차는 언어 단계를 거치지 않는다(시간도 결과도 없다). 이것을 실패시키는 것: languages()의
// 빈 요청 조기 반환을 지우는 것(languages 이벤트가 생김).
#[test]
fn git_rounds_without_languages_are_unchanged() {
    let Some(k) = case("git_rounds_without_languages_are_unchanged", 2) else {
        return;
    };
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join("pyproject.toml"), b"").unwrap();
    let languages = if k == 0 { vec![] } else { vec![python()] };
    let (results, events) = round(&request(&repo, &f.0, languages));
    assert_eq!(results.len(), k);
    assert_eq!(
        events.iter().any(|e| e == "languages"),
        k == 1,
        "{events:?}"
    );
}

// 크기 상한: 4,096바이트를 넘는 버전 파일은 값이 없다(Refused, 요약값 0). 이것을 실패시키는
// 것: Limit을 그 파일의 부재로 보는 것(답이 None이 됨).
#[test]
fn version_file_over_its_cap_has_no_value() {
    if case("version_file_over_its_cap_has_no_value", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let mut body = b"3.12\n".to_vec();
    body.resize(4_097, b'#');
    fs::write(repo.join(".python-version"), &body).unwrap();
    match python_version(&repo, &f.0) {
        Version::Refused {
            file: 0, digest, ..
        } => assert_eq!(digest, [0; 16]),
        other => panic!("{other:?}"),
    }
}

// 한 요청의 stat·읽기 수에는 상한이 있다(PROBES_MAX). 넘으면 남은 언어는 보내지 않는다(틀린 답 대신 답 없음).
// 이것을 실패시키는 것: Meter::charge의 상한 검사를 지우는 것(16개가 모두 온다).
#[test]
fn probe_bound_stops_further_languages() {
    if case("probe_bound_stops_further_languages", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let cwd = repo.join("a/b/c");
    fs::create_dir_all(&cwd).unwrap();
    // 16 languages × 16 absent markers × 4 folders = 1,024 stats.
    let query = LanguageQuery {
        id: b"custom/none".to_vec(),
        markers: (0..16)
            .map(|i| format!("absent-{i}").into_bytes())
            .collect(),
        version_files: vec![],
    };
    let (results, events) = round(&request(&cwd, &f.0, vec![query; 16]));
    assert!(results.len() < 16, "{}", results.len());
    assert!(events.iter().any(|e| e == "languages_over_bound"));
}

// 한 요청이 읽는 바이트에는 상한이 있다(BYTES_MAX 65,536). 16 KiB go.mod를 네 번 읽으면 다 쓰고, 다섯째부터는
// 보내지 않는다. 이것을 실패시키는 것: 읽은 바이트를 Spend에 더하지 않는 것(16개가 모두 온다).
#[test]
fn byte_bound_stops_further_languages() {
    if case("byte_bound_stops_further_languages", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let mut go = b"module m\ngo 1.21\n".to_vec();
    go.resize(16_384, b'\n');
    fs::write(repo.join("go.mod"), &go).unwrap();
    let (results, _) = round(&request(&repo, &f.0, vec![BUILTIN[3].query(); 16]));
    assert_eq!(results.len(), 4, "{results:?}");
    assert!(
        results
            .iter()
            .all(|r| matches!(r.version, Version::Found { .. }))
    );
}

// 언어 요청이 있는 회차에만 C가 2 ms를 언어 단계에 준다(8 → 6). 없는 회차는 그대로다.
// 이것을 실패시키는 것: product()가 언어 요청에도 PRODUCT를 돌려주는 것, 요청이 없어도 C를 줄이는 것.
#[test]
fn product_stages_give_c_time_to_languages_only() {
    use bingsu_core::collection::budget::{C_MS, LANG_MS};
    let plain = git::StageDeadlines::product(false);
    let with = git::StageDeadlines::product(true);
    assert_eq!(
        (plain.c_ms, plain.b_ms),
        (C_MS, bingsu_core::collection::budget::B_MS)
    );
    assert_eq!((with.c_ms, with.lang_ms), (C_MS - LANG_MS, LANG_MS));
    let total = |d: git::StageDeadlines| d.a_ms + d.path_ms + d.b_ms + d.c_ms + d.d_ms;
    assert_eq!(total(with) + with.lang_ms, total(plain));
}

// 호출 자리: 제품 입구(collect_with_access)가 언어 요청 회차에 C 6 ms와 언어 2 ms를 쓴다. 요청이 없으면 C 8 ms.
// 이것을 실패시키는 것: collect_with_access가 product(...) 대신 StageDeadlines::PRODUCT를 쓰는 것.
#[test]
fn product_entry_gives_c_time_to_languages() {
    let Some(k) = case("product_entry_gives_c_time_to_languages", 2) else {
        return;
    };
    let f = Fixture::new();
    let cwd = f.dir("plain");
    let languages = if k == 0 { vec![] } else { vec![python()] };
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        output.borrow_mut().push(event.to_owned())
    }));
    let mut sink = Sink::default();
    let _ = git::collect_with_access(&request(&cwd, &f.0, languages), &mut sink, m, full_access());
    let want = if k == 0 {
        "stages c=8 lang=2"
    } else {
        "stages c=6 lang=2"
    };
    assert!(
        events.borrow().iter().any(|e| e == want),
        "{:?}",
        events.borrow()
    );
}

// 파일 하나를 안전하게 읽을 수 없으면 그 언어만 답이 없다. hard link인 `.python-version`(링크 수 2)은
// 읽지 않고, 뒤의 go는 답이 오며, 회차는 완료된다(round_with가 Complete를 단언한다). 이것을 실패시키는 것:
// detect_all이 읽기 오류에서 멈추는 것(go가 오지 않음), 읽기 오류를 회차 오류로 올리는 것(round가 실패).
#[test]
fn hard_linked_version_file_leaves_only_that_language() {
    if case("hard_linked_version_file_leaves_only_that_language", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(f.0.join("pv"), b"3.12\n").unwrap();
    fs::hard_link(f.0.join("pv"), repo.join(".python-version")).unwrap();
    fs::write(repo.join("go.mod"), b"module m\ngo 1.21\n").unwrap();
    let (results, events) = round(&request(&repo, &f.0, vec![python(), BUILTIN[3].query()]));
    assert_eq!(results.len(), 1, "{results:?}");
    assert_eq!(results[0].index, 1);
    assert!(matches!(results[0].version, Version::Found { .. }));
    assert!(
        events.iter().any(|e| e == "language_unreadable"),
        "{events:?}"
    );
}

// 언어 단계 시간이 0이어도 회차는 완료되고, 남은 언어는 보내지 않는다(하나씩 건너뛰지 않고 멈춘다).
// 이것을 실패시키는 것: detect_all에서 Deadline을 멈춤 대신 그 언어만 건너뛰는 쪽으로 보내는 것
// (language_unreadable이 생김), Deadline을 회차 오류로 올리는 것(round가 실패).
#[test]
fn lang_ms_zero_keeps_the_round_complete() {
    if case("lang_ms_zero_keeps_the_round_complete", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join("pyproject.toml"), b"").unwrap();
    let mut stages = deadlines();
    stages.lang_ms = 0;
    let (results, events) = round_with(
        &request(&repo, &f.0, vec![python(), python()]),
        stages,
        |_| {},
    );
    assert!(results.is_empty(), "{results:?}");
    assert!(
        events.iter().any(|e| e == "languages_over_bound"),
        "{events:?}"
    );
    assert!(
        !events.iter().any(|e| e == "language_unreadable"),
        "{events:?}"
    );
}

// 언어 단계 안의 panic도 회차를 실패시키지 않는다(Sink 오류만 실패시킨다). 이것을 실패시키는 것:
// languages()가 Sink가 아닌 오류를 그대로 돌려주는 것(round가 실패).
#[test]
fn a_panic_in_the_language_stage_keeps_the_round_complete() {
    if case("a_panic_in_the_language_stage_keeps_the_round_complete", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    fs::write(repo.join("pyproject.toml"), b"").unwrap();
    let (results, _) = round_with(&request(&repo, &f.0, vec![python()]), deadlines(), |e| {
        assert_ne!(e, "languages", "injected panic");
    });
    assert!(results.is_empty(), "{results:?}");
}

// 한 언어는 폴더 stack 하나로 찾으므로, 20단 아래에서 16×16 요청을 해도 언어 단계가 쓰는
// Directories는 언어마다 폴더 깊이(20)를 넘지 않고, git B가 쓸 몫(4,096)이 남는다. 이것을 실패시키는 것:
// is_file이 탐침마다 새 stack(worktree_metadata)을 쓰는 것(탐침마다 20씩 씀).
#[test]
fn directories_stay_for_git_after_a_deep_request() {
    if case("directories_stay_for_git_after_a_deep_request", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let cwd = repo.join(vec!["d"; 20].join("/"));
    fs::create_dir_all(&cwd).unwrap();
    let query = LanguageQuery {
        id: b"custom/none".to_vec(),
        markers: (0..16)
            .map(|i| format!("absent-{i}").into_bytes())
            .collect(),
        version_files: vec![],
    };
    let (results, events) = round(&request(&cwd, &f.0, vec![query; 16]));
    let used = directories(&events);
    assert!(
        used <= 20 * (results.len() as u64 + 1),
        "{used} for {} languages",
        results.len()
    );
    assert!(
        used < bingsu_core::collection::budget::DIRECTORIES / 8,
        "{used}"
    );
}

// 호출 상한(1,024)은 meter가 호출을 세는 자리
// (Meter::charge)에서, 세는 모든 종류(stat·open·read·identity·mount·component·retry 등)에 건다. 20단 아래에서 표시
// 파일 둘짜리 언어 16개는 탐침이 672개(1,024 미만)지만, 폴더를 열고 확인하는 호출까지 세면 상한을 넘는다. 언어
// 단계의 실제 호출 수(모든 종류의 합)는 1,024를 넘지 않는다. 이것을 실패시키는 것: Meter::charge의 상한 검사를
// 지우는 것(16개가 모두 오고 호출이 1,024를 넘음), Meter::calls가 stat·open만 세는 것(다른 종류까지 합한 실제
// 호출이 넘음).
#[test]
fn probe_bound_counts_folder_calls() {
    if case("probe_bound_counts_folder_calls", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let cwd = repo.join(vec!["d"; 20].join("/"));
    fs::create_dir_all(&cwd).unwrap();
    let query = LanguageQuery {
        id: b"custom/none".to_vec(),
        markers: vec![b"absent-0".to_vec(), b"absent-1".to_vec()],
        version_files: vec![],
    };
    let (results, events) = round(&request(&cwd, &f.0, vec![query; 16]));
    assert!(results.len() < 16, "{}", results.len());
    assert!(events.iter().any(|e| e == "languages_over_bound"));
    assert!(calls(&events) <= 1_024, "{}", calls(&events));
}

// 언어 단계의 호출 상한은 그 단계에서 끝난다. 상한을 다 쓴 뒤에도 git 단계는 HEAD와 config를 읽고
// 저장소를 연다(repository_init). 이것을 실패시키는 것: languages()가 calls_limit을 되돌리지 않는 것(git 단계의
// 첫 호출이 거부되어 회차가 실패함).
#[test]
fn language_bound_ends_with_the_stage() {
    if case("language_bound_ends_with_the_stage", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let cwd = repo.join(vec!["d"; 20].join("/"));
    fs::create_dir_all(&cwd).unwrap();
    let query = LanguageQuery {
        id: b"custom/none".to_vec(),
        markers: vec![b"absent".to_vec()],
        version_files: vec![],
    };
    let mut r = request(&cwd, &f.0, vec![query; 16]);
    r.binding.mask = 1 << bingsu_core::collection::git::SEGMENT;
    let (_, events) = round(&r);
    let at = events
        .iter()
        .position(|e| e.starts_with("languages calls="))
        .unwrap();
    assert!(events.iter().any(|e| e == "languages_over_bound"));
    assert!(
        events[at..].iter().any(|e| e == "repository_init"),
        "{:?}",
        &events[at..]
    );
}

// Codex M1: 실패한 읽기의 바이트도 65,536 예산에 센다. stat 뒤 `.python-version`이 커지면 읽기는 4,097바이트를
// 읽고 상한 초과로 끝나며(값 없음), 그 4,097바이트가 남은 예산에서 빠져 16 KiB go.mod는 셋만 읽힌다(빼지 않으면
// 넷). 이것을 실패시키는 것: 성공한 읽기의 바이트만 세는 것.
#[test]
fn bytes_of_failed_reads_count() {
    if case("bytes_of_failed_reads_count", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let pv = repo.join(".python-version");
    fs::write(&pv, b"3.12\n").unwrap();
    let mut go = b"module m\ngo 1.21\n".to_vec();
    go.resize(16_384, b'\n');
    fs::write(repo.join("go.mod"), &go).unwrap();
    let mut armed = false;
    let mut grown = false;
    let grow = move |event: &str| {
        armed |= event == "languages";
        if armed && !grown && event == "before_read" {
            grown = true;
            use std::io::Write;
            let mut file = fs::OpenOptions::new().append(true).open(&pv).unwrap();
            file.write_all(&[b'#'; 8_000]).unwrap();
        }
    };
    let mut languages = vec![python()];
    languages.extend(std::iter::repeat_n(BUILTIN[3].query(), 4));
    let (results, _) = round_with(&request(&repo, &f.0, languages), deadlines(), grow);
    assert!(
        matches!(results[0].version, Version::Refused { file: 0, .. }),
        "{results:?}"
    );
    assert_eq!(results.len(), 4, "{results:?}");
}

// 회차를 실패시키는 것은 Sink 오류뿐이고, 언어 결과를 보내지 못하면 회차가 실패한다.
// 이것을 실패시키는 것: languages()가 Sink 오류도 삼키는 것(회차가 완료됨).
#[test]
fn a_sink_error_in_the_language_stage_fails_the_round() {
    if case("a_sink_error_in_the_language_stage_fails_the_round", 1).is_none() {
        return;
    }
    struct Refusing(Sink);
    impl update_sink::UpdateSink for Refusing {
        fn update(&mut self, value: Update) -> std::io::Result<()> {
            self.0.update(value)
        }
        fn progress(&mut self, value: Progress) -> std::io::Result<()> {
            self.0.progress(value)
        }
        fn language(&mut self, _value: LanguageResult) -> std::io::Result<()> {
            Err(std::io::Error::other("closed"))
        }
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let mut sink = Refusing(Sink::default());
    let result = git::collect_with_deadlines(
        &request(&repo, &f.0, vec![python()]),
        &mut sink,
        meter(),
        full_access(),
        deadlines(),
    );
    assert!(
        matches!(result, Err(git::CollectError::Sink(_))),
        "{result:?}"
    );
}

// 형식 상한과 같은 cap으로 읽다가 meter의 바이트·할당·호출 상한이 낸 Limit은 파일이 크다는 뜻이
// 아니다. 그 언어를 Refused로 답하지 않고 남은 언어를 멈춘다. 이것을 실패시키는 것: read_version이 cap이 형식
// 상한과 같은 모든 Limit을 Refused로 보는 것(파일 크기·읽은 바이트 검사를 지우는 것).
#[test]
fn meter_limits_stop_instead_of_refusing() {
    if case("meter_limits_stop_instead_of_refusing", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let cwd = f.dir("plain");
    fs::write(cwd.join(".python-version"), b"3.12\n").unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        output.borrow_mut().push(event.to_owned())
    }));
    // The read reserves the format's cap plus one byte (4,097): over this.
    m.byte_limit = 4_096;
    let mut sink = Sink::default();
    git::collect_with_deadlines(
        &request(&cwd, &f.0, vec![python()]),
        &mut sink,
        m,
        full_access(),
        deadlines(),
    )
    .unwrap();
    assert!(sink.languages.is_empty(), "{:?}", sink.languages);
    assert!(
        events.borrow().iter().any(|e| e == "languages_over_bound"),
        "{:?}",
        events.borrow()
    );
}

// sink가 늦었다고 답한 언어 결과는 멈춤으로 처리하고, 회차는 완료된다(Sink 오류가 아니다). 남은
// 언어는 보내지 않는다. 이것을 실패시키는 것: detect_all이 늦은 결과를 오류로 올리는 것(회차 실패), languages()
// 호출부가 늦은 결과를 Sink 오류로 바꾸는 것.
#[test]
fn a_late_language_result_keeps_the_round_complete() {
    if case("a_late_language_result_keeps_the_round_complete", 1).is_none() {
        return;
    }
    struct Late(Sink, usize);
    impl update_sink::UpdateSink for Late {
        fn update(&mut self, value: Update) -> std::io::Result<()> {
            self.0.update(value)
        }
        fn progress(&mut self, value: Progress) -> std::io::Result<()> {
            self.0.progress(value)
        }
        fn language(&mut self, _value: LanguageResult) -> std::io::Result<()> {
            self.1 += 1;
            Err(update_sink::late_language())
        }
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        output.borrow_mut().push(event.to_owned())
    }));
    let mut sink = Late(Sink::default(), 0);
    let result = git::collect_with_deadlines(
        &request(&repo, &f.0, vec![python(), python()]),
        &mut sink,
        m,
        full_access(),
        deadlines(),
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(sink.1, 1);
    assert!(events.borrow().iter().any(|e| e == "language_late"));
}

// 확인 리뷰 L: 늦음만 멈춤이다. Language 프레임 일부를 쓴 뒤 나는 일반 TimedOut(쓰기 마감)은 Sink 오류라서 회차가
// 실패하고 Complete는 쓰이지 않는다. 이것을 실패시키는 것: is_late_language를 `error.kind() == TimedOut`으로
// 약하게 하는 것(일반 TimedOut도 멈춤이 되어 회차가 완료됨).
#[test]
fn a_partial_language_write_fails_the_round() {
    // Frame header byte 10 is the kind's wire tag.
    const LANGUAGE_TAG: u8 = 8;
    const COMPLETE_TAG: u8 = 6;
    if case("a_partial_language_write_fails_the_round", 1).is_none() {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("repo");
    let r = request(&repo, &f.0, vec![python()]);
    let mut ready = wire::FEATURES.to_le_bytes().to_vec();
    ready.extend(r.binding.mask.to_le_bytes());
    ready.extend([0; 12]);
    let output = RefCell::new(Vec::<Vec<u8>>::new());
    let mut write = |bytes: &[u8]| {
        if bytes[10] == LANGUAGE_TAG {
            output.borrow_mut().push(bytes[..bytes.len() / 2].to_vec());
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        output.borrow_mut().push(bytes.to_vec());
        Ok(())
    };
    let mut buffer = [0; wire::FRAME_MAX];
    let mut sink = update_sink::WireSink::new(
        &r,
        bingsu_core::field::BUILTIN,
        &ready,
        &mut buffer,
        &mut write,
    )
    .unwrap();
    let result = git::collect_with_deadlines(&r, &mut sink, meter(), full_access(), deadlines());
    // The exchange owner sends Complete only after a complete round.
    let completed = result.is_ok() && sink.complete().is_ok();
    assert!(
        matches!(&result, Err(git::CollectError::Sink(e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert!(!completed);
    let frames = output.borrow();
    assert!(frames.iter().any(|f| f[10] == LANGUAGE_TAG));
    assert!(!frames.iter().any(|f| f[10] == COMPLETE_TAG));
}
