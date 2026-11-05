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
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        output.borrow_mut().push(event.to_owned())
    }));
    let mut sink = Sink::default();
    git::collect_with_deadlines(r, &mut sink, m, full_access(), deadlines()).unwrap();
    let events = events.borrow().clone();
    (sink.languages, events)
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

// C2 판정 Q2(D1): 저장소 루트가 32단 위면 루트의 표시 파일까지 본다. 33단 위의 루트는 탐색이 찾지 못해 저장소
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
    assert_eq!(results[0].version, Version::None);
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

// 크기 상한(C2 판정 Q4, D1): 4,096바이트를 넘는 버전 파일은 값이 없다(Refused, 요약값 0). 이것을 실패시키는
// 것: Limit을 그 파일의 부재로 보는 것(다음 파일로 넘어가 Found).
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
    fs::write(repo.join(".tool-versions"), b"python 3.11\n").unwrap();
    match python_version(&repo, &f.0) {
        Version::Refused {
            file: 0, digest, ..
        } => assert_eq!(digest, [0; 16]),
        other => panic!("{other:?}"),
    }
}

// 한 요청의 stat·읽기 수에는 상한이 있다(PROBES_MAX). 넘으면 남은 언어는 보내지 않는다(틀린 답 대신 답 없음).
// 이것을 실패시키는 것: Spend::probe의 상한 검사를 지우는 것(16개가 모두 온다).
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

// 사용자 결정 U-19: 언어 요청이 있는 회차에만 C가 2 ms를 언어 단계에 준다(8 → 6). 없는 회차는 그대로다.
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

// U-19 호출 자리: 제품 입구(collect_with_access)가 언어 요청 회차에 C 6 ms와 언어 2 ms를 쓴다. 요청이 없으면 C 8 ms.
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
