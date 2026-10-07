//! Every probe prints its JSON keys even when the platform cannot do the
//! thing it probes (unsupported is data, not a crash).
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Runs `cmd` to completion, but kills it (and fails the test) after
/// `limit`: a probe that never returns is a failure, not a stuck test run.
fn output_within(cmd: &mut Command, limit: Duration) -> Output {
    use std::io::Read;
    let mut c = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pipe = |r: Option<Box<dyn Read + Send>>| {
        let mut r = r.unwrap();
        std::thread::spawn(move || {
            let mut v = Vec::new();
            r.read_to_end(&mut v).unwrap();
            v
        })
    };
    let out = pipe(c.stdout.take().map(|o| Box::new(o) as _));
    let err = pipe(c.stderr.take().map(|e| Box::new(e) as _));
    let t = Instant::now();
    let status = loop {
        if let Some(st) = c.try_wait().unwrap() {
            break st;
        }
        if t.elapsed() > limit {
            let _ = c.kill();
            let _ = c.wait();
            panic!("{cmd:?} still running after {limit:?}; killed");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

fn run(bin: &str, args: &[&str]) -> String {
    let out = output_within(Command::new(bin).args(args), Duration::from_secs(120));
    assert!(
        out.status.success(),
        "{bin}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A new folder under the cargo test temp dir (never reused: the name
/// carries the pid, the time and the tag).
fn new_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("probe-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A flat JSON object (string, bool, number or null values) as (key,
/// type) pairs in order. Strings keep their escapes; enough to tell keys
/// from string contents.
fn flat_object(o: &str) -> Vec<(String, &'static str)> {
    let mut c = o.trim_end().chars().peekable();
    let string = |c: &mut std::iter::Peekable<std::str::Chars<'_>>| {
        assert_eq!(c.next(), Some('"'), "string expected in {o}");
        let mut s = String::new();
        loop {
            match c.next().unwrap_or_else(|| panic!("open string in {o}")) {
                '"' => return s,
                '\\' => s.push(c.next().unwrap()),
                ch => s.push(ch),
            }
        }
    };
    assert_eq!(c.next(), Some('{'), "{o}");
    let mut out = Vec::new();
    loop {
        let k = string(&mut c);
        assert_eq!(c.next(), Some(':'), "{o}");
        let t = match c.peek() {
            Some('"') => {
                string(&mut c);
                "str"
            }
            _ => {
                let v: String =
                    std::iter::from_fn(|| c.next_if(|ch| !matches!(ch, ',' | '}'))).collect();
                match v.as_str() {
                    "true" | "false" => "bool",
                    "null" => "null",
                    n if n.parse::<f64>().is_ok() => "num",
                    other => panic!("bad value {other:?} in {o}"),
                }
            }
        };
        out.push((k, t));
        match c.next() {
            Some(',') => {}
            Some('}') => break,
            other => panic!("{other:?} in {o}"),
        }
    }
    assert_eq!(c.next(), None, "one object: {o}");
    out
}

/// The line has exactly the keys of x04-schema.tsv, in order, each of its type.
fn check_x04_schema(o: &str) {
    let schema = include_str!("../../../bench/probes/x04-schema.tsv");
    let want: Vec<(String, &str)> = schema
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_once('\t').expect("key<TAB>type"))
        .map(|(k, t)| (k.to_string(), t))
        .collect();
    assert!(
        want.iter().all(|(_, t)| matches!(*t, "str" | "bool")),
        "unknown schema type"
    );
    assert_eq!(o.trim_end().lines().count(), 1, "one line: {o}");
    assert_eq!(flat_object(o), want, "{o}");
}

// 이것을 실패시키는 것: 판정에 필요한 키를 빼거나, 스키마(ingest.py와 같은 파일)와 키·타입이 어긋나거나,
// 바깥 문자열(label)의 따옴표가 키처럼 세어지는 것. 탐침 없이도 도는 쪽이라 macOS에서도 돈다.
#[test]
fn x04_line_matches_schema() {
    use bingsu_bench::cgroup_rule::X04;
    check_x04_schema(&X04::default().line());
    check_x04_schema(
        &X04 {
            label: "q\":x".into(),
            ..X04::default()
        }
        .line(),
    );
}

/// The X-04 tests run one probe at a time: each counts the probe folders
/// left in its cgroup, and a concurrent probe's folder is not a leftover.
#[cfg(target_os = "linux")]
static X04_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// 이것을 실패시키는 것: 판정에 필요한 키를 빼거나, 스키마와 키·타입이 어긋나거나,
// 할 수 없는 환경(위임 밖의 CI 러너)에서 패닉하는 것.
#[cfg(target_os = "linux")]
#[test]
fn x04_keys() {
    let _one = X04_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let o = run(env!("CARGO_BIN_EXE_m1-cgroup-probe"), &["ci"]);
    check_x04_schema(&o);
    assert!(o.contains(r#""label":"ci""#), "{o}");
}

/// Probe folders (`bingsu-x04-<pid>`) directly under `dir`.
#[cfg(target_os = "linux")]
fn x04_leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("bingsu-x04-"))
        .collect()
}

// 위임 영역(BINGSU_TEST_CGROUP_DIR, CI의 Delegate=yes scope) 안에서 돈다. 영역이 없으면 NOTE를 남기고
// 건너뛰며, BINGSU_REQUIRE_CGROUP_TESTS=1이면 실패한다.
// 이것을 실패시키는 것: 6.x 위임 영역에서 원자 경로를 끄는 것(atomic·kill_ok가 false면 함의가 공허하게
// 참이 되므로 둘 다 true를 직접 단언한다), cgroup.kill 쓰기를 빼는 것, 끝나거나 패닉한 뒤 자식 폴더를
// 남기는 것(guard 없이 rmdir하는 것), 패닉 때 sleeper를 죽이지 않고 기다리는 것(30초 sleep),
// 다시 읽기를 하지 않고 옮기기 성공만으로 readback을 참으로 두는 것(형제 cgroup seam), 형제 폴더를 남기는 것.
#[cfg(target_os = "linux")]
#[test]
fn x04_delegated() {
    let Some(dir) = std::env::var_os("BINGSU_TEST_CGROUP_DIR").map(PathBuf::from) else {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_CGROUP_TESTS").is_none_or(|v| v != "1"),
            "BINGSU_REQUIRE_CGROUP_TESTS=1 but BINGSU_TEST_CGROUP_DIR is not set"
        );
        eprintln!("NOTE: x04_delegated skipped: BINGSU_TEST_CGROUP_DIR is not set");
        return;
    };
    let _one = X04_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = env!("CARGO_BIN_EXE_m1-cgroup-probe");
    assert_eq!(x04_leftovers(&dir), Vec::<String>::new(), "before");
    let o = run(bin, &["delegated"]);
    check_x04_schema(&o);
    let own = dir
        .to_str()
        .unwrap()
        .strip_prefix("/sys/fs/cgroup")
        .unwrap();
    assert!(o.contains(&format!(r#""cgroup":"{own}""#)), "{o}");
    for k in [
        "mkdir_child",
        "child_has_kill",
        "move_ok",
        "readback_ok",
        "kill_ok",
        "rmdir_ok",
        "delegated",
        "atomic",
    ] {
        assert!(o.contains(&format!(r#""{k}":true"#)), "{k} in {o}");
    }
    assert_eq!(x04_leftovers(&dir), Vec::<String>::new(), "after a run");
    // The sleeper runs 30 s: a probe that does not kill it on unwind
    // waits that long before its folder can go.
    let t = Instant::now();
    let p = output_within(
        Command::new(bin)
            .arg("panic")
            .env("BINGSU_X04_PANIC_AFTER_MOVE", "1"),
        Duration::from_secs(120),
    );
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(p.status.code(), Some(101), "{p:?}");
    assert!(
        String::from_utf8_lossy(&p.stderr).contains("BINGSU_X04_PANIC_AFTER_MOVE"),
        "{p:?}"
    );
    assert_eq!(x04_leftovers(&dir), Vec::<String>::new(), "after a panic");
    // The sleeper leaves for a sibling cgroup before the readback: the
    // readback, and everything that rests on it, must be false.
    let o = output_within(
        Command::new(bin)
            .arg("sibling")
            .env("BINGSU_X04_SIBLING_BEFORE_READBACK", "1"),
        Duration::from_secs(120),
    );
    assert!(o.status.success(), "{o:?}");
    let o = String::from_utf8(o.stdout).unwrap();
    check_x04_schema(&o);
    for (k, v) in [
        ("mkdir_child", true),
        ("move_ok", true),
        ("readback_ok", false),
        ("delegated", false),
        ("atomic", false),
        ("kill_ok", false),
        ("rmdir_ok", true),
    ] {
        assert!(o.contains(&format!(r#""{k}":{v}"#)), "{k} in {o}");
    }
    assert_eq!(
        x04_leftovers(&dir),
        Vec::<String>::new(),
        "after the sibling run"
    );
}

// 이것을 실패시키는 것: 시도 줄을 빼는 것, 자식이 setrlimit 결과를 보고하지 않는 것,
// 수용 기준 밖의 판정(limited·error)을 내는 것. 판정 순서는 bin의 단위 시험 `verdicts`가 잡는다.
#[cfg(target_os = "macos")]
#[test]
fn x29_classifies_each_trial() {
    let o = run(env!("CARGO_BIN_EXE_m1-macos-rlimit-as"), &[]);
    assert!(
        o.lines().next().unwrap().contains("\"vsize_before\":"),
        "{o}"
    );
    assert!(!o.lines().next().unwrap().contains("na:"), "{o}");
    assert_eq!(o.matches("\"verdict\"").count(), 3, "{o}");
    for l in o.lines().skip(1) {
        assert!(l.contains("setrlimit rc="), "{l}");
        assert!(
            l.contains(r#""verdict":"refused""#) || l.contains(r#""verdict":"not-limited""#),
            "X-29 acceptance: {l}"
        );
    }
}

fn row<'a>(o: &'a str, name: &str) -> &'a str {
    o.lines()
        .find(|l| l.contains(&format!(r#""row":"{name}""#)))
        .unwrap_or_else(|| panic!("no row {name} in {o}"))
}

fn field(l: &str, key: &str) -> u64 {
    let rest = l
        .split(&format!(r#""{key}":"#))
        .nth(1)
        .unwrap_or_else(|| panic!("{key} in {l}"));
    rest.split([',', '}'])
        .next()
        .unwrap()
        .parse()
        .unwrap_or_else(|e| panic!("{key} in {l}: {e}"))
}

/// The fixture script with `cwd` as its folder and a minimal environment:
/// no inherited `GIT_*`, OLDPWD and HOME are `cwd`, and git discovery stops
/// at `cwd`'s parent. A broken script (a regression or a mutation) then
/// stays inside the test's temp folder instead of reaching this repository
/// (a `cd -` to an inherited OLDPWD once committed a fixture here).
fn fixture_cmd(cwd: &Path) -> Command {
    let mut c = Command::new(repo().join("bench/probes/make-pack-fixture.sh"));
    c.current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", cwd)
        .env("OLDPWD", cwd)
        .env("GIT_CEILING_DIRECTORIES", cwd.parent().unwrap());
    c
}

#[cfg(target_os = "macos")]
fn make_pack(blobs: &str) -> (PathBuf, PathBuf) {
    let dir = new_dir("pack");
    let fixture = dir.join("repo");
    let out = output_within(
        fixture_cmd(&dir).arg(&fixture).arg(blobs),
        Duration::from_secs(120),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pack = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim_end());
    assert!(
        pack.extension().is_some_and(|e| e == "pack"),
        "{}",
        pack.display()
    );
    (dir, pack)
}

// 이것을 실패시키는 것: 행을 빼는 것, 파일을 매핑만 하고 페이지를 건드리지 않는 것(resident가 그대로),
// 익명 64MiB를 footprint에 잡히지 않게 만드는 것, 넘침 표본을 하나도 못 얻는 것.
#[cfg(target_os = "macos")]
#[test]
fn watchdog_rows_and_phases() {
    let (dir, pack) = make_pack("4"); // 16 MiB pack
    let o = run(
        env!("CARGO_BIN_EXE_m1-macos-watchdog"),
        &[
            pack.to_str().unwrap(),
            "--batches",
            "3",
            "--interval-secs",
            "1",
            "--trials",
            "3",
        ],
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!o.contains("\"na\""), "{o}");
    assert!(
        field(row(&o, "proc_pid_rusage/call"), "median_ns") > 0,
        "{o}"
    );
    for ms in [1, 2, 4] {
        assert!(
            field(row(&o, &format!("interval/{ms}ms")), "samples") > 0,
            "{o}"
        );
    }
    let start = row(&o, "phase/start");
    let touched = row(&o, "phase/file-touched");
    let anon = row(&o, "phase/anon-64mib");
    assert!(
        field(touched, "resident") >= field(start, "resident") + 12 * 1024 * 1024,
        "{o}"
    );
    assert!(
        field(anon, "footprint") >= field(touched, "footprint") + 60 * 1024 * 1024,
        "{o}"
    );
    let over = row(&o, "overshoot/2ms");
    assert_eq!(field(over, "n") + field(over, "missed"), 3, "{o}");
    assert!(field(over, "n") > 0, "{o}");
}

// 이것을 실패시키는 것: 매핑할 수 없는 파일에서 패닉하거나, 자식이 가지 못한 단계를 0으로 적는 것,
// 한도를 넘지 못한 시도를 기다림 없이 무한히 표본하거나 넘침으로 세는 것, 없는 PACK으로 도는 것.
#[cfg(target_os = "macos")]
#[test]
fn watchdog_failures_are_na() {
    let dir = new_dir("empty-pack");
    let empty = dir.join("empty.pack");
    std::fs::write(&empty, b"").unwrap();
    let bin = env!("CARGO_BIN_EXE_m1-macos-watchdog");
    let o = run(
        bin,
        &[
            empty.to_str().unwrap(),
            "--batches",
            "1",
            "--interval-secs",
            "1",
            "--trials",
            "2",
            "--over-mib",
            "1024",
        ],
    );
    let missing = output_within(
        Command::new(bin).arg(dir.join("none.pack")),
        Duration::from_secs(120),
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(row(&o, "phase/start").contains("\"footprint\":"), "{o}");
    for p in ["phase/file-touched", "phase/anon-64mib"] {
        assert!(row(&o, p).contains(r#""na":"child exit status: 3""#), "{o}");
    }
    assert!(
        row(&o, "overshoot/2ms").contains(r#""na":"no trial crossed the limit (2 missed)""#),
        "{o}"
    );
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
}

/// A stand-in stub that ignores its arguments.
fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

// 이것을 실패시키는 것: VM 값을 파싱하지 못한 실행이나 실패한 stub(종료 3)을 0으로 섞어 정상 행으로 내는 것,
// na에 round를 빼는 것.
#[test]
fn rlimit_start_rows_and_na() {
    let dir = new_dir("rlimit-start");
    let good = stub(&dir, "good.sh", "printf 'VM 2048\\nR'");
    let unsupported = stub(&dir, "unsupported.sh", "printf 'VM unsupported\\nR'");
    let limits_failed = stub(&dir, "limits-failed.sh", "printf 'VM 1\\nR'; exit 3");
    let bin = env!("CARGO_BIN_EXE_m1-rlimit-as-start");
    let s = |p: &PathBuf| p.to_str().unwrap().to_string();
    let o = run(
        bin,
        &[
            "--dedicated",
            &s(&good),
            "--same",
            &s(&unsupported),
            "--runs",
            "3",
        ],
    );
    let ded = row(&o, "dedicated");
    assert_eq!(
        (
            field(ded, "n"),
            field(ded, "vmsize_kib_median"),
            field(ded, "vmsize_kib_max")
        ),
        (3, 2048, 2048),
        "{o}"
    );
    assert!(
        row(&o, "same").contains(r#"not \"VM <KiB>\" (round 1)""#),
        "{o}"
    );
    let o = run(
        bin,
        &[
            "--dedicated",
            &s(&limits_failed),
            "--same",
            &s(&good),
            "--runs",
            "2",
        ],
    );
    assert!(
        row(&o, "dedicated").contains(r#""na":"stub exit status: 3 (round 1)""#),
        "{o}"
    );
    assert_eq!(field(row(&o, "same"), "n"), 2, "{o}");
    let _ = std::fs::remove_dir_all(&dir);
}

// 이것을 실패시키는 것: 열 수가 달라지거나, 부팅 정체가 OS 값과 다르거나, 넷째 열이 부팅 시각(Unix 초)이 아니거나
// (Linux 가동 시간, macOS kern.boottime 원문), 탭·공백이 든 label을 받아 TSV를 깨는 것.
#[test]
fn x05_line() {
    let script = repo().join("bench/probes/x05-boot-id.sh");
    let o = run("bash", &[script.to_str().unwrap(), "before-logout"]);
    let cols: Vec<&str> = o.trim_end_matches('\n').split('\t').collect();
    assert_eq!(cols.len(), 4, "{o:?}");
    assert_eq!(cols[1], "before-logout");
    let want = if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "kern.bootsessionuuid"])
    } else {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap()
    };
    assert_eq!(cols[2], want.trim(), "{o:?}");
    // Boot time in Unix seconds on both OSes, read here independently.
    let boot = if cfg!(target_os = "macos") {
        let raw = run("sysctl", &["-n", "kern.boottime"]);
        raw.split("sec = ")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .to_string()
    } else {
        let stat = std::fs::read_to_string("/proc/stat").unwrap();
        stat.lines()
            .find_map(|l| l.strip_prefix("btime "))
            .unwrap()
            .trim()
            .to_string()
    };
    assert_eq!(cols[3], boot, "{o:?}");
    let bad = output_within(
        Command::new("bash").arg(&script).arg("a\tb"),
        Duration::from_secs(120),
    );
    assert_eq!(bad.status.code(), Some(2));
}

// 이것을 실패시키는 것: 이미 있는 폴더를 지우고 다시 쓰는 것(잘못 준 경로가 데이터를 지움).
#[test]
fn pack_fixture_refuses_existing_dir() {
    let dir = new_dir("pack-exists");
    std::fs::write(dir.join("keep"), b"x").unwrap();
    let out = output_within(
        fixture_cmd(&dir).arg(&dir).arg("1"),
        Duration::from_secs(120),
    );
    let kept = dir.join("keep").exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!((out.status.code(), kept), (Some(2), true));
}

// 이것을 실패시키는 것: 절대 경로 검사를 빼는 것(`-`가 OLDPWD로, 상대 경로가 현재 폴더로 감),
// 빈 BLOBS를 기본값으로 바꾸는 것, 인자 개수를 확인하지 않는 것.
#[test]
fn pack_fixture_refuses_bad_args() {
    let cwd = new_dir("pack-args");
    let fresh = cwd.join("fresh");
    let f = fresh.to_str().unwrap();
    for args in [
        &[][..],
        &[""],
        &["-"],
        &["rel"],
        &[f, ""],
        &[f, "0"],
        &[f, "1", "extra"],
    ] {
        let out = output_within(fixture_cmd(&cwd).args(args), Duration::from_secs(120));
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
    }
    let left: Vec<_> = std::fs::read_dir(&cwd).unwrap().collect();
    let _ = std::fs::remove_dir_all(&cwd);
    assert!(left.is_empty(), "{left:?}");
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = output_within(
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1"),
        Duration::from_secs(120),
    );
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

// 이것을 실패시키는 것: 지역 git 환경 변수(GIT_DIR·GIT_WORK_TREE·GIT_INDEX_FILE·GIT_OBJECT_DIRECTORY)를
// 지우는 줄을 빼는 것(fixture 커밋·repack이 sentinel 저장소에서 돈다), `git init`의 `--template=`을 빼는 것
// (GIT_TEMPLATE_DIR의 post-commit 훅이 fixture 커밋에서 돈다).
#[test]
fn pack_fixture_ignores_git_env() {
    let root = new_dir("pack-git-env");
    let sentinel = root.join("sentinel");
    std::fs::create_dir(&sentinel).unwrap();
    git(&sentinel, &["init", "-q", "--template="]);
    std::fs::write(sentinel.join("a"), b"a").unwrap();
    git(&sentinel, &["add", "a"]);
    git(
        &sentinel,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-qm",
            "s",
        ],
    );
    let state = |d: &Path| {
        (
            git(d, &["rev-parse", "HEAD"]),
            git(d, &["status", "--porcelain", "--untracked-files=all"]),
            git(d, &["count-objects", "-v"]),
        )
    };
    let before = state(&sentinel);
    // GIT_TEMPLATE_DIR is not a local-env var, so the unset above keeps it:
    // a template hook must still not reach the fixture (`--template=`).
    let tpl = root.join("tpl");
    let marker = root.join("hook-ran");
    std::fs::create_dir_all(tpl.join("hooks")).unwrap();
    let hook = tpl.join("hooks/post-commit");
    std::fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let fixture = root.join("fixture");
    let gd = sentinel.join(".git");
    let out = output_within(
        fixture_cmd(&sentinel)
            .arg(&fixture)
            .arg("1")
            .env("GIT_DIR", &gd)
            .env("GIT_WORK_TREE", &sentinel)
            .env("GIT_INDEX_FILE", gd.join("index"))
            .env("GIT_OBJECT_DIRECTORY", gd.join("objects"))
            .env("GIT_TEMPLATE_DIR", &tpl),
        Duration::from_secs(120),
    );
    let after = state(&sentinel);
    let hook_ran = marker.exists();
    let hooks_dir = fixture.join(".git/hooks").exists();
    let pack = String::from_utf8(out.stdout.clone()).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(before, after);
    assert!(
        !hook_ran && !hooks_dir,
        "template used: hook ran {hook_ran}, hooks dir {hooks_dir}"
    );
    let pack = Path::new(pack.trim_end());
    assert!(
        pack.starts_with(fixture.join(".git/objects/pack")),
        "{}",
        pack.display()
    );
}

// 이것을 실패시키는 것: X-04가 LABEL 없이·빈 LABEL로·추가 인자와 함께 줄을 내는 것(환경 표식이 빠진 자료),
// X-05가 인자 개수를 확인하지 않는 것.
#[test]
fn probe_args_fail_closed() {
    let x04 = env!("CARGO_BIN_EXE_m1-cgroup-probe");
    for args in [&[][..], &[""], &["ssh", "extra"]] {
        let out = output_within(Command::new(x04).args(args), Duration::from_secs(120));
        assert_eq!(out.status.code(), Some(2), "x04 {args:?}: {out:?}");
        assert!(out.stdout.is_empty(), "x04 {args:?}: {out:?}");
    }
    let x05 = repo().join("bench/probes/x05-boot-id.sh");
    for args in [&[][..], &["a", "b"]] {
        let out = output_within(
            Command::new("bash").arg(&x05).args(args),
            Duration::from_secs(120),
        );
        assert_eq!(out.status.code(), Some(2), "x05 {args:?}: {out:?}");
        assert!(out.stdout.is_empty(), "x05 {args:?}: {out:?}");
    }
}

// macOS에서 PATH 맨 앞의 가짜 sysctl로 값을 바꾼다(Linux의 /proc 쪽은 shim을 둘 수 없다).
// 이것을 실패시키는 것: 빈 부팅 정체를 거르는 `[[ -n $id ]]`를 지우는 것, 숫자가 아닌 부팅 시각을 거르는
// 검사를 지우는 것. 둘 다 빈 열이나 원문이 든 줄을 정상 자료처럼 낸다.
#[cfg(target_os = "macos")]
#[test]
fn x05_refuses_empty_or_odd_values() {
    let dir = new_dir("x05-shim");
    let shim = dir.join("sysctl");
    std::fs::write(
        &shim,
        "#!/bin/sh\ncase $2 in kern.bootsessionuuid) printf '%s\\n' \"$SHIM_ID\" ;; \
         kern.boottime) printf '%s\\n' \"$SHIM_BT\" ;; *) exit 9 ;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap());
    let script = repo().join("bench/probes/x05-boot-id.sh");
    let x05 = |id: &str, bt: &str| {
        output_within(
            Command::new("bash")
                .arg(&script)
                .arg("t")
                .env("PATH", &path)
                .env("SHIM_ID", id)
                .env("SHIM_BT", bt),
            Duration::from_secs(120),
        )
    };
    let good_bt = "{ sec = 5, usec = 0 } Thu Jan  1 09:00:05 1970";
    let ok = x05("ID-1", good_bt);
    let empty_id = x05("", good_bt);
    let weird_bt = x05("ID-1", "weird");
    let _ = std::fs::remove_dir_all(&dir);
    // The shim is what the script read: id and boot time come from it.
    assert!(ok.status.success(), "{ok:?}");
    assert!(
        String::from_utf8_lossy(&ok.stdout).ends_with("\tt\tID-1\t5\n"),
        "{ok:?}"
    );
    for (what, out) in [("empty id", &empty_id), ("weird boottime", &weird_bt)] {
        assert_ne!(out.status.code(), Some(0), "{what}: {out:?}");
        assert!(out.stdout.is_empty(), "{what}: {out:?}");
    }
}
