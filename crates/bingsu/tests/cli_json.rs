//! `--format json` of `explain` and `config check` through the real binary:
//! each document matches `schema/diag-output-v1.json` (a renamed, dropped
//! or added field fails), representative output is pinned byte for byte
//! (BINGSU_UPDATE_GOLDEN=1 rewrites it), an environment value never appears,
//! and wrong flags exit 2.
#![cfg(unix)]

#[path = "../../bingsu-core-tests/src/json_schema.rs"]
mod json_schema;
#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, quiet, text};

const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/json/");

const LAYOUT: &str = r#"version = 1
[segment."custom/a"]
kind = "text"
text = "AAAAAAAAAAAAAAAA"
[segment."custom/b"]
kind = "text"
text = "BBBBBBBBBBBBBBBB"
[layout.line2]
left = ["custom/a", "dir", "char"]
right = ["custom/b"]
[layout.when.wide]
min_cols = 100
"#;

fn run(e: &Env, args: &[&str]) -> std::process::Output {
    // `dir` shows the current folder: `/` keeps the output the same everywhere.
    e.cmd(args).current_dir("/").output().unwrap()
}

fn ok(e: &Env, args: &[&str]) -> String {
    let o = run(e, args);
    assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o.stderr));
    assert_eq!(quiet(&o.stderr), "", "{args:?}");
    text(&o.stdout)
}

#[allow(clippy::disallowed_methods, reason = "golden update switch of a test")]
fn golden(name: &str, got: &str) {
    let path = format!("{GOLDEN_DIR}{name}");
    if std::env::var_os("BINGSU_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        got, want,
        "{name}: run with BINGSU_UPDATE_GOLDEN=1 and review the diff"
    );
}

fn schema(docs: &[&str]) {
    if let Err(e) = json_schema::validate(None, docs) {
        panic!("{e}\n{docs:?}");
    }
}

// 이것을 실패시키는 것: explain의 json 필드 이름·구조를 바꾸는 것(스키마 위반), 폭마다 다른 구간·넘침·숨김 기록을 다르게
// 내보내는 것(golden), 사람용 글과 json의 모델이 갈라지는 것(같은 폭 40·41 경계의 구간).
#[test]
fn explain_json_matches_the_schema_and_the_golden() {
    let e = Env::new("cli_json", "explain");
    let file = e.put("layout.toml", LAYOUT);
    let shown = file.to_str().unwrap();
    let (mut docs, mut all) = (Vec::new(), String::new());
    for w in ["120", "100", "60", "41", "40", "20", "1"] {
        let doc = ok(
            &e,
            &[
                "explain", "--config", shown, "--width", w, "--format", "json",
            ],
        );
        assert_eq!(doc.matches('\n').count(), 1, "one line: {doc}");
        all.push_str(&doc.replace(shown, "<file>"));
        docs.push(doc);
    }
    schema(&docs.iter().map(String::as_str).collect::<Vec<_>>());
    golden("explain-widths.jsonl", &all);
    // The band of the JSON is the band of the text, at the edge.
    for (w, band) in [("100", "band `wide`"), ("99", "the default layout")] {
        let t = ok(&e, &["explain", "--config", shown, "--width", w]);
        let j = ok(
            &e,
            &[
                "explain", "--config", shown, "--width", w, "--format", "json",
            ],
        );
        assert!(t.contains(band), "{t}");
        assert_eq!(
            j.contains("\"band\":\"wide\""),
            band.contains("wide"),
            "{j}"
        );
    }
}

// 이것을 실패시키는 것: 명령 세그먼트의 실행 조건(`execution`)을 json에서 빼거나 모양을 바꾸는 것, `--config`에서
// 실행 파일을 조회하게 되는 것(execution이 null이 아님), 환경 변수 값을 문서에 넣는 것.
#[test]
fn execution_units_in_json_never_carry_environment_values() {
    let e = Env::new("cli_json", "execution");
    let cfg = "version = 1\n[segment.\"custom/c\"]\nkind = \"command\"\ncommand = [\"/bin/echo\", \"hi\"]\nenv_allow = [\"BINGSU_SECRET_PROBE\"]\n[segment.\"custom/e\"]\nkind = \"env\"\nenv = \"BINGSU_SECRET_PROBE\"\n[layout.line2]\nleft = [\"custom/c\", \"custom/e\", \"char\"]\n";
    e.put_config("config.toml", cfg);
    let file = e.put("work.toml", cfg);
    let secret = "topsecretvalue";
    let with_secret = |args: &[&str]| {
        let o = e
            .cmd(args)
            .current_dir("/")
            .env("BINGSU_SECRET_PROBE", secret)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o.stderr));
        format!("{}{}", text(&o.stdout), quiet(&o.stderr))
    };
    let own = with_secret(&["explain", "custom/c", "--width", "80", "--format", "json"]);
    let given = with_secret(&[
        "explain",
        "custom/c",
        "--config",
        file.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let check = with_secret(&["config", "check", "--explain", "--format", "json"]);
    for doc in [&own, &given, &check] {
        assert!(!doc.contains(secret), "{doc}");
    }
    schema(&[&own, &given, &check]);
    assert!(
        own.contains("\"environment\":[{\"name\":\"BINGSU_SECRET_PROBE\""),
        "{own}"
    );
    assert!(own.contains("\"id\":\"custom/c\""), "{own}");
    assert!(given.contains("\"execution\":null"), "{given}");
    assert!(
        given.contains("\"execution_note\":\"not shown for --config"),
        "{given}"
    );
    assert!(check.contains("\"execution\":[{"), "{check}");
}

// 이것을 실패시키는 것: config check의 json 필드를 바꾸는 것(스키마), 오류가 있는데 종료 코드·result가 text와 다른 것,
// `--format json`이 사람용 글을 섞는 것.
#[test]
fn config_check_json_matches_the_schema_and_exits_like_the_text() {
    let e = Env::new("cli_json", "check");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let valid = ok(&e, &["config", "check", "--format", "json"]);
    let valid_x = ok(&e, &["config", "check", "--explain", "--format", "json"]);
    assert!(
        valid.contains("\"result\":\"valid\"") && valid.contains("\"exit_code\":0"),
        "{valid}"
    );
    e.put_config("config.toml", "colr = 1\n");
    let o = run(&e, &["config", "check", "--format", "json"]);
    assert_eq!(o.status.code(), Some(1));
    let invalid = text(&o.stdout);
    assert!(
        invalid.starts_with('{') && invalid.ends_with("}\n"),
        "{invalid}"
    );
    assert!(invalid.contains("\"code\":\"E201\""), "{invalid}");
    assert!(invalid.contains("\"exit_code\":1"), "{invalid}");
    assert!(invalid.contains("\"result\":\"invalid\""), "{invalid}");
    assert!(
        invalid.contains("\"result_text\":\"invalid; the prompt keeps"),
        "{invalid}"
    );
    schema(&[&valid, &valid_x, &invalid]);
    let base = e.base.to_str().unwrap();
    golden(
        "config-check-invalid.json",
        &invalid.replace(base, "<base>"),
    );
    // The same run as text agrees on the verdict.
    let t = run(&e, &["config", "check"]);
    assert_eq!(t.status.code(), Some(1));
    assert!(text(&t.stdout).contains("result: invalid"));
}

// With the files broken after a publish, explain still explains what the prompt draws and says the files have
// errors, in both formats.
// 이것을 실패시키는 것: 원본에 오류가 있을 때 발행본이 있어도 explain이 실패하는 것, 오류 알림 줄(또는 json의
// diagnostics)을 빼는 것, 발행본이 없으면 그대로 실패하는 것을 바꾸는 것.
#[test]
fn explain_with_invalid_files_uses_the_published_settings() {
    let e = Env::new("cli_json", "invalid");
    e.put_config("config.toml", LAYOUT);
    let none = run(&e, &["explain", "--width", "120"]);
    assert_eq!(none.status.code(), Some(0));
    e.put_config("config.toml", "colr = 1\n");
    let no_snapshot = run(&e, &["explain", "--width", "120"]);
    assert_eq!(
        no_snapshot.status.code(),
        Some(1),
        "nothing is published to explain"
    );
    e.put_config("config.toml", LAYOUT);
    assert_eq!(e.run(&["reload"]).status.code(), Some(0));
    e.put_config("config.toml", "colr = 1\n");
    let t = ok(&e, &["explain", "--width", "120"]);
    assert!(t.contains("your files have errors"), "{t}");
    assert!(t.contains("E201"), "{t}");
    let j = ok(&e, &["explain", "--width", "120", "--format", "json"]);
    assert!(j.contains("\"basis\":\"published-files-invalid\""), "{j}");
    assert!(j.contains("\"code\":\"E201\""), "{j}");
    schema(&[&j]);
}

// Without `--width`, explain decides at `COLUMNS` and says so in both forms; a missing or wrong
// value keeps 80 and the "assumed" note.
// 이것을 실패시키는 것: COLUMNS를 읽지 않는 것(40칸의 narrow 대신 80칸), text·JSON에서 출처를 빼거나 틀리게
// 적는 것, 스키마가 `columns`를 모르는 것, 0이나 숫자 아닌 COLUMNS를 폭으로 받는 것.
#[test]
fn without_width_explain_reads_columns() {
    let e = Env::new("cli_json", "columns");
    let file = e.put("layout.toml", LAYOUT);
    let shown = file.to_str().unwrap();
    let run = |columns: Option<&str>, json: bool| {
        let mut args = vec!["explain", "--config", shown];
        if json {
            args.extend(["--format", "json"]);
        }
        let mut c = e.cmd(&args);
        if let Some(v) = columns {
            c.env("COLUMNS", v);
        }
        let o = c.current_dir("/").output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{columns:?}: {}", text(&o.stderr));
        text(&o.stdout)
    };
    let t = run(Some("40"), false);
    assert!(t.contains("width: 40 cells (from COLUMNS)\n"), "{t}");
    assert!(t.contains("layout: band `narrow`\n"), "{t}");
    let j = run(Some("40"), true);
    assert!(j.contains("\"width\":40,\"width_source\":\"columns\""), "{j}");
    schema(&[&j]);
    for bad in [None, Some("0"), Some("wide")] {
        let t = run(bad, false);
        assert!(
            t.contains("width: 80 cells (assumed; give --width N)\n"),
            "{bad:?}: {t}"
        );
        let j = run(bad, true);
        assert!(
            j.contains("\"width\":80,\"width_source\":\"default\""),
            "{bad:?}: {j}"
        );
    }
}

// 이것을 실패시키는 것: 모르는 형식·중복·값 없는 `--format`을 받는 것.
#[test]
fn a_wrong_format_exits_2() {
    let e = Env::new("cli_json", "usage");
    for args in [
        vec!["explain", "--format", "xml"],
        vec!["explain", "--format"],
        vec!["explain", "--format", "json", "--format", "text"],
        vec!["config", "check", "--format", "yaml"],
        vec!["config", "check", "--format"],
        vec!["config", "check", "--format", "json", "--format", "json"],
        vec!["config", "path", "--format", "json"],
    ] {
        let o = run(&e, &args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
    }
}

// When the settings cannot be compiled, JSON mode still answers with one JSON document on stdout
// (`result: "invalid"`, the errors), and the exit code is the text mode's.
// 이것을 실패시키는 것: JSON 모드에서 컴파일 실패 때 stdout이 비는 것(사람용 글만 stderr로 나감), 종료 코드를 바꾸는 것,
// 설정을 읽지 못하는 경우(없는 파일)에 문서를 내지 않는 것.
#[test]
fn json_mode_answers_with_a_document_when_the_settings_fail() {
    let e = Env::new("cli_json", "failure");
    let bad = e.put("bad.toml", "version = 1\ncolr = 1\n");
    let o = run(
        &e,
        &[
            "explain",
            "--config",
            bad.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(quiet(&o.stderr), "");
    let doc = text(&o.stdout);
    assert!(
        doc.contains("\"result\":\"invalid\"") && doc.contains("\"code\":\"E201\""),
        "{doc}"
    );
    let missing = run(
        &e,
        &[
            "explain",
            "--config",
            "/nonexistent/none.toml",
            "--format",
            "json",
        ],
    );
    assert_eq!(missing.status.code(), Some(1));
    let gone = text(&missing.stdout);
    assert!(
        gone.contains("\"result\":\"invalid\"") && gone.contains("cannot open"),
        "{gone}"
    );
    // The settings folder itself unusable: config check answers the same way.
    user_env::chmod(&e.config_dir(), 0o777);
    let c = run(&e, &["config", "check", "--format", "json"]);
    let code = c.status.code();
    let unusable = text(&c.stdout);
    assert_ne!(code, Some(0), "{unusable}");
    assert!(
        unusable.contains("\"command\":\"config-check\""),
        "{unusable} {}",
        text(&c.stderr)
    );
    schema(&[&doc, &gone, &unusable]);
}

// A file with an error the report keeps a snapshot for (`match` that is not a regular expression) is an error
// basis in both formats, with the error listed.
// 이것을 실패시키는 것: 스냅샷이 유지되는 오류를 `published-files-changed`로 고르고 진단을 빼는 것(text도 오류를 빠뜨림).
#[test]
fn an_error_that_keeps_the_snapshot_is_still_an_error_basis() {
    let e = Env::new("cli_json", "kept");
    let good = "version = 1\n[segment.\"custom/c\"]\nkind = \"command\"\ncommand = [\"/bin/echo\", \"1\"]\n[layout.line2]\nleft = [\"custom/c\", \"char\"]\n";
    e.put_config("config.toml", good);
    assert_eq!(e.run(&["reload"]).status.code(), Some(0));
    let broken = good.replace(
        "command = [\"/bin/echo\", \"1\"]\n",
        "command = [\"/bin/echo\", \"1\"]\nmatch = \"[\"\n",
    );
    assert_ne!(broken, good);
    e.put_config("config.toml", &broken);
    let j = ok(&e, &["explain", "--width", "80", "--format", "json"]);
    assert!(j.contains("\"basis\":\"published-files-invalid\""), "{j}");
    assert!(j.contains("\"severity\":\"error\""), "{j}");
    let t = ok(&e, &["explain", "--width", "80"]);
    assert!(t.contains("your files have errors"), "{t}");
    assert!(t.contains("E203"), "{t}");
    schema(&[&j]);
}

// `config check --explain --format json` carries the builtin language outcomes the text section has.
// 이것을 실패시키는 것: JSON에서 내장 언어 판정을 빼는 것(`builtin_languages`가 null), text와 다른 판정을 내는 것.
#[test]
fn builtin_language_outcomes_are_in_the_json() {
    let e = Env::new("cli_json", "builtin");
    e.put_config("config.toml", "[layout.line2]\nleft = ['node','char']\n");
    let j = ok(&e, &["config", "check", "--explain", "--format", "json"]);
    let t = ok(&e, &["config", "check", "--explain"]);
    assert!(t.contains("node  not decided"), "{t}");
    assert!(
        j.contains("\"language\":\"node\",\"outcome\":\"not-decided\""),
        "{j}"
    );
    schema(&[&j]);
    let plain = ok(&e, &["config", "check", "--format", "json"]);
    assert!(plain.contains("\"builtin_languages\":null"), "{plain}");
}
