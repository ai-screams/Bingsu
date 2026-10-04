//! Runs the checker binary on small fixture files. Each failing fixture checks
//! the specific reason on stderr, not only the exit code, because some inputs
//! trip more than one rule and the exit code alone would hide a removed rule.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn fixture(source: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-cfg-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("f{n}.rs"));
    std::fs::write(&path, source).unwrap();
    path
}

fn run(source: &str) -> (bool, String) {
    let path = fixture(source);
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .arg(&path)
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    (output.status.success(), stderr)
}

fn passes(source: &str) {
    let (ok, stderr) = run(source);
    assert!(ok, "expected pass for {source:?}, stderr: {stderr}");
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
}

fn fails_with(source: &str, reason: &str) {
    let (ok, stderr) = run(source);
    assert!(!ok, "expected failure for {source:?}");
    assert!(
        stderr.contains(reason),
        "expected {reason:?} for {source:?}, stderr: {stderr}"
    );
}

// What makes these fail: counting cfg tokens without matching #[cfg(test)]
// attributes (allowed_cfg += 1 removed), or treating comments and strings as
// tokens.
#[test]
fn cfg_test_module_passes() {
    passes("#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n");
}

// What makes this fail: matching any identifier starting with include.
#[test]
fn include_str_passes() {
    passes("pub const X: &str = include_str!(\"x.txt\");\n");
}

// What makes this fail: scanning comment text instead of tokens.
#[test]
fn cfg_in_doc_comment_passes() {
    passes("/// doc mentions cfg and cfg_attr and include!(x)\npub fn f() {}\n");
}

// What makes this fail: scanning string contents instead of tokens.
#[test]
fn cfg_in_string_passes() {
    passes("pub const S: &str = \"cfg cfg_attr #[path = x] include!(y) /*\";\n");
}

// rustc treats #[r#cfg(test)] as #[cfg(test)]. What makes this fail: dropping
// unraw in either the token count or the attribute check (the two counts then
// disagree).
#[test]
fn raw_cfg_test_passes() {
    passes("#[r#cfg(test)]\nmod tests {}\n");
}

// What makes this fail: removing the include check in scan_tokens.
#[test]
fn spaced_include_fails() {
    fails_with("include ! (\"x.rs\");\n", "include! pulls in code");
}

// What makes this fail: removing unraw from the include check.
#[test]
fn raw_include_fails() {
    fails_with("r#include!(\"x.rs\");\n", "include! pulls in code");
}

// What makes these fail: removing the path check in visit_attribute.
#[test]
fn path_attribute_split_across_lines_fails() {
    fails_with("#\n[path = \"x.rs\"] mod m;\n", "#[path] pulls in code");
}

#[test]
fn path_attribute_with_comment_fails() {
    fails_with("#/*c*/[path = \"x.rs\"] mod m;\n", "#[path] pulls in code");
}

// rustc accepts #[r#path = ..]. What makes this fail: comparing the attribute
// name without unraw.
#[test]
fn raw_path_attribute_fails() {
    fails_with("#[r#path = \"x.rs\"] mod m;\n", "#[path] pulls in code");
}

// What makes this fail: removing the cfg_attr check in scan_tokens.
#[test]
fn cfg_attr_fails() {
    fails_with(
        "#[cfg_attr(test, allow(dead_code))]\npub fn f() {}\n",
        "cfg_attr",
    );
}

// What makes these fail: removing the "cfg other than #[cfg(test)]" branch.
#[test]
fn cfg_not_clippy_fails() {
    fails_with(
        "#[cfg(not(clippy))]\nfn f() {}\n",
        "cfg other than #[cfg(test)]",
    );
}

#[test]
fn cfg_all_test_fails() {
    fails_with(
        "#[cfg(all(test))]\nmod tests {}\n",
        "cfg other than #[cfg(test)]",
    );
}

#[test]
fn raw_cfg_other_fails() {
    fails_with(
        "#[r#cfg(not(test))]\nfn f() {}\n",
        "cfg other than #[cfg(test)]",
    );
}

// What makes these fail: removing the cfg_count != allowed_cfg check (the
// attribute visitor does not enter macro bodies or see cfg!()).
#[test]
fn cfg_inside_macro_body_fails() {
    fails_with(
        "macro_rules! m { () => { #[cfg(not(clippy))] fn f() {} } }\nm!();\n",
        "cfg token outside #[cfg(test)] attribute",
    );
}

#[test]
fn cfg_macro_fails() {
    fails_with(
        "pub fn f() { if cfg!(windows) {} }\n",
        "cfg token outside #[cfg(test)] attribute",
    );
}

// Balanced delimiters, so it lexes but does not parse. What makes this
// fail: ignoring a syn::parse_file error (an empty tree then passes).
#[test]
fn unparsable_source_fails() {
    fails_with("pub fn f() -> {}\n", "unparsable");
}

// Unbalanced delimiters fail both the parser and the lexer.
#[test]
fn unlexable_source_fails() {
    fails_with("fn f( {\n", "unparsable");
}

// What makes this fail: removing the empty-argument check in main.
#[test]
fn no_files_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no files")
    );
}

// What makes this fail: stopping at the first failing file, or letting a
// later passing file reset the result.
#[test]
fn failure_in_any_file_fails() {
    let bad = fixture("#[cfg(windows)]\nfn f() {}\n");
    let good = fixture("pub fn g() {}\n");
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .arg(&bad)
        .arg(&good)
        .output()
        .unwrap();
    assert!(!output.status.success());
}
