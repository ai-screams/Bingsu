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

// What makes these fail: removing the include check in scan_tokens.
#[test]
fn spaced_include_fails() {
    fails_with("include ! (\"x.rs\");\n", "include pulls in code");
}

// rustc accepts `use core::include as inc; inc!("x.rs");` and pulls the file
// in. What also makes this fail: requiring `!` after `include`.
#[test]
fn renamed_include_fails() {
    fails_with(
        "use core::include as inc;\ninc!(\"x.rs\");\n",
        "include pulls in code",
    );
}

// `m!(include)` hands the name to a macro that calls `$i!(..)`. What also
// makes this fail: requiring `!` after `include`.
#[test]
fn include_as_macro_argument_fails() {
    fails_with("m!(include);\n", "include pulls in code");
}

// What makes this fail: removing unraw from the include check.
#[test]
fn raw_include_fails() {
    fails_with("r#include!(\"x.rs\");\n", "include pulls in code");
}

// What makes these fail: removing the macro_rules check in scan_tokens.
#[test]
fn macro_rules_fails() {
    fails_with(
        "macro_rules! m {\n    () => {};\n}\n",
        "macro_rules forbidden in core",
    );
}

// rustc accepts this and pulls outside.rs in through `#[$i = ..]`; the
// substituted name never appears next to `#`, so only the macro_rules rule
// stops it.
#[test]
fn path_through_macro_argument_fails() {
    fails_with(
        "macro_rules! m { ($i:ident) => { #[$i = \"x.rs\"] mod o; } }\nm!(path);\n",
        "macro_rules forbidden in core",
    );
}

// What makes this fail: removing unraw from the macro_rules check.
#[test]
fn raw_macro_rules_fails() {
    fails_with(
        "r#macro_rules! m {\n    () => {};\n}\n",
        "macro_rules forbidden in core",
    );
}

// Both path rules report these. What makes them fail: removing the token
// rule (scan_tokens, "#[path] tokens") or the attribute rule
// (visit_attribute, "path attribute").
#[test]
fn path_attribute_split_across_lines_fails() {
    let source = "#\n[path = \"x.rs\"] mod m;\n";
    fails_with(source, "#[path] tokens pull in code");
    fails_with(source, "path attribute pulls in code");
}

#[test]
fn path_attribute_with_comment_fails() {
    let source = "#/*c*/[path = \"x.rs\"] mod m;\n";
    fails_with(source, "#[path] tokens pull in code");
    fails_with(source, "path attribute pulls in code");
}

// rustc accepts #[r#path = ..]. What makes this fail: comparing either path
// rule's name without unraw.
#[test]
fn raw_path_attribute_fails() {
    let source = "#[r#path = \"x.rs\"] mod m;\n";
    fails_with(source, "#[path] tokens pull in code");
    fails_with(source, "path attribute pulls in code");
}

// The parser does not look inside macro calls. What makes this fail:
// removing the token rule, or not descending into groups.
#[test]
fn path_tokens_inside_macro_call_fail() {
    fails_with(
        "m! { #[path = \"x.rs\"] mod o; }\n",
        "#[path] tokens pull in code",
    );
}

// What makes this fail: not skipping the `!` of an inner attribute.
#[test]
fn inner_path_tokens_inside_macro_call_fail() {
    fails_with(
        "m! { #![path = \"x.rs\"] }\n",
        "#[path] tokens pull in code",
    );
}

// Only a `[...]` group makes an attribute. What makes this fail: dropping
// the delimiter check in is_path_attr_group.
#[test]
fn path_in_parenthesized_group_after_hash_passes() {
    passes("m! { # (path) }\n");
}

// Only the first token of the `[...]` group counts. What makes this fail:
// treating any `path` identifier as the attribute.
#[test]
fn path_as_field_name_passes() {
    passes("#[derive(Debug)]\npub struct S {\n    pub path: u8,\n}\n");
}

// What makes this fail: removing the `feature` branch in AttrCheck.
#[test]
fn feature_attribute_fails() {
    fails_with("#![feature(f16)]\npub fn f() {}\n", "feature attribute");
}

// What makes this fail: matching the word `feature` anywhere instead of the
// attribute name.
#[test]
fn feature_as_identifier_passes() {
    passes("pub fn f() -> u8 {\n    let feature = 1;\n    feature\n}\n");
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
// attribute visitor does not enter macro calls or see cfg!()).
#[test]
fn cfg_inside_macro_call_fails() {
    fails_with(
        "m! { #[cfg(not(clippy))] fn f() {} }\n",
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

// What makes this fail: removing the shebang policy in check.
#[test]
fn shebang_fails() {
    fails_with(
        "#!/usr/bin/env rust\npub fn f() {}\n",
        "shebang in core source",
    );
}

// rustc drops the first line and compiles the rest. If the lexer got the
// original text, `/*` would hide everything up to `// */` from the token
// scan; the parser does not look into the macro. So this checks both rules
// on their own. What makes the second assertion fail: lexing the original
// text instead of the text syn parsed (the body/shebang cut in check).
#[test]
fn shebang_hiding_macro_rules_fails() {
    let source = "#!x /*\nmacro_rules! m { ($i:ident) => { #[$i(not(clippy))] pub fn leak() -> Vec<u8> { std::fs::read(\"/etc/hosts\").unwrap() } } } m!(cfg);\n// */\n";
    fails_with(source, "shebang in core source");
    fails_with(source, "macro_rules forbidden in core");
}

// rustc does not treat U+3000 as whitespace, so it drops this first line as
// a shebang; syn does, so it parses an inner attribute whose raw string
// hides line 2. Only the literal `#![` rule stops it. What makes this fail:
// relaxing the policy to skip whitespace before `[`.
#[test]
fn ideographic_space_shebang_fails() {
    fails_with(
        "#!\u{3000}[doc = r\"\nmacro_rules! m { () => {} }\n// \"]\n",
        "shebang in core source",
    );
}

// What makes this fail: rejecting every first line that starts with `#!`.
#[test]
fn inner_attribute_at_start_passes() {
    passes("#![allow(dead_code)]\npub fn f() {}\n");
}

// What makes this fail: applying the shebang policy before removing the BOM
// (or not removing it).
#[test]
fn bom_then_shebang_fails() {
    fails_with("\u{feff}#!x\npub fn f() {}\n", "shebang in core source");
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

// 이것을 실패시키는 것: `extern crate std`를 놓치는 것(no_std core에 std가 돌아옴), 이름 바꾼 것(`as`)을 놓치는 것,
// 세 낱말 가운데 `extern`이나 `crate`를 보지 않아 다른 자리의 `std`를 막는 것.
#[test]
fn extern_crate_std_fails() {
    for bad in [
        "extern crate std;\n",
        "extern crate std as s;\n",
        "extern crate r#std;\n",
    ] {
        let (ok, err) = run(bad);
        assert!(!ok && err.contains("extern crate std"), "{bad}: {err}");
    }
    passes("extern crate alloc;\n");
    passes("extern fn std() {}\n");
    passes("m!(a crate std);\n");
}

// 이것을 실패시키는 것: core에 호출 사이 상태를 둘 static·atomic을 놓치는 것(`atomic` 모듈 이름과 `Atomic…` 타입 이름 각각),
// `'static` 수명을 static 항목으로 잘못 세는 것, `atomic`으로 시작하는 다른 이름을 막는 것.
#[test]
fn core_keeps_no_state() {
    fails_with("static N: u8 = 0;\n", "static item");
    fails_with("fn f() {\n    static N: u8 = 0;\n}\n", "static item");
    fails_with("use core::sync::atomic::AtomicU8;\n", "atomics");
    fails_with("fn f(x: &core::sync::atomic::AtomicBool) {}\n", "atomics");
    fails_with("use core::sync::atomic;\n", "atomics");
    fails_with("fn f(x: &AtomicBool) {}\n", "atomics");
    passes(
        "fn f(x: &'static str) -> &'static str {\n    x\n}\nconst C: u8 = 1;\nfn atomically() {}\n",
    );
}

// 이것을 실패시키는 것: core가 주소를 값으로 바꾸는 길(Box::into_raw, as_ptr, 원시 포인터 타입, ptr 모듈, 매크로 안팎의 {:p})을
// 놓치는 것, `cfg(test)`가 아닌 속성이나 `cfg(test)`가 아닌 cfg를 시험 항목으로 보는 것,
// ptr::eq와 시험 안(모듈·함수·impl)의 as_ptr를 막는 것.
#[test]
fn core_exposes_no_address() {
    for (bad, why) in [
        (
            "fn f() -> usize {\n    alloc::boxed::Box::into_raw(alloc::boxed::Box::new(1u8)) as usize\n}\n",
            "into_raw",
        ),
        (
            "fn f(v: &[u8]) -> usize {\n    v.as_ptr() as usize\n}\n",
            "as_ptr",
        ),
        (
            "fn f(v: &u8) -> usize {\n    v as *const u8 as usize\n}\n",
            "raw pointer",
        ),
        (
            "fn f(v: &u8) -> usize {\n    core::ptr::from_ref(v).addr()\n}\n",
            "core::ptr",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{v:p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: alloc::boxed::Box<u8>) -> &'static u8 {\n    alloc::boxed::Box::leak(v)\n}\n",
            "leak",
        ),
        ("const F: &str = \"{:p}\";\n", "{:p}"),
        (
            "#[allow(test)]\nfn f(v: &[u8]) -> usize {\n    v.as_ptr() as usize\n}\n",
            "as_ptr",
        ),
        (
            "#[cfg(not(test))]\nfn f(v: &[u8]) -> usize {\n    v.as_ptr() as usize\n}\n",
            "as_ptr",
        ),
    ] {
        fails_with(bad, why);
    }
    passes(
        "fn f(a: &u8, b: &u8) -> bool {\n    core::ptr::eq(a, b)\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let v = [1u8];\n        let _ = v.as_ptr();\n    }\n}\n",
    );
    passes("#[cfg(test)]\nfn t() {\n    let _ = [1u8].as_ptr();\n}\n");
    passes(
        "struct S;\n\n#[cfg(test)]\nimpl S {\n    fn t() {\n        let _ = [1u8].as_ptr();\n    }\n}\n",
    );
}
