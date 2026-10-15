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

// include_str no longer passes in library files: it brings in a string from
// outside the source, which could be a format string with a pointer
// placeholder. Test targets (after --test-targets) still read shared tables
// with it. What makes this fail: matching any identifier starting with
// include in the include rule, or applying the format-source rule to test
// targets.
#[test]
fn include_str_passes_in_test_targets() {
    let lib = fixture("pub fn f() {}\n");
    let test = fixture("pub const X: &str = include_str!(\"x.txt\");\n");
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .arg(&lib)
        .arg("--test-targets")
        .arg(&test)
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success() && stderr.is_empty(), "{stderr}");
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

// 이것을 실패시키는 것: core가 주소를 값으로 바꾸는 길(Box::into_raw, as_ptr, 원시 포인터 타입, ptr 모듈, 매크로 안팎의 {:p},
// fill·정렬·플래그·폭·정밀도가 붙은 p 지정자, `{`·`}`를 fill로 쓴 지정자)을
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
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{v:#p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{v:20p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{v:}>20p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{v:<p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{v:>20p }\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(r\"{:.*p}\", 1, v)\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{}\", alloc::format!(\"{v:#p}\"))\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{0:+#020p}\", v)\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v:w$.w$p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v:-p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v:.3p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v :p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v:p }\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v:0w$p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{1:0$p}\", w, v)\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8, w: usize) -> alloc::string::String {\n    alloc::format!(\"{v:.p}\")\n}\n",
            "{:p}",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{{{v:p}\")\n}\n",
            "{:p}",
        ),
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
    // fill p (`{:p<5}` is Display), an escaped brace, Debug in hex, a fill `}`, a width argument named pw,
    // and template text that is not a std::fmt placeholder (style.rs).
    passes(
        "fn f(v: u8, pw: usize) -> alloc::string::String {\n    alloc::format!(\"{v:p<5}|{{:p}}|{v:x?}|{v:}<5}|{v:pw$}\")\n}\n\nconst T: &str = \"{@icon:frame.top}|{@x:p}|{x:frame.top}\";\n",
    );
    passes(
        "struct S;\n\n#[cfg(test)]\nimpl S {\n    fn t() {\n        let _ = [1u8].as_ptr();\n    }\n}\n",
    );
}

// 이것을 실패시키는 것: concat!·stringify!로 서식 문자열을 조각에서 만드는 길(이름 바꾼 use 포함)을 놓치는 것,
// 슬라이스 메서드 `.concat()`을 막는 것.
#[test]
fn format_strings_are_not_assembled() {
    fails_with(
        "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(concat!(\"{:\", \"p}\"), v)\n}\n",
        "concat builds a format string",
    );
    fails_with(
        "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(stringify!({:p}), v)\n}\n",
        "stringify builds a format string",
    );
    fails_with("use core::concat as c;\n", "concat builds a format string");
    passes("fn f(a: &[&[u8]]) -> alloc::vec::Vec<u8> {\n    a.concat()\n}\n");
}

// 이것을 실패시키는 것: 라이브러리에서 소스 밖 문자열을 들여오는 include_str!·include_bytes!·option_env!·env!를 놓치는 것
// (include_str!로 읽은 "{:p}"나 빌드 환경 변수가 서식 문자열이 됨), `const VERSION = env!("CARGO_PKG_VERSION")`를 막는 것,
// 그 한 자리 밖(다른 이름, 다른 변수, 서식 인자)의 env!를 허용하는 것.
#[test]
fn library_takes_no_string_from_outside() {
    for (bad, why) in [
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(include_str!(\"fmt.txt\"), v)\n}\n",
            "include_str brings a string in",
        ),
        (
            "fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(env!(\"FMTX\"), v)\n}\n",
            "env other than const VERSION",
        ),
        (
            "pub const B: &[u8] = include_bytes!(\"x.bin\");\n",
            "include_bytes brings a string in",
        ),
        (
            "pub const O: Option<&str> = option_env!(\"X\");\n",
            "option_env brings a string in",
        ),
        (
            "pub const V: &str = env!(\"CARGO_PKG_VERSION\");\n",
            "env other than const VERSION",
        ),
        (
            "pub const VERSION: &str = env!(\"HOME\");\n",
            "env other than const VERSION",
        ),
        (
            "pub const VERSION: &str = env!(\"CARGO_PKG_VERSION\");\nuse core::env as e;\n",
            "env other than const VERSION",
        ),
        (
            "pub const VERSION: &str = m!(\"CARGO_PKG_VERSION\");\nuse core::env as e;\n",
            "env other than const VERSION",
        ),
    ] {
        fails_with(bad, why);
    }
    passes("pub const VERSION: &str = env!(\"CARGO_PKG_VERSION\");\n");
}

/// Runs the checker on `source` saved as a crate root (`lib.rs`).
fn run_root(source: &str) -> (bool, String) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-cfg-check-{}-root{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("lib.rs");
    std::fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .arg(&path)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

// 이것을 실패시키는 것: crate root의 `#![no_std]`·`#![forbid(unsafe_code)]`를 글자로만 찾는 것(주석·문자열·모듈 안 속성이 통과),
// 둘 가운데 하나를 보지 않는 것, crate root가 아닌 파일에 요구하는 것.
#[test]
fn crate_root_keeps_no_std_and_forbid_unsafe() {
    let both = "#![no_std]\n#![forbid(unsafe_code)]\n";
    for (bad, why) in [
        (
            "/*\n#![no_std]\n*/\n#![forbid(unsafe_code)]\n",
            "lacks #![no_std]",
        ),
        (
            "#![forbid(unsafe_code)]\npub const S: &str = r\"\n#![no_std]\n\";\n",
            "lacks #![no_std]",
        ),
        (
            "#![forbid(unsafe_code)]\nmod m {\n    #![no_std]\n}\n",
            "lacks #![no_std]",
        ),
        ("#![no_std]\n", "lacks #![forbid(unsafe_code)]"),
        (
            "#![no_std]\n// #![forbid(unsafe_code)]\n",
            "lacks #![forbid(unsafe_code)]",
        ),
        (
            "#![no_std]\n#![forbid(unused)]\n",
            "lacks #![forbid(unsafe_code)]",
        ),
        (
            "#![no_std]\n#![deny(unsafe_code)]\n",
            "lacks #![forbid(unsafe_code)]",
        ),
    ] {
        let (ok, err) = run_root(bad);
        assert!(!ok && err.contains(why), "{bad}: {err}");
    }
    let (ok, err) = run_root(both);
    assert!(ok && err.is_empty(), "{err}");
    passes("pub fn f() {}\n");
}

// 이것을 실패시키는 것: 함수 주소를 값으로 바꾸는 길(같은 파일 함수의 정수 cast, 함수 포인터 타입)과 매크로 본문 안의
// 주소 API(into_raw, as_ptr_range, UnsafeCell, *const, ptr::, fn() 타입)를 놓치는 것, 시험 항목 안의 매크로까지 막는 것,
// 함수 이름이 아닌 값의 정수 cast를 막는 것.
#[test]
fn function_and_macro_addresses_fail() {
    for (bad, why) in [
        (
            "fn marker() {}\npub fn address() -> usize {\n    marker as usize\n}\n",
            "casting function marker",
        ),
        (
            "fn marker() {}\npub fn address() -> usize {\n    (marker) as usize\n}\n",
            "casting function marker",
        ),
        (
            "fn marker() {}\npub fn s() -> alloc::string::String {\n    alloc::format!(\"{:x}\", marker as usize)\n}\n",
            "casting function marker",
        ),
        (
            "pub fn f(v: &[u8]) -> usize {\n    v.as_ptr_range().start as usize\n}\n",
            "as_ptr_range exposes",
        ),
        (
            "pub fn f(v: &[u8]) -> alloc::string::String {\n    alloc::format!(\"{:?}\", v.as_ptr_range())\n}\n",
            "as_ptr_range exposes",
        ),
        (
            "pub fn f(v: &mut [u8]) -> usize {\n    v.as_mut_ptr_range().start as usize\n}\n",
            "as_mut_ptr_range exposes",
        ),
        (
            "fn fn_address() -> usize {\n    0\n}\npub fn f() -> usize {\n    fn_address as fn() -> usize as usize\n}\n",
            "function pointer type",
        ),
        (
            "pub fn f() -> alloc::string::String {\n    let f: fn() -> usize = || 0;\n    alloc::format!(\"{f:?}\")\n}\n",
            "function pointer type",
        ),
        (
            "pub fn f(b: alloc::boxed::Box<u8>) -> alloc::string::String {\n    alloc::format!(\"{}\", alloc::boxed::Box::into_raw(b) as usize)\n}\n",
            "into_raw exposes",
        ),
        (
            "pub fn f() -> usize {\n    core::cell::UnsafeCell::new(0u8).get() as usize\n}\n",
            "UnsafeCell exposes",
        ),
        (
            "pub fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{}\", v as *const u8 as usize)\n}\n",
            "raw pointer type",
        ),
        (
            "pub fn f(v: &mut u8) -> alloc::string::String {\n    alloc::format!(\"{}\", v as *mut u8 as usize)\n}\n",
            "raw pointer type",
        ),
        (
            "pub fn f(v: &u8) -> alloc::string::String {\n    alloc::format!(\"{}\", core::ptr::from_ref(v).addr())\n}\n",
            "core::ptr other than ptr::eq",
        ),
        ("m!(use core::ptr);\n", "core::ptr other than ptr::eq"),
        (
            "pub fn f() -> alloc::string::String {\n    alloc::format!(\"{:?}\", ptr::null::<u8>())\n}\n",
            "core::ptr other than ptr::eq",
        ),
        (
            "pub fn f() -> alloc::string::String {\n    alloc::format!(\"{:?}\", (|| 0) as fn() -> u8)\n}\n",
            "function pointer type",
        ),
    ] {
        fails_with(bad, why);
    }
    passes(
        "fn marker() -> u8 {\n    1\n}\npub fn f(a: &u8, b: &u8, n: u8, ptr: u8) -> alloc::string::String {\n    alloc::format!(\"{} {} {} {}\", core::ptr::eq(a, b), n as usize, ptr, marker())\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let _ = alloc::format!(\"{:?}\", [1u8].as_ptr_range());\n    }\n}\n",
    );
}

// 이것을 실패시키는 것: atomic이나 static 없이 호출 사이 상태를 두는 이름(forget, ManuallyDrop, Arc, strong_count, weak_count)을
// 놓치는 것, 주석 속 낱말을 막는 것.
#[test]
fn hidden_state_fails() {
    for (bad, name) in [
        (
            "pub fn f() {\n    core::mem::forget(alloc::boxed::Box::new(1u8));\n}\n",
            "forget",
        ),
        (
            "pub fn f() -> core::mem::ManuallyDrop<u8> {\n    core::mem::ManuallyDrop::new(1)\n}\n",
            "ManuallyDrop",
        ),
        ("use alloc::sync::Arc;\n", "Arc"),
        (
            "pub fn f(r: &alloc::rc::Rc<u8>) -> usize {\n    alloc::rc::Rc::strong_count(r)\n}\n",
            "strong_count",
        ),
        (
            "pub fn f(r: &alloc::rc::Rc<u8>) -> usize {\n    alloc::rc::Rc::weak_count(r)\n}\n",
            "weak_count",
        ),
    ] {
        fails_with(bad, &format!("{name} keeps state between calls"));
    }
    passes("/// Starts a new call: forget earlier records.\npub fn f() {}\n");
}
