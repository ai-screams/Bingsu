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
        "fn f(a: &u8, b: &u8) -> bool {\n    a == b\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let v = [1u8];\n        let _ = v.as_ptr();\n    }\n}\n",
    );
    passes("#[cfg(test)]\nfn t() {\n    let _ = [1u8].as_ptr();\n}\n");
    // fill p (`{:p<5}` is Display), an escaped brace, hex, a fill `}`, a width argument named pw,
    // and template text that is not a std::fmt placeholder (style.rs).
    passes(
        "fn f(v: u8, pw: usize) -> alloc::string::String {\n    alloc::format!(\"{v:p<5}|{{:p}}|{v:x}|{v:}<5}|{v:pw$}\")\n}\n\nconst T: &str = \"{@icon:frame.top}|{@x:p}|{x:frame.top}\";\n",
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
            "core::ptr exposes an address",
        ),
        ("m!(use core::ptr);\n", "core::ptr exposes an address"),
        (
            "pub fn f() -> alloc::string::String {\n    alloc::format!(\"{:?}\", ptr::null::<u8>())\n}\n",
            "core::ptr exposes an address",
        ),
        (
            "pub fn f() -> alloc::string::String {\n    alloc::format!(\"{:?}\", (|| 0) as fn() -> u8)\n}\n",
            "function pointer type",
        ),
    ] {
        fails_with(bad, why);
    }
    passes(
        "fn marker() -> u8 {\n    1\n}\npub fn f(a: &u8, b: &u8, n: u8, ptr: u8) -> alloc::string::String {\n    alloc::format!(\"{} {} {} {}\", a == b, n as usize, ptr, marker())\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let _ = alloc::format!(\"{:?}\", [1u8].as_ptr_range());\n    }\n}\n",
    );
}

// 이것을 실패시키는 것: atomic이나 static 없이 호출 사이 상태를 두는 이름(forget, ManuallyDrop, MaybeUninit, Arc, strong_count, weak_count)을
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
            "pub fn leak() {\n    let _leak = core::mem::MaybeUninit::new(alloc::boxed::Box::new(1u8));\n}\n",
            "MaybeUninit",
        ),
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

// 이것을 실패시키는 것: production 코드의 Debug 서식(`{:?}`, `{:#?}`, `{:x?}`)과 Debug·Hash 이름(trait, derive(Hash), 메서드 hash,
// debug 빌더)을 놓치는 것(Waker·Context의 vtable, 함수 포인터의 주소가 나감), `#[derive(Debug)]`를 막는 것,
// `#[cfg(test)]` 항목을 production으로 세거나 첫 시험 항목 뒤를 모두 시험으로 보는 것, 시험 target 파일에 이 규칙을 거는 것.
#[test]
fn debug_and_hash_stay_out_of_production() {
    let hasher = "struct H(u64);\nimpl core::hash::Hasher for H {\n    fn finish(&self) -> u64 {\n        self.0\n    }\n    fn write(&mut self, _: &[u8]) {}\n    fn write_usize(&mut self, n: usize) {\n        self.0 = n as u64;\n    }\n}\nfn a() {}\nfn b() {}\npub fn f() -> u64 {\n    let fs = [a, b];\n    let mut h = H(0);\n    core::hash::Hash::hash(&fs, &mut h);\n    h.0\n}\n";
    for (bad, why) in [
        (
            "pub fn address() -> alloc::string::String {\n    alloc::format!(\"{:?}\", core::task::Waker::noop())\n}\n",
            "{:?} may write",
        ),
        (
            "pub fn f(c: &core::task::Context<'_>) -> alloc::string::String {\n    alloc::format!(\"{c:#?}\")\n}\n",
            "{:?} may write",
        ),
        (
            "pub fn f(v: u8) -> alloc::string::String {\n    alloc::format!(\"{v:x?}\")\n}\n",
            "{:?} may write",
        ),
        (
            "fn a() {}\nfn b() {}\npub fn f() -> alloc::string::String {\n    let fs = [a, b];\n    alloc::format!(\"{fs:?}\")\n}\n",
            "{:?} may write",
        ),
        (hasher, "Hasher may write"),
        ("#[derive(Clone, Hash)]\npub struct S;\n", "Hash may write"),
        ("#[derive(Debug, Hash)]\npub struct S;\n", "Hash may write"),
        (
            "pub struct S;\nimpl core::fmt::Debug for S {\n    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {\n        f.write_str(\"S\")\n    }\n}\n",
            "Debug may write",
        ),
        ("#[allow(Debug)]\npub fn f() {}\n", "Debug may write"),
        ("m!(derive(Debug));\n", "Debug may write"),
        (
            "#[cfg(test)]\nfn t() {}\n\npub fn f() -> alloc::string::String {\n    alloc::format!(\"{:?}\", 1)\n}\n",
            "{:?} may write",
        ),
        (
            "#[cfg(test)]\nmod tests {}\n\npub struct S;\nimpl S {\n    #[cfg(test)]\n    fn t() {}\n    pub fn f() -> alloc::string::String {\n        alloc::format!(\"{:?}\", 1)\n    }\n}\n",
            "{:?} may write",
        ),
    ] {
        fails_with(bad, why);
    }
    for name in [
        "Debug",
        "debug_struct",
        "debug_tuple",
        "debug_list",
        "debug_map",
        "debug_set",
        "Hash",
        "Hasher",
        "BuildHasher",
        "hash",
    ] {
        fails_with(
            &format!("pub fn f() {{\n    {name}();\n}}\n"),
            &format!("{name} may write"),
        );
    }
    passes(
        "#[derive(Debug, Clone)]\npub struct S;\n\npub fn f(v: u8) -> alloc::string::String {\n    alloc::format!(\"{v} {v:x} {{:?}}\")\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let _ = alloc::format!(\"{:?}\", 1);\n    }\n}\n\npub struct T;\nimpl T {\n    #[cfg(test)]\n    fn t() -> alloc::string::String {\n        alloc::format!(\"{:#?}\", 1)\n    }\n}\n\npub trait U {\n    #[cfg(test)]\n    fn u() -> alloc::string::String {\n        alloc::format!(\"{:?}\", 1)\n    }\n}\n\n#[cfg(test)]\nconst C: &str = \"{:?}\";\n\n#[cfg(test)]\nfn tf() -> alloc::string::String {\n    alloc::format!(\"{:?}\", 1)\n}\n",
    );
    // Every kind of item, impl item and trait item under #[cfg(test)] (static items are refused anywhere).
    passes(
        "#[cfg(test)]\n#[derive(Debug, Hash)]\nenum E {}\n#[cfg(test)]\n#[derive(Hash)]\nstruct S;\n#[cfg(test)]\n#[derive(Hash)]\nunion U {\n    a: u8,\n}\n#[cfg(test)]\nuse core::hash::Hash;\n#[cfg(test)]\nextern crate hash;\n#[cfg(test)]\ntype T = dyn core::hash::Hasher;\n#[cfg(test)]\ntrait Tr: core::fmt::Debug {}\n#[cfg(test)]\ntrait Ta = core::hash::Hash;\n#[cfg(test)]\nimpl core::fmt::Debug for X {}\n#[cfg(test)]\nm!(Debug);\n#[cfg(test)]\nunsafe extern \"C\" {\n    fn hash();\n}\npub struct X;\nimpl X {\n    #[cfg(test)]\n    const C: &str = \"{:?}\";\n    #[cfg(test)]\n    type T = dyn core::hash::Hasher;\n    #[cfg(test)]\n    m!(Debug);\n}\npub trait Y {\n    #[cfg(test)]\n    const C: &str = \"{:?}\";\n    #[cfg(test)]\n    type T: core::hash::Hash;\n    #[cfg(test)]\n    m!(Debug);\n}\n",
    );
    let lib = fixture("pub fn f() {}\n");
    let test =
        fixture("pub fn f() -> alloc::string::String {\n    alloc::format!(\"{:?}\", 1)\n}\n");
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .arg(&lib)
        .arg("--test-targets")
        .arg(&test)
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success() && stderr.is_empty(), "{stderr}");
}

const MAIN: &str = "fn main() -> std::process::ExitCode {\n    commands::run(prompt::dispatch(sandbox::enter))\n}\n";

/// Writes `files` (name, source) into a fresh folder and runs --binary on
/// all of them.
fn run_binary_files(files: &[(&str, &str)]) -> (bool, String) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-cfg-check-{}-bin{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"));
    c.arg("--binary");
    for (name, source) in files {
        let path = dir.join(name);
        std::fs::write(&path, source).unwrap();
        c.arg(path);
    }
    let output = c.output().unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn run_binary(extra: &str) -> (bool, String) {
    run_binary_files(&[("main.rs", &format!("{extra}{MAIN}"))])
}

// 이것을 실패시키는 것: --binary가 전역 allocator·링커 constructor·global_asm 식별자를 놓치는 것, cfg를 쓰는 바이너리 코드를 거부하는 것.
#[test]
fn binary_mode() {
    let (ok, err) = run_binary("#[cfg(unix)]\nmod m {}\n");
    assert!(ok, "{err}");
    for bad in [
        "#[global_allocator]\nstatic A: std::alloc::System = std::alloc::System;\n",
        "#[unsafe(link_section = \".init_array\")]\nstatic F: fn() = f;\nfn f() {}\n",
        "#[ctor::ctor]\nfn f() {}\n",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn f() {}\n",
        "std::arch::global_asm!(\"\");\n",
    ] {
        let (ok, err) = run_binary(bad);
        assert!(
            !ok && err.contains("runs code outside main"),
            "{bad}: {err}"
        );
    }
}

// Native fixture paths use backslashes on Windows. Both line endings must
// pass, while a different basename or dispatch target must still fail.
#[test]
fn binary_main_paths_and_line_endings() {
    let main = MAIN.replace(
        "commands::run(prompt::dispatch(sandbox::enter))",
        "commands::run(\n        prompt::dispatch(sandbox::enter)\n    )",
    );
    for source in [&main, &main.replace('\n', "\r\n")] {
        let (ok, err) = run_binary_files(&[("main.rs", source)]);
        assert!(ok && err.is_empty(), "{source:?}: {err}");

        for name in ["not-main.rs", "main.rs.bak"] {
            let (ok, err) = run_binary_files(&[(name, source)]);
            assert!(!ok && err.contains("fn main"), "{name}: {err}");
        }

        let bad = source.replace("sandbox::enter", "other::enter");
        let (ok, err) = run_binary_files(&[("main.rs", &bad)]);
        assert!(!ok && err.contains("fn main"), "{bad:?}: {err}");
    }
}

// 이것을 실패시키는 것: main이 dispatch 앞에서 다른 일을 하는 것, main이 둘(decoy)인 것, main.rs 밖이나 모듈 안의 main을 받는 것.
#[test]
fn main_only_dispatches() {
    for files in [
        vec![(
            "main.rs",
            "fn main() -> std::process::ExitCode {\n    let _ = std::fs::read(\"x\");\n    commands::run(prompt::dispatch(sandbox::enter))\n}\n",
        )],
        vec![(
            "main.rs",
            "fn main() -> std::process::ExitCode {\n    commands::run(prompt::dispatch(other::enter))\n}\n",
        )],
        vec![
            ("main.rs", MAIN),
            ("other.rs", "mod m {\n    fn main() {}\n}\n"),
        ],
        vec![(
            "main.rs",
            "const DECOY: &str = \"commands::run(prompt::dispatch(sandbox::enter))\";\nfn main() {\n    commands::run(x())\n}\n",
        )],
        vec![("main.rs", &format!("#[inline(never)]\n{MAIN}"))],
        vec![("lib.rs", MAIN)],
        vec![(
            "main.rs",
            "mod m {\n    fn main() -> std::process::ExitCode {\n        commands::run(prompt::dispatch(sandbox::enter))\n    }\n}\n",
        )],
    ] {
        let (ok, err) = run_binary_files(&files);
        assert!(!ok && err.contains("fn main"), "{files:?}: {err}");
    }
}

const TSV: &str =
    "# c\nsyscall\tlibc\twhy\nwrite\twrite\tx\nexit_group\t_exit\tx\n-\tEINTR\tx\nbrk\t-\tx\n";
const ADAPTER_OK: &str = "use bingsu_core::front;\nuse std::ffi::OsString;\n\nfn w(b: &[u8]) {\n    let n = unsafe { libc::write(1, b.as_ptr().cast(), b.len()) };\n    if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {}\n}\n\nfn e() -> ! {\n    unsafe { libc::_exit(0) }\n}\n\npub fn run(a: &[OsString]) -> ! {\n    let _ = front::respond(&[]);\n    let _ = a;\n    w(b\"\");\n    e()\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t() {\n        let _ = std::fs::read(\"x\");\n        assert!(true);\n    }\n}\n";

fn run_adapter(source: &str) -> (bool, String) {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-cfg-check-{}-ad{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("t.tsv"), TSV).unwrap();
    std::fs::write(dir.join("p.rs"), source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .arg("--adapter")
        .arg(dir.join("t.tsv"))
        .arg(dir.join("p.rs"))
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

// 이것을 실패시키는 것: 어댑터 검사가 경로를 철자로만 보는 것(별칭·group·super·중간 cfg(test)·extern 주석·asm 별칭·global_asm),
// 목록과 사용이 같지 않은데 통과하는 것.
#[test]
fn adapter_mode() {
    let (ok, err) = run_adapter(ADAPTER_OK);
    assert!(ok, "{err}");
    let add = |item: &str| ADAPTER_OK.replace("pub fn run", &format!("{item}\n\npub fn run"));
    for (bad, why) in [
        (
            add("fn g() {\n    use libc::{getenv as g};\n    unsafe { g(c\"H\".as_ptr()) };\n}"),
            "group use",
        ),
        (add("use libc::getenv as g;"), "renaming use"),
        (
            add("fn g() {\n    unsafe { libc::getenv(c\"H\".as_ptr()) };\n}"),
            "not a row",
        ),
        (
            add("fn g() {\n    let _ = super::sys::current_uid();\n}"),
            "another module",
        ),
        (
            add("fn g() {\n    let _ = crate::commands::run;\n}"),
            "another module",
        ),
        (
            add("#[cfg(test)]\nfn t() {}\n\nfn g() {\n    let _ = std::fs::read(\"x\");\n}"),
            "cfg outside",
        ),
        (
            add("fn g() {\n    let _ = std::fs::read(\"x\");\n}"),
            "not in STD_ALLOWED",
        ),
        (
            add("unsafe extern/**/\"C\" {\n    fn getenv(n: *const i8) -> *const i8;\n}"),
            "other than use",
        ),
        (
            add("fn g() {\n    use std::arch::asm as a;\n    unsafe { a!(\"nop\") };\n}"),
            "renaming use",
        ),
        (
            add("fn g() {\n    unsafe { std::arch::asm!(\"nop\") };\n}"),
            "a macro call",
        ),
        (add("std::arch::global_asm!(\"\");"), "other than use"),
        (add("static N: u8 = 0;"), "other than use"),
        (add("mod m;"), "other than use"),
        (add("use std as s;"), "renaming use"),
        (add("use std::*;"), "glob use"),
        (add("extern \"C\" fn g() {}"), "extern fn"),
        (
            add("fn g() {\n    let _ = bingsu_core::record::write_minimal_b1;\n}"),
            "only bingsu_core::front",
        ),
        (
            ADAPTER_OK.replace("unsafe { libc::_exit(0) }", "loop {}"),
            "listed but unused",
        ),
    ] {
        let (ok, err) = run_adapter(&bad);
        assert!(!ok && err.contains(why), "{why}: {bad}\n{err}");
    }
}

// 이것을 실패시키는 것: 바이너리에서 예약 루트 이름(libc·std·core·alloc·front)을 로컬로 선언하는 것,
// 어댑터 타입에 impl을 더하는 것, #[path]·include!로 검사 밖 코드를 들이는 것을 놓치는 것.
#[test]
fn binary_keeps_reserved_roots_and_files() {
    for (bad, why) in [
        (
            "#[allow(non_camel_case_types)]\npub struct libc;\n",
            "shadows a reserved root",
        ),
        ("mod std {}\n", "shadows a reserved root"),
        ("fn f<front>() {}\n", "shadows a reserved root"),
        ("use other::thing as libc;\n", "shadows a reserved root"),
        ("use crate::fake::libc;\n", "shadows a reserved root"),
        (
            "impl prompt::NonPromptArgs {\n    fn f() {}\n}\n",
            "impl for a type of the prompt adapter",
        ),
        ("#[path = \"../outside.rs\"]\nmod pre;\n", "#[path]"),
        ("include!(\"../outside.rs\");\n", "include"),
    ] {
        let (ok, err) = run_binary(bad);
        assert!(!ok && err.contains(why), "{bad}: {err}");
    }
    let (ok, err) = run_binary("use bingsu_core::front;\nconst S: &str = include_str!(\"x\");\n");
    assert!(ok, "{err}");
}

// 이것을 실패시키는 것: 어댑터가 NonPromptArgs 밖의 struct(예: libc 위장)를 두거나 닫힌 목록 밖의 경로 뿌리를 쓰는 것을 놓치는 것.
#[test]
fn adapter_closed_roots() {
    let add = |item: &str| ADAPTER_OK.replace("pub fn run", &format!("{item}\n\npub fn run"));
    for (bad, why) in [
        (
            add("#[allow(non_camel_case_types)]\npub struct libc;"),
            "only NonPromptArgs",
        ),
        (
            add("fn g() {\n    let _ = other::thing();\n}"),
            "not in PATH_ROOTS",
        ),
    ] {
        let (ok, err) = run_adapter(&bad);
        assert!(!ok && err.contains(why), "{why}: {bad}\n{err}");
    }
}

// 이것을 실패시키는 것: --tcb 뒤 파일에 주소·라이브러리 규칙(as_ptr, 함수 포인터, std::env)을 거는 것, 그 파일에서
// 모든 파일 공통 규칙(static, cfg)을 빼는 것, 같은 파일을 라이브러리로 넘겨도 통과시키는 것.
#[test]
fn tcb_files_skip_only_the_address_and_library_rules() {
    let ok = "fn w(b: &[u8], f: fn() -> u8) -> usize {\n    let _ = std::env::args_os();\n    let _ = f;\n    b.as_ptr() as usize\n}\n";
    let run_tcb = |source: &str| {
        let core = fixture("pub fn f() {}\n");
        let output = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
            .arg(core)
            .arg("--tcb")
            .arg(fixture(source))
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stderr).unwrap(),
        )
    };
    let (pass, err) = run_tcb(ok);
    assert!(pass, "{err}");
    let (pass, err) = run(ok);
    assert!(!pass && err.contains("as_ptr exposes an address"), "{err}");
    for (bad, why) in [
        ("static N: u8 = 0;\n", "static"),
        ("#[cfg(unix)]\nfn f() {}\n", "cfg"),
    ] {
        let (pass, err) = run_tcb(bad);
        assert!(!pass && err.contains(why), "{bad}: {err}");
    }
}

// 이것을 실패시키는 것: bootstrap을 필터 뒤나 다른 함수에서 허용하거나 다른 모듈 호출도 허용하는 것.
#[test]
fn bootstrap_is_only_a_prefilter_entry() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/bingsu/src/prompt.rs"),
    )
    .unwrap();
    let (ok, err) = run_adapter(&source);
    assert!(ok, "{err}");
    let call = "crate::prompt_spawn::bootstrap(exe, &raw, Some(deadline));";
    assert!(source.contains(call));
    let after = source.replace(call, "").replace(
        "respond(staged())",
        &format!("{call}\n            respond(staged())"),
    );
    assert!(!run_adapter(&after).0);
    let early = source.replace("let rec =", "enter_sandbox(); let rec =");
    assert!(!run_adapter(&early).0);
    let other = source.replace(call, "crate::other::run(exe, &raw);");
    assert!(!run_adapter(&other).0);
    let extra = source.replace(
        "respond(staged())",
        "crate::other::run(); respond(staged())",
    );
    assert!(!run_adapter(&extra).0);
}

// 이것을 실패시키는 것: reader 호출을 필터 뒤·다른 함수·추가 모듈 호출로 확대하는 것.
#[test]
fn reader_is_only_a_prefilter_entry() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/bingsu/src/prompt.rs"),
    )
    .unwrap();
    assert!(run_adapter(&source).0);
    let call = "let staged = crate::prompt_read::prepare(&raw, deadline);";
    assert!(source.contains(call));
    for bad in [
        source
            .replace(call, "")
            .replace("respond(staged())", &format!("{call} respond(staged())")),
        source.replace(
            call,
            &format!("{call} crate::prompt_read::prepare(&raw, deadline);"),
        ),
        source.replace(
            "respond(staged())",
            "crate::other::run(); respond(staged())",
        ),
        source.replace(
            "fn write_until",
            "fn extra() { crate::prompt_read::prepare(&[]); } fn write_until",
        ),
        source.replace("crate::prompt_read::prepare", "crate::other::prepare"),
    ] {
        let (ok, err) = run_adapter(&bad);
        assert!(!ok, "{err}");
    }
}

// 이것을 실패시키는 것: 타이머 설치를 필터 뒤·다른 함수에서 허용하거나 실패를 무시하는 것.
#[test]
fn deadline_install_is_only_a_fail_closed_prefilter_entry() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/bingsu/src/prompt.rs"),
    )
    .unwrap();
    assert!(run_adapter(&source).0);
    for bad in [
        source.replace("crate::prompt_io::arm_deadline(deadline)", "true"),
        source.replace(
            "if !crate::prompt_io::arm_deadline",
            "if crate::prompt_io::arm_deadline",
        ),
        source.replace(
            "respond(staged())",
            "crate::prompt_io::arm_deadline(deadline); respond(staged())",
        ),
        source.replace(
            "fn write_until",
            "fn extra() { crate::prompt_io::arm_deadline(d); } fn write_until",
        ),
        source.replace(
            "let deadline = crate::prompt_io::entry_deadline();",
            "let skipped = 0; let deadline = crate::prompt_io::entry_deadline();",
        ),
        source.replace(
            "crate::prompt_io::deadline_now",
            "crate::prompt_io::observe_clock",
        ),
    ] {
        assert!(!run_adapter(&bad).0, "{bad}");
    }
}

// 이것을 실패시키는 것: XID_Start/Continue를 alphabetic/alphanumeric으로 되돌리는 것.
#[test]
fn unicode_xid_format_arguments_and_counts() {
    for fmt in [
        "{a\u{332}:p}",
        "{℘:p}",
        "{x:a\u{332}$p}",
        "{x:.a\u{332}$p}",
        "{a\u{332}:?}",
        "{℘:#?}",
        "{x:a\u{332}$?}",
    ] {
        let source = format!("const X: &str = {fmt:?};");
        fails_with(&source, if fmt.ends_with("p}") { "{:p}" } else { "{:?}" });
    }
    passes("const X: &str = \"{a̲} {@icon:frame.top} {{a̲:p}}\";");
}

// 이것을 실패시키는 것: production glob visitor 제거 또는 group 안 glob을 놓치는 것.
#[test]
fn production_glob_cannot_import_debug_fmt() {
    for import in [
        "use core::fmt::*;",
        "use core::{fmt::{*}};",
        "use core::r#fmt::*;",
    ] {
        fails_with(
            &format!(
                "{import}\nstruct S(core::task::Waker);\nimpl core::fmt::Display for S {{ fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{ self.0.fmt(f) }} }}"
            ),
            "production glob",
        );
    }
    passes("#[cfg(test)] mod tests { use core::fmt::*; }");
}

// 이것을 실패시키는 것: 매크로 그룹 안 use를 AST glob 검사에서 제외하는 것.
#[test]
fn production_glob_in_macro_blocks_is_checked() {
    fails_with(
        "fn f() { let _ = alloc::vec![{ use core::fmt::*; 0 }]; }",
        "production glob",
    );
    passes("#[cfg(test)] mod tests { fn t() { m!({ use core::fmt::*; }); } }");
}

// 이것을 실패시키는 것: 함수 item 검사 제거, callee를 허용하면서 배열·분기까지 건너뛰는 것.
#[test]
fn function_items_cannot_be_stored_or_coerced_for_ordering() {
    for body in [
        "let fs = [a, b]; let _ = fs[0] < fs[1];",
        "let mut fs = [a, b]; fs.sort();",
        "let _ = alloc::collections::BTreeMap::from([(a, 1), (b, 2)]);",
        "let _ = a;",
        "let a = [a, b];",
        "consume(if flag { a } else { b });",
        "let _ = alloc::vec![a, b];",
        "let _ = || a;",
        "let _ = (a);",
        "let _ = &a;",
        "consume(a);",
        "let fs = [core::convert::identity(a), core::convert::identity(b)];",
    ] {
        fails_with(
            &format!("extern crate alloc; fn a() {{}} fn b() {{}} fn f(flag: bool) {{ {body} }}"),
            "function item",
        );
    }
    fails_with(
        "use crate::elsewhere::f as F; fn g() { let _ = F; }",
        "function item F",
    );
    fails_with(
        "fn f() { let _ = [crate::a::f, crate::b::f]; }",
        "function item f",
    );
    passes("fn a() {} fn f() { a(); (a)(); consume(|| a()); let a = 1; let _ = a; }");
    passes("fn a() {} #[cfg(test)] mod tests { fn t() { let _ = super::a; } }");
}

// 이것을 실패시키는 것: 매크로 표현식 파싱 제거로 turbofish를 경로 접두사처럼 건너뛰는 것.
#[test]
fn function_items_with_turbofish_in_macros_cannot_escape() {
    fails_with(
        "fn a<T>() {} fn b<T>() {} fn f() { let fs = alloc::vec![a::<u8>, b::<u8>]; }",
        "function item",
    );
    fails_with(
        "fn f() { let fs = alloc::vec![crate::a::f, crate::b::f]; }",
        "function item",
    );
    fails_with(
        "struct S; impl S { fn A() {} fn B() {} } fn f() { let fs = [S::A, S::B]; }",
        "function item",
    );
}

// 이것을 실패시키는 것: ptr::eq 예외 복구 또는 ptr_eq를 ADDRESS_APIS에서 빼는 것.
#[test]
fn pointer_identity_is_not_a_pure_value() {
    for body in [
        "core::ptr::eq(a, b)",
        "core::ptr::r#eq(a, b)",
        "alloc::rc::Rc::ptr_eq(a, b)",
        "alloc::rc::Weak::ptr_eq(a, b)",
    ] {
        fails_with(
            &format!("fn f(a: &u8, b: &u8) -> bool {{ {body} }}"),
            "exposes an address",
        );
        fails_with(&format!("m!({body});"), "exposes an address");
    }
    fails_with("use core::ptr::eq as same;", "pointer identity");
    passes("#[cfg(test)] mod tests { fn t() { core::ptr::eq(&1, &1); } }");
}

fn run_rules(source: &str) -> (bool, String) {
    let source = fixture(source);
    let table = fixture("syscall\tlibc\twhy\nread\tread\theld fd\n");
    let result = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .args(["--rules", table.to_str().unwrap(), source.to_str().unwrap()])
        .output()
        .unwrap();
    (
        result.status.success(),
        String::from_utf8(result.stderr).unwrap(),
    )
}

// 이것을 실패시키는 것: 실제 RULES 대신 파일 전체의 tuple/문자열/주석을 비교하는 것.
#[test]
fn rules_initializer_ignores_decoys_and_rejects_indirection() {
    let good = r#"const RULES: [(&str, i64, &[u8]); 1] = [("read", libc::SYS_read, &[])];
        fn rules() -> Vec<(u32, &'static [Cond])> {
            RULES.iter()
                .map(|&(_, nr, c)| (u32::try_from(nr).expect("syscall number"), c))
                .collect()
        }"#;
    assert!(run_rules(good).0);
    for bad in [
        "// (\"read\", libc::SYS_read, &[])\nconst RULES: [(); 0] = [];",
        "const DECOY: &[(&str, i64, &[u8])] = &[(\"read\", libc::SYS_read, &[])]; const RULES: [(); 0] = [];",
        "const DECOY: &str = r#\"(\"read\", libc::SYS_read, &[])\"#; const RULES: [(); 0] = [];",
        "const DECOY: [(&str, i64, &[u8]); 1] = [(\"read\", libc::SYS_read, &[])]; const RULES: [(&str, i64, &[u8]); 1] = DECOY;",
        "const RULES: [(&str, i64, &[u8]); 1] = [(\"read\", libc::SYS_write, &[])];",
        "const RULES: [(&str, i64, &[u8]); 1] = [row()];",
    ] {
        let (ok, err) = run_rules(bad);
        assert!(!ok && err.contains("RULES:"), "{bad}: {err}");
    }
    // A decoy must not create a false syscall mismatch either.
    assert!(run_rules(&format!("{good}\n// (\"execve\", libc::SYS_execve, &[])")).0);
}

// 이것을 실패시키는 것: prepare 인자 AST 검사를 제거하거나 인자 개수만 보는 것.
#[test]
fn prepare_arguments_are_exact() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/bingsu/src/prompt.rs"),
    )
    .unwrap();
    assert!(run_adapter(&source).0);
    for args in [
        "&[], deadline",
        "&raw, deadline + 1",
        "&raw, other",
        "&mut raw, deadline",
        "&raw, { deadline }",
    ] {
        let bad = source.replace("prepare(&raw, deadline)", &format!("prepare({args})"));
        let (ok, err) = run_adapter(&bad);
        assert!(!ok, "{args}: {err}");
    }
}

// 이것을 실패시키는 것: 직접 호출의 인자를 건너뛰어 identity로 함수 값을 유출하는 것.
#[test]
fn function_items_cannot_escape_through_arguments() {
    fails_with(
        "fn a() {} fn b() {} fn f() { let fs = [core::convert::identity(a), core::convert::identity(b)]; }",
        "function item",
    );
}

// 이것을 실패시키는 것: tuple variant 생성자와 그 import를 함수 item으로 세지 않는 것.
#[test]
fn function_item_constructors_cannot_be_ordered() {
    fails_with(
        "enum E { A(u8), B(u8) } fn f() { let fs = [E::A, E::B]; }",
        "function item",
    );
    fails_with(
        "enum E { A(u8), B(u8) } use E::{A,B}; fn f() { let fs = [A,B]; }",
        "function item",
    );
    passes("enum E { Unit } use E::Unit as Data; fn f() { consume(Data); }");
}
