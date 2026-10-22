//! Bypass fixtures for the core and prompt adapter gates.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use syn::spanned::Spanned;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// A Windows checkout has CRLF line endings; the mutations below replace LF text.
fn repo_source(path: &str) -> String {
    std::fs::read_to_string(root().join(path))
        .unwrap()
        .replace("\r\n", "\n")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bypass")
            .join(name),
    )
    .unwrap()
    .replace("\r\n", "\n")
}

fn check(source: &str, mode: &[&str]) -> (bool, String) {
    let path = std::env::temp_dir().join(format!(
        "gate-bypass-{}-{}.rs",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, source).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
        .args(mode)
        .arg(&path)
        .current_dir(root())
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    (
        result.status.success(),
        String::from_utf8(result.stderr).unwrap(),
    )
}

fn rejects(source: &str, mode: &[&str], reason: &str) {
    let (ok, err) = check(source, mode);
    assert!(!ok && err.contains(reason), "expected {reason}: {err}");
}

fn accepts(source: &str, mode: &[&str]) {
    let (ok, err) = check(source, mode);
    assert!(ok && err.is_empty(), "{err}");
}

// Extract whole top-level items so another rejected construct in zz.rs cannot mask a bypass.
fn probe_items(names: &[&str]) -> String {
    fixture_items("wt/crates/bingsu-core/src/zz.rs", names)
}

fn fixture_items(name: &str, names: &[&str]) -> String {
    let source = fixture(name);
    let file = syn::parse_file(&source).unwrap();
    file.items
        .iter()
        .filter_map(|item| {
            let name = match item {
                syn::Item::Fn(f) => f.sig.ident.to_string(),
                syn::Item::Struct(s) => s.ident.to_string(),
                _ => return None,
            };
            names.contains(&name.as_str()).then(|| {
                source
                    .lines()
                    .skip(item.span().start().line - 1)
                    .take(item.span().end().line - item.span().start().line + 1)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// 이것을 실패시키는 것: identity의 금지 토큰을 빼거나 함수·상수·속성·매크로 토큰을 건너뛰는 것.
#[test]
fn bypass_identity_generated_input_is_the_only_exception() {
    let mode = ["--identity"];
    let good = repo_source("crates/bingsu-identity/src/lib.rs");
    accepts(&good, &mode);
    accepts(
        &format!(
            "{good}\n// include! env! macro_rules!\nconst TEXT: &str = \"include_bytes! option_env! include_str!\";"
        ),
        &mode,
    );
    for token in [
        "include",
        "include_str",
        "include_bytes",
        "env",
        "option_env",
        "macro_rules",
    ] {
        let reason = format!("identity forbidden token {token} outside build_id include");
        rejects(&fixture(&format!("identity/{token}.rs")), &mode, &reason);
        for extra in [
            format!("fn hidden() {{ m!((::core::r#{token})); }}"),
            format!("#[cfg(any())] const HIDDEN: () = m!(r#{token});"),
            format!("#[m(r#{token})] fn hidden() {{}}"),
        ] {
            rejects(&format!("{good}\n{extra}"), &mode, &reason);
        }
    }
    rejects(
        &format!(
            "{good}\nfn hidden() {{ include!(concat!(env!(\"OUT_DIR\"), \"/build_id.rs\")); }}"
        ),
        &mode,
        "identity forbidden token include outside build_id include",
    );
}

// 이것을 실패시키는 것: enter 본문·DENY 초기식 고정이나 libc 별칭 금지를 제거하는 것.
#[test]
fn bypass_k24_entry_and_deny_are_pinned() {
    let mode = ["--rules", "crates/bingsu/prompt-syscalls.tsv"];
    for name in ["k24/literal.rs", "k24/alias.rs", "k24/miss_allow.rs"] {
        rejects(&fixture(name), &mode, "enter() must");
    }
    rejects(&fixture("k24/alias.rs"), &mode, "renamed libc import");
    let good = repo_source("crates/bingsu/src/sandbox.rs");
    for source in [
        good.replace("pub fn enter()", "pub fn other()"),
        good.replace("pub fn enter()", "#[cfg(any())] pub fn enter()"),
        format!("{good}\nmod nested {{ fn enter() {{}} }}"),
        good.replace("install(&prog)", "Sandbox::Installed"),
    ] {
        rejects(&source, &mode, "enter() must");
    }
    for source in [
        good.replace(
            "libc::SECCOMP_RET_ERRNO | libc::EPERM as u32",
            "libc::SECCOMP_RET_ALLOW",
        ),
        good.replace("const DENY:", "const OTHER:"),
        good.replace("const DENY:", "#[cfg(any())] const DENY:"),
        format!("{good}\nmod nested {{ const DENY: u32 = 0; }}"),
    ] {
        rejects(&source, &mode, "DENY must");
    }
    // A renamed import must fail even when enter and DENY remain intact.
    for import in [
        "use libc as l;",
        "use ::r#libc as l;",
        "use {libc as l};",
        "use libc::{self as l};",
        "use libc::SECCOMP_RET_ALLOW as ALLOW;",
        "extern crate libc as l;",
        "fn hidden() { use libc as l; }",
        "#[cfg(test)] mod extra { use libc as l; }",
    ] {
        rejects(&format!("{good}\n{import}"), &mode, "renamed libc import");
    }
}

// 이것을 실패시키는 것: RULES 밖 syscall 경로 검사와 소비 함수 본문 고정을 제거하는 것.
#[test]
fn bypass_k24_decoy() {
    let source = fixture("k24/decoy.rs");
    let mode = ["--rules", "crates/bingsu/prompt-syscalls.tsv"];
    rejects(&source, &mode, "outside RULES initializer");
    rejects(&source, &mode, "rules() must");
    let good = repo_source("crates/bingsu/src/sandbox.rs");
    accepts(&good, &mode);
    // Each half also has an independent witness: a correct consumer cannot
    // excuse an extra syscall, and no extra syscall is needed to swap consumers.
    rejects(
        &format!("{good}\nconst EXTRA: i64 = libc::SYS_execve;"),
        &mode,
        "outside RULES initializer",
    );
    rejects(
        &good.replace("fn rules() ->", "fn alternate() ->"),
        &mode,
        "rules() must",
    );
    rejects(
        &good.replace("RULES\n        .iter()", "OTHER\n        .iter()"),
        &mode,
        "rules() must",
    );
    rejects(
        &format!("{good}\nfn hidden() {{ m!(::libc::r#SYS_execve); }}"),
        &mode,
        "outside RULES initializer",
    );
    rejects(
        &format!("{good}\nuse libc::{{SYS_execve as exec}};"),
        &mode,
        "outside RULES initializer",
    );
    accepts(
        &format!("{good}\n#[cfg(test)] fn probe() {{ m!(libc::SYS_execve); }}"),
        &mode,
    );
}

// 이것을 실패시키는 것: prompt_io의 외부 모듈 경계 검사를 제거하는 것.
#[test]
fn bypass_k68_external_module() {
    let mode = [
        "--prompt-io",
        "var,var_os,vars,vars_os,home_dir,exit,write_all",
    ];
    rejects(&fixture("k68/bin/src/prompt_io.rs"), &mode, "out-of-line");
    rejects(
        &fixture("k68/bin/src/prompt_io/evil.rs"),
        &mode,
        "forbidden token var",
    );
    accepts(
        "#[cfg(target_os = \"linux\")] mod linux {} #[cfg(test)] mod tests {}",
        &mode,
    );
    for source in [
        "mod outer { #[cfg(test)] mod hidden; }",
        "#[path = \"evil.rs\"] mod inline {}",
        "m!(#[r#path = \"evil.rs\"] mod inline {});",
    ] {
        let (ok, err) = check(source, &mode);
        assert!(!ok, "{source}: {err}");
    }
}

// 이것을 실패시키는 것: Expr::RawAddr 방문자를 제거하는 것.
#[test]
fn bypass_k04_raw_borrow() {
    rejects(&probe_items(&["same", "ident"]), &[], "raw borrow");
    rejects(
        "fn f(a: &mut u8) { let _ = &raw mut *a; }",
        &[],
        "raw borrow",
    );
}

// 이것을 실패시키는 것: 매크로 토큰의 & raw const|mut 검사를 제거하는 것.
#[test]
fn bypass_k04_macro_raw_borrow() {
    for kind in ["const", "mut"] {
        rejects(
            &format!("fn f() {{ m!((& /* gap */ raw {kind} a)); }}"),
            &[],
            "raw borrow",
        );
    }
    accepts("fn f(a: &u8) { consume(a); }", &[]);
    accepts("#[cfg(test)] fn f(a: &u8) { let _ = &raw const *a; }", &[]);
}

// 이것을 실패시키는 것: closure 병합 검사와 생성자 함수 item 분류를 제거하는 것.
#[test]
fn bypass_k03_closure_merges() {
    rejects(&probe_items(&["lt", "pick"]), &[], "closure");
    rejects(&probe_items(&["lt", "W", "pick2"]), &[], "function item W");
    rejects(&probe_items(&["lt", "pick3"]), &[], "function item Some");
    for value in [
        "match c { true => |x: u8| x, false => |x: u8| x + 1 }",
        "[|x: u8| x, |x: u8| x + 1]",
        "alloc::vec![|x: u8| x, |x: u8| x + 1]",
        "if c { (|x: u8| x) } else { { |x: u8| x + 1 } }",
        "{ let a = |x: u8| x; let b = |x: u8| x + 1; [a, b] }",
        "{ let a = |x: u8| x; let b = |x: u8| x + 1; if c { a } else { b } }",
        "if c { let a = |x: u8| x; a } else { let b = |x: u8| x + 1; b }",
    ] {
        rejects(
            &format!("fn f(c: bool) {{ let _ = {value}; }}"),
            &[],
            "closure",
        );
    }
    accepts(
        "fn f(xs: &[u8]) { let _ = xs.iter().map(|x| x + 1).filter(|x| *x > 1); }",
        &[],
    );
    accepts(
        "fn f(c: bool) { let _ = if c { consume(|| 1) } else { consume(|| 2) }; }",
        &[],
    );
    accepts("fn f() { let _ = [consume(|| 1), consume(|| 2)]; }", &[]);
}

// 이것을 실패시키는 것: 필드로 저장한 클로저의 병합을 허용하는 것.
#[test]
fn bypass_k03_closure_fields() {
    let fixture = "wt/crates/bingsu-core/src/zz2.rs";
    let reason = "closure stored in a tuple or struct field";
    for name in ["k03_tuple_field", "k03_array_fields", "k03_struct_field"] {
        rejects(&fixture_items(fixture, &["lt", "P", name]), &[], reason);
    }
    for body in [
        "let _ = ((|x: u8| x),);",
        "let _ = ({ |x: u8| x },);",
        "let _ = ((|x: u8| x,),);",
        "let _ = S { field: (|x: u8| x) };",
        "let _ = S { field: { |x: u8| x } };",
        "let f = |x: u8| x; let _ = (f,);",
        "let field = |x: u8| x; let _ = S { field };",
        "m!((|x: u8| x,));",
        "m!(S { field: |x: u8| x });",
    ] {
        rejects(&format!("fn f() {{ {body} }}"), &[], reason);
        accepts(&format!("#[cfg(test)] fn f() {{ {body} }}"), &[]);
    }
    accepts("fn f() { let _ = (consume(|| 1), 2); }", &[]);
    accepts("fn f() { let _ = S { field: consume(|| 1) }; }", &[]);
}

// 이것을 실패시키는 것: tuple struct 또는 대문자 import를 값으로 간주하는 것.
#[test]
fn bypass_k03_constructors_and_uppercase_import() {
    rejects(&fixture("fx/k03_tuple_struct.rs"), &[], "function item W");
    rejects(
        &fixture("fx/k03_upper_fn_import.rs"),
        &[],
        "function item Make",
    );
    for name in ["Some", "Ok", "Err"] {
        rejects(
            &format!("fn f() {{ consume({name}); }}"),
            &[],
            "function item",
        );
        accepts(&format!("fn f() {{ consume(|| {name}(1)); }}"), &[]);
    }
    for source in [
        "use crate::other::MAKE; fn f() { consume(MAKE); }",
        "enum E { Make } use crate::other::Make; fn f() { consume(Make); }",
        "fn f() { consume(core::option::Option::Some); }",
        "fn f() { consume(core::result::Result::Ok); }",
        "fn f() { consume(core::result::Result::Err); }",
        "struct W(u8); fn f() { custom!(item => W); }",
        "struct W(u8); impl W { fn f() { consume(Self); } }",
        "enum E { A(u8) } impl E { fn f() { consume(Self::A); } }",
        "enum E { A(u8) } fn f() { custom!(item => E::A); }",
    ] {
        rejects(source, &[], "function item");
    }
}

// 이것을 실패시키는 것: 확인된 상수·unit struct까지 함수로 분류하거나,
// 대문자라는 이유만으로 함수/생성자 import를 면제하는 것.
#[test]
fn bypass_k03_imports_use_declarations_not_spelling() {
    let dir = std::env::temp_dir().join(format!("bypass-spelling-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib = dir.join("lib.rs");
    let other = dir.join("other.rs");
    std::fs::write(&other, "pub const DATA: u8 = 1; pub struct Unit; pub struct Tuple(u8); #[allow(non_snake_case)] pub fn Make(x: u8) -> u8 { x } #[allow(non_snake_case)] pub fn ALL_CAPS(x: u8) -> u8 { x }").unwrap();
    for (name, ok) in [
        ("DATA", true),
        ("Unit", true),
        ("Tuple", false),
        ("Make", false),
        ("ALL_CAPS", false),
    ] {
        std::fs::write(&lib, format!("#![no_std]\n#![forbid(unsafe_code)]\nmod other; use crate::other::{name}; fn f() {{ consume({name}); }}")).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
            .args([&lib, &other])
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            ok,
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

// 이것을 실패시키는 것: run_prompt 본문의 raw·deadline 바인딩 개수 검사를 제거하는 것.
#[test]
fn bypass_k83_shadow_bindings() {
    let mode = ["--adapter", "crates/bingsu/prompt-syscalls.tsv"];
    for name in ["k83/shadow2.rs", "k83/shadow_dl.rs"] {
        let (ok, err) = check(&fixture(name), &mode);
        assert!(!ok, "{name}: {err}");
    }
    let good = repo_source("crates/bingsu/src/prompt.rs");
    accepts(&good, &mode);
    for shadow in [
        "let (raw,) = (&raw[..0],);",
        "let Some(deadline) = Some(deadline) else { exit(0) };",
        "let _ = |raw: &[u8]| raw.len();",
    ] {
        let bad = good.replace("let rec =", &format!("{shadow} let rec ="));
        assert!(!check(&bad, &mode).0, "{shadow}");
    }
}

// 이것을 실패시키는 것: raw 바인딩 개수만 검사하고 초기식은 허용하는 것.
#[test]
fn bypass_k83_raw_initializer_is_pinned() {
    let mode = ["--adapter", "crates/bingsu/prompt-syscalls.tsv"];
    let reason = "another module of the binary";
    rejects(&fixture("k83/init.rs"), &mode, reason);
    let good = repo_source("crates/bingsu/src/prompt.rs");
    for initializer in [
        "args[..0].iter().map(|a| a.as_bytes()).collect()",
        "args.iter().skip(1).map(|a| a.as_bytes()).collect()",
        "args.iter().map(|a| &a.as_bytes()[..0]).collect()",
        "Vec::new()",
    ] {
        rejects(
            &good.replace("args.iter().map(|a| a.as_bytes()).collect()", initializer),
            &mode,
            reason,
        );
    }
    rejects(&good.replace("let raw:", "let mut raw:"), &mode, reason);
    accepts(&good, &mode);
}

// 이것을 실패시키는 것: 데이터 증명을 이름만으로 공유하여 다른 모듈의 함수를 허용하는 것.
#[test]
fn bypass_k03_import_resolution_is_path_specific() {
    let dir = std::env::temp_dir().join(format!("bypass-import-paths-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib = dir.join("lib.rs");
    let data = dir.join("data.rs");
    let other = dir.join("other.rs");
    let prefix = "#![no_std]\n#![forbid(unsafe_code)]\nmod data; mod other;\n";
    std::fs::write(&data, "pub const Make: u8 = 1; pub struct Unit;\n").unwrap();
    std::fs::write(
        &other,
        "#[allow(non_snake_case)] pub fn Make(x: u8) -> u8 { x }\n",
    )
    .unwrap();
    for (source, expected) in [
        ("use crate::data::Make; fn f() { consume(Make); }", true),
        ("use crate::data::Unit; fn f() { consume(Unit); }", true),
        ("use crate::other::Make; fn f() { consume(Make); }", false),
        (
            "use crate::other::Make as Alias; fn f() { consume(Alias); }",
            false,
        ),
        (
            "mod nested { use super::other::Make; fn f() { consume(Make); } }",
            false,
        ),
        (
            "const Make: u8 = 1; mod nested { #[allow(non_snake_case)] pub fn Make(x: u8) -> u8 { x } mod inner { use super::Make; fn f() { consume(Make); } } }",
            false,
        ),
        (
            "mod nested { use super::data::Unit; fn f() { consume(Unit); } }",
            true,
        ),
    ] {
        std::fs::write(&lib, format!("{prefix}{source}")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_core-cfg-check"))
            .args([&lib, &data, &other])
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            expected,
            "{source}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
