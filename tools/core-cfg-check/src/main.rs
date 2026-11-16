//! Token-level conditional-compilation and pull-in check for bingsu-core.
//!
//! Usage: `core-cfg-check FILE.rs... [--test-targets FILE.rs...] [--tcb FILE.rs...]`
//! (scripts/check_core_cfg.py collects the files and passes them here; the
//! files after `--test-targets`, core's tests/ and benches/, skip the
//! library-only rules (production globs, function items, Debug and Hash,
//! strings from outside the source) and the crate-root rule; the files after
//! `--tcb`, the prompt adapter, get the rules that hold for every file but
//! not the library-only ones, the address rule and the crate-root rule: the
//! adapter hands buffers to write(2), takes a function pointer and reads its
//! arguments through `std::env`). purity.rs lists the rules.
//!
//! Code behind `cfg` can drop out of the lint run, and `#[path]` or
//! `include!` can pull code in from outside the checked file set. A text or
//! regex check misses spacing, line breaks, comments and strings, so this
//! looks at the Rust tokens instead.
//!
//! The other modes, each described in its module:
//!   - `core-cfg-check --binary FILE.rs...`: every source file of the `bingsu`
//!     binary crate (binary.rs);
//!   - `--adapter SYSCALLS.tsv FILE.rs`: the prompt adapter (adapter.rs);
//!   - `--rules SYSCALLS.tsv FILE.rs`: the actual sandbox RULES initializer
//!     (rules.rs);
//!   - `--prompt-io NAMES FILE.rs`: every OS bridge branch, for CLI forbidden
//!     calls (prompt_io.rs);
//!   - `--identity FILE.rs`: the shared no_std identity root (identity.rs);
//!   - `--prompt-main FILE.rs`: the entry of the dedicated prompt binary
//!     (prompt_main.rs).
//!
//! Raw identifiers (`r#cfg`) are compared without the `r#` prefix, since
//! rustc treats `#[r#cfg(..)]` and `#[r#path = ..]` as the real attributes.
//!
//! The parser and the lexer see the same text: the shebang line syn strips
//! is stripped before lexing too. Otherwise a
//! first line `#!x /*` would open a block comment for the lexer only, and the
//! code after it would reach rustc unchecked.

use std::process::ExitCode;

use proc_macro2::{Delimiter, Span, TokenTree};
use syn::ext::IdentExt;

mod adapter;
mod binary;
mod function_items;
mod identity;
mod prompt_io;
mod prompt_main;
mod purity;
mod rules;
mod test_scope;

use binary::{check_binary, check_main};
use identity::check_identity;
use prompt_io::check_prompt_io;
use purity::check;

struct Finding {
    line: usize,
    reason: String,
}

fn line_of(span: Span) -> usize {
    span.start().line
}

/// Name of an identifier without a raw `r#` prefix.
fn unraw(ident: &proc_macro2::Ident) -> String {
    ident.unraw().to_string()
}

fn is_punct(token: Option<&TokenTree>, ch: char) -> bool {
    matches!(token, Some(TokenTree::Punct(p)) if p.as_char() == ch)
}

/// True if `token` is a `[...]` group whose first token is the identifier
/// `path`.
fn is_path_attr_group(token: Option<&TokenTree>) -> bool {
    let Some(TokenTree::Group(group)) = token else {
        return false;
    };
    if group.delimiter() != Delimiter::Bracket {
        return false;
    }
    matches!(group.stream().into_iter().next(), Some(TokenTree::Ident(ident)) if unraw(&ident) == "path")
}

fn is_ident(token: Option<&TokenTree>, name: &str) -> bool {
    matches!(token, Some(TokenTree::Ident(ident)) if unraw(ident) == name)
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "--identity") {
        let [_, path] = args.as_slice() else {
            eprintln!("usage: core-cfg-check --identity FILE.rs");
            return ExitCode::FAILURE;
        };
        let Ok(source) = std::fs::read_to_string(path) else {
            eprintln!("{path}: unreadable");
            return ExitCode::FAILURE;
        };
        let findings = check_identity(&source);
        for f in &findings {
            eprintln!("{path}:{}: {}", f.line, f.reason);
        }
        return if findings.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    if args.first().is_some_and(|a| a == "--prompt-main") {
        let [_, path] = args.as_slice() else {
            eprintln!("usage: core-cfg-check --prompt-main FILE.rs");
            return ExitCode::FAILURE;
        };
        let Ok(source) = std::fs::read_to_string(path) else {
            eprintln!("{path}: unreadable");
            return ExitCode::FAILURE;
        };
        let findings = prompt_main::check_prompt_main(&source);
        for f in &findings {
            eprintln!("{path}:{}: {}", f.line, f.reason);
        }
        return if findings.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    if args.first().is_some_and(|a| a == "--prompt-io") {
        let [_, forbidden, path] = args.as_slice() else {
            eprintln!("usage: core-cfg-check --prompt-io NAME,NAME,... FILE.rs");
            return ExitCode::FAILURE;
        };
        let Ok(source) = std::fs::read_to_string(path) else {
            eprintln!("{path}: unreadable");
            return ExitCode::FAILURE;
        };
        let names: Vec<_> = forbidden.split(',').collect();
        let findings = check_prompt_io(&source, &names);
        for f in &findings {
            eprintln!("{path}:{}: {}", f.line, f.reason);
        }
        return if findings.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    let binary = args.first().is_some_and(|a| a == "--binary");
    if binary {
        args.remove(0);
    }
    if args
        .first()
        .is_some_and(|a| a == "--adapter" || a == "--rules")
    {
        let [_, tsv, file] = args.as_slice() else {
            eprintln!("usage: core-cfg-check --adapter SYSCALLS.tsv FILE.rs");
            return ExitCode::FAILURE;
        };
        let (Ok(table), Ok(source)) = (std::fs::read_to_string(tsv), std::fs::read_to_string(file))
        else {
            eprintln!("core-cfg-check: unreadable {tsv} or {file}");
            return ExitCode::FAILURE;
        };
        let findings = if args[0] == "--rules" {
            rules::check(&source, &table)
        } else {
            adapter::check_adapter(&source, &table)
        };
        for finding in &findings {
            eprintln!("{file}:{}: {}", finding.line, finding.reason);
        }
        return if findings.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    // Files after `--tcb` (the prompt adapter), then the files after
    // `--test-targets`, then the library files.
    let tcb = match args.iter().position(|a| a == "--tcb") {
        Some(at) => args.split_off(at)[1..].to_vec(),
        None => Vec::new(),
    };
    let tests = match args.iter().position(|a| a == "--test-targets") {
        Some(at) => args.split_off(at)[1..].to_vec(),
        None => Vec::new(),
    };
    let library = args;
    if library.is_empty() {
        eprintln!("core-cfg-check: no files");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    let mut sources = Vec::new();
    let data = function_items::Data::from_paths(&library);
    let files = library
        .iter()
        .map(|p| (p, Kind::Library))
        .chain(tests.iter().map(|p| (p, Kind::Test)))
        .chain(tcb.iter().map(|p| (p, Kind::Tcb)));
    for (path, kind) in files {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(err) => {
                eprintln!("{path}: unreadable: {err}");
                failed = true;
                continue;
            }
        };
        let findings = if binary {
            check_binary(&source)
        } else {
            let crate_root = kind == Kind::Library
                && std::path::Path::new(path).file_name() == Some(std::ffi::OsStr::new("lib.rs"));
            check(
                &source,
                kind == Kind::Library,
                crate_root,
                kind != Kind::Tcb,
                path,
                &data,
            )
        };
        sources.push((path.clone(), source));
        for finding in findings {
            eprintln!("{path}:{}: {}", finding.line, finding.reason);
            failed = true;
        }
    }
    if binary {
        for (path, finding) in check_main(&sources) {
            eprintln!("{path}:{}: {}", finding.line, finding.reason);
            failed = true;
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Which rules a file gets: core's library files all of them, its test
/// and bench targets all but the library-only ones, the prompt adapter all
/// but the library-only, address and crate-root ones.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Library,
    Test,
    Tcb,
}
