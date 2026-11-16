//! The default mode: core's library files, its test and bench targets
//! (after `--test-targets`) and the prompt adapter (after `--tcb`); main.rs
//! says which rules each kind of file skips.
//!
//! Every file fails on:
//!   - a first line that starts with `#!` but not `#![` (a shebang): rustc
//!     drops that line, and its rule for telling a shebang from an inner
//!     attribute differs from syn's (rustc does not count U+3000 as
//!     whitespace, syn does), so core allows no shebang at all;
//!   - source that does not parse (it cannot be checked);
//!   - an identifier `cfg_attr` anywhere;
//!   - an identifier `include` anywhere, not only before `!`: a renaming
//!     `use core::include as inc;` or a macro argument `m!(include)` still
//!     names it (include_str and include_bytes are different identifiers,
//!     handled by the format-source rule below);
//!   - an identifier `macro_rules` anywhere: bingsu-core uses no declarative
//!     macros, and without them no token substitution can build `#[path]`,
//!     `include!` or a cfg attribute out of a macro argument;
//!   - the tokens `#` (or `#!`) followed by a `[...]` group whose first token
//!     is `path`, wherever they appear (also inside macro bodies, which the
//!     parser does not look into);
//!   - an attribute named `path` that the parser sees (overlaps the token
//!     rule on purpose, reported with its own reason);
//!   - an attribute named `feature` (`#![feature(..)]`): stable rustc rejects
//!     it, but `RUSTC_BOOTSTRAP=1` turns it on, so the gate also refuses it;
//!   - a `cfg` attribute other than exactly `#[cfg(test)]`;
//!   - more `cfg` identifier tokens than `#[cfg(test)]` attributes, which
//!     catches `cfg!()`, cfg inside macro bodies and any other spot;
//!   - the identifiers `extern crate std` in a row: bingsu-core is `no_std`,
//!     and this is the one way to bring std back;
//!   - an item `static` anywhere (core keeps no state between calls; with no
//!     static there is nowhere to keep it), an identifier `atomic` or one
//!     starting with `Atomic`, and an identifier in HIDDEN_STATE (`forget`
//!     and `ManuallyDrop` leak allocations, `Arc` counts are atomics);
//!   - outside `#[cfg(test)]` items, anything that turns an address into a
//!     value (a leaked allocation's or a function's address would make the
//!     output depend on the allocator or on ASLR): a raw pointer type, a
//!     function pointer type, a cast of a function of the same file (`f as
//!     usize`; clippy's fn_to_numeric_cast_any covers the rest), a name in
//!     ADDRESS_APIS (including Rc/Weak::ptr_eq), any `core::ptr`,
//!     and a string that formats a pointer (a placeholder whose type is `p`,
//!     with any fill, alignment, flags, width or precision: `{:p}`, `{v:#p}`,
//!     `{:>20p}`, `{:}>20p}`). Macro bodies, which syn does not parse, get
//!     the same checks on their tokens;
//!   - an identifier `concat` or `stringify` anywhere except right after `.`
//!     (the slice method `.concat()`): both macros build a format string
//!     out of pieces, so no single literal shows the placeholder;
//!   - in library files (not after `--test-targets`), an identifier
//!     `include_str`, `include_bytes` or `option_env`, and an identifier
//!     `env` other than in `const VERSION: &str = env!("CARGO_PKG_VERSION")`:
//!     each brings in a string from outside the source, which could be a
//!     format string with a pointer placeholder. Test targets read shared
//!     tables with include_str and never reach the prompt;
//!   - in library files, outside `#[cfg(test)]` items (found by the parser,
//!     at any depth), a Debug placeholder (`{:?}`, `{:#?}`, `{:x?}`) and a
//!     name in DEBUG_AND_HASH: Debug and Hash implementations may write an
//!     address (a Waker's vtable, a function pointer). `#[derive(Debug)]`
//!     stays allowed, since nothing in production code can call it;
//!   - production glob imports (they can import Debug::fmt without naming
//!     Debug), and function items stored/returned/merged outside a direct
//!     call (see function_items.rs);
//!   - in a library file named `lib.rs` (the crate root), a missing inner
//!     attribute `#![no_std]` or `#![forbid(unsafe_code)]`, read by the
//!     parser so a commented-out or quoted copy does not count.

use std::str::FromStr;

use proc_macro2::TokenStream;
use syn::visit::Visit;

use crate::test_scope::{TestSpans, is_test_file};
use crate::{Finding, function_items, line_of};

mod address;
mod debug_hash;
mod format_sources;
mod format_spec;
mod tokens;

use address::{Addresses, FnNames};
use debug_hash::{ProductionGlobs, scan_debug_and_hash};
use format_sources::{VersionEnv, scan_format_sources};
use tokens::{AttrCheck, scan_tokens};

/// The crate root must keep `#![no_std]` and `#![forbid(unsafe_code)]` as
/// real inner attributes.
pub(crate) fn check_crate_root(attrs: &[syn::Attribute], out: &mut Vec<Finding>) {
    // syn::File::attrs holds the crate's inner attributes only.
    let no_std = attrs
        .iter()
        .any(|a| matches!(&a.meta, syn::Meta::Path(p) if p.is_ident("no_std")));
    let forbid = attrs.iter().any(|a| {
        matches!(&a.meta, syn::Meta::List(l)
            if l.path.is_ident("forbid") && l.tokens.to_string() == "unsafe_code")
    });
    for (ok, what) in [(no_std, "#![no_std]"), (forbid, "#![forbid(unsafe_code)]")] {
        if !ok {
            out.push(Finding {
                line: 1,
                reason: format!("crate root lacks {what}"),
            });
        }
    }
}

pub(super) fn check(
    source: &str,
    library: bool,
    crate_root: bool,
    addresses: bool,
    path: &str,
    data: &function_items::Data,
) -> Vec<Finding> {
    let mut out = Vec::new();
    // syn::parse_file and the proc-macro2 lexer each drop a leading BOM on
    // their own; remove it here too, so the shebang policy sees the first
    // line and the shebang cut below counts bytes in the text syn parsed.
    let text = source.strip_prefix('\u{feff}').unwrap_or(source);
    // Policy, independent of how syn detects a shebang. What makes this
    // fail: removing this check (the tool tests shebang_fails and
    // ideographic_space_shebang_fails).
    if text.starts_with("#!") && !text.starts_with("#![") {
        out.push(Finding {
            line: 1,
            reason: "shebang in core source".to_owned(),
        });
    }
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(err) => {
            out.push(Finding {
                line: line_of(err.span()),
                reason: format!("unparsable: {err}"),
            });
            return out;
        }
    };
    // Lex exactly the text syn parsed: syn strips the shebang line up to (not
    // including) its newline and returns it in file.shebang, so cutting that
    // many bytes keeps line numbers. Comments and the rest of the text are
    // lexed, so nothing the parser drops escapes the token scan.
    let body = match &file.shebang {
        Some(shebang) => &text[shebang.len()..],
        None => text,
    };
    let stream = match TokenStream::from_str(body) {
        Ok(stream) => stream,
        Err(err) => {
            out.push(Finding {
                line: line_of(err.span()),
                reason: format!("unparsable: {err}"),
            });
            return out;
        }
    };
    if library {
        let mut tests = TestSpans(Vec::new());
        if is_test_file(&file.attrs, library, crate_root) {
            let end = proc_macro2::LineColumn {
                line: usize::MAX,
                column: usize::MAX,
            };
            tests
                .0
                .push((proc_macro2::LineColumn { line: 1, column: 0 }, end));
        }
        tests.visit_file(&file);
        ProductionGlobs {
            tests: &tests,
            out: &mut out,
        }
        .visit_file(&file);
        function_items::check(&file, path, data, &tests, &mut out);
        scan_debug_and_hash(stream.clone(), &tests, false, &mut out);
        let mut env_count = 0;
        scan_format_sources(stream.clone(), &mut env_count, &mut out);
        let mut version = VersionEnv { allowed: 0 };
        version.visit_file(&file);
        if env_count != version.allowed {
            out.push(Finding {
                line: 0,
                reason: format!(
                    "env other than const VERSION: &str = env!(\"CARGO_PKG_VERSION\") ({env_count} env tokens, {} allowed)",
                    version.allowed
                ),
            });
        }
    }
    let mut cfg_count = 0;
    scan_tokens(stream, &mut cfg_count, &mut out);
    let mut attrs = AttrCheck {
        allowed_cfg: 0,
        out: &mut out,
    };
    attrs.visit_file(&file);
    let allowed_cfg = attrs.allowed_cfg;
    if addresses && !is_test_file(&file.attrs, library, crate_root) {
        let mut fns = FnNames(Vec::new());
        fns.visit_file(&file);
        Addresses {
            fns: fns.0,
            out: &mut out,
        }
        .visit_file(&file);
    }
    if crate_root {
        check_crate_root(&file.attrs, &mut out);
    }
    if cfg_count != allowed_cfg {
        out.push(Finding {
            line: 0,
            reason: format!(
                "cfg token outside #[cfg(test)] attribute ({cfg_count} cfg tokens, {allowed_cfg} #[cfg(test)])"
            ),
        });
    }
    out
}
