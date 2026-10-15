//! Token-level conditional-compilation and pull-in check for bingsu-core.
//!
//! Usage: `core-cfg-check FILE.rs... [--test-targets FILE.rs...] [--tcb FILE.rs...]`
//! (scripts/check_core_cfg.py collects the files and passes them here; the
//! files after `--test-targets`, core's tests/ and benches/, skip only the
//! format-source rule below; the files after `--tcb`, the prompt adapter,
//! get the rules that hold for every file but not the library-only ones,
//! the address rule and the crate-root rule: the adapter hands buffers to
//! write(2), takes a function pointer and reads its arguments through
//! `std::env`).
//!
//! Code behind `cfg` can drop out of the lint run, and `#[path]` or
//! `include!` can pull code in from outside the checked file set. A text or
//! regex check misses spacing, line breaks, comments and strings, so this
//! looks at the Rust tokens instead. Every file fails on:
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
//!     ADDRESS_APIS, `core::ptr` other than `ptr::eq`,
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
//!   - in a library file named `lib.rs` (the crate root), a missing inner
//!     attribute `#![no_std]` or `#![forbid(unsafe_code)]`, read by the
//!     parser so a commented-out or quoted copy does not count.
//!
//! `core-cfg-check --binary FILE.rs...` checks every source file of the
//! `bingsu` binary crate instead (scripts/check_cli_prompt_forbid.py):
//! nothing may run outside `fn main`, and `main` only dispatches. Every file
//! fails on an identifier `global_allocator`, `link_section`, `export_name`,
//! `no_mangle`, `ctor` or `global_asm` anywhere (a custom allocator or a
//! linker constructor runs code before or around main), on `#[path]` and
//! `include` (code from outside the checked files), on a declaration named
//! `libc`, `std`, `core`, `alloc` or `front` (an item, a generic, a use
//! rename, or an import other than `use bingsu_core::front`: the adapter's
//! paths must mean the real crates), on an `impl` for a type of the prompt
//! adapter, and on source that does not parse. Over all files there must be
//! exactly one `fn main`, at the top of a file `main.rs`, with no attribute
//! and the body `commands::run(prompt::dispatch(sandbox::enter))`: the
//! prompt adapter is the first code that runs, and on Linux it installs the
//! seccomp filter before the core sees the arguments.
//!
//! `core-cfg-check --adapter SYSCALLS.tsv FILE.rs` checks the prompt adapter
//! (see adapter.rs).
//! Raw identifiers (`r#cfg`) are compared without the `r#` prefix, since
//! rustc treats `#[r#cfg(..)]` and `#[r#path = ..]` as the real attributes.
//!
//! The parser and the lexer see the same text: the shebang line syn strips
//! is stripped before lexing too. Otherwise a
//! first line `#!x /*` would open a block comment for the lexer only, and the
//! code after it would reach rustc unchecked.

use std::process::ExitCode;
use std::str::FromStr;

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::Visit;

mod adapter;

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

/// Names that keep state between calls without an atomic or a static:
/// leaked allocations stay in the allocator (`forget`, `ManuallyDrop`,
/// `MaybeUninit` never drops what it holds), `Arc` counts are atomics.
const HIDDEN_STATE: [&str; 6] = [
    "forget",
    "ManuallyDrop",
    "MaybeUninit",
    "Arc",
    "strong_count",
    "weak_count",
];

/// Walks every token (into groups) and counts `cfg` identifiers.
fn scan_tokens(stream: TokenStream, cfg_count: &mut usize, out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        if is_ident(Some(token), "extern")
            && is_ident(tokens.get(i + 1), "crate")
            && is_ident(tokens.get(i + 2), "std")
        {
            out.push(Finding {
                line: line_of(token.span()),
                reason: "extern crate std brings std back into no_std core".to_owned(),
            });
        }
        match token {
            TokenTree::Group(group) => scan_tokens(group.stream(), cfg_count, out),
            TokenTree::Punct(punct) if punct.as_char() == '#' => {
                let next = if is_punct(tokens.get(i + 1), '!') {
                    i + 2
                } else {
                    i + 1
                };
                if is_path_attr_group(tokens.get(next)) {
                    out.push(Finding {
                        line: line_of(punct.span()),
                        reason: "#[path] tokens pull in code".to_owned(),
                    });
                }
            }
            TokenTree::Ident(ident) => {
                let name = unraw(ident);
                if name == "atomic" || name.starts_with("Atomic") {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "atomics keep state between calls".to_owned(),
                    });
                }
                if HIDDEN_STATE.contains(&name.as_str()) {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: format!("{name} keeps state between calls"),
                    });
                }
                if name == "cfg" {
                    *cfg_count += 1;
                } else if name == "cfg_attr" {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "cfg_attr".to_owned(),
                    });
                } else if name == "include" {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "include pulls in code".to_owned(),
                    });
                } else if name == "macro_rules" {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "macro_rules forbidden in core".to_owned(),
                    });
                } else if (name == "concat" || name == "stringify")
                    && !(i > 0 && is_punct(tokens.get(i - 1), '.'))
                {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: format!("{name} builds a format string out of pieces"),
                    });
                }
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// Checks every attribute the parser sees.
struct AttrCheck<'a> {
    allowed_cfg: usize,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for AttrCheck<'_> {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if let Some(ident) = attr.path().get_ident() {
            let name = unraw(ident);
            if name == "path" {
                self.out.push(Finding {
                    line: line_of(ident.span()),
                    reason: "path attribute pulls in code".to_owned(),
                });
            } else if name == "feature" {
                self.out.push(Finding {
                    line: line_of(ident.span()),
                    reason: "feature attribute enables unstable language items".to_owned(),
                });
            } else if name == "cfg" {
                let only_test = matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string() == "test");
                if only_test {
                    self.allowed_cfg += 1;
                } else {
                    self.out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "cfg other than #[cfg(test)]".to_owned(),
                    });
                }
            }
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.out.push(Finding {
            line: line_of(item.ident.span()),
            reason: "static item keeps state between calls".to_owned(),
        });
        syn::visit::visit_item_static(self, item);
    }
}

/// Names whose call or path exposes an address or leaks an allocation.
const ADDRESS_APIS: [&str; 15] = [
    "into_raw",
    "into_raw_parts",
    "leak",
    "as_ptr",
    "as_mut_ptr",
    "addr",
    "expose_provenance",
    "expose_addr",
    "addr_of",
    "addr_of_mut",
    "NonNull",
    "Pointer",
    "as_ptr_range",
    "as_mut_ptr_range",
    "UnsafeCell",
];

/// Names of every function and method defined in the file.
struct FnNames(Vec<String>);

impl<'ast> Visit<'ast> for FnNames {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.0.push(unraw(&f.sig.ident));
        syn::visit::visit_item_fn(self, f);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.0.push(unraw(&f.sig.ident));
        syn::visit::visit_impl_item_fn(self, f);
    }
}

/// The address checks on tokens, for macro bodies: names in ADDRESS_APIS,
/// `*const`/`*mut`, a `fn(` type, `ptr` as a path segment other than
/// `ptr::eq`, `name as` for a function of the file, and string literals
/// that format a pointer.
fn macro_addresses(stream: TokenStream, fns: &[String], out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        let reason = match token {
            TokenTree::Group(group) => {
                macro_addresses(group.stream(), fns, out);
                None
            }
            TokenTree::Literal(lit) => {
                matches!(syn::Lit::new(lit.clone()), syn::Lit::Str(s) if formats_pointer(&s.value()))
                    .then(|| "{:p} formats an address".to_owned())
            }
            TokenTree::Punct(p) if p.as_char() == '*' => (is_ident(tokens.get(i + 1), "const")
                || is_ident(tokens.get(i + 1), "mut"))
            .then(|| "raw pointer type exposes an address".to_owned()),
            TokenTree::Punct(_) => None,
            TokenTree::Ident(ident) => {
                let name = unraw(ident);
                let in_path = (i >= 1 && is_punct(tokens.get(i - 1), ':'))
                    || is_punct(tokens.get(i + 1), ':');
                if ADDRESS_APIS.contains(&name.as_str()) {
                    Some(format!("{name} exposes an address"))
                } else if name == "fn" && matches!(tokens.get(i + 1), Some(TokenTree::Group(_))) {
                    Some("function pointer type exposes an address".to_owned())
                } else if name == "ptr" && in_path && !is_ident(tokens.get(i + 3), "eq") {
                    Some("core::ptr other than ptr::eq exposes an address".to_owned())
                } else if fns.contains(&name) && is_ident(tokens.get(i + 1), "as") {
                    Some(format!("casting function {name} exposes its address"))
                } else {
                    None
                }
            }
        };
        if let Some(reason) = reason {
            out.push(Finding {
                line: line_of(token.span()),
                reason,
            });
        }
    }
}

/// True if `text`, read as a format string, has a placeholder whose type is
/// `p`, with any fill, alignment, sign, `#`, `0`, width or precision
/// (`{:p}`, `{v:#p}`, `{:>20p}`, `{0:w$.*p}`). A placeholder counts only when
/// its argument (empty, an integer or an identifier) and its spec follow
/// the std::fmt grammar, so template text such as `{@icon:frame.top}` is not
/// one. A fill character comes before an alignment and may itself be `{` or
/// `}`; `{{` is a literal brace.
fn formats_pointer(text: &str) -> bool {
    formats_type(text, |t| t == "p")
}

/// True if `text`, read as a format string, has a Debug placeholder
/// (`{:?}`, `{v:#?}`, `{:x?}`: a type that ends in `?`), with the same
/// grammar as formats_pointer.
fn formats_debug(text: &str) -> bool {
    formats_type(text, |t| t.ends_with('?'))
}

/// True if a placeholder of `text` has a type for which `wanted` holds.
fn formats_type(text: &str, wanted: fn(&str) -> bool) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        if chars.get(i + 1) == Some(&'{') {
            i += 2;
            continue;
        }
        let mut j = i + 1;
        while j < chars.len() && chars[j] != ':' && chars[j] != '}' {
            j += 1;
        }
        if chars.get(j) != Some(&':') {
            i = j + 1;
            continue;
        }
        let mut k = j + 1;
        if matches!(chars.get(k + 1), Some('<' | '^' | '>')) {
            k += 2;
        }
        while k < chars.len() && chars[k] != '}' {
            k += 1;
        }
        let arg: String = chars[i + 1..j].iter().collect();
        let arg = arg.trim_end();
        let arg_ok = arg.is_empty()
            || arg.chars().all(|c| c.is_ascii_digit())
            || ident_len(&arg.chars().collect::<Vec<_>>(), 0) == arg.chars().count();
        if arg_ok && wanted(&spec_type(&chars[j + 1..k.min(chars.len())])) {
            return true;
        }
        i = k + 1;
    }
    false
}

/// Length of the identifier that starts at `at` (0 if none).
fn ident_len(s: &[char], at: usize) -> usize {
    match s.get(at) {
        Some(c) if c.is_alphabetic() || *c == '_' => {
            1 + s[at + 1..]
                .iter()
                .take_while(|c| c.is_alphanumeric() || **c == '_')
                .count()
        }
        _ => 0,
    }
}

/// A count at `at`: an integer, or an integer or identifier followed by `$`.
/// Returns the position after it (`at` itself when there is none).
fn count_end(s: &[char], at: usize) -> usize {
    let digits = s[at.min(s.len())..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    if digits > 0 {
        return at + digits + usize::from(s.get(at + digits) == Some(&'$'));
    }
    let ident = ident_len(s, at);
    if ident > 0 && s.get(at + ident) == Some(&'$') {
        return at + ident + 1;
    }
    at
}

/// The type of a std::fmt spec (the text after `:`): what is left after
/// `[[fill]align][sign]['#']['0'][width]['.' [precision]]`. Only a type of
/// exactly `p` matters to the caller, so other leftovers need no checking.
fn spec_type(s: &[char]) -> String {
    let mut k = if matches!(s.get(1), Some('<' | '^' | '>')) {
        2
    } else {
        usize::from(matches!(s.first(), Some('<' | '^' | '>')))
    };
    if matches!(s.get(k), Some('+' | '-')) {
        k += 1;
    }
    if s.get(k) == Some(&'#') {
        k += 1;
    }
    if s.get(k) == Some(&'0') && s.get(k + 1) != Some(&'$') {
        k += 1;
    }
    k = count_end(s, k);
    if s.get(k) == Some(&'.') {
        k += 1;
        // rustc also takes `.` with no precision (`{x:.p}` formats a pointer).
        if s.get(k) == Some(&'*') {
            k += 1;
        } else {
            k = count_end(s, k);
        }
    }
    let rest: String = s[k.min(s.len())..].iter().collect();
    rest.trim_end().to_owned()
}

/// Address-to-value checks, outside `#[cfg(test)]` items.
struct Addresses<'a> {
    fns: Vec<String>,
    out: &'a mut Vec<Finding>,
}

fn is_test_item(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        matches!(&a.meta, syn::Meta::List(l)
        if l.path.is_ident("cfg") && l.tokens.to_string() == "test")
    })
}

impl<'ast> Visit<'ast> for Addresses<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Mod(m) => &m.attrs,
            syn::Item::Fn(f) => &f.attrs,
            syn::Item::Impl(i) => &i.attrs,
            _ => return syn::visit::visit_item(self, item),
        };
        if !is_test_item(attrs) {
            syn::visit::visit_item(self, item);
        }
    }
    fn visit_type_fn_ptr(&mut self, t: &'ast syn::TypeFnPtr) {
        self.out.push(Finding {
            line: line_of(t.fn_token.span),
            reason: "function pointer type exposes an address".to_owned(),
        });
        syn::visit::visit_type_fn_ptr(self, t);
    }
    fn visit_expr_cast(&mut self, c: &'ast syn::ExprCast) {
        let mut inner = &*c.expr;
        while let syn::Expr::Paren(p) = inner {
            inner = &p.expr;
        }
        if let syn::Expr::Path(e) = inner
            && let Some(f) = e.path.get_ident()
            && self.fns.contains(&unraw(f))
        {
            self.out.push(Finding {
                line: line_of(f.span()),
                reason: format!("casting function {} exposes its address", unraw(f)),
            });
        }
        syn::visit::visit_expr_cast(self, c);
    }
    fn visit_type_ptr(&mut self, t: &'ast syn::TypePtr) {
        self.out.push(Finding {
            line: line_of(t.star_token.span),
            reason: "raw pointer type exposes an address".to_owned(),
        });
        syn::visit::visit_type_ptr(self, t);
    }
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let name = unraw(&m.method);
        if ADDRESS_APIS.contains(&name.as_str()) {
            self.out.push(Finding {
                line: line_of(m.method.span()),
                reason: format!("{name} exposes an address"),
            });
        }
        syn::visit::visit_expr_method_call(self, m);
    }
    fn visit_path(&mut self, path: &'ast syn::Path) {
        // core::ptr: only ptr::eq (compares two addresses, exposes neither).
        let segs: Vec<String> = path.segments.iter().map(|s| unraw(&s.ident)).collect();
        if let Some(at) = segs.iter().position(|s| s == "ptr")
            && segs.get(at + 1).map(String::as_str) != Some("eq")
        {
            self.out.push(Finding {
                line: line_of(path.segments[at].ident.span()),
                reason: "core::ptr other than ptr::eq exposes an address".to_owned(),
            });
        }
        syn::visit::visit_path(self, path);
    }
    fn visit_path_segment(&mut self, seg: &'ast syn::PathSegment) {
        let name = unraw(&seg.ident);
        if ADDRESS_APIS.contains(&name.as_str()) {
            self.out.push(Finding {
                line: line_of(seg.ident.span()),
                reason: format!("{name} exposes an address"),
            });
        }
        syn::visit::visit_path_segment(self, seg);
    }
    fn visit_lit_str(&mut self, l: &'ast syn::LitStr) {
        if formats_pointer(&l.value()) {
            self.out.push(Finding {
                line: line_of(l.span()),
                reason: "{:p} formats an address".to_owned(),
            });
        }
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        // Macro bodies are tokens, which syn does not parse.
        macro_addresses(m.tokens.clone(), &self.fns, self.out);
        syn::visit::visit_macro(self, m);
    }
}

/// Identifiers that bring a string in from outside the library source.
const FORMAT_SOURCES: [&str; 3] = ["include_str", "include_bytes", "option_env"];

/// Walks every token (into groups): reports FORMAT_SOURCES and counts `env`.
fn scan_format_sources(stream: TokenStream, env_count: &mut usize, out: &mut Vec<Finding>) {
    for token in stream {
        match token {
            TokenTree::Group(group) => scan_format_sources(group.stream(), env_count, out),
            TokenTree::Ident(ident) => {
                let name = unraw(&ident);
                if FORMAT_SOURCES.contains(&name.as_str()) {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: format!("{name} brings a string in from outside the source"),
                    });
                } else if name == "env" {
                    *env_count += 1;
                }
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// Counts the one allowed use of `env`:
/// `const VERSION: &str = env!("CARGO_PKG_VERSION");`.
struct VersionEnv {
    allowed: usize,
}

impl<'ast> Visit<'ast> for VersionEnv {
    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if let syn::Expr::Macro(m) = &*item.expr
            && item.ident == "VERSION"
            && m.mac.path.is_ident("env")
            && m.mac.tokens.to_string() == "\"CARGO_PKG_VERSION\""
        {
            self.allowed += 1;
        }
        syn::visit::visit_item_const(self, item);
    }
}

/// Names through which a value's Debug output or hash reaches the program:
/// a Debug or Hash implementation may write an address (a Waker's vtable,
/// a function pointer), so production code may not call them.
/// `#[derive(Debug)]` stays allowed: with no Debug format, no `Debug` name
/// and no debug builder outside it, nothing can call the derived impl.
const DEBUG_AND_HASH: [&str; 10] = [
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
];

/// Start and end of every item, impl item and trait item marked
/// `#[cfg(test)]`, at any depth: the production code is everything else.
struct TestSpans(Vec<(proc_macro2::LineColumn, proc_macro2::LineColumn)>);

impl TestSpans {
    fn push(&mut self, attrs: &[syn::Attribute], node: &dyn syn::spanned::Spanned) -> bool {
        if is_test_item(attrs) {
            let span = node.span();
            self.0.push((span.start(), span.end()));
            return true;
        }
        false
    }
    fn contains(&self, span: Span) -> bool {
        let at = span.start();
        let key = |l: proc_macro2::LineColumn| (l.line, l.column);
        self.0
            .iter()
            .any(|(s, e)| key(*s) <= key(at) && key(at) <= key(*e))
    }
}

impl<'ast> Visit<'ast> for TestSpans {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::ExternCrate(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::ForeignMod(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::TraitAlias(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Union(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[],
        };
        if !self.push(attrs, item) {
            syn::visit::visit_item(self, item);
        }
    }
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !self.push(attrs, item) {
            syn::visit::visit_impl_item(self, item);
        }
    }
    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::TraitItem::Const(i) => &i.attrs,
            syn::TraitItem::Fn(i) => &i.attrs,
            syn::TraitItem::Type(i) => &i.attrs,
            syn::TraitItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !self.push(attrs, item) {
            syn::visit::visit_trait_item(self, item);
        }
    }
}

/// Production tokens of a library file (outside TestSpans): DEBUG_AND_HASH
/// names (`Debug` allowed inside `#[derive(..)]`) and Debug placeholders.
fn scan_debug_and_hash(
    stream: TokenStream,
    tests: &TestSpans,
    in_derive: bool,
    out: &mut Vec<Finding>,
) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        if tests.contains(token.span()) {
            continue;
        }
        match token {
            TokenTree::Group(group) => {
                let derive = i >= 1
                    && is_punct(tokens.get(i - 1), '#')
                    && is_ident(group.stream().into_iter().next().as_ref(), "derive");
                scan_debug_and_hash(group.stream(), tests, in_derive || derive, out);
            }
            TokenTree::Ident(ident) => {
                let name = unraw(ident);
                if DEBUG_AND_HASH.contains(&name.as_str()) && !(in_derive && name == "Debug") {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: format!("{name} may write an address (Debug and Hash stay out of production code)"),
                    });
                }
            }
            TokenTree::Literal(lit) => {
                if matches!(syn::Lit::new(lit.clone()), syn::Lit::Str(s) if formats_debug(&s.value()))
                {
                    out.push(Finding {
                        line: line_of(lit.span()),
                        reason:
                            "{:?} may write an address (Debug and Hash stay out of production code)"
                                .to_owned(),
                    });
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}

/// The crate root must keep `#![no_std]` and `#![forbid(unsafe_code)]` as
/// real inner attributes.
fn check_crate_root(attrs: &[syn::Attribute], out: &mut Vec<Finding>) {
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

fn check(source: &str, library: bool, crate_root: bool, addresses: bool) -> Vec<Finding> {
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
        tests.visit_file(&file);
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
    if addresses {
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

const BINARY_FORBIDDEN: [&str; 6] = [
    "global_allocator",
    "link_section",
    "export_name",
    "no_mangle",
    "ctor",
    "global_asm",
];

const MAIN_BODY: &str = "commands::run(prompt::dispatch(sandbox::enter))";

/// Every `fn main` the parser sees, at any depth: (line, top level, attrs,
/// body tokens).
struct Mains<'a> {
    depth: usize,
    found: &'a mut Vec<(usize, bool, usize, String)>,
}

impl<'ast> Visit<'ast> for Mains<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.sig.ident == "main" {
            let body = match f.block.stmts.as_slice() {
                [syn::Stmt::Expr(e, None)] => quote_tokens(e),
                _ => String::new(),
            };
            self.found.push((
                line_of(f.sig.ident.span()),
                self.depth == 0,
                f.attrs.len(),
                body,
            ));
        }
        self.depth += 1;
        syn::visit::visit_item_fn(self, f);
        self.depth -= 1;
    }
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        self.depth += 1;
        syn::visit::visit_item_mod(self, m);
        self.depth -= 1;
    }
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        self.depth += 1;
        syn::visit::visit_item_impl(self, i);
        self.depth -= 1;
    }
}

/// The source text of `e` without whitespace (comments inside it stay and
/// so fail the comparison).
fn quote_tokens(e: &syn::Expr) -> String {
    use syn::spanned::Spanned;
    e.span()
        .source_text()
        .unwrap_or_default()
        .split_whitespace()
        .collect()
}

/// The `--binary` check over all files: one `fn main` of the right shape.
fn check_main(files: &[(String, String)]) -> Vec<(String, Finding)> {
    let mut out = Vec::new();
    let mut all = Vec::new();
    for (path, source) in files {
        let Ok(file) = syn::parse_file(source.strip_prefix('\u{feff}').unwrap_or(source)) else {
            continue; // reported by check_binary
        };
        let mut found = Vec::new();
        Mains {
            depth: 0,
            found: &mut found,
        }
        .visit_file(&file);
        all.extend(found.into_iter().map(|m| (path.clone(), m)));
    }
    match all.as_slice() {
        [(path, (line, top, attrs, body))] => {
            if std::path::Path::new(path).file_name() != Some(std::ffi::OsStr::new("main.rs"))
                || !*top
                || *attrs != 0
                || body != MAIN_BODY
            {
                out.push((
                    path.clone(),
                    Finding {
                        line: *line,
                        reason: format!("fn main must be top level in main.rs, without attributes, with the body `{MAIN_BODY}`"),
                    },
                ));
            }
        }
        _ => out.push((
            String::from("(all files)"),
            Finding {
                line: 0,
                reason: format!("expected exactly one fn main, found {}", all.len()),
            },
        )),
    }
    out
}

fn scan_binary_tokens(stream: TokenStream, out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        if let TokenTree::Punct(punct) = token
            && punct.as_char() == '#'
        {
            let next = if is_punct(tokens.get(i + 1), '!') {
                i + 2
            } else {
                i + 1
            };
            if is_path_attr_group(tokens.get(next)) {
                out.push(Finding {
                    line: line_of(punct.span()),
                    reason: "#[path] pulls in code from outside the checked files".to_owned(),
                });
            }
        }
        if is_ident(Some(token), "include") {
            out.push(Finding {
                line: line_of(token.span()),
                reason: "include pulls in code from outside the checked files".to_owned(),
            });
        }
        match token.clone() {
            TokenTree::Group(group) => scan_binary_tokens(group.stream(), out),
            TokenTree::Ident(ident) if BINARY_FORBIDDEN.contains(&unraw(&ident).as_str()) => out
                .push(Finding {
                    line: line_of(ident.span()),
                    reason: format!("{} runs code outside main", unraw(&ident)),
                }),
            _ => {}
        }
    }
}

/// Names the prompt adapter's paths start with (`libc::`, `std::`,
/// `front::` …). No file of the binary may declare one of them, so such a
/// path always means the real crate or the one `use bingsu_core::front`.
const RESERVED: [&str; 5] = ["libc", "std", "core", "alloc", "front"];

struct Decls<'a> {
    out: &'a mut Vec<Finding>,
}

impl Decls<'_> {
    fn name(&mut self, ident: &proc_macro2::Ident, what: &str) {
        let name = unraw(ident);
        if RESERVED.contains(&name.as_str()) {
            self.out.push(Finding {
                line: line_of(ident.span()),
                reason: format!("{what} named {name} shadows a reserved root"),
            });
        }
    }
}

impl<'ast> Visit<'ast> for Decls<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let ident = match item {
            syn::Item::Const(i) => Some(&i.ident),
            syn::Item::Enum(i) => Some(&i.ident),
            syn::Item::Fn(i) => Some(&i.sig.ident),
            syn::Item::Mod(i) => Some(&i.ident),
            syn::Item::Static(i) => Some(&i.ident),
            syn::Item::Struct(i) => Some(&i.ident),
            syn::Item::Trait(i) => Some(&i.ident),
            syn::Item::TraitAlias(i) => Some(&i.ident),
            syn::Item::Type(i) => Some(&i.ident),
            syn::Item::Union(i) => Some(&i.ident),
            syn::Item::Macro(i) => i.ident.as_ref(),
            syn::Item::ExternCrate(i) => i.rename.as_ref().map(|(_, r)| r),
            _ => None,
        };
        if let Some(ident) = ident {
            self.name(ident, "an item");
        }
        if let syn::Item::Impl(i) = item {
            let ty = i.self_ty.to_token_stream_string();
            if ty.contains("prompt") || ty.contains("NonPromptArgs") {
                self.out.push(Finding {
                    line: line_of(i.impl_token.span),
                    reason: "impl for a type of the prompt adapter".to_owned(),
                });
            }
        }
        syn::visit::visit_item(self, item);
    }
    fn visit_generic_param(&mut self, g: &'ast syn::GenericParam) {
        match g {
            syn::GenericParam::Type(t) => self.name(&t.ident, "a generic"),
            syn::GenericParam::Const(c) => self.name(&c.ident, "a generic"),
            syn::GenericParam::Lifetime(_) => {}
        }
        syn::visit::visit_generic_param(self, g);
    }
    fn visit_use_rename(&mut self, r: &'ast syn::UseRename) {
        self.name(&r.rename, "a use rename");
        syn::visit::visit_use_rename(self, r);
    }
}

trait SourceText {
    fn to_token_stream_string(&self) -> String;
}

impl SourceText for syn::Type {
    fn to_token_stream_string(&self) -> String {
        use syn::spanned::Spanned;
        self.span().source_text().unwrap_or_default()
    }
}

/// Imports of a reserved name: only `use bingsu_core::front;` may bring one in.
fn reserved_imports(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<Finding>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(unraw(&p.ident));
            reserved_imports(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let name = unraw(&n.ident);
            let full = [prefix.join("::"), name.clone()].join("::");
            if RESERVED.contains(&name.as_str())
                && !prefix.is_empty()
                && full != "bingsu_core::front"
            {
                out.push(Finding {
                    line: line_of(n.ident.span()),
                    reason: format!("use {full} brings in a name that shadows a reserved root"),
                });
            }
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                reserved_imports(t, prefix, out);
            }
        }
        syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
    }
}

struct Uses<'a> {
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for Uses<'_> {
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        reserved_imports(&u.tree, &mut Vec::new(), self.out);
    }
}

/// The `--binary` check of one file.
fn check_binary(source: &str) -> Vec<Finding> {
    let text = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut out = Vec::new();
    match syn::parse_file(text)
        .map_err(|e| e.span())
        .and_then(|file| {
            let body = match &file.shebang {
                Some(shebang) => &text[shebang.len()..],
                None => text,
            };
            TokenStream::from_str(body).map_err(|e| e.span())
        }) {
        Ok(stream) => scan_binary_tokens(stream, &mut out),
        Err(span) => out.push(Finding {
            line: line_of(span),
            reason: "unparsable".to_owned(),
        }),
    }
    if let Ok(file) = syn::parse_file(text) {
        Decls { out: &mut out }.visit_file(&file);
        Uses { out: &mut out }.visit_file(&file);
    }
    out
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let binary = args.first().is_some_and(|a| a == "--binary");
    if binary {
        args.remove(0);
    }
    if args.first().is_some_and(|a| a == "--adapter") {
        let [_, tsv, file] = args.as_slice() else {
            eprintln!("usage: core-cfg-check --adapter SYSCALLS.tsv FILE.rs");
            return ExitCode::FAILURE;
        };
        let (Ok(table), Ok(source)) = (std::fs::read_to_string(tsv), std::fs::read_to_string(file))
        else {
            eprintln!("core-cfg-check: unreadable {tsv} or {file}");
            return ExitCode::FAILURE;
        };
        let findings = adapter::check_adapter(&source, &table);
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
