//! Token-level conditional-compilation and pull-in check for bingsu-core.
//!
//! Usage: `core-cfg-check FILE.rs...` (scripts/check_core_cfg.py collects the
//! files and passes them here).
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
//!     names it (include_str and include_bytes are different identifiers and
//!     stay allowed);
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
//!     static there is nowhere to keep it), and an identifier `atomic` or
//!     one starting with `Atomic`;
//!   - outside `#[cfg(test)]` items, anything that turns an address into a
//!     value (a leaked allocation's address would make the output depend on
//!     the allocator): a raw pointer type, a call or path named in
//!     ADDRESS_APIS, and a `{:p}` format.
//!
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
const ADDRESS_APIS: [&str; 12] = [
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
];

/// Address-to-value checks, outside `#[cfg(test)]` items.
struct Addresses<'a> {
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
        if l.value().contains(":p}") {
            self.out.push(Finding {
                line: line_of(l.span()),
                reason: "{:p} formats an address".to_owned(),
            });
        }
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        // Format strings sit in macro tokens, which syn does not parse.
        if m.tokens.to_string().contains(":p}") {
            self.out.push(Finding {
                line: line_of(syn::spanned::Spanned::span(&m.path)),
                reason: "{:p} formats an address".to_owned(),
            });
        }
        syn::visit::visit_macro(self, m);
    }
}

fn check(source: &str) -> Vec<Finding> {
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
    let mut cfg_count = 0;
    scan_tokens(stream, &mut cfg_count, &mut out);
    let mut attrs = AttrCheck {
        allowed_cfg: 0,
        out: &mut out,
    };
    attrs.visit_file(&file);
    let allowed_cfg = attrs.allowed_cfg;
    Addresses { out: &mut out }.visit_file(&file);
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

fn main() -> ExitCode {
    let files: Vec<String> = std::env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("core-cfg-check: no files");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for path in &files {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(err) => {
                eprintln!("{path}: unreadable: {err}");
                failed = true;
                continue;
            }
        };
        for finding in check(&source) {
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
