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
//!     catches `cfg!()`, cfg inside macro bodies and any other spot.
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

/// Walks every token (into groups) and counts `cfg` identifiers.
fn scan_tokens(stream: TokenStream, cfg_count: &mut usize, out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
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
