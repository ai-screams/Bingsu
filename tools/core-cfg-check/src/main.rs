//! Token-level conditional-compilation and pull-in check for bingsu-core.
//!
//! Usage: `core-cfg-check FILE.rs...` (scripts/check_core_cfg.py collects the
//! files and passes them here).
//!
//! Code behind `cfg` can drop out of the lint run, and `#[path]` or
//! `include!` can pull code in from outside the checked file set. A text or
//! regex check misses spacing, line breaks, comments and strings, so this
//! looks at the Rust tokens instead. Every file fails on:
//!   - source that does not parse (it cannot be checked);
//!   - an identifier `cfg_attr` anywhere;
//!   - an identifier `include` followed by `!` (include_str and include_bytes
//!     are different identifiers and stay allowed);
//!   - an attribute named `path`;
//!   - a `cfg` attribute other than exactly `#[cfg(test)]`;
//!   - more `cfg` identifier tokens than `#[cfg(test)]` attributes, which
//!     catches `cfg!()`, cfg inside macro bodies and any other spot.
//!
//! Raw identifiers (`r#cfg`) are compared without the `r#` prefix, since
//! rustc treats `#[r#cfg(..)]` and `#[r#path = ..]` as the real attributes.

use std::process::ExitCode;
use std::str::FromStr;

use proc_macro2::{Span, TokenStream, TokenTree};
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

/// Walks every token (into groups) and counts `cfg` identifiers.
fn scan_tokens(stream: TokenStream, cfg_count: &mut usize, out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => scan_tokens(group.stream(), cfg_count, out),
            TokenTree::Ident(ident) => {
                let name = unraw(ident);
                if name == "cfg" {
                    *cfg_count += 1;
                } else if name == "cfg_attr" {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "cfg_attr".to_owned(),
                    });
                } else if name == "include"
                    && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
                {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: "include! pulls in code".to_owned(),
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
                    reason: "#[path] pulls in code".to_owned(),
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
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(err) => {
            out.push(Finding {
                line: line_of(err.span()),
                reason: format!("unparsable: {err}"),
            });
            return out;
        }
    };
    // Lex the original text, not the parsed tree, so nothing the parser
    // drops escapes the token scan.
    let stream = match TokenStream::from_str(source) {
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
