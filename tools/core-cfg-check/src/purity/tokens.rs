//! Token and attribute rules for every file of the default mode: `cfg`,
//! `cfg_attr`, `include`, `macro_rules`, `#[path]`, `feature`, `extern crate
//! std`, `static` items, atomics and HIDDEN_STATE, `concat` and `stringify`.
//! The token scan counts `cfg` identifiers and the attribute walk counts
//! `#[cfg(test)]` attributes; `check` compares the two counts.

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use crate::test_scope::is_test_args;
use crate::{Finding, is_ident, is_path_attr_group, is_punct, line_of, unraw};

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
pub(super) fn scan_tokens(stream: TokenStream, cfg_count: &mut usize, out: &mut Vec<Finding>) {
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
pub(super) struct AttrCheck<'a> {
    pub(super) allowed_cfg: usize,
    pub(super) out: &'a mut Vec<Finding>,
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
                let only_test = is_test_args(&attr.meta);
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
