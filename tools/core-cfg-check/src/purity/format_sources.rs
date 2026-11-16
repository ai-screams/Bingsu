//! Library files take no string from outside the source: no FORMAT_SOURCES
//! identifier, and `env` only in `const VERSION`.

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use crate::{Finding, line_of, unraw};

/// Identifiers that bring a string in from outside the library source.
const FORMAT_SOURCES: [&str; 3] = ["include_str", "include_bytes", "option_env"];

/// Walks every token (into groups): reports FORMAT_SOURCES and counts `env`.
pub(super) fn scan_format_sources(
    stream: TokenStream,
    env_count: &mut usize,
    out: &mut Vec<Finding>,
) {
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
pub(super) struct VersionEnv {
    pub(super) allowed: usize,
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
