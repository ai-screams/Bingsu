//! `--identity FILE.rs` checks the shared no_std identity root. Its only
//! generated input is the exact build_id.rs include from the pinned builder.
//! Outside that include, the identifiers `include`, `include_str`,
//! `include_bytes`, `env`, `option_env` and `macro_rules` are refused everywhere.

use std::str::FromStr;

use proc_macro2::{Span, TokenStream, TokenTree};

use crate::purity::check_crate_root;
use crate::{Finding, line_of, unraw};

pub(super) fn check_identity(source: &str) -> Vec<Finding> {
    use syn::spanned::Spanned;

    let mut out = Vec::new();
    let Ok(file) = syn::parse_file(source) else {
        return vec![Finding {
            line: 1,
            reason: "unparsable identity".into(),
        }];
    };
    check_crate_root(&file.attrs, &mut out);
    // Hash pins cover the implementation. Independently reject modules/imports
    // in any branch and accept only the one reviewed generated constant input.
    fn scan(stream: TokenStream, generated_input: Option<Span>, out: &mut Vec<Finding>) {
        for token in stream {
            // Only tokens of the reviewed top-level include are exempt. A
            // matching include nested in a function or macro still fails.
            if generated_input.is_some_and(|span| {
                token.span().start() >= span.start() && token.span().end() <= span.end()
            }) {
                continue;
            }
            match token {
                TokenTree::Ident(i) if matches!(unraw(&i).as_str(), "mod" | "use" | "extern") => {
                    out.push(Finding {
                        line: line_of(i.span()),
                        reason: "identity must not declare modules or imports".into(),
                    });
                }
                TokenTree::Ident(i)
                    if matches!(
                        unraw(&i).as_str(),
                        "include"
                            | "include_str"
                            | "include_bytes"
                            | "env"
                            | "option_env"
                            | "macro_rules"
                    ) =>
                {
                    out.push(Finding {
                        line: line_of(i.span()),
                        reason: format!(
                            "identity forbidden token {} outside build_id include",
                            unraw(&i)
                        ),
                    });
                }
                TokenTree::Group(g) => scan(g.stream(), None, out),
                _ => {}
            }
        }
    }
    let mut includes = 0;
    let mut generated_input = None;
    for item in &file.items {
        match item {
            syn::Item::Const(_) | syn::Item::Fn(_) => {}
            syn::Item::Macro(m)
                if m.attrs.is_empty()
                    && m.mac.path.is_ident("include")
                    && m.mac.tokens.to_string()
                        == "concat ! (env ! (\"OUT_DIR\") , \"/build_id.rs\")" =>
            {
                includes += 1;
                generated_input = Some(item.span());
            }
            _ => out.push(Finding {
                line: 1,
                reason: "identity allows only constants, functions and its build_id include".into(),
            }),
        }
    }
    if includes != 1 {
        generated_input = None;
        out.push(Finding {
            line: 1,
            reason: "identity requires exactly one build_id include".into(),
        });
    }
    let tokens = TokenStream::from_str(source).unwrap();
    scan(tokens, generated_input, &mut out);
    out
}
