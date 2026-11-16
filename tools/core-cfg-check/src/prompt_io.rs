//! `--prompt-io NAMES FILE.rs` scans every OS bridge branch for CLI forbidden
//! calls; this supplements its binary scan, clippy forbid and TCB hash.

use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use crate::{Finding, is_path_attr_group, is_punct, line_of, unraw};

/// The OS bridge deliberately has platform cfg, atomics and pointer arguments.
/// Scan *all* branches (including test code), with no cfg evaluation, for the
/// CLI's forbidden call names and syntax that could conceal/generate them.
/// This adds a scan; it does not replace --binary, clippy forbid or TCB pins.
pub(super) fn check_prompt_io(source: &str, names: &[&str]) -> Vec<Finding> {
    struct Modules<'a>(&'a mut Vec<Finding>);
    impl<'ast> Visit<'ast> for Modules<'_> {
        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            if module.content.is_none() {
                self.0.push(Finding {
                    line: line_of(module.ident.span()),
                    reason: "prompt I/O out-of-line module escapes the scanned file".to_owned(),
                });
            }
            syn::visit::visit_item_mod(self, module);
        }
    }
    fn scan(stream: TokenStream, names: &[&str], out: &mut Vec<Finding>) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for (at, t) in tokens.iter().enumerate() {
            if is_punct(Some(t), '#') {
                let next = at
                    + if is_punct(tokens.get(at + 1), '!') {
                        2
                    } else {
                        1
                    };
                if is_path_attr_group(tokens.get(next)) {
                    out.push(Finding {
                        line: line_of(t.span()),
                        reason: "prompt I/O #[path] escapes the scanned file".to_owned(),
                    });
                }
            }
            match t {
                TokenTree::Group(g) => scan(g.stream(), names, out),
                TokenTree::Ident(n)
                    if names.contains(&unraw(n).as_str())
                        || ["include", "macro_rules", "cfg_attr"].contains(&unraw(n).as_str()) =>
                {
                    out.push(Finding {
                        line: line_of(n.span()),
                        reason: format!("prompt I/O forbidden token {}", unraw(n)),
                    });
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    // Parse and lex the same source. A shebang is never valid in this TCB file.
    let parsed = syn::parse_file(source);
    if (source.starts_with("#!") && !source.starts_with("#![")) || parsed.is_err() {
        out.push(Finding {
            line: 1,
            reason: "prompt I/O unparsable or shebang".to_owned(),
        });
        return out;
    }
    // Inline linux/tests modules remain in this token stream, even behind cfg.
    Modules(&mut out).visit_file(&parsed.expect("parsed prompt I/O"));
    match TokenStream::from_str(source) {
        Ok(stream) => scan(stream, names, &mut out),
        Err(e) => out.push(Finding {
            line: line_of(e.span()),
            reason: "prompt I/O unparsable".to_owned(),
        }),
    }
    out
}
