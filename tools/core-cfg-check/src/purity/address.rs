//! The address rules, outside `#[cfg(test)]` items: raw and function pointer
//! types, casts of the file's functions, ADDRESS_APIS, `core::ptr` and `{:p}`,
//! on the syntax tree and on the tokens of macro bodies. `check` skips them
//! for the prompt adapter (`--tcb`) and for a test-only library file.

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use super::format_spec::formats_pointer;
use crate::test_scope::is_test_item;
use crate::{Finding, is_ident, is_punct, line_of, unraw};

/// Names whose call or path exposes an address or leaks an allocation.
// Known: revisit element_offset when the MSRV reaches 1.94; it reopens
// allocation identity without an explicit pointer type.
const ADDRESS_APIS: [&str; 16] = [
    "ptr_eq",
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
pub(super) struct FnNames(pub(super) Vec<String>);

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
/// `*const`/`*mut`, a `fn(` type, `ptr` as a path segment,
/// `name as` for a function of the file, and string literals
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
            TokenTree::Punct(p) if p.as_char() == '&' => (is_ident(tokens.get(i + 1), "raw")
                && (is_ident(tokens.get(i + 2), "const") || is_ident(tokens.get(i + 2), "mut")))
            .then(|| "raw borrow exposes an address or pointer identity".to_owned()),
            TokenTree::Punct(_) => None,
            TokenTree::Ident(ident) => {
                let name = unraw(ident);
                let in_path = (i >= 1 && is_punct(tokens.get(i - 1), ':'))
                    || is_punct(tokens.get(i + 1), ':');
                if ADDRESS_APIS.contains(&name.as_str()) {
                    Some(format!("{name} exposes an address"))
                } else if name == "fn" && matches!(tokens.get(i + 1), Some(TokenTree::Group(_))) {
                    Some("function pointer type exposes an address".to_owned())
                } else if name == "ptr" && in_path {
                    Some("core::ptr exposes an address or pointer identity".to_owned())
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

/// Address-to-value checks, outside `#[cfg(test)]` items.
pub(super) struct Addresses<'a> {
    pub(super) fns: Vec<String>,
    pub(super) out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for Addresses<'_> {
    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        let ident = match tree {
            syn::UseTree::Path(p) => Some(&p.ident),
            syn::UseTree::Name(n) => Some(&n.ident),
            syn::UseTree::Rename(r) => Some(&r.ident),
            _ => None,
        };
        if let Some(ident) = ident {
            let name = unraw(ident);
            if name == "ptr" || name == "ptr_eq" {
                self.out.push(Finding {
                    line: line_of(ident.span()),
                    reason: format!(
                        "{name} exposes an address or pointer identity through an import"
                    ),
                });
            }
        }
        syn::visit::visit_use_tree(self, tree);
    }
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
    fn visit_expr_raw_addr(&mut self, r: &'ast syn::ExprRawAddr) {
        self.out.push(Finding {
            line: line_of(r.and_token.span),
            reason: "raw borrow exposes an address or pointer identity".to_owned(),
        });
        syn::visit::visit_expr_raw_addr(self, r);
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
        // Equality still observes allocation identity without exposing a number.
        let segs: Vec<String> = path.segments.iter().map(|s| unraw(&s.ident)).collect();
        if let Some(at) = segs.iter().position(|s| s == "ptr") {
            self.out.push(Finding {
                line: line_of(path.segments[at].ident.span()),
                reason: "core::ptr exposes an address or pointer identity".to_owned(),
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
