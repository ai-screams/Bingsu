//! Compare the actual RULES initializer, never tuples in comments or decoys.
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::{Finding, line_of};

pub(super) fn check(source: &str, table: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let fail = |out: &mut Vec<Finding>, span, reason: &str| {
        out.push(Finding {
            line: line_of(span),
            reason: format!("RULES: {reason}"),
        })
    };
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(e) => {
            fail(&mut out, e.span(), "unparsable sandbox");
            return out;
        }
    };
    struct Count(usize);
    impl<'ast> Visit<'ast> for Count {
        fn visit_item_const(&mut self, c: &'ast syn::ItemConst) {
            if c.ident == "RULES" {
                self.0 += 1;
            }
            syn::visit::visit_item_const(self, c);
        }
    }
    let mut count = Count(0);
    count.visit_file(&file);
    let rules = file.items.iter().find_map(|i| match i {
        syn::Item::Const(c) if c.ident == "RULES" => Some(c),
        _ => None,
    });
    let Some(rules) =
        rules.filter(|c| count.0 == 1 && c.attrs.iter().all(|a| a.path().is_ident("doc")))
    else {
        fail(
            &mut out,
            file.span(),
            "expected one unconditional top-level const RULES",
        );
        return out;
    };
    let syn::Expr::Array(array) = rules.expr.as_ref() else {
        fail(
            &mut out,
            rules.expr.span(),
            "initializer must be a literal array",
        );
        return out;
    };
    let mut names = Vec::new();
    for expr in &array.elems {
        let row = (|| {
            let syn::Expr::Tuple(t) = expr else {
                return None;
            };
            if !t.attrs.is_empty() || t.elems.len() != 3 {
                return None;
            }
            let syn::Expr::Lit(lit) = &t.elems[0] else {
                return None;
            };
            let syn::Lit::Str(name) = &lit.lit else {
                return None;
            };
            let syn::Expr::Path(number) = &t.elems[1] else {
                return None;
            };
            let segments: Vec<_> = number.path.segments.iter().collect();
            if number.qself.is_some()
                || segments.len() != 2
                || segments[0].ident != "libc"
                || segments[1].ident != format!("SYS_{}", name.value())
                || segments.iter().any(|s| !s.arguments.is_empty())
            {
                return None;
            }
            Some(name.value())
        })();
        if let Some(name) = row {
            names.push(name);
        } else {
            fail(
                &mut out,
                expr.span(),
                "entry must be (\"name\", libc::SYS_name, conditions)",
            );
        }
    }
    let mut expected: Vec<_> = table
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .skip(1)
        .filter_map(|l| l.split('\t').next())
        .filter(|name| *name != "-")
        .map(str::to_owned)
        .collect();
    names.sort();
    expected.sort();
    if names != expected {
        fail(
            &mut out,
            rules.span(),
            &format!("initializer names {names:?} differ from syscall column {expected:?}"),
        );
    }
    out
}
