//! Pin the RULES initializer and its consumer; no second syscall table.
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::{Finding, TestSpans, is_ident, is_punct, line_of, unraw};

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
    let mut tests = TestSpans(Vec::new());
    tests.visit_file(&file);
    // Scan tokens too: macro arguments can contain paths that syn won't visit.
    fn syscalls(
        stream: proc_macro2::TokenStream,
        tests: &TestSpans,
        initializer: &TestSpans,
        out: &mut Vec<Finding>,
    ) {
        use proc_macro2::TokenTree;
        fn syscall_tail(token: &TokenTree) -> bool {
            match token {
                TokenTree::Ident(n) => unraw(n).starts_with("SYS_"),
                // A group import still names libc::SYS_* paths.
                TokenTree::Group(g) if g.delimiter() == proc_macro2::Delimiter::Brace => {
                    g.stream().into_iter().any(|t| syscall_tail(&t))
                }
                _ => false,
            }
        }
        let tokens: Vec<_> = stream.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            if tests.contains(token.span()) || initializer.contains(token.span()) {
                continue;
            }
            if let TokenTree::Group(g) = token {
                syscalls(g.stream(), tests, initializer, out);
            }
            if is_ident(Some(token), "libc")
                && is_punct(tokens.get(i + 1), ':')
                && is_punct(tokens.get(i + 2), ':')
                && tokens.get(i + 3).is_some_and(syscall_tail)
            {
                out.push(Finding {
                    line: line_of(token.span()),
                    reason: "RULES: libc::SYS_* outside RULES initializer".to_owned(),
                });
            }
        }
    }
    match source.parse() {
        Ok(stream) => syscalls(
            stream,
            &tests,
            &TestSpans(vec![(rules.expr.span().start(), rules.expr.span().end())]),
            &mut out,
        ),
        Err(_) => fail(&mut out, file.span(), "unlexable sandbox"),
    }
    struct Consumers<'a> {
        tests: &'a TestSpans,
        functions: Vec<&'a syn::ItemFn>,
    }
    impl<'ast> Visit<'ast> for Consumers<'ast> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            if !self.tests.contains(item.span()) {
                syn::visit::visit_item(self, item);
            }
        }
        fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
            if f.sig.ident == "rules" {
                self.functions.push(f);
            }
            syn::visit::visit_item_fn(self, f);
        }
    }
    let mut consumers = Consumers {
        tests: &tests,
        functions: Vec::new(),
    };
    consumers.visit_file(&file);
    let pinned: syn::ItemFn = syn::parse_str(
        r#"fn rules() -> Vec<(u32, &'static [Cond])> {
            RULES.iter()
                .map(|&(_, nr, c)| (u32::try_from(nr).expect("syscall number"), c))
                .collect()
        }"#,
    )
    .expect("pinned rules function");
    let consumer = file.items.iter().find_map(|i| match i {
        syn::Item::Fn(f) if f.sig.ident == "rules" => Some(f),
        _ => None,
    });
    if !consumer.is_some_and(|f| {
        consumers.functions.len() == 1
            && f.attrs.iter().all(|a| a.path().is_ident("doc"))
            && f.sig == pinned.sig
            && f.block == pinned.block
    }) {
        fail(
            &mut out,
            file.span(),
            "rules() must use the pinned RULES.iter().map(...).collect() body",
        );
    }
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
