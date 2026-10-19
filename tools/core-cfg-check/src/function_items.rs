//! Function values may be called directly, but not passed as callbacks,
//! stored, returned or merged (two distinct items coerce to address-ordered
//! function pointers). Explicit function-pointer types/casts are gated too.
//! No type inference: qualified lowercase value paths and imported lowercase
//! names are conservatively functions; local bindings are tracked by scope.
use std::collections::BTreeSet;

use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::{Finding, TestSpans, line_of, unraw};

struct Names {
    free: BTreeSet<String>,
    associated: BTreeSet<String>,
    data: BTreeSet<String>,
    aliases: Vec<(String, String)>,
    constructors: BTreeSet<String>,
    imports: Vec<(String, String)>,
}
impl<'ast> Visit<'ast> for Names {
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        fn paths(tree: &syn::UseTree, prefix: &str, out: &mut Vec<(String, String)>) {
            match tree {
                syn::UseTree::Path(p) => {
                    paths(&p.tree, &format!("{prefix}{}::", unraw(&p.ident)), out)
                }
                syn::UseTree::Name(n) => {
                    out.push((format!("{prefix}{}", unraw(&n.ident)), unraw(&n.ident)))
                }
                syn::UseTree::Rename(r) => {
                    out.push((format!("{prefix}{}", unraw(&r.ident)), unraw(&r.rename)))
                }
                syn::UseTree::Group(g) => {
                    for t in &g.items {
                        paths(t, prefix, out);
                    }
                }
                syn::UseTree::Glob(_) => {}
            }
        }
        paths(&u.tree, "", &mut self.imports);
        syn::visit::visit_item_use(self, u);
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.free.insert(unraw(&f.sig.ident));
        syn::visit::visit_item_fn(self, f);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.associated.insert(unraw(&f.sig.ident));
        syn::visit::visit_impl_item_fn(self, f);
    }
    fn visit_use_name(&mut self, n: &'ast syn::UseName) {
        if unraw(&n.ident)
            .chars()
            .next()
            .is_some_and(char::is_lowercase)
            && n.ident != "self"
        {
            self.free.insert(unraw(&n.ident));
        }
    }
    fn visit_use_rename(&mut self, n: &'ast syn::UseRename) {
        if n.rename != "_" {
            self.aliases.push((unraw(&n.ident), unraw(&n.rename)));
        }
    }
    fn visit_item_enum(&mut self, e: &'ast syn::ItemEnum) {
        for v in &e.variants {
            if matches!(v.fields, syn::Fields::Unit) {
                self.data.insert(unraw(&v.ident));
            }
            if matches!(v.fields, syn::Fields::Unnamed(_)) {
                self.constructors
                    .insert(format!("{}::{}", unraw(&e.ident), unraw(&v.ident)));
            }
        }
        syn::visit::visit_item_enum(self, e);
    }
}

struct Bindings(Vec<String>);
impl<'ast> Visit<'ast> for Bindings {
    fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
        self.0.push(unraw(&p.ident));
        syn::visit::visit_pat_ident(self, p);
    }
}

struct Walk<'a> {
    names: Names,
    locals: Vec<String>,
    tests: &'a TestSpans,
    out: &'a mut Vec<Finding>,
}
impl Walk<'_> {
    fn bind(&mut self, pat: &syn::Pat) {
        let mut b = Bindings(Vec::new());
        b.visit_pat(pat);
        self.locals.extend(b.0);
    }
    // Only a bare path is a direct callee. Arrays, blocks, if/match, etc.
    // are visited normally so implicit pointer coercions cannot hide here.
    fn call_operand(&mut self, e: &syn::Expr) {
        match e {
            syn::Expr::Path(p) => self.visit_path(&p.path),
            syn::Expr::Paren(p) => self.call_operand(&p.expr),
            syn::Expr::Group(g) => self.call_operand(&g.expr),
            syn::Expr::Reference(r) => self.call_operand(&r.expr),
            _ => self.visit_expr(e),
        }
    }
}
impl<'ast> Visit<'ast> for Walk<'_> {
    fn visit_item(&mut self, i: &'ast syn::Item) {
        if !self.tests.contains(i.span()) {
            syn::visit::visit_item(self, i);
        }
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        let saved = std::mem::take(&mut self.locals);
        for arg in &f.sig.inputs {
            match arg {
                syn::FnArg::Typed(t) => self.bind(&t.pat),
                syn::FnArg::Receiver(_) => self.locals.push("self".to_owned()),
            }
        }
        self.visit_block(&f.block);
        self.locals = saved;
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if self.tests.contains(f.span()) {
            return;
        }
        let saved = std::mem::take(&mut self.locals);
        for arg in &f.sig.inputs {
            match arg {
                syn::FnArg::Typed(t) => self.bind(&t.pat),
                syn::FnArg::Receiver(_) => self.locals.push("self".to_owned()),
            }
        }
        self.visit_block(&f.block);
        self.locals = saved;
    }
    fn visit_block(&mut self, b: &'ast syn::Block) {
        let at = self.locals.len();
        syn::visit::visit_block(self, b);
        self.locals.truncate(at);
    }
    fn visit_local(&mut self, l: &'ast syn::Local) {
        // The initializer precedes its binding: `let f = [f, g]` must fail.
        if let Some(init) = &l.init {
            self.visit_local_init(init);
        }
        self.bind(&l.pat);
    }
    fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
        let at = self.locals.len();
        for p in &c.inputs {
            self.bind(p);
        }
        self.visit_expr(&c.body);
        self.locals.truncate(at);
    }
    fn visit_expr_for_loop(&mut self, f: &'ast syn::ExprForLoop) {
        self.visit_expr(&f.expr);
        let at = self.locals.len();
        self.bind(&f.pat);
        self.visit_block(&f.body);
        self.locals.truncate(at);
    }
    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        let at = self.locals.len();
        self.bind(&a.pat);
        self.visit_pat(&a.pat);
        self.visit_expr(&a.body);
        self.locals.truncate(at);
    }
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        self.call_operand(&c.func);
        for a in &c.args {
            self.visit_expr(a);
        }
    }
    fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
        self.visit_expr(&c.receiver);
        for a in &c.args {
            self.visit_expr(a);
        }
    }
    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if let Some(last) = p.path.segments.last() {
            let name = unraw(&last.ident);
            let qualified = p.path.segments.len() > 1;
            let tail = p
                .path
                .segments
                .iter()
                .rev()
                .take(2)
                .map(|s| unraw(&s.ident))
                .collect::<Vec<_>>();
            let constructor = tail.len() == 2
                && self
                    .names
                    .constructors
                    .contains(&format!("{}::{}", tail[1], tail[0]));
            let function = if qualified {
                name.chars().next().is_some_and(char::is_lowercase)
                    || self.names.free.contains(&name)
                    || self.names.associated.contains(&name)
                    || constructor
            } else {
                self.names.free.contains(&name) && !self.locals.contains(&name)
            };
            if function {
                self.out.push(Finding {
                    line: line_of(last.ident.span()),
                    reason: format!("function item {name} escapes a call"),
                });
            }
        }
        syn::visit::visit_expr_path(self, p);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        use syn::parse::Parser;
        // Standard expression macros preserve generics, blocks and lexical
        // scopes. In particular `vec![a::<u8>, b::<u8>]` must not disguise a
        // function item as a path prefix in the conservative token fallback.
        if let Ok(exprs) =
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(m.tokens.clone())
        {
            for expr in &exprs {
                self.visit_expr(expr);
            }
            return;
        }
        fn scan(walk: &mut Walk<'_>, stream: proc_macro2::TokenStream) {
            use proc_macro2::TokenTree;
            let tokens: Vec<_> = stream.into_iter().collect();
            for (i, token) in tokens.iter().enumerate() {
                match token {
                    TokenTree::Group(g) => scan(walk, g.stream()),
                    TokenTree::Ident(n)
                        if (walk.names.free.contains(&unraw(n))
                            || (i >= 2
                                && crate::is_punct(tokens.get(i - 1), ':')
                                && crate::is_punct(tokens.get(i - 2), ':')
                                && (unraw(n).chars().next().is_some_and(char::is_lowercase)
                                    || walk.names.associated.contains(&unraw(n)))))
                            && !walk.locals.contains(&unraw(n))
                            && !matches!(i.checked_sub(1).and_then(|at| tokens.get(at)),
                            Some(TokenTree::Punct(p)) if p.as_char() == '.')
                            && !matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == ':' || p.as_char() == '!')
                            && !matches!(tokens.get(i + 1), Some(TokenTree::Group(g))
                            if g.delimiter() == proc_macro2::Delimiter::Parenthesis) =>
                    {
                        walk.out.push(Finding {
                            line: line_of(n.span()),
                            reason: format!(
                                "function item {} escapes a call in macro tokens",
                                unraw(n)
                            ),
                        });
                    }
                    _ => {}
                }
            }
        }
        scan(self, m.tokens.clone());
    }
}

pub(super) fn check(file: &syn::File, tests: &TestSpans, out: &mut Vec<Finding>) {
    let mut names = Names {
        free: BTreeSet::new(),
        associated: BTreeSet::new(),
        data: BTreeSet::new(),
        aliases: Vec::new(),
        constructors: BTreeSet::new(),
        imports: Vec::new(),
    };
    names.visit_file(file);
    for (path, name) in &names.imports {
        let tail: Vec<_> = path.rsplit("::").take(2).collect();
        if tail.len() == 2
            && names
                .constructors
                .contains(&format!("{}::{}", tail[1], tail[0]))
        {
            names.free.insert(name.clone());
        }
    }
    for (original, alias) in &names.aliases {
        // Enum unit variants are values, not function item constructors.
        if !names.data.contains(original) || names.free.contains(original) {
            names.free.insert(alias.clone());
        }
    }
    Walk {
        names,
        locals: Vec::new(),
        tests,
        out,
    }
    .visit_file(file);
}
