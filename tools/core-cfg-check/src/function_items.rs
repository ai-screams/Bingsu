//! Function values may be called directly, but not passed as callbacks,
//! stored, returned or merged (two distinct items coerce to address-ordered
//! function pointers). Explicit function-pointer types/casts are gated too.
//! No type inference: qualified lowercase value paths and imported values
//! are conservatively functions; local bindings are tracked by scope.
use std::collections::BTreeSet;

use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::{Finding, TestSpans, line_of, unraw};

mod data;
pub(super) use data::Data;

struct Names {
    free: BTreeSet<String>,
    associated: BTreeSet<String>,
    data: BTreeSet<String>,
    aliases: Vec<(String, String)>,
    constructors: BTreeSet<String>,
    imports: Vec<(String, String, Vec<String>)>,
    module: Vec<String>,
    imported_values: BTreeSet<String>,
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
        let mut imports = Vec::new();
        paths(&u.tree, "", &mut imports);
        self.imports.extend(
            imports
                .into_iter()
                .map(|(path, name)| (path, name, self.module.clone())),
        );
        syn::visit::visit_item_use(self, u);
    }
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        self.module.push(unraw(&m.ident));
        syn::visit::visit_item_mod(self, m);
        self.module.pop();
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
    fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
        if matches!(s.fields, syn::Fields::Unnamed(_)) {
            self.free.insert(unraw(&s.ident));
        }
        syn::visit::visit_item_struct(self, s);
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
    locals: Vec<(String, bool)>,
    self_type: Option<String>,
    tests: &'a TestSpans,
    out: &'a mut Vec<Finding>,
}
impl Walk<'_> {
    fn constructor(&self, owner: &str, name: &str) -> bool {
        matches!((owner, name), ("Option", "Some") | ("Result", "Ok" | "Err"))
            || self.names.constructors.contains(&format!(
                "{}::{name}",
                if owner == "Self" {
                    self.self_type.as_deref().unwrap_or("Self")
                } else {
                    owner
                }
            ))
    }
    fn closure_value(&self, e: &syn::Expr) -> usize {
        Self::closure_value_in(e, &self.locals)
    }
    fn closure_value_in(e: &syn::Expr, locals: &[(String, bool)]) -> usize {
        match e {
            syn::Expr::Closure(_) => 1,
            syn::Expr::Path(p) if p.qself.is_none() => p
                .path
                .get_ident()
                .and_then(|n| locals.iter().rev().find(|(name, _)| name == &unraw(n)))
                .map_or(0, |(_, closure)| usize::from(*closure)),
            syn::Expr::Paren(p) => Self::closure_value_in(&p.expr, locals),
            syn::Expr::Group(g) => Self::closure_value_in(&g.expr, locals),
            syn::Expr::Block(b) => Self::closure_tail_in(&b.block, locals),
            syn::Expr::If(i) => {
                Self::closure_tail_in(&i.then_branch, locals)
                    + i.else_branch
                        .as_ref()
                        .map_or(0, |(_, e)| Self::closure_value_in(e, locals))
            }
            syn::Expr::Match(m) => m
                .arms
                .iter()
                .map(|a| Self::closure_value_in(&a.body, locals))
                .sum(),
            _ => 0,
        }
    }
    fn closure_tail(&self, b: &syn::Block) -> usize {
        Self::closure_tail_in(b, &self.locals)
    }
    fn closure_tail_in(b: &syn::Block, locals: &[(String, bool)]) -> usize {
        // Branch-local aliases still return closures at the merge site.
        let mut locals = locals.to_vec();
        for stmt in &b.stmts {
            if let syn::Stmt::Local(l) = stmt {
                let closure = matches!(l.pat, syn::Pat::Ident(_))
                    && l.init
                        .as_ref()
                        .is_some_and(|init| Self::closure_value_in(&init.expr, &locals) > 0);
                let mut bindings = Bindings(Vec::new());
                bindings.visit_pat(&l.pat);
                locals.extend(bindings.0.into_iter().map(|name| (name, closure)));
            }
        }
        match b.stmts.last() {
            Some(syn::Stmt::Expr(e, None)) => Self::closure_value_in(e, &locals),
            _ => 0,
        }
    }
    fn closure_merge(&mut self, count: usize, span: proc_macro2::Span) {
        if count >= 2 {
            self.out.push(Finding {
                line: line_of(span),
                reason: "closures merge into function pointers".to_owned(),
            });
        }
    }
    fn bind(&mut self, pat: &syn::Pat) {
        let mut b = Bindings(Vec::new());
        b.visit_pat(pat);
        self.locals
            .extend(b.0.into_iter().map(|name| (name, false)));
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
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let name = match i.self_ty.as_ref() {
            syn::Type::Path(p) => p.path.segments.last().map(|s| unraw(&s.ident)),
            _ => None,
        };
        let saved = std::mem::replace(&mut self.self_type, name);
        syn::visit::visit_item_impl(self, i);
        self.self_type = saved;
    }
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        if let Some((_, other)) = &i.else_branch {
            self.closure_merge(
                self.closure_tail(&i.then_branch) + self.closure_value(other),
                i.span(),
            );
        }
        syn::visit::visit_expr_if(self, i);
    }
    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        self.closure_merge(
            m.arms.iter().map(|a| self.closure_value(&a.body)).sum(),
            m.span(),
        );
        syn::visit::visit_expr_match(self, m);
    }
    fn visit_expr_array(&mut self, a: &'ast syn::ExprArray) {
        self.closure_merge(
            a.elems.iter().map(|e| self.closure_value(e)).sum(),
            a.span(),
        );
        syn::visit::visit_expr_array(self, a);
    }
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
                syn::FnArg::Receiver(_) => self.locals.push(("self".to_owned(), false)),
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
                syn::FnArg::Receiver(_) => self.locals.push(("self".to_owned(), false)),
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
        let closure = l
            .init
            .as_ref()
            .is_some_and(|init| self.closure_value(&init.expr) > 0);
        self.bind(&l.pat);
        if closure && matches!(l.pat, syn::Pat::Ident(_)) {
            self.locals.last_mut().expect("identifier binding").1 = true;
        }
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
            let constructor = tail.len() == 2 && self.constructor(&tail[1], &tail[0]);
            let function = if qualified {
                name.chars().next().is_some_and(char::is_lowercase)
                    || self.names.free.contains(&name)
                    || self.names.associated.contains(&name)
                    || constructor
            } else {
                (self.names.free.contains(&name)
                    || self.names.imported_values.contains(&name)
                    || (name == "Self"
                        && self
                            .self_type
                            .as_ref()
                            .is_some_and(|t| self.names.free.contains(t)))
                    || matches!(name.as_str(), "Some" | "Ok" | "Err"))
                    && !self.locals.iter().any(|(local, _)| local == &name)
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
            if m.path.segments.last().is_some_and(|s| s.ident == "vec") {
                self.closure_merge(exprs.iter().map(|e| self.closure_value(e)).sum(), m.span());
            }
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
                            || walk.names.imported_values.contains(&unraw(n))
                            || matches!(unraw(n).as_str(), "Some" | "Ok" | "Err")
                            || (i >= 2
                                && crate::is_punct(tokens.get(i - 1), ':')
                                && crate::is_punct(tokens.get(i - 2), ':')
                                && (unraw(n).chars().next().is_some_and(char::is_lowercase)
                                    || walk.names.associated.contains(&unraw(n))
                                    || (i >= 3
                                        && matches!(tokens.get(i - 3), Some(TokenTree::Ident(owner)) if walk.constructor(&unraw(owner), &unraw(n)))))))
                            && !walk.locals.iter().any(|(local, _)| local == &unraw(n))
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

pub(super) fn check(
    file: &syn::File,
    path: &str,
    data: &Data,
    tests: &TestSpans,
    out: &mut Vec<Finding>,
) {
    let mut names = Names {
        free: BTreeSet::new(),
        associated: BTreeSet::new(),
        data: BTreeSet::new(),
        aliases: Vec::new(),
        constructors: BTreeSet::new(),
        imports: Vec::new(),
        module: Vec::new(),
        imported_values: BTreeSet::new(),
    };
    names.visit_file(file);
    for (import, name, module) in &names.imports {
        let tail: Vec<_> = import.rsplit("::").take(2).collect();
        if name != "self" && name != "_" && !data.imported(path, module, import) {
            names.imported_values.insert(name.clone());
        }
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
        self_type: None,
        tests,
        out,
    }
    .visit_file(file);
}
