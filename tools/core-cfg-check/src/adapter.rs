//! `core-cfg-check --adapter SYSCALLS.tsv FILE.rs`: the prompt adapter
//! (crates/bingsu/src/prompt.rs), the trusted computing base of
//! `bingsu prompt`. A regex over the text cannot follow Rust paths (a group
//! import, a rename, `super::`), so this walks syn's tree. Outside the one
//! test module the file fails on:
//!   - an item other than `use`, the one `struct NonPromptArgs` and a plain
//!     `fn` (no `extern` ABI): no `extern` block, `static`, `mod`, `impl`,
//!     `macro_rules`, `extern crate`;
//!   - a path of two or more segments whose first segment is not in
//!     PATH_ROOTS (a closed list; `--binary` keeps every file from declaring
//!     a local `libc`, `std` or `front`, so these mean the real ones);
//!   - a `use` that is not one plain path from USE_ALLOWED (no group, no
//!     rename, no glob);
//!   - a path that starts with `crate`, `super` or `self`, or with
//!     `std`/`core`/`alloc` and is not in STD_ALLOWED, or with `libc` and
//!     names something that is not a row of SYSCALLS.tsv, or with
//!     `bingsu_core` and is not under `bingsu_core::front`;
//!   - any macro call (that covers `asm!`, `global_asm!` and renamed asm);
//!   - any `cfg` or `cfg_attr` attribute;
//!   - libc names that differ from the `libc` column of SYSCALLS.tsv, in
//!     either direction (a listed call the adapter no longer makes fails
//!     too).
//!
//! The test module is exactly one item, the last, `#[cfg(test)] mod tests
//! { … }`; a `#[cfg(test)]` anywhere else fails.

use std::collections::BTreeSet;

use proc_macro2::Span;
use syn::ext::IdentExt;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::{Finding, line_of};

/// Every `use` the adapter may write, as the full path.
const USE_ALLOWED: [&str; 3] = [
    "bingsu_core::front",
    "std::ffi::OsString",
    "std::os::unix::ffi::OsStrExt",
];

/// The first segment of every path with two or more segments.
const PATH_ROOTS: [&str; 5] = ["std", "libc", "front", "Box", "usize"];

/// Every std path the adapter may name (calls, types, traits).
const STD_ALLOWED: [&str; 7] = [
    "std::ffi::OsString",
    "std::os::unix::ffi::OsStrExt",
    "std::env::args_os",
    "std::io::Error::last_os_error",
    "std::panic::catch_unwind",
    "std::panic::AssertUnwindSafe",
    "std::panic::set_hook",
];

/// The `libc` column of the syscall table (found by its header), rows that
/// name something (`-` skipped), `#` lines skipped.
pub fn libc_column(tsv: &str) -> Vec<String> {
    let mut rows = tsv
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').collect::<Vec<_>>());
    let Some(at) = rows
        .next()
        .and_then(|h| h.iter().position(|c| *c == "libc"))
    else {
        return Vec::new();
    };
    rows.filter_map(|r| r.get(at).copied())
        .filter(|c| *c != "-")
        .map(str::to_owned)
        .collect()
}

struct Walk<'a> {
    listed: &'a BTreeSet<String>,
    used: BTreeSet<String>,
    out: Vec<Finding>,
    prefilter_lines: Option<[(usize, usize); 2]>,
    timer_lines: Option<[(usize, usize); 2]>,
}

impl Walk<'_> {
    fn bad(&mut self, span: Span, reason: String) {
        self.out.push(Finding {
            line: line_of(span),
            reason,
        });
    }
}

fn joined(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|s| s.ident.unraw().to_string())
        .collect()
}

fn use_paths(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut Vec<Result<String, &'static str>>,
) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.unraw().to_string());
            use_paths(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let mut full = prefix.clone();
            full.push(n.ident.unraw().to_string());
            out.push(Ok(full.join("::")));
        }
        syn::UseTree::Rename(_) => out.push(Err("a renaming use")),
        syn::UseTree::Glob(_) => out.push(Err("a glob use")),
        syn::UseTree::Group(_) => out.push(Err("a group use")),
    }
}

impl<'ast> Visit<'ast> for Walk<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        match item {
            syn::Item::Use(u) => {
                let mut found = Vec::new();
                use_paths(&u.tree, &mut Vec::new(), &mut found);
                for f in found {
                    match f {
                        Ok(p) if USE_ALLOWED.contains(&p.as_str()) => {}
                        Ok(p) => self.bad(u.span(), format!("use {p} is not in USE_ALLOWED")),
                        Err(what) => self.bad(u.span(), format!("{what} hides the path")),
                    }
                }
                // The use path itself is checked above, not as an expression path.
                return;
            }
            syn::Item::Fn(f) if f.sig.abi.is_some() => {
                self.bad(f.sig.span(), "an extern fn".to_owned());
            }
            syn::Item::Struct(st) if st.ident == "NonPromptArgs" => {}
            syn::Item::Struct(st) => {
                self.bad(
                    st.ident.span(),
                    format!("struct {}: only NonPromptArgs", st.ident),
                );
            }
            syn::Item::Fn(_) => {}
            other => self.bad(
                other.span(),
                "an item other than use, struct and fn".to_owned(),
            ),
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if let Some(ident) = attr.path().get_ident() {
            let name = ident.unraw().to_string();
            if name == "cfg" || name == "cfg_attr" {
                self.bad(ident.span(), "cfg outside the last test module".to_owned());
            }
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.bad(mac.path.span(), "a macro call".to_owned());
        syn::visit::visit_macro(self, mac);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segs = joined(path);
        let full = segs.join("::");
        if segs.len() > 1
            && !PATH_ROOTS.contains(&segs[0].as_str())
            && !matches!(segs[0].as_str(), "crate" | "super" | "self")
        {
            self.bad(path.span(), format!("{full}: path root not in PATH_ROOTS"));
        }
        match segs.first().map(String::as_str) {
            Some("crate")
                if full == "crate::prompt_spawn::bootstrap"
                    && self.prefilter_lines.map(|lines| lines[0])
                        == Some((line_of(path.span()), path.span().start().column)) => {}
            Some("crate")
                if full == "crate::prompt_read::prepare"
                    && self.prefilter_lines.map(|lines| lines[1])
                        == Some((line_of(path.span()), path.span().start().column)) => {}
            Some("crate")
                if full == "crate::prompt_io::entry_deadline"
                    && self.timer_lines.map(|lines| lines[0])
                        == Some((line_of(path.span()), path.span().start().column)) => {}
            Some("crate")
                if full == "crate::prompt_io::arm_deadline"
                    && self.timer_lines.map(|lines| lines[1])
                        == Some((line_of(path.span()), path.span().start().column)) => {}
            // Hash-pinned observation wrapper: clock + lock-free flag, no timer
            // or pathname access. It is also passed to the injected write loop.
            Some("crate") if full == "crate::prompt_io::deadline_now" => {}
            Some("crate" | "super") => {
                self.bad(path.span(), format!("{full}: another module of the binary"))
            }
            Some("self") if segs.len() > 1 => {
                self.bad(path.span(), format!("{full}: a module path"))
            }
            Some("std" | "core" | "alloc") if !STD_ALLOWED.contains(&full.as_str()) => {
                self.bad(path.span(), format!("{full} is not in STD_ALLOWED"));
            }
            Some("libc") => {
                if segs.len() == 2 && self.listed.contains(&segs[1]) {
                    self.used.insert(segs[1].clone());
                } else {
                    self.bad(
                        path.span(),
                        format!("{full} is not a row of the syscall table"),
                    );
                }
            }
            Some("bingsu_core") if segs.get(1).map(String::as_str) != Some("front") => {
                self.bad(path.span(), format!("{full}: only bingsu_core::front"));
            }
            _ => {}
        }
        syn::visit::visit_path(self, path);
    }
}

fn is_test_mod(item: &syn::Item) -> bool {
    match item {
        syn::Item::Mod(m) => {
            m.ident == "tests"
                && m.content.is_some()
                && m.attrs.len() == 1
                && matches!(&m.attrs[0].meta, syn::Meta::List(l)
                    if l.path.is_ident("cfg") && l.tokens.to_string() == "test")
        }
        _ => false,
    }
}

/// The `--adapter` check.
pub fn check_adapter(source: &str, tsv: &str) -> Vec<Finding> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(e) => {
            return vec![Finding {
                line: line_of(e.span()),
                reason: format!("unparsable: {e}"),
            }];
        }
    };
    let listed: BTreeSet<String> = libc_column(tsv).into_iter().collect();
    let mut walk = Walk {
        listed: &listed,
        used: BTreeSet::new(),
        out: Vec::new(),
        prefilter_lines: prefilter_lines(&file),
        timer_lines: timer_lines(&file),
    };
    if walk.prefilter_lines.is_some() && walk.timer_lines.is_none() {
        walk.bad(
            Span::call_site(),
            "missing fail-closed prefilter deadline setup".to_owned(),
        );
    }
    let n = file.items.len();
    for (i, item) in file.items.iter().enumerate() {
        if i + 1 == n && is_test_mod(item) {
            continue;
        }
        walk.visit_item(item);
    }
    if walk.used != listed {
        let missing: Vec<_> = listed.difference(&walk.used).collect();
        let extra: Vec<_> = walk.used.difference(&listed).collect();
        walk.out.push(Finding {
            line: 0,
            reason: format!("libc names differ from the syscall table: listed but unused {missing:?}, used but unlisted {extra:?}"),
        });
    }
    walk.out
}

/// The two approved entry calls are consecutive in run_prompt's unwind guard:
/// fixed spawn, then held-fd preparation, immediately before the filter branch.
/// Neither function may be imported or saved as a function value; all other
/// module path rules remain unchanged. The prepared closure owns the held fds.
fn prefilter_lines(file: &syn::File) -> Option<[(usize, usize); 2]> {
    let f = file.items.iter().find_map(|i| match i {
        syn::Item::Fn(f) if f.sig.ident == "run_prompt" => Some(f),
        _ => None,
    })?;
    // The incoming Option is refined once by the first statement. Count all
    // body patterns (including closures, loops and match arms), not just lets.
    let syn::Stmt::Local(deadline) = f.block.stmts.first()? else {
        return None;
    };
    let pinned: syn::Stmt = syn::parse_str("let Some(deadline) = deadline else { exit(0) };")
        .expect("pinned deadline refinement");
    if syn::Stmt::Local(deadline.clone()) != pinned {
        return None;
    }
    struct Bindings {
        raw: usize,
        deadline: usize,
    }
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
            match p.ident.unraw().to_string().as_str() {
                "raw" => self.raw += 1,
                "deadline" => self.deadline += 1,
                _ => {}
            }
            syn::visit::visit_pat_ident(self, p);
        }
    }
    let mut bindings = Bindings {
        raw: 0,
        deadline: 0,
    };
    bindings.visit_block(&f.block);
    if bindings.raw != 1 || bindings.deadline != 1 {
        return None;
    }
    struct Calls(usize);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(call.func.as_ref(),syn::Expr::Path(p) if p.path.is_ident("enter_sandbox")) {
                self.0 += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls(0);
    calls.visit_block(&f.block);
    if calls.0 != 1 {
        return None;
    }
    let local = f.block.stmts.iter().find_map(|s| match s {
        syn::Stmt::Local(l) if matches!(&l.pat, syn::Pat::Ident(p) if p.ident == "rec") => Some(l),
        _ => None,
    })?;
    let syn::Expr::MethodCall(unwrap) = local.init.as_ref()?.expr.as_ref() else {
        return None;
    };
    if unwrap.method != "unwrap_or_else" {
        return None;
    }
    let syn::Expr::Call(catch) = unwrap.receiver.as_ref() else {
        return None;
    };
    let syn::Expr::Path(path) = catch.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "std::panic::catch_unwind" {
        return None;
    }
    let syn::Expr::Call(guard) = catch.args.first()? else {
        return None;
    };
    let syn::Expr::Path(path) = guard.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "std::panic::AssertUnwindSafe" {
        return None;
    }
    let syn::Expr::Closure(closure) = guard.args.first()? else {
        return None;
    };
    let syn::Expr::Block(block) = closure.body.as_ref() else {
        return None;
    };
    let [
        syn::Stmt::Expr(syn::Expr::Call(bootstrap), Some(_)),
        syn::Stmt::Local(prepared),
        syn::Stmt::Expr(syn::Expr::If(branch), None),
    ] = block.block.stmts.as_slice()
    else {
        return None;
    };
    let syn::Expr::Path(path) = bootstrap.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "crate::prompt_spawn::bootstrap"
        || bootstrap.args.len() != 3
    {
        return None;
    }
    if !matches!(&prepared.pat, syn::Pat::Ident(p) if p.ident == "staged") {
        return None;
    }
    let syn::Expr::Call(prepare) = prepared.init.as_ref()?.expr.as_ref() else {
        return None;
    };
    let syn::Expr::Path(path) = prepare.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "crate::prompt_read::prepare"
        || prepare.args.len() != 2
        || !matches!(prepare.args.first()?, syn::Expr::Reference(r)
            if r.mutability.is_none() && matches!(r.expr.as_ref(), syn::Expr::Path(p)
                if p.qself.is_none() && p.path.is_ident("raw")))
        || !matches!(prepare.args.last()?, syn::Expr::Path(p)
            if p.qself.is_none() && p.path.is_ident("deadline"))
    {
        return None;
    }
    let syn::Expr::Call(runs) = branch.cond.as_ref() else {
        return None;
    };
    let syn::Expr::Path(path) = runs.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "front::runs_core" {
        return None;
    }
    let syn::Expr::Call(enter) = runs.args.first()? else {
        return None;
    };
    let syn::Expr::Path(path) = enter.func.as_ref() else {
        return None;
    };
    if !path.path.is_ident("enter_sandbox") || !enter.args.is_empty() {
        return None;
    }
    Some([
        (
            line_of(bootstrap.func.span()),
            bootstrap.func.span().start().column,
        ),
        (
            line_of(prepare.func.span()),
            prepare.func.span().start().column,
        ),
    ])
}

/// N6: capture time as dispatch's first statement; install the timer in a
/// fail-closed guard before the unwind block containing the sole filter call.
/// These two pre-filter capabilities cannot be called elsewhere or aliased.
fn timer_lines(file: &syn::File) -> Option<[(usize, usize); 2]> {
    prefilter_lines(file)?;
    let function = |name: &str| {
        file.items.iter().find_map(|i| match i {
            syn::Item::Fn(f) if f.sig.ident == name => Some(f),
            _ => None,
        })
    };
    let dispatch = function("dispatch")?;
    let syn::Stmt::Local(local) = dispatch.block.stmts.first()? else {
        return None;
    };
    if !matches!(&local.pat, syn::Pat::Ident(p) if p.ident == "deadline") {
        return None;
    }
    let syn::Expr::Call(entry) = local.init.as_ref()?.expr.as_ref() else {
        return None;
    };
    let syn::Expr::Path(path) = entry.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "crate::prompt_io::entry_deadline" || !entry.args.is_empty()
    {
        return None;
    }
    let run = function("run_prompt")?;
    let at = run.block.stmts.iter().position(|s| {
        matches!(s,
        syn::Stmt::Local(l) if matches!(&l.pat, syn::Pat::Ident(p) if p.ident == "rec"))
    })?;
    let syn::Stmt::Expr(syn::Expr::If(guard), _) = run.block.stmts.get(at.checked_sub(1)?)? else {
        return None;
    };
    if guard.else_branch.is_some() {
        return None;
    }
    let syn::Expr::Unary(negation) = guard.cond.as_ref() else {
        return None;
    };
    if !matches!(negation.op, syn::UnOp::Not(_)) {
        return None;
    }
    let syn::Expr::Call(arm) = negation.expr.as_ref() else {
        return None;
    };
    let syn::Expr::Path(path) = arm.func.as_ref() else {
        return None;
    };
    if joined(&path.path).join("::") != "crate::prompt_io::arm_deadline"
        || arm.args.len() != 1
        || !matches!(arm.args.first()?, syn::Expr::Path(p) if p.path.is_ident("deadline"))
    {
        return None;
    }
    let [syn::Stmt::Expr(syn::Expr::Call(exit), _)] = guard.then_branch.stmts.as_slice() else {
        return None;
    };
    if !matches!(exit.func.as_ref(), syn::Expr::Path(p) if p.path.is_ident("exit"))
        || exit.args.len() != 1
        || !matches!(exit.args.first()?, syn::Expr::Lit(l) if matches!(&l.lit, syn::Lit::Int(n) if n.base10_digits() == "0"))
    {
        return None;
    }
    Some([
        (line_of(entry.func.span()), entry.func.span().start().column),
        (line_of(arm.func.span()), arm.func.span().start().column),
    ])
}
