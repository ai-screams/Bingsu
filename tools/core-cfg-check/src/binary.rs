//! `core-cfg-check --binary FILE.rs...` checks every source file of the
//! `bingsu` binary crate instead (scripts/check_cli_prompt_forbid.py):
//! nothing may run outside `fn main`, and `main` only dispatches. Every file
//! fails on an identifier `global_allocator`, `link_section`, `export_name`,
//! `no_mangle`, `ctor` or `global_asm` anywhere (a custom allocator or a
//! linker constructor runs code before or around main), on `#[path]` and
//! `include` (code from outside the checked files), on a declaration named
//! `libc`, `std`, `core`, `alloc` or `front` (an item, a generic, a use
//! rename, or an import other than `use bingsu_core::front`: the adapter's
//! paths must mean the real crates), on an `impl` for a type of the prompt
//! adapter, and on source that does not parse. Over all files there must be
//! exactly one `fn main`, at the top of a file `main.rs`, with no attribute
//! and the body `commands::run(prompt::dispatch(sandbox::enter))`: the
//! prompt adapter is the first code that runs, and on Linux it installs the
//! seccomp filter before the core sees the arguments.

use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use crate::{Finding, is_ident, is_path_attr_group, is_punct, line_of, unraw};

const BINARY_FORBIDDEN: [&str; 6] = [
    "global_allocator",
    "link_section",
    "export_name",
    "no_mangle",
    "ctor",
    "global_asm",
];

const MAIN_BODY: &str = "commands::run(prompt::dispatch(sandbox::enter))";

/// Every `fn main` the parser sees, at any depth: (line, top level, attrs,
/// body tokens).
struct Mains<'a> {
    depth: usize,
    found: &'a mut Vec<(usize, bool, usize, String)>,
}

impl<'ast> Visit<'ast> for Mains<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.sig.ident == "main" {
            let body = match f.block.stmts.as_slice() {
                [syn::Stmt::Expr(e, None)] => quote_tokens(e),
                _ => String::new(),
            };
            self.found.push((
                line_of(f.sig.ident.span()),
                self.depth == 0,
                f.attrs.len(),
                body,
            ));
        }
        self.depth += 1;
        syn::visit::visit_item_fn(self, f);
        self.depth -= 1;
    }
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        self.depth += 1;
        syn::visit::visit_item_mod(self, m);
        self.depth -= 1;
    }
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        self.depth += 1;
        syn::visit::visit_item_impl(self, i);
        self.depth -= 1;
    }
}

/// The source text of `e` without whitespace (comments inside it stay and
/// so fail the comparison).
fn quote_tokens(e: &syn::Expr) -> String {
    use syn::spanned::Spanned;
    e.span()
        .source_text()
        .unwrap_or_default()
        .split_whitespace()
        .collect()
}

/// The `--binary` check over all files: one `fn main` of the right shape.
pub(super) fn check_main(files: &[(String, String)]) -> Vec<(String, Finding)> {
    let mut out = Vec::new();
    let mut all = Vec::new();
    for (path, source) in files {
        let Ok(file) = syn::parse_file(source.strip_prefix('\u{feff}').unwrap_or(source)) else {
            continue; // reported by check_binary
        };
        let mut found = Vec::new();
        Mains {
            depth: 0,
            found: &mut found,
        }
        .visit_file(&file);
        all.extend(found.into_iter().map(|m| (path.clone(), m)));
    }
    match all.as_slice() {
        [(path, (line, top, attrs, body))] => {
            if std::path::Path::new(path).file_name() != Some(std::ffi::OsStr::new("main.rs"))
                || !*top
                || *attrs != 0
                || body != MAIN_BODY
            {
                out.push((
                    path.clone(),
                    Finding {
                        line: *line,
                        reason: format!("fn main must be top level in main.rs, without attributes, with the body `{MAIN_BODY}`"),
                    },
                ));
            }
        }
        _ => out.push((
            String::from("(all files)"),
            Finding {
                line: 0,
                reason: format!("expected exactly one fn main, found {}", all.len()),
            },
        )),
    }
    out
}

fn scan_binary_tokens(stream: TokenStream, out: &mut Vec<Finding>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        if let TokenTree::Punct(punct) = token
            && punct.as_char() == '#'
        {
            let next = if is_punct(tokens.get(i + 1), '!') {
                i + 2
            } else {
                i + 1
            };
            if is_path_attr_group(tokens.get(next)) {
                out.push(Finding {
                    line: line_of(punct.span()),
                    reason: "#[path] pulls in code from outside the checked files".to_owned(),
                });
            }
        }
        if is_ident(Some(token), "include") {
            out.push(Finding {
                line: line_of(token.span()),
                reason: "include pulls in code from outside the checked files".to_owned(),
            });
        }
        match token.clone() {
            TokenTree::Group(group) => scan_binary_tokens(group.stream(), out),
            TokenTree::Ident(ident) if BINARY_FORBIDDEN.contains(&unraw(&ident).as_str()) => out
                .push(Finding {
                    line: line_of(ident.span()),
                    reason: format!("{} runs code outside main", unraw(&ident)),
                }),
            _ => {}
        }
    }
}

/// Names the prompt adapter's paths start with (`libc::`, `std::`,
/// `front::` …). No file of the binary may declare one of them, so such a
/// path always means the real crate or the one `use bingsu_core::front`.
const RESERVED: [&str; 5] = ["libc", "std", "core", "alloc", "front"];

struct Decls<'a> {
    out: &'a mut Vec<Finding>,
}

impl Decls<'_> {
    fn name(&mut self, ident: &proc_macro2::Ident, what: &str) {
        let name = unraw(ident);
        if RESERVED.contains(&name.as_str()) {
            self.out.push(Finding {
                line: line_of(ident.span()),
                reason: format!("{what} named {name} shadows a reserved root"),
            });
        }
    }
}

impl<'ast> Visit<'ast> for Decls<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let ident = match item {
            syn::Item::Const(i) => Some(&i.ident),
            syn::Item::Enum(i) => Some(&i.ident),
            syn::Item::Fn(i) => Some(&i.sig.ident),
            syn::Item::Mod(i) => Some(&i.ident),
            syn::Item::Static(i) => Some(&i.ident),
            syn::Item::Struct(i) => Some(&i.ident),
            syn::Item::Trait(i) => Some(&i.ident),
            syn::Item::TraitAlias(i) => Some(&i.ident),
            syn::Item::Type(i) => Some(&i.ident),
            syn::Item::Union(i) => Some(&i.ident),
            syn::Item::Macro(i) => i.ident.as_ref(),
            syn::Item::ExternCrate(i) => i.rename.as_ref().map(|(_, r)| r),
            _ => None,
        };
        if let Some(ident) = ident {
            self.name(ident, "an item");
        }
        if let syn::Item::Impl(i) = item {
            let ty = i.self_ty.to_token_stream_string();
            if ty.contains("prompt") || ty.contains("NonPromptArgs") {
                self.out.push(Finding {
                    line: line_of(i.impl_token.span),
                    reason: "impl for a type of the prompt adapter".to_owned(),
                });
            }
        }
        syn::visit::visit_item(self, item);
    }
    fn visit_generic_param(&mut self, g: &'ast syn::GenericParam) {
        match g {
            syn::GenericParam::Type(t) => self.name(&t.ident, "a generic"),
            syn::GenericParam::Const(c) => self.name(&c.ident, "a generic"),
            syn::GenericParam::Lifetime(_) => {}
        }
        syn::visit::visit_generic_param(self, g);
    }
    fn visit_use_rename(&mut self, r: &'ast syn::UseRename) {
        self.name(&r.rename, "a use rename");
        syn::visit::visit_use_rename(self, r);
    }
}

trait SourceText {
    fn to_token_stream_string(&self) -> String;
}

impl SourceText for syn::Type {
    fn to_token_stream_string(&self) -> String {
        use syn::spanned::Spanned;
        self.span().source_text().unwrap_or_default()
    }
}

/// Imports of a reserved name: only `use bingsu_core::front;` may bring one in.
fn reserved_imports(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<Finding>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(unraw(&p.ident));
            reserved_imports(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let name = unraw(&n.ident);
            let full = [prefix.join("::"), name.clone()].join("::");
            if RESERVED.contains(&name.as_str())
                && !prefix.is_empty()
                && full != "bingsu_core::front"
            {
                out.push(Finding {
                    line: line_of(n.ident.span()),
                    reason: format!("use {full} brings in a name that shadows a reserved root"),
                });
            }
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                reserved_imports(t, prefix, out);
            }
        }
        syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
    }
}

struct Uses<'a> {
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for Uses<'_> {
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        reserved_imports(&u.tree, &mut Vec::new(), self.out);
    }
}

/// The `--binary` check of one file.
pub(super) fn check_binary(source: &str) -> Vec<Finding> {
    let text = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut out = Vec::new();
    match syn::parse_file(text)
        .map_err(|e| e.span())
        .and_then(|file| {
            let body = match &file.shebang {
                Some(shebang) => &text[shebang.len()..],
                None => text,
            };
            TokenStream::from_str(body).map_err(|e| e.span())
        }) {
        Ok(stream) => scan_binary_tokens(stream, &mut out),
        Err(span) => out.push(Finding {
            line: line_of(span),
            reason: "unparsable".to_owned(),
        }),
    }
    if let Ok(file) = syn::parse_file(text) {
        Decls { out: &mut out }.visit_file(&file);
        Uses { out: &mut out }.visit_file(&file);
    }
    out
}
