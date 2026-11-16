//! Library production code reaches no Debug or Hash output: DEBUG_AND_HASH
//! names, Debug placeholders, and glob imports that could bring Debug::fmt in
//! without naming it.

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

use super::format_spec::formats_debug;
use crate::test_scope::TestSpans;
use crate::{Finding, is_ident, is_punct, line_of, unraw};

/// Glob imports can put Debug::fmt in scope without a Debug token.
pub(super) struct ProductionGlobs<'a> {
    pub(super) tests: &'a TestSpans,
    pub(super) out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for ProductionGlobs<'_> {
    fn visit_use_glob(&mut self, glob: &'ast syn::UseGlob) {
        if !self.tests.contains(glob.star_token.span) {
            self.out.push(Finding {
                line: line_of(glob.star_token.span),
                reason: "production glob import hides Debug or Hash".to_owned(),
            });
        }
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        fn scan(walk: &mut ProductionGlobs<'_>, stream: TokenStream) {
            let tokens: Vec<_> = stream.into_iter().collect();
            for (at, t) in tokens.iter().enumerate() {
                if let TokenTree::Group(g) = t {
                    scan(walk, g.stream());
                }
                if is_ident(Some(t), "use") {
                    let end = tokens[at..].iter().position(|t| is_punct(Some(t), ';'));
                    if let Some(end) = end
                        && let Ok(import) = syn::parse2::<syn::ItemUse>(
                            tokens[at..=at + end].iter().cloned().collect(),
                        )
                    {
                        walk.visit_item_use(&import);
                    }
                }
            }
        }
        scan(self, m.tokens.clone());
    }
}

/// Names through which a value's Debug output or hash reaches the program:
/// a Debug or Hash implementation may write an address (a Waker's vtable,
/// a function pointer), so production code may not call them.
/// `#[derive(Debug)]` stays allowed: with no Debug format, no `Debug` name
/// and no debug builder outside it, nothing can call the derived impl.
const DEBUG_AND_HASH: [&str; 10] = [
    "Debug",
    "debug_struct",
    "debug_tuple",
    "debug_list",
    "debug_map",
    "debug_set",
    "Hash",
    "Hasher",
    "BuildHasher",
    "hash",
];

/// Production tokens of a library file (outside TestSpans): DEBUG_AND_HASH
/// names (`Debug` allowed inside `#[derive(..)]`) and Debug placeholders.
pub(super) fn scan_debug_and_hash(
    stream: TokenStream,
    tests: &TestSpans,
    in_derive: bool,
    out: &mut Vec<Finding>,
) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        if tests.contains(token.span()) {
            continue;
        }
        match token {
            TokenTree::Group(group) => {
                let derive = i >= 1
                    && is_punct(tokens.get(i - 1), '#')
                    && is_ident(group.stream().into_iter().next().as_ref(), "derive");
                scan_debug_and_hash(group.stream(), tests, in_derive || derive, out);
            }
            TokenTree::Ident(ident) => {
                let name = unraw(ident);
                if DEBUG_AND_HASH.contains(&name.as_str()) && !(in_derive && name == "Debug") {
                    out.push(Finding {
                        line: line_of(ident.span()),
                        reason: format!("{name} may write an address (Debug and Hash stay out of production code)"),
                    });
                }
            }
            TokenTree::Literal(lit) => {
                if matches!(syn::Lit::new(lit.clone()), syn::Lit::Str(s) if formats_debug(&s.value()))
                {
                    out.push(Finding {
                        line: line_of(lit.span()),
                        reason:
                            "{:?} may write an address (Debug and Hash stay out of production code)"
                                .to_owned(),
                    });
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}
