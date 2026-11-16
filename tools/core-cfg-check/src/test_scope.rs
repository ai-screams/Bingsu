//! What counts as test code: an item marked `#[cfg(test)]`, at any depth,
//! and a library child module file whose first inner attribute is
//! `#![cfg(test)]`. The default mode, `--rules` and function_items.rs share
//! this judgement.

use proc_macro2::Span;
use syn::visit::Visit;

/// A test-only file: its first inner attribute is exactly `#![cfg(test)]`,
/// so rustc builds it only into test binaries (it is a child module file
/// declared with `mod x;`). The same policy as an inline `#[cfg(test)]`
/// item, applied to a file's shape. Only a library child module file can be
/// one: a crate root (`lib.rs`) and a `--test-targets` file (each is the root
/// of its own test crate) never are, and the
/// attribute must come first: a doc comment or another attribute before it
/// leaves the file checked as production code.
pub(crate) fn is_test_file(attrs: &[syn::Attribute], library: bool, crate_root: bool) -> bool {
    library && !crate_root && is_test_item(attrs.get(..1).unwrap_or_default())
}

/// The arguments of a `cfg` attribute are exactly `(test)`, with parentheses:
/// rustc rejects `cfg[test]` and `cfg{test}` without stripping the item, so
/// they are not test code here. The attribute's name is checked by the caller.
pub(crate) fn is_test_args(meta: &syn::Meta) -> bool {
    matches!(meta, syn::Meta::List(l)
        if matches!(l.delimiter, syn::MacroDelimiter::Paren(_)) && l.tokens.to_string() == "test")
}

pub(crate) fn is_test_item(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("cfg") && is_test_args(&a.meta))
}

/// Start and end of every item, impl item and trait item marked
/// `#[cfg(test)]`, at any depth: the production code is everything else.
pub(crate) struct TestSpans(pub(crate) Vec<(proc_macro2::LineColumn, proc_macro2::LineColumn)>);

impl TestSpans {
    fn push(&mut self, attrs: &[syn::Attribute], node: &dyn syn::spanned::Spanned) -> bool {
        if is_test_item(attrs) {
            let span = node.span();
            self.0.push((span.start(), span.end()));
            return true;
        }
        false
    }
    pub(crate) fn contains(&self, span: Span) -> bool {
        let at = span.start();
        let key = |l: proc_macro2::LineColumn| (l.line, l.column);
        self.0
            .iter()
            .any(|(s, e)| key(*s) <= key(at) && key(at) <= key(*e))
    }
}

impl<'ast> Visit<'ast> for TestSpans {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::ExternCrate(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::ForeignMod(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::TraitAlias(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Union(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[],
        };
        if !self.push(attrs, item) {
            syn::visit::visit_item(self, item);
        }
    }
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !self.push(attrs, item) {
            syn::visit::visit_impl_item(self, item);
        }
    }
    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::TraitItem::Const(i) => &i.attrs,
            syn::TraitItem::Fn(i) => &i.attrs,
            syn::TraitItem::Type(i) => &i.attrs,
            syn::TraitItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !self.push(attrs, item) {
            syn::visit::visit_trait_item(self, item);
        }
    }
}
