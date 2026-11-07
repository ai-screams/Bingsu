//! `core-cfg-check --prompt-main FILE.rs`: crates/bingsu-prompt/src/main.rs,
//! the entry of the dedicated prompt binary. It compiles the prompt files of
//! crates/bingsu/src through `#[path]`, which `--binary` forbids everywhere
//! else, so this file is held to one exact shape instead: item by item equal
//! to SHAPE (doc comments aside). That shape is, per platform:
//!   - Linux: the five prompt files, sandbox.rs among them, and
//!     `prompt::dedicated(sandbox::enter)`;
//!   - other Unix (macOS): the four prompt files and an empty sandbox, as the
//!     `bingsu` binary has;
//!   - elsewhere (Windows): no prompt file, and `main` exits 2.
//!
//! Both `main`s name the prompt's role marker, which init's sibling check
//! reads. Another item (an allocator, a constructor, a `mod` naming another
//! file), another attribute (a `cfg` that hides a branch, an `export_name`),
//! another path or body fails, whatever the TCB hash pin says.

use crate::Finding;

const SHAPE: &str = r#"
#![deny(unsafe_code)]
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt.rs"]
mod prompt;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt_io.rs"]
mod prompt_io;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt_read.rs"]
mod prompt_read;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt_spawn.rs"]
mod prompt_spawn;
#[cfg(target_os = "linux")]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/sandbox.rs"]
mod sandbox;
#[cfg(all(unix, not(target_os = "linux")))]
mod sandbox {
    pub fn enter() -> bingsu_core::front::Sandbox {
        bingsu_core::front::Sandbox::Absent
    }
}
#[used]
static ROLE_TAG: [u8; 49] = bingsu_identity::role_tag(bingsu_identity::PROMPT_ROLE);
#[cfg(unix)]
fn main() {
    std::hint::black_box(&ROLE_TAG);
    prompt::dedicated(sandbox::enter)
}
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::hint::black_box(&ROLE_TAG);
    std::process::ExitCode::from(2)
}
"#;

fn without_docs(attrs: &[syn::Attribute]) -> Vec<syn::Attribute> {
    attrs
        .iter()
        .filter(|a| !a.path().is_ident("doc"))
        .cloned()
        .collect()
}

fn item_without_docs(item: &syn::Item) -> syn::Item {
    let mut item = item.clone();
    let attrs = match &mut item {
        syn::Item::Mod(i) => &mut i.attrs,
        syn::Item::Static(i) => &mut i.attrs,
        syn::Item::Fn(i) => &mut i.attrs,
        _ => return item,
    };
    *attrs = without_docs(attrs);
    item
}

pub fn check_prompt_main(source: &str) -> Vec<Finding> {
    let file = match syn::parse_file(source.strip_prefix('\u{feff}').unwrap_or(source)) {
        Ok(f) => f,
        Err(e) => {
            return vec![Finding {
                line: crate::line_of(e.span()),
                reason: format!("unparsable: {e}"),
            }];
        }
    };
    let want = syn::parse_file(SHAPE).expect("pinned prompt main shape");
    let mut out = Vec::new();
    if file.shebang.is_some() || without_docs(&file.attrs) != want.attrs {
        out.push(Finding {
            line: 1,
            reason: "inner attributes must be exactly #![deny(unsafe_code)]".to_owned(),
        });
    }
    let got: Vec<_> = file.items.iter().map(item_without_docs).collect();
    if got.len() != want.items.len() {
        out.push(Finding {
            line: 0,
            reason: format!(
                "expected the {} items of the pinned shape, found {}",
                want.items.len(),
                got.len()
            ),
        });
    }
    for (i, (have, should)) in got.iter().zip(&want.items).enumerate() {
        if have != should {
            use syn::spanned::Spanned;
            out.push(Finding {
                line: crate::line_of(file.items[i].span()),
                reason: format!("item {} differs from the pinned shape", i + 1),
            });
        }
    }
    out
}
