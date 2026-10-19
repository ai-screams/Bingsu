//! Positive evidence for imported data, never an uppercase-name exemption.
//! Unknown imports remain possible functions (including ALL_CAPS functions).
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::unraw;

#[derive(Default)]
pub(crate) struct Data {
    values: BTreeSet<(PathBuf, String)>,
    functions: BTreeSet<(PathBuf, String)>,
}

fn location(path: &Path) -> (PathBuf, Vec<String>) {
    let parent = path.parent().unwrap_or(Path::new("."));
    let root = parent
        .ancestors()
        .find(|p| p.join("lib.rs").is_file())
        .unwrap_or(parent);
    let mut module: Vec<_> = path
        .strip_prefix(root)
        .unwrap_or(path)
        .with_extension("")
        .components()
        .map(|p| p.as_os_str().to_string_lossy().into_owned())
        .collect();
    if module.last().is_some_and(|s| s == "lib" || s == "mod") {
        module.pop();
    }
    (root.to_owned(), module)
}

impl Data {
    pub(crate) fn from_paths(paths: &[String]) -> Self {
        let mut data = Self::default();
        for path in paths {
            if let Ok(source) = std::fs::read_to_string(path)
                && let Ok(file) = syn::parse_file(&source)
            {
                let (root, module) = location(Path::new(path));
                data.items(&root, &module, &file.items);
            }
        }
        data
    }

    fn items(&mut self, root: &Path, module: &[String], items: &[syn::Item]) {
        let key = |name: String| {
            (
                root.to_owned(),
                [module.join("::"), name]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("::"),
            )
        };
        for item in items {
            match item {
                syn::Item::Const(c) => {
                    self.values.insert(key(unraw(&c.ident)));
                }
                syn::Item::Struct(s) => {
                    let set = if matches!(s.fields, syn::Fields::Unnamed(_)) {
                        &mut self.functions
                    } else {
                        &mut self.values
                    };
                    set.insert(key(unraw(&s.ident)));
                }
                syn::Item::Enum(e) => {
                    for v in &e.variants {
                        let set = if matches!(v.fields, syn::Fields::Unnamed(_)) {
                            &mut self.functions
                        } else {
                            &mut self.values
                        };
                        set.insert(key(format!("{}::{}", unraw(&e.ident), unraw(&v.ident))));
                    }
                }
                syn::Item::Fn(f) => {
                    self.functions.insert(key(unraw(&f.sig.ident)));
                }
                syn::Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        let mut nested = module.to_vec();
                        nested.push(unraw(&m.ident));
                        self.items(root, &nested, items);
                    }
                }
                _ => {}
            }
        }
    }

    pub(super) fn imported(&self, file: &str, scope: &[String], import: &str) -> bool {
        let (root, mut module) = location(Path::new(file));
        module.extend_from_slice(scope);
        let mut parts = import.split("::").peekable();
        match parts.peek() {
            Some(&"crate") => {
                module.clear();
                parts.next();
            }
            Some(&"self") => {
                parts.next();
            }
            Some(&"super") => {
                while parts.peek() == Some(&"super") {
                    module.pop();
                    parts.next();
                }
            }
            // An unqualified import may be local or external. Only local,
            // fully recorded declarations can provide positive evidence.
            _ => {}
        }
        module.extend(parts.map(str::to_owned));
        let key = (root, module.join("::"));
        self.values.contains(&key) && !self.functions.contains(&key)
    }
}
