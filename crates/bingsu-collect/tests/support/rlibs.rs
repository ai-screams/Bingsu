//! The libraries cargo built for this test run, for tests that compile
//! source probes with rustc. Where they sit depends on the Cargo version:
//! up to 1.99 every library of a profile is in `<profile>/deps`, next to the
//! test binary; from 1.100 each unit has its own
//! `<profile>/build/<package>/<hash>/out`, the test binary included. The
//! layout is read from where this test binary sits, so a target folder that
//! holds both layouts (two toolchains) never mixes them.
use std::path::{Path, PathBuf};

pub struct Rlibs {
    dirs: Vec<PathBuf>,
}

impl Rlibs {
    pub fn find() -> Rlibs {
        let exe = std::env::current_exe().unwrap();
        let parent = exe.parent().unwrap();
        if parent.file_name().is_some_and(|n| n == "deps") {
            return Rlibs {
                dirs: vec![parent.to_path_buf()],
            };
        }
        // <profile>/build/<package>/<hash>/out/<binary>
        Rlibs {
            dirs: unit_dirs(parent.ancestors().nth(3).unwrap()),
        }
    }

    /// The newest `lib<name>-*.rlib`: several builds of one crate (other
    /// features, an earlier run) can sit side by side, and any one built by
    /// this toolchain serves a probe; the newest is the one this run built or
    /// checked last.
    pub fn rlib(&self, name: &str) -> PathBuf {
        let prefix = format!("lib{name}-");
        self.dirs
            .iter()
            .flat_map(|d| std::fs::read_dir(d).unwrap())
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "rlib")
                    && p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(&prefix)
            })
            .max_by_key(|p| p.metadata().unwrap().modified().unwrap())
            .unwrap_or_else(|| panic!("cargo-built {name} rlib in {:?}", self.dirs))
    }

    /// `-L dependency=<folder>` for every folder that holds a library, so
    /// rustc finds the dependencies of the libraries given with `--extern`
    /// (it picks each by the hash recorded in its dependent).
    pub fn search_args(&self) -> Vec<String> {
        self.dirs
            .iter()
            .flat_map(|d| ["-L".to_string(), format!("dependency={}", d.display())])
            .collect()
    }
}

/// The `<package>/<hash>/out` folders under `build` that hold a library;
/// the others (build-script output, the test binaries) and stray files are
/// left out.
fn unit_dirs(build: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for package in std::fs::read_dir(build).unwrap() {
        let package = package.unwrap().path();
        let Ok(units) = std::fs::read_dir(&package) else {
            continue;
        };
        for unit in units {
            let out = unit.unwrap().path().join("out");
            let has_rlib = std::fs::read_dir(&out).is_ok_and(|mut entries| {
                entries.any(|e| e.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "rlib")))
            });
            if has_rlib {
                dirs.push(out);
            }
        }
    }
    dirs.sort();
    dirs
}

// What fails this: a prefix without the dash (`libfoo_bar` taken for
// `foo`), no rlib extension check (`.rmeta` taken), the oldest build
// instead of the newest, folders without a library given to rustc, a stray
// file under build/ that panics the walk.
#[test]
fn newest_rlib_of_the_exact_crate_and_only_library_folders() {
    use std::fs;
    use std::time::{Duration, SystemTime};
    let build = std::env::temp_dir().join(format!("bingsu-rlibs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&build);
    let at = |rel: &str, secs: u64| {
        let path = build.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = fs::File::create(&path).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
        path
    };
    at("foo/a/out/libfoo-a.rlib", 1_000);
    let newest = at("foo/b/out/libfoo-b.rlib", 2_000);
    at("foo_bar/c/out/libfoo_bar-c.rlib", 3_000);
    at("foo/b/out/libfoo-b.rmeta", 4_000);
    at("tool/e/out/generated.rs", 5_000);
    at("stray-file", 6_000);
    let rlibs = Rlibs {
        dirs: unit_dirs(&build),
    };
    assert_eq!(rlibs.rlib("foo"), newest);
    let folders: Vec<_> = ["foo/a/out", "foo/b/out", "foo_bar/c/out"]
        .iter()
        .map(|rel| build.join(rel))
        .collect();
    assert_eq!(rlibs.dirs, folders);
    fs::remove_dir_all(&build).unwrap();
}
