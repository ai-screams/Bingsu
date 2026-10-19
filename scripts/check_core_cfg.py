#!/usr/bin/env python3
"""Conditional-compilation check for bingsu-core (spec section 1, F-05),
and for the prompt adapter crates/bingsu/src/prompt.rs (the token rules
below, so its code is the code that is linted and reviewed). The `bingsu`
binary crate may have no build script either: it could link code that runs
before main.

Code behind cfg can drop out of the lint run (`#[cfg(not(clippy))]`, a target
the CI does not lint, a feature that --all-features turns off), and `#[path]`
or `include!` can pull in code from outside the checked files. bingsu-core is
platform independent and needs no cfg. This script owns the policy and the
file set; the token-level checks live in tools/core-cfg-check (a Rust tool
that sees tokens, so spacing, line breaks, comments and strings cannot hide
anything). It fails on:
  - a symbolic link (file or directory) anywhere under crates/bingsu-core
    (purity-canary/ and target/ excluded): the compiler follows links, so a
    linked directory could bring in code from outside the checked set;
  - any *.rs under crates/bingsu-core outside src/, tests/ and benches/:
    src/ holds the library, tests/ and benches/ hold its test and bench
    targets, and all three get the same checks;
  - a collected file whose real path is not inside crates/bingsu-core;
  - a build script (crates/bingsu-core/build.rs or package.build), which could
    emit cargo:rustc-cfg;
  - a [features] table in crates/bingsu-core/Cargo.toml;
  - a [lib], [[bin]], [[test]], [[bench]] or [[example]] table, or a
    package.autolib/autobins/autotests/autobenches/autoexamples key, in that
    manifest: a target path could point outside the checked folders, so
    targets come only from cargo's automatic discovery;
  - a `.cargo` directory anywhere in the repository (target/ and .git/
    excluded): cargo reads `.cargo/config*` from the working directory up,
    where `[build] rustflags = ["--cap-lints", "warn"]` would turn the forbid
    lints into warnings and `[alias]` could replace a subcommand;
  - a `rust-toolchain` or `rust-toolchain.toml` file anywhere in the
    repository: rustup takes the toolchain from it ahead of the default, and
    a nightly toolchain accepts `cargo-features` that add rustc flags;
  - a `Cargo.toml` anywhere in the repository with a `cargo-features` key
    or a `rustflags` key in any `[profile...]` table: profile rustflags
    reach rustc for one package only (`--extern std` brings std back into
    a no_std crate, `--cap-lints allow` silences the forbid lints there)
    and the canaries, separate crates, would not notice;
  - a `.clippy.toml` anywhere in the repository, or a `clippy.toml` other than
    crates/bingsu-core/clippy.toml and crates/bingsu/clippy.toml: a stray
    config can replace the rules clippy applies;
  - a file under crates/bingsu-core whose extension is `.rs` in another case
    (`.RS`, `.Rs`): on a case-insensitive file system rustc reads `up.RS`
    for `mod up;`, and only lower-case `.rs` files are collected;
  - anything the checker binary rejects (its exit code is passed through).
    Files under src/ go to it as library files; tests/ and benches/ follow
    `--test-targets`, where include_str may read shared tables; the prompt
    adapter follows `--tcb` (every rule but the library-only, address and
    crate-root ones: it hands buffers to write(2)).
Names are compared case-insensitively (`.Cargo`, `Clippy.toml`, `Build.rs`),
since cargo and clippy find them on a case-insensitive file system.

Two phases, so no cargo call runs before the policy that keeps cargo honest
(a `.cargo/config.toml` could set rustc-wrapper, [env] or [alias] for the
build of the checker itself):
  --phase policy                everything above except the checker; no cargo
  --phase tokens --checker PATH runs the token checker on the collected files
Usage (from the repository root):
  check_core_cfg.py --phase policy
  check_core_cfg.py --phase tokens --checker PATH
"""
import argparse
import os
import subprocess
import sys
import tempfile
import tomllib

CORE = "crates/bingsu-core"
ADAPTER = "crates/bingsu/src/prompt.rs"
PROMPT_IO = "crates/bingsu/src/prompt_io.rs"
BINARY = "crates/bingsu"
SKIP = {"purity-canary", "target"}
ALLOWED = {"src", "tests", "benches"}
TARGET_TABLES = ("lib", "bin", "test", "bench", "example")
AUTO_KEYS = ("autolib", "autobins", "autotests", "autobenches", "autoexamples")
CLIPPY_CONFIGS = {"crates/bingsu-core/clippy.toml", "crates/bingsu/clippy.toml"}
REPO_SKIP = {"target", ".git"}


def check_repo_tree(errors):
    for root, dirs, names in os.walk(".", followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in REPO_SKIP)
        for entry in dirs + names:
            path = os.path.normpath(os.path.join(root, entry))
            name = entry.lower()
            if name == ".cargo":
                errors.append(f"cargo config directory in the repository: {path}")
            elif name == ".clippy.toml":
                errors.append(f"clippy config not allowed: {path}")
            # The exact path, so `Clippy.toml` next to an allowed config fails.
            elif name == "clippy.toml" and path not in CLIPPY_CONFIGS:
                errors.append(f"clippy config not allowed: {path}")
            elif name in ("rust-toolchain", "rust-toolchain.toml"):
                errors.append(f"toolchain file not allowed: {path}")
            elif name == "cargo.toml" and os.path.isfile(path):
                check_manifest(path, errors)


def profile_rustflags(table, where):
    """Paths of every `rustflags` key under a [profile...] table."""
    found = []
    for key, value in table.items():
        if key == "rustflags":
            found.append(where)
        elif isinstance(value, dict):
            found.extend(profile_rustflags(value, f"{where}.{key}"))
    return found


def check_manifest(path, errors):
    try:
        with open(path, "rb") as f:
            manifest = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as err:
        errors.append(f"{path}: unreadable manifest: {err}")
        return
    if "cargo-features" in manifest:
        errors.append(f"{path}: cargo-features is not allowed")
    for where in profile_rustflags(manifest.get("profile", {}), "profile"):
        errors.append(f"{path}: rustflags in [{where}] is not allowed")


def collect(errors):
    core_real = os.path.realpath(CORE)
    files = []
    for root, dirs, names in os.walk(CORE, followlinks=False):
        rel = os.path.relpath(root, CORE)
        top = rel.split(os.sep)[0]
        if top in SKIP:
            dirs[:] = []
            continue
        if rel == ".":
            dirs[:] = [d for d in dirs if d not in SKIP]
        # os.walk lists a linked directory in dirs, not names: check both.
        for entry in dirs + names:
            path = os.path.join(root, entry)
            if os.path.islink(path):
                errors.append(f"symlink in core: {path}")
        for name in sorted(names):
            path = os.path.join(root, name)
            if not name.lower().endswith(".rs"):
                continue
            if not name.endswith(".rs"):
                errors.append(f"non-canonical rust extension: {path}")
                continue
            if top not in ALLOWED:
                errors.append(f"rust source outside src/, tests/, benches/: {path}")
            real = os.path.realpath(path)
            if os.path.commonpath([real, core_real]) != core_real:
                errors.append(f"rust source resolves outside {CORE}: {path} -> {real}")
            files.append(path)
    return sorted(files)


def check_policy(errors):
    collect(errors)
    manifest = tomllib.loads(open(os.path.join(CORE, "Cargo.toml")).read())
    build_scripts = [n for n in os.listdir(CORE) if n.lower() == "build.rs"]
    if build_scripts or "build" in manifest.get("package", {}):
        errors.append(f"{CORE}: build script is not allowed (it can emit cargo:rustc-cfg)")
    if "features" in manifest:
        errors.append(f"{CORE}/Cargo.toml: [features] is not allowed (lint every feature combination first)")
    for table in TARGET_TABLES:
        if table in manifest:
            errors.append(f"{CORE}/Cargo.toml: [{table}] is not allowed (targets come from automatic discovery)")
    for key in AUTO_KEYS:
        if key in manifest.get("package", {}):
            errors.append(f"{CORE}/Cargo.toml: package.{key} is not allowed")
    binary = tomllib.loads(open(os.path.join(BINARY, "Cargo.toml")).read())
    if [n for n in os.listdir(BINARY) if n.lower() == "build.rs"] or "build" in binary.get("package", {}):
        errors.append(f"{BINARY}: build script is not allowed (it could link code that runs before main)")
    check_repo_tree(errors)


def checker_args(files):
    """Library files first; tests/ and benches/ after --test-targets, where
    include_str may read shared tables (they never reach the prompt)."""
    library = [f for f in files if f.startswith(f"{CORE}/src/")]
    targets = [f for f in files if not f.startswith(f"{CORE}/src/")]
    return [*library, "--test-targets", *targets]


def check_split_canary(checker, errors):
    """The split above decides which files get the format-source rule, and a
    clean tree passes whichever way it goes. So this runs it the same way on
    a throwaway tree with include_str in src/ and in tests/: the checker must
    reject the src/ file and only it. What makes this fail: sending src/
    files after --test-targets, or tests/ files before it."""
    line = 'pub const X: &str = include_str!("x.txt");\n'
    with tempfile.TemporaryDirectory() as tmp:
        files = [f"{CORE}/src/lib.rs", f"{CORE}/tests/t.rs"]
        for rel in files:
            os.makedirs(os.path.join(tmp, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(tmp, rel), "w") as f:
                f.write(line)
        result = subprocess.run([os.path.abspath(checker), *checker_args(files)], cwd=tmp,
                                capture_output=True, text=True)
    flagged = sorted({l.split(":")[0] for l in result.stderr.splitlines() if "include_str" in l})
    if flagged != [f"{CORE}/src/lib.rs"]:
        errors.append(f"split canary: include_str flagged in {flagged}, expected only {CORE}/src/lib.rs")


def check_tokens(checker, errors):
    # The policy phase already reported collection errors; here only the
    # file list matters. With no files the checker fails on its own.
    result = subprocess.run([checker, *checker_args(collect([])), "--tcb", ADAPTER])
    if result.returncode != 0:
        errors.append("core-cfg-check rejected the files above")
    # Unlike pure core, this bridge owns OS cfg/atomics. Its forbidden-call
    # scan visits every branch; keep the existing adapter --tcb rules intact.
    with open(f"{BINARY}/clippy.toml", "rb") as f:
        config = tomllib.load(f)
    names = sorted({entry["path"].split("::")[-1]
                    for entry in config["disallowed-methods"]})
    result = subprocess.run([checker, "--prompt-io", ",".join(names), PROMPT_IO])
    if result.returncode != 0:
        errors.append("core-cfg-check rejected prompt I/O forbidden calls")
    check_split_canary(checker, errors)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("policy", "tokens"))
    parser.add_argument("--checker", help="path to the core-cfg-check binary (tokens phase)")
    args = parser.parse_args()
    if (args.phase == "tokens") != (args.checker is not None):
        parser.error("--checker goes with --phase tokens, and only with it")
    errors = []
    if args.phase == "policy":
        check_policy(errors)
    else:
        check_tokens(args.checker, errors)
    if errors:
        print(f"core cfg check FAILED ({args.phase}):\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
