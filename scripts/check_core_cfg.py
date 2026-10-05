#!/usr/bin/env python3
"""Conditional-compilation check for bingsu-core (spec section 1, F-05).

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
  - a `.clippy.toml` anywhere in the repository, or a `clippy.toml` other than
    crates/bingsu-core/clippy.toml and crates/bingsu/clippy.toml: a stray
    config can replace the rules clippy applies;
  - a file under crates/bingsu-core whose extension is `.rs` in another case
    (`.RS`, `.Rs`): on a case-insensitive file system rustc reads `up.RS`
    for `mod up;`, and only lower-case `.rs` files are collected;
  - anything the checker binary rejects (its exit code is passed through).
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
import tomllib

CORE = "crates/bingsu-core"
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
    check_repo_tree(errors)


def check_tokens(checker, errors):
    # The policy phase already reported collection errors; here only the
    # file list matters. With no files the checker fails on its own.
    files = collect([])
    result = subprocess.run([checker, *files])
    if result.returncode != 0:
        errors.append("core-cfg-check rejected the files above")


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
