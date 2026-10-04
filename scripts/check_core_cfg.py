#!/usr/bin/env python3
"""Conditional-compilation check for bingsu-core (spec section 1, F-05).

Code behind cfg can drop out of the lint run (`#[cfg(not(clippy))]`, a target
the CI does not lint, a feature that --all-features turns off). bingsu-core is
platform independent and needs no cfg, so this fails on:
  - any line in crates/bingsu-core/src/**/*.rs with a token starting with `cfg`
    (cfg, cfg_attr, cfg!) unless the line is exactly `#[cfg(test)]`; comments
    are not exempt, so do not write the word in comments there;
  - any *.rs under crates/bingsu-core outside src/ (purity-canary/ and
    target/ excluded): core sources live only in src/;
  - a path attribute (`#[path = ...]`) or `include!(...)` in any scanned
    file, since both pull in code from elsewhere; include_str!/include_bytes!
    are data and stay allowed. Comments are not exempt;
  - a build script (crates/bingsu-core/build.rs or package.build), which could
    emit cargo:rustc-cfg;
  - a [features] table in crates/bingsu-core/Cargo.toml.
Usage: check_core_cfg.py   (run from the repository root)
"""
import pathlib
import re
import sys
import tomllib

CORE = pathlib.Path("crates/bingsu-core")
CFG = re.compile(r"\bcfg")
PULL_IN = re.compile(r"#\s*\[\s*path\s*=|\binclude!\s*\(")
SKIP = {"purity-canary", "target"}


def main():
    errors = []
    for rs in sorted(CORE.rglob("*.rs")):
        rel = rs.relative_to(CORE)
        if rel.parts[0] in SKIP:
            continue
        if rel.parts[0] != "src":
            errors.append(f"rust source outside src/: {rs}")
        for i, line in enumerate(rs.read_text().splitlines(), 1):
            if CFG.search(line) and line.strip() != "#[cfg(test)]":
                errors.append(f"{rs}:{i}: cfg other than #[cfg(test)]: {line.strip()}")
            if PULL_IN.search(line):
                errors.append(f"{rs}:{i}: #[path] or include! pulls in code: {line.strip()}")
    manifest = tomllib.loads((CORE / "Cargo.toml").read_text())
    if (CORE / "build.rs").exists() or "build" in manifest.get("package", {}):
        errors.append(f"{CORE}: build script is not allowed (it can emit cargo:rustc-cfg)")
    if "features" in manifest:
        errors.append(f"{CORE}/Cargo.toml: [features] is not allowed (lint every feature combination first)")
    if errors:
        print("core cfg check FAILED:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
