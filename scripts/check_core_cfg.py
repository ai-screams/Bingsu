#!/usr/bin/env python3
"""Conditional-compilation check for bingsu-core (spec section 1, F-05).

Code behind cfg can drop out of the lint run (`#[cfg(not(clippy))]`, a target
the CI does not lint, a feature that --all-features turns off). bingsu-core is
platform independent and needs no cfg, so this fails on:
  - any line in crates/bingsu-core/src/**/*.rs with a token starting with `cfg`
    (cfg, cfg_attr, cfg!) unless the line is exactly `#[cfg(test)]`; comments
    are not exempt, so do not write the word in comments there;
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


def main():
    errors = []
    for rs in sorted((CORE / "src").rglob("*.rs")):
        for i, line in enumerate(rs.read_text().splitlines(), 1):
            if CFG.search(line) and line.strip() != "#[cfg(test)]":
                errors.append(f"{rs}:{i}: cfg other than #[cfg(test)]: {line.strip()}")
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
