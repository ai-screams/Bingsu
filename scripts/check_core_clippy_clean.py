#!/usr/bin/env python3
"""Runs clippy on bingsu-core and counts its diagnostics (spec section 1, F-05).

Runs `cargo clippy --message-format=json` on bingsu-core and fails if clippy
exits non-zero or if any compiler message has level warning or error. The
exit code alone is not enough: `--cap-lints warn` (from RUSTFLAGS or a cargo
config) turns the forbid and deny lints into warnings and clippy then exits
0, but the diagnostics are still emitted. (`--cap-lints allow` emits nothing;
the purity canary catches that as dead rules.)

clippy reads the rules from crates/bingsu-core (CLIPPY_CONF_DIR set here, not
inherited). Each run uses a fresh, temporary CARGO_TARGET_DIR: cargo replays
a cached clippy result without checking which rustc wrapper produced it, so a
run under a wrapper that added `--cap-lints allow` for bingsu-core would
otherwise leave a clean result that later runs repeat.
Usage: check_core_clippy_clean.py   (run from the repository root)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

CLIPPY = [
    "cargo", "clippy", "--quiet", "--message-format=json", "-p", "bingsu-core",
    "--all-targets", "--all-features", "--", "-D", "warnings",
    "-F", "clippy::disallowed_methods", "-F", "clippy::disallowed_types",
    "-F", "clippy::disallowed_macros",
]


def main():
    target_dir = tempfile.mkdtemp(prefix="core-clippy-")
    env = {
        **os.environ,
        "CLIPPY_CONF_DIR": os.path.abspath("crates/bingsu-core"),
        "CARGO_TARGET_DIR": target_dir,
    }
    try:
        proc = subprocess.run(CLIPPY, capture_output=True, text=True, env=env)
    finally:
        shutil.rmtree(target_dir, ignore_errors=True)
    found = []
    for line in proc.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("reason") != "compiler-message":
            continue
        m = d["message"]
        if m.get("level") in ("warning", "error"):
            found.append(m.get("rendered") or m.get("message", ""))
    if found:
        print(f"core clippy FAILED: {len(found)} diagnostics\n" + "".join(found), file=sys.stderr)
        return 1
    if proc.returncode != 0:
        tail = "\n  ".join(proc.stderr.splitlines()[-20:])
        print(f"core clippy FAILED: clippy exited {proc.returncode}\n  {tail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
