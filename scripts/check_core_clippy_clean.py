#!/usr/bin/env python3
"""Counts clippy diagnostics for bingsu-core (spec section 1, F-05).

Reads `cargo clippy --message-format=json` on stdin and fails if any
compiler message has level warning or error. The exit code alone is not
enough: `--cap-lints warn` (from RUSTFLAGS or a cargo config) turns the
forbid and deny lints into warnings and clippy then exits 0, but the
diagnostics are still emitted. (`--cap-lints allow` emits nothing; the purity
canary catches that as dead rules.) Run it behind `set -o pipefail` so a
failing cargo also fails the pipeline.
Usage: cargo clippy ... --message-format=json | check_core_clippy_clean.py
"""
import json
import sys


def main():
    found = []
    for line in sys.stdin:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
