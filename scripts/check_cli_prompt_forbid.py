#!/usr/bin/env python3
"""The prompt path of the CLI crate (crates/bingsu) forbids the disallowed_*
lints in each of its modules: forbid cannot be switched off by #[expect] or
#[allow], while the crate-wide clippy.toml rules are only denied (init's
trusted_env needs its #[expect]). Fails if a listed file's first inner
attribute is not that forbid, or if a listed file is missing."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The modules `bingsu prompt` runs: the command, its argument parser and the
# syscall wrappers it writes and exits through.
PROMPT_PATH = ["crates/bingsu/src/prompt.rs", "crates/bingsu/src/envelope.rs", "crates/bingsu/src/sys.rs"]
WANT = "#![forbid(clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]"

bad = []
for rel in PROMPT_PATH:
    p = ROOT / rel
    if not p.is_file():
        bad.append(f"{rel}: missing")
        continue
    # The first inner attribute, joined over the lines rustfmt splits it into.
    text = p.read_text()
    start = text.find("#![")
    first = None if start < 0 else "".join(text[start:text.index("]", start) + 1].split())
    if first != "".join(WANT.split()):
        bad.append(f"{rel}: first inner attribute is {first!r}")
if bad:
    print("prompt forbid gate FAILED:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(1)
print(f"prompt forbid gate: ok ({len(PROMPT_PATH)} files)")
