#!/usr/bin/env python3
"""The prompt path of the CLI crate (crates/bingsu) forbids the disallowed_*
lints in each of its modules: forbid cannot be switched off by #[expect] or
#[allow], while the crate-wide clippy.toml rules are only denied (init's
trusted_env needs its #[expect]). Fails if a listed file's first inner
attribute is not that forbid, if a listed file is missing, or if prompt.rs
or envelope.rs names a file API (see NO_FILE_API)."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The modules `bingsu prompt` runs: the command, its argument parser and the
# syscall wrappers it writes and exits through. The `fn main` that picks the
# prompt branch carries the same forbid as an item attribute (MAIN): a crate
# root #![forbid] would also forbid init's #[expect] in trusted_env.
PROMPT_PATH = ["crates/bingsu/src/prompt.rs", "crates/bingsu/src/envelope.rs", "crates/bingsu/src/sys.rs"]
MAIN = "crates/bingsu/src/main.rs"
WANT = "#![forbid(clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]"
WANT_MAIN = WANT.replace("#!", "#", 1)

# A second, coarser guard: the forbid above covers only the clippy.toml list,
# which names no file API. prompt.rs and envelope.rs must not name one either,
# nor start a process (Command). Plain token search over lines that are not //
# comments, so it misses:
#   - std::path::Path methods that touch the file system (exists, metadata,
#     is_file, canonicalize): Path::new("x").exists() passes this guard;
#   - an alias imported elsewhere and a macro that expands to a file call;
#   - raw libc calls (libc::open, libc::stat): sys.rs makes those and is not
#     searched here;
#   - fn main in main.rs, which is not searched either.
# It skips a line only when the whole line starts with //, so a token in a
# string, in a comment after code, or inside a /* */ block trips it: a false
# alarm, never a miss. At run time the strace allowlist test
# (tests/shell/test_prompt_env_paths.py) checks every path the binary names.
NO_FILE_API = ["crates/bingsu/src/prompt.rs", "crates/bingsu/src/envelope.rs"]
FILE_TOKENS = ("std::fs", "fs::", "File", "OpenOptions", "read_dir", "Command")

bad = []
for rel in NO_FILE_API:
    p = ROOT / rel
    if not p.is_file():
        continue  # reported as missing below
    for n, line in enumerate(p.read_text().splitlines(), 1):
        if line.lstrip().startswith("//"):
            continue
        hit = [tok for tok in FILE_TOKENS if tok in line]
        if hit:
            bad.append(f"{rel}:{n}: names a file or process API ({', '.join(hit)})")
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
# The attribute right before `fn main`, whitespace and line breaks ignored.
main_text = "".join((ROOT / MAIN).read_text().split()) if (ROOT / MAIN).is_file() else ""
at = main_text.find("fnmain(")
if at < 0:
    bad.append(f"{MAIN}: no fn main")
elif not main_text[:at].endswith("".join(WANT_MAIN.split())):
    bad.append(f"{MAIN}: fn main is not preceded by {WANT_MAIN}")
if bad:
    print("prompt forbid gate FAILED:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(1)
print(f"prompt forbid gate: ok ({len(PROMPT_PATH)} files and fn main forbid, {len(NO_FILE_API)} name no file API)")
