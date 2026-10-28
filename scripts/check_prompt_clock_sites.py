#!/usr/bin/env python3
"""Pins the call sites of the counted clock read (`prompt_io::monotonic_ns`).

Every executed read is counted by use in test builds (GATE-CLOCK-READS.1):
the caller passes a `ClockUse`. This check compares the non-test call sites
in crates/bingsu/src with SITES: file, enclosing function and the use it
passes. A new site, a removed one or a changed use fails until SITES is
updated in the same pull request. It is auxiliary evidence: a new call of an
existing site (another `check_deadline` in a loop) changes no site, and only
the executed-read counter catches it.
Test code is skipped: files named tests.rs, and `#[cfg(test)]` modules.
Usage: check_prompt_clock_sites.py   (from the repository root)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = "crates/bingsu/src"
SITES = {
    ("crates/bingsu/src/prompt_io.rs", "entry_deadline", "Entry"),
    ("crates/bingsu/src/prompt_io.rs", "deadline_now", "Deadline"),
    ("crates/bingsu/src/prompt_io.rs", "observe_clock_until", "Identity"),
    ("crates/bingsu/src/prompt_read.rs", "observe", "Approval"),
    ("crates/bingsu/src/commands/collector_process.rs", "now_ns", "Deadline"),
}
CALL = re.compile(r"\bmonotonic_ns\s*\(")
USE = re.compile(r"\A\s*#\[cfg\(test\)\]\s*(?:crate::prompt_io::)?ClockUse::(\w+)\s*,?\s*\)")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|unsafe\s+|extern\s+\"C\"\s+)*fn\s+(\w+)", re.M)
TEST_MOD = re.compile(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")


def without_test_modules(text):
    """Blanks `#[cfg(test)] mod … { … }` bodies, keeping offsets and line numbers."""
    out = list(text)
    for m in TEST_MOD.finditer(text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        for j in range(m.start(), i):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


def sites(root=ROOT):
    found, errors = [], []
    for path in sorted((root / SRC).rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if path.name == "tests.rs":
            continue
        text = without_test_modules(path.read_text().replace("\r\n", "\n"))
        for m in CALL.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            before = text[: m.start()]
            if re.search(r"\bfn\s*$", before):
                continue  # the definition
            functions = FN.findall(before)
            use = USE.match(text[m.end():])
            if not functions or not use:
                errors.append(f"{rel}:{line}: monotonic_ns call without an enclosing fn or a #[cfg(test)] ClockUse argument")
                continue
            found.append((rel, functions[-1], use.group(1)))
    return found, errors


def check(root=ROOT):
    found, errors = sites(root)
    seen = set(found)
    for site in sorted(seen - SITES):
        errors.append(f"unpinned clock read site: {site}")
    for site in sorted(SITES - seen):
        errors.append(f"pinned clock read site missing: {site}")
    for site in sorted(seen):
        if found.count(site) > 1:
            errors.append(f"clock read site appears {found.count(site)} times: {site}")
    return errors


def main():
    errors = check()
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        print("prompt clock sites FAILED: update SITES only with the reviewed change", file=sys.stderr)
        return 1
    print(f"prompt clock sites: ok ({len(SITES)} pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
