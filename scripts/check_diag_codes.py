#!/usr/bin/env python3
"""Diagnostic codes are append-only (spec section 6 "진단 구조"): every code
of the base branch's crates/bingsu-core/diag-codes.txt is still listed, with
the same status, or moved from `stable` to `deprecated <version>`. A code is
never removed, reused or brought back from deprecated. The file-backed test in
crates/bingsu-core-tests/tests/config_files.rs keeps the list equal to the registry.

Usage: check_diag_codes.py <base-ref>        (CI: origin/<base branch>)
       check_diag_codes.py --base-file <path>
A base without the file (before the registry existed) passes.
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REL = "crates/bingsu-core/diag-codes.txt"


def codes(text):
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            code, status = line.split(" ", 1)
            out[code] = status
    return out


def main(argv):
    if argv[:1] == ["--base-file"]:
        base_text = pathlib.Path(argv[1]).read_text()
    else:
        git = lambda *a: subprocess.run(["git", *a], capture_output=True, text=True, cwd=ROOT)
        if git("rev-parse", "--verify", "--quiet", f"{argv[0]}^{{commit}}").returncode != 0:
            print(f"diag codes FAILED: base {argv[0]} is not a commit here (fetch it first)", file=sys.stderr)
            return 1
        if not git("ls-tree", "--name-only", argv[0], "--", REL).stdout.strip():
            print(f"diag codes: no {REL} at {argv[0]}, nothing to compare")
            return 0
        r = git("show", f"{argv[0]}:{REL}")
        if r.returncode != 0:
            print(f"diag codes FAILED: {r.stderr.strip()}", file=sys.stderr)
            return 1
        base_text = r.stdout
    base, head = codes(base_text), codes((ROOT / REL).read_text())
    bad = []
    for code, was in base.items():
        now = head.get(code)
        if now is None:
            bad.append(f"{code} was removed")
        elif now != was and not (was == "stable" and now.startswith("deprecated ")):
            bad.append(f"{code} changed from `{was}` to `{now}`")
    if bad:
        print("diag codes FAILED:\n  " + "\n  ".join(bad), file=sys.stderr)
        return 1
    print(f"diag codes: ok ({len(base)} base codes kept, {len(head) - len(base)} new)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
