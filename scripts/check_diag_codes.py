#!/usr/bin/env python3
"""Diagnostic codes are append-only (spec section 6 "진단 구조"): every code
of the base branch's crates/bingsu-core/diag-codes.txt is still listed, with
the same status, or moved from `stable` to `deprecated <version>`. A code is
never removed, reused or brought back from deprecated. The file-backed test in
crates/bingsu-core-tests/tests/config_files.rs keeps the list equal to the registry.

Usage: check_diag_codes.py <base-ref>        (CI: origin/<base branch>)
       check_diag_codes.py --base-file <list> --base-registry <diag_codes.rs>
A base without the file (before the registry existed) passes.

Registry changes (including wording) need one review entry in
crates/bingsu-core/diag-code-reviews.json, a JSON array of objects:
  {"before": "<base SHA-256>", "after": "<head SHA-256>",
   "kind": "wording", "reason": "E101 still means invalid TOML; ..."}
The gate prints the exact hashes. `kind` is `wording` for text-only edits or
`meaning` for changes to the diagnostic contract. Review the triggering
condition, arguments and remedies for each affected code; explain whether
its original meaning is retained. A genuinely different condition needs a
new number; deprecate the old code, never reuse it. The PR reviewer checks
that reasoning against the exact diff. This is a review tripwire, not an
automatic natural-language semantics oracle. Tests/comments/formatting in
the registry also need an acknowledgement; wording edits are not prohibited.
"""
import pathlib
import hashlib
import json
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REL = "crates/bingsu-core/diag-codes.txt"
REGISTRY = "crates/bingsu-core/src/diag_codes.rs"
REVIEWS = "crates/bingsu-core/diag-code-reviews.json"


def registry_review(base, head, reviews, bad):
    """Semantics need human review, not a wording-equality heuristic.

    Bind that review to the exact registry diff so a stale acknowledgement
    cannot authorize a later change. Status/deletion rules still apply.
    """
    if base == head:
        return
    before, after = (hashlib.sha256(text.encode()).hexdigest() for text in (base, head))
    matches = [r for r in reviews if isinstance(r, dict)
               and r.get("before") == before and r.get("after") == after]
    if len(matches) != 1 or matches[0].get("kind") not in ("wording", "meaning") \
            or not isinstance(matches[0].get("reason"), str) or not matches[0]["reason"].strip():
        bad.append(f"registry change needs one explicit wording/meaning review in {REVIEWS}: "
                   f"before={before} after={after}; explain why existing code meanings are preserved "
                   "or which new code replaces a deprecated meaning")


def codes(text):
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            code, status = line.split(" ", 1)
            out[code] = status
    return out


def main(argv):
    base_registry = None
    if argv[:1] == ["--base-file"]:
        base_text = pathlib.Path(argv[1]).read_text()
        if len(argv) != 4 or argv[2] != "--base-registry":
            print("diag codes FAILED: --base-file requires --base-registry <path>", file=sys.stderr)
            return 1
        base_registry = pathlib.Path(argv[3]).read_text()
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
        r = git("show", f"{argv[0]}:{REGISTRY}")
        if r.returncode != 0:
            print(f"diag codes FAILED: cannot read base registry: {r.stderr.strip()}", file=sys.stderr)
            return 1
        base_registry = r.stdout
    base, head = codes(base_text), codes((ROOT / REL).read_text())
    bad = []
    try:
        review_path = ROOT / REVIEWS
        reviews = json.loads(review_path.read_text()) if review_path.exists() else []
        if not isinstance(reviews, list):
            raise ValueError("review file must be a JSON array")
        registry_review(base_registry, (ROOT / REGISTRY).read_text(), reviews, bad)
    except (OSError, ValueError) as error:
        bad.append(f"registry review unreadable: {error}")
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
