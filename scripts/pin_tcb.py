#!/usr/bin/env python3
"""Re-pins the trusted files of the prompt path (TCB_SHA256 in
scripts/check_cli_prompt_forbid.py). Without --write it only reports: each
changed file with its pinned and current SHA-256, so the change can be
reviewed as a security change. With --write it rewrites the pins it
reported, and nothing else. A changed pin belongs in the same pull request
as the change and needs the security review of that pull request.
Usage: pin_tcb.py [--write]   (from the repository root)
"""
import argparse
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/check_cli_prompt_forbid.py"
PIN = re.compile(r'^(    "([^"]+)": )"([0-9a-f]*)",$', re.M)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="rewrite the changed pins")
    args = parser.parse_args()
    text = GATE.read_text()
    changed = []
    for m in PIN.finditer(text):
        rel, old = m.group(2), m.group(3)
        new = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        if new != old:
            changed.append((rel, old, new))
    for rel, old, new in changed:
        print(f"{rel}\n  pinned  {old or '(none)'}\n  current {new}")
    if not changed:
        print("TCB pins: all current")
        return 0
    if args.write:
        for rel, old, new in changed:
            text = text.replace(f'    "{rel}": "{old}",', f'    "{rel}": "{new}",', 1)
        GATE.write_text(text)
        print(f"rewrote {len(changed)} pin(s) in {GATE.relative_to(ROOT)}")
        return 0
    print(f"{len(changed)} pin(s) differ; review the files above, then run with --write", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
