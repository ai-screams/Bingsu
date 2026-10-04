#!/usr/bin/env python3
"""Purity canary checker (spec section 1, F-05).

Every path configured in CLIPPY_TOML must have exactly one `// CANARY: <path>`
line in the canary, and clippy must report a disallowed_* diagnostic whose
message names that exact path on that line. A dead rule (no diagnostic), a
rule without a canary, or a canary without a rule all fail.
Usage: check_core_purity.py CANARY_DIR CLIPPY_TOML
"""
import json
import pathlib
import re
import subprocess
import sys
import tomllib


def main():
    canary, cfg_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    cfg = tomllib.loads(cfg_path.read_text())
    paths = [e["path"] for k in ("disallowed-methods", "disallowed-types", "disallowed-macros") for e in cfg.get(k, [])]
    src = (canary / "src/lib.rs").read_text().splitlines()
    tags = {i + 1: m.group(1) for i, l in enumerate(src) if (m := re.search(r"// CANARY: (\S+)$", l))}
    out = subprocess.run(["cargo", "clippy", "--quiet", "--message-format=json", "--manifest-path", str(canary / "Cargo.toml")],
                         capture_output=True, text=True).stdout
    hits: dict[int, list[str]] = {}
    for line in out.splitlines():
        d = json.loads(line)
        if d.get("reason") != "compiler-message":
            continue
        m = d["message"]
        if not ((m.get("code") or {}).get("code") or "").startswith("clippy::disallowed"):
            continue
        for sp in m["spans"]:
            hits.setdefault(sp["line_start"], []).append(m["message"])
    errors = []
    for p in paths:
        lines = [ln for ln, t in tags.items() if t == p]
        if len(lines) != 1:
            errors.append(f"{p}: {len(lines)} canary lines (want 1)")
        elif not any(f"`{p}`" in msg for msg in hits.get(lines[0], [])):
            errors.append(f"{p}: no diagnostic on canary line {lines[0]} (dead rule)")
    for ln, t in tags.items():
        if t not in paths:
            errors.append(f"canary line {ln} tags {t}, which is not configured")
    if errors:
        print("purity canary FAILED:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    print(f"purity canary: {len(paths)} configured paths, each diagnosed on its own line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
