#!/usr/bin/env python3
"""Purity canary checker (spec section 1, F-05).

Every path configured in CLIPPY_TOML must have exactly one `// CANARY: <path>`
line in the canary, and clippy must report a disallowed_* diagnostic whose
message names that exact path on that line. A dead rule (no diagnostic), a
rule without a canary, or a canary without a rule all fail.

EXPECTED_COUNT pins the number of configured paths. Change it together with
the config when you add or remove a path, so a rule cannot vanish quietly
(removing a rule and its canary line together would otherwise still pass).

clippy is pointed at CLIPPY_TOML's own folder (CLIPPY_CONF_DIR), and a
clippy.toml or .clippy.toml inside the canary fails, so the config this script
parses is the config clippy applies.
Usage: check_core_purity.py CANARY_DIR CLIPPY_TOML EXPECTED_COUNT
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    canary, cfg_path, expected = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3])
    cfg = tomllib.loads(cfg_path.read_text())
    paths = [e["path"] for k in ("disallowed-methods", "disallowed-types", "disallowed-macros") for e in cfg.get(k, [])]
    if len(paths) != expected:
        print(f"purity canary FAILED: configured paths {len(paths)} != expected {expected}", file=sys.stderr)
        return 1
    dups = sorted({p for p in paths if paths.count(p) > 1})
    if dups:
        print("purity canary FAILED: duplicate configured path: " + ", ".join(dups), file=sys.stderr)
        return 1
    stray = [str(canary / n) for n in ("clippy.toml", ".clippy.toml") if (canary / n).exists()]
    if stray:
        print("purity canary FAILED: stray clippy config in canary: " + ", ".join(stray), file=sys.stderr)
        return 1
    lib = (canary / "src/lib.rs").resolve()
    src = lib.read_text().splitlines()
    tags = {i + 1: m.group(1) for i, l in enumerate(src) if (m := re.search(r"// CANARY: (\S+)$", l))}
    proc = subprocess.run(["cargo", "clippy", "--quiet", "--message-format=json", "--manifest-path", str(canary / "Cargo.toml")],
                          capture_output=True, text=True, env={**os.environ, "CLIPPY_CONF_DIR": str(cfg_path.resolve().parent)})
    if proc.returncode != 0:
        tail = "\n  ".join(proc.stderr.splitlines()[-20:])
        print(f"purity canary FAILED: clippy exited {proc.returncode}\n  {tail}", file=sys.stderr)
        return 1
    hits: dict[int, list[str]] = {}
    errors = []
    for line in proc.stdout.splitlines():
        d = json.loads(line)
        if d.get("reason") != "compiler-message":
            continue
        m = d["message"]
        if not ((m.get("code") or {}).get("code") or "").startswith("clippy::disallowed"):
            continue
        for sp in m["spans"]:
            f = (canary / sp["file_name"]).resolve()
            if f == lib:
                hits.setdefault(sp["line_start"], []).append(m["message"])
            elif canary.resolve() in f.parents:
                errors.append(f"diagnostic outside src/lib.rs: {sp['file_name']}:{sp['line_start']}")
            # Spans in toolchain sources (dbg! expanding to eprintln!) are not
            # counted; they can never satisfy a tag line.
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
