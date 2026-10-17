#!/usr/bin/env python3
"""The JSON Schema and core's checker accept the same durations: every
`pattern` of a duration key in the committed config and theme schemas
gives, on each row of crates/bingsu-core/schema/duration-corpus.json, the
answer core's `parse_duration_ms` gives (core's own test reads the same
corpus in bingsu-core-tests). A schema that lets through what `config check` refuses would show
an editor no error for a config bingsu then rejects.
Usage: check_schema_corpus.py   (from the repository root)
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS = [ROOT / f"crates/bingsu-core/schema/{name}-v1.json" for name in ("config", "theme")]
CORPUS = ROOT / "crates/bingsu-core/schema/duration-corpus.json"


def patterns(node, path=""):
    """`(path, pattern)` of every key named cache, timeout or min (the
    duration keys) that has a pattern."""
    if isinstance(node, dict):
        if node.get("pattern") and path.rsplit(".", 1)[-1] in ("cache", "timeout", "min"):
            yield path, node["pattern"]
        for k, v in node.items():
            yield from patterns(v, f"{path}.{k}")


# 이것을 실패시키는 것: 시간 패턴이 corpus의 경계·앞자리 0·줄바꿈을 잘못 허용하거나 거부하는 것.
def main():
    corpus = json.loads(CORPUS.read_text())
    found = []
    for file in SCHEMAS:
        found.extend((file.name + path, pat) for path, pat in patterns(json.loads(file.read_text())))
    bad = []
    if len(found) < 4:
        bad.append(f"expected the duration patterns of cache, timeout and min, found {[p for p, _ in found]}")
    for path, pat in found:
        rx = re.compile(pat)
        for text, ok in corpus:
            if bool(rx.search(text)) != ok:
                bad.append(f"{path}: {text!r} schema {'accepts' if not ok else 'refuses'}, core {'accepts' if ok else 'refuses'}")
    if bad:
        print("schema corpus FAILED:\n  " + "\n  ".join(bad), file=sys.stderr)
        return 1
    print(f"schema corpus: ok ({len(found)} duration patterns, {len(corpus)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
