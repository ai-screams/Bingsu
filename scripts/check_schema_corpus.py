#!/usr/bin/env python3
"""Check the shared engine/schema corpora against both generated schemas.

Only the schema keywords used by these focused checks are interpreted here;
this is not a general JSON Schema validator. No third-party dependency is
needed by the purity CI job. Rust also calls this with freshly generated
schemas on stdin, after checking the same rows against engine functions.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "crates/bingsu-core/schema"


def corpus(name):
    return json.loads((SCHEMA_DIR / f"{name}-corpus.json").read_text())


def nodes(node, path=()):
    """Yield schema nodes at key-table paths, including generated builtins."""
    yield path, node
    for key, child in node.get("properties", {}).items():
        yield from nodes(child, (*path, key))
    extra = node.get("additionalProperties")
    if isinstance(extra, dict):
        yield from nodes(extra, (*path, "*"))


def accepts(node, value):
    """Evaluate the keywords needed by corpus fragments (including if/then)."""
    if isinstance(node, bool):
        return node
    if "type" in node:
        typ = node["type"]
        types = {"string": str, "array": list, "object": dict,
                 "boolean": bool, "integer": int, "number": (int, float)}
        if not isinstance(value, types[typ]):
            return False
    if "enum" in node and value not in node["enum"]:
        return False
    if "const" in node and value != node["const"]:
        return False
    if "pattern" in node and isinstance(value, str):
        if not re.search(node["pattern"], value):
            return False
    if "allOf" in node and not all(accepts(n, value) for n in node["allOf"]):
        return False
    if "if" in node and accepts(node["if"], value):
        if not accepts(node.get("then", True), value):
            return False
    if isinstance(value, dict):
        if any(key not in value for key in node.get("required", [])):
            return False
        props = node.get("properties", {})
        for key, item in value.items():
            if not accepts(node.get("propertyNames", True), key):
                return False
            if not accepts(props.get(key, node.get("additionalProperties", True)), item):
                return False
    if isinstance(value, list) and "items" in node:
        if not all(accepts(node["items"], item) for item in value):
            return False
    return True


def check(schemas, segment_cases=()):
    bad = []
    counts = {}
    for name, root in schemas.items():
        by_path = dict(nodes(root))
        # Engine types, rather than property-name guesses, identify every
        # duration/text/color/segments occurrence through the generated tag.
        for kind in ("duration", "segment-id", "color", "text"):
            rows = corpus(kind)
            targets = []
            for path, node in by_path.items():
                if node.get("x-bingsu-type") == kind:
                    targets.append((path, node))
                if node.get("items", {}).get("x-bingsu-type") == kind:
                    targets.append(((*path, "items"), node["items"]))
                if node.get("propertyNames", {}).get("x-bingsu-type") == kind:
                    targets.append(((*path, "propertyNames"), node["propertyNames"]))
            if not targets:
                bad.append(f"{name}: missing {kind} constraints")
            counts[f"{name}/{kind}"] = len(targets)
            for path, node in targets:
                for text, ok in rows:
                    if accepts(node, text) != ok:
                        bad.append(f"{name}:{'.'.join(path)} {kind} {text!r}: expected {ok}")
            # Check IDs at both real use sites, so moving a constraint to
            # an ineffective keyword cannot silently pass.
            if kind == "segment-id":
                segments = by_path[("segment",)]
                for text, ok in rows:
                    if accepts(segments, {text: {}}) != ok:
                        bad.append(f"{name}: segment property {text!r}: expected {ok}")
        for case in corpus("segment-keys"):
            if name not in case["schemas"]:
                continue
            actual = accepts(by_path[("segment",)], case["segment"])
            if actual != case["ok"]:
                bad.append(f"{name}: segment keys {case!r}")
        # Rust supplies exhaustive combinations from KEYS and KINDS;
        # theme cases are filtered by the same key-table visibility flag.
        for case in segment_cases:
            if name in case["schemas"]:
                if accepts(by_path[("segment",)], case["segment"]) != case["ok"]:
                    bad.append(f"{name}: generated key case {case!r}")
    if bad:
        raise AssertionError("schema corpus FAILED:\n  " + "\n  ".join(bad))
    sizes = {kind: len(corpus(kind)) for kind in
             ("duration", "segment-id", "color", "text", "segment-keys")}
    print(f"schema corpus: ok; rows={sizes}; occurrences={counts}; key combinations={len(segment_cases)}")


def main():
    if "--stdin" in sys.argv:
        data = json.load(sys.stdin)
        check(data["schemas"], data.get("segment_cases", []))
    else:
        check({name: json.loads((SCHEMA_DIR / f"{name}-v1.json").read_text())
               for name in ("config", "theme")})
    return 0


if __name__ == "__main__":
    sys.exit(main())
