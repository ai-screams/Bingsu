#!/usr/bin/env python3
"""Validate shared engine/schema corpora with JSON Schema draft 2020-12.

Install scripts/schema-requirements.txt first. Standalone runs the Rust oracle,
which supplies fresh schemas and exhaustive key combinations on stdin. Missing
Python dependencies, a failed engine check, and empty combinations all fail.
"""
import json
import os
import pathlib
import subprocess
import sys

from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "crates/bingsu-core/schema"


def corpus(name):
    return json.loads((SCHEMA_DIR / f"{name}-corpus.json").read_text(encoding="utf-8"))


def nodes(node, path=()):
    """Yield schema nodes at key-table paths, including generated builtins."""
    yield path, node
    for key, child in node.get("properties", {}).items():
        yield from nodes(child, (*path, key))
    extra = node.get("additionalProperties")
    if isinstance(extra, dict):
        yield from nodes(extra, (*path, "*"))


def accepts(node, value):
    return Draft202012Validator(node).is_valid(value)


def check(schemas, segment_cases):
    # 이것을 실패시키는 것: stdin에서 키 조합을 빠뜨리고 corpus만 통과시키는 것.
    assert segment_cases, "missing engine-generated key combinations"
    # 이것을 실패시키는 것: config 또는 theme 스키마를 통째로 누락하는 것.
    assert set(schemas) == {"config", "theme"}, "both schemas are required"
    bad = []
    counts = {}
    for name, root in schemas.items():
        # 이것을 실패시키는 것: 잘못된 스키마 keyword/type을 검사 없이 사용하는 것.
        Draft202012Validator.check_schema(root)
        # 이것을 실패시키는 것: 한 스키마의 생성 키 조합만 모두 누락하는 것.
        assert any(name in c["schemas"] for c in segment_cases), f"{name}: no key combinations"
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
        data = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        check(data["schemas"], data["segment_cases"])
    else:
        # The same engine oracle and generated combinations as cargo test.
        # The Rust test invokes this script with --stdin, so no recursion.
        result = subprocess.run([
            "cargo", "test", "-j", "2", "-p", "bingsu-core-tests",
            "--test", "config_files", "schema", "--", "--nocapture",
        ], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
            env={**os.environ, "BINGSU_SCHEMA_PY": sys.executable})
        print(result.stdout, end="")
        # 이것을 실패시키는 것: Rust 시험 이름 변경/필터 오타로 0개만 실행하는 것.
        assert "schema corpus: ok;" in result.stdout, "Rust schema oracle did not run"
    return 0


if __name__ == "__main__":
    sys.exit(main())
