#!/usr/bin/env python3
"""Validates JSON documents against crates/bingsu-core/schema/diag-output-v1.json.

Reads {"def": null | "<name>", "documents": [<text>, ...]} from stdin. With a
`def`, each document is checked against that entry of the schema's `$defs`
instead of the root. Documents are given as text so that invalid JSON is a
failure too. Exit 0 when all pass, 1 with the first problems on stderr.
Needs the `jsonschema` package of scripts/schema-requirements.txt.
"""
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

SCHEMA = pathlib.Path(__file__).resolve().parents[1] / "crates/bingsu-core/schema/diag-output-v1.json"


def main() -> int:
    request = json.load(sys.stdin)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    if request.get("def"):
        schema = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/" + request["def"]}
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    bad = 0
    for n, text in enumerate(request["documents"]):
        try:
            doc = json.loads(text)
        except ValueError as e:
            print(f"document {n}: not JSON: {e}", file=sys.stderr)
            bad += 1
            continue
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        for e in errors[:5]:
            where = "/".join(str(p) for p in e.path) or "(root)"
            print(f"document {n}: {where}: {e.message[:200]}", file=sys.stderr)
        bad += bool(errors)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
