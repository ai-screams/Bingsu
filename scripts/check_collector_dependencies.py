#!/usr/bin/env python3
"""Exact normal dependency closure, separate from bench/dev and build edges.

No update/approval mode: changes to the committed allowlist require review.
Cargo's target and package scoped tree supplies active features and edges.
Metadata alone overapproximates optional/workspace feature edges.
"""
import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "crates/bingsu-collect/dependencies.allowlist.tsv"
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu",
           "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-musl", "x86_64-pc-windows-gnu")


def closure(tree):
    import re
    rows, stack = set(), []
    for line in tree.splitlines():
        match = re.fullmatch(r"(\d+)([\w-]+) v([^ |]+)(?: \([^|]*\))?\|([^|]*)", line)
        if not match:
            raise ValueError("unrecognized dependency tree line: " + line)
        depth, name, version, features = match.groups()
        depth = int(depth)
        label = name + "@" + version
        rows.add(f"node\t{label}\t{features or '-'}\t-")
        if depth:
            rows.add(f"edge\t{stack[depth - 1]}\t{name}\t{label}")
        stack[depth:] = [label]
    return rows


def tree(target, scope):
    package = "bingsu-bench" if scope == "bench" else "bingsu-collect"
    command = ["cargo", "tree", "--locked", "-p", package, "--target", target,
               "--edges", "normal,dev" if scope == "collector-tests" else "normal",
               "--no-dedupe", "--prefix", "depth", "--format", "{p}|{f}"]
    if scope == "product-all":
        command.append("--all-features")
    return subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True).stdout

SCOPES = ("product-default", "product-all", "bench", "collector-tests")

def audit(actual, expected):
    return sorted(actual - expected), sorted(expected - actual)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=pathlib.Path, help="dependency tree fixture (audit tests)")
    parser.add_argument("--target", choices=TARGETS)
    args = parser.parse_args()
    rows = {line for line in ALLOWLIST.read_text().splitlines() if line and not line.startswith("#")}
    failed = False
    for target in ([args.target] if args.target else TARGETS):
        for scope in SCOPES:
            value = args.tree.read_text() if args.tree else tree(target, scope)
            prefix = target + "\t" + scope + "\t"
            expected = {row[len(prefix):] for row in rows if row.startswith(prefix)}
            extra, missing = audit(closure(value), expected)
            if not expected or extra or missing:
                failed = True
                print(f"{target}/{scope}: unexpected={extra}, missing={missing}", file=sys.stderr)
    print(f"collector dependency allowlist: {'FAILED' if failed else 'ok'}")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
