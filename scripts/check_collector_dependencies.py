#!/usr/bin/env python3
"""Exact normal dependency closure, separate from bench/dev and build edges.

No update/approval mode: changes to the committed allowlist require review.
Cargo's target and package scoped tree supplies active features and edges.
Metadata alone overapproximates optional/workspace feature edges.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "crates/bingsu-collect/dependencies.allowlist.tsv"
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu",
           "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-musl",
           "aarch64-unknown-linux-musl", "x86_64-pc-windows-gnu")
GIT_PINS = {"gix-index": "0.56.0", "gix-pack": "0.75.0", "gix-object": "0.65.0",
            "gix-config": "0.61.0", "gix-ref": "0.68.0", "gix-ignore": "0.23.0",
            "gix-attributes": "0.36.0", "gix-revwalk": "0.36.0",
            "gix-utils": "0.4.0", "gix-error": "0.4.0", "gix-zlib": "0.2.0"}
FORBIDDEN_PACKAGES = {"gix", "gix-diff", "gix-status", "gix-filter", "gix-worktree",
                      "gix-odb", "gix-discover", "gix-command"}
FORBIDDEN_FEATURES = {"blob", "signature", "parallel", "generate", "streaming-input"}


def closure(tree):
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
    # Include the front's feature unification in the actual deployment graph.
    package = ("bingsu-bench" if scope == "bench" else
               "bingsu" if scope.startswith("product-") else "bingsu-collect")
    edges = {"collector-tests": "normal,dev", "collector-build": "normal,build"}.get(scope, "normal")
    command = ["cargo", "tree", "--locked", "-p", package, "--target", target,
               "--edges", edges,
               "--no-dedupe", "--prefix", "depth", "--format", "{p}|{f}"]
    if scope in {"product-all", "collector-all"}:
        command.append("--all-features")
    return subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True).stdout

SCOPES = ("product-default", "product-all", "bench", "collector-default", "collector-all", "collector-tests", "collector-build")


def git_policy(rows, *, front=False):
    """Deny dangerous capabilities even if someone adds them to the allowlist."""
    bad = []
    for row in sorted(rows):
        kind, label, features, _ = row.split("\t")
        if kind != "node":
            continue
        name = label.split("@", 1)[0]
        # 이것을 실패시키는 것: shared identity를 통해 앞단에 Git package를 넣는 것.
        if front and (name == "gix" or name.startswith("gix-")):
            bad.append("Git package reached the front: " + label)
        if name in FORBIDDEN_PACKAGES:
            bad.append("forbidden package: " + label)
        if name.startswith("gix-"):
            for feature in features.split(","):
                if feature in FORBIDDEN_FEATURES or feature.startswith("parallel-"):
                    bad.append(f"forbidden feature: {label}/{feature}")
        if name in GIT_PINS:
            want = {"gix-object": "sha1", "gix-utils": "bstr"}.get(name, "-")
            if label != name + "@" + GIT_PINS[name] or features != want:
                bad.append("lower-crate version/features changed: " + row)
    return bad


def manifest_policy(root=ROOT):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    collector = tomllib.loads((root / "crates/bingsu-collect/Cargo.toml").read_text())
    expected = {name: {"version": "=" + version, "default-features": False,
                       **({"features": ["sha1"]} if name == "gix-object" else {})}
                for name, version in GIT_PINS.items()}
    actual = {k: v for k, v in workspace["workspace"]["dependencies"].items()
              if k == "gix" or k.startswith("gix-")}
    direct = {k: v for k, v in collector["dependencies"].items()
              if k == "gix" or k.startswith("gix-")}
    return [] if actual == expected and direct == {k: {"workspace": True} for k in expected} else [
        "collector Git dependencies must use the reviewed workspace pins with defaults disabled"]


def origins(labels, root=ROOT):
    """Pin registry source, SPDX license and archive checksum for the audited graph.

    Cargo verifies archive checksums against Cargo.lock; local workspace sources
    are covered by the sibling source inventory instead of a registry checksum.
    """
    meta = json.loads(subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1"],
                                    cwd=root, check=True, capture_output=True, text=True).stdout)
    locked = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum", "-") for p in locked}
    rows = set()
    for package in meta["packages"]:
        name, version, source = package["name"], package["version"], package["source"]
        label = name + "@" + version
        if label not in labels:
            continue
        checksum = checksums[name, version, source]
        license_ = package["license"]
        if not license_ or (source and not re.fullmatch("[0-9a-f]{64}", checksum)):
            raise ValueError("missing license or registry checksum: " + label)
        if source is None:
            source = "workspace:" + str(pathlib.Path(package["manifest_path"]).parent.relative_to(root))
        rows.add(f"*\t*\torigin\t{label}\t{source}\t{license_}\t{checksum}")
    if {row.split("\t")[3] for row in rows} != labels:
        raise ValueError("dependency metadata is incomplete")
    return rows

def audit(actual, expected):
    return sorted(actual - expected), sorted(expected - actual)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=pathlib.Path, help="dependency tree fixture (audit tests)")
    parser.add_argument("--target", choices=TARGETS)
    args = parser.parse_args()
    rows = {line for line in ALLOWLIST.read_text().splitlines() if line and not line.startswith("#")}
    failed = False
    labels = set()
    errors = manifest_policy()
    for target in ([args.target] if args.target else TARGETS):
        for scope in SCOPES:
            value = args.tree.read_text() if args.tree else tree(target, scope)
            prefix = target + "\t" + scope + "\t"
            expected = {row[len(prefix):] for row in rows if row.startswith(prefix)}
            actual = closure(value)
            labels.update(row.split("\t")[1] for row in actual if row.startswith("node\t"))
            errors.extend(git_policy(actual, front=scope.startswith("product-")))
            extra, missing = audit(actual, expected)
            if not expected or extra or missing:
                failed = True
                print(f"{target}/{scope}: unexpected={extra}, missing={missing}", file=sys.stderr)
    if not args.tree:
        expected_origins = {row for row in rows if row.startswith("*\t*\torigin\t")}
        # Target-limited audits still reject changed provenance, but other
        # targets' packages need not be present in this closure.
        if args.target:
            expected_origins = {row for row in expected_origins if row.split("\t")[3] in labels}
        try:
            extra, missing = audit(origins(labels), expected_origins)
            if extra or missing:
                errors.append(f"dependency provenance: unexpected={extra}, missing={missing}")
        except ValueError as error:
            errors.append(str(error))
    for error in sorted(set(errors)):
        print(error, file=sys.stderr)
    failed |= bool(errors)
    print(f"collector dependency allowlist: {'FAILED' if failed else 'ok'}")
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
