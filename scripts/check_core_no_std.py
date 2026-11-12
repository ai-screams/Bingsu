#!/usr/bin/env python3
"""The graphs of bingsu-core (which is `no_std`) and of the shipped `bingsu`
are pinned (spec section 1, F-05; decisions 2026-10-14).

`no_std` keeps std's file, environment, process, clock, network and thread
APIs out of core's own source, but a dependency may still use std and hand
core a safe function that does I/O. So the whole graph each root links is
pinned here, package by package: name, exact version, source (crates.io, or
a path package of this workspace at its exact manifest), resolved feature
set and target kinds. A build script runs only when its package and version
are in REVIEWED_BUILD (it was read: it prints cfg lines only, no link or
native code); proc-macro targets and `links` are refused. Any change to the
graph (a new crate, a new version, a path or git replacement under the same
name, a feature turned on by another member) fails until PINS changes in
the same pull request.

The shipped packages' non-test targets are pinned too (name, kind, crate
types, source path, required features, whether a test build of it exists):
`bingsu` has one bin, src/main.rs, so a second bin or another entry file
cannot replace the one the gates read; `bingsu-prompt` has one bin with no
test or bench build, so the test modules of the prompt files it includes
are never compiled against it.

`bingsu-prompt` is the prompt alone: its graph is core's, identity and libc.
A dependency of the other commands (regular expressions, for example) that
reaches it fails here.

Also fails on a [patch] or [replace] table. The `#![no_std]` attribute
itself is checked by core-cfg-check (parsed, so a commented-out copy does
not count) and by the wasm32v1-none build in check-core-purity.sh.

The decision is the pure function `judge` over the metadata and the root
manifest; scripts/test_check_core_no_std.py runs it on synthetic metadata,
one case per rule, in the same purity gate.
Usage: check_core_no_std.py   (from the repository root)
"""
import json
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
# (name, version, source or workspace manifest) -> (features, target kinds)
# Target kinds leave out test, bench and example targets, which never link.
CORE_GRAPH = {
    ("bingsu-core", "0.0.0", "crates/bingsu-core/Cargo.toml"): ((), ("lib",)),
    ("libm", "0.2.16", CRATES_IO): ((), ("custom-build", "lib")),
    ("unicode-segmentation", "1.13.3", CRATES_IO): ((), ("lib",)),
    # TOML for the config model (M3a S1): `parse` without `std`. Its nesting
    # caps rely on the `unbounded` feature staying off; this pin keeps it so.
    ("toml", "1.1.8+spec-1.1.0", CRATES_IO): (("parse",), ("lib",)),
    ("toml_parser", "1.1.5+spec-1.1.0", CRATES_IO): (("alloc",), ("lib",)),
    ("toml_datetime", "1.1.2+spec-1.1.0", CRATES_IO): (("alloc",), ("lib",)),
    ("serde_spanned", "1.1.2", CRATES_IO): (("alloc",), ("lib",)),
    ("winnow", "1.0.4", CRATES_IO): ((), ("lib",)),
}
# The shipped binary with default features (bench-stubs off): core's graph,
# the binary and libc.
BINGSU_GRAPH = {
    **CORE_GRAPH,
    ("bingsu", "0.0.0", "crates/bingsu/Cargo.toml"): ((), ("bin",)),
    # The shared no_std identity library, not the worker binary's OS modules.
    ("bingsu-identity", "0.0.0", "crates/bingsu-identity/Cargo.toml"): ((), ("custom-build", "lib")),
    ("libc", "0.2.191", CRATES_IO): (("default", "std"), ("custom-build", "lib")),
    # A command segment's `match` (U-9c, U-28): the CLI's own crate and the
    # standard regex with Unicode classes and no perf engines (C4c ruling
    # Q6), so a perf or other feature turned on fails here. regex-syntax's
    # `default` comes from proptest in the workspace resolution.
    ("bingsu-match", "0.0.0", "crates/bingsu-match/Cargo.toml"): ((), ("lib",)),
    ("regex", "1.13.1", CRATES_IO): (
        ("std", "unicode", "unicode-age", "unicode-bool", "unicode-case", "unicode-gencat",
         "unicode-perl", "unicode-script", "unicode-segment"),
        ("lib",),
    ),
    ("regex-automata", "0.4.18", CRATES_IO): (
        ("alloc", "dfa-search", "meta", "nfa-pikevm", "nfa-thompson", "std", "syntax", "unicode",
         "unicode-age", "unicode-bool", "unicode-case", "unicode-gencat", "unicode-perl",
         "unicode-script", "unicode-segment", "unicode-word-boundary"),
        ("lib",),
    ),
    ("regex-syntax", "0.8.11", CRATES_IO): (
        ("default", "std", "unicode", "unicode-age", "unicode-bool", "unicode-case",
         "unicode-gencat", "unicode-perl", "unicode-script", "unicode-segment"),
        ("lib",),
    ),
}
# The dedicated prompt binary: the same graph without the CLI.
PROMPT_GRAPH = {
    **CORE_GRAPH,
    ("bingsu-prompt", "0.0.0", "crates/bingsu-prompt/Cargo.toml"): ((), ("bin",)),
    ("bingsu-identity", "0.0.0", "crates/bingsu-identity/Cargo.toml"): ((), ("custom-build", "lib")),
    ("libc", "0.2.191", CRATES_IO): (("default", "std"), ("custom-build", "lib")),
}
PINS = {"bingsu-core": CORE_GRAPH, "bingsu": BINGSU_GRAPH, "bingsu-prompt": PROMPT_GRAPH}
# Build scripts read at these versions: they print cargo:rustc-cfg,
# rustc-check-cfg, rustc-env and warnings, and no rustc-link-* line.
# Identity's hash-pinned script runs the compiler cargo passes in RUSTC once
# (`-vV`, for its release and commit-hash) and writes only an identity
# constant to OUT_DIR; it emits rerun directives, no linker/configuration/
# native-code directives. It refuses symlinks, names that are not UTF-8 and
# names with a control character, so no source name can add a directive line.
REVIEWED_BUILD = {("libm", "0.2.16"), ("libc", "0.2.191"), ("bingsu-identity", "0.0.0")}
SKIP_KINDS = {"test", "bench", "example"}
TARGETS = {
    "bingsu": [{"name": "bingsu", "kind": ["bin"], "crate_types": ["bin"],
                "src_path": "crates/bingsu/src/main.rs", "required-features": [], "test": True}],
    "bingsu-prompt": [{"name": "bingsu-prompt", "kind": ["bin"], "crate_types": ["bin"],
                       "src_path": "crates/bingsu-prompt/src/main.rs", "required-features": [], "test": False}],
}


def turned_on(pkg, features):
    """Dependency keys (rename or name) of `pkg` that its resolved
    `features` turn on: `dep:x`, a non-weak `x/feature`, or the implicit
    feature `x` of a package that never writes `dep:x`. A weak `x?/feature`
    turns nothing on."""
    table = pkg.get("features", {})
    on = set()
    for f in features:
        for v in table.get(f, []):
            if v.startswith("dep:"):
                on.add(v[4:])
            elif "/" in v and "?/" not in v:
                on.add(v.split("/", 1)[0])
    explicit = {v[4:] for vs in table.values() for v in vs if v.startswith("dep:")}
    on |= {f for f in features if f not in explicit}
    return on


def edge_is_built(pkg, features, target, kinds):
    """Whether the build links an edge from `pkg` to the package `target`
    for these dep kinds. `cargo metadata` also lists an edge to an optional
    dependency that only a weak feature names, when another workspace member
    pulls that package in; the build leaves it out (`cargo build -p` makes
    no unit for it). The edge is matched to its declarations by the target
    package's name, never by the edge's lib name (a required dependency
    whose lib is named like an optional one must not hide behind it)."""
    on = turned_on(pkg, features)
    decls = [d for d in pkg.get("dependencies", [])
             if d["name"] == target["name"] and d.get("kind") in kinds]
    if not decls:
        return True  # no declaration to judge by: follow it
    return any(not d["optional"] or (d.get("rename") or d["name"]) in on for d in decls)


def closure(pkgs, nodes, root):
    """Packages a root links or builds with: normal and build edges, followed
    by package id; an optional dependency only when a resolved feature turns
    it on."""
    seen, todo = set(), [root]
    while todo:
        nid = todo.pop()
        if nid in seen:
            continue
        seen.add(nid)
        for d in nodes[nid]["deps"]:
            kinds = {k["kind"] for k in d["dep_kinds"]} & {None, "build"}
            if kinds and edge_is_built(pkgs[nid], nodes[nid]["features"], pkgs[d["pkg"]], kinds):
                todo.append(d["pkg"])
    return seen


def key_of(p, root):
    if p["source"] is None:
        manifest = pathlib.Path(p["manifest_path"])
        try:
            where = str(manifest.relative_to(root))
        except ValueError:
            where = str(manifest)
        return (p["name"], p["version"], where)
    return (p["name"], p["version"], p["source"])


def manifest_rules(root_manifest):
    """Rules on the root manifest alone (they hold even when cargo metadata
    fails, as it does under --locked when [patch] changes the graph)."""
    if "patch" in root_manifest or "replace" in root_manifest:
        return ["Cargo.toml: [patch] and [replace] are not allowed"]
    return []


def judge(meta, root_manifest, root):
    """Every rule broken by `meta` (cargo metadata) and the root manifest."""
    bad = manifest_rules(root_manifest)
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    for p in pkgs.values():
        if p["name"] in TARGETS and p["source"] is None:
            got = [{"name": t["name"], "kind": t["kind"], "crate_types": t["crate_types"],
                    "src_path": str(pathlib.Path(t["src_path"]).relative_to(root)),
                    "required-features": t.get("required-features", []), "test": t.get("test")}
                   for t in p["targets"] if not set(t["kind"]) & SKIP_KINDS]
            if got != TARGETS[p["name"]]:
                bad.append(f"{p['name']} targets {got}, pinned {TARGETS[p['name']]}")
    for name, pins in PINS.items():
        roots = [i for i, p in pkgs.items() if p["name"] == name and p["source"] is None]
        if len(roots) != 1:
            bad.append(f"{name}: expected one workspace package, got {len(roots)}")
            continue
        got = {}
        for nid in closure(pkgs, nodes, roots[0]):
            p = pkgs[nid]
            kinds = tuple(sorted({k for t in p["targets"] for k in t["kind"]} - SKIP_KINDS))
            got[key_of(p, root)] = (tuple(sorted(nodes[nid]["features"])), kinds)
            if p.get("links"):
                bad.append(f"{name} graph: {p['name']} links native library {p['links']!r}")
            if "proc-macro" in kinds:
                bad.append(f"{name} graph: {p['name']} is a proc-macro")
            if "custom-build" in kinds and (p["name"], p["version"]) not in REVIEWED_BUILD:
                bad.append(f"{name} graph: build script of {p['name']} {p['version']} is not reviewed")
        for k in sorted(set(got) | set(pins)):
            if got.get(k) != pins.get(k):
                bad.append(f"{name} graph: {k} is {got.get(k)}, pinned {pins.get(k)}")
    return bad


def main():
    root_manifest = tomllib.load(open(ROOT / "Cargo.toml", "rb"))
    out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"],
                         capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        bad = manifest_rules(root_manifest) + [f"cargo metadata failed: {out.stderr.strip()[-300:]}"]
    else:
        bad = judge(json.loads(out.stdout), root_manifest, ROOT)
    if bad:
        print("core graph gate FAILED:\n  " + "\n  ".join(bad), file=sys.stderr)
        return 1
    print(f"core graph gate: ok ({len(CORE_GRAPH)} core packages and "
          f"{len(BINGSU_GRAPH)} bingsu and {len(PROMPT_GRAPH)} bingsu-prompt packages pinned, no [patch])")
    return 0


if __name__ == "__main__":
    sys.exit(main())
