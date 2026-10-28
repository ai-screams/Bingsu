#!/usr/bin/env python3
"""The `bingsu prompt` adapter (crates/bingsu/src/prompt.rs) is the trusted
computing base of the prompt path: every decision is bingsu_core::front
(pure, `no_std`, checked by check_core_no_std.py and the core gates); the
adapter turns argv into bytes, calls the core, writes and exits. This gate
keeps it that small (spec section 4 front end, F-01):

1. the adapter's first inner attribute forbids the clippy.toml rules
   (environment reads, std::process::exit, write_all), so no #[allow] can
   switch them off;
2. core-cfg-check --adapter: outside its last `#[cfg(test)] mod tests` the
   adapter names only allowlisted paths (syn tree, not text: no group or
   renaming `use`, no `crate::`/`super::`, no extern block, no macro call),
   and its libc names equal the `libc` column of
   crates/bingsu/prompt-syscalls.tsv;
3. core-cfg-check --binary over every source file of the binary: no global
   allocator, linker constructor, global_asm, #[path] or include, no local
   declaration named libc/std/core/alloc/front, no impl for an adapter type,
   and exactly one `fn main` whose body is
   `commands::run(prompt::dispatch(sandbox::enter))`;
4. the syscall table has the header `syscall libc why`, three columns, no
   duplicate cell in either name column, and its `syscall` column equals
   RULES in crates/bingsu/src/sandbox.rs (the Linux seccomp filter;
   cargo build scripts are not allowed, so the Rust table is committed and
   compared by core-cfg-check --rules); the actual RULES initializer must be
   an array of `("name", libc::SYS_name, conditions)`, not matching text in
   comments, strings, other constants or aliases;
5. no symlink under crates/bingsu/src, and crates/bingsu/Cargo.toml has no
   `autobins`, `autoexamples`, `autotests`, `autobenches`, `[lib]` or
   `[[bin]]` (the bin target itself is pinned by check_core_no_std.py);
6. the trusted files hash to TCB_SHA256: on macOS and anywhere without
   seccomp the kernel does not hold the adapter to the table, so any change
   to these files changes a pinned value in the same pull request, making
   the change visible to maintainers.
The adapter's file also passes core's token rules (check_core_cfg.py), and
at run time the strace test checks files, threads, processes, network and
the syscall column of the same table.
Usage: check_cli_prompt_forbid.py --checker PATH   (from the repository root)
"""
import argparse
import hashlib
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFETCH = ROOT / "crates/bingsu/src/prompt_read.rs"
TIMING = ROOT / "crates/bingsu/src/prompt_io.rs"
BOOTSTRAP = ROOT / "crates/bingsu/src/prompt_spawn.rs"
ADAPTER = ROOT / "crates/bingsu/src/prompt.rs"
SYSCALLS = ROOT / "crates/bingsu/prompt-syscalls.tsv"
SANDBOX = ROOT / "crates/bingsu/src/sandbox.rs"
MANIFEST = ROOT / "crates/bingsu/Cargo.toml"
# K38: copying a new hash can self-approve a change; these pins are a change-detection
# tripwire, not an independent proof that the TCB is safe.
TCB_SHA256 = {
    "crates/bingsu-identity/Cargo.toml": "1c6aeb48d7416df0d76252cf460c62af75c43da16cf834a227ac6cfef9ab336c",
    "crates/bingsu-identity/build.rs": "4b91d1c9e8bbbe1453fbd3d5ec089525c725c0a33c468372ee6cdf23c2330aab",
    "crates/bingsu-identity/src/lib.rs": "6af258f59e81c5bb33db541685b19c517bf10002a7ac56e4c7d05a7bddd2c925",
    "crates/bingsu/src/prompt_read.rs": "e17afb8d62ba6eb4ebae07e4e4bf1fb3f9a8717651b13d6e9712cc42971d103e",
    "crates/bingsu/src/prompt_spawn.rs": "597a93d49e3cee36e641e6da3b0327f03bdfd07d68b7c94f12e28fb42d6270c2",
    "crates/bingsu/src/prompt_io.rs": "1ce5d695c9d828da7f9ebdfda10b606219747029d6e2937af888cc3a79fb7e46",
    "crates/bingsu/src/prompt.rs": "a593d7d74425a29ee31f0f618ff4778463801ba3aa61bbfa9633e567663c5cb2",
    "crates/bingsu/src/main.rs": "2f4d0c5f7e49ef71721c499fb9b3f757bb07bd0d402116a9fc97f2262c08b3c1",
    "crates/bingsu/src/sandbox.rs": "a8ef03197c75a326c365b3c2ac0ce0170df58b05b4d9af13c8d9e5064bcac929",
    "crates/bingsu/Cargo.toml": "8f0481d83e662b0792242456355a7b3127b0e1646548eb177a3facae8e62193a",
    "crates/bingsu/prompt-syscalls.tsv": "afc7097e055c590c531eb3814543450d8b711b9ea39400b1846263a0b00d50fd",
}
WANT = "#![forbid(clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]"


def check_product_fixture_isolation(binary=None):
    """The worker fixture is an explicit test target, with no product entry."""
    bad = []
    fixture = "tests/fixtures/collector_builtin.rs"
    metadata = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version=1"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    import json
    graph = json.loads(metadata.stdout)
    packages = graph["packages"]
    workspace = pathlib.Path(graph["workspace_root"])
    targets = [(p["name"], t) for p in packages for t in p["targets"]
               if pathlib.Path(t["src_path"]).resolve() == workspace / fixture]
    if len(targets) != 1 or targets[0][0] != "bingsu-core-tests" or targets[0][1]["kind"] != ["test"]:
        bad.append("collector fixture must be exactly one test target in bingsu-core-tests")
    for package in packages:
        if package["name"] in {"bingsu", "bingsu-core", "bingsu-collect", "bingsu-identity"}:
            if any(d["name"] == "bingsu-core-tests" for d in package["dependencies"]):
                bad.append("product dependency reaches the collector fixture package")
    if binary is not None:
        data = pathlib.Path(binary).read_bytes()
        for marker in (b"collector_builtin", b"collector_builtin_test_only_31"):
            if marker in data:
                bad.append("product binary contains a collector fixture symbol or string")
    return bad


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, help="path to the core-cfg-check binary")
    parser.add_argument("--product-binary", help="also audit the built product for fixture symbols and strings")
    args = parser.parse_args()
    bad = check_product_fixture_isolation(args.product_binary)
    # All prompt entry TCB files are scanned by --binary below and must forbid the
    # unchanged clippy forbidden-call rules. Their exact bytes are pinned.
    for source in (ADAPTER, BOOTSTRAP, PREFETCH, TIMING):
        text = source.read_text()
        start = text.find("#![")
        first = None if start < 0 else "".join(text[start:text.index("]", start) + 1].split())
        if first != "".join(WANT.split()):
            bad.append(f"{source.relative_to(ROOT)}: first inner attribute is {first!r}")
    for argv in ([args.checker, "--identity", str(ROOT / "crates/bingsu-identity/src/lib.rs")],
                 [args.checker, "--adapter", str(SYSCALLS), str(ADAPTER)],
                 [args.checker, "--rules", str(SYSCALLS), str(SANDBOX)],
                 [args.checker, "--binary", *sorted(str(p) for p in (ROOT / "crates/bingsu/src").rglob("*.rs"))]):
        out = subprocess.run(argv, capture_output=True, text=True)
        if out.returncode != 0:
            bad.append(f"core-cfg-check {argv[1]}: " + out.stderr.strip())
    rows = [l.split("\t") for l in SYSCALLS.read_text().splitlines() if l and not l.startswith("#")]
    if not rows or rows[0] != ["syscall", "libc", "why"]:
        bad.append(f"{SYSCALLS.name}: header must be syscall, libc, why")
    else:
        body = rows[1:]
        for r in body:
            if len(r) != 3 or not all(c.strip() for c in r):
                bad.append(f"{SYSCALLS.name}: row {r} does not have three filled columns")
        for col in (0, 1):
            names = [r[col] for r in body if len(r) == 3 and r[col] != "-"]
            dups = sorted({n for n in names if names.count(n) > 1})
            if dups:
                bad.append(f"{SYSCALLS.name}: duplicate {('syscall', 'libc')[col]} {dups}")
    links = [str(p.relative_to(ROOT)) for p in (ROOT / "crates/bingsu/src").rglob("*") if p.is_symlink()]
    if links:
        bad.append(f"symlinks under crates/bingsu/src: {links}")
    manifest = tomllib.loads(MANIFEST.read_text())
    keys = {"autobins", "autoexamples", "autotests", "autobenches", "autolib"} & set(manifest.get("package", {}))
    if keys or "bin" in manifest or "lib" in manifest:
        bad.append(f"crates/bingsu/Cargo.toml: target tables or auto-target keys {sorted(keys)} are not allowed")
    for rel, want in TCB_SHA256.items():
        got = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        if got != want:
            bad.append(f"{rel}: sha256 {got}, pinned {want or '(none)'}; assess the security impact of the change, then run scripts/pin_tcb.py")
    if bad:
        print("prompt adapter gate FAILED:\n  " + "\n  ".join(bad), file=sys.stderr)
        return 1
    print("prompt adapter gate: ok (forbid attribute, adapter paths and syscall table, seccomp table, "
          "one fn main that only dispatches, no code outside main, pinned TCB files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
