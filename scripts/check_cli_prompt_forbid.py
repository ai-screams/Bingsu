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
6. the dedicated `bingsu-prompt` binary (crates/bingsu-prompt) compiles
   the same prompt files through `#[path]`: core-cfg-check --prompt-main
   holds its src/main.rs to one exact shape per platform; src holds that
   file alone, with no symlink under the package; its manifest has the one
   bin target with no test or bench build, the three dependencies and
   nothing else (no build script, features or other targets);
7. the trusted files hash to TCB_SHA256: on macOS and anywhere without
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
PROMPT_PACKAGE = ROOT / "crates/bingsu-prompt"
PROMPT_MANIFEST = {
    "package": {"name": "bingsu-prompt", "version": "0.0.0",
                "description": "The bingsu prompt alone: the prompt files of the bingsu crate, without its other commands",
                "publish": False, "edition": {"workspace": True}, "rust-version": "1.88",
                "license": {"workspace": True}, "repository": {"workspace": True}},
    "lints": {"workspace": True},
    "bin": [{"name": "bingsu-prompt", "path": "src/main.rs", "test": False, "bench": False}],
    "dependencies": {"bingsu-core": {"path": "../bingsu-core"}, "bingsu-identity": {"path": "../bingsu-identity"}},
    "target": {"cfg(unix)": {"dependencies": {"libc": "0.2"}}},
}
# K38: copying a new hash can self-approve a change; these pins are a change-detection
# tripwire, not an independent proof that the TCB is safe.
TCB_SHA256 = {
    "crates/bingsu-identity/Cargo.toml": "1c6aeb48d7416df0d76252cf460c62af75c43da16cf834a227ac6cfef9ab336c",
    "crates/bingsu-identity/build.rs": "1d4f6851c6b09467c578ae1e00bde5078eec3146b9b592a244b24a3dcee9eb57",
    "crates/bingsu-identity/src/lib.rs": "fd944c745ea76076f1c1c5f15ed0849df0045da526ab870459ce28880d48521d",
    "crates/bingsu/src/prompt_read.rs": "c84ea1f15b273825d48f7d4f15df9d3457c275b15070d4e9dc8950360eaf3484",
    "crates/bingsu-core/src/command/env_frame.rs": "237c6cdd21b42d45f247651a923f050122ee65a1ff8b54abaa16a695b9272db6",
    "crates/bingsu/src/prompt_spawn.rs": "be8921dbeda19a51addc5cbbd6ddf037a2a24f2fecf168024c7f1dd980971120",
    "crates/bingsu/src/prompt_io.rs": "31dc5ba3b067a86a6f3ca2b3e4c849013259ae5e3882b592115bac846cff4d2e",
    "crates/bingsu/src/prompt.rs": "79f5e5bf5c34c64211287c078701b43ceb9852eb3a64feb8dbc669dd7389776a",
    "crates/bingsu/src/main.rs": "012b20fb9bd130c577497c3dc8da4ccc19305c601d7aeaed35f6c7301f2e52b8",
    "crates/bingsu/src/relay.rs": "aac26af4519aaca3d43d0c1fb2c48332d3e6611a47276378e8a490687af2556e",
    "crates/bingsu-core/src/fs_trust.rs": "cc71c39796a8fbb553ab678ada14860caa14a5f57b09591b0669e9f654575df9",
    "crates/bingsu-core/src/handoff.rs": "212b609746503fca73852e0c2f9e18d0928328adf1ba57d54d2115aa7de65b14",
    "crates/bingsu-core/src/command/response.rs": "a6acb365582240a08236f54722c47bad9c350f8ec0fdec3a0de827ed82e23eb3",
    "crates/bingsu-core/src/command/display.rs": "ee67a255f0080ce1b4a7d5a3b797f8e5f1b51d842a9f515671ed33206bebeb13",
    "crates/bingsu-core/src/command/path.rs": "35bd7c130b33491297b0842f9dce7f7f4560fccb3ebab19b1596ea3c51091dc4",
    "crates/bingsu/src/sandbox.rs": "a8ef03197c75a326c365b3c2ac0ce0170df58b05b4d9af13c8d9e5064bcac929",
    "crates/bingsu/Cargo.toml": "8f0481d83e662b0792242456355a7b3127b0e1646548eb177a3facae8e62193a",
    "crates/bingsu/prompt-syscalls.tsv": "afc7097e055c590c531eb3814543450d8b711b9ea39400b1846263a0b00d50fd",
    "crates/bingsu-prompt/src/main.rs": "de8a254547b88ecd41bdd799574b01ca12516ba0620c43f35761d82e0a61de35",
    "crates/bingsu-prompt/Cargo.toml": "da03cbb0ffb87da704ba5b186308071b36e2ba072705346505ead5882bbacc61",
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
        if package["name"] in {"bingsu", "bingsu-prompt", "bingsu-core", "bingsu-collect", "bingsu-identity"}:
            if any(d["name"] == "bingsu-core-tests" for d in package["dependencies"]):
                bad.append("product dependency reaches the collector fixture package")
    for path in binary or ():
        data = pathlib.Path(path).read_bytes()
        for marker in (b"collector_builtin", b"collector_builtin_test_only_31"):
            if marker in data:
                bad.append(f"product binary {path} contains a collector fixture symbol or string")
    return bad


def prompt_package_rules(package=PROMPT_PACKAGE):
    """Rule 6 outside the checker: the files and manifest of bingsu-prompt."""
    bad = []
    if not package.is_dir():
        return [f"{package.name}: package is missing"]
    # 이것을 실패시키는 것: src에 다른 파일을 두거나 패키지 아래 symlink를 허용하는 것.
    files = sorted(str(p.relative_to(package / "src")) for p in (package / "src").rglob("*"))
    if files != ["main.rs"]:
        bad.append(f"{package.name}/src: holds {files}, only main.rs is allowed")
    links = sorted(str(p.relative_to(package)) for p in package.rglob("*") if p.is_symlink())
    if links:
        bad.append(f"symlinks under {package.name}: {links}")
    # 이것을 실패시키는 것: 의존·대상·build script·feature를 더하거나 test/bench 빌드를 켜는 것.
    manifest = tomllib.loads((package / "Cargo.toml").read_text())
    if manifest != PROMPT_MANIFEST:
        bad.append(f"{package.name}/Cargo.toml: differs from the pinned manifest")
    return bad


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, help="path to the core-cfg-check binary")
    parser.add_argument("--product-binary", action="append",
                        help="also audit a built product binary (bingsu, bingsu-prompt) for fixture symbols and strings")
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
                 [args.checker, "--binary", *sorted(str(p) for p in (ROOT / "crates/bingsu/src").rglob("*.rs"))],
                 [args.checker, "--prompt-main", str(PROMPT_PACKAGE / "src/main.rs")]):
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
    bad += prompt_package_rules()
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
