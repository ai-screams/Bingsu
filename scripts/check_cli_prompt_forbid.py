#!/usr/bin/env python3
"""The `bingsu prompt` adapter (crates/bingsu/src/prompt.rs) is the trusted
computing base of the prompt path: every decision is bingsu_core::front
(pure, `no_std`, checked by check_core_no_std.py and the core gates); the
adapter turns argv into bytes, calls the core, writes and exits. This gate
keeps it that small:

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
    "package": {"name": "bingsu-prompt", "version": {"workspace": True},
                "description": "The bingsu prompt alone: the prompt files of the bingsu crate, without its other commands",
                "publish": False, "edition": {"workspace": True}, "rust-version": "1.88",
                "license": {"workspace": True}, "repository": {"workspace": True}},
    "lints": {"workspace": True},
    "bin": [{"name": "bingsu-prompt", "path": "src/main.rs", "test": False, "bench": False}],
    "dependencies": {"bingsu-core": {"path": "../bingsu-core"}, "bingsu-identity": {"path": "../bingsu-identity"}},
    "target": {"cfg(unix)": {"dependencies": {"libc": "0.2"}}},
}
# Copying a new hash can self-approve a change; these pins are a change-detection
# tripwire, not an independent proof that the TCB is safe.
TCB_SHA256 = {
    "crates/bingsu-identity/Cargo.toml": "ff75b6ce44e1359c1e99593a65b93beb1a43605d38449cbb19abe34e981fecf0",
    "crates/bingsu-identity/build.rs": "10a627b742c558418ca780876fcd93b4cc12d2dae5295f32c0fe4caeaff66cad",
    "crates/bingsu-identity/src/lib.rs": "fd944c745ea76076f1c1c5f15ed0849df0045da526ab870459ce28880d48521d",
    "crates/bingsu/src/prompt_read.rs": "0f4886b584c9e55c0673058ff6efcee0d749f9a1f3f34d7d1172335c7387f2c4",
    "crates/bingsu-core/src/command/env_frame.rs": "13bbfb30d49aeca74ae63f848176111f9ab0f9766f8b208621261c3c49796070",
    "crates/bingsu/src/prompt_spawn.rs": "9943c19023affaa5dcd55a36b35d7c5d08647a3fb800c588e21b0e3993339b1d",
    "crates/bingsu/src/prompt_io.rs": "79210722e8c41e4253b72d77958550fcefdb4c58ab3dea0b664e93f6d8e372b9",
    "crates/bingsu/src/prompt.rs": "4b8f9f56e54e11ce01b6f81242934d5cbcb44f1da1c11f86f2fe8d1b0e507722",
    "crates/bingsu/src/main.rs": "012b20fb9bd130c577497c3dc8da4ccc19305c601d7aeaed35f6c7301f2e52b8",
    "crates/bingsu/src/relay.rs": "657ed164928bcaf58de82ab272d1c695f4eb4572495d3c0f053b403d5b16613e",
    "crates/bingsu-core/src/fs_trust.rs": "c5015c2385fbef79a16a5be07f984abbe8a73b14c3409bc62c4b1ef64bbef013",
    "crates/bingsu-core/src/handoff.rs": "a2fbac66aed7f3af54d78c33a6ac015a6e4c656ce25340a04386b32fa6fd6603",
    "crates/bingsu-core/src/command/response.rs": "fd49a2551fbd0661fe7fb71f8c3d6f988725f29bcac28e956aa9cbc68ee2ad22",
    "crates/bingsu-core/src/command/display.rs": "376780e89abd663e1bd4db1c495b55c5bbee7625d9e83e642c647f213f48cb5e",
    "crates/bingsu-core/src/command/path.rs": "fabe23e9881ac0256a5a1613da36e5c2022afe1a284f3812eb4692d334daa47a",
    # The prompt links these and they decide what it reads and draws: the
    # unit judgement and digests display.rs checks (plan.rs, wire.rs), the
    # builtin languages' environment digest (builtin.rs), the front's read
    # plan (staged.rs) and the text it lets reach the terminal (sanitize.rs),
    # the characters a builtin version may draw (language.rs), and the
    # folder digest and text cleaning those digests use (cwd_hash.rs, field.rs).
    "crates/bingsu-core/src/command/plan.rs": "cc7b95c0a618255388b764ad116b018a17b893f71f10fcbc6bc74da6f1d85782",
    "crates/bingsu-core/src/command/wire.rs": "5f3dda9a5835e3533de42c205af42f795421cc1c085b0918f0b0d4173aba5d5e",
    "crates/bingsu-core/src/front/staged.rs": "a051e52a769a9754c262bf7aaf88efec9b80e441b0e88e43cc2d7d13d1cdca4e",
    "crates/bingsu-core/src/sanitize.rs": "0e0817b571091f102bde7a1a0f884c6cdb8da35bbb7f3e3be26aee98d9f6a038",
    "crates/bingsu-core/src/command/builtin.rs": "6d4bc235ce7776b91c8465210c7cafd86e33083a7cc09c8f598e6e399cd7e85c",
    "crates/bingsu-core/src/collection/language.rs": "df76baf6d24e1d9b49c625825e446eab0d73e4aa49368c15d4419462c94829de",
    "crates/bingsu-core/src/collection/cwd_hash.rs": "63dd0e1ad5d643c100d8f0798729adab652533ef1c47f2a30253e8be1aff8549",
    "crates/bingsu-core/src/field.rs": "c4a870a6ab580a303e3d14ccc03129c2b6a17cf4a77f9062b0bfca89fffee1f2",
    # The names the prompt keeps from its environment frame: data plan.rs reads
    # (keep.rs; no code of its own reaches the prompt binary).
    "crates/bingsu-core/src/command/keep.rs": "217bf65950b2e90607f0114cd5a8afcf36ef44cb76698a1cd82d44647c04cba6",
    "crates/bingsu/src/sandbox.rs": "9fb81df86386aded6aef6cf8e485ab6d7fbba4d8ef11000586afa8dc7d2a44d6",
    "crates/bingsu/Cargo.toml": "c20d60d7c262562331c44fc022c10bd00b1a2a9b53dcfd2ad358708775c27037",
    "crates/bingsu/prompt-syscalls.tsv": "a324b6b21bbda01af82107ae3fecc29e6e2f8fb6d5ccb450bb7c5fc431901e02",
    "crates/bingsu-prompt/src/main.rs": "94585d3f07affd25f2a0b407e7c33759dd8b56f4fc5dd33587d96dd199c838cd",
    "crates/bingsu-prompt/Cargo.toml": "520a117c771ca2b087e0ca92f47593629d89aa23f353258fb76c17aaf791fe8c",
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
        if package["name"] in {"bingsu", "bingsu-prompt", "bingsu-core", "bingsu-collect", "bingsu-identity", "bingsu-match"}:
            if any(d["name"] == "bingsu-core-tests" for d in package["dependencies"]):
                bad.append("product dependency reaches the collector fixture package")
    for path in binary or ():
        data = pathlib.Path(path).read_bytes()
        if any(marker in data for marker in (b"collector_builtin", b"collector_builtin_test_only_31")):
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
