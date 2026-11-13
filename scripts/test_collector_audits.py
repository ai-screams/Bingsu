"""Host-only collector dependency, import and shared manifest audit tests."""
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# 이것을 실패시키는 것: Cargo의 첫 실행 파일(제품 collector)을 filter 테스트로 실행하는 것.
def test_repository_trace_selects_only_filter_test_artifact():
    audit = load("check_collector_filter")
    def artifact(name, kind, test, executable):
        return json.dumps({"reason": "compiler-artifact", "target": {"name": name, "kind": [kind]},
                           "profile": {"test": test}, "executable": executable})
    product = artifact("bingsu-collect", "bin", False, "/target/debug/bingsu-collect")
    probe = artifact("filter", "test", True, "/target/debug/deps/filter-1234")
    assert audit.filter_test_binary(product + "\n" + probe) == "/target/debug/deps/filter-1234"
    for bad in (product, probe + "\n" + probe,
                artifact("filter", "bin", True, "/wrong"),
                artifact("filter", "test", False, "/wrong"),
                artifact("filter", "test", True, None)):
        with pytest.raises(AssertionError, match="expected one filter test executable"):
            audit.filter_test_binary(bad)


# 이것을 실패시키는 것: Linux 전용 선택 테스트를 다른 호스트에서도 실행하거나 0개 실행을 통과시키는 것.
@pytest.mark.parametrize("platform,count", [("linux", 10), ("darwin", 9), ("win32", 9)])
def test_filter_host_test_count_matches_linux_cfg(monkeypatch, platform, count):
    audit = load("check_collector_filter")
    monkeypatch.setattr(audit.sys, "platform", platform)
    for observed in (0, 9, 10):
        result = subprocess.CompletedProcess([], 0,
            f"test result: ok. {observed} passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.01s\n")
        assert audit.host_tests_passed(result) == (observed == count)


# 이것을 실패시키는 것: 금지된 exec/spawn/fork 계열 또는 dlsym을 감사에서 허용하는 것.
def test_macos_collection_binary_has_no_spawn_imports(tmp_path):
    audit = load("check_collector_symbols")
    for symbol in ("posix_spawn", "posix_spawnp", "execve", "execv", "execvp", "execvpe",
                   "execl", "execlp", "execle", "fork", "vfork", "system", "popen", "dlsym", "dlopen", "syscall"):
        fixture = tmp_path / "symbols"
        fixture.write_text(f"                 _{symbol}\n")
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check_collector_symbols.py"),
                                 "--symbols-file", str(fixture)], capture_output=True)
        assert result.returncode == 1, (symbol, result)
    assert audit.forbidden_imports("_malloc\n_read\n_write\n") == []
    if sys.platform == "darwin":
        subprocess.run([sys.executable, str(ROOT / "scripts/check_collector_symbols.py"),
                        str(ROOT / "target/release/bingsu-collect")], check=True)


# 이것을 실패시키는 것: 제품의 새 간접 edge·feature·version을 자동 승인하는 것.
def test_collector_dependency_allowlist_rejects_new_edges(monkeypatch):
    audit = load("check_collector_dependencies")
    good = "0bingsu-collect v0.0.0|\n1bingsu-core v0.0.0|\n2libm v0.2.16|\n"
    expected = audit.closure(good)
    assert audit.audit(expected, expected) == ([], [])
    for package in ("seccompiler", "gix", "process"):
        extra = good + f"2{package} v1.0.0|spawn\n"
        assert audit.audit(audit.closure(extra), expected)[0]
    for changed in (good.replace("0.2.16", "0.2.17"), good.replace("libm v0.2.16|", "libm v0.2.16|std")):
        assert audit.audit(audit.closure(changed), expected) != ([], [])
    subprocess.run([sys.executable, str(ROOT / "scripts/check_collector_dependencies.py")], check=True)
    # 이것을 실패시키는 것: 제품 외 dev graph를 감사 대상에서 빼는 것.
    original_tree = audit.tree
    def with_dev_edge(target, scope):
        tree = original_tree(target, scope)
        return tree + "1process v1.0.0|spawn\n" if scope == "collector-tests" else tree
    monkeypatch.setattr(audit, "tree", with_dev_edge)
    monkeypatch.setattr(sys, "argv", ["check_collector_dependencies", "--target", "aarch64-apple-darwin"])
    assert audit.main() == 1



RUSTC_VV = ("rustc 1.99.1 (58cf8f9c3 2026-10-13)\nbinary: rustc\ncommit-hash: 58cf8f9c3d0e4a1b\n"
            "commit-date: 2026-10-13\nhost: aarch64-apple-darwin\nrelease: 1.99.1\nLLVM version: 21.1.2\n")


def manifest_builder(tmp_path):
    """The identity build script compiled on its own, and a stand-in compiler
    whose `-vV` answer is the file next to it and whose exit status is
    FAKE_RUSTC_EXIT (shell builtins only: the builder runs with no PATH)."""
    builder = tmp_path / "manifest-builder"
    subprocess.run(["rustc", "--edition=2024", str(ROOT / "crates/bingsu-identity/build.rs"),
                    "-o", str(builder)], check=True, capture_output=True)
    rustc = tmp_path / "rustc"
    rustc.write_text('#!/bin/sh\n[ "$1" = -vV ] || exit 3\n'
                     'while IFS= read -r line; do printf \'%s\\n\' "$line"; done < "$0.vV"\n'
                     'exit "${FAKE_RUSTC_EXIT:-0}"\n')
    rustc.chmod(0o755)
    (tmp_path / "rustc.vV").write_text(RUSTC_VV)
    return builder, rustc


def built_id(out):
    """All 32 bytes of the identity the builder wrote, not a prefix."""
    text = (out / "build_id.rs").read_text()
    found = re.findall(r"BuildId\(\[([0-9, ]+)\]\)", text)
    assert len(found) == 1, text
    value = bytes(int(x) for x in found[0].split(","))
    assert len(value) == 32
    return value


# 이것을 실패시키는 것: source·lock·collector 정책·feature·target·profile·flags 중 하나를 build-id에서 빼는 것,
# bingsu-prompt의 manifest·entry 소스를 빼는 것, bingsu-match 또는 crate의 build.rs를 빼는 것,
# rustc의 release·commit-hash를 빼거나 host·LLVM 줄까지 넣는 것, 뿌리·OUT_DIR 경로를 정체에 넣는 것,
# 제어 문자가 든 이름이나 UTF-8이 아닌 이름을 받아들이는 것, `--version`이 보일 target·rustc 값을 쓰지 않거나
# 공백·제어 문자, 괄호·쉼표·따옴표처럼 그 줄을 나누는 글자가 든 값을 받아들이는 것.
def test_sibling_build_manifest_is_exact(tmp_path):
    builder, rustc = manifest_builder(tmp_path)
    answer = tmp_path / "rustc.vV"
    root = tmp_path / "source"
    root.mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        (root / name).write_text("baseline\n")
    for package in ("bingsu", "bingsu-prompt", "bingsu-core", "bingsu-collect", "bingsu-bench", "bingsu-identity",
                    "bingsu-match"):
        path = root / "crates" / package
        (path / "src").mkdir(parents=True)
        (path / "Cargo.toml").write_text("baseline\n")
        (path / "src/lib.rs").write_text("baseline\n")
    for package in ("bingsu-identity", "bingsu-collect"):
        (root / "crates" / package / "build.rs").write_text("baseline\n")
    policies = ("crates/bingsu-collect/dependencies.allowlist.tsv",
                "crates/bingsu-collect/collector-syscalls.tsv")
    for relative in policies:
        (root / relative).write_text("baseline policy\n")
    out = tmp_path / "out"
    out.mkdir()
    settings = {"CARGO_MANIFEST_DIR": str(root / "crates/bingsu-identity"), "OUT_DIR": str(out), "RUSTC": str(rustc),
                "TARGET": "aarch64-apple-darwin", "PROFILE": "release", "OPT_LEVEL": "3", "DEBUG": "false"}
    def identity(extra=None):
        subprocess.run([str(builder)], env=settings | (extra or {}), check=True, capture_output=True)
        return built_id(out)
    baseline = identity()
    assert identity() == baseline
    for relative in ("Cargo.toml", "Cargo.lock", "crates/bingsu-collect/Cargo.toml", "crates/bingsu/src/lib.rs", "crates/bingsu-core/src/lib.rs",
                     "crates/bingsu-prompt/Cargo.toml", "crates/bingsu-prompt/src/lib.rs",
                     "crates/bingsu-collect/src/lib.rs", "crates/bingsu-bench/src/lib.rs", "crates/bingsu-identity/src/lib.rs",
                     "crates/bingsu-identity/Cargo.toml", "crates/bingsu-identity/build.rs",
                     "crates/bingsu-match/Cargo.toml", "crates/bingsu-match/src/lib.rs", "crates/bingsu-collect/build.rs",
                     *policies):
        file = root / relative
        saved = file.read_bytes()
        try:
            file.write_bytes(bytes([saved[0] ^ 1]) + saved[1:])  # one byte
            assert identity() != baseline, relative
        finally:
            file.write_bytes(saved)
        assert identity() == baseline
    for key, value in (("TARGET", "x86_64-unknown-linux-musl"), ("PROFILE", "debug"), ("OPT_LEVEL", "2"), ("DEBUG", "true"),
                       ("CARGO_FEATURE_BENCH_BUILD", "1"), ("CARGO_ENCODED_RUSTFLAGS", "-Copt-level=1"),
                       ("CARGO_CFG_TARGET_FEATURE", "sse2"), ("CARGO_PROFILE_RELEASE_LTO", "false")):
        assert identity({key: value}) != baseline, key

    # The compiler: its release and commit-hash lines, and nothing about the host
    # it runs on, so a cross build from another host can match.
    for before, after, changes in (("release: 1.99.1", "release: 1.99.2", True),
                                   ("commit-hash: 58cf8f9c3d0e4a1b", "commit-hash: 58cf8f9c3d0e4a1c", True),
                                   ("host: aarch64-apple-darwin", "host: x86_64-unknown-linux-gnu", False),
                                   ("LLVM version: 21.1.2", "LLVM version: 21.1.3", False),
                                   ("rustc 1.99.1 (58cf8f9c3 2026-10-13)", "rustc 1.99.1 (other)", False)):
        try:
            answer.write_text(RUSTC_VV.replace(before, after))
            assert (identity() != baseline) == changes, after
        finally:
            answer.write_text(RUSTC_VV)
    for broken in (RUSTC_VV.replace("release: 1.99.1\n", ""), RUSTC_VV.replace("commit-hash: 58cf8f9c3d0e4a1b\n", "")):
        try:
            answer.write_text(broken)
            with pytest.raises(subprocess.CalledProcessError):
                identity()
        finally:
            answer.write_text(RUSTC_VV)
    # A compiler that cannot run, and one that answers but fails.
    for extra in ({"RUSTC": str(tmp_path / "missing-rustc")}, {"FAKE_RUSTC_EXIT": "1"}):
        with pytest.raises(subprocess.CalledProcessError):
            identity(extra)
    assert identity() == baseline

    # `bingsu --version` prints these: written as constants, visible ASCII only.
    text = (out / "build_id.rs").read_text()
    for line in ('pub const TARGET: &str = "aarch64-apple-darwin";', 'pub const RUSTC_RELEASE: &str = "1.99.1";',
                 'pub const RUSTC_COMMIT_HASH: &str = "58cf8f9c3d0e4a1b";'):
        assert line in text.splitlines(), (line, text)
    for before, after in (("release: 1.99.1", "release: 1.99.1 beta"), ("release: 1.99.1", "release: 1.99.1\x1b[2J"),
                          ("commit-hash: 58cf8f9c3d0e4a1b", "commit-hash: "), ("release: 1.99.1", "release: 1.99.\u00e9"),
                          ("release: 1.99.1", "release: 1.99.1)"), ("release: 1.99.1", "release: 1.99,1"),
                          ("commit-hash: 58cf8f9c3d0e4a1b", 'commit-hash: 58cf"8f9'), ("release: 1.99.1", "release: (1.99.1")):
        try:
            answer.write_text(RUSTC_VV.replace(before, after))
            with pytest.raises(subprocess.CalledProcessError):
                identity()
        finally:
            answer.write_text(RUSTC_VV)
    for target in ("x86 64", "", "aarch64\napple", "x86_64,linux", "x86_64)", 'x86"64'):
        with pytest.raises(subprocess.CalledProcessError):
            identity({"TARGET": target})
    assert identity() == baseline

    # Another checkout path and another OUT_DIR (target folder) give the same identity.
    moved = tmp_path / "elsewhere" / "checkout"
    shutil.copytree(root, moved, symlinks=True)
    other = tmp_path / "other-target" / "out"
    other.mkdir(parents=True)
    subprocess.run([str(builder)], env=settings | {"CARGO_MANIFEST_DIR": str(moved / "crates/bingsu-identity"),
                                                   "OUT_DIR": str(other)}, check=True, capture_output=True)
    assert built_id(other) == baseline

    link = root / "crates/bingsu/src/linked.rs"
    link.symlink_to(root / "Cargo.lock")
    try:
        with pytest.raises(subprocess.CalledProcessError):
            identity()
    finally:
        link.unlink()

    # Each hashed path is printed as a cargo directive line. A name with a
    # newline would add a directive of its own (here one that redirects
    # OUT_DIR, which src/lib.rs includes from), so the builder refuses control
    # characters in file and folder names, and names that are not UTF-8.
    bad = [(root / "crates/bingsu-match/src" / "x\ncargo:rustc-env=OUT_DIR=..", "file"),
           (root / "crates/bingsu/src" / "dir\ncargo:warning=injected", "folder"),
           (root / "crates/bingsu-core/src" / "tab\tname", "file"),
           (root / "crates/bingsu-collect/src" / os.fsdecode(b"bad-\xff"), "folder")]
    for path, kind in bad:
        try:
            path.mkdir() if kind == "folder" else path.write_text("baseline\n")
        except OSError:
            # macOS file systems refuse names that are not UTF-8 themselves.
            assert path.name.startswith("bad-") and sys.platform == "darwin", path
            continue
        try:
            with pytest.raises(subprocess.CalledProcessError):
                identity()
        finally:
            path.rmdir() if kind == "folder" else path.unlink()
        assert identity() == baseline


def linked_workspace_packages():
    """Workspace packages the three binaries link, from cargo's own reading of
    the manifests: normal and build edges for every target, optional ones
    included (bingsu-bench under bench-stubs), dev edges left out."""
    metadata = json.loads(subprocess.run(["cargo", "metadata", "--no-deps", "--format-version=1", "--offline"],
                                         cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    by_dir = {pathlib.Path(p["manifest_path"]).resolve().parent: p for p in metadata["packages"]}
    by_name = {p["name"]: p for p in metadata["packages"]}
    linked = {}
    todo = [by_name[name] for name in ("bingsu", "bingsu-prompt", "bingsu-collect")]
    while todo:
        package = todo.pop()
        directory = pathlib.Path(package["manifest_path"]).resolve().parent
        if directory in linked:
            continue
        linked[directory] = package
        for dependency in package["dependencies"]:
            if dependency.get("path") and dependency["kind"] != "dev":
                # A path dependency outside the workspace members is a KeyError here.
                todo.append(by_dir[pathlib.Path(dependency["path"]).resolve()])
    return linked


# 이것을 실패시키는 것: build.rs 목록에서 crate 하나를 빼는 것, 제품 crate에 새 path 의존을 더하고 목록에
# 넣지 않는 것, crate의 build script나 lib·bin 진입 파일을 정체 입력에서 빼는 것, RUSTC 감시 줄을 빼는 것.
def test_sibling_build_inputs_are_the_linked_workspace_crates(tmp_path):
    builder, rustc = manifest_builder(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    run = subprocess.run([str(builder)], env={"CARGO_MANIFEST_DIR": str(ROOT / "crates/bingsu-identity"),
                                              "OUT_DIR": str(out), "RUSTC": str(rustc), "TARGET": "x86_64-unknown-linux-gnu",
                                              "PROFILE": "debug", "OPT_LEVEL": "0", "DEBUG": "true"},
                         check=True, capture_output=True, text=True)
    # Cargo reruns the script when the compiler it is handed changes.
    assert "cargo:rerun-if-env-changed=RUSTC" in run.stdout.splitlines()
    prefix = "cargo:rerun-if-changed="
    hashed = {pathlib.Path(line[len(prefix):]).resolve() for line in run.stdout.splitlines() if line.startswith(prefix)}
    linked = linked_workspace_packages()
    assert {"bingsu-match", "bingsu-identity", "bingsu-bench"} <= {p["name"] for p in linked.values()}
    inventoried = {path.parent for path in hashed if path.name == "Cargo.toml" and path.parent != ROOT}
    assert inventoried == set(linked), (sorted(map(str, inventoried ^ set(linked))))
    for directory, package in linked.items():
        assert directory / "src" in hashed, package["name"]
        for target in package["targets"]:
            if set(target["kind"]) & {"lib", "rlib", "bin", "custom-build", "proc-macro"}:
                assert pathlib.Path(target["src_path"]).resolve() in hashed, (package["name"], target["name"])


# 이것을 실패시키는 것: 동일 build-id인 다른 역할, 역할 없음, 중복 역할을 허용하는 것.
def test_sibling_audit_requires_distinct_roles(tmp_path):
    audit = load("check_collector_symbols")
    identity = bytes(range(32))
    manifest = audit.TAG + identity
    collector = audit.ROLE + bytes([1]) + identity
    front = audit.ROLE + bytes([2]) + identity
    path = tmp_path / "bingsu-collect"
    for role, tag in [(1, collector), (2, front)]:
        path.write_bytes(manifest + tag)
        assert audit.build_id(path, role) == identity
        for bad in [manifest, manifest + (front if role == 1 else collector),
                    manifest + collector + front, manifest + tag + tag,
                    manifest + tag[:-1], manifest + tag[:-1] + bytes([255])]:
            path.write_bytes(bad)
            with pytest.raises(ValueError):
                audit.build_id(path, role)


# 이것을 실패시키는 것: exact pin/defaults/sha1 계약 또는 금지 crate/feature를 허용하는 것.
def test_collector_git_dependency_features_are_exact(tmp_path):
    audit = load("check_collector_dependencies")
    assert set(audit.TARGETS) >= {"aarch64-apple-darwin", "x86_64-apple-darwin",
                                  "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                                  "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"}
    assert set(audit.SCOPES) == {"product-default", "product-all", "bench", "collector-default", "collector-all", "collector-tests", "collector-build"}
    assert audit.manifest_policy() == []
    for relative in ("Cargo.toml", "crates/bingsu-collect/Cargo.toml"):
        dest = tmp_path / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, dest)
    workspace = tmp_path / "Cargo.toml"
    original = workspace.read_text().replace("\r\n", "\n")
    for before, after in [('"=0.58.0"', '"0.58.0"'),
                          ('default-features = false', 'default-features = true'),
                          ('features = ["sha1"]', 'features = ["sha1", "sha256"]')]:
        try:
            workspace.write_text(original.replace(before, after, 1))
            assert audit.manifest_policy(tmp_path), (before, after)
        finally:
            workspace.write_text(original)
    for name in audit.FORBIDDEN_PACKAGES:
        assert audit.git_policy({f"node\t{name}@1.0.0\t-\t-"}), name
    for feature in (*audit.FORBIDDEN_FEATURES, "parallel-walkdir"):
        assert audit.git_policy({f"node\tgix-parallel@0.50.1\t{feature}\t-"}), feature
    for name, version in audit.GIT_PINS.items():
        features = audit.GIT_FEATURES.get(name, "-")
        good = f"node\t{name}@{version}\t{features}\t-"
        assert not audit.git_policy({good})
        assert audit.git_policy({good}, front=True)
        assert audit.git_policy({good.replace(version, "99.0.0")})
        assert audit.git_policy({good.replace("\t" + features + "\t", "\tdefault\t")})


# 이것을 실패시키는 것: source/license/checksum 변경을 같다고 보거나 provenance 감사를 생략하는 것.
@pytest.mark.parametrize("column", [4, 5, 6])
def test_collector_dependency_provenance_is_exact(tmp_path, monkeypatch, column):
    audit = load("check_collector_dependencies")
    rows = audit.ALLOWLIST.read_text().replace("\r\n", "\n").splitlines()
    index = next(i for i, row in enumerate(rows) if row.startswith("*\t*\torigin\tgix-index@"))
    fields = rows[index].split("\t")
    fields[column] = "unreviewed"
    rows[index] = "\t".join(fields)
    path = tmp_path / "allowlist.tsv"
    path.write_text("\n".join(rows) + "\n")
    monkeypatch.setattr(audit, "ALLOWLIST", path)
    monkeypatch.setattr(sys, "argv", ["audit", "--target", "aarch64-apple-darwin"])
    assert audit.main() == 1


# 이것을 실패시키는 것: ELF @/@@ 버전·Mach-O $ 접미사 또는 Rust Command 경로를 무시하는 것.
def test_process_free_adapter_has_no_forbidden_imports():
    audit = load("check_collector_symbols")
    for symbol in ("posix_spawn", "posix_spawnp", "posix_spawnattr_init", "fork", "vfork",
                   "execve", "execvp", "system", "popen", "dlsym", "dlopen", "__libc_fork"):
        for raw in ("_" + symbol, "_" + symbol + "$UNIX2003", symbol + "@GLIBC_2.2.5",
                    symbol + "@@GLIBC_2.2.5", symbol + "@GLIBC_2.2.5 (2)"):
            assert audit.forbidden_imports("00000000 T " + raw, elf=True), raw
    assert audit.forbidden_imports(" U _syscall") == ["syscall"]
    assert audit.forbidden_imports(" U syscall@GLIBC_2.2.5", elf=True) == []
    assert audit.forbidden_imports(" U _read\n U malloc@GLIBC_2.2.5", elf=True) == []
    assert audit.command_symbols("000000 T std::process::Command::spawn")
    assert audit.command_symbols("000000 T gix_path::env::git_cmd")
    assert not audit.command_symbols("000000 T bingsu_collect::worker::execute")


# 이것을 실패시키는 것: 실제 앞단 linked gix 코드 또는 mangled crate 이름을 놓치는 것.
def test_git_feature_graph_does_not_reach_prompt_symbols():
    audit = load("check_collector_symbols")
    for line in ("000000 T gix_config::file::init", "000000 T _ZN10gix_config4file4init17h0123456789abcdefE",
                 "000000 T _RNvNtCsg123_8gix_path3env7git_cmd"):
        assert audit.prompt_git_symbols(line), line
    assert not audit.prompt_git_symbols("000000 T bingsu_identity::build_id")
    # CI saves the exact linked pair before stripping, not an empty test driver.
    release = ROOT / "target/release"
    audit.audit_pair(release / "bingsu-collect", release / "bingsu", release / "symbol-audit")


# 이것을 실패시키는 것: 빈 static ELF 표·동적 표 누락·다른 sibling의 full symbols를 통과시키는 것.
def test_symbol_audit_requires_complete_link_evidence(tmp_path, monkeypatch):
    audit = load("check_collector_symbols")
    identity = bytes(range(32))
    for name, role in (("bingsu-collect", 1), ("bingsu", 2)):
        (tmp_path / name).write_bytes(b"\x7fELF" + audit.TAG + identity + audit.ROLE + bytes([role]) + identity)
    table = "00000001 T harmless\n"
    dynamic, headers = "", ""
    def output(command):
        if command[0] == "nm":
            return table
        return dynamic if "--dyn-syms" in command else headers
    monkeypatch.setattr(audit, "output", output)
    worker, front = tmp_path / "bingsu-collect", tmp_path / "bingsu"
    audit.audit_pair(worker, front)
    for headers in ("INTERP", "(NEEDED)"):
        with pytest.raises(ValueError, match="dynamic symbol table"):
            audit.audit_pair(worker, front)
    headers = ""
    for table in ("", "00000001 T execve", "00000001 T gix_config::file::init",
                  "00000001 T std::process::Command::spawn"):
        with pytest.raises(ValueError):
            audit.audit_pair(worker, front)
    table = "00000001 T harmless\n"
    dynamic = "Symbol table '.dynsym'\n1: 00000000 0 FUNC GLOBAL DEFAULT UND execve@GLIBC_2.2.5"
    with pytest.raises(ValueError, match="execve"):
        audit.audit_pair(worker, front)
    dynamic = ""
    saved = tmp_path / "saved"
    saved.mkdir()
    for source in (worker, front):
        shutil.copyfile(source, saved / source.name)
    for name, role in (("bingsu-collect", 1), ("bingsu", 2)):
        original = (saved / name).read_bytes()
        other = bytes([99]) * 32
        try:
            (saved / name).write_bytes(b"\x7fELF" + audit.TAG + other + audit.ROLE + bytes([role]) + other)
            with pytest.raises(ValueError, match="identity or format mismatch"):
                audit.audit_pair(worker, front, saved)
        finally:
            (saved / name).write_bytes(original)
    worker.write_bytes(b"not a binary")
    with pytest.raises(ValueError, match="Mach-O or ELF"):
        audit.audit_pair(worker)


# 이것을 실패시키는 것: 한 출하 arch/libc·MSRV·strip 전후 감사 또는 Linux exec 시험을 CI에서 빼는 것.
def test_c1_ci_requires_every_shipped_link_and_msrv():
    spec = importlib.util.spec_from_file_location("security_ci", ROOT / "tests/shell/test_collector_security.py")
    security = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security)
    text = (ROOT / ".github/workflows/ci.yml").read_text().replace("\r\n", "\n")

    def check(text):
        steps = security.security_steps(text)
        names = {step.get("name"): step for step in steps}
        native = names["Product imports and matching deployment pair"]
        assert "if" not in native
        for name, directories in (
            ("Product imports and matching deployment pair", ("target/release",)),
            ("M3b native musl lifecycle security", ("target/$triple/release",)),
        ):
            commands = security.run_commands(names[name])
            for directory in directories:
                assert ["python3", "scripts/check_collector_symbols.py", directory + "/bingsu-collect",
                        "--sibling", directory + "/bingsu", "--unstripped-dir", directory + "/symbol-audit", "--strip"] in commands
        linux = names["Assert native Linux M3b security passes"]["run"]
        musl = names["M3b native musl lifecycle security"]["run"]
        for commands in (linux, musl):
            assert "test_security_table_resource_failures_preserve_front[exec]" in commands
        meta, msrv = security.workflow_job(text, "collector-msrv")
        assert meta["if"][0] == "needs.detect.outputs.rust == 'true'"
        assert "continue-on-error" not in meta
        assert "toolchain: 1.88.0" in text
        assert any(security.run_commands(step) == [["cargo", "build", "--locked", "-j", "2", "-p", "bingsu", "-p", "bingsu-prompt", "-p", "bingsu-collect"]]
                   and "if" not in step and "continue-on-error" not in step for step in msrv)

    check(text)
    for before, after in (
        ("--unstripped-dir", "--unchecked"), ("--strip", "--unchecked"),
        (", macos-latest", ""),
        ('"target/$triple/release/bingsu-collect"', '"unshipped"'),
        ("toolchain: 1.88.0", "toolchain: stable"),
        ("test_security_table_resource_failures_preserve_front[exec]", "unrun_exec"),
        ("      - name: Product imports and matching deployment pair", "      - if: runner.os == 'macOS'\n        name: Product imports and matching deployment pair"),
    ):
        assert before in text
        with pytest.raises(AssertionError):
            check(text.replace(before, after))
