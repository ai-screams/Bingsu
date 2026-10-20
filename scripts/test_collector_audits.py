"""Host-only collector dependency, import and shared manifest audit tests."""
import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# 이것을 실패시키는 것: 금지된 exec/spawn/fork 계열 또는 dlsym을 감사에서 허용하는 것.
def test_macos_collection_binary_has_no_spawn_imports(tmp_path):
    audit = load("check_collector_symbols")
    for symbol in ("posix_spawn", "posix_spawnp", "execve", "execv", "execvp", "execvpe",
                   "execl", "execlp", "execle", "fork", "vfork", "system", "popen", "dlsym"):
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



# 이것을 실패시키는 것: source·lock·feature·target·profile·flags 중 하나를 build-id에서 빼는 것.
def test_sibling_build_manifest_is_exact(tmp_path):
    builder = tmp_path / "manifest-builder"
    subprocess.run(["rustc", "--edition=2024", str(ROOT / "crates/bingsu-collect/build.rs"),
                    "-o", str(builder)], check=True, capture_output=True)
    root = tmp_path / "source"
    root.mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        (root / name).write_text("baseline\n")
    for package in ("bingsu", "bingsu-core", "bingsu-collect", "bingsu-bench"):
        path = root / "crates" / package
        (path / "src").mkdir(parents=True)
        (path / "Cargo.toml").write_text("baseline\n")
        (path / "src/lib.rs").write_text("baseline\n")
    (root / "crates/bingsu-collect/build.rs").write_text("baseline\n")
    out = tmp_path / "out"
    out.mkdir()
    settings = {"CARGO_MANIFEST_DIR": str(root / "crates/bingsu-collect"), "OUT_DIR": str(out),
                "TARGET": "aarch64-apple-darwin", "PROFILE": "release", "OPT_LEVEL": "3", "DEBUG": "false"}
    def identity(extra=None):
        subprocess.run([str(builder)], env=settings | (extra or {}), check=True, capture_output=True)
        return (out / "build_id.rs").read_bytes()
    baseline = identity()
    assert identity() == baseline
    for relative in ("Cargo.toml", "Cargo.lock", "crates/bingsu-collect/Cargo.toml", "crates/bingsu/src/lib.rs", "crates/bingsu-core/src/lib.rs",
                     "crates/bingsu-collect/src/lib.rs", "crates/bingsu-bench/src/lib.rs"):
        file = root / relative
        saved = file.read_bytes()
        try:
            file.write_bytes(b"changed!\n")
            assert identity() != baseline, relative
        finally:
            file.write_bytes(saved)
        assert identity() == baseline
    for key, value in (("TARGET", "x86_64-unknown-linux-musl"), ("PROFILE", "debug"), ("OPT_LEVEL", "2"), ("DEBUG", "true"),
                       ("CARGO_FEATURE_BENCH_BUILD", "1"), ("CARGO_ENCODED_RUSTFLAGS", "-Copt-level=1"),
                       ("CARGO_CFG_TARGET_FEATURE", "sse2"), ("CARGO_PROFILE_RELEASE_LTO", "false")):
        assert identity({key: value}) != baseline, key

    link = root / "crates/bingsu/src/linked.rs"
    link.symlink_to(root / "Cargo.lock")
    try:
        with pytest.raises(subprocess.CalledProcessError):
            identity()
    finally:
        link.unlink()
