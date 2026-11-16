"""Self-tests for the mutation harness; no cargo or source mutations needed."""
import ast
import json
import os
import re
import shlex
import signal
import sys

import pytest

import run_mutations as harness


# 이것을 실패시키는 것: timeout이 직접 자식만 죽이거나 SIGTERM을 무시한 손자를 남기는 것.
def test_timeout_reaps_grandchild_before_returning(tmp_path):
    ready = tmp_path / "ready"
    late = tmp_path / "late"
    grandchild = (
        "import os, pathlib, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid())); "
        "time.sleep(3); "
        f"pathlib.Path({str(late)!r}).touch()"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "time.sleep(30)"
    )
    try:
        code, output = harness.execute([sys.executable, "-c", parent], tmp_path / "log", 1)
        assert ready.exists(), "grandchild was never scheduled; test did not exercise cleanup"
        assert code == harness.TIMEOUT and "N7 HARNESS TIMEOUT" in output
        pid = int(ready.read_text())
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("grandchild survived timeout")
        assert not late.exists()
    finally:
        if ready.exists():
            try:
                os.kill(int(ready.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


# 이것을 실패시키는 것: timeout 전에 출력된 FAILED를 변이 검출로 세는 것.
def test_timeout_after_named_failure_is_error_and_restores(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"original")
    calls = iter([(0, "anchor PASSED"), (harness.TIMEOUT, "anchor FAILED")])
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "execute", lambda *args: next(calls))
    case = {"id": "timeout", "kind": "python", "anchor": "anchor", "command": [],
            "patches": [{"file": "source", "before": "original", "after": "mutant"}]}
    result = harness.run(case, tmp_path)
    assert result["status"] == "ERROR"
    assert source.read_bytes() == b"original"
    assert (tmp_path / "timeout-restored.json").exists()


VISIBILITY = r"(?:pub(?:\([^)]*\))?\s+)?"


def rust_target_root(command, root):
    """The root file of the cargo test target a manifest command runs (`-p` with
    `--lib`, `--bin` or `--test <name>`, also inside `sh -c`), or None."""
    words = shlex.split(command[2]) if command[:2] == ["sh", "-c"] else list(command)
    if "-p" not in words:
        return None
    crate = root / "crates" / words[words.index("-p") + 1]
    if "--lib" in words:
        return crate / "src/lib.rs"
    if "--bin" in words:
        return crate / "src/main.rs"
    if "--test" in words:
        return crate / "tests" / (words[words.index("--test") + 1] + ".rs")
    return None


def rust_path_declared(text, folder, segments, depth=0):
    """Whether the module path `segments[:-1]`, read from a module's `text` the
    way rustc finds module files, reaches a module that declares
    `fn segments[-1]`. `folder` holds the module's child files: `mod a;` is
    `folder/a.rs` (whose children are in `folder/a/`) or `folder/a/mod.rs`, and
    an inline `mod a { … }` keeps its children in `folder/a/`. rustfmt indents
    an inline module's items four spaces more and closes it at its own
    indentation, so `depth` inline modules deep an item starts after exactly
    4 × depth spaces, and the module's body ends at the first `}` there."""
    first, rest = segments[0], segments[1:]
    at = rf"(?m)^ {{{4 * depth}}}{VISIBILITY}"
    if not rest:
        return re.search(rf"{at}(?:async\s+)?fn\s+{re.escape(first)}\s*\(", text) is not None
    if re.search(rf"{at}mod\s+{re.escape(first)}\s*;", text):
        for child in (folder / f"{first}.rs", folder / first / "mod.rs"):
            if child.is_file() and rust_path_declared(child.read_text(errors="replace"), folder / first, rest):
                return True
    for opened in re.finditer(rf"{at}mod\s+{re.escape(first)}\s*\{{", text):
        closed = re.compile(rf"(?m)^ {{{4 * depth}}}\}}").search(text, opened.end())
        body = text[opened.end():closed.start() if closed else len(text)]
        if rust_path_declared(body, folder / first, rest, depth + 1):
            return True
    return False


def python_test_declared(source, names):
    """Whether `names` (any classes, then the function) are nested in that order
    at the top of the pytest file `source`."""
    body = ast.parse(source.read_text(errors="replace")).body
    *classes, name = names
    for cls in classes:
        found = [node for node in body if isinstance(node, ast.ClassDef) and node.name == cls]
        if not found:
            return False
        body = found[0].body
    return any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name for node in body)


def anchor_declared(case, root):
    """Whether the whole anchor names a test the case's command can select: a
    Rust module path from its cargo target's root, a pytest file and function."""
    anchor = case["anchor"].split("[")[0]
    if case["kind"] == "rust":
        target = rust_target_root(case.get("command", []), root)
        return target is not None and target.is_file() and \
            rust_path_declared(target.read_text(errors="replace"), target.parent, anchor.split("::"))
    path, *names = anchor.split("::")
    source = root / path
    return bool(names) and source.is_file() and python_test_declared(source, names)


def manifest_problems(manifest, root):
    """Every patch set of `manifest`, applied in order to an in-memory copy, the
    way run() applies it. A stale `before` or a test that left the tree would
    otherwise turn into an ERROR only when somebody runs that one mutation; an
    anchor whose module path is stale would run no test ("not done")."""
    problems = []
    for case in manifest:
        if not anchor_declared(case, root):
            problems.append(f"{case['id']}: no test {case['anchor']}")
        for patches in (case["patches"], *case.get("platform_patches", {}).values()):
            texts = {}
            for patch in patches:
                name = patch["file"]
                source = texts.setdefault(name, (root / name).read_text().replace("\r\n", "\n"))
                count = source.count(patch["before"])
                if count != patch.get("count", 1):
                    problems.append(f"{case['id']}: {name}: expected {patch.get('count', 1)}, got {count}")
                    continue
                texts[name] = source.replace(patch["before"], patch["after"], patch.get("replace", count))
    return problems


# 이것을 실패시키는 것: 소스가 바뀌었는데 mutations.json의 `before`나 anchor를 그대로 두는 것.
@pytest.mark.parametrize("name", ["mutations.json", "m3a_os_boundary.json"])
def test_every_manifest_patch_applies_to_the_current_source(name):
    manifest = json.loads((harness.ROOT / "tests/n7" / name).read_text())
    assert manifest_problems(manifest, harness.ROOT) == []


# 이것을 실패시키는 것: 맞는 횟수를 보지 않는 것, 앞 패치를 반영하지 않고 뒤 패치를 원본에 대는 것,
# platform_patches나 anchor를 건너뛰는 것.
def test_manifest_check_names_each_stale_entry(tmp_path):
    crate = tmp_path / "crates/a"
    (crate / "src").mkdir(parents=True)
    (crate / "src/lib.rs").write_text("mod m;\n")
    (crate / "src/m.rs").write_text("fn real() { one; two; two; }\n")
    lib = ["cargo", "test", "-p", "a", "--lib", "--", "m::real", "--exact"]
    case = {"id": "x", "kind": "rust", "anchor": "m::real", "command": lib,
            "patches": [{"file": "crates/a/src/m.rs", "before": "one", "after": "first"}]}
    assert manifest_problems([case], tmp_path) == []
    stale = [{"file": "crates/a/src/m.rs", "before": "gone", "after": "x"}]
    assert manifest_problems([{**case, "patches": stale}], tmp_path) == ["x: crates/a/src/m.rs: expected 1, got 0"]
    assert manifest_problems([{**case, "patches": [{**stale[0], "before": "two"}]}], tmp_path) == [
        "x: crates/a/src/m.rs: expected 1, got 2"]
    chained = [{"file": "crates/a/src/m.rs", "before": "one", "after": "three"},
               {"file": "crates/a/src/m.rs", "before": "three", "after": "four"}]
    assert manifest_problems([{**case, "patches": chained}], tmp_path) == []
    assert manifest_problems([{**case, "platform_patches": {"linux": stale}}], tmp_path) == [
        "x: crates/a/src/m.rs: expected 1, got 0"]
    assert manifest_problems([{**case, "anchor": "m::gone"}], tmp_path) == ["x: no test m::gone"]


# The anchor is the whole name the runner selects with --exact and looks for in
# "test <anchor> ... ok"; a stale module on its path selects no test.
# 이것을 실패시키는 것: anchor의 마지막 이름만 보는 것(경로 한 단계가 틀린 anchor가 통과), inline
# `mod … {`의 들여쓰기 깊이를 보지 않는 것(inline 단계 하나를 빠뜨린 anchor가 통과), inline 모듈의
# 몸통 밖까지 찾는 것(이웃 inline 모듈의 시험을 받음), `mod a;`를 mod-rs가 아닌 파일 옆에서 찾거나
# inline 모듈 안의 `mod a;`를 그 모듈 폴더 밖에서 찾는 것, `a/mod.rs`를 찾지 않는 것, `sh -c`·
# `--test`의 target을 읽지 않는 것, pytest anchor의 파일이나 class 안을 보지 않는 것.
def test_manifest_check_follows_the_whole_anchor_path(tmp_path):
    crate = tmp_path / "crates/a"
    for folder in ("src/m", "src/d", "tests"):
        (crate / folder).mkdir(parents=True)
    (crate / "src/w").mkdir()
    (crate / "src/lib.rs").write_text("mod d;\nmod m;\nmod w {\n    mod s;\n}\n")
    (crate / "src/m.rs").write_text("fn real() {}\n#[cfg(test)]\nmod t;\n")
    (crate / "src/m/t.rs").write_text("mod cases {\n    #[test]\n    fn deep() {}\n}\nmod other {\n    fn sib() {}\n}\n")
    (crate / "src/w/s.rs").write_text("fn held() {}\n")
    (crate / "src/d/mod.rs").write_text("pub fn dir() {}\n")
    (crate / "tests/api.rs").write_text("#[test]\nfn top() {}\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_x.py").write_text("class TestK:\n    def test_y(self):\n        pass\n\n\ndef test_z():\n    pass\n")
    lib = ["cargo", "test", "-p", "a", "--lib"]
    api = ["sh", "-c", "exec cargo test -j 2 -p a --test api -- top --exact"]

    def problems(anchor, kind="rust", command=lib):
        return manifest_problems([{"id": "x", "kind": kind, "anchor": anchor, "command": command, "patches": []}],
                                 tmp_path)

    for anchor, kind, command in [("m::real", "rust", lib), ("m::t::cases::deep", "rust", lib),
                                  ("d::dir", "rust", lib), ("top", "rust", api), ("w::s::held", "rust", lib),
                                  ("m::t::other::sib", "rust", lib),
                                  ("tests/test_x.py::TestK::test_y", "python", []),
                                  ("tests/test_x.py::test_z[1]", "python", [])]:
        assert problems(anchor, kind, command) == [], anchor
    for anchor, kind, command in [("n::real", "rust", lib), ("m::t::deep", "rust", lib),
                                  ("m::cases::deep", "rust", lib), ("t::cases::deep", "rust", lib),
                                  ("m::t::cases::sib", "rust", lib), ("s::held", "rust", lib),
                                  ("top", "rust", lib), ("m::real", "rust", ["cargo", "test", "--lib"]),
                                  ("tests/test_w.py::test_z", "python", []),
                                  ("tests/test_x.py::TestJ::test_y", "python", []),
                                  ("tests/test_x.py::test_y", "python", []),
                                  ("tests/test_x.py::TestK::test_z", "python", [])]:
        assert problems(anchor, kind, command) == [f"x: no test {anchor}"], anchor
