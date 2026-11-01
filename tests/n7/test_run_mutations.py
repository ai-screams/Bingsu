"""Self-tests for the mutation harness; no cargo or source mutations needed."""
import json
import os
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


def manifest_problems(manifest, root):
    """Every patch set of `manifest`, applied in order to an in-memory copy, the
    way run() applies it. A stale `before` or a test that left the tree would
    otherwise turn into an ERROR only when somebody runs that one mutation."""
    problems = []
    for case in manifest:
        anchor = case["anchor"].rsplit("::", 1)[-1].split("[")[0]
        word = "fn" if case["kind"] == "rust" else "def"
        declared = f"{word} {anchor}("
        sources = (*root.glob("crates/**/*.rs"), *root.glob("fuzz/**/*.rs")) if word == "fn" \
            else (*root.glob("tests/**/*.py"), *root.glob("tools/**/*.py"), *root.glob("bench/**/*.py"))
        if not any(declared in path.read_text(errors="replace") for path in sources):
            problems.append(f"{case['id']}: no test named {anchor}")
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
    (tmp_path / "crates").mkdir()
    (tmp_path / "crates/a.rs").write_text("fn real() { one; two; two; }\n")
    case = {"id": "x", "kind": "rust", "anchor": "m::real",
            "patches": [{"file": "crates/a.rs", "before": "one", "after": "first"}]}
    assert manifest_problems([case], tmp_path) == []
    stale = [{"file": "crates/a.rs", "before": "gone", "after": "x"}]
    assert manifest_problems([{**case, "patches": stale}], tmp_path) == ["x: crates/a.rs: expected 1, got 0"]
    assert manifest_problems([{**case, "patches": [{**stale[0], "before": "two"}]}], tmp_path) == [
        "x: crates/a.rs: expected 1, got 2"]
    chained = [{"file": "crates/a.rs", "before": "one", "after": "three"},
               {"file": "crates/a.rs", "before": "three", "after": "four"}]
    assert manifest_problems([{**case, "patches": chained}], tmp_path) == []
    assert manifest_problems([{**case, "platform_patches": {"linux": stale}}], tmp_path) == [
        "x: crates/a.rs: expected 1, got 0"]
    assert manifest_problems([{**case, "anchor": "m::gone"}], tmp_path) == ["x: no test named gone"]
