"""M3c observation contracts; product runtime lives in the dedicated CI job."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("git_product", ROOT / "bench/git-product.py")
git = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(git)


# Exercise observe itself: the summary tests replace it and missed a Path in
# prompt_context's argv. Include cached contexts and paths containing spaces.
@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("executable_type", [str, Path])
def test_observe_normalizes_path_argv_before_retargeting(monkeypatch, tmp_path, cached, executable_type):
    binary = executable_type(tmp_path / "front binary")
    repo, directory = tmp_path / "repo with spaces", tmp_path / "observation"
    command = [binary, "prompt", "--home=/old", "--pwd", Path("/old")]
    original = list(command)
    env = {"context": "preserved"}
    prep = {"fixture": tmp_path / "helper fixture"}
    if cached:
        prep["prompt_contexts"] = {str(directory): (command, env)}
    class Helper:
        returncode = 0
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def poll(self): return 0
        def communicate(self): return b'F3_RESULT {"published": true}\n', b""
    def popen(argv, **kwargs):
        assert argv == [str(prep["fixture"]), str(directory), str(repo)]
        return Helper()
    calls = []
    def run(argv, **kwargs):
        assert all(isinstance(word, str) for word in argv)
        calls.append(argv)
        if "--read" in argv:
            return SimpleNamespace(stdout=b'{"front_read_ns": 12}')
        assert argv == [str(binary), "prompt", "--home=" + str(repo), "--pwd", str(repo)]
        assert kwargs["env"] is env
        return SimpleNamespace(returncode=0, stderr=b"", stdout=b"B1\x1f" + b"\x1f" * 8 + b"ok:none\x1e")
    monkeypatch.setattr(git.subprocess, "Popen", popen)
    monkeypatch.setattr(git.M3B, "run", run)
    monkeypatch.setattr(git.M3B, "prompt_context", lambda *args: (command, env))
    monkeypatch.setattr(git, "observe_stages", lambda *args: {"status": "OBSERVED"})
    result = git.observe(binary, prep, directory, repo)
    assert result["status"] == "OBSERVED" and "prompt_ns" in result
    assert result["previous_read"]["front_read_ns"] == 12
    assert len(calls) == 2 and command == original


def sample(*, partial=False, reason="Complete", published=True, at=20):
    events = {name: 1000 + i * 10 for i, name in enumerate(git.M3B.EVENTS)}
    events["request_deadline"] = 2000
    return {"status": "OBSERVED", "events": events, "published": published,
            "reaped": True, "stage_a": True, "partial": partial, "reason": reason,
            "completed_at_ns": at, "cwd": "/same", "prompt_ns": 100,
            "admission_gc_ns": 30, "memory_samples": [{"at_ns": 1, "resident_bytes": 1000,
            "footprint_bytes": 800, "as_peak_bytes": 4000, "rss_peak_bytes": 1000}], "load": [1, 2, 3]}


@pytest.fixture
def pair(monkeypatch, tmp_path):
    prep = {"hashes": {"front": "front", "collector": "collector"}, "source_hashes": {"source": "digest"},
            "sibling_build_id": "id", "stripped_bytes": {"front": 101, "collector": 202, "combined": 303},
            "compiler": "rustc", "product_mask": 10}
    monkeypatch.setattr(git, "OUT", tmp_path)
    monkeypatch.setattr(git, "prepared", lambda _: copy.deepcopy(prep))
    monkeypatch.setattr(git.M3B, "host", lambda: {"load": [1, 2, 3]})
    monkeypatch.setattr(git, "repositories", lambda _: {case: Path("/same") for case in git.CASES})
    monkeypatch.setattr(git, "observe", lambda *args: sample())
    return prep


# 이것을 실패시키는 것: M3c를 정식 B5-B7로 부르거나 교대/200회/원시 표본을 생략하는 것.
def test_m3c_measurement_is_not_formal_b5_b7(pair):
    value = git.measure_pair("base", "candidate", 200)
    assert value["milestone"] == "M3c" and value["formal_B5_B7"] is False
    assert set(value["common"]) == {"I", "S", "L"}
    assert "M3d formal B5-B7" in value["pending"]
    assert set(value["cases"]) == set(git.CASES)
    for case in value["cases"].values():
        assert case["order"] == ["base", "candidate", "candidate", "base"] * 100
        assert set(case["cold_first_process"]) == {"base", "candidate"}
        for row in case["variants"].values():
            assert len(row["samples"]) == row["observed"] == 200
            assert row["metrics"]["prompt_ns"] == {"status": "OBSERVED", "n": 200, "p50": 100,
                                                       "p95": 100, "variance": 0, "min": 100, "max": 100}
    with pytest.raises(ValueError, match="200"):
        git.measure_pair("base", "candidate", 199)


# 이것을 실패시키는 것: 합계만 남기거나 git 메모리를 가설/고정 수치로 대신하는 것.
def test_two_binary_sizes_and_git_memory_are_reported(pair):
    value = git.measure_pair("base", "candidate", 200)
    for row in value["variants"].values():
        assert row["stripped_bytes"] == {"front": 101, "collector": 202, "combined": 303}
        assert row["hashes"] == pair["hashes"] and row["product_mask"] == 10
    for case in value["cases"].values():
        for row in case["variants"].values():
            assert row["memory"]["samples"] == 200
            assert row["memory"]["peaks"] == {"resident_bytes": 1000, "footprint_bytes": 800,
                                               "as_peak_bytes": 4000, "rss_peak_bytes": 1000}
    empty = sample()
    empty["memory_samples"] = []
    assert all(v is None for v in git.summarize([empty], 200)["memory"]["peaks"].values())


# 이것을 실패시키는 것: 실패/정상 화면 부재를 버리고 남은 값이나 degraded fallback으로 200회를 채우는 것.
@pytest.mark.parametrize("damage", ["prompt", "helper"])
def test_missing_normal_round_remains_blocked(pair, monkeypatch, damage):
    calls = []
    def observe(*args):
        calls.append(args[0])
        value = sample()
        if damage == "prompt":
            value.pop("prompt_ns")
            value["prompt_blocked"] = "normal snapshot unavailable"
        else:
            value = {"status": "BLOCKED", "error": "worker", "memory_samples": []}
        return value
    monkeypatch.setattr(git, "observe", observe)
    value = git.measure_pair("base", "candidate", 200)
    assert value["status"] == "BLOCKED"
    assert len(calls) == len(git.CASES) * 402  # cold plus 200 per binary, no retry
    for case in value["cases"].values():
        for row in case["variants"].values():
            assert row["attempted"] == 200
            assert row["metrics"]["prompt_ns"] == {"status": "BLOCKED", "n": 0}


# 이것을 실패시키는 것: 미발행/다른 cwd/오래된 Partial을 덮어쓰기 분자에 세거나 Deadline을 Protocol로 합치는 것.
def test_partial_replacement_rate_uses_published_same_cwd_and_order():
    first = sample(at=10)
    deadline = sample(at=20, partial=True, reason="Deadline")
    protocol = sample(at=30, partial=True, reason="Protocol")
    dropped = sample(at=40, partial=True, reason="Deadline", published=False)
    other = {**sample(at=50, partial=True), "cwd": "/other"}
    old = sample(at=1, partial=True)
    samples = [first, dropped, deadline, protocol, first, other, first, old]
    assert git.summarize([first, dropped], 2)["complete_to_partial"] == {"count": 0, "denominator": 0, "rate": None}
    stats = git.summarize(samples, 8)
    assert stats["complete_to_partial"] == {"count": 1, "denominator": 2, "rate": .5}
    assert stats["complete_to_partial_per_round"]["rate"] == 1 / 8
    assert stats["partial"]["count"] == 4 and stats["partial"]["denominator"] == 7
    assert stats["partial_reasons"] == {"Deadline": 1, "Protocol": 1, "Complete": 2}
    assert stats["deadline"]["rate"] == 2 / 8
    assert stats["budget_overrun"]["counter_limits"]["status"] == "BLOCKED"


# 이것을 실패시키는 것: budget/facts bench를 등록하지 않거나 helper를 inline하여 Ir을 빠뜨리는 것.
def test_git_instruction_targets_keep_measured_helpers():
    text = (ROOT / "crates/bingsu-core-bench/benches/git.rs").read_text()
    for name in ("budget_call", "facts_call"):
        assert f"#[inline(never)]\nfn {name}(" in text
    assert "benchmarks = format_git, merge_git, readonly_layout, git_budget, path_facts_codec" in text
    assert '\n[[bench]]\n# M3c schema/budget/merge/format/PathFacts; new cases record positive Ir first.\nname = "git"\nharness = false\ntest = false' in (ROOT / "crates/bingsu-core-bench/Cargo.toml").read_text()


# 이것을 실패시키는 것: stage 초과/표본 간격/overshoot/앞단 읽기를 누락하거나 다른 구간으로 대체하는 것.
def test_stage_memory_and_previous_read_intervals_keep_their_basis():
    value = sample()
    value["events"]["as_baseline"] = 100
    value["memory_samples"] = [{"at_ns": 10, "footprint_bytes": 33_554_542},
                               {"at_ns": 40, "footprint_bytes": 33_554_542}]
    value["previous_read"] = {"front_read_ns": 10, "front_prefetch_ns": 20}
    value["stage_diagnostic"] = {"stages": [{"stage": "B", "elapsed_ns": 29_000_000,
        "budget_ns": 28_000_000, "result": "Err(Read(Deadline))"}], "raw": "F1_FIELD untracked count:256:true\n"}
    stats = git.summarize([value], 1)
    assert stats["stage_diagnostic"]["B"]["p50"] == 29_000_000
    assert stats["stage_diagnostic"]["B"]["deadline"]["rate"] == 1
    assert stats["stage_diagnostic"]["B"]["elapsed_over_budget"]["rate"] == 1
    assert stats["stage_diagnostic"]["A"]["n"] == 0
    assert stats["memory"]["sample_interval_ns"]["p50"] == 30
    assert stats["memory"]["sampled_overshoot_bytes"]["p50"] == 10
    assert stats["metrics"]["front_read_ns"]["p50"] == 10
    assert stats["metrics"]["front_prefetch_ns"]["p50"] == 20
    assert stats["budget_overrun"]["saturated_diagnostic"]["rate"] == 1


# 이것을 실패시키는 것: 다른 binary/source, debug 빌드 또는 mask 0의 준비 파일을 받아들이는 것.
@pytest.mark.parametrize("damage", ["front", "collector", "fixture", "diagnostic", "sources", "profile", "mask"])
def test_preparation_is_bound_to_release_sources_and_both_siblings(monkeypatch, tmp_path, damage):
    import json
    files = {name: tmp_path / filename for name, filename in
             (("front", "bingsu"), ("collector", "bingsu-collect"), ("fixture", "helper"), ("diagnostic", "stages"))}
    for name, path in files.items():
        path.write_text(name)
    prepared = {"fixture": str(files["fixture"]), "diagnostic": str(files["diagnostic"]), "source": str(tmp_path),
                "source_hashes": {"source": "hash"}, "profile": "release", "product_mask": 10,
                "hashes": {name: git.M3B.digest(path) for name, path in files.items()}}
    monkeypatch.setattr(git, "sources", lambda _: {"source": "hash"})
    manifest = git.manifest_path(files["front"])
    manifest.write_text(json.dumps(prepared))
    assert git.prepared(files["front"]) == prepared
    if damage in files:
        files[damage].write_text("changed")
    elif damage == "sources":
        prepared["source_hashes"] = {}
    elif damage == "profile":
        prepared["profile"] = "debug"
    else:
        prepared["product_mask"] = 0
    manifest.write_text(json.dumps(prepared))
    with pytest.raises(ValueError):
        git.prepared(files["front"])


# 이것을 실패시키는 것: Darwin rusage 필드 위치를 wired/resident와 혼동해 footprint를 잘못 보고하는 것.
def test_darwin_memory_sampler_uses_resident_and_footprint(monkeypatch):
    class Lib:
        def proc_pid_rusage(self, pid, version, output):
            assert pid == 123 and version == 2
            output._obj[7] = 700
            output._obj[8] = 800
            output._obj[9] = 900
            return 0
    monkeypatch.setattr(git.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(git.ctypes, "CDLL", lambda *a, **k: Lib())
    monkeypatch.setattr(git.time, "monotonic_ns", lambda: 10)
    assert git.memory_sample(123) == {"at_ns": 10, "resident_bytes": 800, "footprint_bytes": 900}
