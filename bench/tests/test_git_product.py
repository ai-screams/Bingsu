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


@pytest.mark.parametrize("panic", [False, True])
def test_admission_yield_and_panic_keep_raw_evidence(monkeypatch, tmp_path, panic):
    record = {"status": "BLOCKED", "product_mask": 10, "blocked_at": "admission",
              "deferred": "Some(YieldTime)", "broker": "Busy"}
    stdout = b"" if panic else b"F3_RESULT " + json.dumps(record).encode() + b"\n"
    stderr = b"thread 'main' panicked: helper admission\n" if panic else b""
    class Helper:
        returncode = 101 if panic else 0
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def poll(self): return self.returncode
        def communicate(self): return stdout, stderr
    monkeypatch.setattr(git.subprocess, "Popen", lambda *a, **k: Helper())
    def unexpected(*args, **kwargs):
        pytest.fail("blocked observation must not retry or synthesize downstream measurements")
    monkeypatch.setattr(git.M3B, "run", unexpected)
    monkeypatch.setattr(git, "observe_stages", unexpected)
    result = git.observe("front", {"fixture": "helper"}, tmp_path / "context", tmp_path / "repo")
    assert result["status"] == "BLOCKED"
    assert result["exit"] == Helper.returncode
    assert result["stdout"] == stdout.decode() and result["stderr"] == stderr.decode()
    if not panic:
        assert result.items() >= record.items()
    assert git.summarize([result], 1)["observed"] == 0


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
        assert len(case['order']) == 400
        assert case['order'].count('base') == case['order'].count('candidate') == 200
        for block in case['blocks']:
            first = block['order'][:2]
            assert first in (['base', 'candidate'], ['candidate', 'base'])
            assert block['order'] == (first + first[::-1]) * 10
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


@pytest.fixture(autouse=True)
def controlled_protocol(monkeypatch):
    # Product tests exercise real pairing; host probes have dedicated negative controls.
    p = git.M3B.protocol
    calibration = dict(stable=True, p95_of_medians=100, **p.identity())
    monkeypatch.setattr(p, 'calibrate', lambda _: calibration)
    monkeypatch.setattr(p, 'snapshot', lambda _: dict(**p.identity(), power='ac',
        thermal='normal', load_1m=1., reference=p.summary([100] * 20)))


# 이것을 실패시키는 것: --cases 선택을 무시하고 모든 칸을 측정한다.
def test_cases_option_selects_only_named_cases(pair):
    value = git.measure_pair('base', 'candidate', 200, cases=['git-clean'])
    assert list(value['cases']) == ['git-clean']
    with pytest.raises(ValueError):
        git.measure_pair('base', 'candidate', 200, cases=['unknown'])


def test_cli_forwards_cases_mode_and_condition(monkeypatch, tmp_path):
    import sys
    received = {}
    def measure(base, candidate, rounds, **kwargs):
        received.update(kwargs)
        return {'status': 'OBSERVED'}
    monkeypatch.setattr(git, 'measure_pair', measure)
    monkeypatch.setattr(git.M3B.protocol, 'write_output', lambda *_: None)
    monkeypatch.setattr(sys, 'argv', ['git-product.py', '--base', 'b', '--candidate', 'c',
        '--out', str(tmp_path / 'out.json'), '--cases', 'git-clean', '--mode', 'experiment',
        '--condition', '{"power":"battery","load_range":[1,3],"synthetic_load":0}'])
    assert git.main() == 0
    assert received['cases'] == ['git-clean']
    assert received['condition'] == dict(mode='experiment', power='battery', load_range=[1,3], synthetic_load=0)


@pytest.mark.parametrize('metric', ['prompt_ns', 'admission_gc_ns'])
def test_protocol_blocks_missing_git_metric(pair, monkeypatch, metric):
    row = sample()
    row.pop(metric)
    monkeypatch.setattr(git, 'observe', lambda *args: row)
    result = git.measure_pair('base', 'candidate', 200, cases=['git-clean'])
    assert result['status'] == 'BLOCKED'
    assert result['cases']['git-clean']['status'] == 'BLOCKED'
    assert metric in result['cases']['git-clean']['reason']


YY_TRACE = """\
100   execve("/b/bingsu", ["/b/bingsu", "prompt", "--ctx", "1"], 0x7ffd /* 2 vars */) = 0
100   openat(AT_FDCWD</>, "/proc/self/fd", O_RDONLY|O_CLOEXEC) = 3</proc/100/fd>
100   clone(child_stack=0xe250, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
101   execve("/b/bingsu", ["/b/bingsu", "__refresh-v1", "--config-root=/c"], 0x7ffe /* 0 vars */ <unfinished ...>
100   <... clone resumed>)              = 101
101   <... execve resumed>)             = 0
100   write(1<pipe:[1906095]>, "B1\\378\\37"..., 241 <unfinished ...>
100   +++ exited with 0 +++
101   clone(child_stack=0xfee2, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD <unfinished ...>
101   <... clone resumed>, parent_tid=[103], tls=0xfee2, child_tidptr=0xfee1) = 103
101   vfork( <unfinished ...>
102   execve("/b/bingsu-collect", ["/b/bingsu-collect", "__collect-v1"], 0x7ffe /* 0 vars */) = 0
101   <... vfork resumed>)              = 102
102   write(1<pipe:[9]>, "\\x01", 1) = 1
102   writev(1<pipe:[9]>, [{iov_base="x", iov_len=1}], 1) = 1
103   write(43<pipe:[10]>, "BNGIPC05", 518 <unfinished ...>
102   +++ exited with 1 +++
101   pwrite64(7</r/store/marker.tmp>, "m", 1, 0) = 1
103   +++ exited with 0 +++
101   +++ exited with 0 +++
"""
COUNT_TRACE = """\
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 60.00    0.000300          30        10           openat
 30.00    0.000150          15        10         2 read
 10.00    0.000050           5        10           write
------ ----------- ----------- --------- --------- ----------------
100.00    0.000500          16        30         2 total
"""


# 이것을 실패시키는 것: 역할을 exec 인자(prompt·__refresh-v1·bingsu-collect)가 아닌 pid 순서로 정하거나,
# 끝나지 않은 호출을 두 번 세거나 놓치는 것, exec 전 자식의 쓰기를 다른 역할에 넣는 것.
def test_process_model_parses_roles_spawns_writes_and_syscall_time():
    spawns, writes = git.parse_process_trace(YY_TRACE)
    assert spawns == {"front": 1, "helper": 1, "collector": 1}
    assert writes == {"front": 1, "helper": 2, "collector": 2}  # helper: its thread 103 and pwrite64
    assert git.parse_syscall_time(COUNT_TRACE) == {"openat": 300, "read": 150, "write": 50}
    with pytest.raises(ValueError):
        git.parse_syscall_time("no summary")


# 이것을 실패시키는 것: strace 실행 결과를 지연 요약(summarize·measure_pair)에 넣거나,
# trace 출력에 지연 필드를 두는 것, Linux가 아닌 host에서 trace를 PASS/skip으로 남기는 것.
def test_trace_runs_never_feed_latency_summaries(monkeypatch, tmp_path):
    traced = {"kind": "process-model-trace", "spawns": {}, "write_calls": {}, "syscall_time_us": {}}
    with pytest.raises(ValueError, match="trace"):
        git.summarize([{**sample(), **traced}], 200)
    monkeypatch.setattr(git.platform, "system", lambda: "Linux")
    monkeypatch.setattr(git, "observe_process_model",
                        lambda binary, case: git.ProcessModelSample(spawns={"front": 1}, write_calls={"front": 1},
                                                                     syscall_time_us={"write": 1}))
    value = git.trace_run("bingsu", ["git-clean"])
    assert value["status"] == "OBSERVED" and value["kind"] == "process-model-trace"
    assert value["evidence_use"] == "process model only; never a latency sample"
    flat = json.dumps(value)
    for latency in ("prompt_ns", "metrics", "variants", "p50", "collection_ns"):
        assert latency not in flat
    monkeypatch.setattr(git.platform, "system", lambda: "Darwin")
    value = git.trace_run("bingsu", ["git-clean"])
    assert value["status"] == "BLOCKED" and value["cases"] == {}
    written = {}
    monkeypatch.setattr(git.M3B.protocol, "write_output", lambda path, payload: written.update(payload))
    import sys
    monkeypatch.setattr(sys, "argv", ["git-product.py", "--x03-trace", "bingsu", "--out", str(tmp_path / "t.json")])
    assert git.main() == 2 and written["status"] == "BLOCKED"


# 이것을 실패시키는 것: 준비 폴더를 front 바이너리 해시만으로 정하는 것. 제품에 닿지 않는 변경은 base와
# candidate의 front가 바이트까지 같아, 같은 폴더를 쓰며 fixture를 덮어쓰고 base 쪽 해시가 낡아진다.
def test_prepared_directory_differs_for_identical_binaries_from_different_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(git, "OUT", tmp_path / "out")
    front = tmp_path / "front"
    front.write_bytes(b"same bytes")
    base, candidate = git.prepared_directory(front, tmp_path / "base"), git.prepared_directory(front, tmp_path / "candidate")
    assert base != candidate and base.parent == candidate.parent
    assert git.prepared_directory(front, tmp_path / "base") == base
