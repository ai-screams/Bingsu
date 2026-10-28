"""M3b measurement acceptance, including deliberately broken observations."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import shutil

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "collector-product.py"
SPEC = importlib.util.spec_from_file_location("collector_product", SOURCE)
product = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(product)


# 이것을 실패시키는 것: init 셸 문장의 끝 세미콜론을 collector 실행 경로에 붙이는 것.
def test_prompt_context_preserves_collector_pin(monkeypatch, tmp_path):
    from subprocess import CompletedProcess
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        output = (b"'--runtime-root=1:2:/r' '--config-root=/c' "
                  b"'--collector-exe=/trusted/semi;colon/bingsu-collect';\n") if command[1] == "init" else (
                      b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e")
        return CompletedProcess(command, 0, output, b"")
    monkeypatch.setattr(product, "run", run)
    command, _ = product.prompt_context("/trusted/bingsu", tmp_path)
    assert "--collector-exe=/trusted/semi;colon/bingsu-collect" in command
    assert calls[-1] == command



def sample():
    result = {"events": dict(zip(product.EVENTS, (1, 2, 4, 5, 6, 7, 8, 9, 3, 10))),
              "request_deadline": 20, "reason": "Complete", "published": True, "reaped": True,
              "front_read_ns": 4, "front_prefetch_ns": 5, "filter_install_ns": 6,
              "m1_stub_exit_ns": 4, "m1_stub_limits_ns": 5, "m1_stub_sandbox_ns": 0, "product_mask0_verify_ns": 6,
              "collector_peak_rss_bytes": 100, "collector_as_bytes": 200, "prompt_ns": 11}
    return result


# 이것을 실패시키는 것: 구간을 합쳐 검증 전체·검증 완료·spawn·Ready·읽기 비용을 숨기는 것.
def test_latency_measures_verification_spawn_ready_and_read_separately():
    got = product.validate_sample(sample())
    assert [got[k] for k in product.INTERVALS] == [3, 2, 1, 2, 1, 1, 7]
    assert got["front_read_ns"] == 4
    assert got["front_prefetch_ns"] == 5


# 이것을 실패시키는 것: 필수 이벤트나 측정 열 하나가 빠져도 PASS로 기록하는 것.
@pytest.mark.parametrize("name", product.EVENTS + product.REQUIRED)
def test_missing_event_or_metric_is_blocked(name):
    broken = deepcopy(sample())
    if name in product.EVENTS:
        broken["events"].pop(name)
    else:
        broken = product.validate_sample(broken)
        # Derived metrics are reconstructed from events, never trusted inputs.
        if name in product.INTERVALS:
            broken["events"].pop(product.INTERVALS[name][0])
        else:
            broken.pop(name)
    with pytest.raises((KeyError, ValueError)):
        product.validate_sample(broken)


# 이것을 실패시키는 것: 다른 순서·마감 뒤 완료·발행/회수 누락을 유효 표본으로 받는 것.
@pytest.mark.parametrize("path,value", [("ready", 3), ("lock_acquired", 5), ("completed", 20),
                                       ("published", False), ("reaped", False), ("reason", "Deadline")])
def test_invalid_lifecycle_is_blocked(path, value):
    broken = sample()
    (broken["events"] if path in product.EVENTS else broken)[path] = value
    with pytest.raises(ValueError):
        product.validate_sample(broken)


# 이것을 실패시키는 것: 200 warm회·교대·cold 분리·분산·M3b 표기를 없애는 것.
def test_pair_alternates_and_preserves_raw_observations(monkeypatch, tmp_path):
    calls = []
    def observe(binary, preparation, directory):
        calls.append(Path(binary).name)
        return product.validate_sample(sample())
    monkeypatch.setattr(product, "prepared", lambda _: {"hashes": {}, "policy": {}, "stripped_bytes": {}})
    monkeypatch.setattr(product, "observe", observe)
    monkeypatch.setattr(product, "watchdog_evidence", lambda _: {"status": "PASS"})
    monkeypatch.setattr(product, "host", lambda: {"kernel": "test", "power": "unobserved", "revision": "test"})
    monkeypatch.setattr(product, "ROOT", tmp_path)
    (tmp_path / "target").mkdir()
    result = product.measure_pair("base", "candidate", 200)
    assert calls[:2] == ['base', 'candidate']
    assert calls[2:] == result['order']
    assert len(result['order']) == 400
    for block in result['blocks']:
        first = block['order'][:2]
        assert first in (['base', 'candidate'], ['candidate', 'base'])
        assert block['order'] == (first + first[::-1]) * 10
    assert result["milestone"] == "M3b" and result["formal_B5_B7"] is False
    assert set(result["cold_first_process"]) == {"base", "candidate"}
    assert not result["missing"]
    for variant in result["variants"].values():
        assert len(variant["samples"]) == 200
        for metric in product.REQUIRED:
            assert variant["metrics"][metric] == product.summary([variant["samples"][0][metric]] * 200)
    assert "M3d formal B5-B7" in result["pending"]
    with pytest.raises(ValueError, match="200"):
        product.measure_pair("base", "candidate", 199)


# 이것을 실패시키는 것: p95·분산을 기록하지 않거나 음수/NaN·빈 표본을 통과시키는 것.
@pytest.mark.parametrize("values", [[], [-1], [float("nan")], [float("inf")]])
def test_bad_distribution_is_rejected(values):
    with pytest.raises(ValueError):
        product.summary(values)


# 이것을 실패시키는 것: p95 순위를 바꾸거나 분산을 0으로 기록하는 것.
def test_percentile_and_variance():
    assert product.summary(list(range(1, 201))) == {"n": 200, "p50": 100.5, "p95": 190,
                                                  "variance": 3333.25, "min": 1, "max": 200}


# 이것을 실패시키는 것: 한 번 찍은 합계를 cwd·읽기 청크·발행/GC 단계 축 대신 쓰는 것.
def test_product_budgets_cover_success_failure_and_gc():
    import sys
    sys.path.insert(0, str(SOURCE.parents[1] / "tools/fsbudget"))
    from fsbudget.formula import collector_product_expected
    fixture = json.loads((SOURCE.parents[1] / "tests/shell/fixtures/collector-product-linux.json").read_text())
    required = {"product-mask0", "fixture", "ready-failure", "partial", "malformed-flood", "current", "previous",
                "snapshot-change", "busy", "long-cwd", "collision", "legacy-gc", "runtime-unsafe", "proc-absent", "nofile-lowered"}
    assert set(fixture["cases"]) == required
    for case, axes in fixture["cases"].items():
        expected = collector_product_expected(case, **axes)
        assert expected["collector-effects"] == {"spawn": 0, "network": 0, "write": 0, "renameat": 0, "unlinkat": 0, "fsync": 0}
    small = collector_product_expected("current", body_bytes=16384)
    big = collector_product_expected("current", body_bytes=16385)
    assert big["front-prefetch"]["read"] == small["front-prefetch"]["read"] + 1
    assert collector_product_expected("long-cwd", cwd_bytes=65536)["front-prefetch"]["openat"] == small["front-prefetch"]["openat"] == 5
    assert collector_product_expected("busy")["helper-publication"] == {}
    assert collector_product_expected("legacy-gc", gc_directories=2, gc_files=1)["helper-gc"] == {"getdents": 4, "unlinkat": 1, "fsync": 0}


def fake_preparation(tmp_path, monkeypatch):
    paths = {key: tmp_path / name for key, name in
             (("front", "bingsu"), ("collector", "bingsu-collect"), ("fixture", "fixture"), ("stub", "m1-collect-stub"))}
    for path in paths.values():
        path.write_bytes(b"original")
    for name in ("Cargo.toml", "Cargo.lock", "bench/collector-product.py",
                 *(f"crates/{crate}/Cargo.toml" for crate in ("bingsu", "bingsu-core", "bingsu-collect", "bingsu-bench", "bingsu-identity")),
                 "crates/bingsu/src/commands/collector_supervisor.rs",
                 "crates/bingsu-identity/src/lib.rs", "crates/bingsu-identity/build.rs"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"original source")
    monkeypatch.setattr(product, "ROOT", tmp_path)
    manifest = {"fixture": str(paths["fixture"]), "stub": str(paths["stub"]),
                "hashes": {key: product.digest(path) for key, path in paths.items()},
                "source_hashes": product.preparation_sources(tmp_path)}
    product.manifest_path(paths["front"]).write_text(json.dumps(manifest))
    return paths, manifest


# 이것을 실패시키는 것: M1 stub을 포함한 실행 파일 교체 뒤 과거 준비를 다시 수용하는 것.
@pytest.mark.parametrize("changed", ["front", "collector", "fixture", "stub"])
def test_prepared_pair_hashes_are_exact(tmp_path, monkeypatch, changed):
    paths, manifest = fake_preparation(tmp_path, monkeypatch)
    assert product.prepared(paths["front"]) == manifest
    saved = paths[changed].read_bytes()
    try:
        paths[changed].write_bytes(b"mutated")
        with pytest.raises(ValueError, match="stale"):
            product.prepared(paths["front"])
    finally:
        paths[changed].write_bytes(saved)
    assert product.prepared(paths["front"]) == manifest


# 이것을 실패시키는 것: prepare 뒤 소스 변경·추가·삭제 또는 해시 목록 누락을 검증하지 않는 것.
@pytest.mark.parametrize("changed", ["modified", "added", "deleted", "missing-hashes", "identity", "identity-build"])
def test_prepared_source_hashes_are_checked_at_use(tmp_path, monkeypatch, changed):
    paths, manifest = fake_preparation(tmp_path, monkeypatch)
    source = tmp_path / "crates/bingsu/src/commands/collector_supervisor.rs"
    if changed.startswith("identity"):
        source = tmp_path / "crates/bingsu-identity" / ("build.rs" if changed == "identity-build" else "src/lib.rs")
    saved = source.read_bytes()
    extra = source.with_name("new.rs")
    try:
        if changed in ("modified", "identity", "identity-build"):
            source.write_bytes(b"changed after prepare")
        elif changed == "added":
            extra.write_bytes(b"new source")
        elif changed == "deleted":
            source.unlink()
        else:
            broken = deepcopy(manifest)
            broken.pop("source_hashes")
            product.manifest_path(paths["front"]).write_text(json.dumps(broken))
        with pytest.raises((ValueError, OSError), match="stale|No such file"):
            product.prepared(paths["front"])
    finally:
        source.write_bytes(saved)
        extra.unlink(missing_ok=True)
        product.manifest_path(paths["front"]).write_text(json.dumps(manifest))
    assert product.prepared(paths["front"]) == manifest


@pytest.fixture(scope="module")
def security_tests():
    spec = importlib.util.spec_from_file_location(
        "collector_security", SOURCE.parents[1] / "tests/shell/test_collector_security.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# 이것을 실패시키는 것: 재빌드 뒤 오래된 준비를 증거로 인정하거나 CI에서 skip하는 것.
@pytest.mark.parametrize("ci", [False, True])
@pytest.mark.parametrize("changed", ["missing", "front", "collector", "fixture", "stub", "source"])
def test_security_preparation_missing_or_stale_is_explicit(security_tests, monkeypatch, tmp_path, ci, changed):
    paths, _ = fake_preparation(tmp_path, monkeypatch)
    monkeypatch.setattr(security_tests.product, "ROOT", tmp_path)
    if changed == "missing":
        product.manifest_path(paths["front"]).unlink()
    elif changed == "source":
        (tmp_path / "crates/bingsu/src/commands/collector_supervisor.rs").write_bytes(b"changed")
    else:
        paths[changed].write_bytes(b"rebuilt")
    monkeypatch.setattr(security_tests, "real_bin", lambda: paths["front"])
    if ci:
        monkeypatch.setenv("CI", "true")
    else:
        monkeypatch.delenv("CI", raising=False)
    outcome = pytest.fail.Exception if ci else pytest.skip.Exception
    with pytest.raises(outcome) as caught:
        security_tests.preparation.__wrapped__()
    message = str(caught.value)
    assert ("manifest missing" if changed == "missing" else "stale prepared source_hashes" if changed == "source" else f"stale or missing prepared {changed}") in message
    assert f"--prepare {paths['front']}" in message
    assert "After the last binary build" in message


# 이것을 실패시키는 것: 제품 helper가 공유 계측 호출을 빼고 시험 fixture만 시간을 기록하는 것.
@pytest.mark.parametrize("call", ["let mut verification = Verification::start();",
                                  "verification.verified();", "verification.attach(collector::spawn("])
def test_product_helper_keeps_the_shared_observation_wiring(call):
    helper = (SOURCE.parents[1] / "crates/bingsu/src/commands/helper.rs").read_text()
    run = helper.split("pub fn run(", 1)[1].split("pub(crate) struct Verification", 1)[0]
    assert re.sub(r"\s+", "", call) in re.sub(r"\s+", "", run)


# 이것을 실패시키는 것: 정상 prompt 전제 실패를 fallback 수치나 passing skip으로 감추는 것.
def test_unavailable_normal_prompt_keeps_evidence_but_blocks_acceptance(monkeypatch, tmp_path):
    def blocked(*_):
        got = product.validate_sample(sample())
        got.pop("prompt_ns")
        got["blocked"] = {"prompt_ns": "clock prerequisite unavailable"}
        return got
    monkeypatch.setattr(product, "prepared", lambda _: {"hashes": {}, "policy": {}, "stripped_bytes": {}})
    monkeypatch.setattr(product, "observe", blocked)
    monkeypatch.setattr(product, "watchdog_evidence", lambda _: {"status": "PASS"})
    monkeypatch.setattr(product, "host", lambda: {})
    monkeypatch.setattr(product, "ROOT", tmp_path)
    (tmp_path / "target").mkdir()
    got = product.measure_pair("base", "candidate", 200)
    assert got["status"] == "BLOCKED" and got["missing"] == ["base.prompt_ns", "candidate.prompt_ns"]
    for name in ("base", "candidate"):
        assert got["variants"][name]["metrics"]["prompt_ns"] == {"n": 0, "status": "BLOCKED", "reason": "clock prerequisite unavailable"}
        assert got["variants"][name]["metrics"]["spawn_to_ready_ns"]["n"] == 200
        assert got["hypotheses"][name]["prompt_p50_within_10ms"] is None


# 이것을 실패시키는 것: fallback·손상 B1·stderr를 정상 제품 prompt 수치로 받아들이는 것.
@pytest.mark.parametrize("damage", ["degraded", "version", "field-count", "stderr", "exit"])
def test_normal_product_measurement_refuses_fallback_and_broken_records(damage):
    from subprocess import CompletedProcess
    record = b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"
    result = CompletedProcess([], 0, record, b"")
    assert product.normal_record(result)
    if damage == "degraded":
        result.stdout = record.replace(b"ok:none", b"degraded:runtime-root")
    elif damage == "version":
        result.stdout = record.replace(b"B1", b"B2", 1)
    elif damage == "field-count":
        result.stdout = record.replace(b"\x1f", b"", 1)
    elif damage == "stderr":
        result.stderr = b"warning"
    else:
        result.returncode = 1
    assert not product.normal_record(result)


# 이것을 실패시키는 것: watchdog 분포의 필수 행·200회·실제 실행 증거를 버리는 것.
@pytest.mark.parametrize("damage", ["row", "count", "passed", "percentile"])
def test_watchdog_distribution_requires_measured_samples(damage):
    labels = ("spawn-to-termination us", "footprint overshoot bytes", "completed sample interval us", "sample-to-kill-request us")
    valid = "\n".join(label + ": count=200 p50=1 p95=2 max=3" for label in labels)
    valid += "\ntest result: ok. 1 passed; 0 failed; 0 ignored;"
    assert all(v["n"] == 200 for v in product.parse_watchdog_evidence(valid).values())
    if damage == "row":
        broken = valid.replace(labels[1], "absent")
    elif damage == "count":
        broken = valid.replace("count=200", "count=199", 1)
    elif damage == "passed":
        broken = valid.replace("1 passed;", "0 passed;")
    else:
        broken = valid.replace("p95=2", "p95=unobserved", 1)
    with pytest.raises(ValueError):
        product.parse_watchdog_evidence(broken)


# 이것을 실패시키는 것: worker 치환 대상이 없거나 중복되어도 준비를 통과시키는 것.
@pytest.mark.parametrize("source,old,new", [("changed", "missing", "x"), ("xx", "x", "y"), ("x", "x", "x")])
def test_worker_substitution_must_change_exactly_once(source, old, new):
    with pytest.raises(AssertionError):
        product.replace_required(source, old, new)
    assert product.replace_required("before", "before", "after") == "after"


# 이것을 실패시키는 것: main.rs의 meter/safe_read 또는 새 모듈·cfg를 fixture에서 누락하는 것.
def test_fixture_modules_follow_collector_main(tmp_path):
    root = tmp_path / "crates/bingsu-collect/src"
    shutil.copytree(SOURCE.parents[1] / "crates/bingsu-collect/src", root)
    main = root / "main.rs"
    # A module unknown to the harness must also be picked up automatically.
    extra = '#[cfg(unix)]\n#[allow(dead_code)]\nmod future_worker_dependency;\n'
    main.write_text(main.read_text() + extra)
    (root / "future_worker_dependency.rs").write_text("")
    worker = tmp_path / "worker.rs"
    worker.write_text("")
    modules = product.collector_modules(tmp_path, worker)
    names = re.findall(r"(?m)^mod (\w+);$", main.read_text())
    assert len(modules) == len(names)
    for name in names:
        declaration, = [m for m in modules if m.endswith(f" mod {name};")]
        path = worker if name == "worker" else root / f"{name}.rs"
        if not path.is_file():
            path = root / name / "mod.rs"
        assert f'#[path={json.dumps(str(path))}] mod {name};' in declaration
    assert '#[cfg(unix)]\n#[allow(dead_code)]\n' in modules[-1]
    assert '#[cfg(target_os = "linux")]\n' in next(m for m in modules if m.endswith(" mod filter;"))


# 이것을 실패시키는 것: CARGO_TARGET_DIR를 무시하고 바이너리 조상에서만 source를 찾거나 다른 사본을 준비하는 것.
@pytest.mark.parametrize("triple", [None, "aarch64-unknown-linux-musl"])
def test_prepare_accepts_external_cargo_target_and_names_expected_path(monkeypatch, tmp_path, triple):
    from subprocess import CompletedProcess
    source = tmp_path / "src"
    source.mkdir()
    target = tmp_path / "target"
    binary = target / triple / "debug/bingsu" if triple else target / "debug/bingsu"
    calls = []
    def metadata(command, **kwargs):
        calls.append((command, kwargs))
        return CompletedProcess(command, 0, json.dumps({"workspace_root": str(source), "target_directory": str(target)}).encode())
    monkeypatch.setattr(product, "ROOT", source)
    monkeypatch.setattr(product, "run", metadata)
    assert product.build_context(binary) == source
    assert calls[0] == (["cargo", "metadata", "--no-deps", "--format-version=1"], {"cwd": source})
    copied = tmp_path / "installed" / binary.relative_to(target)
    with pytest.raises(ValueError, match=str(binary)):
        product.build_context(copied)


@pytest.fixture(autouse=True)
def controlled_protocol(monkeypatch):
    # Product tests exercise real pairing; host probes have dedicated negative controls.
    p = product.protocol
    calibration = dict(stable=True, p95_of_medians=100, **p.identity())
    monkeypatch.setattr(p, 'calibrate', lambda _: calibration)
    monkeypatch.setattr(p, 'snapshot', lambda _: dict(**p.identity(), power='ac',
        thermal='normal', load_1m=1., reference=p.summary([100] * 20)))


def test_blocked_calibration_preserves_protocol_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(product, 'prepared', lambda _: dict(hashes={}, policy={}, stripped_bytes={}))
    monkeypatch.setattr(product, 'host', lambda: {})
    monkeypatch.setattr(product, 'watchdog_evidence', lambda _: {})
    monkeypatch.setattr(product, 'ROOT', tmp_path)
    (tmp_path / 'target').mkdir()
    monkeypatch.setattr(product.protocol, 'calibrate', lambda _: dict(stable=False))
    got = product.measure_pair('base', 'candidate', 200)
    assert got['status'] == 'BLOCKED' and got['calibration'] == dict(stable=False)
    assert got['hypotheses']['base']['ready_p50_within_hypothesis'] is None


def test_legacy_host_keeps_unknown_power_instead_of_raising(monkeypatch):
    monkeypatch.setattr(product.protocol, 'observe_host', lambda: {'power': 'unknown'})
    def unavailable(*args, **kwargs): raise OSError('pmset unavailable')
    monkeypatch.setattr(product, 'run', unavailable)
    assert product.host()['power'] == 'unknown'


def test_cli_forwards_mode_and_condition(monkeypatch, tmp_path):
    import sys
    received = {}
    def measure(base, candidate, rounds, **kwargs):
        received.update(kwargs)
        return {'status': 'OBSERVED'}
    monkeypatch.setattr(product, 'measure_pair', measure)
    monkeypatch.setattr(product.protocol, 'write_output', lambda *_: None)
    monkeypatch.setattr(sys, 'argv', ['collector-product.py', '--base', 'b', '--candidate', 'c',
        '--out', str(tmp_path / 'out.json'), '--mode', 'experiment',
        '--condition', '{"power":"battery","load_range":[1,3],"synthetic_load":0}'])
    assert product.main() == 0
    assert received['condition'] == dict(mode='experiment', power='battery', load_range=[1,3], synthetic_load=0)


@pytest.mark.parametrize('metric', product.REQUIRED)
def test_protocol_blocks_missing_collector_metric(monkeypatch, tmp_path, metric):
    row = sample()
    # validate_sample computes intervals from events; remove after validation.
    row = product.validate_sample(row)
    row.pop(metric)
    monkeypatch.setattr(product, 'observe', lambda *args: row)
    monkeypatch.setattr(product, 'prepared', lambda _: dict(hashes={}, policy={}, stripped_bytes={}))
    monkeypatch.setattr(product, 'host', lambda: {})
    monkeypatch.setattr(product, 'watchdog_evidence', lambda _: {})
    monkeypatch.setattr(product, 'ROOT', tmp_path)
    (tmp_path / 'target').mkdir()
    result = product.measure_pair('base', 'candidate', 200)
    assert result['status'] == 'BLOCKED'
    assert metric in result['reason']
