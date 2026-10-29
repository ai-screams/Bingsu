"""Each assertion is a negative control for a protocol rule; see mutation ledger."""
import copy
import importlib.util
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocol as p


def calibration():
    return dict(stable=True, p95_of_medians=100, **p.identity())


def host(**kwargs):
    return {**p.identity(), 'power': 'ac', 'load_1m': 2., 'thermal': 'normal',
            'reference': p.summary([100] * 20), **kwargs}


def block(**kwargs):
    return dict(index=0, before=host(**kwargs), after=host())


@pytest.fixture
def controlled(monkeypatch):
    monkeypatch.setattr(p, 'calibrate', lambda _: calibration())
    monkeypatch.setattr(p, 'snapshot', lambda _: host())


# 이것을 실패시키는 것: 부하 중 기준 작업 drift, 배터리, 열 경고, 누락을 인정한다.
@pytest.mark.parametrize('damage', [dict(power='battery'), dict(power='unknown'),
    dict(thermal='warning'), dict(thermal=None), dict(load_1m=None),
    dict(reference={}), dict(reference=p.summary([101] * 20))])
def test_protocol_blocks_on_condition_drift_or_short_rounds(damage):
    row = block(**damage)
    assert not p.admit(row, p.DEFAULT, calibration())
    assert row['reason'] and row['kept'] is False


def test_short_rounds(controlled):
    got = p.paired('base', 'candidate', 199, None, lambda *_: {}, required_metrics=('ns',))
    assert got['status'] == 'BLOCKED' and '200' in got['reason']


@pytest.mark.parametrize('side', ['before', 'after'])
@pytest.mark.parametrize('field', ['power', 'load_1m', 'thermal', 'reference', 'host', 'kernel', 'arch'])
def test_missing_telemetry_is_blocked(side, field):
    row = block()
    del row[side][field]
    assert not p.admit(row, p.DEFAULT, calibration())


def test_thermal_warning_invalidates_block():
    assert not p.admit(block(thermal='warning'), p.DEFAULT, calibration())


@pytest.mark.parametrize('damage', [dict(stable=False), dict(host='other-host'), dict(session='other-session')])
def test_unstable_calibration_blocks_the_session(damage):
    assert not p.admit(block(), p.DEFAULT, {**calibration(), **damage})


def test_mains_host_is_admitted_by_reference_only():
    row = block(power='mains-assumed', thermal='unavailable', load_1m=10000.)
    assert p.admit(row, p.DEFAULT, calibration())
    row['after']['reference'] = p.summary([101] * 20)
    assert not p.admit(row, p.DEFAULT, calibration())


@pytest.mark.parametrize('damage', [dict(power='battery'), dict(thermal='unavailable'), dict(load_1m=4.)])
def test_experiment_cell_rejects_mismatched_condition(damage):
    condition = dict(mode='experiment', power='ac', load_range=(1, 3), synthetic_load=0)
    assert p.admit(block(), condition, calibration())
    assert not p.admit(block(**damage), condition, calibration())


# 이것을 실패시키는 것: 첫 보정 블록을 유지하거나 불안정한 분포를 인정한다.
def test_calibration_drops_first_block(monkeypatch, tmp_path):
    binary = tmp_path / 'base'; binary.write_bytes(b'base')
    rows = iter([p.summary([v]*20) for v in [1000, 100, 101, 102, 103]])
    monkeypatch.setattr(p, 'reference_block', lambda _: next(rows))
    got = p.calibrate(binary)
    assert len(got['blocks']) == 5 and got['discarded'] == [0]
    assert got['p95_of_medians'] == 103 and got['stable']
    rows = iter([p.summary([v]*20) for v in [1000, 100, 100, 100, 200]])
    assert not p.calibrate(binary)['stable']


# 이것을 실패시키는 것: 위반 블록을 유지하거나 warm-up을 표본에 넣거나 순서를 고정한다.
def test_violating_block_is_discarded_and_rerun(controlled, monkeypatch):
    snapshots = iter([host(reference=p.summary([200]*20)), host()] + [host()] * 22)
    monkeypatch.setattr(p, 'snapshot', lambda _: next(snapshots))
    calls = []
    def observe(name, binary):
        calls.append(name)
        return dict(ns=len(calls))
    got = p.paired('base', 'candidate', 200, None, observe, required_metrics=("ns",), seed=42)
    assert got['status'] == 'OBSERVED'
    assert len(got['blocks']) == 11 and not got['blocks'][0]['kept']
    assert got['blocks'][1]['attempt'] == 1
    assert [b['index'] for b in got['blocks'][1:]] != list(range(10))
    assert len(got['order']) == 400
    assert all(b['order'].count('base') == b['order'].count('candidate') for b in got['blocks'])
    for name in ('base', 'candidate'):
        assert len(got['variants'][name]['samples']) == 200
        assert min(s['ns'] for s in got['variants'][name]['samples']) > 42


def test_retries_are_bounded(controlled, monkeypatch):
    monkeypatch.setattr(p, 'snapshot', lambda _: host(power='battery'))
    got = p.paired('b', 'c', 200, None, lambda *_: {'ns': 1}, required_metrics=('ns',))
    assert got['status'] == 'BLOCKED' and len(got['blocks']) == 3
    assert not got['variants']['base']['samples']


@pytest.mark.parametrize('marker', ['directory', 'file', 'symlink'])
def test_raw_json_refuses_repository_and_worktree_paths(tmp_path, marker):
    repo = tmp_path / 'repo'; repo.mkdir()
    if marker == 'directory': (repo / '.git').mkdir()
    else: (repo / '.git').write_text('gitdir: elsewhere')
    dest = repo / 'target'
    if marker == 'symlink':
        dest = tmp_path / 'link'; dest.symlink_to(repo, target_is_directory=True)
    with pytest.raises(ValueError, match='repository/worktree'):
        p.persist_raw(dest, {})
    path = p.persist_raw(tmp_path / 'external', {'status': 'BLOCKED'})
    assert path.is_file()


def test_bench_workflow_writes_outside_checkout():
    text = (Path(__file__).resolve().parents[2] / '.github/workflows/bench.yml').read_text()
    assert 'candidate/target/f3/' not in text
    assert '${{ runner.temp }}/measurements/m3c-product.json' in text
    assert '--out ${{ runner.temp }}/measurements/' in text


@pytest.mark.parametrize('field', ['n', 'p50', 'p95', 'variance', 'min', 'max'])
def test_reference_summary_cannot_be_partial(field):
    row = block()
    del row['after']['reference'][field]
    assert not p.admit(row, p.DEFAULT, calibration())


def test_output_file_symlink_is_rejected(tmp_path):
    repo = tmp_path / 'repo'; repo.mkdir(); (repo / '.git').mkdir()
    link = tmp_path / 'out.json'; link.symlink_to(repo / 'raw.json')
    with pytest.raises(ValueError):
        p.write_output(link, {})
    assert not (repo / 'raw.json').exists()


def test_seed_replays_random_order_and_warmup_is_discarded(controlled):
    def run(seed):
        calls = []
        def observe(n, b):
            calls.append(n)
            return {'ns': len(calls)}
        result = p.paired('b', 'c', 200, None, observe, required_metrics=("ns",), seed=seed)
        assert min(s['ns'] for v in result['variants'].values() for s in v['samples']) == 3
        assert result['status'] == 'OBSERVED' and result['seed'] == seed
        assert calls[2:] == result['order']
        starts = [b['order'][0] for b in result['blocks']]
        assert starts.count('base') == starts.count('candidate')
        for b in result['blocks']:
            pairs = [b['order'][i:i+2] for i in range(0, len(b['order']), 2)]
            assert all(pair == pairs[0][::(-1 if i % 2 else 1)] for i, pair in enumerate(pairs))
        return calls
    assert run(42) == run(42)
    assert run(42) != run(43)


def test_transition_requires_three_stable_normal_blocks(controlled, monkeypatch):
    rows = iter([host(thermal='warning')] + [host()] * 3)
    monkeypatch.setattr(p, 'snapshot', lambda _: next(rows))
    assert len(p.settle(Path('b'))) == 4
    monkeypatch.setattr(p, 'snapshot', lambda _: host(thermal='unavailable'))
    with pytest.raises(ValueError, match='transition'):
        p.settle(Path('b'))


def test_experiment_load_is_bounded_background_and_cleaned_up(monkeypatch):
    commands, workers = [], []
    monkeypatch.setattr(p, 'ensure_idle', lambda: None)
    class Worker:
        def __init__(self, command, **kwargs):
            commands.append(command); workers.append(self); self.stopped = False
        def poll(self): return None
        def terminate(self): self.stopped = True
        def wait(self, timeout): assert timeout == 10
    monkeypatch.setattr(p.os, 'cpu_count', lambda: 4)
    monkeypatch.setattr(p.platform, 'system', lambda: 'Darwin')
    monkeypatch.setattr(p.subprocess, 'Popen', Worker)
    with p.experiment_load(dict(mode='experiment', synthetic_load=2)):
        assert len(commands) == 2
        assert all(c[:5] == ['taskpolicy', '-b', 'nice', '-n', '19'] for c in commands)
        assert all('+60' in c[-1] for c in commands)
    assert all(w.stopped for w in workers)
    with pytest.raises(ValueError):
        with p.experiment_load(dict(mode='gate', synthetic_load=2)): pass


def test_snapshot_rejects_build_overlap(monkeypatch):
    monkeypatch.setattr(p, 'command_text', lambda _: '/bin/cargo\n')
    with pytest.raises(ValueError, match='concurrent'):
        p.snapshot(Path('b'))


def test_reference_dispatch_is_checked(monkeypatch):
    from subprocess import CompletedProcess
    monkeypatch.setattr(p.subprocess, 'run', lambda *a, **kw: CompletedProcess(a, 0, b'', b'usage'))
    with pytest.raises(ValueError, match='dispatch'):
        p.reference_block(Path('b'))


def test_transition_does_not_accept_one_normal_block(controlled):
    assert len(p.settle(Path('b'))) == 3


def test_transition_drift_is_blocked(controlled, monkeypatch):
    rows = iter([host(reference=p.summary([100 if i % 2 else 200]*20)) for i in range(15)])
    monkeypatch.setattr(p, 'snapshot', lambda _: next(rows))
    with pytest.raises(ValueError, match='transition'):
        p.settle(Path('b'))


def test_n7_adapter_blocks_setup_failures(monkeypatch):
    import n7_measure as n7
    def unavailable(*args, **kwargs): raise ValueError('unavailable snapshot')
    monkeypatch.setattr(n7, '_n7_pairs', unavailable)
    got = p.n7_pairs(Path('b'), Path('c'), 200, p.DEFAULT)
    assert got['status'] == 'BLOCKED' and 'snapshot' in got['reason']


@pytest.mark.parametrize('system,outputs,power,thermal', [
    ('Darwin', ["Now drawing from 'AC Power'", 'No thermal warning level has been recorded\nNo performance warning level has been recorded'], 'ac', 'normal'),
    ('Darwin', ["Now drawing from 'Battery Power'", 'CPU_Speed_Limit = 80'], 'battery', 'warning'),
])
def test_host_probe_records_power_and_heat(monkeypatch, system, outputs, power, thermal):
    monkeypatch.setattr(p.platform, 'system', lambda: system)
    output = iter(outputs)
    monkeypatch.setattr(p, 'command_text', lambda _: next(output))
    got = p.observe_host()
    assert got['power'] == power and got['thermal'] == thermal


def test_host_probe_failure_is_not_mains_assumed(monkeypatch):
    monkeypatch.setattr(p.platform, 'system', lambda: 'Darwin')
    def unavailable(_): raise OSError('missing telemetry')
    monkeypatch.setattr(p, 'command_text', unavailable)
    got = p.observe_host()
    assert got['power'] == 'unknown' and got['thermal'] is None


@pytest.mark.parametrize('command', ['123 python python -m pytest bench/tests',
    '123 python python bench/git-product.py', '123 xctrace xctrace record'])
def test_python_test_or_measurement_overlap_is_rejected(monkeypatch, command):
    monkeypatch.setattr(p, 'command_text', lambda _: command)
    with pytest.raises(ValueError, match='concurrent'):
        p.ensure_idle()


def test_load_preflight_refuses_concurrent_activity(monkeypatch):
    monkeypatch.setattr(p.os, 'cpu_count', lambda: 4)
    def busy(): raise ValueError('concurrent trace')
    monkeypatch.setattr(p, 'ensure_idle', busy)
    def unexpected(*a, **kw): pytest.fail('must check activity before spawning')
    monkeypatch.setattr(p.subprocess, 'Popen', unexpected)
    with pytest.raises(ValueError, match='concurrent'):
        with p.experiment_load(dict(mode='experiment', synthetic_load=2)): pass


def test_launcher_shell_is_not_a_second_measurement(monkeypatch):
    monkeypatch.setattr(p, 'command_text', lambda _: '123 zsh zsh -lc python3 bench/git-product.py --base b')
    p.ensure_idle()


def test_ci_preparation_outputs_are_external():
    text = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
    # A command continued with a trailing backslash is one caller.
    callers = [line.strip() for line in text.replace('\\\n', ' ').splitlines() if 'bench/git-product.py' in line]
    assert len(callers) == 5
    assert all('--out "$RUNNER_TEMP/measurements/' in line for line in callers)
    assert '${{ runner.temp }}/measurements/' in text
    assert 'target/f3/' not in text


@pytest.mark.parametrize('missing', ['all', 'one-row', 'one-variant'])
def test_adapter_metric_fields_are_required(controlled, missing):
    calls = 0
    def observe(name, binary):
        nonlocal calls
        calls += 1
        if missing == 'all' or (missing == 'one-row' and calls == 10) or (missing == 'one-variant' and name == 'candidate'):
            return {}
        return {'ns': 1, 'bytes': 2}
    got = p.paired('b', 'c', 200, None, observe, required_metrics=('ns', 'bytes'))
    assert got['status'] == 'BLOCKED'
    assert 'missing required metric' in got['reason']


def test_empty_adapter_schema_is_blocked(controlled):
    got = p.paired('b', 'c', 200, None, lambda *_: {})
    assert got['status'] == 'BLOCKED' and 'schema' in got['reason']


@pytest.mark.parametrize('native', [False, True])
def test_n7_legacy_rows_are_diagnostic_only(monkeypatch, tmp_path, capsys, native):
    import json
    import n7_measure as n7
    from subprocess import CompletedProcess
    monkeypatch.setattr(sys, 'argv', ['n7_measure.py', '--out', str(tmp_path)])
    def checked(command, **kwargs):
        if command[0] == 'rustc':
            return CompletedProcess(command, 0, b'rustc test')
        return CompletedProcess(command, 0, json.dumps(dict(reason='compiler-artifact', executable=__file__, profile=dict(test=True))).encode())
    monkeypatch.setattr(n7, 'checked', checked)
    front = 'fixture\tprefilter_ns\tstaged_file_read_decode_ns\trespond_render_ns\tread_ns\tchecksum_decode_ns\tcompiled_bytes\n'
    front += ''.join(f'{fixture}\t1\t2\t3\t4\t5\t6\n' for fixture in ('normal', '4096-band') for _ in range(240))
    publish = ''.join(f'N7_PUBLISH\t{fixture}\t0\t1\t2\n' for fixture in ('normal', '4096-band') for _ in range(240))
    results = iter([CompletedProcess([], 0, front.encode(), b'native_clock_available=true' if native else b''), CompletedProcess([], 0, publish.encode(), b'')])
    monkeypatch.setattr(n7, 'resource_run', lambda _: next(results))
    monkeypatch.setattr(n7, 'measure_prompt', lambda *args: None)
    n7.main()
    rows = json.loads((tmp_path / 'summary.json').read_text())
    legacy = {k: v for k, v in rows.items() if k.startswith(('normal/', '4096-band/'))}
    assert len(legacy) == 16
    for row in legacy.values():
        assert row.get('status') == 'BLOCKED'
        assert row['evidence_use'] == 'diagnostic-only'
        assert row['certification_eligible'] is False
    assert json.loads((tmp_path / 'method.json').read_text())['legacy_front_publish']['status'] == 'BLOCKED'
