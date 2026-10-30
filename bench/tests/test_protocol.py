"""Each assertion is a negative control for a protocol rule; see mutation ledger."""
import copy
import importlib.util
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocol as p


def calibration():
    return dict(stable=True, p95_of_medians=100, median_of_medians=100, **p.identity())


@pytest.fixture(autouse=True)
def outside_ci(monkeypatch):
    # Rule R2 needs GITHUB_ACTIONS=true (and the explicit request); tests opt in explicitly.
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)


R2 = {**p.DEFAULT, 'admission': 'ci-r2'}


def on_actions(monkeypatch):
    monkeypatch.setenv('CI', 'true')
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')


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


# Reference p50 of calibration blocks 1-4 and of each block (before, after, kept) of the
# hosted pull request run that motivated rule R2 (ubuntu-24.04, same binary on both sides).
HOSTED_RUN = {
    'git-dirty': ([838577.5, 850971.0, 837084.5, 839960.0], [
        (861269.0, 847709.0, False), (849412.5, 848670.5, True), (850930.5, 854542.0, False), (827131.0, 862011.0, False), (851666.5, 839795.5, False)]),
    'git-clean': ([845946.5, 843000.5, 835471.5, 832461.0], [
        (941524.5, 843341.5, False), (842695.0, 858965.5, False), (842194.0, 833482.5, True), (829631.0, 837125.0, True), (822116.5, 846788.0, False), (847940.0, 834600.0, False), (822783.0, 848615.5, False)]),
    'no-git': ([850074.0, 842900.5, 846857.5, 841277.0], [
        (922493.5, 850509.5, False), (846237.0, 853054.5, False), (845735.5, 844403.5, True), (836043.0, 846376.5, True), (830843.0, 852573.5, False), (833869.0, 853841.0, False), (849844.0, 847845.0, True), (846558.0, 856436.0, False), (847699.5, 831564.5, True), (839234.0, 847729.5, True), (838913.0, 837457.5, True), (836696.5, 845227.0, True), (844255.5, 846820.0, True), (835644.5, 857284.5, False), (843954.0, 852165.0, False), (840032.5, 839835.0, True), (838677.5, 853710.5, False), (831965.5, 864660.5, False), (853761.0, 841913.5, False)]),
}


def calibrated(monkeypatch, tmp_path, medians):
    binary = tmp_path / 'base'; binary.write_bytes(b'base')
    rows = iter([p.summary([v] * 20) for v in [1, *medians]])
    monkeypatch.setattr(p, 'reference_block', lambda _: next(rows))
    return p.calibrate(binary)


def hosted(before, after=None, **kwargs):
    row = block(power='mains-assumed', thermal='unavailable', reference=p.summary([before] * 20), **kwargs)
    row['after'].update(power='mains-assumed', thermal='unavailable', reference=p.summary([after or before] * 20))
    return row


# 이것을 실패시키는 것: R2를 끄거나 기준을 보정 최댓값으로 되돌린다(앞선 run의 kept 판정이 그대로 돌아온다).
@pytest.mark.parametrize('case', HOSTED_RUN)
def test_ci_rule_admits_the_hosted_run_retrospectively(monkeypatch, tmp_path, case):
    medians, blocks = HOSTED_RUN[case]
    cal = calibrated(monkeypatch, tmp_path, medians)
    on_actions(monkeypatch)
    # Without the request the recorded verdicts come back, even on the runner: the fixture is the run as judged.
    assert [p.admit(hosted(b, a), p.DEFAULT, cal) for b, a, _ in blocks] == [k for *_, k in blocks]
    kept = [p.admit(hosted(b, a), R2, cal) for b, a, _ in blocks]
    # The two rejected blocks are the 1.12x and 1.09x before-references, each over 5% from its after side.
    assert kept.count(False) == {'git-dirty': 0, 'git-clean': 1, 'no-git': 1}[case]
    assert all(k or b / cal['median_of_medians'] > 1.09 for (b, _, _), k in zip(blocks, kept))


# Reference p50 of calibration blocks 1-4 and of each block (before, after, kept) of the first
# hosted run judged by the earlier R2 (1.03 x median): the runner drifted 2-9% above calibration.
FIRST_R2_RUN = {
    'git-dirty': ([890009.5, 866370.0, 868624.5, 891948.0], [
        (1043128.0, 903875.0, False), (918287.5, 922896.5, False), (898741.0, 903424.5, True), (927308.5, 908448.5, False), (906671.0, 960055.0, False), (930895.5, 933200.0, False)]),
    'no-git': ([894132.0, 888251.0, 883206.0, 891532.0], [
        (975183.0, 886883.0, False), (888611.0, 906665.0, True), (910026.5, 935694.5, False), (907842.0, 924709.0, False), (914294.0, 897509.0, True), (898410.0, 935299.5, False), (923648.0, 919670.0, False), (901776.5, 880492.0, True), (888116.5, 951955.5, False), (922405.5, 887891.0, False), (924519.5, 913814.0, False)]),
    'git-clean': ([886102.0, 880552.5, 877211.0, 888297.0], [
        (970815.5, 909506.5, False), (879540.5, 898635.5, True), (915282.0, 913859.0, False), (885811.5, 930751.0, False), (900739.5, 901606.0, True), (892800.0, 909886.5, False), (908920.5, 904160.5, True), (919610.0, 888732.0, False), (889869.5, 900133.5, True), (893961.5, 906715.5, True), (889293.5, 918572.5, False), (889308.0, 921498.0, False), (913583.5, 904982.5, False)]),
}


# 이것을 실패시키는 것: 5%를 10%로 넓히거나, 상한을 빼거나 1.20배로 넓히거나, 기준을 보정 p95로 바꾼다.
@pytest.mark.parametrize('case', FIRST_R2_RUN)
def test_ci_rule_replays_the_first_r2_run(monkeypatch, tmp_path, case):
    medians, blocks = FIRST_R2_RUN[case]
    cal = calibrated(monkeypatch, tmp_path, medians)
    on_actions(monkeypatch)
    kept = [p.admit(hosted(b, a), R2, cal) for b, a, _ in blocks]
    assert (kept.count(True), len(kept)) == {'git-dirty': (4, 6), 'no-git': (9, 11), 'git-clean': (11, 13)}[case]
    assert all(k == (abs(a / b - 1) <= 0.05 and max(a, b) <= 1.10 * cal['median_of_medians'])
               for (b, a, _), k in zip(blocks, kept))


# 이것을 실패시키는 것: 블록에 판정 기준을 기록하지 않거나, 요청 없이·GITHUB_ACTIONS 없이·AC host에서도 'ci-r2'로 적는다.
def test_block_records_its_admission_basis(monkeypatch, tmp_path):
    cal = calibrated(monkeypatch, tmp_path, [100, 100, 100, 100])
    on_actions(monkeypatch)
    for row in (hosted(102), block()):
        p.admit(row, p.DEFAULT, cal)
        assert row['admission_basis'] == 'default'
    kept, rejected, ac = hosted(110), hosted(111), block()
    assert p.admit(kept, R2, cal) and not p.admit(rejected, R2, cal) and not p.admit(ac, R2, cal)
    assert kept['admission_basis'] == rejected['admission_basis'] == 'ci-r2'
    assert ac['admission_basis'] == 'default' and ac['reason'] == p.CI_R2_OUTSIDE
    mixed = hosted(100)
    mixed['after']['power'] = 'ac'
    p.admit(mixed, R2, cal)
    assert mixed['admission_basis'] == 'mixed'
    experiment = dict(mode='experiment', power='ac', load_range=(1, 3), synthetic_load=0)
    row = block()
    p.admit(row, experiment, cal)
    assert 'admission_basis' not in row


# 이것을 실패시키는 것: 블록 안 안정 5%나 상한 1.10배를 넓히거나 빼거나, 한쪽 방향만 보거나,
# 요청·GITHUB_ACTIONS=true·mains-assumed 중 하나 없이 적용하거나, CI 변수로 켜거나,
# 요청이 거부될 때 조용히 기본 규칙으로 판정하거나, 상한 기준을 보정 p95·최댓값으로 바꾼다.
def test_ci_rule_boundary_and_scope(monkeypatch, tmp_path):
    cal = calibrated(monkeypatch, tmp_path, [100, 100, 100, 100])
    assert p.admit(hosted(100), p.DEFAULT, cal)
    monkeypatch.setenv('CI', 'true')
    assert not p.admit(hosted(102), p.DEFAULT, cal)  # ambient CI alone: today's rule
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    assert not p.admit(hosted(102), p.DEFAULT, cal)  # no request: today's rule
    monkeypatch.delenv('GITHUB_ACTIONS')
    row = hosted(100)
    assert not p.admit(row, R2, cal) and row['reason'] == p.CI_R2_OUTSIDE  # requested off the runner: refused
    monkeypatch.setenv('GITHUB_ACTIONS', '1')
    assert not p.admit(hosted(100), R2, cal)
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.delenv('CI')
    assert p.admit(hosted(102), R2, cal) and p.admit(hosted(110), R2, cal)  # CI is not consulted
    assert not p.admit(hosted(110.01), R2, cal) and not p.admit(hosted(120), R2, cal)  # the cap
    assert not p.admit(hosted(100, 110.01), R2, cal) and not p.admit(hosted(110.01, 105), R2, cal)  # either side
    # In-block stability, both directions: exactly 5% is admitted, just above is not.
    assert p.admit(hosted(100, 105), R2, cal) and p.admit(hosted(105, 100), R2, cal)
    assert p.admit(hosted(100, 95), R2, cal) and not p.admit(hosted(95, 100), R2, cal)  # ratio is after/before
    assert not p.admit(hosted(100, 105.01), R2, cal) and not p.admit(hosted(100, 94.99), R2, cal)
    assert not p.admit(hosted(104, 110), R2, cal)  # both under the cap, 5.8% apart
    row = hosted(100, 106)
    assert not p.admit(row, R2, cal) and row['reason'] == 'power or reference drift'
    ac = block(reference=p.summary([100] * 20))
    assert not p.admit(ac, R2, cal) and ac['reason'] == p.CI_R2_OUTSIDE  # AC host
    assert not p.admit(block(power='battery', reference=p.summary([100] * 20)), R2, cal)
    # The cap follows the median, not the calibration p95 or maximum.
    wide = calibrated(monkeypatch, tmp_path, [100, 100, 100, 104.9])
    assert wide['stable'] and wide['p95_of_medians'] > 104 and not p.admit(hosted(111), R2, wide)


# 이것을 실패시키는 것: R2 아래에서 보정 안정·identity·host 일치·telemetry·summary 20표본 검사 중 하나를 뺀다.
@pytest.mark.parametrize('damage', ['unstable', 'foreign session', 'host changed', 'no load', 'no thermal',
                                    'short summary', 'no median'])
def test_ci_rule_keeps_every_other_check(monkeypatch, tmp_path, damage):
    cal = calibrated(monkeypatch, tmp_path, [100, 100, 100, 100])
    on_actions(monkeypatch)
    # In the R2 band only (above the calibration maximum); without a median even 100 is refused.
    row = hosted(100 if damage == 'no median' else 102)
    assert p.admit(copy.deepcopy(row), R2, cal)
    if damage == 'unstable':
        cal['stable'] = False
    elif damage == 'foreign session':
        cal['session'] = 'other-session'
    elif damage == 'host changed':
        row['after']['host'] = 'other-host'
    elif damage == 'no load':
        del row['before']['load_1m']
    elif damage == 'no thermal':
        row['after']['thermal'] = None
    elif damage == 'short summary':
        row['after']['reference'] = p.summary([102] * 19)
    else:
        del cal['median_of_medians']
    assert not p.admit(row, R2, cal) and row['reason']


# 이것을 실패시키는 것: 로컬 Linux(전원 장치 없음)에서 ambient CI·GITHUB_ACTIONS만으로 R2가 켜진다.
def test_local_linux_shape_keeps_the_default_rule(monkeypatch, tmp_path):
    monkeypatch.setattr(p.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(p.Path, 'iterdir', lambda self: iter([]))
    power = p.observe_host()['power']
    assert power == 'mains-assumed'
    on_actions(monkeypatch)
    assert p.admission_basis(power, p.DEFAULT) == 'default'
    cal = calibrated(monkeypatch, tmp_path, [100, 100, 100, 100])
    row = hosted(102)
    assert not p.admit(row, p.DEFAULT, cal) and row['admission_basis'] == 'default'


def mains(monkeypatch):
    monkeypatch.setattr(p, 'observe_host', lambda: host(power='mains-assumed', thermal='unavailable'))
    monkeypatch.setattr(p, 'snapshot', lambda _: host(power='mains-assumed', thermal='unavailable', reference=p.summary([102] * 20)))


# 이것을 실패시키는 것: 측정 시작에서 요청을 검사하지 않거나(GITHUB_ACTIONS·전원·gate 모드), 결과에 요청·적용 정책을 남기지 않는다.
def test_paired_run_checks_and_records_the_requested_admission(controlled, monkeypatch):
    run = lambda condition: p.paired('base', 'candidate', 200, condition, lambda *_: dict(ns=1), required_metrics=('ns',), seed=1)
    mains(monkeypatch)
    monkeypatch.setenv('CI', 'true')
    got = run(R2)
    assert got['status'] == 'BLOCKED' and got['reason'] == p.CI_R2_OUTSIDE and got['blocks'] == []
    assert got['admission_requested'] == 'ci-r2' and got['admission_applied'] is None
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    got = run(R2)
    assert got['status'] == 'OBSERVED' and got['admission_requested'] == got['admission_applied'] == 'ci-r2'
    got = run(None)  # 102 is over the calibration maximum: the default rule blocks
    assert got['status'] == 'BLOCKED' and got['admission_requested'] == 'default' and got['admission_applied'] is None
    assert {b['admission_basis'] for b in got['blocks']} == {'default'}
    monkeypatch.setattr(p, 'observe_host', lambda: host())
    assert run(R2)['reason'] == p.CI_R2_OUTSIDE  # AC host
    mains(monkeypatch)
    assert run({**R2, 'mode': 'experiment', 'load_range': (1, 3)})['reason'] == p.CI_R2_OUTSIDE
    assert run({**p.DEFAULT, 'admission': 'wide'})['reason'] == 'unknown admission'
    monkeypatch.setattr(p, 'snapshot', lambda _: host(reference=p.summary([100] * 20)))
    got = run(None)
    assert got['status'] == 'OBSERVED' and got['admission_applied'] == 'default'


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
    assert got['p95_of_medians'] == 103 and got['median_of_medians'] == 101.5 and got['stable']
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
