"""Controlled, same-session measurement admission. No product budget is changed."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import sys
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import statistics
import subprocess
import tempfile
import time
from typing import Literal, TypedDict
import uuid


class Summary(TypedDict):
    n: int
    p50: float
    p95: float
    variance: float
    min: float
    max: float


class HostCondition(TypedDict):
    power: Literal['ac', 'battery', 'mains-assumed', 'unknown']
    load_1m: float
    thermal: str | None
    reference: Summary
    host: str
    kernel: str
    arch: str


class Condition(TypedDict):
    mode: Literal['gate', 'experiment']
    power: str
    load_range: tuple[float, float] | None
    synthetic_load: int
    admission: Literal['default', 'ci-r2']


Calibration = dict
Block = dict
Paired = dict
Blocked = dict
SESSION = uuid.uuid4().hex
DEFAULT = Condition(mode='gate', power='ac', load_range=None, synthetic_load=0, admission='default')
CI_R2_OUTSIDE = 'ci-r2 requested outside GitHub Actions'


def summary(values):
    if not values or any(not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('missing/non-finite/negative observations')
    ordered = sorted(values)
    return Summary(n=len(values), p50=statistics.median(values),
                   p95=ordered[math.ceil(.95 * len(values)) - 1],
                   variance=statistics.pvariance(values), min=ordered[0], max=ordered[-1])


def command_text(command):
    return subprocess.run(command, capture_output=True, text=True, check=True, timeout=10).stdout


def observe_host() -> HostCondition:
    power, thermal = 'unknown', None
    try:
        if platform.system() == 'Darwin':
            text = command_text(['pmset', '-g', 'batt'])
            power = 'ac' if "AC Power" in text else 'battery' if 'Battery Power' in text else 'unknown'
            text = command_text(['pmset', '-g', 'therm'])
            thermal = 'normal' if ('No thermal warning' in text and 'No performance warning' in text) else 'warning'
        elif platform.system() == 'Linux':
            root = Path('/sys/class/power_supply')
            devices = list(root.iterdir())
            if not devices:
                power = 'mains-assumed'
            else:
                online = [int(p.read_text().strip()) for p in root.glob('*/online')]
                power = ('ac' if any(online) else 'battery') if online else 'unknown'
            # No portable warning threshold: record absence explicitly, never infer normal.
            thermal = 'unavailable'
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return HostCondition(power=power, load_1m=os.getloadavg()[0], thermal=thermal,
                         reference={}, host=platform.node(), kernel=platform.release(), arch=platform.machine())


def identity():
    return dict(host=platform.node(), kernel=platform.release(), arch=platform.machine(), session=SESSION)


def reference_block(reference: Path):
    values = []
    for _ in range(20):
        start = time.perf_counter_ns()
        result = subprocess.run([str(reference), '__m3d-no-such-command'], capture_output=True, timeout=10)
        elapsed = time.perf_counter_ns() - start
        if result.returncode != 2 or not result.stderr or result.stdout:
            raise ValueError('reference must exit through rejected dispatch usage (2)')
        values.append(elapsed)
    return summary(values)


def calibrate(reference: Path, blocks: int = 5) -> Calibration:
    if blocks != 5:
        raise ValueError('calibration requires 5 blocks')
    rows = [reference_block(reference) for _ in range(blocks)]
    medians = [r['p50'] for r in rows[1:]]  # D0: first block is discarded.
    return dict(reference_binary=str(reference), reference_sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
                blocks=rows, discarded=[0], p95_of_medians=summary(medians)['p95'],
                median_of_medians=statistics.median(medians),
                stable=min(medians) > 0 and max(medians) / min(medians) <= 1.05, **identity())


def complete_summary(row, n):
    return (row.get('n') == n and all(type(row.get(k)) in (int, float) and
            math.isfinite(row[k]) and row[k] >= 0 for k in ('p50', 'p95', 'variance', 'min', 'max')))


CI_REFERENCE_FACTOR = 1.03


def ci_r2_host(power):
    """A GitHub Actions runner without a power device: the only host U3 rule R2 may judge."""
    return power == 'mains-assumed' and os.environ.get('GITHUB_ACTIONS') == 'true'


def admission_basis(power, condition):
    """'ci-r2' when a gate block is judged by U3 rule R2, else 'default'.

    R2 needs both the explicit request (condition admission 'ci-r2') and a
    hosted runner; an ambient environment alone never selects it.
    """
    return 'ci-r2' if condition.get('admission') == 'ci-r2' and ci_r2_host(power) else 'default'


def reference_limit(power, calibration, condition):
    """The largest admitted before/after reference p50 of a gate block, or None.

    Rule R2 compares with 1.03 times the median of the four calibration medians;
    the default rule keeps the largest calibration median. Only this baseline
    differs: the caller keeps every other admission check.
    """
    if admission_basis(power, condition) == 'ci-r2':
        median = calibration.get('median_of_medians')
        if type(median) not in (int, float) or not math.isfinite(median) or median <= 0:
            return None
        return median * CI_REFERENCE_FACTOR
    return calibration['p95_of_medians']


def admit(block: Block, condition: Condition, calibration: Calibration) -> bool:
    reason = None
    if not calibration.get('stable') or any(calibration.get(k) != v for k, v in identity().items()):
        reason = 'unstable or foreign calibration'
    for side in ('before', 'after'):
        h = block.get(side, {})
        ref = h.get('reference', {})
        if any(h.get(k) != calibration.get(k) for k in ('host', 'kernel', 'arch')):
            reason = 'host changed'
        if (h.get('power') not in ('ac', 'battery', 'mains-assumed') or
                h.get('thermal') not in ('normal', 'unavailable') or
                not isinstance(h.get('load_1m'), (float, int)) or not math.isfinite(h['load_1m']) or
                not complete_summary(ref, 20) or not isinstance(ref.get('p50'), (int, float)) or
                not math.isfinite(ref['p50']) or ref['p50'] <= 0):
            reason = 'missing telemetry or thermal warning'
        elif condition['mode'] == 'gate':
            limit = reference_limit(h['power'], calibration, condition)
            if condition.get('admission') == 'ci-r2' and not ci_r2_host(h['power']):
                reason = CI_R2_OUTSIDE  # requested R2 is never silently the default rule
            elif h['power'] not in ('ac', 'mains-assumed') or limit is None or ref['p50'] > limit:
                reason = 'power or reference drift'
        elif condition['mode'] == 'experiment':
            bounds = condition.get('load_range')
            if (h['power'] != condition['power'] or h['power'] == 'mains-assumed' or
                    h['thermal'] != 'normal' or bounds is None or not bounds[0] <= h['load_1m'] <= bounds[1]):
                reason = 'experiment condition mismatch or unavailable'
        else:
            reason = 'unknown mode'
    block.update(kept=reason is None, reason=reason)
    if condition.get('mode') == 'gate':
        # Which drift baseline judged the block; a host whose power changed mid-block is 'mixed'.
        bases = {admission_basis(block.get(side, {}).get('power'), condition) for side in ('before', 'after')}
        block['admission_basis'] = bases.pop() if len(bases) == 1 else 'mixed'
    return block['kept']


def ensure_idle():
    processes = command_text(['ps', '-axo', 'pid=,comm=,args=']).splitlines()
    busy = []
    for line in processes:
        parts = line.split(None, 2)
        if not parts:
            continue
        if parts[0].isdigit():
            if int(parts[0]) == os.getpid() or len(parts) < 2:
                continue
            program = Path(parts[1]).name
            args = parts[2] if len(parts) > 2 else ''
        else:
            program, args = Path(parts[0]).name, ''
        is_python = program.startswith(('python', 'pypy'))
        if (program in ('cargo', 'rustc', 'pytest', 'xctrace') or
                (is_python and re.search(r'-m pytest|(?:git-product|collector-product|n7_measure)\.py', args))):
            busy.append(line)
    if busy:
        raise ValueError('concurrent build/test/trace activity')


def snapshot(reference):
    ensure_idle()
    host = observe_host()
    host['reference'] = reference_block(reference)
    return host


def _paired(base, candidate, rounds, condition, observe, *, required_metrics=(), seed=None):
    condition = dict(DEFAULT if condition is None else condition)
    seed = random.SystemRandom().randrange(2**63) if seed is None else seed
    result = dict(command=sys.argv, libc=platform.libc_ver(), binaries={n: dict(path=str(b), sha256=hashlib.sha256(Path(b).read_bytes()).hexdigest() if Path(b).is_file() else None, revision=os.environ.get('BINGSU_' + n.upper() + '_REVISION', 'unrecorded')) for n, b in (('base', base), ('candidate', candidate))}, schema=1, condition=condition, calibration={}, seed=seed, order=[], blocks=[],
                  variants={n: dict(samples=[], summary={}) for n in ('base', 'candidate')}, status='BLOCKED')
    if not required_metrics:
        result['reason'] = 'adapter metric schema required'
        return result
    if rounds < 200:
        result['reason'] = 'at least 200 samples required'
        return result
    if condition.get('mode') not in ('gate', 'experiment'):
        result['reason'] = 'unsupported condition; synthetic load requires an external bounded experiment driver'
        return result
    if condition.get('admission', 'default') not in ('default', 'ci-r2'):
        result['reason'] = 'unknown admission'
        return result
    if condition.get('admission') == 'ci-r2' and (condition['mode'] != 'gate' or not ci_r2_host(observe_host()['power'])):
        result['reason'] = CI_R2_OUTSIDE
        return result
    try:
        reference = Path(base).resolve()
        calibration = calibrate(reference)
        result['calibration'] = calibration
        if not calibration['stable']:
            result['reason'] = 'unstable calibration'
            return result
        if condition['mode'] == 'experiment':
            result['transition'] = settle(reference)
        binaries = dict(base=base, candidate=candidate)
        result['cold_first_process'] = {n: observe(n, b) for n, b in binaries.items()}
        indices = list(range(math.ceil(rounds / 20)))
        rng = random.Random(seed)
        rng.shuffle(indices)
        # Balance block starts, then shuffle actual execution rather than only labels.
        starts = [i % 2 for i in range(len(indices))]
        rng.shuffle(starts)
        for index, start in zip(indices, starts):
            count = min(20, rounds - index * 20)
            for attempt in range(3):
                block = dict(index=index, attempt=attempt, before=snapshot(reference), samples={n: [] for n in binaries}, order=[])
                for i in range(count):
                    for n in (('base', 'candidate') if (start + i) % 2 == 0 else ('candidate', 'base')):
                        block['order'].append(n)
                        block['samples'][n].append(observe(n, binaries[n]))
                block['after'] = snapshot(reference)
                result['blocks'].append(block)
                if admit(block, condition, calibration):
                    result['order'].extend(block['order'])
                    for n in binaries:
                        result['variants'][n]['samples'].extend(block['samples'][n])
                    break
            else:
                result['reason'] = 'retry limit; invalid blocks retained as raw evidence'
                return result
        for variant in result['variants'].values():
            rows = variant['samples']
            if len(rows) != rounds:
                raise ValueError('incomplete sample count')
            for metric in required_metrics:
                if any(metric not in row for row in rows):
                    raise ValueError('missing required metric: ' + metric)
            variant['summary'] = {k: summary([row[k] for row in rows]) for k in required_metrics}
            if not all(complete_summary(row, rounds) for row in variant['summary'].values()):
                raise ValueError('incomplete metric summary')
        result['status'] = 'OBSERVED'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['reason'] = str(error)
    return result


def validate_output(out_dir: Path):
    path = out_dir.resolve()
    # Ancestors cover ordinary repositories and .git files used by linked worktrees.
    if any((p / '.git').exists() for p in (path, *path.parents)):
        raise ValueError('raw output must be outside repository/worktree')
    return path


def persist_raw(out_dir: Path, payload: dict) -> Path:
    directory = validate_output(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ('measurement-' + uuid.uuid4().hex + '.json')
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + '\n')
    return path


def write_output(path, payload):
    validate_output(path)
    validate_output(path.parent)
    persist_raw(path.parent, payload)
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + '\n')


def settle(reference):
    """Bounded transition polling: normal heat and 3 reference medians within 5%."""
    rows = []
    for _ in range(15):
        h = snapshot(reference)
        rows.append(h)
        recent = rows[-3:]
        if len(recent) == 3 and all(r['thermal'] == 'normal' for r in recent):
            medians = [r['reference']['p50'] for r in recent]
            if min(medians) > 0 and max(medians) / min(medians) <= 1.05:
                return rows
    raise ValueError('experiment transition not thermally/reference stable')


@contextmanager
def experiment_load(condition):
    count = condition.get('synthetic_load', 0)
    if type(count) is not int or count < 0:
        raise ValueError('invalid synthetic_load')
    if count and (condition.get('mode') != 'experiment' or count != (os.cpu_count() or 1) // 2):
        raise ValueError('synthetic load requires half the logical cores in experiment mode')
    if count:
        ensure_idle()
    workers = []
    try:
        for _ in range(count):
            command = ['nice', '-n', '19', sys.executable, '-c',
                       'import time; end=time.monotonic()+60\nwhile time.monotonic()<end: pass']
            if platform.system() == 'Darwin':
                command = ['taskpolicy', '-b', *command]
            workers.append(subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        yield workers
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.terminate()
            worker.wait(timeout=10)


def paired(base, candidate, rounds, condition, observe, *, required_metrics=(), seed=None):
    condition = dict(DEFAULT if condition is None else condition)
    try:
        # Advisory host session lock: a second harness cannot overlap this one.
        with open(Path(tempfile.gettempdir()) / 'bingsu-measurement.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with experiment_load(condition) as workers:
                def checked_observe(name, binary):
                    if any(worker.poll() is not None for worker in workers):
                        raise ValueError('bounded synthetic load expired')
                    return observe(name, binary)
                result = _paired(base, candidate, rounds, condition, checked_observe, required_metrics=required_metrics, seed=seed)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result = dict(schema=1, status='BLOCKED', reason=str(error), condition=condition,
                      calibration={}, seed=seed, order=[], blocks=[],
                      variants={n: dict(samples=[], summary={}) for n in ('base', 'candidate')})
    # Requested policy next to the one that admitted the kept blocks (None: no block kept).
    applied = {b.get('admission_basis') for b in result['blocks'] if b.get('kept')}
    result.update(admission_requested=condition.get('admission', 'default'),
                  admission_applied=applied.pop() if len(applied) == 1 else 'mixed' if applied else None)
    return result


def n7_pairs(base: Path, candidate: Path, rounds: int, condition: Condition) -> Paired:
    from n7_measure import n7_pairs as adapter
    return adapter(base, candidate, rounds, condition)
