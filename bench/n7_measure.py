#!/usr/bin/env python3
"""N7 measurements; run after release builds, with no concurrent mutations.

Raw TSV, nearest-rank p95, machine/build identity, and explicit unavailable rows.
Only --cold-command opts into an external cache eviction command (it needs
privileges a normal test run does not have). It changes no budget, syscall
policy or product setting.
"""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import importlib.util
import shutil
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol

ROOT = Path(__file__).resolve().parents[1]
SAMPLES, WARMUP = 240, 20


def summary(values):
    ordered = sorted(values)
    result = dict(n=len(values), median_ms=statistics.median(ordered) / 1e6,
                  p95_ms=ordered[math.ceil(0.95 * len(ordered)) - 1] / 1e6)
    if len(values) < 200:
        result["not_done"] = "fewer than 200 samples; not a completed budget measurement"
    return result


def checked(command, **kwargs):
    return subprocess.run(command, capture_output=True, check=True, **{'cwd': ROOT, **kwargs})


def resource_run(command):
    # A fresh Python parent has no earlier child max-RSS to contaminate this run.
    script = '''import json, resource, subprocess, sys
r = subprocess.run(sys.argv[1:], capture_output=True)
u = resource.getrusage(resource.RUSAGE_CHILDREN)
sys.stdout.buffer.write(r.stdout)
sys.stderr.buffer.write(r.stderr)
print("N7_RESOURCE " + json.dumps(dict(cpu_user_s=u.ru_utime, cpu_system_s=u.ru_stime,
    maxrss_native_units=u.ru_maxrss)), file=sys.stderr)
sys.exit(r.returncode)
'''
    return checked([sys.executable, "-c", script, *command])


def diagnostic_only(value):
    """Legacy batched runners have no admission evidence and cannot certify budgets."""
    return dict(status='BLOCKED', evidence_use='diagnostic-only', certification_eligible=False,
                reason='legacy batched runner has no calibration or condition admission',
                diagnostic_summary=value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path(tempfile.gettempdir()) / "bingsu-n7-measurements")
    parser.add_argument("--baseline", type=Path, help="already built V3 binary; never checks out revisions")
    parser.add_argument("--cold-command", nargs="+", help="page-cache eviction command to run before each cold sample")
    parser.add_argument("--mode", choices=("gate", "experiment"), default="gate")
    parser.add_argument("--condition", type=json.loads)
    args = parser.parse_args()
    out = protocol.validate_output(args.out)
    out.mkdir(parents=True, exist_ok=True)
    binary = ROOT / "target/release/bingsu"
    front = ROOT / "target/release/examples/n7_front_cost"
    metadata = dict(machine=platform.platform(), architecture=platform.machine(),
                    samples=SAMPLES, warmup=WARMUP, clock="perf_counter_ns / Rust Instant",
                    quantile="nearest rank ceil(0.95*n)",
                    rustc=checked(["rustc", "--version"]).stdout.decode().strip(),
                    binaries={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in (front, binary) if p.exists()},
                    baseline=str(args.baseline) if args.baseline else None,
                    cold_command=args.cold_command,
                    maxrss_units="bytes on macOS; KiB on Linux",
                    legacy_front_publish=diagnostic_only({}))
    (out / "method.json").write_text(json.dumps(metadata, indent=2) + "\n")
    measured = {}
    result = resource_run([str(front), str(out / "front-fixture")])
    (out / "front.tsv").write_bytes(result.stdout)
    (out / "front.stderr").write_bytes(result.stderr)
    native = b"native_clock_available=true" in result.stderr
    rows = list(csv.DictReader(result.stdout.decode().splitlines(), delimiter="\t"))
    for fixture in ("normal", "4096-band"):
        selected = [row for row in rows if row["fixture"] == fixture]
        for col in ("prefilter_ns", "staged_file_read_decode_ns", "respond_render_ns", "read_ns", "checksum_decode_ns"):
            nums = [int(row[col]) for row in selected if row[col].isdigit()]
            label = f"{fixture}/{col}"
            if col == "prefilter_ns" and not native:
                label += " (clock denied; incomplete path)"
            measured[label] = diagnostic_only(summary(nums) if nums else {"not_done": "native boot observation denied"})
        measured[f"{fixture}/compiled_bytes"] = diagnostic_only(int(selected[0]["compiled_bytes"]))
    # The ignored fixture injects identity ONLY; real monotonic elapsed time and
    # the original 500 ms/2 s budgets still apply to actual filesystem publishing.
    built = checked(["cargo", "test", "--release", "-j", "2", "-p", "bingsu", "--bin", "bingsu",
                     "--no-run", "--message-format=json"])
    artifacts = [json.loads(line) for line in built.stdout.decode().splitlines() if line.startswith("{")]
    test_binary = next(row["executable"] for row in artifacts
                       if row.get("reason") == "compiler-artifact" and row.get("executable")
                       and row.get("profile", {}).get("test"))
    metadata["publish_test_binary"] = dict(path=test_binary,
        sha256=hashlib.sha256(Path(test_binary).read_bytes()).hexdigest())
    (out / "method.json").write_text(json.dumps(metadata, indent=2) + "\n")
    result = resource_run([test_binary, "commands::refresh::tests::n7_measure_publish",
                           "--exact", "--ignored", "--nocapture"])
    (out / "publish.log").write_bytes(result.stdout + result.stderr)
    for fixture in ("normal", "4096-band"):
        samples = [line.split("\t") for line in result.stdout.decode().splitlines()
                   if line.startswith(f"N7_PUBLISH\t{fixture}\t")]
        for index, phase in ((3, "changed"), (4, "unchanged")):
            measured[f"{fixture}/publish-{phase} (clock identity DI)"] = diagnostic_only(
                summary([int(row[index]) for row in samples]) if samples
                else {"not_done": "publication incomplete; inspect N7_STOP in publish.log; no budget changed"})
    if not native:
        for label in ("prompt-common", "prompt-cold-page-cache", "redraw", "cold-init", "warm-init",
                      "start-args", "helper-spawn", "snapshot-boundary/normal", "snapshot-boundary/4096-band"):
            measured[label] = {"not_done": "native boot UUID denied; fallback is not a normal-path sample"}
    else:
        measure_prompt(args, out, binary, measured, front, Path(test_binary))
    (out / "summary.json").write_text(json.dumps(measured, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(measured, ensure_ascii=False, indent=2))


def collector_product():
    spec = importlib.util.spec_from_file_location('n7_collector', ROOT / 'bench/collector-product.py')
    product = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product)
    return product


def _n7_pairs(base: Path, candidate: Path, rounds: int, condition: protocol.Condition, *, redraw=False) -> protocol.Paired:
    product = collector_product()
    (ROOT / 'target').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='n7-pairs-', dir=ROOT / 'target') as temp:
        contexts = {}
        for name, binary in (('base', base), ('candidate', candidate)):
            directory = Path(temp) / name
            directory.mkdir(mode=0o700)
            contexts[name] = product.prompt_context(binary.resolve(), directory)
        def observe(name, binary):
            command, env = contexts[name]
            command = command + (['--redraw'] if redraw else [])
            start = time.perf_counter_ns()
            result = checked(command, env=env)
            elapsed = time.perf_counter_ns() - start
            if not product.normal_record(result):
                raise ValueError('normal prompt record unavailable')
            return dict(prompt_ns=elapsed, command=command)
        return protocol.paired(base, candidate, rounds, condition, observe,
                               required_metrics=("prompt_ns",))


def n7_pairs(base: Path, candidate: Path, rounds: int, condition: protocol.Condition, *, redraw=False) -> protocol.Paired:
    try:
        return _n7_pairs(base, candidate, rounds, condition, redraw=redraw)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return dict(status='BLOCKED', reason=str(error), variants={}, blocks=[])


def start_args_observe(name, binary):
    """Proxy for process start + argument handling: dispatch refuses the word
    as a command and exits through usage (one entry_deadline, no prompt
    argument parsing, no bootstrap). It does not bound the prompt's row."""
    start = time.perf_counter_ns()
    result = subprocess.run([str(binary), '__m3d-no-such-command'], capture_output=True, timeout=10)
    elapsed = time.perf_counter_ns() - start
    if result.returncode != 2 or not result.stderr or result.stdout:
        raise ValueError('start-args proxy must exit through rejected dispatch usage (2)')
    return dict(start_args_proxy_ns=elapsed)


def helper_spawn_observe(front: Path, context):
    product = collector_product()
    def observe(name, binary):
        command, env = context
        words = [str(word) for word in command[2:]]  # argv after `bingsu prompt`
        result = checked([str(front), '--helper-spawn', str(binary), *words], env=env, timeout=10)
        sample = product.validate_helper_spawn(json.loads(result.stdout))
        return dict(helper_spawn_ns=sample['helper_spawn_ns'], events=sample['events'])
    return observe


BOUNDARY_METRICS = ('snapshot_boundary_ns', 'snapshot_read_decode_ns', 'finish_ns')


def boundary_observe(test_binary: Path, directory: Path):
    """One confined child of the release test binary per sample; its private
    working folder names the fixture (prompt_read::tests::n7_snapshot_boundary_child)."""
    def observe(name, binary):
        result = checked([str(test_binary.resolve()), 'prompt_read::tests::n7_snapshot_boundary_child', '--exact',
                          '--ignored', '--test-threads=1', '--nocapture', '-q'], cwd=directory, timeout=10)
        for child in directory.iterdir():
            shutil.rmtree(child)
        lines = [line for line in result.stdout.decode(errors='replace').splitlines() if line.startswith('N7_BOUNDARY')]
        if len(lines) != 1 or not lines[0].startswith('N7_BOUNDARY {'):
            raise ValueError('snapshot boundary child gave no sample (deadline, refusal or denied clock): ' + repr(lines))
        sample = json.loads(lines[0].split(' ', 1)[1])
        if sample.get('normal_record') is not True:
            raise ValueError('snapshot boundary sample did not render a normal ok:none record')
        return {k: sample[k] for k in BOUNDARY_METRICS}
    return observe


def segment_pairs(binary: Path, rounds: int, condition, observe, metrics) -> protocol.Paired:
    """Absolute segment rows: the same binary on both sides of the admitted protocol."""
    try:
        return protocol.paired(binary, binary, rounds, condition, observe, required_metrics=metrics)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return dict(status='BLOCKED', reason=str(error), variants={}, blocks=[])


def record(measured, out, label, result, **extra):
    raw = protocol.persist_raw(out, result)
    measured[label] = dict(status=result['status'], raw=str(raw), **extra,
                           variants={n: v['summary'] for n, v in result['variants'].items()},
                           **({'reason': result['reason']} if 'reason' in result else {}))


def measure_prompt(args, out, binary, measured, front=None, test_binary=None):
    condition = {**protocol.DEFAULT, **(args.condition or {}), 'mode': args.mode}
    for mode in ('common', 'redraw'):
        result = n7_pairs(args.baseline or binary, binary, SAMPLES, condition, redraw=mode == 'redraw')
        record(measured, out, 'prompt-' + mode, result)
    measured['prompt-cold-page-cache'] = dict(status='BLOCKED', reason='cold is record-only; separate permitted cache eviction run required')
    measured['cold-init/warm-init'] = dict(status='BLOCKED', reason='separate shell-startup run: bench/init_cost.py')
    record(measured, out, 'start-args', segment_pairs(binary, SAMPLES, condition, start_args_observe, ('start_args_proxy_ns',)),
           disposition='proxy: not a bound of process start + argument handling')
    (ROOT / 'target').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='n7-segments-', dir=ROOT / 'target') as temp:
        try:
            directory = Path(temp) / 'spawn'
            directory.mkdir(mode=0o700)
            context = collector_product().prompt_context(binary.resolve(), directory)
            result = segment_pairs(binary, SAMPLES, condition, helper_spawn_observe(front, context), ('helper_spawn_ns',))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result = dict(status='BLOCKED', reason=str(error), variants={}, blocks=[])
        record(measured, out, 'helper-spawn', result)
        for fixture in ('normal', '4096-band'):
            directory = Path(temp) / 'boundary' / fixture
            directory.mkdir(mode=0o700, parents=True)
            result = segment_pairs(binary, SAMPLES, condition, boundary_observe(test_binary, directory), BOUNDARY_METRICS)
            record(measured, out, 'snapshot-boundary/' + fixture, result,
                   overlaps='snapshot_boundary_ns contains snapshot_read_decode_ns and the collection reads of front_read_ns')


if __name__ == "__main__":
    main()
