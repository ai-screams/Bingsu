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
    return subprocess.run(command, cwd=ROOT, capture_output=True, check=True, **kwargs)


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
                    maxrss_units="bytes on macOS; KiB on Linux")
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
            measured[label] = summary(nums) if nums else {"not_done": "native boot observation denied"}
        measured[f"{fixture}/compiled_bytes"] = int(selected[0]["compiled_bytes"])
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
            measured[f"{fixture}/publish-{phase} (clock identity DI)"] = (
                summary([int(row[index]) for row in samples]) if samples
                else {"not_done": "publication incomplete; inspect N7_STOP in publish.log; no budget changed"})
    if not native:
        for label in ("prompt-common", "prompt-cold-page-cache", "redraw", "cold-init", "warm-init"):
            measured[label] = {"not_done": "native boot UUID denied; fallback is not a normal-path sample"}
    else:
        measure_prompt(args, out, binary, measured)
    (out / "summary.json").write_text(json.dumps(measured, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(measured, ensure_ascii=False, indent=2))


def _n7_pairs(base: Path, candidate: Path, rounds: int, condition: protocol.Condition, *, redraw=False) -> protocol.Paired:
    spec = importlib.util.spec_from_file_location('n7_collector', ROOT / 'bench/collector-product.py')
    product = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product)
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
        return protocol.paired(base, candidate, rounds, condition, observe)


def n7_pairs(base: Path, candidate: Path, rounds: int, condition: protocol.Condition, *, redraw=False) -> protocol.Paired:
    try:
        return _n7_pairs(base, candidate, rounds, condition, redraw=redraw)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return dict(status='BLOCKED', reason=str(error), variants={}, blocks=[])


def measure_prompt(args, out, binary, measured):
    condition = {**protocol.DEFAULT, **(args.condition or {}), 'mode': args.mode}
    for mode in ('common', 'redraw'):
        result = n7_pairs(args.baseline or binary, binary, SAMPLES, condition, redraw=mode == 'redraw')
        raw = protocol.persist_raw(out, result)
        measured['prompt-' + mode] = dict(status=result['status'], raw=str(raw),
            variants={n: v['summary'] for n, v in result['variants'].items()})
    measured['prompt-cold-page-cache'] = dict(status='BLOCKED', reason='cold is record-only; separate permitted cache eviction run required')
    measured['cold-init/warm-init'] = dict(status='BLOCKED', reason='separate shell-startup baseline required (bench/run-e2e.sh)')


if __name__ == "__main__":
    main()
