#!/usr/bin/env python3
"""N7 single-condition mutations. No git, no production injection switches.

Run serially in an otherwise idle checkout. A baseline must pass the named test;
only that test's FAILED line kills a mutation. Every edit is restored and byte
compared in finally, including build errors and timeouts. Logs are in target/n7.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


def execute(command, log, timeout):
    environment = dict(os.environ)
    cache = ROOT / "target/n7/uv-cache"
    if cache.is_dir():
        environment.setdefault("UV_CACHE_DIR", str(cache))
    try:
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout,
                                env=environment)
        output = result.stdout.decode(errors="replace")
        code = result.returncode
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"").decode(errors="replace") + "\nN7 HARNESS TIMEOUT\n"
        code = 124
    log.write_text(output)
    return code, output


def run(case, dest):
    name = case["id"]
    command = case["command"]
    anchor = case["anchor"]
    timeout = case.get("timeout", 90)
    patches = case.get("platform_patches", {}).get(sys.platform, case["patches"])
    if case.get("build"):
        code, _ = execute(case["build"], dest / f"{name}-baseline-build.log", timeout)
        if code:
            return {"status": "not done", "reason": "baseline build failed"}
    baseline_code, baseline = execute(command, dest / f"{name}-baseline.log", timeout)
    passed = f"test {anchor} ... ok" if case["kind"] == "rust" else f"{anchor} PASSED"
    if baseline_code or passed not in baseline:
        return {"status": "not done", "reason": "baseline did not pass the named test"}
    originals = {patch["file"]: (ROOT / patch["file"]).read_bytes() for patch in patches}
    started = time.monotonic()
    try:
        for patch in patches:
            path = ROOT / patch["file"]
            source = path.read_text()
            before = patch["before"]
            count = source.count(before)
            if count != patch.get("count", 1):
                raise ValueError(f"{path}: expected {patch.get('count', 1)} occurrences, got {count}")
            path.write_text(source.replace(before, patch["after"], patch.get("replace", count)))
        if case.get("build"):
            code, _ = execute(case["build"], dest / f"{name}-mutant-build.log", timeout)
            if code:
                return {"status": "ERROR", "reason": "mutant build failed; not a test failure"}
        code, output = execute(command, dest / f"{name}-mutant.log", timeout)
        failed = (f"test {anchor} ... FAILED" if case["kind"] == "rust"
                  else f"{anchor} FAILED")
        status = "KILLED" if code != 0 and failed in output else "SURVIVED" if code == 0 else "ERROR"
        return {"status": status, "returncode": code, "seconds": round(time.monotonic() - started, 3),
                "reason": "named test failed" if status == "KILLED" else "named failure not observed"}
    finally:
        for name, original in originals.items():
            path = ROOT / name
            path.write_bytes(original)
            assert path.read_bytes() == original, f"restore failed: {name}"
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in originals.items()}
        (dest / f"{case['id']}-restored.json").write_text(json.dumps(hashes, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ids", nargs="*")
    parser.add_argument("--manifest", type=pathlib.Path, default=ROOT / "tests/n7/mutations.json")
    args = parser.parse_args()
    dest = ROOT / "target/n7"
    dest.mkdir(parents=True, exist_ok=True)
    result_path = dest / "mutation-results.json"
    results = json.loads(result_path.read_text()) if result_path.exists() else {}
    cases = json.loads(args.manifest.read_text())
    selected = [case for case in cases if not args.ids or case["id"] in args.ids]
    unknown = set(args.ids) - {case["id"] for case in cases}
    if unknown:
        parser.error(f"unknown IDs: {sorted(unknown)}")
    for case in selected:
        try:
            result = run(case, dest)
        except Exception as error:
            result = {"status": "ERROR", "reason": str(error)}
        results[case["id"]] = result
        result_path.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
        print(case["id"], result, flush=True)
    return int(any(results[case["id"]]["status"] != "KILLED" for case in selected))


if __name__ == "__main__":
    raise SystemExit(main())
