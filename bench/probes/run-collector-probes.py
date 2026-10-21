#!/usr/bin/env python3
"""Standalone experiments. PASS is scoped to one measured environment.

Exit 0: selected host cells observed; 1: failed evidence; 2: unavailable or
missing required acceptance cells. --case all also requires the entire ledger.
No sysctl writes, privilege escalation, or product configuration changes.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CELLS = {
    "X-02": ("bash_handoff", "python_handoff", "native_modes", "shebang_boundary",
             "size_and_noexec", "system_walk", "refusals"),
    "X-32": ("setsid", "cloexec_default", "both", "fallback_missing", "fallback_einval", "race"),
    "X-14": ("status",),
    "X-16": ("O_RDONLY|O_TRUNC", "O_WRONLY|O_TRUNC", "unlink", "rename", "socket", "connect"),
}
FIELDS = ("case", "environment", "arch", "cell", "status", "outcome", "evidence_file", "command", "reason")


@dataclass
class ProbeResult:
    case: str
    platform: str
    kernel: str
    libc: str
    arch: str
    build_id: str
    outcome: str
    evidence: dict


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def build_id(case):
    paths = [Path(__file__)]
    if case in ("X-02", "X-32"):
        paths.append(HERE / ("x02-memfd.c" if case == "X-02" else "x32-spawn.c"))
    else:
        paths.extend([ROOT / "crates/bingsu-collect/src/filter.rs",
                      ROOT / "crates/bingsu-collect/tests/filter/runtime.rs"])
        paths.extend(sorted((HERE / "collector-x14").rglob("*.rs")) if case == "X-14"
                     else [HERE / "x16-write-denial.c"])
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def run_probe(case: str, command: list[str], timeout_s: float) -> ProbeResult:
    result = ProbeResult(case, platform.system(), platform.release(),
                         " ".join(platform.libc_ver()).strip() or ("libSystem" if platform.system() == "Darwin" else "unknown"),
                         {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine()),
                         build_id(case), "FAIL", {})
    start = time.monotonic()
    try:
        # Kill the entire group on timeout, including compiler/probe children.
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise ValueError("timeout; process group killed") from None
        result.evidence = {"returncode": process.returncode, "stdout": stdout,
                           "stderr": stderr, "elapsed_s": time.monotonic() - start,
                           "observed_at": datetime.now(timezone.utc).isoformat()}
        if process.returncode == 0:
            result.outcome = "PASS"
    except FileNotFoundError:
        result.outcome = "BLOCKED"
        result.evidence = {"reason": "required executable unavailable"}
    except ValueError as error:
        result.evidence = {"reason": str(error)}
    return result


def validate(case, stdout, mutate=False):
    """Validate raw observations, not a standalone PASS word."""
    if case == "X-14":
        matches = re.findall(r"^X-14 status PASS changes=(\d+) index_unchanged=1 baseline=(\d+) limit=(\d+)$", stdout, re.M)
        require(len(matches) == 1 and stdout.splitlines().count("X-14 PASS") == 1, "missing X-14 status")
        changes, baseline, limit = map(int, matches[0])
        require(changes >= (999999 if mutate else 2) and 0 < baseline < limit, "X-14 status/AS evidence")
        return {"status": {"changes": changes, "index_unchanged": 1, "baseline": baseline, "limit": limit}}
    if case == "X-16":
        for cell in CELLS[case]:
            require(stdout.splitlines().count(f"X-16 {cell} EPERM unchanged") == (2 if mutate else 1), "missing X-16 denial")
        require("X-16 PASS cells=6 fsize=0 control_truncated=1" in stdout, "missing FSIZE control")
        require(re.search(r"test result: ok\. 1 passed; 0 failed;", stdout), "required test did not execute")
        return {cell: {"errno": 1, "unchanged": 1, "fsize": 0, "control_truncated": 1} for cell in CELLS[case]}
    records = [json.loads(line) for line in stdout.splitlines()]
    require(all(set(r) == {"cell", "evidence"} and isinstance(r["evidence"], dict) for r in records), "invalid record schema")
    require(len(records) == len(CELLS[case]), "missing/duplicate record")
    cells = {r["cell"]: r["evidence"] for r in records}
    require(set(cells) == set(CELLS[case]), "wrong acceptance cells")
    if case == "X-02":
        for cell in ("bash_handoff", "python_handoff"):
            e = cells[cell]
            require(e["closed_exit"] != 0 and e["closed_canary"] == 0 and e["open_exit"] == 0
                    and e["open_canary"] == (2 if mutate else 1) and e["exec_errno"] == 0
                    and e["leaks"] == 0 and e["seals"] & 15 == 15 and e["fallback_errno"] in (0, 22), "handoff evidence")
            require(e["noexec_errno"] == (0 if e["fallback_errno"] == 22 else 13), "NOEXEC_SEAL execution refusal")
        require(cells["native_modes"] == {"rdonly_exit": 0, "opath_exit": 0, "opath_read_errno": 9, "canaries": 2}, "native modes")
        require(cells["shebang_boundary"] == {"exec_errno": 2, "canary": 0, "nested_rejected": 1}, "shebang boundary")
        e = cells["size_and_noexec"]
        require(e["accepted_bytes"] == 65536 and e["rejected_bytes"] == 65537 and e["fallback_errno"] in (0, 22)
                and e["other_errno_rejected"] == 1, "size/noexec")
        e = cells["system_walk"]
        require(e["native"] == 1 and e["exit"] == 0 and e["canary"] == 1 and e["links"] >= 1
                and e["merged_usr"] == 1, "merged-/usr walk")
        require(cells["refusals"] == dict.fromkeys(("relative", "relative_link", "env", "proc_missing", "replaced_link", "writable_chain"), 1), "refusal fixtures")
    else:
        for cell in CELLS[case][:-1]:
            e = cells[cell]
            require(e["errno"] in (0, 22) and e["missing"] in (0, 1) and e["exit"] == 0 and e["elapsed_us"] > 0, "spawn result")
            require(e["fallback"] == int(bool(e["missing"] or e["errno"] == 22)), "unapproved fallback")
            require(e["close_ns"] > 0 if e["fallback"] else e["close_ns"] == 0, "fallback fd-close timing")
            if cell != "cloexec_default" or e["fallback"]:
                require(e["sid"] == e["pid"] and e["sid"] != e["parent_sid"], "session isolation")
            else:
                require(e["sid"] == e["parent_sid"], "CLOEXEC-only session control")
            if cell != "setsid" or e["fallback"]:
                require(e["leaks"] == 0 and e["high_open"] == 0, "fd isolation")
        require(cells["fallback_missing"]["missing"] == 1 and cells["fallback_einval"]["errno"] == 22, "fallback injection")
        e = cells["race"]
        require(e["opens"] > 0 and e["high_fd"] == 1025 and e["soft_limit"] == 256
                and e["close_ceiling"] > 1025 and e["other_errno_rejected"] == 1, "race fixture")
        require(not mutate, "mutated session expectation")
    return cells


def environment(case, result, check_acceptance=True):
    if case == "X-32":
        version = platform.mac_ver()[0]
        result.evidence["os_version"] = version
        result.evidence["os_build"] = subprocess.check_output(["sw_vers", "-buildVersion"], text=True).strip()
        return "macos-11.0" if version == "11.0" or version.startswith("11.0.") else "macos-current"
    if case == "X-02":
        sysctl = Path("/proc/sys/vm/memfd_noexec")
        value = sysctl.read_text().strip() if sysctl.exists() else "absent"
        result.evidence["memfd_noexec"] = value
        major, minor = map(int, re.match(r"(\d+)\.(\d+)", result.kernel).groups())
        if (major, minor) >= (6, 3):
            require(value in ("0", "1", "2"), "new kernel without readable memfd_noexec")
            if check_acceptance:
                require(result.evidence["cells"]["size_and_noexec"]["fallback_errno"] == 0, "unexpected NOEXEC_SEAL EINVAL")
            return "linux-ge6.3-noexec" + value
        require(value == "absent", "old kernel sysctl unexpectedly present")
        if check_acceptance:
            require(result.evidence["cells"]["size_and_noexec"]["fallback_errno"] == 22,
                    "old kernel must observe NOEXEC_SEAL EINVAL")
        return "linux-le6.2-einval"
    require("musl" in result.libc or "glibc" in result.libc, "libc was not identified")
    return "linux-" + ("musl" if "musl" in result.libc else "glibc")


def execute_case(case, target=None):
    supported = "Darwin" if case == "X-32" else "Linux"
    if platform.system() != supported:
        r = run_probe(case, ["true"], 5)
        r.outcome = "BLOCKED"; r.evidence = {"reason": f"requires native {supported}"}
        return r
    with tempfile.TemporaryDirectory(prefix="collector-probes-") as directory:
        if case in ("X-02", "X-32"):
            source = HERE / ("x02-memfd.c" if case == "X-02" else "x32-spawn.c")
            binary = Path(directory) / "probe"
            command = shlex.split(os.environ.get("CC", "cc")) + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
            if case == "X-32":
                command += ["-pthread", "-mmacosx-version-min=11.0"]
            compiled = run_probe(case, command + [str(source), "-o", str(binary)], 120)
            if compiled.outcome != "PASS":
                return compiled
            result = run_probe(case, [str(binary)], 120)
            result.evidence["compiler"] = subprocess.check_output(shlex.split(os.environ.get("CC", "cc")) + ["--version"], text=True).splitlines()[0]
            result.evidence["compile_flags"] = command[len(shlex.split(os.environ.get("CC", "cc"))):]
            result.evidence["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            if case == "X-32":
                result.evidence["sdk"] = subprocess.check_output(["xcrun", "--show-sdk-version"], text=True).strip()
                result.evidence["deployment_target"] = "11.0"
            if result.outcome == "PASS":
                mutant = run_probe(case, [str(binary), "--mutate-expectation"], 120)
                # Compilation errors, signals and timeouts do not kill this mutation.
                result.evidence["mutation"] = {"returncode": mutant.evidence.get("returncode"),
                                                "stderr": mutant.evidence.get("stderr", "")}
                if mutant.evidence.get("returncode") != 90 or "assertion:" not in mutant.evidence.get("stderr", ""):
                    result.outcome = "FAIL"; result.evidence["reason"] = "expectation mutation survived"
        else:
            if case == "X-14":
                command = ["cargo", "run", "--locked", "-j", "2", "--manifest-path", "bench/probes/collector-x14/Cargo.toml", "--release"]
                if target:
                    command += ["--target", target]
                command += ["--", "--case", "all"]
            else:
                command = ["cargo", "test", "--locked", "-j", "2", "-p", "bingsu-collect"]
                if target:
                    command += ["--target", target]
                command += ["--test", "filter", "--", "--exact", "runtime::x16_all_mutations_are_denied_with_fsize_zero", "--nocapture", "--test-threads=1"]
            result = run_probe(case, command, 900)
            if target and "musl" in target:
                result.libc = "musl (static target)"
        if result.outcome == "PASS":
            try:
                result.evidence["cells"] = validate(case, result.evidence["stdout"])
                if case in ("X-14", "X-16"):
                    try:
                        validate(case, result.evidence["stdout"], mutate=True)
                    except ValueError:
                        result.evidence["mutation"] = {"expectation_rejected": True}
                    else:
                        raise ValueError("expectation mutation survived")
                result.evidence["environment"] = environment(case, result)
                if case == "X-14" and "glibc" in result.libc:
                    require(tuple(map(int, platform.libc_ver()[1].split(".")[:2])) >= (2, 35), "glibc >=2.35 required")
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                result.outcome = "FAIL"; result.evidence["reason"] = str(error)
        return result


def ledger_rows():
    rows = list(csv.DictReader((HERE / "collector-acceptance.tsv").open(), delimiter="\t"))
    require(rows and set(rows[0]) == set(FIELDS), "ledger schema")
    expected = set()
    for arch in ("x86_64", "aarch64"):
        for case, environments in (("X-02", ("linux-ge6.3-noexec0", "linux-ge6.3-noexec1", "linux-ge6.3-noexec2", "linux-le6.2-einval")),
                                   ("X-32", ("macos-11.0", "macos-current")),
                                   ("X-14", ("linux-glibc", "linux-musl")),
                                   ("X-16", ("linux-glibc", "linux-musl"))):
            expected.update((case, env, arch, cell) for env in environments for cell in CELLS[case])
    keys = [(r["case"], r["environment"], r["arch"], r["cell"]) for r in rows]
    require(len(keys) == len(set(keys)) and set(keys) == expected, "required ledger cells missing or duplicated")
    for row in rows:
        require((row["status"], row["outcome"]) in (("observed", "PASS"), ("not observed", "BLOCKED"), ("failed", "FAIL")), "ledger status")
        require(row["command"] and (row["reason"] or row["evidence_file"]), "ledger evidence/command missing")
        if row["outcome"] == "PASS":
            evidence_path = ROOT / row["evidence_file"]
            require(not Path(row["evidence_file"]).is_absolute() and evidence_path.is_file(), "observed evidence unavailable")
            saved = json.loads(evidence_path.read_text())
            matches = [r for r in saved["results"] if r["case"] == row["case"] and r["arch"] == row["arch"]
                       and r["outcome"] == "PASS" and r["evidence"]["environment"] == row["environment"]]
            require(len(matches) == 1, "observed evidence mismatch")
            result = matches[0]
            require(result["platform"] == ("Darwin" if row["case"] == "X-32" else "Linux"), "wrong native platform")
            require(row["cell"] in validate(row["case"], result["evidence"]["stdout"]), "observed cell missing")
            if row["case"] == "X-32":
                version = result["evidence"]["os_version"]
                minimum = version == "11.0" or version.startswith("11.0.")
                require((row["environment"] == "macos-11.0") == minimum, "current OS cannot substitute for minimum VM")
            mutation = result["evidence"].get("mutation", {})
            require(mutation.get("returncode") == 90 if row["case"] in ("X-02", "X-32")
                    else mutation.get("expectation_rejected") is True, "mutation proof missing")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=(*CELLS, "all"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ledger-out", type=Path)
    parser.add_argument("--require-environment", help="fail if the measured environment differs")
    parser.add_argument("--target", help="native musl target for the existing X-14/X-16 harnesses")
    args = parser.parse_args()
    if args.ledger_out and args.ledger_out.resolve() == (HERE / "collector-acceptance.tsv").resolve():
        parser.error("use a separate output ledger")
    try:
        rows = ledger_rows()
    except (ValueError, KeyError, OSError) as error:
        print(f"BLOCKED: {error}")
        return 2
    results = [execute_case(case, args.target) for case in (CELLS if args.case == "all" else [args.case])]
    for result in results:
        if result.outcome != "BLOCKED" and "environment" not in result.evidence:
            try:
                result.evidence["environment"] = environment(result.case, result, check_acceptance=False)
            except (OSError, ValueError):
                pass  # No environment is inferred without host metadata.
        if args.require_environment and result.outcome == "PASS" and result.evidence["environment"] != args.require_environment:
            result.outcome = "FAIL"; result.evidence["reason"] = "required environment not observed"
        print(result.case, result.outcome, result.evidence.get("environment", result.evidence.get("reason", "")))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Strip temporary build paths from logs; committed evidence is portable.
    data = json.dumps({"schema_version": 1, "results": [asdict(r) for r in results]}, indent=2)
    data = data.replace(str(ROOT), "<checkout>")
    data = re.sub(r"(?:/private)?/var/folders/[^\s\"']+", "<temporary>", data)
    data = re.sub(r"/tmp/collector-probes-[^/\s\"']+", "<temporary>", data)
    args.out.write_text(data + "\n")
    for row in rows:
        for r in results:
            if (row["case"], row["environment"], row["arch"]) == (r.case, r.evidence.get("environment"), r.arch):
                row.update(status={"PASS": "observed", "FAIL": "failed", "BLOCKED": "not observed"}[r.outcome], outcome=r.outcome,
                           evidence_file=os.path.relpath(args.out, ROOT),
                           reason=r.evidence.get("reason", "suite failed; no criterion accepted" if r.outcome == "FAIL" else ""))
    if args.ledger_out:
        args.ledger_out.parent.mkdir(parents=True, exist_ok=True)
        with args.ledger_out.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)
    if any(r.outcome == "FAIL" for r in results):
        return 1
    if any(r.outcome == "BLOCKED" for r in results) or (args.case == "all" and any(r["outcome"] != "PASS" for r in rows)):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
