#!/usr/bin/env python3
"""M3c acceptance probes: X-08, X-09, X-10, X-11, X-13 and X-15.

Each cell runs the existing product tests that carry its evidence and checks
their raw output: the exact "test ... ok" or "PASSED" line, a run with zero
ignored tests, and the cell's own observation lines. A success word alone is
never evidence. A selected probe that is absent (missing tool, wrong host,
ignored test, a "BLOCKED:" panic, missing preparation) is BLOCKED.

Exit 0: selected cells observed; 1: failed evidence; 2: blocked, or --case
all with any ledger cell not PASS. This runner owns only these six cases in
bench/probes/collector-acceptance.tsv; run-collector-probes.py owns the rest.
No sysctl writes, privilege escalation or product configuration changes.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
LEDGER = "collector-acceptance.tsv"
FIELDS = ("case", "environment", "arch", "cell", "status", "outcome", "evidence_file", "command", "reason")
ARCHES = ("x86_64", "aarch64")
# U4: Linux collection needs 5.9+ and the required kernel features; below it
# the product collects nothing and the prompt stays normal. U5: the current
# macOS runtime; the minimum macOS VM is decision 24, never a substitute here.
LINUX_FLOOR = (5, 9)
ALL_ENVIRONMENTS = ("macos-current", "linux-glibc", "linux-musl")


@dataclass(frozen=True)
class Rust:
    """One cargo test run with --exact; `module` prefixes libtest's name."""
    package: str
    target: str
    name: str
    module: str = ""
    ignored: bool = False
    lines: tuple = ()  # regexes that must each match at least one stdout line
    env: tuple = ()


@dataclass(frozen=True)
class Pytest:
    node: str
    requires: str = ""  # a prepared fixture file, relative to ROOT
    env: tuple = ()


@dataclass(frozen=True)
class Docker:
    """Raw errno of openat2 inside a container under Docker's default seccomp."""
    source: str = "bench/probes/x15-openat2.c"


# case -> environments, cells -> {platform: [probes]}
CASES = {
    "X-08": {
        "environments": ALL_ENVIRONMENTS,
        "cells": {
            "fifty_ms_stage_a": {
                "any": [Rust("bingsu", "collector_lifecycle", "x08_stage_a_survives_fifty_ms_cutoff"),
                        Pytest("tests/shell/test_git_collection_security.py::test_actual_fifty_ms_partial_preserves_stage_a",
                               "target/git-corpus/prepared.json", (("BINGSU_GIT_CORPUS_REQUIRED", "1"),))],
            },
            "zero_filter_processes": {
                "any": [Pytest("tests/shell/test_git_collection_security.py::test_hostile_git_canaries_have_zero_effects",
                               "target/git-corpus/prepared.json", (("BINGSU_GIT_CORPUS_REQUIRED", "1"),)),
                        Pytest("tests/shell/test_git_collection_security.py::test_no_spawn_harness_detects_attempts",
                               "target/git-corpus/prepared.json", (("BINGSU_GIT_CORPUS_REQUIRED", "1"),))],
            },
        },
    },
    # Product A-only for the pinned lower crates. The three historical
    # override probes (true, false, replaceRefBase) stay separate evidence.
    "X-09": {
        "environments": ALL_ENVIRONMENTS,
        "cells": {"replace_alternates_a_only": {
            "any": [Rust("bingsu-collect", "git_stage_a", "x09_replace_and_alternates_are_stage_a_only")]}},
    },
    "X-10": {
        "environments": ALL_ENVIRONMENTS,
        "cells": {"request_roots_ignore_environment": {
            "any": [Rust("bingsu-collect", "git_stage_a", "x10_request_roots_ignore_git_work_tree")]}},
    },
    "X-11": {
        "environments": ("macos-current",),
        "cells": {
            "runtime_probe": {"macos": [
                Rust("bingsu-collect", "safe_read_macos", "x11_each_flag_requires_negative_semantics",
                     lines=(r"^X11 path=\S+ flags=0x[0-9a-f]+ errno=\d+$",)),
                Rust("bingsu-collect", "safe_read_macos", "darwin_mount_and_devfd_are_refused",
                     lines=(r"^X11 beneath_dev_crossing=success adapter_dev_crossing=Escape$",)),
                Rust("bingsu-collect", "safe_read_macos", "startup_probe_is_closed_before_ready",
                     lines=(r"^X11 spawn_to_ready_ns=\d+ fds=",))]},
            "forced_unsupported_fallback": {"macos": [
                Rust("bingsu-collect", "safe_read_macos", "unknown_darwin_flags_do_not_enable_fast_path"),
                Rust("bingsu-collect", "safe_read_macos", "invalid_probe_fixture_falls_back_without_authority")]},
        },
    },
    "X-13": {
        "environments": ALL_ENVIRONMENTS,
        "cells": {
            "both_resolvers": {"any": [Rust("bingsu-collect", "safe_read", "x13_resolvers_share_static_verdicts")]},
            "rename_during_walk": {
                "linux": [Rust("bingsu-collect", "safe_read_linux", "linux_openat2_coarse_rename_reads_zero_external_bytes")],
                "macos": [Rust("bingsu-collect", "safe_read", "coarse_rename_with_guarantee_reads_zero_external_bytes")]},
            "inner_mount_refused": {
                "linux": [Rust("bingsu-collect", "safe_read", "cwd_on_other_mount_is_allowed", ignored=True)],
                "macos": [Rust("bingsu-collect", "safe_read_macos", "darwin_mount_and_devfd_are_refused")]},
            "cwd_on_other_mount_allowed": {
                "linux": [Rust("bingsu-collect", "safe_read", "cwd_on_other_mount_is_allowed", ignored=True)],
                "macos": [Rust("bingsu-collect", "safe_read_macos", "cwd_on_other_mount_is_allowed")]},
        },
    },
    "X-15": {
        "environments": ("linux-glibc", "linux-musl"),
        "cells": {
            "docker_default_errno": {"linux": [Docker()]},
            "forced_enosys": {"linux": [Rust("bingsu-collect", "safe_read", "x15_enosys_and_eperm_select_stepwise")]},
            "forced_eperm": {"linux": [Rust("bingsu-collect", "safe_read", "x15_enosys_and_eperm_select_stepwise")]},
        },
    },
}


@dataclass
class ProbeResult:
    case: str
    platform: str
    kernel: str
    libc: str
    arch: str
    build_id: str
    source_hash: str
    lock_hash: str
    table_hash: str
    outcome: str
    evidence: dict = field(default_factory=dict)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256_paths(paths):
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def probe_sources(case):
    files = set()
    for platforms in CASES[case]["cells"].values():
        for probes in platforms.values():
            for probe in probes:
                if isinstance(probe, Rust):
                    files.add(ROOT / "crates" / probe.package / "tests" / (probe.target + ".rs"))
                elif isinstance(probe, Pytest):
                    files.add(ROOT / probe.node.split("::")[0])
                else:
                    files.add(ROOT / probe.source)
    return files


def source_hash(case):
    paths = probe_sources(case)
    for crate in ("bingsu-collect", "bingsu-core", "bingsu-identity", "bingsu"):
        paths.update((ROOT / "crates" / crate / "src").rglob("*.rs"))
        paths.add(ROOT / "crates" / crate / "Cargo.toml")
        # A build script changes the binary bytes as much as src does.
        paths.update((ROOT / "crates" / crate).glob("build.rs"))
    return sha256_paths(paths)


def lock_hash():
    return sha256_paths([ROOT / "Cargo.lock"])


def table_hash():
    return sha256_paths([ROOT / "crates/bingsu-collect/collector-syscalls.tsv"])


def build_id(case):
    """Runner, product sources, tests, lock and syscall table together."""
    digest = hashlib.sha256()
    digest.update(Path(__file__).read_bytes().replace(b"\r\n", b"\n"))
    for part in (source_hash(case), lock_hash(), table_hash()):
        digest.update(part.encode())
    return digest.hexdigest()


def host_libc():
    name, version = platform.libc_ver()
    if platform.system() == "Darwin":
        return "libSystem"
    return f"{name} {version}".strip() or "unknown"


def host_arch():
    return {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())


def new_result(case):
    return ProbeResult(case, platform.system(), platform.release(), host_libc(), host_arch(),
                       build_id(case), source_hash(case), lock_hash(), table_hash(), "FAIL")


def run_probe(case: str, command: list[str], timeout_s: float, env=None) -> ProbeResult:
    """Run one command in its own process group; a timeout kills the group."""
    result = new_result(case)
    start = time.monotonic()
    try:
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, start_new_session=True,
                              env={**os.environ, **dict(env or ())}) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise ValueError("timeout; process group killed") from None
        result.evidence = {"command": command, "returncode": process.returncode, "stdout": stdout,
                           "stderr": stderr, "elapsed_s": time.monotonic() - start,
                           "observed_at": datetime.now(timezone.utc).isoformat()}
        result.outcome = "PASS" if process.returncode == 0 else "FAIL"
    except FileNotFoundError:
        result.outcome = "BLOCKED"
        result.evidence = {"command": command, "reason": "required executable unavailable"}
    except ValueError as error:
        result.evidence = {"command": command, "reason": str(error)}
    return result


class Blocked(Exception):
    pass


def rust_command(probe, target=None):
    command = ["cargo", "test", "--locked", "-j", "2", "-p", probe.package, "--test", probe.target]
    if target:
        command += ["--target", target]
    # --show-output keeps "test <name> ... ok" on one line (--nocapture would
    # interleave the test's own observation lines into it).
    command += ["--", "--exact", probe.module + probe.name, "--show-output", "--test-threads=1"]
    if probe.ignored:
        command.append("--ignored")
    return command


def check_rust(probe, run):
    """Raw libtest evidence for exactly one selected, executed test."""
    stdout, stderr = run.get("stdout", ""), run.get("stderr", "")
    label = probe.module + probe.name
    if "BLOCKED:" in stdout + stderr:
        raise Blocked(label + " reported BLOCKED")
    results = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", stdout, re.M)
    selected = [r for r in results if r[1] != "0" or r[2] != "0"]
    if not selected and any(r[3] != "0" for r in results):
        raise Blocked(label + " was ignored, not executed")
    require(len(selected) == 1, "missing or duplicate libtest result for " + label)
    require(selected[0] == ("ok", "1", "0", "0"), "selected test did not pass alone: " + label)
    require(stdout.splitlines().count(f"test {label} ... ok") == 1, "missing exact pass line: " + label)
    require(run.get("returncode") == 0, "nonzero cargo exit: " + label)
    observed = {}
    for pattern in probe.lines:
        matches = [line for line in stdout.splitlines() if re.search(pattern, line)]
        require(matches, f"missing observation {pattern!r} from {label}")
        observed[pattern] = matches
    binaries = re.findall(r"Running \S+ \(([^)]+)\)", stderr)
    return {"test": label, "observations": observed, "binaries": binaries}


PYTHON = os.environ.get("BINGSU_PROBE_PYTHON", sys.executable)


def pytest_command(probe):
    return [PYTHON, "-B", "-m", "pytest", probe.node, "-q", "-rA", "-p", "no:cacheprovider"]


def check_pytest(probe, run):
    stdout = run.get("stdout", "")
    if "No module named pytest" in run.get("stderr", ""):
        raise Blocked("pytest is not installed for " + PYTHON + " (set BINGSU_PROBE_PYTHON)")
    if re.search(r"^SKIPPED ", stdout, re.M) or "BLOCKED:" in stdout:
        raise Blocked(probe.node + " skipped or blocked")
    require(stdout.splitlines().count("PASSED " + probe.node) == 1, "missing exact PASSED line: " + probe.node)
    require(re.search(r"^(?:=+ )?1 passed in ", stdout, re.M), "pytest did not run exactly one test")
    require(run.get("returncode") == 0, "nonzero pytest exit")
    return {"test": probe.node}


def check_docker(run):
    stdout = run.get("stdout", "")
    values = re.findall(r"^X-15 openat2 errno=(\d+) docker=(\S+) seccomp=default$", stdout, re.M)
    require(len(values) == 1, "missing X-15 container observation")
    errno, docker = int(values[0][0]), values[0][1]
    # 0: openat2 allowed (Openat2 backend); ENOSYS or EPERM: Stepwise. The
    # forced cells prove both errors select Stepwise in the product probe.
    require(errno in (0, 1, 38), "unexpected openat2 errno under default seccomp")
    require(run.get("returncode") == 0, "nonzero container exit")
    return {"errno": errno, "docker": docker, "resolver": "Openat2" if errno == 0 else "Stepwise"}


def environment(result, target=None):
    if result.platform == "Darwin":
        return "macos-current"
    require(result.platform == "Linux", "unsupported platform")
    major, minor = map(int, re.match(r"(\d+)\.(\d+)", result.kernel).groups())
    if (major, minor) < LINUX_FLOOR:
        raise Blocked(f"kernel {result.kernel} is below the Linux collection floor 5.9")
    if target and "musl" in target:
        result.libc = "musl (static target)"
        return "linux-musl"
    require("glibc" in result.libc, "libc was not identified")
    return "linux-glibc"


def platform_probes(case, cell, system):
    probes = CASES[case]["cells"][cell]
    return probes.get("any", probes.get("linux" if system == "Linux" else "macos"))


def docker_run(case, probe, directory, image):
    compiled = run_probe(case, ["cc", "-std=c11", "-O2", "-Wall", "-Werror", "-static",
                                str(ROOT / probe.source), "-o", str(Path(directory) / "x15")], 120)
    if compiled.outcome != "PASS":
        return compiled.evidence, compiled.outcome
    version = run_probe(case, ["docker", "version", "--format", "{{.Server.Version}}"], 30)
    if version.outcome != "PASS":
        return version.evidence, "BLOCKED"
    run = run_probe(case, ["docker", "run", "--rm", "--pull=never", "--network=none",
                           "-v", f"{directory}:/probe:ro", image, "/probe/x15",
                           version.evidence["stdout"].strip()], 120)
    return run.evidence, "PASS" if run.outcome == "PASS" else "BLOCKED"


def execute_case(case, target=None, image="debian:bookworm-slim"):
    result = new_result(case)
    system = platform.system()
    try:
        result.evidence["environment"] = environment(result, target)
    except Blocked as error:
        result.outcome = "BLOCKED"
        result.evidence["reason"] = str(error)
        return result
    except ValueError as error:
        result.outcome = "BLOCKED"
        result.evidence["reason"] = str(error)
        return result
    if result.evidence["environment"] not in CASES[case]["environments"]:
        result.outcome = "BLOCKED"
        result.evidence["reason"] = "case not defined for " + result.evidence["environment"]
        return result
    cells, runs, cache = {}, [], {}
    with tempfile.TemporaryDirectory(prefix="m3c-probes-") as directory:
        for cell in CASES[case]["cells"]:
            outcome, evidence = "PASS", []
            for probe in platform_probes(case, cell, system) or []:
                try:
                    if isinstance(probe, Docker):
                        run, status = cache.get(probe) or docker_run(case, probe, directory, image)
                        cache[probe] = (run, status)
                        if status == "BLOCKED":
                            raise Blocked("docker or its local image is unavailable")
                        require(status == "PASS", "probe build failed")
                        evidence.append(check_docker(run))
                    elif isinstance(probe, Pytest):
                        if result.evidence["environment"] == "linux-musl":
                            raise Blocked(MUSL_PYTEST)
                        if probe.requires and not (ROOT / probe.requires).is_file():
                            raise Blocked(probe.requires + " is not prepared")
                        run = cache.get(probe) or run_probe(case, pytest_command(probe), 900, probe.env).evidence
                        cache[probe] = run
                        evidence.append(check_pytest(probe, run))
                    else:
                        run = cache.get(probe) or run_probe(case, rust_command(probe, target), 900, probe.env).evidence
                        cache[probe] = run
                        if "returncode" not in run:
                            raise Blocked(run.get("reason", "probe unavailable"))
                        evidence.append(check_rust(probe, run))
                    runs.append(run)
                except Blocked as error:
                    outcome = "BLOCKED" if outcome != "FAIL" else outcome
                    evidence.append({"blocked": str(error)})
                except (ValueError, KeyError, TypeError) as error:
                    outcome = "FAIL"
                    evidence.append({"failed": str(error)})
            if not platform_probes(case, cell, system):
                outcome = "BLOCKED"
                evidence.append({"blocked": "no probe for this platform"})
            cells[cell] = {"outcome": outcome, "evidence": evidence}
    result.evidence.update(cells=cells, runs=runs)
    outcomes = {c["outcome"] for c in cells.values()}
    result.outcome = "FAIL" if "FAIL" in outcomes else "BLOCKED" if "BLOCKED" in outcomes else "PASS"
    return result


def expected_cells():
    return {(case, env, arch, cell) for case, spec in CASES.items() for env in spec["environments"]
            for arch in ARCHES for cell in spec["cells"]}


def ledger_rows(allow_stale=False, path=None):
    """This runner's rows only; any other case belongs to run-collector-probes.py."""
    rows = list(csv.DictReader((path or HERE / LEDGER).open(), delimiter="\t"))
    require(rows and set(rows[0]) == set(FIELDS), "ledger schema")
    rows = [row for row in rows if row["case"] in CASES]
    keys = [(r["case"], r["environment"], r["arch"], r["cell"]) for r in rows]
    require(len(keys) == len(set(keys)) and set(keys) == expected_cells(),
            "required M3c ledger cells missing or duplicated")
    for row in rows:
        require((row["status"], row["outcome"]) in (("observed", "PASS"), ("not observed", "BLOCKED"),
                                                    ("failed", "FAIL")), "ledger status")
        require(row["command"] and (row["reason"] or row["evidence_file"]), "ledger evidence/command missing")
        if row["status"] != "observed":
            continue
        try:
            validate_observed(row)
        except StaleEvidence:
            require(allow_stale, "observed build_id is stale")
            row.update(status="not observed", outcome="BLOCKED", evidence_file="", reason="observed build_id is stale")
    return rows


# The F1 corpus worker is a host (glibc) build; a musl cell would need its
# own musl-prepared corpus, so it stays BLOCKED rather than borrow glibc runs.
MUSL_PYTEST = "F1 corpus pytest runs the host glibc worker; no musl-prepared corpus for this cell"


def musl_target(command):
    """The --target value of a cargo command, or None for a native build."""
    values = [b for a, b in pairs(command) if a == "--target"]
    return values[0] if len(values) == 1 else None


class StaleEvidence(ValueError):
    pass


def validate_observed(row, saved=None):
    """PASS needs complete identity, host, command, exit code and raw output."""
    if saved is None:
        evidence_path = ROOT / row["evidence_file"]
        require(row["evidence_file"] and not Path(row["evidence_file"]).is_absolute() and evidence_path.is_file(),
                "observed evidence unavailable")
        saved = json.loads(evidence_path.read_text())
    require(saved.get("schema_version") == 1, "evidence schema")
    matches = [r for r in saved["results"] if r.get("case") == row["case"] and r.get("arch") == row["arch"]
               and r.get("evidence", {}).get("environment") == row["environment"]]
    require(len(matches) == 1, "observed evidence mismatch")
    result = matches[0]
    for key in ("build_id", "source_hash", "lock_hash", "table_hash", "platform", "kernel", "libc", "arch"):
        require(isinstance(result.get(key), str) and result[key], "missing " + key)
    if (result["build_id"], result["source_hash"], result["lock_hash"], result["table_hash"]) != (
            build_id(row["case"]), source_hash(row["case"]), lock_hash(), table_hash()):
        raise StaleEvidence("observed build_id is stale")
    require(result["platform"] == ("Darwin" if row["environment"].startswith("macos") else "Linux"),
            "wrong native platform")
    require(result["arch"] == row["arch"], "wrong architecture")
    if result["platform"] == "Linux":
        major, minor = map(int, re.match(r"(\d+)\.(\d+)", result["kernel"]).groups())
        require((major, minor) >= LINUX_FLOOR, "kernel below the collection floor")
    require(row["outcome"] == "PASS" and result.get("outcome") == "PASS", "unexpected observed failure")
    cell = result["evidence"].get("cells", {}).get(row["cell"])
    require(cell and cell["outcome"] == "PASS", "observed cell missing")
    # Re-derive the cell from the raw runs (command, returncode, stdout);
    # never trust the stored verdict.
    runs = result["evidence"].get("runs", [])
    musl = row["environment"] == "linux-musl"
    # 이것을 실패시키는 것: glibc 실행(--target 없음)이나 glibc libc 기록을
    # linux-musl 셀로 다시 붙이는 것, 또는 musl 실행을 glibc 셀로 붙이는 것.
    require(("musl" in result["libc"]) is musl, "libc does not match the cell")
    for probe in platform_probes(row["case"], row["cell"], result["platform"]):
        if isinstance(probe, Rust):
            found = [r for r in runs if r["command"][:2] == ["cargo", "test"]
                     and ["-p", probe.package] in pairs(r["command"])
                     and ["--test", probe.target] in pairs(r["command"])
                     and ["--exact", probe.module + probe.name] in pairs(r["command"])]
            require(len(found) == 1, "raw run missing for " + probe.name)
            target = musl_target(found[0]["command"])
            require(target == (f"{row['arch']}-unknown-linux-musl" if musl else None),
                    "run target does not match the cell: " + str(target))
            check_rust(probe, found[0])
        elif isinstance(probe, Pytest):
            require(not musl, MUSL_PYTEST)
            found = [r for r in runs if probe.node in r["command"]]
            require(found, "raw run missing for " + probe.node)
            check_pytest(probe, found[0])
        else:
            found = [r for r in runs if "docker" in r["command"][:1]]
            require(found, "raw container run missing")
            check_docker(found[-1])
    return result


def pairs(command):
    return [command[i:i + 2] for i in range(len(command) - 1)]


def write_ledger(path, rows):
    """Keep the other runner's rows unchanged; replace only this runner's."""
    all_rows = list(csv.DictReader((HERE / LEDGER).open(), delimiter="\t"))
    mine = {(r["case"], r["environment"], r["arch"], r["cell"]): r for r in rows}
    merged = [mine.get((r["case"], r["environment"], r["arch"], r["cell"]), r) for r in all_rows]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(merged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=(*CASES, "all"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ledger-out", type=Path)
    parser.add_argument("--require-environment", help="fail if the measured environment differs")
    parser.add_argument("--target", help="native musl target for the Rust probes")
    parser.add_argument("--image", default="debian:bookworm-slim", help="local image for X-15 (never pulled)")
    # The F1 pytest cells need a Python with the hash-pinned test requirements.
    parser.add_argument("--python", help="interpreter for the pytest probes (default BINGSU_PROBE_PYTHON or this one)")
    args = parser.parse_args()
    global PYTHON
    PYTHON = args.python or PYTHON
    if args.ledger_out and args.ledger_out.resolve() == (HERE / LEDGER).resolve():
        parser.error("use a separate output ledger")
    try:
        rows = ledger_rows(allow_stale=True)
    except (ValueError, KeyError, OSError) as error:
        print(f"BLOCKED: {error}")
        return 2
    results = [execute_case(case, args.target, args.image) for case in (CASES if args.case == "all" else [args.case])]
    for result in results:
        if (args.require_environment and result.outcome != "BLOCKED"
                and result.evidence.get("environment") != args.require_environment):
            result.outcome = "FAIL"
            result.evidence["reason"] = "required environment not observed"
        print(result.case, result.outcome, result.evidence.get("environment", result.evidence.get("reason", "")))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"schema_version": 1, "results": [asdict(r) for r in results]}, indent=2)
    data = data.replace(str(ROOT), "<checkout>")
    data = re.sub(r"(?:/private)?/var/folders/[^\s\"']+", "<temporary>", data)
    data = re.sub(r"/tmp/m3c-probes-[^/\s\"']+", "<temporary>", data)
    args.out.write_text(data + "\n")
    for row in rows:
        for r in results:
            if (row["case"], row["environment"], row["arch"]) != (r.case, r.evidence.get("environment"), r.arch):
                continue
            cell = r.evidence.get("cells", {}).get(row["cell"], {"outcome": r.outcome, "evidence": []})
            reasons = [e.get("blocked") or e.get("failed") for e in cell["evidence"] if "blocked" in e or "failed" in e]
            row.update(status={"PASS": "observed", "FAIL": "failed", "BLOCKED": "not observed"}[cell["outcome"]],
                       outcome=cell["outcome"], evidence_file=os.path.relpath(args.out, ROOT),
                       reason="; ".join(reasons) or r.evidence.get("reason", ""))
    if args.ledger_out:
        write_ledger(args.ledger_out, rows)
    if any(r.outcome == "FAIL" for r in results):
        return 1
    if any(r.outcome == "BLOCKED" for r in results) or (args.case == "all" and any(r["outcome"] != "PASS" for r in rows)):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
