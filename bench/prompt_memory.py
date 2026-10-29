#!/usr/bin/env python3
"""M3d D5: whole-prompt peak RSS across the prompt's process tree.

One sample is one prompt of a real install hook, traced by
`probes/prompt-memtrace.c`. The boundary is every process the hook creates
for that prompt over its whole life: the command-substitution shell, the
front, children before and after exec, the helper and the collector. The
already running shell is outside.

The measurer certifies only what it can prove. Each task's terminal wait4
`ru_maxrss` plus the counter error E is the upper-bound candidate; it becomes
`rss_upper_bytes` only when every proof obligation of the D0 record holds for
the sample, and stays in the raw evidence otherwise. The lower bound needs the
vfork-inherited high-water separated, which no check here does, so it is
always None. cgroup `memory.peak` and macOS footprint are diagnostics and
never feed either bound. macOS has no method that meets the criteria (D0).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[1]
PROBES = ROOT / "bench/probes"
SHELLS = ("bash", "zsh", "fish")
ROUNDS = 200
TIMEOUT_MS = 10_000
START, END = "BINGSU_D5_START", "BINGSU_D5_END"
PROCESS_KINDS = ("fork", "vfork", "clone")
METHOD = "linux ptrace: terminal wait4 ru_maxrss per thread group + percpu counter error E per process"
# Kernel builds whose source the D0 record and this task read (Ubuntu-6.8.0-117.117).
AUDITED_KERNELS = frozenset({"6.8.0-117-generic"})
# Cumulative /proc/vmstat events that a sample requires unchanged. Reclaim and
# migration are other mutators of a process's address space; THP collapse and
# split, and the OOM reaper, lower RSS without updating the high-water mark.
QUIET_EVENTS = ("pgscan_kswapd", "pgscan_direct", "pgscan_khugepaged", "pgsteal_kswapd", "pgsteal_direct",
                "pgsteal_khugepaged", "pgmigrate_success", "pgmigrate_fail", "thp_migration_success",
                "thp_collapse_alloc", "thp_file_mapped", "thp_split_pmd", "thp_split_page", "oom_kill",
                "pswpout", "ksm_swpin_copy")
# Proof gaps the per-sample checks cannot close on any host this task reached.
# Every one must be present and proven for an upper bound; a missing entry
# counts as open.
UPPER_OBLIGATIONS = ("lifetime_upper", "serial_mutation", "trace_perturbation", "controls")
OPEN_LIFETIME = ("uprobe page replacement (kernel/events/uprobes.c:199,202) is not excluded: listing registered "
                 "uprobes needs tracefs as root", "decrease sites outside mm, kernel, fs, include, lib, arch/arm64 "
                 "and arch/x86 (drivers and others) were not audited")
OPEN_LOWER = "vfork-inherited high-water (grow-release-spawn) and reaped-child cmaxrss are not separated"
OPEN_PERTURBATION = ("no proof that a traced prompt allocates at least what an untraced one does; the per-sample "
                     "checks only show the same roles ran and exited cleanly")
OPEN_CONTROLS = "shell processes in the command-substitution control have reference points, not a constructed peak"


class ProcessPeak(TypedDict):
    role: str
    pid: int
    peak_bytes: int | None


class Diagnostic(TypedDict):
    cgroup_peak_bytes: int | None
    footprint_bytes: dict[str, int | None]


class PromptMemory(TypedDict):
    metric: str
    method: str
    rss_upper_bytes: int | None
    rss_lower_bytes: int | None
    per_process_peak: list[ProcessPeak]
    diagnostic: Diagnostic
    complete: bool
    reason: str | None


def counter_error_bytes(cpus: int, page: int) -> int:
    """Largest amount one get_mm_rss read can miss: three rss_stat counters,
    each CPU's local delta below the batch max(32, 2 * cpus)
    (lib/percpu_counter.c:228, include/linux/mm.h:2659-2712)."""
    if cpus < 1 or page < 1:
        raise ValueError("cpu count and page size must be positive")
    return 3 * cpus * (max(32, 2 * cpus) - 1) * page


def online_cpus(text: str) -> int:
    count = 0
    for part in text.strip().split(","):
        lo, _, hi = part.partition("-")
        count += int(hi or lo) - int(lo) + 1
    return count


def load_trace(text: str) -> list[dict]:
    events = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not events or events[0]["ev"] != "root":
        raise ValueError("trace has no root event")
    return events


def _group(events):
    """Thread groups keyed by tgid with their tasks, spawn edges and records."""
    root = events[0]["pid"]
    tasks = {root: {"tid": root, "spawn": None}}
    for e in events:
        if e["ev"] == "spawn":
            tasks[e["child"]] = {"tid": e["child"], "spawn": e}
    tgid = {root: root}
    for e in events:
        if e["ev"] in ("start_ref", "exec_ref", "mark_ref", "exit_ref") and e.get("tgid", -1) > 0:
            tgid.setdefault(e["pid"], e["tgid"])
    for tid, task in tasks.items():
        spawn = task["spawn"]
        if spawn and spawn["kind"] in ("fork", "vfork"):
            tgid[tid] = tid
    return root, tasks, tgid


def inconsistencies(events: list[dict]) -> list[str]:
    """Cross-checks of the tracer's records before any boundary is drawn: a
    spawn's parent must be the thread group of the task that reported it, a
    task's thread group must be one value that fits how it was made, an exec
    must come from the reported task itself under its own group, and exec
    reference points need their exec event. Runs on the whole trace, so a
    task that cannot be placed blocks the sample wherever it would fall."""
    root, tasks, tgid = _group(events)
    found = []
    seen = {}
    for e in events:
        if e["ev"] in ("start_ref", "exec_ref", "mark_ref", "exit_ref"):
            seen.setdefault(e["pid"], set()).add(e.get("tgid", -1))
    for pid, values in seen.items():
        if len(values) != 1 or min(values) <= 0:
            found.append(f"pid {pid}: thread group read as {sorted(values)}")
    for e in events:
        if e["ev"] != "spawn":
            continue
        spawner = tgid.get(e["pid"])
        if e["parent_tgid"] <= 0 or spawner is None or e["parent_tgid"] != spawner:
            found.append(f"spawn of {e['child']}: parent {e['parent_tgid']} is not the group of task {e['pid']} ({spawner})")
        child = seen.get(e["child"], set())
        if e["kind"] in ("fork", "vfork") and child - {e["child"]}:
            found.append(f"{e['kind']} child {e['child']} joined thread group {sorted(child)}")
        if e["kind"] == "clone" and child - {e["child"], spawner}:
            found.append(f"clone child {e['child']} joined an unrelated thread group {sorted(child)}")
    # Over the whole trace, before any boundary: an exec makes the task its
    # own thread group leader (fs/exec.c de_thread), so it must be reported
    # under its own pid, and every record of that pid must name that group.
    for e in events:
        if e["ev"] != "exec":
            continue
        if e.get("former", e["pid"]) != e["pid"]:
            found.append(f"exec by task {e['former']} reported as pid {e['pid']} (non-leader exec)")
        if seen.get(e["pid"], {e["pid"]}) != {e["pid"]}:
            found.append(f"exec'd task {e['pid']} recorded in thread group {sorted(seen[e['pid']])}")
    execs = {e["pid"] for e in events if e["ev"] == "exec"}
    for pid in sorted({e["pid"] for e in events if e["ev"] == "exec_ref"} - execs):
        found.append(f"pid {pid}: exec reference point without its exec event")
    return found


def processes(events: list[dict]) -> dict[int, dict]:
    root, tasks, tgid = _group(events)
    groups = {}
    for tid, task in tasks.items():
        g = tgid.get(tid)
        if g is None:
            # A task that never stopped where its thread group is readable.
            groups.setdefault(-tid, {"tgid": -tid, "tids": [tid], "unknown": True})
            continue
        group = groups.setdefault(g, {"tgid": g, "tids": [], "unknown": False})
        group["tids"].append(tid)
    for g in groups.values():
        leader = tasks.get(g["tgid"])
        spawn = leader["spawn"] if leader else None
        g.update(spawn=spawn, parent=spawn["parent_tgid"] if spawn else None,
                 kind=spawn["kind"] if spawn else ("root" if g["tgid"] == root else None),
                 parent_threads=spawn["parent_threads"] if spawn else None,
                 execs=[], refs=[], reaped={})
    for e in events:
        if e["ev"] == "exec" and e["pid"] in groups:
            groups[e["pid"]]["execs"].append(e)
        elif e["ev"] in ("start_ref", "exec_ref", "mark_ref", "exit_ref"):
            g = tgid.get(e["pid"])
            if g in groups:
                groups[g]["refs"].append(e)
        elif e["ev"] == "reaped":
            g = tgid.get(e["pid"])
            if g in groups:
                groups[g]["reaped"][e["pid"]] = e
    return groups


def role(group: dict) -> str:
    if group["execs"]:
        last = group["execs"][-1]
        argv = last.get("argv", [])
        if Path(last["exe"]).name == "bingsu-collect":
            return "collector"
        second = argv[1] if len(argv) > 1 else None
        if second == "prompt":
            return "front"
        if second == "__refresh-v1":
            return "helper"
        return "other:" + Path(last["exe"]).name
    return "subshell" if group["kind"] == "fork" else "pre-exec:" + str(group["kind"])


def boundary(events: list[dict], groups: dict[int, dict]) -> list[int]:
    """Thread groups the top shell created between the start and end markers,
    and all their descendants; the markers themselves are outside."""
    root = events[0]["pid"]
    marker = {}
    for g in groups.values():
        for e in g["execs"]:
            for word in e.get("argv", []):
                if word in (START, END):
                    marker[word] = g
    if set(marker) != {START, END}:
        raise ValueError("trace lacks the prompt markers")
    lo, hi = marker[START]["spawn"]["seq"], marker[END]["spawn"]["seq"]
    # Threads join their group, so every group but the root is a process,
    # whatever clone flavour made it.
    inside = {g["tgid"] for g in groups.values() if g["parent"] == root and g["kind"] in PROCESS_KINDS
              and lo < g["spawn"]["seq"] < hi}
    grew = True
    while grew:
        grew = False
        for g in groups.values():
            if g["tgid"] not in inside and g["parent"] in inside and g["kind"] in PROCESS_KINDS:
                inside.add(g["tgid"])
                grew = True
    return sorted(inside)


def observation(events: list[dict]) -> dict:
    """Per-process peaks and the completeness verdict of one traced prompt.
    The process list is the tracer's own spawn/exec/reap stream."""
    groups = processes(events)
    end = events[-1]
    problems = []
    if end["ev"] != "end" or end.get("timed_out") or end.get("live"):
        problems.append("trace did not end with every tracee reaped")
    if any(e["ev"] == "overflow" for e in events):
        problems.append("tracer task table overflowed")
    children = [e["child"] for e in events if e["ev"] == "spawn"]
    if len(children) != len(set(children)) or events[0]["pid"] in children:
        problems.append("a pid was reused inside one trace")
    spawned = {events[0]["pid"]} | set(children)
    stray = sorted({e["pid"] for e in events if e["ev"] in ("reaped", "exec", "start_ref", "exit_ref", "mark_ref")} - spawned)
    if stray:
        problems.append(f"tasks without a spawn event: {stray}")
    problems += inconsistencies(events)
    # A task whose thread group is unknown cannot be placed inside or outside.
    unplaced = sorted(t for g in groups.values() if g["unknown"] for t in g["tids"])
    if unplaced:
        problems.append(f"tasks without a readable thread group: {unplaced}")
    inside = boundary(events, groups)
    peaks, rows = [], []
    for tgid in inside:
        g = groups[tgid]
        leader = g["reaped"].get(tgid)
        missing = [t for t in g["tids"] if t not in g["reaped"]]
        late = [t for t in g["tids"] if t != tgid and t in g["reaped"] and leader and g["reaped"][t]["seq"] > leader["seq"]]
        peak = None
        if missing:
            problems.append(f"pid {tgid}: no terminal record for {missing}")
        elif late:
            problems.append(f"pid {tgid}: thread records after the group leader {late}")
        else:
            peak = leader["maxrss_kb"] * 1024
        name = role(g)
        threads = max([len(g["tids"])] + [e.get("threads", 0) for e in g["refs"]])
        rows.append({"role": name, "pid": tgid, "peak_bytes": peak, "threads": threads, "kind": g["kind"],
                     "parent_threads": g["parent_threads"],
                     "pre_exec_bytes": max([e["rollup_rss_kb"] * 1024 for e in g["refs"] if e["ev"] == "start_ref"], default=None),
                     "truth_bytes": max([e["rollup_rss_kb"] for e in g["refs"] if e.get("rollup_rss_kb", -1) >= 0], default=-1) * 1024,
                     "file_pmd_kb": max([e.get("file_pmd_kb", 0) for e in g["refs"]], default=0),
                     "exit": {k: leader[k] for k in ("exited", "code", "signal")} if leader else None})
        peaks.append(ProcessPeak(role=name, pid=tgid, peak_bytes=peak))
    if not inside:
        problems.append("no process inside the prompt boundary")
    return {"per_process_peak": peaks, "rows": rows, "complete": not problems, "problems": problems}


def candidate_upper_bytes(peaks: list[ProcessPeak], error: int) -> int | None:
    if not peaks or any(p["peak_bytes"] is None for p in peaks):
        return None
    return sum(p["peak_bytes"] for p in peaks) + len(peaks) * error


def _read(path):
    try:
        return Path(path).read_text()
    except OSError:
        return None


def host_counters() -> dict:
    vmstat = {}
    for line in (_read("/proc/vmstat") or "").splitlines():
        name, _, value = line.partition(" ")
        vmstat[name] = int(value)
    mm = "/sys/kernel/mm/"
    peak = _read("/sys/fs/cgroup/memory.peak")
    return {"kernel": platform.release(), "arch": platform.machine(), "page": os.sysconf("SC_PAGE_SIZE"),
            "cpus_online": (_read("/sys/devices/system/cpu/online") or "").strip(),
            "vmstat": {k: vmstat.get(k) for k in QUIET_EVENTS},
            "ksm_run": (_read(mm + "ksm/run") or "absent").strip(),
            "ksm_full_scans": (_read(mm + "ksm/full_scans") or "absent").strip(),
            "khugepaged_pages_collapsed": (_read(mm + "transparent_hugepage/khugepaged/pages_collapsed") or "absent").strip(),
            "numa_balancing": (_read("/proc/sys/kernel/numa_balancing") or "absent").strip(),
            "damon_reclaim": (_read("/sys/module/damon_reclaim/parameters/enabled") or "absent").strip(),
            "damon_sysfs": Path(mm + "damon").exists(),
            "swaps": len((_read("/proc/swaps") or "").splitlines()[1:]),
            "cgroup_peak_bytes": int(peak) if peak and peak.strip().isdigit() else None}


def obligations(before: dict, after: dict, obs: dict) -> dict:
    """The five D0 proof obligations for one sample. A check that cannot run
    is open; an open obligation keeps the sample uncertified."""
    host = []
    if before["kernel"] not in AUDITED_KERNELS or after["kernel"] != before["kernel"]:
        host.append(f"kernel {before['kernel']} is not a source-audited build")
    if before["cpus_online"] != after["cpus_online"] or not before["cpus_online"]:
        host.append("online CPU set changed or unreadable")
    moved = [k for k in QUIET_EVENTS if before["vmstat"].get(k) is None or before["vmstat"][k] != after["vmstat"].get(k)]
    if moved:
        host.append(f"vmstat events moved or missing: {moved}")
    for key, quiet in (("ksm_run", ("0", "absent")), ("numa_balancing", ("0", "absent")), ("damon_reclaim", ("N", "absent"))):
        if before[key] not in quiet or after[key] != before[key]:
            host.append(f"{key}={before[key]}->{after[key]}")
    for key in ("ksm_full_scans", "khugepaged_pages_collapsed"):
        if after[key] != before[key]:
            host.append(f"{key} moved")
    if before["damon_sysfs"]:
        host.append("DAMON sysfs present; kdamond state not checked")
    if before["swaps"]:
        host.append("swap is enabled")
    pmd = [r["pid"] for r in obs["rows"] if r["file_pmd_kb"]]
    if pmd:
        host.append(f"file PMD mappings in {pmd}")
    lifetime_gaps = host + list(OPEN_LIFETIME)
    concurrent = [f"{r['role']} pid {r['pid']} had {r['threads']} threads" for r in obs["rows"] if r["threads"] != 1]
    concurrent += [f"{r['role']} pid {r['pid']} shared a parent address space with {r['parent_threads']} threads"
                   for r in obs["rows"] if r["kind"] == "vfork" and r["parent_threads"] != 1]
    serial_gaps = host + concurrent
    perturbed = [f"{r['role']} pid {r['pid']} ended {r['exit']}" for r in obs["rows"]
                 if r["role"] in ("front", "helper", "collector") and r["exit"] != {"exited": 1, "code": 0, "signal": 0}]
    roles = {r["role"] for r in obs["rows"]}
    if not {"front", "helper"} <= roles:
        perturbed.append(f"engine roles missing: {sorted({'front', 'helper'} - roles)}")
    def status(gaps):
        return {"status": "proven" if not gaps else "open", "gaps": gaps}
    return {"lifetime_upper": status(lifetime_gaps), "serial_mutation": status(serial_gaps),
            "lower_bound": status([OPEN_LOWER]), "trace_perturbation": status(perturbed + [OPEN_PERTURBATION]),
            "controls": status([OPEN_CONTROLS])}


def certify(obs: dict, proofs: dict, error: int, diagnostic: Diagnostic, method: str) -> PromptMemory:
    """The only place a bound is issued. The upper bound needs a complete
    observation and every obligation except the lower bound's proven; the
    lower bound needs its own. Diagnostics are never read here."""
    upper = lower = None
    reason = None
    candidate = candidate_upper_bytes(obs["per_process_peak"], error)
    if not obs["complete"]:
        reason = "incomplete: " + "; ".join(obs["problems"])
    else:
        def gaps(name):
            return ", ".join(proofs[name]["gaps"]) if name in proofs else "obligation not evaluated"
        open_upper = [n for n in UPPER_OBLIGATIONS if proofs.get(n, {}).get("status") != "proven"]
        if open_upper:
            reason = "BLOCKED: open proof obligations " + "; ".join(f"{n}: {gaps(n)}" for n in open_upper)
        else:
            upper = candidate
        if proofs.get("lower_bound", {}).get("status") == "proven" and upper is not None:
            lower = max(p["peak_bytes"] for p in obs["per_process_peak"]) - error
        elif upper is not None:
            reason = "lower bound BLOCKED: " + gaps("lower_bound")
    return PromptMemory(metric="rss", method=method, rss_upper_bytes=upper, rss_lower_bytes=lower,
                        per_process_peak=obs["per_process_peak"], diagnostic=diagnostic,
                        complete=obs["complete"], reason=reason)


def verdict(memory: PromptMemory, hypothesis_bytes: int) -> str:
    """D5 rule: upper at or under the hypothesis meets it, lower over it exceeds
    it, anything between is undecided (U6). No certified upper is BLOCKED."""
    if memory["rss_upper_bytes"] is None:
        return "BLOCKED"
    if memory["rss_upper_bytes"] <= hypothesis_bytes:
        return "meets"
    if memory["rss_lower_bytes"] is not None and memory["rss_lower_bytes"] > hypothesis_bytes:
        return "exceeds"
    return "undecided"


def blocked(reason: str, method: str = METHOD) -> PromptMemory:
    return PromptMemory(metric="rss", method=method, rss_upper_bytes=None, rss_lower_bytes=None, per_process_peak=[],
                        diagnostic=Diagnostic(cgroup_peak_bytes=None, footprint_bytes={}), complete=False, reason=reason)


def build_tools(directory: Path) -> dict[str, Path]:
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise ValueError("the tracer needs a C compiler")
    directory.mkdir(parents=True, exist_ok=True)
    tools = {}
    for name, source in (("tracer", "prompt-memtrace.c"), ("controls", "memory-controls.c")):
        tools[name] = directory / name
        subprocess.run([cc, "-O2", "-Wall", "-Werror", "-o", str(tools[name]), str(PROBES / source)],
                       check=True, capture_output=True, timeout=120)
    return tools


def trace(tracer: Path, command: list[str], out: Path, *, env=None, timeout_ms=TIMEOUT_MS):
    result = subprocess.run([str(tracer), str(out), str(timeout_ms), *command], env=env,
                            capture_output=True, timeout=timeout_ms / 1000 + 30)
    return result, out.read_text()


HOOK = {
    "bash": ("bash", ["--norc", "--noprofile"], '. {init}\ncd {repo} || exit 9\nCOLUMNS=80\n/bin/true {start}\n'
             'for _c in "${{PROMPT_COMMAND[@]}}"; do eval "$_c"; done\n/bin/true {end}\n'
             'printf "REC%s\\n" "$_bingsu_rec" >&2\n'),
    "zsh": ("zsh", ["-f"], '. {init}\ncd {repo} || exit 9\nCOLUMNS=80\n/bin/true {start}\n'
            'for _f in $precmd_functions; do $_f; done\n/bin/true {end}\nprint -r -- "REC$_bingsu_rec" >&2\n'),
    "fish": ("fish", ["--no-config"], 'source {init}\ncd {repo}; or exit 9\n/bin/true {start}\n'
             'fish_prompt >/dev/null\n/bin/true {end}\nprintf "REC%s\\n" "$_bingsu_rec" >&2\n'),
}


def _engine_alive(paths) -> bool:
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                if os.readlink(proc / "exe") in paths:
                    return True
            except OSError:
                pass
    return False


def quiesce(binary: Path, timeout_s: float = 10.0):
    """Waits (condition polling) until no front, helper or collector runs, so
    the next prompt does not meet the previous prompt's helper."""
    paths = {str(binary), str(binary.with_name("bingsu-collect"))}
    end = time.monotonic() + timeout_s
    while _engine_alive(paths):
        if time.monotonic() > end:
            raise ValueError("engine processes still running before the sample")
        time.sleep(0.01)


def default_scratch() -> Path:
    """Outside any checkout: a no-git case under the checkout would discover
    the checkout's own repository before reaching the pinned home."""
    path = Path(os.environ.get("BINGSU_D5_SCRATCH") or Path.home() / ".cache/bingsu-d5")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def enclosing_repository(path: Path) -> str | None:
    """The hook pins the passwd home, so discovery may walk every ancestor."""
    return next((str(p) for p in Path(path).parents if (p / ".git").exists()), None)


def prepare_prompt(binary: Path, case: str, shell: str, directory: Path) -> dict:
    """An isolated install of the real hook for one case. The hook pins the
    passwd home; the XDG roots are private folders next to the case."""
    spec = importlib.util.spec_from_file_location("d5_git_product", ROOT / "bench/git-product.py")
    git_product = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(git_product)
    home = directory / "home"
    home.mkdir(mode=0o700, parents=True)
    repo = git_product.repository(home, case)
    if case == "no-git" and enclosing_repository(repo):
        raise ValueError(f"no-git case sits inside a repository: {enclosing_repository(repo)}")
    # An 80-column terminal: without COLUMNS the hooks pass width 0 and the
    # front draws an empty record, which is not a prompt anyone sees.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8", "HOME": str(home), "COLUMNS": "80"}
    for key, name in (("XDG_CONFIG_HOME", "config"), ("XDG_STATE_HOME", "state"),
                      ("XDG_RUNTIME_DIR", "runtime"), ("XDG_CACHE_HOME", "cache")):
        path = directory / name
        path.mkdir(mode=0o700)
        env[key] = str(path)
    (directory / "config/bingsu").mkdir(mode=0o700)
    (directory / "config/bingsu/config.toml").write_text("icons = 'ascii'\n")
    init = subprocess.run([str(binary), "init", shell], env=env, capture_output=True, timeout=30)
    if init.returncode != 0 or not init.stdout:
        raise ValueError(f"init {shell} failed: {init.stderr.decode(errors='replace')[:500]}")
    (directory / ("init." + shell)).write_bytes(init.stdout)
    program, flags, body = HOOK[shell]
    script = directory / ("prompt." + shell)
    script.write_text(body.format(init=directory / ("init." + shell), repo=repo, start=START, end=END))
    resolved = shutil.which(program, path=env["PATH"])
    if resolved is None:
        raise ValueError(f"{shell} is not installed")
    return {"command": [resolved, *flags, str(script)], "env": env, "repo": str(repo)}


def record_problem(returncode: int, stderr: bytes) -> str | None:
    """The traced prompt must have drawn a record: the script prints REC and
    the record's first bytes; a dead or empty hook is a missing sample."""
    if returncode != 0:
        return f"prompt script exited {returncode}"
    if b"REC" not in stderr or stderr.split(b"REC", 1)[1][:1] in (b"\n", b""):
        return "prompt produced no record"
    return None


def observe_prompt_memory(binary: str, case: str, *, shell: str = "bash", tools: dict | None = None,
                          prepared: dict | None = None, scratch: Path | None = None) -> tuple[PromptMemory, dict]:
    """One traced prompt: the PromptMemory and the raw evidence it came from."""
    method = f"{METHOD}; shell {shell}"
    if platform.system() != "Linux":
        return blocked(f"BLOCKED: {platform.system()} RSS has no method meeting the three criteria (D0)", method), {}
    if shell not in HOOK:
        raise ValueError("unknown shell")
    binary = Path(binary).resolve()
    owned = None
    if tools is None or prepared is None:
        owned = tempfile.TemporaryDirectory(prefix="d5-memory-", dir=scratch or default_scratch())
        base = Path(owned.name)
        tools = tools or build_tools(base / "tools")
        prepared = prepared or prepare_prompt(binary, case, shell, base / "prompt")
        warm(binary, prepared)
    try:
        quiesce(binary)
        before = host_counters()
        with tempfile.TemporaryDirectory(prefix="d5-trace-", dir=scratch or default_scratch()) as out:
            result, text = trace(tools["tracer"], prepared["command"], Path(out) / "trace.jsonl", env=prepared["env"])
        after = host_counters()
        events = load_trace(text)
        obs = observation(events)
        problem = record_problem(result.returncode, result.stderr)
        if problem:
            obs["complete"] = False
            obs["problems"].append(problem)
        cpus = online_cpus(before["cpus_online"]) if before["cpus_online"] else 0
        error = counter_error_bytes(cpus, before["page"]) if cpus else 0
        proofs = obligations(before, after, obs)
        # The readable memory.peak is the container cgroup's peak since its
        # creation, not this prompt's; a per-prompt value needs a fresh child
        # cgroup, which takes privileges this measurer does not have.
        diagnostic = Diagnostic(cgroup_peak_bytes=None, footprint_bytes={})
        memory = certify(obs, proofs, error, diagnostic, method)
        evidence = {"case": case, "shell": shell, "counter_error_bytes": error,
                    "container_cgroup_peak_bytes": after["cgroup_peak_bytes"],
                    "candidate_upper_bytes": candidate_upper_bytes(obs["per_process_peak"], error),
                    "rows": obs["rows"], "problems": obs["problems"], "obligations": proofs,
                    "host_before": before, "host_after": after, "trace": events}
        return memory, evidence
    finally:
        if owned is not None:
            owned.cleanup()


def measure_prompt_memory(binary: str, case: str, *, shell: str = "bash") -> PromptMemory:
    return observe_prompt_memory(binary, case, shell=shell)[0]


def warm(binary: Path, prepared: dict, prompts: int = 2):
    """Untraced prompts first: the snapshot is published and the folder has a
    response, so traced samples meet a warm product (spec warm condition)."""
    for _ in range(prompts):
        quiesce(binary)
        subprocess.run(prepared["command"], env=prepared["env"], capture_output=True, timeout=30)


def measure_row(binary: str, case: str, rounds: int = ROUNDS, *, shell: str = "bash", scratch: Path | None = None) -> dict:
    """At least 200 traced prompts of one case. Fewer than `rounds` complete
    samples make the row BLOCKED; a certified bound needs every sample's."""
    if rounds < ROUNDS:
        raise ValueError("a memory row needs at least 200 prompts")
    if platform.system() != "Linux":
        return {"status": "BLOCKED", "case": case, "shell": shell,
                "reason": f"{platform.system()} RSS has no method meeting the three criteria (D0)", "samples": []}
    binary = Path(binary).resolve()
    with tempfile.TemporaryDirectory(prefix="d5-row-", dir=scratch or default_scratch()) as base:
        base = Path(base)
        tools = build_tools(base / "tools")
        prepared = prepare_prompt(binary, case, shell, base / "prompt")
        warm(binary, prepared)
        samples = []
        for _ in range(rounds):
            try:
                memory, evidence = observe_prompt_memory(str(binary), case, shell=shell, tools=tools, prepared=prepared,
                                                         scratch=base)
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                memory, evidence = blocked(f"incomplete: {error}"), {}
            evidence.pop("trace", None)
            samples.append({"memory": memory, "evidence": evidence})
        publication = publication_check(binary, prepared, tools, base)
    row = summarize_row(case, shell, rounds, samples)
    row["publication_check"] = publication
    return row


def record_of(stderr: bytes) -> bytes:
    return stderr.split(b"REC", 1)[1] if b"REC" in stderr else b""


def publication_check(binary: Path, prepared: dict, tools: dict, scratch: Path, pairs: int = 20) -> dict:
    """Tracing must not change what the prompt publishes. After each traced
    and each untraced prompt, an untraced prompt draws the record the
    published snapshot and folder response produce; the two sets must match.
    This is evidence for the perturbation obligation, not its proof."""
    seen = {"untraced": {}, "traced": {}}
    for _ in range(pairs):
        for mode in seen:
            quiesce(binary)
            if mode == "traced":
                trace(tools["tracer"], prepared["command"], scratch / "publication.jsonl", env=prepared["env"])
            else:
                subprocess.run(prepared["command"], env=prepared["env"], capture_output=True, timeout=30)
            quiesce(binary)
            after = subprocess.run(prepared["command"], env=prepared["env"], capture_output=True, timeout=30)
            key = hashlib.sha256(record_of(after.stderr)).hexdigest()
            seen[mode][key] = seen[mode].get(key, 0) + 1
    return {"pairs": pairs, **seen, "same": same_publication(seen["untraced"], seen["traced"])}


def same_publication(untraced: dict, traced: dict) -> bool:
    return bool(untraced) and set(untraced) == set(traced)


def summarize_row(case: str, shell: str, rounds: int, samples: list[dict]) -> dict:
    complete = [s for s in samples if s["memory"]["complete"]]
    certified = [s for s in complete if s["memory"]["rss_upper_bytes"] is not None]
    candidates = [s["evidence"]["candidate_upper_bytes"] for s in complete
                  if s["evidence"].get("candidate_upper_bytes") is not None]
    row = {"case": case, "shell": shell, "rounds": rounds, "attempted": len(samples), "complete": len(complete),
           "certified": len(certified), "samples": samples,
           "candidate_upper_bytes": {"n": len(candidates), "max": max(candidates, default=None),
                                     "p50": sorted(candidates)[len(candidates) // 2] if candidates else None,
                                     "use": "diagnostic; not a certified bound"}}
    need = max(rounds, ROUNDS)
    if len(complete) < need or len(samples) < need:
        row.update(status="BLOCKED", reason=f"{len(complete)} of {need} samples complete")
    elif len(certified) < len(samples):
        reasons = sorted({s["memory"]["reason"] for s in complete if s["memory"]["rss_upper_bytes"] is None})
        row.update(status="BLOCKED", reason="RSS certification blocked: " + " | ".join(reasons[:3]))
    else:
        row.update(status="OBSERVED", reason=None,
                   rss_upper_bytes=max(s["memory"]["rss_upper_bytes"] for s in certified),
                   rss_lower_bytes=None if any(s["memory"]["rss_lower_bytes"] is None for s in certified)
                   else max(s["memory"]["rss_lower_bytes"] for s in certified))
    return row


CONTROLS = {
    "small": "{ctl} small",
    "anon64": "{ctl} anon64",
    "tree3": "{ctl} tree3",
    "bigparent-spawn": "{ctl} bigparent-spawn",
    "file64": "{ctl} file64 {file}",
    "shared64": "{ctl} shared64",
    "cached-exec": "{ctl} cached-exec >/dev/null; {ctl} cached-exec",
    # The subshell marks itself around the control; the top shell is outside.
    "cmdsubst": 'x=$(kill -STOP $BASHPID; {ctl} anon64; kill -STOP $BASHPID; echo .); echo "$x"',
}


def control(tools: dict, name: str, out: Path, *, file: Path | None = None) -> dict:
    """One control between the prompt markers under the tracer, measured by
    the same observation as a prompt. Truth is each process's largest
    page-table reference point, taken while it was stopped."""
    script = CONTROLS[name].format(ctl=tools["controls"], file=file)
    command = ["bash", "--norc", "--noprofile", "-c", f"/bin/true {START}; {script}; /bin/true {END}; :"]
    result, text = trace(tools["tracer"], command, out)
    return {"rc": result.returncode, "stdout": result.stdout.decode(errors="replace"), "events": load_trace(text)}


def kernel_gate(kernel: str | None = None) -> str | None:
    """Why every row on this host will be BLOCKED before anything runs, if a
    reason is known up front."""
    if platform.system() != "Linux":
        return f"{platform.system()} RSS has no method meeting the three criteria (D0)"
    kernel = kernel or platform.release()
    if kernel not in AUDITED_KERNELS:
        return f"kernel {kernel} is not a source-audited build ({', '.join(sorted(AUDITED_KERNELS))}); lifetime_upper stays open"
    return None


def blocked_lines(value: dict) -> list[str]:
    """One line per BLOCKED row of a git-product memory run: the counts and,
    for each open obligation, how many samples it held back and its first gap."""
    if value.get("status") != "BLOCKED":
        return []
    label = f"prompt memory ({value.get('shell', '?')})"
    if not value.get("cases"):
        return [f"{label}: BLOCKED: {value.get('reason', 'no rows')}"]
    lines = []
    for case, row in value["cases"].items():
        if row.get("status") == "OBSERVED":
            continue
        opened, first = {}, {}
        for sample in row.get("samples", []):
            for name, proof in sample.get("evidence", {}).get("obligations", {}).items():
                if proof["status"] != "proven":
                    opened[name] = opened.get(name, 0) + 1
                    first.setdefault(name, proof["gaps"][0] if proof["gaps"] else "")
        detail = "; ".join(f"{name} open in {count} ({first[name]})" for name, count in opened.items())
        lines.append(f"{label} {case}: BLOCKED, {row.get('complete', 0)}/{row.get('rounds', '?')} complete, "
                     f"{row.get('certified', 0)} certified: {detail or row.get('reason')}")
    return lines


def main(argv: list[str]) -> int:
    """CI report: `--kernel-gate` before measuring, `--summary FILE...` after.
    Each BLOCKED reason becomes an error annotation and a step-summary line."""
    if argv[:1] == ["--kernel-gate"]:
        reason = kernel_gate()
        lines = [f"prompt memory rows will be BLOCKED: {reason}"] if reason else []
    elif argv[:1] == ["--summary"]:
        lines = []
        for name in argv[1:]:
            try:
                lines += blocked_lines(json.loads(Path(name).read_text()))
            except (OSError, ValueError) as error:
                lines.append(f"prompt memory {name}: BLOCKED: unreadable result ({error})")
    else:
        print("usage: prompt_memory.py --kernel-gate | --summary FILE...", file=sys.stderr)
        return 2
    for line in lines:
        print(f"::error title=prompt memory BLOCKED::{line}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and lines:
        with open(summary, "a") as out:
            out.write("".join(f"- {line}\n" for line in lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
