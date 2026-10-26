"""F1 fixed-catalog collection: compiler-free runtime and policy oracles.

Prepare on the host with scripts/prepare_git_corpus.py. Required CI cells fail
when preparation or tracing is absent; the unrelated minimum-shell jobs do
not opt into this host fixture. No Git command ever sees an armed repository.
"""
import csv
import copy
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import statistics
import shutil
import subprocess
import sys
import time

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.attribute import assert_repository_trace

PREPARED = ROOT / "target/git-corpus/prepared.json"
ROWS = list(csv.DictReader((ROOT / "tests/fixtures/git-corpus/manifest.tsv").open(), delimiter="\t"))
CANARIES = {"clean", "smudge", "process", "fsmonitor", "textconv", "external-diff", "hooksPath",
            "credential", "askpass", "editor", "pager", "sshCommand", "submodule", "include", "includeIf",
            "attributes", "excludes", "alternates", "http-alternates", "replace-loose", "replace-packed", "core.worktree"}


@dataclass(frozen=True)
class CorpusCase:
    data: dict

    @property
    def name(self):
        return self.data["case"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def corpus():
    if not PREPARED.is_file() and os.environ.get("BINGSU_GIT_CORPUS_REQUIRED") != "1":
        pytest.skip("host F1 corpus not selected; Dedicated collector requires preparation")
    assert PREPARED.is_file(), "BLOCKED: run scripts/prepare_git_corpus.py on the host"
    manifest = json.loads(PREPARED.read_text())
    for name, expected in manifest["source_hashes"].items():
        assert digest(ROOT / name) == expected, ("stale F1 preparation", name)
    for name, expected in manifest["binary_hashes"].items():
        assert digest(name) == expected, ("stale F1 binary", name)
    assert [c["case"] for c in manifest["cases"]] == [r["case"] for r in ROWS]
    return manifest


def snapshot(paths):
    result = {}
    for root in map(Path, paths):
        for path in [root, *sorted(root.rglob("*"))]:
            st = path.lstat()
            value = os.readlink(path) if path.is_symlink() else digest(path) if path.is_file() else None
            result[str(path)] = (st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns, value)
    return result


def capabilities(case, *, unique=False):
    roots = case.data["roots"]
    ancestors = {"/"}
    for root in roots:
        ancestors.update(str(p) for p in Path(root).parents)
    axes = {"read-layer": {"phase": "read-layer", "roots": len(roots), "root_inputs": len(roots)}} if sys.platform == "linux" else {}
    # F2 refused-pointer seeds end before any read layer; they assert its absence.
    axes = case.data.get("axes", axes)
    return {"roots": roots, "repo": case.data["repo"], "ancestors": sorted(ancestors), "forbidden": [case.data["outside"]],
            "no_open": ([str(Path(case.data["repo"]) / "sub")] if case.name == "gitlink-staged" else []) + case.data.get("no_open", []),
            "no_read": [str(Path(case.data["repo"]) / "tracked")] if case.data["policy"].startswith("filtered") else [],
            "names": [str(Path(case.data["repo"]).parent)] if unique else [], "platform": sys.platform, "axes": axes}


def decode(output, *, require_update=True):
    updates, current, result, display = [], None, None, None
    times, siblings = {}, []
    for line in output.decode().splitlines():
        if line == "F1_UPDATE":
            assert current is None
            current = {}
        elif line.startswith("F1_FIELD "):
            _, name, raw = line.split(" ", 2)
            assert current is not None and name not in current
            if raw.startswith("count:"):
                _, n, saturated = raw.split(":")
                value = int(n) if saturated == "false" else (int(n), "saturated")
            elif raw.startswith("text:"):
                value = bytes.fromhex(raw[5:]).decode()
            elif raw.startswith("bool:"):
                value = raw[5:] == "true"
            else:
                assert raw in {"absent", "pending"}
                value = raw
            current[name] = value
        elif line == "F1_END_UPDATE":
            updates.append(current)
            current = None
        elif line.startswith("F1_RESULT "):
            result = line[10:].rsplit(" ", 1)
        elif line.startswith("F1_DISPLAY "):
            display = bytes.fromhex(line[11:]).decode()
        elif line.startswith("F1_SIBLING "):
            assert int(line.split()[-1]) <= 256
            _, component, complete, count = line.split()
            siblings.append((int(component), complete == "true", int(count)))
        elif line.startswith("F1_TIME "):
            _, phase, ns = line.split()
            times[phase] = int(ns)
    # F2's refused-pointer seeds end before stage A; their effects are still audited.
    assert current is None and (updates or not require_update) and result is not None, output[-4000:]
    return {"updates": updates, "value": updates[-1] if updates else None, "result": result[0], "elapsed_ns": int(result[1]),
            "display": display, "times": times, "siblings": siblings}


def execute(corpus, case, tmp_path, *, mutant=False, timed=False, unique=False, trace=True, require_update=True):
    """Own, drain, kill on error, and reap every child before returning."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    worker = "effect-mutant" if mutant in {"read", "write", "deadline"} else "spawn-mutant" if mutant else "worker"
    binary = corpus["workers"][worker]
    repo = case.data["repo"]
    command = [binary, repo, str(Path(repo).parent if unique else Path(repo)),
               "slow" if timed == "slow" else "timed" if timed else "semantic",
               "unknown" if case.data["policy"] == "unknown" else "known",
               "unique" if unique else "plain", str(mutant), str(Path(case.data["outside"]) / "sentinel")]
    trace_path = tmp_path / "collection.strace"
    env = {}
    if sys.platform == "linux" and trace:
        assert shutil.which("strace"), "BLOCKED: strace is required for the F1 Linux cell"
        command = ["strace", "-f", "-q", "-yy", "-s", "4096", "-o", str(trace_path), *command]
    elif sys.platform == "darwin" and trace:
        env = {"DYLD_INSERT_LIBRARIES": corpus["interposer"]}
    watched = list(dict.fromkeys([repo, *case.data["roots"], case.data["outside"]]))
    before = snapshot(watched)
    read, write_fd = os.pipe()
    lock_path = tmp_path / "lock"
    lock_path.touch(mode=0o600)
    lock = os.open(lock_path, os.O_RDONLY)
    originals = [read, lock]
    if sys.platform == "darwin":
        originals.append(os.open(corpus["probe"], os.O_RDONLY))
    sources = [fcntl.fcntl(fd, fcntl.F_DUPFD, 20) for fd in originals]
    for fd in sources:
        os.set_inheritable(fd, True)

    def setup():
        for source, target in zip(sources, [3, 5, 6]):
            os.dup2(source, target)

    process = None
    output = bytearray()
    seen = []
    sent = False
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, cwd="/", env=env,
                                   close_fds=False, preexec_fn=setup, start_new_session=True)
        for fd in sources:
            os.close(fd)
        sources.clear()
        deadline = time.monotonic() + 10
        while True:
            assert time.monotonic() < deadline, "worker timed out"
            if sys.platform == "darwin" and process.poll() is None:
                from test_collector_no_spawn_macos import children
                seen.extend(children(process.pid))
            if select.select([process.stdout], [], [], 0.002)[0]:
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    break
                output.extend(data)
            if not sent and b"F1_READY " in output and b"\n" in output:
                assert b"AllStages(" in output, ("BLOCKED: kernel read guarantee absent", bytes(output))
                os.write(write_fd, b"x")
                sent = True
        code = process.wait(timeout=2)
        (tmp_path / "worker.log").write_bytes(output)
        if sys.platform == "darwin":
            from test_collector_no_spawn_macos import assert_no_process_effects
            assert_no_process_effects(code, seen)
        assert code != 88, "forbidden file write attempt: interposer exit 88"
        assert code == 0 and sent, ("collector/spawn interposer exit", code, bytes(output[-2000:]))
        assert snapshot(watched) == before, "canary file mutation"
        lines = trace_path.read_text().splitlines() if sys.platform == "linux" and trace else output.decode().splitlines()
        phases = {}
        if trace:
            assert_repository_trace(lines, capabilities(case, unique=unique), phases)
        result = decode(output, require_update=require_update)
        result["phases"] = phases
        (tmp_path / "observations.json").write_text(json.dumps(result, indent=2))
        return result
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
        for fd in [*sources, *originals, write_fd]:
            os.close(fd)


def porcelain_counts(raw):
    counts = dict(staged=0, modified=0, untracked=0, conflicted=0)
    for line in raw.decode().splitlines():
        if line.startswith("? "):
            counts["untracked"] += 1
        elif line.startswith("u "):
            counts["conflicted"] += 1
        elif line.startswith(("1 ", "2 ")):
            xy = line.split()[1]
            counts["staged"] += xy[0] != "."
            counts["modified"] += xy[1] != "."
        else:
            raise AssertionError(("unexpected porcelain row", line))
    return counts


def compare_policy_porcelain(case: CorpusCase, collected: dict) -> None:
    """Explicit deviations; never turn a protection difference into a skip."""
    value = collected["value"]
    expected = porcelain_counts(Path(case.data["porcelain"]).read_bytes())
    policy = case.data["policy"]
    assert collected["updates"][0]["stage"] == "A", case.name
    assert collected["result"] == "Ok(())", (case.name, collected)
    if policy == "a-only":
        assert value["stage"] == "A" and value["partial"] is True, (case.name, value)
        for key in (*expected, "ahead", "behind", "stash", "filtered"):
            assert value[key] == "pending", (case.name, key, value)
        return
    assert value["stage"] == "D", (case.name, value)
    if policy == "split-partial":
        # The bytes-only decoder explicitly rejects link extensions before
        # reading sharedindex. Do not mistake unsupported B for a clean index.
        assert expected == dict(staged=0, modified=1, untracked=0, conflicted=0)
        assert all(value[key] == "pending" for key in (*expected, "filtered")), (case.name, value)
        assert value["partial"] is True
        assert value["ahead"] == value["behind"] == value["stash"] == 0
        return
    if policy == "unknown":
        expected["untracked"] = "pending"
    elif policy == "linked-embedded":
        assert expected["untracked"] == 1
        expected["untracked"] = 0  # no-follow .git policy; no outside metadata open
    elif policy == "collision":
        for key in ("modified", "untracked"):
            assert value[key] == "pending", (case.name, value)
        assert value["staged"] == expected["staged"]
        assert value["conflicted"] == expected["conflicted"]
        assert value["partial"] is True
        assert value["filtered"] == "pending"
        return
    elif policy == "filtered-zero":
        assert expected["modified"] == 1, ("raw oracle must see changed bytes", case.name, expected)
        expected["modified"] = 0  # documented size/mtime approximation
    assert {k: value[k] for k in expected if k != "untracked"} == {
        k: v for k, v in expected.items() if k != "untracked"}, (case.name, value, expected)
    if policy == "unknown":
        assert value["filtered"] == "pending", (case.name, value)
    else:
        assert value["filtered"] is policy.startswith("filtered"), (case.name, value)
    if policy == "untracked-cap-boundary":
        # #131: an index-free subtree reaching the cap reports cap+ even
        # when Git's count equals the cap: the collector has not proven EOF.
        # Product pin: git_status_untracked.rs::untracked_subtree_cap_boundary.
        assert case.name == "untracked-at-cap" and expected["untracked"] == 256, (case.name, expected)
        count = value["untracked"]
        assert count == (256, "saturated"), (case.name, value)
        assert "?256+" in collected["display"], collected
    elif policy == "untracked-capped":
        count = value["untracked"]
        assert isinstance(count, tuple) and len(count) == 2 and count[1] == "saturated", (case.name, value)
        assert type(count[0]) is int and 0 < count[0] <= expected["untracked"], (case.name, count, expected)
        assert f"?{count[0]}+" in collected["display"], collected
    else:
        assert value["untracked"] == expected["untracked"], (case.name, value, expected)
    assert value["partial"] is (policy in {"filtered", "filtered-zero", "include", "unknown", "untracked-capped", "untracked-cap-boundary"}), (case.name, value)
    if policy.startswith("filtered"):
        assert "~" in collected["display"], collected
        if policy == "filtered-zero":
            assert "!0~" in collected["display"], collected
    if policy == "include":
        assert value["ahead"] == value["behind"] == "pending", value


# 이것을 실패시키는 것: canary 하나를 빼거나 실행·외부 byte read·파일 변화를 허용하는 것.
def test_hostile_git_canaries_have_zero_effects(corpus, tmp_path):
    canaries = [c for c in corpus["cases"] if c["canary"] != "-"]
    assert len(canaries) == len(CANARIES) and {c["canary"] for c in canaries} == CANARIES
    for data in canaries:
        case = CorpusCase(data)
        compare_policy_porcelain(case, execute(corpus, case, tmp_path / case.name))


# 이것을 실패시키는 것: EPERM 접근을 성공0으로 지우는 trace gate 변이.
def test_trace_rejects_outside_root_even_on_eperm():
    lines = ['10 write(1<pipe:[9]>, "F1_PHASE acquisition\\n", 21) = 21',
             '10 openat(AT_FDCWD</>, "/outside/sentinel", O_RDONLY) = -1 EPERM (Operation not permitted)',
             '10 write(1<pipe:[9]>, "F1_PHASE end\\n", 13) = 13']
    with pytest.raises(AssertionError, match="outside selected roots"):
        assert_repository_trace(lines, {"roots": ["/repo"], "ancestors": ["/"], "names": []}, {})


# 이것을 실패시키는 것: 생성 호출 실패를 무시하거나 macOS interposer를 끄는 것.
def test_no_spawn_harness_detects_attempts(corpus, tmp_path):
    case = CorpusCase(corpus["cases"][0])
    execute(corpus, case, tmp_path / "baseline")
    with pytest.raises(AssertionError, match="spawn|descendant|process"):
        execute(corpus, case, tmp_path / "mutation", mutant=True)


# 이것을 실패시키는 것: count·Partial·filtered를 고정 값 또는 blanket skip으로 바꾸는 것.
def test_status_matches_policy_porcelain_corpus(corpus, tmp_path):
    errors = []
    for data in corpus["cases"]:
        case = CorpusCase(data)
        result = execute(corpus, case, tmp_path / case.name)
        try:
            compare_policy_porcelain(case, result)
        except AssertionError as error:
            errors.append((case.name, str(error)))
    assert not errors, errors


@pytest.mark.parametrize("name", [
    "untracked", "untracked-under-cap", "untracked-at-cap",
    "untracked-over-cap", "untracked-large",
])
def test_untracked_file_counts_follow_u7(corpus, tmp_path, name):
    case = CorpusCase(next(data for data in corpus["cases"] if data["case"] == name))
    compare_policy_porcelain(case, execute(corpus, case, tmp_path))


# Each wrong result must independently fail against a verified real baseline.
@pytest.mark.parametrize("mutation", ["exact-256", "wrong-number", "non-partial", "missing-plus"])
def test_untracked_cap_boundary_rejects_wrong_results(corpus, tmp_path, mutation):
    case = CorpusCase(next(data for data in corpus["cases"] if data["case"] == "untracked-at-cap"))
    assert case.data["policy"] == "untracked-cap-boundary"
    result = execute(corpus, case, tmp_path)
    compare_policy_porcelain(case, result)
    changed = copy.deepcopy(result)
    if mutation == "exact-256":
        changed["value"]["untracked"] = 256
        changed["display"] = changed["display"].replace("?256+", "?256")
    elif mutation == "wrong-number":
        # 255 is still a valid generic lower bound: only this boundary policy
        # must reject it, rather than relying on the over-cap range check.
        changed["value"]["untracked"] = (255, "saturated")
        changed["display"] = changed["display"].replace("?256+", "?255+")
    elif mutation == "non-partial":
        changed["value"]["partial"] = False
    else:
        changed["display"] = changed["display"].replace("?256+", "?256")
    with pytest.raises(AssertionError):
        compare_policy_porcelain(case, changed)


# 이것을 실패시키는 것: names-only ancestor를 content capability로 승격하는 것.
def test_ancestor_names_keep_their_capability(corpus, tmp_path):
    case = CorpusCase(corpus["cases"][0])
    result = execute(corpus, case, tmp_path, unique=True)
    assert "ancestor-names" in result["phases"] and "read-layer" in result["phases"]
    assert result["siblings"] and all(complete and count <= 256 for _, complete, count in result["siblings"])
    bounded = CorpusCase(next(c for c in corpus["cases"] if c["case"] == "ancestor-bound"))
    result = execute(corpus, bounded, tmp_path / "bounded", unique=True)
    assert result["siblings"] and all(not complete and count <= 256 for _, complete, count in result["siblings"])


# Every canary gets all three negative controls; denied calls still fail.
def test_each_canary_rejects_read_spawn_and_write_mutations(corpus, tmp_path):
    killed = []
    for data in corpus["cases"]:
        if data["canary"] == "-":
            continue
        case = CorpusCase(data)
        for mutation, message in (("read", "outside|forbidden"), ("write", "write|mutation"),
                                  ("spawn", "spawn|process|forbidden repository effect")):
            with pytest.raises(AssertionError, match=message):
                execute(corpus, case, tmp_path / case.name / mutation, mutant=mutation)
            killed.append((case.name, mutation))
    assert len(killed) == len(CANARIES) * 3
    (tmp_path / "mutations.json").write_text(json.dumps(killed, indent=2))


# Mutate each independently observable policy promise after checking the real
# collector baseline. A baseline mismatch fails without synthetic repair.
def test_each_policy_case_rejects_wrong_results(corpus, tmp_path):
    killed, errors = [], []
    for data in corpus["cases"]:
        case = CorpusCase(data)
        result = execute(corpus, case, tmp_path / case.name)
        expected = porcelain_counts(Path(data["porcelain"]).read_bytes())
        try:
            compare_policy_porcelain(case, result)
        except AssertionError as error:
            errors.append((case.name, str(error)))
            continue
        keys = ["staged", "modified", "untracked", "conflicted", "partial", "filtered", "stage"]
        if data["policy"] in {"a-only", "include", "split-partial"}:
            keys += ["ahead", "behind"]
        if data["policy"] in {"a-only", "split-partial"}:
            keys += ["stash"]
        for key in keys:
            changed = copy.deepcopy(result)
            old = changed["value"][key]
            changed["value"][key] = not old if isinstance(old, bool) else old + 1 if isinstance(old, int) else "wrong"
            with pytest.raises(AssertionError):
                compare_policy_porcelain(case, changed)
            killed.append((case.name, key))
        if data["policy"].startswith("filtered"):
            changed = copy.deepcopy(result)
            changed["display"] = changed["display"].replace("~", "")
            with pytest.raises(AssertionError):
                compare_policy_porcelain(case, changed)
            killed.append((case.name, "approximation-marker"))
        if data["policy"] == "untracked-capped":
            for bad in (0, expected["untracked"] + 1):
                changed = copy.deepcopy(result)
                changed["value"]["untracked"] = (bad, "saturated")
                changed["display"] = f"main +1 !1 ?{bad}+"
                with pytest.raises(AssertionError):
                    compare_policy_porcelain(case, changed)
                killed.append((case.name, f"invalid-lower-bound-{bad}"))
            changed = copy.deepcopy(result)
            changed["display"] = changed["display"].replace("+", "")
            with pytest.raises(AssertionError):
                compare_policy_porcelain(case, changed)
            killed.append((case.name, "saturation-marker"))
    (tmp_path / "mutations.json").write_text(json.dumps(killed, indent=2))
    assert not errors, errors


def assert_fifty_ms_partial(result):
    assert result["result"] == "Err(Read(Deadline))", result
    assert [v["stage"] for v in result["updates"]] == ["A"]
    assert result["value"]["partial"] is True
    assert result["value"]["branch"] == "main"
    assert all(result["value"][key] == "pending" for key in
               ("staged", "modified", "untracked", "conflicted", "ahead", "behind", "stash"))
    assert 50_000_000 <= result["elapsed_ns"] < 250_000_000, result


def test_actual_fifty_ms_partial_preserves_stage_a(corpus, tmp_path):
    case = CorpusCase(corpus["cases"][0])
    assert_fifty_ms_partial(execute(corpus, case, tmp_path / "baseline", timed="slow", trace=False))
    with pytest.raises(AssertionError):
        assert_fifty_ms_partial(execute(corpus, case, tmp_path / "mutation", timed="slow", trace=False, mutant="deadline"))


def test_warm_collection_observations(corpus, tmp_path):
    observations, failures = {}, []
    for data in corpus["cases"]:
        case = CorpusCase(data)
        first = execute(corpus, case, tmp_path / case.name / "first", trace=False)
        samples = []
        for attempt in range(200):
            try:
                samples.append(execute(corpus, case, tmp_path / case.name / "warm", trace=False))
            except AssertionError as error:
                failures.append({"case": case.name, "attempt": attempt, "error": str(error)})
                shutil.copytree(tmp_path / case.name / "warm", tmp_path / case.name / f"failed-{attempt}")
                (tmp_path / "warm-failures.json").write_text(json.dumps(failures, indent=2))
        values = sorted(row["elapsed_ns"] for row in samples)
        assert all(row["result"] == "Ok(())" for row in samples), case.name
        observations[case.name] = {"first_ns": first["elapsed_ns"], "successful_runs": len(values),
                                  "p50_ns": statistics.median(values) if values else None,
                                  "p95_ns": values[(len(values) * 95 + 99) // 100 - 1] if values else None,
                                  "variance_ns2": statistics.pvariance(values) if values else None,
                                  "samples": [{"elapsed_ns": row["elapsed_ns"], "times": row["times"]} for row in samples]}
        # Preserve completed cases if a later worker fails; never retry or
        # silently replace a bad sample with a successful one.
        (tmp_path / "warm-200.json").write_text(json.dumps(observations, indent=2))
    assert not failures, failures
