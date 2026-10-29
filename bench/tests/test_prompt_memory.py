"""D5 whole-prompt RSS measurer. `recorded` cases replay traces the tracer
wrote in a Linux container (bench/fixtures/prompt-memory); `live` cases run
the controls under the tracer now and need Linux with ptrace and cc.
BINGSU_D5_REQUIRE_LIVE=1 turns a missing live host into a failure, and
BINGSU_D5_BINARY names the release bingsu for the live prompt case."""
import copy
import json
import os
from pathlib import Path
import platform
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bench"))
import prompt_memory as pm  # noqa: E402

FIXTURES = ROOT / "bench/fixtures/prompt-memory"
MiB = 1 << 20
REQUIRE_LIVE = os.environ.get("BINGSU_D5_REQUIRE_LIVE") == "1"


def recorded(name):
    value = json.loads((FIXTURES / (name + ".json")).read_text())
    return value["events"], pm.counter_error_bytes(value["cpus"], value["page"]), value.get("stdout", "")


@pytest.fixture(scope="module")
def live_tools(tmp_path_factory):
    if platform.system() != "Linux" or not (shutil.which("cc") or shutil.which("gcc")):
        if REQUIRE_LIVE:
            pytest.fail("live controls need Linux ptrace and a C compiler")
        pytest.skip("live controls need Linux ptrace and a C compiler")
    return pm.build_tools(tmp_path_factory.mktemp("d5-tools"))


def run_control(source, name, live_tools_request, tmp_path):
    if source == "recorded":
        return recorded("control-" + name)
    tools = live_tools_request.getfixturevalue("live_tools")
    file = tmp_path / "f64"
    if name == "file64":
        file.write_bytes(os.urandom(64 * MiB))
        file.read_bytes()
    host = pm.host_counters()
    r = pm.control(tools, name, tmp_path / "trace.jsonl", file=file)
    assert r["rc"] == 0, r
    return r["events"], pm.counter_error_bytes(pm.online_cpus(host["cpus_online"]), host["page"]), r["stdout"]


def checked(events, error):
    obs = pm.observation(events)
    assert obs["complete"], obs["problems"]
    candidate = pm.candidate_upper_bytes(obs["per_process_peak"], error)
    truth = sum(r["truth_bytes"] for r in obs["rows"])
    # Every process's own term covers its page-table reference points, and
    # the candidate covers their sum.
    for r in obs["rows"]:
        assert r["peak_bytes"] + error >= r["truth_bytes"], r
    assert candidate >= truth, (candidate, truth)
    return obs, candidate, truth


SOURCES = ["recorded", "live"]


@pytest.mark.parametrize("source", SOURCES)
def test_rss_upper_bound_covers_reaped_grandchildren(source, request, tmp_path):
    # Three generations, each touching more memory and reaping its child.
    # 이것을 실패시키는 것: 상한 후보를 합 대신 최댓값으로 만드는 것, 경계에서 손자 이하를 빼는 것.
    events, error, _ = run_control(source, "tree3", request, tmp_path)
    obs, candidate, truth = checked(events, error)
    assert len(obs["rows"]) == 3
    assert sorted(r["truth_bytes"] // MiB for r in obs["rows"]) >= [8, 16, 32]
    assert candidate >= 56 * MiB


@pytest.mark.parametrize("source", SOURCES)
def test_large_parent_small_exec_child_control(source, request, tmp_path):
    # The child shares the 256 MiB parent before exec and is small after;
    # its own term must cover both, and the pre-exec interval is sampled.
    # 이것을 실패시키는 것: 프로세스 값으로 wait4 maxrss 대신 exit 정지의 VmHWM을 쓰는 것.
    events, error, _ = run_control(source, "bigparent-spawn", request, tmp_path)
    obs, candidate, truth = checked(events, error)
    parent, child = sorted(obs["rows"], key=lambda r: r["pid"])
    assert child["kind"] == "vfork" and child["pre_exec_bytes"] >= 256 * MiB
    assert child["peak_bytes"] + error >= child["pre_exec_bytes"]
    assert candidate >= parent["truth_bytes"] + child["pre_exec_bytes"]
    host = quiet_host()
    assert pm.certify(obs, pm.obligations(host, host, obs), error, no_diagnostic(), "m")["rss_lower_bytes"] is None


@pytest.mark.parametrize("shell,roles", [("bash", ["subshell", "front", "helper", "collector"]),
                                         ("zsh", ["subshell", "front", "helper", "collector"]),
                                         ("fish", ["front", "helper", "collector"])])
def test_boundary_includes_hook_subshell_and_pre_exec_children(shell, roles):
    # A real hook prompt: the command-substitution shell (bash, zsh), the
    # front, and the posix_spawn children observed before their exec.
    # 이것을 실패시키는 것: exec하지 않은 fork 자식이나 vfork 자식을 경계에서 빼는 것, 표식 사이 창을 쓰지 않는 것.
    events, error, _ = recorded("prompt-" + shell)
    obs, candidate, truth = checked(events, error)
    assert [r["role"] for r in obs["rows"]] == roles
    by_role = {r["role"]: r for r in obs["rows"]}
    for name in ("helper", "collector"):
        assert by_role[name]["kind"] == "vfork" and by_role[name]["pre_exec_bytes"] > 0
    assert by_role["front"]["kind"] == ("vfork" if shell == "fish" else "fork")
    # The marker processes the top shell ran around the hook stay outside.
    markers = [e for e in events if e["ev"] == "exec" and set(e["argv"]) & {pm.START, pm.END}]
    assert len(markers) == 2 and not set(e["pid"] for e in markers) & {r["pid"] for r in obs["rows"]}


def test_boundary_includes_the_live_prompt(tmp_path):
    binary = os.environ.get("BINGSU_D5_BINARY")
    if platform.system() != "Linux" or not binary:
        if REQUIRE_LIVE:
            pytest.fail("the live prompt needs Linux and BINGSU_D5_BINARY")
        pytest.skip("the live prompt needs Linux and BINGSU_D5_BINARY")
    for shell in ("bash", "zsh", "fish"):
        memory, evidence = pm.observe_prompt_memory(binary, "git-clean", shell=shell, scratch=tmp_path)
        assert memory["complete"], evidence["problems"]
        assert {"front", "helper", "collector"} <= {p["role"] for p in memory["per_process_peak"]}
        assert memory["rss_upper_bytes"] is None and memory["rss_lower_bytes"] is None
        assert memory["diagnostic"]["cgroup_peak_bytes"] is None
        assert evidence["candidate_upper_bytes"] >= sum(r["truth_bytes"] for r in evidence["rows"])


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", ["file64", "shared64", "cached-exec", "cmdsubst", "anon64", "small"])
def test_file_and_shared_mapping_controls_stay_conservative(source, name, request, tmp_path):
    # File pages, a MAP_SHARED area both processes touch, cached executable
    # and libc pages, and the command-substitution shell around a 64 MiB child.
    # 이것을 실패시키는 것: 상한 후보에서 계수기 오차 E를 빼는 것(보고값이 참조점보다 작다).
    events, error, stdout = run_control(source, name, request, tmp_path)
    obs, candidate, truth = checked(events, error)
    if name == "shared64":
        # Both processes count the one shared area: the sum double counts it.
        assert len(obs["rows"]) == 2 and truth >= 128 * MiB and candidate - 64 * MiB >= 64 * MiB
    if name == "cached-exec":
        resident, total = (int(w.split("=")[1]) for w in stdout.split("RESIDENT ")[1].split()[:2])
        assert total and resident / total >= 0.9
    if name == "cmdsubst":
        assert [r["role"] for r in obs["rows"]][0] == "subshell" and len(obs["rows"]) == 2


def corrupt(events, how):
    events = copy.deepcopy(events)
    groups = pm.processes(events)
    collector = next(g for g in groups.values() if pm.role(g) == "collector")
    helper = next(g for g in groups.values() if pm.role(g) == "helper")
    thread = next(t for t in helper["tids"] if t != helper["tgid"])
    # Cases about grouping and parents use a helper thread, which never execs
    # and leaves the boundary as it is, so only the check under test can fire.
    def reaped(pid):
        return next(i for i, e in enumerate(events) if e["ev"] == "reaped" and e["pid"] == pid)
    if how == "collector-unreaped":
        del events[reaped(collector["tgid"])]
    elif how == "thread-unreaped":
        del events[reaped(thread)]
    elif how == "thread-after-leader":
        e = events.pop(reaped(thread))
        e["seq"] = events[-1]["seq"] + 1
        events.insert(len(events) - 1, e)
    elif how == "timed-out":
        events[-1]["timed_out"] = 1
    elif how == "stray-task":
        events.insert(-1, {"seq": 10**6, "ev": "reaped", "pid": 999_999, "maxrss_kb": 1, "exited": 1, "code": 0, "signal": 0})
    elif how == "overflow":
        events.insert(-1, {"seq": 10**6, "ev": "overflow", "pid": 999_998})
    elif how == "non-leader-exec":
        next(e for e in events if e["ev"] == "exec" and e["pid"] == collector["tgid"])["former"] = thread
    elif how in ("unknown-parent", "unreadable-parent"):
        spawn = next(e for e in events if e["ev"] == "spawn" and e["child"] == thread)
        spawn["parent_tgid"] = 999_999 if how == "unknown-parent" else -1
    elif how == "exec-dropped":
        del events[next(i for i, e in enumerate(events) if e["ev"] == "exec" and e["pid"] == collector["tgid"])]
    elif how == "group-conflict":
        # A helper thread's stops disagree: one names the thread itself, which
        # the clone rule allows on its own, so only the one-value rule fires.
        next(e for e in events if e.get("pid") == thread and e["ev"] == "exit_ref")["tgid"] = thread
    elif how == "fork-joins-group":
        # The subshell is forked and never execs: only the fork rule can fire.
        subshell = next(g for g in groups.values() if pm.role(g) == "subshell")
        for e in events:
            if e.get("pid") == subshell["tgid"] and "tgid" in e:
                e["tgid"] = events[0]["pid"]
    elif how == "clone-joins-unrelated":
        for e in events:
            if e.get("pid") == thread and "tgid" in e:
                e["tgid"] = events[0]["pid"]
    elif how in ("root-clone-exec", "root-nonleader-exec"):
        # Second review: shapes placed between the markers, under the root.
        root = events[0]["pid"]
        start = next(e["seq"] for e in events if e["ev"] == "exec" and pm.START in e["argv"])
        at = next(i for i, e in enumerate(events) if e["seq"] > start)
        exe = {"exe": "/bin/true", "argv": ["/bin/true"]}
        ref = {"threads": 1, "rollup_rss_kb": 100, "file_pmd_kb": 0, "vmhwm_kb": 100, "vmrss_kb": 100}
        if how == "root-clone-exec":
            added = [{"seq": start, "ev": "spawn", "pid": root, "child": 999_999, "kind": "clone", "parent_tgid": root, "parent_threads": 1},
                     {"seq": start, "ev": "start_ref", "pid": 999_999, "tgid": root, **ref},
                     {"seq": start, "ev": "exec", "pid": 999_999, "former": 999_999, **exe},
                     {"seq": start, "ev": "exec_ref", "pid": 999_999, "tgid": root, **ref},
                     {"seq": start, "ev": "reaped", "pid": 999_999, "maxrss_kb": 100, "exited": 1, "code": 0, "signal": 0}]
        else:
            added = [{"seq": start, "ev": "exec", "pid": root, "former": 999_999, **exe},
                     {"seq": start, "ev": "exec_ref", "pid": root, "tgid": root, **ref}]
        events[at:at] = added
    elif how == "collector-unknown-parent":
        # The first review's shape: two checks catch it, neither alone is pinned here.
        next(e for e in events if e["ev"] == "spawn" and e["child"] == collector["tgid"])["parent_tgid"] = 999_999
    elif how == "clone-exec-merged":
        # A clone child that execs, recorded in the helper's thread group.
        next(e for e in events if e["ev"] == "spawn" and e["child"] == collector["tgid"])["kind"] = "clone"
        for e in events:
            if e.get("pid") == collector["tgid"] and "tgid" in e:
                e["tgid"] = helper["tgid"]
    elif how == "pid-reused":
        spawn = next(e for e in events if e["ev"] == "spawn" and e["child"] == collector["tgid"])
        events.insert(-1, {**spawn, "seq": 10**6})
    elif how == "no-thread-group":
        # A thread that never stopped where its thread group was readable.
        events[:] = [e for e in events if not (e.get("pid") == thread and "tgid" in e)]
    return events


@pytest.mark.parametrize("how", ["collector-unreaped", "thread-unreaped", "thread-after-leader", "timed-out",
                                 "stray-task", "overflow", "non-leader-exec", "no-thread-group", "pid-reused",
                                 "unknown-parent", "unreadable-parent", "exec-dropped", "group-conflict",
                                 "fork-joins-group", "clone-joins-unrelated", "clone-exec-merged",
                                 "collector-unknown-parent", "root-clone-exec", "root-nonleader-exec"])
def test_incomplete_terminal_observation_blocks_the_row(how):
    # The process list is the tracer's spawn/exec/reap stream: a task it saw
    # without a final record, or a record it cannot place, is a missing sample.
    # 이것을 실패시키는 것: 종료 기록 없는 pid나 리더 뒤 스레드 기록, 시간 초과, 출처 없는 기록을 받아들이는 것.
    events, error, _ = recorded("prompt-bash")
    assert pm.observation(events)["complete"]
    obs = pm.observation(corrupt(events, how))
    assert not obs["complete"] and obs["problems"]
    memory = pm.certify(obs, all_proven(), error, no_diagnostic(), "m")
    assert memory["rss_upper_bytes"] is None and memory["reason"].startswith("incomplete")
    good = {"memory": pm.certify(pm.observation(events), all_proven(), error, no_diagnostic(), "m"),
            "evidence": {"candidate_upper_bytes": 1}}
    bad = {"memory": memory, "evidence": {}}
    assert pm.summarize_row("git-clean", "bash", 200, [good] * 200)["status"] == "OBSERVED"
    row = pm.summarize_row("git-clean", "bash", 200, [good] * 199 + [bad])
    assert row["status"] == "BLOCKED" and row["complete"] == 199 and row["reason"] == "199 of 200 samples complete"
    assert pm.summarize_row("git-clean", "bash", 200, [good] * 199)["status"] == "BLOCKED"
    # Complete but uncertified samples block the row as well.
    host = quiet_host()
    full = pm.observation(events)
    open_sample = {"memory": pm.certify(full, pm.obligations(host, host, full), error, no_diagnostic(), "m"),
                   "evidence": {"candidate_upper_bytes": 1}}
    row = pm.summarize_row("git-clean", "bash", 200, [good] * 199 + [open_sample])
    assert row["status"] == "BLOCKED" and row["reason"].startswith("RSS certification blocked")


def all_proven():
    return {name: {"status": "proven", "gaps": []}
            for name in (*pm.UPPER_OBLIGATIONS, "lower_bound")}


def no_diagnostic(peak=None, footprint=None):
    return pm.Diagnostic(cgroup_peak_bytes=peak, footprint_bytes=footprint or {})


def test_diagnostic_metrics_never_certify():
    # cgroup memory.peak and footprint are other metrics: they never become a
    # bound, and an open obligation keeps the bound None whatever they say.
    # 이것을 실패시키는 것: 진단값이 있을 때 그것을 상한으로 쓰는 것, 열린 의무가 있는데 상한을 내는 것.
    events, error, _ = recorded("prompt-bash")
    obs = pm.observation(events)
    candidate = pm.candidate_upper_bytes(obs["per_process_peak"], error)
    diagnostic = no_diagnostic(peak=1, footprint={"front": 1})
    proven = pm.certify(obs, all_proven(), error, diagnostic, "m")
    assert proven["rss_upper_bytes"] == candidate and proven["diagnostic"] == diagnostic
    for name in pm.UPPER_OBLIGATIONS:
        proofs = all_proven()
        proofs[name] = {"status": "open", "gaps": ["gap " + name]}
        memory = pm.certify(obs, proofs, error, no_diagnostic(peak=candidate), "m")
        assert memory["rss_upper_bytes"] is None and "gap " + name in memory["reason"]
        assert pm.verdict(memory, 10 * 10**6) == "BLOCKED"
    lower_open = all_proven()
    lower_open["lower_bound"] = {"status": "open", "gaps": ["inherited"]}
    upper_only = pm.certify(obs, lower_open, error, diagnostic, "m")
    assert upper_only["rss_upper_bytes"] == candidate and upper_only["rss_lower_bytes"] is None
    assert "inherited" in upper_only["reason"]
    assert proven["rss_lower_bytes"] == max(p["peak_bytes"] for p in obs["per_process_peak"]) - error
    assert pm.verdict({**proven, "rss_lower_bytes": candidate - 2}, candidate - 2) == "undecided"
    assert pm.verdict(proven, candidate) == "meets"
    assert pm.verdict(proven, candidate - 1) == "undecided"
    assert pm.verdict({**proven, "rss_lower_bytes": candidate - 1}, candidate - 2) == "exceeds"


def test_real_prompt_obligations_stay_open_and_name_the_helper():
    # The recorded host passed every per-sample check; the helper's threads
    # and the unexcluded gaps still keep the prompt uncertified.
    events, error, _ = recorded("prompt-bash")
    obs = pm.observation(events)
    host = quiet_host()
    proofs = pm.obligations(host, copy.deepcopy(host), obs)
    assert proofs["serial_mutation"]["status"] == "open"
    assert any(g.startswith("helper pid") and "threads" in g for g in proofs["serial_mutation"]["gaps"])
    assert proofs["lower_bound"]["status"] == "open"
    memory = pm.certify(obs, proofs, error, no_diagnostic(), "m")
    assert memory["complete"] and memory["rss_upper_bytes"] is None and memory["rss_lower_bytes"] is None


def quiet_host():
    return {"kernel": "6.8.0-117-generic", "arch": "aarch64", "page": 4096, "cpus_online": "0-3",
            "vmstat": {k: 0 for k in pm.QUIET_EVENTS}, "ksm_run": "0", "ksm_full_scans": "0",
            "khugepaged_pages_collapsed": "0", "numa_balancing": "absent", "damon_reclaim": "absent",
            "damon_sysfs": False, "swaps": 0, "cgroup_peak_bytes": None}


def single_threaded_prompt():
    events, error, _ = recorded("prompt-bash")
    obs = pm.observation(events)
    for r in obs["rows"]:
        r["threads"], r["parent_threads"] = 1, 1
    return obs


@pytest.mark.parametrize("change,gap", [
    (lambda b, a: b.update(kernel="6.9.0") or a.update(kernel="6.9.0"), "source-audited"),
    (lambda b, a: a.update(cpus_online="0-2"), "online CPU"),
    (lambda b, a: a["vmstat"].update(pgscan_kswapd=1), "pgscan_kswapd"),
    (lambda b, a: a["vmstat"].update(thp_collapse_alloc=1), "thp_collapse_alloc"),
    (lambda b, a: a["vmstat"].update(oom_kill=1), "oom_kill"),
    (lambda b, a: b["vmstat"].update(pgmigrate_success=None) or a["vmstat"].update(pgmigrate_success=None), "pgmigrate_success"),
    (lambda b, a: b.update(ksm_run="1") or a.update(ksm_run="1"), "ksm_run"),
    (lambda b, a: b.update(numa_balancing="1") or a.update(numa_balancing="1"), "numa_balancing"),
    (lambda b, a: b.update(damon_reclaim="Y") or a.update(damon_reclaim="Y"), "damon_reclaim"),
    (lambda b, a: a.update(khugepaged_pages_collapsed="1"), "khugepaged_pages_collapsed"),
    (lambda b, a: b.update(damon_sysfs=True), "DAMON"),
    (lambda b, a: b.update(swaps=1), "swap"),
])
def test_host_events_open_the_serial_and_lifetime_obligations(change, gap):
    # 이것을 실패시키는 것: 커널 빌드·CPU 집합·vmstat 사건·KSM·NUMA·DAMON·swap 검사 중 하나를 빼는 것.
    obs = single_threaded_prompt()
    before, after = quiet_host(), quiet_host()
    assert pm.obligations(before, after, obs)["serial_mutation"]["status"] == "proven"
    change(before, after)
    proofs = pm.obligations(before, after, obs)
    for name in ("serial_mutation", "lifetime_upper"):
        assert proofs[name]["status"] == "open" and any(gap in g for g in proofs[name]["gaps"]), proofs[name]


def test_threads_and_file_pmd_open_the_obligations():
    # 이것을 실패시키는 것: 스레드 수, vfork 부모의 스레드 수, 파일 PMD 매핑 검사를 빼는 것.
    host = quiet_host()
    for field, value, gap in (("threads", 2, "had 2 threads"), ("parent_threads", 3, "with 3 threads"),
                              ("file_pmd_kb", 2048, "file PMD")):
        obs = single_threaded_prompt()
        target = next(r for r in obs["rows"] if r["kind"] == "vfork")
        target[field] = value
        proofs = pm.obligations(host, copy.deepcopy(host), obs)
        assert any(gap in g for g in proofs["serial_mutation"]["gaps"]), (field, proofs)


def test_engine_exit_and_roles_feed_the_perturbation_gaps():
    # 이것을 실패시키는 것: 엔진 프로세스의 비정상 종료나 빠진 역할을 교란 검사에서 놓치는 것.
    host = quiet_host()
    obs = single_threaded_prompt()
    assert pm.obligations(host, host, obs)["trace_perturbation"]["gaps"] == [pm.OPEN_PERTURBATION]
    killed = copy.deepcopy(obs)
    next(r for r in killed["rows"] if r["role"] == "collector")["exit"] = {"exited": 0, "code": -1, "signal": 9}
    assert any("collector" in g for g in pm.obligations(host, host, killed)["trace_perturbation"]["gaps"])
    gone = copy.deepcopy(obs)
    gone["rows"] = [r for r in gone["rows"] if r["role"] != "helper"]
    assert any("missing" in g for g in pm.obligations(host, host, gone)["trace_perturbation"]["gaps"])


def test_counter_error_follows_the_kernel_batch():
    # 4 CPUs, 4 KiB pages: 3 x 4 x 31 pages = 1,488 KiB (the D0 value);
    # 64 CPUs raise the batch to 128.
    assert pm.counter_error_bytes(4, 4096) == 1488 * 1024
    assert pm.counter_error_bytes(64, 4096) == 3 * 64 * 127 * 4096
    assert pm.online_cpus("0-3") == 4 and pm.online_cpus("0,2-3") == 3
    with pytest.raises(ValueError):
        pm.counter_error_bytes(0, 4096)


def test_macos_and_short_rows_are_blocked(monkeypatch):
    monkeypatch.setattr(pm.platform, "system", lambda: "Darwin")
    memory = pm.measure_prompt_memory("/nonexistent", "git-clean")
    assert memory["complete"] is False and memory["rss_upper_bytes"] is None and "BLOCKED" in memory["reason"]
    assert pm.measure_row("/nonexistent", "git-clean")["status"] == "BLOCKED"
    with pytest.raises(ValueError):
        pm.measure_row("/nonexistent", "git-clean", 199)


def test_git_product_memory_rows_block_the_run(monkeypatch, tmp_path):
    # 이것을 실패시키는 것: BLOCKED 행이 있어도 실행 전체를 OBSERVED로 두는 것.
    import importlib.util
    spec = importlib.util.spec_from_file_location("git_product_d5", ROOT / "bench/git-product.py")
    git = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(git)
    rows = {"git-clean": {"status": "OBSERVED"}, "tracked-19000": {"status": "BLOCKED"}}
    real = git.module
    def module(name, path):
        value = real(name, path)
        if name == "d5_prompt_memory":
            monkeypatch.setattr(value, "measure_row", lambda binary, case, rounds, shell: rows[case])
        return value
    monkeypatch.setattr(git, "module", module)
    monkeypatch.setattr(git.tempfile, "gettempdir", lambda: str(tmp_path))
    assert git.memory_run("b", ["git-clean"], 200, "bash", {})["status"] == "OBSERVED"
    value = git.memory_run("b", ["git-clean", "tracked-19000"], 200, "bash", {})
    assert value["status"] == "BLOCKED" and value["kind"] == "prompt-memory"


def test_quiesce_waits_for_engine_processes(monkeypatch):
    # 이것을 실패시키는 것: 앞 프롬프트의 도우미·collector가 살아 있는데 표본을 시작하는 것.
    alive = iter([True, True, False])
    monkeypatch.setattr(pm, "_engine_alive", lambda paths: next(alive))
    pm.quiesce(Path("/b/bingsu"), timeout_s=5)
    monkeypatch.setattr(pm, "_engine_alive", lambda paths: True)
    with pytest.raises(ValueError):
        pm.quiesce(Path("/b/bingsu"), timeout_s=0.05)


@pytest.mark.parametrize("rc,stderr,ok", [(0, b"REC\x1e1\n", True), (0, b"REC\n", False), (0, b"", False), (1, b"REC1\n", False)])
def test_a_prompt_without_a_record_is_a_missing_sample(rc, stderr, ok):
    # 이것을 실패시키는 것: 종료 코드나 빈 기록을 보지 않고 표본을 받는 것.
    assert (pm.record_problem(rc, stderr) is None) == ok


def test_no_git_case_refuses_an_enclosing_repository(tmp_path):
    # 이것을 실패시키는 것: no-git 폴더가 checkout 안에 있어 checkout 저장소를 발견하는데도 측정하는 것.
    (tmp_path / "outer/.git").mkdir(parents=True)
    (tmp_path / "outer/home/no-git").mkdir(parents=True)
    assert pm.enclosing_repository(tmp_path / "outer/home/no-git") == str(tmp_path / "outer")
    (tmp_path / "clean/home/no-git").mkdir(parents=True)
    assert pm.enclosing_repository(tmp_path / "clean/home/no-git") is None


def test_publication_check_needs_the_same_records():
    # 이것을 실패시키는 것: 추적 실행 뒤 게시된 기록이 보통 실행과 달라도 같다고 보는 것.
    assert pm.same_publication({"a": 20}, {"a": 20})
    assert not pm.same_publication({"a": 20}, {"b": 20})
    assert not pm.same_publication({"a": 10, "b": 10}, {"a": 20})
    assert not pm.same_publication({}, {})
    assert pm.record_of(b"noise REC B1\x1fx\n") == b" B1\x1fx\n" and pm.record_of(b"") == b""


def test_a_process_made_by_a_plain_clone_is_inside_the_boundary():
    # clone() with an exit signal other than SIGCHLD is a process, not a thread.
    # 이것을 실패시키는 것: 경계를 fork·vfork 사건으로만 넓히는 것.
    events, error, _ = recorded("prompt-bash")
    events = copy.deepcopy(events)
    groups = pm.processes(events)
    collector = next(g for g in groups.values() if pm.role(g) == "collector")
    next(e for e in events if e["ev"] == "spawn" and e["child"] == collector["tgid"])["kind"] = "clone"
    obs = pm.observation(events)
    assert obs["complete"] and "collector" in [r["role"] for r in obs["rows"]]


@pytest.mark.parametrize("cases", ["bogus", "no-git,no-git", ""])
def test_git_product_memory_refuses_unknown_cases(monkeypatch, tmp_path, cases):
    # An unknown name would otherwise build an ordinary repository and pass for a case.
    # 이것을 실패시키는 것: --prompt-memory의 경우 이름 검사를 빼는 것.
    import importlib.util
    spec = importlib.util.spec_from_file_location("git_product_cases", ROOT / "bench/git-product.py")
    git = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(git)
    monkeypatch.setattr(git, "memory_run", lambda *a: {"status": "OBSERVED"})
    out = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv", ["git-product.py", "--prompt-memory", "b", "--cases", cases, "--out", str(out)])
    assert git.main() == 2 and "cases" in json.loads(out.read_text())["reason"]
    monkeypatch.setattr(sys, "argv", ["git-product.py", "--prompt-memory", "b", "--cases", "no-git", "--out", str(out)])
    assert git.main() == 0


def test_ci_report_names_why_rows_are_blocked(monkeypatch, tmp_path, capsys):
    # The workflow prints these as annotations and step-summary lines.
    # 이것을 실패시키는 것: 감사하지 않은 커널을 통과시키는 것, OBSERVED가 아닌 행이나 열린 의무를 빼고 적는 것.
    monkeypatch.setattr(pm.platform, "system", lambda: "Darwin")
    assert "Darwin" in pm.kernel_gate("6.8.0-117-generic")
    monkeypatch.setattr(pm.platform, "system", lambda: "Linux")
    assert pm.kernel_gate("6.8.0-117-generic") is None
    assert "6.11.0-azure" in pm.kernel_gate("6.11.0-azure")
    proofs = {"serial_mutation": {"status": "open", "gaps": ["helper pid 7 had 3 threads"]},
              "lower_bound": {"status": "proven", "gaps": []}}
    row = {"status": "BLOCKED", "complete": 200, "rounds": 200, "certified": 0,
           "samples": [{"evidence": {"obligations": proofs}}] * 2}
    value = {"status": "BLOCKED", "shell": "bash", "cases": {"no-git": row, "git-clean": {**row, "status": "OBSERVED"}}}
    lines = pm.blocked_lines(value)
    assert len(lines) == 1 and "no-git" in lines[0] and "serial_mutation open in 2 (helper pid 7 had 3 threads)" in lines[0]
    assert "lower_bound" not in lines[0]
    assert pm.blocked_lines({"status": "OBSERVED", "cases": {}}) == []
    assert "lock busy" in pm.blocked_lines({"status": "BLOCKED", "reason": "lock busy"})[0]
    (tmp_path / "r.json").write_text(json.dumps(value))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert pm.main(["--summary", str(tmp_path / "r.json"), str(tmp_path / "missing.json")]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 2 and all(line.startswith("::error title=prompt memory BLOCKED::") for line in out)
    assert "unreadable" in out[1] and summary.read_text().count("\n- ") + 1 == 2
    monkeypatch.setattr(pm.platform, "release", lambda: "6.11.0-azure")
    assert pm.main(["--kernel-gate"]) == 0 and "6.11.0-azure" in capsys.readouterr().out


@pytest.mark.parametrize("missing", list(pm.UPPER_OBLIGATIONS) + ["all"])
def test_a_missing_obligation_is_an_open_one(missing):
    # 이것을 실패시키는 것: certify가 넘겨받은 항목만 보고 빠진 의무를 증명된 것으로 치는 것.
    events, error, _ = recorded("prompt-bash")
    obs = pm.observation(events)
    proofs = all_proven()
    for name in (pm.UPPER_OBLIGATIONS if missing == "all" else [missing]):
        del proofs[name]
    memory = pm.certify(obs, proofs, error, no_diagnostic(), "m")
    assert memory["rss_upper_bytes"] is None and "not evaluated" in memory["reason"]
    assert pm.verdict(memory, 10**12) == "BLOCKED"
    only_lower = pm.certify(obs, {"lower_bound": {"status": "open", "gaps": ["x"]}}, error, no_diagnostic(), "m")
    assert only_lower["rss_upper_bytes"] is None
    no_lower = all_proven()
    del no_lower["lower_bound"]
    memory = pm.certify(obs, no_lower, error, no_diagnostic(), "m")
    assert memory["rss_upper_bytes"] is not None and memory["rss_lower_bytes"] is None
    assert "not evaluated" in memory["reason"]


def test_the_row_itself_requires_200_complete_samples():
    # The row function holds the 200-sample floor, whatever count it is asked for.
    # 이것을 실패시키는 것: 호출자가 넘긴 rounds와만 비교하는 것.
    events, error, _ = recorded("prompt-bash")
    good = {"memory": pm.certify(pm.observation(events), all_proven(), error, no_diagnostic(), "m"),
            "evidence": {"candidate_upper_bytes": 1}}
    assert pm.summarize_row("git-clean", "bash", 1, [good])["status"] == "BLOCKED"
    assert pm.summarize_row("git-clean", "bash", 1, [good] * 199)["reason"] == "199 of 200 samples complete"
    assert pm.summarize_row("git-clean", "bash", 1, [good] * 200)["status"] == "OBSERVED"


def test_untraced_creation_keeps_the_bound_blocked():
    # ptrace never sees a CLONE_UNTRACED child, so a complete sample is complete
    # only over reported creations; the obligation stays open on every host.
    # 이것을 실패시키는 것: untraced_creation을 상한 의무에서 빼거나 proven으로 두는 것.
    events, error, _ = recorded("prompt-bash")
    obs = pm.observation(events)
    assert "untraced_creation" in pm.UPPER_OBLIGATIONS
    proofs = all_proven()
    proofs["untraced_creation"] = {"status": "open", "gaps": [pm.OPEN_UNTRACED]}
    memory = pm.certify(obs, proofs, error, no_diagnostic(), "m")
    assert memory["rss_upper_bytes"] is None and "CLONE_UNTRACED" in memory["reason"]
    del proofs["untraced_creation"]
    assert pm.certify(obs, proofs, error, no_diagnostic(), "m")["rss_upper_bytes"] is None
    host = quiet_host()
    assert pm.obligations(host, host, single_threaded_prompt())["untraced_creation"] == {"status": "open", "gaps": [pm.OPEN_UNTRACED]}
