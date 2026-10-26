"""Compiler-free M3b integration. Prepare all fixtures in the native host job."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/fsbudget"))


def real_bin():
    return Path(os.environ.get("BINGSU_BIN", ROOT / "target/debug/bingsu")).resolve()


SPEC = importlib.util.spec_from_file_location("security_product", ROOT / "bench/collector-product.py")
product = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(product)


@pytest.fixture(scope="module")
def preparation():
    # No auto-discovery, compiler or toolchain fallback in shell images.
    binary = real_bin()
    try:
        return product.prepared(binary)
    except (ValueError, OSError, KeyError, TypeError) as error:
        message = (
            f"M3b security preparation unavailable for {binary}: {error}. "
            "After the last binary build, prepare this sibling pair on the host with "
            f"`python3 bench/collector-product.py --prepare {shlex.quote(str(binary))}`, "
            "then rerun pytest with the same BINGSU_BIN."
        )
        if os.environ.get("CI"):
            pytest.fail(message, pytrace=False)
        pytest.skip(message)


def native_contract(preparation, group, name):
    binary = preparation["contracts"][group]
    assert product.digest(binary) == preparation["contract_hashes"][group], "stale native contract binary"
    result = subprocess.run([binary, "--exact", name, "--nocapture", "--test-threads=1"],
                            capture_output=True, timeout=90)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout), result.stdout
    return result


# 이것을 실패시키는 것: helper 선택을 0으로 되돌리거나 excludes wire 입력을 버려 stage B가 무시 파일을 세는 것.
@pytest.mark.parametrize("case", [
    "known", "missing", "empty", "unknown", "invalid-home", "invalid-xdg", "invalid-both",
])
def test_product_global_excludes_reaches_stage_b(preparation, tmp_path, case):
    repo, home, xdg = (tmp_path / name for name in ("repo", "home", "xdg"))
    for path in (repo, home, xdg / "git"):
        path.mkdir(parents=True)
    rules = xdg / "git/ignore"
    rules.write_bytes(b".DS_Store\n")
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_CONFIG_HOME": str(xdg),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "f@example.org",
           "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "f@example.org"}
    def git(*args):
        return product.run(["git", "-C", repo, *args], env=env).stdout
    git("init", "-q", "--initial-branch=main")
    (repo / "tracked").write_text("base\n")
    git("add", "tracked")
    git("commit", "-qm", "base")
    git("branch", "upstream")
    git("branch", "--set-upstream-to=upstream")
    (repo / "tracked").write_text("modified\n")
    (repo / "added").write_text("staged\n")
    git("add", "added")
    (repo / ".DS_Store").write_text("globally ignored\n")
    (repo / "visible").write_text("untracked\n")
    assert [line for line in git("status", "--porcelain=v2").splitlines() if line.startswith(b"? ")] == [b"? visible"]
    if case == "missing":
        rules.unlink()
    if case == "unknown":
        rules.write_bytes(b"x" * 65_537)
    home_arg = "relative" if case in ("invalid-home", "invalid-both") else str(home)
    xdg_arg = "~/.config" if case in ("invalid-xdg", "invalid-both") else str(xdg)
    if case == "empty":
        home_arg = xdg_arg = ""
    result = product.run([preparation["fixture"], "--global-excludes-stream", repo, home_arg, xdg_arg])
    observed = json.loads(result.stdout)
    known = case in ("known", "missing", "empty")
    assert observed == {
        "known": known, "reason": "Loaded" if case == "known" else
        "Missing" if known else "TooLarge" if case == "unknown" else "UnsafePath",
        "pattern_bytes": 10 if case == "known" else 0,
        "complete": True, "partial": not known,
    }


# 이것을 실패시키는 것: 한도/exec 실패를 실제 공유 보호·감독·발행 경로에 연결하지 않는 것.
@pytest.mark.parametrize("mode", ["cpu", "nofile", *(
    pytest.param(mode, marks=pytest.mark.skipif(sys.platform != "linux", reason="Linux resource filter"))
    for mode in ("as", "exec"))])
def test_security_table_resource_failures_preserve_front(preparation, tmp_path, mode):
    result = subprocess.run([preparation["fixture"], "--limit-" + mode], capture_output=True, timeout=30)
    if mode == "cpu":
        assert result.returncode in (-signal.SIGKILL, -signal.SIGXCPU) and result.stdout == b"CPU1\n", result
    else:
        assert result.returncode == 0 and result.stdout == b"RESOURCE PASS\n", result
    # A valid Update survives the subsequent failure through the actual shared
    # supervisor and atomic store. The 50ms request deadline still wins over a
    # CPU-bound worker; CPU1 above independently verifies its kernel ceiling.
    scratch = tmp_path / mode
    scratch.mkdir(mode=0o700)
    failed = product.run([preparation["fixture"], "--helper-case", scratch, "--" + mode + "-worker"],
                         env={**os.environ, "TMPDIR": str(scratch)})
    report = json.loads(failed.stdout)
    assert report["published"] and report["reaped"] and report["partial_values"] == 1, report
    assert report["reason"] in {"Protocol", "Deadline", "Resource"}, report
    assert report["probe"] == f"probe-{mode}-pass", report
    # 이것을 실패시키는 것: probe 성공 Update를 빼거나 실패 저장소 대신 별도 reader fixture를 읽는 것.
    reader = product.run([preparation["fixture"], "--read", scratch], env={**os.environ, "TMPDIR": str(scratch)})
    assert reader.returncode == 0 and reader.stderr == b""
    record = bytes.fromhex(json.loads(reader.stdout)["record_hex"])
    assert record.startswith(b"B1\x1f") and record.endswith(b"\x1e") and record.count(b"\x1f") == 9
    assert f"probe-{mode}-pass".encode() in record, record



# 이것을 실패시키는 것: 실패·잠금·경쟁·고정 주소·회수의 실제 계약 시험을 선택만 하고 실행하지 않는 것.
@pytest.mark.parametrize("group,name", [
    ("collector_lifecycle", "partial_survives_only_after_validated_updates"),
    ("collector_lifecycle", "slow_drip_does_not_extend_spawn_deadline"),
    ("collector_lifecycle", "early_exit_never_signals_recycled_pid"),
    ("collector_lifecycle", "immediate_ready_is_not_read_or_decoded_before_confinement"),
    ("collector_lifecycle", "verified_screen_spawns_once_before_helper_tsync"),
    ("collection_store", "publication_checks_same_fd_bytes_and_identity"),
    ("collection_store", "hash_collision_never_reuses_or_overwrites_other_cwd"),
    ("collection_store", "helper_close_never_unlocks_live_worker"),
    ("collection_store", "gc_cannot_split_lock_inode_or_delete_inflight_store"),
    ("collection_store", "legacy_gc_prunes_only_empty_suffixes"),
    ("collection_store", "gc_time_cap_stops_before_filesystem_work"),
    ("collection_store", "review_deep_context_undercount"),
    ("collection_store", "review_cross_context_starvation"),
])
def test_product_security_contract(preparation, group, name):
    native_contract(preparation, group, name)


# 이것을 실패시키는 것: 첫 완료 초과 표본의 감지/종료·초과량·표본 간격 분포를 놓치는 것.
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sampled footprint contract")
def test_macos_first_completed_overlimit_sample(preparation):
    result = native_contract(preparation, "collector_lifecycle", "macos_first_completed_overlimit_sample_terminates")
    print(result.stdout.decode())
    for label in (b"footprint overshoot bytes", b"completed sample interval us", b"sample-to-kill-request us"):
        assert label + b": count=" in result.stdout, result.stdout


# 이것을 실패시키는 것: B2 하한을 제품 필터 측정으로 재사용하거나 Ready를 읽지 않고 측정하는 것.
def test_b2_lower_bound_is_replaced_by_product_filter_evidence(preparation, tmp_path):
    sample = product.observe(real_bin(), preparation, tmp_path)
    assert sample["events"]["ready"] >= sample["events"]["spawn_return"]
    assert preparation["policy"]["table_sha256"] == product.digest(ROOT / "crates/bingsu-collect/collector-syscalls.tsv")
    assert preparation["policy"]["product_mask"] == 10 and preparation["policy"]["fixture_mask"] == 1 << 31
    assert sample["as_baseline"] > 0 and sample["collector_peak_rss_bytes"] > 0
    if sys.platform == "linux":
        assert 0 < preparation["policy"]["initial_bpf_instructions"] <= 4096
        assert 0 < preparation["policy"]["final_bpf_instructions"] <= 4096
        assert sample["filter_install_ns"] > 0
    assert sample["m1_stub_exit_ns"] > 0 and sample["m1_stub_limits_ns"] > 0


def workflow_job(text, job):
    """Conservative structural subset, not a general YAML loader.

    No YAML parser is hash-pinned in the test requirements. The gate accepts
    only our block-mapping job/step layout, literal run blocks or quoted/plain
    single-line runs. Duplicate keys, anchors, aliases, merges, folded scalars
    and multiline conditions fail closed. actionlint validates the full YAML.
    Comments and metadata can never supply executable evidence.
    """
    header = text.split("\njobs:\n", 1)[0]
    assert not re.search(r"(?m)^defaults:", header), "workflow shell defaults"
    assert not re.search(r"\b(?:BASH_ENV|SHELLOPTS)\b", header), "workflow shell startup env"
    matches = re.findall(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [\w-]+:|\Z)", text)
    assert len(matches) == 1, job
    block, = matches
    assert not re.search(r"(?m)^\s*(?:<<:|[^#\n]*: [*&])", block), "YAML indirection"

    def fields(lines, indent):
        result = {}
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip() or line.lstrip().startswith("#"):
                i += 1
                continue
            match = re.fullmatch(r" {" + str(indent) + r"}([\w-]+):(?: (.*))?", line)
            assert match, (job, "unsupported structural YAML", line)
            key, value = match[1], match[2] or ""
            assert key not in result, (job, "duplicate YAML key", key)
            i += 1
            nested = []
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                nested.append(lines[i])
                i += 1
            if key == "run":
                if value == "|":
                    assert all(not v.strip() or v.startswith(" " * (indent + 2)) for v in nested)
                    value = "\n".join(v[indent + 2:] for v in nested)
                else:
                    assert not nested or not any(v.strip() for v in nested)
                    assert value and value[0] not in "|>&*!", (key, value)
                    if value.startswith("'"):
                        assert value.endswith("'")
                        value = value[1:-1].replace("''", "'")
                    elif value.startswith('"'):
                        value = json.loads(value)
            elif key == "if":
                assert not any(v.strip() for v in nested) and value and value[0] not in "|>&*!", value
            result[key] = (value, nested)
        return result

    split = block.split("    steps:\n")
    assert len(split) == 2, (job, "steps")
    meta = fields(split[0].splitlines(), 4)
    chunks = re.split(r"(?m)^      - ", split[1])
    assert not chunks[0].strip(), chunks[0]
    steps = []
    for chunk in chunks[1:]:
        lines = chunk.splitlines()
        lines[0] = "        " + lines[0]
        parsed = fields(lines, 8)
        assert_shell_settings(parsed)
        steps.append({key: value for key, (value, _) in parsed.items()})
    assert_shell_settings(meta)
    return meta, steps


def assert_shell_settings(fields):
    # 이것을 실패시키는 것: shell/defaults/startup 환경으로 errexit 계약을 바꾸는 것.
    assert "defaults" not in fields, "shell defaults override"
    if "shell" in fields:
        value, nested = fields["shell"]
        assert not any(v.strip() for v in nested)
        assert re.fullmatch(r"bash(?: --noprofile)?(?: --norc)? (?:-e|-e(?:u)?o pipefail) \{0\}", value), value
    if "env" in fields:
        value, nested = fields["env"]
        assert not value, "inline env is unsupported"
        assert not re.search(r"\b(?:BASH_ENV|SHELLOPTS)\b", "\n".join(nested)), "shell startup env"


LINUX_SECURITY_STEPS = {
    "Native collector kernel probes (required cells, no silent skip)",
    "Collector policy mutations, including real seal and fd rules",
    "Repository read layer trace and acceptance",
    "Final filter refuses root limit and capability changes",
    "Native musl collector probes (both architectures)",
    "Independent gix 0.83.0 X-14 (locked, glibc and musl)",
    "Privileged capability removal (no silent skip)", "Install native M3b trace tool",
    "Assert native Linux M3b security passes", "M3b native musl lifecycle security",
    "Path facts ACL and read-only mount oracles",
    "Assert native Linux F1 collection passes", "Assert exact F3 musl collection passes",
}
MACOS_SECURITY_STEPS = {"Both shipped Mach-O architectures", "Assert native macOS M3b security passes",
                        "Assert native macOS F1 collection passes"}


def security_steps(text):
    meta, steps = workflow_job(text, "collector")
    assert "continue-on-error" not in meta
    assert meta["if"][0] == "needs.detect.outputs.rust == 'true'"
    assert meta["needs"][0] == "detect"
    matrix = "\n".join(meta["strategy"][1])
    assert [line.strip() for line in matrix.splitlines() if line.strip() and not line.lstrip().startswith("#")] == [
        "fail-fast: false", "matrix:", "os: [ubuntu-24.04, ubuntu-24.04-arm, macos-latest, macos-26-intel]"]
    required_names = LINUX_SECURITY_STEPS | MACOS_SECURITY_STEPS | {
        "Prepare M3b compiler-free product fixtures", "M3b product security and measurements contracts",
        "Product imports and matching deployment pair", "Prepare F1 hostile Git corpus on the host",
        "F1 protected collection and policy corpus"}
    for name in required_names:
        assert sum(step.get("name") == name for step in steps) == 1, ("required security step", name)
    for step in steps:
        if "run" not in step:
            continue
        name = step.get("name", "")
        assert "continue-on-error" not in step, name
        condition = ("runner.os == 'Linux'" if name in LINUX_SECURITY_STEPS else
                     "runner.os == 'macOS'" if name in MACOS_SECURITY_STEPS else None)
        assert step.get("if") == condition, (name, "skippable security step", step.get("if"))
        assert_run_unconditional(step)
    f1 = {step.get("name"): step for step in steps if "F1" in step.get("name", "")}
    assert run_commands(f1["Prepare F1 hostile Git corpus on the host"]) == [["python3", "scripts/prepare_git_corpus.py"]]
    assert ["export", "BINGSU_GIT_CORPUS_REQUIRED=1"] in run_commands(f1["F1 protected collection and policy corpus"]), "F1 preparation must fail closed"
    common = [command[2] for command in run_commands(f1["F1 protected collection and policy corpus"])
              if command[:2] == ["grep", "-F"]]
    required = ["test_hostile_git_canaries_have_zero_effects", "test_trace_rejects_outside_root_even_on_eperm",
                "test_no_spawn_harness_detects_attempts", "test_status_matches_policy_porcelain_corpus",
                "test_ancestor_names_keep_their_capability", "test_each_canary_rejects_read_spawn_and_write_mutations",
                "test_each_policy_case_rejects_wrong_results", "test_actual_fifty_ms_partial_preserves_stage_a",
                "test_warm_collection_observations"]
    assert common == ["PASSED tests/shell/test_git_collection_security.py::" + name for name in required], "F1 required pass assertions"
    untracked_passes = [
        "PASSED tests/shell/test_git_collection_security.py::test_untracked_file_counts_follow_u7[" + name + "]"
        for name in ("untracked", "untracked-under-cap", "untracked-at-cap", "untracked-over-cap", "untracked-large")]
    for platform in ("Linux", "macOS"):
        commands = run_commands(f1[f"Assert native {platform} F1 collection passes"])
        assert commands == [["grep", "-Fx", name, "$RUNNER_TEMP/f1-security.txt"]
                            for name in common + untracked_passes], "F1 exact platform passes"
    return steps


def run_commands(step):
    return [tokens for line in step.get("run", "").splitlines()
            if (tokens := shlex.split(line, comments=True))]


def assert_run_unconditional(step):
    # 이것을 실패시키는 것: 옵션 해제·동적 실행·heredoc·성공 명령으로 grep 실패를 숨기는 것.
    for command in run_commands(step):
        assert command[0] not in {
            "if", "for", "while", "until", "case", "exit", ":", "!", "true",
            "trap", "exec", "return", "eval", "source", ".",
        }, command
        assert not any("<<" in token for token in command), command
        assert not set(command) & {"||", "&&", ";"}, command
        if command[0] == "set":
            assert command in (["set", "-o", "pipefail"], ["set", "-euo", "pipefail"],
                               ["set", "-eo", "pipefail"]), command
        if command[0] == "grep":
            # One literal pattern and one log only: no pipeline, redirection,
            # command suffix or background operator may replace grep's status.
            assert len(command) == 4 and command[1] in {"-F", "-Fx"}, command
            assert not any(c in command[3] for c in ";&|<>`"), command


def rust_cfg_holds(expression, platform):
    """Fail closed outside the cfg predicates used by these native rows."""
    tokens = re.findall(r'"[^"\n]*"|[A-Za-z_]\w*|[(),=]|\S', expression)
    index = 0

    def predicate():
        nonlocal index
        assert index < len(tokens), expression
        key = tokens[index]
        index += 1
        if key in {"all", "any", "not"}:
            assert tokens[index:index + 1] == ["("], expression
            index += 1
            values = []
            while tokens[index:index + 1] != [")"]:
                values.append(predicate())
                if tokens[index:index + 1] != [","]:
                    break
                index += 1
            assert tokens[index:index + 1] == [")"], expression
            index += 1
            if key == "not":
                assert len(values) == 1, expression
                return not values[0]
            return all(values) if key == "all" else any(values)
        if key == "target_os":
            assert tokens[index:index + 1] == ["="], expression
            index += 1
            value = tokens[index]
            index += 1
            assert value in {'"linux"', '"macos"'}, expression
            return value == '"' + platform + '"'
        assert key in {"unix", "test"}, ("unsupported cfg", expression)
        return True

    result = predicate()
    if tokens[index:] == [","]:
        index += 1
    assert index == len(tokens), expression
    return result


def ci_test_evidence(text):
    steps = security_steps(text)
    meta, probes = workflow_job(text, "collector-probes")
    assert "if" not in meta and "continue-on-error" not in meta
    for step in probes:
        if "run" in step:
            assert "if" not in step and "continue-on-error" not in step
            assert_run_unconditional(step)
    for job, entries in (("collector", steps), ("collector-probes", probes)):
        for step in entries:
            step["_job"] = job
    return steps + probes


def assert_acceptance_table(table, workflow, *, read=lambda name: (ROOT / name).read_text(), collected=None):
    import ast
    import csv
    import io
    rows = list(csv.DictReader(io.StringIO(table), delimiter="\t"))
    assert rows and len({r["id"] for r in rows}) == len(rows)
    assert {"SEC-FSIZE", "SEC-WRITE", "SEC-FORK", "SEC-LANDLOCK", "SEC-PIDFD", "SEC-NOWAIT"} <= {r["id"] for r in rows}
    steps = ci_test_evidence(workflow)
    commands = [(step, command) for step in steps for command in run_commands(step)]
    for row in rows:
        path, name = row["test"].split("::", 1)
        source = read(path)
        base = name.split("[", 1)[0]
        if path.endswith(".py"):
            found = [node for node in ast.walk(ast.parse(source))
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == base]
            assert len(found) == 1, (row["id"], "test declaration", path, base)
            if collected is not None:
                nodes = [node for node in collected if node == row["test"] or
                         ("[" not in name and node.startswith(row["test"] + "["))]
                assert nodes and len(nodes) == len(set(nodes)), (row["id"], "pytest collection", row["test"])
            evidence = []
            for step, command in commands:
                if command[:2] != ["grep", "-F"] or command[2:3] != ["PASSED " + row["test"]]:
                    continue
                log = command[3:]
                # The corresponding pytest must produce this asserted log in
                # the same matrix job, and actually select the file/directory.
                for run_step, run in commands:
                    if (run_step["_job"] != step["_job"] or run[1:3] != ["-m", "pytest"] or
                            run[0] not in {"$RUNNER_TEMP/collector-tests/bin/python", "$RUNNER_TEMP/probe-tests/bin/python"} or
                            "tee" not in run or run[run.index("tee") + 1:] != log):
                        continue
                    selected = run[run.index("pytest") + 1:run.index("|")]
                    assert not any(token in {"-k", "-m"} or token.startswith(("--ignore", "--deselect")) for token in selected), (row["id"], "pytest selection filter")
                    required_if = ("runner.os == 'Linux'" if row["platform"].startswith("Linux") else
                                   "runner.os == 'macOS'" if row["platform"] == "macOS" else None)
                    if any(entry.get("if") not in (None, required_if) for entry in (step, run_step)):
                        continue
                    if any(token in {path, row["test"]} or path.startswith(token.rstrip("/") + "/") for token in selected):
                        evidence.append((step, run_step))
            assert evidence, (row["id"], "no asserted CI pytest", row["test"])
        else:
            # Read the entire contiguous outer attribute group, irrespective
            # of #[test]/#[ignore]/#[cfg] order, including multiline cfgs.
            found = re.findall(r"((?:^[ \t]*#\[[^\]]*\](?:\s|//[^\n]*(?:\n|\Z)|/\*[\s\S]*?\*/)*)+)"
                               r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+" + re.escape(base) + r"\s*\(",
                               source, re.M)
            assert len(found) == 1, (row["id"], "test declaration", path, base)
            attributes = re.findall(r"#\[([^\]]*)\]", found[0])
            assert "test" in [a.strip() for a in attributes], (row["id"], "not a test")
            platforms = ["linux"] if row["platform"].startswith("Linux") else (
                ["macos"] if row["platform"] == "macOS" else ["linux", "macos"])
            for attr in attributes:
                assert not re.match(r"\s*cfg_attr\b", attr), (row["id"], "conditional attributes")
                cfg = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", attr, re.S)
                if cfg:
                    assert all(rust_cfg_holds(cfg[1], platform) for platform in platforms), (row["id"], "disabled cfg", attr)
            ignored = any(re.match(r"\s*ignore\b", attr) for attr in attributes)
            # The pre-existing privileged root fixture is deliberately isolated.
            # No other acceptance row may become ignored, in either order.
            assert not ignored or (row["id"], path, base) == (
                "SEC-ROOT", "crates/bingsu-collect/src/limits.rs", "root_cannot_restore_limits_or_capabilities"
            ), (row["id"], "ignored test")
            crate = path.split("/")[1]
            # These paths are included by an explicit native test target.
            target = {"crates/bingsu-collect/src/limits.rs": "startup",
                      "crates/bingsu-collect/src/landlock.rs": "startup",
                      "crates/bingsu-collect/tests/filter/runtime.rs": "filter",
                      "crates/bingsu/src/prompt_read.rs": "collector_lifecycle"}.get(path, Path(path).stem)
            target_path = f"crates/{crate}/tests/{target}.rs"
            if path != target_path:
                target_source = read(target_path)
                if path.endswith("/runtime.rs"):
                    assert "mod runtime;" in target_source
                else:
                    includes = re.findall(r'#\[path = "([^"\n]+)"\]', target_source)
                    assert path in {str((ROOT / target_path).parent.joinpath(include).resolve().relative_to(ROOT)) for include in includes}, (row["id"], "target module inclusion")
            runnable = [run for _, run in commands if run[:2] == ["cargo", "test"] and "--no-run" not in run
                        and ["-p", crate] in [run[i:i+2] for i in range(len(run))]
                        and ["--test", target] in [run[i:i+2] for i in range(len(run))]
                        and not any(v in run for v in ("--skip", "--list", "--exact", "--ignored"))
                        and ("--" not in run or all(v == "--nocapture" or v.startswith("--test-threads=") for v in run[run.index("--") + 1:run.index("|") if "|" in run else len(run)]))]
            assert runnable, (row["id"], "no CI cargo target", crate, target)
            module = {"crates/bingsu-collect/src/limits.rs": "limits::tests::",
                      "crates/bingsu-collect/src/landlock.rs": "landlock::tests::",
                      "crates/bingsu-collect/tests/filter/runtime.rs": "runtime::",
                      "crates/bingsu/src/prompt_read.rs": "prompt_read::tests::"}.get(path, "")
            label = "test " + module + base + " ... ok"
            evidence = []
            for step, grep in commands:
                if grep[:3] != ["grep", "-F", label]:
                    continue
                for run_step, run in commands:
                    if run_step["_job"] != step["_job"] or "tee" not in run or run[run.index("tee") + 1:] != grep[3:]:
                        continue
                    required_if = ("runner.os == 'Linux'" if row["platform"].startswith("Linux") else
                                   "runner.os == 'macOS'" if row["platform"] == "macOS" else None)
                    if any(entry.get("if") not in (None, required_if) for entry in (step, run_step)):
                        continue
                    if ignored:
                        if not ("sudo" == run[0] and "$bin" in run and "--exact" in run and
                                module + base in run and "--ignored" in run):
                            continue
                        # Tie the selected privileged binary to this cargo target.
                        if not any("--no-run" in c and ["--test", target] in [c[i:i+2] for i in range(len(c))]
                                   and ["-p", crate] in [c[i:i+2] for i in range(len(c))]
                                   for c in run_commands(run_step)):
                            continue
                    elif run not in runnable:
                        continue
                    evidence.append((step, run_step))
            assert evidence, (row["id"], "no asserted CI Rust pass", label)


# 이것을 실패시키는 것: TSV의 오타·중복 선언·미수집 매개변수·CI에서 실행/단언하지 않는 행.
def test_acceptance_table_tests_exist_and_run_in_ci():
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    files = sorted({line.split("\t")[3].split("::")[0] for line in table.splitlines()[1:] if ".py::" in line})
    collected = []
    # These historical test directories both expose a top-level conftest;
    # isolate collection so their helpers cannot shadow each other.
    for file in files:
        result = subprocess.run([sys.executable, "-B", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", file],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, (file, result.stdout, result.stderr)
        collected.extend(result.stdout.splitlines())
    assert_acceptance_table(table, (ROOT / ".github/workflows/ci.yml").read_text(), collected=collected)


@pytest.mark.parametrize("before,after", [
    ("run: python3 scripts/prepare_git_corpus.py", "run: python3 --version"),
    ("export BINGSU_GIT_CORPUS_REQUIRED=1", "export BINGSU_GIT_CORPUS_REQUIRED=0"),
    ("grep -Fx 'PASSED tests/shell/test_git_collection_security.py::test_hostile_git_canaries_have_zero_effects'",
     "grep -F 'PASSED tests/shell/test_git_collection_security.py::test_hostile_git_canaries_have_zero_effects'"),
    ("-m pytest tests/shell/test_git_collection_security.py -q", "-m pytest tools/fsbudget/tests -q"),
    ("grep -F 'PASSED tests/shell/test_git_collection_security.py::test_status_matches_policy_porcelain_corpus'",
     "# grep -F 'PASSED tests/shell/test_git_collection_security.py::test_status_matches_policy_porcelain_corpus'"),
    ("grep -Fx 'PASSED tests/shell/test_git_collection_security.py::test_untracked_file_counts_follow_u7[untracked]",
     "grep -F 'PASSED tests/shell/test_git_collection_security.py::test_untracked_file_counts_follow_u7[untracked]"),
    ("PASSED tests/shell/test_git_collection_security.py::test_untracked_file_counts_follow_u7[untracked-at-cap]'",
     "XFAIL tests/shell/test_git_collection_security.py::test_untracked_file_counts_follow_u7[untracked-at-cap]'"),
])
def test_f1_ci_seam_rejects_missing_preparation_or_exact_pass(before, after):
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert before in workflow
    with pytest.raises(AssertionError):
        assert_acceptance_table(table, workflow.replace(before, after))


# 이것을 실패시키는 것: 빠진 선언·중복 선언 또는 주석뿐인 CI 단언을 수용하는 것.
@pytest.mark.parametrize("damage", ["missing", "duplicate", "uncollected", "not-run", "comment", "cargo-target", "cargo-filter", "removed-row", "module"])
def test_acceptance_table_rejects_mutations(damage):
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    path = "bench/tests/test_collector_product.py"
    name = "test_latency_measures_verification_spawn_ready_and_read_separately"
    sources = {}
    collected = None
    if damage == "removed-row":
        table = "\n".join(line for line in table.splitlines() if not line.startswith("SEC-FSIZE\t")) + "\n"
    elif damage == "module":
        target = "crates/bingsu-collect/tests/startup.rs"
        sources[target] = (ROOT / target).read_text().replace('#[path = "../src/landlock.rs"]', '#[path = "../src/absent.rs"]')
    elif damage == "cargo-filter":
        workflow = workflow.replace("--test collector_lifecycle --test collection_store --bin bingsu -- --test-threads=2", "--test collector_lifecycle --test collection_store --bin bingsu -- --exact absent")
    elif damage == "missing":
        table = table.replace(name, "test_absent")
    elif damage == "duplicate":
        sources[path] = (ROOT / path).read_text() + f"\ndef {name}(): pass\n"
    elif damage == "uncollected":
        collected = []
    elif damage == "cargo-target":
        workflow = workflow.replace("--test collector_lifecycle", "--test absent")
    elif damage == "not-run":
        workflow = workflow.replace("bench/tests/test_collector_product.py ", "")
    else:
        workflow = workflow.replace("          grep -F 'PASSED " + path + "::" + name, "          # grep -F 'PASSED " + path + "::" + name)
    with pytest.raises(AssertionError):
        assert_acceptance_table(table, workflow, read=lambda p: sources.get(p, (ROOT / p).read_text()), collected=collected)


# 이것을 실패시키는 것: #[test] 앞/뒤 ignore·플랫폼 불일치/거짓 cfg·조건부 ignore로 행을 없애는 것.
@pytest.mark.parametrize("attribute", [
    "#[ignore]", "#[ignore]\n/* attribute order must include comments */", '#[ignore = "hidden"]', "#[cfg(any())]", '#[cfg(target_os = "macos")]',
    '#[cfg(all(unix, not(test)))]', '#[cfg(\n    any(),\n)]', '#[cfg_attr(test, ignore)]',
])
@pytest.mark.parametrize("before", [True, False], ids=["before-test", "after-test"])
def test_acceptance_table_refuses_disabled_rust_attributes(attribute, before):
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    path = "crates/bingsu/tests/collector_lifecycle.rs"
    source = (ROOT / path).read_text()
    anchor = "#[test]\nfn early_exit_never_signals_recycled_pid"
    replacement = (attribute + "\n#[test]" if before else "#[test]\n" + attribute)
    changed = source.replace(anchor, replacement + "\nfn early_exit_never_signals_recycled_pid")
    assert changed != source
    with pytest.raises(AssertionError, match="SEC-PIDFD"):
        assert_acceptance_table(table, workflow, read=lambda p: changed if p == path else (ROOT / p).read_text())


# 이것을 실패시키는 것: row 플랫폼에서 참인 복합 cfg까지 거부하는 것.
@pytest.mark.parametrize("attribute", ["#[cfg(all(unix, test))]", "#[cfg(not(any()))]",
                                        '#[cfg(any(target_os = "linux", target_os = "macos"))]'])
def test_acceptance_table_accepts_enabled_rust_attributes(attribute):
    path = "crates/bingsu/tests/collector_lifecycle.rs"
    source = (ROOT / path).read_text()
    anchor = "#[test]\nfn early_exit_never_signals_recycled_pid"
    changed = source.replace(anchor, attribute + "\n" + anchor)
    assert changed != source
    assert_acceptance_table((ROOT / "tests/collector-acceptance.tsv").read_text(),
                            (ROOT / ".github/workflows/ci.yml").read_text(),
                            read=lambda p: changed if p == path else (ROOT / p).read_text())


# 이것을 실패시키는 것: Rust 행 하나의 ... ok 증거를 삭제/주석 처리하거나 다른 로그에서 가져오는 것.
@pytest.mark.parametrize("row", [line.split("\t") for line in (ROOT / "tests/collector-acceptance.tsv").read_text().splitlines()[1:]
                                 if ".rs::" in line], ids=lambda row: row[0])
@pytest.mark.parametrize("damage", ["comment", "wrong-log"])
def test_acceptance_table_requires_each_rust_pass(row, damage):
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    name = row[3].split("::", 1)[1]
    lines = workflow.splitlines(True)
    changed = []
    count = 0
    for line in lines:
        if "grep -F 'test " in line and name + " ... ok'" in line:
            count += 1
            line = (line.replace("grep -F", "# grep -F") if damage == "comment" else
                    re.sub(r'"\$RUNNER_TEMP/[^"\n]+"', '"$RUNNER_TEMP/absent.txt"', line))
        changed.append(line)
    assert count
    with pytest.raises(AssertionError, match="no asserted CI Rust pass"):
        assert_acceptance_table(table, "".join(changed))


# 이것을 실패시키는 것: PERF-NORMAL의 PASS 하나 또는 괄호 없는 grep으로 누락된 매개변수를 숨기는 것.
@pytest.mark.parametrize("parameter", ["degraded", "version", "field-count", "stderr", "exit"])
@pytest.mark.parametrize("damage", ["comment", "unparameterized"])
def test_acceptance_table_requires_each_normal_parameter(parameter, damage):
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    anchor = f"          grep -F 'PASSED bench/tests/test_collector_product.py::test_normal_product_measurement_refuses_fallback_and_broken_records[{parameter}]'"
    assert anchor in workflow
    replacement = anchor.replace("grep -F", "# grep -F") if damage == "comment" else anchor.replace(f"[{parameter}]", "")
    with pytest.raises(AssertionError, match="PERF-NORMAL-" + parameter.upper()):
        assert_acceptance_table(table, workflow.replace(anchor, replacement))


# 이것을 실패시키는 것: 보안 단계 하나에 continue-on-error 또는 필수 행을 건너뛰는 if를 붙이는 것.
@pytest.mark.parametrize("control", ["continue-on-error: true", "continue-on-error: false", "if: false"])
def test_every_security_step_rejects_skip_controls(control):
    saved = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    for job in ("collector", "collector-probes"):
        _, steps = workflow_job(saved["ci.yml"], job)
        job_text = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [\w-]+:|\Z)", saved["ci.yml"])[1]
        blocks = re.findall(r"(?ms)^      - .*?(?=^      - |\Z)", job_text)
        assert len(blocks) == len(steps)
        for index, step in enumerate(steps):
            if "run" not in step:
                continue
            block = blocks[index]
            before, after = saved["ci.yml"].split(block, 1)
            if control.startswith("if:") and "if" in step:
                block = block.replace("if: " + step["if"], control, 1)
            else:
                lines = block.splitlines()
                lines.insert(1, "        " + control)
                block = "\n".join(lines) + "\n"
            changed = dict(saved)
            changed["ci.yml"] = before + block + after
            with pytest.raises(AssertionError):
                assert_ci_contract(changed)
    assert saved["ci.yml"] == (ROOT / ".github/workflows/ci.yml").read_text()


# 이것을 실패시키는 것: job 우회·중복 YAML 키·간접 참조·run 주석·셸 조건으로 단언을 숨기는 것.
@pytest.mark.parametrize("damage", ["job-continue", "job-if", "duplicate-run", "alias", "folded-if",
                                        "comment-assertions", "shell-if", "comment-basetemp", "matrix-exclude",
                                        # 이것을 실패시키는 것: workflow 기본 셸·startup env와 inline env로 검사를 우회하는 것.
                                        "workflow-defaults", "workflow-BASH_ENV", "workflow-SHELLOPTS", "inline-env",
                                        # 이것을 실패시키는 것: step/job의 shell·defaults·BASH_ENV·SHELLOPTS 우회.
                                        *[f"{job}-{scope}-{setting}" for job in ("collector", "collector-probes")
                                          for scope in ("job", "step")
                                          for setting in ("shell", "defaults", "BASH_ENV", "SHELLOPTS")],
                                        # 이것을 실패시키는 것: set +e/옵션 해제, trap/exec/return/eval/source/. 실행 우회.
                                        "set+e", "set+o", "set-args", "trap", "exec", "return", "eval", "source", "dot",
                                        # 이것을 실패시키는 것: heredoc/here-string 속 grep과 후행 true/상태 대체 구문.
                                        "heredoc", "here-string", "trailing-true", "grep-pipe", "grep-and", "grep-semicolon", "grep-background"])
def test_ci_structural_mutations_are_refused(damage):
    texts = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    saved = texts["ci.yml"]
    anchor = '          grep -F \'PASSED tests/shell/test_collector_security.py::test_shipped_collector_trace_has_no_forbidden_effect\' "$RUNNER_TEMP/m3b-security.txt"\n'
    shell_commands = {
        "set+e": "set +e", "set+o": "set +o errexit", "set-args": "set -- ignored",
        "trap": "trap 'exit 0' ERR", "exec": "exec true", "return": "return 0",
        "eval": "eval 'set +e'", "source": "source /dev/null", "dot": ". /dev/null",
    }
    if damage.startswith("workflow-"):
        setting = damage.removeprefix("workflow-")
        value = ("defaults:\n  run:\n    shell: bash {0}\n" if setting == "defaults" else
                 "env:\n  " + setting + ": /tmp/override\n")
        changed = saved.replace("\njobs:\n", "\n" + value + "\njobs:\n", 1)
    elif damage == "inline-env":
        changed = saved.replace("        name: Assert native Linux M3b security passes\n",
                                '        name: Assert native Linux M3b security passes\n        env: {BASH_ENV: /tmp/override}\n', 1)
    elif damage.startswith(("collector-job-", "collector-step-", "collector-probes-")):
        job, scope, setting = damage.rsplit("-", 2)
        start = saved.index(f"  {job}:\n")
        end_match = re.search(r"(?m)^  [\w-]+:", saved[start + len(f"  {job}:\n"):])
        end = start + len(f"  {job}:\n") + end_match.start() if end_match else len(saved)
        block = saved[start:end]
        indent = "    " if scope == "job" else "        "
        value = ({"shell": "shell: bash {0}\n", "defaults": "defaults:\n" + indent + "  run:\n" + indent + "    shell: bash {0}\n"}
                 .get(setting, "env:\n" + indent + "  " + setting + ": /tmp/override\n"))
        if scope == "job":
            block = block.replace(f"  {job}:\n", f"  {job}:\n" + indent + value, 1)
        else:
            block = block.replace("        run:", indent + value + "        run:", 1)
        changed = saved[:start] + block + saved[end:]
    elif damage in shell_commands:
        changed = saved.replace(anchor, "          " + shell_commands[damage] + "\n" + anchor, 1)
    elif damage == "heredoc":
        changed = saved.replace(anchor, "          cat > /dev/null <<'EOF'\n" + anchor + "          EOF\n", 1)
    elif damage == "here-string":
        changed = saved.replace(anchor, "          cat <<<ignored\n" + anchor, 1)
    elif damage == "trailing-true":
        changed = saved.replace(anchor, anchor + "          true\n", 1)
    elif damage.startswith("grep-"):
        suffix = {"grep-pipe": " | true", "grep-and": " && true", "grep-semicolon": ";true", "grep-background": " & true"}[damage]
        changed = saved.replace(anchor, anchor.rstrip("\n") + suffix + "\n", 1)
    elif damage == "job-continue":
        changed = saved.replace("  collector:\n", "  collector:\n    continue-on-error: true\n")
    elif damage == "job-if":
        start = saved.index("  collector:\n")
        changed = saved[:start] + saved[start:].replace("if: needs.detect.outputs.rust == 'true'", "if: false", 1)
    elif damage == "duplicate-run":
        changed = saved.replace("        run: python3 scripts/check_collector_filter.py\n", "        run: echo ignored\n        run: python3 scripts/check_collector_filter.py\n", 1)
    elif damage == "alias":
        changed = saved.replace("if: runner.os == 'Linux'", "if: *skip", 1)
    elif damage == "folded-if":
        changed = saved.replace("if: runner.os == 'Linux'", "if: >\n          false", 1)
    elif damage == "matrix-exclude":
        changed = saved.replace("        os: [ubuntu-24.04, ubuntu-24.04-arm, macos-latest, macos-26-intel]", "        os: [ubuntu-24.04, ubuntu-24.04-arm, macos-latest, macos-26-intel]\n        exclude: [{os: ubuntu-24.04-arm}]")
    elif damage == "comment-assertions":
        changed = re.sub(r"(?m)^(\s*)grep -F", r"\1# grep -F", saved)
    elif damage == "comment-basetemp":
        changed = saved.replace(' --basetemp="$RUNNER_TEMP/m3b-traces/native"', '')
        changed += '\n# --basetemp="$RUNNER_TEMP/m3b-traces/native"\n'
    else:
        changed = saved.replace("          grep -F 'PASSED", "          if false; then\n            grep -F 'PASSED", 1)
    assert changed != saved
    texts["ci.yml"] = changed
    with pytest.raises(AssertionError):
        assert_ci_contract(texts)


# 이것을 실패시키는 것: 허용한 errexit 셸과 옵션 추가만 하는 set까지 잘못 거부하는 것.
@pytest.mark.parametrize("shell", ["bash -e {0}", "bash --noprofile --norc -eo pipefail {0}"])
@pytest.mark.parametrize("options", ["set -o pipefail", "set -eo pipefail", "set -euo pipefail"])
def test_ci_accepts_shells_and_options_that_keep_errexit(shell, options):
    texts = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    anchor = "        name: Assert native Linux M3b security passes\n        run: |\n"
    assert anchor in texts["ci.yml"]
    texts["ci.yml"] = texts["ci.yml"].replace(anchor, "        name: Assert native Linux M3b security passes\n        shell: " + shell + "\n        run: |\n          " + options + "\n", 1)
    assert_ci_contract(texts)
    assert_acceptance_table((ROOT / "tests/collector-acceptance.tsv").read_text(), texts["ci.yml"])


def assert_ci_contract(texts):
    required = {
        "ci.yml": ("ubuntu-24.04-arm", "macos-latest", "M3b native musl lifecycle security",
                   "--prepare target/release/bingsu", "collector-tests/bin/python",
                   "test_shipped_collector_ready_has_installed_limits", "test_failure_modes_trace_collector_effects",
                   "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[as]",
                   "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[exec]",
                   "PASSED tests/shell/test_collector_security.py::test_macos_first_completed_overlimit_sample",
                   "check_collector_symbols.py", "check_collector_dependencies.py", "test_collector_no_spawn_macos.py",
                   "root_cannot_restore_limits_or_capabilities", "B2 limits PASS",
                   "test runtime::x14_threads_and_status_survive_fork_is_refused ... ok",
                   "test runtime::x16_all_mutations_are_denied_with_fsize_zero ... ok", "X-14 PASS", "X-14", "X-02", "X-32"),
        "shell.yml": ("libc: [gnu, musl]", "--ignore tests/shell/test_collector_security.py"),
        "bench.yml": ("base_ref:", "--rounds 200", "--base base/target/release/bingsu", "--out candidate/target/f3/m3c-product.json",
                      "if: always()", "if-no-files-found: error"),
    }
    steps = ci_test_evidence(texts["ci.yml"])
    executable = "\n".join(" ".join(command) for step in steps for command in run_commands(step))
    for file, tokens in required.items():
        for token in tokens:
            if file == "ci.yml" and token not in {"ubuntu-24.04-arm", "macos-latest", "M3b native musl lifecycle security", "X-14", "X-02", "X-32"}:
                assert token in executable, (file, "run evidence", token)
            else:
                assert token in texts[file], (file, token)
    assert any(step.get("name") == "M3b native musl lifecycle security" for step in steps)
    collector = re.search(r"(?ms)^  collector:\n(.*?)(?=^  [\w-]+:|\Z)", texts["ci.yml"])[1]
    for libc in ("native", "musl"):
        assert f'--basetemp=$RUNNER_TEMP/m3b-traces/{libc}' in executable
    artifact = collector.split("      - name: Preserve M3b raw security traces on failure\n")[1].split("      - name:")[0]
    for token in ("if: failure()", "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
                  "name: m3b-security-traces-${{ matrix.os }}", "path: ${{ runner.temp }}/m3b-traces/**/*.trace"):
        assert token in artifact, token
    # Both full-suite jobs must exclude the unprepared security module. The
    # Linux job applies the same invocation to all three container images.
    for job in ("shell-linux", "shell-macos"):
        block = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [\w-]+:|\Z)", texts["shell.yml"])
        assert block, job
        assert "--ignore tests/shell/test_collector_security.py" in block[1], job
    ledger = (ROOT / "bench/probes/collector-acceptance.tsv").read_text()
    for case in ("X-02", "X-14", "X-16", "X-32"):
        assert case + "\t" in ledger, case


# 이것을 실패시키는 것: 필수 native/권한/macOS/실험 행을 CI에서 빼거나 측정 부재를 숨기는 것.
def test_ci_has_no_silent_acceptance_skip():
    assert_ci_contract({name: (ROOT / ".github/workflows" / name).read_text()
                        for name in ("ci.yml", "shell.yml", "bench.yml")})


# 이것을 실패시키는 것: 필수 셀 하나를 삭제한 CI도 게이트가 수용하는 것.
@pytest.mark.parametrize("file,token", [
    ("ci.yml", "M3b native musl lifecycle security"),
    ("ci.yml", "test_shipped_collector_ready_has_installed_limits"),
    ("ci.yml", "test_failure_modes_trace_collector_effects"),
    ("ci.yml", "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[exec]"),
    ("ci.yml", "PASSED tests/shell/test_collector_security.py::test_macos_first_completed_overlimit_sample"),
    ("ci.yml", "check_collector_symbols.py"),
    ("ci.yml", "check_collector_dependencies.py"),
    ("ci.yml", "root_cannot_restore_limits_or_capabilities"),
    ("ci.yml", "test runtime::x14_threads_and_status_survive_fork_is_refused ... ok"),
    ("ci.yml", "test runtime::x16_all_mutations_are_denied_with_fsize_zero ... ok"),
    ("ci.yml", '--basetemp="$RUNNER_TEMP/m3b-traces/native"'),
    ("ci.yml", '--basetemp="$RUNNER_TEMP/m3b-traces/musl"'),
    ("ci.yml", "if: failure()"),
    ("ci.yml", "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"),
    ("ci.yml", "path: ${{ runner.temp }}/m3b-traces/**/*.trace"),
    ("bench.yml", "--rounds 200"),
])
def test_missing_ci_cell_is_refused(file, token):
    saved = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    changed = dict(saved)
    changed[file] = changed[file].replace(token, "REMOVED")
    with pytest.raises(AssertionError):
        assert_ci_contract(changed)
    assert saved[file] == (ROOT / ".github/workflows" / file).read_text()


@pytest.mark.parametrize("job", ["shell-linux", "shell-macos"])
def test_each_unprepared_shell_job_must_exclude_security(job):
    texts = {name: (ROOT / ".github/workflows" / name).read_text()
             for name in ("ci.yml", "shell.yml", "bench.yml")}
    start = texts["shell.yml"].index(f"\n  {job}:")
    before, block = texts["shell.yml"][:start], texts["shell.yml"][start:]
    texts["shell.yml"] = before + block.replace("--ignore tests/shell/test_collector_security.py", "", 1)
    with pytest.raises(AssertionError, match=job):
        assert_ci_contract(texts)


def assert_collector_roles(lines, fixture, collector=None, *, collector_debug_assertions=False, repository_probe=False):
    from fsbudget.attribute import collector_attribute
    from fsbudget.classify import split_args
    from fsbudget.formula import collector_success_expected
    from fsbudget.gate import check
    from fsbudget.strace_parse import parse
    observed = collector_attribute(lines,
                                   {"front": fixture, "helper": fixture, "collector": collector or fixture,
                                    "verbs": {"front": "--trace", "helper": "--trace-helper", "collector": "__collect-v1" if collector else "--security-worker"}})
    print("collector CLOEXEC open pairs:", json.dumps(observed.cloexec_pairs))
    assert not observed.errors, observed.errors
    calls = parse("\n".join(lines))
    entry, = [c for c in calls if c.name == "execve" and
              split_args(c.args)[:1] == [json.dumps(collector or fixture)] and
              split_args(c.args)[1] == json.dumps([collector or fixture, "__collect-v1" if collector else "--security-worker"])]
    worker = [c for c in calls if c.pid == entry.pid and c.index > entry.index]
    landlock = any(c.name == "landlock_restrict_self" and c.ret == "0" for c in worker)
    variant = "fixture" if collector is None else "shipped-debug" if collector_debug_assertions else "shipped-release"
    openat2_succeeded = any(c.name == "openat2" and not c.ret.startswith("-1") for c in worker)
    want = {"collector": collector_success_expected(variant, landlock=landlock,
        repository_probe=repository_probe, openat2_succeeded=openat2_succeeded)}
    assert not check(observed.counts, want, "exact", ["collector"]), observed.counts
    assert {role for role in observed.counts} == {"front", "helper", "collector"}

    # Each extra query has a reviewed owner and immediately precedes its close
    # in this PID (other traced threads may interleave). Do not accept eight
    # arbitrary queries merely because their aggregate matches the formula.
    queries = [c for c in worker if c.name == "fcntl" and "F_GETFD" in c.args]
    expected_fds = ([4] if landlock else []) + [4, 1, 3, 5] if variant == "shipped-debug" else []
    if repository_probe and variant == "shipped-debug":
        # Probe opens root at 4, then openat2 dot at 6 (lock owns fd5).
        expected_fds = ([4] if landlock else []) + [4] + ([6] if openat2_succeeded else []) + [4, 1, 3, 5]
    assert [int(split_args(c.args)[0].split("<")[0]) for c in queries] == expected_fds
    for query in queries:
        following = worker[worker.index(query) + 1]
        assert following.name == "close" and following.args == split_args(query.args)[0]
        assert not query.ret.startswith("-1") and following.ret == "0"
    if variant == "shipped-debug":
        if landlock:
            assert "<anon_inode:[landlock-ruleset]>" in queries[0].args
        assert f"</proc/{entry.pid}/statm>" in queries[int(landlock)].args

    return observed


def assert_native_trace(lines, fixture, body_bytes):
    from fsbudget.gate import check
    observed = assert_collector_roles(lines, fixture, repository_probe=True)
    # Validate the actual publisher window against the phase formula, rather
    # than reasserting the formula's own constants in a Rust fixture.
    from collections import Counter
    from fsbudget.classify import collection_publication_kind
    from fsbudget.formula import collection_expected
    from fsbudget.strace_parse import parse
    calls = parse("\n".join(lines))
    assert not calls.errors, calls.errors
    begin, = [c for c in calls if c.name == "write" and '"D2-PUBLICATION-BEGIN\\n"' in c.args]
    end, = [c for c in calls if c.name == "write" and '"D2-PUBLICATION-END\\n"' in c.args]
    phase = [c for c in calls if c.pid == begin.pid and begin.index < c.index < end.index]
    expected = collection_expected(3, body_bytes, False, False)
    counts = Counter(k for c in phase if (k := collection_publication_kind(c)))
    measured = {key: counts[key] for key in expected}
    assert not check({"helper-publication": measured}, {"helper-publication": expected}, "exact", ["helper-publication"]), counts
    assert not any(c.name in {"clone", "clone3", "fork", "vfork", "execve", "execveat", "socket", "connect"} for c in phase)
    return observed


def recorded_success_trace(worker):
    directory = ROOT / "tools/fsbudget/tests/fixtures"
    lines = (directory / f"m3b-bookworm-aarch64-{worker}-fd-queries.strace").read_text().splitlines()
    fixture = "/home/tester/target/debug/collector-product-fixture/collector-product"
    shipped = "/home/tester/target/debug/bingsu-collect" if worker == "shipped-debug" else None
    return lines, fixture, shipped


# 실제 Bookworm/aarch64 발췌: -O fixture 3회, 출하 debug 3+5회.
@pytest.mark.parametrize("worker,queries", [("fixture", 3), ("shipped-debug", 8)])
def test_recorded_success_trace_fd_queries(worker, queries):
    lines, fixture, shipped = recorded_success_trace(worker)
    got = assert_collector_roles(lines, fixture, shipped, collector_debug_assertions=bool(shipped))
    assert got.errors == [] and got.counts["collector"]["fd_query"] == queries


def recorded_repository_trace(worker):
    # Bookworm/aarch64 glibc 2.36 startup/shutdown excerpts. Preserve the raw
    # unfinished/resumed records; omit only pipe payloads and parent FS work.
    path = ROOT / f"tools/fsbudget/tests/fixtures/m3c-bookworm-aarch64-{worker}-probe.strace"
    fixture = "/home/tester/target/debug/collector-product-fixture/collector-product"
    shipped = "/home/tester/target/debug/bingsu-collect" if worker == "shipped-debug" else None
    return path.read_text().splitlines(), fixture, shipped


# 이것을 실패시키는 것: newfstatat metadata 또는 SYNC_AS_STAT 표기의 mount-id를 probe에서 누락하는 것.
@pytest.mark.parametrize("worker,queries", [("fixture", 3), ("shipped-debug", 10)])
def test_recorded_repository_probe_metadata(worker, queries):
    lines, fixture, shipped = recorded_repository_trace(worker)
    got = assert_collector_roles(lines, fixture, shipped,
        collector_debug_assertions=bool(shipped), repository_probe=True)
    assert got.errors == [] and got.counts["collector"]["fd_query"] == queries
    assert got.counts["collector"]["probe_fstat"] == got.counts["collector"]["probe_statx"] == 1
    assert got.counts["collector"]["fstat"] == 1  # inherited lock, outside probe


# 이것을 실패시키는 것: 실제 probe의 호출 누락/중복/다른 fd/경로/flags를 exact 공식이 놓치는 것.
@pytest.mark.parametrize("worker", ["fixture", "shipped-debug"])
@pytest.mark.parametrize("call", ["newfstatat", "statx"])
@pytest.mark.parametrize("damage", ["removed", "duplicate", "wrong-fd", "path", "no-empty-path", "extra-flag"])
def test_recorded_repository_probe_rejects_mutations(worker, call, damage):
    lines, fixture, shipped = recorded_repository_trace(worker)
    index, = [i for i, line in enumerate(lines) if re.match(rf"\d+\s+{call}\(4</>,", line)]
    pid = lines[index].split()[0]
    group = [index]
    if "<unfinished ...>" in lines[index]:
        group.append(next(i for i in range(index + 1, len(lines))
                          if re.match(rf"{pid}\s+<\.\.\. {call} resumed>", lines[i])))
    changed = lines.copy()
    if damage == "removed":
        changed = [line for i, line in enumerate(changed) if i not in group]
    elif damage == "duplicate":
        changed[group[-1] + 1:group[-1] + 1] = [lines[i] for i in group]
    else:
        old, new = {"wrong-fd": ("4</>", "7</>"), "path": ('""', '"HEAD"'),
                    "no-empty-path": ("AT_EMPTY_PATH", "0"),
                    "extra-flag": ("AT_EMPTY_PATH", "AT_EMPTY_PATH|0x80000000")}[damage]
        assert old in "\n".join(lines[i] for i in group)
        for i in group:
            changed[i] = changed[i].replace(old, new)
    with pytest.raises(AssertionError):
        assert_collector_roles(changed, fixture, shipped,
            collector_debug_assertions=bool(shipped), repository_probe=True)


# 각 OwnedFd의 검사 누락/중복 및 같은 합계의 엉뚱한 조회를 개별적으로 거부한다.
@pytest.mark.parametrize("query", range(5), ids=["ruleset", "statm", "result", "request", "lock"])
@pytest.mark.parametrize("damage", ["removed", "duplicate", "wrong-command", "before-close"])
def test_shipped_fd_drop_checks_are_exact(query, damage):
    lines, fixture, shipped = recorded_success_trace("shipped-debug")
    indices = [i for i, line in enumerate(lines) if " F_GETFD" in line]
    index = indices[query]
    group = [index]
    if "<unfinished ...>" in lines[index]:
        group.append(next(i for i in range(index + 1, len(lines)) if "<... fcntl resumed>" in lines[i]))
    changed = lines.copy()
    if damage == "removed":
        changed = [line for i, line in enumerate(changed) if i not in group]
    elif damage == "duplicate":
        changed[group[-1] + 1:group[-1] + 1] = [lines[i] for i in group]
    elif damage == "wrong-command":
        changed[index] = changed[index].replace("F_GETFD", "F_GETFL")
    else:
        # Preserve the exact aggregate and fd identity, but break the reviewed
        # query/close adjacency in the collector's own syscall sequence.
        changed.insert(group[-1] + 1, "2783 getpid() = 2783")
    with pytest.raises(AssertionError):
        assert_collector_roles(changed, fixture, shipped, collector_debug_assertions=True)


# fsbudget conftest나 선행 테스트 없이 이 모듈만 읽어도 import가 성공해야 한다.
def test_native_trace_import_is_independent():
    code = """
import importlib.util
spec = importlib.util.spec_from_file_location('security', 'tests/shell/test_collector_security.py')
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)
try:
    security.assert_native_trace([], '/fixture', 0)
except AssertionError:
    pass
else:
    raise AssertionError('empty trace was accepted')
"""
    result = subprocess.run([sys.executable, "-B", "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (result.stdout, result.stderr)


# 이것을 실패시키는 것: 실제 TEST_MASK worker의 파일 쓰기/자식/소켓 효과 또는 역할 누락을 놓치는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux native strace product filter")
def test_native_collector_trace_has_no_forbidden_effect(preparation, tmp_path):
    import shutil
    strace = shutil.which("strace")
    assert strace, "the native Linux gate requires strace"
    trace = tmp_path / "collector.trace"
    scratch = tmp_path / "trace-store"
    scratch.mkdir(mode=0o700)
    fixture = preparation["fixture"]
    result = product.run([strace, "-f", "-q", "-y", "-s", "65536", "-e", "trace=all", "-o", trace,
                          fixture, "--trace", scratch], env={**os.environ, "TMPDIR": str(scratch)})
    assert json.loads(result.stdout.splitlines()[-1])["published"], result.stdout
    response, = (scratch / "runtime").rglob("response")
    assert_native_trace(trace.read_text().splitlines(), fixture, response.stat().st_size - 64)


# 이것을 실패시키는 것: 출하 실행 파일 대신 fixture를 부르거나 빈 제품 요청을 완료하지 못하는 것.
def test_shipped_collector_empty_request_completes(preparation, tmp_path):
    result = product.run([preparation["fixture"], "--helper-case", tmp_path, "--shipped-worker"],
                         env={**os.environ, "TMPDIR": str(tmp_path)})
    report = json.loads(result.stdout.splitlines()[-1])
    # Explicit mask0 remains a successful empty exchange after activation.
    assert report == {"reason": "Complete", "published": False, "reaped": True, "partial_values": 0, "probe": ""}


# 이것을 실패시키는 것: 성공 trace가 fixture만 실행하거나 출하 collector의 금지 효과를 놓치는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux native strace shipped collector")
def test_shipped_collector_trace_has_no_forbidden_effect(preparation, tmp_path):
    import shutil
    strace = shutil.which("strace")
    assert strace, "the native Linux gate requires strace"
    trace = tmp_path / "shipped-collector.trace"
    scratch = tmp_path / "shipped-store"
    scratch.mkdir(mode=0o700)
    fixture = preparation["fixture"]
    shipped = str(real_bin().with_name("bingsu-collect"))
    result = product.run([strace, "-f", "-q", "-y", "-s", "65536", "-e", "trace=all", "-o", trace,
                          fixture, "--trace", scratch, "--shipped-worker"],
                         env={**os.environ, "TMPDIR": str(scratch)})
    report = json.loads(result.stdout.splitlines()[-1])
    assert report["reason"] == "Complete" and not report["published"] and report["reaped"], report
    assert_collector_roles(trace.read_text().splitlines(), fixture, shipped,
                           collector_debug_assertions=preparation["collector_debug_assertions"], repository_probe=True)


# 이것을 실패시키는 것: 출하 경로 pin 대신 fixture exec를 수용하거나 쓰기 효과를 허용하는 것.
@pytest.mark.parametrize("damage", ["fixture-exec", "write"])
def test_shipped_trace_gate_rejects_mutations(damage):
    lines = [
        '10 execve("/fixture", ["/fixture", "--trace"], 0x0) = 0',
        '10 clone(flags=SIGCHLD) = 11',
        '11 execve("/fixture", ["/fixture", "--trace-helper"], 0x0) = 0',
        '11 clone(flags=SIGCHLD) = 12',
        '12 execve("/shipped/bingsu-collect", ["/shipped/bingsu-collect", "__collect-v1"], 0x0) = 0',
        '12 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=12}) = 0',
        '12 fcntl(3, F_GETFL) = 0', '12 fcntl(1, F_GETFL) = 0', '12 fcntl(5, F_GETFL) = 0',
        '12 newfstatat(5, "", {st_mode=S_IFREG|0600}, AT_EMPTY_PATH) = 0',
        '12 fgetxattr(5, "system.posix_acl_access", 0x0, 132) = -1 ENODATA',
        '12 getcwd("/", 512) = 2',
        '12 openat(AT_FDCWD, "/proc/self/statm", O_RDONLY|O_CLOEXEC) = 4</proc/12/statm>',
        '12 read(4</proc/12/statm>, "100 10", 128) = 6',
    ]
    assert_collector_roles(lines, "/fixture", "/shipped/bingsu-collect")
    saved = lines.copy()
    if damage == "fixture-exec":
        lines[4] = lines[4].replace("/shipped/bingsu-collect", "/fixture")
    else:
        lines.append('12 openat(AT_FDCWD, "/repo/escape", O_WRONLY|O_CREAT, 0600) = 6</repo/escape>')
    with pytest.raises(AssertionError):
        assert_collector_roles(lines, "/fixture", "/shipped/bingsu-collect")
    lines[:] = saved
    assert_collector_roles(lines, "/fixture", "/shipped/bingsu-collect")


# 이것을 실패시키는 것: 출하 execute()에서 base/AS 보호를 빼도 fixture만 검사하여 통과시키는 것.
def test_shipped_collector_ready_has_installed_limits(preparation, tmp_path):
    import fcntl
    import select
    import struct
    lock = tmp_path / "shipped.lock"
    lock.touch(mode=0o600)
    request, writer = os.pipe()
    lock_fd = os.open(lock, os.O_RDONLY)
    copies = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 20) for fd in (request, lock_fd)]
    def setup():
        os.dup2(copies[0], 3)
        os.dup2(copies[1], 5)
    try:
        with subprocess.Popen([real_bin().with_name("bingsu-collect"), "__collect-v1"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env={}, cwd="/", close_fds=False, preexec_fn=setup) as child:
            try:
                ready = bytearray()
                while len(ready) < 104:
                    assert select.select([child.stdout], [], [], 2)[0], "shipped collector did not reach Ready"
                    chunk = os.read(child.stdout.fileno(), 104 - len(ready))
                    assert chunk, "shipped collector exited before Ready"
                    ready.extend(chunk)
                assert ready[:8] == b"BNGIPC05" and ready[10] == 1, ready
                baseline, = struct.unpack_from("<Q", ready, 96)
                assert baseline > 0
                if sys.platform == "linux":
                    limits = Path(f"/proc/{child.pid}/limits").read_text()
                    for name, ceiling in (("Max cpu time", 1), ("Max open files", 64),
                                          ("Max file size", 0), ("Max core file size", 0),
                                          ("Max address space", baseline + 33_554_432)):
                        row = re.search(rf"(?m)^{name}\s+(\d+)\s+(\d+)\s", limits)
                        assert row and 0 <= int(row[1]) <= int(row[2]) <= ceiling, (name, limits)
            finally:
                child.kill()
                child.wait(timeout=3)
    finally:
        for fd in (request, writer, lock_fd, *copies):
            os.close(fd)


def assert_failure_trace(lines, fixture, mode):
    from collections import Counter
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    from fsbudget.attribute import collector_attribute
    from fsbudget.formula import collector_product_expected
    from fsbudget.gate import check
    from fsbudget.strace_parse import parse
    from fsbudget.classify import split_args
    observed = collector_attribute(lines, {"front": fixture, "helper": fixture, "collector": fixture,
        "verbs": {"front": "--trace", "helper": "--trace-helper", "collector": mode}},
        helper_kill=mode in {"--cpu-worker", "--nofile-worker", "--as-worker", "--exec-worker",
                             "--ready-failure-worker", "--malformed-worker"})
    print("collector CLOEXEC open pairs:", json.dumps(observed.cloexec_pairs))
    print("collector unknown syscalls:", observed.counts.get("collector", {}).get("unknown-syscall", 0))
    calls = parse("\n".join(lines))
    assert not calls.errors, calls.errors
    # Front/helper pass mode as a later argument too. Only the successful
    # pinned executable with the exact worker argv starts this worker.
    workers = [c for c in calls if c.name == "execve" and c.ret == "0"
               and split_args(c.args)[:2] == [json.dumps(fixture), json.dumps([fixture, mode])]]
    assert len(workers) == 1, workers
    worker_exec, = workers
    worker = worker_exec.pid
    # The NOFILE probe deliberately opens only /dev/null until EMFILE. Keep
    # collector_attribute strict; account for precisely those probe diagnostics
    # here, with all other errors still rejected. No product allowance changes.
    # The same PID opens /dev/null for stdio in the vfork child while it is
    # still a helper. Only calls after the worker exec are resource probes.
    probes = [c for c in calls if c.pid == worker and c.index > worker_exec.index and c.name in {"open", "openat"}
              and '"/dev/null"' in split_args(c.args)]
    expected_errors = []
    if mode == "--nofile-worker":
        worker_calls = [c for c in calls if c.pid == worker and c.index > worker_exec.index]
        expected_pairs = []
        assert probes and 0 < sum(not c.ret.startswith("-1") for c in probes) < 64, probes
        assert probes[-1].ret.startswith("-1 EMFILE"), probes[-1]
        for c in probes:
            args = split_args(c.args)
            flags = set(args[1 if c.name == "open" else 2].split("|"))
            assert {"O_RDONLY", "O_CLOEXEC"} <= flags <= {"O_RDONLY", "O_CLOEXEC", "O_LARGEFILE"}, c
            # Legacy open remains unknown-fs except for absolute own statm.
            reason = "collector forbidden effect" if c.name == "open" else "collector read outside the M3b bootstrap"
            expected_errors.append(f"pid {worker} (collector): {reason}: {c.name}({c.args})")
            # musl's immediate redundant F_SETFD belongs to this successful
            # O_CLOEXEC open, even on EPERM. It adds no expected diagnostic;
            # check its attribution independently and keep every other error.
            at = worker_calls.index(c)
            following = worker_calls[at + 1] if at + 1 < len(worker_calls) else None
            following_args = split_args(following.args) if following else []
            opened_fd = re.match(r"^\d+", c.ret)
            paired_fd = re.fullmatch(r"(\d+)(?:<.+>)?", following_args[0]) if following_args else None
            if (not c.ret.startswith("-1") and following and following.name == "fcntl"
                    and following_args[1:] == ["F_SETFD", "FD_CLOEXEC"]
                    and opened_fd and paired_fd and int(opened_fd[0]) == int(paired_fd[1])):
                expected_pairs.append({"pid": worker, "open": f"{c.name}({c.args})", "open_ret": c.ret,
                                       "fcntl": f"fcntl({following.args})", "fcntl_ret": following.ret})
        assert [pair for pair in observed.cloexec_pairs if '"/dev/null"' in pair["open"]] == expected_pairs
    else:
        assert not probes, probes
    assert Counter(observed.errors) == Counter(expected_errors), observed.errors
    if mode == "--exec-worker":
        attempts = [c for c in calls if c.pid == worker and c.name == "execve" and '"/never-executed"' in c.args]
        assert len(attempts) == 1 and attempts[0].ret.startswith("-1 EPERM"), attempts
    assert observed.counts["collector"]["exec"] == (2 if mode == "--exec-worker" else 1)
    effects = collector_product_expected("partial")["collector-effects"]
    measured = {key: observed.counts["collector"].get(key, 0) for key in effects}
    assert not check({"collector-effects": measured}, {"collector-effects": effects}, "exact", ["collector-effects"]), measured
    return observed


# 이것을 실패시키는 것: mode를 전달하는 front/helper도 worker로 선택하거나 exec 전 stdio를 NOFILE 탐침으로 세는 것.
# Source filenames and exact original line numbers are in the adjacent
# d2s-bookworm-aarch64-sources.json; these fixtures contain verbatim excerpts.
@pytest.mark.parametrize("mode", ["cpu", "nofile", "as", "exec", "ready-failure", "malformed"])
def test_bookworm_failure_trace_replay(mode):
    directory = ROOT / "tools/fsbudget/tests/fixtures"
    lines = (directory / f"d2s-bookworm-aarch64-{mode}.strace").read_text().splitlines()
    fixture = "/home/tester/target/debug/collector-product-fixture/collector-product"
    assert_failure_trace(lines, fixture, f"--{mode}-worker")
    # 이것을 실패시키는 것: 실제 재생에서도 collector의 금지 효과/잘못된 exec를 허용하는 것.
    from fsbudget.strace_parse import parse
    from fsbudget.classify import split_args
    worker, = [c.pid for c in parse("\n".join(lines)) if c.name == "execve"
               and split_args(c.args)[1] == json.dumps([fixture, f"--{mode}-worker"])]
    for effect in ('write(9</forbidden>, "x", 1) = 1',
                   'openat(AT_FDCWD</>, "/dev/null", O_RDWR) = 9</dev/null>',
                   'execve("/never-executed", ["/never-executed"], 0x0) = 0'):
        changed = list(lines)
        # Insert before exit so the process still has its collector role.
        at = next((i for i, line in enumerate(changed) if line.startswith(f"{worker}  +++")), len(changed))
        changed.insert(at, f"{worker}  {effect}")
        with pytest.raises(AssertionError):
            assert_failure_trace(changed, fixture, f"--{mode}-worker")


# 이것을 실패시키는 것: 실제 AS 실패 trace의 terminal ???를 거부하거나 success/알 수 없는 mode에도 허용하는 것.
def test_ubuntu_as_failure_trace_replay():
    path = ROOT / "tools/fsbudget/tests/fixtures/d2s-ubuntu-aarch64-unknown-syscall.strace"
    lines = path.read_text().splitlines()
    fixture = "/home/runner/work/Bingsu/Bingsu/target/release/collector-product-fixture/collector-product"
    observed = assert_failure_trace(lines, fixture, "--as-worker")
    assert observed.counts["collector"]["unknown-syscall"] == 1
    # Mutation: preserve the trace shape while relabeling it as the success mode.
    for mode in ("--security-worker", "--unreviewed-worker"):
        changed = [line.replace("--as-worker", mode) for line in lines]
        with pytest.raises(AssertionError, match="unknown syscall requires"):
            assert_failure_trace(changed, fixture, mode)


# 이것을 실패시키는 것: 실패 worker의 파일 쓰기/생성/소켓을 실제 trace 대신 상수 0으로 대조하는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace failure-mode effects")
@pytest.mark.parametrize("mode", ["--cpu-worker", "--nofile-worker", "--as-worker", "--exec-worker",
                                  "--ready-failure-worker", "--malformed-worker"])
def test_failure_modes_trace_collector_effects(preparation, tmp_path, mode):
    import shutil
    strace = shutil.which("strace")
    assert strace, "the native Linux gate requires strace"
    trace = tmp_path / "failure.trace"
    scratch = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    fixture = preparation["fixture"]
    # -y keeps device annotations comparable on glibc and musl.
    result = product.run([strace, "-f", "-q", "-y", "-s", "65536", "-o", trace,
                          fixture, "--trace", scratch, mode], env={**os.environ, "TMPDIR": str(scratch)})
    assert result.stderr == b""
    report = json.loads(result.stdout.splitlines()[-1])
    assert report["reaped"], report
    assert report["published"] == (mode != "--ready-failure-worker"), report
    if mode in {"--cpu-worker", "--nofile-worker", "--as-worker", "--exec-worker"}:
        assert report["probe"] == "probe-" + mode[2:-7] + "-pass", report
    assert_failure_trace(trace.read_text().splitlines(), fixture, mode)


# 이것을 실패시키는 것: 실패 trace의 금지 효과를 분류해도 measured를 상수 0으로 덮는 것.
def test_failure_trace_budget_uses_measured_effects(monkeypatch):
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    import fsbudget.attribute as attribution
    fixture = "/fixture"
    lines = [
        '10 execve("/fixture", ["/fixture", "--trace"], 0x0) = 0',
        '10 clone(flags=SIGCHLD) = 11',
        '11 execve("/fixture", ["/fixture", "--trace-helper"], 0x0) = 0',
        '11 clone(flags=SIGCHLD) = 12',
        '12 execve("/fixture", ["/fixture", "--malformed-worker"], 0x0) = 0',
    ]
    assert_failure_trace(lines, fixture, "--malformed-worker")
    # 이것을 실패시키는 것: libc가 더하는 O_LARGEFILE만으로 NOFILE 탐침을 거부하는 것.
    nofile = [line.replace("--malformed-worker", "--nofile-worker") for line in lines]
    for call in ("open", "openat"):
        prefix = 'AT_FDCWD</>, ' if call == "openat" else ''
        for flags in ("O_RDONLY|O_CLOEXEC", "O_RDONLY|O_LARGEFILE|O_CLOEXEC"):
            probes = [f'12 {call}({prefix}"/dev/null", {flags}) = 7</dev/null>',
                      f'12 {call}({prefix}"/dev/null", {flags}) = -1 EMFILE (Too many open files)']
            assert_failure_trace(nofile + probes, fixture, "--nofile-worker")
    real_attribute = attribution.collector_attribute
    def counts_only(*args, **kwargs):
        result = real_attribute(*args, **kwargs)
        result.errors.clear()  # Isolate the independent formula comparison.
        return result
    monkeypatch.setattr(attribution, "collector_attribute", counts_only)
    for effect in ('write(9</file>, "x", 1) = 1', 'socket(AF_INET, SOCK_STREAM, 0) = 9<socket:[1]>',
                   'rename("/a", "/b") = 0', 'unlink("/a") = 0', 'fsync(9</file>) = 0',
                   'fork() = -1 EPERM (Operation not permitted)'):
        with pytest.raises(AssertionError):
            assert_failure_trace(lines + ['12 ' + effect], fixture, "--malformed-worker")


# 이것을 실패시키는 것: NOFILE의 musl 짝을 추가 오류로 세거나 다른 F_SETFD 오류도 함께 지우는 것.
@pytest.mark.parametrize("call", ["open", "openat"])
@pytest.mark.parametrize("result", ["0", "-1 EPERM (Operation not permitted)"])
@pytest.mark.parametrize("fd", ["4</dev/null>", "4"], ids=["named-fd", "bare-fd"])
def test_nofile_musl_pairs_preserve_all_other_errors(call, result, fd):
    fixture = "/fixture"
    lines = [
        '10 execve("/fixture", ["/fixture", "--trace"], 0x0) = 0',
        '10 clone(flags=SIGCHLD) = 11',
        '11 execve("/fixture", ["/fixture", "--trace-helper"], 0x0) = 0',
        '11 clone(flags=SIGCHLD) = 15532',
        '15532 execve("/fixture", ["/fixture", "--nofile-worker"], 0x0) = 0',
    ]
    prefix = 'AT_FDCWD</>, ' if call == "openat" else ''
    opening = f'15532 {call}({prefix}"/dev/null", O_RDONLY|O_LARGEFILE|O_CLOEXEC)'
    paired = f'15532 fcntl({fd}, F_SETFD, FD_CLOEXEC) = ' + result
    probes = [opening + ' = 4</dev/null>', paired,
              opening + ' = -1 EMFILE (Too many open files)']
    got = assert_failure_trace(lines + probes, fixture, "--nofile-worker")
    assert len(got.errors) == 2 and len(got.cloexec_pairs) == 1
    assert got.cloexec_pairs[0]["fcntl_ret"] == result
    for changed in (
        [probes[0], paired.replace(f'({fd}', '(5</dev/null>'), probes[2]],
        [probes[0], paired.replace('FD_CLOEXEC', '0'), probes[2]],
        [probes[0], '15532 getpid() = 15532', paired, probes[2]],
        [probes[0], paired, paired, probes[2]],
        [probes[0].replace('|O_CLOEXEC', ''), paired, probes[2]],
        [*probes, paired],
        [*probes, '15532 write(9</forbidden>, "x", 1) = 1'],
    ):
        with pytest.raises(AssertionError):
            assert_failure_trace(lines + changed, fixture, "--nofile-worker")


FUZZ = ROOT / "fuzz/collector"
FUZZ_ONLY = {"arbitrary", "bingsu-collector-fuzz", "cc", "find-msvc-tools", "jobserver", "libfuzzer-sys", "shlex"}


def assert_fuzz_isolation(texts):
    """The fuzz crate's own graph and cfg, never the product's."""
    import tomllib
    workspace = tomllib.loads(texts["Cargo.toml"])
    fuzz = tomllib.loads(texts["fuzz/collector/Cargo.toml"])
    # 이것을 실패시키는 것: fuzz crate를 root workspace member로 넣거나 자체 [workspace]를 지우는 것.
    assert "workspace" in fuzz and not any("fuzz" in member for member in workspace["workspace"]["members"])
    # 이것을 실패시키는 것: fuzz copy가 product와 다른 gix 하위 crate pin·feature를 쓰는 것.
    pins = {k: v for k, v in workspace["workspace"]["dependencies"].items() if k.startswith("gix-")}
    assert {k: v for k, v in fuzz["dependencies"].items() if k.startswith("gix-")} == pins
    # 이것을 실패시키는 것: fuzz lock에서 공유 crate 버전이 product lock과 갈라지는 것.
    root = {}
    for package in tomllib.loads(texts["Cargo.lock"])["package"]:
        root.setdefault(package["name"], set()).add(package["version"])
    for package in tomllib.loads(texts["fuzz/collector/Cargo.lock"])["package"]:
        assert package["version"] in root.get(package["name"], set()) or package["name"] in FUZZ_ONLY, package
    # 이것을 실패시키는 것: product build·feature·config·workflow flag로 collector_fuzz를 켜는 것.
    # Text is only the first gate; scripts/check_no_fuzz_cfg.py audits the real
    # rustc command lines of a product build in CI.
    for name, text in texts.items():
        if name.startswith("fuzz/"):
            if name == "fuzz/collector/build.rs":
                assert 'println!("cargo:rustc-cfg=collector_fuzz");' in text
        elif name.endswith("build.rs"):
            # 이것을 실패시키는 것: format!/concat!으로 쪼갠 rustc-cfg 출력이나 이름 조각.
            allowed = 'println!("cargo:rustc-check-cfg=cfg(collector_fuzz)");'
            rest = text.replace(allowed, "") if name == "crates/bingsu-collect/build.rs" else text
            assert "rustc-cfg" not in rest and "_fuzz" not in rest and "collector_fuzz" not in rest, name
        elif name.endswith("Cargo.toml"):
            assert "collector_fuzz" not in text, name
        elif name.startswith(".github/"):
            # Only the gate's own step name may say it; no flag, env or command.
            code = re.sub(r"(?m)^\s*#.*$", "", text).replace("name: Product rustc never enables collector_fuzz", "")
            assert "collector_fuzz" not in code, name
        elif name.startswith("crates/bingsu-collect/src/"):
            # 이것을 실패시키는 것: cfg!(…), cfg_attr, not(…) 등 다른 형태로 이름을 쓰는 것.
            code = re.sub(r"//[^\n]*", "", text)
            assert code.count("collector_fuzz") == code.count("#[cfg(any(test, collector_fuzz))]"), name
    assert texts["cargo-config"] == "", "a .cargo config can add --cfg flags"


def test_product_rustc_cfg_gate_runs_in_ci():
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    _, steps = workflow_job(text, "collector")
    step, = [s for s in steps if s.get("name") == "Product rustc never enables collector_fuzz"]
    assert "if" not in step and step["shell"] == "bash --noprofile --norc -euo pipefail {0}"
    assert run_commands(step) == [
        ["touch", "crates/bingsu-collect/src/main.rs"],
        ["cargo", "build", "--locked", "-j", "2", "--release", "-p", "bingsu-collect", "-v", "2>&1", "|", "tee",
         "$RUNNER_TEMP/collector-build-v.txt"],
        ["python3", "scripts/check_no_fuzz_cfg.py", "$RUNNER_TEMP/collector-build-v.txt"]]


# 이것을 실패시키는 것: --cfg collector_fuzz가 든 rustc 줄을 받거나, bingsu_collect
# rustc 줄이 없는(Fresh) 로그를 통과시키는 것.
def test_product_rustc_cfg_gate_rejects_enabled_or_vacuous_logs():
    spec = importlib.util.spec_from_file_location("check_no_fuzz_cfg", ROOT / "scripts/check_no_fuzz_cfg.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    line = ("     Running `/r/rustc --crate-name bingsu_collect --edition=2024 crates/bingsu-collect/src/main.rs "
            "--check-cfg 'cfg(collector_fuzz)' --cfg feature=\"x\"`")
    assert gate.check(line) == []
    for bad in (line.replace("--check-cfg", "--cfg collector_fuzz --check-cfg"),
                line.replace("--edition", "--cfg=collector_fuzz --edition"),
                line.replace("bingsu_collect", "gix_index") + "\n" + line.replace("--check-cfg", "--cfg collector_fuzz --check-cfg"),
                "       Fresh bingsu-collect v0.0.0"):
        assert gate.check(bad), bad
    # CI form: cargo colours the status word (CARGO_TERM_COLOR=always).
    coloured = line.replace("     Running", "\x1b[1m\x1b[92m     Running\x1b[0m")
    assert gate.check(coloured) == []
    for hidden in (coloured.replace("--check-cfg", "--cfg \x1b[0mcollector_fuzz --check-cfg"),
                   coloured.replace("--check-cfg", "\x1b[1m--cfg\x1b[0m collector\x1b[0m_fuzz --check-cfg")):
        assert gate.check(hidden), repr(hidden)


def fuzz_texts():
    names = ["Cargo.toml", "Cargo.lock", "fuzz/collector/Cargo.toml", "fuzz/collector/Cargo.lock",
             "fuzz/collector/build.rs"]
    names += [str(p.relative_to(ROOT)) for p in ROOT.glob("crates/*/build.rs")]
    names += [str(p.relative_to(ROOT)) for p in ROOT.glob("crates/*/Cargo.toml")]
    names += [str(p.relative_to(ROOT)) for p in (ROOT / ".github/workflows").glob("*.yml")]
    names += [str(p.relative_to(ROOT)) for p in (ROOT / "crates/bingsu-collect/src").rglob("*.rs")]
    texts = {name: (ROOT / name).read_text().replace("\r\n", "\n") for name in names}
    configs = [p for p in ROOT.rglob(".cargo/config*") if "target" not in p.relative_to(ROOT).parts]
    texts["cargo-config"] = "".join(p.read_text() for p in configs)
    return texts


def test_fuzz_crate_stays_outside_product_graphs():
    assert_fuzz_isolation(fuzz_texts())


@pytest.mark.parametrize("damage", ["member", "no-workspace", "pin", "lock", "build-script", "feature",
                                    "workflow-flag", "hook-cfg", "cargo-config", "fuzz-cfg-removed"])
def test_fuzz_isolation_rejects_mutations(damage):
    texts = fuzz_texts()
    if damage == "member":
        texts["Cargo.toml"] = texts["Cargo.toml"].replace('"tools/core-cfg-check"]', '"tools/core-cfg-check", "fuzz/collector"]')
    elif damage == "no-workspace":
        texts["fuzz/collector/Cargo.toml"] = texts["fuzz/collector/Cargo.toml"].replace("\n[workspace]\n", "\n")
    elif damage == "pin":
        texts["fuzz/collector/Cargo.toml"] = texts["fuzz/collector/Cargo.toml"].replace('"=0.56.0"', '"=0.56.1"')
    elif damage == "lock":
        texts["fuzz/collector/Cargo.lock"] = texts["fuzz/collector/Cargo.lock"].replace(
            'name = "gix-index"\nversion = "0.56.0"', 'name = "gix-index"\nversion = "0.56.9"')
    elif damage == "build-script":
        texts["crates/bingsu-collect/build.rs"] += '\nfn x() { println!("cargo:rustc-cfg=collector_fuzz"); }\n'
    elif damage == "feature":
        texts["crates/bingsu-collect/Cargo.toml"] += "\n[features]\nfuzz = []\ncollector_fuzz = []\n"
        texts["crates/bingsu-collect/Cargo.toml"] = texts["crates/bingsu-collect/Cargo.toml"].replace(
            '[features]\n# Identity only', '[x]\n# Identity only')
    elif damage == "workflow-flag":
        texts[".github/workflows/ci.yml"] = texts[".github/workflows/ci.yml"].replace(
            "  CARGO_TERM_COLOR: always\n", "  CARGO_TERM_COLOR: always\n  RUSTFLAGS: --cfg collector_fuzz\n")
    elif damage == "hook-cfg":
        texts["crates/bingsu-collect/src/git/io.rs"] = texts["crates/bingsu-collect/src/git/io.rs"].replace(
            "#[cfg(any(test, collector_fuzz))]", "#[cfg(any(feature = \"bench-build\", collector_fuzz))]")
    elif damage == "cargo-config":
        texts["cargo-config"] = '[build]\nrustflags = ["--cfg", "collector_fuzz"]\n'
    else:
        texts["fuzz/collector/build.rs"] = texts["fuzz/collector/build.rs"].replace("rustc-cfg=collector_fuzz", "rustc-cfg=other")
    with pytest.raises((AssertionError, KeyError)):
        assert_fuzz_isolation(texts)


def assert_fuzz_job(text, targets):
    meta, steps = workflow_job(text, "fuzz")
    assert re.search(r"(?m)^permissions:\n  contents: read$", text), "top-level read-only token"
    assert meta["if"][0] == "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    env = dict(line.strip().split(": ", 1) for line in meta["env"][1] if line.strip())
    # 이것을 실패시키는 것: nightly 날짜나 cargo-fuzz 버전을 떠 있는 값으로 바꾸는 것.
    assert re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", env["FUZZ_TOOLCHAIN"]), env
    assert re.fullmatch(r"\d+\.\d+\.\d+", env["CARGO_FUZZ_VERSION"]), env
    matrix = "\n".join(meta["strategy"][1])
    assert re.search(r"target: \[(.*)\]", matrix)[1].split(", ") == targets
    block = re.search(r"(?ms)^  fuzz:\n(.*?)(?=^  [\w-]+:|\Z)", text)[1]
    for uses in re.findall(r"uses: (\S+)(.*)", block):
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses[0]) and re.fullmatch(r" # \S+", uses[1]), uses
    assert "persist-credentials: false" in block
    assert f"toolchain: {env['FUZZ_TOOLCHAIN']}" in block
    commands = [command for step in steps for command in run_commands(step)]
    assert ["cargo", "install", "--locked", "cargo-fuzz", "--version", "=${CARGO_FUZZ_VERSION}"] in commands
    fuzz, = [c for c in commands if c[1:3] == ["+$FUZZ_TOOLCHAIN", "fuzz"]]
    for option in ("--sanitizer", "-max_total_time=900", "-rss_limit_mb=2048", "-timeout=10"):
        assert option in fuzz, option
    for step in steps:
        if "run" in step:
            assert step.get("shell") == "bash --noprofile --norc -euo pipefail {0}", step.get("name")
            assert_run_unconditional(step)
    assert "run: cargo audit --file fuzz/collector/Cargo.lock" in text
    # 이것을 실패시키는 것: main push가 정기·수동 fuzz run을 같은 group에서 취소하는 것.
    concurrency = re.search(r"(?m)^concurrency:\n((?:  .*\n)+)", text)[1]
    assert "  group: security-${{ github.workflow }}-${{ github.ref }}-${{ github.event_name }}\n" in concurrency
    assert ("  cancel-in-progress: ${{ github.event_name != 'schedule' && "
            "github.event_name != 'workflow_dispatch' }}\n") in concurrency
    # 이것을 실패시키는 것: crash 입력(저장소 바이트) artifact를 기본 90일 보존하는 것.
    upload = block.split("uses: actions/upload-artifact@", 1)[1]
    assert re.search(r"(?m)^          retention-days: 2$", upload), "crash input retention"


def test_security_fuzz_job_is_pinned_and_covers_every_target():
    targets = [line.split('"')[1] for line in (FUZZ / "Cargo.toml").read_text().splitlines()
               if line.startswith('name = "') and line != 'name = "bingsu-collector-fuzz"' and line != 'name = "write-seeds"']
    assert sorted(targets) == sorted(p.stem for p in (FUZZ / "fuzz_targets").glob("*.rs")) and len(targets) == 10
    assert_fuzz_job((ROOT / ".github/workflows/security.yml").read_text(), targets)


@pytest.mark.parametrize("old, new", [
    ("FUZZ_TOOLCHAIN: nightly-2026-09-15", "FUZZ_TOOLCHAIN: nightly"),
    ("CARGO_FUZZ_VERSION: 0.13.2", "CARGO_FUZZ_VERSION: 0.13"),
    ("cargo install --locked cargo-fuzz", "cargo install cargo-fuzz"),
    ("-max_total_time=900 ", ""),
    ("-rss_limit_mb=2048 ", ""),
    ("--sanitizer address ", ""),
    ("target: [index, pack,", "target: [pack,"),
    ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n      - uses: dtolnay",
     "actions/checkout@v7\n        with:\n          persist-credentials: false\n      - uses: dtolnay"),
    ("    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\n", ""),
    ("        run: cargo install", "        shell: bash {0}\n        run: cargo install"),
    ("run: cargo audit --file fuzz/collector/Cargo.lock", "run: cargo audit"),
    ("-${{ github.event_name }}\n  cancel", "\n  cancel"),
    ("cancel-in-progress: ${{ github.event_name != 'schedule' && github.event_name != 'workflow_dispatch' }}", "cancel-in-progress: true"),
    ("          retention-days: 2\n", ""),
])
def test_security_fuzz_job_rejects_mutations(old, new):
    text = (ROOT / ".github/workflows/security.yml").read_text()
    block = text.split("\n  fuzz:\n")[1]
    if old.startswith(("run: cargo audit", "-${{", "cancel-in")):
        assert text.count(old) == 1
        changed = text.replace(old, new)
    else:
        assert block.count(old) >= 1, old
        changed = text.split("\n  fuzz:\n")[0] + "\n  fuzz:\n" + block.replace(old, new, 1)
    targets = [p.stem for p in sorted((FUZZ / "fuzz_targets").glob("*.rs"))]
    order = ["index", "pack", "config", "attributes", "ignore", "refs", "commit_objects", "multi_pack_index", "gitdir", "commondir"]
    assert sorted(targets) == sorted(order)
    with pytest.raises((AssertionError, KeyError, TypeError, ValueError)):
        assert_fuzz_job(changed, order)


F3_CASES = ("no-git", "git-clean", "git-dirty", "tracked-19000", "budget-bound")


def assert_real_collection_ci(workflow, table):
    steps = security_steps(workflow)
    named = {step.get("name"): step for step in steps}
    positions = {step.get("name"): i for i, step in enumerate(steps)}
    release = next(i for i, step in enumerate(steps) if
                   ["cargo", "build", "-j", "2", "--release", "-p", "bingsu", "-p", "bingsu-collect"] in run_commands(step))
    assert positions["F2 fixed fuzz seed regression corpus"] < release < positions["Prepare F3 release collection observations"]
    assert positions["Prepare F3 release collection observations"] < positions["Prepare M3b compiler-free product fixtures"] < positions["M3b product security and measurements contracts"]
    assert run_commands(named["Prepare F3 release collection observations"]) == [[
        "python3", "bench/git-product.py", "--prepare", "target/release/bingsu", "--out", "target/f3/preparation.json"]]
    for name, log in (("Assert exact F3 collection passes", "$RUNNER_TEMP/m3b-security.txt"),
                      ("Assert exact F3 musl collection passes", "$RUNNER_TEMP/m3b-musl.txt")):
        commands = run_commands(named[name])
        for case in F3_CASES:
            assert ["grep", "-Fx", f"PASSED tests/shell/test_collector_security.py::test_shipped_real_collection[{case}]", log] in commands, case
    common = run_commands(named["M3b product security and measurements contracts"])
    for case in ("known", "missing", "empty", "unknown", "invalid-home", "invalid-xdg", "invalid-both"):
        assert ["grep", "-Fx", f"PASSED tests/shell/test_collector_security.py::test_product_global_excludes_reaches_stage_b[{case}]", "$RUNNER_TEMP/m3b-security.txt"] in common, case
    for name in ("Product imports and matching deployment pair", "Both shipped Mach-O architectures"):
        assert "scripts/check_collector_symbols.py" in named[name]["run"]
    linux = run_commands(named["Assert native Linux M3b security passes"])
    musl = run_commands(named["M3b native musl lifecycle security"])
    for commands, log in ((linux, "$RUNNER_TEMP/m3b-security.txt"), (musl, "$RUNNER_TEMP/m3b-musl.txt")):
        assert ["grep", "-F", "PASSED tests/shell/test_collector_security.py::test_security_table_resource_failures_preserve_front[exec]", log] in commands
    import csv
    import io
    rows = {r["id"]: r for r in csv.DictReader(io.StringIO(table), delimiter="\t")}
    required = {
        "F3-REAL": "tests/shell/test_collector_security.py::test_real_collection_has_no_silent_skip",
        "F3-ROLES": "tools/fsbudget/tests/test_git_collection.py::test_repository_budget_cannot_hide_other_role_surplus",
        "F3-OBSERVATIONS": "bench/tests/test_git_product.py::test_m3c_measurement_is_not_formal_b5_b7",
        "F3-MEMORY": "bench/tests/test_git_product.py::test_two_binary_sizes_and_git_memory_are_reported",
    }
    for name, test in required.items():
        assert rows[name]["test"] == test


# 이것을 실패시키는 것: native 아키텍처/libc·심벌·exec·정확한 매개변수 PASS·TSV 행을 빼는 것.
def test_real_collection_has_no_silent_skip():
    assert_real_collection_ci((ROOT / ".github/workflows/ci.yml").read_text(),
                              (ROOT / "tests/collector-acceptance.tsv").read_text())


# 이것을 실패시키는 것: 한 매개변수나 실행 순서 삭제를 정상으로 받아들이는 것.
@pytest.mark.parametrize("damage", [*F3_CASES, "prepare", "intel", "symbols", "exec", "tsv", "order", "global", "release-order"])
def test_real_collection_ci_rejects_mutations(damage):
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    table = (ROOT / "tests/collector-acceptance.tsv").read_text()
    if damage in F3_CASES:
        workflow = workflow.replace(f"test_shipped_real_collection[{damage}]", "removed")
    elif damage == "prepare":
        workflow = workflow.replace("bench/git-product.py --prepare target/release/bingsu", "true")
    elif damage == "intel":
        workflow = workflow.replace(", macos-26-intel", "")
    elif damage == "symbols":
        workflow = workflow.replace("scripts/check_collector_symbols.py", "removed.py")
    elif damage == "exec":
        workflow = workflow.replace("test_security_table_resource_failures_preserve_front[exec]", "removed")
    elif damage == "tsv":
        table = table.replace("F3-MEMORY\t", "REMOVED\t")
    elif damage == "global":
        workflow = workflow.replace("test_product_global_excludes_reaches_stage_b[invalid-both]", "removed")
    elif damage == "release-order":
        release = "      - run: cargo build -j 2 --release -p bingsu -p bingsu-collect\n"
        workflow = workflow.replace(release, "").replace("      - name: F2 fixed fuzz seed regression corpus\n",
                                                        release + "      - name: F2 fixed fuzz seed regression corpus\n")
    else:
        workflow = workflow.replace("name: Prepare F3 release collection observations", "name: swap").replace(
            "name: M3b product security and measurements contracts", "name: Prepare F3 release collection observations").replace(
            "name: swap", "name: M3b product security and measurements contracts")
    with pytest.raises((AssertionError, KeyError)):
        assert_real_collection_ci(workflow, table)


@pytest.fixture(scope="module")
def real_collection_context(tmp_path_factory):
    import importlib.util
    spec = importlib.util.spec_from_file_location("f3_runtime", ROOT / "bench/git-product.py")
    measurement = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measurement)
    binary = real_bin()
    # Required cells must fail on missing preparation; this module is already
    # excluded from minimum-shell jobs that never prepare host fixtures.
    prepared = measurement.prepared(binary)
    directory = tmp_path_factory.mktemp("f3-real")
    # Repositories are also used by the 200-round bench, including exact 19000.
    repos = measurement.repositories(directory)
    return measurement, binary, prepared, directory, repos


# 이것을 실패시키는 것: 출하 mask 10을 0으로 되돌려 실제 git/path 프레임 없이 통과하는 것.
@pytest.mark.parametrize("case", F3_CASES)
def test_shipped_real_collection(real_collection_context, case):
    measurement, binary, prepared, directory, repos = real_collection_context
    sample = measurement.observe(binary, prepared, directory / "context" / case, repos[case])
    assert sample["status"] == "OBSERVED", sample
    assert sample["stage_a"] and sample["published"] and sample["reaped"], sample
    frames = [bytes.fromhex(raw) for _, raw in sample["frames"]]
    updates = [raw[80:] for raw in frames if raw[10] == 5]
    assert any(raw[:2] == b"\x03\0" for raw in updates), sample
    if case in ("no-git", "git-clean", "git-dirty"):
        assert any(raw[:2] == b"\x01\0" for raw in updates), sample
        assert sample["reason"] == "Complete" and sample["partial"] is False, sample
    if case == "budget-bound":
        assert sample["partial"] is True, sample
