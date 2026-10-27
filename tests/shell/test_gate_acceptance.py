"""M3d gate rows: every clause of every gate is a CI-asserted test or pending.

`tests/gate-acceptance.tsv` maps each (gate, clause) to a real test that a CI
job runs and asserts as passed, through the same checker as the collector
table. A test that exists and runs is not coverage of the behaviour: each gate
Task proves the behaviour with its own live test and product mutations.
"""
import csv
import io
import subprocess
import sys

import pytest

# Helpers only: importing test_* names here would collect them twice.
from test_collector_security import ROOT, assert_acceptance_table

TABLE = "tests/gate-acceptance.tsv"
WORKFLOWS = ("ci.yml", "shell.yml")

# Gate id -> its clauses, in order; clause N is the N-th entry. Clauses whose
# work belongs to a later milestone are listed too and have a deferred row.
M3D_GATES = {
    "GATE-FS-HELPER": (
        "Helper filesystem calls per publication stage equal the formula, counted per role and call kind",
        "Each of the nine helper axes has its own cap; exceeding any one fails the check closed",
    ),
    "GATE-FS-FRONT": (
        "Front snapshot reads per attempt stay within axis C, counted per call kind",
    ),
    "GATE-CHILDREN": (
        "The front spawns at most one refresh helper per prompt",
        "A collector is spawned only when a segment needs one, at most one per helper, and it spawns nothing",
        "No write-only child is spawned",
    ),
    "GATE-FDS": (
        "The helper starts with only the allowed descriptors and no shell pipe",
        "The collector holds only its fixed descriptors",
        "The write-only child starts with only the allowed descriptors",
    ),
    "GATE-HELPER-LIFETIME": (
        "After the deadline a kill request is sent, on the normal and the blocked-mount fixture",
        "The helper never holds the shell's descriptors",
        "After the lock at most one blocked helper per config context; other contexts are independent",
    ),
    "GATE-ZOMBIES": (
        "No zombie is left after N prompts",
    ),
    "GATE-FRONT-READ-BYTES": (
        "Front snapshot reads stay within each fixture's byte cap",
        "The front never reads the trust metadata section",
    ),
    "GATE-GENERATION": (
        "A kill between the snapshot and marker writes leaves the front's behaviour unchanged",
        "The next helper treats a generation mismatch as changed",
    ),
    "GATE-TRUST-REVOKE": (
        "After `chmod g+w` on a config file, no command from it is approved past verified_at + T",
        "The same holds on the blocked-mount fixture",
        "The exec time of a revoked unit is recorded (best effort)",
    ),
    "GATE-EXEC-DEADLINE": (
        "A clock moved past the deadline right after the decision makes the front approve no spawn",
        "A chmod or file replacement during the scan leaves the marker unchanged",
        "A deadline passed after approval and before the pre-exec check: the target is not executed",
        "Asleep after approval and woken past the deadline (wake-generation platforms): the target is not executed",
    ),
    "GATE-CLOCK-READS": (
        "A test-build counter shows a fixed number of executed front clock reads per use and fixture",
        "Same-machine A/B total latency of the deadline checks",
        "Per execution unit, exec count +1 and an unchanged process count through the trusted relay",
    ),
    "GATE-COLLECTOR-TIMING": (
        "No segment needs a collector: zero collectors",
        "The collector count is the same with a valid and an invalid marker",
        "An invalid marker yields zero execution units from the config",
        "A collector is spawned only after the helper reads the header and the marker",
    ),
    "GATE-RUNTIME-ROOT": (
        "A prompt-time XDG_RUNTIME_DIR inside the repository is never opened by the front or the helper",
        "A deleted and recreated runtime folder degrades every prompt with degraded:runtime-root and one notice",
        "Running init again recovers",
        "The five runtime-root path examples hold",
    ),
    "GATE-MARKER-UPDATE": (
        "A deadline overrun, partial scan, ACL error or conf.d listing failure leaves the marker unchanged",
        "A marker whose generation or summary disagrees with the snapshot makes the front launch no unit",
        "A confirmed trust or compile failure writes an invalid marker and the next prompt degrades",
    ),
}
M3D_GATE_IDS = tuple(M3D_GATES)

# Supplementary rows that must stay: existing tests that cover part of a clause.
M3D_SUPPLEMENTARY = ("GATE-EXEC-DEADLINE.2-m3a", "GATE-MARKER-UPDATE.3-m3a")

# Clauses deferred to a later milestone, with that milestone. Each has a row
# whose stage is `deferred:<milestone>`; removing one fails the table check.
M3D_DEFERRED = {
    "GATE-FDS.3": "M4",
    "GATE-TRUST-REVOKE.3": "M6",
    "GATE-EXEC-DEADLINE.3": "M6",
    "GATE-EXEC-DEADLINE.4": "M6",
    "GATE-CLOCK-READS.2": "M6",
    "GATE-CLOCK-READS.3": "M6",
}
DEFERRED_MILESTONES = ("M4", "M6")

# (gate, clause) pairs without a primary row yet, as "GATE-ID.N". Each gate
# Task adds its primary rows (id exactly GATE-ID.N) and removes its pairs here;
# the final Task asserts this is empty. A supplementary row (id GATE-ID.N-<tag>)
# points at an existing test that covers part of a clause and does not close
# its pair.
M3D_PENDING = (
    "GATE-FS-HELPER.1", "GATE-FS-HELPER.2",
    "GATE-FS-FRONT.1",
    "GATE-CHILDREN.1", "GATE-CHILDREN.2", "GATE-CHILDREN.3",
    "GATE-FDS.1", "GATE-FDS.2",
    "GATE-HELPER-LIFETIME.1", "GATE-HELPER-LIFETIME.2", "GATE-HELPER-LIFETIME.3",
    "GATE-ZOMBIES.1",
    "GATE-FRONT-READ-BYTES.1", "GATE-FRONT-READ-BYTES.2",
    "GATE-GENERATION.1", "GATE-GENERATION.2",
    "GATE-TRUST-REVOKE.1", "GATE-TRUST-REVOKE.2",
    "GATE-EXEC-DEADLINE.1", "GATE-EXEC-DEADLINE.2",
    "GATE-CLOCK-READS.1",
    "GATE-COLLECTOR-TIMING.1", "GATE-COLLECTOR-TIMING.2", "GATE-COLLECTOR-TIMING.3", "GATE-COLLECTOR-TIMING.4",
    "GATE-RUNTIME-ROOT.1", "GATE-RUNTIME-ROOT.2", "GATE-RUNTIME-ROOT.3", "GATE-RUNTIME-ROOT.4",
    "GATE-MARKER-UPDATE.1", "GATE-MARKER-UPDATE.2", "GATE-MARKER-UPDATE.3",
)


def workflows():
    return {name: (ROOT / ".github/workflows" / name).read_text() for name in WORKFLOWS}


def rows(table):
    return list(csv.DictReader(io.StringIO(table), delimiter="\t"))


def is_deferred(row):
    return row["stage"].startswith("deferred")


def covered(table):
    # Pairs with a primary row; supplementary and deferred rows do not close a pair.
    return {row["id"] for row in rows(table)
            if row["id"] == f'{row["gate"]}.{row["clause"]}' and not is_deferred(row)}


def deferred(table):
    return {row["id"] for row in rows(table) if is_deferred(row)}


def without_deferred(table):
    lines = table.splitlines(True)
    return lines[0] + "".join(line for line, row in zip(lines[1:], rows(table)) if not is_deferred(row))


def assert_deferred_rows(table):
    # 이것을 실패시키는 것: deferred 행 삭제·추가, M4·M6 밖 마일스톤, 시험을 가진 deferred 행,
    # gate.clause와 다른 id.
    found = {}
    for row in rows(table):
        if not is_deferred(row):
            continue
        milestone = row["stage"].removeprefix("deferred:")
        assert row["stage"] == "deferred:" + milestone and milestone in DEFERRED_MILESTONES, (row["id"], row["stage"])
        assert row["id"] == f'{row["gate"]}.{row["clause"]}', (row["id"], "deferred id")
        assert (row["platform"], row["test"], row["target"]) == ("-", "-", "-"), (row["id"], "deferred row names a test")
        assert row["property"].strip(), (row["id"], "deferred disposition")
        found[row["id"]] = milestone
    assert found == M3D_DEFERRED, (sorted(found.items()), sorted(M3D_DEFERRED.items()))


def named(table):
    return {f'{row["gate"]}.{row["clause"]}' for row in rows(table)}


def clauses():
    return {f"{gate}.{index}" for gate, texts in M3D_GATES.items() for index in range(1, len(texts) + 1)}


def assert_gate_table(table, texts, *, pending=M3D_PENDING, collected=None):
    # Each clause that is neither pending nor deferred keeps a primary row whose id is
    # exactly GATE-ID.N; the listed supplementary rows stay too. Deferred rows name no test.
    assert_deferred_rows(table)
    required = clauses() - set(pending) - set(M3D_DEFERRED)
    assert_acceptance_table(without_deferred(table), texts, required_ids=frozenset(required) | set(M3D_SUPPLEMENTARY),
                            required_gates=frozenset(M3D_GATE_IDS), collected=collected)


def assert_clauses_accounted(table, pending=M3D_PENDING):
    # 이것을 실패시키는 것: 행 삭제(쌍이 행도 pending도 아님), primary 행을 더하고 pending을 남김,
    # 없는 절을 pending이나 표에 둠(합집합 비교), pending 중복, 보조 행만으로 쌍을 닫음,
    # deferred 절을 pending으로 셈.
    expected = clauses()
    assert len(set(pending)) == len(pending), "duplicate pending pair"
    assert named(table) <= expected, sorted(named(table) - expected)
    assert not covered(table) & set(pending), sorted(covered(table) & set(pending))
    assert not deferred(table) & (covered(table) | set(pending)), sorted(deferred(table) & (covered(table) | set(pending)))
    accounted = covered(table) | set(pending) | deferred(table)
    assert accounted == expected, sorted(expected ^ accounted)


# 이것을 실패시키는 것: TSV 오타·중복 선언·미수집 매개변수·CI에서 실행/단언하지 않는 행.
def test_gate_rows_exist_and_run_in_ci():
    table = (ROOT / TABLE).read_text()
    files = sorted({row["test"].split("::")[0] for row in rows(table) if row["target"] == "pytest"})
    collected = []
    for file in files:
        result = subprocess.run([sys.executable, "-B", "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", file],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, (file, result.stdout, result.stderr)
        collected.extend(result.stdout.splitlines())
    assert_gate_table(table, workflows(), collected=collected)


def test_every_gate_clause_is_a_row_or_pending():
    assert len(M3D_GATE_IDS) == 14
    table = (ROOT / TABLE).read_text()
    assert_deferred_rows(table)
    assert_clauses_accounted(table)


def assert_self_rows(texts, target="pytest", files=("shell.yml",)):
    names = ("test_gate_rows_exist_and_run_in_ci", "test_every_gate_clause_is_a_row_or_pending")
    table = "id\tproperty\tplatform\ttest\ttarget\tstage\n" + "".join(
        f"SELF-{index}\tGate table check\tLinux\ttests/shell/test_gate_acceptance.py::{name}\t{target}\tM3d\n"
        for index, name in enumerate(names))
    assert_acceptance_table(table, {name: texts[name] for name in files}, required_ids=frozenset({"SELF-0", "SELF-1"}))


# 이것을 실패시키는 것: shell.yml에서 이 표 검사의 실행이나 PASSED 단언을 빼는 것.
def test_gate_table_checks_are_asserted_in_ci():
    assert_self_rows(workflows())


# 이것을 실패시키는 것: 행 삭제(primary·보조)·gate 오타·절 번호 아닌 clause·gate.clause와 다른 id·CI 단언 주석 처리를 받는 것.
# 오타 행은 원래 행 옆에 더해, 다른 검사(필수 id)가 대신 잡지 않게 한다.
@pytest.mark.parametrize("damage,reason", [
    pytest.param(damage, reason, id=damage) for damage, reason in (
        ("removed-row", "GATE-"), ("removed-supplementary", "-m3a"), ("gate-typo", "unknown gate"), ("clause-zero", "clause"),
        ("id-mismatch", "'id'"), ("ci-grep", "no asserted CI Rust pass"))])
def test_gate_table_rejects_mutations(damage, reason):
    table = (ROOT / TABLE).read_text()
    texts = workflows()
    first = rows(table)[0]
    line = next(line for line in table.splitlines(True) if line.startswith(first["id"] + "\t"))
    gate, clause = first["gate"], first["clause"]
    tag = first["id"][len(f"{gate}.{clause}"):]
    pending = M3D_PENDING
    if damage == "removed-row":
        # The pair is no longer pending, so its primary row is required.
        pending = tuple(p for p in pending if p != f"{gate}.{clause}")
    elif damage == "removed-supplementary":
        table = table.replace(line, "")
    elif damage == "gate-typo":
        table += line.replace(f"{gate}.{clause}{tag}\t{gate}\t", f"{gate}S.{clause}{tag}\t{gate}S\t", 1)
    elif damage == "clause-zero":
        table += line.replace(f"{gate}.{clause}{tag}\t{gate}\t{clause}\t", f"{gate}.0{tag}\t{gate}\t0\t", 1)
    elif damage == "id-mismatch":
        table += line.replace(f"{gate}.{clause}{tag}\t", f"{gate}.9{tag}\t", 1)
    else:
        label = "test " + first["test"].split("::", 1)[1] + " ... ok"
        assert label in texts["ci.yml"]
        texts["ci.yml"] = texts["ci.yml"].replace("grep -F '" + label, "# grep -F '" + label)
    assert table != (ROOT / TABLE).read_text() or damage in ("ci-grep", "removed-row")
    with pytest.raises(AssertionError, match=reason):
        assert_gate_table(table, texts, pending=pending)


# 이것을 실패시키는 것: 행이 생긴 쌍을 pending에 남김, 없는 절·중복을 pending에 둠, 행 삭제.
HEADER = "id\tgate\tclause\tproperty\tplatform\ttest\ttarget\tstage\n"


def row_line(row_id, gate, clause):
    return f"{row_id}\t{gate}\t{clause}\tp\tUnix\tcrates/x/src/main.rs::t\tbin:x\tM3d\n"


def deferred_lines():
    table = (ROOT / TABLE).read_text()
    return "".join(line for line, row in zip(table.splitlines(True)[1:], rows(table)) if is_deferred(row))


@pytest.mark.parametrize("damage", ["removed-row", "row-still-pending", "unknown-pending", "duplicate-pending",
                                    "supplementary-closes", "unknown-supplementary", "deferred-also-pending",
                                    "deferred-also-primary", "removed-deferred"])
def test_clause_accounting_rejects_mutations(damage):
    pending = tuple(p for p in M3D_PENDING if p != "GATE-ZOMBIES.1")
    table = HEADER + row_line("GATE-ZOMBIES.1", "GATE-ZOMBIES", 1) + deferred_lines()
    assert_clauses_accounted(table, pending)
    if damage == "removed-row":
        table = HEADER + deferred_lines()
    elif damage == "deferred-also-pending":
        pending = pending + ("GATE-FDS.3",)
    elif damage == "deferred-also-primary":
        table += row_line("GATE-FDS.3", "GATE-FDS", 3)
    elif damage == "removed-deferred":
        table = "".join(line for line in table.splitlines(True) if not line.startswith("GATE-FDS.3\t"))
    elif damage == "row-still-pending":
        pending = pending + ("GATE-ZOMBIES.1",)
    elif damage == "unknown-pending":
        pending = pending + ("GATE-ZOMBIES.2",)
    elif damage == "duplicate-pending":
        pending = pending + pending[:1]
    elif damage == "supplementary-closes":
        table = HEADER + row_line("GATE-ZOMBIES.1-m3a", "GATE-ZOMBIES", 1)
    else:
        table += row_line("GATE-ZOMBIES.2-m3a", "GATE-ZOMBIES", 2)
    with pytest.raises(AssertionError):
        assert_clauses_accounted(table, pending)


# 이것을 실패시키는 것: deferred 행 삭제·마일스톤 변경·시험을 가진 deferred 행·고정 목록 밖 deferred 행을 받는 것.
@pytest.mark.parametrize("damage", ["removed", "milestone", "named-test", "extra", "id", "no-disposition"])
def test_deferred_rows_reject_mutations(damage, monkeypatch):
    table = (ROOT / TABLE).read_text()
    assert_deferred_rows(table)
    line = next(line for line in table.splitlines(True) if line.startswith("GATE-CLOCK-READS.3\t"))
    if damage == "removed":
        table = table.replace(line, "")
    elif damage == "milestone":
        # The pinned list moves too, so only the milestone rule can refuse it.
        monkeypatch.setitem(M3D_DEFERRED, "GATE-CLOCK-READS.3", "M5")
        table = table.replace(line, line.replace("deferred:M6", "deferred:M5"))
    elif damage == "named-test":
        table = table.replace(line, line.replace("\t-\t-\t-\t", "\tUnix\tcrates/x/src/main.rs::t\tbin:x\t"))
    elif damage == "extra":
        table += line.replace("GATE-CLOCK-READS.3\tGATE-CLOCK-READS\t3\t", "GATE-CLOCK-READS.1\tGATE-CLOCK-READS\t1\t")
    elif damage == "id":
        monkeypatch.delitem(M3D_DEFERRED, "GATE-CLOCK-READS.3")
        monkeypatch.setitem(M3D_DEFERRED, "GATE-CLOCK-READS.3-m6", "M6")
        table = table.replace(line, line.replace("GATE-CLOCK-READS.3\t", "GATE-CLOCK-READS.3-m6\t", 1))
    else:
        table = table.replace(line, "\t".join(v if i != 3 else " " for i, v in enumerate(line.split("\t"))))
    assert table != (ROOT / TABLE).read_text()
    with pytest.raises(AssertionError):
        assert_deferred_rows(table)


# 이것을 실패시키는 것: 보조 행이 있는 pending 쌍을 거부하는 것(부분 증거를 가리키되 쌍은 열어 둠).
def test_supplementary_row_keeps_its_pair_pending():
    table = (ROOT / TABLE).read_text()
    supplementary = [row for row in rows(table) if row["id"] != f'{row["gate"]}.{row["clause"]}']
    assert supplementary and all(f'{row["gate"]}.{row["clause"]}' in M3D_PENDING for row in supplementary)
    assert_clauses_accounted(table)


# A lib row has no real counterpart yet: a synthetic row and CI step check the
# lib branch against the real bingsu-core sources.
LIB_TEST = ("crates/bingsu-core/src/front/staged/tests.rs::"
            "front::staged::tests::cases::collection_address_is_computed_only_after_advancing_past_the_root")
LIB_STEP = (
    "      - run: |\n"
    "          set -o pipefail\n"
    "          cargo test -j 2 -p bingsu-core --lib | tee \"$RUNNER_TEMP/core-lib.txt\"\n"
    "          grep -F 'test front::staged::tests::cases::collection_address_is_computed_only_after_advancing_past_the_root"
    " ... ok' \"$RUNNER_TEMP/core-lib.txt\"\n")
LIB_ANCHOR = "      - name: Collector policy evaluator and table correspondence\n"


def lib_case(damage):
    table = ("id\tgate\tclause\tproperty\tplatform\ttest\ttarget\tstage\n"
             f"GATE-ZOMBIES.1\tGATE-ZOMBIES\t1\tSynthetic lib row\tUnix\t{LIB_TEST}\tlib\tM3d\n")
    texts = workflows()
    assert texts["ci.yml"].count(LIB_ANCHOR) == 1
    step = LIB_STEP
    sources = {}
    if damage == "test-target":
        step = step.replace("--lib", "--test staged")
    elif damage == "no-grep":
        step = step.replace("grep -F", "# grep -F")
    elif damage == "module-path":
        table = table.replace("::front::staged::tests::cases::", "::back::staged::tests::cases::")
    elif damage == "bin-target":
        table = table.replace("\tlib\t", "\tbin:bingsu-core\t")
    elif damage == "path-module":
        path = "crates/bingsu-core/src/front.rs"
        sources[path] = (ROOT / path).read_text().replace("pub mod staged;", '#[path = "staged.rs"]\npub mod staged;')
    elif damage == "disabled-module":
        path = "crates/bingsu-core/src/front/staged.rs"
        sources[path] = (ROOT / path).read_text().replace("#[cfg(test)]\nmod tests;", '#[cfg(test)]\n#[cfg(target_os = "macos")]\nmod tests;')
    elif damage == "inline-module":
        path = "crates/bingsu-core/src/front/staged/tests.rs"
        sources[path] = (ROOT / path).read_text().replace("mod cases {", "mod kases {")
    texts["ci.yml"] = texts["ci.yml"].replace(LIB_ANCHOR, step + LIB_ANCHOR)
    for path, text in sources.items():
        assert text != (ROOT / path).read_text(), damage
    return table, texts, (lambda p: sources[p] if p in sources else (ROOT / p).read_text())


def test_lib_row_is_accepted_with_its_exact_ci_assertion():
    table, texts, read = lib_case(None)
    assert_acceptance_table(table, texts, required_ids=frozenset({"GATE-ZOMBIES.1"}),
                            required_gates=frozenset(M3D_GATE_IDS), read=read)


# 이것을 실패시키는 것: lib 행을 --test 실행·주석 단언으로 받거나, 표의 모듈 경로·bin target을 믿거나,
# #[path]·꺼진 cfg·없는 inline 모듈을 지나치는 것.
@pytest.mark.parametrize("damage", ["test-target", "no-grep", "module-path", "bin-target",
                                    "path-module", "disabled-module", "inline-module"])
def test_lib_row_rejects_mutations(damage):
    table, texts, read = lib_case(damage)
    with pytest.raises(AssertionError):
        assert_acceptance_table(table, texts, required_ids=frozenset({"GATE-ZOMBIES.1"}),
                                required_gates=frozenset(M3D_GATE_IDS), read=read)


SELF_GREP = "          grep -F 'PASSED tests/shell/test_gate_acceptance.py::test_gate_rows_exist_and_run_in_ci' \"$RUNNER_TEMP/gate-acceptance.txt\"\n"
SELF_STEP = "      - name: Gate acceptance rows map every clause to a CI-asserted test\n"
JOB_HEADER = "    name: Prompt filter calls (x86_64 ${{ matrix.libc }} ${{ matrix.profile }})\n    needs: detect\n"
JOB_IF = "    if: needs.detect.outputs.rust == 'true'\n"
MATRIX = "        libc: [gnu, musl]\n        profile: [debug, release]\n"


# 이것을 실패시키는 것: shell.yml 증거 step의 단언 삭제·`set +e`·continue-on-error·matrix if,
# 다른 workflow의 interpreter, 다른 로그, .py 파일의 Rust target, job 단위 우회·matrix exclude,
# 모르는 workflow를 받는 것.
@pytest.mark.parametrize("damage", ["delete", "set+e", "continue", "matrix-if", "interpreter", "other-log", "target",
                                    "job-continue", "job-if", "matrix-exclude", "unknown-workflow"])
def test_gate_ci_step_rejects_mutations(damage):
    texts = workflows()
    shell = texts["shell.yml"]
    assert all(shell.count(text) == 1 for text in (SELF_GREP, SELF_STEP, JOB_HEADER + JOB_IF, MATRIX))
    if damage == "delete":
        shell = shell.replace(SELF_GREP, "")
    elif damage == "set+e":
        shell = shell.replace(SELF_GREP, "          set +e\n" + SELF_GREP)
    elif damage == "continue":
        shell = shell.replace(SELF_STEP, SELF_STEP + "        continue-on-error: true\n")
    elif damage == "matrix-if":
        shell = shell.replace(SELF_STEP, SELF_STEP + "        if: matrix.profile == 'debug'\n")
    elif damage == "interpreter":
        shell = shell.replace('"$RUNNER_TEMP/venv/bin/python" -m pytest tests/shell/test_gate_acceptance.py',
                              '"$RUNNER_TEMP/collector-tests/bin/python" -m pytest tests/shell/test_gate_acceptance.py')
    elif damage == "other-log":
        shell = shell.replace(SELF_GREP, SELF_GREP.replace("gate-acceptance.txt", "pytest.out"))
    elif damage == "job-continue":
        shell = shell.replace(JOB_HEADER, JOB_HEADER + "    continue-on-error: true\n")
    elif damage == "job-if":
        shell = shell.replace(JOB_HEADER + JOB_IF, JOB_HEADER + "    if: always()\n")
    elif damage == "matrix-exclude":
        shell = shell.replace(MATRIX, MATRIX + "        exclude: [{profile: release}]\n")
    if damage == "unknown-workflow":
        # A workflow the checker does not read must be refused, not ignored.
        texts["bench.yml"] = (ROOT / ".github/workflows/bench.yml").read_text()
        with pytest.raises(AssertionError, match="bench.yml"):
            assert_self_rows(texts, files=("shell.yml", "bench.yml"))
        return
    if damage == "target":
        # A pytest row must say pytest; a Rust target on a .py file is refused.
        with pytest.raises(AssertionError, match="target and file"):
            assert_self_rows(texts, target="test:gate_acceptance")
        return
    assert shell != texts["shell.yml"]
    texts["shell.yml"] = shell
    with pytest.raises(AssertionError):
        assert_self_rows(texts)
