"""M3d gate rows: every clause of every gate is a CI-asserted test or pending.

`tests/gate-acceptance.tsv` maps each (gate, clause) to a real test that a CI
job runs and asserts as passed, through the same checker as the collector
table. A test that exists and runs is not coverage of the behaviour: each gate
Task proves the behaviour with its own live test and product mutations.
"""
import csv
import io
import re
import subprocess
import sys

import pytest

# Helpers only: importing test_* names here would collect them twice.
from test_collector_security import ROOT, assert_acceptance_table, job_platforms

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
        "A test-build counter shows a fixed number of executed pre-exec clock reads per execution unit",
    ),
    "GATE-COLLECTOR-TIMING": (
        "No segment needs a collector: zero collectors",
        "The collector count is the same with a valid and an invalid marker",
        "An invalid marker yields zero execution units from the config",
        "A collector is spawned only after the helper reads the header and the marker",
    ),
    "GATE-RUNTIME-ROOT": (
        "A prompt-time XDG_RUNTIME_DIR inside the repository is never opened by the front or the helper",
        "A deleted and recreated runtime folder degrades every prompt with degraded:runtime-root",
        "Running init again recovers",
        "The five runtime-root path examples hold",
        "Status-notice hook output prints the fixed runtime-root notice once (M4 zsh, M5 fish/bash)",
    ),
    "GATE-MARKER-UPDATE": (
        "A deadline overrun, partial scan, ACL error or conf.d listing failure leaves the marker unchanged",
        "A marker whose generation or summary disagrees with the snapshot makes the front launch no unit",
        "A confirmed trust or compile failure writes an invalid marker and the next prompt degrades",
    ),
}
M3D_GATE_IDS = tuple(M3D_GATES)

# Supplementary rows that must stay, with their stage: existing tests that cover part of a clause.
M3D_SUPPLEMENTARY = {"GATE-EXEC-DEADLINE.2-m3a": "M3a", "GATE-MARKER-UPDATE.3-m3a": "M3a",
                     # GATE-FS-HELPER.1 is one row per stage parameter; the primary row is unchanged.
                     "GATE-FS-HELPER.1-publish": "M3d", "GATE-FS-HELPER.1-collect": "M3d",
                     "GATE-FS-HELPER.1-last_good": "M3d", "GATE-FS-HELPER.1-recover": "M3d"}
# 이것을 실패시키는 것: fallback/상한/머리 거부 행을 지우고 normal만으로 게이트를 닫는 것.
M3D_SUPPLEMENTARY.update({f"{gate}.1-{case}": "M3d"
                          for gate in ("GATE-FS-FRONT", "GATE-FRONT-READ-BYTES")
                          for case in ("checksum_last_good", "body_limit", "header_only")})
# 이것을 실패시키는 것: 막힌 마운트 행을 지우고 정상 폴더만으로 GATE-HELPER-LIFETIME.1을 닫는 것.
M3D_SUPPLEMENTARY["GATE-HELPER-LIFETIME.1-blocked_mount"] = "M3d"
# 이것을 실패시키는 것: 계획의 시계 단계 고정 행을 지우고 실행 횟수 계수기 행만으로 GATE-CLOCK-READS.1을 닫는 것.
M3D_SUPPLEMENTARY["GATE-CLOCK-READS.1-staged_plan"] = "M3d"
# Stages an active row may name: the milestone whose work added the test.
ACTIVE_STAGES = ("M1", "M2", "M3a", "M3b", "M3c", "M3d")

# Clauses deferred to a later milestone, with that milestone. Each has a row
# whose stage is `deferred:<milestone>`; removing one fails the table check.
M3D_DEFERRED = {
    "GATE-RUNTIME-ROOT.5": "M4/M5",
    "GATE-FDS.3": "M4",
    "GATE-TRUST-REVOKE.3": "M6",
    "GATE-EXEC-DEADLINE.3": "M6",
    "GATE-EXEC-DEADLINE.4": "M6",
    "GATE-CLOCK-READS.2": "M6",
    "GATE-CLOCK-READS.3": "M6",
    "GATE-CLOCK-READS.4": "M6",
}
DEFERRED_MILESTONES = ("M4", "M4/M5", "M6")

# Gates whose rows count a live capture of a release build: their evidence must
# come from steps that run only in release matrix cells (followups 106).
M3D_RELEASE_GATES = frozenset({"GATE-FS-HELPER", "GATE-FS-FRONT", "GATE-FRONT-READ-BYTES",
                               "GATE-HELPER-LIFETIME", "GATE-ZOMBIES", "GATE-FDS", "GATE-RUNTIME-ROOT"})

# (gate, clause) pairs without a primary row yet, as "GATE-ID.N". Each gate
# Task adds its primary rows (id exactly GATE-ID.N) and removes its pairs here;
# the final Task asserts this is empty. A supplementary row (id GATE-ID.N-<tag>)
# points at an existing test that covers part of a clause and does not close
# its pair.
M3D_PENDING = (
    "GATE-FS-HELPER.2",
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
    # 이것을 실패시키는 것: deferred 행 삭제·추가·중복, M4·M6 밖 마일스톤, 시험을 가진 deferred 행,
    # gate.clause와 다른 id, 마일스톤 밖 active stage, 보조 행 stage 변경.
    ids = [row["id"] for row in rows(table)]
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})
    found = {}
    for row in rows(table):
        if not is_deferred(row):
            assert row["stage"] in ACTIVE_STAGES, (row["id"], "stage", row["stage"])
            if row["id"] in M3D_SUPPLEMENTARY:
                assert row["stage"] == M3D_SUPPLEMENTARY[row["id"]], (row["id"], "supplementary stage", row["stage"])
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
    # 이것을 실패시키는 것: B1 release·runs-on 계약 검사를 primary 게이트에서 생략하는 것.
    assert_b1_contract(texts["shell.yml"])
    assert_deferred_rows(table)
    required = clauses() - set(pending) - set(M3D_DEFERRED)
    assert_acceptance_table(without_deferred(table), texts, required_ids=frozenset(required) | set(M3D_SUPPLEMENTARY),
                            required_gates=frozenset(M3D_GATE_IDS), collected=collected,
                            release_gates=M3D_RELEASE_GATES)


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


SELF_STEP = "      - name: Gate acceptance rows map every clause to a CI-asserted test\n"
# shell.yml jobs that run this file and assert its passes; shell-macos is a required check.
GATE_STEP_JOBS = ("filter-calls", "shell-macos")


def job_span(text, job):
    start = text.index(f"\n  {job}:\n") + 1
    after = re.search(r"(?m)^  [\w-]+:\n", text[start + 1:])
    return start, (start + 1 + after.start() if after else len(text))


def in_job(text, job, old, new):
    start, end = job_span(text, job)
    block = text[start:end]
    assert block.count(old) == 1, (job, old)
    return text[:start] + block.replace(old, new) + text[end:]


def drop_gate_step(text, job):
    start, end = job_span(text, job)
    block = text[start:end]
    first = block.index(SELF_STEP)
    last = block.index("      - ", first + len(SELF_STEP))
    return text[:start] + block[:first] + block[last:] + text[end:]


def assert_self_rows(texts, job, target="pytest", files=("shell.yml",), platform=None):
    # Only `job` keeps its gate step, so each job must carry the evidence on its own.
    texts = dict(texts)
    for other in GATE_STEP_JOBS:
        if other != job:
            texts["shell.yml"] = drop_gate_step(texts["shell.yml"], other)
    names = ("test_gate_rows_exist_and_run_in_ci", "test_every_gate_clause_is_a_row_or_pending")
    platform = platform or {"filter-calls": "Linux", "shell-macos": "macOS"}[job]
    table = "id\tproperty\tplatform\ttest\ttarget\tstage\n" + "".join(
        f"SELF-{index}\tGate table check\t{platform}\ttests/shell/test_gate_acceptance.py::{name}\t{target}\tM3d\n"
        for index, name in enumerate(names))
    assert_acceptance_table(table, {name: texts[name] for name in files}, required_ids=frozenset({"SELF-0", "SELF-1"}))


# 이것을 실패시키는 것: 필수 job(Shell PTY macOS) 또는 filter-calls에서 이 표 검사의 실행이나 PASSED 단언을 빼는 것.
@pytest.mark.parametrize("job", GATE_STEP_JOBS)
def test_gate_table_checks_are_asserted_in_ci(job):
    assert_self_rows(workflows(), job)


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
        primary = f"{gate}.{clause}"
        if primary in pending:
            # The pair is no longer pending, so its primary row is required.
            pending = tuple(p for p in pending if p != primary)
        else:
            # The pair is closed: delete its primary row, keeping the supplementary one.
            table = "".join(l for l in table.splitlines(True) if not l.startswith(primary + "\t"))
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


def standing_lines():
    """The real table's deferred rows and the primary rows of closed pairs:
    the synthetic accounting tables below vary only GATE-ZOMBIES.1, so its own
    rows in the real table are left out."""
    # 이것을 실패시키는 것: 실제 표의 GATE-ZOMBIES.1 행을 남겨 removed-row 변이가 쌍을 계속 닫는 것.
    table = (ROOT / TABLE).read_text()
    closed = covered(table)
    return "".join(line for line, row in zip(table.splitlines(True)[1:], rows(table))
                   if (is_deferred(row) or row["id"] in closed)
                   and f'{row["gate"]}.{row["clause"]}' != "GATE-ZOMBIES.1")


@pytest.mark.parametrize("damage", ["removed-row", "row-still-pending", "unknown-pending", "duplicate-pending",
                                    "supplementary-closes", "unknown-supplementary", "deferred-also-pending",
                                    "deferred-also-primary", "removed-deferred"])
def test_clause_accounting_rejects_mutations(damage):
    pending = tuple(p for p in M3D_PENDING if p != "GATE-ZOMBIES.1")
    table = HEADER + row_line("GATE-ZOMBIES.1", "GATE-ZOMBIES", 1) + standing_lines()
    assert_clauses_accounted(table, pending)
    if damage == "removed-row":
        table = HEADER + standing_lines()
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
@pytest.mark.parametrize("damage", ["removed", "milestone", "named-test", "extra", "id", "no-disposition",
                                    "duplicate", "active-stage", "supplementary-stage"])
def test_deferred_rows_reject_mutations(damage, monkeypatch):
    table = (ROOT / TABLE).read_text()
    assert_deferred_rows(table)
    line = next(line for line in table.splitlines(True) if line.startswith("GATE-CLOCK-READS.3\t"))
    supplementary = next(line for line in table.splitlines(True) if line.startswith("GATE-EXEC-DEADLINE.2-m3a\t"))
    if damage == "removed":
        table = table.replace(line, "")
    elif damage == "duplicate":
        table += line
    elif damage == "active-stage":
        # The pinned stage moves too, so only the active-stage rule can refuse it.
        monkeypatch.setitem(M3D_SUPPLEMENTARY, "GATE-EXEC-DEADLINE.2-m3a", "M6")
        table = table.replace(supplementary, supplementary.replace("\tM3a\n", "\tM6\n"))
    elif damage == "supplementary-stage":
        # M3b is an active stage, so only the pinned supplementary stage refuses it.
        table = table.replace(supplementary, supplementary.replace("\tM3a\n", "\tM3b\n"))
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


# 이것을 실패시키는 것: 보조 행이 있는 pending 쌍을 거부하는 것(부분 증거를 가리키되 쌍은 열어 둠),
# 또는 나중에 primary 행이 그 쌍을 닫는 것을 거부하는 것.
@pytest.mark.parametrize("closed", [False, True], ids=["pending", "closed-by-primary"])
def test_supplementary_row_keeps_its_pair_pending(closed):
    pending = tuple(p for p in M3D_PENDING if p != "GATE-ZOMBIES.1")
    table = HEADER + row_line("GATE-ZOMBIES.1-m3a", "GATE-ZOMBIES", 1) + standing_lines()
    if closed:
        table += row_line("GATE-ZOMBIES.1", "GATE-ZOMBIES", 1)
    else:
        pending += ("GATE-ZOMBIES.1",)
    assert_clauses_accounted(table, pending)


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


SELF_GREP = "          grep -Fx 'PASSED tests/shell/test_gate_acceptance.py::test_gate_rows_exist_and_run_in_ci' \"$RUNNER_TEMP/gate-acceptance.txt\"\n"
JOB_NEEDS = "    needs: detect\n"
JOB_IF = "    if: needs.detect.outputs.rust == 'true'\n"
MATRIX = {"filter-calls": ("        profile: [debug, release]\n", "        profile: [debug, release]\n        exclude: [{profile: release}]\n"),
          "shell-macos": (JOB_NEEDS, JOB_NEEDS + "    strategy:\n      matrix:\n        os: [macos-latest]\n")}


# 이것을 실패시키는 것: shell.yml 증거 step의 단언 삭제·`set +e`·continue-on-error·matrix if,
# 다른 workflow의 interpreter, 다른 로그, .py 파일의 Rust target, job 단위 우회·matrix 변경,
# 모르는 workflow를 받는 것.
@pytest.mark.parametrize("damage", ["delete", "set+e", "continue", "matrix-if", "interpreter", "other-log", "target",
                                    "job-continue", "job-if", "matrix", "unknown-workflow", "runner",
                                    "other-platform", "both-platforms", "no-pipefail", "prefix-grep"])
@pytest.mark.parametrize("job", GATE_STEP_JOBS)
def test_gate_ci_step_rejects_mutations(job, damage):
    texts = workflows()
    shell = texts["shell.yml"]
    if damage == "delete":
        shell = in_job(shell, job, SELF_GREP, "")
    elif damage == "set+e":
        shell = in_job(shell, job, SELF_GREP, "          set +e\n" + SELF_GREP)
    elif damage == "continue":
        shell = in_job(shell, job, SELF_STEP, SELF_STEP + "        continue-on-error: true\n")
    elif damage == "matrix-if":
        shell = in_job(shell, job, SELF_STEP, SELF_STEP + "        if: matrix.os == 'macos-latest'\n")
    elif damage == "interpreter":
        shell = in_job(shell, job, '"$RUNNER_TEMP/venv/bin/python" -m pytest tests/shell/test_gate_acceptance.py',
                       '"$RUNNER_TEMP/collector-tests/bin/python" -m pytest tests/shell/test_gate_acceptance.py')
    elif damage == "other-log":
        shell = in_job(shell, job, SELF_GREP, SELF_GREP.replace("gate-acceptance.txt", "pytest.out"))
    elif damage == "job-continue":
        shell = in_job(shell, job, JOB_NEEDS, JOB_NEEDS + "    continue-on-error: true\n")
    elif damage == "job-if":
        shell = in_job(shell, job, JOB_IF, "    if: always()\n")
    elif damage == "matrix":
        shell = in_job(shell, job, *MATRIX[job])
    elif damage == "runner":
        runner = {"filter-calls": "ubuntu-latest", "shell-macos": "macos-latest"}[job]
        other = {"filter-calls": "macos-latest", "shell-macos": "ubuntu-latest"}[job]
        if job == "filter-calls":
            # runs-on is the matrix os here: move every cell to macOS.
            for label in ("ubuntu-latest", "ubuntu-24.04-arm"):
                shell = shell.replace(label, other)
        else:
            shell = in_job(shell, job, f"    runs-on: {runner}\n", f"    runs-on: {other}\n")
    elif damage == "no-pipefail":
        start, end = job_span(shell, job)
        block = shell[start:end]
        at = block.index(SELF_STEP)
        block = block[:at] + block[at:].replace("          set -o pipefail\n", "", 1)
        shell = shell[:start] + block + shell[end:]
    elif damage == "prefix-grep":
        # A substring match would accept a passing `..._decoy` test in place of a skipped one.
        shell = in_job(shell, job, SELF_GREP, SELF_GREP.replace("grep -Fx", "grep -F"))
    if damage in ("other-platform", "both-platforms"):
        # Only this job keeps its step: a row for the other OS, or for both, lacks evidence.
        platform = {"filter-calls": "macOS", "shell-macos": "Linux"}[job] if damage == "other-platform" else "Unix"
        with pytest.raises(AssertionError, match="no asserted CI pytest|platform evidence"):
            assert_self_rows(texts, job, platform=platform)
        return
    if damage == "unknown-workflow":
        # A workflow the checker does not read must be refused, not ignored.
        texts["bench.yml"] = (ROOT / ".github/workflows/bench.yml").read_text()
        with pytest.raises(AssertionError, match="bench.yml"):
            assert_self_rows(texts, job, files=("shell.yml", "bench.yml"))
        return
    if damage == "target":
        # A pytest row must say pytest; a Rust target on a .py file is refused.
        with pytest.raises(AssertionError, match="target and file"):
            assert_self_rows(texts, job, target="test:gate_acceptance")
        return
    assert shell != texts["shell.yml"]
    texts["shell.yml"] = shell
    with pytest.raises(AssertionError):
        assert_self_rows(texts, job)


# A named binary resolves through its [[bin]] path: a synthetic CI step checks
# the real bingsu-bench `m1-cgroup-probe` test.
BIN_TEST = "crates/bingsu-bench/src/bin/m1_cgroup_probe.rs::tests::label_fails_closed"
BIN_STEP = (
    "      - run: |\n"
    "          set -o pipefail\n"
    "          cargo test -j 2 -p bingsu-bench --bin m1-cgroup-probe | tee \"$RUNNER_TEMP/bench-bin.txt\"\n"
    "          grep -F 'test tests::label_fails_closed ... ok' \"$RUNNER_TEMP/bench-bin.txt\"\n")


def bin_case(damage):
    table = ("id\tgate\tclause\tproperty\tplatform\ttest\ttarget\tstage\n"
             f"GATE-ZOMBIES.1\tGATE-ZOMBIES\t1\tSynthetic bin row\tUnix\t{BIN_TEST}\tbin:m1-cgroup-probe\tM3d\n")
    texts = workflows()
    step = BIN_STEP
    if damage == "other-bin":
        table = table.replace("\tbin:m1-cgroup-probe\t", "\tbin:m1-file-costs\t")
    elif damage == "unknown-bin":
        table = table.replace("\tbin:m1-cgroup-probe\t", "\tbin:m1-absent\t")
    elif damage == "selection":
        step = step.replace("--bin m1-cgroup-probe", "--bin m1-file-costs")
    texts["ci.yml"] = texts["ci.yml"].replace(LIB_ANCHOR, step + LIB_ANCHOR)
    return table, texts


def test_named_bin_row_is_accepted():
    table, texts = bin_case(None)
    assert_acceptance_table(table, texts, required_ids=frozenset({"GATE-ZOMBIES.1"}),
                            required_gates=frozenset(M3D_GATE_IDS))


# 이것을 실패시키는 것: 이름 붙은 bin을 다른 bin의 root로 풀거나, 없는 bin·다른 --bin 실행을 받는 것.
@pytest.mark.parametrize("damage", ["other-bin", "unknown-bin", "selection"])
def test_named_bin_row_rejects_mutations(damage):
    table, texts = bin_case(damage)
    with pytest.raises(AssertionError):
        assert_acceptance_table(table, texts, required_ids=frozenset({"GATE-ZOMBIES.1"}),
                                required_gates=frozenset(M3D_GATE_IDS))


COLLECTOR_RUNS_ON = "    runs-on: ${{ matrix.os }}\n    # F3 first-run native failures"


# 이것을 실패시키는 것: ci.yml collector job의 runs-on을 바꿔도 하드코딩한 플랫폼으로 Unix 행을 받는 것.
@pytest.mark.parametrize("runner", ["macos-latest", "ubuntu-latest"])
def test_ci_job_platforms_come_from_the_workflow(runner):
    texts = workflows()
    assert texts["ci.yml"].count(COLLECTOR_RUNS_ON) == 1
    texts["ci.yml"] = texts["ci.yml"].replace(COLLECTOR_RUNS_ON, COLLECTOR_RUNS_ON.replace("${{ matrix.os }}", runner))
    with pytest.raises(AssertionError, match="platform evidence"):
        assert_gate_table((ROOT / TABLE).read_text(), texts)


# 이것을 실패시키는 것: matrix exclude로 빠진 OS를 그 job의 플랫폼으로 세는 것, 모르는 runner를 받는 것.
@pytest.mark.parametrize("strategy,runs_on", [
    (["matrix:", "  os: [ubuntu-24.04, macos-latest]", "  exclude: [{os: macos-latest}]"], "${{ matrix.os }}"),
    ([], "windows-latest"),
])
def test_job_platforms_refuse_excludes_and_unknown_runners(strategy, runs_on):
    with pytest.raises(AssertionError):
        job_platforms("synthetic", {"runs-on": (runs_on, []), "strategy": ("", strategy)})


def test_job_platforms_read_lists_and_includes():
    assert job_platforms("synthetic", {"runs-on": ("${{ matrix.os }}", []), "strategy": (
        "", ["matrix:", "  include:", "    - os: ubuntu-24.04", "    - os: macos-latest"])}) == {"linux", "macos"}
    assert job_platforms("synthetic", {"runs-on": ("ubuntu-latest", [])}) == {"linux"}


RELEASE_STEP = "      - name: Helper calls per publication stage equal the formula (release)\n"
RELEASE_IF = "        if: matrix.profile == 'release'\n"


# 이것을 실패시키는 것: release 게이트(GATE-FS-HELPER) 행을 debug 칸까지 도는 step, debug 칸만 도는 step,
# 또는 profile 축이 없는 job의 profile 조건으로 받는 것.
@pytest.mark.parametrize("damage", ["no-condition", "debug-only", "release-gate-unknown"])
def test_release_gate_rows_need_release_only_cells(damage):
    table = (ROOT / TABLE).read_text()
    texts = workflows()
    shell = texts["shell.yml"]
    assert shell.count(RELEASE_STEP + RELEASE_IF) == 1
    if damage == "no-condition":
        shell = shell.replace(RELEASE_STEP + RELEASE_IF, RELEASE_STEP)
    elif damage == "debug-only":
        shell = shell.replace(RELEASE_STEP + RELEASE_IF, RELEASE_STEP + RELEASE_IF.replace("release", "debug"))
    texts["shell.yml"] = shell
    if damage == "release-gate-unknown":
        # The same evidence without the release-gate set passes: the set is what refuses debug cells.
        assert_acceptance_table(without_deferred(table), texts,
                                required_ids=frozenset(covered(table)) | set(M3D_SUPPLEMENTARY),
                                required_gates=frozenset(M3D_GATE_IDS))
        return
    with pytest.raises(AssertionError, match="release cells"):
        assert_gate_table(table, texts)


# 이것을 실패시키는 것: profile 축이 없는 job(shell-macos)의 profile 조건 step을 증거로 받는 것.
def test_profile_condition_needs_a_profile_axis():
    from test_collector_security import acceptance_pair_allowed
    row = {"id": "GATE-FS-HELPER.1", "platform": "Linux"}
    step = {"if": "matrix.profile == 'release'", "run": "echo ok", "_platforms": {"linux"}, "_cells": None}
    assert acceptance_pair_allowed(row, step, step, ["echo", "ok"]) is None
    step["_cells"] = [{"os": "ubuntu-latest", "libc": "gnu", "profile": "release"}]
    assert acceptance_pair_allowed(row, step, step, ["echo", "ok"]) == {"linux"}


HELPER_STAGE_ROWS = ("GATE-FS-HELPER.1", "GATE-FS-HELPER.1-publish", "GATE-FS-HELPER.1-collect",
                     "GATE-FS-HELPER.1-last_good", "GATE-FS-HELPER.1-recover")


# 이것을 실패시키는 것: 다섯 단계 행 중 하나(와 그 CI 선택·단언)를 지워도 표 검사가 통과하는 것.
@pytest.mark.parametrize("row_id", HELPER_STAGE_ROWS)
def test_every_helper_stage_row_is_required(row_id):
    table = (ROOT / TABLE).read_text()
    texts = workflows()
    line = next(l for l in table.splitlines(True) if l.startswith(row_id + "\t"))
    node = line.split("\t")[5]
    shell = texts["shell.yml"]
    grep = f"          grep -Fx 'PASSED {node}' \"$RUNNER_TEMP/helper-stage.txt\"\n"
    assert shell.count(grep) == 1 and shell.count(f" '{node}'") == 1
    texts["shell.yml"] = shell.replace(grep, "").replace(f" '{node}'", "")
    with pytest.raises(AssertionError):
        assert_gate_table(table.replace(line, ""), texts)


ARM_MUSL = "          - os: ubuntu-24.04-arm\n            libc: musl\n            profile: release\n"


# 이것을 실패시키는 것: x86_64·aarch64 × glibc·musl release 칸 중 하나가 빠진 job을 release 게이트 증거로 받는 것.
# 고정한 matrix 줄도 함께 바꿔, matrix 고정 검사가 아니라 칸 규칙만 거부하게 한다.
def test_release_gate_rows_need_every_arch_and_libc(monkeypatch):
    import test_collector_security as security
    texts = workflows()
    assert texts["shell.yml"].count(ARM_MUSL) == 1
    texts["shell.yml"] = texts["shell.yml"].replace(ARM_MUSL, "")
    pinned = list(security.SHELL_EVIDENCE_JOBS["filter-calls"])
    at = len(pinned) - 3
    assert pinned[at:] == ["- os: ubuntu-24.04-arm", "libc: musl", "profile: release"]
    monkeypatch.setitem(security.SHELL_EVIDENCE_JOBS, "filter-calls", pinned[:at])
    with pytest.raises(AssertionError, match="release cells"):
        assert_gate_table((ROOT / TABLE).read_text(), texts)


# 이것을 실패시키는 것: include 항목을 새 칸이 아니라 기존 칸에 덮어쓰거나 버리는 것.
def test_job_cells_follow_the_include_rule():
    from test_collector_security import job_cells
    strategy = ["fail-fast: false", "matrix:", "os: [ubuntu-latest]", "libc: [gnu, musl]", "profile: [debug, release]",
                "include:", "- os: ubuntu-24.04-arm", "  libc: gnu", "  profile: release", "- libc: gnu", "  extra: x"]
    cells = job_cells(strategy)
    assert len(cells) == 5
    assert {"os": "ubuntu-24.04-arm", "libc": "gnu", "profile": "release"} in cells
    assert sum(cell.get("extra") == "x" for cell in cells) == 2


# 이것을 실패시키는 것: ARM matrix 라벨을 남긴 채 모든 칸을 x86_64 runner에서 돌리는 것.
def test_release_gate_cells_require_effective_matrix_runner():
    texts = workflows()
    runner = "    runs-on: ${{ matrix.os }}\n"
    texts["shell.yml"] = in_job(texts["shell.yml"], "filter-calls", runner, "    runs-on: ubuntu-latest\n")
    with pytest.raises(AssertionError, match="release runner"):
        assert_gate_table((ROOT / TABLE).read_text(), texts)


# 이것을 실패시키는 것: A4 fallback/상한/머리 거부 행을 삭제하는 것.
@pytest.mark.parametrize('gate', ['GATE-FS-FRONT', 'GATE-FRONT-READ-BYTES'])
@pytest.mark.parametrize('suffix', ['', '-checksum_last_good', '-body_limit', '-header_only'])
def test_every_front_attempt_row_is_required(gate, suffix):
    row_id = gate + '.1' + suffix
    table = (ROOT / TABLE).read_text()
    table = '\n'.join(line for line in table.splitlines() if not line.startswith(row_id + '\t')) + '\n'
    with pytest.raises(AssertionError):
        assert_gate_table(table, workflows())


# 이것을 실패시키는 것: A4 live를 debug에서 돌리거나 정확한 PASSED 단언/pipefail을 빼는 것.
@pytest.mark.parametrize('mutation', ['release', 'grep', 'pipefail'])
def test_front_live_ci_evidence_is_required(mutation):
    texts = workflows()
    step = '      - name: Front attempts equal axis C and byte formulas (release)\n'
    start = texts['shell.yml'].index(step)
    end = texts['shell.yml'].index('      - name: Upload failed', start)
    block = texts['shell.yml'][start:end]
    if mutation == 'release':
        changed = block.replace("        if: matrix.profile == 'release'\n", '')
    elif mutation == 'grep':
        changed = block.replace("grep -Fx 'PASSED tests/shell/test_prompt_env_paths.py::test_live_front_attempts_match_axis_c[body-limit]'", "grep -Fx 'PASSED absent'")
    else:
        changed = block.replace('          set -o pipefail\n', '')
    texts['shell.yml'] = texts['shell.yml'][:start] + changed + texts['shell.yml'][end:]
    with pytest.raises(AssertionError):
        assert_gate_table((ROOT / TABLE).read_text(), texts)


# 이것을 실패시키는 것: release 대신 debug 계측, arm runner를 x86로 교체, trace evidence 삭제.
def assert_b1_contract(text):
    start, end = job_span(text, "b1-children")
    job = text[start:end]
    # 이것을 실패시키는 것: uname 뒤 arch·target 덮어쓰기 또는 실제 빌드 인자 바꿔치기.
    expected_build = '''          arch=$(uname -m)
          target="$arch-unknown-linux-$LIBC"
          rustup target add "$target"
          if [ "$LIBC" = musl ]; then sudo apt-get update -q; sudo apt-get install -y musl-tools; fi
          cargo build -p bingsu -p bingsu-collect --release --target "$target"
          echo "BINGSU_BIN=$PWD/target/$target/release/bingsu" >> "$GITHUB_ENV"
'''
    actual_build = job.split("      - name: Build release siblings\n        run: |\n", 1)[1].split("      - name:", 1)[0]
    # 이것을 실패시키는 것: assert actual_build == expected_build 조건을 제거하거나 반전하는 변이.
    assert actual_build == expected_build
    for required in ("runs-on: ${{ matrix.os }}", "os: [ubuntu-latest, ubuntu-24.04-arm]",
                     "libc: [gnu, musl]", "PROFILE: release", "arch=$(uname -m)",
                     'target="$arch-unknown-linux-$LIBC"',
                     'cargo build -p bingsu -p bingsu-collect --release --target "$target"',
                     '--basetemp="$RUNNER_TEMP/b1-evidence"', "if: failure()"):
        # 이것을 실패시키는 것: assert required in job, required 조건을 제거하거나 반전하는 변이.
        assert required in job, required


# 이것을 실패시키는 것: B1 행렬의 유효 runs-on과 계측 빌드의 아키텍처를 분리하는 것.
def test_b1_release_platform_contract():
    assert_b1_contract(workflows()["shell.yml"])


# 이것을 실패시키는 것: 위 release·플랫폼·evidence 조건 하나를 지워도 checker가 통과하는 것.
@pytest.mark.parametrize("token", ["runs-on: ${{ matrix.os }}", "ubuntu-24.04-arm", "PROFILE: release",
                                   "arch=$(uname -m)", "--release --target", "--basetemp="])
def test_b1_release_platform_contract_rejects_mutations(token):
    text = workflows()["shell.yml"]
    start, end = job_span(text, "b1-children")
    damaged = text[:start] + text[start:end].replace(token, "BROKEN") + text[end:]
    with pytest.raises(AssertionError):
        assert_b1_contract(damaged)


# 이것을 실패시키는 것: 실제 runs-on과 다른 arch를 uname 뒤에서 덮어쓰는 변이.
def test_b1_rejects_arch_override():
    text = workflows()["shell.yml"].replace('arch=$(uname -m)\n', 'arch=$(uname -m)\n          arch=x86_64\n')
    with pytest.raises(AssertionError):
        assert_b1_contract(text)


# 이것을 실패시키는 것: C1의 네 PASSED 단언 중 하나를 빼도 표가 통과하는 것.
@pytest.mark.parametrize("clause", [1, 2, 3, 4])
def test_runtime_root_rows_require_each_pass(clause):
    table = (ROOT / TABLE).read_text()
    row = next(r for r in rows(table) if r["id"] == f"GATE-RUNTIME-ROOT.{clause}")
    texts = workflows()
    assertion = f"grep -Fx 'PASSED {row['test']}'"
    assert texts["shell.yml"].count(assertion) == 1
    texts["shell.yml"] = texts["shell.yml"].replace(assertion, "# " + assertion)
    with pytest.raises(AssertionError):
        assert_gate_table(table, texts)


# 이것을 실패시키는 것: 상태 알림을 active 또는 pending으로 되돌리는 것, deferred 행을 지우는 것.
def test_runtime_notice_stays_deferred():
    table = (ROOT / TABLE).read_text()
    row = next(r for r in rows(table) if r["id"] == "GATE-RUNTIME-ROOT.5")
    assert "Status-notice hook output" in row["property"]
    assert row["stage"] == "deferred:M4/M5"
    line = next(l for l in table.splitlines(True) if l.startswith(row["id"] + "\t"))
    with pytest.raises(AssertionError):
        assert_gate_table(table.replace(line, ""), workflows())
