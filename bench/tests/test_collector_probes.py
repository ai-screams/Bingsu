"""Acceptance parser and real host-probe mutation anchors.

이것을 실패시키는 것: 누락된 셀, PASS 한 단어, 잘못된 errno/canary/fd 증거를 수용하는 것.
"""
import copy
import importlib.util
import json
import platform
import subprocess
from pathlib import Path
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "probes/run-collector-probes.py"
SPEC = importlib.util.spec_from_file_location("collector_probes", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def current_x32():
    saved = SOURCE.parent / "results/x32-macos-27.0.1-aarch64.json"
    return json.loads(saved.read_text())["results"][0]


@pytest.fixture
def recorded_x32_build(monkeypatch):
    # Validate the historical fixture against its recorded build. Runner edits
    # make real observations stale; dedicated ledger tests enforce that guard.
    recorded = current_x32()["build_id"]
    original = probe.build_id
    monkeypatch.setattr(probe, "build_id", lambda case: recorded if case == "X-32" else original(case))


def test_ledger_requires_every_acceptance_cell(monkeypatch, tmp_path, recorded_x32_build):
    rows = probe.ledger_rows()
    assert len(rows) == 108
    assert sum(row["status"] == "observed" and row["case"] == "X-32"
               and row["environment"] == "macos-current" and row["arch"] == "aarch64" for row in rows) == 6
    # Missing one required kernel/arch/criterion cell must block acceptance.
    text = (SOURCE.parent / "collector-acceptance.tsv").read_text()
    (tmp_path / "collector-acceptance.tsv").write_text("\n".join(text.splitlines()[:-1]) + "\n")
    monkeypatch.setattr(probe, "HERE", tmp_path)
    with pytest.raises(ValueError, match="missing or duplicated"):
        probe.ledger_rows()


@pytest.mark.parametrize("damage", ["missing", "duplicate", "errno", "leak", "sid", "race", "close_time", "word"])
def test_x32_evidence_rejects_mutations(damage):
    records = [json.loads(line) for line in current_x32()["evidence"]["stdout"].splitlines()]
    if damage == "missing":
        records.pop()
    elif damage == "duplicate":
        records[-1] = copy.deepcopy(records[0])
    elif damage == "errno":
        records[0]["evidence"]["errno"] = 1
    elif damage == "leak":
        records[1]["evidence"]["leaks"] = 1
    elif damage == "sid":
        records[2]["evidence"]["sid"] = records[2]["evidence"]["parent_sid"]
    elif damage == "race":
        records[-1]["evidence"]["opens"] = 0
    elif damage == "close_time":
        records[3]["evidence"]["close_ns"] = 0
    stdout = "PASS" if damage == "word" else "\n".join(map(json.dumps, records))
    with pytest.raises((ValueError, KeyError)):
        probe.validate("X-32", stdout)


def test_recorded_x32_evidence_and_mutation():
    result = current_x32()
    assert set(probe.validate("X-32", result["evidence"]["stdout"])) == set(probe.CELLS["X-32"])
    assert result["evidence"]["os_version"] == "27.0.1"
    assert result["evidence"]["deployment_target"] == "11.0"
    assert result["evidence"]["returncode"] == 0
    assert result["evidence"]["mutation"]["returncode"] == 90
    with pytest.raises(ValueError, match="mutated session"):
        probe.validate("X-32", result["evidence"]["stdout"], mutate=True)


def x02_fixture():
    # Synthetic parser input only; never entered in the observation ledger.
    cells = {}
    for name in ("bash_handoff", "python_handoff"):
        cells[name] = dict(closed_exit=2, closed_canary=0, open_exit=0, open_canary=1,
                           exec_errno=0, leaks=0, high_fd=257, soft_limit=256, seals=47, fallback_errno=0, noexec_errno=13)
    cells.update(native_modes=dict(rdonly_exit=0, opath_exit=0, opath_read_errno=9, canaries=2),
                 shebang_boundary=dict(exec_errno=2, canary=0, nested_rejected=1),
                 size_and_noexec=dict(accepted_bytes=65536, rejected_bytes=65537, fallback_errno=0, other_errno_rejected=1),
                 system_walk=dict(links=2, merged_usr=1, native=1, exit=0, canary=1),
                 refusals=dict.fromkeys(("relative", "relative_link", "env", "proc_missing", "replaced_link", "writable_chain", "writable_control", "relative_control", "replacement_control"), 1))
    return cells


@pytest.mark.parametrize("cell,key,value", [("bash_handoff", "open_canary", 0),
                                          ("bash_handoff", "high_fd", 256),
                                          ("python_handoff", "high_fd", 255),
                                          ("python_handoff", "soft_limit", 257),
                                          ("bash_handoff", "leaks", 1),
                                          ("python_handoff", "seals", 7),
                                          ("native_modes", "opath_read_errno", 0),
                                          ("shebang_boundary", "exec_errno", 13),
                                          ("size_and_noexec", "fallback_errno", 1),
                                          ("system_walk", "links", 0),
                                          ("refusals", "replaced_link", 0)])
def test_x02_parser_mutations(cell, key, value):
    cells = x02_fixture()
    serialize = lambda: "\n".join(json.dumps(dict(cell=k, evidence=v)) for k, v in cells.items())
    probe.validate("X-02", serialize())
    cells[cell][key] = value
    with pytest.raises(ValueError):
        probe.validate("X-02", serialize())


@pytest.mark.parametrize("soft_limit,high_fd", [(126, 127), (254, 255), (256, 257), (256, 300)])
def test_x02_accepts_high_fd_relative_to_soft_limit(soft_limit, high_fd):
    cells = x02_fixture()
    for name in ("bash_handoff", "python_handoff"):
        cells[name].update(soft_limit=soft_limit, high_fd=high_fd)
    text = "\n".join(json.dumps(dict(cell=k, evidence=v)) for k, v in cells.items())
    probe.validate("X-02", text)


def test_existing_experiments_need_actual_evidence():
    for case in ("X-14", "X-16"):
        with pytest.raises(ValueError):
            probe.validate(case, f"{case} PASS\n")
    text = "X-14 status PASS changes=2 index_unchanged=1 baseline=100 limit=200\nX-14 PASS\n"
    assert probe.validate("X-14", text)["status"]["changes"] == 2
    with pytest.raises(ValueError):
        probe.validate("X-14", text, mutate=True)
    text = "\n".join(f"X-16 {cell} EPERM unchanged" for cell in probe.CELLS["X-16"])
    text += "\nX-16 PASS cells=6 fsize=0 control_truncated=1\ntest result: ok. 1 passed; 0 failed;\n"
    text += x16_metadata("musl")
    assert len(probe.validate("X-16", text)) == 6
    with pytest.raises(ValueError):
        probe.validate("X-16", text, mutate=True)


def test_run_probe_exit_and_timeout():
    result = probe.run_probe("X-32", [sys.executable, "-c", "raise SystemExit(7)"], 5)
    assert result.outcome == "FAIL" and result.evidence["returncode"] == 7
    result = probe.run_probe("X-32", [sys.executable, "-c", "import time; time.sleep(30)"], 0.05)
    assert result.outcome == "FAIL" and "timeout" in result.evidence["reason"]
    result = probe.run_probe("X-32", ["x32-deliberately-missing-executable"], 5)
    assert result.outcome == "BLOCKED"


@pytest.mark.parametrize("damage", ["build_id", "returncode"])
def test_ledger_rejects_stale_or_failed_evidence(monkeypatch, damage):
    saved = current_x32()
    monkeypatch.setattr(probe, "build_id", lambda case: saved["build_id"])
    damaged = copy.deepcopy(saved)
    if damage == "build_id":
        damaged["build_id"] = "stale-build"
    else:
        damaged["evidence"]["returncode"] = 7
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        if path.name == "x32-macos-27.0.1-aarch64.json":
            return json.dumps({"results": [damaged]})
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    with pytest.raises(ValueError, match="build|returncode"):
        probe.ledger_rows()


@pytest.mark.parametrize("damage", ["high_fd", "resolver_control"])
def test_x02_requires_real_fixture_observations(damage):
    cells = x02_fixture()
    if damage == "high_fd":
        for name in ("bash_handoff", "python_handoff"):
            cells[name].pop("high_fd", None)
    else:
        cells["refusals"].pop("writable_control", None)
    text = "\n".join(json.dumps(dict(cell=k, evidence=v)) for k, v in cells.items())
    with pytest.raises((ValueError, KeyError)):
        probe.validate("X-02", text)


@pytest.mark.parametrize("metadata", [False, True])
def test_x16_musl_target_cannot_relabel_glibc_probe(monkeypatch, metadata):
    text = "\n".join(f"X-16 {cell} EPERM unchanged" for cell in probe.CELLS["X-16"])
    text += "\nX-16 PASS cells=6 fsize=0 control_truncated=1\ntest result: ok. 1 passed; 0 failed;\n"
    if metadata:
        text += x16_metadata("glibc")
    monkeypatch.setattr(probe.platform, "system", lambda: "Linux")
    monkeypatch.setattr(probe, "run_probe", lambda case, command, timeout: probe.ProbeResult(
        case, "Linux", "6.8", "glibc 2.39", "x86_64", probe.build_id(case), "PASS",
        {"returncode": 0, "stdout": text}))
    result = probe.execute_case("X-16", "x86_64-unknown-linux-musl")
    assert result.outcome == "FAIL"


def x16_metadata(libc):
    loader = "/lib/ld-musl-x86_64.so.1" if libc == "musl" else "/lib64/ld-linux-x86-64.so.2"
    headers = "non-glibc" if libc == "musl" else "glibc"
    return (f"X-16 compiler={libc}-gcc: GCC 14\nX-16 cflags=-O2\n"
            f"X-16 elf_interpreter={loader}\nX-16 c_libc={headers}\n")


@pytest.mark.parametrize("libc", ["musl", "glibc"])
def test_x16_actual_c_linkage_is_required(libc):
    text = x16_metadata(libc)
    assert probe.x16_build(text, libc)["libc"] == libc
    with pytest.raises(ValueError, match="does not match"):
        probe.x16_build(text, "glibc" if libc == "musl" else "musl")
    with pytest.raises(ValueError, match="headers/linkage"):
        probe.x16_build(text.replace("c_libc=", "c_libc=wrong-"))
    with pytest.raises(ValueError, match="unidentified"):
        probe.x16_build(text.replace("ld-musl-", "unknown-").replace("ld-linux", "unknown-"))


def test_x16_ledger_commands_configure_c_and_rust_musl(recorded_x32_build):
    for row in probe.ledger_rows():
        if row["case"] == "X-16" and row["environment"] == "linux-musl":
            assert "CC=musl-gcc" in row["command"]
            assert f'CARGO_TARGET_{row["arch"].upper()}_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc' in row["command"]
            assert "BINGSU_X16_CFLAGS=" in row["command"]


@pytest.mark.skipif(platform.system() != "Linux", reason="requires native Linux memfd/execveat")
@pytest.mark.parametrize("nofile", [128, 256, 1024])
@pytest.mark.parametrize("mutation", [None, "fd", "python_fd", "replacement", "relative", "writable"])
def test_x02_native_guards_kill_mutations(tmp_path, mutation, nofile):
    import resource

    source = (SOURCE.parent / "x02-memfd.c").read_text()
    arguments = []
    if mutation in ("fd", "python_fd"):
        arguments = ["--mutate-fd-close" if mutation == "fd" else "--mutate-python-fd-close"]
    elif mutation is not None:
        old, new = {
            "replacement": ("n <= 0 || !unchanged", "n <= 0 || (unchanged && 0)"),
            "relative": ("!link_target_allowed(target, trusted)", "!link_target_allowed(target, 1)"),
            "writable": ("s.st_uid != owner || (s.st_mode & 0022)", "s.st_uid != owner"),
        }[mutation]
        assert old in source
        source = source.replace(old, new)
    path = tmp_path / "probe.c"
    path.write_text(source)
    binary = tmp_path / "probe"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(path), "-o", str(binary)], check=True)
    def lower_nofile():
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limit = nofile if hard == resource.RLIM_INFINITY else min(nofile, hard)
        # Cap both limits: passing must not rely on raising the soft limit.
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))

    result = subprocess.run([str(binary), *arguments], capture_output=True, text=True, timeout=30,
                            preexec_fn=lower_nofile)
    if mutation is None:
        assert result.returncode == 0, result.stderr
        cells = probe.validate("X-02", result.stdout)
        for name in ("bash_handoff", "python_handoff"):
            e = cells[name]
            assert e["soft_limit"] < e["high_fd"] < nofile
        return
    assert result.returncode == 90 and "assertion:" in result.stderr
    if mutation in ("fd", "python_fd"):
        cell = "bash_handoff" if mutation == "fd" else "python_handoff"
        records = [json.loads(line) for line in result.stdout.splitlines()]
        assert next(r["evidence"]["leaks"] for r in records if r["cell"] == cell) == 1
        with pytest.raises(ValueError):
            probe.validate("X-02", result.stdout)
    else:
        assert 'interpreter_at("/link"' in result.stderr


def test_stale_observations_become_blocked_for_remeasurement(monkeypatch):
    original = probe.build_id
    monkeypatch.setattr(probe, "build_id", lambda case: "new-build" if case == "X-32" else original(case))
    rows = probe.ledger_rows(allow_stale=True)
    assert len(rows) == 108
    assert all(row["outcome"] == "BLOCKED" for row in rows)
    assert sum(row["reason"] == "observed build_id is stale" for row in rows) == 6
