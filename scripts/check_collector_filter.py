#!/usr/bin/env python3
"""Check identity-only library isolation, collector table, BPF evaluator and probes.

--mutations changes one rule/condition at a time and restores saved bytes even
on failure. Compilation errors do not count as killed mutations. Runtime-only
mutations additionally require --runtime on a native Linux host.
"""
import argparse
import json
import os
import sys
import csv
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIB = Path("crates/bingsu-identity/src/lib.rs")
TABLE = Path("crates/bingsu-collect/collector-syscalls.tsv")
FILTER = Path("crates/bingsu-collect/src/filter.rs")
LANDLOCK = Path("crates/bingsu-collect/src/landlock.rs")
WORKER = Path("crates/bingsu-collect/src/worker.rs")
SYS = Path("crates/bingsu-collect/src/sys.rs")


def check_identity_only():
    # The helper reaches this pinned file. Keep worker modules and re-exports
    # out even behind cfg: a macOS check must also guard the Linux build.
    item = re.search(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:mod|use)\b[^\n]*",
                     (ROOT / LIB).read_text(), re.MULTILINE)
    assert item is None, f"identity library must not declare modules or imports: {item.group().strip()}"


def host_tests_passed(result):
    return result.returncode == 0 and re.search(
        r"^test result: ok\. 9 passed; 0 failed; 0 ignored; 0 measured; "
        r"\d+ filtered out; finished in \d+\.\d+s$", result.stdout, re.MULTILINE) is not None


def run(test=None, target="filter", binary=False):
    command = ["cargo", "test", "--offline", "-j", "2", "-p", "bingsu-collect",
               "--bin" if binary else "--test", target]
    if test:
        command += [test, "--", "--exact", "--test-threads=2"]
    else:
        command += ["--", "--skip", "runtime::", "--skip", "safe_read::", "--skip", "meter::", "--test-threads=2"]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--repository-trace", action="store_true")
    args = parser.parse_args()
    check_identity_only()
    rows = list(csv.DictReader((line for line in (ROOT / TABLE).read_text().splitlines()
                              if not line.startswith("#")), delimiter="\t"))
    assert len(rows) == 51 and len({r["probe"] for r in rows}) == len(rows)
    assert all(r["why"].strip() and r["probe"] == f'row_{r["syscall"]}_{r["condition"]}' for r in rows)
    result = run()
    assert host_tests_passed(result), result.stdout + result.stderr
    print("collector identity/table/program/probes PASS: identity-only lib, 51 rows, both ABIs, 9 host tests")
    if args.repository_trace:
        repository_trace()
    if not args.mutations:
        return
    cases = []

    def add(name, path, old, new, test, target="filter", binary=False):
        cases.append((name, path, old, new, test, target, binary))

    for module in ("filter", "landlock"):
        add("library exposes " + module, LIB, "#![forbid(unsafe_code)]",
            "#![forbid(unsafe_code)]\n#[cfg(target_os = \"linux\")]\nextern crate std;\n"
            f"#[cfg(target_os = \"linux\")]\n#[allow(unsafe_code)]\npub mod {module};",
            "identity-only library", target=None)

    table_test = "table_program_and_row_removal_probes_agree"
    for row in rows:
        line = "\t".join(row.values()) + "\n"
        add("remove " + row["probe"], TABLE, line, "", table_test)
    add("wrong syscall number", TABLE, "read\t0\t63", "read\t999\t63", table_test)
    arch = "bpf_arch_x32_and_64bit_arguments_are_exact"
    clone = "bpf_clone_allows_threads_only"
    write = "bpf_write_paths_have_no_alias_bypass"
    memory = "bpf_fd_and_mapping_rules_cannot_write_files"
    limits = "bpf_final_filter_refuses_limit_changes"
    for name, old, new, test in [
        ("architecture", "op(JEQ, 1, 0, arch.value())", "op(JEQ, 0, 1, arch.value())", arch),
        ("x32 bit", "0x4000_0000)", "0)", arch),
        ("legacy x32 lower", "op(JGE, 0, 2, 512)", "op(JGE, 0, 2, 513)", arch),
        ("legacy x32 upper", "op(JGT, 1, 0, 547)", "op(JGT, 1, 0, 546)", arch),
        ("default denial", "p.push(op(RET, 0, 0, DENY));", "p.push(op(RET, 0, 0, ALLOW));", write),
        ("clone3 fallback", "{\n                    ENOSYS\n", "{\n                    DENY\n", clone),
        ("clone high word", '"thread" => vec![vec![\n            high(0, 0),', '"thread" => vec![vec![\n            low(0, 0, 0),', clone),
        ("clone forbidden flags", "low(0, !THREAD_FLAGS, 0)", "low(0, 0, 0)", clone),
        ("clone required flags", "low(0, THREAD_REQUIRED, THREAD_REQUIRED)", "low(0, 0, 0)", clone),
        ("response fd", '"response" => vec![vec![eq(0, 1)]]', '"response" => vec![vec![]]', memory),
        ("fcntl duplication", "vec![eq(1, 1)], vec![eq(1, 3)]", "vec![eq(1, 0)], vec![eq(1, 3)]", memory),
        ("clock scope", "vec![eq(0, 1)], vec![eq(0, 7)]", "vec![eq(0, 0)], vec![eq(0, 7)]", memory),
        ("prctl scope", '"nnp_query" => vec![vec![eq(0, 39)]]', '"nnp_query" => vec![vec![]]', limits),
        ("NULL low word", '"query" => vec![vec![eq(2, 0), high(2, 0)]]', '"query" => vec![vec![high(2, 0)]]', limits),
        ("NULL high word", '"query" => vec![vec![eq(2, 0), high(2, 0)]]', '"query" => vec![vec![eq(2, 0)]]', limits),
        ("bootstrap pid", '"bootstrap_as" => vec![vec![eq(0, 0), eq(1, 9)]]', '"bootstrap_as" => vec![vec![eq(1, 9)]]', limits),
        ("bootstrap resource", '"bootstrap_as" => vec![vec![eq(0, 0), eq(1, 9)]]', '"bootstrap_as" => vec![vec![eq(0, 0)]]', limits),
        ("bootstrap operation", '"bootstrap_filter" => vec![vec![eq(0, 1), eq(1, 0)]]', '"bootstrap_filter" => vec![vec![eq(1, 0)]]', limits),
        ("bootstrap flags", '"bootstrap_filter" => vec![vec![eq(0, 1), eq(1, 0)]]', '"bootstrap_filter" => vec![vec![eq(0, 1)]]', limits),
        ("final seal", 'row.condition.starts_with("bootstrap_") && !bootstrap', 'row.condition.starts_with("bootstrap_") && bootstrap', limits),
        ("anonymous prot", "low(2, !3, 0), low(3, 0x2f, 0x22)", "low(2, 0, 0), low(3, 0x2f, 0x22)", memory),
        ("anonymous private", "low(3, 0x2f, 0x22)", "low(3, 0, 0)", memory),
        ("file read only", "low(2, !1, 0), low(3, 0x2f, 2)", "low(2, 0, 0), low(3, 0x2f, 2)", memory),
        ("file private", "low(3, 0x2f, 2)", "low(3, 0, 0)", memory),
        ("mmap prot high", "high(2, 0), high(3, 0), low(2, !3, 0)", "low(2, 0, 0), high(3, 0), low(2, !3, 0)", memory),
        ("mmap flags high", "high(2, 0), high(3, 0), low(2, !3, 0)", "high(2, 0), low(3, 0, 0), low(2, !3, 0)", memory),
        ("mprotect high", '"protect" => vec![vec![high(2, 0), low(2, !3, 0)]]', '"protect" => vec![vec![low(2, !3, 0)]]', memory),
        ("mprotect EXEC", '"protect" => vec![vec![high(2, 0), low(2, !3, 0)]]', '"protect" => vec![vec![high(2, 0)]]', memory),
    ]:
        add(name, FILTER, old, new, test)
    for bit in [3, 0x40, 0x200, 0x400, 0x400000]:
        add(f"open write bit {bit:#x}", FILTER,
            "const WRITE_OPEN: u32 = 3 | 0x40 | 0x200 | 0x400 | 0x40_0000;",
            f"const WRITE_OPEN: u32 = (3 | 0x40 | 0x200 | 0x400 | 0x40_0000) & !{bit};", write)
    for symbol in ["CREATE_RULESET_VERSION", "WRITE_FILE", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR",
                   "MAKE_DIR", "MAKE_REG", "MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE"]:
        line = next(s for s in (ROOT / LANDLOCK).read_text().splitlines() if s.startswith("const " + symbol + ":"))
        definition, comment = line.split(";", 1)
        add("UAPI " + symbol, LANDLOCK, line, definition + " ^ 1;" + comment,
            "landlock::tests::landlock_uapi_constants_and_layout_are_pinned")
    for name, old, new in [
        ("ruleset layout", "#[repr(C)]", "#[repr(C, align(16))]"),
        ("ABI2 rights", "if abi >= 2", "if abi >= 3"),
        ("ABI3 rights", "if abi >= 3", "if abi >= 4"),
        ("absence errno", "Some(38 | 95)", "Some(38 | 95 | 1)"),
        ("ABI zero", "if abi == 0", "if abi == u32::MAX"),
        ("restrict failure", "restrict(&fd)?;", "let _ = restrict(&fd);"),
    ]:
        add(name, LANDLOCK, old, new, "landlock::tests::landlock_uapi_constants_and_layout_are_pinned" if name=="ruleset layout" else "landlock::tests::landlock_abi_and_failure_matrix")
    add("startup seal stage", WORKER, "    final_filter()?;", "    let _ = final_filter;",
        "worker::tests::filter_installed_before_threads_and_ready", "bingsu-collect", True)
    # 이것을 실패시키는 것: 새 syscall 조건/handled set/counter 연결의 검사 제거.
    repository = "repository_rows_require_exact_arguments_and_handled_write_set"
    for old in ["eq(3, 24)", "high(3, 0)", "eq(2, 2)", "eq(3, 0x200)",
                "eq(0, 0), high(0, 0)", "eq(1, 0), high(1, 0)",
                "eq(1, 8)", "high(1, 0), eq(2, 0)", "eq(2, 1)"]:
        source = (ROOT / FILTER).read_text()
        section = source[source.index('"handled_write_set" =>'):source.index('"response" =>')]
        line = next(line for line in section.splitlines() if old in line)
        add("repository condition " + old, FILTER, line, line.replace(old, "low(0, 0, 0)", 1), repository)
    for kind, old in [("read_layer_add", "eq(1, 1), eq(3, 0)"), ("read_layer_restrict", "eq(1, 0)")]:
        add("repository " + kind, FILTER, f'"{kind}" => vec![vec![{old}]]', f'"{kind}" => vec![vec![]]', repository)
    add("openat2 deny mode", FILTER, 'mode == Openat2Policy::Deny', 'mode != Openat2Policy::Deny', repository)
    add("handled set not ABI", LANDLOCK, 'handled_access_fs & rights(3) == rights(3)', 'handled_access_fs != 0', repository)
    for axis, old in [("stats", 'self.charge_axis(Axis::Stats, 1)?;'),
                      ("bytes", 'self.charge_axis(Axis::WorktreeReadBytes, bytes as u64)?;'),
                      ("entries", 'self.charge_axis(Axis::WorktreeEntries, 1)?;')]:
        add("pure budget " + axis, Path("crates/bingsu-collect/src/meter.rs"), old, '',
            "meter::tests::pure_budget_precedes_io_across_phases", "safe_read")
    add("installed handled set", LANDLOCK, '        handled_access_fs,\n    })', '        handled_access_fs: rights(abi),\n    })',
        "landlock::tests::landlock_abi_and_failure_matrix")
    for old, new in [
        ('Ok(()) => Ok(Some(false))', 'Ok(()) => Ok(Some(true))'),
        ('Err(libc::ENOSYS | libc::EPERM) => Ok(None)', 'Err(libc::ENOSYS | libc::EPERM) => Ok(Some(false))'),
        ('Err(libc::EACCES | libc::EROFS) => Ok(Some(true))', 'Err(libc::EACCES | libc::EROFS) => Ok(Some(false))'),
        ('Err(error) => Err(ReadError::errno(error))', 'Err(error) => Err(ReadError::Denied)'),
    ]:
        add("readonly status " + old, Path("crates/bingsu-collect/src/safe_read/mod.rs"), old, new,
            "safe_read::tests::readonly_observation_preserves_unknown_and_errors", "safe_read")
    add("Linux floor", SYS, '(major, minor) >= (5, 9)', '(major, minor) >= (5, 8)',
        "sys::floor_tests::linux_collection_floor_requires_capabilities", "startup")
    if args.runtime:
        add("kernel seal omitted", FILTER, "install(&program(AuditArch::native(), mode))", "Ok(())",
            "runtime::filter_installed_before_threads_and_ready")
        add("writable inherited lock", SYS, "access(5, libc::O_RDONLY)?;", "let _ = 5;",
            "writable_lock_is_rejected_on_linux", "startup")
    if args.runtime:
        safe = Path("crates/bingsu-collect/src/safe_read/mod.rs")
        add("probe moved after layer", safe, '        resolver(meter)?;', '',
            "runtime::openat2_probe_precedes_read_layer")
        add("read layer omitted", LANDLOCK,
            'if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) } != 0 {',
            'if false {', "runtime::read_landlock_grants_only_selected_roots")
        add("read root count bound", LANDLOCK, 'roots.len() > 3', 'roots.len() > 4',
            "runtime::read_landlock_grants_only_selected_roots")
        add("duplicate read roots", LANDLOCK, '.any(|(_, dev, ino)| (*dev, *ino) == (stat.st_dev, stat.st_ino))',
            '.any(|(_, _, _)| false)', "runtime::read_landlock_grants_only_selected_roots")
        add("slash root allowed", LANDLOCK,
            '(stat.st_dev, stat.st_ino) == (slash.st_dev, slash.st_ino)', 'false',
            "runtime::read_landlock_grants_only_selected_roots")
        add("write layer omitted", LANDLOCK, '    restrict(&fd)?;', '    let _ = &restrict;',
            "runtime::openat2_never_bypasses_write_denial")
        add("cached resolver cleared", safe, '*self.0.get_or_init(|| linux::probe(meter))',
            'linux::probe(meter)', "runtime::resolver_is_selected_once_per_process")
        add("mount probe omitted", Path("crates/bingsu-collect/src/safe_read/linux.rs"),
            'identity(root.as_raw_fd(), meter)?;', '', "runtime::linux_collection_floor_requires_capabilities")
        add("read layer sample missing", Path("crates/bingsu-collect/tests/filter/runtime.rs"),
            'for _ in 0..=199', 'for _ in 0..=198', "runtime::repository_read_layer_cost_has_200_samples")
    report = ROOT / "target/b3-evidence/mutations.tsv"
    report.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="collector-mutations-", dir=report.parent) as saved:
        with report.open("w") as ledger:
            ledger.write("mutation\tanchor\tresult\n")
            for i, (name,path,old,new,test,target,binary) in enumerate(cases):
                source = ROOT / path
                backup = Path(saved) / str(i)
                shutil.copyfile(source,backup)
                text = source.read_text()
                assert text.count(old)==1, (name,"mutation anchor must be unique",text.count(old))
                try:
                    source.write_text(text.replace(old,new,1))
                    if target is None:
                        try:
                            check_identity_only()
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError((name, "identity-only library mutation survived"))
                    else:
                        result=run(test,target,binary)
                        assert result.returncode!=0 and "test result: FAILED." in result.stdout and "1 failed;" in result.stdout, (name,result.stdout,result.stderr)
                    ledger.write(f"{name}\t{test}\tKILLED\n")
                    ledger.flush()
                    print(f"KILLED {name}",flush=True)
                finally:
                    shutil.copyfile(backup,source)
                    assert source.read_bytes()==backup.read_bytes()
    check_identity_only()
    result=run()
    assert host_tests_passed(result),result.stdout+result.stderr
    print(f"mutations PASS: {len(cases)} killed; saved copies restored; host tests green")


def repository_trace():
    assert sys.platform == "linux", "BLOCKED: native Linux strace required"
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
    from fsbudget.repository import check_repository_trace
    build = subprocess.run(["cargo", "test", "--offline", "-j", "2", "-p", "bingsu-collect", "--test", "filter", "--no-run", "--message-format=json"], cwd=ROOT, capture_output=True, text=True, check=True)
    binary = next(v["executable"] for line in build.stdout.splitlines()
                  if (v := json.loads(line)).get("reason") == "compiler-artifact" and v.get("executable"))
    evidence = ROOT / "target/b3-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="b3-trace-") as directory:
        root = Path(directory)
        for name in ("worktree", "gitdir", "commondir"):
            (root / name).mkdir()
            (root / name / "HEAD").write_bytes(b"sentinel")
        for backend, case in [("openat2", "trace"), ("stepwise", "trace-stepwise")]:
            trace = evidence / f"repository-{backend}.strace"
            result = subprocess.run(["strace", "-f", "-yy", "-s", "4096", "-o", str(trace), binary,
                "--exact", "runtime::repository_child", "--ignored", "--nocapture", "--test-threads=1"],
                env={**os.environ, "BINGSU_B3_CASE": case, "BINGSU_B3_PATH": str(root), "BINGSU_REQUIRE_LANDLOCK": "1"},
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0 and f"B3 {case} PASS" in result.stdout, result.stdout + result.stderr
            counts = check_repository_trace(trace.read_text(), str(root), backend)
            (evidence / f"repository-{backend}.json").write_text(json.dumps(counts, indent=2))
            print(f"B3 repository trace {backend} PASS: {counts}")


if __name__ == "__main__":
    main()
