#!/usr/bin/env python3
"""Check identity-only library isolation, collector table, BPF evaluator and probes.

--mutations changes one rule/condition at a time and restores saved bytes even
on failure. Compilation errors do not count as killed mutations. Runtime-only
mutations additionally require --runtime on a native Linux host.
"""
import argparse
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
        r"^test result: ok\. 8 passed; 0 failed; 0 ignored; 0 measured; "
        r"\d+ filtered out; finished in \d+\.\d+s$", result.stdout, re.MULTILINE) is not None


def run(test=None, target="filter", binary=False):
    command = ["cargo", "test", "--offline", "-j", "2", "-p", "bingsu-collect",
               "--bin" if binary else "--test", target]
    if test:
        command += [test, "--", "--exact", "--test-threads=2"]
    else:
        command += ["--", "--skip", "runtime::", "--test-threads=2"]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--runtime", action="store_true")
    args = parser.parse_args()
    check_identity_only()
    rows = list(csv.DictReader((line for line in (ROOT / TABLE).read_text().splitlines()
                              if not line.startswith("#")), delimiter="\t"))
    assert len(rows) == 45 and len({r["probe"] for r in rows}) == len(rows)
    assert all(r["why"].strip() and r["probe"] == f'row_{r["syscall"]}_{r["condition"]}' for r in rows)
    result = run()
    assert host_tests_passed(result), result.stdout + result.stderr
    print("collector identity/table/program/probes PASS: identity-only lib, 45 rows, both ABIs, 8 host tests")
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
        ("clone high word", "high(0, 0),", "low(0, 0, 0),", clone),
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
    if args.runtime:
        add("kernel seal omitted", SYS, "crate::filter::seal_limits()", "Ok(())",
            "runtime::filter_installed_before_threads_and_ready")
        add("writable inherited lock", SYS, "access(5, libc::O_RDONLY)?;", "let _ = 5;",
            "writable_lock_is_rejected_on_linux", "startup")
    report = ROOT / "target/b2-mutations.tsv"
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


if __name__ == "__main__":
    main()
