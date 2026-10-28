"""Unit checks of the product helper stage formula and its vocabulary.

The live gate (tests/shell/test_prompt_env_paths.py::
test_live_helper_calls_match_stage_formula) compares release captures with
the stage formula (collect: prefix exact, tail upper bound); these tests pin
the pieces it is built from.
"""
import pytest
from collections import Counter

from fsbudget.classify import helper_kind
from fsbudget.formula import (MAX_RW_COUNT, HelperAxes, HelperPlan, helper_stage_expected,
                              read_to_end_calls, verify_build_reads)
from fsbudget.strace_parse import Call


def plan(stages=("unchanged",), **change):
    fields = dict(stages=stages, ax=HelperAxes(F=1, P=6, L=0, R=3, D=0, M=0, B=[31]),
                  runtime_components=6, context_components=6, snapshot_bytes=19_647, marker_bytes=208,
                  buf=MAX_RW_COUNT, state_components=6, exe_link_components=5, exe_components=4,
                  nsswitch_reads=2, passwd_reads=1)
    if "collect" in stages:
        fields.update(collector_components=4, collector_bytes=1_249_936, catalog_bytes=723,
                      response_bytes=516, previous_bytes=516, breaker_bytes=284)
    fields.update(change)
    return HelperPlan(**fields)


def call(name, args, ret="0"):
    return Call(pid=1, name=name, args=args, ret=ret, index=0)


# 이것을 실패시키는 것: Rust read_to_end의 32바이트 probe·증가 규칙을 바꾸는 것. 값은 aarch64 release
# 캡처에서 잰 config.toml 읽기 횟수다(7·31바이트 2회, 43·44바이트 3회).
@pytest.mark.parametrize("size,calls", [(7, 2), (31, 2), (43, 3), (44, 3)])
def test_read_to_end_calls(size, calls):
    assert read_to_end_calls(size) == calls


# 이것을 실패시키는 것: verify_build의 48바이트 겹침을 빼는 것. 1,249,936바이트 collector는 캡처에서
# pread 20회였다; 1,375,297바이트는 collector.rs 루프를 따라 손으로 센 값(64 KiB + 65,488×20 + 1)이다.
def test_verify_build_reads():
    assert [verify_build_reads(n) for n in (65_537, 1_249_936, 1_375_297)] == [2, 20, 22]


# 이것을 실패시키는 것: 검토하지 않은 원본 모양(conf.d 목록, 링크, ACL, 상속 lock)이나 단계 조합을 받는 것.
@pytest.mark.parametrize("change", [
    {"stages": ("publish", "collect")}, {"stages": ("collect",)}, {"stages": ("unchanged", "failure-recover")},
    {"ax": HelperAxes(F=1, P=6, L=1, R=3, D=0, M=0, B=[31])}, {"ax": HelperAxes(F=1, P=6, L=0, R=3, D=1, M=0, B=[31])},
    {"ax": HelperAxes(F=1, P=6, L=0, R=3, D=0, M=0, B=[31], acl=True)}, {"buf": 4096}, {"libc": "bionic"},
    {"libc": "musl"}, {"arch": "riscv64"}, {"stages": ("unchanged", "collect"), "breaker_bytes": 0}])
def test_unreviewed_plans_are_refused(change):
    with pytest.raises(ValueError):
        helper_stage_expected(plan(**change))


# 이것을 실패시키는 것: runtime fsync를 0이 아닌 값으로 두거나 발행 단계의 snapshot·last-good 단계를 빼는 것.
def test_publish_adds_two_stagings_and_installs():
    unchanged, publish = helper_stage_expected(plan()), helper_stage_expected(plan(("publish",)))
    assert unchanged["fsync"] == publish["fsync"] == 0
    delta = {k: publish[k] - unchanged.get(k, 0) for k in publish if publish[k] != unchanged.get(k, 0)}
    # Two clocks, two stages (create, write, check, rewind, readback) and two large installs.
    assert delta == {"chmod": 2, "fstat": 32, "openat": 10, "read": 8, "readlink": 4, "renameat": 2,
                     "seek": 2, "statfs": 14, "write": 2}


# 이것을 실패시키는 것: musl 차이를 NSS와 F_SETFD 밖(예: 걷기 원시 연산)으로 넓히는 것.
def test_musl_differs_in_nss_and_cloexec_fallbacks():
    gnu = helper_stage_expected(plan())
    musl = helper_stage_expected(plan(libc="musl", nsswitch_reads=0))
    delta = {k: musl.get(k, 0) - gnu.get(k, 0) for k in set(gnu) | set(musl) if musl.get(k, 0) != gnu.get(k, 0)}
    assert delta == {"network": -4, "fstat": -5, "openat": -1, "read": -2, "seek": -1, "fd_flags": 7}


@pytest.mark.parametrize("libc,seeks", [("gnu", 2), ("musl", 0)])
@pytest.mark.parametrize("stages", [("unchanged",), ("publish",), ("failure-last-good",),
                                    ("failure-recover",), ("unchanged", "collect")])
def test_platform_stack_guard_is_exact_and_only_in_prefix(libc, seeks, stages):
    from dataclasses import replace
    from fsbudget.formula import helper_collect_expected
    arm = plan(stages, arch="aarch64", libc=libc, nsswitch_reads=0 if libc == "musl" else 2)
    x86 = replace(arm, arch="x86_64")
    a, x = Counter(helper_stage_expected(arm)), Counter(helper_stage_expected(x86))
    assert x == a + Counter(seek=seeks)
    if "collect" in stages:
        for deadline in (False, True):
            a = helper_collect_expected(arm, deadline=deadline)
            x = helper_collect_expected(x86, deadline=deadline)
            assert Counter(x["prefix"]) == Counter(a["prefix"]) + Counter(seek=seeks)
            assert x["supervisor"] == a["supervisor"]
            assert x["finish_gc"] == a["finish_gc"]


# 이것을 실패시키는 것: helper 어휘가 다른 모양까지 받아 넓어지는 것(경로 statx의 상대 경로, 파이프가 아닌
# 이름 없는 fd, "/"가 아닌 chdir), 또는 각 제품 모양을 다른 종류로 세는 것.
@pytest.mark.parametrize("c,kind", [
    (call("statx", '3</r/f>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mask=0}'), "fstat"),
    (call("statx", 'AT_FDCWD</>, "/r/config.local.toml", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, 0x1'), "fstat"),
    (call("statx", 'AT_FDCWD</>, "config.toml", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1'), "unknown-fs"),
    (call("statx", '3, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mask=0}'), "unknown-fs"),
    (call("mkdirat", '3</r>, "contexts-v2", 0700', "-1 EEXIST (File exists)"), "mkdir"),
    (call("mkdirat", 'AT_FDCWD</>, "/r/x", 0700'), "unknown-fs"),
    (call("fchmod", "21</r/.sequence.stage>, 0600"), "chmod"),
    (call("lseek", "21</r/.sequence.stage>, 0, SEEK_SET"), "seek"),
    (call("lseek", "21, 0, SEEK_SET"), "unknown-fs"),
    (call("fcntl", "9</r>, F_DUPFD_CLOEXEC, 3", "3</r>"), "dup"),
    (call("fcntl", "7</r/store>, F_GETFL"), "fd_query"),
    (call("fcntl", "7</r/store>, F_SETFD, FD_CLOEXEC"), "fd_flags"),
    (call("fcntl", "7</r/store>, F_SETFL, O_NONBLOCK"), "unknown-fs"),
    (call("fcntl", "40<pipe:[1]>, F_DUPFD_CLOEXEC, 3", "41<pipe:[1]>"), None),
    (call("chdir", '"/"'), "cwd"),
    (call("chdir", '"/r"'), "unknown-fs"),
    (call("umask", "077", "022"), "umask"),
])
def test_helper_vocabulary(c, kind):
    assert helper_kind(c) == kind


# Each pair is one operation on the same fixture object. Failed attempts count
# too. The permission operation's existing formula primitive uses held-fd fchmod.
LEGACY_EQUIVALENTS = [
    ("open", '"/r/f", O_RDONLY|O_CLOEXEC', "openat", 'AT_FDCWD, "/r/f", O_RDONLY|O_CLOEXEC', "openat"),
    ("creat", '"/r/f", 0600', "openat", 'AT_FDCWD, "/r/f", O_WRONLY|O_CREAT|O_TRUNC, 0600', "openat"),
    ("stat", '"/r/f", {}', "newfstatat", 'AT_FDCWD, "/r/f", {}, 0', "fstat"),
    ("lstat", '"/r/f", {}', "newfstatat", 'AT_FDCWD, "/r/f", {}, AT_SYMLINK_NOFOLLOW', "fstat"),
    ("fstat", '3</r/f>, {}', "statx", '3</r/f>, "", AT_EMPTY_PATH, STATX_ALL, {}', "fstat"),
    ("readlink", '"/r/f", "target", 4097', "readlinkat", '3</r>, "f", "target", 4097', "readlink"),
    ("mkdir", '"/r/d", 0700', "mkdirat", '3</r>, "d", 0700', "mkdir"),
    ("chmod", '"/r/f", 0600', "fchmod", '3</r/f>, 0600', "chmod"),
    ("unlink", '"/r/f"', "unlinkat", '3</r>, "f", 0', "unlinkat"),
    ("rmdir", '"/r/d"', "unlinkat", '3</r>, "d", AT_REMOVEDIR', "unlinkat"),
    ("rename", '"/r/a", "/r/b"', "renameat", '3</r>, "a", 3</r>, "b"', "renameat"),
    ("getdents", '3</r>, [], 32768', "getdents64", '3</r>, [], 32768', "getdents"),
]


# 이것을 실패시키는 것: 아키텍처별 이름만 다른 한 호출을 다른 kind로 세거나 실패한 호출을 버리는 것.
@pytest.mark.parametrize("legacy,args,modern,modern_args,expected", LEGACY_EQUIVALENTS)
@pytest.mark.parametrize("ret", ["0", "-1 EACCES (Permission denied)"])
def test_helper_legacy_equivalence(legacy, args, modern, modern_args, expected, ret):
    assert helper_kind(call(legacy, args, ret)) == expected
    assert helper_kind(call(modern, modern_args, ret)) == expected


# 이것을 실패시키는 것: helper alias를 다른 역할로 넓히거나 상대 경로까지 신뢰하는 것.
@pytest.mark.parametrize("name,args", [(n, a) for n, a, *_ in LEGACY_EQUIVALENTS
                                      if n in {"open", "creat", "stat", "lstat", "mkdir", "chmod", "rmdir"}])
def test_helper_legacy_scope(name, args):
    from fsbudget.classify import kind, collector_kind, collector_bootstrap_kind, collection_publication_kind
    c = call(name, args)
    for classify in (kind, collector_kind, collector_bootstrap_kind, collection_publication_kind):
        assert classify(c) == "unknown-fs"
    assert helper_kind(call(name, args.replace('"/r/', '"'))) == "unknown-fs"


# No helper formula operation covers these aliases; do not invent access,
# ownership, link-creation or timestamp budgets to make a trace pass.
@pytest.mark.parametrize("name,args", [
    ("access", '"/r/f", R_OK'), ("faccessat", 'AT_FDCWD, "/r/f", R_OK'),
    ("faccessat2", 'AT_FDCWD, "/r/f", R_OK, 0'),
    ("link", '"/r/a", "/r/b"'), ("symlink", '"/r/a", "/r/b"'),
    ("chown", '"/r/f", 1, 1'), ("lchown", '"/r/f", 1, 1'),
    ("mknod", '"/r/f", S_IFIFO|0600, 0'), ("utime", '"/r/f", NULL'),
    ("utimes", '"/r/f", NULL'), ("fchmodat", 'AT_FDCWD, "/r/f", 0600'),
])
def test_helper_unreviewed_legacy_operations_stay_unknown(name, args):
    assert helper_kind(call(name, args)) == "unknown-fs"


def legacy_trace_counts():
    from collections import Counter
    from pathlib import Path
    from fsbudget.strace_parse import parse
    # Handwritten ABI-equivalence fixture, not a new live x86_64 capture.
    trace = parse((Path(__file__).with_name("fixtures") / "m3d-x86_64-helper-legacy.strace").read_text())
    assert not trace.errors, trace.errors
    return trace, Counter(helper_kind(c) for c in trace)


# Independent ledger: twelve calls, including one unfinished/resumed unlink.
LEGACY_EXPECTED = {"openat": 2, "fstat": 3, "readlink": 1, "mkdir": 1,
                   "chmod": 1, "unlinkat": 2, "renameat": 1, "getdents": 1}


# 이것을 실패시키는 것: legacy 호출을 무시하거나 둘로 세거나 추가 호출을 exact가 허용하는 것.
@pytest.mark.parametrize("name", [row[0] for row in LEGACY_EQUIVALENTS])
def test_helper_legacy_stored_trace_extra_call_fails_exact(name):
    from collections import Counter
    from fsbudget.gate import check
    from fsbudget.strace_parse import parse
    trace, counts = legacy_trace_counts()
    assert sum(counts.values()) == len(trace) == 12
    assert check({"helper": counts}, {"helper": LEGACY_EXPECTED}, "exact", ["helper"]) == []
    extra = next(c for c in trace if c.name == name)
    damaged = parse("\n".join(f"{c.pid} {c.name}({c.args}) = {c.ret}" for c in [*trace, extra]))
    assert not damaged.errors, damaged.errors
    counts = Counter(helper_kind(c) for c in damaged)
    kind = helper_kind(extra)
    assert check({"helper": counts}, {"helper": LEGACY_EXPECTED}, "exact", ["helper"]) == [
        f"helper.{kind}: measured {counts[kind]}, formula {LEGACY_EXPECTED[kind]} (exact)"]


# 이것을 실패시키는 것: 매핑 삭제를 unknown-fs=0과 원래 kind의 exact가 검출하지 못하는 것.
@pytest.mark.parametrize("name", ["open", "creat", "stat", "lstat", "mkdir", "chmod", "rmdir"])
def test_helper_legacy_mapping_removal_fails_exact(monkeypatch, name):
    from fsbudget.classify import HELPER_LEGACY_PATH_KINDS
    from fsbudget.gate import check
    expected_kind = HELPER_LEGACY_PATH_KINDS[name]
    monkeypatch.delitem(HELPER_LEGACY_PATH_KINDS, name)
    _, counts = legacy_trace_counts()
    assert counts["unknown-fs"] == 1
    assert counts[expected_kind] == LEGACY_EXPECTED[expected_kind] - 1
    errors = check({"helper": counts}, {"helper": LEGACY_EXPECTED}, "exact", ["helper"])
    assert len(errors) == 2
    assert "helper.unknown-fs: measured 1, formula 0 (exact)" in errors


# 이것을 실패시키는 것: prefix/tail 분리가 기존 원시 연산 합계나 libc 차이를 넓히는 것.
@pytest.mark.parametrize("libc", ["gnu", "musl"])
def test_collect_partition_preserves_primitive_totals(libc):
    from collections import Counter
    from fsbudget.formula import helper_collect_expected, PRIMITIVES
    p = plan(("unchanged", "collect"), libc=libc, nsswitch_reads=2 if libc == "gnu" else 0)
    phases = helper_collect_expected(p)
    total = Counter()
    for counts in phases.values():
        total.update(counts)
    assert total == Counter(helper_stage_expected(p))
    deadline = helper_collect_expected(p, deadline=True)
    assert deadline["prefix"] == phases["prefix"]
    assert deadline["finish_gc"] == phases["finish_gc"]
    assert deadline["supervisor"] == PRIMITIVES["clock"]
