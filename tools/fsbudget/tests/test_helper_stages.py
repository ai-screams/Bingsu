"""Unit checks of the product helper stage formula and its vocabulary.

The live gate (tests/shell/test_prompt_env_paths.py::
test_live_helper_calls_match_stage_formula) compares release captures with
helper_stage_expected exactly; these tests pin the pieces it is built from.
"""
import pytest

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
    {"libc": "musl"}, {"stages": ("unchanged", "collect"), "breaker_bytes": 0}])
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


# 이것을 실패시키는 것: 마감을 넘긴 collector에도 발행 비용을 세거나, 발행 비용을 다른 단계 항으로 옮기는 것.
def test_collector_deadline_drops_only_the_publication():
    published = helper_stage_expected(plan(("unchanged", "collect")))
    missed = helper_stage_expected(plan(("unchanged", "collect"), collection_published=False))
    delta = {k: published[k] - missed[k] for k in published if published[k] != missed[k]}
    assert delta == {"chmod": 1, "fstat": 112, "openat": 5, "read": 4, "renameat": 2, "seek": 1,
                     "statfs": 38, "write": 1}


# 이것을 실패시키는 것: musl 차이를 NSS와 F_SETFD 밖(예: 걷기 원시 연산)으로 넓히는 것.
def test_musl_differs_in_nss_and_cloexec_fallbacks():
    gnu = helper_stage_expected(plan())
    musl = helper_stage_expected(plan(libc="musl", nsswitch_reads=0))
    delta = {k: musl.get(k, 0) - gnu.get(k, 0) for k in set(gnu) | set(musl) if musl.get(k, 0) != gnu.get(k, 0)}
    assert delta == {"network": -4, "fstat": -5, "openat": -1, "read": -2, "seek": -1, "fd_flags": 7}


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
    (call("umask", "077", "022"), None),
])
def test_helper_vocabulary(c, kind):
    assert helper_kind(c) == kind
