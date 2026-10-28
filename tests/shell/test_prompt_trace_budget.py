"""Portable regression/mutation fixtures for the Linux strace gate."""
from pathlib import Path
from collections import Counter
import hashlib

import pytest

import test_prompt_env_paths as budget
from test_prompt_env_paths import assert_historical_prompt_trace_budget as assert_prompt_trace_budget

EXE = "/pinned/bin/bingsu"
ROOTS = ["/pinned/run", "/pinned/config", "/pinned/state"]


COLLECT_BASE = "/home/tester/pt/test_prompt_binary_names_only_1"
COLLECT_PIN = "/home/tester/target/release/bingsu-collect"


def collecting_prompt():
    """A release prompt whose helper started and supervised one collecting
    collector (global-missing, warm snapshot). read/write payloads are cut to
    120 characters; provenance: fixtures/prompt-m3d-collect-trace.md."""
    import gzip
    data = gzip.decompress(Path(__file__).with_name("fixtures").joinpath(
        "prompt-m3d-collect-linux-1.strace.gz").read_bytes())
    assert hashlib.sha256(data).hexdigest() == "18c030e2e135874a418bc047bc6f0dbe731f5821b2bcd9663afefbd3632c8fab"
    return data.decode().splitlines()


def check_collecting_prompt(lines, *, collectors=1, audit=True):
    roots = [COLLECT_BASE + suffix for suffix in ("/run-t/bingsu", "/cfg-t/bingsu", "/state-t/bingsu", "/state-t/bingsu/log")]
    inputs = tuple(COLLECT_BASE + suffix for suffix in ("/cfg-t/git/config", "/home-t/.gitconfig", "/cfg-t/git/ignore"))
    repo = COLLECT_BASE + "/repo"
    budget.assert_prompt_trace_budget(lines, COLLECT_BASE + "/bin/bingsu", roots, global_inputs=inputs,
                                      collector_exe=COLLECT_PIN, collectors=collectors,
                                      repository_roots=[repo, repo + "/.git"] if audit else None,
                                      repository_evidence=[repo + "/.git/HEAD"])


def insert_after(lines, pattern, extra):
    at = next(i for i, line in enumerate(lines) if pattern in line)
    return lines[:at + 1] + extra + lines[at + 1:]


def test_collecting_prompt_passes_the_path_allowlist():
    check_collecting_prompt(collecting_prompt())
    # A thread's interrupted futex wait can resume under strace (seen live once).
    # 이것을 실패시키는 것: helper 경로 표가 restart_syscall의 빈 인자를 해석하려는 것.
    check_collecting_prompt(insert_after(collecting_prompt(), "1099  waitid(P_PIDFD, 33<anon_inode:[pidfd]>",
                                         ["1099  restart_syscall(<... resuming interrupted futex ...>) = 0"]))
    # The supervisor's SIGKILL of its own child on a deadline is the one allowed signal.
    check_collecting_prompt(insert_after(collecting_prompt(), "1099  waitid(P_PIDFD, 33<anon_inode:[pidfd]>",
                                         ["1099  pidfd_send_signal(33<anon_inode:[pidfd]>, SIGKILL, NULL, 0) = 0"]))


# 이것을 실패시키는 것: collector 수를 정확히 보지 않는 것, 수집하는 collector를 감사 없이 통과시키는 것,
# collector가 요청 뒤 roots 밖을 여는 것, collector bootstrap의 읽기를 저장소 감사로 넘기는 것, futex 아닌 restart를 건너뛰는 것, readv(3)로 위임한 뒤 감사 창을 늦게 여는 것, 시험 저장소의 HEAD를 읽은 증거 없이 통과시키는 것, pidfd 아닌 waitid·SIGKILL 아닌 신호·둘째 pidfd_open을 허용하는 것.
@pytest.mark.parametrize("damage", ["count-zero", "no-audit", "collector-outside-open", "waitid-by-pid",
                                    "signal-sigterm", "second-pidfd-open", "collector-bootstrap-read", "restart-other", "readv-handoff", "empty-head-read"])
def test_collecting_prompt_rejects_mutations(damage):
    lines, collectors, audit = collecting_prompt(), 1, True
    if damage == "count-zero":
        collectors = 0
    elif damage == "no-audit":
        audit = False
    elif damage == "collector-outside-open":
        walk = next(i for i, line in enumerate(lines)
                    if line.startswith("1098  openat(AT_FDCWD</>, \"/\", O_RDONLY|O_NONBLOCK|O_NOFOLLOW"))
        at = next(i for i in range(walk, len(lines)) if lines[i].startswith("1098") and lines[i].endswith("= 4</>"))
        lines = lines[:at + 1] + ['1098  openat(AT_FDCWD</>, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 40</etc/hostname>',
                                  '1098  close(40</etc/hostname>) = 0'] + lines[at + 1:]
    elif damage == "waitid-by-pid":
        lines = [line.replace("1099  waitid(P_PIDFD, 33<anon_inode:[pidfd]>", "1099  waitid(P_PID, 1098") for line in lines]
    elif damage == "signal-sigterm":
        lines = insert_after(lines, "1099  waitid(P_PIDFD, 33<anon_inode:[pidfd]>",
                             ["1099  pidfd_send_signal(33<anon_inode:[pidfd]>, SIGTERM, NULL, 0) = 0"])
    elif damage == "second-pidfd-open":
        lines = insert_after(lines, "1096  pidfd_open(1098, 0)", ["1096  pidfd_open(1098, 0) = 34<anon_inode:[pidfd]>"])
    elif damage == "collector-bootstrap-read":
        ready = next(i for i, line in enumerate(lines) if line.startswith("1098  write(1<pipe:"))
        lines = lines[:ready] + ['1098  openat(AT_FDCWD</>, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 40</etc/hostname>',
                                 '1098  close(40</etc/hostname>) = 0'] + lines[ready:]
    elif damage == "readv-handoff":
        at = next(i for i, line in enumerate(lines) if line.startswith("1098  read(3<pipe:"))
        lines = lines[:at] + [f'1098  readv({lines[at].split("(", 1)[1].split(",")[0]}, [{{iov_base="", iov_len=1}}], 1) = 0',
                              '1098  openat(AT_FDCWD</>, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 40</etc/hostname>',
                              '1098  read(40</etc/hostname>, "x\\n", 64) = 2',
                              '1098  close(40</etc/hostname>) = 0'] + lines[at:]
    elif damage == "empty-head-read":
        lines = [line.replace('"ref: refs/heads/main\\n", 22) = 21', '"", 22) = 0') for line in lines]
        assert lines != collecting_prompt()
    elif damage == "restart-other":
        lines = insert_after(lines, "1099  waitid(P_PIDFD, 33<anon_inode:[pidfd]>",
                             ["1099  restart_syscall(<... resuming interrupted read ...>) = 0"])
    with pytest.raises(AssertionError):
        check_collecting_prompt(lines, collectors=collectors, audit=audit)


# prompt 트리의 read 계열 payload만 줄였다. provenance: fixtures/prompt-e4-trace.md.
# 컨테이너 경로는 문자열 인자로만 전달하며,
# macOS의 realpath/stat 또는 현재 빌드 위치로 바꾸지 않는다.
@pytest.mark.parametrize("capture,base,digest", [
    (0, "/home/tester/pt/test_prompt_binary_names_only_0",
     "66caaeed9d79a542f5d6837581e96cc9e00f907d996a9220c5709ad48108e684"),
    (1, "/home/tester/pt/test_prompt_binary_names_only_1",
     "4dde46365d2758ba745a656fa7d116603513d4858cde4c65e0b470d4e5f9c34c"),
])
def test_real_e4_linux_fd_contract(capture, base, digest):
    data = Path(__file__).with_name("fixtures").joinpath(
        f"prompt-e4-linux-{capture}.strace").read_bytes()
    assert len(data) < 600_000
    assert hashlib.sha256(data).hexdigest() == digest
    lines = data.decode().splitlines()
    exe = base + "/bin/bingsu"
    collector = "/home/tester/target/debug/bingsu-collect"
    roots = [base + suffix for suffix in (
        "/run-t/bingsu", "/cfg-t/bingsu", "/state-t/bingsu", "/state-t/bingsu/log",
    )]
    inputs = tuple(base + suffix for suffix in (
        "/cfg-t/git/config", "/home-t/.gitconfig", "/cfg-t/git/ignore",
    ))
    budget.assert_prompt_trace_budget(lines, exe, roots, global_inputs=inputs,
                                      collector_exe=collector)
    _, scoped = budget.tree(lines, exe)
    calls = budget.parse_trace("\n".join(scoped))
    assert not calls.errors, calls.errors
    inventory = {path: Counter() for path in (collector, *inputs)}
    for call in calls:
        args = budget.args_of(call)
        if not args:
            continue
        # 모든 대상 fd 인자와 open/부모 기준 이름 조회를 집계한다.
        paths = set(budget.call_paths(call)) | {
            path for path in inventory if any(f"<{path}>" in arg for arg in args)
        }
        for path in paths & inventory.keys():
            shape = call.name
            if call.name in {"read", "pread64"}:
                shape += ":" + args[2]
            elif call.name == "newfstatat":
                shape += ":" + args[3]
            elif call.name == "statx":
                shape += ":" + args[2] + ":" + args[3]
            elif call.name == "fcntl":
                shape += ":" + ",".join(args[1:])
            elif call.name == "openat":
                shape += ":" + args[2]
            inventory[path][shape] += 1
    if capture == 0:
        assert inventory[collector] == Counter({
            "openat:O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC": 1,
            "newfstatat:AT_EMPTY_PATH": 2, "newfstatat:AT_SYMLINK_NOFOLLOW": 1,
            "statx:AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH:STATX_ALL": 4,
            "fstatfs": 1, "pread64:65536": 1, "pread64:65488": 873,
            "fcntl:F_GETFD": 1, "close": 1,
        })
        for path in inputs:
            assert inventory[path] == Counter({
                "openat:O_RDONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC": 1,
            })
        budget.assert_global_inputs_exercised(lines, exe, inputs, False)
        # 축소한 실제 trace에서도 열린 collector fd의 변경/복제/마스크 확대는 거부한다.
        read = next(c for c in calls if c.name == "pread64" and collector in c.args)
        fd = budget.args_of(read)[0]
        at = next(i for i, line in enumerate(lines) if f"pread64({fd}," in line)
        for operation in (
            f'write({fd}, "x", 1) = 1',
            f'fcntl({fd}, F_SETFD, 0) = 0',
            f'dup({fd}) = 60<{collector}>',
            f'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, '
            'STATX_ALL|STATX_MNT_ID, {}) = 0',
        ):
            mutated = lines[:at] + [f"{read.pid} {operation}"] + lines[at:]
            with pytest.raises(AssertionError):
                budget.assert_prompt_trace_budget(mutated, exe, roots, global_inputs=inputs,
                                                  collector_exe=collector)
    else:
        # _1은 helper exit_group(1) 전에 대상 파일에 도달하지 않았다.
        # 경로 게이트 통과를 전역 입력의 성공 읽기 증거로 오인하면 실패한다.
        assert all(not counts for counts in inventory.values())
        assert any(c.name == "exit_group" and c.args == "1" for c in calls)
        with pytest.raises(AssertionError, match="global input opens missing"):
            budget.assert_global_inputs_exercised(lines, exe, inputs, True)


@pytest.fixture(scope="module")
def debian_trace():
    """Real strace -f -q -y -s 65536 -e trace=all, Debian bookworm glibc aarch64.

    Captured as non-root tester by the binary-path test (target/linux-trace/trace2.txt),
    after the state-root fix, with a fresh state home.
    USER/CASE/SOURCE/TRACE_HOST replace machine paths/host; encoded context path
    components are normalized too, preserving their observed chunk boundaries.
    All 3012 records, including shell setup, are retained. The historical
    legacy verb is projected to its current spelling before validation. The helper creates
    state-t/bingsu with 0700, executes the pinned __collect-legacy-v1, revalidates
    config absence and publishes snapshot/marker; both processes exit with 0.
    """
    return Path(__file__).with_name("fixtures").joinpath(
        "prompt-debian-bookworm-glibc-aarch64.strace"
    ).read_text().replace("__collect-v1", "__collect-legacy-v1").splitlines()


DEBIAN_BASE = "/home/USER/pt/CASE"
DEBIAN_EXE = DEBIAN_BASE + "/bin/bingsu"
DEBIAN_ROOTS = [DEBIAN_BASE + suffix for suffix in (
    "/run-t/bingsu", "/cfg-t/bingsu", "/state-t/bingsu", "/state-t/bingsu/log",
)]


# 이것을 실패시키는 것: 현재 제품 collector 허용이 과거 고정 stub 실행까지 허용하는 것.
def test_product_trace_rejects_the_historical_collector(debian_trace):
    with pytest.raises(AssertionError):
        budget.assert_prompt_trace_budget(debian_trace, DEBIAN_EXE, DEBIAN_ROOTS)


def test_real_debian_prompt_trace(debian_trace):
    assert_prompt_trace_budget(debian_trace, DEBIAN_EXE, DEBIAN_ROOTS)
    pids, scoped = budget.tree(debian_trace, DEBIAN_EXE)
    assert pids == {"1947", "1948", "1949", "1950", "1951"}
    calls = budget.parse_trace("\n".join(scoped))
    assert len(debian_trace) == 3012
    assert len(calls) == 2338
    # Guard against accidentally restoring the old pre-publication capture.
    for path in (DEBIAN_BASE + "/state-t", DEBIAN_ROOTS[2]):
        assert any(c.pid == 1948 and c.name == "mkdirat" and c.ret == "0"
                   and budget.call_paths(c) == [path] and budget.args_of(c)[2] == "0700"
                   for c in calls)
    assert any(c.pid == 1950 and budget.fixed_exec(c, DEBIAN_EXE, "__collect-legacy-v1")
               for c in calls if c.name == "execve")
    for stage, final in ((".snapshot.stage", "snapshot"), (".marker.stage", "marker")):
        assert any(c.pid == 1948 and c.name == "renameat" and c.ret == "0"
                   and budget.args_of(c)[1] == f'"{stage}"'
                   and budget.args_of(c)[3] == f'"{final}"' for c in calls)
    assert {c.pid for c in calls if c.name == budget.EXIT_EVENT and c.args == "exited with 0"} == set(map(int, pids))


H2_BASE = "/home/USER/pt/CASE_BUILD_IDENTITY_TRACE_0000000"
H2_EXE = H2_BASE + "/bin/bingsu"
H2_ROOTS = [H2_BASE + suffix for suffix in (
    "/run-t/bingsu", "/cfg-t/bingsu", "/state-t/bingsu", "/state-t/bingsu/log",
)]
H2_TARGET = "/home/USER/target/debug/bingsu"


@pytest.fixture(scope="module")
def h2_trace():
    """c4da804 capture with the legacy verb renamed; see fixtures/prompt-h2-trace.md."""
    return Path(__file__).with_name("fixtures").joinpath(
        "prompt-h2-debian-bookworm-glibc-aarch64.strace"
    ).read_text().replace("__collect-v1", "__collect-legacy-v1").splitlines()


def test_real_h2_build_identity_trace(h2_trace):
    assert_prompt_trace_budget(h2_trace, H2_EXE, H2_ROOTS)
    pids, scoped = budget.tree(h2_trace, H2_EXE)
    calls = budget.parse_trace("\n".join(scoped))
    assert pids == {"1169", "1170", "1171", "1172", "1173"}
    assert len(h2_trace) == 3566
    assert len(calls) == 2547
    links = [c for c in calls if c.name == "readlinkat" and budget.call_paths(c) == [H2_EXE]]
    assert len(links) == 2  # Initial resolution and retained-link revalidation.
    assert all(budget.args_of(c)[2] == f'"{H2_TARGET}"' for c in links)
    assert any(c.name == "openat" and budget.call_paths(c) == [H2_TARGET] for c in calls)
    assert not any(H2_TARGET in budget.content_paths(c) for c in calls)
    assert {c.pid for c in calls if c.name == budget.EXIT_EVENT and c.args == "exited with 0"} == set(map(int, pids))


@pytest.mark.parametrize("extra", [
    f'readlinkat(8<{H2_BASE}/bin>, "other", "/elsewhere", 4097) = 10',
    'readlinkat(12</home/USER/target/debug>, "other", "/elsewhere", 4097) = 10',
    'read(12</home/USER/target/debug>, "contents", 8) = 8',
    'getdents64(12</home/USER/target/debug>, [], 4096) = 0',
    'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 12</home/USER/target/debug>, 0) = 0x1',
    f'read(13<{H2_TARGET}>, "contents", 8) = 8',
    f'read(8<{H2_EXE}>, "contents", 8) = 8',
    'openat(12</home/USER/target/debug>, "other", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK|O_NOCTTY) = 99',
    'newfstatat(12</home/USER/target/debug>, "other", {}, AT_SYMLINK_NOFOLLOW) = 0',
    f'fstat(99<{H2_TARGET}>, {{}}) = 0',
])
def test_real_h2_rejects_executable_walk_expansion(h2_trace, extra):
    # Both the original link parent and the target parent are still held here;
    # unrelated links must fail by scope, not merely because their fd closed.
    lines = list(h2_trace)
    at = next(i for i, line in enumerate(lines)
              if '1170  openat(12</home/USER/target/debug>, "bingsu",' in line)
    lines.insert(at, "1170 " + extra)
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(lines, H2_EXE, H2_ROOTS)


@pytest.mark.parametrize("allowance", ["readlink", "file_op", "fd_stat"])
def test_real_h2_needs_each_executable_allowance(h2_trace, monkeypatch, allowance):
    monkeypatch.setattr(budget.HelperExecutableWalk, allowance, lambda *args: False)
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(h2_trace, H2_EXE, H2_ROOTS)


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"])
def test_real_h2_requires_final_open_flags(h2_trace, flag):
    changed = [line.replace("|" + flag, "")
               if 'openat(12</home/USER/target/debug>, "bingsu",' in line else line
               for line in h2_trace]
    assert changed != h2_trace
    with pytest.raises(AssertionError, match="helper executable path"):
        assert_prompt_trace_budget(changed, H2_EXE, H2_ROOTS)


@pytest.mark.parametrize("flag", ["O_PATH", "O_NOFOLLOW", "O_DIRECTORY"])
def test_real_h2_requires_target_ancestor_walk_flags(h2_trace, flag):
    changed = [line.replace("|" + flag, "")
               if 'openat(11</home/USER/target>, "debug",' in line else line
               for line in h2_trace]
    assert changed != h2_trace
    with pytest.raises(AssertionError, match="helper path"):
        assert_prompt_trace_budget(changed, H2_EXE, H2_ROOTS)


def test_real_h2_requires_nofollow_target_ancestor_metadata(h2_trace):
    lines = list(h2_trace)
    at = next(i for i, line in enumerate(lines)
              if '1170  openat(11</home/USER/target>, "debug",' in line)
    lines.insert(at, '1170 newfstatat(11</home/USER/target>, "debug", {}, 0) = 0')
    with pytest.raises(AssertionError, match="helper path"):
        assert_prompt_trace_budget(lines, H2_EXE, H2_ROOTS)


# 이것을 실패시키는 것: glibc에서 실제로 관측한 각 runtime 호출의 허용을 제거하는 것.
@pytest.mark.parametrize("table,name", [
    ("ROOT_CALLS", "sched_getaffinity"),
    ("ROOT_CALLS", "gettid"),
    ("HELPER_CALLS", "sched_getaffinity"),
    ("HELPER_CALLS", "gettid"),
])
def test_real_trace_needs_each_runtime_allowance(debian_trace, monkeypatch, table, name):
    monkeypatch.setattr(budget, table, getattr(budget, table) - {name})
    with pytest.raises(AssertionError, match=name):
        assert_prompt_trace_budget(debian_trace, DEBIAN_EXE, DEBIAN_ROOTS)


# 이것을 실패시키는 것: 실제 trace의 메타데이터·순회·생성 허용을 하나라도 제거하는 것.
@pytest.mark.parametrize("allowance", [
    "helper_nss_root_stat", "helper_walk_step", "helper_ancestor_stat",
    "helper_chain_stat", "helper_mkdir_step", "helper_created_open",
])
def test_real_trace_needs_each_helper_path_allowance(debian_trace, monkeypatch, allowance):
    monkeypatch.setattr(budget, allowance, lambda *args: False)
    with pytest.raises(AssertionError, match="helper mkdir" if allowance == "helper_mkdir_step" else "helper path"):
        assert_prompt_trace_budget(debian_trace, DEBIAN_EXE, DEBIAN_ROOTS)


def test_real_trace_needs_collector_exec_allowance(debian_trace, monkeypatch):
    original = budget.fixed_exec
    monkeypatch.setattr(budget, "fixed_exec", lambda call, exe, verb:
                        verb != "__collect-legacy-v1" and original(call, exe, verb))
    with pytest.raises(AssertionError, match="execve"):
        assert_prompt_trace_budget(debian_trace, DEBIAN_EXE, DEBIAN_ROOTS)


def test_real_trace_rejects_followed_missing_ancestor(debian_trace):
    lines = [line.replace("|AT_SYMLINK_NOFOLLOW", "")
             if f'"{DEBIAN_BASE}/cfg-t",' in line and "statx(" in line else line
             for line in debian_trace]
    assert lines != debian_trace
    with pytest.raises(AssertionError, match="helper path"):
        assert_prompt_trace_budget(lines, DEBIAN_EXE, DEBIAN_ROOTS)


# glibc/Rust의 lstat 구현별로 pinned root 조상의 메타데이터만 허용한다.
@pytest.mark.parametrize("suffix", ["/run-t", "/cfg-t", "/state-t", "/"])
@pytest.mark.parametrize("lookup", [
    'lstat("{path}", {{}})',
    'newfstatat(AT_FDCWD</>, "{path}", {{}}, AT_SYMLINK_NOFOLLOW)',
    'statx(AT_FDCWD</>, "{path}", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, {{}})',
])
def test_real_trace_allows_only_nofollow_ancestor_metadata(debian_trace, suffix, lookup):
    path = "/" if suffix == "/" else DEBIAN_BASE + suffix
    extra = "1948 " + lookup.format(path=path) + " = -1 ENOENT (No such file or directory)"
    assert_prompt_trace_budget(debian_trace + [extra], DEBIAN_EXE, DEBIAN_ROOTS)


# 이것을 실패시키는 것: 새 metadata 허용이 link 추적·다른 경로·내용 접근으로 넓어지는 것.
@pytest.mark.parametrize("operation", [
    'stat("{path}", {{}})',  # stat has no no-follow mode
    'newfstatat(AT_FDCWD</>, "{path}", {{}}, 0)',
    'statx(AT_FDCWD</>, "{path}", AT_STATX_SYNC_AS_STAT, STATX_ALL, {{}})',
    'lstat("{path}-other", {{}})',
    'lstat("{path}/../cfg-t", {{}})',
    'statx(AT_FDCWD</>, "{path}", AT_EMPTY_PATH, STATX_ALL, {{}})',
    'openat(AT_FDCWD</>, "{path}", O_RDONLY|O_NOFOLLOW|O_DIRECTORY)',
    'read(3<{path}>, "contents", 8)',
    'getdents64(3<{path}>, [], 4096)',
    'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3<{path}>, 0)',
])
def test_real_trace_rejects_expanded_ancestor_metadata(debian_trace, operation):
    extra = "1948 " + operation.format(path=DEBIAN_BASE + "/cfg-t") + " = 0"
    with pytest.raises(AssertionError, match="helper path"):
        assert_prompt_trace_budget(debian_trace + [extra], DEBIAN_EXE, DEBIAN_ROOTS)


# 이것을 실패시키는 것: ancestor 순회의 search-only/no-follow/directory 플래그를 빼도 통과하는 것.
@pytest.mark.parametrize("flag", ["O_PATH", "O_NOFOLLOW", "O_DIRECTORY"])
def test_real_trace_rejects_readable_or_followed_ancestor(debian_trace, flag):
    lines = [line.replace("|" + flag, "") if 'openat(AT_FDCWD</>, "/",' in line else line
             for line in debian_trace]
    assert lines != debian_trace
    with pytest.raises(AssertionError, match="helper path"):
        assert_prompt_trace_budget(lines, DEBIAN_EXE, DEBIAN_ROOTS)


# 이것을 실패시키는 것: NSS stat을 다른 경로/호출로 넓히거나, ancestor 내용 읽기·임의 경로·추가 spawn을 허용하는 것.
@pytest.mark.parametrize("extra,error", [
    ('1948 newfstatat(AT_FDCWD</>, "/home", {}, 0) = 0', "helper path"),
    ('1948 newfstatat(AT_FDCWD</>, "/", {}, AT_NO_AUTOMOUNT) = 0', "helper path"),
    ('1948 newfstatat(AT_FDCWD</>, "/repo/..", {}, 0) = 0', "helper path"),
    ('1948 statx(AT_FDCWD</>, "/", 0, STATX_ALL, {}) = 0', "helper path"),
    ('1948 openat(AT_FDCWD</>, "/", O_RDONLY|O_DIRECTORY) = 3</>', "helper path"),
    ('1948 openat(3</>, "opt", O_RDONLY|O_PATH|O_NOFOLLOW|O_DIRECTORY) = 4</opt>', "helper path"),
    ('1948 openat(AT_FDCWD</>, "/home", O_PATH|O_NOFOLLOW|O_DIRECTORY) = 3</home>', "helper path"),
    ('1948 openat(3</>, "home", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CREAT) = 4</home>', "helper path"),
    ('1948 read(3</home>, "contents", 8) = 8', "helper path"),
    ('1948 getdents64(3</>, [], 4096) = 0', "helper path"),
    ('1948 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3</home>, 0) = 0x1', "helper path"),
    ('1948 read(3</repo/secret>, "contents", 8) = 8', "helper path"),
    ('1948 openat(AT_FDCWD</>, "/repo/secret", O_RDONLY) = 3</repo/secret>', "helper path"),
    ('1948 openat(3</proc/999/ns>, "time", O_RDONLY) = 4', "helper path"),
    ('1950 lstat("/repo/secret", {}) = 0', "helper path"),
    (f'1950 openat(AT_FDCWD</>, "{DEBIAN_BASE}/cfg-t", O_RDONLY|O_NOFOLLOW|O_DIRECTORY) = 3', "helper path"),
    ('1947 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 2000', "exactly one prompt spawn"),
])
def test_real_trace_rejects_expanded_allowances(debian_trace, extra, error):
    with pytest.raises(AssertionError, match=error):
        assert_prompt_trace_budget(debian_trace + [extra], DEBIAN_EXE, DEBIAN_ROOTS)


def valid_trace():
    return [
        '10 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "prompt"], 0x1 /* 2 vars */) = 0',
        '10 openat(AT_FDCWD, "/proc/self/fd", O_RDONLY|O_DIRECTORY) = 3</proc/10/fd>',
        '10 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88) = -1 ENOSYS (Function not implemented)',
        '10 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
        '11 openat(AT_FDCWD, "/dev/null", O_RDWR) = 0</dev/null>',
        '11 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "__refresh-v1", "--ctx", "1"], 0x2 /* 0 vars */) = 0',
        '10 <... clone resumed>) = 11',
        '10 openat(AT_FDCWD, "/", O_RDONLY|O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 20</>',
        '10 openat(20</>, "proc", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 21</proc>',
        '10 openat(21</proc>, "10", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 22</proc/10>',
        '10 openat(22</proc/10>, "ns", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 23</proc/10/ns>',
        '10 fstatfs(23</proc/10/ns>, {f_type=PROC_SUPER_MAGIC}) = 0',
        '10 readlinkat(23</proc/10/ns>, "time", "time:[4026531834]", 28) = 17',
        '10 readlinkat(23</proc/10/ns>, "time_for_children", "time:[4026531834]", 28) = 17',
        '10 close(23</proc/10/ns>) = 0',
        '10 close(22</proc/10>) = 0',
        '10 close(21</proc>) = 0',
        '10 close(20</>) = 0',
        '10 prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=42, filter=0x1}) = 0',
        '10 write(1</dev/null>, "B1\\37...", 16) = 16',
        '10 exit_group(0) = ?',
        '10 +++ exited with 0 +++',
        '11 chdir("/") = 0',
        '11 prlimit64(0, RLIMIT_CORE, {rlim_cur=0, rlim_max=0}, NULL) = 0',
        '11 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = 12',
        '12 prctl(PR_SET_NAME, "refresh-watchdo") = 0',
        '12 futex(0x1, FUTEX_WAIT_BITSET_PRIVATE, 0, {tv_sec=2, tv_nsec=0}, FUTEX_BITSET_MATCH_ANY <unfinished ...>',
        '11 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3</etc/passwd>',
        '11 openat(AT_FDCWD, "/proc/self/statm", O_RDONLY) = 3</proc/11/statm>',
        '11 openat(AT_FDCWD, "/proc/self", O_RDONLY|O_DIRECTORY) = 8</proc/11>',
        '11 openat(8</proc/11>, "ns", O_RDONLY|O_DIRECTORY) = 9</proc/11/ns>',
        '11 readlinkat(9</proc/11/ns>, "time", "time:[4026531834]", 28) = 17',
        '11 readlinkat(9</proc/11/ns>, "time_for_children", "time:[4026531834]", 28) = 17',
        '11 openat(AT_FDCWD, "/proc/sys/kernel/random/boot_id", O_RDONLY) = 3</proc/sys/kernel/random/boot_id>',
        '11 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3<UNIX-STREAM:[1]>',
        '11 connect(3<UNIX-STREAM:[1]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)',
        # R1 state/log creation and final held-chain metadata recheck.
        '11 mkdirat(3</pinned>, "state", 0700) = 0',
        '11 openat(3</pinned>, "state", O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 6</pinned/state>',
        '11 mkdirat(6</pinned/state>, "log", 0700) = 0',
        '11 newfstatat(3</>, "pinned", {}, AT_SYMLINK_NOFOLLOW) = 0',
        '11 openat(4</pinned/run>, "snapshot", O_RDONLY <unfinished ...>',
        '11 <... openat resumed>) = 5</pinned/run/snapshot>',
        '11 read(5</pinned/run/snapshot>, "not a pathname", 64) = 14',
        '11 renameat(4</pinned/run>, ".stage", 4</pinned/run>, "marker") = 0',
        '11 clone(child_stack=0x2, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 13',
        '13 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "__collect-legacy-v1"], []) = 0',
        '13 openat(4</pinned/run>, "collection.lock", O_RDONLY) = 6</pinned/run/collection.lock>',
        '13 chdir("/") = 0',
        '13 clone(child_stack=0x3, flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = 14',
        '14 exit(0) = ?',
        '13 exit_group(0) = ?',
        '11 seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, {len=12, filter=0x1}) = 0',
        '12 <... futex resumed>) = 0',
        '12 exit(0) = ?',
        '11 exit_group(0) = ?',
    ]


@pytest.fixture
def executable_trace():
    """Two observed hops: an absolute target then a relative ancestor link."""
    lines = valid_trace()
    walk = [
        'openat(AT_FDCWD</>, "/", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 30</>',
        'openat(30</>, "pinned", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 31</pinned>',
        'openat(31</pinned>, "bin", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 32</pinned/bin>',
        'newfstatat(32</pinned/bin>, "bingsu", {st_mode=S_IFLNK|0777}, AT_SYMLINK_NOFOLLOW) = 0',
        'readlinkat(32</pinned/bin>, "bingsu", "/build/current/bingsu", 4097) = 21',
        'openat(30</>, "build", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 33</build>',
        'newfstatat(33</build>, "current", {st_mode=S_IFLNK|0777}, AT_SYMLINK_NOFOLLOW) = 0',
        'readlinkat(33</build>, "current", "releases/v2", 4097) = 11',
        'openat(33</build>, "releases", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 34</build/releases>',
        'openat(34</build/releases>, "v2", O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 35</build/releases/v2>',
        'newfstatat(35</build/releases/v2>, "bingsu", {st_mode=S_IFREG|0755}, AT_SYMLINK_NOFOLLOW) = 0',
        'openat(35</build/releases/v2>, "bingsu", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK|O_NOCTTY) = 36</build/releases/v2/bingsu>',
        'fstat(36</build/releases/v2/bingsu>, {st_mode=S_IFREG|0755}) = 0',
        # Revalidation may revisit previously resolved links.
        'readlinkat(32</pinned/bin>, "bingsu", "/build/current/bingsu", 4097) = 21',
        'readlinkat(33</build>, "current", "releases/v2", 4097) = 11',
    ]
    at = next(i for i, line in enumerate(lines) if line.startswith('11 chdir'))
    lines[at:at] = ["11 " + line for line in walk]
    return lines


def test_executable_walk_derives_later_relative_ancestor_hop(executable_trace):
    assert_prompt_trace_budget(executable_trace, EXE, ROOTS)


@pytest.mark.parametrize("old,new", [
    ('32</pinned/bin>, "bingsu", "/build', '32</pinned/bin>, "/pinned/bin/bingsu", "/build'),
    ('32</pinned/bin>, "bingsu", "/build', '99</pinned/bin>, "bingsu", "/build'),
    ('33</build>, "current", "releases', '33</build>, "other", "releases'),
    (', 4097)', ', 4098)'),
    (') = 21', ') = 4097'),  # Truncated result must never grant a new path.
    ('"/build/current/bingsu", 4097', '"/build/current/bingsu"..., 4097'),
    ('{st_mode=S_IFREG|0755}, AT_SYMLINK_NOFOLLOW', '{st_mode=S_IFLNK|0777}, AT_SYMLINK_NOFOLLOW'),
    ('AT_SYMLINK_NOFOLLOW) = 0', '0) = 0'),
    ('fstat(36<', 'fstat(99<'),
    ('"releases", O_PATH|O_NOFOLLOW', '"releases", O_PATH'),
])
def test_executable_walk_rejects_scope_mutations(executable_trace, old, new):
    changed = [line.replace(old, new) for line in executable_trace]
    assert changed != executable_trace
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(changed, EXE, ROOTS)


def test_executable_walk_cannot_use_future_link_results(executable_trace):
    lines = list(executable_trace)
    at = next(i for i, line in enumerate(lines) if '11 openat(30</>, "build"' in line)
    entry = lines.pop(at)
    at = next(i for i, line in enumerate(lines) if '11 readlinkat(32' in line)
    lines.insert(at, entry)
    with pytest.raises(AssertionError, match="helper path"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


def test_executable_walk_cannot_use_closed_parent(executable_trace):
    lines = list(executable_trace)
    at = next(i for i, line in enumerate(lines) if '11 readlinkat(32' in line)
    lines.insert(at, '11 close(32</pinned/bin>) = 0')
    with pytest.raises(AssertionError, match="helper namespace link"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


def test_executable_walk_cannot_use_another_process_evidence(executable_trace):
    lines = list(executable_trace)
    at = next(i for i, line in enumerate(lines) if '11 readlinkat(33' in line)
    lines[at] = lines[at].replace("11 readlinkat", "12 readlinkat")
    with pytest.raises(AssertionError, match="helper namespace link"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


def test_executable_walk_requires_latest_regular_file_check(executable_trace):
    lines = list(executable_trace)
    at = next(i for i, line in enumerate(lines) if '11 openat(35' in line)
    lines.insert(at, '11 newfstatat(35</build/releases/v2>, "bingsu", {}, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)')
    with pytest.raises(AssertionError, match="helper executable path"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


# 이것을 실패시키는 것: 부모 clone 반환보다 앞선 helper exec를 놓치거나, helper write/exit를 root 표에 합치는 것,
# read 버퍼를 경로로 보거나 상속/dup된 dirfd·미완료 파일 syscall을 해석하지 못하는 것.
def test_approved_prompt_and_helper_trace():
    assert_prompt_trace_budget(valid_trace(), EXE, ROOTS)


# 이것을 실패시키는 것: 다른 PID 사이의 exec 완료 출력 순서를 실행 순서로 취급하는 것.
def test_exec_completion_may_follow_parent_filter():
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if '"__refresh-v1"' in line)
    lines[at] = lines[at].replace(') = 0', ' <unfinished ...>')
    at = next(i for i, line in enumerate(lines) if 'PR_SET_SECCOMP' in line)
    lines.insert(at + 1, '11 <... execve resumed>) = 0')
    assert_prompt_trace_budget(lines, EXE, ROOTS)


def clone_prompt_reference(historical):
    lines = valid_trace()
    if not historical:
        lines = [line for line in lines if not line.startswith(("13 ", "14 ", "11 clone(child_stack=0x2"))]
        # Keep the abbreviated fd 3 lifetime: inherited /proc/10/fd, then
        # passwd, statm and boot_id with no close records between them. Those
        # stale/differently named entries are not proof of a live collision.
        # The archived fixture abbreviates held directory opens, reusing 3
        # for unrelated names. Give those implicit inherited fds distinct
        # numbers for the current gate's descriptor-lifetime validation.
        lines = [line.replace('3</pinned>', '30</pinned>').replace('3</>', '31</>')
                 if line.startswith('11 ') else line for line in lines]
    return lines


def clone3_prompt_trace(split, historical):
    # A successful clone3 replaces the ENOSYS + clone fallback pair.
    lines = [line for line in clone_prompt_reference(historical) if "ENOSYS" not in line]
    text = '\n'.join(lines).replace(
        'clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
        'clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD} <unfinished ...>'
    ).replace('<... clone resumed>)', '<... clone3 resumed>, 88)')
    text = text.replace(
        'clone(child_stack=0x2, flags=CLONE_VM|CLONE_VFORK|SIGCHLD)',
        'clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88)')
    for parent, child, stack in ((11, 12, "0x1"), (13, 14, "0x3")):
        before = '{flags=CLONE_VM|CLONE_FILES|CLONE_THREAD|CLONE_PARENT_SETTID, exit_signal=0}'
        after = f' => {{parent_tid=[{child}]}}, 88) = {child}'
        if split:
            after = f' <unfinished ...>\n{parent} <... clone3 resumed>' + after
        text = text.replace(
            f'clone(child_stack={stack}, flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = {child}',
            'clone3(' + before + after)
    return text.splitlines()


GLOBAL_INPUTS = ("/trusted/xdg/git/config", "/trusted/home/.gitconfig", "/trusted/xdg/git/ignore")
GLOBAL_FLAGS = "O_RDONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC"


def product_collector_trace(collector_exe="/pinned/bin/bingsu-collect"):
    lines = clone_prompt_reference(historical=False)
    at = next(i for i, line in enumerate(lines) if line.startswith('11 seccomp'))
    lines[at:at] = [
        '11 clone(child_stack=0x2, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 13',
        f'13 execve("{collector_exe}", ["{collector_exe}", "__collect-v1"], []) = 0',
        '13 clone(child_stack=0x3, flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = 14',
        '14 exit(0) = ?',
        '13 exit_group(0) = ?',
    ]
    return lines


# 이것을 실패시키는 것: 기본 화면에서 고정 collector 하나의 생성을 거부하는 것.
@pytest.mark.parametrize("collector_exe", ["/pinned/bin/bingsu-collect", "/trusted/build/bingsu-collect"])
def test_product_allows_one_pinned_collector(collector_exe):
    budget.assert_prompt_trace_budget(product_collector_trace(collector_exe), EXE, ROOTS,
                                      collector_exe=collector_exe)


def collector_verification_trace(collector_exe, *, spawn=True):
    lines = (product_collector_trace(collector_exe) if spawn
             else clone_prompt_reference(historical=False))
    at = next(i for i, line in enumerate(lines)
              if line.startswith('11 clone(child_stack=0x2') or line.startswith('11 seccomp'))
    parent = str(Path(collector_exe).parent)
    walk = ['11 openat(AT_FDCWD</>, "/", O_RDONLY|O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 40</>']
    directory, fd = "", 40
    for name in Path(parent).parts[1:]:
        child = directory + "/" + name
        walk.append(f'11 openat({fd}<{directory or "/"}>, "{name}", '
                    f'O_RDONLY|O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = {fd + 1}<{child}>')
        directory, fd = child, fd + 1
    walk += [
        f'11 openat({fd}<{parent}>, "bingsu-collect", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = 50<{collector_exe}>',
        f'11 fstat(50<{collector_exe}>, {{st_mode=S_IFREG|0755, st_size=128, ...}}) = 0',
        f'11 fstatfs(50<{collector_exe}>, {{f_type=EXT4_SUPER_MAGIC}}) = 0',
        f'11 fgetxattr(50<{collector_exe}>, "system.posix_acl_access", NULL, 0) = -1 ENODATA (No data available)',
        f'11 pread64(50<{collector_exe}>, "build and role tags", 65536, 0) = 128',
        f'11 newfstatat(50<{collector_exe}>, "", {{st_mode=S_IFREG|0755, ...}}, AT_EMPTY_PATH) = 0',
        f'11 newfstatat({fd}<{parent}>, "bingsu-collect", {{st_mode=S_IFREG|0755, ...}}, AT_SYMLINK_NOFOLLOW) = 0',
    ]
    lines[at:at] = walk
    at = next(i for i, line in enumerate(lines) if line.startswith('11 seccomp'))
    lines.insert(at, f'11 close(50<{collector_exe}>) = 0')
    return lines


# 이것을 실패시키는 것: init의 collector pin 대신 실행 파일의 별칭 옆 경로나 빌드 환경 경로를 쓰는 것.
@pytest.mark.parametrize("pin", ["/pinned/bin/bingsu-collect", "/trusted/build/bingsu-collect"])
@pytest.mark.parametrize("spawn", [False, True], ids=["verify-only", "spawn"])
def test_collector_verification_uses_init_pin(pin, spawn):
    script = f"_bingsu_call() {{ '{EXE}' prompt '--collector-exe={pin}'; }}\n".encode()
    collector_exe = budget.init_collector_exe(script)
    assert collector_exe == pin
    budget.assert_prompt_trace_budget(collector_verification_trace(pin, spawn=spawn), EXE, ROOTS,
                                      collector_exe=collector_exe)


# 이것을 실패시키는 것: 실제 _0에서 관찰한 fd 조회 중 하나를 다시 빠뜨리는 것.
@pytest.mark.parametrize("operation", [
    'newfstatat({fd}, "", {{st_mode=S_IFREG|0755}}, AT_EMPTY_PATH) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, '
    '{{stx_mask=STATX_ALL|STATX_MNT_ID, stx_mode=S_IFREG|0755}}) = 0',
    'fcntl({fd}, F_GETFD) = 0x1 (flags FD_CLOEXEC)',
])
def test_collector_verification_allows_observed_fd_metadata(operation):
    pin = "/trusted/build/bingsu-collect"
    lines = collector_verification_trace(pin, spawn=False)
    at = next(i for i, line in enumerate(lines) if line.startswith('11 fstat(50<'))
    lines.insert(at, '11 ' + operation.format(fd=f'50<{pin}>'))
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, collector_exe=pin)


# 이것을 실패시키는 것: collector pin이 없거나 중복·상대 경로·다른 이름인데 추측해서 통과시키는 것.
@pytest.mark.parametrize("words", ["", "'--collector-exe=relative'",
    "'--collector-exe=/trusted/build/other'",
    "'--collector-exe=/a/bingsu-collect' '--collector-exe=/b/bingsu-collect'"])
def test_collector_init_pin_is_unambiguous(words):
    with pytest.raises(AssertionError):
        budget.init_collector_exe(words.encode())


# 이것을 실패시키는 것: 같은 디렉터리의 다른 파일·쓰기·필수 플래그 누락·다른 pin·살아 있지 않은 fd를 허용하는 것.
@pytest.mark.parametrize("mutation", [
    "sibling", "write-open", "readwrite-open", "truncate-open", "nofollow", "nonblock", "cloexec",
    "absolute-open", "wrong-parent", "wrong-result", "different-pin", "different-name",
    "write", "pwrite", "truncate", "chmod", "mmap", "oversized-read", "closed-fd", "unopened-fd",
    "unheld-parent", "other-process", "followed-stat",
])
def test_collector_verification_rejects_trace_injection(mutation):
    pin = "/trusted/build/bingsu-collect"
    lines = collector_verification_trace(pin, spawn=False)
    opened = next(i for i, line in enumerate(lines) if '"bingsu-collect", O_RDONLY' in line)
    read = next(i for i, line in enumerate(lines) if line.startswith('11 pread64(50<'))
    fd = f"50<{pin}>"
    if mutation in {"different-pin", "different-name"}:
        pin = "/other/build/bingsu-collect" if mutation == "different-pin" else "/trusted/build/other"
    elif mutation == "sibling":
        lines[opened] = lines[opened].replace("bingsu-collect", "neighbor")
    elif mutation in {"write-open", "readwrite-open", "truncate-open"}:
        lines[opened] = lines[opened].replace("O_RDONLY", {
            "write-open": "O_WRONLY", "readwrite-open": "O_RDWR", "truncate-open": "O_RDONLY|O_TRUNC",
        }[mutation])
    elif mutation in {"nofollow", "nonblock", "cloexec"}:
        lines[opened] = lines[opened].replace("|O_" + mutation.upper(), "")
    elif mutation == "absolute-open":
        lines[opened] = lines[opened].replace('42</trusted/build>, "bingsu-collect"', f'AT_FDCWD, "{pin}"')
    elif mutation == "wrong-parent":
        lines[opened] = lines[opened].replace('42</trusted/build>', '42</other/build>')
    elif mutation == "wrong-result":
        lines[opened] = lines[opened].replace(f'= {fd}', '= 50</trusted/build/neighbor>')
    elif mutation == "unheld-parent":
        lines.insert(opened, '11 close(42</trusted/build>) = 0')
    elif mutation == "other-process":
        lines[opened] = lines[opened].replace('11 openat', '12 openat')
    elif mutation == "followed-stat":
        lines = [line.replace('AT_SYMLINK_NOFOLLOW', '0') if '"bingsu-collect", {' in line else line
                 for line in lines]
    else:
        extra = {
            "write": f'11 write({fd}, "x", 1) = 1',
            "pwrite": f'11 pwrite64({fd}, "x", 1, 0) = 1',
            "truncate": f'11 ftruncate({fd}, 0) = 0',
            "chmod": f'11 fchmod({fd}, 0777) = 0',
            "mmap": f'11 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, {fd}, 0) = 0x1000',
            "oversized-read": f'11 pread64({fd}, "x", 65537, 0) = 1',
            "closed-fd": f'11 close({fd}) = 0',
            "unopened-fd": f'11 pread64(51<{pin}>, "x", 1, 0) = 1',
        }[mutation]
        lines.insert(read, extra)
    with pytest.raises(AssertionError):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS, collector_exe=pin)


# 이것을 실패시키는 것: collector 상한을 늘리거나 실행 경로·verb·argv·빈 환경 계약을 푸는 것.
@pytest.mark.parametrize("mutation", ["second", "path", "verb", "argv", "env"])
def test_product_collector_allowance_stays_bounded(mutation):
    lines = product_collector_trace()
    at = next(i for i, line in enumerate(lines) if line.startswith('13 execve'))
    if mutation == "second":
        lines[at:at] = [
            '11 clone(child_stack=0x4, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 15',
            lines[at].replace('13 execve', '15 execve'),
        ]
    else:
        old, new = {
            "path": ('/pinned/bin/bingsu-collect', '/other/bingsu-collect'),
            "verb": ('__collect-v1', '__other'),
            "argv": ('"__collect-v1"]', '"__collect-v1", "extra"]'),
            "env": ('], [])', '], ["HOME=/repo"])'),
        }[mutation]
        lines[at] = lines[at].replace(old, new)
    with pytest.raises(AssertionError):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS)


# 이것을 실패시키는 것: collector_limit=1로 바꾸면서 기존 C3 경로/횟수 검사를 건너뛰는 것.
def test_one_collector_keeps_front_collection_budget():
    lines = product_collector_trace()
    lines[0] = lines[0].replace('"prompt"]', '"prompt", "--pwd", "/cwd"]')
    absent, _ = collection_trace(absent=True)
    entry = absent[0].replace('77 openat', '10 openat')
    at = next(i for i, line in enumerate(lines) if 'PR_SET_SECCOMP' in line)
    lines.insert(at, entry)
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS)
    lines.insert(at, entry)
    with pytest.raises(AssertionError, match="collection extra open"):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS)


def watchdog_killed_trace(lines, *, split=False):
    lines = [line for line in lines if line not in {'12 exit(0) = ?', '11 exit_group(0) = ?'}]
    lines += (['12 kill(11, SIGKILL <unfinished ...>'] if split else ['12 kill(11, SIGKILL) = 0'])
    return lines + ['12 +++ killed by SIGKILL +++', '11 +++ killed by SIGKILL +++']


# 이것을 실패시키는 것: helper TGID에 속한 watchdog의 자기 SIGKILL(미완료 호출 포함)을 거부하는 것.
@pytest.mark.parametrize("split", [False, True], ids=["whole", "unfinished-at-death"])
@pytest.mark.parametrize("collector", [False, True], ids=["no-collector", "one-collector"])
def test_product_allows_helper_watchdog_self_kill(split, collector):
    lines = product_collector_trace() if collector else clone_prompt_reference(historical=False)
    budget.assert_prompt_trace_budget(watchdog_killed_trace(lines, split=split), EXE, ROOTS)


# 이것을 실패시키는 것: 자기 종료 허용을 다른 PID·신호·collector 발신·collector 대상까지 넓히는 것.
@pytest.mark.parametrize("extra", [
    '12 kill(999, SIGKILL) = -1 EPERM (Operation not permitted)',
    '12 kill(10, SIGKILL) = 0',
    '12 kill(12, SIGKILL) = 0',
    '12 kill(0, SIGKILL) = 0',
    '12 kill(-11, SIGKILL) = 0',
    '12 kill(11, SIGTERM) = 0',
    '12 kill(11, 0) = 0',
    '12 kill(13, SIGKILL) = 0',
    '11 kill(13, SIGKILL) = 0',
    '13 kill(11, SIGKILL) = 0',
    '14 kill(11, SIGKILL) = 0',
    '13 kill(13, SIGKILL) = 0',
    '14 kill(13, SIGKILL) = 0',
    '12 tkill(11, SIGKILL) = 0',
    '12 tgkill(11, 12, SIGKILL) = 0',
    '10 kill(11, SIGKILL) = 0',
])
def test_product_rejects_other_signal_calls(extra):
    lines = product_collector_trace()
    # Inject while the root and all workers are live, with no pending syscall.
    lines = [line for line in lines if not line.startswith(('12 futex', '12 <... futex'))]
    root_exit = [line for line in lines if line.startswith(('10 exit_group', '10 +++ exited'))]
    lines = [line for line in lines if line not in root_exit]
    at = next(i for i, line in enumerate(lines) if line.startswith('14 exit'))
    lines[at:at] = [extra]
    with pytest.raises(AssertionError):
        budget.assert_prompt_trace_budget(lines + root_exit, EXE, ROOTS)


def global_input_trace(path, *, missing=False):
    lines = clone_prompt_reference(historical=False)
    result = "-1 ENOENT (No such file or directory)" if missing else f"40<{path}>"
    extra = [f'11 openat(AT_FDCWD</>, "{path}", {GLOBAL_FLAGS}) = {result}']
    if not missing:
        extra += [f'11 fstat(40<{path}>, {{st_mode=S_IFREG|0600, st_size=5}}) = 0',
                  f'11 read(40<{path}>, "# e4\\n", 32) = 5',
                  f'11 read(40<{path}>, "", 32) = 0',
                  f'11 fstat(40<{path}>, {{st_mode=S_IFREG|0600, st_size=5}}) = 0',
                  f'11 close(40<{path}>) = 0']
    at = next(i for i, line in enumerate(lines) if line.startswith('12 prctl'))
    lines[at:at] = extra
    return lines


def all_global_inputs_trace(missing):
    lines = product_collector_trace()
    at = next(i for i, line in enumerate(lines) if line.startswith('12 prctl'))
    extra = [line for path in GLOBAL_INPUTS for line in global_input_trace(path, missing=missing)
             if path in line]
    lines[at:at] = extra
    return watchdog_killed_trace(lines)


# 이것을 실패시키는 것: 전역 입력 접근을 마친 실행도 watchdog 종료만으로 거부하는 것.
@pytest.mark.parametrize("missing", [False, True], ids=["present", "missing"])
def test_watchdog_death_preserves_global_input_coverage(missing):
    lines = all_global_inputs_trace(missing)
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)
    budget.assert_global_inputs_exercised(lines, EXE, GLOBAL_INPUTS, not missing)


# 이것을 실패시키는 것: watchdog이 먼저 끝낸 실행에서 생략된 open/read를 조용히 통과시키는 것.
@pytest.mark.parametrize("missing", [False, True], ids=["present", "missing"])
@pytest.mark.parametrize("path", GLOBAL_INPUTS)
def test_watchdog_death_cannot_hide_missing_global_input(missing, path):
    lines = [line for line in all_global_inputs_trace(missing) if path not in line]
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)
    with pytest.raises(AssertionError, match="global input opens missing"):
        budget.assert_global_inputs_exercised(lines, EXE, GLOBAL_INPUTS, not missing)


@pytest.mark.parametrize("path", GLOBAL_INPUTS)
def test_watchdog_death_cannot_replace_reads_with_opens(path):
    lines = [line for line in all_global_inputs_trace(False)
             if not (line.startswith('11 read(') and path in line)]
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)
    with pytest.raises(AssertionError, match="global input reads missing"):
        budget.assert_global_inputs_exercised(lines, EXE, GLOBAL_INPUTS, True)


# 이것을 실패시키는 것: 허용된 watchdog 종료가 앞선 금지 경로 접근을 덮어버리는 것.
def test_watchdog_death_does_not_relax_path_rules():
    lines = all_global_inputs_trace(False)
    at = next(i for i, line in enumerate(lines) if line.startswith('12 kill'))
    lines.insert(at, '11 openat(AT_FDCWD</>, "/repo/secret", O_RDONLY) = -1 ENOENT (No such file or directory)')
    with pytest.raises(AssertionError, match="helper path"):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)


# 이것을 실패시키는 것: 세 파일 각각의 ENOENT/성공 open 또는 같은 fd read 허용을 제거하는 것.
@pytest.mark.parametrize("path", GLOBAL_INPUTS)
@pytest.mark.parametrize("missing", [False, True], ids=["read", "enoent"])
def test_helper_global_inputs_are_exact_reads(path, missing):
    budget.assert_prompt_trace_budget(global_input_trace(path, missing=missing), EXE, ROOTS,
                                      global_inputs=GLOBAL_INPUTS)


# 이것을 실패시키는 것: 전역 입력의 같은 fd 메타데이터 확인을 Linux stat 형태로 기록한 실행을 거부하는 것.
@pytest.mark.parametrize("path", GLOBAL_INPUTS)
@pytest.mark.parametrize("operation", [
    'newfstatat({fd}, "", {{st_mode=S_IFREG|0600, st_size=5}}, AT_EMPTY_PATH) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, '
    '{{stx_mask=STATX_ALL|STATX_MNT_ID, stx_mode=S_IFREG|0600, stx_size=5}}) = 0',
])
def test_helper_global_input_allows_empty_path_fd_stat(path, operation):
    lines = ['11 ' + operation.format(fd=f'40<{path}>')
             if line.startswith('11 fstat(40<') else line for line in global_input_trace(path)]
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)


@pytest.mark.parametrize("path", GLOBAL_INPUTS)
def test_helper_global_input_allows_fd_flags_query(path):
    lines = global_input_trace(path)
    at = next(i for i, line in enumerate(lines) if line.startswith(f'11 close(40<{path}>'))
    lines.insert(at, f'11 fcntl(40<{path}>, F_GETFD) = 0x1 (flags FD_CLOEXEC)')
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)


# 이것을 실패시키는 것: musl open의 CLOEXEC 설정부터 빈 config/ignore 읽기·stamp 재확인·close까지 중간 호출을 빠뜨리는 것.
@pytest.mark.parametrize("debug", [False, True], ids=["release", "debug"])
@pytest.mark.parametrize("open_call", ["open", "openat"])
def test_helper_global_inputs_allow_complete_musl_fd_sequence(debug, open_call):
    # Source-derived trace, not a live capture: read_bounded uses Take<File>,
    # whose default_read_to_end reads directly (no File size/seek fast path).
    lines = clone_prompt_reference(historical=False)
    extra = []
    for path in GLOBAL_INPUTS:
        fd = f"40<{path}>"
        prefix = 'AT_FDCWD</>, ' if open_call == "openat" else ''
        size = 10 if path.endswith("/ignore") else 0
        stamp = f'fstat({fd}, {{st_mode=S_IFREG|0600, st_size={size}}}) = 0'
        extra += [f'11 {open_call}({prefix}"{path}", {GLOBAL_FLAGS}) = {fd}',
                  f'11 fcntl({fd}, F_SETFD, FD_CLOEXEC) = 0',
                  f'11 {stamp}']
        if size:
            extra.append(f'11 read({fd}, ".DS_Store\\n", 32) = 10')
        extra += [f'11 read({fd}, "", 32) = 0', f'11 {stamp}']
        if debug:
            extra.append(f'11 fcntl({fd}, F_GETFD) = 0x1 (flags FD_CLOEXEC)')
        extra.append(f'11 close({fd}) = 0')
    at = next(i for i, line in enumerate(lines) if line.startswith('12 prctl'))
    lines[at:at] = extra
    budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)
    budget.assert_global_inputs_exercised(lines, EXE, GLOBAL_INPUTS, True)


# 이것을 실패시키는 것: openat을 직접 쓰는 collector까지 musl open의 F_SETFD 예외를 넓히는 것.
def test_collector_rejects_cloexec_setter_injection():
    pin = "/trusted/build/bingsu-collect"
    lines = collector_verification_trace(pin, spawn=False)
    at = next(i for i, line in enumerate(lines) if line.startswith('11 fstat(50<'))
    lines.insert(at, f'11 fcntl(50<{pin}>, F_SETFD, FD_CLOEXEC) = 0')
    with pytest.raises(AssertionError, match="helper collector fd"):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS, collector_exe=pin)


# 이것을 실패시키는 것: CLOEXEC 설정 예외가 미개방·닫힌·재사용 fd 또는 watchdog까지 허용하는 것.
@pytest.mark.parametrize("path", GLOBAL_INPUTS)
@pytest.mark.parametrize("mutation", ["unopened", "closed", "reused", "watchdog"])
def test_helper_global_cloexec_requires_held_helper_fd(path, mutation):
    lines = global_input_trace(path)
    fd = f"40<{path}>"
    at = next(i for i, line in enumerate(lines) if line.startswith(f'11 fstat({fd}'))
    if mutation == "unopened":
        at -= 1
    elif mutation == "closed":
        at = next(i for i, line in enumerate(lines) if line.startswith(f'11 close({fd}')) + 1
    elif mutation == "reused":
        lines[at:at] = [f'11 close({fd}) = 0',
                       f'11 openat(AT_FDCWD</>, "/dev/null", O_RDONLY|O_CLOEXEC) = 40</dev/null>']
        at += 2
    pid = 12 if mutation == "watchdog" else 11
    lines.insert(at, f'{pid} fcntl({fd}, F_SETFD, FD_CLOEXEC) = 0')
    with pytest.raises(AssertionError):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS)


# 이것을 실패시키는 것: collector와 세 전역 입력의 열린 fd에서 조회 허용을
# 변경·복제·다른 statx 플래그/마스크 또는 인자 수까지 넓히는 것.
@pytest.mark.parametrize("path", ["/trusted/build/bingsu-collect", *GLOBAL_INPUTS])
@pytest.mark.parametrize("operation", [
    'statx({fd}, "child", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {{}}) = 0',
    'statx({fd}, "{path}", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {{}}) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT, STATX_ALL, {{}}) = 0',
    'statx({fd}, "", AT_EMPTY_PATH, STATX_ALL, {{}}) = 0',
    'statx({fd}, "", AT_EMPTY_PATH|AT_STATX_FORCE_SYNC, STATX_ALL, {{}}) = 0',
    'statx({fd}, "", AT_EMPTY_PATH|AT_STATX_DONT_SYNC, STATX_ALL, {{}}) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW, STATX_ALL, {{}}) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL|STATX_MNT_ID, {{}}) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_BASIC_STATS, {{}}) = 0',
    'statx({fd}, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {{}}, 0) = 0',
    'newfstatat({fd}, "child", {{}}, AT_EMPTY_PATH) = 0',
    'newfstatat({fd}, "", {{}}, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) = 0',
    'newfstatat({fd}, "", {{}}, AT_EMPTY_PATH, 0) = 0',
    'fcntl({fd}, F_GETFD, 0) = 0x1 (flags FD_CLOEXEC)',
    'fcntl({fd}, F_GETFL) = 0',
    'fchmod({fd}, 0777) = 0',
    'fchown({fd}, 0, 0) = 0',
    'ftruncate({fd}, 0) = 0',
    'lseek({fd}, 0, SEEK_SET) = 0',
    'fsync({fd}) = 0',
    'fdatasync({fd}) = 0',
    'write({fd}, "x", 1) = 1',
    'pwrite64({fd}, "x", 1, 0) = 1',
    'fcntl({fd}, F_SETFD, 0) = 0',
    'fcntl({fd}, F_SETFD, 2) = 0',
    'fcntl({fd}, F_SETFD, -1) = 0',
    'fcntl({fd}, F_SETFD, FD_CLOEXEC|0x2) = 0',
    'fcntl({fd}, F_SETFD) = 0',
    'fcntl({fd}, F_SETFD, FD_CLOEXEC, 0) = 0',
    'fcntl({fd}, F_SETFD, FD_CLOEXEC) = -1 EPERM (Operation not permitted)',
    'fcntl({fd}, F_SETFL, O_RDWR|O_APPEND) = 0',
    'fcntl({fd}, F_DUPFD, 60) = 60<{path}>',
    'fcntl({fd}, F_DUPFD_CLOEXEC, 60) = 60<{path}>',
    'dup({fd}) = 60<{path}>',
    'dup2({fd}, 60) = 60<{path}>',
    'dup3({fd}, 60, O_CLOEXEC) = 60<{path}>',
])
def test_helper_pinned_input_rejects_fd_operation_injection(path, operation):
    collector = path.endswith("/bingsu-collect")
    lines = collector_verification_trace(path, spawn=False) if collector else global_input_trace(path)
    fd = f'{50 if collector else 40}<{path}>'
    at = next(i for i, line in enumerate(lines) if 'openat(' in line and line.endswith('= ' + fd))
    lines.insert(at + 1, '11 ' + operation.format(fd=fd, path=path))
    with pytest.raises(AssertionError):
        budget.assert_prompt_trace_budget(lines, EXE, ROOTS, global_inputs=GLOBAL_INPUTS,
                                          collector_exe=path if collector else None)


# 이것을 실패시키는 것: 각 허용 파일을 같은 뿌리의 다른 이름으로 바꾸거나, 쓰기·다른 errno·
# symlink 대상·미개방/닫힌 fd·watchdog 읽기를 허용하는 것. 변이는 실제 제품 trace 게이트를 거친다.
@pytest.mark.parametrize("path", GLOBAL_INPUTS)
@pytest.mark.parametrize("mutation", [
    "sibling", "write-open", "write-fd", "errno", "symlink", "unopened", "closed", "watchdog",
])
def test_helper_global_input_mutations_are_refused(path, mutation):
    lines = global_input_trace(path)
    text = "\n".join(lines)
    if mutation == "sibling":
        text = text.replace(path, path + ".other")
    elif mutation == "write-open":
        text = text.replace(GLOBAL_FLAGS, GLOBAL_FLAGS.replace("O_RDONLY", "O_RDWR"))
    elif mutation == "write-fd":
        text = text.replace(f'11 read(40<{path}>, "", 32) = 0', f'11 write(40<{path}>, "x", 1) = 1')
    elif mutation == "errno":
        text = "\n".join(global_input_trace(path, missing=True)).replace(
            "ENOENT (No such file or directory)", "EACCES (Permission denied)")
    elif mutation == "symlink":
        text = text.replace(f"40<{path}>", f"40<{path}.target>")
    elif mutation == "unopened":
        text = "\n".join(line for line in lines if f'"{path}", {GLOBAL_FLAGS}' not in line)
    elif mutation == "closed":
        text = text.replace(f"11 read(40<{path}>", f"11 close(40<{path}>) = 0\n11 read(40<{path}>")
    else:
        text = text.replace(f'11 openat(AT_FDCWD</>, "{path}"', f'12 openat(AT_FDCWD</>, "{path}"')
    error = "descriptor lifetime/identity mismatch" if mutation == "closed" else "helper (global input|path)"
    with pytest.raises(AssertionError, match=error):
        budget.assert_prompt_trace_budget(text.splitlines(), EXE, ROOTS, global_inputs=GLOBAL_INPUTS)


# 이것을 실패시키는 것: prompt의 현재/과거 게이트가 성공 clone3의 =>·스레드 owner·vfork 생성 예산을 다르게 처리하는 것.
@pytest.mark.parametrize("split", [False, True], ids=["whole", "split"])
@pytest.mark.parametrize("historical", [False, True], ids=["product", "historical"])
def test_prompt_gates_accept_clone3_struct_updates(split, historical):
    from collections import Counter
    from fsbudget.classify import kind
    lines = clone3_prompt_trace(split, historical)
    check = assert_prompt_trace_budget if historical else budget.assert_prompt_trace_budget
    check(lines, EXE, ROOTS)
    pids, scoped = budget.tree(lines, EXE)
    assert pids == ({"10", "11", "12", "13", "14"} if historical else {"10", "11", "12"})
    original = clone_prompt_reference(historical)
    check(original, EXE, ROOTS)

    def counts(records):
        calls = budget.parse_trace('\n'.join(records))
        assert not calls.errors, calls.errors
        return Counter((c.pid, k) for c in calls if (k := kind(c)) is not None)

    assert counts(scoped) == counts(original)


# 이것을 실패시키는 것: clone3 형식으로 root 스레드·추가 watchdog·파서 손상을 숨겨 prompt 게이트를 우회하는 것.
@pytest.mark.parametrize("historical", [False, True], ids=["product", "historical"])
@pytest.mark.parametrize("change", ["root-thread", "extra-thread", "stray-angle"])
def test_prompt_clone3_mutations_are_refused(historical, change):
    lines = clone3_prompt_trace(split=True, historical=historical)
    text = '\n'.join(lines)
    if change == "root-thread":
        text = text.replace("CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD", "CLONE_VM|CLONE_THREAD, exit_signal=SIGCHLD", 1)
    elif change == "extra-thread":
        text += '\n11 clone3({flags=CLONE_VM|CLONE_FILES|CLONE_THREAD} => {parent_tid=[15]}, 88) = 15'
    else:
        text = text.replace(" => ", " > ", 1)
    check = assert_prompt_trace_budget if historical else budget.assert_prompt_trace_budget
    with pytest.raises(AssertionError):
        check(text.splitlines(), EXE, ROOTS)


# 이것을 실패시키는 것: bootstrap의 횟수·시점·고정 exe/verb·빈 환경 또는 root의 기존 제한을 완화하는 것,
# helper 하위 트리의 경로·syscall·자식 예산을 통째로 제외하거나 NSS를 임의 네트워크로 넓히는 것.
@pytest.mark.parametrize("old,new", [
    ('= 11', '= -1 EAGAIN (Resource temporarily unavailable)'),
    ('flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished', 'flags=CLONE_VM|CLONE_THREAD|SIGCHLD <unfinished'),
    ('"__refresh-v1"', '"__other"'),
    ('11 execve("/pinned/bin/bingsu"', '11 execve("/evil/bingsu"'),
    ('0x2 /* 0 vars */', '0x2 /* 1 vars */'),
    ('10 write(1', '10 writev(1'),
    ('"/proc/self/fd"', '"/repo/secret"'),
    ('"/etc/passwd"', '"/repo/secret"'),
    ('4</pinned/run>, "marker"', '4</repo>, "marker"'),
    ('13 openat(4</pinned/run>', '13 openat(4</repo>'),
    ('11 read(5', '11 ptrace(5'),
    ('socket(AF_UNIX', 'socket(AF_INET'),
    ('"/var/run/nscd/socket"', '"/repo/socket"'),
    ('"__collect-legacy-v1"', '"__other"'),
    ('"snapshot", O_RDONLY', '"../secret", O_RDONLY'),
    ('9</proc/11/ns>', '9</proc/999/ns>'),
])
def test_trace_rejects_contract_mutations(old, new):
    lines = [line.replace(old, new) for line in valid_trace()]
    assert lines != valid_trace()
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


# 이것을 실패시키는 것: 필터 뒤의 생성·두 번째 생성·root 네트워크·helper의 추가 스레드/손자 생성을 허용하는 것.
@pytest.mark.parametrize("extra", [
    '10 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 15',
    '10 socket(AF_UNIX, SOCK_STREAM, 0) = 6',
    '11 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 15',
    '12 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 15',
    '13 execve("/bin/sh", ["sh"], []) = 0',
])
def test_trace_rejects_extra_calls(extra):
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(valid_trace() + [extra], EXE, ROOTS)


# 이것을 실패시키는 것: syscall 완료 순서에서 helper spawn보다 이른 필터 설치를 받아들이는 것.
def test_trace_rejects_filter_before_spawn():
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if "PR_SET_SECCOMP" in line)
    lines.insert(1, lines.pop(at))
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


# 새 state pin 위 XDG_STATE_HOME도 없으면 보유 fd 아래 한 이름씩만 생성한다.
def test_fresh_state_parent_creation_budget():
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if 'mkdirat(3</pinned>' in line)
    lines[at:at] = [
        '11 mkdirat(3</>, "pinned", 0700) = 0',
        '11 openat(3</>, "pinned", O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 3</pinned>',
    ]
    assert_prompt_trace_budget(lines, EXE, ROOTS)


@pytest.mark.parametrize("extra,error", [
    ('11 mkdirat(3</repo>, "state", 0700) = 0', "helper mkdir"),
    ('11 mkdirat(3</pinned>, "config", 0700) = 0', "helper mkdir"),
    ('11 mkdirat(3</pinned>, "../pinned/state", 0700) = 0', "helper mkdir"),
    ('11 mkdirat(AT_FDCWD, "/pinned/state", 0700) = 0', "helper mkdir"),
    ('11 mkdirat(3</pinned>, "state", 0755) = 0', "helper mkdir"),
    ('11 mkdir("/pinned/state", 0700) = 0', "helper mkdir"),
    ('11 openat(3</>, "pinned", O_RDONLY|O_NOFOLLOW|O_DIRECTORY) = 4</pinned>', "helper path"),
    ('11 newfstatat(3</>, "pinned", {}, 0) = 0', "helper path"),
    ('11 newfstatat(3</>, "pinned/../pinned", {}, AT_SYMLINK_NOFOLLOW) = 0', "helper path"),
])
def test_trace_rejects_expanded_creation_and_collector_budget(extra, error):
    with pytest.raises(AssertionError, match=error):
        assert_prompt_trace_budget(valid_trace() + [extra], EXE, ROOTS)


# 각 새 허용 조건을 제거하면 그 조건을 쓰는 합성 trace가 반드시 거부된다.
@pytest.mark.parametrize("allowance", ["helper_mkdir_step", "helper_chain_stat", "fixed_exec"])
def test_trace_needs_creation_and_collector_allowances(monkeypatch, allowance):
    original = getattr(budget, allowance)
    if allowance == "fixed_exec":
        # Disable only the collector allowance, preserving the refresh check.
        monkeypatch.setattr(budget, allowance, lambda call, exe, verb:
                            verb != "__collect-legacy-v1" and original(call, exe, verb))
    else:
        monkeypatch.setattr(budget, allowance, lambda *args: False)
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(valid_trace(), EXE, ROOTS)


def test_trace_needs_created_ancestor_open_allowance(monkeypatch):
    monkeypatch.setattr(budget, "helper_created_open", lambda *args: False)
    with pytest.raises(AssertionError, match="helper path"):
        test_fresh_state_parent_creation_budget()


@pytest.mark.parametrize("old,new", [
    ('"__collect-legacy-v1"], []', '"__collect-legacy-v1", "extra"], []'),
    ('13 execve("/pinned/bin/bingsu"', '13 execve("/other/bin/bingsu"'),
    ('"__collect-legacy-v1"], []', '"__collect-legacy-v1"], 0x3 /* 1 vars */'),
])
def test_trace_rejects_collector_exec_contract_mutation(old, new):
    original = valid_trace()
    mutated = [line.replace(old, new) for line in original]
    assert mutated != original
    with pytest.raises(AssertionError, match="execve"):
        assert_prompt_trace_budget(mutated, EXE, ROOTS)


@pytest.fixture
def held_trace():
    """Small generated contract for successful held snapshot reads.

    The real N4 capture below covers a first prompt with no context yet.
    """
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if "PR_SET_SECCOMP" in line)
    dirs, files = budget.prompt_sources(ROOTS)
    held = []
    fds = {}
    for fd, path in enumerate(sorted(dirs, key=lambda p: (p.count("/"), p)), 21):
        parent, _, name = path.rpartition("/")
        base = "AT_FDCWD</>" if path == "/" else f"{fds[parent or '/']}<{parent or '/'}>"
        name = "/" if path == "/" else name
        held.append(f'10 openat({base}, "{name}", O_RDONLY|O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = {fd}<{path}>')
        held.append(f'10 fstatfs({fd}<{path}>, {{}}) = 0')
        held.append(f'10 fgetxattr({fd}<{path}>, "system.posix_acl_access", NULL, 0) = -1 ENODATA (No data available)')
        fds[path] = fd
    for fd, path in enumerate(sorted(files), max(fds.values()) + 1):
        parent, _, name = path.rpartition("/")
        held.append(f'10 openat({fds[parent]}<{parent}>, "{name}", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK|O_NOCTTY) = {fd}<{path}>')
        fds[path] = fd
    lines[at:at] = held
    at = next(i for i, line in enumerate(lines) if "PR_SET_SECCOMP" in line) + 1
    snapshot = next(path for path in files if path.endswith("/snapshot"))
    lines[at:at] = [
        '10 clock_gettime(CLOCK_BOOTTIME, {tv_sec=100, tv_nsec=0}) = 0',
        f'10 read({fds[snapshot]}<{snapshot}>, "bytes", 1024) = 1024',
        *[f'10 close({fd}<{path}>) = 0' for path, fd in fds.items()],
    ]
    return lines


@pytest.fixture(scope="module")
def n4_real_trace():
    """Real non-root debug capture at 4371ab3 with documented fd/link fixes
    projected (see fixtures/prompt-n4-trace.md); not a post-fix execution.
    """
    return Path(__file__).with_name("fixtures").joinpath(
        "prompt-n4-debian-bookworm-glibc-aarch64.strace"
    ).read_text().replace("__collect-v1", "__collect-legacy-v1").splitlines()


def test_real_n4_debian_prompt_trace(n4_real_trace):
    assert_prompt_trace_budget(n4_real_trace, DEBIAN_EXE, DEBIAN_ROOTS)
    pids, scoped = budget.tree(n4_real_trace, DEBIAN_EXE)
    assert pids == {"2809", "2810", "2811", "2812", "2813"}
    assert len(n4_real_trace) == 3320
    calls = budget.parse_trace("\n".join(scoped))
    assert len(calls) == 2473
    links = [c for c in calls if c.name == "readlinkat"]
    assert sum(c.pid == 2809 for c in links) == 2
    assert sum(c.pid == 2810 for c in links) == 32
    assert not any(c.name == "openat" and budget.args_of(c)[1] in {'"time"', '"time_for_children"'}
                   for c in calls)
    assert any(c.pid == 2809 and c.name == "openat" and '"contexts-v2"' in c.args
               and c.ret.startswith("-1 ENOENT") for c in calls)
    assert any(c.pid == 2810 and c.name == "renameat" and '"snapshot"' in c.args for c in calls)


def test_real_n4_rejects_debug_fd_probe(n4_real_trace):
    changed = list(n4_real_trace)
    at = next(i for i, line in enumerate(changed) if line.startswith("2809 ") and "write(1" in line)
    changed.insert(at, '2809 fcntl(7<time:[4026532442]>, F_GETFD) = -1 EPERM (Operation not permitted)')
    with pytest.raises(AssertionError, match="post-filter syscall"):
        assert_prompt_trace_budget(changed, DEBIAN_EXE, DEBIAN_ROOTS)



def test_held_snapshot_contract(held_trace):
    assert_prompt_trace_budget(held_trace, EXE, ROOTS)


@pytest.mark.parametrize("name", ["fcntl", "openat", "readlinkat", "fstat", "fstatfs", "fgetxattr", "getuid", "getpid", "lseek", "pread64", "readv"])
def test_held_trace_rejects_every_non_table_call_after_filter(held_trace, name):
    # A path operation is refused even if it would name an otherwise approved file.
    extra = f'10 {name}(3, "snapshot", 0) = -1 EPERM (Operation not permitted)'
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(held_trace + [extra], EXE, ROOTS)


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"])
def test_held_data_opens_require_each_flag(held_trace, flag):
    changed = [line.replace("|" + flag, "") if '"snapshot",' in line and line.startswith("10 ") else line for line in held_trace]
    assert changed != held_trace
    with pytest.raises(AssertionError, match="root path"):
        assert_prompt_trace_budget(changed, EXE, ROOTS)


@pytest.mark.parametrize("flag", ["O_PATH", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"])
def test_held_walk_requires_each_flag(held_trace, flag):
    changed = [line.replace("|" + flag, "") if '"contexts-v2",' in line and line.startswith("10 ") else line for line in held_trace]
    assert changed != held_trace
    with pytest.raises(AssertionError, match="root path"):
        assert_prompt_trace_budget(changed, EXE, ROOTS)


@pytest.mark.parametrize("old,new", [
    ('"snapshot", O_RDONLY', '"other", O_RDONLY'),
    ('"snapshot", O_RDONLY', '"../snapshot", O_RDONLY'),
    ('"contexts-v2",', '"contexts-v3",'),
    ('CLOCK_BOOTTIME', 'CLOCK_REALTIME'),
    ('"system.posix_acl_access"', '"user.other"'),
    (', 1024) = 1024', ', 16385) = 1024'),
])
def test_held_trace_rejects_scope_mutation(held_trace, old, new):
    changed = [line.replace(old, new) if line.startswith("10 ") else line for line in held_trace]
    assert changed != held_trace
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(changed, EXE, ROOTS)


def test_held_trace_rejects_read_without_successful_prefilter_open(held_trace):
    changed = [line.split(" = ")[0] + " = -1 ENOENT (No such file or directory)"
               if '"snapshot",' in line and line.startswith("10 ") else line for line in held_trace]
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(changed, EXE, ROOTS)


def test_held_trace_rejects_read_before_filter(held_trace):
    lines = list(held_trace)
    read = next(i for i, line in enumerate(lines) if '10 read(' in line and '/snapshot>' in line)
    entry = lines.pop(read)
    at = next(i for i, line in enumerate(lines) if 'PR_SET_SECCOMP' in line)
    lines.insert(at, entry)
    with pytest.raises(AssertionError, match="root pre-filter content"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


@pytest.mark.parametrize("call", [
    'read(99</pinned/config/secret>, "x", 1)',
    'close(99</pinned/config/secret>)',
    'read(0</dev/null>, "", 1)',
])
def test_held_trace_rejects_inherited_or_closed_descriptor(held_trace, call):
    with pytest.raises(AssertionError, match="root held"):
        assert_prompt_trace_budget(held_trace + [f'10 {call} = 0'], EXE, ROOTS)


def test_held_trace_needs_exact_prefilter_allowance(held_trace, monkeypatch):
    monkeypatch.setattr(budget, "prompt_open", lambda *args: False)
    with pytest.raises(AssertionError, match="root path"):
        assert_prompt_trace_budget(held_trace, EXE, ROOTS)


def test_held_root_open_is_absolute_even_with_hostile_cwd(held_trace):
    lines = [line.replace('openat(AT_FDCWD</>, "/",', 'openat(AT_FDCWD</repo/untrusted>, "/",')
             if line.startswith("10 ") else line for line in held_trace]
    assert lines != held_trace
    assert_prompt_trace_budget(lines, EXE, ROOTS)


# 이것을 실패시키는 것: open_flags가 O_LARGEFILE을 남기는 것.
def test_walk_step_accepts_x86_64_largefile_flag():
    import test_prompt_env_paths as t
    line = '9 openat(AT_FDCWD</>, "/", O_RDONLY|O_LARGEFILE|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY) = 3</>'
    call = next(c for c in t.parse_trace(line) if c.name == "openat")
    assert t.helper_walk_step(call, "/", ["/root/x/run-t/bingsu"])


def test_real_n4_rejects_duplicate_fstatfs(n4_real_trace):
    lines = list(n4_real_trace)
    at = next(i for i, line in enumerate(lines) if line.startswith("2809 ") and "fstatfs(4</proc>" in line)
    lines.insert(at, '2809 fstatfs(4</proc>, {f_type=PROC_SUPER_MAGIC}) = 0')
    with pytest.raises(AssertionError, match="root duplicate fstatfs"):
        assert_prompt_trace_budget(lines, DEBIAN_EXE, DEBIAN_ROOTS)


def test_real_n4_rejects_kernel_walk_held_after_filter(n4_real_trace):
    lines = list(n4_real_trace)
    at = next(i for i, line in enumerate(lines) if line.startswith("2809 ") and "close(4</proc>" in line)
    entry = [lines.pop(at)]
    if "<unfinished ...>" in entry[0]:
        resumed = next(i for i in range(at, len(lines)) if lines[i].startswith("2809 ") and "<... close resumed>" in lines[i])
        entry.append(lines.pop(resumed))
    with pytest.raises(AssertionError, match="root kernel walk held after filter"):
        assert_prompt_trace_budget(lines + entry, DEBIAN_EXE, DEBIAN_ROOTS)


@pytest.mark.parametrize("old,new", [
    ('"time", "time:', '"mnt", "time:'),
    ('"2809", O_RDONLY', '"999", O_RDONLY'),
])
def test_real_n4_rejects_kernel_path_expansion(n4_real_trace, old, new):
    changed = [line.replace(old, new) if line.startswith("2809 ") else line for line in n4_real_trace]
    assert changed != n4_real_trace
    with pytest.raises(AssertionError, match="root path"):
        assert_prompt_trace_budget(changed, DEBIAN_EXE, DEBIAN_ROOTS)


# Each new allowance is needed by both adapters, but only for the exact
# relative namespace names and bounded buffer. Link output is not a pathname.
@pytest.mark.parametrize("pid", [10, 11])
@pytest.mark.parametrize("old,new", [
    ('"time",', '"mnt",'),
    ('"time_for_children",', '"mnt",'),
    ('/ns>', '/other>'),
    ('"time",', '"../ns/time",'),
    (', 28)', ', 29)'),
])
def test_namespace_readlink_scope(pid, old, new):
    lines = valid_trace()
    changed = [line.replace(old, new) if line.startswith(f"{pid} readlinkat(") else line
               for line in lines]
    assert changed != lines
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(changed, EXE, ROOTS)


@pytest.mark.parametrize("pid", [10, 11])
def test_namespace_readlink_needs_allowance(monkeypatch, pid):
    original = budget.time_namespace_readlink
    monkeypatch.setattr(budget, "time_namespace_readlink", lambda call, path, owner:
                        call.pid != pid and original(call, path, owner))
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(valid_trace(), EXE, ROOTS)


# 이것을 실패시키는 것: proc/self의 상대 경로·11-byte 상한·보유 procfs fd·필터 전 경계를 없애는 것.
@pytest.mark.parametrize("change", ["valid", "path", "absolute", "size", "unobserved", "closed", "after"])
def test_proc_self_link_is_bounded_and_held(change):
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if line.startswith('10 openat(21'))
    probe = '10 readlinkat(21</proc>, "self", "10", 11) = 2'
    facts = '10 fstatfs(21</proc>, {f_type=PROC_SUPER_MAGIC}) = 0'
    if change == "path":
        probe = probe.replace('"self"', '"thread-self"')
    if change == "absolute":
        probe = probe.replace('"self"', '"/proc/self"')
    if change == "size":
        probe = probe.replace(', 11)', ', 12)')
    (parsed,) = budget.parse_trace(probe)
    assert budget.proc_self_readlink(parsed, budget.call_paths(parsed)[0]) == (
        change not in {"path", "absolute", "size"})
    lines[at:at] = ([] if change == "unobserved" else [facts]) + (
        ['10 close(21</proc>) = 0'] if change == "closed" else []) + (
        [] if change == "after" else [probe])
    if change == "after":
        lines.append(probe)
    if change == "valid":
        assert_prompt_trace_budget(lines, EXE, ROOTS)
    else:
        with pytest.raises(AssertionError):
            assert_prompt_trace_budget(lines, EXE, ROOTS)


@pytest.mark.parametrize("call", [
    'newfstatat(23</proc/10/ns>, "time", {}, 28)',
    'readlinkat(23</proc/10/ns>, "/proc/10/ns/time", "time:[123]", 28)',
    'openat(23</proc/10/ns>, "time", O_RDONLY|O_CLOEXEC)',
    'readlinkat(23</proc/999/ns>, "time", "time:[123]", 28)',
])
def test_root_refuses_namespace_open_or_nonrelative_readlink(call):
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if '10 readlinkat(' in line)
    lines[at] = f'10 {call} = -1 EACCES (Permission denied)'
    with pytest.raises(AssertionError, match="root path"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


@pytest.mark.parametrize("missing", ['10 fstatfs(23', '10 openat(22'])
def test_root_namespace_link_requires_observed_held_directory(missing):
    lines = [line for line in valid_trace() if not line.startswith(missing)]
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


def test_root_namespace_link_rejects_wrong_held_file():
    lines = [
        '10 openat(22</proc/10>, "timens_offsets", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 23</proc/10/timens_offsets>'
        if line.startswith('10 openat(22') else line for line in valid_trace()
    ]
    # The same fd has filesystem evidence, but it was not opened as ns.
    with pytest.raises(AssertionError, match="root namespace walk"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)


def test_root_namespace_link_is_prefilter_only():
    lines = valid_trace()
    at = next(i for i, line in enumerate(lines) if '10 readlinkat(' in line)
    lines.append(lines.pop(at))
    with pytest.raises(AssertionError, match="post-filter syscall"):
        assert_prompt_trace_budget(lines, EXE, ROOTS)

# 이것을 실패시키는 것: 타이머 호출을 필터 뒤·반복 없는 값·다른 타이머·재설정으로 넓히는 것.
@pytest.mark.parametrize("change", ["valid", "after", "oneshot", "zero", "long", "virtual", "twice"])
def test_n6_timer_is_one_repeating_prefilter_timer(debian_trace, change):
    line = '1947 setitimer(ITIMER_REAL, {it_interval={tv_sec=0, tv_usec=1000}, it_value={tv_sec=0, tv_usec=49000}}, NULL) = 0'
    lines = list(debian_trace)
    at = next(i for i, l in enumerate(lines) if l.startswith("1947 ") and "PR_SET_SECCOMP" in l)
    if change == "after":
        at = next(i for i, l in enumerate(lines) if l.startswith("1947 ") and "write(1" in l)
    if change == "oneshot":
        line = line.replace("tv_usec=1000", "tv_usec=0")
    if change == "zero":
        line = line.replace("tv_usec=49000", "tv_usec=0")
    if change == "long":
        line = line.replace("tv_usec=49000", "tv_usec=50001")
    if change == "virtual":
        line = line.replace("ITIMER_REAL", "ITIMER_VIRTUAL")
    lines[at:at] = [line] * (2 if change == "twice" else 1)
    if change == "valid":
        assert_prompt_trace_budget(lines, DEBIAN_EXE, DEBIAN_ROOTS)
    else:
        with pytest.raises(AssertionError, match="timer"):
            assert_prompt_trace_budget(lines, DEBIAN_EXE, DEBIAN_ROOTS)


def collection_trace(*, absent=False, previous=False):
    """Minimal C3 window with real header bytes and all five same-fd facts."""
    import hashlib
    import struct
    cwd = b"/cwd"
    _, snapshots = budget.prompt_sources(ROOTS)
    context = str(Path(next(iter(snapshots))).parent)
    root = context + "/collections-v1"
    paths = [root, root + "/" + hashlib.sha256(cwd).hexdigest()]
    paths += [paths[-1] + "/store"]
    paths += [paths[-1] + "/response", paths[-1] + "/previous"]
    lines = []
    for i, path in enumerate(paths):
        fd = i + 20
        base = 19 if i == 0 else (22 if i == 4 else fd - 1)
        parent = str(Path(path).parent)
        flags = "O_RDONLY|O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC" if i < 3 else "O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK|O_NOCTTY"
        result = "-1 ENOENT (No such file or directory)" if absent else f"{fd}<{path}>"
        lines.append(f'77 openat({base}<{parent}>, "{Path(path).name}", {flags}) = {result}')
        if absent:
            break
        mode = "S_IFDIR|0700" if i < 3 else "S_IFREG|0600"
        lines.append(f'77 fstat({fd}<{path}>, {{st_mode={mode}, st_size=100}}) = 0')
        lines.append(f'77 fstatfs({fd}<{path}>, {{f_type=EXT4_SUPER_MAGIC}}) = 0')
        result = "-1 EBADF (Bad file descriptor)" if i < 3 else "-1 ENODATA (No data available)"
        lines.append(f'77 fgetxattr({fd}<{path}>, "system.posix_acl_access", NULL, 0) = {result}')
        if i < 3:
            lines.append(f'77 getxattr("/proc/self/fd/{fd}", "system.posix_acl_access", NULL, 0) = -1 ENODATA (No data available)')
    lines.append('77 prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0x1) = 0')
    if not absent:
        for i in ([3, 4] if previous else [3]):
            path = paths[i]; fd = i + 20
            header = b"BNGRES03" + struct.pack("<HHII", 3, 64, 36, 0) + bytes(44)
            encoded = ''.join(chr(b) if 32 <= b < 127 and b not in (34,92) else f'\\{b:03o}' for b in header)
            lines.append(f'77 read({fd}<{path}>, "{encoded}", 64) = 64')
            lines.append(f'77 read({fd}<{path}>, "' + 'a'*36 + '", 36) = 36')
    return lines, paths


def check_collection(lines):
    calls = budget.parse_trace("\n".join(lines))
    assert not calls.errors
    boundary, = [c.index for c in calls if c.name == "prctl"]
    return budget.assert_collection_trace(calls, boundary, ROOTS, b"/cwd", required=True)


# 이것을 실패시키는 것: 부재1회·정상5회의 facts/read 항을 gate하지 않는 것.
@pytest.mark.parametrize("absent,previous,opens,reads", [(True,False,1,0), (False,False,5,2), (False,True,5,4)])
def test_collection_exact_open_and_read_budget(absent, previous, opens, reads):
    lines, _ = collection_trace(absent=absent, previous=previous)
    counts = check_collection(lines)
    assert counts["openat"] == opens and counts["read"] == reads


# 이것을 실패시키는 것: 경로/플래그/부모/facts/read/필터 경계 확장을 하나라도 허용하는 것.
@pytest.mark.parametrize("change", ["extra-open", "absent-retry", "nofollow", "cloexec", "nonblock", "noctty", "wrong-hash", "wrong-parent", "extra-fstat", "extra-statfs", "extra-acl", "pre-read", "post-open", "post-facts", "eof-read", "large-read", "short-header", "missing-facts", "missing-open"])
def test_collection_budget_rejects_one_mutation(change):
    lines, paths = collection_trace(absent=change == "absent-retry")
    original = list(lines)
    filt = next(i for i,s in enumerate(lines) if "prctl(" in s)
    open_at = next(i for i,s in enumerate(lines) if '"collections-v1"' in s)
    response_at = next((i for i,s in enumerate(lines) if '"response"' in s), open_at)
    fact_at = next((i for i,s in enumerate(lines) if 'fstat(23<' in s), 1)
    if change in {"extra-open", "absent-retry"}: lines.insert(open_at+1, lines[open_at])
    elif change in {"nofollow", "cloexec", "nonblock", "noctty"}:
        lines[response_at] = lines[response_at].replace("|O_"+change.upper(), "")
    elif change == "wrong-hash": lines[5] = lines[5].replace(Path(paths[1]).name, "a"*64)
    elif change == "wrong-parent": lines[response_at] = lines[response_at].replace("22<", "99<")
    elif change == "extra-fstat": lines.insert(fact_at, lines[fact_at])
    elif change == "extra-statfs": lines.insert(fact_at+1, lines[fact_at+1])
    elif change == "extra-acl": lines.insert(fact_at+2, lines[fact_at+2])
    elif change == "pre-read": lines.insert(filt, lines.pop(filt+1))
    elif change == "post-open": lines.append(lines[response_at])
    elif change == "post-facts": lines.append(lines[fact_at])
    elif change == "eof-read": lines.append(f'77 read(23<{paths[3]}>, "", 1) = 0')
    elif change == "large-read": lines[-1] = lines[-1].replace(", 36) = 36", ", 16385) = 36")
    elif change == "short-header": lines[-2] = lines[-2].replace(", 64) = 64", ", 63) = 63")
    elif change == "missing-facts": lines.pop(fact_at)
    elif change == "missing-open": lines = [s for s in lines if "openat(" not in s]
    assert lines != original, change
    with pytest.raises(AssertionError):
        check_collection(lines)


# 이것을 실패시키는 것: D2가 과거 fixture의 collector 허용량을 새 역할 게이트에 재사용하는 것.
def test_collector_gate_keeps_role_and_kind_budgets_separate():
    from copy import deepcopy
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools/fsbudget"))
    # Share the adversarial entry-order fixture with the attribution oracle.
    spec_path = Path(__file__).resolve().parents[2] / "tools/fsbudget/tests/test_attribute.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("collector_attribution_fixture", spec_path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    expected = {"front": {"exec": 1, "spawn": 1}, "helper": {"exec": 1, "spawn": 1},
                "collector": {"exec": 1, "openat": 1, "read": 1}}
    budget.assert_collector_trace_budget(fixture.PRODUCT, fixture.PINNED_PRODUCT, expected)
    saved = list(fixture.PRODUCT)
    mutated = saved.copy()
    mutated.insert(-3, '12 write(9</stage>, "x", 1) = 1')
    with pytest.raises(AssertionError):
        budget.assert_collector_trace_budget(mutated, fixture.PINNED_PRODUCT, expected)
    assert saved == fixture.PRODUCT
    reduced = deepcopy(expected)
    reduced["collector"]["read"] = 0
    with pytest.raises(AssertionError, match="collector.read"):
        budget.assert_collector_trace_budget(saved, fixture.PINNED_PRODUCT, reduced)


# GATE-FS-HELPER.1 judge regressions on reduced release captures (provenance:
# fixtures/helper-stage-traces.md). The live gate is
# test_prompt_env_paths.py::test_live_helper_calls_match_stage_formula.
HELPER_STAGE_TRACES = Path(__file__).with_name("fixtures") / "helper-stage-traces.json"
HELPER_EXE = "/fx/bin/bingsu"


def helper_stage_case(stage):
    import json
    from fsbudget.formula import HelperAxes, HelperPlan
    meta = json.loads(HELPER_STAGE_TRACES.read_text())[stage]
    data = (HELPER_STAGE_TRACES.parent / f"helper-stage-{stage}.strace").read_bytes()
    assert hashlib.sha256(data).hexdigest() == meta["sha256"], stage
    plan = dict(meta["plan"])
    plan["stages"] = tuple(plan["stages"])
    plan["ax"] = HelperAxes(**plan["ax"])
    return data.decode().splitlines(), meta["collector"], HelperPlan(**plan)


def helper_stage_errors(lines, collector, expected, **attribution):
    from fsbudget.gate import check
    _, counts = budget.measured_helper_calls(lines, HELPER_EXE, collector, **attribution)
    return check({"helper": counts.get("helper", {})}, {"helper": expected}, "exact", ["helper"])


def first_helper_line(lines, pattern):
    import re
    helper = next(l.split()[0] for l in lines if "__refresh-v1" in l and "execve(" in l)
    return next(i for i, l in enumerate(lines) if l.split()[0] == helper and re.search(pattern, l))


STAGE_NAMES = ["unchanged", "publish", "collect", "failure-last-good", "failure-recover"]


# CI 40650736942 unchanged helper pid 2756, lines 730-736: glibc's
# pthread_getattr_np maps fclose seeks. Replay those call shapes on each
# saved aarch64 capture; this is a platform mutation, not a new live capture.
@pytest.mark.parametrize("stage", STAGE_NAMES)
@pytest.mark.parametrize("damage", [None, "extra-read", "missing-cur", "missing-set", "missing-both"])
def test_helper_stack_guard_exact(stage, damage):
    from dataclasses import replace
    lines, collector, plan = helper_stage_case(stage)
    at = first_helper_line(lines, r"close\(3</proc/\d+/maps>")
    pid = lines[at].split()[0]
    startup = [f'{pid} lseek(3</proc/{pid}/maps>, 0, SEEK_CUR) = 2906',
               f'{pid} lseek(3</proc/{pid}/maps>, 2822, SEEK_SET) = 2822']
    if damage == "extra-read":
        startup.append(f'{pid} read(3</proc/{pid}/maps>, "", 1024) = 0')
    elif damage == "missing-cur":
        del startup[0]
    elif damage == "missing-set":
        del startup[1]
    elif damage == "missing-both":
        startup = []
    lines[at:at] = startup
    plan = replace(plan, arch="x86_64")
    if damage is None:
        budget.check_helper_capture(stage, lines, HELPER_EXE, collector, plan)
    else:
        kind = "read" if damage == "extra-read" else "seek"
        with pytest.raises(AssertionError, match=rf"{kind}: measured .*\(exact\)"):
            budget.check_helper_capture(stage, lines, HELPER_EXE, collector, plan)


@pytest.mark.parametrize("ready_after", [0, 1, 3])
def test_collection_warmup_waits_for_rotation(tmp_path, ready_after):
    (tmp_path / "response").write_bytes(b"r" * 64)
    prompts, waits = [], []

    def publish():
        prompts.append(1)
        if len(prompts) == ready_after:
            (tmp_path / "response").replace(tmp_path / "previous")
            (tmp_path / "response").write_bytes(b"n" * 72)

    if ready_after == 0:
        (tmp_path / "previous").write_bytes(b"p" * 64)
    sizes = budget.warm_collection_previous(tmp_path, publish, lambda: waits.append(1))
    assert sizes == {"response_bytes": 72 if ready_after else 64, "previous_bytes": 64}
    assert len(prompts) == len(waits) == ready_after


def test_collection_warmup_never_rotated_fails(tmp_path):
    (tmp_path / "response").write_bytes(b"r" * 64)
    prompts = []
    with pytest.raises(AssertionError, match="warm-up did not rotate"):
        budget.warm_collection_previous(tmp_path, lambda: prompts.append(1), lambda: None)
    assert len(prompts) == 3


@pytest.mark.parametrize("damage", ["missing-response", "symlink", "directory", "short", "permission", "io"])
def test_collection_warmup_does_not_swallow_errors(tmp_path, monkeypatch, damage):
    (tmp_path / "response").write_bytes(b"r" * 64)
    previous = tmp_path / "previous"
    error = AssertionError
    if damage == "missing-response":
        (tmp_path / "response").unlink()
        error = FileNotFoundError
    elif damage == "symlink":
        previous.symlink_to(tmp_path / "absent")
    elif damage == "directory":
        previous.mkdir()
    elif damage == "short":
        previous.write_bytes(b"short")
    else:
        error = PermissionError if damage == "permission" else OSError
        original = Path.lstat

        def lstat(path, *args, **kwargs):
            if path == previous:
                raise error("injected slot IO error")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "lstat", lstat)

    def unexpected():
        pytest.fail("a real preparation error must not trigger another prompt")

    with pytest.raises(error):
        budget.warm_collection_previous(tmp_path, unexpected, unexpected)


def legacy_helper_stage_case(stage):
    """Change three stored helper calls to equivalent x86_64 spellings.

    Keep the capture's plan/libc/counts: this is an ABI spelling mutation of
    the saved aarch64 capture, not an asserted live x86_64 musl measurement.
    """
    import ast
    import json
    import posixpath
    from fsbudget.classify import split_args, fd_identity
    lines, collector, plan = helper_stage_case(stage)
    start = first_helper_line(lines, r"umask\(077")
    pid = lines[start].split()[0]
    replacements = {}
    for at in range(start + 1, len(lines)):
        if lines[at].split()[0] != pid:
            continue
        parsed = budget.parse_trace(lines[at])
        if parsed.errors or len(parsed) != 1:
            continue  # leave unfinished/resumed records intact
        c = parsed[0]
        if c.name not in {"openat", "newfstatat"}:
            continue
        args = split_args(c.args)
        path = ast.literal_eval(args[1])
        if not path:
            # A held directory in this symlink-free fixture is the same
            # object when queried by stat(path). No extra open is introduced.
            identity = fd_identity(args[0])
            if (c.name == "newfstatat" and args[-1] == "AT_EMPTY_PATH"
                    and "S_IFDIR" in args[2] and identity and identity.startswith("file:")
                    and "stat" not in replacements):
                lines[at] = f'{pid} stat({json.dumps(identity[5:])}, {args[2]}) = {c.ret}'
                replacements["stat"] = at
            continue
        if not path.startswith("/"):
            identity = fd_identity(args[0])
            if not identity or not identity.startswith("file:"):
                continue
            path = posixpath.join(identity[5:], path)
        if c.name == "openat":
            name, tail = "open", args[2:]
        else:
            if args[-1] not in {"0", "AT_SYMLINK_NOFOLLOW"}:
                continue
            name = "lstat" if args[-1] == "AT_SYMLINK_NOFOLLOW" else "stat"
            tail = [args[2]]
        if name in replacements:
            continue
        lines[at] = f'{pid} {name}({", ".join([json.dumps(path), *tail])}) = {c.ret}'
        replacements[name] = at
        if len(replacements) == 3:
            break
    assert set(replacements) == {"open", "stat", "lstat"}, (stage, replacements)
    return lines, collector, plan, replacements


# 이것을 실패시키는 것: legacy 이름이 역할 집계/실제 단계 판정기를 우회하거나 누락 매핑을 허용하는 것.
@pytest.mark.parametrize("stage", STAGE_NAMES)
@pytest.mark.parametrize("name", ["open", "stat", "lstat"])
@pytest.mark.parametrize("damage", [None, "extra", "remove-mapping"])
def test_legacy_helper_stage_trace_mutations(monkeypatch, stage, name, damage):
    from fsbudget.classify import HELPER_LEGACY_PATH_KINDS
    from fsbudget.formula import helper_stage_expected
    lines, collector, plan, replacements = legacy_helper_stage_case(stage)
    original, _, _ = helper_stage_case(stage)
    _, before = budget.measured_helper_calls(original, HELPER_EXE, collector)
    _, after = budget.measured_helper_calls(lines, HELPER_EXE, collector)
    assert before == after  # every role unchanged; each alias counts exactly once
    assert budget.check_helper_capture(stage, lines, HELPER_EXE, collector, plan) == (stage == "collect")
    kind = HELPER_LEGACY_PATH_KINDS[name]
    if damage == "extra":
        at = replacements[name]
        # A failed open is still one call; reusing its successful fd would
        # fail descriptor attribution before reaching the exact count gate.
        extra = lines[at].split(" = ")[0] + " = -1 EACCES (Permission denied)"
        lines.insert(at + 1, extra)
    elif damage == "remove-mapping":
        monkeypatch.delitem(HELPER_LEGACY_PATH_KINDS, name)
    errors = helper_stage_errors(lines, collector, helper_stage_expected(plan))
    if damage is None:
        assert errors == []
        return
    assert any(f"helper.{kind}:" in error and "(exact)" in error for error in errors)
    if damage == "remove-mapping":
        assert "helper.unknown-fs: measured 1, formula 0 (exact)" in errors
    phase = "prefix" if stage == "collect" else "helper"
    with pytest.raises(AssertionError, match=rf"{phase}\.{kind}.*exact"):
        budget.check_helper_capture(stage, lines, HELPER_EXE, collector, plan)


# 이것을 실패시키는 것: 판정기가 저장 trace의 종류별 호출 수를 공식과 exact로 비교하지 않는 것,
# 도우미 호출 하나를 더하거나(fstat) 앞단으로 옮기는 것(git 전역 입력 open), helper 어휘 없이 세는 것,
# umask를 세지 않는 것(더하거나 빼도 통과), 시작 뒤의 loader 모양 접근(/proc/<pid>/maps)을 면제하는 것.
@pytest.mark.parametrize("stage,damage", [
    (stage, damage) for stage in STAGE_NAMES
    for damage in (None, "extra-fstat", "generic-vocabulary", "extra-umask", "missing-umask", "maps-after-startup")
    + (("moved-to-front",) if stage == "collect" else ())])
def test_stage_formula_checker_regressions(stage, damage):
    from fsbudget.formula import helper_stage_expected
    lines, collector, plan = helper_stage_case(stage)
    expected = helper_stage_expected(plan)
    kwargs = {}
    if damage == "extra-fstat":
        # A complete fd stat of a held runtime folder, repeated once.
        at = first_helper_line(lines, r'newfstatat\(\d+</fx/run-t/bingsu>, "", \{.*\) = 0$')
        lines = lines[:at + 1] + [lines[at]] + lines[at + 1:]
    elif damage == "moved-to-front":
        # The helper's first global Git input open, made by the live front instead.
        root = lines[0].split()[0]
        at = first_helper_line(lines, r'openat\(AT_FDCWD</>, "/fx/(?:cfg|home)-t/[^"]*git[^"]*",.*\) = -1 ENOENT')
        moved = root + lines[at][len(lines[at].split()[0]):]
        lines = [lines[0], moved] + lines[1:at] + lines[at + 1:]
    elif damage == "generic-vocabulary":
        kwargs["helper_vocabulary"] = False
    elif damage in ("extra-umask", "missing-umask", "maps-after-startup"):
        # detach()'s umask(077), split by strace into a call and its resumption.
        at = first_helper_line(lines, r"umask\(077")
        end = next(i for i in range(at, len(lines)) if lines[i].split()[0] == lines[at].split()[0] and " = " in lines[i])
        pid = lines[at].split()[0]
        if damage == "missing-umask":
            lines = lines[:at] + lines[at + 1:end] + lines[end + 1:]
        else:
            # A loader-allowlisted path after startup must still count (review control).
            extra = (f"{pid}  umask(077) = 077" if damage == "extra-umask" else
                     f'{pid}  newfstatat(AT_FDCWD</>, "/proc/{pid}/maps", {{st_mode=S_IFREG|0444, st_size=0, ...}}, 0) = 0')
            lines = lines[:end + 1] + [extra] + lines[end + 1:]
    errors = helper_stage_errors(lines, collector, expected, **kwargs)
    if damage is None:
        assert errors == []
    else:
        assert errors, damage


# 이것을 실패시키는 것: 제품 도우미 게이트가 옛 합성 고정 항(잠금 1·머리 1·표식 1, e["read"] += 2)이나
# 합성 공식(synthetic_helper_expected)을 받아들이는 것.
@pytest.mark.parametrize("stage", STAGE_NAMES)
def test_product_helper_gate_rejects_legacy_fixed_terms(stage):
    from fsbudget.formula import Coeffs, helper_stage_expected, synthetic_helper_expected
    lines, collector, plan = helper_stage_case(stage)
    expected = helper_stage_expected(plan)
    assert helper_stage_errors(lines, collector, expected) == []
    legacy = dict(expected, read=expected["read"] + 2)
    assert helper_stage_errors(lines, collector, legacy)
    synthetic = synthetic_helper_expected(plan.ax, Coeffs(), plan.stages[0] == "publish", 4096, plan.snapshot_bytes)
    assert helper_stage_errors(lines, collector, synthetic)


# 이것을 실패시키는 것: GC 시간 예산으로 tail 호출 하나가 줄어도 collect 전체를 exact로 검사하는 것.
def test_collect_accepts_short_time_bound_tail(monkeypatch, tmp_path):
    lines, collector, plan = helper_stage_case("collect")
    at = max(i for i, line in enumerate(lines) if 'newfstatat(' in line and ' = 0' in line)
    del lines[at]
    run_helper_captures(monkeypatch, tmp_path, [(lines, collector, plan)])


def run_helper_captures(monkeypatch, tmp_path, captures):
    """Run the actual live gate with stored captures, without Linux or a binary."""
    from types import SimpleNamespace
    used = []

    class Fixture:
        def __init__(self, stage):
            assert stage == "collect"
            assert len(used) < len(captures), "unexpected extra attempt"
            self.lines, self.collector, self.expected_plan = captures[len(used)]
            used.append(self)
            self.base = tmp_path / str(len(used))
            self.base.mkdir()
            self.inst = SimpleNamespace(exe=HELPER_EXE)

        def prompt(self, trace):
            trace.write_text("\n".join(self.lines) + "\n")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        def plan(self, libc):
            return self.expected_plan

    monkeypatch.setattr(budget, "HelperStageFixture", Fixture)
    monkeypatch.setattr(budget, "require_release_helper", lambda _: "gnu")
    monkeypatch.setattr(budget, "real_bin", lambda: Path(HELPER_EXE))
    monkeypatch.setattr(budget.shutil, "which", lambda _: "/synthetic/strace")
    monkeypatch.setattr(budget, "wait_helpers", lambda _: None)
    budget.test_live_helper_calls_match_stage_formula("collect", tmp_path)
    return len(used)


# 이것을 실패시키는 것: 업로드가 다른 시험/fixture/환경변수 파일까지 포함하는 것.
def test_helper_stage_upload_contains_only_fixture_evidence(monkeypatch, tmp_path_factory):
    import json
    from test_collector_security import workflow_job
    root = budget.helper_stage_evidence.__wrapped__(tmp_path_factory)
    root.mkdir()
    unrelated = root.parent / "unrelated-secret-canary"
    unrelated.write_text("not fixture evidence")
    monkeypatch.setenv("M3D_SECRET_CANARY", "must-not-be-inherited")
    assert "M3D_SECRET_CANARY" not in budget.trusted_env(root)
    assert run_helper_captures(monkeypatch, root, [helper_stage_case("collect")]) == 1
    files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    assert files == {f"collect/attempt-1/{name}" for name in ("trace.strace", "stdout", "stderr", "attempt.json")}
    assert not any(p.is_symlink() for p in root.rglob("*"))
    record = json.loads((root / "collect/attempt-1/attempt.json").read_text())
    assert record["published"] is True and record["errors"] == []
    _, steps = workflow_job((budget.ROOT / ".github/workflows/shell.yml").read_text(),
                            "filter-calls", action_inputs=True)
    upload, = [s for s in steps
               if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert upload["if"] == "failure()"
    assert upload["with"]["path"] == "${{ runner.temp }}/helper-stage-pytest/" + root.name + "/"
    assert unrelated.exists() and unrelated.parent != root


def deadline_helper_capture():
    """Synthetic exit-75 variant: retain clock/finish/GC, omit publication.

    This is a checker fixture, not a claim of a live deadline capture.
    """
    lines, collector, plan = helper_stage_case("collect")
    _, roles = budget.measured_helper_attribution(lines, HELPER_EXE, collector)
    threads = [c.ret.split()[0] for c, kind in roles.helper_calls
               if kind == "thread" and c.ret.split()[0].isdigit()]
    supervisor = threads[1]
    start = next(i for i, line in enumerate(lines) if line.split()[0] == supervisor
                 and 'newfstatat(' in line and '/contexts-v2/' in line)
    lines = [line for i, line in enumerate(lines)
             if i < start or line.split()[0] != supervisor or 'exit' in line]
    pid = next(line.split()[0] for line in lines if budget.is_root(line, collector))
    lines = [line.replace('exit_group(0)', 'exit_group(75)').replace('exited with 0', 'exited with 75')
             if line.split()[0] == pid else line for line in lines]
    return lines, collector, plan


def deadline_published_capture():
    """Synthetic exit-75 variant that keeps the supervisor publication.

    The collector sent a verified update, hit its own stage deadline and exited
    75; the supervisor reaped it and stored the Deadline partial (spec message
    row: results so far; S-17: a timeout after verified A). CI run 40730902708
    attempt 8 traced this order. A checker fixture, not a live capture.
    """
    lines, collector, plan = helper_stage_case("collect")
    pid = next(line.split()[0] for line in lines if budget.is_root(line, collector))
    lines = [line.replace('exit_group(0)', 'exit_group(75)').replace('exited with 0', 'exited with 75')
             if line.split()[0] == pid else line for line in lines]
    return lines, collector, plan


def failed_before_install(capture, result="-1 EIO (Input/output error)"):
    """The supervisor's last check of the staged name before its installing
    rename fails, and the rename is kept: publication after failed verification."""
    lines, collector, plan = capture
    install = max(i for i, line in enumerate(lines) if 'renameat(' in line and '".response.stage"' in line
                  and line.rstrip().endswith('"response") = 0'))
    pid = lines[install].split()[0]
    check = max(i for i in range(install) if lines[i].split()[0] == pid and 'newfstatat(' in lines[i]
                and '".response.stage"' in lines[i])
    assert lines[check].endswith(" = 0"), lines[check]
    lines = list(lines)
    lines[check] = lines[check][:-len(" = 0")] + " = " + result
    return lines, collector, plan


def move_absence_probe(lines, supervisor, creation, dirfd):
    """Move the supervisor's read-only .response.stage absence probe (an
    entry/resumed pair before the creation) to just after the creation, so
    every per-kind count stays the same."""
    entry = max(i for i in range(creation) if lines[i].split()[0] == supervisor
                and '".response.stage", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC' in lines[i])
    drop = {entry}
    if lines[entry].endswith("<unfinished ...>"):
        drop.add(next(i for i in range(entry + 1, creation) if lines[i].split()[0] == supervisor
                      and lines[i].split(None, 1)[1].startswith("<... openat resumed>")))
    probe = (f'{supervisor}  openat({dirfd}, ".response.stage", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)'
             " = -1 ENOENT (No such file or directory)")
    moved = []
    for i, line in enumerate(lines):
        if i not in drop:
            moved.append(line)
        if i == creation:
            moved.append(probe)
    return moved


def creation_then_failure(capture, damage):
    """Failures shaped like the stage's absence probe or creation.

    create-absence / write-absence: the supervisor's read-only .stage-request
    absence probe becomes a failed exclusive create / a failed write open.
    open-creation: the stage is created through the absolute-path open alias,
    and its read-only ENOENT absence probe moves after the creation; open-creation-check: the
    same creation, then its last name check reports ENOENT."""
    import re
    lines, collector, plan = capture
    lines = list(lines)
    install = max(i for i, line in enumerate(lines) if 'renameat(' in line and '".response.stage"' in line
                  and line.rstrip().endswith('"response") = 0'))
    supervisor = lines[install].split()[0]
    probe = "O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)"
    if damage in ("create-absence", "write-absence"):
        at = next(i for i in range(install) if lines[i].split()[0] == supervisor
                  and '".stage-request", ' + probe in lines[i])
        flags = {"create-absence": "O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600)",
                 "write-absence": "O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)"}[damage]
        lines[at] = lines[at].replace(probe, flags)
        return lines, collector, plan
    if damage == "forged-annotation":
        # Review reproduction: the creation's fd annotation names another
        # file (and so does every later use of that fd); a read-only absence
        # probe after the creation reports ENOENT.
        at = next(i for i in range(install) if lines[i].split()[0] == supervisor
                  and '".response.stage", O_RDWR|O_CREAT|O_EXCL' in lines[i])
        fd = re.search(r"= (\d+)<[^>]*>$", lines[at])[1]
        held = re.compile(rf"(?<![\d]){fd}<[^<>]*/(?:\.response\.stage|response)>")
        end = next(i for i in range(at, len(lines)) if lines[i].split()[0] == supervisor
                   and lines[i].split(None, 1)[1].startswith(f"close({fd}<"))
        for i in range(at, end + 1):
            if lines[i].split()[0] == supervisor:
                lines[i] = held.sub(f"{fd}</forged/other>", lines[i])
        dirfd = re.search(r"openat\((\d+<([^>]+)>), ", lines[at])
        lines = move_absence_probe(lines, supervisor, at, dirfd[1])
        return lines, collector, plan
    if damage.startswith("truncated-creation"):
        # Review reproduction: a creation path strace cuts at -s 256, then a
        # read-only absence probe after the creation reports ENOENT.
        at = next(i for i in range(install) if lines[i].split()[0] == supervisor
                  and '".response.stage", O_RDWR|O_CREAT|O_EXCL' in lines[i])
        dirfd = re.search(r"openat\((\d+<([^>]+)>), ", lines[at])
        cut = '"' + ('.//' * 100 + '.response.stage')[:256] + '"...'
        lines[at] = lines[at].replace('".response.stage", O_RDWR', cut + ", O_RDWR")
        if damage == "truncated-creation-unannotated":
            lines[at] = re.sub(r"= (\d+)<[^>]*>$", r"= \1", lines[at])
        lines = move_absence_probe(lines, supervisor, at, dirfd[1])
        return lines, collector, plan
    if damage == "open-creation-check":
        lines, collector, plan = failed_before_install((lines, collector, plan), "-1 ENOENT (No such file or directory)")
    at = next(i for i in range(install) if lines[i].split()[0] == supervisor
              and '".response.stage", O_RDWR|O_CREAT|O_EXCL' in lines[i])
    dirfd = re.search(r"openat\((\d+<([^>]+)>), ", lines[at])
    lines[at] = lines[at].replace(dirfd[0] + '".response.stage"', f'open("{dirfd[2]}/.response.stage"')
    if damage == "open-creation":
        lines = move_absence_probe(lines, supervisor, at, dirfd[1])
    return lines, collector, plan


COLLECT_CAPTURES = {"published": lambda: helper_stage_case("collect"),
                    "deadline": deadline_helper_capture,
                    "deadline-published": deadline_published_capture}


def extra_helper_stat(lines, *, tail=False, supervisor=False):
    lines = list(lines)
    if supervisor:
        at = next(i for i, line in enumerate(lines) if 'PR_SET_NAME, "collect-supervi"' in line)
        pid = lines[at].split()[0]
        at = next(i for i, line in enumerate(lines) if line.split()[0] == pid and 'exit(0)' in line)
        lines.insert(at, f'{pid} newfstatat(AT_FDCWD</>, "/proc/{pid}/maps", {{}}, 0) = 0')
    else:
        matches = [i for i, line in enumerate(lines) if 'newfstatat(' in line
                   and '</fx/run-t/bingsu>' in line and ' = 0' in line]
        at = matches[-1] if tail else matches[0]
        lines.insert(at, lines[at])
    return lines


# 이것을 실패시키는 것: prefix 초과/누락, tail 상한 초과, 마감 회차 폐기 후 정상 회차만 검사하는 것.
@pytest.mark.parametrize("capture", list(COLLECT_CAPTURES))
@pytest.mark.parametrize("damage,diagnostic", [
    ("extra-prefix", r"prefix.fstat.*exact"),
    ("missing-prefix", r"prefix.fstat.*exact"),
    ("extra-tail", r"finish_gc.fstat.*le"),
    ("extra-supervisor", r"supervisor.fstat.*le"),
])
def test_collect_attempt_mutations(monkeypatch, tmp_path, capture, damage, diagnostic):
    clean = helper_stage_case("collect")
    lines, collector, plan = COLLECT_CAPTURES[capture]()
    # Validate the unmodified fixture first, including the deadline attempts.
    assert budget.check_helper_capture("collect", lines, HELPER_EXE, collector, plan) == (capture != "deadline")
    if damage == "missing-prefix":
        lines = list(lines)
        at = first_helper_line(lines, r'newfstatat\(\d+</fx/run-t/bingsu>, "", \{.*\) = 0$')
        del lines[at]
    else:
        lines = extra_helper_stat(lines, tail=damage == "extra-tail", supervisor=damage == "extra-supervisor")
    # The review reproduction is the deadline/extra-prefix cell: attempt 1
    # has one extra fstat and exits 75; the available clean attempt 2 cannot hide it.
    with pytest.raises(AssertionError, match=diagnostic):
        run_helper_captures(monkeypatch, tmp_path, [(lines, collector, plan), clean])


# 이것을 실패시키는 것: exit 75 회차를 검사하지 않거나 실제 발행 없이 재시도 한도에서 통과하는 것.
def test_collect_requires_a_publication_within_the_attempt_cap(monkeypatch, tmp_path):
    with pytest.raises(pytest.fail.Exception, match=f"zero publishes.*{budget.COLLECT_ATTEMPTS}"):
        run_helper_captures(monkeypatch, tmp_path, [deadline_helper_capture()] * budget.COLLECT_ATTEMPTS)
    # All capped non-publications remain inspectable after the terminal failure.
    import json
    from collections import Counter
    for attempt in range(1, budget.COLLECT_ATTEMPTS + 1):
        artifacts = tmp_path / "collect" / f"attempt-{attempt}"
        assert {p.name for p in artifacts.iterdir()} == {"trace.strace", "stdout", "stderr", "attempt.json"}
        assert all(p.is_file() and not p.is_symlink() for p in artifacts.iterdir())
        evidence = json.loads((artifacts / "attempt.json").read_text())
        assert evidence["collector_exit"] == 75
        assert evidence["published"] is False
        assert evidence["publish_attempt"] is None
        assert set(evidence["phase_counts"]) == {"prefix", "supervisor", "finish_gc"}
        assert Counter(evidence["phase_counts"]["prefix"]) == Counter(evidence["phase_expected"]["prefix"])
        assert (artifacts / "trace.strace").read_text().splitlines() == deadline_helper_capture()[0]
        assert not (tmp_path / str(attempt)).exists(), "product fixture should be cleaned up"


# 이것을 실패시키는 것: exit 75 회차를 발행 여부와 무관하게 마감 공식(감독 tail에 발행 호출 0)으로 재는 것,
# exit 75 회차의 발행 자체를 오류로 보는 것, 그 발행을 발행 회차로 세지 않는 것.
def test_collect_accepts_a_deadline_partial_publication(monkeypatch, tmp_path):
    import json
    lines, collector, plan = deadline_published_capture()
    assert budget.check_helper_capture("collect", lines, HELPER_EXE, collector, plan) is True
    assert run_helper_captures(monkeypatch, tmp_path, [(lines, collector, plan)]) == 1
    evidence = json.loads((tmp_path / "collect" / "attempt-1" / "attempt.json").read_text())
    assert evidence["collector_exit"] == 75 and evidence["published"] is True
    assert evidence["publish_attempt"] == 1 and evidence["errors"] == []
    from fsbudget.formula import helper_collect_expected
    assert evidence["phase_expected"] == json.loads(json.dumps(helper_collect_expected(plan)))


# 이것을 실패시키는 것: 설치 rename만 보고 발행으로 받는 것(그 앞 감독 검증의 실패를 보지 않음), 만든 뒤의
# 단계 이름 부재(ENOENT)를 처음의 부재 확인처럼 허용하는 것. exit 0과 exit 75 모두.
@pytest.mark.parametrize("capture", ["published", "deadline-published"])
@pytest.mark.parametrize("result", ["-1 EIO (Input/output error)", "-1 ENOENT (No such file or directory)"])
def test_collect_rejects_publication_after_failed_verification(capture, result):
    lines, collector, plan = failed_before_install(COLLECT_CAPTURES[capture](), result)
    with pytest.raises(AssertionError, match="publication after a failed supervisor call"):
        budget.check_helper_capture("collect", lines, HELPER_EXE, collector, plan)


# 이것을 실패시키는 것: 부재 확인의 flags 비교에서 musl의 O_LARGEFILE을 빼지 않는 것(CI musl 칸의 정상 발행이 실패).
@pytest.mark.parametrize("capture", ["published", "deadline-published"])
def test_collect_accepts_musl_absence_probes(capture):
    lines, collector, plan = COLLECT_CAPTURES[capture]()
    install = max(i for i, line in enumerate(lines) if 'renameat(' in line and '".response.stage"' in line)
    supervisor = lines[install].split()[0]
    probe = "O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = -1 ENOENT"
    musl = [line.replace(probe, "O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_NOFOLLOW|O_CLOEXEC) = -1 ENOENT")
            if line.split()[0] == supervisor else line for line in lines]
    assert musl != lines
    assert budget.check_helper_capture("collect", musl, HELPER_EXE, collector, plan) is True


# 이것을 실패시키는 것: 잘린 생성 경로를 fd 주석으로 확인하지 않는 것, 확인할 수 없는 생성을 넘기는 것(fail closed 제거),
# 단계 이름 인자와 다른 fd 주석을 받아들이는 것.
@pytest.mark.parametrize("capture", ["published", "deadline-published"])
@pytest.mark.parametrize("damage,message", [
    ("truncated-creation", "publication after a failed supervisor call"),
    ("truncated-creation-unannotated", "supervisor open of an unresolved path"),
    ("forged-annotation", "supervisor open annotation disagrees with its path"),
])
def test_collect_rejects_truncated_creation(capture, damage, message):
    lines, collector, plan = creation_then_failure(COLLECT_CAPTURES[capture](), damage)
    with pytest.raises(AssertionError, match=message):
        budget.check_helper_capture("collect", lines, HELPER_EXE, collector, plan)


# 이것을 실패시키는 것: 부재 확인 예외의 syscall·flags 고정을 지우는 것, 단계 생성을 openat으로만 추적하는 것.
@pytest.mark.parametrize("capture", ["published", "deadline-published"])
@pytest.mark.parametrize("damage", ["create-absence", "write-absence", "open-creation", "open-creation-check"])
def test_collect_rejects_creation_shaped_failures(capture, damage):
    lines, collector, plan = creation_then_failure(COLLECT_CAPTURES[capture](), damage)
    assert lines != COLLECT_CAPTURES[capture]()[0]
    with pytest.raises(AssertionError, match="publication after a failed supervisor call"):
        budget.check_helper_capture("collect", lines, HELPER_EXE, collector, plan)


def test_collect_checks_deadline_then_accepts_publication(monkeypatch, tmp_path):
    assert run_helper_captures(monkeypatch, tmp_path,
                              [deadline_helper_capture()] * 5 + [helper_stage_case("collect")]) == 6


# 이것을 실패시키는 것: 시도 상한을 40 미만으로 되돌리는 것(40번째 회차의 발행을 못 본다).
def test_collect_accepts_a_publication_on_the_last_allowed_attempt(monkeypatch, tmp_path):
    import json
    n = 39  # CI publishes in about 1 of 8 attempts: the last allowed attempt must still count
    assert run_helper_captures(monkeypatch, tmp_path,
                              [deadline_helper_capture()] * n + [helper_stage_case("collect")]) == n + 1
    evidence = json.loads((tmp_path / "collect" / f"attempt-{n + 1}" / "attempt.json").read_text())
    assert evidence["published"] is True and evidence["publish_attempt"] == n + 1


# 이것을 실패시키는 것: collector exit 0만으로 실제 response rename을 대신하는 것.
def test_collect_exit_zero_without_publish_does_not_pass(monkeypatch, tmp_path):
    lines, collector, plan = deadline_helper_capture()
    lines = [line.replace('exit_group(75)', 'exit_group(0)').replace('exited with 75', 'exited with 0')
             for line in lines]
    with pytest.raises(pytest.fail.Exception, match="zero publishes"):
        run_helper_captures(monkeypatch, tmp_path, [(lines, collector, plan)] * budget.COLLECT_ATTEMPTS)


# 이것을 실패시키는 것: 새 syscall을 볼 수 없는 제한된 strace 집합으로 되돌리는 것.
def test_helper_stage_capture_traces_all_calls(monkeypatch, tmp_path):
    from types import SimpleNamespace
    fixture = object.__new__(budget.HelperStageFixture)
    fixture.base, fixture.pwd, fixture.seq, fixture.script, fixture.env = tmp_path, tmp_path, 0, b"", {}
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stderr=b"")
    monkeypatch.setattr(budget.subprocess, "run", run)
    fixture.prompt(tmp_path / "trace")
    assert commands[0][commands[0].index("-e") + 1] == "trace=all"


# 이것을 실패시키는 것: exit 75를 이유로 누락된 완료 경계와 필수 prefix 호출을 허용하는 것.
@pytest.mark.parametrize("deadline", [False, True])
def test_collect_missing_prefix_boundary_is_rejected(deadline):
    from fsbudget.formula import helper_collect_expected
    from fsbudget.gate import check_collect
    lines, collector, plan = deadline_helper_capture()
    _, roles = budget.measured_helper_attribution(lines, HELPER_EXE, collector)
    main = next(c.pid for c, kind in roles.helper_calls if kind == "exec")
    boundary = next(i for i, (c, kind) in enumerate(roles.helper_calls)
                    if c.pid == main and c.name == "flock" and '/snapshot.lock>' in c.args
                    and 'LOCK_UN' in c.args)
    roles.helper_calls = [(c, kind) for i, (c, kind) in enumerate(roles.helper_calls)
                          if c.pid != main or i < boundary]
    errors, _ = check_collect(roles, helper_collect_expected(plan),
                              deadline=helper_collect_expected(plan, deadline=True) if deadline else None)
    assert "collect: missing snapshot unlock boundary" in errors
    assert any("prefix.flock" in error and "(exact)" in error for error in errors)


# Re-review's in-memory bypass: omit unlock, subsequent main-thread calls,
# and startup umask; a later clean publication must not hide attempt 1.
def test_collect_review_missing_boundary_and_umask_bypass(monkeypatch, tmp_path):
    lines, collector, plan = deadline_helper_capture()
    boundary = first_helper_line(lines, r'flock\(.*snapshot.lock>.*LOCK_UN')
    main = lines[boundary].split()[0]
    lines = [line for i, line in enumerate(lines)
             if (i < boundary or line.split()[0] != main)
             and not (line.split()[0] == main and ('umask(' in line or '<... umask resumed>' in line))]
    with pytest.raises(AssertionError, match="missing snapshot unlock boundary") as error:
        run_helper_captures(monkeypatch, tmp_path, [(lines, collector, plan), helper_stage_case("collect")])
    assert "prefix.umask: measured 0, formula 1 (exact)" in str(error.value)
    assert not (tmp_path / "collect" / "attempt-2").exists(), "must fail before the clean second attempt"
    # 이것을 실패시키는 것: 판정 실패 시 trace나 실패 이전 계수를 삭제하는 것.
    import json
    artifacts = tmp_path / "collect" / "attempt-1"
    evidence = json.loads((artifacts / "attempt.json").read_text())
    assert evidence["collector_exit"] == 75 and evidence["published"] is False
    assert evidence["prefix_complete"] is False
    assert evidence["phase_counts"]["prefix"].get("umask", 0) == 0
    assert evidence["phase_expected"]["prefix"]["umask"] == 1
    assert set(evidence["phase_counts"]) == {"prefix", "supervisor", "finish_gc"}
    assert "missing snapshot unlock boundary" in evidence["failure"]
    assert (artifacts / "trace.strace").read_text().splitlines() == lines
    assert not (tmp_path / "1").exists(), "product fixture should be cleaned up"


def test_collect_counted_events_preserve_all_helper_counts():
    from collections import Counter
    for stage in STAGE_NAMES:
        lines, collector, _ = helper_stage_case(stage)
        _, roles = budget.measured_helper_attribution(lines, HELPER_EXE, collector)
        assert Counter(kind for _, kind in roles.helper_calls) == roles.counts["helper"]


# 이것을 실패시키는 것: 반환 바이트 대신 요청량, 사본별 ceil 대신 전체 합, metadata 읽기 또는 재읽기 허용.
def front_read_control(case='checksum-last-good'):
    attempts = budget.front_attempt_plan(case, 16385)
    lines = []
    for a in attempts:
        path = '/store/' + ('snapshot' if a.copy == 'current' else 'last-good')
        chunks = [64] + ([128] if a.prefix_read else []) + ([16384, 1] if a.body_bytes_read else [])
        lines += [f'1 read(3<{path}>, "x"..., {n}) = {n}' for n in chunks]
    lines += ['1 read(4</store/marker>, "x"..., 208) = 208',
              '1 read(5</proc/sys/kernel/random/boot_id>, "x"..., 38) = 37',
              '1 read(5</proc/sys/kernel/random/boot_id>, "", 1) = 0']
    return lines, attempts


@pytest.mark.parametrize('case', budget.FRONT_CASES)
def test_front_read_control_accepts_each_attempt(case):
    lines, attempts = front_read_control(case)
    budget.assert_front_reads(budget.parse_trace('\n'.join(lines)), Path('/store'), attempts)


# 이것을 실패시키는 것: TrustMetadata 읽기·last-good 뒤 재읽기·부분 캡처를 통과시키는 것.
@pytest.mark.parametrize('mutation', ['metadata', 'reread', 'missing-prefix', 'missing-boot-eof', 'borrow-bytes'])
def test_front_read_control_rejects_mutations(mutation):
    lines, attempts = front_read_control()
    if mutation == 'metadata':
        lines.insert(4, '1 read(3</store/snapshot>, "trust", 5) = 5')
    elif mutation == 'reread':
        lines.append('1 read(3</store/snapshot>, "x"..., 64) = 64')
    elif mutation == 'missing-prefix':
        del lines[1]
    elif mutation == 'missing-boot-eof':
        lines.pop()
    else:
        lines[3] = lines[3].replace(', 1) = 1', ', 2) = 2')
        lines[7] = lines[7].replace(', 1) = 1', ', 1) = 0')
    with pytest.raises(AssertionError, match='front read sequence'):
        budget.assert_front_reads(budget.parse_trace('\n'.join(lines)), Path('/store'), attempts)


# 이것을 실패시키는 것: libc별 fd facts를 무시하거나 유사한 경로 stat으로 대체하는 것.
@pytest.mark.parametrize('primitive', [
    'fstat(3</store/snapshot>, {st_size=1})',
    'newfstatat(3</store/snapshot>, "", {st_size=1}, AT_EMPTY_PATH)',
    'statx(3</store/snapshot>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_size=1})',
])
def test_front_platform_facts_counted(primitive):
    call = budget.parse_trace('1 ' + primitive + ' = 0')[0]
    assert budget.front_fact_kind(call) == 'fstat'
    if call.name != 'fstat':
        call.args = call.args.replace('""', '"sibling"')
        with pytest.raises(AssertionError, match='unexpected front facts primitive'):
            budget.front_fact_kind(call)


# 이것을 실패시키는 것: fixture의 청크 메타데이터만 바꾸어 제품 청크 변경을 감추는 것.
def test_front_chunk_metadata_mutation(monkeypatch):
    monkeypatch.setattr(budget, 'FRONT_CHUNK', 8192)
    with pytest.raises(AssertionError):
        budget.test_front_chunk_matches_product_constant()


def front_axis_control():
    """Synthetic syscall control, not a substitute for the required live capture."""
    pinned = ['/run', '/config', '/state']
    dirs, files = budget.prompt_sources(pinned)
    store = Path(next(iter(files))).parent
    lines = ['1 execve("/bin/bingsu", ["/bin/bingsu", "prompt", "--pwd", "/repo"], []) = 0']
    lines += ['1 openat(AT_FDCWD, "/proc/self/fd", O_RDONLY|O_DIRECTORY) = 3</proc/1/fd>',
              '1 close(3</proc/1/fd>) = 0']
    fd = 2
    boot = ['/', '/proc', '/proc/1', '/proc/1/ns', '/proc/1/timens_offsets',
            '/proc/sys', '/proc/sys/kernel', '/proc/sys/kernel/random', '/proc/sys/kernel/random/boot_id']
    for path, fallback in [(p, True) for p in sorted(dirs)] + [(p, False) for p in sorted(files)] + [(p, p == '/') for p in boot]:
        fd += 1
        lines += [f'1 openat(AT_FDCWD, "{path}", O_RDONLY) = {fd}<{path}>',
                  f'1 fstat({fd}<{path}>, {{st_size=1}}) = 0',
                  f'1 fstatfs({fd}<{path}>, {{f_type=EXT4_SUPER_MAGIC}}) = 0',
                  f'1 fgetxattr({fd}<{path}>, "system.posix_acl_access", NULL, 0) = -1 ENODATA (No data)']
        if fallback:
            lines += [f'1 getxattr("/proc/self/fd/{fd}", "system.posix_acl_access", NULL, 0) = -1 ENODATA (No data)']
    for name in ('self', 'time', 'time_for_children'):
        lines += [f'1 readlinkat({fd}<{boot[-1]}>, "{name}", "x", 10) = 1']
    collection, _ = budget.prompt_collection_sources(pinned, b'/repo')
    lines += [f'1 openat(AT_FDCWD, "{min(collection, key=len)}", O_RDONLY) = -1 ENOENT (No file)',
              '1 prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {}) = 0']
    reads, attempts = front_read_control('normal')
    # Use the actual file descriptors: the counter must attribute every read.
    for line in reads:
        line = line.replace('/store/', str(store) + '/')
        path = budget.args_of(budget.parse_trace(line)[0])[0].split('<')[1][:-1]
        opened = next(l for l in lines if l.startswith('1 openat(') and l.endswith('<' + path + '>'))
        number = opened.split(' = ')[1].split('<')[0]
        line = budget.re.sub(r'read\(\d+<', 'read(' + number + '<', line)
        lines.append(line)
    lines += ['1 +++ exited with 0 +++']
    return lines, pinned, store, attempts


# 이것을 실패시키는 것: 정상 종료 레코드를 syscall로 세거나 open/facts/read 누락·중복을 숨기는 것.
@pytest.mark.parametrize('arch', ['aarch64', 'x86_64'])
@pytest.mark.parametrize('mutation', ['none', 'extra-open', 'extra-facts', 'missing-read', 'failed-filter', 'untracked-read', 'extra-seek'])
def test_front_axis_capture_counter(monkeypatch, arch, mutation):
    lines, pinned, store, attempts = front_axis_control()
    # Path confinement has its own live/portable suite; isolate the new counter.
    monkeypatch.setattr(budget, 'prompt_root_io', lambda *args: None)
    if mutation == 'extra-open':
        lines.insert(1, '1 openat(AT_FDCWD, "/run", O_RDONLY) = 99</run>')
    elif mutation == 'extra-facts':
        lines.insert(-1, next(l for l in lines if ' fstat(' in l))
    elif mutation == 'missing-read':
        lines.remove(next(l for l in lines if ' read(' in l))
    elif mutation == 'failed-filter':
        lines = [l.replace('MODE_FILTER, {}) = 0', 'MODE_FILTER, {}) = -1 EINVAL (Invalid)') for l in lines]
    elif mutation == 'untracked-read':
        lines.insert(1, '1 read(99</proc/1/maps>, "", 1024) = 0')
    elif mutation == 'extra-seek':
        lines.insert(1, '1 lseek(99</proc/1/maps>, 0, SEEK_CUR) = 0')
    if mutation == 'none':
        budget.check_front_capture(lines, '/bin/bingsu', pinned, store, attempts, arch=arch, libc='musl', evidence={})
    else:
        with pytest.raises(AssertionError):
            budget.check_front_capture(lines, '/bin/bingsu', pinned, store, attempts, arch=arch, libc='musl', evidence={})


# A2 keep-musl/unchanged.strace PID 1838, normalized fd/inode/PID.
# Successful parent channel: pipe2, clone, close writer, EOF read, close reader.
@pytest.mark.parametrize('arch', ['aarch64', 'x86_64'])
@pytest.mark.parametrize('libc', ['gnu', 'musl'])
@pytest.mark.parametrize('spawn', [False, True])
@pytest.mark.parametrize('mutation', [
    'none', 'extra-read', 'missing-read', 'missing-pipe', 'missing-close',
    'extra-pipe', 'wrong-size', 'non-eof', 'late-pipe',
])
def test_front_spawn_pipe_counter(monkeypatch, arch, libc, spawn, mutation):
    lines, pinned, store, attempts = front_axis_control()
    monkeypatch.setattr(budget, 'prompt_root_io', lambda *args: None)
    if libc == 'gnu':
        startup = []
        for fd, path, reads in [(80, '/etc/ld.so.cache', 0),
                                (81, '/lib/libgcc_s.so.1', 1),
                                (82, '/lib/libc.so.6', 1),
                                (83, '/proc/1/maps', 3)]:
            startup += [f'1 openat(AT_FDCWD, "{path}", O_RDONLY) = {fd}<{path}>']
            startup += [f'1 read({fd}<{path}>, "x", 1) = 1'] * reads
            if arch == 'x86_64' and fd == 82:
                startup += [f'1 pread64({fd}<{path}>, "x", 1, 0) = 1'] * 2
            if arch == 'x86_64' and fd == 83:
                startup += [f'1 lseek({fd}<{path}>, 0, SEEK_CUR) = 0',
                            f'1 lseek({fd}<{path}>, 0, SEEK_SET) = 0']
            startup += [f'1 close({fd}<{path}>) = 0']
        lines[1:1] = startup
    pipe = '1 pipe2([90<pipe:[525252]>, 91<pipe:[525252]>], O_CLOEXEC) = 0'
    read = '1 read(90<pipe:[525252]>, "", 4) = 0'
    close = '1 close(90<pipe:[525252]>) = 0'
    channel = ([pipe] if libc == 'musl' and spawn else [])
    if spawn:
        channel += ['1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 2']
    if libc == 'musl' and spawn:
        channel += ['1 close(91<pipe:[525252]>) = 0', read, close]
    baseline = lines.copy()
    boundary = next(i for i, l in enumerate(baseline) if 'PR_SET_SECCOMP' in l)
    baseline[boundary:boundary] = channel
    budget.check_front_capture(baseline, '/bin/bingsu', pinned, store, attempts,
                               arch=arch, libc=libc, evidence={})
    if mutation == 'extra-read':
        channel.insert(-1, read)
    elif mutation == 'missing-read':
        channel = [l for l in channel if l != read]
    elif mutation == 'missing-pipe':
        channel = [l for l in channel if l != pipe]
    elif mutation == 'missing-close':
        channel = [l for l in channel if l != close]
    elif mutation == 'extra-pipe':
        channel.insert(0, pipe)
    elif mutation == 'wrong-size':
        channel = [l.replace('"", 4)', '"", 8)') for l in channel]
    elif mutation == 'non-eof':
        channel = [l.replace('"", 4) = 0', '"x", 4) = 1') for l in channel]
    boundary = next(i for i, l in enumerate(lines) if 'PR_SET_SECCOMP' in l)
    lines[boundary + (mutation == 'late-pipe'):boundary + (mutation == 'late-pipe')] = channel
    evidence = {}
    changed = (mutation in ('extra-read', 'extra-pipe')
               or libc == 'musl' and spawn and mutation != 'none')
    if changed:
        with pytest.raises(AssertionError):
            budget.check_front_capture(lines, '/bin/bingsu', pinned, store, attempts,
                                       arch=arch, libc=libc, evidence=evidence)
    else:
        budget.check_front_capture(lines, '/bin/bingsu', pinned, store, attempts,
                                   arch=arch, libc=libc, evidence=evidence)
        expected = {'pipe2': 1, 'read': 1, 'close': 2} if libc == 'musl' and spawn else {}
        assert evidence['spawn_pipe_counts'] == expected
        assert evidence['spawn_pipe_expected'] == expected


# 이것을 실패시키는 것: 실제 aarch64 glibc 캡처의 kernel 9개 facts/ACL fallback/EOF 비용을 누락하는 것.
@pytest.mark.parametrize('capture,base', [
    (0, '/home/tester/pt/test_prompt_binary_names_only_0'),
    (1, '/home/tester/pt/test_prompt_binary_names_only_1'),
])
@pytest.mark.parametrize('arch', ['aarch64', 'x86_64'])
@pytest.mark.parametrize('mutation', [
    'reread', 'mmap', 'unknown', 'startup-read', 'startup-open', 'untracked-read',
    'extra-seek', 'missing-seek', 'snapshot-seek', 'reverse-seeks', 'extra-pread',
])
def test_front_axis_archived_capture(capture, base, arch, mutation):
    lines = Path(__file__).with_name('fixtures').joinpath(f'prompt-e4-linux-{capture}.strace').read_text().splitlines()
    pinned = [base + suffix for suffix in ('/run-t/bingsu', '/cfg-t/bingsu', '/state-t/bingsu')]
    _, files = budget.prompt_sources(pinned)
    store = Path(next(iter(files))).parent
    # Published fixture's compiled body is 3008 bytes, not inferred from reads.
    attempts = budget.front_attempt_plan('normal', 3008)
    maps_close = next(i for i, l in enumerate(lines) if ' close(3</proc/' in l and '/maps>' in l)
    pid = lines[maps_close].split()[0]
    # Legacy E4 captured two maps reads. Current A2 release front has three
    # (keep/unchanged.strace pid 1130); CI x86_64 has three too (A2 report).
    # Replay current startup on this older product-axis fixture explicitly.
    lines.insert(maps_close, f'{pid} read(3</proc/{pid}/maps>, "<payload>", 1024) = 858')
    maps_close += 1
    seek_pair = [f'{pid} lseek(3</proc/{pid}/maps>, 0, SEEK_CUR) = 2906',
                 f'{pid} lseek(3</proc/{pid}/maps>, 2822, SEEK_SET) = 2822']
    if arch == 'x86_64':
        lines[maps_close:maps_close] = seek_pair
        libc_close = next(i for i, l in enumerate(lines) if ' close(3<' in l and '/libc.so.6>' in l)
        # Replay x86_64 loader program-header reads; this is no live capture.
        lines[libc_close:libc_close] = [f'{pid} pread64(3</lib/x86_64-linux-gnu/libc.so.6>, "<payload>", 784, 64) = 784'] * 2
        maps_close += 2
    budget.check_front_capture(lines, base + '/bin/bingsu', pinned, store, attempts, arch=arch, libc='gnu', evidence={})
    # 이것을 실패시키는 것: last-good 뒤 재읽기와 같은 추가 current 읽기를 live 판정기가 허용하는 것.
    extra = next(l for l in lines if ' read(' in l and str(store / 'snapshot') + '>' in l)
    pid = extra.split()[0]
    if mutation == 'mmap':
        extra = f'{pid} mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3<{store / "snapshot"}>, 0) = 0x1000'
    elif mutation == 'unknown':
        extra = f'{pid} io_uring_setup(1, {{}}) = 99'
    if mutation == 'startup-read':
        lines.insert(maps_close, next(l for l in lines if ' read(3</proc/' in l and '/maps>' in l))
    elif mutation == 'startup-open':
        at = next(i for i, l in enumerate(lines) if ' close(3</etc/ld.so.cache>' in l)
        lines[at + 1:at + 1] = [next(l for l in lines if ' openat(' in l and '"/etc/ld.so.cache"' in l), lines[at]]
    elif mutation == 'untracked-read':
        # A permitted system path must not hide an fd that was never opened.
        lines.insert(maps_close, f'{pid} read(99</proc/{pid}/maps>, "", 1024) = 0')
    elif mutation == 'extra-seek':
        lines.insert(maps_close, seek_pair[0])
    elif mutation == 'missing-seek':
        if arch == 'x86_64':
            lines.remove(seek_pair[0])
        else:
            lines.insert(maps_close, seek_pair[1])
    elif mutation == 'reverse-seeks':
        if arch == 'x86_64':
            lines[maps_close:maps_close + 2] = seek_pair[::-1]
        else:
            lines[maps_close:maps_close] = seek_pair[::-1]
    elif mutation == 'extra-pread':
        lines.insert(maps_close, f'{pid} pread64(3</proc/{pid}/maps>, "", 1024, 0) = 0')
    elif mutation == 'snapshot-seek':
        lines.insert(-1, f'{pid} lseek(3<{store / "snapshot"}>, 0, SEEK_CUR) = 0')
    else:
        lines.insert(-1, extra)
    with pytest.raises(AssertionError):
        budget.check_front_capture(lines, base + '/bin/bingsu', pinned, store, attempts, arch=arch, libc='gnu', evidence={})
