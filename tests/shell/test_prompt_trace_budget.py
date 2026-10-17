"""Portable regression/mutation fixtures for the Linux strace gate."""
from pathlib import Path

import pytest

import test_prompt_env_paths as budget
from test_prompt_env_paths import assert_prompt_trace_budget

EXE = "/pinned/bin/bingsu"
ROOTS = ["/pinned/run", "/pinned/config", "/pinned/state"]


@pytest.fixture(scope="module")
def debian_trace():
    """Real strace -f -q -y -s 65536 -e trace=all, Debian bookworm glibc aarch64.

    Captured as non-root tester by the binary-path test (target/linux-trace/trace2.txt),
    after the state-root fix, with a fresh state home.
    USER/CASE/SOURCE/TRACE_HOST replace machine paths/host; encoded context path
    components are normalized too, preserving their observed chunk boundaries.
    All 3012 records, including shell setup, are retained. The helper creates
    state-t/bingsu with 0700, executes the pinned __collect-v1, revalidates
    config absence and publishes snapshot/marker; both processes exit with 0.
    """
    return Path(__file__).with_name("fixtures").joinpath(
        "prompt-debian-bookworm-glibc-aarch64.strace"
    ).read_text().splitlines()


DEBIAN_BASE = "/home/USER/pt/CASE"
DEBIAN_EXE = DEBIAN_BASE + "/bin/bingsu"
DEBIAN_ROOTS = [DEBIAN_BASE + suffix for suffix in (
    "/run-t/bingsu", "/cfg-t/bingsu", "/state-t/bingsu", "/state-t/bingsu/log",
)]


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
    assert any(c.pid == 1950 and budget.fixed_exec(c, DEBIAN_EXE, "__collect-v1")
               for c in calls if c.name == "execve")
    for stage, final in ((".snapshot.stage", "snapshot"), (".marker.stage", "marker")):
        assert any(c.pid == 1948 and c.name == "renameat" and c.ret == "0"
                   and budget.args_of(c)[1] == f'"{stage}"'
                   and budget.args_of(c)[3] == f'"{final}"' for c in calls)
    assert {c.pid for c in calls if c.name == budget.EXIT_EVENT and c.args == "exited with 0"} == set(map(int, pids))


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
                        verb != "__collect-v1" and original(call, exe, verb))
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
        '11 openat(9</proc/11/ns>, "time", O_RDONLY) = 10<time:[4026531834]>',
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
        '13 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "__collect-v1"], []) = 0',
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
    ('"__collect-v1"', '"__other"'),
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
                            verb != "__collect-v1" and original(call, exe, verb))
    else:
        monkeypatch.setattr(budget, allowance, lambda *args: False)
    with pytest.raises(AssertionError):
        assert_prompt_trace_budget(valid_trace(), EXE, ROOTS)


def test_trace_needs_created_ancestor_open_allowance(monkeypatch):
    monkeypatch.setattr(budget, "helper_created_open", lambda *args: False)
    with pytest.raises(AssertionError, match="helper path"):
        test_fresh_state_parent_creation_budget()


@pytest.mark.parametrize("old,new", [
    ('"__collect-v1"], []', '"__collect-v1", "extra"], []'),
    ('13 execve("/pinned/bin/bingsu"', '13 execve("/other/bin/bingsu"'),
    ('"__collect-v1"], []', '"__collect-v1"], 0x3 /* 1 vars */'),
])
def test_trace_rejects_collector_exec_contract_mutation(old, new):
    original = valid_trace()
    mutated = [line.replace(old, new) for line in original]
    assert mutated != original
    with pytest.raises(AssertionError, match="execve"):
        assert_prompt_trace_budget(mutated, EXE, ROOTS)


# 이것을 실패시키는 것: open_flags가 O_LARGEFILE을 남기는 것.
def test_walk_step_accepts_x86_64_largefile_flag():
    import test_prompt_env_paths as t
    line = '9 openat(AT_FDCWD</>, "/", O_RDONLY|O_LARGEFILE|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY) = 3</>'
    call = next(c for c in t.parse_trace(line) if c.name == "openat")
    assert t.helper_walk_step(call, "/", ["/root/x/run-t/bingsu"])
