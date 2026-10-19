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


H2_BASE = "/home/USER/pt/CASE_BUILD_IDENTITY_TRACE_0000000"
H2_EXE = H2_BASE + "/bin/bingsu"
H2_ROOTS = [H2_BASE + suffix for suffix in (
    "/run-t/bingsu", "/cfg-t/bingsu", "/state-t/bingsu", "/state-t/bingsu/log",
)]
H2_TARGET = "/home/USER/target/debug/bingsu"


@pytest.fixture(scope="module")
def h2_trace():
    """Unprojected c4da804 non-root capture; see fixtures/prompt-h2-trace.md."""
    return Path(__file__).with_name("fixtures").joinpath(
        "prompt-h2-debian-bookworm-glibc-aarch64.strace"
    ).read_text().splitlines()


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
    ).read_text().splitlines()


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
