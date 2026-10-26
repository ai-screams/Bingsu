"""F1 trace mutations; the primitive model is shared with the B3 gate."""
import pytest

from fsbudget.attribute import assert_repository_trace
from fsbudget.classify import collector_kind
from fsbudget.formula import CollectorAxes, collector_repository_expected
from fsbudget.strace_parse import parse


def marker(name):
    return f'12 write(1<pipe:[1]>, "F1_PHASE {name}\\n", 32) = 32'


CAPS = {"repo": "/home/repo", "roots": ["/home/repo", "/metadata/worktrees/linked", "/metadata/common"],
        "names": ["/home"], "forbidden": ["/outside", "/home/repo/sub"]}
ACQUIRE = [marker("acquisition"),
           '12 openat(AT_FDCWD</>, "/", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 7</>',
           '12 openat(7</>, "home", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 8</home>',
           '12 openat(8</home>, "repo", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = 9</home/repo>']
CONTENT = [marker("stage_a_head"), marker("path_facts"), marker("ancestor_names"),
           '12 getdents64(8</home>, [{d_ino=1, d_off=1, d_reclen=24, d_type=DT_DIR, d_name="repo"}], 8192) = 24',
           '12 getdents64(8</home>, [], 8192) = 0', marker("before_read_layer"), marker("preflight_start"),
           '12 openat2(9</home/repo>, "tracked", {flags=O_RDONLY|O_CLOEXEC, resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV}, 24) = 10</home/repo/tracked>',
           '12 fstat(10</home/repo/tracked>, {st_mode=S_IFREG|0644}) = 0',
           '12 read(10</home/repo/tracked>, "data", 5) = 4',
           '12 read(10</home/repo/tracked>, "", 1) = 0',
           '12 close(10</home/repo/tracked>) = 0', marker("end")]


# 이것을 실패시키는 것: role classifier가 NON_FS 때문에 실패한 생성/네트워크를 버리는 것.
@pytest.mark.parametrize("effect,call", [
    ("spawn", 'fork()'), ("spawn", 'vfork()'),
    ("spawn", 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD)'),
    ("spawn", 'clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88)'),
    ("exec", 'execve("/bin/true", ["/bin/true"], 0x0 /* 0 vars */)'),
    ("exec", 'execveat(4</bin/true>, "", ["true"], 0x0, AT_EMPTY_PATH)'),
    ("network", 'socket(AF_INET, SOCK_STREAM, 0)'),
    ("network", 'connect(4<socket:[1]>, {sa_family=AF_INET}, 16)'),
    ("network", 'sendto(4<socket:[1]>, "x", 1, 0, NULL, 0)'),
    ("network", 'recvmsg(4<socket:[1]>, {msg_name=NULL}, 0)'),
    ("network", 'socketpair(AF_UNIX, SOCK_STREAM, 0, [4, 5])'),
    ("network", 'bind(4<socket:[1]>, {sa_family=AF_INET}, 16)'),
    ("network", 'listen(4<socket:[1]>, 1)'),
    ("network", 'accept(4<socket:[1]>, NULL, NULL)'),
    ("network", 'accept4(4<socket:[1]>, NULL, NULL, SOCK_CLOEXEC)'),
    ("network", 'sendmsg(4<socket:[1]>, {msg_name=NULL}, 0)'),
    ("network", 'sendmmsg(4<socket:[1]>, [], 0, 0)'),
    ("network", 'recvfrom(4<socket:[1]>, "", 1, 0, NULL, NULL)'),
    ("network", 'recvmmsg(4<socket:[1]>, [], 0, 0, NULL)'),
    ("network", 'shutdown(4<socket:[1]>, SHUT_RDWR)'),
    ("network", 'getsockname(4<socket:[1]>, NULL, NULL)'),
    ("network", 'getpeername(4<socket:[1]>, NULL, NULL)'),
    ("network", 'setsockopt(4<socket:[1]>, SOL_SOCKET, SO_REUSEADDR, [1], 4)'),
    ("network", 'getsockopt(4<socket:[1]>, SOL_SOCKET, SO_REUSEADDR, 0x0, 0x0)'),
])
@pytest.mark.parametrize("result", ["-1 EPERM (Operation not permitted)", "-1 ENOSYS (Function not implemented)", "0"])
def test_no_spawn_harness_counts_attempts(effect, call, result):
    line = f"12 {call} = {result}"
    parsed = parse(line)
    assert not parsed.errors
    assert collector_kind(parsed[0]) == effect
    with pytest.raises(AssertionError, match="forbidden repository effect"):
        assert_repository_trace(ACQUIRE + [line] + CONTENT, CAPS, {})


# 이것을 실패시키는 것: failed outside open, linked metadata의 부모, closed fd, alias.
@pytest.mark.parametrize("line,message", [
    ('12 openat(9</home/repo>, "/outside/sentinel", O_RDONLY) = -1 EPERM', "outside"),
    ('12 openat(9</home/repo>, "../../outside/sentinel", O_RDONLY) = -1 EPERM', "outside"),
    ('12 openat(9</home/repo>, "/metadata/worktrees/other/HEAD", O_RDONLY) = -1 ENOENT', "outside"),
    ('12 openat(9</home/repo>, "sub", O_RDONLY|O_DIRECTORY) = -1 EPERM', "forbidden"),
    ('12 read(10</home/repo/tracked>, "", 1) = -1 EBADF', "closed"),
    ('12 read(9</home/repo/different>, "", 1) = -1 EPERM', "alias"),
    ('12 read(11</home/repo/tracked>, "", 1) = -1 EBADF', "unheld"),
    ('12 openat(9</home/repo>, "tracked", O_RDONLY|O_TRUNC) = -1 EPERM', "write open"),
])
def test_trace_rejects_outside_root_even_on_eperm(line, message):
    assert_repository_trace(ACQUIRE + CONTENT, CAPS, {})
    with pytest.raises(AssertionError, match=message):
        assert_repository_trace(ACQUIRE + CONTENT[:-1] + [line, CONTENT[-1]], CAPS, {})


# 이것을 실패시키는 것: U2 names-only 권한을 stat/open/더 넓은 Landlock root로 바꾸는 것.
@pytest.mark.parametrize("call,message", [
    ('newfstatat(8</home>, "other", {st_mode=S_IFREG|0600}, AT_SYMLINK_NOFOLLOW)', "outside|metadata"),
    ('openat(8</home>, ".", O_RDONLY|O_DIRECTORY)', "already-held"),
    ('read(8</home>, "", 1)', "metadata/content"),
    ('landlock_add_rule(6<anon_inode:[landlock-ruleset]>, LANDLOCK_RULE_PATH_BENEATH, {allowed_access=LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR, parent_fd=8</home>}, 0)', "widening"),
])
def test_ancestor_names_do_not_grant_content_or_entry_metadata(call, message):
    lines = ACQUIRE + CONTENT[:3] + [f"12 {call} = -1 EPERM"] + CONTENT[3:]
    with pytest.raises(AssertionError, match=message):
        assert_repository_trace(lines, CAPS, {})


# 이것을 실패시키는 것: raw 257번째 이름을 필터 뒤 세거나 phase 식의 EOF를 지우는 것.
def test_ancestor_raw_cap_and_phase_formula():
    phases = {"ancestor-names": {"phase": "ancestor-names", "directories": 1,
                                  "dir_bytes": (24,), "raw_entries": 1}}
    caps = {**CAPS, "axes": phases}
    assert_repository_trace(ACQUIRE + CONTENT, caps, {})
    with pytest.raises(AssertionError, match="ancestor-names"):
        assert_repository_trace(ACQUIRE + CONTENT[:4] + CONTENT[5:], caps, {})
    entries = ", ".join(f'{{d_name="hidden-{n}"}}' for n in range(257))
    # A returned batch may exceed the cap. Only processed raw slots count;
    # the adapter must stop before slot 257 or a further getdents call.
    batch = [f'12 getdents64(8</home>, [{entries}], 8192) = 8192']
    processed = [f'12 write(1<pipe:[1]>, "F1_RAW {n}\\n", 16) = 16' for n in range(1, 258)]
    assert_repository_trace(ACQUIRE + CONTENT[:3] + batch + processed[:256] + CONTENT[5:], CAPS, {})
    with pytest.raises(AssertionError, match="raw 256"):
        assert_repository_trace(ACQUIRE + CONTENT[:3] + batch + processed + CONTENT[5:], CAPS, {})
    with pytest.raises(AssertionError, match="raw 256"):
        assert_repository_trace(ACQUIRE + CONTENT[:3] + batch + processed[:256] + CONTENT[4:], CAPS, {})
    with pytest.raises(ValueError, match="names-only"):
        collector_repository_expected(CollectorAxes(phase="ancestor-names", directories=1, dir_bytes=(24,), files=1))
    with pytest.raises(ValueError, match="names-only"):
        collector_repository_expected(CollectorAxes(phase="ancestor-names", directories=33, dir_bytes=(24,) * 33))


# 이것을 실패시키는 것: phase를 섞거나 성공한 open 반환 경로를 검사하지 않는 것.
def test_repository_trace_checks_result_paths_order_and_missing_observation():
    with pytest.raises(AssertionError, match="outside"):
        assert_repository_trace(ACQUIRE + [line.replace('= 10</home/repo/tracked>', '= 10</outside/sentinel>') for line in CONTENT], CAPS, {})
    with pytest.raises(AssertionError, match="reversal"):
        assert_repository_trace(ACQUIRE + CONTENT + [marker("acquisition")], CAPS, {})
    with pytest.raises(AssertionError, match="missing repository"):
        assert_repository_trace([], CAPS, {})


def test_descriptor_dup_reuse_and_post_collection_attempts():
    duplicate = ['12 fcntl(9</home/repo>, F_DUPFD_CLOEXEC, 0) = 11</home/repo>',
                 '12 fstat(11</home/repo>, {st_mode=S_IFDIR|0700}) = 0',
                 '12 close(11</home/repo>) = 0']
    assert_repository_trace(ACQUIRE + CONTENT[:-1] + duplicate + CONTENT[-1:], CAPS, {})
    for changed in (
        duplicate[:1] + [duplicate[1].replace('11</home/repo>', '11</outside>')],
        duplicate + [duplicate[1]],
        ['12 fcntl(9</home/repo>, F_SETFD, FD_CLOEXEC) = 0'],
        ['12 openat(AT_FDCWD</>, "home/repo/tracked", O_RDONLY) = -1 EPERM'],
    ):
        with pytest.raises(AssertionError):
            assert_repository_trace(ACQUIRE + CONTENT[:-1] + changed + CONTENT[-1:], CAPS, {})
    for attempt in ('fork()', 'socket(AF_INET, SOCK_STREAM, 0)', 'read(9</home/repo>, "", 1)'):
        with pytest.raises(AssertionError):
            assert_repository_trace(ACQUIRE + CONTENT + [f'12 {attempt} = -1 EPERM'], CAPS, {})


def test_darwin_attempt_paths_and_descriptor_generations():
    hx = lambda s: s.encode().hex()
    caps = {"platform": "darwin", "roots": ["/home/repo"], "names": []}
    lines = ['F1_PHASE acquisition', f'F1_IO open {hx("/")} {hx("/home/repo")} 1048576 -2',
             f'F1_BIND 9 {hx("/home/repo")}', 'F1_PHASE stage_a_head',
             f'F1_IO fstat {hx("/home/repo")} - 0 9', 'F1_PHASE end']
    assert_repository_trace(lines, caps, {})
    for event in (f'F1_IO open {hx("/")} {hx("/outside/sentinel")} 0 -2',
                  f'F1_IO read {hx("/home/repo")} - 1 10',
                  f'F1_IO read {hx("/home/repo/alias")} - 1 9',
                  f'F1_IO open {hx("/")} {hx("/home/repo/file")} 1024 -2',
                  f'F1_BIND 10 {hx("/outside/sentinel")}',
                  f'F1_CLOSE 9\nF1_IO read {hx("/home/repo")} - 1 9'):
        with pytest.raises(AssertionError):
            assert_repository_trace(lines[:-1] + event.splitlines() + lines[-1:], caps, {})


# 이것을 실패시키는 것: repository 여유를 front/helper/startup 초과와 합산해 상쇄하는 것.
@pytest.mark.parametrize("role,kind", [("front", "openat"), ("helper", "read"),
                                       ("collector-startup", "exec"), ("collector", "network")])
def test_repository_budget_cannot_hide_other_role_surplus(role, kind):
    from copy import deepcopy
    from fsbudget.gate import check
    repository = collector_repository_expected(CollectorAxes(files=2, read_bytes=(16384, 16385)))
    expected = {"repository": repository, "front": {"openat": 5}, "helper": {"read": 3},
                "collector-startup": {"exec": 1}, "collector": {"network": 0, "read": 1}}
    measured = deepcopy(expected)
    assert check(measured, expected, "le", expected) == []
    measured["repository"] = {k: 0 for k in repository}
    measured[role][kind] += 1
    assert check(measured, expected, "le", expected) == [
        f"{role}.{kind}: measured {measured[role][kind]}, formula {expected[role][kind]} (le)"]
