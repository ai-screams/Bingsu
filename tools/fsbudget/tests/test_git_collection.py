"""F1 trace mutations; the primitive model is shared with the B3 gate."""
from pathlib import Path

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


# The shipped collector writes no F1_PHASE markers. The collector task (its pid's
# records) of tests/shell/fixtures/prompt-m3d-collect-linux-1.strace.gz: a
# Bookworm/aarch64 release prompt with a warm snapshot in a hand-made repository.
SHIPPED = Path(__file__).parent / "fixtures/m3d-bookworm-aarch64-shipped-collection.strace"
SHIPPED_REPO = "/home/tester/pt/test_prompt_binary_names_only_1/repo"
SHIPPED_CAPS = {"mode": "shipped", "roots": [SHIPPED_REPO, SHIPPED_REPO + "/.git"],
                "evidence": [SHIPPED_REPO + "/.git/HEAD"]}


def shipped_lines():
    return SHIPPED.read_text().splitlines()


def after_root_open(lines, extra):
    """Insert after the discovery walk's "/" open, inside the request window."""
    walk = next(i for i, line in enumerate(lines) if 'openat(AT_FDCWD</>, "/", O_RDONLY|O_NONBLOCK|O_NOFOLLOW' in line)
    at = next(i for i in range(walk, len(lines)) if lines[i].endswith("= 4</>"))
    return lines[:at + 1] + extra + lines[at + 1:]


def test_shipped_collection_trace_passes_without_phase_markers():
    phases = {}
    assert_repository_trace(shipped_lines(), SHIPPED_CAPS, phases)
    assert set(phases) == {"shipped"} and phases["shipped"]["openat2"] > 0


# 이것을 실패시키는 것: 출하 창에서 "/"·조상 폴더의 목록 읽기나 내용 read, roots 밖 open, 쓰기 open,
# roots가 아닌 Landlock 규칙, "/" 아닌 조상의 O_DIRECTORY 없는 open, identity 전용 "/" fd의 하위 open·하위 stat·fstatfs·dup, 출하 창 미완료(collector exit 없음·다른
# pid의 exit·요청 읽기 없음), collector exit 뒤의 호출, readv(3)로 시작한 창, 저장소 작업이 없는 창, HEAD를 빈 read로만 본 창을 허용하는 것.
@pytest.mark.parametrize("damage", [
    "root-getdents", "root-read", "ancestor-getdents", "ancestor-read", "outside-open",
    "writable-open", "landlock-outside", "no-exit", "foreign-exit", "after-exit", "no-request",
    "ancestor-open-without-directory", "readv-first", "no-repository-work", "empty-head-read", "identity-fd-walk", "identity-fd-statfs", "identity-fd-dup", "identity-fd-child-stat"])
def test_shipped_collection_trace_rejects_mutations(damage):
    lines = shipped_lines()
    home = '1098  openat(4</>, "home", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 30</home>'
    if damage == "root-getdents":
        lines = after_root_open(lines, ['1098  getdents64(4</>, 0xffff00000000 /* 3 entries */, 8192) = 72'])
    elif damage == "root-read":
        lines = after_root_open(lines, ['1098  read(4</>, "", 32) = 0'])
    elif damage == "ancestor-getdents":
        lines = after_root_open(lines, [home, '1098  getdents64(30</home>, 0xffff00000000 /* 3 entries */, 8192) = 72'])
    elif damage == "ancestor-read":
        lines = after_root_open(lines, [home, '1098  read(30</home>, "", 32) = 0'])
    elif damage == "outside-open":
        lines = after_root_open(lines, ['1098  openat(AT_FDCWD</>, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 30</etc/passwd>'])
    elif damage == "writable-open":
        lines = after_root_open(lines, [f'1098  openat(AT_FDCWD</>, "{SHIPPED_REPO}/x", O_WRONLY|O_CREAT|O_CLOEXEC, 0600) = 30<{SHIPPED_REPO}/x>'])
    elif damage == "landlock-outside":
        lines = [line.replace(f"parent_fd=10<{SHIPPED_REPO}>", "parent_fd=10</home>") for line in lines]
    elif damage == "no-exit":
        lines = [line for line in lines if "+++ exited" not in line]
    elif damage == "foreign-exit":
        lines = [line.replace("1098  +++ exited", "1200  +++ exited") for line in lines]
    elif damage == "after-exit":
        lines = lines + ['1101  openat(AT_FDCWD</>, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3</etc/passwd>']
    elif damage == "no-request":
        lines = [line.replace("read(3<pipe:", "read(9<pipe:") for line in lines]
    elif damage == "ancestor-open-without-directory":
        lines = [line.replace('openat(4</>, "home", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY',
                              'openat(4</>, "home", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC') for line in lines]
    elif damage == "readv-first":
        # Review reproduction: a readv on the request fd hands the collector to
        # the audit, then an outside read precedes the usual request read.
        at = next(i for i, line in enumerate(lines) if line.startswith("1098  read(3<pipe:"))
        lines = lines[:at] + [f'1098  readv({lines[at].split("(", 1)[1].split(",")[0]}, [{{iov_base="", iov_len=1}}], 1) = 0',
                              '1098  openat(AT_FDCWD</>, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 30</etc/hostname>',
                              '1098  read(30</etc/hostname>, "x\\n", 64) = 2',
                              '1098  close(30</etc/hostname>) = 0'] + lines[at:]
    elif damage == "no-repository-work":
        # Every call between the request reads and the exit removed.
        last = max(i for i, line in enumerate(lines) if line.startswith("1098  read(3<pipe:"))
        assert lines[last + 1].startswith("1098  <... read resumed>"), lines[last + 1]
        lines = lines[:last + 2] + [line for line in lines if "+++ exited" in line]
    elif damage == "empty-head-read":
        lines = [line.replace('"ref: refs/heads/main\\n", 22) = 21', '"", 22) = 0') for line in lines]
    elif damage.startswith("identity-fd-"):
        extra = {"identity-fd-walk": '1098  openat(6</>, "home", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 30</home>',
                 "identity-fd-statfs": '1098  fstatfs(6</>, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096}) = 0',
                 "identity-fd-dup": '1098  dup(6</>) = 30</>',
                 "identity-fd-child-stat": '1098  newfstatat(6</>, "home", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0'}[damage]
        at = next(i for i, line in enumerate(lines) if line.startswith('1098  openat(AT_FDCWD</>, "/", O_RDONLY|O_CLOEXEC <'))
        lines = lines[:at + 2] + [extra] + lines[at + 2:]
    assert lines != shipped_lines()
    with pytest.raises(AssertionError):
        assert_repository_trace(lines, SHIPPED_CAPS, {})
