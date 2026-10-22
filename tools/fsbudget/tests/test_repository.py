import pytest
from fsbudget.formula import CollectorAxes, collector_repository_expected, collector_success_expected
from fsbudget.attribute import collector_attribute

# 이것을 실패시키는 것: fast/stepwise 원시 계수를 섞거나 EOF·중복 root validation 비용을 빼는 것.
def test_repository_formula_uses_independent_primitive_axes():
    assert collector_repository_expected(CollectorAxes(files=1, read_bytes=(16384,))) == {
        'openat2': 1, 'fstat': 1, 'newfstatat': 0, 'fstatfs': 1, 'statx': 1,
        'readlinkat': 0, 'read': 2, 'getdents64': 0, 'mmap': 0, 'faccessat2': 0}
    assert collector_repository_expected(CollectorAxes(backend='stepwise', components=3, files=1, read_bytes=(16385,)))['newfstatat'] == 3
    assert collector_repository_expected(CollectorAxes(phase='read-layer', roots=2, root_inputs=3)) == {
        'openat': 1, 'fstat': 4, 'landlock_create_ruleset': 1, 'landlock_add_rule': 2, 'landlock_restrict_self': 1}
    assert collector_repository_expected(CollectorAxes(phase='probe', probes=1)) == {
        'openat': 1, 'openat2': 1, 'fstat': 1, 'fstatfs': 1, 'statx': 1}
    with pytest.raises(ValueError):
        collector_repository_expected(CollectorAxes(files=1))
    with pytest.raises(ValueError):
        collector_repository_expected(CollectorAxes(phase='read-layer', roots=4, root_inputs=4))
    assert collector_success_expected('shipped-debug', landlock=True, repository_probe=True)['fd_query'] == 10


PREFIX = '''10 execve("/b", ["/b", "prompt"], 0x0 /* 0 vars */) = 0
10 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 11
11 execve("/b", ["/b", "__refresh-v1"], 0x0 /* 0 vars */) = 0
11 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 12
12 execve("/c", ["/c", "__collect-v1"], 0x0 /* 0 vars */) = 0
12 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=1, filter=0x1}) = 0
12 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=1, filter=0x1}) = 0
'''
PROBE = '''12 openat(AT_FDCWD</>, "/", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 4</>
12 fstat(4</>, {st_mode=S_IFDIR|0755}) = 0
12 fstatfs(4</>, {f_type=EXT4_SUPER_MAGIC}) = 0
12 statx(4</>, "", AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH, STATX_MNT_ID, {stx_mask=STATX_MNT_ID, stx_mnt_id=1}) = 0
12 openat2(4</>, ".", {flags=O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY, resolve=RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH}, 24) = 6</>
12 close(6</>) = 0
12 close(4</>) = 0
'''

# 이것을 실패시키는 것: probe 예외를 필터 전·요청 뒤·다른 fd/path·중복 호출까지 넓히는 것.
def test_probe_trace_window_is_exact():
    def check(text):
        return collector_attribute(text.splitlines(), {'front': '/b', 'helper': '/b', 'collector': '/c'})
    good = check(PREFIX + PROBE)
    assert not good.errors
    assert {k: v for k, v in good.counts['collector'].items() if k.startswith('probe_')} == {
        'probe_openat': 1, 'probe_fstat': 1, 'probe_fstatfs': 1, 'probe_statx': 1, 'probe_openat2': 1}
    after_request = check(PREFIX + '12 read(3<pipe:[1]>, "request", 7) = 7\n' + PROBE)
    assert after_request.counts['collector'].get('probe_openat', 0) == 0
    for changed in [
        PREFIX.replace('12 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=1, filter=0x1}) = 0\n', '') + PROBE,
        PREFIX + '12 read(3<pipe:[1]>, "request", 7) = 7\n' + PROBE,
        PREFIX + PROBE.replace('"/"', '"/home"'),
        PREFIX + PROBE.replace('openat2(4</>', 'openat2(7</>'),
        PREFIX + PROBE.replace('"."', '"etc/passwd"'),
        PREFIX + PROBE + PROBE,
    ]:
        assert check(changed).errors, changed

# 이것을 실패시키는 것: 경로/phase/계수/금지 효과 검사를 없애는 것.
def test_repository_trace_checks_paths_counts_and_phases():
    from fsbudget.repository import check_repository_trace
    root = '/fixture'
    def marker(phase): return f'12 write(1<pipe:[9]>, "B3_PHASE {phase}\\n", 30) = 30\n'
    trace = marker('probe') + PROBE + marker('end')
    trace += marker('read-layer') + '''12 openat(AT_FDCWD</>, "/", O_RDONLY|O_CLOEXEC) = 4</>
12 fstat(4</>, {st_mode=S_IFDIR|0755}) = 0
12 fstat(7</fixture/worktree>, {st_mode=S_IFDIR|0755}) = 0
12 fstat(8</fixture/gitdir>, {st_mode=S_IFDIR|0755}) = 0
12 fstat(9</fixture/commondir>, {st_mode=S_IFDIR|0755}) = 0
12 landlock_create_ruleset({handled_access_fs=LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR}, 8, 0) = 6<anon_inode:[landlock-ruleset]>
'''
    for fd, name in [(7, 'worktree'), (8, 'gitdir'), (9, 'commondir')]:
        trace += f'12 landlock_add_rule(6<anon_inode:[landlock-ruleset]>, LANDLOCK_RULE_PATH_BENEATH, {{allowed_access=LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR, parent_fd={fd}</fixture/{name}>}}, 0) = 0\n'
    trace += '12 landlock_restrict_self(6<anon_inode:[landlock-ruleset]>, 0) = 0\n' + marker('end') + marker('content')
    trace += '''12 openat2(7</fixture/worktree>, "HEAD", {flags=O_RDONLY|O_NONBLOCK|O_CLOEXEC, resolve=RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH}, 24) = 10</fixture/worktree/HEAD>
12 fstat(10</fixture/worktree/HEAD>, {st_mode=S_IFREG|0644}) = 0
12 fstatfs(10</fixture/worktree/HEAD>, {f_type=EXT4_SUPER_MAGIC}) = 0
12 statx(10</fixture/worktree/HEAD>, "", AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH, STATX_MNT_ID, {stx_mask=STATX_MNT_ID, stx_mnt_id=1}) = 0
12 read(10</fixture/worktree/HEAD>, "sentinel", 65) = 8
12 read(10</fixture/worktree/HEAD>, "", 57) = 0
12 faccessat2(7</fixture/worktree>, ".", W_OK, AT_EACCESS) = 0
''' + marker('end')
    assert check_repository_trace(trace, root, 'openat2')['content']['read'] == 2
    for changed in [trace.replace('worktree/HEAD', 'outside/HEAD'),
                    trace.replace('O_RDONLY|O_NONBLOCK|O_CLOEXEC,', 'O_RDWR|O_NONBLOCK|O_CLOEXEC,'),
                    trace.replace('12 read(10</fixture/worktree/HEAD>, "", 57) = 0\n', ''),
                    trace.replace(marker('content'), marker('content') + '12 socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM\n'),
                    trace.replace(marker('read-layer'), marker('probe') + PROBE + marker('end') + marker('read-layer'))]:
        with pytest.raises(AssertionError):
            check_repository_trace(changed, root, 'openat2')
