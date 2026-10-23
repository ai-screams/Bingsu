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

METADATA = [
    'fstat(4</>, {st_mode=S_IFDIR|0755})',
    'fstat64(4</>, {st_mode=S_IFDIR|0755})',
    'newfstatat(4</>, "", {st_mode=S_IFDIR|0755}, AT_EMPTY_PATH)',
    'fstatat64(4</>, "", {st_mode=S_IFDIR|0755}, AT_EMPTY_PATH)',
    'statx(4</>, "", AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS})',
    'statx(4</>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mask=STATX_ALL|STATX_MNT_ID})',
]


# 이것을 실패시키는 것: libc별 fd metadata를 누락하거나 mount-id와 합쳐 중복/누락을 허용하는 것.
@pytest.mark.parametrize('metadata', METADATA)
@pytest.mark.parametrize('sync', ['', 'AT_STATX_SYNC_AS_STAT|'])
def test_probe_metadata_shapes_have_the_same_exact_budget(metadata, sync):
    from fsbudget.gate import check
    trace = PROBE.replace(METADATA[0], metadata).replace(
        'AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH', sync + 'AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH')
    expected = {'exec': 1, **{'probe_' + k: v for k, v in
        collector_repository_expected(CollectorAxes(phase='probe', probes=1)).items()}}

    def errors(probe):
        got = collector_attribute((PREFIX + probe).splitlines(), {'front': '/b', 'helper': '/b', 'collector': '/c'})
        return got.errors + check(got.counts, {'collector': expected}, 'exact', ['collector'])

    assert not errors(trace)
    for line in trace.splitlines(keepends=True):
        if line.startswith('12 close'):
            continue
        assert errors(trace.replace(line, '')), line
        assert errors(trace.replace(line, line + line)), line
    for fd in ['7</>', '4</outside>', '4', '-1</>', 'AT_FDCWD</>']:
        damaged = metadata.replace('4</>', fd)
        assert errors(trace.replace(metadata, damaged))
    if '""' in metadata:
        for damaged in [metadata.replace('""', '"HEAD"'),
                        metadata.replace('AT_EMPTY_PATH', '0'),
                        metadata.replace('AT_EMPTY_PATH', 'AT_SYMLINK_NOFOLLOW'),
                        metadata.replace('AT_EMPTY_PATH', 'AT_EMPTY_PATH|0x80000000')]:
            assert errors(trace.replace(metadata, damaged))
    # Same total stat calls, but one metadata operation cannot replace MNT_ID.
    mount = next(line for line in trace.splitlines(keepends=True) if ', STATX_MNT_ID,' in line)
    assert errors(trace.replace(mount, '12 ' + metadata + ' = 0\n'))
    assert errors(trace.replace(mount, mount.replace('AT_SYMLINK_NOFOLLOW|', '')))

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
@pytest.mark.parametrize('metadata', METADATA)
@pytest.mark.parametrize('sync', ['', 'AT_STATX_SYNC_AS_STAT|'])
def test_repository_trace_checks_paths_counts_and_phases(metadata, sync):
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
    # Exercise the same canonical metadata rule in probe/read-layer/content.
    import re
    trace = re.sub(r'fstat\((\d+<[^>]+>), \{[^}]+\}\)',
                   lambda m: metadata.replace('4</>', m[1]), trace)
    trace = trace.replace('AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH', sync + 'AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH')
    assert check_repository_trace(trace, root, 'openat2')['content']['read'] == 2
    for fd in ['4', '-1</>', 'AT_FDCWD</>', '4<pipe:[9]>']:
        with pytest.raises(AssertionError):
            check_repository_trace(trace.replace(metadata, metadata.replace('4</>', fd)), root, 'openat2')
    for changed in [trace.replace('worktree/HEAD', 'outside/HEAD'),
                    trace.replace('O_RDONLY|O_NONBLOCK|O_CLOEXEC,', 'O_RDWR|O_NONBLOCK|O_CLOEXEC,'),
                    trace.replace('12 read(10</fixture/worktree/HEAD>, "", 57) = 0\n', ''),
                    trace.replace(marker('content'), marker('content') + '12 socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM\n'),
                    trace.replace(marker('read-layer'), marker('probe') + PROBE + marker('end') + marker('read-layer'))]:
        with pytest.raises(AssertionError):
            check_repository_trace(changed, root, 'openat2')
    for damaged in [trace.replace('AT_EMPTY_PATH', '0'),
                    trace.replace('AT_EMPTY_PATH', 'AT_EMPTY_PATH|0x80000000'),
                    trace.replace(', STATX_MNT_ID,', ', STATX_ALL,')]:
        with pytest.raises(AssertionError):
            check_repository_trace(damaged, root, 'openat2')
    if metadata.startswith('statx'):
        with pytest.raises(AssertionError):
            check_repository_trace(trace.replace('STATX_BASIC_STATS', 'STATX_INO').replace('STATX_ALL', 'STATX_INO'), root, 'openat2')


def probe_attribute(text):
    return collector_attribute(text.splitlines(), {'front': '/b', 'helper': '/b', 'collector': '/c'})


# 이것을 실패시키는 것: musl O_LARGEFILE이나 -y/-yy 표기 차이로 고정 root probe를 거부하는 것.
@pytest.mark.parametrize('directory', ['AT_FDCWD', 'AT_FDCWD</>', 'AT_FDCWD</unused-cwd>'])
@pytest.mark.parametrize('flags', [
    'O_RDONLY|O_CLOEXEC|O_DIRECTORY',
    'O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY',
    'O_PATH|O_DIRECTORY|O_CLOEXEC',
    'O_CLOEXEC|O_DIRECTORY|O_LARGEFILE|O_PATH|O_RDONLY',
])
def test_probe_root_libc_spellings_keep_exact_counts(directory, flags):
    trace = PROBE.replace('AT_FDCWD</>', directory).replace('O_RDONLY|O_CLOEXEC|O_DIRECTORY', flags)
    got = probe_attribute(PREFIX + trace)
    assert not got.errors
    assert got.counts == probe_attribute(PREFIX + PROBE).counts
    # Legacy open has the same narrowly scoped fixed-root allowance.
    legacy = trace.replace(f'openat({directory},', 'open(')
    assert probe_attribute(PREFIX + legacy).counts == got.counts
    assert not probe_attribute(PREFIX + legacy).errors


# 이것을 실패시키는 것: root/open_how에 임의 flag·경로·dirfd·size를 허용하는 것.
@pytest.mark.parametrize('old,new', [
    ('AT_FDCWD</>', '8</>'),
    ('"/"', '"/etc"'),
    ('"/"', '"."'),
    ('O_RDONLY|O_CLOEXEC|O_DIRECTORY', 'O_RDONLY|O_DIRECTORY'),
    ('O_RDONLY|O_CLOEXEC|O_DIRECTORY', 'O_RDONLY|O_CLOEXEC'),
    ('O_RDONLY|O_CLOEXEC|O_DIRECTORY', 'O_DIRECTORY|O_CLOEXEC'),
    ('O_RDONLY|O_CLOEXEC|O_DIRECTORY', 'O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW'),
    ('O_RDONLY|O_CLOEXEC|O_DIRECTORY', 'O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_TRUNC'),
    ('O_RDONLY|O_CLOEXEC|O_DIRECTORY', 'O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_CLOEXEC'),
    ('openat2(4</>', 'openat2(7</>'),
    ('openat2(4</>', 'openat2(4'),
    ('"."', '"etc/passwd"'),
    ('"."', '"/"'),
    ('RESOLVE_NO_XDEV|', ''),
    ('RESOLVE_NO_MAGICLINKS|', ''),
    ('|RESOLVE_BENEATH', ''),
    ('|RESOLVE_BENEATH', '|RESOLVE_BENEATH|RESOLVE_IN_ROOT'),
    ('|RESOLVE_BENEATH', '|RESOLVE_BENEATH|RESOLVE_BENEATH'),
    ('O_NONBLOCK|', ''),
    ('{flags=O_RDONLY', '{flags=O_WRONLY'),
    ('{flags=O_RDONLY', '{flags=O_RDONLY|O_PATH'),
    ('}, 24)', '}, 32)'),
    ('}, 24)', ', mode=0}, 24)'),
    ('fstatfs(4</>,', 'fstatfs(7</>,'),
    ('fstatfs(4</>,', 'fstatfs(4,'),
    ('{f_type=EXT4_SUPER_MAGIC})', '{f_type=EXT4_SUPER_MAGIC}, 0)'),
])
def test_probe_rejects_changed_shapes_without_formula(old, new):
    got = probe_attribute(PREFIX + PROBE.replace(old, new))
    assert got.errors
    assert any('collector forbidden effect' in e or 'collector read outside the M3b bootstrap' in e for e in got.errors)


BOUNDARIES = [
    '12 write(1<pipe:[1]>, "Ready", 5) = 5\n',
    '12 write(1<pipe:[1]>, "Ready", 5) = -1 EPIPE (Broken pipe)\n',
    '12 writev(1<pipe:[1]>, [{iov_base="Ready", iov_len=5}], 1) = 5\n',
    '12 read(3<pipe:[1]>, "request", 7) = 7\n',
    '12 readv(3<pipe:[1]>, [{iov_base="request", iov_len=7}], 1) = 7\n',
    '12 landlock_create_ruleset({handled_access_fs=LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR}, 8, 0) = 8<anon_inode:[landlock-ruleset]>\n',
    '12 landlock_restrict_self(8<anon_inode:[landlock-ruleset]>, 0) = 0\n',
    '12 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=1, filter=0x1}) = 0\n',
]


# 이것을 실패시키는 것: Ready·read layer 뒤에 probe 시작/metadata/openat2/close를 허용하는 것.
@pytest.mark.parametrize('boundary', BOUNDARIES)
@pytest.mark.parametrize('at', range(7))
def test_probe_ends_before_ready_or_read_layer(boundary, at):
    lines = PROBE.splitlines(keepends=True)
    got = probe_attribute(PREFIX + ''.join(lines[:at]) + boundary + ''.join(lines[at:]))
    assert got.errors


# 이것을 실패시키는 것: macOS(두 Linux 필터 없음)에 root probe 예외를 추가하는 것.
@pytest.mark.parametrize('filters', [0, 1])
def test_probe_requires_both_linux_filters(filters):
    prefix = PREFIX.split('12 seccomp')[0]
    prefix += '12 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=1, filter=0x1}) = 0\n' * filters
    assert probe_attribute(prefix + PROBE).errors


# 이것을 실패시키는 것: probe fd를 복제·닫은 뒤 재사용하거나 directory 내용을 읽는 것.
@pytest.mark.parametrize('extra', [
    '12 dup(4</>) = 7</>\n',
    '12 read(4</>, "root", 4) = 4\n',
    '12 getdents64(4</>, [], 1024) = 0\n',
    '12 close(4</>) = 0\n',
    '12 close(4</>) = 0\n12 dup2(9</>, 4) = 4</>\n',
])
def test_probe_keeps_descriptor_lifetimes(extra):
    opening, rest = PROBE.split('\n', 1)
    assert probe_attribute(PREFIX + opening + '\n' + extra + rest).errors


# 이것을 실패시키는 것: 실패한 openat2를 재시도하거나 thread마다 probe 예산을 새로 주는 것.
@pytest.mark.parametrize('result', ['6</>', '-1 ENOSYS (Function not implemented)', '-1 EPERM (Operation not permitted)'])
def test_probe_attempts_count_once_including_failures(result):
    trace = PROBE.replace('= 6</>', '= ' + result)
    if result.startswith('-1'):
        trace = trace.replace('12 close(6</>) = 0\n', '')
    got = probe_attribute(PREFIX + trace)
    assert not got.errors
    assert got.counts == probe_attribute(PREFIX + PROBE).counts
    call = next(line for line in trace.splitlines(keepends=True) if 'openat2(' in line)
    assert probe_attribute(PREFIX + trace.replace(call, call + call)).errors
    threaded = PREFIX + '12 clone(child_stack=0, flags=CLONE_VM|CLONE_FILES|CLONE_THREAD) = 13\n'
    assert not probe_attribute(threaded + trace.replace('12 ', '13 ')).errors
    assert probe_attribute(threaded + trace + trace.replace('12 ', '13 ')).errors


# 이것을 실패시키는 것: PID 재사용을 이전 process의 probe/filter 상태와 섞는 것.
def test_probe_pid_reuse_starts_a_new_lifetime():
    prefix = PREFIX.split('11 clone', 1)[1]
    second = '11 clone' + prefix
    trace = PREFIX + PROBE + '12 +++ exited with 0 +++\n' + second + PROBE
    pins = {'front': '/b', 'helper': '/b', 'collector': '/c', 'collectors': 2}
    got = collector_attribute(trace.splitlines(), pins)
    assert not got.errors
    assert got.counts['collector']['probe_openat'] == got.counts['collector']['probe_openat2'] == 2


# 이것을 실패시키는 것: unfinished open의 entry에서 반환 fd를 너무 일찍 생성하는 것.
def test_probe_binds_descriptors_at_open_return():
    trace = PROBE.replace(') = 4</>', ' <unfinished ...>\n12 <... openat resumed>) = 4</>', 1)
    trace = trace.replace('}, 24) = 6</>', '}, 24 <unfinished ...>\n12 <... openat2 resumed>) = 6</>')
    got = probe_attribute(PREFIX + trace)
    assert not got.errors
    assert got.counts == probe_attribute(PREFIX + PROBE).counts


# 이것을 실패시키는 것: musl의 즉시 F_SETFD 쌍을 새 fd 수명으로 오인하는 것.
@pytest.mark.parametrize('result', ['0', '-1 EPERM (Operation not permitted)'])
def test_probe_musl_cloexec_pair_preserves_lifetime(result):
    trace = PROBE.replace('openat(AT_FDCWD</>,', 'open(')
    opening, rest = trace.split('\n', 1)
    got = probe_attribute(PREFIX + opening + '\n' + f'12 fcntl(4</>, F_SETFD, FD_CLOEXEC) = {result}\n' + rest)
    assert not got.errors
    assert len(got.cloexec_pairs) == 1
    assert got.counts == probe_attribute(PREFIX + PROBE).counts


# 이것을 실패시키는 것: 실패한 root open을 반복하거나 얻지 못한 fd에 probe를 허용하는 것.
def test_probe_failed_root_still_consumes_attempt():
    opening, rest = PROBE.split('\n', 1)
    failed = opening.replace('4</>', '-1 EMFILE (Too many open files)') + '\n'
    got = probe_attribute(PREFIX + failed)
    assert not got.errors and got.counts['collector']['probe_openat'] == 1
    assert probe_attribute(PREFIX + failed + PROBE).errors
    assert probe_attribute(PREFIX + failed + rest).errors
