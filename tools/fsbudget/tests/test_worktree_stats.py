"""C4 directory-cache trace primitives, separate from prompt permissions."""
import pytest

from fsbudget.attribute import _Descriptors
from fsbudget.classify import split_args
from fsbudget.formula import CollectorAxes, collector_repository_expected
from fsbudget.strace_parse import parse


# 이것을 실패시키는 것: leaf마다 open 계상·directory 퇴출 검증 비용 누락·leaf stat 축 누락.
@pytest.mark.parametrize('backend', ['openat2', 'stepwise'])
def test_worktree_stats_charge_leaves_and_shared_directory_edges(backend):
    counts = collector_repository_expected(CollectorAxes(
        backend=backend, stat_leaves=19000, stat_directory_groups=190))
    assert counts['openat2' if backend == 'openat2' else 'openat'] == 190
    assert counts['newfstatat'] == 19000 + 380
    assert counts['fstat'] == counts['fstatfs'] == counts['statx'] == 190
    assert counts['read'] == counts['getdents64'] == 0
    assert sum(counts.values()) <= 100000
    flat = collector_repository_expected(CollectorAxes(stat_leaves=19000))
    assert flat['newfstatat'] == 19000 and sum(flat.values()) == 19000


def descriptor_errors(text):
    model = _Descriptors()
    model.start(12)
    errors = []
    calls = parse(text)
    assert not calls.errors
    for c in calls:
        model.observe(c, 12, split_args(c.args), not c.ret.startswith('-1'),
                      lambda call, reason: errors.append(reason))
    return errors


# 이것을 실패시키는 것: stat의 dirfd 수명 검사 제거·rename/dup alias 손상·닫힌 raw fd 허용.
@pytest.mark.parametrize('syscall', ['newfstatat', 'fstatat64'])
@pytest.mark.parametrize('annotated', [False, True])
def test_worktree_leaf_stat_uses_held_directory_lifetime(syscall, annotated):
    opened = '12 openat2(7</repo>, "d", {flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC, resolve=RESOLVE_BENEATH|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS}, 24) = 8</repo/d>\n'
    token = '8</repo/d>' if annotated else '8'
    leaf = f'12 {syscall}({token}, "leaf", {{st_mode=S_IFREG|0644}}, AT_SYMLINK_NOFOLLOW) = 0\n'
    closed = '12 close(8</repo/d>) = 0\n'
    assert not descriptor_errors(opened + leaf + leaf + closed)
    assert descriptor_errors(opened + closed + leaf) == ['descriptor lifetime/identity mismatch']
    # A cached directory retains its identity when it moves. This does NOT
    # authorize metadata outside the root; the adapter's exit check rejects it.
    renamed = '12 renameat(7</repo>, "d", 9</outside>, "moved") = 0\n'
    moved = leaf.replace('8</repo/d>', '8</outside/moved>')
    assert not descriptor_errors(opened + renamed + moved)
    if annotated:
        assert descriptor_errors(opened + moved) == ['descriptor lifetime/identity mismatch']
    duplicate = '12 dup(8</repo/d>) = 10</repo/d>\n'
    assert not descriptor_errors(opened + duplicate + closed + leaf.replace(token, '10</repo/d>'))


# 이것을 실패시키는 것: 공유 조상 재해석·mount/dev 검사 생략·hash 사후 stat 누락·op/fd 상한 완화.
@pytest.mark.parametrize('backend, expected_ops', [('openat2', 61440), ('stepwise', 69632)])
def test_worktree_deep_4096_hash_model_within_caps(backend, expected_ops):
    c = collector_repository_expected(CollectorAxes(
        backend=backend, stat_leaves=4096, stat_directory_groups=4096,
        worktree_hash_bytes=(1,) * 4096))
    assert c['openat2' if backend == 'openat2' else 'openat'] == 8192
    assert c['fstatfs'] == c['statx'] == 8192
    assert c['fstat'] == 12288
    assert c['newfstatat'] == (12288 if backend == 'openat2' else 16384)
    assert c['read'] == 8192
    components = 4096 + (4096 if backend == 'stepwise' else 0)
    assert sum(c.values()) + components == expected_ops <= 100000
    # One root, eight cached directories and one content fd, independent of width.
    assert 1 + 8 + 1 <= 56
