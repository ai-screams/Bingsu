"""Exact B3 fixture windows; never an ambient repository path allowlist."""
from collections import Counter
import json
import re

from .classify import FD_ARG, NON_FS, fd_identity, split_args
from .formula import CollectorAxes, collector_repository_expected
from .strace_parse import parse


def held_metadata_kind(c, args):
    """Canonical fd metadata, separate from the explicit mount-id query.

    libc may implement fstat with newfstatat or statx. strace may spell the
    zero-valued statx sync flag explicitly; neither changes the primitive.
    Only an annotated, nonnegative held fd and an empty-path query qualify.
    """
    if not args or not (fd := FD_ARG.fullmatch(args[0])) or int(fd[1]) < 0:
        return None
    identity = fd_identity(args[0])
    if not identity or not identity.startswith('file:'):
        return None
    if c.name in {'fstat', 'fstat64'} and len(args) == 2:
        return 'fstat'
    if c.name in {'newfstatat', 'fstatat64'} and len(args) == 4 and args[1] == '""':
        flags = set(args[3].split('|'))
        if 'AT_EMPTY_PATH' in flags and flags <= {'AT_EMPTY_PATH', 'AT_SYMLINK_NOFOLLOW'}:
            return 'fstat'
    if c.name == 'statx' and len(args) == 5 and args[1] == '""':
        flags = set(args[2].split('|')) - {'AT_STATX_SYNC_AS_STAT'}
        if 'AT_EMPTY_PATH' in flags and flags <= {'AT_EMPTY_PATH', 'AT_SYMLINK_NOFOLLOW'}:
            if args[3] in {'STATX_BASIC_STATS', 'STATX_ALL'}:
                return 'fstat'
            if args[3] == 'STATX_MNT_ID' and flags == {'AT_EMPTY_PATH', 'AT_SYMLINK_NOFOLLOW'}:
                return 'statx'
    return None


def check_repository_trace(text: str, root: str, backend: str) -> dict:
    calls = parse(text)
    assert not calls.errors, calls.errors
    phases, active, owner = {}, None, None
    roots = {root + '/' + name for name in ('worktree', 'gitdir', 'commondir')}
    for c in calls:
        args = split_args(c.args)
        if c.name == 'write' and len(args) >= 2 and args[0].split('<')[0] == '1':
            try:
                marker = json.loads(args[1]).strip()
            except (ValueError, TypeError):
                marker = ''
            if marker.startswith('B3_PHASE '):
                phase = marker.split()[1]
                if phase == 'end':
                    assert active is not None and owner == c.pid
                    active = None
                else:
                    assert phase in {'probe', 'read-layer', 'content'} and phase not in phases and active is None
                    active, owner = phase, c.pid
                    phases[phase] = Counter()
                continue
        if active is None:
            continue
        assert c.pid == owner, 'other thread/process inside repository phase'
        name = c.name
        if name in {'clone', 'clone3', 'fork', 'vfork', 'execve', 'execveat', 'socket', 'connect', 'write', 'writev'}:
            raise AssertionError(f'forbidden repository effect: {c}')
        if name in NON_FS:
            continue
        if name == 'fcntl' and len(args) >= 2 and args[1] == 'F_GETFD':
            continue  # debug OwnedFd drop; lifetime is checked by the role gate
        if name == 'mmap' and 'MAP_ANONYMOUS' in c.args:
            continue
        path_args = c.args
        # -yy annotates even an unused AT_FDCWD. The fixed absolute slash
        # open does not access that cwd; relative opens still check its name.
        if name == 'openat' and len(args) >= 2 and args[0].split('<')[0] == 'AT_FDCWD' and args[1] == '"/"':
            path_args = ', '.join(args[1:])
        paths = re.findall(r'<(/[^>]*)>', path_args)
        allowed = {'/'} if active == 'probe' else {'/', *roots} if active == 'read-layer' else {root + '/worktree', root + '/worktree/HEAD'}
        assert set(paths) <= allowed, (active, 'outside selected roots', c)
        if name in {'open', 'openat', 'openat2'}:
            assert not any(flag in c.args for flag in ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND', 'O_TMPFILE'))
            path = args[0] if name == 'open' else args[1]
            assert path in ({'"/"', '"."'} if active == 'probe' else {'"/"'} if active == 'read-layer' else {'"HEAD"'})
            if name == 'open': name = 'openat'  # libc File::open of fixed slash only
        if (name in {'fstat', 'fstat64', 'statx'}
                or name in {'newfstatat', 'fstatat64'} and len(args) > 1 and args[1] == '""'):
            name = held_metadata_kind(c, args)
            assert name, (active, 'not held-fd metadata', c)
        if name == 'landlock_add_rule':
            assert active == 'read-layer' and 'LANDLOCK_RULE_PATH_BENEATH' in c.args
            assert len(paths) == 1 and paths[0] in roots
            assert 'LANDLOCK_ACCESS_FS_READ_FILE' in c.args and 'LANDLOCK_ACCESS_FS_READ_DIR' in c.args
        if name == 'faccessat2':
            assert args[1:] == ['"."', 'W_OK', 'AT_EACCESS']
        assert not c.ret.startswith('-1'), (active, 'unexpected failure', c)
        phases[active][name] += 1
    assert active is None and set(phases) == {'probe', 'read-layer', 'content'}
    axes = {
        'probe': CollectorAxes(phase='probe', probes=1),
        'read-layer': CollectorAxes(phase='read-layer', roots=3, root_inputs=3),
        'content': CollectorAxes(backend=backend, components=1, files=1, read_bytes=(8,), readonly=1),
    }
    for phase, counts in phases.items():
        expected = {k: v for k, v in collector_repository_expected(axes[phase]).items() if v}
        assert dict(counts) == expected, (phase, dict(counts), expected)
    return {phase: dict(counts) for phase, counts in phases.items()}
