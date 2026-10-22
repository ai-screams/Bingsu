"""Exact B3 fixture windows; never an ambient repository path allowlist."""
from collections import Counter
import json
import re

from .classify import NON_FS, split_args
from .formula import CollectorAxes, collector_repository_expected
from .strace_parse import parse


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
        paths = re.findall(r'<(/[^>]*)>', c.args)
        allowed = {'/'} if active == 'probe' else {'/', *roots} if active == 'read-layer' else {root + '/worktree', root + '/worktree/HEAD'}
        assert set(paths) <= allowed, (active, 'outside selected roots', c)
        if name in {'open', 'openat', 'openat2'}:
            assert not any(flag in c.args for flag in ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND', 'O_TMPFILE'))
            path = args[0] if name == 'open' else args[1]
            assert path in ({'"/"', '"."'} if active == 'probe' else {'"/"'} if active == 'read-layer' else {'"HEAD"'})
            if name == 'open': name = 'openat'  # libc File::open of fixed slash only
        if name in {'newfstatat', 'fstatat64', 'statx'} and args[1] == '""' and 'STATX_MNT_ID' not in c.args:
            name = 'fstat'
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
