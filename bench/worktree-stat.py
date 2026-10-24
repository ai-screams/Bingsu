#!/usr/bin/env python3
"""Alternate two release git_io test binaries on one 190 x 100 tree.

Build each revision with:
  cargo test -j 2 -p bingsu-collect --test git_io --release --no-run
Copy the printed executable before rebuilding; both need the ignored
worktree_stat_release_bench test. No git checkout or source modification here.

  python3 bench/worktree-stat.py --previous /tmp/previous-git-io \
      --current target/release/deps/git_io-HASH --output /tmp/stat-results.json
The C syscall-only floor is separate: see worktree-stat-floor.c.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--floor', type=Path, help='optional compiled worktree-stat-floor.c (macOS bulk)')
    parser.add_argument('--rounds', type=int, default=200)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    bins = {'previous': args.previous.resolve(), 'current': args.current.resolve()}
    if args.floor:
        bins['bulk_floor'] = args.floor.resolve()
    result = {'files': 19000, 'directories': 190, 'rounds': args.rounds,
              'binaries': {k: str(v) for k, v in bins.items()},
              'samples_ns': {k: [] for k in bins}, 'first_ns': {}, 'counts': {}}
    with tempfile.TemporaryDirectory(prefix='bingsu-stat-bench-') as temp:
        tree = Path(temp).resolve()
        for d in range(190):
            parent = tree / f'd{d:03}'
            parent.mkdir()
            for f in range(100):
                (parent / f'f{f:03}').write_bytes(b'x')
        env = {**os.environ, 'BINGSU_STAT_TREE': str(tree), 'BINGSU_STAT_ROUNDS': '1'}
        for run in range(args.rounds):
            order = list(bins) if run % 2 == 0 else list(reversed(bins))
            for name in order:
                if name == 'bulk_floor':
                    p = subprocess.run([str(bins[name]), str(tree), 'bulk', '1'],
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
                    sample = re.search(r'FLOOR bulk n=1 p50_ns=(\d+) p95_ns=(\d+) calls=(\d+)', p.stdout)
                    if not sample:
                        raise RuntimeError(p.stdout)
                    result['samples_ns'][name].append(int(sample[1]))
                    result['first_ns'].setdefault(name, int(re.search(r'FLOOR_FIRST_NS (\d+)', p.stdout)[1]))
                    result['counts'][name] = 'getattrlistbulk=' + sample[3]
                    continue
                p = subprocess.run([str(bins[name]), '--exact', 'worktree_stat_release_bench',
                                    '--ignored', '--nocapture', '--test-threads=1'],
                                   env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
                sample = re.search(r'STAT_BENCH n=1 p50_ns=(\d+) p95_ns=(\d+)', p.stdout)
                if not sample:
                    raise RuntimeError(p.stdout)
                result['samples_ns'][name].append(int(sample[1]))
                result['first_ns'].setdefault(name, int(re.search(r'STAT_FIRST_NS (\d+)', p.stdout)[1]))
                result['counts'][name] = re.search(r'STAT_COUNTS (.+)', p.stdout)[1]
            args.output.write_text(json.dumps(result, indent=2) + '\n')
            if (run + 1) % 25 == 0:
                print(f'{run+1}/{args.rounds} alternating pairs', flush=True)
    result['summary'] = {}
    for name, raw in result['samples_ns'].items():
        ordered = sorted(raw)
        result['summary'][name] = {'p50_ns': ordered[(len(raw)-1)//2],
                                  'p95_ns': ordered[math.ceil(len(raw)*0.95)-1],
                                  'variance_ns2': statistics.pvariance(raw)}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary'], indent=2))


if __name__ == '__main__':
    main()
