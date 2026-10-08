#!/usr/bin/env python3
"""X-24: how often the write-only child runs with the default layout
(time and duration segments). The child runs only when the session state
(segment values and facts) changes (spec section 4 side-effect rules).

Model: state = (formatted time, cwd, last status, duration if >= 2 s).
Git values are not modelled (M3), so the result is a lower bound.
All traces are synthetic (no personal shell history is read) and the
output says so ("source": "synthetic").
Usage: x24_writer_frequency.py [--seed N]
"""
import argparse
import json
import random
import time
from dataclasses import dataclass


@dataclass
class Prompt:
    t: float
    cwd: str
    status: int
    duration_s: float | None


def state(p: Prompt, fmt: str):
    shown = p.duration_s if p.duration_s is not None and p.duration_s >= 2.0 else None
    return (time.strftime(fmt, time.gmtime(p.t)), p.cwd, p.status, shown)


def writer_spawns(events, fmt):
    prev, n = None, 0
    for p in events:
        s = state(p, fmt)
        if s != prev:
            n += 1
            prev = s
    return n


def synthetic(seed, profile, count=2000):
    rnd = random.Random(seed)
    gap, empty, cd, fail, slow = {
        "typing": (6.0, 0.25, 0.10, 0.08, 0.05),
        "build": (40.0, 0.05, 0.03, 0.15, 0.40),
        "idle": (300.0, 0.30, 0.05, 0.02, 0.02),
    }[profile]
    t, cwd, out = 0.0, "/home/u/p", []
    for _ in range(count):
        t += rnd.expovariate(1.0 / gap)
        if rnd.random() < empty:
            out.append(Prompt(t, cwd, 0, None))
            continue
        if rnd.random() < cd:
            cwd = f"/home/u/p/{rnd.randint(0, 20)}"
        dur = rnd.lognormvariate(1.5, 1.2) if rnd.random() < slow else rnd.uniform(0.01, 0.5)
        out.append(Prompt(t, cwd, 1 if rnd.random() < fail else 0, dur))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    sets = {p: synthetic(a.seed, p) for p in ("typing", "build", "idle")}
    for name, ev in sets.items():
        for fmt in ("%H:%M:%S", "%H:%M"):
            n = writer_spawns(ev, fmt)
            print(json.dumps({"x": "X-24", "source": "synthetic", "profile": name, "time_format": fmt, "prompts": len(ev),
                              "writer_spawns": n, "frequency": round(n / max(1, len(ev)), 3)}))


if __name__ == "__main__":
    main()
