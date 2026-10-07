#!/usr/bin/env python3
"""Summarize M1 measurements against the spec's hypotheses (spec section 8).

Usage: summarize.py RAW_DIR   (reads *.jsonl rows and hyperfine *.json)
Never changes a target: an overrun prints OVER and goes to the user
(spec section 8 "gate reinforcement", last rule).

Input that cannot be read is an error (exit 2), never a zero: a missing
folder, a line that is not JSON, a row of an unknown shape, the same row in
two files, rows from two operating systems, a hyperfine result without
times. A row that was not measured (`na`) stays in the table as
`unavailable` and every line that needs it says so.
"""
import json
import pathlib
import sys

HYP_MS = {
    "startup": {"linux": 1.0, "macos": 3.0},       # process start + argument parsing
    "writer_spawn": {"linux": 0.5, "macos": 1.0},  # write-only child spawn
    "collector": {"linux": 1.0, "macos": 2.0},     # spawn + protection + ready
    "helper_spawn": {"linux": 1.0, "macos": 2.0},  # upper end of 0.5-1 / 1-2
    "init": {"linux": 5.0, "macos": 8.0},
    "redraw": 3.0,
    "front_median": 10.0,
    "front_p95": 15.0,
}
BINARY_MB = 6.0
SIZE_JUDGED = "regex-yaml-json"  # the last combination of the capacity table


class InputError(Exception):
    """Input the summary cannot stand on (exit 2)."""


class Unavailable(KeyError):
    """The row exists but was not measured (`na` with its reason)."""


def verdict(measured, limit):
    return "OVER" if measured > limit else "ok"


def subpath_verdict(quantile, target):
    """Verdict from one measured run of a sub-path that lies wholly inside the
    target path (e.g. the `bingsu prompt` process inside the front path).
    The whole path is never faster than its own sub-path, so the sub-path's
    quantile above the target is a real overrun (OVER); below it proves
    nothing (unjudged). Never "ok"."""
    return "OVER" if quantile > target else "unjudged"


# Sums and differences of separately measured medians are not bounds on any
# quantile of the composite: they are estimates and never judged.
ESTIMATE = "estimate, unjudged"


def nearest_rank(sorted_vals, p):
    n = len(sorted_vals)
    return sorted_vals[max(1, -(-p * n // 100)) - 1]


def measured(row, key):
    """The row's values; `Unavailable` for an `na` row."""
    if "na" in row:
        raise Unavailable(f"{key} unavailable: {row['na']}")
    return row


def get(rows, key):
    """`rows[key]`: `KeyError` when missing, `Unavailable` when `na`."""
    return measured(rows[key], key)


def hyperfine_rows(path):
    try:
        results = json.loads(path.read_text())["results"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise InputError(f"{path}: not a hyperfine export ({e!r})") from None
    rows = {}
    for r in results:
        if not r.get("times"):
            raise InputError(f"{path}: {r.get('command')!r} has no times")
        if r.get("exit_codes") and any(c != 0 for c in r["exit_codes"]):
            rows[r["command"]] = {"na": f"non-zero exit codes {sorted(set(r['exit_codes']))}"}
            continue
        t = sorted(x * 1000 for x in r["times"])
        rows[r["command"]] = {"median_ms": nearest_rank(t, 50), "p95_ms": nearest_rank(t, 95)}
    return rows


def serial_sum(rows, os):
    collector = "sandbox-ready/dedicated" if os == "linux" else "env-limits/dedicated"
    parts = [("prompt-empty", "prompt-empty"), ("header64+marker128", "header64+marker128"),
             ("min-child-spawn-call (helper)", "min-child-spawn-call"), (collector, collector),
             ("min-child-spawn-call (writer)", "min-child-spawn-call")]
    return {
        "parts": [label for label, _ in parts],
        "median_ms": sum(get(rows, key)["median_ms"] for _, key in parts),
        "p95_ms": sum(get(rows, key)["p95_ms"] for _, key in parts),
    }


def one_row(rows, prefix, suffix=""):
    hits = [(k, v) for k, v in rows.items() if k.startswith(prefix) and k.endswith(suffix)]
    if len(hits) != 1:
        raise KeyError(f"{prefix}*{suffix}: need exactly one hyperfine row, got {len(hits)}")
    return measured(hits[0][1], hits[0][0])


def redraw_estimate(rows):
    """X-23 redraw estimate: the --redraw run's median plus the median of
    reading the snapshot-present fixture (header+section, marker, session)."""
    return one_row(rows, "redraw:")["median_ms"] + get(rows, "snapshot-present-read")["median_ms"]


def init_added_estimate(rows, shell):
    """X-23 init estimate for one shell: warm start with the init line minus
    the empty rc (clamped at 0, noise can make it negative), plus the header
    64 + marker 128 read that checks the snapshot is valid for this boot.
    Cold rows (init-<shell>-cold) are not mixed in."""
    def one(kind):
        hits = [(k, v) for k, v in rows.items() if k.startswith(f"init-{shell}:") and f"{shell}-{kind}" in k]
        if len(hits) != 1:
            raise KeyError(f"init-{shell}: need exactly one {kind} row")
        return measured(hits[0][1], hits[0][0])["median_ms"]
    return max(0.0, one("init") - one("empty")) + get(rows, "header64+marker128")["median_ms"]


def _missing(e):
    """`not measured` for an absent row, `unavailable` for an `na` one."""
    return f"unavailable ({e.args[0]})" if isinstance(e, Unavailable) else f"not measured ({e.args[0]})"


def x22_line(rows, os):
    """X-22: the measured `bingsu prompt` run is a sub-path of the front
    serial part (judged); the serial sum is an estimate (never judged)."""
    try:
        p = get(rows, "prompt-empty")
    except KeyError as e:
        return f"X-22 front path ({os}): prompt run {_missing(e)}"
    line = (f"X-22 front path ({os}): prompt run median {p['median_ms']:.2f} ms "
            f"[{subpath_verdict(p['median_ms'], HYP_MS['front_median'])} vs 10], "
            f"p95 {p['p95_ms']:.2f} ms [{subpath_verdict(p['p95_ms'], HYP_MS['front_p95'])} vs 15]; ")
    try:
        s = serial_sum(rows, os)
    except KeyError as e:
        return line + f"serial estimate {_missing(e)}"
    return line + f"serial estimate median {s['median_ms']:.2f} ms, p95 sum {s['p95_ms']:.2f} ms [{ESTIMATE}]"


def startup_line(rows, os):
    """The empty prompt run is the startup hypothesis itself: ok/OVER."""
    t = HYP_MS["startup"][os]
    try:
        m = get(rows, "prompt-empty")["median_ms"]
    except KeyError as e:
        return f"startup ({os}): {_missing(e)}"
    return f"startup ({os}): median {m:.2f} ms [{verdict(m, t)} vs {t}]"


def x23_lines(rows, os):
    """Redraw per OS and init per OS/shell. Judged only from a measured
    sub-path run (--redraw run; the `bingsu init <shell>` generator run, which
    eval runs inside the added time); estimates are printed, never judged.
    A missing measurement prints "not measured", an `na` one "unavailable"."""
    out = []
    try:
        run = one_row(rows, "redraw:")["median_ms"]
        line = f"X-23 redraw ({os}): run median {run:.2f} ms [{subpath_verdict(run, HYP_MS['redraw'])} vs {HYP_MS['redraw']}]"
        try:
            line += f"; estimate with fixture read {redraw_estimate(rows):.2f} ms [{ESTIMATE}]"
        except KeyError as e:
            line += f"; estimate {_missing(e)}"
        out.append(line)
    except KeyError as e:
        out.append(f"X-23 redraw ({os}): {_missing(e)}")
    t = HYP_MS["init"][os]
    for shell in ("zsh", "bash", "fish"):
        try:
            gen = one_row(rows, "init-gen:", f" init {shell}")["median_ms"]
            line = f"X-23 init added ({os}, {shell}): generator run median {gen:.2f} ms [{subpath_verdict(gen, t)} vs {t}]"
        except KeyError as e:
            line = f"X-23 init added ({os}, {shell}): generator run {_missing(e)}"
        try:
            line += f"; estimate {init_added_estimate(rows, shell):.2f} ms [{ESTIMATE}]"
        except KeyError as e:
            line += f"; estimate {_missing(e)}"
        out.append(line)
    return out


def size_lines(sizes):
    """Stripped size per combination; the last combination is compared with
    6 MB (decimal; the binary MiB is printed next to it)."""
    out = []
    for (os, row), b in sorted(sizes.items()):
        line = f"size ({os}) {row}: {b} bytes ({b / 1e6:.2f} MB, {b / 2**20:.2f} MiB)"
        if row == SIZE_JUDGED:
            line += f" [{verdict(b / 1e6, BINARY_MB)} vs {BINARY_MB} MB]"
        out.append(line)
    return out


def _put(rows, origin, key, value, where):
    if key in rows:
        raise InputError(f"row {key!r} twice: {origin[key]} and {where}")
    rows[key], origin[key] = value, where


def load(raw):
    """(rows, os, sizes). Rows from both kinds of file share one namespace;
    a hyperfine row is `<file stem>:<command>`, except the prompt run in
    prompt.json, which is `prompt-empty`."""
    if not raw.is_dir():
        raise InputError(f"{raw}: not a folder")
    rows, origin, oses, sizes = {}, {}, set(), {}
    for f in sorted(raw.glob("*.jsonl")):
        for i, line in enumerate(f.read_text().splitlines(), 1):
            where = f"{f.name}:{i}"
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                raise InputError(f"{where}: not JSON ({e})") from None
            if not isinstance(r, dict):
                raise InputError(f"{where}: not a JSON object")
            if "meta" in r:
                if isinstance(r["meta"], dict) and r["meta"].get("os"):
                    oses.add(r["meta"]["os"])
                continue
            if r.get("x") == "X-24":
                continue  # the X-24 model is recorded, not judged
            if "row" not in r or "os" not in r:
                raise InputError(f"{where}: no row or os")
            oses.add(r["os"])
            if r.get("matrix") == "size":
                if not isinstance(r.get("bytes"), int):
                    raise InputError(f"{where}: size row without bytes")
                sizes[(r["os"], r["row"])] = r["bytes"]
            elif "na" in r:
                _put(rows, origin, r["row"], {"na": r["na"]}, where)
            elif "median_ns" in r and "p95_ns" in r:
                _put(rows, origin, r["row"], {"median_ms": r["median_ns"] / 1e6, "p95_ms": r["p95_ns"] / 1e6}, where)
            elif "mean_ns" in r:
                # fish hook cost: a mean timed from outside, not a median.
                _put(rows, origin, f"{r['row']} (mean)", {"mean_ms": r["mean_ns"] / 1e6}, where)
            else:
                raise InputError(f"{where}: neither measured nor na")
    for f in sorted(raw.glob("*.json")):
        for cmd, v in hyperfine_rows(f).items():
            key = "prompt-empty" if f.stem == "prompt" and " prompt " in cmd else f"{f.stem}:{cmd}"
            _put(rows, origin, key, v, f.name)
    if not rows and not sizes:
        raise InputError(f"{raw}: no results (*.jsonl rows or hyperfine *.json)")
    if len(oses) > 1:
        raise InputError(f"rows from more than one OS: {sorted(oses)}")
    return rows, (oses.pop() if oses else None), sizes


def table(rows):
    out = ["| row | median ms | p95 ms |", "| -- | -- | -- |"]
    for k, v in rows.items():
        if "na" in v:
            out.append(f"| `{k}` | unavailable | {v['na']} |")
        elif "mean_ms" in v:
            out.append(f"| `{k}` | mean {v['mean_ms']:.3f} | -- |")
        else:
            out.append(f"| `{k}` | {v['median_ms']:.3f} | {v['p95_ms']:.3f} |")
    return out


def main(argv):
    if len(argv) != 1:
        print("usage: summarize.py RAW_DIR", file=sys.stderr)
        return 2
    try:
        rows, os, sizes = load(pathlib.Path(argv[0]))
    except (InputError, OSError) as e:
        print(f"summarize.py: {e}", file=sys.stderr)
        return 2
    print("\n".join(table(rows)))
    if os is None:
        print("\nX-22, X-23, startup: unavailable (no os in any .jsonl row or meta line)")
    else:
        print("\n" + x22_line(rows, os))
        print(startup_line(rows, os))
        print("\n".join(x23_lines(rows, os)))
    if sizes:
        print("\n" + "\n".join(size_lines(sizes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
