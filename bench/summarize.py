#!/usr/bin/env python3
"""Summarize M1 measurements against the spec's hypotheses (spec section 8).

Usage: summarize.py PATH...   (each a folder of *.jsonl rows and hyperfine
*.json, or one such file). Several paths are how results from different runs
(a warm and a --cold-once folder, the B3/B4 row files) are put together; the
merge is explicit, never "whatever is in the folder".
Never changes a target: an overrun prints OVER and goes to the user
(spec section 8 "gate reinforcement", last rule).

Input that cannot be read is an error (exit 2), never a zero: a missing
path, a line that is not JSON (NaN and Infinity included), a row of an
unknown shape, a value that is not a finite number >= 0 (a bool is not a
number), the same row in two places, rows from two operating systems, a
hyperfine result without times. A row that was not measured (`na`) stays in
the table as `unavailable` and every line that needs it says so.
"""
import json
import math
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


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def parse_json(text):
    """`json.loads` without the NaN/Infinity extension Python accepts."""
    return json.loads(text, parse_constant=_no_constant)


def number(v, where, field, integer=False):
    """`v` when it is a finite number >= 0 (an int when `integer`); a bool,
    a string, null, NaN or a negative value is an `InputError`."""
    kinds = (int,) if integer else (int, float)
    if isinstance(v, bool) or not isinstance(v, kinds) or not math.isfinite(v) or v < 0:
        raise InputError(f"{where}: {field} {v!r} is not a finite {'integer' if integer else 'number'} >= 0")
    return v


def hyperfine_rows(path):
    try:
        results = parse_json(path.read_text())["results"]
    except (ValueError, KeyError, TypeError) as e:
        raise InputError(f"{path}: not a hyperfine export ({e!r})") from None
    if not isinstance(results, list):
        raise InputError(f"{path}: results is not a list")
    rows = {}
    for r in results:
        if not isinstance(r, dict) or not isinstance(r.get("command"), str):
            raise InputError(f"{path}: a result that is not an object with a command string: {r!r}")
        if r["command"] in rows:
            raise InputError(f"{path}: {r['command']!r} twice")
        if not r.get("times"):
            raise InputError(f"{path}: {r.get('command')!r} has no times")
        for field in ("times", "exit_codes"):
            if not isinstance(r.get(field, []), list):
                raise InputError(f"{path}: {r['command']!r}: {field} is not a list")
        if any(not isinstance(c, int) or isinstance(c, bool) for c in r.get("exit_codes", [])):
            raise InputError(f"{path}: {r['command']!r}: exit_codes holds a non-integer")
        if r.get("exit_codes") and any(c != 0 for c in r["exit_codes"]):
            rows[r["command"]] = {"na": f"non-zero exit codes {sorted(set(r['exit_codes']))}"}
            continue
        t = sorted(number(x, f"{path}: {r['command']!r}", "time") * 1000 for x in r["times"])
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


def _files(paths):
    """The *.jsonl and *.json files named by `paths` (a folder gives its own
    files of both kinds, sorted); a missing path or another kind of file is
    an `InputError`, and so is the same file given twice."""
    jsonl, js = [], []
    for p in paths:
        if p.is_dir():
            jsonl += sorted(p.glob("*.jsonl"))
            js += sorted(p.glob("*.json"))
        elif p.is_file() and p.suffix in (".jsonl", ".json"):
            (jsonl if p.suffix == ".jsonl" else js).append(p)
        else:
            raise InputError(f"{p}: not a folder, a .jsonl or a .json file")
    real = [f.resolve() for f in jsonl + js]
    if len(set(real)) != len(real):
        raise InputError("the same file given twice")
    return jsonl, js


def load(*paths):
    """(rows, os, sizes) from one or more folders or files. Rows from both
    kinds of file share one namespace; a hyperfine row is `<file
    stem>:<command>`, except the prompt run in prompt.json, which is
    `prompt-empty`."""
    jsonl, js = _files(paths)
    rows, origin, oses, sizes, size_origin = {}, {}, set(), {}, {}
    for f in jsonl:
        for i, line in enumerate(f.read_text().splitlines(), 1):
            where = f"{f.name}:{i}"
            if not line.strip():
                continue
            try:
                r = parse_json(line)
            except ValueError as e:
                raise InputError(f"{where}: not JSON ({e})") from None
            if not isinstance(r, dict):
                raise InputError(f"{where}: not a JSON object")
            if "meta" in r:
                meta_os = r["meta"].get("os") if isinstance(r["meta"], dict) else None
                if meta_os is not None and not isinstance(meta_os, str):
                    raise InputError(f"{where}: meta os {meta_os!r} is not a string")
                if meta_os:
                    oses.add(meta_os)
                continue
            if r.get("x") == "X-24":
                continue  # the X-24 model is recorded, not judged
            if "row" not in r or "os" not in r:
                raise InputError(f"{where}: no row or os")
            for field in ("row", "os") + (("na",) if "na" in r else ()):
                if not isinstance(r[field], str):
                    raise InputError(f"{where}: {field} {r[field]!r} is not a string")
            oses.add(r["os"])
            ns = lambda field: number(r[field], where, field) / 1e6  # noqa: E731
            if r.get("matrix") == "size":
                if "bytes" not in r:
                    raise InputError(f"{where}: size row without bytes")
                _put(sizes, size_origin, (r["os"], r["row"]), number(r["bytes"], where, "bytes", integer=True), where)
            elif "na" in r:
                _put(rows, origin, r["row"], {"na": r["na"]}, where)
            elif "median_ns" in r and "p95_ns" in r:
                _put(rows, origin, r["row"], {"median_ms": ns("median_ns"), "p95_ms": ns("p95_ns")}, where)
            elif "mean_ns" in r:
                # fish hook cost: a mean timed from outside, not a median.
                _put(rows, origin, f"{r['row']} (mean)", {"mean_ms": ns("mean_ns")}, where)
            else:
                raise InputError(f"{where}: neither measured nor na")
    for f in js:
        for cmd, v in hyperfine_rows(f).items():
            key = "prompt-empty" if f.stem == "prompt" and " prompt " in cmd else f"{f.stem}:{cmd}"
            _put(rows, origin, key, v, f.name)
    if not rows and not sizes:
        raise InputError(f"{' '.join(map(str, paths))}: no results (*.jsonl rows or hyperfine *.json)")
    if len(oses) > 1:
        raise InputError(f"rows from more than one OS: {sorted(oses)}")
    return rows, (oses.pop() if oses else None), sizes


FIRST_SHELL_PHASES = ("cold", "warm")
LOGIN_PAIRS = {"logout": ("before-logout", "after-login"), "reboot": ("before-reboot", "after-reboot")}


def ingest_first_shell(rows, reservations=None):
    """{boot: {"cold": {...}, "warm": {...}}} from first-shell-logger rows
    (UTC, boot, shell, phase=, status=, <n>us). A phase is `{"us": n}` or
    `{"na": reason}`: a row whose status is not 0 voids that boot's phase (the
    failed run already loaded the pages, so a later shell is not cold), and a
    reservation `(boot, phase)` with no row means the shell died inside init,
    so that boot has no such phase. `reservations=None` skips the second
    rule. Malformed or repeated rows are an `InputError`."""
    out, seen = {}, set()
    for i, r in enumerate(rows, 1):
        if len(r) != 6 or not r[1]:
            raise InputError(f"first-shell row {i}: expected 6 columns with a boot identity, got {list(r)!r}")
        _, boot, _, phase, status, us = r
        if not (phase.startswith("phase=") and phase[6:] in FIRST_SHELL_PHASES):
            raise InputError(f"first-shell row {i}: bad phase {phase!r}")
        if not (status.startswith("status=") and status[7:].isdigit() and us.endswith("us") and us[:-2].isdigit()):
            raise InputError(f"first-shell row {i}: bad status or time {status!r} {us!r}")
        phase = phase[6:]
        if (boot, phase) in seen:
            raise InputError(f"first-shell row {i}: boot {boot} phase {phase} twice")
        seen.add((boot, phase))
        cell = out.setdefault(boot, {})
        cell[phase] = {"us": int(us[:-2])} if int(status[7:]) == 0 else {"na": f"init status {int(status[7:])}"}
    for boot, phase in reservations or ():
        if phase not in FIRST_SHELL_PHASES:
            raise InputError(f"reservation {boot}.{phase}: bad phase")
        if (boot, phase) not in seen:
            out.setdefault(boot, {})[phase] = {"na": "reserved, no row (shell ended inside init)"}
    for cell in out.values():
        for phase in FIRST_SHELL_PHASES:
            cell.setdefault(phase, {"na": "not logged"})
    return out


def first_shell_file(log):
    """Rows and reservations of one logger file: the reservation folders sit
    next to it as `<log>.<boot>.<phase>`."""
    log = pathlib.Path(log)
    rows = [line.split("\t") for line in log.read_text().splitlines() if line.strip()] if log.exists() else []
    res = []
    for d in log.parent.glob(log.name + ".*"):
        boot, _, phase = d.name[len(log.name) + 1:].rpartition(".")
        res.append((boot, phase))
    return rows, res


def judge_login_transition(text):
    """{"logout": (verdict, why), "reboot": (...)} from login-transition.sh
    lines (UTC, label, boot identity, boot time). A pair judges only when both
    of its labels have exactly one line; anything else is BLOCKED, never a
    guess from the logger. Same identity before and after logout is a login
    transition, which is not a cold start; a new identity after the reboot is
    a boot."""
    by = {}
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        c = line.split("\t")
        if len(c) != 4 or not c[3].isdigit() or not c[2]:
            raise InputError(f"login-transition line {i}: not 4 columns with an identity and a boot time")
        by.setdefault(c[1], []).append(c[2])
    out = {}
    for name, (a, b) in LOGIN_PAIRS.items():
        bad = [l for l in (a, b) if len(by.get(l, ())) != 1]
        if bad:
            out[name] = ("BLOCKED", f"label {', '.join(bad)} needs exactly one line")
            continue
        same = by[a][0] == by[b][0]
        if name == "logout":
            out[name] = ("same-boot", "login transition, not a cold start") if same else \
                ("boot-changed", "the boot identity changed across the logout")
        else:
            out[name] = ("not-rebooted", "same boot identity after the reboot") if same else \
                ("new-boot", "the boot identity changed")
    return out


def first_shell_lines(result):
    out = []
    for boot, cell in sorted(result.items()):
        for phase in FIRST_SHELL_PHASES:
            v = cell[phase]
            out.append(f"first-shell {boot} {phase}: " + (f"{v['us'] / 1000:.3f} ms" if "us" in v else f"unavailable ({v['na']})"))
    return out


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
    if not argv:
        print("usage: summarize.py PATH...  |  summarize.py --first-shell LOG.tsv [--login-transition PROBE.tsv]",
              file=sys.stderr)
        return 2
    if argv[0] == "--first-shell":
        try:
            if len(argv) not in (2, 4) or (len(argv) == 4 and argv[2] != "--login-transition"):
                raise InputError("usage: --first-shell LOG.tsv [--login-transition PROBE.tsv]")
            lines = first_shell_lines(ingest_first_shell(*first_shell_file(argv[1])))
            if len(argv) == 4:
                lines += [f"login-transition {k}: {v} ({why})" for k, (v, why) in
                          judge_login_transition(pathlib.Path(argv[3]).read_text()).items()]
        except (InputError, OSError) as e:
            print(f"summarize.py: {e}", file=sys.stderr)
            return 2
        print("\n".join(lines))
        return 0
    try:
        rows, os, sizes = load(*map(pathlib.Path, argv))
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
