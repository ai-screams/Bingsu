#!/usr/bin/env python3
"""Judge the cause of PTY session stalls from session_stall.py results
(Task R0 Step 5). Runs on Python 3.9 or later.

One judgement per body (case), host and load. A cell is one side (this
host, or the other host at the same load), product and driver; its value is

  Y  stalls are there: at least MIN_STALLS stalls
  N  no stalls: zero stalls in at least the planned rounds of the case
  U  undecided: 1 to MIN_STALLS-1 stalls, fewer rounds, or the cell is n/a

Each cause is a condition over the cells it lists in REQUIRES, in
three-valued (Kleene) logic: a condition that needs an undecided cell is
itself undecided. A cause applies to a body only when the body runs every
cell the cause requires (APPLIES is computed, not written by hand).
Conditions may overlap; the verdict row is chosen so that every combination
of cell values lands in exactly one row:

  exactly one cause true, the others false     that cause
  two or more true                             undecided: several causes
  one true, some undecided                     undecided: the others are not ruled out
  none true, some undecided                    undecided: missing cells
  all false                                    undecided: no cause fits

--table prints the causes and their cells; --self-check tests the refusal
of results given twice; --enumerate walks every
combination of Y, N and U over each body's cells, checks that it lands in
exactly one row, and checks that each condition reads exactly the cells
REQUIRES lists; --examples prints the worked examples of the plan;
otherwise the artifact folders given are judged."""
import argparse
import csv
import itertools
import pathlib
import re
import sys

MIN_STALLS = 5
# Planned rounds per cell (pty-stall.yml): sessions, not groups.
PLANNED = {"bash-nonzero": 1000, "fish-nothing": 400, "fish-nul": 200}
PRODUCTS = ("real", "function", "stub", "none")
DRIVERS = ("session", "drain")
# Products a body runs with; the other cells are n/a.
RUNS = {"bash-nonzero": PRODUCTS, "fish-nothing": ("stub",), "fish-nul": ("real", "stub")}
CAUSES = ("harness", "test double", "binary", "hook", "environment")
ROWS = CAUSES + ("undecided: several causes", "undecided: the others are not ruled out",
                 "undecided: missing cells", "undecided: no cause fits")

T, F, U = "T", "F", "U"
HERE, OTHER = "here", "other"

# Cells each cause needs (required) and reads when the body has them
# (optional). A cause applies to a body that runs all its required cells.
# "harness" reads every product the body runs, so it lists none as required.
REQUIRES = {
    "harness": ((), tuple((HERE, p, d) for p in PRODUCTS for d in DRIVERS)),
    "test double": (((HERE, "stub", "drain"), (HERE, "real", "drain")),
                    ((HERE, "function", "drain"), (HERE, "none", "drain"))),
    "binary": (((HERE, "real", "drain"), (HERE, "stub", "drain")), ()),
    "hook": (((HERE, "none", "drain"), (HERE, "stub", "drain"), (HERE, "real", "drain")),
             ((HERE, "function", "drain"),)),
    "environment": (((HERE, "stub", "session"), (HERE, "stub", "drain"),
                     (OTHER, "stub", "session"), (OTHER, "stub", "drain")), ()),
}


def body_cells(case):
    """Every cell the body runs: this host and the other, its products, both
    drivers."""
    return {(side, p, d) for side in (HERE, OTHER) for p in RUNS[case] for d in DRIVERS}


def applies(case):
    have = body_cells(case)
    return tuple(c for c in CAUSES if set(REQUIRES[c][0]) <= have)


def reads(case, cause):
    """Cells the cause's condition must read for this body."""
    req, opt = REQUIRES[cause]
    return set(req) | (set(opt) & body_cells(case))


def is_(v, want):
    """Atom: the cell's value is `want` (Y or N), three-valued."""
    return U if v == "U" else (T if v == want else F)


def and_(*xs):
    return F if F in xs else (U if U in xs else T)


def or_(*xs):
    return T if T in xs else (U if U in xs else F)


def condition(case, cause, cell):
    """The cause's condition; `cell(side, product, driver)` gives Y, N or U.
    Optional cells the body does not run are left out, never read."""
    have = body_cells(case)

    def has(*k):
        return k in have

    if cause == "harness":
        drains = [is_(cell(HERE, p, "drain"), "N") for p in RUNS[case]]
        sessions = [is_(cell(HERE, p, "session"), "Y") for p in RUNS[case]]
        # The driver alone: no stall under the draining driver for any
        # product the body runs, a stall under the existing Session.
        return and_(*drains, or_(*sessions))
    if cause == "test double":
        # Only the test double stalls.
        others = [is_(cell(HERE, p, "drain"), "N") for p in ("real", "function", "none") if has(HERE, p, "drain")]
        return and_(is_(cell(HERE, "stub", "drain"), "Y"), *others)
    if cause == "binary":
        # The real binary stalls where the double does not.
        return and_(is_(cell(HERE, "real", "drain"), "Y"), is_(cell(HERE, "stub", "drain"), "N"))
    if cause == "hook":
        # The hooks: a stall without the binary (function), or with both
        # binaries, and none without bingsu.
        both = and_(is_(cell(HERE, "stub", "drain"), "Y"), is_(cell(HERE, "real", "drain"), "Y"))
        alt = or_(is_(cell(HERE, "function", "drain"), "Y"), both) if has(HERE, "function", "drain") else both
        return and_(is_(cell(HERE, "none", "drain"), "N"), alt)
    if cause == "environment":
        # Stays when the driver changes, splits by host: the double stalls
        # under both drivers here and under neither on the other host.
        return and_(is_(cell(HERE, "stub", "session"), "Y"), is_(cell(HERE, "stub", "drain"), "Y"),
                    is_(cell(OTHER, "stub", "session"), "N"), is_(cell(OTHER, "stub", "drain"), "N"))
    raise ValueError(cause)


def predicates(case, cell):
    return {c: condition(case, c, cell) for c in applies(case)}


def verdict(preds):
    vals = list(preds.values())
    t, u = vals.count(T), vals.count(U)
    if t >= 2:
        return "undecided: several causes"
    if t == 1:
        return next(k for k, v in preds.items() if v == T) if u == 0 else "undecided: the others are not ruled out"
    return "undecided: missing cells" if u else "undecided: no cause fits"


def rows_matched(preds):
    """Every row whose condition holds, written out separately from verdict()
    so that the enumeration checks the conditions, not one function twice."""
    vals = list(preds.values())
    t, u = vals.count(T), vals.count(U)
    out = [k for k, v in preds.items() if v == T and t == 1 and u == 0]
    if t >= 2:
        out.append("undecided: several causes")
    if t == 1 and u >= 1:
        out.append("undecided: the others are not ruled out")
    if t == 0 and u >= 1:
        out.append("undecided: missing cells")
    if t == 0 and u == 0:
        out.append("undecided: no cause fits")
    return out


def universe(case):
    """The cells any applicable cause reads, in a fixed order."""
    cells = set()
    for c in applies(case):
        cells |= reads(case, c)
    return sorted(cells)


def table(out):
    out.write("| cause | required cells | optional cells | bodies |\n| -- | -- | -- | -- |\n")
    for c in CAUSES:
        req, opt = REQUIRES[c]
        if c == "harness":
            req_s, opt_s = "every product the body runs, both drivers, this host", "-"
        else:
            req_s = ", ".join(f"{s}:{p}/{d}" for s, p, d in req)
            opt_s = ", ".join(f"{s}:{p}/{d}" for s, p, d in opt) or "-"
        bodies = ", ".join(b for b in RUNS if c in applies(b))
        out.write(f"| {c} | {req_s} | {opt_s} | {bodies} |\n")


def enumerate_all(out):
    ok = True
    for case in RUNS:
        cells = universe(case)
        # Each condition reads exactly the cells REQUIRES lists for this body.
        for cause in applies(case):
            seen = set()

            def spy(*k, seen=seen):
                seen.add(k)
                return "Y"
            condition(case, cause, spy)
            if seen != reads(case, cause):
                ok = False
                out.write(f"FAIL {case} {cause}: reads {sorted(seen)}, REQUIRES says {sorted(reads(case, cause))}\n")
        counts = dict.fromkeys(ROWS, 0)
        for values in itertools.product("YNU", repeat=len(cells)):
            v = dict(zip(cells, values))
            preds = predicates(case, lambda *k, v=v: v[k])
            matched = rows_matched(preds)
            if len(matched) != 1 or matched[0] != verdict(preds):
                ok = False
                out.write(f"FAIL {case} {''.join(values)}: rows {matched}, verdict {verdict(preds)}\n")
            counts[matched[0]] += 1
        out.write(f"{case}: causes {', '.join(applies(case))}; {3 ** len(cells)} combinations of "
                  f"{len(cells)} cells, each in exactly one row\n")
        for row in ROWS:
            out.write(f"  {row}: {counts[row]}\n")
    out.write("ok\n" if ok else "FAILED\n")
    return ok


def ex(**kv):
    """Example cells: here_real_drain="Y", other_stub_session="N", ..."""
    return {tuple(k.split("_", 2)): v for k, v in kv.items()}


EXAMPLES = [
    ("review: real Y, stub N, function Y, none N (bash)", "bash-nonzero",
     ex(here_real_drain="Y", here_stub_drain="N", here_function_drain="Y", here_none_drain="N",
        here_real_session="Y", here_stub_session="N", here_function_session="Y", here_none_session="N",
        other_stub_session="N", other_stub_drain="N")),
    ("environment: stub Y under both drivers here, N on the other host (fish-nothing)", "fish-nothing",
     ex(here_stub_session="Y", here_stub_drain="Y", other_stub_session="N", other_stub_drain="N")),
    ("environment and test double together (fish-nul)", "fish-nul",
     ex(here_stub_session="Y", here_stub_drain="Y", here_real_session="N", here_real_drain="N",
        other_stub_session="N", other_stub_drain="N")),
    ("smoke: fish-nul real/session Y, the rest N", "fish-nul",
     ex(here_real_session="Y", here_real_drain="N", here_stub_session="N", here_stub_drain="N",
        other_stub_session="N", other_stub_drain="N")),
    ("smoke: fish-nul real/drain Y, stub/drain N", "fish-nul",
     ex(here_real_session="Y", here_real_drain="Y", here_stub_session="N", here_stub_drain="N",
        other_stub_session="N", other_stub_drain="N")),
    ("smoke: fish-nul real and stub Y under both drivers, other host stub Y", "fish-nul",
     ex(here_real_session="Y", here_real_drain="Y", here_stub_session="Y", here_stub_drain="Y",
        other_stub_session="Y", other_stub_drain="Y")),
]


def examples(out):
    for name, case, given in EXAMPLES:
        preds = predicates(case, lambda *k, g=given: g.get(k, "U"))
        true = [k for k, v in preds.items() if v == T]
        out.write(f"{name}: {verdict(preds)} (true: {', '.join(true) or 'none'})\n")


NAME = re.compile(r"stall-(macos|linux)-(none|cargo)-(real|function|stub|none)-(session|drain)$")


class DuplicateInput(Exception):
    """The same results would be counted twice."""


def judge_dirs(dirs, out, err=sys.stderr):
    """Counts per (case, host, load, product, driver) from artifact folders
    named as pty-stall.yml names them, then one verdict per case, host and
    load. Runs with different seeds add up; the same folder twice, or two
    folders with the same seed for the same cell, are refused (they would
    cross MIN_STALLS or PLANNED with counts that were never run)."""
    count = {}
    folders = set()
    seeded = set()
    for d in dirs:
        path = pathlib.Path(d)
        m = NAME.search(path.name)
        if not m:
            err.write(f"skipped (name is not stall-<host>-<load>-<product>-<driver>): {path}\n")
            continue
        real = path.resolve()
        if real in folders:
            raise DuplicateInput(f"folder given twice: {real}")
        folders.add(real)
        host, load, product, driver = m.groups()
        with open(path / "summary.tsv") as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        for seed in sorted({row["seed"] for row in rows}):
            key = (seed, host, load, product, driver)
            if key in seeded:
                raise DuplicateInput(f"seed {seed} for {host}/{load}/{product}/{driver} given twice: {path}")
            seeded.add(key)
        for row in rows:
            if row["result"] == "n/a":
                continue
            k = (row["case"], host, load, product, driver)
            n, s = count.get(k, (0, 0))
            count[k] = (n + 1, s + (row["result"] == "stall"))

    def value(case, host, load, product, driver):
        if product not in RUNS[case]:
            return "U"
        n, s = count.get((case, host, load, product, driver), (0, 0))
        if s >= MIN_STALLS:
            return "Y"
        if s == 0 and n >= PLANNED[case]:
            return "N"
        return "U"

    for case in RUNS:
        for host, load in itertools.product(("macos", "linux"), ("none", "cargo")):
            other = "linux" if host == "macos" else "macos"

            def cell(side, p, d, case=case, host=host, other=other, load=load):
                return value(case, host if side == HERE else other, load, p, d)
            preds = predicates(case, cell)
            cells = " ".join(f"{s}:{p}/{d}={cell(s, p, d)}" for s, p, d in universe(case))
            out.write(f"{case} {host} {load}: {verdict(preds)} [{cells}]\n")


def self_check(out):
    """judge_dirs on made-up folders: the same folder twice and a copy with
    the same seed are refused, a second seed adds up."""
    import io
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)

        def art(name, seed, n, stalls):
            d = root / name
            d.mkdir(parents=True)
            with open(d / "summary.tsv", "w") as f:
                f.write("case\tproduct\tdriver\tround\tstage\tresult\tseconds\tseed\tnotes\n")
                for i in range(n):
                    f.write(f"fish-nul\tx\tx\t{i}\tbody\t{'stall' if i < stalls else 'ok'}\t1\t{seed}\t\n")
            return str(d)

        a = art("a/stall-macos-cargo-real-drain", "1", 100, 3)
        same_seed = art("b/stall-macos-cargo-real-drain", "1", 100, 3)
        other_seed = art("c/stall-macos-cargo-real-drain", "2", 100, 3)
        skipped = art("d/stall-macos-cargo-real-drain-strace", "1", 100, 3)
        for name, dirs, want in (("same folder twice", [a, a], "refused"),
                                 ("same seed in another folder", [a, same_seed], "refused"),
                                 ("two seeds add up", [a, other_seed], "real/drain=Y"),
                                 ("one seed alone", [a], "real/drain=U")):
            buf, err = io.StringIO(), io.StringIO()
            try:
                judge_dirs([skipped] + dirs, buf, err)
                got = "real/drain=Y" if "here:real/drain=Y" in buf.getvalue().split("fish-nul macos cargo")[1].split("\n")[0] \
                    else "real/drain=U"
            except DuplicateInput:
                got = "refused"
            good = got == want and "skipped" in err.getvalue()
            ok &= good
            out.write(f"{'ok' if good else 'FAIL'} {name}: {got} (want {want})\n")
    out.write("ok\n" if ok else "FAILED\n")
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--table", action="store_true")
    ap.add_argument("--enumerate", action="store_true")
    ap.add_argument("--examples", action="store_true")
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("dirs", nargs="*")
    args = ap.parse_args(argv)
    if args.table:
        table(sys.stdout)
        return 0
    if args.enumerate:
        return 0 if enumerate_all(sys.stdout) else 1
    if args.examples:
        examples(sys.stdout)
        return 0
    if args.self_check:
        return 0 if self_check(sys.stdout) else 1
    try:
        judge_dirs(args.dirs, sys.stdout)
    except DuplicateInput as e:
        sys.stderr.write(f"refused: {e}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
