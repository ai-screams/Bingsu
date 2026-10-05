#!/usr/bin/env python3
"""Run the record golden vectors through one shell reader and compare.

Usage: run.py --shell zsh|bash|fish --locale LOCALE [--opts a,b]
Fails if any row differs from expected.tsv/transitions.tsv, if the shell
wrote anything to stderr, or if a hostile vector created the canary.
For bash it also fails if _bingsu_frame changes the nocasematch state.
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
READER = {
    "zsh": ROOT / "crates/bingsu/src/shell/zsh/reader.zsh",
    "bash": ROOT / "crates/bingsu/src/shell/bash/reader.bash",
    "fish": ROOT / "crates/bingsu/src/shell/fish/reader.fish",
}
CMD = {"zsh": ["zsh", "-f"], "bash": ["bash", "--noprofile", "--norc"], "fish": ["fish", "--no-config"]}


def quote(shell, word):
    """Same rule as bingsu_core::shell_word::encode_word, so the reader this
    runner tests is byte-identical to the one init embeds."""
    if shell == "fish":
        return "'" + word.replace("\\", "\\\\").replace("'", "\\'") + "'"
    return "'" + word.replace("'", "'\\''") + "'"


def render_reader(shell, dst):
    codes = (HERE / "known_codes.txt").read_text().split()
    text = READER[shell].read_text().replace("@KNOWN_CODES@", " ".join(quote(shell, c) for c in codes))
    dst.write_text(text)


def shell_version(shell):
    cmd = {"zsh": ["zsh", "-fc", "echo $ZSH_VERSION"], "bash": ["bash", "-c", 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"'],
           "fish": ["fish", "--version"]}[shell]
    m = re.search(r"(\d+)\.(\d+)", subprocess.run(cmd, capture_output=True, text=True).stdout)
    return (int(m.group(1)), int(m.group(2)))


def _version_ok(rule, v):
    if rule == "*":
        return True
    m = re.fullmatch(r"(>=|<)(\d+)\.(\d+)", rule)
    want = (int(m.group(2)), int(m.group(3)))
    return v >= want if m.group(1) == ">=" else v < want


COLUMNS = {"frame": 4, "pty": 5}
# "accept-stripped" (bash): the reader prints accept, and the fields equal the
# input with every NUL removed, because bash drops NUL in command substitution
# before the reader sees the bytes.
ACCEPTED = ("accept", "accept-stripped")


def nul_override(rows, vector, shell, version, locale, column="frame"):
    """The `column` value ("frame": reader outcome, "pty": screen outcome) of
    the first row matching vector, shell, version range and locale group.
    None when no row matches or the matching row leaves that column "-"
    (unpinned)."""
    for row in rows:
        vec, sh, rule, locales = row[:4]
        if vec == vector and sh == shell and _version_ok(rule, version) and (locales == "*" or locale in locales.split(",")):
            value = row[COLUMNS[column]]
            return None if value == "-" else value
    return None


def resolve_observations(want, nrows, shell, version, locale, record):
    """Pin every `observe` vector from nul_expected.tsv (first matching row
    wins, so row order matters). Without --record-observations an unmatched
    vector is an error: a new shell, version or locale cannot pass unpinned."""
    errors = []
    for name in list(want):
        if want[name][0] != "observe":
            continue
        frame = nul_override(nrows, name, shell, version, locale)
        if frame:
            want[name] = (frame, "ok", "-") if frame in ACCEPTED else (frame, "-", "-")
        elif not record:
            errors.append(f"{name}: no nul_expected.tsv row for {shell} {version[0]}.{version[1]} {locale} "
                          "(run with --record-observations, review the output, add a row)")
    return errors


def nul_rows():
    rows = []
    for line in (HERE / "nul_expected.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            rows.append(tuple(line.split("\t")))
    return rows


def expected(shell, locale):
    rows = {}
    for line in (HERE / "expected.tsv").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, frame, disp, note, over = line.split("\t")
        if over != "-":
            loc, rules = over.split(":", 1)
            for rule in rules.split(","):
                sh, val = rule.split("=")
                if loc == locale and sh == shell:  # exact: "C" must not match "C.UTF-8"
                    frame, disp, note = val, "-", "-"
        rows[name] = (frame, disp, note)
    sys.path.insert(0, str(HERE.parents[1] / "hostile"))  # tests/hostile/
    import matrix  # noqa: E402
    for cls, _, _, _, reader, _ in matrix.rows():
        rows[f"hostile_{cls}"] = (reader, "ok", "-") if reader == "accept" else (reader, "-", "-")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shell", required=True, choices=sorted(CMD))
    ap.add_argument("--locale", required=True)
    ap.add_argument("--opts", default="")
    # Opt-in only: print unpinned NUL results instead of failing on them.
    ap.add_argument("--record-observations", action="store_true",
                    default=os.environ.get("BINGSU_RECORD_OBSERVATIONS") == "1")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        canary = td / "canary"
        subprocess.run([sys.executable, HERE / "make_vectors.py", td / "v", canary], check=True, capture_output=True)
        reader = td / f"reader.{a.shell}"
        render_reader(a.shell, reader)
        env = {"PATH": os.environ["PATH"], "HOME": str(td), "LC_ALL": a.locale,
               "BINGSU_TEST_OPTS": a.opts, "BINGSU_TEST_SHOPT": a.opts}
        ext = {"zsh": "zsh", "bash": "bash", "fish": "fish"}[a.shell]
        r = subprocess.run(CMD[a.shell] + [HERE / f"run.{ext}", reader, td / "v", HERE / "transitions.tsv"],
                           capture_output=True, env=env, timeout=300)
        errors = []
        if r.returncode != 0:
            errors.append(f"runner exit {r.returncode}")
        if r.stderr:
            errors.append(f"stderr not empty: {r.stderr[:400]!r}")
        if canary.exists():
            errors.append("CANARY CREATED: a status string was executed")
        want = expected(a.shell, a.locale)
        errors += resolve_observations(want, nul_rows(), a.shell, shell_version(a.shell), a.locale,
                                      a.record_observations)
        seen = set()
        stdout = r.stdout.decode("utf-8", "replace")
        shopt_seen = set()
        fseen = {}
        useen = {}
        nm_want = "on" if "nocasematch" in a.opts.split(",") else "off"
        for line in stdout.splitlines():
            kind, *cols = line.split("\t")
            if kind == "R":
                name, frame, disp, note = cols
                seen.add(name)
                w = want.get(name)
                if w is None:
                    errors.append(f"unexpected vector {name}")
                elif w[0] == "observe":
                    print(f"OBSERVE {a.shell} {a.locale} {name}: {frame} {disp} {note}")
                elif (frame, disp, note) != (("accept",) + w[1:] if w[0] == "accept-stripped" else w):
                    errors.append(f"{name}: got {(frame, disp, note)} want {w}")
            elif kind == "U":
                useen[cols[0]] = cols[1]
            elif kind == "F":
                name, n, hexs = cols
                fseen[name] = (int(n), hexs)
            elif kind == "S":
                name, before, after = cols
                shopt_seen.add(name)
                if (before, after) != (nm_want, nm_want):
                    errors.append(f"{name}: nocasematch before={before} after={after} want {nm_want} both")
            elif kind == "T":
                old, new, due, key = cols
                seen.add(f"T:{old}>{new}")
        # Contract: a rejected record leaves _bingsu_f empty; an accepted one
        # leaves the nine input field bytes unchanged (nothing is expanded),
        # except that an accept-stripped one has lost every NUL.
        for name, w in want.items():
            if w[0] == "observe":
                continue
            if name not in fseen:
                errors.append(f"{name}: no F line")
                continue
            n, hexs = fseen[name]
            if w[0] == "reject":
                if n != 0:
                    errors.append(f"{name}: rejected but _bingsu_f has {n} elements")
            else:
                data = (td / "v" / f"{name}.bin").read_bytes()
                if w[0] == "accept-stripped":
                    data = data.replace(b"\x00", b"")
                fields = data[:-1].split(b"\x1f")
                if (n, hexs) != (len(fields), ",".join(f.hex() for f in fields)):
                    errors.append(f"{name}: field bytes differ from the input record")
        standalone = {"bash": "status_ok_upper", "fish": "status_ok_lf"}.get(a.shell)
        if standalone and useen.get(standalone) != "reject":
            errors.append(f"standalone _bingsu_status_ok {standalone}: {useen.get(standalone)}, want reject")
        if a.shell == "bash" and shopt_seen != set(want):
            errors.append(f"nocasematch state not reported for: {sorted(set(want) - shopt_seen)}")
        for line in (HERE / "transitions.tsv").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            old, new, due, key = line.split("|")
            got = [l for l in stdout.splitlines() if l == f"T\t{old}\t{new}\t{due}\t{key}"]
            if not got:
                errors.append(f"transition {old!r}->{new!r}: want due={due} key={key!r}")
        missing = set(want) - seen
        if missing:
            errors.append(f"vectors not reported: {sorted(missing)}")
        label = f"{a.shell} {a.locale} opts={a.opts or '-'}"
        if errors:
            print(f"FAIL {label}\n  " + "\n  ".join(errors))
            return 1
        print(f"ok {label}: {len(want)} vectors, transitions match")
        return 0


if __name__ == "__main__":
    sys.exit(main())
