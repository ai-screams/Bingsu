"""The hostile-value matrix (tests/hostile/classes.tsv). Every reader of the
matrix goes through rows(): it checks the declared row count, so a deleted
or added row without a matching declaration fails every test that uses it."""
import pathlib
import re

MATRIX = pathlib.Path(__file__).resolve().parent / "classes.tsv"


def rows():
    text = MATRIX.read_text()
    m = re.search(r"^# rows\t(\d+)$", text, re.M)
    if not m:
        raise ValueError("classes.tsv: missing the '# rows<TAB>N' line")
    out = [line.split("\t") for line in text.splitlines() if line and not line.startswith("#")]
    if len(out) != int(m.group(1)):
        raise ValueError(f"classes.tsv declares {m.group(1)} rows but has {len(out)}")
    return out
