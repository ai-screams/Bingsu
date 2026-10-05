"""The hostile-value matrix (tests/hostile/classes.tsv). Every Python reader
of the matrix goes through rows() and payload(): rows() checks the declared
row count, the column count and every enumerated column, so a deleted,
added or mistyped row fails every test that uses it. The Rust producer test
(crates/bingsu-core/tests/hostile_classes.rs) parses the same file itself."""
import pathlib
import re

MATRIX = pathlib.Path(__file__).resolve().parent / "classes.tsv"
CLASS = re.compile(r"[a-z][a-z0-9_]*")
COLUMNS = ("class", "payload", "canary", "producer", "reader", "pty")
ALLOWED = {
    "canary": {"yes", "no"},
    "producer": {"accept", "reject", "replaced"},
    "reader": {"accept", "reject", "observe"},
    "pty": {"noexec", "minimal", "observe"},
}


def payload(spec, canary=b"CANARY"):
    """The bytes of a payload column; CANARY becomes `canary` (bytes)."""
    if spec.startswith("repeat:"):
        _, byte, n = spec.split(":")
        return bytes([int(byte, 16)]) * int(n)
    return bytes.fromhex(spec).replace(b"CANARY", canary)


def rows():
    text = MATRIX.read_text()
    m = re.search(r"^# rows\t(\d+)$", text, re.M)
    if not m:
        raise ValueError("classes.tsv: missing the '# rows<TAB>N' line")
    numbered = [(n, line.split("\t")) for n, line in enumerate(text.splitlines(), 1)
                if line and not line.startswith("#")]
    out = [r for _, r in numbered]
    if len(out) != int(m.group(1)):
        raise ValueError(f"classes.tsv declares {m.group(1)} rows but has {len(out)}")
    seen = {}
    for n, r in numbered:
        # The class names the golden vector (hostile_<class>) and the test id:
        # an empty or repeated one would let two rows share one vector.
        if not CLASS.fullmatch(r[0]):
            raise ValueError(f"classes.tsv line {n}: class {r[0]!r} does not match {CLASS.pattern}")
        if r[0] in seen:
            raise ValueError(f"classes.tsv line {n}: class {r[0]!r} repeats line {seen[r[0]]}")
        seen[r[0]] = n
        if len(r) != len(COLUMNS):
            raise ValueError(f"classes.tsv row {r[0]!r}: {len(r)} columns, want {len(COLUMNS)}")
        for i, name in enumerate(COLUMNS):
            if name in ALLOWED and r[i] not in ALLOWED[name]:
                raise ValueError(f"classes.tsv row {r[0]!r}: {name}={r[i]!r}, want one of {sorted(ALLOWED[name])}")
        # canary=yes exactly when the payload carries the canary path.
        if (r[2] == "yes") != (b"CANARY" in payload(r[1])):
            raise ValueError(f"classes.tsv row {r[0]!r}: canary={r[2]} disagrees with the payload")
    return out
