"""Parse `strace STRACE_FLAGS -o FILE` output into calls (one per syscall).

Fail-closed: anything the parser cannot account for is a structural error
(returned in `Trace.errors`, which the attribution step turns into a gate
failure): a non-blank line without a PID prefix, a PID-prefixed record that
is neither a call, a signal nor an exit, a `resumed` record with no matching
`unfinished` one (or for another syscall), a second `unfinished` call on the
same PID, and an `unfinished` call still open at the end of the trace.
"""
import re
from dataclasses import dataclass

# -q, not -qq: the parser closes a call a dead process never finished at
# its "+++ exited/killed +++" record. -qq drops the "+++ exited with N +++"
# records (strace 5.16 and 6.13 still print "+++ killed by ... +++").
STRACE_FLAGS = ("-f", "-q", "-y", "-s", "256")
LINE = re.compile(r"^(\d+)\s+(.*)$")
FULL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(.*)$")
UNFINISHED = re.compile(r"^(\w+)\((.*?)\s*<unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(.*)$")
SIGNAL = re.compile(r"^--- \S.* ---$")
EXIT = re.compile(r"^\+\+\+ (exited with \d+|killed by \S+( \(core dumped\))?) \+\+\+$")


@dataclass
class Call:
    pid: int
    name: str
    args: str
    ret: str
    index: int


class Trace(list):
    """The parsed calls (a list) plus the structural errors."""

    def __init__(self):
        super().__init__()
        self.errors: list[str] = []


def parse(text: str) -> Trace:
    calls = Trace()
    pending: dict[int, tuple[str, str]] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        m = LINE.match(raw)
        if not m:
            calls.errors.append(f"line {n}: no PID prefix: {raw[:80]}")
            continue
        pid, rest = int(m.group(1)), m.group(2)
        if SIGNAL.match(rest):
            continue
        if EXIT.match(rest):
            pending.pop(pid, None)  # a killed process never resumes its call
            continue
        if u := UNFINISHED.match(rest):
            if pid in pending:
                calls.errors.append(f"line {n}: pid {pid}: second unfinished call ({u.group(1)}) "
                                    f"while {pending[pid][0]} is open")
            pending[pid] = (u.group(1), u.group(2))
            continue
        if r := RESUMED.match(rest):
            if pid not in pending:
                calls.errors.append(f"line {n}: pid {pid}: {r.group(1)} resumed without an unfinished call")
                continue
            name, head = pending.pop(pid)
            if name != r.group(1):
                calls.errors.append(f"line {n}: pid {pid}: {r.group(1)} resumed but {name} was unfinished")
                continue
            calls.append(Call(pid, name, head + r.group(2), r.group(3), len(calls)))
            continue
        if f := FULL.match(rest):
            calls.append(Call(pid, f.group(1), f.group(2), f.group(3), len(calls)))
            continue
        calls.errors.append(f"line {n}: pid {pid}: unparsed record: {rest[:80]}")
    for pid, (name, _) in sorted(pending.items()):
        calls.errors.append(f"pid {pid}: {name} still unfinished at the end of the trace")
    return calls
