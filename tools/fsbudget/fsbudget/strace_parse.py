"""Parse `strace STRACE_FLAGS -o FILE` output into calls (one per syscall).

Fail-closed: anything the parser cannot account for is a structural error
(returned in `Trace.errors`, which the attribution step turns into a gate
failure): a non-blank line without a PID prefix, a PID-prefixed record that
is neither a call, a signal nor an exit, a call whose arguments are not
balanced (quotes, `()[]{}`, `-y` fd names, see `scan`), a `resumed` record
with no matching `unfinished` one (or for another syscall), a second
`unfinished` call on the same PID, and an `unfinished` call still open at
the end of the trace.

Exit records become `EXIT` events in the call list, so attribution can close
a TID's state before the kernel hands the number to another task. A call
still unfinished at its process's exit record is kept as a call with result
`?` (it was made; it counts).
"""
import re
from dataclasses import dataclass

# -q, not -qq: the parser closes a call a dead process never finished at
# its "+++ exited/killed +++" record. -qq drops the "+++ exited with N +++"
# records (strace 5.16 and 6.13 still print "+++ killed by ... +++").
STRACE_FLAGS = ("-f", "-q", "-y", "-s", "256")
LINE = re.compile(r"^(\d+)\s+(.*)$")
CALL_HEAD = re.compile(r"^(\w+)\(")
UNFINISHED = re.compile(r"^(\w+)\((.*?)\s*<unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
# strace 5.16 and 6.13 close a call cut short by death this way.
CUT_SHORT = re.compile(r"^\s*<unfinished \.\.\.>\)\s+=\s+\?$")
RESULT = re.compile(r"^\s+=\s+(\S.*)$")
SIGNAL = re.compile(r"^--- \S.* ---$")
EXIT = re.compile(r"^\+\+\+ (exited with \d+|killed by \S+( \(core dumped\))?) \+\+\+$")
# The event name of an exit record; never a syscall name.
EXIT_EVENT = "+++exit"
# An fd that strace -y names: a number (also `fd=3` in a struct) or AT_FDCWD.
FD_BEFORE_NAME = re.compile(r"(?:^|[^\w])(?:\d+|AT_FDCWD)$")
CLOSE = {")": "(", "]": "[", "}": "{"}


class StructureError(ValueError):
    pass


def scan(text: str, start: int = 0, until_close: bool = False) -> tuple[list[str], int]:
    """Split call arguments at top-level commas, checking their structure.

    Quoted strings (with backslash escapes, optionally followed by `...` when
    truncated) and `/* comments */` are opaque. `<...>` is an fd name and is
    allowed only right after an fd number or AT_FDCWD; strace -y escapes `<`
    and `>` inside it (\\74, \\76), so the first `>` closes it. Brackets must
    nest by type. Anything else is a StructureError.

    With until_close the scan stops at the `)` that closes the call and
    returns the index after it; otherwise the whole text must be balanced.
    """
    out, cur, stack = [], [], []
    i, n = start, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise StructureError("unterminated string")
            j += 1
            if text.startswith("...", j):
                j += 3
            cur.append(text[i:j])
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise StructureError("unterminated comment")
            cur.append(text[i:j + 2])
            i = j + 2
            continue
        if ch == "<":
            if not FD_BEFORE_NAME.search("".join(cur)):
                raise StructureError(f"'<' not after an fd at {i}")
            j = text.find(">", i + 1)
            if j < 0 or "<" in text[i + 1:j]:
                raise StructureError(f"unterminated fd name at {i}")
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        if ch == ">":
            raise StructureError(f"stray '>' at {i}")
        if ch in "([{":
            stack.append(ch)
        elif ch in CLOSE:
            if not stack:
                if until_close and ch == ")":
                    out.append("".join(cur).strip())
                    return (out if out != [""] else []), i + 1
                raise StructureError(f"unbalanced '{ch}' at {i}")
            if stack.pop() != CLOSE[ch]:
                raise StructureError(f"mismatched '{ch}' at {i}")
        elif ch == "," and not stack:
            out.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if until_close:
        raise StructureError("call not closed")
    if stack:
        raise StructureError(f"unclosed '{stack[-1]}'")
    if cur or out:
        out.append("".join(cur).strip())
    return out, i


def _complete(name: str, body: str) -> tuple[str, str]:
    """`body` is everything after `name(`; returns (args, result)."""
    _, end = scan(body, until_close=True)
    r = RESULT.match(body[end:])
    if not r:
        raise StructureError(f"{name}: no result after the closing parenthesis")
    return body[:end - 1], r.group(1)


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

    def add(pid, name, args, ret):
        calls.append(Call(pid, name, args, ret, len(calls)))

    def cut_short(n, pid, name, head):
        # The arguments printed before <unfinished ...> must be well formed too.
        try:
            scan(head)
        except StructureError as err:
            calls.errors.append(f"line {n}: pid {pid}: unparsed record: {name}: {err}")
            return
        add(pid, name, head, "?")

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
        if e := EXIT.match(rest):
            if pid in pending:  # a dead process never resumes its call; it still made it
                cut_short(n, pid, *pending.pop(pid))
            add(pid, EXIT_EVENT, e.group(1), "")
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
            if CUT_SHORT.match(r.group(2)):
                cut_short(n, pid, name, head)
                continue
            try:
                args, ret = _complete(name, head + r.group(2))
            except StructureError as err:
                calls.errors.append(f"line {n}: pid {pid}: unparsed record: {name}: {err}")
                continue
            add(pid, name, args, ret)
            continue
        if h := CALL_HEAD.match(rest):
            try:
                args, ret = _complete(h.group(1), rest[h.end():])
            except StructureError as err:
                calls.errors.append(f"line {n}: pid {pid}: unparsed record: {h.group(1)}: {err}: {rest[:80]}")
                continue
            add(pid, h.group(1), args, ret)
            continue
        calls.errors.append(f"line {n}: pid {pid}: unparsed record: {rest[:80]}")
    for pid, (name, _) in sorted(pending.items()):
        calls.errors.append(f"pid {pid}: {name} still unfinished at the end of the trace")
    return calls
