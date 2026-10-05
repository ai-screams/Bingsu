"""Drive an interactive shell in a pseudo-terminal with pexpect.

fish 4 asks the terminal questions at startup and before prompts (primary
device attributes `ESC [ c`, cursor position `ESC [ 6 n`, background colour
`OSC 11 ; ?`) and waits for the answers; a bare PTY never answers, so a fish
session answers them in every expect (observed with fish 4.9.3 on
2026-10-04). Other shells are never answered: their output may contain the
same sequences (a hostile record), and an answer would reach the child's
stdin as typed input."""
import io
import re
import subprocess
import time
import warnings

import pexpect

ANSI = re.compile(rb"\x1b\[[0-9;:?<=>]*[A-Za-z@`~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1bP[^\x1b]*\x1b\\|\x1b[()][A-Za-z0-9]|\x1b[=>78]|[\x01\x02\r]")
ARGV = {"zsh": ["-f", "-i"], "bash": ["--noprofile", "--norc", "-i"], "fish": ["--no-config", "-i"]}
QUERIES = [rb"\x1b\[0?c", rb"\x1b\[6n", rb"\x1b\]11;\?"]
ANSWERS = [b"\x1b[?62;c", b"\x1b[1;1R", b"\x1b]11;rgb:0000/0000/0000\x1b\\"]


def visible(transcript: bytes) -> bytes:
    """Transcript without terminal control sequences and readline markers."""
    return ANSI.sub(b"", transcript)


def sends_prompt_end(version_text):
    """Whether a fish sends the prompt-end mark (OSC 133;B), from the text of
    `fish --version`. Observed 2026-10-05: 3.6.0 sends no OSC 133 at all,
    4.0.2 sends 133;A, C and D but no B (and asks no terminal questions),
    4.9.3 sends B. 4.1 to 4.8 were not observed: B is expected there, and a
    missing one only warns (see Session._ready)."""
    m = re.search(r"(\d+)\.(\d+)", version_text)
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2))) >= (4, 1)


class Session:
    """An interactive shell in a PTY. Use as a context manager, or rely on
    the conftest finalizer that ends every Session a test left running."""

    live = set()

    def __init__(self, shell, env, cols=80, rows=24, respond_queries=None):
        self.shell = shell
        # Explicit only for tests of this driver; sessions answer when fish.
        self.respond_queries = shell == "fish" if respond_queries is None else respond_queries
        version = ""
        if shell == "fish":
            version = subprocess.run(["fish", "--version"], capture_output=True, text=True, env=env).stdout
        # Whether _ready waits for OSC 133;B, decided by the fish version.
        self.prompt_end = sends_prompt_end(version)
        self.log = io.BytesIO()
        # Without TERM zsh's line editor treats the terminal as dumb and never
        # draws RPROMPT; trusted_env() carries no TERM.
        env = {"TERM": "xterm-256color", **env}
        self.p = pexpect.spawn(shell, ARGV[shell], env=env, dimensions=(rows, cols), timeout=15)
        self.p.logfile_read = self.log
        Session.live.add(self)
        self.n = 0
        self._mark()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.kill()
        return False

    def kill(self):
        """End the child whatever state it is in."""
        Session.live.discard(self)
        if self.p.isalive():
            self.p.terminate(force=True)
        if not self.p.closed:
            self.p.close(force=True)

    def expect(self, pattern, timeout=15):
        """Like pexpect.expect, answering terminal queries while waiting.
        `timeout` is one deadline for the whole call: answering a query
        does not restart it."""
        pats = [pattern] + (QUERIES if self.respond_queries else [])
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise pexpect.TIMEOUT(f"no match for {pattern!r} within {timeout}s")
            i = self.p.expect(pats, timeout=left)
            if i == 0:
                return
            self.p.send(ANSWERS[i - 1])

    def _ready(self):
        """fish 4.9 drops input typed while it waits for query answers: wait
        for its prompt-end mark (OSC 133;B). Versions that send no B (3.6,
        4.0) are never waited for (sends_prompt_end). A missing B on a
        version that should send one warns and goes on: input typed now may
        be dropped, which shows up as a timeout in the test itself."""
        if not self.prompt_end:
            return
        try:
            self.expect(re.compile(rb"\x1b\]133;B"), timeout=2)
        except pexpect.TIMEOUT:
            warnings.warn("fish sent no OSC 133;B within 2 s")

    def _mark(self, timeout=15):
        self._ready()
        self.n += 1
        tok = f"BINGSU_MARK_{self.n}"
        # Typed as BINGSU_""MARK_n, printed as BINGSU_MARK_n: the echoed input
        # never contains the token, so only the command's output matches.
        self.p.sendline(f'echo BINGSU_""MARK_{self.n}')
        self.expect(tok.encode(), timeout=timeout)
        return tok

    def run(self, line, timeout=15):
        """Send `line`, then wait up to `timeout` seconds for a marker
        command typed after it."""
        self._ready()
        self.p.sendline(line)
        return self._mark(timeout)

    def close(self) -> bytes:
        try:
            self.p.sendline("exit")
            self.expect(pexpect.EOF)
        except pexpect.EOF:
            pass
        finally:
            self.kill()
        return self.log.getvalue()
