"""A terminal screen over a Session: what the shell has drawn, cell by cell.

The model is pyte, which ignores the alternate screen; the subclass below
adds the one thing the tests need from it. Rows, columns and cursor are
zero-based."""
import copy
import time

import pexpect
import pyte

ALTERNATE = 1049


class Screen(pyte.Screen):
    """pyte.Screen with the xterm alternate screen (private mode 1049): on
    entry the rows and the cursor are kept and the screen clears, on leaving
    both come back. Without it an app's rows stay on the screen after it ends."""

    def __init__(self, columns, lines):
        self.kept = None
        super().__init__(columns, lines)

    def set_mode(self, *modes, **kwargs):
        if kwargs.get("private") and ALTERNATE in modes and self.kept is None:
            self.kept = (copy.deepcopy(self.buffer), copy.copy(self.cursor))
            self.erase_in_display(2)
        super().set_mode(*modes, **kwargs)

    def reset_mode(self, *modes, **kwargs):
        if kwargs.get("private") and ALTERNATE in modes and self.kept is not None:
            self.buffer, self.cursor = self.kept
            self.kept = None
            self.dirty.update(range(self.lines))
        super().reset_mode(*modes, **kwargs)


class ScreenSession:
    def __init__(self, session, rows, cols):
        self.session = session
        self.screen = Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.fed = 0

    def feed(self) -> None:
        """Read what the shell has written so far and apply the new bytes.
        The screen follows the session's whole transcript, including what an
        expect already consumed."""
        while True:
            try:
                self.session.p.read_nonblocking(65536, timeout=0)
            except (pexpect.TIMEOUT, pexpect.EOF):
                break
        data = self.session.log.getvalue()
        self.stream.feed(data[self.fed:])
        self.fed = len(data)

    def lines(self) -> list[str]:
        """The rows as text, trailing blanks removed."""
        return [row.rstrip() for row in self.screen.display]

    def cursor(self) -> tuple[int, int]:
        """(row, column). After the last cell of a row the column equals the
        width until the next character wraps: pyte keeps the pending wrap there."""
        return self.screen.cursor.y, self.screen.cursor.x

    def resize(self, rows, cols) -> None:
        """Set the terminal size: the kernel sends SIGWINCH to the foreground
        process group. Output so far is applied at the old size first."""
        self.feed()
        self.screen.resize(rows, cols)
        self.session.p.setwinsize(rows, cols)

    def wait(self, done, timeout=10, stable=False) -> bool:
        """Feed until done(self) holds (a condition, not a fixed sleep). With
        stable=True the screen and cursor must also be the same on two polls
        in a row, so a redraw in progress is not judged."""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            self.feed()
            if done(self):
                snap = (self.lines(), self.cursor())
                if not stable or snap == last:
                    return True
                last = snap
            else:
                last = None
            time.sleep(0.05)
        return False
