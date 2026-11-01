"""zsh on a modelled screen (spec section 7, screen and layer 3 rows): the
real binary and the built-in default theme in a PTY, judged cell by cell.
These rows pin today's behaviour before the hooks grow widgets. Text that
depends on the machine (host name, folder) is never compared: a row is judged
by its marks, its right edge and the cursor."""
import io
import os
import shutil
import subprocess
import time

import pexpect
import pytest

from conftest import Install, short_dir, trusted_env
from pty_session import Session
from screen_session import ScreenSession

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")

BLOCK_END = "▸"  # the block separator of the wide band; the narrow band has none
OK_CHAR, FAIL_CHAR = "❯", "✗"
ELLIPSIS = "…"
# A long machine name fills the row and takes the right block off the wide
# band; these rows judge the block, so the shell gets a short name. zsh keeps
# a HOST it inherits.
# 이것을 실패시키는 것: 환경에서 HOST를 빼는 것(긴 호스트 이름의 러너에서 오른쪽 블록이 사라짐).
SHORT_HOST = {"HOST": "h"}
EDITOR_ON, EDITOR_OFF = b"\x1b[?2004h", b"\x1b[?2004l"


class Recorded:
    """A stand-in Session: the transcript is given, the PTY has nothing to read."""

    class Pty:
        size = None

        def read_nonblocking(self, size, timeout):
            raise pexpect.TIMEOUT("nothing to read")

        def setwinsize(self, rows, cols):
            self.size = (rows, cols)

    def __init__(self, transcript):
        self.log = io.BytesIO()
        self.log.write(transcript)
        self.p = self.Pty()


def recorded(transcript, rows=3, cols=10):
    screen = ScreenSession(Recorded(transcript), rows, cols)
    screen.feed()
    return screen


# 이것을 실패시키는 것: .feed가 `\r`을 버리는 것, 새 바이트만 넣지 않고 처음부터 다시 넣는 것, SGR을 칸으로 세는 것,
# .cursor의 행·열을 뒤바꾸는 것, 마지막 칸 뒤 줄바꿈 대기를 다음 줄로 앞당기는 것.
def test_screen_model_tracks_cursor_and_wrap():
    screen = recorded(b"abc\rX")
    assert (screen.lines(), screen.cursor()) == (["Xbc", "", ""], (0, 1))
    screen.session.log.write(b"Y")
    screen.feed()
    assert (screen.lines()[0], screen.cursor()) == ("XYc", (0, 2))

    screen = recorded(b"\x1b[31mAB\x1b[0m" + b"x" * 8)
    assert (screen.lines()[0], screen.cursor()) == ("ABxxxxxxxx", (0, 10))
    screen.session.log.write(b"y")
    screen.feed()
    assert (screen.lines()[:2], screen.cursor()) == (["ABxxxxxxxx", "y"], (1, 1))


# 이것을 실패시키는 것: 대체 화면을 흉내 내지 않는 것(pyte는 1049를 무시한다), 복귀 때 행이나 커서를 되돌리지 않는 것.
def test_screen_model_alternate_screen_comes_back():
    screen = recorded(b"keep\r\nab\x1b[?1049h\x1b[2;2HJUNK")
    assert screen.lines() == ["", " JUNK", ""]
    screen.session.log.write(b"\x1b[?1049lc")
    screen.feed()
    assert (screen.lines(), screen.cursor()) == (["keep", "abc", ""], (1, 3))


# 이것을 실패시키는 것: .resize가 화면 모델만 바꾸거나 pty 크기만 바꾸는 것, 새 크기 전에 쌓인 출력을 넣지 않는 것.
def test_screen_model_resize_sets_both_sizes():
    screen = recorded(b"", rows=3, cols=10)
    screen.session.log.write(b"x" * 11)
    screen.resize(5, 8)
    assert screen.session.p.size == (5, 8)
    assert (screen.screen.lines, screen.screen.columns) == (5, 8)
    assert screen.lines()[:2] == ["x" * 8, "x"]


# 이것을 실패시키는 것: stable을 무시하는 것(그리는 중인 화면을 판정함), 조건이 깨졌을 때 직전 화면을 잊지 않는 것, 시간이 다 되어도 True를 내는 것.
def test_screen_wait_needs_two_equal_polls_in_a_row():
    screen = recorded(b"")
    seen = []

    def growing(view):
        seen.append(view.lines()[0])
        if len(seen) < 3:
            view.session.log.write(b"x")
        return True

    assert screen.wait(growing, stable=True)
    assert seen == ["", "x", "xx", "xx"]

    answers = iter([True, False, True, True])
    calls = []
    assert screen.wait(lambda view: calls.append(1) or next(answers), stable=True)
    assert len(calls) == 4
    assert not screen.wait(lambda view: False, timeout=0.1)


def start(tmp_path, cols=100, rows=30):
    """A real prompt in a short folder. Cols 0 draws on the 80 columns zsh falls back to."""
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / "init.zsh"
    init.write_bytes(inst.init("zsh", env))
    env.update(SHORT_HOST, BINGSU_T_DIR=str(short_dir()))
    s = Session("zsh", env, cols=cols, rows=rows)
    s.run(f'source "{init}"')
    s.run('cd -- "$BINGSU_T_DIR"')
    return s, ScreenSession(s, rows, cols or 80)


def at_prompt(view):
    """The line editor is back: its bracketed-paste switch is on, and nothing moved
    between two polls (ScreenSession.wait with stable=True)."""
    log = view.session.log.getvalue()
    return log.rfind(EDITOR_ON) > log.rfind(EDITOR_OFF)


def settle(screen):
    assert screen.wait(at_prompt, stable=True), (screen.lines(), screen.cursor())


def enter(screen, line):
    """Run `line` and wait for the prompt after it. Session.run would type a
    marker command behind it, and that command's prompt would be the one judged."""
    log = screen.session.log
    seen = log.getvalue().count(EDITOR_OFF)
    screen.session.p.sendline(line)
    assert screen.wait(lambda v: log.getvalue().count(EDITOR_OFF) > seen and at_prompt(v), stable=True), (screen.lines(), screen.cursor())


def typed(screen, text):
    """Type `text` and wait until it has been drawn."""
    before = screen.session.log.tell()
    screen.session.p.send(text)
    assert screen.wait(lambda v: v.session.log.tell() > before, stable=True), screen.lines()


def filled(screen, row, col):
    """A cell with a mark or a background colour: the right block ends in a coloured blank."""
    cell = screen.screen.buffer[row][col]
    return cell.data != " " or cell.bg != "default"


def right_edge(screen, row):
    return max((col for col in range(screen.screen.columns) if filled(screen, row, col)), default=-1)


# 이것을 실패시키는 것: 목표 폭을 `폭 − 1`에서 `폭`으로 바꾸는 것(마지막 칸까지 채움), 채움을 한 칸 줄이는 것,
# 윗줄과 입력 줄 사이 줄바꿈을 더하거나 빼는 것.
@pytest.mark.parametrize("cols", [60, 61, 80, 100, 200])
def test_right_block_ends_on_the_second_to_last_cell(tmp_path, cols):
    _, screen = start(tmp_path, cols=cols)
    enter(screen, "false")
    row = screen.cursor()[0] - 1
    assert screen.lines()[row + 1].lstrip().startswith(FAIL_CHAR), screen.lines()
    assert right_edge(screen, row) == cols - 2, screen.lines()[row]
    assert not filled(screen, row, cols - 1)
    assert screen.lines()[row].endswith("1"), screen.lines()[row]


# 이것을 실패시키는 것: zsh 쪽 SGR을 `%{ %}`로 감싸지 않는 것. 터미널은 입력을 스스로 접어 위쪽 줄은 맞아 보이지만,
# 줄 처음으로 돌아가 끼워 넣으면 zsh가 자기 폭 계산으로 커서를 놓으므로 어긋난다.
@pytest.mark.parametrize("cols,band", [(40, "narrow"), (70, "wide")])
def test_cursor_follows_a_long_command(tmp_path, cols, band):
    s, screen = start(tmp_path, cols=cols)
    settle(screen)
    row, start_col = screen.cursor()
    if band == "wide":
        assert BLOCK_END in screen.lines()[row]
    k = cols + 5
    typed(screen, "x" * k)
    end = start_col + k
    assert screen.wait(lambda v: v.cursor() == (row + end // cols, end % cols), stable=True), (screen.cursor(), screen.lines())
    assert screen.lines()[row][start_col:] == "x" * (cols - start_col) and screen.lines()[row + 1] == "x" * (end - cols)
    typed(screen, "\x01Y")
    assert screen.wait(lambda v: v.cursor() == (row, start_col + 1), stable=True), (screen.cursor(), screen.lines())
    assert screen.lines()[row][start_col] == "Y"
    s.p.sendcontrol("c")


# 이것을 실패시키는 것: 프롬프트의 폭 계산이 틀려 다시 그릴 때 줄이 쌓이거나 윗줄이 지워지는 것, 다중행 항목에서 돌아온 뒤 찌꺼기가 남는 것.
def test_history_navigation_redraws_in_place(tmp_path):
    cols = 70
    s, screen = start(tmp_path, cols=cols)
    entry = "print -r -- " + "h" * (cols + 10)
    enter(screen, entry)
    enter(screen, "true")
    before, cursor = screen.lines(), screen.cursor()
    row, col = cursor
    upper = before[row - 1]
    for key in ("\x1b[A", "\x1b[A"):
        typed(screen, key)
    end = col + len(entry)
    wrapped = (row + end // cols, end % cols)
    assert screen.wait(lambda v: v.cursor()[1] == wrapped[1] and v.lines()[row + 1].startswith("h"), stable=True), screen.lines()
    assert screen.lines()[row - 1] == upper
    assert screen.lines()[row][col:].startswith(entry[:cols - col])
    for key in ("\x1b[B", "\x1b[B"):
        typed(screen, key)
    assert screen.wait(lambda v: v.cursor() == cursor and not v.lines()[row + 1], stable=True), screen.lines()
    assert (screen.lines(), screen.cursor()) == (before, cursor)


# 이것을 실패시키는 것: 프롬프트가 맨 아래 줄에서 한 줄을 더 먹는 것(윗줄과 입력 줄 사이 빈 줄), 스크롤 뒤 커서가 입력 줄을 벗어나는 것.
def test_prompt_on_the_bottom_row(tmp_path):
    rows, cols = 8, 70
    s, screen = start(tmp_path, cols=cols, rows=rows)
    for _ in range(3):
        enter(screen, "false")
    assert screen.cursor()[0] == rows - 1, screen.lines()
    assert FAIL_CHAR in screen.lines()[rows - 1] and BLOCK_END in screen.lines()[rows - 2], screen.lines()
    _, col = screen.cursor()
    typed(screen, "x" * cols)
    assert screen.wait(lambda v: v.cursor() == (rows - 1, col), stable=True), (screen.cursor(), screen.lines())
    assert BLOCK_END in screen.lines()[rows - 3], screen.lines()  # one scroll moved the prompt up as a whole
    s.p.sendcontrol("c")


# 이것을 실패시키는 것: 입력이 마지막 칸을 넘을 때 커서가 다음 줄로 가지 않거나 프롬프트 폭 계산이 한 칸 어긋나는 것.
@pytest.mark.parametrize("extra", [-1, 0, 1])
def test_input_reaching_the_last_cell(tmp_path, extra):
    cols = 70
    s, screen = start(tmp_path, cols=cols)
    settle(screen)
    row, col = screen.cursor()
    k = cols - col + extra
    typed(screen, "x" * k)
    end = col + k
    assert screen.wait(lambda v: v.cursor() == (row + end // cols, end % cols), stable=True), (screen.cursor(), screen.lines())
    assert screen.lines()[row].endswith("x" * (min(k, cols - col)))
    assert screen.lines()[row + 1] == "x" * max(extra, 0)
    s.p.sendcontrol("c")


# Width 0 in the PTY is not bingsu's width-0 rule: zsh falls back to 80 columns.
# 이것을 실패시키는 것: 좁은 폭에서 윗줄 생략 기호나 char를 잃는 것, 폭 1에서 ASCII `>`가 아닌 것, 레코드 오류로 최소 프롬프트가 되는 것.
@pytest.mark.parametrize("cols,columns,upper,lower", [
    pytest.param(0, 80, None, None, id="zero-is-zsh-80"),
    pytest.param(1, 1, ">", "", id="one"),
    pytest.param(2, 2, ELLIPSIS, OK_CHAR, id="two"),
    pytest.param(3, 3, ELLIPSIS, OK_CHAR, id="three"),
])
def test_very_narrow_widths(tmp_path, cols, columns, upper, lower):
    s, screen = start(tmp_path, cols=cols)
    s.run('print -r -- "W=$COLUMNS"')
    settle(screen)
    assert f"W={columns}".encode() in s.log.getvalue()
    row = screen.cursor()[0]
    lines = screen.lines()
    if upper is None:
        assert OK_CHAR in lines[row] and BLOCK_END in lines[row - 1], lines
    else:
        assert (lines[row - 1], lines[row]) == (upper, lower), lines
    assert b"error" not in s.log.getvalue()


# 이것을 실패시키는 것: 복귀 뒤 프롬프트가 복원된 커서 자리에 그려지지 않는 것(윗줄이 앱 출력 위에 겹침), 화면 모델이 1049를 무시하는 것.
def test_prompt_after_alternate_screen(tmp_path):
    s, screen = start(tmp_path, cols=70)
    s.run("print -r -- KEEP''ME")
    s.run(r"print -n $'\e[?1049h\e[2J\e[H'; print -r -- ALT''JUNK; print -n $'\e[?1049l'")
    settle(screen)
    lines = screen.lines()
    assert not any("ALTJUNK" in line for line in lines), lines
    assert any(line == "KEEPME" for line in lines), lines
    row = screen.cursor()[0]
    assert OK_CHAR in lines[row] and BLOCK_END in lines[row - 1], lines


# 이것을 실패시키는 것: 다음 프롬프트가 새 폭을 넘기지 않는 것(hook의 `--width`), 구간 경계를 `≤ 59`에서 옮기는 것.
def test_band_boundary_59_60_on_the_next_prompt(tmp_path):
    _, screen = start(tmp_path, cols=60)
    for cols, wide in ((60, True), (59, False), (60, True), (59, False)):
        screen.resize(30, cols)
        enter(screen, "false")
        row = screen.cursor()[0]
        lines = screen.lines()
        assert (BLOCK_END in lines[row], lines[row - 1].endswith("1")) == (wide, wide), (cols, lines)
        assert FAIL_CHAR in lines[row], (cols, lines)


def tmux(socket, *args):
    return subprocess.run(["tmux", "-S", str(socket), *args], capture_output=True, text=True, timeout=10, check=True).stdout


# tmux is the terminal here, so its capture judges, not pyte. The Linux images
# install it; the macOS job has none and deselects this test in shell.yml.
# 이것을 실패시키는 것: tmux가 없을 때 건너뛰어 통과로 세는 것, tmux 안에서 윗줄이 넘치거나 커서가 입력 줄을 벗어나는 것.
def test_prompt_inside_tmux(tmp_path):
    if shutil.which("tmux") is None:
        pytest.fail("BLOCKED: tmux is not installed in this image")
    cols, rows = 80, 24
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / "init.zsh"
    init.write_bytes(inst.init("zsh", env))
    folder = short_dir()
    socket = folder / "s"
    subprocess.run(["tmux", "-u", "-S", str(socket), "-f", "/dev/null", "new-session", "-d", "-x", str(cols), "-y", str(rows),
                    "zsh", "-f", "-i"], env={**env, **SHORT_HOST, "TERM": "xterm-256color"}, check=True, timeout=10)
    try:
        for line in (f'source "{init}"', f'cd -- "{folder}"', "false"):
            tmux(socket, "send-keys", "-l", line)
            tmux(socket, "send-keys", "Enter")
        deadline = time.monotonic() + 10
        pane = [""]
        y = 0
        while time.monotonic() < deadline:
            pane = tmux(socket, "capture-pane", "-p").splitlines()
            x, y = map(int, tmux(socket, "display-message", "-p", "#{cursor_x} #{cursor_y}").split())
            if y < len(pane) and pane[y].lstrip().startswith(FAIL_CHAR):
                break
            time.sleep(0.05)
        assert y < len(pane) and pane[y].lstrip().startswith(FAIL_CHAR), pane
        assert BLOCK_END in pane[y - 1] and pane[y - 1].endswith("1"), pane
        assert len(pane[y - 1]) == cols - 2, pane  # the digit, then the block's blank, then the empty last cell
        assert x == len(pane[y]), (x, pane[y])
    finally:
        tmux(socket, "kill-server")
