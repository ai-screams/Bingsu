"""`bingsu setup`'s one-screen editor on a pseudo-terminal: the editor opens
where it can draw and the line questions come where it cannot, a saved file
is private and is what the editor showed, every way out puts the terminal
back, nothing a config names runs while the editor previews, and settings
that changed meanwhile stop the save.

The test plays the terminal. `sh` prints the terminal settings (`stty -g`)
before and after `bingsu setup`, and the test types keys; the background
query is answered (or not) as a terminal would."""
import io
import os
import re
import shutil
import signal
import tempfile
import time
from pathlib import Path

import pexpect
import pyte
import pytest

from conftest import real_bin
from pty_session import Session
from screen_session import ScreenSession
from shell_support import trusted_env

QUERY = rb"\x1b\]11;\?\x1b\\"
DARK = b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\"
TITLE = rb"bingsu setup"
KEYS = rb"enter save"
# The end of a frame: a key's frame draws only the cells that changed.
FRAME = rb"\x1b\[\?2026l"


@pytest.fixture
def home():
    root = Path(tempfile.mkdtemp(prefix="bedit-")).resolve()
    root.chmod(0o700)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def spawn(home, *args, term="xterm-256color", rows=24, cols=80, extra=None, background=False):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "PWD": str(home)}
    if term is not None:
        env["TERM"] = term
    env.update(extra or {})
    run = f'"{real_bin()}" setup {" ".join(args)}'
    # In the background `$!` names bingsu itself, for a signal; without job
    # control the job stays in the terminal's foreground group.
    run = f"{run} & echo BPID=$!; wait $!" if background else run
    script = f"echo BEFORE=$(stty -g); {run}; echo RC=$?; echo AFTER=$(stty -g)"
    child = pexpect.spawn("/bin/sh", ["-c", script], env=env, timeout=10, dimensions=(rows, cols),
                          cwd=str(home))
    child.delaybeforesend = None
    child.transcript = io.BytesIO()
    child.logfile_read = child.transcript
    return child


def finish(child):
    child.expect(pexpect.EOF)
    text = child.transcript.getvalue().decode("utf-8", "replace")
    before, after = (re.search(rf"{k}=(\S+)", text).group(1) for k in ("BEFORE", "AFTER"))
    return int(re.search(r"RC=(\d+)", text).group(1)), before, after, text


def opened(child):
    """Answers the background query and waits for the first whole frame."""
    child.expect(QUERY)
    child.send(DARK)
    child.expect(KEYS)


def config(home):
    path = home / "cfg/bingsu/config.toml"
    return path if path.exists() else None


# 이것을 실패시키는 것: 그릴 수 있는 터미널에서 편집판을 열지 않는 것, 기본 그대로 저장하면 파일을 만들지 않는 것,
# 파일이 0600이 아닌 것, 저장 화면이 보인 키와 파일이 다른 것, 확인을 같은 읽기의 두 번째 Enter로 받는 것(한 번에
# 두 Enter가 저장함), 나간 뒤 터미널 설정이 다른 것, 대체 화면을 나가지 않는 것, doctor 안내를 빼는 것.
def test_the_editor_saves_a_private_file_it_showed(home):
    child = spawn(home)
    opened(child)
    child.send("\r\r")
    child.expect(rb"enter write")
    assert config(home) is None, "one read's second Enter is no confirmation"
    child.send("\r")
    code, before, after, text = finish(child)
    assert code == 0, text
    assert before == after
    path = config(home)
    assert path is not None, text
    assert path.stat().st_mode & 0o777 == 0o600
    written = path.read_text()
    assert 'preset = "triangle"' in written and 'icons = "nerd"' in written, written
    log = child.transcript.getvalue()
    assert b"\x1b[?1049h" in log and log.rfind(b"\x1b[?1049l") > log.rfind(b"enter write")
    assert "Line ends look off? `bingsu doctor` checks the character widths." in text
    assert "wrote " in text


# 이것을 실패시키는 것: 고친 값을 파일에 쓰지 않는 것(s로 바꾼 프리셋), 미리보기가 키마다 바뀌지 않는 것.
def test_a_changed_value_is_written(home):
    child = spawn(home)
    opened(child)
    child.send("s")
    child.expect(FRAME)
    child.send("\r")
    child.expect(rb'style.preset = "pill"')
    child.send("\r")
    code, _, _, text = finish(child)
    assert code == 0, text
    assert 'preset = "pill"' in config(home).read_text()


# 이것을 실패시키는 것: q로 나갈 때 파일을 쓰는 것, 종료 코드가 0이 아닌 것, Ctrl-C를 130으로 끝내지 않는 것, 어느 쪽이든
# 터미널 설정을 되돌리지 않는 것.
@pytest.mark.parametrize(("key", "want"), [(b"q", 0), (b"\x03", 130)])
def test_quit_and_ctrl_c_write_nothing(home, key, want):
    child = spawn(home)
    opened(child)
    child.send(key)
    code, before, after, text = finish(child)
    assert code == want, text
    assert before == after
    assert config(home) is None
    assert "nothing written" in text, text


# 이것을 실패시키는 것: TERM이 dumb·빈 값·없음, `--plain`, 편집판보다 작은 창에서 편집판을 여는 것(대체 화면을 씀).
@pytest.mark.parametrize(("term", "args", "size"), [
    ("dumb", [], (24, 80)),
    ("", [], (24, 80)),
    (None, [], (24, 80)),
    ("xterm-256color", ["--plain"], (24, 80)),
    ("xterm-256color", [], (15, 80)),
    ("xterm-256color", [], (24, 39)),
])
def test_plain_terminals_get_the_line_questions(home, term, args, size):
    child = spawn(home, "--icons", "nerd", *args, term=term, rows=size[0], cols=size[1])
    child.expect(QUERY)
    child.send(DARK)
    child.expect(rb"the terminal looks dark")
    child.send("\n")
    child.expect(rb"\[Y/n\] ")
    child.send("\n")
    code, before, after, text = finish(child)
    assert code == 0, text
    assert before == after
    assert b"\x1b[?1049h" not in child.transcript.getvalue()
    assert config(home) is not None


# 이것을 실패시키는 것: 미리보기에서 설정의 명령을 돌리는 것. 명령은 돌면 표지 파일을 만든다(시험이 먼저 확인).
def test_nothing_a_config_names_runs_while_the_editor_previews(home):
    marker = home / "ran"
    conf = home / "cfg/bingsu/conf.d"
    conf.mkdir(parents=True)
    for d in [home / "cfg", home / "cfg/bingsu", conf]:
        d.chmod(0o700)
    touch = shutil.which("touch")
    (conf / "10-cmd.toml").write_text(
        f'[segment."custom/mark"]\nkind = "command"\ncommand = ["{touch}", "{marker}"]\n\n'
        '[layout.line1]\nleft = ["dir", "custom/mark"]\n')
    (conf / "10-cmd.toml").chmod(0o600)
    os.system(f'"{touch}" "{marker}"')
    assert marker.exists(), "the command leaves the marker"
    marker.unlink()
    child = spawn(home)
    opened(child)
    for key in "soj":
        child.send(key)
        child.expect(FRAME)
    child.send("q")
    child.expect(FRAME)
    child.send("q")
    code, _, _, text = finish(child)
    assert code == 0, text
    assert not marker.exists(), "a preview ran the command"
    assert config(home) is None


# 이것을 실패시키는 것: 편집하는 동안 바뀐 설정(새 conf.d 파일)을 보지 않고 쓰는 것, 그때 쓰려던 키를 알리지 않는 것,
# 종료 코드가 1이 아닌 것.
def test_settings_changed_while_editing_stop_the_save(home):
    child = spawn(home)
    opened(child)
    conf = home / "cfg/bingsu/conf.d"
    conf.mkdir(parents=True)
    for d in [home / "cfg", home / "cfg/bingsu", conf]:
        d.chmod(0o700)
    (conf / "10-mine.toml").write_text("[style]\ngap = true\n")
    (conf / "10-mine.toml").chmod(0o600)
    child.send("\r")
    child.expect(rb"enter write")
    child.send("\r")
    code, before, after, text = finish(child)
    assert code == 1, text
    assert before == after
    assert "settings changed while you edited; nothing written." in text, text
    assert 'preset = "triangle"' in text, text
    assert config(home) is None


# 이것을 실패시키는 것: NO_COLOR에서 고른 값을 반전으로 표시하지 않는 것.
def test_no_color_marks_the_pick_by_reverse(home):
    child = spawn(home, extra={"NO_COLOR": "1"})
    opened(child)
    child.send("q")
    finish(child)
    assert b"\x1b[0;1;7m" in child.transcript.getvalue()


# 이것을 실패시키는 것: 다른 사용자가 바꿀 수 있는 설정 폴더(읽는 쪽이 빼는 폴더)에서 편집판을 여는 것, 그 거부를
# 폴더 탓이라고 말하지 않는 것, 종료 코드가 1이 아닌 것.
def test_a_folder_others_can_change_is_refused_before_the_editor(home):
    folder = home / "cfg/bingsu"
    folder.mkdir(parents=True)
    (home / "cfg").chmod(0o700)
    folder.chmod(0o777)
    child = spawn(home)
    code, before, after, text = finish(child)
    assert code == 1, text
    assert before == after
    assert "is not a folder only you can change" in text, text
    assert b"\x1b[?1049h" not in child.transcript.getvalue()
    assert config(home) is None


def screen_of(child, rows=24, cols=80):
    """The editor's screen as the transcript draws it so far."""
    screen = pyte.Screen(cols, rows)
    pyte.ByteStream(screen).feed(child.transcript.getvalue())
    return screen.display


# 이것을 실패시키는 것: 키마다 미리보기를 다시 만들지 않는 것(프리셋을 바꿔도 미리보기 줄이 그대로).
def test_the_preview_follows_each_key(home):
    child = spawn(home)
    opened(child)
    child.expect(FRAME)
    before = screen_of(child)
    child.send("s")
    child.expect(FRAME)
    after = screen_of(child)
    child.send("u")
    child.expect(FRAME)
    child.send("q")
    finish(child)
    row = next(i for i, line in enumerate(before) if line.startswith(" preview"))
    assert before[row + 1] != after[row + 1], (before[row + 1], after[row + 1])
    # The folder as the shell shows it, and this machine's name.
    assert home.name in before[row + 1], before[row + 1]
    assert os.uname().nodename.split(".")[0] in before[row + 1], before[row + 1]


# 이것을 실패시키는 것: 터미널의 배경 답을 편집판에 넘기지 않는 것(밝은 터미널인데 안내가 없음), 답이 없을 때 기다리기만
# 하는 것(편집판이 열리지 않음).
def test_the_terminal_background_is_asked_once(home):
    child = spawn(home)
    child.expect(QUERY)
    child.send(b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\")
    child.expect(KEYS)
    child.expect(FRAME)
    assert any("the terminal looks light; pick light" in line for line in screen_of(child))
    child.send("q")
    assert finish(child)[0] == 0
    child = spawn(home)
    child.expect(QUERY)
    child.expect(KEYS, timeout=2)
    child.send("q")
    code, _, _, text = finish(child)
    assert code == 0, text
    assert child.transcript.getvalue().count(b"\x1b]11;?") == 1


# 이것을 실패시키는 것: Ctrl-L에 화면 전체를 다시 그리지 않는 것.
def test_ctrl_l_draws_everything_again(home):
    child = spawn(home)
    opened(child)
    child.expect(FRAME)
    start = len(child.transcript.getvalue())
    child.send(b"\x0c")
    child.expect(FRAME)
    assert b"\x1b[2J" in child.transcript.getvalue()[start:]
    child.send("q")
    finish(child)


# Ctrl-Z, `fg`, a resize and `q` under an interactive zsh. 이것을 실패시키는 것: 다시 이어 갈 때 화면 전체를 다시
# 그리지 않는 것(1049로 지워진 화면에 차이만 그림), 키 읽기와 프레임 쓰기를 처음으로 돌리지 않는 것, 크기 변경을
# 미리보기 폭에 반영하지 않는 것, 끝난 뒤 종료 코드나 터미널 설정이 다른 것.
@pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                    reason="zsh not under test")
def test_ctrl_z_fg_and_a_resize_under_zsh(tmp_path):
    env = {**trusted_env(tmp_path), "HOME": str(tmp_path), "TERM": "xterm-256color"}
    with Session("zsh", env, cols=80, rows=24) as sh:
        screen = ScreenSession(sh, 24, 80)
        sh.run(f"cd '{tmp_path}' && stty -g > before")
        sh.p.sendline(f"'{real_bin()}' setup")
        title = lambda v: v.screen.private_mode(1049) and v.lines()[0].startswith(" bingsu setup")
        assert screen.wait(title, stable=True), screen.lines()
        sh.p.send(b"\x1a")
        assert screen.wait(lambda v: not v.screen.private_mode(1049)
                           and any("suspended" in line for line in v.lines()), stable=True), screen.lines()
        sh.p.sendline("fg")
        assert screen.wait(title, stable=True), screen.lines()
        assert any(line.startswith(" preview  80 columns") for line in screen.lines()), screen.lines()
        below = lambda lines: next(lines[i + 1] for i, l in enumerate(lines) if l.startswith(" preview"))
        narrow = below(screen.lines()).rstrip()
        screen.resize(30, 100)
        assert screen.wait(lambda v: any(line.startswith(" preview  100 columns") for line in v.lines()),
                           stable=True), screen.lines()
        # Laid out again for the width (the 80-column line, kept, would be the same).
        assert below(screen.lines()).rstrip() != narrow, screen.lines()
        sh.p.send(b"q")
        assert screen.wait(lambda v: not v.screen.private_mode(1049), stable=True), screen.lines()
        # `fg` ends with the job's status.
        sh.run("echo RC=$? > rc; stty -g > after")
    assert (tmp_path / "rc").read_text().strip() == "RC=0"
    assert (tmp_path / "after").read_text() == (tmp_path / "before").read_text()


def preview_row(child, rows=24, cols=80):
    display = screen_of(child, rows, cols)
    row = next(i for i, line in enumerate(display) if line.startswith(" preview"))
    return display[row + 1]


# 이것을 실패시키는 것: 편집판 도중 창이 작아질 때 작은 화면으로 바꾸지 않는 것, 작은 동안 값 키를 받는 것, 59칸에서 내장 narrow 안내를 빼는 것,
# `layout.use_last_column` 설정의 미리보기를 한 칸 좁게 배치하지 않는 것(오른쪽 끝이 잘림).
def test_sizes_and_the_last_column(home):
    child = spawn(home)
    opened(child)
    child.setwinsize(10, 30)
    child.expect(rb"Too small")
    # While too small a value key changes nothing.
    child.send("s")
    child.expect(FRAME)
    child.setwinsize(24, 80)
    child.expect(KEYS)
    child.send("\r")
    child.expect(rb"enter write")
    child.send("\r")
    finish(child)
    assert 'preset = "triangle"' in config(home).read_text()
    config(home).unlink()
    child = spawn(home, cols=59)
    opened(child)
    child.expect(FRAME)
    assert any("narrow layout under 60 columns" in line for line in screen_of(child, 24, 59))
    child.send("q")
    finish(child)
    child = spawn(home)
    opened(child)
    child.expect(FRAME)
    plain = preview_row(child)
    child.send("q")
    finish(child)
    conf = home / "cfg/bingsu/conf.d"
    conf.mkdir(parents=True)
    for d in [home / "cfg", home / "cfg/bingsu", conf]:
        d.chmod(0o700)
    (conf / "10-last.toml").write_text("[layout]\nuse_last_column = true\n")
    (conf / "10-last.toml").chmod(0o600)
    child = spawn(home)
    opened(child)
    child.expect(FRAME)
    assert preview_row(child) == plain
    child.send("q")
    finish(child)


# 이것을 실패시키는 것: 편집판 도중 밖에서 온 TERM·HUP에 터미널을 되돌리지 않고 끝나는 것(대체 화면을 나가지 않음),
# 그 신호로 끝나지 않는 것, 파일을 쓰는 것. INT는 시험하지 않는다: 작업 제어 없는 sh의 배경 작업은 INT를 무시한다.
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_an_outside_signal_puts_the_terminal_back(home, sig):
    child = spawn(home, background=True)
    opened(child)
    child.expect(FRAME)
    pid = int(re.search(rb"BPID=(\d+)", child.transcript.getvalue()).group(1))
    os.kill(pid, sig)
    code, before, after, text = finish(child)
    assert code == 128 + sig, text
    assert before == after
    log = child.transcript.getvalue()
    assert log.rfind(b"\x1b[?1049l") > log.rfind(b"\x1b[?2026l")
    assert config(home) is None


# 이것을 실패시키는 것: 배경색을 묻는 동안 온 Ctrl-C를 버리는 것(줄 질문에서는 취소인데 편집판이 열림).
def test_ctrl_c_while_the_terminal_is_asked_cancels(home):
    child = spawn(home)
    child.expect(QUERY)
    child.send(b"\x03")
    code, before, after, text = finish(child)
    assert code == 130, text
    assert before == after
    assert "cancelled" in text, text
    assert config(home) is None


# 이것을 실패시키는 것: 편집판 도중 터미널이 끊길 때 panic으로 끝나는 것(101), 끝나지 않고 기다리는 것, 파일을 쓰는 것.
def test_a_hung_up_terminal_ends_the_editor_without_a_panic(home):
    err, rc = home / "stderr", home / "rc"
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm-256color"}
    # The shell ignores SIGHUP so that it outlives the hang-up and records how bingsu ended.
    script = f'trap "" HUP; "{real_bin()}" setup 2>"{err}"; echo $? > "{rc}"'
    child = pexpect.spawn("/bin/sh", ["-c", script], env=env, timeout=10, dimensions=(24, 80))
    child.expect(QUERY)
    child.send(DARK)
    child.expect(KEYS)
    os.close(child.child_fd)
    end = time.monotonic() + 5
    while time.monotonic() < end and not rc.exists():
        time.sleep(0.05)
    assert rc.exists(), "bingsu did not end after the terminal hung up"
    text = err.read_text()
    assert "panicked" not in text, text
    assert int(rc.read_text()) != 101, text
    assert config(home) is None
