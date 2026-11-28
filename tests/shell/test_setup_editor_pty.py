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
import subprocess
import tempfile
import time
from pathlib import Path

import pexpect
import pyte
import pytest

from conftest import real_bin, track_background
from pty_session import Session
from screen_session import ScreenSession
from shell_support import account_state_listing, setup_env, trusted_env

QUERY = rb"\x1b\]11;\?\x1b\\"
DARK = b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\"
TITLE = rb"bingsu setup"
KEYS = rb"enter save"
# The end of a frame: a key's frame draws only the cells that changed.
FRAME = rb"\x1b\[\?2026l"
# Entering the alternate screen: the editor opened.
ALT_SCREEN = rb"\x1b\[\?1049h"


# Nothing a setup test runs may reach the account's own state folder (a
# `config use` there once replaced the user's settings choice).
@pytest.fixture(autouse=True, scope="module")
def account_state_untouched():
    before = account_state_listing()
    yield
    assert account_state_listing() == before, "a test changed the account's own bingsu state folder"


@pytest.fixture
def home():
    root = Path(tempfile.mkdtemp(prefix="bedit-")).resolve()
    root.chmod(0o700)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def spawn(home, *args, term="xterm-256color", rows=24, cols=80, extra=None, background=False,
          out=None):
    env = {**setup_env(home), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "PWD": str(home)}
    if term is not None:
        env["TERM"] = term
    env.update(extra or {})
    run = f'"{real_bin()}" setup {" ".join(args)}'
    # Standard output apart from the terminal: the startup line only.
    run = f'{run} > "{out}"' if out else run
    # In the background `$!` names bingsu itself, for a signal; without job
    # control the job stays in the terminal's foreground group.
    run = f"{run} & echo BPID=$!; wait $!" if background else run
    script = f"echo BEFORE=$(stty -g); {run}; echo RC=$?; echo AFTER=$(stty -g)"
    child = pexpect.spawn("/bin/sh", ["-c", script], env=env, timeout=10, dimensions=(rows, cols),
                          cwd=str(home))
    child.delaybeforesend = None
    child.transcript = io.BytesIO()
    child.logfile_read = child.transcript
    if background:
        track_background(child.transcript.getvalue)
    return child


# Closes the child as it ends (see there): tests here spawn again too.
from test_setup_pty import finish  # noqa: E402


def ended_without_the_editor(child):
    """`finish` for a run that must not open the editor: fails at once, and
    closes the child, when it enters the alternate screen."""
    if child.expect([pexpect.EOF, ALT_SCREEN]) == 1:
        child.close(force=True)
        pytest.fail("the editor opened")
    return finish(child)


def opened(child, rows=24, cols=80):
    """Answers the background query and waits for the first whole frame."""
    child.expect(QUERY)
    child.send(DARK)
    until(child, lambda d: any("enter save" in line for line in d), rows, cols)


def until(child, shown, rows=24, cols=80, timeout=10):
    """Reads frames until the screen they draw satisfies `shown` (a test on
    the screen's lines); returns those lines. A frame marker alone says
    nothing about which key's frame it ends."""
    end = time.monotonic() + timeout
    while True:
        display = screen_of(child, rows, cols)
        if shown(display):
            return display
        left = end - time.monotonic()
        assert left > 0, "\n".join(display)
        try:
            child.expect(FRAME, timeout=left)
        except pexpect.TIMEOUT:
            pass


def config(home):
    path = home / "cfg/bingsu/config.toml"
    return path if path.exists() else None


def has(text):
    return lambda display: any(text in line for line in display)


# 이것을 실패시키는 것: 그릴 수 있는 터미널에서 편집판을 열지 않는 것, 기본 그대로 저장하면 파일을 만들지 않는 것,
# 파일이 0600이 아닌 것, 저장 화면이 보인 키와 파일이 다른 것, 나간 뒤 터미널 설정이 다른 것, 대체 화면을 나가지
# 않는 것, doctor 안내를 빼는 것. 같은 읽기의 두 번째 Enter는 단위 시험(`setup_screen`)이 읽기 경계를 정해 본다.
def test_the_editor_saves_a_private_file_it_showed(home):
    child = spawn(home)
    opened(child)
    child.send("\r")
    until(child, has("enter write"))
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
    child.send("\r")
    until(child, has('style.preset = "pill"'))
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
        before = screen_of(child)
        child.send(key)
        until(child, lambda d: d != before)
    child.send("q")
    until(child, has("press q again"))
    child.send("q")
    code, _, _, text = finish(child)
    assert code == 0, text
    assert not marker.exists(), "a preview ran the command"
    assert config(home) is None


# 이것을 실패시키는 것: 설정이 지금 불러지지 않을 때(conf.d나 config.local의 문법 오류) 새 파일 편집판을 여는 것(불러오지
# 못한 읽기에는 적용 순서가 없어 물려받는 값을 모른 채 쓸 키를 정함), 그 이유와 위치를 알리지 않는 것, 파일을 쓰는 것,
# 종료 코드가 0이 아니거나 stdout에 시작 줄이 없는 것.
@pytest.mark.parametrize("bad", ["conf.d/10-bad.toml", "config.local.toml"])
def test_a_new_file_is_not_made_while_the_settings_do_not_load(home, bad):
    path = home / "cfg/bingsu" / bad
    path.parent.mkdir(parents=True)
    for d in [home / "cfg", home / "cfg/bingsu", path.parent]:
        d.chmod(0o700)
    path.write_text("x = [\n")
    path.chmod(0o600)
    out = home / "out"
    child = spawn(home, out=out)
    code, before, after, text = ended_without_the_editor(child)
    assert code == 0, text
    assert before == after
    assert "bingsu: nothing was written." in text, text
    assert "The settings do not load now, so setup cannot tell what a new file would change:" in text, text
    assert "E101: this is not valid TOML" in text and f"{bad}:1:" in text, text
    assert "`bingsu config check` lists every problem." in text, text
    assert out.read_text() == 'eval "$(bingsu init zsh)"\n'
    assert config(home) is None
    # Nothing else in the settings folder (no left temporary file either).
    assert [p.name for p in (home / "cfg/bingsu").iterdir()] == [bad.split("/")[0]]


# 이것을 실패시키는 것: 편집하는 동안 바뀐 설정(새 conf.d 파일)을 보지 않고 쓰는 것, 그때 쓰려던 키를 알리지 않는 것,
# 종료 코드가 1이 아닌 것.
def settings_with(home, conf_d_file, text):
    conf = home / "cfg/bingsu/conf.d"
    conf.mkdir(parents=True)
    for d in [home / "cfg", home / "cfg/bingsu", conf]:
        d.chmod(0o700)
    (conf / conf_d_file).write_text(text)
    (conf / conf_d_file).chmod(0o600)
    return conf


# 이것을 실패시키는 것: 다 읽지 못한 시작 읽기(없는 `extends` 대상, 읽을 수 없는 conf.d)에서 새 파일 편집판을 여는 것. 그
# 읽기는 놓친 출처를 빼고도 적용 순서를 남기므로, 순서만 보면 편집판이 열려 물려받는 값을 모른 채 쓴다. 그 이유를 알리지 않는
# 것, 종료 코드가 0이 아니거나 stdout에 시작 줄이 없는 것, 파일을 쓰는 것.
@pytest.mark.skipif(os.geteuid() == 0, reason="root lists a folder whatever its mode")
@pytest.mark.parametrize("case", ["missing extends", "unreadable conf.d"])
def test_a_new_file_is_not_made_while_the_settings_are_not_read_whole(home, case):
    text = 'extends = ["missing.toml"]\n' if case == "missing extends" else "[style]\ngap = true\n"
    conf = settings_with(home, "10-a.toml", text)
    if case == "unreadable conf.d":
        conf.chmod(0)
    out = home / "out"
    try:
        code, before, after, text = ended_without_the_editor(spawn(home, out=out))
    finally:
        conf.chmod(0o700)
    assert code == 0, text
    assert before == after
    assert "bingsu: nothing was written." in text, text
    why = "`extends` entry `missing.toml` cannot be used" if case == "missing extends" else \
        "a settings folder or file could not be read"
    assert why in text, text
    assert out.read_text() == 'eval "$(bingsu init zsh)"\n'
    assert config(home) is None


# 이것을 실패시키는 것: 다 읽은 시작 읽기로 고른 것을, 저장 직전 읽기가 다 읽지 못했는데(그사이 conf.d를 읽을 수 없게 됨)
# 쓰는 것, 그 까닭을 알리지 않는 것, 종료 코드가 1이 아닌 것.
@pytest.mark.skipif(os.geteuid() == 0, reason="root lists a folder whatever its mode")
def test_settings_not_read_whole_before_the_save_stop_it(home):
    conf = settings_with(home, "10-a.toml", "[style]\ngap = true\n")
    child = spawn(home)
    opened(child)
    child.send("\r")
    until(child, has("enter write"))
    conf.chmod(0)
    try:
        child.send("\r")
        code, before, after, text = finish(child)
    finally:
        conf.chmod(0o700)
    assert code == 1, text
    assert before == after
    assert "the settings could not all be read again, so nothing was written" in text, text
    assert config(home) is None


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
    until(child, has("enter write"))
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
    before = screen_of(child)
    child.send("s")
    after = until(child, lambda d: d != before)
    child.send("u")
    until(child, has("undone"))
    child.send("q")
    finish(child)
    row = next(i for i, line in enumerate(before) if line.startswith(" preview"))
    assert before[row + 1] != after[row + 1], (before[row + 1], after[row + 1])
    # The folder as the shell shows it, and this machine's name.
    assert home.name in before[row + 1], before[row + 1]
    assert host_shown(before[row + 1], os.uname().nodename.split(".")[0]), before[row + 1]


# 이것을 실패시키는 것: 쓰는 중인 프레임이 끝난 직후 그 사이 요청된 프레임을 바로 만들지 않는 것(`setup_screen::edit`의
# `wants_frame` 재검사를 뺌). 그러면 `u`의 화면이 다음 입력까지 그려지지 않아 "undone"이 오지 않는다.
def test_a_key_while_a_frame_is_being_written_is_drawn(home):
    rows, cols = 60, 200
    child = spawn(home, "--no-motion", rows=rows, cols=cols)
    opened(child, rows, cols)
    child.send("s")
    until(child, has("writes 2 keys"), rows, cols)
    # `s`'s frame is whole once its end mark has come and nothing follows.
    child.expect(FRAME)
    assert child.expect([pexpect.TIMEOUT, FRAME], timeout=0.5) == 0
    # Not reading: Ctrl-L is a whole screen, more than the terminal holds,
    # so the frame stays pending while `u` arrives.
    child.send(b"\x0c")
    time.sleep(0.3)
    child.send("u")
    time.sleep(0.3)
    until(child, has("undone"), rows, cols)
    child.send("q")
    finish(child)


def host_shown(line, host):
    """Whether the preview line shows the machine name `host`: whole, or,
    when the line has no room for it, cut to a prefix of at least eight
    characters and the ellipsis, as the prompt cuts a long value."""
    if host in line:
        return True
    return any(f"{host[:k]}\u2026" in line for k in range(min(8, len(host)), len(host)))


# 이것을 실패시키는 것: 잘린 머신 이름(CI 러너의 61자 이름이 80칸 미리보기에서 앞 41자와 줄임표로 나온 줄)을 찾지 못하는 것,
# 이름이 아닌 것이나 너무 짧은 앞부분을 이름으로 받는 것.
def test_a_cut_host_name_is_found():
    host = "sjc22-bt144-881efc80-108a-428d-bc68-0d60264e3be6-92F81018D27A"
    row = " \u25c2 sjc22-bt144-881efc80-108a-428d-bc68-0d602\u2026 \u25b8\u25c2 \u2026/bexist-x \u25b8"
    assert host_shown(row, host)
    assert host_shown(f" {host} ", host)
    assert not host_shown(" \u25c2 sjc22-b\u2026 \u25b8", host)
    assert not host_shown(" \u25c2 other-host\u2026 \u25b8", host)


# 이것을 실패시키는 것: 터미널의 배경 답을 편집판에 넘기지 않는 것(밝은 터미널인데 안내가 없음), 답이 없을 때 기다리기만
# 하는 것(편집판이 열리지 않음).
def test_the_terminal_background_is_asked_once(home):
    child = spawn(home)
    child.expect(QUERY)
    child.send(b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\")
    until(child, has("the terminal looks light; pick light"))
    child.send("q")
    assert finish(child)[0] == 0
    child = spawn(home)
    child.expect(QUERY)
    until(child, has("enter save"), timeout=2)
    child.send("q")
    code, _, _, text = finish(child)
    assert code == 0, text
    assert child.transcript.getvalue().count(b"\x1b]11;?") == 1


# 이것을 실패시키는 것: Ctrl-L에 화면 전체를 다시 그리지 않는 것.
def test_ctrl_l_draws_everything_again(home):
    child = spawn(home)
    opened(child)
    start = len(child.transcript.getvalue())
    child.send(b"\x0c")
    child.expect(rb"\x1b\[2J")
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
    until(child, has("Too small"), 10, 30)
    # While too small a value key changes nothing; Ctrl-L, which works
    # then, draws a frame once the `s` was read.
    child.send("s")
    child.send(b"\x0c")
    child.expect(rb"\x1b\[2J")
    child.setwinsize(24, 80)
    until(child, has("enter save"))
    child.send("\r")
    until(child, has("enter write"))
    child.send("\r")
    finish(child)
    assert 'preset = "triangle"' in config(home).read_text()
    config(home).unlink()
    child = spawn(home, cols=59)
    opened(child, 24, 59)
    until(child, has("narrow layout under 60 columns"), 24, 59)
    child.send("q")
    finish(child)
    child = spawn(home)
    opened(child)
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
    assert preview_row(child) == plain
    child.send("q")
    finish(child)


# 이것을 실패시키는 것: 편집판 도중 밖에서 온 TERM·HUP에 터미널을 되돌리지 않고 끝나는 것(대체 화면을 나가지 않음),
# 그 신호로 끝나지 않는 것, 파일을 쓰는 것. INT는 시험하지 않는다: 작업 제어 없는 sh의 배경 작업은 INT를 무시한다.
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_an_outside_signal_puts_the_terminal_back(home, sig):
    child = spawn(home, background=True)
    opened(child)
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
    env = {**setup_env(home), "SHELL": "/bin/zsh",
           "PATH": os.environ["PATH"], "TERM": "xterm-256color"}
    # The shell ignores SIGHUP so that it outlives the hang-up and records how bingsu ended.
    script = f'trap "" HUP; "{real_bin()}" setup 2>"{err}"; echo $? > "{rc}"'
    child = pexpect.spawn("/bin/sh", ["-c", script], env=env, timeout=10, dimensions=(24, 80))
    child.transcript = io.BytesIO()
    child.logfile_read = child.transcript
    opened(child)
    os.close(child.child_fd)
    end = time.monotonic() + 5
    while time.monotonic() < end and not rc.exists():
        time.sleep(0.05)
    assert rc.exists(), "bingsu did not end after the terminal hung up"
    text = err.read_text()
    assert "panicked" not in text, text
    assert int(rc.read_text()) != 101, text
    assert config(home) is None


def pinned(env, base):
    """`BINGSU_ROOTS` as `bingsu init bash` exports it for `env`."""
    init = subprocess.run([str(real_bin()), "init", "bash"], env=env, cwd=base, capture_output=True, timeout=10)
    assert init.returncode == 0, init.stderr
    script = init.stdout + b"\nprintf '%s\\0' \"$BINGSU_ROOTS\"\n"
    out = subprocess.run(["bash", "--noprofile", "--norc"], input=script, env=env, cwd=base,
                         capture_output=True, timeout=10)
    assert out.returncode == 0, out.stderr
    return out.stdout.rstrip(b"\0").decode()


# 이것을 실패시키는 것: bingsu가 도는 셸(init이 고정한 뿌리)에서 편집판의 미리보기나 저장, 발행이 설정의 명령을 돌리는 것.
# 명령은 돌면 표지 파일을 만들고(시험이 먼저 확인), 편집판 없이 기다린 동안에는 아무것도 그것을 돌리지 않는다(대조).
def test_nothing_a_config_names_runs_in_a_shell_that_runs_bingsu(tmp_path):
    env = {**trusted_env(tmp_path), "HOME": str(tmp_path), "SHELL": "/bin/zsh",
           "TERM": "xterm-256color", "PWD": str(tmp_path)}
    env["BINGSU_ROOTS"] = pinned(env, tmp_path)
    marker = tmp_path / "ran"
    conf = Path(env["XDG_CONFIG_HOME"]) / "bingsu" / "conf.d"
    conf.mkdir(parents=True, exist_ok=True)
    for d in [conf.parent.parent, conf.parent, conf]:
        d.chmod(0o700)
    touch = shutil.which("touch")
    (conf / "10-cmd.toml").write_text(
        f'[segment."custom/mark"]\nkind = "command"\ncommand = ["{touch}", "{marker}"]\n\n'
        '[layout.line1]\nleft = ["dir", "custom/mark"]\n')
    (conf / "10-cmd.toml").chmod(0o600)
    subprocess.run([touch, str(marker)], check=True)
    assert marker.exists(), "the command leaves the marker"
    marker.unlink()
    time.sleep(1.0)
    assert not marker.exists(), "something else ran the command"
    child = pexpect.spawn("/bin/sh", ["-c", f'"{real_bin()}" setup; echo RC=$?'], env=env, timeout=10,
                          dimensions=(24, 80), cwd=str(tmp_path))
    child.delaybeforesend = None
    child.transcript = io.BytesIO()
    child.logfile_read = child.transcript
    opened(child)
    for key in "soj":
        before = screen_of(child)
        child.send(key)
        until(child, lambda d: d != before)
    child.send("\r")
    until(child, has("enter write"))
    child.send("\r")
    child.expect(pexpect.EOF)
    text = child.transcript.getvalue().decode("utf-8", "replace")
    assert "RC=0" in text, text
    assert "bingsu: applied; the next prompt shows it" in text, text
    time.sleep(1.0)
    assert not marker.exists(), "the editor, its save or the publication ran the command"


# The opening: the bowl builds in rows 1-7 of the main screen for 4.4 s while the editor already
# takes keys, and stops on its end frame.

def bowl(display):
    """The bowl's rows (1-7) of a screen."""
    return display[1:8]


def quiet(child, seconds):
    """Reads for `seconds`; whether nothing came (no frame, no timer)."""
    before = len(child.transcript.getvalue())
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            child.read_nonblocking(65536, timeout=0.05)
        except pexpect.TIMEOUT:
            pass
    return len(child.transcript.getvalue()) == before


def end_frame(home, rows=24, cols=80):
    """The bowl as `--no-motion` draws it: the end frame, from the start."""
    sub = home / "still"
    sub.mkdir(mode=0o700, exist_ok=True)
    child = spawn(sub, "--no-motion", rows=rows, cols=cols)
    opened(child, rows, cols)
    shown = bowl(screen_of(child, rows, cols))
    child.send("q")
    finish(child)
    return shown


def drain(child, seconds):
    """Reads for `seconds`, as a terminal keeps taking output."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            child.read_nonblocking(65536, timeout=0.05)
        except pexpect.TIMEOUT:
            pass


def bowls_per_frame(log, rows=24, cols=80):
    """The bowl's rows after each frame of `log` (up to each frame's end)."""
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    out = []
    for part in log.split(b"\x1b[?2026l")[:-1]:
        stream.feed(part + b"\x1b[?2026l")
        out.append(bowl(screen.display))
    return out


# 이것을 실패시키는 것: 여는 그림을 그리지 않는 것(1-7행이 움직이지 않음), 끝 프레임에서 멈추지 않는 것, 끝난 뒤에도
# 프레임이나 타이머로 쓰는 것(조용하지 않음), 1초에 30장보다 많이 그리는 것. 읽기를 멈추지 않고(멈추면 놓친 프레임이
# 쌓여 그림이 일찍 끝남) 다 읽은 뒤 프레임마다의 그림을 본다.
def test_the_opening_plays_and_then_stays_still(home):
    still = end_frame(home)
    child = spawn(home)
    opened(child)
    first = len(child.transcript.getvalue())
    # Past its 4.4 s.
    drain(child, 5.2)
    log = child.transcript.getvalue()
    pictures = bowls_per_frame(log)
    assert len({tuple(p) for p in pictures}) >= 3, len(pictures)
    assert pictures[-1] == still, "\n".join(pictures[-1])
    assert quiet(child, 1.5), "output after the end frame"
    frames = log[first:].count(b"\x1b[?2026l")
    # 4.4 s at 30 frames a second at most, with the end frame.
    assert frames <= 4.4 * 30 + 2, frames
    child.send("q")
    finish(child)


# 이것을 실패시키는 것: 키가 여는 그림을 끝 프레임으로 넘기지 않는 것, 그 키의 명령을 하지 않는 것(설계: 넘기고
# 명령도 함), 넘긴 뒤에도 움직이는 것.
def test_a_key_skips_the_opening_and_does_its_own_command(home):
    still = end_frame(home, cols=70)
    child = spawn(home, cols=70)
    opened(child, cols=70)
    child.send("s")
    shown = until(child, has("< pill >"), cols=70)
    assert bowl(shown) == still, "\n".join(bowl(shown))
    assert quiet(child, 1.2), "the opening went on after the key"
    child.send("\x03")
    finish(child)


# 이것을 실패시키는 것: --no-motion이나 비어 있지 않은 NO_COLOR에서 움직이는 것(끝 프레임 한 장이 아님), NO_COLOR에서
# 그릇에 색을 쓰는 것.
@pytest.mark.parametrize("how", ["--no-motion", "NO_COLOR"])
def test_no_motion_and_no_color_draw_one_still_frame(home, how):
    still = end_frame(home)
    args, extra = ((how,), None) if how == "--no-motion" else ((), {"NO_COLOR": "1"})
    child = spawn(home, *args, extra=extra)
    opened(child)
    assert bowl(screen_of(child)) == still
    assert quiet(child, 1.2), "the still opening moved"
    if how == "NO_COLOR":
        screen = pyte.Screen(80, 24)
        pyte.ByteStream(screen).feed(child.transcript.getvalue())
        inked = [screen.buffer[y][x].fg for y in range(1, 8) for x in range(80)
                 if screen.buffer[y][x].data.strip()]
        assert inked and set(inked) == {"default"}, set(inked)
    child.send("q")
    finish(child)


# 이것을 실패시키는 것: 그릇 줄이 없는 창(24줄 미만)에 그리는 것, 그때도 타이머로 깨어나 쓰는 것.
def test_a_window_without_the_bowl_rows_has_no_opening(home):
    child = spawn(home, rows=20)
    opened(child, rows=20)
    display = screen_of(child, rows=20)
    assert display[2].startswith(" preview"), display[:4]
    assert quiet(child, 1.2), "frames with no bowl on the screen"
    child.send("q")
    finish(child)


# 이것을 실패시키는 것: 정지(SIGSTOP)와 재개 뒤에도 여는 그림을 이어 가는 것(설계: 끝 프레임으로 그림).
def test_the_opening_ends_after_a_stop(home):
    still = end_frame(home)
    child = spawn(home, background=True)
    opened(child)
    pid = int(re.search(rb"BPID=(\d+)", child.transcript.getvalue()).group(1))
    os.kill(pid, signal.SIGSTOP)
    time.sleep(0.3)
    resumed_at = len(child.transcript.getvalue())
    os.kill(pid, signal.SIGCONT)
    # The resume draws the whole screen again (`ESC [ 2 J`): that frame,
    # up to its end, has the end frame of the opening.
    def full_frame_after_resume():
        log = child.transcript.getvalue()
        start = log.find(b"\x1b[2J", resumed_at)
        end = log.find(b"\x1b[?2026l", start) if start >= 0 else -1
        return log[:end + len(b"\x1b[?2026l")] if end >= 0 else None
    deadline = time.monotonic() + 10
    while full_frame_after_resume() is None:
        assert time.monotonic() < deadline, "no full frame after the resume"
        drain(child, 0.05)
    screen = pyte.Screen(80, 24)
    pyte.ByteStream(screen).feed(full_frame_after_resume())
    assert bowl(screen.display) == still, "\n".join(bowl(screen.display))
    assert quiet(child, 1.2), "the opening went on after the resume"
    child.send("q")
    finish(child)


# 이것을 실패시키는 것: 색 줄로 모드가 바뀌어도 그릇을 그 모드의 잉크로 다시 칠하지 않는 것.
def test_the_bowl_takes_the_colors_of_the_mode(home):
    def inks(child):
        screen = pyte.Screen(80, 24)
        pyte.ByteStream(screen).feed(child.transcript.getvalue())
        return [screen.buffer[y][x].fg for y in range(1, 8) for x in range(80)
                if screen.buffer[y][x].data.strip()]
    child = spawn(home, "--no-motion", extra={"COLORTERM": "truecolor"})
    opened(child)
    dark = inks(child)
    # The colors row: auto (dark here), dark, light.
    child.send("c")
    until(child, has("preview  80 columns, dark"))
    child.send("c")
    until(child, has("preview  80 columns, light"))
    light = inks(child)
    assert dark and light and dark != light
    child.send("\x03")
    finish(child)
