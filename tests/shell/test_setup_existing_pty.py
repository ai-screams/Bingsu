"""`bingsu setup`'s editor on an existing settings file: it opens the file
the reader reads (the one `config use` chose, else the settings folder's
own), previews the picks from the file changed in memory where the change
can be made in place, and on the save screen shows, then prints on stderr,
what to change in the file. The file is never changed: its bytes, its
modification time and its inode stay; standard output holds the startup
line only."""
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from conftest import real_bin
from shell_support import account_state_listing, setup_env
from test_setup_editor_pty import finish, has, opened, screen_of, spawn, until


# Nothing a setup test runs may reach the account's own state folder.
@pytest.fixture(autouse=True, scope="module")
def account_state_untouched():
    before = account_state_listing()
    yield
    assert account_state_listing() == before, "a test changed the account's own bingsu state folder"


def make_home(resolve):
    root = Path(tempfile.mkdtemp(prefix="bexist-"))
    root = root.resolve() if resolve else root
    root.chmod(0o700)
    for d in ["cfg", "cfg/bingsu"]:
        (root / d).mkdir()
        (root / d).chmod(0o700)
    return root


def drop_home(root):
    for p in root.rglob("*"):
        if not p.is_symlink():
            p.chmod(0o700 if p.is_dir() else 0o600)
    import shutil
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def home():
    root = make_home(True)
    yield root
    drop_home(root)


def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(text)
    path.chmod(0o600)
    return path


def kept(path):
    """What must stay: the bytes, the modification time and the inode (of a
    link, the link's own and its target's)."""
    st = os.lstat(path)
    mine = (st.st_mtime_ns, st.st_ino)
    if path.is_symlink():
        return mine, kept(path.resolve())
    return mine, path.read_bytes()


STARTUP = 'eval "$(bingsu init zsh)"\n'
CHANGED = "Edit it yourself: bingsu config edit"


def change_and_print(child, stale):
    """`o`, the save screen, then Enter: returns the transcript. The
    preview's first line follows the pick when the file can be changed in
    memory, and stays as the file draws it when it cannot."""
    opened(child)
    before = screen_of(child)
    assert has("exists: not changed")(before)
    child.send("o")
    shown = until(child, has("changes 1 key"))
    row = next(i for i, line in enumerate(before) if line.startswith(" preview"))
    if stale:
        assert has(stale)(shown), "\n".join(shown)
        assert shown[row + 1] == before[row + 1], (before[row + 1], shown[row + 1])
    else:
        assert not has("not updated")(shown), "\n".join(shown)
        assert shown[row + 1] != before[row + 1], (before[row + 1], shown[row + 1])
    child.send("\r")
    until(child, has("bingsu does not change it"))
    child.send("\r")
    return finish(child)


# 이것을 실패시키는 것: 있는 파일을 바꾸는 것(바이트, 수정 시각, inode), 편집판을 열지 않는 것, 제목에 "exists: not
# changed"가 없는 것, TOML을 국소 편집한 후보로 미리 보지 않는 것, JSON과 국소 편집이 거부하는 모양에서 미리보기가
# 고른 값을 따르지 않는다고 알리지 않는 것, 바꿀 키와 줄을 stderr에 내지 않는 것, stdout에 시작 줄 말고 다른 것을 내는 것.
@pytest.mark.parametrize(("name", "text", "stale", "line"), [
    ("config.toml", '# mine\nicons = "nerd"\n[style]\npreset = "pill"\n', None, "  under [style]: outer_end = "),
    ("config.json", '{"icons": "nerd", "style": {"preset": "pill"}}\n', "not updated for this format",
     "  style.outer_end: "),
    ("config.toml", 'icons = "nerd"\nstyle = { preset = "pill" }\n', "not updated for this layout",
     "  under [style]: outer_end = "),
])
def test_an_existing_file_shows_what_to_change_and_stays(home, name, text, stale, line):
    path = put(home / "cfg/bingsu" / name, text)
    before = kept(path)
    out = home / "out"
    code, tty_before, tty_after, transcript = change_and_print(spawn(home, out=out), stale)
    assert code == 0, transcript
    assert tty_before == tty_after
    assert "bingsu: " + name + " is already there; bingsu does not change it." in transcript, transcript
    assert "style.outer_end: not set now" in transcript and CHANGED in transcript, transcript
    assert line in transcript, transcript
    assert ("under [" in transcript) == name.endswith(".toml"), transcript
    assert " is a link to " not in transcript, transcript
    assert out.read_text() == STARTUP
    assert kept(path) == before


# 이것을 실패시키는 것: 링크로 된 설정 파일이나 그 링크를 바꾸는 것, 링크 너머의 파일을 열지 않는 것, 제목이 링크
# 너머의 이름인데 어느 링크인지 알리지 않는 것.
def test_a_linked_settings_file_stays(home):
    real = put(home / "real/theme.toml", 'icons = "nerd"\n[style]\npreset = "pill"\n')
    link = home / "cfg/bingsu/config.toml"
    link.symlink_to(real)
    before = kept(link)
    out = home / "out"
    code, _, _, transcript = change_and_print(spawn(home, out=out), None)
    assert code == 0, transcript
    assert "bingsu: theme.toml is already there" in transcript, transcript
    assert f"{link} is a link to {real}." in transcript.replace("\r\n", ""), transcript
    assert "under [style]: outer_end = " in transcript, transcript
    assert out.read_text() == STARTUP
    assert kept(link) == before


# 이것을 실패시키는 것: 지울 키에 지울 줄을 내지 않는 것, 다른 출처(conf.d)가 덮는 키에 그 출처를 알리지 않는 것.
def test_deleted_and_covered_keys_print_their_lines(home):
    path = put(home / "cfg/bingsu/config.toml", '[style]\npreset = "pill"\ngap = true\n')
    put(home / "cfg/bingsu/conf.d/10-a.toml", '[style]\nouter_end = "round"\n')
    before = kept(path)
    child = spawn(home)
    opened(child)
    child.send("g")
    until(child, has("changes 1 key"))
    child.send("o")
    # The status line names the source that covers the row now.
    until(child, has("style.outer_end covered by"))
    child.send("\r")
    until(child, has("bingsu does not change it"))
    child.send("\r")
    code, _, _, transcript = finish(child)
    assert code == 0, transcript
    assert "style.gap: true now, not set chosen\r\n  delete gap under [style]" in transcript, transcript
    assert "conf.d/10-a.toml sets this too, and wins." in transcript, transcript
    assert kept(path) == before


# 이것을 실패시키는 것: `config use`로 고른 YAML 파일을 대상으로 보지 않는 것(설정 폴더에 새 파일을 만들거나 그
# 폴더의 것을 엶), 그 파일을 바꾸는 것, YAML에서 미리보기가 따르지 않는다고 알리지 않는 것.
def test_a_chosen_yaml_file_is_the_one_shown(home):
    chosen = put(home / "other/work.yaml", "icons: nerd\nstyle:\n  preset: pill\n")
    env = setup_env(home)
    used = subprocess.run([str(real_bin()), "config", "use", str(chosen)], env=env, capture_output=True, timeout=10)
    assert used.returncode == 0, used.stderr
    before = kept(chosen)
    out = home / "out"
    code, _, _, transcript = change_and_print(spawn(home, out=out), "not updated for this format")
    assert code == 0, transcript
    assert "work.yaml is already there" in transcript and "  style.outer_end: " in transcript, transcript
    assert "under [" not in transcript, transcript
    assert out.read_text() == STARTUP
    assert kept(chosen) == before
    assert not (home / "cfg/bingsu/config.toml").exists()


# 이것을 실패시키는 것: 바꿀 것이 없을 때 "It already has the choices you made."를 내지 않는 것, 그때도 고치라고 하는 것.
def test_no_change_says_the_file_already_has_it(home):
    path = put(home / "cfg/bingsu/config.toml", 'icons = "nerd"\n[style]\npreset = "pill"\n')
    before = kept(path)
    child = spawn(home)
    opened(child)
    child.send("\r")
    until(child, has("bingsu does not change it"))
    child.send("\r")
    code, _, _, transcript = finish(child)
    assert code == 0, transcript
    assert "It already has the choices you made." in transcript and CHANGED not in transcript, transcript
    assert kept(path) == before


# 이것을 실패시키는 것: 있는 파일에서 q로 나갈 때 종료 코드가 0이 아닌 것, Ctrl-C를 130으로 끝내지 않는 것, 그 파일을
# 바꾸는 것, stdout에 시작 줄 말고 다른 것을 내는 것(Ctrl-C는 시작 줄도 내지 않는다).
@pytest.mark.parametrize(("key", "want", "stdout"), [(b"q", 0, STARTUP), (b"\x03", 130, "")])
def test_quit_and_ctrl_c_keep_the_file(home, key, want, stdout):
    path = put(home / "cfg/bingsu/config.toml", 'icons = "nerd"\n')
    before = kept(path)
    out = home / "out"
    child = spawn(home, out=out)
    opened(child)
    child.send(key)
    code, tty_before, tty_after, transcript = finish(child)
    assert code == want, transcript
    assert tty_before == tty_after
    assert "nothing written" in transcript, transcript
    assert out.read_text() == stdout
    assert kept(path) == before


# 이것을 실패시키는 것: 두 이름(config.toml과 config.json)이 다 있을 때 편집판을 여는 것, 하나를 골라 비교하는 것, 종료
# 코드가 1이 아닌 것.
def test_two_settings_files_in_one_place_open_nothing(home):
    put(home / "cfg/bingsu/config.toml", 'icons = "nerd"\n')
    put(home / "cfg/bingsu/config.json", '{"icons": "nerd"}\n')
    child = spawn(home)
    code, _, _, transcript = finish(child)
    assert code == 1, transcript
    assert "are both here, so no file is opened" in transcript and "E308" in transcript, transcript
    assert b"\x1b[?1049h" not in child.transcript.getvalue()


# 이것을 실패시키는 것: 읽는 쪽이 읽지 못한 설정 파일로 편집판을 여는 것(지금 값을 모르는 채 바꿀 줄을 지어냄), 비교할
# 수 없는데 줄 질문을 하는 것, 그 이유를 알리지 않는 것, 시작 줄을 내지 않는 것, 그 파일을 바꾸는 것.
# 설정 폴더 경로가 링크를 지날 때(macOS의 /var)도 이유를 낸다.
@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
@pytest.mark.parametrize("resolve", [True, False])
def test_an_unreadable_settings_file_opens_no_editor(resolve):
    home = make_home(resolve)
    try:
        unreadable(home)
    finally:
        drop_home(home)


def unreadable(home):
    path = put(home / "cfg/bingsu/config.toml", 'icons = "nerd"\n')
    path.chmod(0)
    before = os.lstat(path)
    out = home / "out"
    # No choices given: the line questions would wait for answers.
    child = spawn(home, out=out)
    code, _, _, transcript = finish(child)
    assert code == 0, transcript
    assert "config.toml is already there, so nothing was written." in transcript, transcript
    assert "It could not be read to compare: " in transcript, transcript
    assert b"\x1b[?1049h" not in child.transcript.getvalue()
    assert out.read_text() == STARTUP
    after = os.lstat(path)
    assert (after.st_mtime_ns, after.st_ino, after.st_mode) == (before.st_mtime_ns, before.st_ino, before.st_mode)
