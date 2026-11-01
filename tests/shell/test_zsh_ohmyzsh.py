"""bingsu next to a real oh-my-zsh, loaded first as the install line says. The
workflow fetches the commit in tests/shell/ohmyzsh.pin into target/ohmyzsh and
this file only checks and copies it, so the tree stays out of the repository.
Synthetic shapes are in test_zsh_hooks.py."""
import os
import shutil

import pytest

from conftest import ROOT, Install, trusted_env
from pty_session import Session, visible
from screen_session import ScreenSession
from test_zsh_hooks import fields, opt, redraws, to_main, to_vicmd, wait_redraws, width_of
from test_zsh_screen import enter, settle

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")

TREE = ROOT / "target/ohmyzsh"
NOTICE = b"bingsu: the runtime folder changed"
LATE = b"another prompt hook runs after bingsu"


def checked_copy(tmp_path):
    """The tree at the pinned commit. Never a skip: a missing tree would count as
    a pass. HEAD is read as a file because the shell images have no git; a fetch
    by hash checks the objects, and a detached HEAD holds that hash."""
    commit = (ROOT / "tests/shell/ohmyzsh.pin").read_text().strip()
    head = TREE / ".git/HEAD"
    got = head.read_text().strip() if head.exists() else "nothing"
    if got != commit:
        pytest.fail(f"BLOCKED: oh-my-zsh tree at {got}, want {commit}")
    copy = tmp_path / "ohmyzsh"
    shutil.copytree(TREE, copy, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    return copy


def start(tmp_path, status=b"ok:none"):
    tree = checked_copy(tmp_path)
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / "init.zsh"
    init.write_bytes(inst.init("zsh", env))
    inst.use_fake(fields(upper=b"UP", vi_left=b"CMD> ", vi_lines=b"l", status=status))
    rc = tmp_path / "rc.zsh"
    rc.write_text(f'''export ZSH="{tree}" ZSH_CACHE_DIR="{tmp_path}/cache" HOME="{tmp_path}"
ZSH_THEME=robbyrussell DISABLE_AUTO_UPDATE=true ZSH_DISABLE_COMPFIX=true plugins=(git)
source "$ZSH/oh-my-zsh.sh"
source "{init}"
''')
    s = Session("zsh", env, cols=200, rows=30)
    s.run(f'source "{rc}"; print -r -- "${{+functions[omz]}} ${{precmd_functions}}" > "{tmp_path}/loaded"', timeout=30)
    loaded = (tmp_path / "loaded").read_text()
    assert loaded.startswith("1 ") and "omz_termsupport_precmd" in loaded, loaded
    return s, inst, ScreenSession(s, 30, 200)


# 이것을 실패시키는 것: init을 프레임워크보다 먼저 두는 것, 프레임워크를 싣지 않는 것, 종료 코드나 실행 시간을
# 잃는 것, transient·vi·크기 변경 등록이 빠지는 것.
def test_ohmyzsh_then_init(tmp_path):
    s, inst, screen = start(tmp_path)
    settle(screen)
    enter(screen, "(exit 7)")
    assert opt(inst.calls()[-1], b"--status") == b"7"
    enter(screen, "sleep 0.1")
    assert 80 <= int(opt(inst.calls()[-1], b"--duration-ms")) < 5000, inst.calls()[-1]
    enter(screen, "print DONE")
    assert "T> print DONE" in screen.lines(), screen.lines()
    row = screen.cursor()[0]
    assert (screen.lines()[row - 1], screen.lines()[row]) == ("UP", "LONG>"), screen.lines()
    enter(screen, "bindkey -v; KEYTIMEOUT=1")
    calls = len(inst.calls())
    to_vicmd(screen)
    to_main(screen, "LONG>")
    assert len(inst.calls()) == calls
    screen.resize(30, 120)
    wait_redraws(screen, inst, 1)
    assert width_of(redraws(inst)[0]) == 120
    out = visible(s.close())
    assert LATE not in out and b"zle:" not in out and b"command not found" not in out, out


# 이것을 실패시키는 것: 같은 상태에서 알림을 반복하는 것.
def test_notice_once_with_ohmyzsh(tmp_path):
    s, inst, screen = start(tmp_path, status=b"degraded:runtime-root")
    settle(screen)
    before = len(inst.calls())
    enter(screen, "true")
    enter(screen, "true")
    assert len(inst.calls()) == before + 2
    assert s.close().count(NOTICE) == 1


# 이것을 실패시키는 것: 고정한 커밋인지 확인하지 않는 것.
def test_tree_at_another_commit_is_refused(tmp_path, monkeypatch):
    tree = tmp_path / "other"
    monkeypatch.setitem(globals(), "TREE", tree)
    with pytest.raises(pytest.fail.Exception, match="BLOCKED: oh-my-zsh tree at nothing"):
        checked_copy(tmp_path)
    (tree / ".git").mkdir(parents=True)
    (tree / ".git/HEAD").write_text("ref: refs/heads/master\n")
    with pytest.raises(pytest.fail.Exception, match="BLOCKED: oh-my-zsh tree at ref:"):
        checked_copy(tmp_path)
