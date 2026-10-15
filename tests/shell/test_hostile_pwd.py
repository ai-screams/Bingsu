"""Hostile folder names through the real binary (M3a Task V3): `$PWD` is
untrusted data that reaches the record through `--pwd`, PathFacts and the
renderer. Rows and expectations come from tests/hostile/classes.tsv
(column `pwd`): `noexec` rows must be drawn as a rendered prompt without
running any part of the name; `noexec-linux` rows only where the file
system accepts the name; `none` rows cannot be a folder name at all."""
import os
import sys
import unicodedata

import pytest

from conftest import Install, short_dir, trusted_env
from test_init_words import source
from pty_session import Session, visible
from test_hostile_matrix import matrix, shell_modes  # puts tests/hostile on sys.path

# U+25B8, the triangle tail of the default theme's first line with the
# unicode icon set Part V draws with (decisions P20, 2026-10-15: East Asian
# Width N): only a rendered record draws it (every fallback prompt is plain
# `❯ `).
RENDERED = "\u25b8".encode()
CD = {"zsh": 'cd -- "$BINGSU_T_DIR"', "bash": 'cd -- "$BINGSU_T_DIR"', "fish": "cd -- $BINGSU_T_DIR"}


def shown_leaf(payload: bytes) -> bytes:
    """The last folder name as the prompt must show it, computed here
    without the product code: invalid UTF-8 becomes U+FFFD, then control
    (Cc), format (Cf, ZWJ kept), line and paragraph separators are removed
    (spec section 3 step 1); a name left empty becomes U+FFFD."""
    text = payload.rsplit(b"/", 1)[-1].decode("utf-8", "replace")
    keep = "".join(c for c in text if c == "\u200d" or unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp"))
    return (keep or "\ufffd").encode()


def cases():
    for r in matrix.rows():
        if r[7] != "none":
            yield pytest.param(r[0], r[1], r[7], id=r[0])


# 이것을 실패시키는 것: 폴더 이름의 일부를 명령으로 실행하는 것(세 셸, 이스케이프 경로 포함), 폴더 이름 때문에
# 레코드가 거부돼 최소 프롬프트로 떨어지는 것(정제 없이 제어 문자를 필드에 넣음), hook이 `--pwd`를 따옴표 없이 넘기는 것,
# dir 세그먼트를 버리거나 고정 글로 바꾸는 것(정제한 마지막 이름이 화면에 없음).
@pytest.mark.parametrize("shell,opts", list(shell_modes()))
@pytest.mark.parametrize("cls,spec,want", list(cases()))
def test_hostile_folder_name(tmp_path, shell, opts, cls, spec, want):
    if want == "noexec-linux" and not sys.platform.startswith("linux"):
        pytest.skip(f"{cls}: this file system refuses the name (row pwd=noexec-linux)")
    canary = short_dir() / "c"
    payload = matrix.payload(spec, str(canary).encode())
    folder = tmp_path.joinpath("h").as_posix().encode() + b"/" + payload
    os.makedirs(folder)
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    env["BINGSU_T_DIR"] = os.fsdecode(folder)
    s = Session(shell, env, cols=200)
    if opts:
        s.run(opts)
    s.run(source(shell, init).decode().rstrip("\n"))
    after_cd = s.run(CD[shell]).encode()
    s.run("true")
    out = s.close()
    assert not canary.exists(), f"{shell}: part of the folder name ran"
    assert out.rfind(RENDERED) > out.find(after_cd), f"{shell}: no rendered prompt after cd"
    # The sanitized last name is on screen after the cd: the dir segment
    # was drawn from this $PWD, not dropped or replaced by a constant.
    leaf = shown_leaf(payload)
    assert leaf in visible(out[out.find(after_cd):]), (shell, leaf)
