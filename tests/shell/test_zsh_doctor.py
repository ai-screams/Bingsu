"""`bingsu_doctor`, the zsh function that hands `bingsu doctor` what only the
shell knows (hook order, the words the last prompt call was given, the shell's
version, the hook's record version), in a real interactive zsh with the real
binary. The function sends one record on the standard input of the pinned
bingsu and exports nothing."""
import os
import re

import pytest

from conftest import Install, trusted_env
from shell_support import plain_script, rewrapped_script
from pty_session import Session

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")

SHELL_LINES = ["shell", "hook version", "hook order", "envelope"]


RECORDING_HELPER = """#!/bin/sh
# Stands in for the pinned bingsu: for `doctor` it keeps what it was given (environment and
# standard input); the prompt also starts it as the refresh helper, which it must leave alone.
[ "$1" = doctor ] || exit 0
env > "{out}/helper.env"
cat > "{out}/helper.stdin"
exit 0
"""


def start(tmp_path, edit=None, recording=False, tag=""):
    """A shell that has run init (the real bingsu), with one prompt drawn.
    `recording`: the pinned bingsu path then leads to a script that keeps its
    environment and standard input in `tmp_path/helper.env` and `helper.stdin`
    (the prompt itself still runs the real bingsu-prompt)."""
    base = tmp_path / tag if tag else tmp_path
    base.mkdir(exist_ok=True)
    inst = Install(base)
    env = trusted_env(base)
    (base / "cfg-t" / "bingsu").mkdir(parents=True, mode=0o700)
    script = inst.init("zsh", env)
    if edit:
        script = edit(script)
    if recording:
        helper = base / "helper.sh"
        helper.write_text(RECORDING_HELPER.format(out=base))
        helper.chmod(0o755)
        inst.exe.unlink()
        os.symlink(helper, inst.exe)
    init = base / "init.zsh"
    init.write_bytes(script)
    s = Session("zsh", env, cols=140, rows=30)
    s.run(f'source "{init}"')
    s.run("true")
    return s, inst


def doctor(s, tmp_path, before="", args=""):
    """Run `bingsu_doctor` after `before` on the same command line, so the
    state `before` sets is what the next call sees; the output is a file."""
    out = tmp_path / "doctor.out"
    out.unlink(missing_ok=True)
    s.run(f'{before}; bingsu_doctor {args} > "{out}" 2>&1')
    return out.read_text()


def line(text, title):
    for l in text.splitlines():
        if l[10:26].strip() == title:
            return l
    raise AssertionError(f"no line for {title}: {text}")


# 이것을 실패시키는 것: 함수가 증거를 보내지 않는 것(unknown), 함수가 실제 hook 순서·봉투를 거꾸로 읽는 것, 정상 셸에서 경고를 내는 것.
def test_a_plain_shell_is_ok(tmp_path):
    s, _ = start(tmp_path)
    t = doctor(s, tmp_path)
    s.close()
    for title in SHELL_LINES:
        assert line(t, title).startswith("  ok"), f"{title}: {t}"
    assert re.search(r"zsh \d+\.\d+", line(t, "shell")), t
    assert "--status 0" in line(t, "envelope"), t


# 이것을 실패시키는 것: 설치 hook 뒤에 다른 함수가 달려도 순서를 정상으로 보는 것, 저장 hook 앞의 함수를 놓치는 것.
@pytest.mark.parametrize("before,name", [
    ("_late() { :; }; precmd_functions+=(_late)", "_late"),
    ("_first() { :; }; precmd_functions=(_first $precmd_functions)", "_first"),
])
def test_a_moved_hook_is_warned_about(tmp_path, before, name):
    s, _ = start(tmp_path)
    t = doctor(s, tmp_path, before=before)
    s.close()
    l = line(t, "hook order")
    assert l.startswith("  warn") and "W609" in l and name in l, t
    for title in ["shell", "hook version", "envelope"]:
        assert line(t, title).startswith("  ok"), f"{title}: {t}"


# 이것을 실패시키는 것: 필드를 빼거나 값을 바꾼 봉투를 정상으로 보는 것(봉투를 셸 값이 아닌 고정값으로 쓰는 것).
@pytest.mark.parametrize("before", [
    "_bingsu_ctx=(${_bingsu_ctx[1,6]} ${_bingsu_ctx[9,-1]})",
    "_bingsu_ctx[2]=notanumber",
])
def test_a_changed_envelope_is_warned_about(tmp_path, before):
    s, _ = start(tmp_path)
    t = doctor(s, tmp_path, before=before)
    s.close()
    l = line(t, "envelope")
    assert l.startswith("  warn") and "W610" in l, t
    assert line(t, "hook order").startswith("  ok"), t


# 이것을 실패시키는 것: hook이 요구하는 레코드 버전을 증거에 싣지 않는 것(하드코딩), 모르는 버전을 정상으로 보는 것.
def test_a_hook_asking_for_another_record_fails(tmp_path):
    def edit(script):
        text = plain_script("zsh", script)
        assert text.count(b"record='B1'") + text.count(b"record=B1") == 1, text[-3000:]
        return rewrapped_script("zsh", script, text.replace(b"record='B1'", b"record='B9'").replace(b"record=B1", b"record=B9"))
    s, _ = start(tmp_path, edit)
    t = doctor(s, tmp_path)
    s.close()
    l = line(t, "hook version")
    assert l.startswith("  fail") and "E608" in l and "B9" in l, t


# 이것을 실패시키는 것: 증거를 환경 변수로 내보내는 것(export, typeset -x, ALL_EXPORT 아래의 새 이름): 자식 프로세스가 본다.
@pytest.mark.parametrize("before", ["", "setopt allexport"], ids=["plain", "allexport"])
def test_nothing_reaches_a_child_environment(tmp_path, before):
    s, _ = start(tmp_path)
    env_file = tmp_path / "child.env"
    s.run(f'{before}; bingsu_doctor > /dev/null 2>&1; unsetopt allexport; /usr/bin/env > "{env_file}"')
    session = tmp_path / "session.txt"
    s.run(f'print -r -- $_bingsu_session > "{session}"')
    s.close()
    child = env_file.read_text()
    sid = session.read_text().strip()
    assert len(sid) == 32, sid
    assert sid not in child, "the session id reached a child environment"
    for name in ["_bingsu_ctx", "_bingsu_drawn_cols", "_bingsu_session", "doctor-evidence", "precmd_functions"]:
        assert name not in child, f"{name} reached a child environment"


# 이것을 실패시키는 것: 함수가 고정 경로 대신 PATH의 bingsu를 부르는 것(PATH 앞의 가짜가 증거를 받음).
def test_the_function_calls_the_pinned_bingsu_not_the_one_on_path(tmp_path):
    s, _ = start(tmp_path)
    fake = tmp_path / "fakebin"
    fake.mkdir()
    marker = tmp_path / "fake-ran"
    (fake / "bingsu").write_text(f"#!/bin/sh\ntouch {marker}\n")
    (fake / "bingsu").chmod(0o755)
    t = doctor(s, tmp_path, before=f'PATH="{fake}:$PATH"')
    s.close()
    assert not marker.exists(), "the bingsu on PATH was run"
    assert line(t, "hook order").startswith("  ok"), t


def record_of(tmp_path, tag=""):
    """What the recording helper got on standard input, without the duration
    and the session id (they differ from run to run)."""
    base = tmp_path / tag if tag else tmp_path
    raw = (base / "helper.stdin").read_bytes()
    raw = re.sub(rb"--duration-ms\x1d\d+", b"--duration-ms\x1dN", raw)
    # init makes a new session id for every shell
    return re.sub(rb"\x1f[0-9a-f]{32}\x1f", b"\x1fSESSION\x1f", raw)


# 이것을 실패시키는 것: 증거 레코드를 환경으로도 내보내는 것. 고정 bingsu가 받는 환경에 세션 id·내부 변수·증거가 없어야 한다
# (`_bingsu_ev=$_bingsu_session "$helper" ...` 앞 환경 대입, 함수 안 `local -x`, export가 모두 여기서 걸린다).
@pytest.mark.parametrize("before", ["true", "setopt allexport"], ids=["plain", "allexport"])
def test_the_pinned_helper_gets_nothing_in_its_environment(tmp_path, before):
    s, _ = start(tmp_path, recording=True)
    s.run(f"{before}; bingsu_doctor")
    sid = (s.run('print -r -- $_bingsu_session > "%s"' % (tmp_path / "sid.txt")), (tmp_path / "sid.txt").read_text().strip())[1]
    s.close()
    child = (tmp_path / "helper.env").read_text()
    assert len(sid) == 32 and sid not in child, "the session id reached the helper's environment"
    for name in ["_bingsu_", "doctor-evidence", "precmd_functions", "preexec_functions", "ZSH_VERSION="]:
        assert name not in child, f"{name} reached the helper's environment"
    assert b"doctor-evidence-v1" in (tmp_path / "helper.stdin").read_bytes()


HOSTILE = "setopt ksh_arrays sh_word_split glob_subst rc_expand_param no_unset ksh_glob sh_glob posix_builtins"


# 이것을 실패시키는 것: 함수에서 `emulate -L zsh`를 빼는 것: 사용자 옵션(배열 첨자, 단어 나눔, 확장 규칙)이 레코드를 바꾼다.
def test_the_record_does_not_depend_on_the_users_options(tmp_path):
    records = []
    for tag, before in [("plain", "true"), ("hostile", HOSTILE)]:
        s, _ = start(tmp_path, recording=True, tag=tag)
        s.run(f"{before}; bingsu_doctor")
        s.close()
        records.append(record_of(tmp_path, tag))
    assert records[0] == records[1], records
    assert records[0].count(b"\x1f") == 9 and records[0].endswith(b"\x1e")


# 이것을 실패시키는 것: `print -r`을 `print`로 바꾸는 것: 이름에 든 백슬래시 글자(`\x1d`)가 구분 글자로 풀려 순서 판정이 달라진다.
def test_a_backslash_in_a_name_is_not_an_escape(tmp_path):
    s, _ = start(tmp_path)
    t = doctor(s, tmp_path, before=r"n='late\x1d_bingsu_install'; functions[$n]=:; precmd_functions+=($n)")
    s.close()
    l = line(t, "hook order")
    assert l.startswith("  warn") and "W609" in l, t
    assert r"late\x1d_bingsu_install" in l, l


# 이것을 실패시키는 것: 이름 속 구분 글자(0x1d)를 레코드에 그대로 실어 순서를 틀리게 ok로 판정하는 것. 셋 모두 "판정 못 함"이어야 한다.
@pytest.mark.parametrize("before", [
    "n=$'x\\x1d_bingsu_install'; functions[$n]=:; precmd_functions+=($n)",
    "n=$'_bingsu_save\\x1dx'; functions[$n]=:; precmd_functions=($n $precmd_functions)",
    "n=$'_bingsu_preexec\\x1dx'; functions[$n]=:; preexec_functions=($n)",
], ids=["after-install", "before-save", "preexec"])
def test_a_separator_in_a_hook_name_is_not_judged(tmp_path, before):
    s, _ = start(tmp_path)
    t = doctor(s, tmp_path, before=before)
    s.close()
    l = line(t, "hook order")
    assert l.startswith("  unknown") and "separator" in l, t
