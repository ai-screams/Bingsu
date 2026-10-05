"""fish connection (spec section 5 fish column). fish 3.6 (container) and
current fish.

fish draws the output of fish_prompt and fish_right_prompt; it never
re-reads that output as a prompt string, so there is no option state
machine. What these tests pin instead: record data leaves the functions as
output only, never as a format string or code."""
import os
import re
import time

import pytest

from conftest import Install, minimal_record, run_shell_script, short_dir, trusted_env
from pty_session import Session, visible

pytestmark = pytest.mark.skipif("fish" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="fish not under test")

SEP = b"<<SEP>>"


def record(left, right=b""):
    return b"B1\x1f7\x1f" + left + b"\x1f" + right + b"\x1f\x1f\x1f\x1f\x1fok:none\x1e"


def start(tmp_path, record, rc_after=""):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    (tmp_path / "init.fish").write_bytes(inst.init("fish", env))
    inst.use_fake(record)
    (tmp_path / "rc.fish").write_text(f"source {tmp_path / 'init.fish'}\n{rc_after}\n")
    s = Session("fish", env, cols=200)  # fish shortens prompts wider than the terminal
    s.run(f"source {tmp_path / 'rc.fish'}")
    return s, inst


def install_once(tmp_path, body, record=None, inherit=None):
    """Source init in a plain (non-interactive) fish script, run `body`,
    return (result, argv of every bingsu call)."""
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("fish", env)
    inst.use_fake(record or minimal_record())
    env.update(inherit or {})
    r = run_shell_script("fish", script + b"\n" + body, env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    return r, inst


def val(argv, k):
    return argv[argv.index(k) + 1] if k in argv else None


# 이것을 실패시키는 것: 필드를 eval하거나 printf 형식 문자열로 쓰는 것.
def test_fish_prints_fields_without_interpreting(tmp_path):
    cdir = short_dir()
    c1, c2 = cdir / "c1", cdir / "c2"
    left = f"D:$(touch {c1});(touch {c2});{{a,b}};$HOME;%s;\\n> ".encode()
    right = b"R:%d"
    rec = b"B1\x1f7\x1f" + left + b"\x1f" + right + b"\x1f\x1f\x1f\x1f\x1fok:none\x1e"
    s, _ = start(tmp_path, rec)
    s.run("true")
    out = visible(s.close())
    assert not c1.exists() and not c2.exists()
    assert left in out
    assert b"R:%d" in out


# 이것을 실패시키는 것: `if _bingsu_frame …` 조건을 `if true`로 바꾸는 것(빈 필드를 그림).
def test_fish_bad_record_falls_back_to_minimal(tmp_path):
    s, _ = start(tmp_path, b"not a record")
    s.run("true")
    out = visible(s.close())
    assert "❯ ".encode() in out


# The brief's two-command capture (`set -l s $status; set -l p $pipestatus`)
# stays green too: `set` changes neither value on fish 3.6, 4.0 and 4.9.
# 이것을 실패시키는 것: `set -l sp $status_generation $status $pipestatus`에서 `$pipestatus`를 `$status`로 바꾸는 것.
def test_fish_pipestatus_survives(tmp_path):
    s, inst = start(tmp_path, minimal_record())
    s.run("true | false")
    s.run("false")
    s.close()
    calls = inst.calls()
    assert any(val(c, b"--pipestatus") == b"0,1" and val(c, b"--status") == b"1" for c in calls), calls
    assert all(val(c, b"--keymap") is not None and val(c, b"--width") not in (None, b"") for c in calls)


# Exact bytes, not a substring of a terminal transcript: `printf '%s'` with
# one argument prints the field and nothing else (no newline, no format).
# 이것을 실패시키는 것: `printf '%s' $_bingsu_f[3]`를 `echo $_bingsu_f[3]`로 바꾸는 것(줄바꿈이 붙음),
# fish_right_prompt의 `printf '%s'`를 `printf`로 바꾸는 것(`%%`가 `%`가 됨).
def test_prompt_functions_print_the_fields_exactly(tmp_path):
    cdir = short_dir()
    left = f"\x1b[31mD:$(touch {cdir / 'c1'});%s%%\\n\\x41\\\\;'\"> \x1b[0m".encode()
    right = b"R:%d%%\\t$(id)"
    body = b"fish_prompt; printf '%s' '" + SEP + b"'; fish_right_prompt\n"
    r, _ = install_once(tmp_path, body, record=record(left, right))
    assert r.stdout == left + SEP + right, r.stdout
    assert not (cdir / "c1").exists()


# A refused record after an accepted one: the left falls back and the right
# prompt saved from the earlier record is dropped.
# 이것을 실패시키는 것: 거부 갈래의 `set -g _bingsu_rps1 ''`를 지우는 것(앞 레코드의 R:OLD가 남음).
def test_refused_record_draws_fallback_and_clears_right(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"B1\x1f7\x1fD:$(touch x)\x1e")
    rec_file = tmp_path / "bin" / "record.bin"
    body = (f"fish_prompt; fish_right_prompt; printf '%s' '{SEP.decode()}'\n"
            f"cat {bad} > {rec_file}\n"
            f"fish_prompt; printf '%s' '{SEP.decode()}'; fish_right_prompt\n").encode()
    r, _ = install_once(tmp_path, body, record=record(b"OLD> ", b"R:OLD"))
    first, second = r.stdout.split(SEP, 1)
    assert first == b"OLD> R:OLD", first
    assert second == "❯ ".encode() + SEP, second


# fish draws the left prompt before the right one, so fish_right_prompt
# prints the value of the same draw. Environment assumption pin: no bingsu
# mutation turns this red that the exact-bytes test above does not already
# catch; it fails on a fish that runs fish_right_prompt first.
# 이것을 실패시키는 것: fish_right_prompt를 fish_prompt보다 먼저 부르는 fish(bingsu 변이로는 죽지 않음).
def test_right_prompt_belongs_to_the_same_draw(tmp_path):
    s, inst = start(tmp_path, record(b"LA> ", b"RA"))
    s.run("true")
    (inst.dir / "record.bin").write_bytes(record(b"LB> ", b"RB"))
    s.run("true")
    out = visible(s.close())
    # Each right prompt belongs to the left prompt drawn last before it
    # (fish redraws the right prompt alone, several times per line).
    marks = re.findall(rb"L[AB]> |R[AB]", out)
    pairs = []
    for i, m in enumerate(marks):
        if m.startswith(b"R"):
            lefts = [x for x in marks[:i] if x.startswith(b"L")]
            pairs.append((lefts[-1] if lefts else None, m))
    assert all(l is not None and l[1:2] == r[1:2] for l, r in pairs), marks
    assert (b"LA> ", b"RA") in pairs and (b"LB> ", b"RB") in pairs, marks


# 이것을 실패시키는 것: `--jobs`에 상수 0을 넘기는 것, `--duration-ms` 블록을 지우는 것, `--seq`가 늘지 않는 것.
def test_ctx_values_passed_each_prompt(tmp_path):
    s, inst = start(tmp_path, minimal_record())
    s.run("sleep 0.3")
    s.run("sleep 5 &")
    s.run("kill %1; wait")
    s.close()
    calls = inst.calls()
    assert any(val(c, b"--jobs") == b"1" for c in calls), calls
    assert val(calls[0], b"--jobs") == b"0" and val(calls[0], b"--keymap") == b"default", calls[0]
    slept = [int(val(c, b"--duration-ms")) for c in calls if val(c, b"--duration-ms")]
    assert any(250 <= ms < 3000 for ms in slept), slept
    seqs = [int(val(c, b"--seq")) for c in calls]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), seqs


# An empty fish variable expands to no word at all, so a flag would take the
# next flag as its value. Each guard keeps one value in place or leaves its
# flag out.
# 이것을 실패시키는 것: COLUMNS 모양 검사 줄 `string match … -- "$w"; or set w 0`을 지우는 것(--width 뒤가 --status),
# keymap 검사 `if string match …`를 지우는 것(--keymap 뒤가 다음 플래그).
def test_erased_prompt_variables_keep_every_flag_paired(tmp_path):
    body = b"set -e COLUMNS; set -e fish_bind_mode\nfish_prompt\n"
    _, inst = install_once(tmp_path, body)
    (argv,) = inst.calls()
    assert val(argv, b"--width") == b"0", argv
    assert b"--keymap" not in argv, argv
    flags = [a for a in argv if a.startswith(b"--") and b"=" not in a]
    assert all(not val(argv, f).startswith(b"--") for f in flags), argv


# fish brings an environment variable in as an exported global, and `set -g`
# keeps that flag. Inherited names stay in the shell but leave the
# environment; a valid inherited session is kept as is.
# 이것을 실패시키는 것: hooks.fish 끝의 `set -gu …` 블록을 지우는 것(EXPORTED가 0이 아님),
# `set -gu _bingsu_session $_bingsu_session`을 값 없는 `set -gu _bingsu_session`으로 바꾸는 것(session이 빔).
def test_owned_globals_are_not_exported(tmp_path):
    names = ("_bingsu_seq", "_bingsu_rec", "_bingsu_rps1", "_bingsu_f", "_bingsu_disp", "_bingsu_note",
             "_bingsu_key", "_bingsu_gen")
    inherit = {n: "1" for n in names}
    session = "0123456789abcdef0123456789abcdef"
    inherit["_bingsu_session"] = session
    body = b"fish_prompt; fish_right_prompt; echo; echo \"EXPORTED=\"(env | grep -c '^_bingsu_')\n"
    r, inst = install_once(tmp_path, body, inherit=inherit)
    assert b"EXPORTED=0\n" in r.stdout, r.stdout
    (argv,) = inst.calls()
    assert val(argv, b"--session") == session.encode(), argv
    assert val(argv, b"--seq") == b"2", argv


# Environment assumption pin: fish gives the next command line the status of
# the last command, whatever fish_prompt ran in between.
# 이것을 실패시키는 것: 프롬프트 함수 뒤에 $status를 되살리지 않는 fish(bingsu 변이로는 죽지 않음).
def test_status_reaches_the_next_command_line(tmp_path):
    s, _ = start(tmp_path, minimal_record())
    # Typed directly: run() would add its marker command in between.
    s.expect(b"> ")
    s.p.sendline("false")
    s.run('echo "S=$status"')
    out = visible(s.close())
    assert b"S=1" in out, out


# The keymap is fish's bind mode as is. Set directly: switching to vi
# bindings from a PTY leaves fish 3.6 in normal mode ("default"), so the
# value would not tell a passed mode from the fallback.
# 이것을 실패시키는 것: `set -a ctx --keymap $fish_bind_mode`에 상수 `default`를 넘기는 것.
def test_keymap_is_the_bind_mode(tmp_path):
    _, inst = install_once(tmp_path, b"set -g fish_bind_mode insert\nfish_prompt\n")
    (argv,) = inst.calls()
    assert val(argv, b"--keymap") == b"insert", argv


# The envelope refuses a keymap outside 1 to 16 of [a-z_] and with it the
# whole call (error:bad-args). A user-defined bind mode with another name is
# left out, so the real binary renders the prompt. A script, not a PTY: a
# shell switched to a mode without bindings takes no more input.
# 이것을 실패시키는 것: keymap 검사를 지우고 `--keymap $fish_bind_mode`를 늘 넘기는 것(bad-args),
# 검사의 `{1,16}`을 `{1,17}`로 바꾸는 것(17자 이름), 집합에 숫자·대문자·`-`를 넣는 것,
# `\z`를 `$`로 바꾸는 것(`$`는 끝 줄바꿈 앞에서도 맞음). `insert\n`은 fish가 줄바꿈으로 읽는다.
@pytest.mark.parametrize("mode", ["My-Mode", "mode2", "a" * 17, "insert\\n"])
def test_bind_mode_outside_the_envelope_is_left_out(tmp_path, mode):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("fish", env)
    body = f"set -g fish_bind_mode {mode}\nfish_prompt >/dev/null\nprintf '%s' $_bingsu_f[9]\n".encode()
    r = run_shell_script("fish", script + b"\n" + body, env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    assert r.stdout.startswith(b"ok:"), r.stdout


# 이것을 실패시키는 것: keymap 집합에서 `_`를 빼는 것(replace_one이 빠짐).
@pytest.mark.parametrize("mode", ["replace_one", "a" * 16])
def test_bind_mode_inside_the_envelope_is_passed(tmp_path, mode):
    _, inst = install_once(tmp_path, f"set -g fish_bind_mode {mode}\nfish_prompt\n".encode())
    (argv,) = inst.calls()
    assert val(argv, b"--keymap") == mode.encode(), argv


def wait_call(inst, start, pred, timeout=15):
    """Index of the first call at or after `start` that matches `pred`."""
    deadline = time.monotonic() + timeout
    while True:
        calls = inst.calls()
        for k in range(start, len(calls)):
            if pred(calls[k]):
                return k
        assert time.monotonic() < deadline, calls[start:]
        time.sleep(0.05)


def ms_between(lo, hi):
    return lambda c: lo <= int(val(c, b"--duration-ms") or -1) < hi


# A line that runs nothing leaves CMD_DURATION at the last command's value
# (fish 3.6, 4.0 and 4.9); fish_preexec still runs for blanks, a comment and
# `;`. The line follows a 300 ms sleep and comes before a 600 ms one: every
# call in between (its prompt, redraws) carries no duration.
# 이것을 실패시키는 것: `test "$g" != "$_bingsu_gen"` 비교를 지우는 것(빈 줄 뒤에 sleep의 300이 다시 감),
# 프롬프트 뒤 `set -g _bingsu_gen $g`를 지우는 것.
@pytest.mark.parametrize("line", ["", "   ", "# c", ";"])
def test_line_that_runs_nothing_sends_no_duration(tmp_path, line):
    s, inst = start(tmp_path, minimal_record())
    s._ready()
    n = len(inst.calls())
    s.p.sendline("sleep 0.3")
    i = wait_call(inst, n, ms_between(250, 550))
    s._ready()
    s.p.sendline(line)
    s._ready()
    s.p.sendline("sleep 0.6")
    j = wait_call(inst, i + 1, ms_between(550, 3000))
    between = inst.calls()[i + 1:j]
    s.close()
    assert between, "no prompt for the line that runs nothing"
    assert all(b"--duration-ms" not in c for c in between), between


# fish runs no command between init and the call here, so the generation is
# the one init saw. In a script the generation stays 0, hence an inherited 5.
# 이것을 실패시키는 것: init이 상속된 `_bingsu_gen`을 그대로 두는 것(`set -q _bingsu_gen; or set -g …`).
def test_inherited_generation_is_replaced_at_init(tmp_path):
    body = b"set -g CMD_DURATION 1234\nfish_prompt\n"
    _, inst = install_once(tmp_path, body, inherit={"_bingsu_gen": "5"})
    (argv,) = inst.calls()
    assert b"--duration-ms" not in argv, argv


# CMD_DURATION erased or replaced after a command ran (a fish_postexec
# handler; fish sets it before those run): the generation advanced but there
# is no number. A PTY, not a script: the generation moves only in an
# interactive fish.
# 이것을 실패시키는 것: duration 조건의 모양 검사를 지우는 것(빈 값: --duration-ms 뒤가 다음 플래그),
# 모양 검사를 `test -n`으로 바꾸는 것(12abc가 넘어감).
@pytest.mark.parametrize("change", ["set -e CMD_DURATION", "set -g CMD_DURATION 12abc"])
def test_erased_duration_after_a_command_leaves_the_flag_out(tmp_path, change):
    rc_after = f"function _change --on-event fish_postexec; {change}; end"
    s, inst = start(tmp_path, minimal_record(), rc_after=rc_after)
    s.run("true")
    s.close()
    calls = inst.calls()
    assert calls and all(b"--duration-ms" not in c for c in calls), calls
    for c in calls:
        flags = [a for a in c if a.startswith(b"--") and b"=" not in a]
        assert all(not val(c, f).startswith(b"--") for f in flags), c


# A COLUMNS a user set to something else: the width falls back to 0 (unknown).
# 이것을 실패시키는 것: COLUMNS 모양 검사를 `test -n`으로 되돌리는 것(abc가 넘어감),
# `{1,6}`을 `{1,7}`로 바꾸는 것.
@pytest.mark.parametrize("cols", ["abc", "1234567", "80x"])
def test_columns_outside_the_shape_send_width_0(tmp_path, cols):
    _, inst = install_once(tmp_path, f"set -g COLUMNS {cols}\nfish_prompt\n".encode())
    (argv,) = inst.calls()
    assert val(argv, b"--width") == b"0", argv


# A refused record draws a constant prompt. fish 3.6 and 4.0 print the
# control characters of a folder name through prompt_pwd as they are; every
# fish prints U+202E. fish_title is emptied so only the prompt can show the
# name.
# 이것을 실패시키는 것: 폴백에 `(prompt_pwd)`를 다시 넣는 것(raw ESC·BEL·U+202E가 터미널로 감).
def test_refused_record_fallback_never_prints_the_directory(tmp_path):
    name = "d\x1b]0;PWNED\x07\x1b[2Jx\u202e"
    folder = short_dir() / name
    folder.mkdir()
    # rc.fish is sourced, never echoed: the control characters reach the
    # terminal only if something prints the directory.
    rc_after = f"function fish_title; end\ncd '{folder}'"
    s, _ = start(tmp_path, b"not a record", rc_after=rc_after)
    s.run("true")
    out = s.close()
    assert name.encode() not in out
    assert b"\x1b]0;PWNED" not in out and "\u202e".encode() not in out, out
    assert "❯ ".encode() in visible(out)
