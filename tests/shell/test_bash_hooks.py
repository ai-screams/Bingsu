"""bash security state machine and PS0 state machine (spec section 3 bash
rows, section 5 "bash execution start time"). bash 5.1 (container) and
current bash."""
import itertools
import os
import re
import subprocess
import time
import warnings

import pyte
import pytest

from conftest import Install, minimal_record, run_shell_script, short_dir, trusted_env
from pty_session import Session, visible

pytestmark = pytest.mark.skipif("bash" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="bash not under test")

LATE = b"bingsu: another prompt hook runs after bingsu"


def hostile_record(c1, c2):
    """What a correct core emits for bash: raw SOH/STX around SGR, data as is."""
    left = (b"\x01\x1b[31m\x02D:$(touch " + c1 + b");`touch " + c2 + b"`;${HOME};$[1+1];\\u;\\w;!\x01\x1b[0m\x02> ")
    return b"B1\x1f7\x1f" + left + b"\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"


def start(tmp_path, rc_before="", rc_after="", record=None, locale=None, cols=200, inherit=None, numeric=None):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    if locale:
        env["LC_ALL"] = locale
    if numeric:
        # LC_ALL would override LC_NUMERIC.
        env.pop("LC_ALL")
        env["LANG"] = "C.UTF-8"
        env["LC_NUMERIC"] = numeric
    (tmp_path / "init.bash").write_bytes(inst.init("bash", env))
    env.update(inherit or {})
    cdir = short_dir()
    canaries = [cdir / "c1", cdir / "c2"]
    inst.use_fake(record or hostile_record(*[str(c).encode() for c in canaries]))
    (tmp_path / "rc.bash").write_text(f"{rc_before}\nsource {tmp_path / 'init.bash'}\n{rc_after}\n")
    s = Session("bash", env, cols=cols)
    s.run(f"source {tmp_path / 'rc.bash'}")
    return s, inst, canaries


def want_left(c):
    return f"D:$(touch {c[0]});`touch {c[1]}`;${{HOME}};$[1+1];\\u;\\w;!> ".encode()


def opts(promptvars, posix, nocase=False):
    return "\n".join([
        f"shopt {'-s' if promptvars else '-u'} promptvars",
        f"set {'-o' if posix else '+o'} posix",
        f"shopt {'-s' if nocase else '-u'} nocasematch",
    ])


def val(argv, k):
    return argv[argv.index(k) + 1] if k in argv else None


def install_once(tmp_path, body, record=None):
    """Source init in a plain (non-interactive) bash script, run `body`,
    return (result, argv of every bingsu call)."""
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("bash", env)
    inst.use_fake(record or minimal_record())
    r = run_shell_script("bash", script + b"\n" + body, env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    return r, inst.calls()


# 이것을 실패시키는 것: promptvars 또는 POSIX에서 값 대입을 쓰는 것, 값 대입에서 `\`를 두 배로 하지 않는 것,
# nocasematch를 복원하지 않는 것.
@pytest.mark.parametrize("locale", ["C.UTF-8", "ko_KR.UTF-8"])
@pytest.mark.parametrize("nocase", [False, True])
@pytest.mark.parametrize("promptvars,posix", list(itertools.product([True, False], repeat=2)))
def test_option_matrix_never_executes_data(tmp_path, promptvars, posix, nocase, locale):
    s, _, canaries = start(tmp_path, rc_before=opts(promptvars, posix, nocase), locale=locale)
    s.run("true")
    s.run("shopt -q nocasematch && echo NOCASE_ON || echo NOCASE_OFF")
    out = visible(s.close())
    assert not any(c.exists() for c in canaries), "data was executed"
    assert want_left(canaries) in out
    assert (b"\nNOCASE_ON" in out) == nocase


# 이것을 실패시키는 것: 옵션을 저장 hook에서 읽는 것.
def test_hook_between_save_and_install_changes_options(tmp_path):
    rc_after = ("_evil() { shopt -s promptvars; }\n"
                'PROMPT_COMMAND=("${PROMPT_COMMAND[0]}" _evil "${PROMPT_COMMAND[@]:1}")')
    s, _, canaries = start(tmp_path, rc_before=opts(False, False), rc_after=rc_after)
    s.run("true")
    s.run("true")
    out = visible(s.close())
    assert not any(c.exists() for c in canaries)
    assert want_left(canaries) in out


# Environment assumption pin, not a mutation target: bash 5.1-5.3 restore $?
# before each PROMPT_COMMAND array element, so the save hook's `return 0`
# does not hide the status from the next hook.
# 이것을 실패시키는 것: 배열 원소마다 $?를 되살리지 않는 bash(bingsu 변이로는 죽지 않음).
def test_exit_status_reaches_the_next_hook(tmp_path):
    rc_after = ('_probe() { echo "PROBE:$?"; }\n'
                'PROMPT_COMMAND=("${PROMPT_COMMAND[0]}" _probe "${PROMPT_COMMAND[@]:1}")')
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("false")
    s.run("true")
    out = visible(s.close())
    assert b"PROBE:1" in out and b"PROBE:0" in out


# Environment assumption pin, same reason: the install hook returns 0 and the
# hook after it still sees the command's status.
# 이것을 실패시키는 것: 배열 원소마다 $?를 되살리지 않는 bash(bingsu 변이로는 죽지 않음).
def test_hook_after_install_sees_command_status(tmp_path):
    rc_after = '_after() { echo "after=$?"; }\nPROMPT_COMMAND+=(_after)'
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("false")
    out = visible(s.close())
    assert b"after=1" in out


# Environment assumption pin: a user hook in the middle that returns 7 does
# not change what the next hook sees (the reason both bingsu hooks can
# return 0 without losing anything).
# 이것을 실패시키는 것: 배열 원소마다 $?를 되살리지 않는 bash(bingsu 변이로는 죽지 않음).
def test_nonzero_middle_hook_does_not_change_status(tmp_path):
    rc_after = ('_seven() { return 7; }\n_probe() { echo "PROBE:$?"; }\n'
                'PROMPT_COMMAND=("${PROMPT_COMMAND[0]}" _seven _probe "${PROMPT_COMMAND[@]:1}")')
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("false")
    out = visible(s.close())
    assert b"PROBE:1" in out and b"PROBE:7" not in out, out


# errexit: a PROMPT_COMMAND element that returns non-zero ends the
# interactive shell, so a status left by `false && :` must not come back
# from a bingsu hook. bingsu still receives the status.
# 이것을 실패시키는 것: 저장 hook이나 설치 hook의 `return 0`을 `return "$_bingsu_s"`로 되돌리는 것(셸 종료).
def test_set_e_shell_survives_a_nonzero_status(tmp_path):
    s, inst, _ = start(tmp_path, rc_before="set -e", record=minimal_record())
    s.run("false && :")
    s.run("echo AL\"\"IVE")
    out = visible(s.close())
    assert b"\nALIVE" in out, out
    assert any(val(c, b"--status") == b"1" for c in inst.calls()), inst.calls()


CHK = r"""_chk() { local n=0 s=$PS0; while [[ $s == *'_bingsu_t0:0:'* ]]; do n=$((n+1)); s=${s#*'_bingsu_t0:0:'}; done; echo "PREFIX=$n"; }"""


# PS0 acceptance list (spec section 5 "bash execution start time", confirmation row).
# 이것을 실패시키는 것: 설치 hook이 `_bingsu_t0=`로 비우지 않는 것(엔터만 친 줄에 실행 시간이 붙음),
# PS0에 _bingsu_ps0를 붙이지 않는 것(실행 시간 없음).
def test_ps0_duration_cases(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record())
    s.run("sleep 0.3")                                   # normal command
    s.run("for i in 1; do\nsleep 0.3\ndone")             # multi-line command
    s.run("f() { sleep 0.3; }; f")                        # function
    s.run("sleep 0.3; false")                            # failing command
    s.run("")                                            # empty line after a real command
    s.close()
    calls = inst.calls()
    durs = [val(c, b"--duration-ms") for c in calls]
    assert sum(1 for d in durs if d and int(d) >= 250) >= 4, durs
    assert durs[-1] is None or durs[-2] is None, "Enter-only must not carry a duration"
    assert any(val(c, b"--status") == b"1" for c in calls)


# 이것을 실패시키는 것: PS0 문자열이나 hook이 unset 변수를 읽는 것(set -u에서 오류).
def test_ps0_under_set_u(tmp_path):
    s, _, _ = start(tmp_path, rc_before="set -u", record=minimal_record())
    s.run("sleep 0.1")
    s.run("")
    out = visible(s.close())
    assert b"unbound variable" not in out


# EPOCHREALTIME unset (it then loses its special meaning): commands still
# run, and no duration is reported.
# 이것을 실패시키는 것: _bingsu_ps0에서 바깥 `${EPOCHREALTIME+…}`를 빼는 것(산술 오류로 명령이 실행되지 않음).
@pytest.mark.parametrize("mode", ["", "set -u"])
def test_ps0_without_epochrealtime(tmp_path, mode):
    s, inst, _ = start(tmp_path, rc_before=mode, rc_after="unset EPOCHREALTIME", record=minimal_record())
    s.run("echo RAN_A")
    s.run("echo RAN_B")
    out = visible(s.close())
    assert b"\nRAN_A" in out and b"\nRAN_B" in out, out
    assert all(val(c, b"--duration-ms") is None for c in inst.calls()), inst.calls()


# The probe tests/shell/probes/bash_ps0_posix.py found PS0 expanded in POSIX
# mode with promptvars off (bash 5.1.16, 5.2.37, 5.3.20), so the prefix is
# installed there and the duration is known.
# 이것을 실패시키는 것: exp0 조건에서 `{ [[ -o posix ]] && (( _bingsu_ps0_posix )); }`를 지우는 것.
def test_ps0_prefix_in_posix_mode_without_promptvars(tmp_path):
    s, inst, _ = start(tmp_path, rc_before=opts(False, True), rc_after=CHK, record=minimal_record())
    s.run("sleep 0.3")
    s.run("_chk")
    out = visible(s.close())
    assert b"PREFIX=1" in out, out
    durs = [int(val(c, b"--duration-ms")) for c in inst.calls() if val(c, b"--duration-ms")]
    assert any(d >= 250 for d in durs), durs


# 이것을 실패시키는 것: 옵션 전환 때 PS0 앞붙임이 둘이 되거나, 확장이 꺼진 상태에서 bingsu 글자가 찍히는 것.
@pytest.mark.parametrize("seq", [("-s", "-u", "-s"), ("-u", "-s", "-u")])
def test_ps0_prefix_stays_single_across_toggles(tmp_path, seq):
    s, _, _ = start(tmp_path, rc_before="set +o posix", rc_after=CHK, record=minimal_record())
    for pv in seq:
        s.run(f"shopt {pv} promptvars")
        s.run("true")
        s.run("_chk")
    out = visible(s.close())
    got = [int(x.split(b"=")[1]) for x in out.split() if x.startswith(b"PREFIX=")]
    want = [1 if pv == "-s" else 0 for pv in seq]
    assert got == want, got
    assert b"${_bingsu_t0" not in out


# 이것을 실패시키는 것: 원래 PS0를 다시 저장하거나(init 두 번에 앞붙임 둘) 원래 PS0를 버리는 것.
def test_ps0_keeps_user_ps0_and_init_twice(tmp_path):
    s, _, _ = start(tmp_path, rc_before="PS0='PS0OUT\\n'", rc_after=CHK, record=minimal_record())
    s.run(f"source {tmp_path / 'init.bash'}")
    before = s.log.getvalue().count(b"PS0OUT")
    s.run("true")   # the command and the marker echo each print PS0 once
    after = s.log.getvalue().count(b"PS0OUT")
    s.run("_chk")
    out = visible(s.close())
    assert after - before == 2, (before, after)
    assert b"PREFIX=1" in out


# Registration is decided by membership, the original PS0 by the owned
# flag: a re-init after PROMPT_COMMAND was emptied registers again but keeps
# the PS0 saved by the first init.
# 이것을 실패시키는 것: 원래 PS0 저장을 owned 플래그가 아니라 등록 여부로 정하는 것(앞붙임 둘).
def test_reinit_after_prompt_command_reset_keeps_one_prefix(tmp_path):
    s, _, _ = start(tmp_path, rc_after=CHK, record=minimal_record())
    s.run("true")
    s.run(f"PROMPT_COMMAND=(); source {tmp_path / 'init.bash'}")
    s.run("true")
    s.run("_chk")
    out = visible(s.close())
    assert b"PREFIX=1" in out, out


# pyte's own model is verified before it judges bash (pyte behaviour is UNVERIFIED until this passes).
def test_pyte_wraps_like_a_vt100():
    screen = pyte.Screen(10, 3)
    stream = pyte.ByteStream(screen)
    stream.feed(b"\x1b[31mAB\x1b[0m" + b"x" * 8)
    assert screen.display[0] == "ABxxxxxxxx"
    stream.feed(b"y")
    assert screen.display[1][0] == "y"


def wait_screen(s, cols, done, timeout=10):
    """Feed the transcript to a pyte screen until done(screen) holds (a
    condition, not a fixed sleep). Returns the screen, or None on timeout."""
    screen = pyte.Screen(cols, 24)
    stream = pyte.ByteStream(screen)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s.p.read_nonblocking(65536, timeout=0.2)
        except Exception:
            pass
        screen.reset()
        stream.feed(s.log.getvalue())
        if done(screen):
            return screen
    return None


def typed_screen(s, cols, k, tmp_path):
    """Type k characters, then wait until the screen shows all of them.
    Returns the pyte screen."""
    s.p.send("x" * k)
    screen = wait_screen(s, cols, lambda sc: sum(row.count("x") for row in sc.display) >= k)
    if screen is None:
        (tmp_path / "transcript.bin").write_bytes(s.log.getvalue())
        raise AssertionError(f"screen never showed {k} typed chars; transcript: {tmp_path / 'transcript.bin'}")
    return screen


# 이것을 실패시키는 것: readline이 원시 SOH·STX(와 그 사이 SGR)를 폭에 넣는 것 — 줄바꿈이 경계보다 일찍 생긴다.
@pytest.mark.parametrize("extra", [-1, 0, 1])
def test_raw_soh_stx_are_zero_width(tmp_path, extra):
    cols = 40
    rec = b"B1\x1f7\x1f\x01\x1b[31m\x02AB\x01\x1b[0m\x02> \x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"
    s, _, _ = start(tmp_path, record=rec, cols=cols)
    k = cols - 4 + extra  # "AB> " is 4 visible cells
    screen = typed_screen(s, cols, k, tmp_path)
    prompt_row = next(i for i, row in enumerate(screen.display) if row.startswith("AB> x"))
    rows = screen.display
    # The terminal wraps typed text by itself, so the rows above look right
    # even when readline miscounts the prompt. Moving to the line start and
    # inserting makes readline place the cursor from its own width count.
    s.p.send("\x01Y")
    screen = wait_screen(s, cols, lambda sc: any("Y" in r for r in sc.display))
    s.p.sendcontrol("c")
    s.close()
    (tmp_path / "transcript.bin").write_bytes(s.log.getvalue())
    where = f"transcript: {tmp_path / 'transcript.bin'}"
    if extra < 0:
        assert rows[prompt_row] == "AB> " + "x" * k + " ", where
    else:
        assert rows[prompt_row] == "AB> " + "x" * (cols - 4), where
        assert rows[prompt_row + 1].rstrip() == "x" * extra, where
    assert screen is not None, f"Y never shown; {where}"
    assert screen.display[screen.cursor.y].startswith("AB> Yx") and screen.cursor.x == 5, where


# 이것을 실패시키는 것: 경고 조건에서 `-z ${_bingsu_warned_last-}`를 빼는 것(경고가 프롬프트마다 나감).
def test_late_hook_warns_exactly_once(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { :; }\nPROMPT_COMMAND+=(_late)", record=minimal_record())
    for _ in range(3):
        s.run("true")
    out = visible(s.close())
    assert out.count(LATE) == 1


# A last hook whose name differs from bingsu's only in case is still another hook.
# 이것을 실패시키는 것: 설치 hook이 nocasematch를 끄지 않고 마지막 hook 이름을 견주는 것(경고 없음).
def test_late_hook_check_ignores_nocasematch(tmp_path):
    rc_after = "_BINGSU_INSTALL() { :; }\nPROMPT_COMMAND+=(_BINGSU_INSTALL)\nshopt -s nocasematch"
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("true")
    out = visible(s.close())
    assert out.count(LATE) == 1


# F-23. 이것을 실패시키는 것: 등록 블록의 멤버십 조건(`_bingsu_reg`)을 지우는 것(HOOKS=4).
def test_init_twice_registers_hooks_once(tmp_path):
    s, _, _ = start(tmp_path, record=minimal_record())
    s.run(f"source {tmp_path / 'init.bash'}")
    s.run('n=0; for h in "${PROMPT_COMMAND[@]}"; do [[ $h == _bingsu_* ]] && n=$((n+1)); done; echo "HOOKS=$n"')
    out = visible(s.close())
    assert b"HOOKS=2" in out
    assert LATE not in out


# A user hook named exactly like bingsu's install hook in another case must
# not count as registered under nocasematch.
# 이것을 실패시키는 것: 등록 블록 앞에서 nocasematch를 끄지 않는 것(등록이 빠져 프롬프트가 그려지지 않음).
def test_registration_ignores_nocasematch(tmp_path):
    rc_before = "_BINGSU_INSTALL() { :; }\nPROMPT_COMMAND=(_BINGSU_INSTALL)\nshopt -s nocasematch"
    s, inst, _ = start(tmp_path, rc_before=rc_before, record=minimal_record(left=b"HOOKED> "))
    s.run('echo "PC=[${PROMPT_COMMAND[*]}]"')
    out = visible(s.close())
    assert b"PC=[_bingsu_save _BINGSU_INSTALL _bingsu_install]" in out, out
    assert b"HOOKED> " in out and inst.calls()


# A scalar PROMPT_COMMAND set before init becomes the middle element, and a
# stray _bingsu_save left in the array is dropped (one save hook, first).
# 이것을 실패시키는 것: 등록 때 기존 _bingsu_save를 걸러내지 않는 것(save가 둘).
def test_registration_keeps_scalar_and_drops_stray_save(tmp_path):
    rc_before = "PROMPT_COMMAND='echo USER_PC; _bingsu_save'\nPROMPT_COMMAND+=(_bingsu_save)"
    s, _, _ = start(tmp_path, rc_before=rc_before, record=minimal_record())
    s.run('printf "PC=[%s]\\n" "${PROMPT_COMMAND[@]}"')
    out = visible(s.close())
    assert b"PC=[_bingsu_save]\nPC=[echo USER_PC; _bingsu_save]\nPC=[_bingsu_install]" in out.replace(b"\r", b""), out
    assert b"USER_PC" in out


# 이것을 실패시키는 것: 등록 조건을 `_bingsu_hooked` 같은 플래그 검사로 되돌리는 것(상속 플래그가 등록을 막음).
def test_inherited_hooked_flag_does_not_block_registration(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record(left=b"HOOKED> "), inherit={"_bingsu_hooked": "1"})
    s.run('echo "PC=[${PROMPT_COMMAND[*]}]"')
    out = visible(s.close())
    assert b"PC=[_bingsu_save _bingsu_install]" in out
    assert b"HOOKED> " in out and inst.calls()


# An owned flag that came from the environment is not ours: the user's PS0
# is saved, not the inherited _bingsu_ps0_orig.
# 이것을 실패시키는 것: 머리에서 export된 _bingsu_ps0_owned를 버리지 않는 것(ORIGLEAK가 찍힘).
def test_inherited_ps0_owned_flag_is_ignored(tmp_path):
    s, _, _ = start(tmp_path, rc_before="PS0='MINE\\n'", record=minimal_record(),
                    inherit={"_bingsu_ps0_owned": "1", "_bingsu_ps0_orig": "ORIGLEAK\\n"})
    s.run("true")
    out = visible(s.close())
    assert b"MINE" in out and b"ORIGLEAK" not in out, out


# An inherited owned flag with a PS0 from the environment: init saves that
# PS0 as the original and installs exactly one prefix in front of it.
# 이것을 실패시키는 것: 머리의 `${_bingsu_ps0_owned@a}` export 검사를 지우는 것(원래 PS0가 저장되지 않음).
def test_inherited_owned_flag_keeps_inherited_ps0_and_one_prefix(tmp_path):
    s, _, _ = start(tmp_path, rc_after=CHK, record=minimal_record(),
                    inherit={"_bingsu_ps0_owned": "1", "PS0": "XPS0"})
    s.run("_chk")
    s.run('[[ $_bingsu_ps0_orig == XPS0 && $PS0 == *XPS0 ]] && echo ORIG""_KEPT')
    out = visible(s.close())
    # The inherited PS0 prints right before each command's output.
    assert b"XPS0PREFIX=1" in out and b"XPS0ORIG_KEPT" in out, out


# 이것을 실패시키는 것: 머리의 `_bingsu_t0=`를 빼는 것(첫 프롬프트에 --duration-ms).
def test_inherited_t0_is_reset(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record(), inherit={"_bingsu_t0": "1", "_bingsu_t1": "999999999999"})
    s.close()
    first = inst.calls()[0]
    assert b"--duration-ms" not in first, first


# 이것을 실패시키는 것: 첫 등록 때 `_bingsu_warned_last=` 초기화를 빼는 것(경고가 사라짐).
def test_inherited_warned_flag_is_reset(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { :; }\nPROMPT_COMMAND+=(_late)",
                    record=minimal_record(), inherit={"_bingsu_warned_last": "1"})
    s.run("true")
    out = visible(s.close())
    assert out.count(LATE) == 1


# The spec says the same order stays quiet after a re-init.
# 이것을 실패시키는 것: `_bingsu_warned_last=` 초기화를 등록 블록 밖(머리)으로 옮기는 것(경고 2회).
def test_reinit_does_not_repeat_late_hook_warning(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { :; }\nPROMPT_COMMAND+=(_late)", record=minimal_record())
    s.run("true")
    s.run(f"source {tmp_path / 'init.bash'}")
    s.run("true")
    s.run("true")
    out = visible(s.close())
    assert out.count(LATE) == 1


# Inherited exported names stay in the shell but leave the environment.
# 이것을 실패시키는 것: init 끝의 `export -n _bingsu_session …` 줄을 지우는 것.
def test_owned_globals_are_not_exported(tmp_path):
    names = ("_bingsu_rec", "_bingsu_f", "_bingsu_disp", "_bingsu_note", "_bingsu_key", "_bingsu_s", "_bingsu_p",
             "_bingsu_t0", "_bingsu_t1", "_bingsu_ps0", "_bingsu_ps0_orig", "_bingsu_ps0_owned",
             "_bingsu_ps0_posix", "_bingsu_ps1", "_bingsu_warned_last", "_bingsu_seq")
    inherit = {n: "1" for n in names}
    inherit["_bingsu_session"] = "0123456789abcdef0123456789abcdef"
    s, _, _ = start(tmp_path, record=minimal_record(), inherit=inherit)
    s.run("echo \"EXPORTED=$(env | grep -c '^_bingsu_')\"")
    out = visible(s.close())
    assert b"EXPORTED=0" in out, out


# 이것을 실패시키는 것: 종료 시각을 설치 hook에서 읽는 것(사이 hook의 0.5초가 들어감).
def test_duration_excludes_hooks_between_save_and_install(tmp_path):
    rc_after = ("_slow() { sleep 1.0; }\n"
                'PROMPT_COMMAND=("${PROMPT_COMMAND[0]}" _slow "${PROMPT_COMMAND[@]:1}")')
    s, inst, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("sleep 0.1")
    s.close()
    ms = [int(val(c, b"--duration-ms")) for c in inst.calls() if val(c, b"--duration-ms")]
    # The command takes 100 ms, the hook between the two 1000 ms: counting
    # the hook gives 1100 or more. 500 ms of slack for a loaded machine.
    assert ms and max(ms) < 600, ms
    assert any(m >= 80 for m in ms), ms


# 이것을 실패시키는 것: `[[ -o vi ]]` 판정을 지우는 것(vi에서도 emacs), 저장 hook의 PIPESTATUS 저장을
# `_bingsu_p=($?)`로 바꾸는 것(0,1 없음), `\j` 대신 상수를 넘기는 것.
def test_ctx_values_passed_each_prompt(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record())
    s.run("true | false")
    s.run("sleep 5 &")
    s.run("set -o vi")
    s.run("true")
    s.run("kill %1; wait")
    s.close()
    calls = inst.calls()
    assert any(val(c, b"--pipestatus") == b"0,1" for c in calls), calls
    assert any(val(c, b"--jobs") == b"1" for c in calls), calls
    assert val(calls[0], b"--jobs") == b"0" and val(calls[0], b"--keymap") == b"emacs", calls[0]
    assert val(calls[-1], b"--keymap") == b"viins", calls[-1]
    seqs = [int(val(c, b"--seq")) for c in calls]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


# 이것을 실패시키는 것: `[[ -z $pst ]] && pst=$_bingsu_s` 줄을 지우는 것(빈 --pipestatus),
# 설치 hook이 저장한 상태를 돌려주는 것(RC=3).
def test_empty_pipestatus_falls_back_to_status(tmp_path):
    r, calls = install_once(tmp_path, b'_bingsu_p=(); _bingsu_s=3; _bingsu_install; echo "RC=$?"\n')
    (argv,) = calls
    assert val(argv, b"--status") == b"3" and val(argv, b"--pipestatus") == b"3", argv
    assert r.stdout == b"RC=0\n", r.stdout


# Review Focus 3. 이것을 실패시키는 것: `${COLUMNS:-0}` 대신 `$COLUMNS`를 넘기는 것(빈 값).
def test_bash_columns_unset(tmp_path):
    _, calls = install_once(tmp_path, b"unset COLUMNS\n_bingsu_install\n")
    (argv,) = calls
    assert val(argv, b"--width") == b"0", argv


# A record the reader refuses leaves the prompt free of record data.
# 이것을 실패시키는 것: 거부된 레코드에서 `PS1='\w ❯ '` 대신 레코드 필드를 쓰는 것.
def test_refused_record_draws_fallback_prompt(tmp_path):
    r, _ = install_once(tmp_path, b'_bingsu_install; printf "P=[%s]\\n" "$PS1"\n',
                        record=b"B1\x1f7\x1fD:$(touch x)\x1e")
    assert r.stdout == "P=[\\w ❯ ]\n".encode(), r.stdout


# Review Focus 1. 이것을 실패시키는 것: hook 안의 빈 배열·unset 변수 참조(set -u),
# 끝나지 않은 파이프의 실패(pipefail)가 셸을 멈추거나 오류를 찍는 것. The set -u cases die when
# init reads `$PS0` instead of `${PS0-}`; the pipefail case is an environment
# pin (no bingsu mutation found that only pipefail exposes).
@pytest.mark.parametrize("mode", ["set -u", "set -o pipefail", "set -euo pipefail"])
def test_bash_strict_modes(tmp_path, mode):
    s, inst, _ = start(tmp_path, rc_before=mode, record=minimal_record())
    s.run("true")
    s.run("true | true")
    s.run("")
    out = visible(s.close())
    assert b"unbound variable" not in out
    assert b"bad substitution" not in out
    assert len(inst.calls()) >= 4


# Review Focus 2. 이것을 실패시키는 것: _bingsu_call의 `{ …; } 2>/dev/null`을 빼는 것
# (bash 4.4+는 명령 치환의 NUL마다 stderr에 경고를 쓴다).
def test_bash_nul_output_is_silent(tmp_path):
    rec = b"B1\x1f7\x1fL\x00x\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"
    s, _, _ = start(tmp_path, record=rec)
    s.run("true")
    out = visible(s.close())
    assert b"null byte" not in out


def nonascii_decimal_locale():
    """A locale whose decimal point is not ASCII (fa_IR, ps_AF: U+066B), as
    the bash under test reports it in EPOCHREALTIME. None if there is none."""
    names = subprocess.run(["locale", "-a"], capture_output=True, text=True).stdout.split()
    for name in names:
        if not re.match(r"(fa_IR|ps_AF|ar_)", name):
            continue
        r = subprocess.run(["bash", "-c", 'printf %s "$EPOCHREALTIME"'], capture_output=True,
                           env={"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_NUMERIC": name})
        if any(b > 0x7f for b in r.stdout):
            return name
    return None


# S1-1. A multibyte decimal point in EPOCHREALTIME made the PS0 arithmetic
# fail, and bash then ran no command line at all (exit included).
# 이것을 실패시키는 것: PS0나 저장 hook의 `${EPOCHREALTIME//[^0123456789]/}`를 `${EPOCHREALTIME/[.,]/}`로 되돌리는 것.
def test_nonascii_decimal_point_locale(tmp_path):
    loc = nonascii_decimal_locale()
    if loc is None:
        warnings.warn("NO non-ASCII decimal-point locale here: S1-1 is NOT tested on this host")
        pytest.skip("NO non-ASCII decimal-point locale (fa_IR, ps_AF, ar_*): S1-1 NOT TESTED")
    s, inst, _ = start(tmp_path, record=minimal_record(), numeric=loc)
    s.run("sleep 0.2")
    s.run('echo R""AN')
    out = visible(s.close())
    assert b"\nRAN" in out and b"syntax error" not in out, out
    ms = [int(val(c, b"--duration-ms")) for c in inst.calls() if val(c, b"--duration-ms")]
    assert any(150 <= m < 5000 for m in ms), (loc, ms)


# S1-2. An exported PS1 holding the value-assigned record (promptvars off)
# would be expanded by a child bash without bingsu (promptvars on there).
# 이것을 실패시키는 것: 설치 hook 끝의 `export -n PS1 PS0 …`에서 PS1·PS0를 빼는 것(canary 생성).
def test_set_a_child_bash_never_runs_the_record(tmp_path):
    s, _, canaries = start(tmp_path, rc_before="set -a\n" + opts(False, False))
    s.run("true")
    s.run("bash --noprofile --norc -i")
    s.run('echo "CPS1=[$PS1] CPS0=[${PS0-unset}]"')
    s.run("set -u")
    s.run('echo CHILD_""OK')
    s.run("exit")
    out = visible(s.close())
    assert not any(c.exists() for c in canaries), "data was executed in the child"
    assert rb"CPS1=[\s-\v\$ ] CPS0=[unset]" in out, out
    assert b"\nCHILD_OK" in out, out


# F1-1. A PS0 copied from a bingsu shell (here exported on the same line, so
# the install hook could not un-export it first) keeps one prefix in the
# child and the grandchild, and the user's PS0 survives.
# 이것을 실패시키는 것: 원래 PS0 저장 때 bingsu 앞붙임을 벗겨내는 while 루프를 지우는 것(PREFIX=2).
def test_exported_ps0_keeps_one_prefix_in_nested_shells(tmp_path):
    s, inst, _ = start(tmp_path, rc_before="PS0=XPS0", record=minimal_record())
    init = tmp_path / "init.bash"
    for level in ("child", "grandchild"):
        s.run("export PS0; bash --noprofile --norc -i")
        s.run(f"source {init}")
        s.run(CHK)
        s.run("_chk")
        s.run('[[ $_bingsu_ps0_orig == XPS0 ]] && echo ORIG""_KEPT')
        n = len(inst.calls())
        s.run("sleep 0.2")
        assert any(val(c, b"--duration-ms") and int(val(c, b"--duration-ms")) >= 150
                   for c in inst.calls()[n:]), (level, inst.calls()[n:])
    s.run("exit")
    s.run("exit")
    out = visible(s.close())
    assert out.count(b"XPS0PREFIX=1") == 2 and b"PREFIX=2" not in out, out
    assert out.count(b"XPS0ORIG_KEPT") == 2, out


# S1-3. Under `set -a` every assignment and function definition is marked
# for export; none of bingsu's names may reach a child's environment.
# 이것을 실패시키는 것: init 끝의 `export -n -f …` 줄이나 hook 끝의 `export -n`을 지우는 것.
def test_set_a_leaks_nothing(tmp_path):
    s, _, _ = start(tmp_path, rc_before="set -a", record=minimal_record())
    s.run("sleep 0.1")
    s.run("true")
    s.run('echo "LEAKED=$(env | grep -c _bingsu_)"')
    out = visible(s.close())
    assert b"LEAKED=0" in out, out


# F1-2. Compatibility pin (no bingsu mutation): glob and redirection options
# leave init, both hooks and the options themselves alone. The options are
# printed back, so a run that never turned them on fails.
OPTS = {"extglob": "shopt -s extglob", "nullglob": "shopt -s nullglob", "failglob": "shopt -s failglob",
        "noclobber": "set -o noclobber"}


@pytest.mark.parametrize("names", [("extglob", "nullglob", "failglob", "noclobber"), ("extglob",), ("nullglob",),
                                   ("failglob",), ("noclobber",)])
def test_glob_and_noclobber_options(tmp_path, names):
    s, inst, _ = start(tmp_path, rc_before="\n".join(OPTS[n] for n in names), record=minimal_record(left=b"OK> "))
    s.run("true")
    s.run("true")
    s.run("shopt -p extglob nullglob failglob; set -o | grep noclobber")
    out = visible(s.close())
    assert b"bash:" not in out, out
    assert len(inst.calls()) >= 4 and b"OK> " in out
    for n in names:
        want = b"set -o noclobber" if n == "noclobber" else f"shopt -s {n}".encode()
        if n == "noclobber":
            assert re.search(rb"noclobber\s+on", out), out
        else:
            assert want in out, out
