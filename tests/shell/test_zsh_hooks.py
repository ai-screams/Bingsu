"""zsh security state machine (spec section 3 option table, section 5 two
hooks, section 7 security table rows for zsh). Runs on zsh 5.8 (container)
and the current zsh."""
import itertools
import os
import re
import subprocess
import threading
import warnings

import pexpect
import pytest

from conftest import ROOT, Install, minimal_record, run_shell_script, short_dir, status_bait_record, trusted_env
from pty_session import Session, visible
from screen_session import ScreenSession
from test_zsh_screen import enter, settle

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")


def hostile_record(c1, c2, c3):
    """What a correct core emits for zsh: data % doubled, SGR in %{ %}."""
    left = (b"%{\x1b[31m%}D:$(touch " + c1 + b");`touch " + c2 + b"`;${HOME};$[1+1];%%F{red};!;\\u%{\x1b[0m%}> ")
    right = b"R:$(touch " + c3 + b")%%"
    return b"B1\x1f12\x1f" + left + b"\x1f" + right + b"\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"


def start(tmp_path, rc_before="", rc_after="", record=None, inherit=None, load="source {}"):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    (tmp_path / "init.zsh").write_bytes(inst.init("zsh", env))
    env.update(inherit or {})
    cdir = short_dir()
    canaries = [cdir / f"c{i}" for i in (1, 2, 3)]
    inst.use_fake(record or hostile_record(*[str(c).encode() for c in canaries]))
    (tmp_path / "rc.zsh").write_text(f"{rc_before}\n{load.format(tmp_path / 'init.zsh')}\n{rc_after}\n")
    s = Session("zsh", env, cols=200)  # RPROMPT is dropped when the line is too wide
    s.run(f"source {tmp_path / 'rc.zsh'}")
    return s, inst, canaries


def want_left(canaries):
    c1, c2, _ = canaries
    return f"D:$(touch {c1});`touch {c2}`;${{HOME}};$[1+1];%F{{red}};!;\\u> ".encode()


def opt_lines(**opts):
    return "\n".join(("setopt " if on else "unsetopt ") + name for name, on in opts.items())


# 이것을 실패시키는 것: PROMPT_SUBST 켬에서 값 대입을 쓰는 것, PROMPT_BANG에서 `!`를 두 배로 하지 않는 것,
# emulate 없이 KSH_ARRAYS 아래 필드를 읽는 것, Session이 TERM을 넣지 않는 것(RPROMPT가 그려지지 않음).
@pytest.mark.parametrize("ksh", [False, True])
@pytest.mark.parametrize("subst,bang,pct", list(itertools.product([True, False], repeat=3)))
def test_option_matrix_never_executes_data(tmp_path, subst, bang, pct, ksh):
    rc = opt_lines(prompt_subst=subst, prompt_bang=bang, prompt_percent=pct, ksh_arrays=ksh)
    s, _, canaries = start(tmp_path, rc_before=rc)
    s.run("true")
    s.run("true")
    out = visible(s.close())
    assert not any(c.exists() for c in canaries), "data was executed"
    if pct:
        assert want_left(canaries) in out
        assert f"R:$(touch {canaries[2]})%".encode() in out
    else:
        assert "❯ ".encode() in out
        assert b"D:$(touch" not in out


# 이것을 실패시키는 것: 옵션을 저장 hook(맨 앞)에서 읽는 것. 사이 hook이 옵션을 켜면 값 대입 경로에서 실행된다.
def test_hook_between_save_and_install_changes_options(tmp_path):
    rc_before = opt_lines(prompt_subst=False, prompt_bang=False)
    rc_after = ("_evil() { setopt prompt_subst prompt_bang }\n"
                "precmd_functions=($precmd_functions[1] _evil $precmd_functions[2,-1])")
    s, _, canaries = start(tmp_path, rc_before, rc_after)
    s.run("true")
    s.run("true")
    out = visible(s.close())
    assert not any(c.exists() for c in canaries)
    assert want_left(canaries) in out


# Environment assumption pin, not a mutation target: zsh 5.9 restores $?
# before each precmd function, so deleting `return $_bingsu_s` from
# _bingsu_save stays green. The install hook's own return value is pinned
# by test_empty_pipestatus_falls_back_to_status.
# 이것을 실패시키는 것: precmd 함수 사이에 $?를 되살리지 않는 zsh(bingsu 변이로는 죽지 않음).
def test_exit_status_is_restored_for_next_precmd_hook(tmp_path):
    rc_after = ("_probe() { print -r -- \"PROBE:$?\" }\n"
                "precmd_functions=($precmd_functions[1] _probe $precmd_functions[2,-1])")
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("false")
    s.run("true")
    out = visible(s.close())
    assert b"PROBE:1" in out and b"PROBE:0" in out


# A record that carries terminal queries must not get answers typed into the
# shell: the PTY driver answers queries for fish sessions only.
# 이것을 실패시키는 것: Session.expect의 질의 응답 조건(`respond_queries`)을 셸과 무관하게 켜는 것(응답 바이트가 stdin으로 들어감).
def test_terminal_queries_in_record_get_no_answer(tmp_path):
    left = b"\x1b[6n\x1b[c\x1b]11;?\x07> "
    s, _, _ = start(tmp_path, record=minimal_record(left=left))
    s.run("true")
    s.run("true")
    out = s.close()
    assert b"\x1b[6n" in out, "the query never reached the terminal"
    assert b"1;1R" not in out and b"?62;c" not in out and b"rgb:0000" not in out, out


# F-23: init twice redefines functions but registers hooks once.
# 이것을 실패시키는 것: 등록 블록의 `(( ! ${precmd_functions[(Ie)_bingsu_install]:-0} ))` 조건을 지우는 것.
def test_init_twice_registers_hooks_once(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record())
    s.run(f"source {tmp_path / 'init.zsh'}")
    # (@) keeps the filtered array an array inside double quotes; without it
    # ${#…} counts the characters of the joined string.
    s.run('print -r -- "N=${#${(@M)precmd_functions:#_bingsu_*}} P=${#${(@M)preexec_functions:#_bingsu_*}}"')
    out = visible(s.close())
    assert b"N=2 P=1" in out
    assert b"another prompt hook" not in out


# 이것을 실패시키는 것: 경고 조건에서 `-z $_bingsu_warned_last`를 빼는 것(경고가 프롬프트마다 나감).
def test_late_hook_warns_exactly_once(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { : }\nprecmd_functions+=(_late)", record=minimal_record())
    for _ in range(3):
        s.run("true")
    out = visible(s.close())
    assert out.count(b"bingsu: another prompt hook runs after bingsu") == 1


# 이것을 실패시키는 것: preexec_functions에 _bingsu_preexec를 등록하지 않는 것(--duration-ms가 없음).
def test_ctx_values_passed_each_prompt(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record())
    s.run("true | false")
    s.run("sleep 0.3")
    s.run("")
    s.close()
    calls = inst.calls()
    def val(argv, k):
        return argv[argv.index(k) + 1] if k in argv else None
    pipe = [c for c in calls if val(c, b"--pipestatus") == b"0,1"]
    assert pipe, calls
    slept = [int(val(c, b"--duration-ms")) for c in calls if val(c, b"--duration-ms")]
    assert any(ms >= 250 for ms in slept), slept
    assert all(val(c, b"--keymap") == b"main" and val(c, b"--jobs") == b"0" for c in calls)
    seqs = [int(val(c, b"--seq")) for c in calls]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)



# Review Focus 3. 이것을 실패시키는 것: `${COLUMNS:-0}` 대신 `$COLUMNS`를 넘기는 것(빈 값 → error:bad-args).
def test_zsh_columns_unset(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("zsh", env)
    inst.use_fake(minimal_record())
    r = run_shell_script("zsh", script + b"\nunset COLUMNS\n_bingsu_install\n", env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    (argv,) = inst.calls()
    assert argv[argv.index(b"--width") + 1] == b"0"


def install_once(tmp_path, body, record=None):
    """Source init in a plain zsh script, run `body`, return (result, argv).

    zsh runs preexec_functions before each top-level command of a script
    file too (not for `zsh -c`), so a body that needs an unset _bingsu_t0
    puts its commands on one line."""
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("zsh", env)
    inst.use_fake(record or minimal_record())
    r = run_shell_script("zsh", script + b"\n" + body, env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    (argv,) = inst.calls()
    return r, argv


def opt(argv, k):
    return argv[argv.index(k) + 1] if k in argv else None


# A record the reader refuses must leave the prompt free of record data.
# 이것을 실패시키는 것: `elif (( o_pct ))` 가지를 지워 거부된 레코드에서 NO_PROMPT_PERCENT 상수로 떨어지는 것.
def test_refused_record_draws_fallback_prompt(tmp_path):
    r, _ = install_once(tmp_path, b'_bingsu_install; print -r -- "P=[$PROMPT] R=[$RPROMPT]"\n',
                        record=b"B1\x1f7\x1fD:$(touch x)\x1e")
    assert r.stdout == "P=[%~ ❯ ] R=[]\n".encode(), r.stdout


# No preexec ran (first prompt, empty line): no duration is reported.
# 이것을 실패시키는 것: `[[ -n $_bingsu_t0 && … ]]`에서 `-n $_bingsu_t0`를 빼는 것(빈 t0가 0으로 읽혀 큰 값이 나감).
def test_no_duration_without_preexec(tmp_path):
    _, argv = install_once(tmp_path, b"_bingsu_t0=; _bingsu_install\n")
    assert opt(argv, b"--duration-ms") is None, argv


# zsh/datetime gone between preexec and precmd: the save hook reads no end
# time, so no duration rather than a negative one.
# 이것을 실패시키는 것: `[[ -n $_bingsu_t0 && -n $_bingsu_t1 ]]`에서 `-n $_bingsu_t1`를 빼는 것(-1500).
def test_no_duration_without_datetime_module(tmp_path):
    _, argv = install_once(tmp_path, b"_bingsu_t0=1.5; zmodload -u zsh/datetime; _bingsu_save; _bingsu_install\n")
    assert opt(argv, b"--duration-ms") is None, argv


# 이것을 실패시키는 것: `[[ -n $pst ]] || pst=$_bingsu_s` 줄을 지우는 것(빈 --pipestatus),
# 설치 hook이 `return $_bingsu_s` 대신 0을 돌려주는 것(RC=0).
def test_empty_pipestatus_falls_back_to_status(tmp_path):
    r, argv = install_once(tmp_path, b'_bingsu_p=(); _bingsu_s=3; _bingsu_install; print -r -- "RC=$?"\n')
    assert opt(argv, b"--status") == b"3" and opt(argv, b"--pipestatus") == b"3", argv
    # The install hook hands the saved status on (spec section 7 "공존 종료 코드").
    assert r.stdout == b"RC=3\n", r.stdout


# _bingsu_save runs before any emulate, under the user's options.
# 이것을 실패시키는 것: `_bingsu_p=("${pipestatus[@]}")`를 `_bingsu_p=($pipestatus)`로 바꾸는 것(KSH_ARRAYS에서 첫 원소만 남음).
def test_save_hook_under_hostile_user_options(tmp_path):
    body = (b"setopt KSH_ARRAYS SH_WORD_SPLIT NO_UNSET GLOB_SUBST NOMATCH\n"
            b'true | false; _bingsu_save; _bingsu_install; print -r -- "RC=$?"\n')
    r, argv = install_once(tmp_path, body)
    assert opt(argv, b"--status") == b"1" and opt(argv, b"--pipestatus") == b"0,1", argv
    assert r.stdout == b"RC=1\n", r.stdout


# A registration flag inherited from the environment must not keep the
# hooks out: registration is decided by the arrays. From init to a drawn
# prompt in one interactive shell.
# 이것을 실패시키는 것: 등록 조건을 `(( ! ${+_bingsu_hooked} ))` 같은 플래그 검사로 되돌리는 것.
def test_inherited_hooked_flag_does_not_block_registration(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record(left=b"HOOKED> "), inherit={"_bingsu_hooked": "1"})
    s.run('print -r -- "PF=[$precmd_functions] EF=[$preexec_functions]"')
    out = visible(s.close())
    assert b"PF=[_bingsu_save _bingsu_install] EF=[_bingsu_preexec]" in out
    assert b"HOOKED> " in out and inst.calls()


# Hook state inherited from the environment is reset by init.
# 이것을 실패시키는 것: 머리의 `typeset -g … _bingsu_t0= …`에서 `_bingsu_t0=`를 빼는 것(첫 프롬프트에 --duration-ms).
def test_inherited_t0_is_reset(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record(), inherit={"_bingsu_t0": "999999999999"})
    s.close()
    first = inst.calls()[0]
    assert b"--duration-ms" not in first, first


# 이것을 실패시키는 것: 등록 블록의 `_bingsu_warned_last=` 초기화를 빼는 것(경고가 사라짐).
def test_inherited_warned_flag_is_reset(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { : }\nprecmd_functions+=(_late)",
                    record=minimal_record(), inherit={"_bingsu_warned_last": "1"})
    s.run("true")
    out = visible(s.close())
    assert out.count(b"bingsu: another prompt hook runs after bingsu") == 1


# A re-init keeps the shown-once state: the spec says the same order stays quiet.
# 이것을 실패시키는 것: `_bingsu_warned_last=` 초기화를 등록 블록 밖(머리)으로 되돌리는 것(재-init 뒤 경고가 2회).
def test_reinit_does_not_repeat_late_hook_warning(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { : }\nprecmd_functions+=(_late)", record=minimal_record())
    s.run("true")
    s.run(f"source {tmp_path / 'init.zsh'}")
    s.run("true")
    s.run("true")
    out = visible(s.close())
    assert out.count(b"bingsu: another prompt hook runs after bingsu") == 1


# The hook chain cannot show the save hook's return value (zsh restores $?
# per precmd function), so call it directly.
# 이것을 실패시키는 것: _bingsu_save의 `return $_bingsu_s`를 지우는 것(RC=0).
def test_save_hook_returns_saved_status(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("zsh", env)
    r = run_shell_script("zsh", script + b'\nfalse; _bingsu_save; print -r -- "RC=$? S=$_bingsu_s"\n', env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    assert r.stdout == b"RC=1 S=1\n", r.stdout


# preexec runs under the user's options; with the module gone and NO_UNSET
# a bare $EPOCHREALTIME is an error on every command.
# 이것을 실패시키는 것: _bingsu_preexec에서 `emulate -L zsh`와 `${EPOCHREALTIME-}`를 둘 다 빼는 것.
def test_preexec_without_datetime_under_no_unset(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record(left=b"OK> "),
                       rc_after="zmodload -u zsh/datetime\nsetopt NO_UNSET")
    s.run("true")
    s.run("true")
    out = visible(s.close())
    assert b"parameter not set" not in out, out
    assert b"OK> " in out
    assert all(opt(c, b"--duration-ms") is None for c in inst.calls()), inst.calls()


# The module cannot be loaded at all, under options that stop init on the
# first failing command.
# 이것을 실패시키는 것: `zmodload zsh/datetime 2>/dev/null || :`에서 `|| :`를 빼는 것(ERR_EXIT로 셸이 끝남).
def test_init_survives_missing_datetime_module(tmp_path):
    s, inst, _ = start(tmp_path, record=minimal_record(left=b"OK> "),
                       rc_before="module_path=(/nonexistent)\nsetopt ERR_RETURN ERR_EXIT NO_UNSET")
    s.run('print -r -- "N=${#${(@M)precmd_functions:#_bingsu_*}} P=${#${(@M)preexec_functions:#_bingsu_*}} M=${+EPOCHREALTIME}"')
    s.run("true")
    out = visible(s.close())
    assert b"N=2 P=1 M=0" in out, out
    assert b"parameter not set" not in out and b"OK> " in out
    assert all(opt(c, b"--duration-ms") is None for c in inst.calls()), inst.calls()


# Hooks between the save hook and the install hook do not count as command
# time (spec section 5: the save hook records the end time).
# 이것을 실패시키는 것: 종료 시각을 설치 hook에서 읽는 것(사이 hook의 0.5초가 들어감).
def test_duration_excludes_hooks_between_save_and_install(tmp_path):
    rc_after = ("_slow() { sleep 0.5 }\n"
                "precmd_functions=($precmd_functions[1] _slow $precmd_functions[2,-1])")
    s, inst, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("true")
    s.run("sleep 0.1")
    s.close()
    ms = [int(opt(c, b"--duration-ms")) for c in inst.calls() if opt(c, b"--duration-ms")]
    # The command takes 100 ms, the hook between the two 500 ms: counting the
    # hook gives 600 or more, 250 ms of slack on a loaded machine.
    assert ms and max(ms) < 350, ms
    assert any(m >= 80 for m in ms), ms


FRAMED_RUNS = 5
EMPTY_STATUS = b"STATUS=\n"


def framed_run(script, env, tmp):
    """Run `script` with the real binary. A front past its 50 ms deadline exits
    0 and prints nothing by design, which a loaded debug build can do; such a
    run says nothing about the record, so it is repeated and counted. Five
    empty runs stay empty for the caller to refuse, and any other result
    returns at once."""
    for empty in range(FRAMED_RUNS):
        r = run_shell_script("zsh", script, env, tmp)
        if r.stdout != EMPTY_STATUS:
            break
        warnings.warn(f"empty record, run {empty + 1} of {FRAMED_RUNS}")
    return r


# 이것을 실패시키는 것: 빈 결과 밖에서도 다시 돌리는 것, 횟수 상한을 지우는 것.
@pytest.mark.parametrize("printed,runs", [(b"", FRAMED_RUNS), (b"error:bad-args", 1)], ids=["empty", "refused"])
def test_framed_run_repeats_only_an_empty_record(tmp_path, printed, runs):
    env = trusted_env(tmp_path)
    log = tmp_path / "runs"
    script = f'print -r -- x >>"{log}"; print -r -- "STATUS={printed.decode()}"\n'.encode()
    r = framed_run(script, env, tmp_path)
    assert r.stdout == b"STATUS=" + printed + b"\n" and len(log.read_text().split()) == runs


# A clock that stepped back: the wall clock moves under EPOCHREALTIME, and a
# negative duration used to turn the whole prompt into error:bad-args.
# 이것을 실패시키는 것: `ms < 0` 조건을 지우는 것.
def test_clock_step_back_drops_duration_and_keeps_record(tmp_path):
    body = b'_bingsu_t0=$(( EPOCHREALTIME + 1.5 )); _bingsu_save; _bingsu_install; print -r -- "STATUS=$_bingsu_f[-1]"\n'
    r, argv = install_once(tmp_path, body)
    assert opt(argv, b"--status") is not None and opt(argv, b"--duration-ms") is None, argv
    assert r.stdout == b"STATUS=ok:none\n", r.stdout
    real = tmp_path / "real"
    real.mkdir()
    inst = Install(real)
    env = trusted_env(real)
    r = framed_run(inst.init("zsh", env) + b"\n" + body, env, real)
    assert r.stdout == b"STATUS=ok:none\n" and r.stderr == b"", r


def decimal_locale():
    """A locale whose decimal point is not `.`. None if this host has none."""
    names = subprocess.run(["locale", "-a"], capture_output=True, text=True).stdout.split()
    return next((n for n in names if re.match(r"(fa_IR|ps_AF|de_DE|fr_FR)\.(UTF-8|utf8)", n)), None)


# 이것을 실패시키는 것: 시각 계산이 로캘의 소수점에 기대는 것(`,`를 만나 산술 오류로 프롬프트가 사라짐).
def test_duration_under_comma_decimal_locale(tmp_path):
    loc = decimal_locale()
    if loc is None:
        pytest.skip("NO locale with a non-dot decimal point here: NOT TESTED")
    rc = f"export LC_NUMERIC={loc}\n"
    s, inst, canaries = start(tmp_path, rc_before=rc, inherit={"LC_ALL": ""})
    s.run("sleep 0.2")
    s.run("true")
    out = visible(s.close())
    assert want_left(canaries) in out and b"bad math" not in out, out
    ms = [int(opt(c, b"--duration-ms")) for c in inst.calls() if opt(c, b"--duration-ms")]
    assert any(150 <= m < 5000 for m in ms), (loc, ms)


# 이것을 실패시키는 것: 경계에서 정수 변환을 바꾸는 것, 큰 값을 그대로 넘겨 봉투가 레코드를 거부하는 것.
@pytest.mark.parametrize("t0,t1,want", [("100.5", "100.5", b"0"), ("100.0004", "100.0", b"0"),
                                        ("100.002", "100.0", None), ("-1e300", "1e300", "any")],
                         ids=["zero", "under-one-ms-back", "one-ms-back", "over-integer-range"])
def test_duration_at_its_edges(tmp_path, t0, t1, want):
    body = f'_bingsu_t0={t0} _bingsu_t1={t1}; _bingsu_install; print -r -- "STATUS=$_bingsu_f[-1]"\n'.encode()
    r, argv = install_once(tmp_path, body)
    assert r.stdout == b"STATUS=ok:none\n", r.stdout
    if want != "any":
        assert opt(argv, b"--duration-ms") == want, argv
    real = tmp_path / "real"
    real.mkdir()
    inst = Install(real)
    env = trusted_env(real)
    r = framed_run(inst.init("zsh", env) + b"\n" + body, env, real)
    assert r.stdout == b"STATUS=ok:none\n" and r.stderr == b"", r


# Every word of the bootstrap is a target of a global alias, and the parsed body too.
# 이것을 실패시키는 것: 머리의 단어 하나라도 따옴표 없이 두는 것(본문이 출력되거나 aliases가 꺼진 채 남음).
@pytest.mark.parametrize("load", ["source {}", '\\eval "$(<{})"'], ids=["source", "eval"])
@pytest.mark.parametrize("word", ["eval", "local_options", "no_aliases", "no_warn_create_global", "no_csh_junkie_quotes", "setopt", "builtin"])
def test_init_survives_global_aliases(tmp_path, word, load):
    rc_before = f"alias -g {word}='print -r -- HIJACK'"
    s, inst, _ = start(tmp_path, rc_before=rc_before, load=load, record=minimal_record(left=b"ALIAS-OK> "))
    s.run(f"unalias \\{word}")
    s.run('[[ -o aliases ]] && print -r -- ALIASES_"ON"')
    out = visible(s.close())
    assert b"HIJACK" not in out and b"ALIAS-OK> " in out and b"ALIASES_ON" in out, out


# Options that change how quotes parse apply before the script can set anything.
# 이것을 실패시키는 것: 본문을 줄바꿈이 든 일반 따옴표로 내는 것(unmatched), 머리에서 파싱 옵션에 기대는 것.
@pytest.mark.parametrize("option", ["csh_junkie_quotes", "rc_quotes", "ignore_braces", "ignore_close_braces"])
def test_init_parses_under_quote_and_brace_options(tmp_path, option):
    s, inst, _ = start(tmp_path, rc_before=f"setopt {option}", record=minimal_record(left=b"PARSED> "))
    s.run("true")
    out = visible(s.close())
    assert b"PARSED> " in out and b"unmatched" not in out and b"parse error" not in out, out


# 이것을 실패시키는 것: 본문을 파싱할 때 CSH_JUNKIE_QUOTES를 끄지 않는 것(줄바꿈이 든 경로 단어에서 파싱 실패).
def test_path_with_a_newline_parses_under_csh_junkie_quotes(tmp_path):
    inst = Install(tmp_path)
    env = {**trusted_env(tmp_path), "HOME": "/tmp/a\nb"}
    r = run_shell_script("zsh", b"setopt csh_junkie_quotes\n" + inst.init("zsh", env) + b"\nprint -r -- ${+functions[_bingsu_install]}\n", env, tmp_path)
    assert r.stdout == b"1\n" and r.stderr == b"", r


# The script is one `$'…'` word that an eval runs, so a byte the encoder gets
# wrong is code. Every byte a word can hold goes through init and the shell and
# comes back as one argument of the prompt call.
# 이것을 실패시키는 것: `$'…'` 인코더에서 작은따옴표, 역슬래시, 줄바꿈 처리를 빼는 것.
@pytest.mark.parametrize("option", ["no_rc_quotes", "rc_quotes", "csh_junkie_quotes"])
def test_every_byte_survives_the_script_word(tmp_path, option):
    value = b"/" + bytes(range(1, 256))
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("zsh", {**env, "HOME": value})
    assert b"\n" not in script.split(b"eval $'", 1)[1].rsplit(b"'\n}\n", 1)[0]
    inst.use_fake(minimal_record())
    r = run_shell_script("zsh", f"setopt {option}\n".encode() + script + b"\n_bingsu_call --width 80\n", env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r
    (argv,) = inst.calls()
    assert [word for word in argv if word.startswith(b"--git-global-home=")] == [b"--git-global-home=" + value], argv


# A body parsed with the user's aliases runs the alias, not the builtin. The
# canary shows it, and the notice and the status show the hooks still work.
# 이것을 실패시키는 것: init 머리의 `no_aliases`를 지우는 것, `_bingsu_call`의 `no_aliases`를 지우는 것
# (zsh는 `$(…)`를 실행할 때 파싱한다: print, exit).
@pytest.mark.parametrize("load", ["source {}", 'eval "$(<{})"'], ids=["source", "eval"])
@pytest.mark.parametrize("name", ["print", "local", "typeset", "emulate", "return", "exit"])
def test_hooks_survive_user_aliases(tmp_path, name, load):
    canary = short_dir() / "c"
    rc_before = f"alias {name}='touch {canary}; :'"
    rc_after = '_after() { builtin print -u2 -r -- "after=$?" }\nprecmd_functions=($precmd_functions[1] _after $precmd_functions[2,-1])'
    s, inst, _ = start(tmp_path, rc_before=rc_before, rc_after=rc_after, load=load,
                       record=minimal_record(status=b"degraded:sandbox", left=b"ALIAS-OK> "))
    s.run("false")
    s.run(f"unalias {name}")
    out = visible(s.close())
    assert not canary.exists(), "an alias ran inside a hook"
    assert b"ALIAS-OK> " in out and b"after=1" in out, out
    assert out.count(b"could not start its system call filter") == 1, out


# 이것을 실패시키는 것: init 머리의 `local_options`를 지우는 것(init 뒤로 사용자 alias가 꺼짐).
def test_user_aliases_keep_working_after_init(tmp_path):
    s, _, _ = start(tmp_path, rc_before="alias zz='print -r -- ALIAS_""WORKS'", record=minimal_record())
    s.run("zz")
    assert b"ALIAS_WORKS" in visible(s.close())


# init under the option that warns about globals made inside a function.
# 이것을 실패시키는 것: init 머리의 `no_warn_create_global`을 지우는 것(셸 시작마다 경고 줄).
def test_init_is_quiet_under_warn_create_global(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    r = run_shell_script("zsh", b"setopt warn_create_global\n" + inst.init("zsh", env), env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr


COEXIST = ROOT / "tests/shell/fixtures/zsh_coexist"


# Spec section 7, coexistence rows. Real frameworks are test D4's; these are their shapes.
# 이것을 실패시키는 것: 저장 hook을 맨 앞으로 옮기지 않는 것, 설치 hook이 저장한 값을 돌려주지 않는 것,
# hook을 다시 등록하는 것, preexec 체인을 덮는 것, late hook 경고를 반복하는 것.
@pytest.mark.parametrize("inits", [1, 2], ids=["init-once", "init-twice"])
def test_coexists_with_framework_shapes(tmp_path, inits):
    log = tmp_path / "hooks.log"
    init = tmp_path / "init.zsh"
    rc_before = f"source {COEXIST}/omz_like.zsh\nsource {COEXIST}/prompt_tool.zsh"
    rc_after = "\n".join([f"source {init}"] * (inits - 1) + ["_tool_attach"])
    s, inst, _ = start(tmp_path, rc_before=rc_before, rc_after=rc_after, inherit={"BINGSU_T_LOG": str(log)},
                       record=minimal_record(left=b"BINGSU> "))
    s.run("(exit 7)")
    s.run("true")
    s.run('print -r -- "FUNCS=$precmd_functions[1]:${#precmd_functions}:${#preexec_functions}"')
    out = visible(s.close())
    lines = log.read_text().splitlines()
    at = lines.index("omz-precmd 7")
    assert lines[at + 1] == "tool-precmd 7", lines
    assert "omz-preexec" in lines and b"BINGSU> " in out and b"tool> " not in out.split(b"BINGSU> ", 1)[1], out
    assert b"FUNCS=_bingsu_save:4:2" in out, out
    assert out.count(b"bingsu: another prompt hook runs after bingsu") == 1, out


# Inherited exported names stay in the shell but leave the environment.
# 이것을 실패시키는 것: hooks.zsh 머리의 `typeset -g +x …` 줄이나 reader.zsh의 `typeset -g +x …` 줄을 지우는 것
# (ALL_EXPORT 아래), 머리의 unset을 지우고 물려받은 값을 남기는 것.
@pytest.mark.parametrize("rc_before", ["", "setopt all_export"], ids=["inherited", "all-export"])
def test_owned_globals_are_not_exported(tmp_path, rc_before):
    inherit = {n: "1" for n in ("_bingsu_rec", "_bingsu_s", "_bingsu_p", "_bingsu_t0", "_bingsu_t1",
                                "_bingsu_ps1", "_bingsu_rps1", "_bingsu_warned_last", "_bingsu_seq",
                                "_bingsu_f", "_bingsu_disp", "_bingsu_note", "_bingsu_key")}
    inherit["_bingsu_session"] = "0123456789abcdef0123456789abcdef"
    s, _, _ = start(tmp_path, rc_before=rc_before, record=minimal_record(), inherit=inherit)
    s.run('print -r -- "EXPORTED=$(env | grep -c \'^_bingsu_\')"')
    out = visible(s.close())
    assert b"EXPORTED=0" in out, out


OWNED = {name: "scalar" for name in ("_bingsu_session", "_bingsu_warned_last", "_bingsu_rec", "_bingsu_s", "_bingsu_t0",
                                     "_bingsu_t1", "_bingsu_ps1", "_bingsu_rps1", "_bingsu_dead", "_bingsu_key_prev", "_bingsu_nested", "_bingsu_keymap", "_bingsu_drawn_cols",
                                     "_bingsu_disp", "_bingsu_note", "_bingsu_key")}
OWNED.update(_bingsu_p="array", _bingsu_f="array", _bingsu_ctx="array", _bingsu_seq="integer")


# Attributes set in this shell before init; the environment cannot carry them.
# 이것을 실패시키는 것: hooks.zsh나 reader.zsh 머리의 unset에서 이름 하나를 빼는 것.
@pytest.mark.parametrize("attr", ["i", "F", "l", "u", "a"])
def test_owned_globals_lose_earlier_attributes(tmp_path, attr):
    rc_before = f"typeset -g{attr} {' '.join(OWNED)}"
    s, _, _ = start(tmp_path, rc_before=rc_before, record=minimal_record(left=b"KEPT> "))
    s.run("true")
    s.run("print -r -- TYPES=" + ",".join(f"${{(t){name}}}" for name in OWNED))
    out = visible(s.close())
    assert b"TYPES=" + ",".join(OWNED.values()).encode() in out, out
    assert b"KEPT> " in out and b"bad math" not in out and b"inconsistent" not in out, out


# A hook between the save and install hooks flips one prompt option either
# way; the install hook reads the state right before installing.
# 이것을 실패시키는 것: 값 대입/참조 선택을 뒤집는 것(`(( o_subst ))` → `(( ! o_subst ))`).
@pytest.mark.parametrize("name", ["prompt_subst", "prompt_bang", "prompt_percent"])
@pytest.mark.parametrize("before", [True, False])
def test_middle_hook_flips_an_option(tmp_path, name, before):
    after = not before
    rc_before = opt_lines(**{name: before})
    rc_after = (f"_mid() {{ {'setopt' if after else 'unsetopt'} {name} }}\n"
                "precmd_functions=($precmd_functions[1] _mid $precmd_functions[2,-1])")
    s, _, canaries = start(tmp_path, rc_before, rc_after)
    s.run("true")
    out = visible(s.close())
    assert not any(c.exists() for c in canaries), "data was executed"
    if name == "prompt_percent" and not after:
        assert "❯ ".encode() in out and b"D:$(touch" not in out
    else:
        assert want_left(canaries) in out


# A hook after the install hook sees the status of the user's command.
# Environment assumption pin, not a mutation target: zsh restores $? before
# each precmd function, so the install hook's `return` is not observable here.
# 이것을 실패시키는 것: precmd 함수 사이에 $?를 되살리지 않는 zsh(bingsu 변이로는 죽지 않음).
def test_hook_after_install_sees_command_status(tmp_path):
    rc_after = '_after() { print -u2 -r -- "after=$?" }\nprecmd_functions+=(_after)'
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("false")
    out = visible(s.close())
    assert b"after=1" in out


# A plain precmd() function and bingsu's precmd_functions both run.
# 이것을 실패시키는 것: init이 precmd 함수를 정의하는 것(사용자 함수를 덮음).
def test_coexists_with_a_precmd_function(tmp_path):
    rc_before = "precmd() { print -u2 -r -- USER_PRECMD }"
    s, _, canaries = start(tmp_path, rc_before=rc_before)
    s.run("true")
    out = visible(s.close())
    assert b"USER_PRECMD" in out and want_left(canaries) in out
    assert not any(c.exists() for c in canaries)


# add-zsh-hook after init: the user hook runs, bingsu warns once.
# 이것을 실패시키는 것: 경고 조건을 지우는 것(늘 경고 또는 경고 없음).
def test_coexists_with_add_zsh_hook_after_init(tmp_path):
    rc_after = ("autoload -Uz add-zsh-hook\nuser_hook() { print -u2 -r -- USER_HOOK }\n"
                "add-zsh-hook precmd user_hook")
    s, _, canaries = start(tmp_path, rc_after=rc_after)
    for _ in range(3):
        s.run("true")
    out = visible(s.close())
    assert b"USER_HOOK" in out and want_left(canaries) in out
    assert out.count(b"bingsu: another prompt hook runs after bingsu") == 1
    assert not any(c.exists() for c in canaries)


def fields(left=b"LONG> ", right=b"", tleft=b"T> ", tright=b"", upper=b"", status=b"ok:none",
           vi_left=b"", vi_right=b"", vi_upper=b"", vi_lines=b""):
    return b"\x1f".join([b"B1", b"12", left, right, tleft, tright, b"", b"", upper,
                         vi_left, vi_right, vi_upper, vi_lines, status]) + b"\x1e"


def typed_screen(tmp_path, rc_before="", rc_after="", record=None, inherit=None):
    s, inst, _ = start(tmp_path, rc_before, rc_after, record=record or fields(), inherit=inherit)
    return s, inst, ScreenSession(s, 24, 200)


def line_written(log):
    """`>>` makes the file before it writes. Read the log before Session.kill,
    whose signals include SIGINT: a shell slow to end runs TRAPINT once more."""
    return log.exists() and log.read_text().endswith("\n")


def interrupted(screen, text):
    """Type `text`, wait until it is drawn, then Ctrl-C: a signal outruns typed input."""
    settle(screen)
    screen.session.p.send(text)
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith(text), stable=True), screen.lines()
    screen.session.p.sendcontrol("c")


# A record's transient field, or an option changed by a widget that runs just before ours.
# 이것을 실패시키는 것: 옵션을 설치 hook에서 한 번만 읽어 위젯 대입에 넘기는 것(값 대입 경로에서 데이터가 실행되거나 `%`가 글자로 남음).
@pytest.mark.parametrize("widget_option,want", [("setopt prompt_subst", b"D:$(touch "), ("unsetopt prompt_percent", "❯ ".encode())],
                         ids=["subst-on", "percent-off"])
def test_paint_reads_options_at_each_assignment(tmp_path, widget_option, want):
    canary = short_dir() / "c"
    rc_before = f"_flip() {{ {widget_option} }}\nzle -N zle-line-finish _flip\nsetopt no_prompt_subst"
    tleft = b"%{\x1b[31m%}D:$(touch " + str(canary).encode() + b")%{\x1b[0m%}> "
    s, _, _ = start(tmp_path, rc_before, record=fields(tleft=tleft))
    s.p.sendline("print DONE")
    s.expect(b"\r\nDONE")
    out = visible(s.close())
    assert want in out, out
    assert not canary.exists(), "data was executed"
    assert b"%{" not in out and b"31m" not in out, out


# 이것을 실패시키는 것: 위젯 경로에서 프레임 실패의 상수 대입을 빼는 것(`%~ ❯ `가 글자로 남음).
def test_frame_failure_then_option_off_installs_constant(tmp_path):
    rc_before = "_flip() { unsetopt prompt_percent }\nzle -N zle-line-finish _flip"
    s, _, screen = typed_screen(tmp_path, rc_before, record=b"not a record")
    enter(screen, "print DONE")
    lines = screen.lines()
    s.close()
    assert not any("%~" in line for line in lines), lines
    assert any(line == "❯ print DONE" for line in lines), lines


# 이것을 실패시키는 것: 기존 위젯 호출을 지우는 것, 우리 대입 뒤에 부르는 것, 저장한 위젯을 `-w`로 불러 $WIDGET을 바꾸는 것
# (add-zle-hook-widget은 그 이름으로 자기 목록을 찾는다).
@pytest.mark.parametrize("rc_before", [
    '_mine() { builtin print -r -- "mine $PROMPT" >>"$BINGSU_T_LOG" }\nzle -N zle-line-finish _mine',
    '_mine() { builtin print -r -- "mine $PROMPT" >>"$BINGSU_T_LOG" }\nzle -N _mine\n'
    'autoload -Uz add-zle-hook-widget\nadd-zle-hook-widget line-finish _mine',
], ids=["plain", "add-zle-hook-widget"])
def test_existing_line_finish_runs_first(tmp_path, rc_before):
    log = tmp_path / "widget.log"
    s, _, _ = start(tmp_path, rc_before, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    s.run("true")
    s.close()
    assert "mine LONG> " in log.read_text().splitlines(), log.read_text()


# init 뒤에 위젯을 다시 정의한 사용자: 사용자 쪽이 살고, 다음 프롬프트는 정상이며 오류 출력이 없다.
# 이것을 실패시키는 것: precmd가 위젯을 다시 차지하는 것, 복원 표시 없이는 프롬프트가 짧은 채 남는 것.
def test_widget_redefined_after_init_keeps_user_widget(tmp_path):
    log = tmp_path / "widget.log"
    rc_after = '_later() { builtin print -r -- later >>"$BINGSU_T_LOG" }\nzle -N zle-line-finish _later'
    s, _, screen = typed_screen(tmp_path, rc_after=rc_after, inherit={"BINGSU_T_LOG": str(log)})
    enter(screen, "print DONE")
    lines = screen.lines()
    out = visible(s.close())
    assert lines[screen.cursor()[0]] == "LONG>" and "LONG> print DONE" in lines, lines
    assert "later" in log.read_text() and b"zle:" not in out and b"_bingsu" not in out, out


# 이것을 실패시키는 것: `_bingsu_zle_wrap`의 이미 우리 것 검사를 지우는 것(저장 이름이 우리 함수를 가리켜 무한 재귀).
def test_init_twice_wraps_once(tmp_path):
    log = tmp_path / "widget.log"
    rc_before = '_mine() { builtin print -r -- mine >>"$BINGSU_T_LOG" }\nzle -N zle-line-finish _mine'
    rc_after = f"source {tmp_path / 'init.zsh'}"
    s, _, _ = start(tmp_path, rc_before, rc_after, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    s.run("print -r -- WIDGET=$widgets[zle-line-finish],$widgets[_bingsu_saved_zle-line-finish]")
    out = visible(s.close())
    assert b"WIDGET=user:_bingsu_line_finish,user:_mine" in out, out
    assert b"maximum nested" not in out and b"recursion" not in out, out


# Ctrl-C ends the line, so its new prompt makes the one call a prompt makes
# (precmd_functions run; only a `precmd` function is skipped after an interrupt).
# 이것을 실패시키는 것: transient가 bingsu를 부르는 것(스펙 1313행, 호출 0).
def test_transient_makes_no_bingsu_call(tmp_path):
    s, inst, screen = typed_screen(tmp_path)
    settle(screen)
    before = len(inst.calls())
    interrupted(screen, "abc")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]] == "LONG>", stable=True), screen.lines()
    interrupted(screen, "def")
    assert screen.wait(lambda v: "T> def" in v.lines() and v.lines()[v.cursor()[0]] == "LONG>", stable=True), screen.lines()
    assert len(inst.calls()) == before + 2
    s.close()


# 이것을 실패시키는 것: transient에 일반 왼쪽이나 오른쪽을 대입하는 것.
def test_transient_fields_replace_left_and_right(tmp_path):
    s, _, screen = typed_screen(tmp_path, record=fields(right=b"LONG-RIGHT", tright=b"T-RIGHT"))
    enter(screen, "print DONE")
    lines = screen.lines()
    s.close()
    row = next(i for i, line in enumerate(lines) if line.startswith("T> print DONE"))
    assert lines[row].endswith("T-RIGHT") and "LONG" not in lines[row], lines


# 이것을 실패시키는 것: 빈 transient로 바꿔 지나간 줄의 프롬프트가 사라지는 것.
def test_record_without_transient_keeps_the_prompt(tmp_path):
    s, _, screen = typed_screen(tmp_path, record=fields(tleft=b""))
    enter(screen, "print DONE")
    lines = screen.lines()
    s.close()
    assert "LONG> print DONE" in lines, lines


# 이것을 실패시키는 것: 설치 hook이 Ctrl-C 뒤에 돌지 않아 입력 줄이 짧은 채 남는 것, 윗줄을 빠뜨리는 것.
def test_interrupt_restores_the_full_prompt_on_the_next_line(tmp_path):
    s, _, screen = typed_screen(tmp_path, record=fields(upper=b"UPPER"))
    interrupted(screen, "abc")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]] == "LONG>" and v.lines()[v.cursor()[0] - 1] == "UPPER", stable=True), screen.lines()
    assert "T> abc" in screen.lines(), screen.lines()
    s.close()


LOGGER = 'builtin print -r -- {word} >>"$BINGSU_T_LOG"'


def logger(name):
    return f"{name}() {{ {LOGGER.format(word=name)} }}\nzle -N {name}\n"


def one_enter(tmp_path, rc_before="", rc_after=""):
    """The widgets the line editor ran for one Enter, with the screen after it."""
    log = tmp_path / "widget.log"
    s, _, screen = typed_screen(tmp_path, rc_before, rc_after, inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    log.write_text("")
    enter(screen, "print DONE")
    lines = screen.lines()
    ran = log.read_text().split()
    out = visible(s.close())
    assert b"maximum nested" not in out and b"zle:" not in out, out
    assert "T> print DONE" in lines, lines
    return ran


AZHW = "autoload -Uz add-zle-hook-widget\n"


# 이것을 실패시키는 것: add-zle-hook-widget 목록에 들어가지 않고 저장 복사본을 부르는 것(뒤에 더한 훅이 우리를 거쳐 디스패처로 돌아옴).
def test_hook_widgets_added_around_init_run_once(tmp_path):
    rc_before = AZHW + logger("_first") + "add-zle-hook-widget line-finish _first"
    rc_after = logger("_second") + "add-zle-hook-widget line-finish _second"
    assert one_enter(tmp_path, rc_before, rc_after) == ["_first", "_second"]


PLUGIN = """_plug() {{ {log}; zle _plug_saved -- "$@" }}
zle -A {widget} _plug_saved
zle -N {widget} _plug
"""


# A plugin wrapped us, then init ran again.
# 이것을 실패시키는 것: 다시 init할 때 플러그인의 감싸기를 저장하는 것(자기 자신을 부르고, 사용자의 원래 위젯을 잃음).
def test_plugin_around_bingsu_survives_init_again(tmp_path):
    rc_before = logger("_mine") + "zle -N zle-line-finish _mine"
    rc_after = PLUGIN.format(log=LOGGER.format(word="_plug"), widget="zle-line-finish") + f"source {tmp_path / 'init.zsh'}"
    assert one_enter(tmp_path, rc_before, rc_after) == ["_plug", "_mine"]


# A dispatcher of its own, the shape add-zle-hook-widget has: a later add puts
# our widget on its list while our saved copy is the dispatcher.
# 이것을 실패시키는 것: `_bingsu_nested` 검사를 지우는 것(Enter나 Ctrl-G마다 재귀 오류).
@pytest.mark.parametrize("widget", ["zle-line-finish", "send-break"])
def test_foreign_dispatcher_does_not_recurse(tmp_path, widget):
    log = tmp_path / "widget.log"
    rc_before = (logger("_one") + '_list=(_one)\n_disp() { local w; for w in $_list; do zle $w -- "$@"; done }\n'
                 + (f"zle -N {widget} _disp\n"))
    rc_after = f"zle -A {widget} _ours\n_list+=(_ours)\nzle -N {widget} _disp"
    s, _, screen = typed_screen(tmp_path, rc_before, rc_after, inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    if widget == "zle-line-finish":
        enter(screen, "print DONE")
    else:
        s.p.send("abc")
        assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith("abc"), stable=True), screen.lines()
        s.p.sendcontrol("g")
        assert screen.wait(lambda v: v.lines()[v.cursor()[0]] == "LONG>", stable=True), screen.lines()
    lines = screen.lines()
    ran = log.read_text().split()
    out = visible(s.close())
    assert b"maximum nested" not in out and len(ran) <= 8, (out, len(ran))  # setup Enters, then one dispatch and one re-entry
    assert "T> print DONE" in lines or "T> abc" in lines, lines


# Continuation lines reach the widget with no prompt between them.
# 이것을 실패시키는 것: 위젯이 끝나도 재귀 표시를 지우지 않는 것(둘째 줄의 사용자 위젯이 건너뜀).
def test_user_widget_runs_on_each_continuation_line(tmp_path):
    log = tmp_path / "widget.log"
    s, _, screen = typed_screen(tmp_path, logger("_mine") + "zle -N zle-line-finish _mine", inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    log.write_text("")
    s.p.send('echo "a\r')
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]].startswith("dquote>"), stable=True), screen.lines()
    enter(screen, 'b"')
    ran = log.read_text().split()
    s.close()
    assert ran == ["_mine", "_mine"]


# 이것을 실패시키는 것: 재귀 표시를 프롬프트에서 지우지 않는 것(한 번 끊긴 뒤 위젯이 영영 건너뜀).
def test_abort_inside_a_widget_leaves_the_next_line_working(tmp_path):
    assert one_enter(tmp_path, rc_after="_bingsu_nested=1") == []


TRAP_LOG = LOGGER.format(word="trapped")


# 사용자 TRAPINT의 반환값이 그대로 결정한다: 0이면 줄이 살고, 0이 아니면 끊긴다.
# 이것을 실패시키는 것: 저장한 trap을 부르지 않는 것, 그 반환값을 가리는 것, 사용자 trap이 있는데 128+신호를 돌려주는 것.
@pytest.mark.parametrize("returned,aborts", [(0, False), (130, True), (7, True)], ids=["keeps-line", "interrupt", "other"])
def test_user_trapint_decides(tmp_path, returned, aborts):
    log = tmp_path / "trap.log"
    rc_before = f"TRAPINT() {{ {TRAP_LOG}; return {returned} }}"
    s, _, _ = start(tmp_path, rc_before, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    screen = ScreenSession(s, 24, 200)
    settle(screen)
    s.p.send("print KEPT")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith("print KEPT"), stable=True), screen.lines()
    s.p.sendcontrol("c")
    assert screen.wait(lambda v: line_written(log), timeout=5), screen.lines()
    s.p.send("\r")
    s.run("true")
    out = visible(s.close())
    assert log.read_text() == "trapped\n"
    assert (b"\nKEPT" in out) != aborts, out


# 이것을 실패시키는 것: 진입 상태를 저장하지 않거나 사용자 trap 직전에 되돌리지 않는 것(언제나 0을 받음).
@pytest.mark.parametrize("entry", [42, 0])
def test_user_trapint_sees_the_status_it_would_see(tmp_path, entry):
    log = tmp_path / "trap.log"
    rc_before = 'TRAPINT() { builtin print -r -- "status=$?" >>"$BINGSU_T_LOG"; return 130 }'
    s, _, screen = typed_screen(tmp_path, rc_before, inherit={"BINGSU_T_LOG": str(log)})
    enter(screen, f"(exit {entry})")
    interrupted(screen, "abc")
    assert screen.wait(lambda v: line_written(log), timeout=5), screen.lines()
    assert log.read_text() == f"status={entry}\n"
    s.kill()


# 이것을 실패시키는 것: 문자열 trap을 보지 못해 TRAPINT 함수로 지우는 것(같이 있을 수 없다).
def test_string_int_trap_stays(tmp_path):
    log = tmp_path / "trap.log"
    rc_before = f"trap '{TRAP_LOG}' INT"
    s, _, screen = typed_screen(tmp_path, rc_before, inherit={"BINGSU_T_LOG": str(log)})
    s.run("print -r -- F=${+functions[TRAPINT]}")
    interrupted(screen, "abc")
    assert screen.wait(lambda v: line_written(log), timeout=5), screen.lines()
    out = visible(s.log.getvalue())
    assert b"F=0" in out and log.read_text() == "trapped\n", out
    s.kill()


# 이것을 실패시키는 것: TRAPINT가 0을 돌려주는 것(Ctrl-C가 무시되어 줄이 끊기지 않고 반복문이 멈추지 않음).
def test_interrupt_acts_as_without_a_trap(tmp_path):
    s, _, screen = typed_screen(tmp_path)
    settle(screen)
    s.p.sendline("while true; do :; done; print NOT''REACHED")
    assert screen.wait(lambda v: any("while true" in line for line in v.lines()), stable=True), screen.lines()
    s.p.sendcontrol("c")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]] == "LONG>", timeout=5, stable=True), screen.lines()
    out = visible(s.close())
    assert b"NOTREACHED" not in out, out


# Status after Ctrl-C at an empty prompt: the same with and without bingsu.
# 이것을 실패시키는 것: TRAPINT가 128+신호와 다른 값을 돌려주는 것.
def test_status_after_interrupt_matches_plain_zsh(tmp_path):
    env = trusted_env(tmp_path)
    plain = Session("zsh", env, cols=200)
    plain.p.sendcontrol("c")
    plain.p.sendline('print -r -- "DOLLAR=$?"')
    plain.expect(rb"DOLLAR=(\d+)\r")
    want = plain.p.match.group(1)
    plain.kill()
    (tmp_path / "b").mkdir()
    s, _, screen = typed_screen(tmp_path / "b")
    settle(screen)
    s.p.sendcontrol("c")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]] == "LONG>", stable=True), screen.lines()
    s.p.sendline('print -r -- "DOLLAR=$?"')
    s.expect(rb"DOLLAR=(\d+)\r")
    assert s.p.match.group(1) == want
    s.kill()


# 이것을 실패시키는 것: hook이 상태를 옛 첨자(10)로 읽는 것. 앞쪽 경우는 알림이 사라지고, 뒤쪽 경우는 필드 글자로
# 없는 경고를 낸다.
@pytest.mark.parametrize("status,bait,warned", [
    (b"degraded:sandbox", b"", 1),
    (b"ok:none", b"degraded:sandbox", 0),
], ids=["status-is-last", "old-place-holds-status-text"])
def test_sandbox_warning_reads_last_element(tmp_path, status, bait, warned):
    s, _, _ = start(tmp_path, record=status_bait_record(status, bait))
    s.run("true")
    out = visible(s.close())
    assert out.count(b"could not start its system call filter") == warned


VI = "bindkey -v\nKEYTIMEOUT=1\n"
VI_RECORD = dict(left=b"INS> ", vi_left=b"CMD> ", right=b"RIGHT", vi_right=b"", upper=b"UP", vi_upper=b"", vi_lines=b"lru")


def to_vicmd(screen, want="CMD>"):
    settle(screen)
    screen.session.p.send("\x1b")
    assert screen.wait(lambda v: want in v.lines()[v.cursor()[0]], stable=True), screen.lines()


def to_main(screen, want="INS>"):
    screen.session.p.send("i")
    assert screen.wait(lambda v: want in v.lines()[v.cursor()[0]], stable=True), screen.lines()


# 스펙 1313행: 모드 전환은 bingsu를 부르지 않는다.
# 이것을 실패시키는 것: 위젯이 `_bingsu_call`을 부르는 것, 키 입력마다 그리는 것.
def test_vi_switch_makes_no_bingsu_call(tmp_path):
    s, inst, screen = typed_screen(tmp_path, VI, record=fields(**VI_RECORD))
    settle(screen)
    before = len(inst.calls())
    for _ in range(3):
        to_vicmd(screen)
        to_main(screen)
    s.p.send("abc")
    assert screen.wait(lambda v: "abc" in v.lines()[v.cursor()[0]], stable=True), screen.lines()
    assert len(inst.calls()) == before
    s.p.sendcontrol("c")
    s.kill()


# vi_lines에 있는 줄의 빈 vicmd 필드는 실제로 빈 줄이다.
# 이것을 실패시키는 것: 빈 vicmd 필드를 main 값으로 되돌리는 것, vi_lines를 보지 않는 것, main 복귀를 빼는 것.
def test_vi_mode_clears_a_really_empty_line(tmp_path):
    s, _, screen = typed_screen(tmp_path, VI, record=fields(**VI_RECORD))
    settle(screen)
    row = screen.cursor()[0]
    assert screen.lines()[row - 1] == "UP" and screen.lines()[row].endswith("RIGHT"), screen.lines()
    to_vicmd(screen)
    row = screen.cursor()[0]
    assert screen.lines()[row] == "CMD>" and screen.lines()[row - 1] != "UP", screen.lines()
    to_main(screen)
    row = screen.cursor()[0]
    assert screen.lines()[row - 1] == "UP" and screen.lines()[row].endswith("RIGHT"), screen.lines()
    s.kill()


# 이것을 실패시키는 것: vi_lines에 없는 줄까지 vicmd 필드로 바꾸는 것(l, r, u 각각).
@pytest.mark.parametrize("lines,left,right,upper", [(b"l", "CMD>", "RIGHT", "UP"), (b"r", "INS>", "CMDR", "UP"),
                                                    (b"u", "INS>", "RIGHT", "CMDU"), (b"", "INS>", "RIGHT", "UP")],
                         ids=["left", "right", "upper", "none"])
def test_only_named_lines_change(tmp_path, lines, left, right, upper):
    record = fields(left=b"INS> ", vi_left=b"CMD> ", right=b"RIGHT", vi_right=b"CMDR", upper=b"UP", vi_upper=b"CMDU", vi_lines=lines)
    s, _, screen = typed_screen(tmp_path, VI, record=record)
    settle(screen)
    s.p.send("\x1b")

    def drawn(view):
        row = view.cursor()[0]
        return (view.lines()[row].startswith(left) and view.lines()[row].endswith(right)
                and view.lines()[row - 1] == upper)

    # The same frame shows every line, and the lines named in `lines` differ
    # from the frame before, so a key not handled yet cannot pass. `none` has
    # no such line and waits instead.
    if not lines:
        screen.wait(lambda v: False, timeout=0.3)
    assert screen.wait(drawn, stable=True), screen.lines()
    s.kill()


# 위젯 함수는 어디서든 부를 수 있다: 줄 편집기 밖이면 아무것도 하지 않고 오류도 없다.
# 이것을 실패시키는 것: `zle` 활성 검사를 지우는 것(`widgets can only be called when ZLE is active`).
def test_keymap_select_outside_the_line_editor_is_silent(tmp_path):
    s, _, screen = typed_screen(tmp_path, VI, record=fields(**VI_RECORD))
    enter(screen, 'KEYMAP=vicmd _bingsu_keymap_select; print -r -- "RC=$? MODE=$_bingsu_keymap"')
    out = visible(s.close())
    assert b"RC=0 MODE=main" in out and b"widgets can only" not in out, out


# 이것을 실패시키는 것: 저장한 위젯을 지우는 것, 우리 대입 뒤에 부르는 것, 그 위젯을 `-w`로 부르는 것.
@pytest.mark.parametrize("rc", ['_mine() { builtin print -r -- "mine $PROMPT" >>"$BINGSU_T_LOG" }\nzle -N zle-keymap-select _mine',
                                '_mine() { builtin print -r -- "mine $PROMPT" >>"$BINGSU_T_LOG" }\nzle -N _mine\n'
                                + AZHW + "add-zle-hook-widget keymap-select _mine"], ids=["plain", "add-zle-hook-widget"])
def test_existing_keymap_select_runs_first(tmp_path, rc):
    log = tmp_path / "widget.log"
    s, _, screen = typed_screen(tmp_path, VI + rc, record=fields(**VI_RECORD), inherit={"BINGSU_T_LOG": str(log)})
    to_vicmd(screen)
    s.kill()
    assert "mine UP\nINS> " in log.read_text() and "CMD" not in log.read_text(), log.read_text()


# 이것을 실패시키는 것: vicmd에서 Enter를 친 줄이 긴 프롬프트로 남는 것, 다음 프롬프트가 vicmd로 남는 것.
def test_accept_in_vicmd_shows_transient(tmp_path):
    s, _, screen = typed_screen(tmp_path, VI, record=fields(**VI_RECORD))
    s.p.send("print DONE")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith("RIGHT") or "print DONE" in v.lines()[v.cursor()[0]], stable=True), screen.lines()
    to_vicmd(screen)
    enter(screen, "")
    lines = screen.lines()
    row = screen.cursor()[0]
    s.kill()
    assert "T> print DONE" in lines and lines[row].startswith("INS>") and lines[row - 1] == "UP", lines


# 이것을 실패시키는 것: 설치 hook이 모드를 main으로 되돌리지 않는 것(다음 위젯이 필드를 잘못 고름).
def test_install_hook_puts_the_mode_back(tmp_path):
    log = tmp_path / "widget.log"
    rc_after = '_after() { builtin print -r -- "mode=$_bingsu_keymap" >>"$BINGSU_T_LOG" }\nprecmd_functions+=(_after)'
    s, _, screen = typed_screen(tmp_path, VI, rc_after, record=fields(**VI_RECORD), inherit={"BINGSU_T_LOG": str(log)})
    to_vicmd(screen)
    enter(screen, "")
    s.kill()
    assert log.read_text().splitlines()[-1] == "mode=main", log.read_text()


# 이것을 실패시키는 것: 모드 대입을 emulate 밖에서 하는 것(사용자 ALL_EXPORT로 환경에 나감).
def test_vi_switch_exports_nothing(tmp_path):
    s, _, screen = typed_screen(tmp_path, VI + "setopt all_export", record=fields(**VI_RECORD))
    to_vicmd(screen)
    to_main(screen)
    enter(screen, """print -r -- "EXPORTED=$(env | grep -c '^_bingsu_')" """)
    out = visible(s.close())
    assert b"EXPORTED=0" in out, out


# 사용자의 이전 키맵 값이나 환경은 봉투에 들어가지 않는다: 렌더러가 vicmd를 따로 주고, vicmd를 넘기면 vi_lines가 빈다.
# 이것을 실패시키는 것: hook이 `$KEYMAP`을 넘기는 것.
def test_envelope_keymap_is_always_main(tmp_path):
    s, inst, screen = typed_screen(tmp_path, VI + "KEYMAP=vicmd", record=fields(**VI_RECORD), inherit={"KEYMAP": "vicmd"})
    to_vicmd(screen)
    enter(screen, "")
    calls = inst.calls()
    s.kill()
    assert calls and all(opt(c, b"--keymap") == b"main" for c in calls), calls


def redraws(inst):
    return [c for c in inst.calls() if b"--redraw" in c]


def resize(screen, cols, rows=24):
    """A new width; fake prompts look alike, so the caller waits on its own condition."""
    screen.resize(rows, cols)


def width_of(call):
    return int(opt(call, b"--width"))


def wait_redraws(screen, inst, n):
    assert screen.wait(lambda v: len(redraws(inst)) >= n, stable=True), (redraws(inst), screen.lines())


# 이것을 실패시키는 것: 저장한 봉투를 넘기지 않는 것, `--redraw` 없이 일반 호출을 하는 것, 새 폭을 넘기지 않는 것.
def test_resize_redraws_at_new_width(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    enter(screen, "(exit 3)")
    resize(screen, 120)
    wait_redraws(screen, inst, 1)
    call, normal = redraws(inst)[0], inst.calls()[-2]
    assert width_of(call) == 120, call
    for word in (b"--status", b"--pipestatus", b"--jobs", b"--keymap"):
        assert opt(call, word) == opt(normal, word), (word, call, normal)
    assert opt(call, b"--status") == b"3"
    resize(screen, 130)
    wait_redraws(screen, inst, 2)
    s.kill()


# 이것을 실패시키는 것: 폭 비교를 지우는 것.
def test_same_width_makes_no_call(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    s.p.setwinsize(30, 200)  # taller, same width
    s.run("true")
    assert not redraws(inst), inst.calls()
    s.kill()


# 신호를 합친 결과는 시간이 아니라 호출 수로 판정한다(스펙 581행).
# 이것을 실패시키는 것: 끝난 뒤 폭을 다시 보지 않는 것(마지막 폭이 그려지지 않음).
def test_winch_burst_ends_at_final_width(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    widths = [150, 151, 152, 153, 154, 155]
    for width in widths:
        s.p.setwinsize(24, width)
    assert screen.wait(lambda v: redraws(inst) and width_of(redraws(inst)[-1]) == widths[-1], stable=True), redraws(inst)
    drawn = [width_of(c) for c in redraws(inst)]
    assert len(drawn) <= len(widths) and len(set(drawn)) == len(drawn), drawn
    s.kill()


def slow_redraw(tmp_path, inst, seconds):
    slow = tmp_path / "slow.sh"
    fake = (ROOT / "tests/shell/fake_bingsu.sh").read_text()
    slow.write_text(fake.replace("here=", f'case " $* " in *" --redraw "*) sleep {seconds} ;; esac\nhere=', 1))
    slow.chmod(0o755)
    (inst.dir / "bingsu").unlink()
    (inst.dir / "bingsu").symlink_to(slow)


def changing_width(s, turns):
    done = threading.Event()

    def change():
        for turn in range(turns):
            s.p.setwinsize(24, 150 + turn)
            if done.wait(0.02):
                return

    driver = threading.Thread(target=change)
    driver.start()
    return done, driver


# 계속 바뀌는 폭이 키 입력을 막지 않는다: 호출 수로 판정한다(지연은 그 수와 호출 시간의 곱이다).
# 이것을 실패시키는 것: 기다리는 키를 먼저 보내지 않는 것.
def test_width_that_keeps_changing_does_not_hold_input(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    slow_redraw(tmp_path, inst, 0.04)
    done, driver = changing_width(s, 100)
    assert screen.wait(lambda v: redraws(inst), timeout=5), inst.calls()
    s.p.send("Q")
    shown = screen.wait(lambda v: "Q" in v.lines()[v.cursor()[0]], timeout=5)
    calls = len(redraws(inst))
    done.set()
    driver.join()
    s.kill()
    assert shown and calls <= 4, (calls, screen.lines())


def scripted_redraw(tmp_path, inst, step):
    """A stand-in that runs shell `step` on each redraw, with $n the count so far."""
    script = tmp_path / "scripted.sh"
    fake = (ROOT / "tests/shell/fake_bingsu.sh").read_text()
    script.write_text(fake.replace("here=", f'case " $* " in *" --redraw "*) echo x >>"${{0%/*}}/steps"; '
                                            f'n=$(wc -l <"${{0%/*}}/steps"); {step} ;; esac\nhere=', 1))
    script.chmod(0o755)
    (inst.dir / "bingsu").unlink()
    (inst.dir / "bingsu").symlink_to(script)


# 첫 호출 중에 폭이 바뀌고 키가 도착하면 그 호출로 멈추고, 폭이 틀어진 채 키를 먼저 처리한다.
# 다음 신호는 남은 폭을 그리고, 그 뒤 높이만 바뀌면 호출이 없다.
# 이것을 실패시키는 것: 다시 부르기 전에 기다리는 키를 보지 않는 것, 폭이 같아도 부르는 것.
def test_redraw_yields_to_a_key_and_skips_the_same_width(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    go = tmp_path / "go"
    started = inst.dir / "steps"
    scripted_redraw(tmp_path, inst, f'[ "$n" -gt 1 ] || {{ stty cols 151 </dev/tty; '
                                    f'until [ -e "{go}" ]; do sleep 0.01; done; }}')
    s.p.setwinsize(24, 149)
    assert screen.wait(lambda v: started.exists(), timeout=5), inst.calls()
    s.p.send("Q")
    go.touch()
    assert screen.wait(lambda v: "Q" in v.lines()[v.cursor()[0]], timeout=5, stable=True), screen.lines()
    assert [width_of(c) for c in redraws(inst)] == [149], redraws(inst)
    s.p.setwinsize(25, 151)
    wait_redraws(screen, inst, 2)
    assert width_of(redraws(inst)[-1]) == 151, redraws(inst)
    s.p.setwinsize(26, 151)
    screen.wait(lambda v: False, timeout=0.3)
    assert len(redraws(inst)) == 2, redraws(inst)
    s.kill()


# 호출 중에 온 크기 변경은 신호로 다시 오지 않는다: `$(…)`를 기다리는 동안 zsh가 COLUMNS만 바꾸고 trap은 돌리지 않는다.
# 폭이 멈추면 반복도 끝난다.
# 이것을 실패시키는 것: 호출 뒤 폭을 다시 보지 않는 것, 호출 수에 상한을 두는 것, 폭이 같아도 반복하는 것.
def test_width_changed_during_a_call_is_drawn(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    scripted_redraw(tmp_path, inst, '[ "$n" -ge 9 ] || stty cols $((150 + n)) </dev/tty')
    s.p.setwinsize(24, 149)
    want = [149, *range(151, 159)]
    assert screen.wait(lambda v: [width_of(c) for c in redraws(inst)] == want, timeout=5, stable=True), redraws(inst)
    screen.wait(lambda v: False, timeout=0.3)
    assert [width_of(c) for c in redraws(inst)] == want, redraws(inst)
    s.kill()


# 이것을 실패시키는 것: `zle` 활성 판정을 지우는 것(명령 실행 중에 redraw가 돈다).
def test_winch_while_command_runs_calls_nothing(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    s.p.sendline("print STARTED; read -t 2 x; print ENDED")
    assert screen.wait(lambda v: "STARTED" in v.lines(), stable=False), screen.lines()
    s.p.setwinsize(24, 120)
    s.p.kill(28)  # the shell itself: a size change reaches only the foreground group
    assert screen.wait(lambda v: "ENDED" in v.lines() and v.lines()[v.cursor()[0]].startswith("LONG>"), timeout=8, stable=True), screen.lines()
    assert not redraws(inst), redraws(inst)
    assert width_of(inst.calls()[-1]) == 120, inst.calls()[-1]
    s.kill()


# 사용자 함수는 먼저 돌고 진입 상태를 받으며, 그 반환값이 그대로 나간다.
# 이것을 실패시키는 것: 저장 trap을 부르지 않는 것, redraw 뒤에 부르는 것, `$?`를 복원하지 않는 것, 반환값을 가리는 것.
@pytest.mark.parametrize("returned", [0, 130])
def test_existing_trapwinch_function_runs_first(tmp_path, returned):
    log = tmp_path / "trap.log"
    rc = f'TRAPWINCH() {{ builtin print -r -- "user status=$?" >>"$BINGSU_T_LOG"; return {returned} }}'
    s, inst, screen = typed_screen(tmp_path, rc, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    enter(screen, "(exit 42)")
    s.p.send("print KEPT")
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]].endswith("print KEPT"), stable=True), screen.lines()
    resize(screen, 120)
    wait_redraws(screen, inst, 1)
    assert screen.wait(lambda v: line_written(log), timeout=5), screen.lines()
    s.p.send("\r")
    s.run("true")
    out = visible(s.close())
    assert log.read_text() == "user status=42\n"
    assert (b"\nKEPT" in out) == (returned == 0), out


# Environment pin, not a mutation target: zsh does not run a trap inside itself,
# so no reentry flag is needed. If a zsh changes this the depth log fills.
def test_winch_during_a_redraw_does_not_nest(tmp_path):
    log = tmp_path / "depth.log"
    rc_after = ('functions[_t_step]=$functions[_bingsu_redraw_step]\n'
                '_bingsu_redraw_step() { local r; (( ++_depth > 1 )) && builtin print -r -- nested >>"$BINGSU_T_LOG"; '
                '_t_step; r=$?; (( _depth-- )); return r }\n_depth=0')
    s, inst, screen = typed_screen(tmp_path, rc_after=rc_after, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    slow_redraw(tmp_path, inst, 0.4)
    s.p.setwinsize(24, 150)
    screen.wait(lambda v: False, timeout=0.15)  # inside the sleep
    s.p.setwinsize(24, 151)
    assert screen.wait(lambda v: redraws(inst) and width_of(redraws(inst)[-1]) == 151, stable=True), redraws(inst)
    s.kill()
    assert not log.exists(), log.read_text()


# 사용자 trap 안의 err_exit는 그대로 듣는다. 이것을 실패시키는 것: 저장 trap을 조건으로 부르는 것(`if`, `||`).
@pytest.mark.parametrize("signal,name", [(28, "TRAPWINCH"), (2, "TRAPINT")])
def test_err_exit_inside_a_user_trap_still_works(tmp_path, signal, name):
    log = tmp_path / "trap.log"
    rc = f'{name}() {{ setopt localoptions err_exit; false; builtin print -r -- BAD >>"$BINGSU_T_LOG"; return 0 }}'
    s, inst, screen = typed_screen(tmp_path, rc, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    s.p.kill(signal)
    s.expect(pexpect.EOF)
    assert not log.exists(), log.read_text()
    s.kill()


# 사용자 trap이 0이 아닌 값을 돌려줘도 우리 쪽 일은 끝난다.
# 이것을 실패시키는 것: `always` 없이 부르는 것(ERR_RETURN이 함수를 끝내 redraw·transient가 빠진다).
def test_err_return_keeps_redraw_after_a_user_trap(tmp_path):
    rc = "TRAPWINCH() { return 130 }\nsetopt err_return"
    s, inst, screen = typed_screen(tmp_path, rc, record=fields())
    settle(screen)
    resize(screen, 120)
    wait_redraws(screen, inst, 1)
    s.kill()


def test_err_return_keeps_transient_after_a_user_trap(tmp_path):
    rc = "TRAPINT() { return 130 }\nsetopt err_return"
    s, inst, screen = typed_screen(tmp_path, rc, record=fields())
    interrupted(screen, "typed")
    assert screen.wait(lambda v: "T> typed" in v.lines(), stable=True), screen.lines()
    s.kill()


TRAP_PIPE = 'builtin print -r -- "user $?:${(j:,:)pipestatus}" >>"$BINGSU_T_LOG"; return 0'


# 사용자 trap은 저장 없이 원래 파이프 상태를 본다. 이것을 실패시키는 것: 저장 trap보다 앞에 명령을 두는 것.
@pytest.mark.parametrize("signal,name", [(28, "TRAPWINCH"), (2, "TRAPINT")])
def test_user_trap_sees_pipestatus(tmp_path, signal, name):
    log = tmp_path / "trap.log"
    rc = f"{name}() {{ {TRAP_PIPE} }}"
    s, inst, screen = typed_screen(tmp_path, rc, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    s.p.sendline("print STARTED; (sleep 0.4; exit 3) | (sleep 0.4; exit 7); print -r -- after=$?")
    assert screen.wait(lambda v: "STARTED" in v.lines(), stable=False), screen.lines()
    s.p.kill(signal)  # the shell itself, so the pipeline still ends with its own codes
    assert screen.wait(lambda v: line_written(log) and "after=7" in v.lines(), timeout=5), screen.lines()
    assert log.read_text() == "user 7:3,7\n"
    s.kill()


# 플러그인이 우리 trap을 감싼 뒤 init을 다시 해도 체인은 그대로다.
# 이것을 실패시키는 것: init마다 trap을 저장 이름으로 옮기는 것(플러그인과 우리가 서로를 부른다).
@pytest.mark.parametrize("name", ["TRAPWINCH", "TRAPINT"])
def test_plugin_wrapped_trap_survives_a_second_init(tmp_path, name):
    log = tmp_path / "trap.log"
    rc_after = (f'functions -c {name} _plugin_old\n'
                f'{name}() {{ builtin print -r -- plugin >>"$BINGSU_T_LOG"; _plugin_old "$@" }}\n'
                f"source {tmp_path / 'init.zsh'}")
    s, inst, screen = typed_screen(tmp_path, rc_after=rc_after, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    settle(screen)
    if name == "TRAPWINCH":
        resize(screen, 120)
        wait_redraws(screen, inst, 1)
    else:
        interrupted(screen, "typed")
    assert screen.wait(lambda v: line_written(log), timeout=5), screen.lines()
    s.run("true", timeout=8)  # zle drops what was typed ahead of a Ctrl-C
    out = visible(s.close())
    assert b"maximum nested" not in out and log.read_text() == "plugin\n", (out, log.read_text())


# 이것을 실패시키는 것: 문자열 trap을 보지 못해 TRAPWINCH 함수로 지우는 것.
def test_string_winch_trap_stays(tmp_path):
    log = tmp_path / "trap.log"
    rc = "trap 'builtin print -r -- trapped >>\"$BINGSU_T_LOG\"' WINCH"
    s, inst, screen = typed_screen(tmp_path, rc, record=fields(), inherit={"BINGSU_T_LOG": str(log)})
    s.run("print -r -- F=${+functions[TRAPWINCH]}")
    settle(screen)
    resize(screen, 120)
    assert screen.wait(lambda v: line_written(log), timeout=5), screen.lines()
    s.run("true")
    assert not redraws(inst) and width_of(inst.calls()[-1]) == 120, inst.calls()
    out = visible(s.close())
    assert b"F=0" in out, out


# 이것을 실패시키는 것: precmd가 trap을 다시 차지하는 것, 오류를 내는 것.
def test_trapwinch_redefined_after_init_falls_back_to_next_prompt(tmp_path):
    s, inst, screen = typed_screen(tmp_path, rc_after="TRAPWINCH() { : }", record=fields())
    settle(screen)
    resize(screen, 120)
    enter(screen, "true")
    assert not redraws(inst) and width_of(inst.calls()[-1]) == 120, inst.calls()
    out = visible(s.close())
    assert b"TRAPWINCH" not in out, out


# 이것을 실패시키는 것: init을 다시 해도 우리 trap을 저장 이름으로 옮기는 것(자기 자신을 부름).
def test_init_twice_installs_trapwinch_once(tmp_path):
    rc_after = f"source {tmp_path / 'init.zsh'}"
    s, inst, screen = typed_screen(tmp_path, rc_after=rc_after, record=fields())
    settle(screen)
    resize(screen, 120)
    wait_redraws(screen, inst, 1)
    out = visible(s.close())
    assert len(redraws(inst)) == 1 and b"maximum nested" not in out, out


# 이것을 실패시키는 것: 레코드가 깨졌을 때 지금 필드를 지우는 것(프롬프트가 상수로 떨어짐).
def test_failed_redraw_keeps_the_fields(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    (inst.dir / "record.bin").write_bytes(b"not a record")
    resize(screen, 120)
    wait_redraws(screen, inst, 1)
    s.run('print -r -- "KEPT=$_bingsu_f[3]"')
    assert b"KEPT=LONG> " in visible(s.close())


# 이것을 실패시키는 것: 계속되는 줄에서 다시 그리는 것(PS2가 `dquote then>`으로 바뀜).
def test_winch_on_a_continuation_line_leaves_it_alone(tmp_path):
    s, inst, screen = typed_screen(tmp_path, record=fields())
    settle(screen)
    s.p.send('echo "a\r')
    assert screen.wait(lambda v: v.lines()[v.cursor()[0]].startswith("dquote>"), stable=True), screen.lines()
    resize(screen, 120)
    enter(screen, 'b"')
    lines = screen.lines()
    s.close()
    assert not redraws(inst) and not any("then" in line for line in lines), lines


# 스펙 3절: 저장한 봉투가 없으면 다시 그리지 않는다.
# 이것을 실패시키는 것: 빈 봉투로 부르는 것(종료 코드 없는 redraw), 그 판정을 사용자 옵션 아래에서 하는 것.
@pytest.mark.parametrize("options", ["", "setopt no_unset ksh_arrays"])
def test_no_saved_words_no_redraw(tmp_path, options):
    rc_after = f"_drop() {{ _bingsu_ctx=() }}\nprecmd_functions+=(_drop)\n{options}"
    s, inst, screen = typed_screen(tmp_path, rc_after=rc_after, record=fields())
    settle(screen)
    resize(screen, 120)
    enter(screen, "true")
    assert not redraws(inst), redraws(inst)
    assert b"parameter not set" not in visible(s.close())


# 이것을 실패시키는 것: redraw가 vicmd 모드를 잊는 것.
def test_vi_symbol_kept_after_redraw(tmp_path):
    s, inst, screen = typed_screen(tmp_path, VI, record=fields(**VI_RECORD))
    to_vicmd(screen)
    resize(screen, 120)
    wait_redraws(screen, inst, 1)
    assert screen.wait(lambda v: "CMD>" in v.lines()[v.cursor()[0]], stable=True), screen.lines()
    to_main(screen)
    s.kill()
