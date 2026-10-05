"""zsh security state machine (spec section 3 option table, section 5 two
hooks, section 7 security table rows for zsh). Runs on zsh 5.8 (container)
and the current zsh."""
import itertools
import os

import pytest

from conftest import Install, minimal_record, run_shell_script, short_dir, trusted_env
from pty_session import Session, visible

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")


def hostile_record(c1, c2, c3):
    """What a correct core emits for zsh: data % doubled, SGR in %{ %}."""
    left = (b"%{\x1b[31m%}D:$(touch " + c1 + b");`touch " + c2 + b"`;${HOME};$[1+1];%%F{red};!;\\u%{\x1b[0m%}> ")
    right = b"R:$(touch " + c3 + b")%%"
    return b"B1\x1f7\x1f" + left + b"\x1f" + right + b"\x1f\x1f\x1f\x1f\x1fok:none\x1e"


def start(tmp_path, rc_before="", rc_after="", record=None, inherit=None):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    (tmp_path / "init.zsh").write_bytes(inst.init("zsh", env))
    env.update(inherit or {})
    cdir = short_dir()
    canaries = [cdir / f"c{i}" for i in (1, 2, 3)]
    inst.use_fake(record or hostile_record(*[str(c).encode() for c in canaries]))
    (tmp_path / "rc.zsh").write_text(f"{rc_before}\nsource {tmp_path / 'init.zsh'}\n{rc_after}\n")
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
def test_exit_status_reaches_next_hook_and_is_returned(tmp_path):
    rc_after = ("_probe() { print -r -- \"PROBE:$?\" }\n"
                "precmd_functions=($precmd_functions[1] _probe $precmd_functions[2,-1])")
    s, _, _ = start(tmp_path, rc_after=rc_after, record=minimal_record())
    s.run("false")
    s.run("true")
    out = visible(s.close())
    assert b"PROBE:1" in out and b"PROBE:0" in out


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


# 이것을 실패시키는 것: 머리의 `typeset -g … _bingsu_warned_last=`에서 초기화를 빼는 것(경고가 사라짐).
def test_inherited_warned_flag_is_reset(tmp_path):
    s, _, _ = start(tmp_path, rc_after="_late() { : }\nprecmd_functions+=(_late)",
                    record=minimal_record(), inherit={"_bingsu_warned_last": "1"})
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
    s.run("sleep 0.3")
    s.close()
    ms = [int(opt(c, b"--duration-ms")) for c in inst.calls() if opt(c, b"--duration-ms")]
    assert ms and max(ms) < 450, ms   # sleep 0.3 is the longest command
    assert any(m >= 250 for m in ms), ms


# Inherited exported names stay in the shell but leave the environment.
# 이것을 실패시키는 것: 머리의 `typeset -g +x …` 줄을 지우는 것.
def test_owned_globals_are_not_exported(tmp_path):
    inherit = {n: "1" for n in ("_bingsu_rec", "_bingsu_s", "_bingsu_p", "_bingsu_t0", "_bingsu_t1",
                                "_bingsu_ps1", "_bingsu_rps1", "_bingsu_warned_last", "_bingsu_seq")}
    inherit["_bingsu_session"] = "0123456789abcdef0123456789abcdef"
    s, _, _ = start(tmp_path, record=minimal_record(), inherit=inherit)
    s.run('print -r -- "EXPORTED=$(env | grep -c \'^_bingsu_\')"')
    out = visible(s.close())
    assert b"EXPORTED=0" in out, out


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
