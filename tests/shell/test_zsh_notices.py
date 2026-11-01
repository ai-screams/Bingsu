"""zsh status notices (spec section 5, key rules and receive table): the hook
prints one fixed line per key change, on stderr, whatever the prompt shows.
The key table rows are spec section 5 "시험", in a real interactive shell."""
import os
import shutil
import subprocess

import pytest

from conftest import ROOT, Install, minimal_record, run_shell_script, short_dir, trusted_env
from pty_session import Session
from screen_session import ScreenSession
from test_runtime_root_gate import wait_refresh_helpers
from test_zsh_screen import enter

pytestmark = pytest.mark.skipif("zsh" not in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split(),
                                reason="zsh not under test")

FAKE = ROOT / "tests/shell/fake_bingsu_status.sh"
GENERIC = "bingsu: a status notice is waiting. Run: bingsu config check"
NO_RECORD = "bingsu: the prompt gave no usable answer, so a minimal prompt is drawn. Open a new shell or evaluate your bingsu init line again"
RUNTIME_ROOT = "bingsu: the runtime folder changed, so the prompt runs without saved state. Open a new shell or evaluate your bingsu init line again"
SANDBOX = "bingsu: the prompt could not start its system call filter, so it draws a minimal prompt. Check that your system permits seccomp filters, then open a new shell"
EXPIRED = "bingsu: settings verification is out of date; configured commands are paused. Run: bingsu reload"
TRUST_INVALID = "bingsu: settings verification failed; configured commands are paused. Run: bingsu config check, then bingsu reload"
# Status::KNOWN_NON_OK, each with its own text.
KNOWN = {
    "error:bad-args": "bingsu: the shell hook and the bingsu program do not match, so a minimal prompt is drawn. Open a new shell or evaluate your bingsu init line again",
    "error:internal": "bingsu: the prompt hit an internal error, so a minimal prompt is drawn. Open a new shell",
    "degraded:runtime-root": RUNTIME_ROOT,
    "degraded:oversize": "bingsu: the prompt grew too large, so a minimal prompt is drawn. Use a shorter layout",
    "degraded:trust-unverified": "bingsu: settings are not verified yet; configured commands are paused. Run: bingsu reload",
    "degraded:trust-expired": EXPIRED,
    "degraded:trust-invalid": TRUST_INVALID,
    "degraded:trust-mismatch": "bingsu: saved settings and their verification do not match; configured commands are paused. Run: bingsu config check, then bingsu reload",
    "degraded:trust-clock": "bingsu: settings verification time could not be confirmed; configured commands are paused. Run: bingsu reload",
    "degraded:sandbox": SANDBOX,
    "error:config-last-good": "bingsu: your settings are not valid, so the prompt keeps the last good settings. Run: bingsu config check",
    "error:config-default": "bingsu: your settings are not valid, so the prompt uses the built-in look. Run: bingsu config check",
}


def start(tmp_path, statuses, rows=30, cols=200, inherit=None, rc_before=""):
    """A shell whose install hook sends its stderr to a file: the shell's own
    stderr also carries the line editor, and the file holds only the hook's
    bytes. The wrapper keeps the hook's name and place in precmd_functions."""
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / "init.zsh"
    init.write_bytes(inst.init("zsh", env))
    env.update(inherit or {})
    inst.use_fake(minimal_record(), script=FAKE)
    (inst.dir / "statuses.txt").write_text("".join(f"{s}\n" for s in statuses))
    err = tmp_path / "hook.err"
    wrap = f'{rc_before}\nsource "{init}"\nfunctions[_t_install]=$functions[_bingsu_install]\n_bingsu_install() {{ _t_install 2>>"{err}"; }}\n'
    (tmp_path / "rc.zsh").write_text(wrap)
    s = Session("zsh", env, cols=cols, rows=rows)
    return s, inst, err


def run_prompts(tmp_path, statuses, **kwargs):
    """Draw at least one prompt per status; further prompts repeat the last one."""
    s, inst, err = start(tmp_path, statuses, **kwargs)
    s.run(f'source "{tmp_path / "rc.zsh"}"')
    while len(inst.calls()) < len(statuses):
        s.run("true")
    s.close()
    return err.read_bytes() if err.exists() else b""


def lines(*messages):
    return "".join(f"{m}\n" for m in messages).encode()


A, B, X, Y = "degraded:runtime-root", "degraded:trust-expired", "degraded:zz-one", "degraded:zz-two"


# 이것을 실패시키는 것: `_bingsu_key_prev` 대입을 지우는 것(알림 반복), no-record 분기를 지우는 것,
# 열쇠 대신 등급만 비교하는 것, `ok`에서 열쇠를 비우지 않는 것, ok를 알리는 것.
@pytest.mark.parametrize("statuses,want", [
    pytest.param(["ok:none", "ok:none"], [], id="ok-silent"),
    pytest.param(["ok:future-code", "ok:none"], [], id="ok-any-code-silent"),
    pytest.param(["ok:none", A], [RUNTIME_ROOT], id="ok-to-a"),
    pytest.param([A, A, A], [RUNTIME_ROOT], id="a-a"),
    pytest.param(["notice:zz-one", "degraded:zz-one", "error:zz-one"], [GENERIC, GENERIC, GENERIC], id="class-only"),
    pytest.param([B, "degraded:trust-invalid"], [EXPIRED, TRUST_INVALID], id="code-only"),
    pytest.param([A, "ok:none", A], [RUNTIME_ROOT, RUNTIME_ROOT], id="a-ok-a"),
    pytest.param(["degraded:sandbox", "ok:none", "degraded:sandbox"], [SANDBOX, SANDBOX], id="sandbox-comes-back"),
    pytest.param([X, X], [GENERIC], id="unknown-x-x"),
    pytest.param([X, Y], [GENERIC, GENERIC], id="unknown-x-y"),
    pytest.param(["weird:zz-one", "weird:zz-one"], [GENERIC], id="unknown-class"),
    pytest.param(["weird:zz-one", "strange:zz-one"], [GENERIC, GENERIC], id="unknown-class-changes"),
    pytest.param(["no-record", "no-record"], [NO_RECORD], id="no-record"),
    pytest.param(["no-record", "ok:none", "no-record"], [NO_RECORD, NO_RECORD], id="no-record-comes-back"),
    pytest.param(["no-record", A, "no-record"], [NO_RECORD, RUNTIME_ROOT, NO_RECORD], id="no-record-and-a"),
])
def test_notice_key_table(tmp_path, statuses, want):
    assert run_prompts(tmp_path, statuses) == lines(*want)


# 이것을 실패시키는 것: 문구 사슬에서 코드 하나가 빠지거나 다른 코드의 문구를 고르는 것.
@pytest.mark.parametrize("status", KNOWN)
def test_known_code_prints_its_own_line(tmp_path, status):
    assert run_prompts(tmp_path, [status, status]) == lines(KNOWN[status])


# 이것을 실패시키는 것: 열쇠 변수를 init에서 지우지 않는 것(다시 init한 뒤 알리지 않거나, 물려받은 값이 첫 알림을 삼킴).
@pytest.mark.parametrize("inherited", [False, True], ids=["reinit", "inherited-key"])
def test_key_starts_empty_on_every_init(tmp_path, inherited):
    if inherited:
        assert run_prompts(tmp_path, [A], inherit={"_bingsu_key_prev": A}) == lines(RUNTIME_ROOT)
        return
    s, inst, err = start(tmp_path, [A])
    rc = tmp_path / "rc.zsh"
    s.run(f'source "{rc}"')
    s.run("true")
    s.run(f'source "{rc}"')
    s.run("true")
    s.close()
    assert err.read_bytes() == lines(RUNTIME_ROOT, RUNTIME_ROOT)


# A status must not reach arithmetic, whatever this shell declared before init.
# 이것을 실패시키는 것: 머리의 unset에서 열쇠 변수를 빼는 것(`bad math expression`, no-record가 0으로 저장되어 매번 알림).
@pytest.mark.parametrize("name", ["_bingsu_key_prev", "_bingsu_key", "_bingsu_note", "_bingsu_disp"])
def test_earlier_integer_attribute_keeps_the_key_a_string(tmp_path, name):
    got = run_prompts(tmp_path, [A, "no-record", "no-record", A], rc_before=f"typeset -gix {name}=0")
    assert got == lines(RUNTIME_ROOT, NO_RECORD, RUNTIME_ROOT)


# 이것을 실패시키는 것: 대화형 검사나 부분 셸 검사를 지우는 것(캡처에 문구가 들어가고 부모 열쇠는 그대로).
@pytest.mark.parametrize("call", ['x=$(_bingsu_install 2>"{err}")', '(_bingsu_install 2>"{err}")'],
                         ids=["substitution", "subshell"])
def test_subshell_of_the_shell_prints_no_notice(tmp_path, call):
    err = tmp_path / "captured"
    s, _, _ = start(tmp_path, [A])
    s.run(f'source "{tmp_path / "init.zsh"}"')
    s.run("_bingsu_key_prev=; " + call.format(err=err))
    s.close()
    assert err.read_bytes() == b""


def test_noninteractive_shell_prints_no_notice(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("zsh", env)
    inst.use_fake(minimal_record(status=A.encode()))
    r = run_shell_script("zsh", script + b"\n_bingsu_save; _bingsu_install\n", env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"" and inst.calls(), r


# 이것을 실패시키는 것: 열쇠 변수를 자식 프로세스 환경에 남기는 것.
def test_key_does_not_reach_children(tmp_path):
    s, _, _ = start(tmp_path, [A], inherit={"_bingsu_key_prev": A})
    s.run(f'source "{tmp_path / "rc.zsh"}"')
    s.run("""print -r -- "EXPORTED=$(env | grep -c '^_bingsu_key_prev')" """)
    assert b"EXPORTED=0" in s.close()


# 이것을 실패시키는 것: 알림이 프롬프트 내용이나 그 뒤에 나와 입력 줄을 밀어내는 것, 맨 아래 줄에서 프롬프트가 알림과 겹치는 것.
def test_notice_output_at_bottom_row_keeps_prompt_position(tmp_path):
    rows, cols = 8, 80
    s, inst, _ = start(tmp_path, ["ok:none"], rows=rows, cols=cols)
    s.run(f'source "{tmp_path / "init.zsh"}"')
    screen = ScreenSession(s, rows, cols)
    while screen.cursor()[0] < rows - 1:
        enter(screen, "print filler")
    (inst.dir / "statuses.txt").write_text("ok:none\n" * len(inst.calls()) + f"{A}\n")
    enter(screen, "true")
    text = screen.lines()
    assert screen.cursor() == (rows - 1, 2) and text[rows - 1] == ">", text
    assert "".join(line.ljust(cols) for line in text[rows - 3:rows - 1]).rstrip() == RUNTIME_ROOT, text
    assert text[rows - 4] == "> true", text


# Spec section 5 test list: a value outside the grammar is refused before it is
# split, so it means no record and only the fixed line comes out.
# 이것을 실패시키는 것: 문법 검사를 건너뛰고 나누는 것, 문구에 상태 문자열을 넣는 것, eval이나 첨자로 쓰는 것.
@pytest.mark.parametrize("template", ["degraded", "degraded:", ":x", "Degraded:x", "degraded:X", "degraded:$(touch {c})",
                                      "degraded:`touch {c}`", "degraded:x;touch {c}", "degraded:x y"])
def test_status_string_never_reaches_output(tmp_path, template):
    canary = short_dir() / "c"
    status = template.format(c=canary)
    assert run_prompts(tmp_path, [status, status]) == lines(NO_RECORD)
    assert not canary.exists()


# 이것을 실패시키는 것: 모르는 코드를 문구에 끼워 넣는 것.
def test_unknown_code_text_stays_out_of_the_notice(tmp_path):
    out = run_prompts(tmp_path, ["degraded:zz-secret"])
    assert out == lines(GENERIC) and b"zz-secret" not in out


# No status can hold a pattern character, so the table above cannot see this.
# 이것을 실패시키는 것: `_bingsu_notice_due`를 패턴 비교로 만드는 것(`$~1`, 스펙 5절 구현 모양).
def test_notice_due_compares_exactly(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("zsh", env) + b"\n_bingsu_notice_due 'degraded:*' degraded:x && print due\n"
    assert run_shell_script("zsh", script, env, tmp_path).stdout == b"due\n"


def interactive_script(script, env, tmp_path):
    (tmp_path / "script.zsh").write_bytes(script)
    return subprocess.run(["zsh", "-f", "-i", str(tmp_path / "script.zsh")], env=env, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=60)


LOOP = b"\nfor attempt in 1 2 3; do\n  _bingsu_save\n  _bingsu_install\n  print -r -- \"$_bingsu_f[-1]\"\ndone\n"


# GATE-RUNTIME-ROOT.5: the real binary, with the runtime folder deleted and recreated.
# 이것을 실패시키는 것: 고정 문구를 프롬프트마다 내는 것, 내지 않는 것, 다시 init한 뒤에도 문구가 이어지는 것.
def test_runtime_root_notice_once_then_reinit_recovers(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    old = inst.init("zsh", env)
    baseline = run_shell_script("zsh", old + LOOP, env, tmp_path)
    assert baseline.returncode == 0 and b"degraded:runtime-root" not in baseline.stdout, baseline
    wait_refresh_helpers(tmp_path)
    root = tmp_path / "run-t/bingsu"
    fd = os.open(root, os.O_RDONLY)
    try:
        shutil.rmtree(root)
        root.mkdir(mode=0o700)
        result = interactive_script(old + LOOP + inst.init("zsh", env) + LOOP, env, tmp_path)
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines()[:3] == [b"degraded:runtime-root"] * 3, result.stdout
        assert b"degraded:runtime-root" not in b"\n".join(result.stdout.splitlines()[3:]), result.stdout
        assert result.stderr == lines(RUNTIME_ROOT), result.stderr
    finally:
        os.close(fd)
