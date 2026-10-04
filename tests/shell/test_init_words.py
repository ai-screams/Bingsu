"""Runtime root and fixed-path words arrive at the binary as single words
(spec section 9 M1 row, change (1)); init twice redefines the call with the
new runtime root (F-23 golden)."""
import importlib.util
import os
import shlex

import pytest

from conftest import ROOT, Install, minimal_record, run_shell_script, trusted_env

# The golden runner's reader rendering (T-A7 below compares against it).
_spec = importlib.util.spec_from_file_location("golden_record_run", ROOT / "tests/golden/record/run.py")
golden = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(golden)

# Probe 4 cases (2026-10-04) plus spec cases: spaces, quotes, newline,
# leading '-', ':' inside the path.
CASES = ["a b", "it's", 'say "hi"', "-leading", "new\nline", "12:34:", "with\\back", "$(echo pwn)`id`", "한글 경로"]
def source(shell, path):
    """A quoted `source` line; the harness's own paths never carry the case."""
    p = str(path)
    q = ("'" + p.replace("\\", "\\\\").replace("'", "\\'") + "'") if shell == "fish" else shlex.quote(p)
    return f"source {q}\n".encode()


def call(shell):
    return {"zsh": b"_bingsu_call --width 80\n", "bash": b"_bingsu_call --width 80\n",
            "fish": b"_bingsu_call --width 80\n"}[shell]


@pytest.mark.parametrize("idx,case", list(enumerate(CASES)))
def test_words_arrive_intact(tmp_path, shells, idx, case):
    for shell in shells:
        base = tmp_path / shell / f"case{idx}"  # the hostile string lives only in the install and XDG dirs
        inst = Install(base, name=f"bin {case}")
        env = trusted_env(base, tag=case)
        script = inst.init(shell, env)
        inst.use_fake(minimal_record())
        init_file = base / "init.sh"
        init_file.write_bytes(script)
        r = run_shell_script(shell, source(shell, init_file) + call(shell), env, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        (argv,) = inst.calls()
        run_root = os.path.realpath(env["XDG_RUNTIME_DIR"] + "/bingsu")
        st = os.stat(run_root)
        assert argv[:5] == [b"prompt", b"--ctx", b"1", b"--record", b"B1"], (shell, argv)
        assert f"--runtime-root={st.st_dev}:{st.st_ino}:{run_root}".encode() in argv, (shell, argv)
        # init canonicalizes the existing part of each root (os.path.realpath does the same).
        assert (b"--config-root=" + os.path.realpath(env["XDG_CONFIG_HOME"] + "/bingsu").encode()) in argv
        assert (b"--state-root=" + os.path.realpath(env["XDG_STATE_HOME"] + "/bingsu").encode()) in argv
        assert (b"--log-root=" + os.path.realpath(env["XDG_STATE_HOME"] + "/bingsu/log").encode()) in argv
        # prompt --ctx 1 --record B1 --width 80 --session S --seq N + four roots
        assert len(argv) == 15, (shell, argv)


def test_init_twice_redefines_runtime_root(tmp_path, shells):
    for shell in shells:
        base = tmp_path / shell
        inst = Install(base)
        a = inst.init(shell, trusted_env(base, "a"))
        b_env = trusted_env(base, "b")
        b = inst.init(shell, b_env)
        inst.use_fake(minimal_record())
        (base / "a.sh").write_bytes(a)
        (base / "b.sh").write_bytes(b)
        r = run_shell_script(shell, source(shell, base / "a.sh") + source(shell, base / "b.sh") + call(shell), b_env, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        (argv,) = inst.calls()
        root_b = os.path.realpath(b_env["XDG_RUNTIME_DIR"] + "/bingsu").encode()
        assert any(x.startswith(b"--runtime-root=") and x.endswith(b":" + root_b) for x in argv), (shell, argv)


# The reader text init embeds must be byte-identical to what the golden
# runner tests, or the golden vectors vouch for a different script.
# 이것을 실패시키는 것: Rust render의 @KNOWN_CODES@ 치환 문자열을 바꾸는 것(구분자, 따옴표, 순서).
def test_reader_substitution_matches_golden_runner(tmp_path, shells):
    for shell in shells:
        base = tmp_path / shell
        inst = Install(base)
        script = inst.init(shell, trusted_env(base))
        if shell == "bash":
            script = script.split(b"\n", 1)[1]  # the version guard's first line
        golden.render_reader(shell, base / "reader")
        want = (base / "reader").read_bytes() + b"\n"
        assert script[: len(want)] == want, shell


# _bingsu_seq and _bingsu_session can arrive from the environment. bash
# evaluates a[$(cmd)] in $(( )); only init's own shapes may survive.
# 이것을 실패시키는 것: hook이 물려받은 _bingsu_seq를 숫자 검사 없이 산술에 넣는 것,
# _bingsu_session을 모양 검사 없이 쓰는 것.
# zsh does not run the command but prints a math error for "$(...)" and
# reads "08" as 8 (or fails under OCTAL_ZEROES).
@pytest.mark.parametrize("seq", ["a[$(touch {c})]", "$(touch {c})", "08"])
def test_inherited_seq_and_session_are_not_trusted(tmp_path, shells, seq):
    for shell in shells:
        base = tmp_path / shell
        inst = Install(base)
        env = trusted_env(base)
        script = inst.init(shell, env)
        inst.use_fake(minimal_record())
        canary = base / "PWNED"
        env["_bingsu_seq"] = seq.format(c=canary)
        env["_bingsu_session"] = f"x$(touch {canary})"
        (base / "init.sh").write_bytes(script)
        r = run_shell_script(shell, source(shell, base / "init.sh") + call(shell), env, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        assert not canary.exists(), shell
        (argv,) = inst.calls()
        i = argv.index(b"--seq")
        assert argv[i + 1] == b"1", (shell, argv)
        s = argv[argv.index(b"--session") + 1]
        assert len(s) == 32 and all(c in b"0123456789abcdef" for c in s), (shell, argv)
