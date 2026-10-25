"""Runtime root and fixed-path words arrive at the binary as single words
(spec section 9 M1 row, change (1)); init twice redefines the call with the
new runtime root (F-23 golden)."""
import importlib.util
import os
import pathlib
import pwd
import re
import shlex
import shutil
import subprocess
import tempfile

import pytest

from conftest import ROOT, Install, minimal_record, run_shell_script, trusted_env, real_bin, real_collector

# The golden runner's reader rendering (T-A7 below compares against it).
_spec = importlib.util.spec_from_file_location("golden_record_run", ROOT / "tests/golden/record/run.py")
golden = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(golden)

# Probe 4 cases (2026-10-04) plus spec cases: spaces, quotes, newline,
# leading '-', ':' inside the path.
CASES = ["a b", "it's", 'say "hi"', "-leading", "new\nline", "12:34:", "with\\back", "$(echo pwn)`id`", "한글 경로"]

# _bingsu_call --width 80 in all three shells. A trailing '=' marks an
# init-pinned or dynamic single-word option; the others consume one value.
# Keep the complete hook contract here instead of counting argv entries.
HOOK_WORDS = (
    b"--ctx", b"--record", b"--width", b"--shell", b"--pwd", b"--colorterm", b"--colorfgbg",
    b"--log-level=", b"--host", b"--venv", b"--ssh=", b"--session", b"--seq",
    b"--runtime-root=", b"--runtime-groups=", b"--config-root=",
    b"--config-root-written=", b"--state-root=", b"--log-root=", b"--home=", b"--git-global-home=", b"--git-global-xdg=", b"--collector-exe=",
)


# 이것을 실패시키는 것: Undecided 뿌리의 작성·정규 경로나 표식을 실제 셸에서 누락·중복·분할하는 것.
def test_shape_only_root_words_survive_real_shells(tmp_path, shells):
    # Produced before pytest on the host; minimum-shell images have no Rust
    # toolchain. The scripts embed this directory (in Docker, under /w).
    fixture = pathlib.Path(os.environ.get("BINGSU_SHAPE_ONLY_FIXTURE", ROOT / "target/shape-only-fixture")).resolve()
    if not all((fixture / f"init.{shell}").is_file() for shell in shells):
        reason = f"missing shape-only init fixture in {fixture}; generate it with write_shape_only_shell_fixture before pytest"
        if os.environ.get("CI") == "true":
            pytest.fail(reason)
        pytest.skip(reason)
    probe = fixture / "probe"
    probe.write_text('#!/bin/sh\nprintf \'%s\\0\' "$@" > "${0%/*}/words"\n')
    probe.chmod(0o700)
    want = [
        b"--config-root=" + os.fsencode(fixture / "canonical ' space"),
        b"--config-root-written=" + os.fsencode(fixture / "written ' space"),
        b"--config-root-shape-only",
    ]
    for shell in shells:
        env = trusted_env(tmp_path)
        env["HOME"] = str(tmp_path / "home ' $(literal)\nname")
        env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg ' `literal`\nname")
        result = run_shell_script(shell, source(shell, fixture / f"init.{shell}") + call(shell),
                                  env, tmp_path)
        assert result.returncode == 0 and result.stderr == b"", (shell, result)
        words = (fixture / "words").read_bytes().split(b"\0")[:-1]
        roots = [w for w in words if w.startswith(b"--config-root")]
        assert roots == want, (shell, words)
        assert [w for w in words if w.startswith(b"--git-global-")] == [
            b"--git-global-home=/home ' $(literal)\nname",
            b"--git-global-xdg=/xdg ' `literal`\nname",
        ], (shell, words)


def source(shell, path):
    """A quoted `source` line; the harness's own paths never carry the case."""
    p = str(path)
    q = ("'" + p.replace("\\", "\\\\").replace("'", "\\'") + "'") if shell == "fish" else shlex.quote(p)
    return f"source {q}\n".encode()


def call(shell):
    return {"zsh": b"_bingsu_call --width 80\n", "bash": b"_bingsu_call --width 80\n",
            "fish": b"_bingsu_call --width 80\n"}[shell]


# 이것을 실패시키는 것: hook이 `--shell`·`--pwd`·`--colorterm`·`--home=`·`--config-root-written=`·`--collector-exe=` 중 하나를 빠뜨리는 것, 빈 `$COLORTERM`의
# 따옴표를 빼는 것(빈 단어가 사라짐).
@pytest.mark.parametrize("idx,case", list(enumerate(CASES)))
def test_words_arrive_intact(tmp_path, shells, idx, case):
    for shell in shells:
        base = tmp_path / shell / f"case{idx}"  # the hostile string lives only in the install and XDG dirs
        inst = Install(base, name=f"bin {case}")
        # Use the actual matched binary pair, including their distinct roles.
        inst.exe.unlink()
        shutil.copyfile(real_bin(), inst.exe)
        inst.exe.chmod(0o700)
        collector = inst.dir / "bingsu-collect"
        shutil.copyfile(real_collector(), collector)
        collector.chmod(0o700)
        env = trusted_env(base, tag=case)
        env["HOME"] = str(base / ("home " + case))
        pathlib.Path(env["HOME"]).mkdir(parents=True)
        script = inst.init(shell, env)
        inst.use_fake(minimal_record())
        init_file = base / "init.sh"
        init_file.write_bytes(script)
        r = run_shell_script(shell, source(shell, init_file) + call(shell), env, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        (argv,) = inst.calls()
        run_root = os.path.realpath(env["XDG_RUNTIME_DIR"] + "/bingsu")
        st = os.stat(run_root)
        assert argv[0] == b"prompt", (shell, argv)
        words = {}
        args = iter(argv[1:])
        for arg in args:
            name, sep, value = arg.partition(b"=")
            word = name + sep
            assert word in HOOK_WORDS and word not in words, (shell, argv)
            if not sep:
                value = next(args, None)
                assert value is not None, (shell, argv)
            words[word] = value
        assert set(words) == set(HOOK_WORDS), (shell, argv)
        assert words[b"--collector-exe="] == os.fsencode(collector.resolve()), (shell, argv)
        assert words[b"--ctx"] == b"1", (shell, argv)
        assert words[b"--record"] == b"B1", (shell, argv)
        assert words[b"--width"] == b"80", (shell, argv)
        assert words[b"--runtime-root="] == f"{st.st_dev}:{st.st_ino}:{run_root}".encode(), (shell, argv)
        # Both spellings must survive shell quoting, including hostile path bytes.
        assert words[b"--config-root-written="] == (env["XDG_CONFIG_HOME"] + "/bingsu").encode(), (shell, argv)
        # init canonicalizes the existing part of each root (os.path.realpath does the same).
        assert words[b"--config-root="] == os.path.realpath(env["XDG_CONFIG_HOME"] + "/bingsu").encode(), (shell, argv)
        assert words[b"--state-root="] == os.path.realpath(env["XDG_STATE_HOME"] + "/bingsu").encode(), (shell, argv)
        assert words[b"--log-root="] == os.path.realpath(env["XDG_STATE_HOME"] + "/bingsu/log").encode(), (shell, argv)
        # The display words of M3a: the hook's shell, $PWD, $COLORTERM, and
        # the home folder init found with getpwuid.
        assert words[b"--shell"] == shell.encode(), (shell, argv)
        assert words[b"--pwd"] == os.getcwd().encode(), (shell, argv)
        assert words[b"--colorterm"] == b"", (shell, argv)
        assert words[b"--colorfgbg"] == b"", (shell, argv)
        assert words[b"--home="] == pwd.getpwuid(os.getuid()).pw_dir.encode(), (shell, argv)
        assert words[b"--git-global-home="] == os.fsencode(env["HOME"]), (shell, argv)
        assert words[b"--git-global-xdg="] == os.fsencode(env["XDG_CONFIG_HOME"]), (shell, argv)


# 이것을 실패시키는 것: 역할 검사를 빼거나 형제 링크를 해석하거나 unsafe bingsu에서 pin하는 것.
@pytest.mark.parametrize("case", ["real", "bingsu-copy", "tag-only", "symlink", "unsafe-bingsu"])
def test_collector_pin_requires_safe_install_and_collector_role(case, tmp_path):
    # Keep the positive control outside sticky temporary-directory ancestors.
    with tempfile.TemporaryDirectory(prefix="collector-pin-", dir=tmp_path) as folder:
        base = pathlib.Path(folder)
        inst = Install(base)
        inst.exe.unlink()
        shutil.copyfile(real_bin(), inst.exe)
        inst.exe.chmod(0o700)
        collector = inst.dir / "bingsu-collect"
        shutil.copyfile(real_collector(), collector)
        collector.chmod(0o700)
        if case == "bingsu-copy":
            shutil.copyfile(inst.exe, collector)
        elif case == "tag-only":
            binary = collector.read_bytes()
            marker = b"BNGSIBLING-ID02\0"
            assert binary.count(marker) == 1
            at = binary.index(marker)
            collector.write_bytes(binary[at:at + 48])
        elif case == "symlink":
            other = base / "other"
            other.mkdir()
            collector.rename(other / collector.name)
            collector.symlink_to(other / collector.name)
        elif case == "unsafe-bingsu":
            inst.exe.chmod(0o702)
        out = subprocess.run([str(inst.exe), "init", "bash"], env=trusted_env(base), capture_output=True)
        assert out.returncode == 0, out
        assert (b"--collector-exe=" in out.stdout) == (case == "real"), out
        if case == "real":
            assert os.fsencode(collector.resolve()) in out.stdout
        if case == "bingsu-copy":
            refused = subprocess.run([str(collector), "__collect-v1"], capture_output=True)
            assert refused.returncode == 2, refused


def test_init_twice_redefines_runtime_root(tmp_path, shells):
    for shell in shells:
        base = tmp_path / shell
        inst = Install(base)
        a_env = dict(trusted_env(base, "a"), HOME=str(base / "home-a"))
        a = inst.init(shell, a_env)
        b_env = trusted_env(base, "b")
        b_env["HOME"] = str(base / "home-b")
        b = inst.init(shell, b_env)
        inst.use_fake(minimal_record())
        (base / "a.sh").write_bytes(a)
        (base / "b.sh").write_bytes(b)
        r = run_shell_script(shell, source(shell, base / "a.sh") + source(shell, base / "b.sh") + call(shell), b_env, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        (argv,) = inst.calls()
        root_b = os.path.realpath(b_env["XDG_RUNTIME_DIR"] + "/bingsu").encode()
        assert any(x.startswith(b"--runtime-root=") and x.endswith(b":" + root_b) for x in argv), (shell, argv)
        # Every other pinned value follows the second init too (N-129), not only the runtime root.
        want = {
            b"--git-global-home=": os.fsencode(b_env["HOME"]),
            b"--git-global-xdg=": os.fsencode(b_env["XDG_CONFIG_HOME"]),
            b"--config-root=": os.path.realpath(b_env["XDG_CONFIG_HOME"] + "/bingsu").encode(),
            b"--config-root-written=": (b_env["XDG_CONFIG_HOME"] + "/bingsu").encode(),
            b"--state-root=": os.path.realpath(b_env["XDG_STATE_HOME"]).encode() + b"/bingsu",
            b"--log-root=": os.path.realpath(b_env["XDG_STATE_HOME"]).encode() + b"/bingsu/log",
        }
        for word, value in want.items():
            assert any(x == word + value for x in argv), (shell, word, argv)
        assert not any(old in x for x in argv for old in (b"run-a", b"cfg-a", b"state-a", b"home-a")), (shell, argv)


def _set_env(shell, name, value):
    q = shlex.quote(value)
    return f"set -gx {name} {q}\n" if shell == "fish" else f"export {name}={q}\n"


# The init script exports the roots it pinned, and the user's commands follow them: after XDG_* moved and a
# second init (the last one wins), `bingsu reload` and `config check` still act on the second init's folders,
# for hostile bytes in every pinned path, and no notice appears.
# 이것을 실패시키는 것: 내보내기 줄을 빼거나 셸 인용을 잘못해 값이 깨지는 것, 재-init이 이전 값을 남기는 것(옛 뿌리에 발행),
# 명령이 변수 대신 바뀐 XDG_*를 쓰는 것.
@pytest.mark.parametrize("idx,case", list(enumerate(CASES)))
def test_exported_roots_survive_hostile_bytes_and_reinit(tmp_path, shells, idx, case):
    for shell in shells:
        base = tmp_path / shell / f"case{idx}"
        inst = Install(base)
        env_a = trusted_env(base, "a")
        env_b = trusted_env(base, case)
        a = inst.init(shell, env_a)
        b = inst.init(shell, env_b)
        (base / "a.sh").write_bytes(a)
        (base / "b.sh").write_bytes(b)
        junk = base / "junk"
        script = source(shell, base / "a.sh") + source(shell, base / "b.sh")
        for name in ("XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
            script += _set_env(shell, name, str(junk / name.lower()).strip()).encode()
        exe = shlex.quote(str(inst.exe))
        script += f"{exe} reload\n{exe} config check\n".encode()
        r = run_shell_script(shell, script, env_b, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        assert b"bingsu: reloaded; " in r.stdout, (shell, r.stdout)
        assert not junk.exists(), shell
        assert b"found from the environment" not in r.stderr + r.stdout, shell
        cfg_b = os.path.realpath(env_b["XDG_CONFIG_HOME"]) + "/bingsu"
        if case.isprintable():
            assert f"settings folder: {cfg_b}".encode() in r.stdout, (shell, r.stdout)
        assert b"cfg-a/bingsu" not in r.stdout, shell


# Top-level hook code runs under the user's own shell options (only function
# bodies are shielded by `emulate -L zsh`), so eval must survive them.
# 이것을 실패시키는 것: hooks.zsh의 `case ${_bingsu_seq-} in`을 `case $_bingsu_seq in`으로 되돌리는 것(NO_UNSET에서 eval이 끊긴다).
def test_zsh_eval_survives_hostile_user_options(tmp_path, shells):
    if "zsh" not in shells:
        pytest.skip("zsh not in BINGSU_TEST_SHELLS")
    base = tmp_path / "zsh"
    inst = Install(base)
    env = trusted_env(base, "opts")
    script = inst.init("zsh", env)
    inst.use_fake(minimal_record())
    init_file = base / "init.sh"
    init_file.write_bytes(script)
    opts = b"setopt NO_UNSET SH_WORD_SPLIT GLOB_SUBST KSH_ARRAYS NOMATCH\n"
    r = run_shell_script("zsh", opts + source("zsh", init_file) + b"_bingsu_call\n", env, base)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    (argv,) = inst.calls()
    i = argv.index(b"--seq")
    assert argv[i + 1] == b"1", argv


# An inherited session value is expanded at top level, under the user's
# options. With GLOB_SUBST the unquoted expansion is a pattern, and with
# NOMATCH a pattern that matches nothing aborts the eval.
# 이것을 실패시키는 것: hooks.zsh의 `: "${_bingsu_session:=@SESSION@}"`에서 따옴표를 빼는 것.
def test_zsh_inherited_session_glob_survives_glob_subst(tmp_path, shells):
    if "zsh" not in shells:
        pytest.skip("zsh not in BINGSU_TEST_SHELLS")
    base = tmp_path / "zsh"
    inst = Install(base)
    env = trusted_env(base, "glob")
    script = inst.init("zsh", env)
    session = re.search(rb"_bingsu_session='([0-9a-f]{32})'", script).group(1)
    inst.use_fake(minimal_record())
    init_file = base / "init.sh"
    init_file.write_bytes(script)
    env["_bingsu_session"] = "*[a]"
    opts = b"setopt GLOB_SUBST NOMATCH\n"
    r = run_shell_script("zsh", opts + source("zsh", init_file) + b"_bingsu_call\n", env, base)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    (argv,) = inst.calls()
    assert argv[argv.index(b"--session") + 1] == session, argv


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
# "1\n" and a trailing newline on a valid session pass a regex anchored
# with "$" (fish string match -r is PCRE2); "\z" refuses them.
@pytest.mark.parametrize("seq,session", [
    ("a[$(touch {c})]", "x$(touch {c})"),
    ("$(touch {c})", "x$(touch {c})"),
    ("08", "x$(touch {c})"),
    ("1\n", "0123456789abcdef0123456789abcdef\n"),
])
def test_inherited_seq_and_session_are_not_trusted(tmp_path, shells, seq, session):
    for shell in shells:
        base = tmp_path / shell
        inst = Install(base)
        env = trusted_env(base)
        script = inst.init(shell, env)
        inst.use_fake(minimal_record())
        canary = base / "PWNED"
        env["_bingsu_seq"] = seq.format(c=canary)
        env["_bingsu_session"] = session.format(c=canary)
        (base / "init.sh").write_bytes(script)
        r = run_shell_script(shell, source(shell, base / "init.sh") + call(shell), env, base)
        assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
        assert not canary.exists(), shell
        (argv,) = inst.calls()
        i = argv.index(b"--seq")
        assert argv[i + 1] == b"1", (shell, argv)
        s = argv[argv.index(b"--session") + 1]
        assert len(s) == 32 and all(c in b"0123456789abcdef" for c in s), (shell, argv)
        assert s != b"0123456789abcdef0123456789abcdef", (shell, argv)


# bash nocasematch makes `case` accept uppercase hex; the binary only takes
# lowercase, so every prompt would be bad-args. The hook clears it around
# the check and restores it.
# 이것을 실패시키는 것: bash hook의 session 검사에서 nocasematch 가드를 빼는 것.
def test_bash_session_check_ignores_nocasematch(tmp_path, shells):
    if "bash" not in shells:
        pytest.skip("bash not in BINGSU_TEST_SHELLS")
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("bash", env)
    inst.use_fake(minimal_record())
    env["_bingsu_session"] = "0123456789ABCDEF0123456789ABCDEF"
    (tmp_path / "init.sh").write_bytes(script)
    body = b"shopt -s nocasematch\n" + source("bash", tmp_path / "init.sh") + call("bash")
    body += b"shopt -q nocasematch || echo lost >&2\n"
    r = run_shell_script("bash", body, env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    (argv,) = inst.calls()
    s = argv[argv.index(b"--session") + 1]
    assert len(s) == 32 and all(c in b"0123456789abcdef" for c in s), argv
