"""The display words of the envelope (M3a V2) arrive as exactly one argument
each, byte for byte, in every shell: `--pwd` carries $PWD and `--colorterm`
carries $COLORTERM whatever they hold. Every hook passes a $PWD over 65,536
bytes as an empty word (it would otherwise sit in argv next to the
environment copy and can hit ARG_MAX)."""
import os
import shutil
import subprocess
import sys

import pytest

from conftest import Install, minimal_record, run_shell_script, trusted_env
from test_init_words import CASES, source

# CASES of test_init_words plus prompt escapes and a glob.
NAMES = CASES + ["50% %F{red}", "a*b?[c]", "!!"]
CD = {"zsh": b'cd -- "$BINGSU_T_DIR"\n', "bash": b'cd -- "$BINGSU_T_DIR"\n', "fish": b"cd -- $BINGSU_T_DIR\n"}


def value_after(argv, flag):
    i = argv.index(flag)
    return argv[i + 1]


def call_once(tmp_path, shell, env, body):
    inst = Install(tmp_path)
    script = inst.init(shell, env)
    inst.use_fake(minimal_record())
    (tmp_path / "init.sh").write_bytes(script)
    r = run_shell_script(shell, source(shell, tmp_path / "init.sh") + body + b"_bingsu_call --width 80\n",
                         env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", (shell, r.stderr)
    (argv,) = inst.calls()
    return argv


# 이것을 실패시키는 것: 어느 셸이든 `--pwd`·`--colorterm` 값의 따옴표를 빼는 것(공백·줄바꿈에서 단어가 갈리거나
# 빈 값이 사라짐), 값을 다시 해석하는 것(`$(…)`·`%`·glob), 다른 변수를 넘기는 것.
@pytest.mark.parametrize("idx,name", list(enumerate(NAMES)))
def test_pwd_and_colorterm_round_trip(tmp_path, shells, idx, name):
    for shell in shells:
        base = tmp_path / shell
        folder = base / "d" / name
        folder.mkdir(parents=True)
        env = dict(trusted_env(base), BINGSU_T_DIR=str(folder), COLORTERM=name, COLORFGBG=name)
        argv = call_once(base, shell, env, CD[shell])
        assert value_after(argv, b"--pwd") == os.fsencode(folder), (shell, argv)
        assert value_after(argv, b"--colorterm") == name.encode(), (shell, argv)
        assert value_after(argv, b"--colorfgbg") == name.encode(), (shell, argv)


# 65,536 bytes: the envelope's PATH_BYTES_MAX. 21,845 "가" are 65,535 bytes.
CAP = 65536
HANGUL = "가".encode()


# 이것을 실패시키는 것: bash·zsh hook에서 64 KiB 상한을 빼는 것(100 KB 값이 argv로 감), 상한을 글자 수로 세는 것
# (30,000글자 한글 90,001바이트가 통과함), 빈 값의 따옴표를 빼는 것(빈 단어가 사라져 다음 플래그가 값이 됨),
# bash에서 `${PWD-}` 대신 `$PWD`를 쓰는 것(set -u + unset PWD), bash에서 바이트를 세는 LC_ALL이 함수 밖으로 새는 것,
# readonly LC_ALL에서 글자 수로 세어 넘기는 것이나 그 오류를 stderr에 내는 것.
@pytest.mark.parametrize("shell", ["zsh", "bash"])
def test_pwd_cap_counts_bytes(tmp_path, shells, shell):
    if shell not in shells:
        pytest.skip(f"{shell} not in BINGSU_TEST_SHELLS")
    env = trusted_env(tmp_path)
    rows = [
        ("ascii-max", b"/" + b"a" * (CAP - 1), True),
        ("ascii-over", b"/" + b"a" * CAP, False),
        ("multibyte-max", b"/" + HANGUL * 21845, True),
        ("multibyte-over", b"/" + HANGUL * 21845 + b"a", False),
        ("chars-under-bytes-over", b"/" + HANGUL * 30000, False),
    ]
    for name, value, passed in rows:
        argv = call_once(tmp_path / name, shell, env, b"PWD=" + value + b"\n")
        assert value_after(argv, b"--pwd") == (value if passed else b""), (name, len(value))
    if shell == "bash":
        # A readonly LC_ALL: the byte count cannot switch to C, so $PWD is
        # not passed at all, and nothing reaches stderr (call_once checks).
        argv = call_once(tmp_path / "readonly", shell, env, b"readonly LC_ALL=C.UTF-8\nPWD=/short\n")
        assert value_after(argv, b"--pwd") == b"", argv
        argv = call_once(tmp_path / "unset", shell, env, b"set -u\nunset PWD\n")
        assert value_after(argv, b"--pwd") == b"", argv
        # The byte count leaves the caller's locale as it was.
        out = tmp_path / "len.txt"
        call_once(tmp_path / "locale", shell, env,
                  b's="\xea\xb0\x80"; _bingsu_bytes x; echo "${#s}" > ' + str(out).encode() + b"\n")
        assert out.read_bytes().strip() == b"1"


# 이것을 실패시키는 것: fish의 바이트 세기를 `string length`(글자 수)로 바꾸는 것, URL escape의 %XX를 세지 않는 것.
def test_fish_counts_bytes(tmp_path, shells):
    if "fish" not in shells:
        pytest.skip("fish not in BINGSU_TEST_SHELLS")
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    (tmp_path / "init.fish").write_bytes(inst.init("fish", env))
    values = [b"/" + b"a" * (CAP - 1), b"/" + HANGUL * 21845, b"/" + HANGUL * 21845 + b"a", b"/a%b c"]
    body = b"".join(b"_bingsu_bytes " + (b"'" + v + b"'") + b"\n" for v in values)
    r = run_shell_script("fish", source("fish", tmp_path / "init.fish") + body, env, tmp_path)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    assert [int(x) for x in r.stdout.split()] == [len(v) for v in values], r.stdout


# fish's $PWD is read-only, but fish started in a folder deeper than 64 KiB
# can have such a $PWD. Observed 2026-10-14 (340 levels of 200-byte names,
# made one level at a time with chdir, as no single path call can name it):
# fish 4.9.3 on macOS starts with a 68,379-byte $PWD; fish 3.6.0 and 4.0.2 on
# Linux print "getcwd() failed with errno 34", leave $PWD empty and go on
# (exit status 1 at the end), with or without PWD in the environment. Both
# give an empty --pwd; only macOS goes through the hook's size check. Linux containers need AppArmor unconfined (docker-default
# refuses paths over about 8 KB: mkdir stopped at depth 40).
# 이것을 실패시키는 것: fish hook에서 상한을 빼는 것, 상한 뒤 빈 값의 따옴표를 빼는 것(macOS에서 단언).
def test_fish_long_cwd_is_passed_empty(tmp_path, shells):
    if "fish" not in shells:
        pytest.skip("fish not in BINGSU_TEST_SHELLS")
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    (tmp_path / "init.fish").write_bytes(inst.init("fish", env))
    inst.use_fake(minimal_record())
    script = tmp_path / "s.fish"
    script.write_bytes(source("fish", tmp_path / "init.fish")
                       + b"_bingsu_call --width 80\nstring length -- $PWD > " + str(tmp_path / "len.txt").encode() + b"\n")
    helper = (
        "import os, sys\n"
        "os.chdir(sys.argv[1])\n"
        "for _ in range(340):\n"
        "    os.mkdir('d' * 200)\n"
        "    os.chdir('d' * 200)\n"
        "env = {k: v for k, v in os.environ.items() if k != 'PWD'}\n"
        "os.execvpe('fish', ['fish', '--no-config', sys.argv[2]], env)\n"
    )
    (tmp_path / "deep").mkdir()
    r = subprocess.run([sys.executable, "-c", helper, str(tmp_path / "deep"), str(script)],
                       env=env, capture_output=True, timeout=60)
    assert b"Traceback" not in r.stderr, ("the folder could not be made (AppArmor?)", r.stderr[-300:])
    if sys.platform.startswith("linux"):
        assert b"getcwd" in r.stderr and int((tmp_path / "len.txt").read_text()) == 0, r.stderr
    else:
        assert r.returncode == 0 and r.stderr == b"", r.stderr
        assert int((tmp_path / "len.txt").read_text()) > CAP
    (argv,) = inst.calls()
    assert value_after(argv, b"--pwd") == b"", argv[:8]
    shutil.rmtree(tmp_path / "deep")



# An LC_ALL that names a locale that is not installed (an image with only
# ENV LC_ALL set, a value sent over ssh): bash itself warns once at start;
# restoring the local LC_ALL of _bingsu_bytes would warn again at every call.
# 이것을 실패시키는 것: bash에서 `_bingsu_bytes` 호출의 `2>/dev/null`을 빼는 것(프롬프트마다 setlocale 경고).
def test_bash_unknown_lc_all_stays_quiet(tmp_path, shells):
    if "bash" not in shells:
        pytest.skip("bash not in BINGSU_TEST_SHELLS")
    inst = Install(tmp_path)
    env = dict(trusted_env(tmp_path), LC_ALL="xx_XX.UTF-8")
    (tmp_path / "init.sh").write_bytes(inst.init("bash", env))
    inst.use_fake(minimal_record())
    r = run_shell_script("bash", source("bash", tmp_path / "init.sh") + b"cd /\n" + b"_bingsu_call --width 80\n" * 3,
                         env, tmp_path)
    assert r.returncode == 0, r.stderr
    assert r.stderr.count(b"setlocale") <= 1 and b"line " not in r.stderr, r.stderr
    assert len(inst.calls()) == 3 and all(value_after(a, b"--pwd") == b"/" for a in inst.calls())

# 이것을 실패시키는 것: 동적 수준·host/venv 한 단어·별도 SSH 전달 또는 새 기본값을 없애는 것.
@pytest.mark.parametrize("level,want", [("debug", "debug"), ("info", "info"), ("error", "error"), ("OFF", "off"), ("/tmp/log", "off")])
def test_optional_helper_display_words(tmp_path, shells, level, want):
    for shell in shells:
        base = tmp_path / shell
        base.mkdir()
        env = trusted_env(base)
        raw = "space ' \" $(false)\nend"
        env.update({"BINGSU_LOG": level, "HOST": raw, "HOSTNAME": raw,
                    "VIRTUAL_ENV": "/venv/" + raw, "SSH_TTY": "yes"})
        body = b""
        if shell == "zsh":
            body = ("HOST='" + raw.replace("'", "'\\''") + "'\n").encode()
        if shell == "bash":
            body += b"shopt -s nocasematch\n"
        argv = call_once(base, shell, env, body)
        assert ("--log-level=" + want).encode() in argv
        # fish owns a read-only hostname; hostile host bytes are tested in bash/zsh.
        if shell != "fish":
            assert value_after(argv, b"--host") == raw.encode()
        else:
            assert value_after(argv, b"--host")
        assert value_after(argv, b"--venv") == ("/venv/" + raw).encode()
        assert b"--ssh=1" in argv
        assert any(word.startswith(b"--runtime-groups=1") for word in argv)

# 이것을 실패시키는 것: host/venv 바이트 상한을 없애거나 64 KiB 경계를 한 바이트 줄이는 것.
def test_optional_display_word_caps(tmp_path, shells):
    for shell in shells:
        for length in (65536, 65537):
            base = tmp_path / f"{shell}-{length}"
            base.mkdir()
            raw = "가".encode() * (length // 3) + b"x" * (length % 3)
            if shell == "fish":
                body = b"set -g VIRTUAL_ENV '" + raw + b"'\n"
            else:
                host = b"HOST" if shell == "zsh" else b"HOSTNAME"
                body = b"VIRTUAL_ENV='" + raw + b"'\n" + host + b"='" + raw + b"'\n"
            if shell == "fish":
                body += b"set -g COLORFGBG '" + raw + b"'\n"
            else:
                body += b"COLORFGBG='" + raw + b"'\n"
            argv = call_once(base, shell, trusted_env(base), body)
            want = raw if length == 65536 else b""
            assert value_after(argv, b"--venv") == want
            assert value_after(argv, b"--colorfgbg") == want
            if shell != "fish":
                assert value_after(argv, b"--host") == want


# NUL cannot occur in an OS argv/env word; core tests cover those three rows.
# All other hostile classes use the same matrix as the renderer/PTY probes.
from test_hostile_matrix import matrix


@pytest.mark.parametrize("row", [r for r in matrix.rows() if b"\0" not in matrix.payload(r[1])], ids=lambda r: r[0])
def test_colorfgbg_hostile_classes_are_one_bounded_word(tmp_path, shells, row):
    for shell in shells:
        base = tmp_path / shell
        base.mkdir()
        canary = base / "PWNED"
        raw = matrix.payload(row[1], str(canary).encode())
        if shell == "fish":
            quoted = raw.replace(b"\\", b"\\\\").replace(b"'", b"\\'")
            body = b"set -g COLORFGBG '" + quoted + b"'\n"
        else:
            body = b"COLORFGBG='" + raw.replace(b"'", b"'\\''") + b"'\n"
        argv = call_once(base, shell, trusted_env(base), body)
        assert not canary.exists(), (shell, row[0])
        assert argv.count(b"--colorfgbg") == 1
        assert value_after(argv, b"--colorfgbg") == (raw if len(raw) <= CAP else b""), (shell, row[0])
