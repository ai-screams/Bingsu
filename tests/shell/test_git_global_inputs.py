"""Global locations are init pins; later environment changes cannot select files."""
import os
import re
import shlex
import subprocess

import pytest

from conftest import SHELL_CMD, real_bin, run_shell_script, trusted_env

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()


# Mutations: read either location at prompt time (argv assertion), or reject
# over-cap input in the envelope (direct CLI assertion).
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("names", [("HOME",), ("XDG_CONFIG_HOME",), ("HOME", "XDG_CONFIG_HOME")])
@pytest.mark.parametrize("later", ["over-cap", "hostile", "unset"])
def test_prompt_time_global_locations_stay_pinned(shell, names, later, tmp_path):
    env = trusted_env(tmp_path)
    env["HOME"] = str(tmp_path / "home ' $(literal)\n@GIT_GLOBAL_XDG@")
    pinned = env.copy()
    binary = real_bin()
    init = subprocess.run([str(binary), "init", shell], env=env, capture_output=True, check=True)
    # Init may report unavailable group trust in a sandbox. Its actual embedded
    # hooks still run the pinned binary and render a degraded prompt normally.
    probe = tmp_path / "probe"
    words = tmp_path / "words"
    probe.write_text("#!/bin/sh\n" + f"printf '%s\\0' \"$@\" > {shlex.quote(str(words))}\n"
                     + f"exec {shlex.quote(str(binary))} \"$@\"\n")
    probe.chmod(0o700)
    script = init.stdout.replace(os.fsencode(binary), os.fsencode(probe))
    assert os.fsencode(probe) in script
    # Exercise the built-in prompt without snapshot/config trust prerequisites.
    # Only init-pinned roots are omitted; the real embedded hook, observed
    # HOME/XDG pins, and real envelope/render path remain under test.
    script = re.sub(rb"'--(?:runtime-root|runtime-groups|config-root|config-root-written|state-root|log-root|collector-exe)=[^']*'", b"", script)
    script = script.replace(b"'--config-root-shape-only'", b"")
    # Set after init: even huge prompt-time values cannot replace the pins.
    for name in names:
        if later == "unset":
            env.pop(name, None)
        elif later == "hostile":
            env[name] = str(tmp_path / "repo ' $(literal)\nconfig")
        else:
            env[name] = "x" * 70_000
    suffix = (b'\n_bingsu_call --width 80\nprintf "%s" "$_bingsu_rec"\n')
    result = run_shell_script(shell, script + suffix, env, tmp_path)
    assert result.returncode == 0, result.stderr
    argv = words.read_bytes().split(b"\0")[:-1]
    for name, flag in [("HOME", b"--git-global-home="), ("XDG_CONFIG_HOME", b"--git-global-xdg=")]:
        assert [word for word in argv if word.startswith(flag)] == [
            flag + os.fsencode(pinned[name])
        ], (shell, name)
    assert_record(result.stdout)
    # Direct callers retain I1's envelope degradation for over-cap input.
    for index, word in enumerate(argv):
        for name, flag in [("HOME", b"--git-global-home="), ("XDG_CONFIG_HOME", b"--git-global-xdg=")]:
            if name in names and word.startswith(flag):
                argv[index] = flag + b"x" * 70_000
    direct = subprocess.run([os.fsencode(binary), *argv], env=trusted_env(tmp_path), capture_output=True, check=True)
    assert_record(direct.stdout)


# Mutations: fail init, preserve invalid bytes, omit/duplicate the notice,
# name the wrong variable/reason, or revive the invalid pin in the hook.
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("names", [("HOME",), ("XDG_CONFIG_HOME",), ("HOME", "XDG_CONFIG_HOME")])
@pytest.mark.parametrize("value,reason", [
    ("relative", "is not an absolute path"),
    ("~/.config", "is not an absolute path"),
    ("/" + "x" * 69_999, "exceeds 65536 bytes"),
], ids=["relative", "literal-tilde", "70000-bytes"])
def test_invalid_global_location_pins_unknown_and_renders(shell, names, value, reason, tmp_path):
    env = trusted_env(tmp_path)
    env["HOME"] = str(tmp_path / "home")
    for name in names:
        env[name] = value
    binary = real_bin()
    result = subprocess.run([str(binary), "init", shell], env=env, capture_output=True)
    assert result.returncode == 0 and result.stdout, (result.returncode, result.stderr)
    notices = [line for line in result.stderr.splitlines() if b"pinning unknown for global Git excludes" in line]
    assert notices == [f"bingsu: {name} {reason}; pinning unknown for global Git excludes".encode() for name in names]
    probe, words = tmp_path / "probe", tmp_path / "words"
    # The probe runs the binary as its child and keeps its own rc and stderr,
    # so an empty record says whether the binary exited 0 without output
    # (a deadline exit), failed to start, or died by a signal.
    binary_rc, binary_err = tmp_path / "binary.rc", tmp_path / "binary.stderr"
    probe.write_text("#!/bin/sh\n" + f"printf '%s\\0' \"$@\" > {shlex.quote(str(words))}\n"
                     + f"{shlex.quote(str(binary))} \"$@\" 2> {shlex.quote(str(binary_err))}\n"
                     + f"rc=$?\nprintf '%s' \"$rc\" > {shlex.quote(str(binary_rc))}\n"
                     + f"cat {shlex.quote(str(binary_err))} >&2\nexit \"$rc\"\n")
    probe.chmod(0o700)
    script = result.stdout.replace(os.fsencode(binary), os.fsencode(probe))
    # Same built-in render fixture as above: sandbox config trust is independent
    # of the real init, hook, pin, envelope and prompt-render path exercised here.
    script = re.sub(rb"'--(?:runtime-root|runtime-groups|config-root|config-root-written|state-root|log-root|collector-exe)=[^']*'", b"", script)
    script = script.replace(b"'--config-root-shape-only'", b"")
    # Fish may create its own config under a relative XDG path on startup.
    # Keep that shell behavior inside the fixture, away from the checkout.
    script_file = tmp_path / f"script.{shell}"
    script_file.write_bytes(script + b'\n_bingsu_call --width 80\nprintf "%s" "$_bingsu_rec"\n')
    rendered = subprocess.run(SHELL_CMD[shell] + [str(script_file)], env=env,
                              cwd=tmp_path, capture_output=True, timeout=60)
    assert rendered.returncode == 0, rendered.stderr
    argv = words.read_bytes().split(b"\0")[:-1]
    for name, flag in [("HOME", b"--git-global-home="), ("XDG_CONFIG_HOME", b"--git-global-xdg=")]:
        assert [word for word in argv if word.startswith(flag)] == [flag + (b"!invalid" if name in names else os.fsencode(env[name]))]
    # 이것을 실패시키는 것: 빈 레코드의 실패 메시지에서 바이너리의 rc·stderr를 빼는 것.
    assert_record(rendered.stdout, {
        "binary rc": binary_rc.read_text() if binary_rc.exists() else "missing (the probe never ran it)",
        "binary stderr": binary_err.read_bytes() if binary_err.exists() else None,
        "shell rc": rendered.returncode, "shell stderr": rendered.stderr})


# Mutation: omit explicit empty pins and accidentally revive the legacy home,
# or resolve newly set prompt-time values after an empty/unset init.
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_empty_global_locations_stay_pinned(shell, value, tmp_path):
    env = trusted_env(tmp_path)
    for name in ["HOME", "XDG_CONFIG_HOME"]:
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    binary = real_bin()
    init = subprocess.run([str(binary), "init", shell], env=env, capture_output=True, check=True)
    probe = tmp_path / "probe"
    words = tmp_path / "words"
    probe.write_text("#!/bin/sh\n" + f"printf '%s\\0' \"$@\" > {shlex.quote(str(words))}\n")
    probe.chmod(0o700)
    script = init.stdout.replace(os.fsencode(binary), os.fsencode(probe))
    env.update(HOME="/hostile/home", XDG_CONFIG_HOME="/hostile/xdg")
    result = run_shell_script(shell, script + b"\n_bingsu_call --width 80\n", env, tmp_path)
    assert result.returncode == 0, result.stderr
    argv = words.read_bytes().split(b"\0")[:-1]
    assert [word for word in argv if word.startswith(b"--git-global-")] == [
        b"--git-global-home=", b"--git-global-xdg="
    ], (shell, argv)


# The pre-global-input hook contract omits the two new words. The helper's
# pinned --home fallback is checked by git_global::tests in the Rust suite.
# Mutation: require either new word in the envelope/helper parser.
@pytest.mark.parametrize("shell", SHELLS)
def test_legacy_hook_without_global_words_still_renders(shell, tmp_path):
    env = trusted_env(tmp_path)
    env["HOME"] = str(tmp_path / "init-home")
    init = subprocess.run([str(real_bin()), "init", shell], env=env, capture_output=True, check=True)
    script, count = re.subn(rb"'--git-global-(?:home|xdg)=[^']*'", b"", init.stdout)
    assert count == 2
    script = re.sub(rb"'--(?:runtime-root|runtime-groups|config-root|config-root-written|state-root|log-root|collector-exe)=[^']*'", b"", script)
    script = script.replace(b"'--config-root-shape-only'", b"")
    env.update(HOME="/hostile/home", XDG_CONFIG_HOME="/hostile/xdg")
    result = run_shell_script(shell, script + b'\n_bingsu_call --width 80\nprintf "%s" "$_bingsu_rec"\n', env, tmp_path)
    assert result.returncode == 0, result.stderr
    assert_record(result.stdout)


def assert_record(record, context=None):
    assert record.startswith(b"B1\x1f8\x1f") and record.endswith(b"\x1e"), (record, context)
    fields = record[:-1].split(b"\x1f")
    assert len(fields) == 10 and fields[2], (record, context)
    assert fields[-1].startswith((b"ok:", b"degraded:")), (fields[-1], context)
