"""F-01 / X-06: at prompt time HOME, USER, XDG_* and BINGSU_LOG point into a
repository; the hook must still pass only the roots pinned by init, and the
binary must touch nothing under the repository."""
import os
import shutil
import subprocess

import pytest

from conftest import SHELL_CMD, Install, minimal_record, run_shell_script, trusted_env

HOSTILE_VARS = ["HOME", "USER", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CACHE_HOME", "BINGSU_LOG"]
CALL = b"_bingsu_call --width 80\n"


def hostile_env(base, trusted):
    repo = base / "repo"
    repo.mkdir()
    env = dict(trusted)
    for k in HOSTILE_VARS:
        env[k] = str(repo / k.lower())
    return env, repo


# 이것을 실패시키는 것: hook이 프롬프트 때 환경 변수로 뿌리를 만드는 것(예: "$XDG_CONFIG_HOME/bingsu").
def test_hook_args_ignore_prompt_time_environment(tmp_path, shells):
    for shell in shells:
        base = tmp_path / shell
        base.mkdir()
        inst = Install(base)
        trusted = trusted_env(base)
        script = inst.init(shell, trusted)
        inst.use_fake(minimal_record())
        env, repo = hostile_env(base, trusted)
        r = run_shell_script(shell, script + b"\n" + CALL, env, base)
        assert r.returncode == 0, (shell, r.stderr)
        (argv,) = inst.calls()
        assert not any(str(repo).encode() in a for a in argv), (shell, argv)
        assert (b"--config-root=" + os.path.realpath(trusted["XDG_CONFIG_HOME"] + "/bingsu").encode()) in argv


# 이것을 실패시키는 것: prompt가 환경 변수로 경로를 정해 그 아래를 여는 것(M3a부터 실제로 여는 코드가 생김).
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace (Linux) not available")
def test_prompt_binary_touches_nothing_under_repo(tmp_path):
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    script = inst.init("bash", trusted)
    env, repo = hostile_env(tmp_path, trusted)
    f = tmp_path / "s.bash"
    f.write_bytes(script + b"\n" + CALL)
    trace = tmp_path / "trace"
    r = subprocess.run(["strace", "-f", "-qq", "-e", "trace=%file,%desc", "-o", str(trace)] + SHELL_CMD["bash"] + [str(f)],
                       env=env, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    lines = trace.read_text(errors="replace").splitlines()
    bingsu_pids = {l.split()[0] for l in lines if "execve(" in l and str(inst.exe) in l}
    assert bingsu_pids, "bingsu was not executed"
    hits = [l for l in lines if l.split()[0] in bingsu_pids and str(repo) in l]
    assert hits == [], hits[:5]
