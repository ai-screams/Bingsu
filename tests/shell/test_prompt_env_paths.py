"""F-01 / X-06: at prompt time HOME, USER, XDG_* and BINGSU_LOG point into a
repository; the hook must still pass only the roots pinned by init, and the
binary (with every process and thread it starts) must touch nothing under
the repository."""
import os
import re
import shutil
import subprocess

import pytest

from conftest import SHELL_CMD, Install, minimal_record, short_dir, trusted_env
from pty_session import Session

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
HOSTILE_VARS = ["HOME", "USER", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CACHE_HOME", "BINGSU_LOG"]
CALL = b"_bingsu_call --width 80\n"


def pinned_roots(trusted):
    """The four root words init pins for `trusted` (same rule as test_init_words)."""
    run_root = os.path.realpath(trusted["XDG_RUNTIME_DIR"] + "/bingsu")
    st = os.stat(run_root)
    return {
        b"--runtime-root=": f"--runtime-root={st.st_dev}:{st.st_ino}:{run_root}".encode(),
        b"--config-root=": b"--config-root=" + os.path.realpath(trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--state-root=": b"--state-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu").encode(),
        b"--log-root=": b"--log-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu/log").encode(),
    }


def export_line(shell, values):
    """One command line that exports every value (no value holds a quote)."""
    if shell == "fish":
        return "; ".join(f"set -gx {k} '{v}'" for k, v in values.items())
    return "export " + " ".join(f"{k}='{v}'" for k, v in values.items())


# 이것을 실패시키는 것: hook이 프롬프트 때 환경 변수로 뿌리를 만드는 것
# (예: `@CONFIG_ROOT@` 대신 "--config-root=$XDG_CONFIG_HOME/bingsu", 세 셸 각각).
@pytest.mark.parametrize("shell", SHELLS)
def test_prompt_time_environment_never_reaches_hook_args(tmp_path, shell):
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    init = tmp_path / f"init.{shell}"
    init.write_bytes(inst.init(shell, trusted))
    inst.use_fake(minimal_record())
    want = pinned_roots(trusted)
    repo = tmp_path / "repo"
    repo.mkdir()
    canary = short_dir() / "c"
    hostile = {k: f"{repo}/{k.lower()} dir $(touch {canary})" for k in HOSTILE_VARS}
    s = Session(shell, trusted)
    s.run(f"source {init}")
    before = len(inst.calls())
    s.run(export_line(shell, hostile))
    s.run("true")
    s.run("true")
    s.close()
    calls = inst.calls()
    assert len(calls) - before >= 2, f"{shell}: fewer than two prompts after the change"
    assert not canary.exists(), f"{shell}: a hostile value was executed"
    for argv in calls:
        assert not any(str(repo).encode() in a for a in argv), (shell, argv)
        for flag, word in want.items():
            assert [a for a in argv if a.startswith(flag)] == [word], (shell, flag, argv)


SPAWN = re.compile(r"^(\d+)\s+(?:<\.\.\. (?:clone3?|fork|vfork) resumed>|(?:clone3?|fork|vfork)\().*\)\s+=\s+(\d+)")


def tree(lines, roots):
    """Every pid and tid started, directly or not, by one of `roots`:
    the return values of clone, clone3, fork and vfork."""
    edges = {}
    for l in lines:
        m = SPAWN.match(l)
        if m and int(m.group(2)) > 0:
            edges.setdefault(m.group(1), set()).add(m.group(2))
    seen, todo = set(), list(roots)
    while todo:
        p = todo.pop()
        if p not in seen:
            seen.add(p)
            todo.extend(edges.get(p, ()))
    return seen


# 이것을 실패시키는 것: prompt가 환경 변수로 경로를 정해 그 아래를 여는 것(M3a부터 실제로 여는 코드가 생김),
# 그 접근을 bingsu가 띄운 스레드나 자식 프로세스에서 하는 것.
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace (Linux) not available")
def test_prompt_binary_touches_nothing_under_repo(tmp_path):
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    script = inst.init("bash", trusted)
    repo = tmp_path / "repo"
    repo.mkdir()
    env = dict(trusted, **{k: str(repo / k.lower()) for k in HOSTILE_VARS})
    f = tmp_path / "s.bash"
    f.write_bytes(script + b"\n" + CALL)
    trace = tmp_path / "trace"
    r = subprocess.run(["strace", "-f", "-qq", "-e", "trace=%file,%desc,%process", "-o", str(trace)]
                       + SHELL_CMD["bash"] + [str(f)], env=env, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    lines = trace.read_text(errors="replace").splitlines()
    roots = {l.split()[0] for l in lines if "execve(" in l and str(inst.exe) in l}
    assert roots, "bingsu was not executed"
    pids = tree(lines, roots)
    hits = [l for l in lines if l.split()[0] in pids and str(repo) in l]
    assert hits == [], hits[:5]
