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
RESUMED = re.compile(r"^\d+\s+<\.\.\. ")


def tree(lines, exe):
    """The trace lines of the pinned binary, in trace order: from the
    execve of `exe` on, the lines of its pid and of every pid or tid it
    starts after that (clone, clone3, fork, vfork, resumed lines included).
    Returns (pids, lines). A pid's lines before its execve, and the children
    it started before, belong to the shell, not to bingsu. Pid reuse inside
    one prompt is not tracked (environment assumption)."""
    pids, scoped = set(), []
    for l in lines:
        if not l.strip():
            continue
        pid = l.split()[0]
        if pid not in pids and "execve(" in l and not RESUMED.match(l) and f'"{exe}"' in l:
            pids.add(pid)
        if pid not in pids:
            continue
        scoped.append(l)
        m = SPAWN.match(l)
        if m and int(m.group(2)) > 0:
            pids.add(m.group(2))
    return pids, scoped


# 이것을 실패시키는 것: 순서를 잊고 execve 전의 edge(셸이 띄운 자식)까지 bingsu에 붙이는 것.
def test_tree_follows_trace_order():
    trace = [
        '100 clone(child_stack=NULL, flags=CLONE_CHILD_SETTID|SIGCHLD) = 101',
        '101 openat(AT_FDCWD, "/repo/x", O_RDONLY) = 3',
        '100 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "prompt"], 0x1 /* 1 vars */) = 0',
        '100 clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0}, 88 <unfinished ...>',
        '100 <... clone3 resumed>) = 102',
        '102 statx(AT_FDCWD, "/pinned/root/x", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = 0',
    ]
    pids, scoped = tree(trace, "/pinned/bin/bingsu")
    assert pids == {"100", "102"}
    assert not any('"/repo/x"' in l for l in scoped)


FIRST_PATH = re.compile(r'^\d+\s+(?!<\.\.\.)\w+\([^"]*"((?:[^"\\]|\\.)*)"')
# What the dynamic loader and Rust's start-up name (glibc, observed in the
# three images on 2026-10-05): the loader cache and preload list, the
# libraries, and /proc/self/maps (main-thread stack guard). The static musl
# build names none of them.
SYSTEM_PATHS = re.compile(r"^/etc/ld\.so\.(cache|preload)$|^/(usr/)?lib(64)?/.+\.so(\.\d+)*$|^/proc/self/maps$")


def allowed(path, line, exe, roots):
    """Spec section 5 (front-end prompt opens no file of the current folder
    or repository) and X-06 (only the roots pinned by init). A relative path
    never passes."""
    if path == "" and "AT_EMPTY_PATH" in line:
        return True  # fstat of an fd already open (glibc 2.35, 2.36): names no path
    if path == exe or SYSTEM_PATHS.match(path):
        return True
    return any(path == r or path.startswith(r + "/") for r in roots)


# 이것을 실패시키는 것: prompt가 시스템 경로와 init이 박은 네 뿌리 밖의 경로를 건드리는 것 —
# 상대 경로("x", Path::exists 포함), 환경 변수가 가리키는 폴더(repo 아래), 현재 폴더, 그 접근을 스레드나 자식 프로세스에서 하는 것.
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace (Linux) not available")
def test_prompt_binary_opens_only_system_paths_and_pinned_roots(tmp_path):
    inst = Install(tmp_path)
    trusted = trusted_env(tmp_path)
    script = inst.init("bash", trusted)
    repo = tmp_path / "repo"
    repo.mkdir()
    env = dict(trusted, **{k: str(repo / k.lower()) for k in HOSTILE_VARS})
    f = tmp_path / "s.bash"
    f.write_bytes(script + b"\n" + CALL)
    trace = tmp_path / "trace"
    # %desc is left out: read and write buffers are quoted strings too.
    r = subprocess.run(["strace", "-f", "-qq", "-e", "trace=%file,%process", "-o", str(trace)]
                       + SHELL_CMD["bash"] + [str(f)], env=env, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    # execve names the pinned path (the symlink); its target never shows.
    exe = str(inst.exe)
    pids, scoped = tree(trace.read_text(errors="replace").splitlines(), exe)
    assert pids, "bingsu was not executed"
    pinned = [os.path.realpath(trusted[k] + sub) for k, sub in
              (("XDG_RUNTIME_DIR", "/bingsu"), ("XDG_CONFIG_HOME", "/bingsu"),
               ("XDG_STATE_HOME", "/bingsu"), ("XDG_STATE_HOME", "/bingsu/log"))]
    bad = [l for l in scoped if (m := FIRST_PATH.match(l)) and not allowed(m.group(1), l, exe, pinned)]
    assert bad == [], bad[:5]
