"""X-06: at prompt time HOME, USER, XDG_* and BINGSU_LOG point into a
repository; the hook must still pass only the roots pinned by init, and the
binary (with every process and thread it starts) must touch nothing under
the repository."""
import os
import platform
import hashlib
import json
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path
import zlib

import pytest

# 이것을 실패시키는 것: 여러 테스트 모음의 conftest 이름 충돌로 통합 수집이 실패하는 것.
from shell_support import ROOT, SHELL_CMD, Install, minimal_record, real_bin, short_dir, trusted_env
from pty_session import Session

sys.path.insert(0, str(ROOT / "tools/fsbudget"))
from fsbudget.strace_parse import EXIT_EVENT, parse as parse_trace
from trace_support import (
    CALL,
    COLLECT_ATTEMPTS,
    COLLECT_WARMUP_MAX,
    COMMAND_WARMUP_MAX,
    FRONT_CASES,
    FRONT_CHUNK,
    HELPER_STAGES,
    HelperStageFixture,
    MARKER_ATTEMPTS,
    OPENS,
    QUOTED,
    RETURN,
    SPAWNS,
    SYSCALL,
    SYSTEM_PATHS,
    TARGET_LINKS_MAX,
    TEMPLATES,
    ADAPTER_ROWS,
    admission_deferred,
    allowed,
    args_of,
    assert_collection_trace,
    bash_prompt_script,
    call_paths,
    check_front_capture,
    check_helper_capture,
    child_strace_argv,
    collect_ready,
    command_ready,
    deadline_shape,
    entry_of,
    folder_outside_repository,
    front_attempt_plan,
    helper_processes,
    helper_stage_evidence,
    init_collector_exe,
    is_root,
    judge_marker_attempt,
    marker_shape,
    passwd_seeks,
    run_allowlist,
    session_cgroup_parent,
    stage_warmup,
    strip_trace_times,
    target_links,
    tree,
    wait_helpers,
    warm_until,
)

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
HOSTILE_VARS = ["HOME", "USER", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CACHE_HOME", "BINGSU_LOG"]


# 이것을 실패시키는 것: 제품 prompt가 시험 전용 --collector-fixture 인자를 받아들이는 것.
def test_product_rejects_collector_fixture():
    base = [str(real_bin()), "prompt", "--ctx", "1", "--record", "B1", "--width", "80"]
    argv = subprocess.run(base + ["--collector-fixture"], capture_output=True, check=True)
    assert b"error:bad-args" in argv.stdout


def pinned_roots(trusted):
    """The root words and original config spelling init pins for `trusted` (same rule as test_init_words)."""
    run_root = os.path.realpath(trusted["XDG_RUNTIME_DIR"] + "/bingsu")
    st = os.stat(run_root)
    return {
        b"--runtime-root=": f"--runtime-root={st.st_dev}:{st.st_ino}:{run_root}".encode(),
        b"--git-global-home=": b"--git-global-home=" + os.fsencode(trusted.get("HOME", "")),
        b"--git-global-xdg=": b"--git-global-xdg=" + os.fsencode(trusted.get("XDG_CONFIG_HOME", "")),
        b"--config-root-written=": b"--config-root-written=" + (trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--config-root=": b"--config-root=" + os.path.realpath(trusted["XDG_CONFIG_HOME"] + "/bingsu").encode(),
        b"--state-root=": b"--state-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu").encode(),
        b"--log-root=": b"--log-root=" + os.path.realpath(trusted["XDG_STATE_HOME"] + "/bingsu/log").encode(),
    }


def export_line(shell, values):
    """One command line that exports every value (no value holds a quote)."""
    if shell == "fish":
        return "; ".join(f"set -gx {k} '{v}'" for k, v in values.items())
    return "export " + " ".join(f"{k}='{v}'" for k, v in values.items())


# 이것을 실패시키는 것: hook이 프롬프트 때 환경 변수로 뿌리 또는 설정 작성 경로를 만드는 것
# (예: `@CONFIG_ROOT@` 대신 "--config-root=$XDG_CONFIG_HOME/bingsu", 세 셸 각각).
@pytest.mark.parametrize("shell", SHELLS)
def test_prompt_time_path_environment_does_not_change_pinned_root_args(tmp_path, shell):
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


# 이것을 실패시키는 것: 순서를 잊고 execve 전의 edge(셸이 띄운 자식)나 root pid의 execve 전 줄(셸 몫)까지 bingsu에 붙이는 것,
# 부모의 반환 줄보다 먼저 찍힌 자식 줄을 빼는 것, argv에 exe 문자열이 든 다른 execve를 root로 보는 것.
def test_tree_follows_trace_order():
    trace = [
        '100 clone(child_stack=NULL, flags=CLONE_CHILD_SETTID|SIGCHLD) = 101',
        '101 openat(AT_FDCWD, "/repo/x", O_RDONLY) = 3',
        '100 openat(AT_FDCWD, "/shell/rc", O_RDONLY) = 3',
        '200 execve("/usr/bin/env", ["/usr/bin/env", "/pinned/bin/bingsu"], 0x1 /* 1 vars */) = 0',
        '100 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "prompt"], 0x1 /* 1 vars */) = 0',
        '100 clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0}, 88 <unfinished ...>',
        '102 openat(AT_FDCWD, "/early", O_RDONLY) = 3',
        '100 <... clone3 resumed>) = 102',
        '102 statx(AT_FDCWD, "/pinned/root/x", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = 0',
    ]
    pids, scoped = tree(trace, "/pinned/bin/bingsu")
    assert pids == {"100", "102"}
    assert not any('"/repo/x"' in l or '"/shell/rc"' in l for l in scoped)
    assert any('"/early"' in l for l in scoped)


# 이것을 실패시키는 것: => 주석이 든 clone3의 자식·스레드 또는 부모 반환 전 자식 기록을 prompt 범위에서 빼는 것.
@pytest.mark.parametrize("split", [False, True], ids=["whole", "split"])
def test_tree_follows_clone3_struct_updates(split):
    before = '10 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_PARENT_SETTID, exit_signal=SIGCHLD}'
    after = ' => {parent_tid=[11]}, 88) = 11'
    child = '11 openat(AT_FDCWD, "/early", O_RDONLY) = 3'
    spawn = ([before + ' <unfinished ...>', child, '10 <... clone3 resumed>' + after]
             if split else [before + after, child])
    lines = ['10 execve("/pinned/bin/bingsu", ["/pinned/bin/bingsu", "prompt"], []) = 0',
             *spawn,
             '11 clone3({flags=CLONE_VM|CLONE_FILES|CLONE_THREAD|CLONE_PARENT_SETTID, exit_signal=0}'
             ' => {parent_tid=[12]}, 88) = 12',
             '12 close(3</early>) = 0']
    pids, scoped = tree(lines, "/pinned/bin/bingsu")
    assert pids == {"10", "11", "12"}
    assert scoped == lines


def named_paths(line):
    """The paths a syscall line names: execve its pathname only (argv
    follows), any other call every quoted string (both paths of linkat,
    renameat2, symlinkat; a symlink's target text is checked too, which only
    rejects more). Resumed lines carry results, not arguments, and are skipped.
    A result buffer printed on the call line (the target of readlinkat, for
    one) is checked as a path too, which errs toward a false failure; when
    M3a reads links under the roots, narrow that syscall to its pathname
    (the first quoted string)."""
    m = SYSCALL.match(line)
    if not m:
        return []
    if m.group(1) == "write":
        return []  # traced for the syscall table; its quoted text is the record
    found = QUOTED.findall(line)
    return found[:1] if m.group(1) == "execve" else found


DIRFD_CALL = re.compile(r'^(\d+)\s+(\w+)\((\d+|AT_FDCWD), "((?:[^"\\]|\\.)*)"')


def resolve_dirfds(lines):
    """Each line with the paths it names, a name relative to a descriptor
    resolved against the path that descriptor was opened with (the
    runtime root walk opens "/" and then one name at a time with
    `openat(fd, name, O_NOFOLLOW)`). Descriptors are tracked per process
    from the `= N` of each open; a relative name under a descriptor this
    trace did not see opened stays relative and fails. Close/dup/fork fd
    lifetimes and unfinished/resumed calls are outside this small decoder's
    fixtures. The live gate uses assert_prompt_trace_budget with strace -y
    descriptor paths and the shared parser; test_prompt_trace_budget covers
    inherited/duplicated descriptors and unfinished/resumed calls."""
    fds = {}
    out = []
    for line in lines:
        paths = named_paths(line)
        m = DIRFD_CALL.match(line)
        # An empty name with AT_EMPTY_PATH is the descriptor itself (allowed below).
        if m and paths and paths[0] and m.group(3) != "AT_FDCWD" and not paths[0].startswith("/"):
            base = fds.get((m.group(1), m.group(3)))
            if base is not None:
                paths = [base.rstrip("/") + "/" + paths[0]] + paths[1:]
        r = RETURN.search(line)
        if m and m.group(2) in OPENS and r and paths:
            fds[(m.group(1), r.group(1))] = paths[0]
        out.append((line, paths))
    return out


# 이것을 실패시키는 것: 기술자 기준 상대 이름을 풀지 않는 것(걷기가 상대 경로로 거부됨), 모르는 기술자 기준 이름을
# 통과시키는 것, 뿌리 위 폴더를 폴더가 아닌 열기에도 허용하는 것, 기술자를 프로세스마다 따로 세지 않는 것,
# AT_EMPTY_PATH의 빈 이름을 기술자 아래의 새 이름으로 붙이는 것.
def test_dirfd_walk_resolves_and_stays_under_the_roots():
    roots = ["/run/user/1/bingsu"]
    lines = [
        '7 openat(AT_FDCWD, "/", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 3',
        '7 openat(3, "run", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 4',
        '7 openat(4, "user", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 5',
        '7 openat(5, "1", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 6',
        '7 openat(6, "bingsu", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY|O_PATH) = 7',
        '7 openat(7, "snapshot", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 8',
    ]
    lines.append('7 newfstatat(8, "", {st_mode=S_IFREG|0600, st_size=64, ...}, AT_EMPTY_PATH) = 0')
    got = resolve_dirfds(lines)
    assert [p for _, p in got][-2] == ["/run/user/1/bingsu/snapshot"]
    assert [p for _, p in got][-1] == [""]
    assert all(allowed(p, l, "/x/bingsu", roots) for l, ps in got for p in ps)
    bad = [
        '7 openat(AT_FDCWD, "/run", O_RDONLY|O_CLOEXEC) = 9',  # a folder above, not as a folder
        '7 openat(4, "other", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 10',  # beside the root
        '7 openat(42, "x", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 11',  # an fd never seen opened
        '8 openat(7, "snapshot", O_RDONLY|O_NOFOLLOW|O_CLOEXEC) = 12',  # fd 7 of another process
    ]
    for b in bad:
        (line, paths), = resolve_dirfds(lines + [b])[-1:]
        assert not all(allowed(p, line, "/x/bingsu", roots) for p in paths), b


def allowlist_capture(base, case):
    """One fresh, traced prompt of the allowlist test in `base`."""
    from types import SimpleNamespace
    base.mkdir(parents=True)
    global_present = case == "global-present"
    inst = Install(base)
    trusted = trusted_env(base)
    trusted["HOME"] = str(base / "home-t")
    global_inputs = tuple(str(path) for path in (
        Path(trusted["XDG_CONFIG_HOME"]) / "git/config", Path(trusted["HOME"]) / ".gitconfig",
        Path(trusted["XDG_CONFIG_HOME"]) / "git/ignore",
    ))
    # Exact init-time locations, independent of the hostile prompt environment.
    # 이것을 실패시키는 것: 각 전역 입력을 같은 뿌리의 다른 파일로 바꾸거나 쓰기 플래그로 여는 것.
    if global_present:
        for path in global_inputs:
            source = Path(path)
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(".DS_Store\n" if source.name == "ignore" else "")
    if case == "no-collection":
        config = Path(trusted["XDG_CONFIG_HOME"]) / "bingsu/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(TEMPLATES["plain"])
        config.chmod(0o600)
    script = inst.init("bash", trusted)
    collector_exe = init_collector_exe(script)
    # A hand-made repository (the test images have no git): an unborn branch.
    repo = base / "repo"
    for sub in ("objects", "refs/heads"):
        (repo / ".git" / sub).mkdir(parents=True)
    (repo / ".git/HEAD").write_text("ref: refs/heads/main\n")
    env = dict(trusted, **{k: str(repo / k.lower()) for k in HOSTILE_VARS})
    f = base / "s.bash"
    f.write_bytes(script + b"\n" + CALL)
    if case != "no-collection":
        warm = subprocess.run(SHELL_CMD["bash"] + [str(f)], env=env, cwd=repo, capture_output=True, timeout=60)
        assert warm.returncode == 0, warm.stderr
        wait_helpers(base)
    trace = base / "trace"
    # Trace all calls; call_paths selects pathname arguments, not quoted data buffers.
    r = subprocess.run(["strace", "-f", "-q", "-y", "-s", "65536", "-e", "trace=all", "-o", str(trace)]
                       + SHELL_CMD["bash"] + [str(f)], env=env, cwd=repo, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    wait_helpers(base)
    real = os.path.realpath(repo)
    return SimpleNamespace(
        lines=trace.read_text(errors="replace").splitlines(), trace=trace,
        # execve names the pinned path (the symlink); its target never shows.
        exe=str(inst.front()), entry="dedicated" if inst.dedicated else "cli", helper_exe=str(inst.exe),
        collector_exe=collector_exe, global_inputs=global_inputs,
        global_present=global_present, collectors=int(case != "no-collection"),
        pinned=[os.path.realpath(trusted[k] + sub) for k, sub in
                (("XDG_RUNTIME_DIR", "/bingsu"), ("XDG_CONFIG_HOME", "/bingsu"),
                 ("XDG_STATE_HOME", "/bingsu"), ("XDG_STATE_HOME", "/bingsu/log"))],
        roots=[real, real + "/.git"],
        # Stage A reads HEAD in every repository it finds (the recorded
        # release capture reads 21 bytes from it), so a non-empty read
        # proves collection reached this repository.
        evidence=[real + "/.git/HEAD"],
        platform=(platform.machine(), "musl" if elf_facts(real_bin())[1] is None else "gnu"))


# A reduction of a deferred capture (Linux, CPU contention): the helper checks
# the collector pin, takes the GC lock, commits the catalog and exits 0; in
# other captures it also opened its collection store first.
DEFERRED_HELPER = [
    '7 execve("/b/bin/bingsu", ["/b/bin/bingsu", "__refresh-v1"], 0x1 /* 0 vars */) = 0',
    '7 openat(20</t/release>, "bingsu-collect", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = 21</t/release/bingsu-collect>',
    '7 pread64(21</t/release/bingsu-collect>, "\\177ELF", 64, 0) = 64',
    '7 openat(15</b/run-t/bingsu>, ".collections.gc.lock", O_RDONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600) = 3</b/run-t/bingsu/.collections.gc.lock>',
    '7 renameat(15</b/run-t/bingsu>, ".collections.catalog.stage", 15</b/run-t/bingsu>, ".collections.catalog") = 0',
    '7 exit_group(0) = ?',
    '7 +++ exited with 0 +++',
]
COLLECTOR = "/t/release/bingsu-collect"


# 이것을 실패시키는 것: admission_deferred가 collector가 뜬 회차, pin 확인이 없는 helper, GC 잠금이 없는 helper,
# 0 아닌 종료를 미룸으로 보는 것, 수집 저장소를 연 뒤의 미룸을 놓치는 것.
def test_admission_deferred_shape():
    assert admission_deferred(DEFERRED_HELPER, COLLECTOR)
    spawned = DEFERRED_HELPER[:4] + [
        '8 execve("/t/release/bingsu-collect", ["/t/release/bingsu-collect", "__collect-v1"], 0x1 /* 0 vars */) = 0',
        '7 openat(15</b/run-t/bingsu/contexts-v2/collections-v1>, "s", O_RDONLY|O_DIRECTORY) = 9</b/x>',
    ] + DEFERRED_HELPER[4:]
    assert not admission_deferred(spawned, COLLECTOR)  # the passing shape: a collector ran
    collector_only = DEFERRED_HELPER[:4] + [spawned[4]] + DEFERRED_HELPER[4:]
    assert not admission_deferred(collector_only, COLLECTOR)
    no_pin = [l for l in DEFERRED_HELPER if "bingsu-collect" not in l]
    assert not admission_deferred(no_pin, COLLECTOR)
    no_read = [l for l in DEFERRED_HELPER if "pread64" not in l]
    assert not admission_deferred(no_read, COLLECTOR)
    no_gc = [l for l in DEFERRED_HELPER if "gc.lock" not in l]
    assert not admission_deferred(no_gc, COLLECTOR)
    failed_gc = [l.replace("= 3</b/run-t/bingsu/.collections.gc.lock>", "= -1 EAGAIN (Resource temporarily unavailable)")
                 for l in DEFERRED_HELPER]
    assert not admission_deferred(failed_gc, COLLECTOR)
    # Deferred after opening its collection store: still this shape.
    store = DEFERRED_HELPER[:4] + ['7 openat(15</b/run-t/bingsu/contexts-v2>, "collections-v1", O_RDONLY) = 9</b/c>'] + DEFERRED_HELPER[4:]
    assert admission_deferred(store, COLLECTOR)
    killed = DEFERRED_HELPER[:-1] + ["7 +++ exited with 75 +++"]
    assert not admission_deferred(killed, COLLECTOR)
    assert not admission_deferred(DEFERRED_HELPER[1:], COLLECTOR)  # no helper exec at all
    two = DEFERRED_HELPER + [l.replace("7 ", "9 ", 1) for l in DEFERRED_HELPER]
    assert not admission_deferred(two, COLLECTOR)  # two helpers: not one deferred round


# deadline_shape가 미뤄진 수집 꼴을 알아본다. 이것을 실패시키는 것: deadline_shape에서 그 꼴을 빼는 것, collector를
# 기대하지 않는 칸(no-collection)도 그 꼴로 다시 도는 것.
def test_deadline_shape_names_a_deferred_collection():
    from types import SimpleNamespace
    front = ['6 execve("/b/bin/bingsu-prompt", ["/b/bin/bingsu-prompt", "prompt"], 0x1 /* 1 var */) = 0',
             '6 vfork() = 7']
    cap = SimpleNamespace(lines=front + DEFERRED_HELPER, exe="/b/bin/bingsu-prompt", collector_exe=COLLECTOR,
                          collectors=1)
    assert deadline_shape(cap) == "admission-deferred"
    assert deadline_shape(SimpleNamespace(**{**vars(cap), "collectors": 0})) is None


# 이것을 실패시키는 것: 미뤄진 수집을 상한 없이 다시 도는 것, 미룸이 아닌 실패를 다시 도는 것.
def test_run_allowlist_caps_deferred_retries():
    calls = []

    def capture(attempt):
        calls.append(attempt)
        return attempt

    def judge(cap, shape=None):
        if shape is None:
            raise AssertionError("collector count")

    with pytest.raises(pytest.fail.Exception, match="deferred 4 times"):
        run_allowlist(capture, judge=judge, shape_of=lambda cap: "admission-deferred", limit=12)
    assert calls == [1, 2, 3, 4]
    calls.clear()
    with pytest.raises(AssertionError, match="collector count"):
        run_allowlist(capture, judge=judge, shape_of=lambda cap: None, limit=12)
    assert calls == [1]


# 이것을 실패시키는 것: prompt가 시스템 경로와 init이 박은 네 뿌리 밖의 경로를 건드리는 것 —
# 상대 경로("x", Path::exists 포함), 환경 변수가 가리키는 폴더(repo 아래), 현재 폴더, 그 접근을 스레드나 자식 프로세스에서 하는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("case", ["no-collection", "global-missing", "global-present"])
def test_prompt_binary_names_only_allowed_system_paths_and_pinned_roots(tmp_path, case):
    """Every path argument of every traced call (open, stat, rename, link,
    ...) of the binary and its threads and children. SYSTEM_PATHS was
    observed on Debian and Ubuntu glibc (aarch64, the three test images) and
    takes the loader paths of Fedora (/lib64), Arch (/usr/lib) and Alpine
    (/lib/ld-musl-*.so.1) by its shape; the CI musl build on x86_64
    also spawns the fixed helper before its filter. NixOS and Guix
    (/nix/store, /gnu/store) are not covered and fail here.

    The collector count is fixed per case. no-collection compiles a template
    without {dir} or {git}: the helper selects no request and starts none.
    The git cases run one untraced prompt first, so the traced prompt's
    helper finds a published snapshot and starts exactly one collector in
    the case's own repository (whether a first prompt after init has time
    left to admit one varies with the machine). Its calls after the request
    are audited against that repository's two roots. Each attempt keeps its
    own folder (attempt-N) and trace."""
    assert shutil.which("strace"), "Linux path gate must execute strace"
    if case != "no-collection":
        # Under strace a debug helper often runs out of time before it admits
        # the collector (measured: 4 of 6 traced prompts started none), so
        # the exact-one cells run on release only (shell.yml filter-calls).
        require_release_helper(real_bin())
    run_allowlist(lambda attempt: allowlist_capture(tmp_path / f"attempt-{attempt}", case))


TABLE_SYSCALLS = {r[0] for r in ADAPTER_ROWS if r[0] != "-"}


# 이것을 실패시키는 것: 필터 뒤에 표에 없는 호출이 필요한 것(이 환경의 할당자·unwind가 부르는 호출을 표에서 빠뜨림),
# 정상 프롬프트에서 호출이 EPERM으로 거부되는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("pwd", ["/srv/p", "/" + "a/" * 32767])
@pytest.mark.parametrize("entry", ["bingsu", "bingsu-prompt"])
def test_calls_after_the_filter_are_in_the_table(tmp_path, pwd, entry):
    """Every call the prompt makes after its seccomp filter is installed
    (strace -e trace=all, from the PR_SET_SECCOMP line on) is a row of the
    table, and none is refused: the table is complete for this libc and
    allocator. LD_PRELOAD in the environment (an allocator under test) is
    passed through."""
    assert shutil.which("strace"), "Linux syscall gate must execute strace"
    # Both entries compile the same filter; each binary links its own libc
    # and allocator code, so each is traced.
    install = Install(tmp_path)
    exe = str(install.exe if entry == "bingsu" else install.prompt)
    trace = tmp_path / "trace"
    args = [exe, "prompt", "--ctx", "1", "--record", "B1", "--width", "100", "--runtime-root=1:2:/r",
            "--shell", "bash", "--pwd", pwd, "--status", "1"]
    env = {"PATH": os.environ["PATH"], **({"LD_PRELOAD": os.environ["LD_PRELOAD"]} if "LD_PRELOAD" in os.environ else {})}
    r = subprocess.run(["strace", "-f", "-qq", "-e", "trace=all", "-o", str(trace)] + args,
                       env=env, capture_output=True, timeout=60)
    assert r.returncode == 0 and r.stdout.endswith(b"\x1e") and b"degraded:sandbox" not in r.stdout, r
    lines = trace.read_text(errors="replace").splitlines()
    at = next(i for i, l in enumerate(lines) if "PR_SET_SECCOMP" in l)
    after = [l for l in lines[at + 1:] if SYSCALL.match(l)]
    names = {SYSCALL.match(l).group(1) for l in after}
    assert names <= TABLE_SYSCALLS, sorted(names - TABLE_SYSCALLS)
    refused = [l for l in after if "= -1 EPERM" in l]
    assert refused == [], refused[:5]


# Command stages (M6 C4): one config unit run through the relay, on a screen
# without dir or git. The miss runs it (no cache: every round); the hit finds
# the warm-up's result inside its cache time; not_run keeps the unit off the
# screen. All three take the session lock and reclaim (both rounds have nothing to run). Paths the
# helper reaches in these rounds, and why:
#   /proc/self/cgroup: the atomic path's input, the delegated cgroup subpath;
#     the helper path rules admit it under /proc/self/.
#   /sys/fs/cgroup/<own>, its cgroup.procs, the session parent bingsu-cmd-*
#     and its unit cgroups: the helper's reclaim under the session lock
#     (CMD-CGROUP-PROCS); uname is the 5.14 check before them.
#   /proc/self/fd, /dev/null (three opens) and chdir("/"): the supervisor
#     spawn's fd census and its posix_spawn child before exec, as the
#     collector spawn (miss only).
#   /usr and /usr/bin walks and the target's header pread: exec_path's
#     PATH and target checks (C2; miss only).
#   the collection catalog, GC lock, store folders, collection.lock,
#     command and .command.stage: the response store and the
#     GC after publication (hit reads the response only).
COMMAND_UNIT = "[segment.\"custom/probe\"]\nkind='command'\ncommand=['/usr/bin/true']\n"
COMMAND_SCREEN = "[layout.line1]\nleft=['char']\n[layout.line2]\nleft=[{shown}'char']\n"
TEMPLATES["command_miss"] = COMMAND_UNIT + COMMAND_SCREEN.format(shown="'custom/probe', ")
TEMPLATES["command_hit"] = COMMAND_UNIT + "cache='30s'\n" + COMMAND_SCREEN.format(shown="'custom/probe', ")
TEMPLATES["command_not_run"] = COMMAND_UNIT + COMMAND_SCREEN.format(shown="")
# Builtin stages (D3a): the collect stage's screen (dir and git) and one
# builtin language segment, with no config unit. The probe runs node (the
# version stub) once its identity changed since the warm-up; the fast path
# decides python from pyenv's selection with nothing to run.
BUILTIN_SCREEN = "[layout.line1]\nleft=['dir','git','char']\n[layout.line2]\nleft=['{language}','char']\n"
TEMPLATES["builtin_probe"] = BUILTIN_SCREEN.format(language="node")
TEMPLATES["builtin_fast"] = BUILTIN_SCREEN.format(language="python")
# The unit drawn only from 120 columns: the prompts here are 80 wide.
TEMPLATES["command_wide"] = (COMMAND_UNIT + "cache='30s'\n" + COMMAND_SCREEN.format(shown="")
                             + "[layout.when.wide]\nmin_cols=120\n[layout.when.wide.line2]\nleft=['custom/probe','char']\n")
# C5: an env segment drawn on the only line (front strace case `env-segment`).
TEMPLATES["env_segment"] = "[segment.\"custom/aws\"]\nkind='env'\nenv='AWS_PROFILE'\n[style]\ntemplate='BASE {custom/aws} {char}'\n"
# 64 bands of 4 columns, the first key widest, each drawing 600 text bytes: width
# 80 selects a variant past INDEX's chunk, with more variants after it.
TEMPLATES["bands"] = "".join(f"[layout.when.b{i:02}]\nmin_cols={(64 - i) * 4}\nmax_cols={(64 - i) * 4 + 3}\n"
                             f"[layout.when.b{i:02}.style]\ntemplate='{'x' * 600} {{char}}'\n" for i in range(64))


def elf_facts(path):
    """(has .symtab, PT_INTERP) of a 64-bit little-endian ELF executable."""
    import struct
    data = Path(path).read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", ("64-bit little-endian ELF", path)
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
    interp = None
    for i in range(phnum):
        kind, _, offset, _, _, size = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if kind == 3:
            interp = data[offset:offset + size].rstrip(b"\0").decode()
    names_at = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 0x18)[0]
    sections = set()
    for i in range(shnum):
        name = struct.unpack_from("<I", data, shoff + i * shentsize)[0]
        sections.add(data[names_at + name:data.index(b"\0", names_at + name)].decode())
    return ".symtab" in sections, interp


def require_release_helper(exe):
    # Budget gates count a release build (followups 106): the release profile
    # strips symbols and a debug build keeps .symtab (and extra fd checks).
    # 이것을 실패시키는 것: debug 바이너리로 이 게이트를 돌리는 것(.symtab이 남아 있어 실패).
    symtab, interp = elf_facts(exe)
    assert not symtab, (f"{exe} keeps .symtab: helper call budgets are measured on the stripped release profile; "
                        "build with --release")
    # The product's musl builds are static (no PT_INTERP); its glibc builds are not.
    return "musl" if interp is None else "gnu"


# 이것을 실패시키는 것: 명령 단계를 2회 고정으로 되돌리는 것, 상한 10을 지우는 것,
# command_not_run을 응답 대기로 바꾸는 것, collect·내장 단계의 대기를 명령 응답으로 바꾸는 것.
@pytest.mark.parametrize("stage, appears, want", [
    ("command_miss", 4, 4), ("command_hit", 1, 2), ("command_miss", None, COMMAND_WARMUP_MAX),
    ("command_not_run", None, 2), ("command_not_run", 1, 2), ("publish", None, 1),
    ("collect", 5, 5), ("builtin_probe", None, COLLECT_WARMUP_MAX)])
def test_stage_warmup_waits_per_stage(tmp_path, stage, appears, want):
    store, runtime = tmp_path / "store", tmp_path / "runtime"
    ran = []

    def prompt():
        ran.append(1)
        # Each stage's own readiness only: a command response alone leaves no
        # breaker, a collection store alone no command response.
        if appears is not None and len(ran) == appears:
            (store / "collections-v1/a/store").mkdir(parents=True)
            if stage.startswith("command_"):
                (store / "collections-v1/a/store/command").write_bytes(b"")
            else:
                (runtime / "collection-control-v1/sessions/s").mkdir(parents=True)
                (runtime / "collection-control-v1/sessions/s/breaker").write_bytes(b"")
    assert stage_warmup(stage, prompt, store, runtime) == want == len(ran)


# 이것을 실패시키는 것: 명령 응답이 없어도 데우기가 끝났다고 보는 것, 다른 이름의 파일을 응답으로 보는 것.
def test_command_warm_needs_a_command_response(tmp_path):
    store = tmp_path / "store"
    assert not command_ready(store)
    (store / "collections-v1/a/store").mkdir(parents=True)
    (store / "collections-v1/a/store/response").write_bytes(b"")
    assert not command_ready(store)
    (store / "collections-v1/a/store/command").write_bytes(b"")
    assert command_ready(store)


# 이것을 실패시키는 것: 저장소나 breaker 하나만 있어도 데우기가 끝났다고 보는 것.
def test_collect_warm_needs_both_store_and_breaker(tmp_path):
    store, runtime = tmp_path / "store", tmp_path / "runtime"
    ready = lambda: collect_ready(store, runtime)
    assert not ready()
    (store / "collections-v1/a/store").mkdir(parents=True)
    assert not ready()
    (runtime / "collection-control-v1/sessions/s").mkdir(parents=True)
    (runtime / "collection-control-v1/sessions/s/breaker").write_bytes(b"")
    assert ready()
    (store / "collections-v1/a/store").rmdir()
    assert not ready()


# 이것을 실패시키는 것: warm_until이 least 전에 멈추거나, ready를 보지 않거나, most를 넘는 것.
def test_warm_until_waits_for_ready_within_bounds():
    def run(ready_at, least, most):
        calls = []
        ran = warm_until(lambda: calls.append(1), lambda: len(calls) >= ready_at, least=least, most=most)
        assert ran == len(calls)
        return ran
    assert run(ready_at=1, least=3, most=10) == 3       # ready at once: still the least
    assert run(ready_at=5, least=3, most=10) == 5       # waits past the least for ready
    assert run(ready_at=99, least=3, most=10) == 10     # never ready: stops at most
    assert run(ready_at=1, least=1, most=1) == 1


def pinned_prompt_argv(script, exe, pwd, seq, env, base):
    """Ask A2's real hook for its expanded invocation without running product code.

    Bash permits an unquoted pathname as a function name with `function`.
    Shadow only this fixture's pinned executable; init and _bingsu_call stay
    intact. The NUL-delimited result preserves empty and quoted arguments.
    """
    import shlex
    exe = str(exe)
    # Fixture install paths are plain words; never interpolate shell syntax.
    assert re.fullmatch(r"[/a-zA-Z0-9_.-]+", exe), exe
    output = base / "prompt-argv.bin"
    output.unlink(missing_ok=True)
    probe = (f"function {exe} {{ printf '%s\\0' {shlex.quote(exe)} \"$@\" > "
             f"{shlex.quote(str(output))}; }}\n").encode()
    path = base / "prompt-argv.bash"
    path.write_bytes(bash_prompt_script(script, pwd, seq, probe))
    result = subprocess.run(SHELL_CMD["bash"] + [str(path)], env=env,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    wire = output.read_bytes()
    assert wire.endswith(b"\0"), wire
    argv = [os.fsdecode(word) for word in wire[:-1].split(b"\0")]
    assert argv[:2] == [exe, "prompt"], argv
    return argv


# 이것을 실패시키는 것: init의 다른 root pin 행 수에 의존하거나 실제 prompt argv를 누락하는 것.
def test_pinned_prompt_argv_from_real_init(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    # Real init emits shell-encoded pins; exercise quotes and a physical newline.
    env["XDG_CONFIG_HOME"] += " ' quoted\nconfig"
    script = inst.init("bash", env)
    (tmp_path / "init.bash").write_bytes(script)
    argv = pinned_prompt_argv(script, inst.front(), tmp_path, 7, env, tmp_path)
    assert inst.dedicated
    assert argv[:8] == [str(inst.prompt), "prompt", "--ctx", "1", "--record", "B1", "--width", "80"]
    assert argv[argv.index("--pwd") + 1] == str(tmp_path)
    assert argv[argv.index("--seq") + 1] == "8"
    assert re.fullmatch(r"[0-9a-f]{32}", argv[argv.index("--session") + 1])
    for flag, word in pinned_roots(env).items():
        assert [os.fsencode(a) for a in argv if os.fsencode(a).startswith(flag)] == [word]
    assert "--collector-exe=" + init_collector_exe(script) in argv
    assert "--helper-exe=" + str(inst.exe) in argv
    # Extra flag-bearing lines (such as init's exported command roots) cannot
    # select a different invocation or make extraction ambiguous.
    extra = b"\n# --runtime-root=decoy --config-root=decoy\n"
    assert pinned_prompt_argv(script + extra * 3, inst.front(), tmp_path, 7, env, tmp_path) == argv
    # Compare every word with the same hook calling the existing fake binary.
    inst.use_fake(minimal_record())
    path = tmp_path / "actual-prompt.bash"
    path.write_bytes(bash_prompt_script(script, tmp_path, 7))
    result = subprocess.run(SHELL_CMD["bash"] + [str(path)], env=env, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert inst.calls() == [[os.fsencode(word) for word in argv[1:]]]


def remove_fixture(fixture):
    """The fixture's base and the folders it made outside it."""
    shutil.rmtree(fixture.base, ignore_errors=True)
    # Test doubles of the fixture carry neither.
    for extra in (getattr(fixture, "tools", None), getattr(fixture, "shell_root", None)):
        if extra:
            shutil.rmtree(extra, ignore_errors=True)


def test_folder_outside_repository_refuses_a_checkout(tmp_path):
    base = tmp_path / "checkout"
    base.mkdir(mode=0o755)
    for folder in (tmp_path, *tmp_path.parents):
        if os.stat(folder).st_mode & 0o022:
            pytest.skip(f"a group/other-writable ancestor here: {folder}")
    tools = folder_outside_repository(base, "t-")
    assert tools.parent == base.resolve() and tools.is_dir() and tools.name.startswith("t-")
    # A .git in an ancestor, not only in the parent itself.
    (base / ".git").mkdir()
    sub = base / "sub"
    sub.mkdir(mode=0o755)
    with pytest.raises(AssertionError, match="inside a git repository"):
        folder_outside_repository(sub, "t-")
    (base / ".git").rmdir()
    base.chmod(0o775)
    with pytest.raises(AssertionError, match="writable"):
        folder_outside_repository(base, "t-")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("stage", list(HELPER_STAGES))
def test_live_helper_calls_match_stage_formula(stage, helper_stage_evidence):
    """GATE-FS-HELPER.1: exact stages; collect prefix exact and tail <=.

    Every attempt is checked before retrying, including exit 75. At least one
    of at most COLLECT_ATTEMPTS fresh collect fixtures must actually rename a response.
    """
    assert shutil.which("strace"), "the helper stage gate must execute strace"
    libc = require_release_helper(real_bin())
    import json
    # Traces live outside the product fixture: cleanup must never erase a
    # failed attempt or earlier deadline attempts. --basetemp locates these
    # artifacts for the controller; each invocation needs its own basetemp.
    collecting = stage == "collect" or stage.startswith("builtin_")
    for attempt in range(1, (COLLECT_ATTEMPTS if collecting else 1) + 1):
        artifacts = helper_stage_evidence / stage / f"attempt-{attempt}"
        artifacts.mkdir(parents=True)
        trace = artifacts / "trace.strace"
        evidence = {"stage": stage, "attempt": attempt, "collector_exit": None,
                    "published": None, "phase_counts": None, "phase_expected": None,
                    "trace": str(trace)}
        fixture = None
        try:
            fixture = HelperStageFixture(stage)
            result = fixture.prompt(trace)
            evidence["prompt_exit"] = result.returncode
            (artifacts / "stdout").write_bytes(result.stdout)
            (artifacts / "stderr").write_bytes(result.stderr)
            lines = trace.read_text(errors="replace").splitlines()
            published = check_helper_capture(stage, lines, str(fixture.inst.exe), fixture.collector,
                                             fixture.plan(libc), evidence=evidence)
            evidence["publish_attempt"] = attempt if published else None
            if not collecting or published:
                return
        except BaseException as error:
            evidence["failure"] = str(error)
            raise
        finally:
            (artifacts / "attempt.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
            print(f"helper stage evidence: {artifacts}")
            if fixture is not None:
                wait_helpers(fixture.base)
                remove_fixture(fixture)
    pytest.fail(f"collect: zero publishes across all {COLLECT_ATTEMPTS} checked attempts; evidence: {helper_stage_evidence / stage}")


# The helper's E_n cap, pinned independently from the product source.
HELPER_E_N_CAP = 1024


# 이것을 실패시키는 것: 제품 AXIS_CAPS의 E_n을 바꾸고 이 게이트의 고정값은 그대로 두는 것.
def test_helper_e_n_cap_matches_product_constant():
    source = (ROOT / 'crates/bingsu/src/commands/io_meter.rs').read_text().replace('\r\n', '\n')
    caps = re.search(r'pub\(crate\) const AXIS_CAPS: AxisCaps = AxisCaps \{(.*?)\};', source, re.S)
    assert caps and re.search(r'\be_n: ([\d_]+),', caps[1])[1].replace('_', '') == str(HELPER_E_N_CAP)


HELPER_B_CAP = 2 * 1024 * 1024
KIB256 = 256 * 1024


def write_private(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".new")
    pending.write_bytes(data)
    pending.chmod(0o600)
    pending.replace(path)


def held_recheck(call, held):
    """Whether `call` rechecks retained evidence: fstat of a held descriptor,
    statx or newfstatat of a held descriptor itself (empty name, AT_EMPTY_PATH)
    or of one held name relative to a held folder descriptor. A lookup by path
    (AT_FDCWD, or a name with a slash) is not."""
    m = re.match(r'(\d+)<([^<>]*)>(?:, "([^"]*)")?', call.args)
    if call.name not in ("fstat", "statx", "newfstatat") or not m:
        return False
    base, name = m[2], m[3]
    if call.name == "fstat":
        return name is None and base in held
    if name == "":
        return "AT_EMPTY_PATH" in call.args and base in held
    return name is not None and "/" not in name and base in held and f"{base}/{name}" in held


def held_chain(fixture):
    config = Path(os.path.realpath(fixture.config / "config.toml"))
    return {str(p) for p in [config, *config.parents]}


def axis_cap_case(axis, fixture):
    """Make `fixture`'s config cross `axis`; return (paths the helper must stop
    touching, the crossing call finder, the call kinds still allowed after it)."""
    root = os.path.realpath(fixture.config)
    plain = TEMPLATES["plain"].encode()
    if axis == "E_n":
        conf_d = fixture.config / "conf.d"
        conf_d.mkdir(mode=0o700)
        # 1,100 names and `.`, `..`: the first listing alone passes the cap.
        for i in range(1100):
            (conf_d / f"n{i:04}.txt").write_bytes(b"")
        listing = f"<{os.path.realpath(conf_d)}>"

        def crossing(calls):
            reads = [c for c in calls if c.name == "getdents64" and listing in c.args]
            assert reads, "the helper never listed conf.d"
            seen = 0
            for c in reads:
                m = re.search(r"/\* (\d+) entries \*/", c.args)
                assert m, ("getdents64 without an entry count", c)
                seen += int(m[1])
                if seen > HELPER_E_N_CAP:
                    assert c is reads[-1], ("listing went on past the batch holding the cap", len(reads))
                    return c
            pytest.fail(f"the listing never passed the cap: {seen} entries")
        return [root], crossing, None
    if axis.startswith("R-"):
        # Entries that pass the lexical check and are walked before R counts the
        # next one. The four root names take R first (config.toml, config.json,
        # config.local.toml, config.local.json): the 253rd entry stops with no
        # call of its own, the 252nd is the last walked.
        written = {"R-missing": [f"parts/none-{i:03}.toml" for i in range(255)],
                   "R-duplicate": ["parts/same.toml"] * 255, "R-cycle": ["config.toml"] * 255}[axis]
        (fixture.config / "parts").mkdir(mode=0o700)
        write_private(fixture.config / "parts/same.toml", b"")
        refs = ", ".join(f'"{r}"' for r in written)
        write_private(fixture.config / "config.toml", f"extends = [{refs}]\n".encode() + plain)
        last = {"R-missing": '"none-251.toml"', "R-duplicate": '"same.toml"', "R-cycle": '"config.toml"'}[axis]

        def crossing(calls):
            walked = [c for c in calls if c.name in ("openat", "newfstatat", "statx") and last in c.args]
            assert walked, f"the helper never walked {last}"
            missing = {m[0] for c in calls if (m := re.search(r'"none-\d+\.toml"', c.args))}
            opens = sum(c.name == "openat" for c in walked)
            # The root reads config.toml twice more than the list names it.
            assert (len(missing), opens) == {"R-missing": (252, 0), "R-duplicate": (0, 252), "R-cycle": (0, 254)}[axis]
            return walked[-1]
        held = held_chain(fixture) | {root + "/parts", root + "/parts/same.toml"}
        return [root], crossing, lambda c: held_recheck(c, held)
    if axis == "R":
        # config.toml, the absent config.json, config.local.toml and
        # config.local.json, and 255 refused entries: 259.
        refs = ", ".join(f'"$THEME_{i}"' for i in range(255))
        write_private(fixture.config / "config.toml", f"extends = [{refs}]\n".encode() + plain)
        config = f"<{os.path.realpath(fixture.config / 'config.toml')}>"

        def crossing(calls):
            reads = [c for c in calls if c.name == "read" and config in c.args]
            assert reads, "the helper never read config.toml"
            return reads[-1]
        # The refused entry has no call of its own. Between the read and it the
        # trusted file's retained evidence is checked again: its descriptors
        # and the names that bind them (config.toml and the folders above it).
        return [root], crossing, lambda c: held_recheck(c, held_chain(fixture))
    assert axis == "B"
    themes = fixture.base / "themes"
    refs = [themes / f"t{i}.toml" for i in range(8)]
    text = ("extends = [" + ", ".join(f'"{os.path.realpath(themes)}/t{i}.toml"' for i in range(8)) + "]\n").encode() + plain
    write_private(fixture.config / "config.toml", text)
    for r in refs:
        write_private(r, b"[style\n" + b"x" * (KIB256 - 7))
    last = f"<{os.path.realpath(refs[-1])}>"
    # The eighth theme gets one byte past what B has left, never its whole size.
    room = HELPER_B_CAP - len(text) - 7 * KIB256

    def crossing(calls):
        reads = [c for c in calls if c.name == "read" and last in c.args]
        assert reads, "the helper never read the eighth theme"
        got = sum(int(c.ret) for c in reads if c.ret.isdigit())
        assert got == room + 1, ("bytes read from the crossing theme", got, room + 1)
        return reads[-1]
    return [root, os.path.realpath(themes)], crossing, None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("axis", ["E_n", "R", "R-missing", "R-duplicate", "R-cycle", "B"])
def test_live_helper_stops_config_io_past_an_axis_cap(axis, tmp_path):
    """GATE-FS-HELPER.2: a config past one axis cap ends the release helper's
    round closed. After the call that crosses the cap (the conf.d batch holding
    raw entry cap + 1, the last read of config.toml before a lexically refused
    extends entry, the last walk before a missing, duplicate or cyclic one, the
    read of the theme that passes 2 MiB) no config source call follows, and
    snapshot, last-good, marker and sequence keep their bytes.

    이것을 실패시키는 것: 목록 항목을 걸러낸 뒤에만 세거나 세지 않는 것(목록이 끝까지 돌고 재목록이 따름), 거부된
    extends 항목을 R에서 빼는 것(재검증 걷기가 따름), 없는·중복·순환 항목을 걷기 뒤에 세거나 세지 않는 것(253번째가
    걸어짐), B 읽기를 남은 여유 + 1바이트로 묶지 않는 것, 상한을 넘은 뒤
    남은 뿌리 후보나 재검증을 이어 가는 것, 상한 초과에서 표식·snapshot·sequence를 쓰는 것.
    """
    assert shutil.which("strace"), "the helper axis gate must execute strace"
    require_release_helper(real_bin())
    fixture = HelperStageFixture("unchanged")
    try:
        names = ("snapshot", "last-good", "marker", "sequence")
        before = {n: (fixture.store / n).read_bytes() for n in names if (fixture.store / n).exists()}
        assert {"snapshot", "marker", "sequence"} <= set(before), sorted(before)
        watched, crossing, allowed = axis_cap_case(axis, fixture)
        trace = tmp_path / "trace.strace"
        fixture.prompt(trace)
        wait_helpers(fixture.base)
        after = {n: (fixture.store / n).read_bytes() for n in names if (fixture.store / n).exists()}
        assert after == before, "an exceeded cap changed the store"
        calls = parse_trace(trace.read_text(errors="replace"))
        assert not calls.errors, calls.errors[:5]
        at = crossing(calls)
        later = [c for c in calls[at.index + 1:] if c.name not in ("close", "exit_group")
                 and not (allowed and allowed(c)) and any(path in c.args for path in watched)]
        assert not later, ("config source calls after the cap", later[:5])
    finally:
        wait_helpers(fixture.base)
        remove_fixture(fixture)


# 이것을 실패시키는 것: 제품 READ_CHUNK를 바꾸고 fixture 메타데이터는 그대로 두는 것.
def test_front_chunk_matches_product_constant():
    source = (ROOT / 'crates/bingsu-core/src/snapshot.rs').read_text().replace('\r\n', '\n')
    match = re.search(r'pub const READ_CHUNK: usize = (\d+) \* (\d+);', source)
    assert match and int(match[1]) * int(match[2]) == FRONT_CHUNK


def snapshot_layout(data, width):
    """(front, compiled length, end of the variant selected at width), from the
    file's bytes and the wire layout, without the product's decoder."""
    import struct
    body = int.from_bytes(data[76:80], 'little')
    c = bytes(data[192:192 + body])
    common, count = struct.unpack_from('<II', c, 12)
    index = 20 + common
    at = 20

    def option(form, size):
        nonlocal at
        at += 1
        if not c[at - 1]:
            return None
        at += size
        return struct.unpack_from(form, c, at - size)[0]
    bands, at = [None] * int.from_bytes(c[at:at + 4], 'little'), at + 4
    for i in range(len(bands)):
        bands[i] = option('<H', 2), option('<H', 2), option('<i', 4)
    length = int.from_bytes(c[at:at + 4], 'little')
    order = struct.unpack_from(f'<{length}I', c, at + 4)
    assert length == len(bands) and count == length + 1
    band = next((i for i in order if (bands[i][0] or 0) <= width <= (0xffff if bands[i][1] is None else bands[i][1])), None)
    offset, size = struct.unpack_from('<II', c, index + (0 if band is None else band + 1) * 16)
    return index + count * 16, body, offset + size


@pytest.fixture
def front_capture(request, tmp_path_factory):
    """Use A2's init/warm-up/trace harness; hold its publication lock while corrupting."""
    import fcntl
    import json
    from dataclasses import asdict
    from fsbudget.formula import front_body_bytes
    libc = require_release_helper(real_bin())
    assert shutil.which('strace'), 'front gate must execute strace'
    case = getattr(request, 'param', 'normal')
    artifacts = tmp_path_factory.getbasetemp() / 'front-evidence' / request.node.name
    artifacts.mkdir(parents=True)
    evidence = {'case': case, 'chunk': FRONT_CHUNK, 'arch': platform.machine(), 'libc': libc}
    fixture = None
    lock = None
    try:
        config = {'selected-band': 'bands', 'env-segment': 'env_segment'}.get(case, 'plain')
        # The shipped front: bingsu-prompt. The fallback entry's calls after
        # the filter are held to the table by test_calls_after_the_filter_are_in_the_table.
        fixture = HelperStageFixture('unchanged', config=config, entry="dedicated")
        lock = (fixture.store / 'snapshot.lock').open('rb')
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = bytearray((fixture.store / 'snapshot').read_bytes())
        body = int.from_bytes(data[76:80], 'little')
        metadata = int.from_bytes(data[80:84], 'little')
        # 이것을 실패시키는 것: metadata 없는 fixture로 TrustMetadata 0 읽기를 공허하게 증명하는 것.
        assert metadata > 0 and len(data) == 64 + 128 + body + metadata
        last = fixture.store / 'last-good'
        last.write_bytes(data)
        last.chmod(0o600)
        front, _, variant_end = snapshot_layout(data, 80)
        read = front_body_bytes(front, body, variant_end, FRONT_CHUNK)
        through_index = min(read, -(-front // FRONT_CHUNK) * FRONT_CHUNK)
        if case == 'selected-band':
            # 이것을 실패시키는 것: 고른 변종이 색인 청크 안이거나 구획 끝이라 버리기·조기 종료를 증명하지 못하는 fixture.
            assert through_index < variant_end < body, (front, variant_end, body)
        if case == 'checksum-last-good':
            data[160] ^= 1
        elif case == 'body-limit':
            limit = 16 * 1024 * 1024 + 1
            data[60:64] = (128 + limit).to_bytes(4, 'little')
            data[76:80] = limit.to_bytes(4, 'little')
            data = data[:192 + body] + bytearray(limit - body) + data[192 + body:]
        elif case == 'header-only':
            data[0] ^= 1
        (fixture.store / 'snapshot').write_bytes(data)
        attempts = front_attempt_plan(case, read, through_index)
        evidence.update(attempts=[asdict(a) for a in attempts], body=body, metadata=metadata)
        trace = artifacts / 'trace.strace'
        if case == 'env-segment':
            # C5: the env segment's value comes from the environment the
            # prompt already holds, so the calls equal the normal case's.
            fixture.env['AWS_PROFILE'] = 'dev-acct'
        result = fixture.prompt(trace)
        if case == 'env-segment':
            # The hook keeps the record in shell variables; the prompt's write
            # of it is in the trace. Only that write counts: the environment
            # frame and execve also carry the value. 이것을 실패시키는 것: env segment 값을 그리지 않는 것(호출
            # 비교가 공허해짐).
            records = [line for line in trace.read_text().splitlines()
                       if re.search(r'\bwrite\(1<[^>]*>, "B1\\0?37', line)]
            assert records and all('dev-acct' in line for line in records), records
        (artifacts / 'stdout').write_bytes(result.stdout)
        (artifacts / 'stderr').write_bytes(result.stderr)
        pinned = [os.path.realpath(Path(fixture.env[key]) / 'bingsu')
                  for key in ('XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME')]
        lines = trace.read_text().splitlines()
        assert_dedicated_front(lines, fixture.inst)
        yield lines, str(fixture.inst.front()), pinned, fixture.store, attempts, evidence
    except BaseException as error:
        evidence['failure'] = str(error)
        raise
    finally:
        (artifacts / 'attempt.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if lock is not None:
            lock.close()
        if fixture is not None:
            wait_helpers(fixture.base)
            remove_fixture(fixture)


# 이것을 실패시키는 것: TrustMetadata 길이 추가, last-good 뒤 현재 사본 재읽기, 사본별 머리/prefix 읽기 생략.
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux strace runtime gate')
@pytest.mark.parametrize('front_capture', FRONT_CASES, indirect=True)
def test_live_front_attempts_match_axis_c(front_capture):
    lines, exe, pinned, store, attempts, evidence = front_capture
    check_front_capture(lines, exe, pinned, store, attempts, arch=evidence['arch'], libc=evidence['libc'], evidence=evidence)


# 이것을 실패시키는 것: FrontDecoder의 end에 TrustMetadata 길이를 더하는 것.
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux strace runtime gate')
def test_front_never_reads_trust_metadata_section(front_capture):
    lines, exe, pinned, store, attempts, evidence = front_capture
    check_front_capture(lines, exe, pinned, store, attempts, arch=evidence['arch'], libc=evidence['libc'], evidence=evidence)


@pytest.fixture
def child_capture(tmp_path):
    # 이것을 실패시키는 것: debug 바이너리 또는 strace 없는 host를 live PASS로 세는 것.
    if sys.platform != "linux":
        pytest.skip("Linux release strace gate; native Linux run required")
    # 이것을 실패시키는 것: if real_bin().parent.name != "release" 조건을 제거하거나 반전하는 변이.
    if real_bin().parent.name != "release":
        pytest.skip("child-count measurement requires release")
    # 이것을 실패시키는 것: assert shutil.which("strace"), "required live tracing tool is missing" 조건을 제거하거나 반전하는 변이.
    assert shutil.which("strace"), "required live tracing tool is missing"

    def capture(template="{dir}{git}{char}", invalid=False, name=None, timestamps=False, redraw=False):
        # `name` keeps a retried attempt's evidence in its own folder.
        base = tmp_path / (name or str(len(list(tmp_path.iterdir()))))
        base.mkdir(parents=True)
        # Reuse A2's real hook, advancing session sequence and untraced warm-up.
        # A cold admission under strace may defer before it can spawn a worker.
        fixture = HelperStageFixture("unchanged" if template == "{char}" else "collect",
                                     template=template, entry="dedicated")
        try:
            return capture_prompt(fixture, base, invalid, timestamps, redraw)
        finally:
            wait_helpers(fixture.base)
            shutil.rmtree(fixture.base)
            remove_fixture(fixture)

    def capture_prompt(fixture, base, invalid, timestamps, redraw):
        marker = fixture.store / "marker"
        wire = bytearray(marker.read_bytes())
        # 이것을 실패시키는 것: assert wire[:8] == b"BNGMRK02" and len(wire) == 208 조건을 제거하거나 반전하는 변이.
        assert wire[:8] == b"BNGMRK02" and len(wire) == 208
        # 이것을 실패시키는 것: if invalid 조건을 제거하거나 반전하는 변이.
        if invalid:
            wire[12] = 2
            crc = 0xffffffff
            for byte in b"bingsu-marker-v2\0" + wire[:176]:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
            wire[176:180] = (crc ^ 0xffffffff).to_bytes(4, "little")
            pending = marker.with_suffix(".b1")
            pending.write_bytes(wire)
            pending.chmod(0o600)
            pending.replace(marker)
        evidence = base / "child-count.strace"
        # Expand A2's exact hook without tracing bash or running a prompt.
        # A2 increments fixture.seq before setting the hook's pre-call counter;
        # use that same next counter so capture cannot replay the last warm-up.
        argv = pinned_prompt_argv(fixture.script, fixture.inst.front(), fixture.pwd,
                                  fixture.seq + 1, fixture.env, base)
        assert "--collector-exe=" + fixture.collector in argv, argv
        if redraw:
            argv = [*argv, "--redraw"]
        # What a full trace judgment needs after the fixture is gone.
        env, repo = fixture.env, os.path.realpath(fixture.pwd)
        (base / "context.json").write_text(json.dumps({
            "exe": str(fixture.inst.front()), "entry": "dedicated" if fixture.inst.dedicated else "cli",
            "helper_exe": str(fixture.inst.exe), "collector_exe": fixture.collector,
            "pinned": [os.path.realpath(env[k] + sub) for k, sub in
                       (("XDG_RUNTIME_DIR", "/bingsu"), ("XDG_CONFIG_HOME", "/bingsu"),
                        ("XDG_STATE_HOME", "/bingsu"), ("XDG_STATE_HOME", "/bingsu/log"))],
            "global_inputs": [str(Path(env["XDG_CONFIG_HOME"]) / "git/config"), str(Path(env["HOME"]) / ".gitconfig"),
                              str(Path(env["XDG_CONFIG_HOME"]) / "git/ignore")],
            "roots": [repo, repo + "/.git"],
            "platform": [platform.machine(), "musl" if elf_facts(real_bin())[1] is None else "gnu"]}, indent=1) + "\n")
        result = subprocess.run(child_strace_argv(evidence, argv, timestamps),
                                cwd=fixture.pwd, env=fixture.env, capture_output=True, timeout=60)
        (base / "stdout").write_bytes(result.stdout)
        (base / "stderr").write_bytes(result.stderr)
        # 이것을 실패시키는 것: assert result.returncode == 0, (result.stderr, evidence) 조건을 제거하거나 반전하는 변이.
        assert result.returncode == 0, (result.stderr, evidence)
        text = evidence.read_text()
        trace = parse_trace(strip_trace_times(text) if timestamps else text)
        # 이것을 실패시키는 것: assert not trace.errors, (trace.errors, evidence) 조건을 제거하거나 반전하는 변이.
        assert not trace.errors, (trace.errors, evidence)
        # The entry the hook ran, for the helper rule of the role attribution.
        trace.entry = "dedicated" if fixture.inst.dedicated else "cli"
        return trace, fixture.store, result.stdout
    return capture


# 이것을 실패시키는 것: helper 생략·중복 생성, collector 중복·자식 생성, 쓰기 전용·명령 프로세스 추가.
def test_live_child_count_is_bounded_per_role(child_capture):
    from fsbudget.attribute import role_children
    trace, _, _ = child_capture()
    children = role_children(trace, entry_of(trace))
    # 이것을 실패시키는 것: assert children == {"front": 1, "helper": 1, "collector": 0, "command": 0}, children 조건을 제거하거나 반전하는 변이.
    assert children == {"front": 1, "helper": 1, "collector": 0, "command": 0}, children


# 이것을 실패시키는 것: redraw에서 도우미를 띄우는 것, redraw 앞단이 설정 원본 폴더를 건드리는 것.
def test_redraw_spawns_no_process_and_reads_no_config_source(child_capture, tmp_path):
    from fsbudget.attribute import role_children

    def config_calls(name, trace):
        root = json.loads((tmp_path / name / "context.json").read_text())["pinned"][1]
        # The bytes a read returned do not count: a snapshot quotes its roots.
        def named(c):
            return re.sub(r'"(?:[^"\\]|\\.)*"', '""', c.args) if c.name in {"read", "pread64"} else c.args
        return [c for c in trace if c.name not in {"execve", "execveat"} and root in named(c)]

    trace, _, record = child_capture(name="prompt")
    assert role_children(trace, entry_of(trace))["front"] == 1
    # 양성 대조: 같은 검사가 일반 프롬프트 도우미의 설정 원본 읽기를 본다.
    assert config_calls("prompt", trace)
    trace, _, record = child_capture(name="redraw", redraw=True)
    assert record.startswith(b"B1\x1f") and record.endswith(b"\x1e")
    assert role_children(trace, entry_of(trace)) == {"front": 0, "helper": 0, "collector": 0, "command": 0}
    assert len({c.pid for c in trace}) == 1, "a redraw is one process"
    assert not config_calls("redraw", trace)
    # 이것을 실패시키는 것: 도우미를 띄우지 않는 redraw에서도 환경 파이프를 만드는 것.
    assert not [c for c in trace if c.name in {"pipe", "pipe2"}], "a redraw makes no environment pipe"


BRANCH = "redrawbranch"


def git_repo(path):
    """A hand-made repository with one commit on BRANCH: the test images have no git."""
    def loose(kind, body):
        data = f"{kind} {len(body)}\0".encode() + body
        name = hashlib.sha1(data).hexdigest()
        target = path / ".git/objects" / name[:2] / name[2:]
        target.parent.mkdir(parents=True)
        target.write_bytes(zlib.compress(data))
        return name

    who = b"t <t@t> 0 +0000"
    tree = loose("tree", b"")
    commit = loose("commit", b"tree %s\nauthor %s\ncommitter %s\n\nc\n" % (tree.encode(), who, who))
    (path / ".git/refs/heads").mkdir(parents=True)
    (path / ".git/refs/heads" / BRANCH).write_text(commit + "\n")
    (path / ".git/HEAD").write_text(f"ref: refs/heads/{BRANCH}\n")
    return path


# 이것을 실패시키는 것: redraw가 저장 봉투 값이나 이전 수집 응답을 버리는 것, 새 폭을 쓰지 않는 것.
def test_redraw_renders_new_width_from_same_values(tmp_path):
    # A debug collector is too large to verify inside the helper's CPU limit.
    if real_bin().parent.name != "release":
        pytest.skip("real collection requires release")
    from test_helper_lifecycle import LifetimeSession, poll
    session = LifetimeSession(tmp_path / "s", tag="r")
    session.put("[layout.line1]\nleft=['dir']\nright=['git']\n[layout.line2]\nleft=['duration','char']\nright=[]\n")
    session.init()
    session.wait_quiet()
    repo = git_repo(session.base / "repo")
    stored = ["--status", "3", "--pipestatus", "3", "--duration-ms", "5000", "--jobs", "2"]

    def prompt(width, *extra):
        args = session.prompt_args(repo)
        args[args.index("--width") + 1] = str(width)
        result = session.run(*args, *stored, *extra, timeout=2)
        assert result.returncode == 0 and result.stderr == b"", result
        return result.stdout

    def collected():
        record = prompt(100)
        session.wait_quiet()
        return BRANCH.encode() in record and record

    wide = poll(collected, 20, "the first prompts never collected git")
    assert b"5.0s" in wide
    redraw = prompt(90, "--redraw")
    assert BRANCH.encode() in redraw and b"5.0s" in redraw
    assert redraw != wide, "the new width was not used"
    assert redraw == prompt(90), "a redraw differs from a prompt with the same envelope"
    session.wait_quiet()
    # 이것을 실패시키는 것: 세션의 도우미 집계가 값 자리의 `--redraw`를 플래그로 보는 것.
    before = session._helper_count
    prompt(90, "--redraw")
    assert session._helper_count == before
    prompt(90, "--host", "--redraw")
    assert session._helper_count == before + 1
    session.wait_quiet()


# 이것을 실패시키는 것: worker가 없는 화면에도 collector 생성.
def test_live_no_worker_segment_spawns_zero_collectors(child_capture):
    from fsbudget.attribute import role_children
    trace, _, _ = child_capture("{char}")
    # 이것을 실패시키는 것: assert role_children(trace, entry_of(trace)) == {"front": 1, "helper": 0, "collector": 0, "command": 0} 조건을 제거하거나 반전하는 변이.
    assert role_children(trace, entry_of(trace)) == {"front": 1, "helper": 0, "collector": 0, "command": 0}


def marker_capture(child_capture, tmp_path, invalid, attempt):
    from types import SimpleNamespace
    name = f"{'invalid' if invalid else 'valid'}/attempt-{attempt}"
    trace, _, record = child_capture(invalid=invalid, name=name, timestamps=True)
    text = (tmp_path / name / "child-count.strace").read_text(errors="replace")
    return SimpleNamespace(trace=trace, lines=text.splitlines(), untimed=strip_trace_times(text).splitlines(),
                           context=json.loads((tmp_path / name / "context.json").read_text()),
                           record=record, invalid=invalid)


# 이것을 실패시키는 것: 표식 무효면 worker mask 0.
def test_live_collector_count_ignores_marker_validity(child_capture, tmp_path):
    """Both marker conditions start exactly one collector. Each condition
    must reach that evidence with a record (the invalid one its degraded
    record) in at most MARKER_ATTEMPTS attempts. Only a deadline shape is
    retried, after its own judgment: a trace-proven front deadline, or in the
    valid condition an exit that does not contradict the deadline
    (front_deadline_window). Attempts stay in valid|invalid/attempt-N."""
    for invalid in (False, True):
        run_allowlist(lambda attempt: marker_capture(child_capture, tmp_path, invalid, attempt),
                      judge_marker_attempt, marker_shape, MARKER_ATTEMPTS,
                      label=f"marker {'invalid' if invalid else 'valid'}")


# 이것을 실패시키는 것: 머리 읽기 전에 collector 생성.
def test_live_collector_spawns_after_helper_header_and_marker_reads(child_capture):
    from fsbudget.attribute import first_index, role_children
    trace, store, _ = child_capture()
    # 이것을 실패시키는 것: assert role_children(trace, entry_of(trace))["helper"] == 1 조건을 제거하거나 반전하는 변이.
    assert role_children(trace, entry_of(trace))["helper"] == 1
    assert_child_timing(trace, store)


def assert_child_timing(trace, store):
    from fsbudget.attribute import first_index
    helper_exec = first_index(trace, "helper", lambda c: c.name == "execve" and c.ret == "0", entry_of(trace))
    main = trace[helper_exec].pid
    spawn = first_index(trace, "helper", lambda c: c.pid == main and c.name in SPAWNS
                        and "CLONE_THREAD" not in c.args and re.fullmatch(r"[1-9][0-9]*", c.ret), entry_of(trace))
    # The helper verifies its freshly staged marker by same-fd readback before
    # admission. This is distinct from the front reading the published marker.
    for name, size in (("snapshot", 192), (".marker.stage", 208)):
        read = first_index(trace, "helper", lambda c: c.pid == main and c.name == "read"
                           and args_of(c)[0].endswith("<" + str(store / name) + ">")
                           and c.ret.isdigit() and int(c.ret) >= size, entry_of(trace))
        # 이것을 실패시키는 것: 머리·표식 읽기를 collector 생성 뒤로 옮기는 것.
        assert read < spawn, (name, read, spawn)


# 이것을 실패시키는 것: 앞단의 marker 읽기로 helper 읽기를 대체하거나 읽기 순서·길이를 무시하는 것.
@pytest.mark.parametrize("mutation", ["none", "early", "front-marker", "short-header", "failed-marker"])
def test_child_timing_negative_controls(mutation):
    head = '11 read(3</store/snapshot>, "header", 192) = 192'
    marker = '11 read(4</store/.marker.stage>, "marker", 208) = 208'
    spawn = '11 vfork() = 13'
    # 이것을 실패시키는 것: if mutation == "front-marker" 조건을 제거하거나 반전하는 변이.
    if mutation == "front-marker":
        marker = marker.replace('11 read', '10 read')
    # 이것을 실패시키는 것: elif mutation == "short-header" 조건을 제거하거나 반전하는 변이.
    elif mutation == "short-header":
        head = head.replace('= 192', '= 1')
    # 이것을 실패시키는 것: elif mutation == "failed-marker" 조건을 제거하거나 반전하는 변이.
    elif mutation == "failed-marker":
        marker = marker.replace('= 208', '= -1 EBADF (Bad file descriptor)')
    prefix = ['10 execve("/bin/bingsu", ["/bin/bingsu", "prompt"], []) = 0',
              '10 vfork() = 11',
              '11 execve("/bin/bingsu", ["/bin/bingsu", "__refresh-v1"], []) = 0']
    events = [spawn, head, marker] if mutation == "early" else [head, marker, spawn]
    trace = parse_trace('\n'.join(prefix + events + [
        '13 execve("/bin/bingsu-collect", ["/bin/bingsu-collect", "__collect-v1"], []) = 0']))
    # 이것을 실패시키는 것: if mutation == "none" 조건을 제거하거나 반전하는 변이.
    if mutation == "none":
        assert_child_timing(trace, Path('/store'))
    else:
        with pytest.raises((AssertionError, StopIteration)):
            assert_child_timing(trace, Path('/store'))


# Stored synthetic control: one collector in both traces, only timing differs.
# No product overlay or warm-up is needed to reach the timing assertion.
def test_stored_child_timing_control():
    from fsbudget.attribute import role_children
    fixtures = Path(__file__).parent / 'fixtures'
    passing = parse_trace((fixtures / 'b1-child-timing-passing.strace').read_text())
    moved = parse_trace((fixtures / 'b1-child-timing-before-reads.strace').read_text())
    expected = {"front": 1, "helper": 1, "collector": 0, "command": 0}
    assert role_children(passing, entry_of(passing)) == role_children(moved, entry_of(moved)) == expected
    assert_child_timing(passing, Path('/store'))
    with pytest.raises(AssertionError, match='snapshot'):
        assert_child_timing(moved, Path('/store'))


# Descriptors the real front hands to the helper, and the helper to the collector.
# The shell holds a pipe write end at each of these fds, without CLOEXEC.
SHELL_PIPE_FDS = (3, 4, 5, 6, 7, 8, 9, 1025)
FD_RECORDER = "bingsu-fd-record"
# The shell runs this child right before the prompt and waits for it, so the
# table it reads from /proc is the shell's table at that spawn. strace never
# sees how the fds came to be (pass_fds), so this record is the initial table.
RECORDER = """import json, os, sys
pid = sys.argv[2]
table = {}
for name in os.listdir(f"/proc/{pid}/fd"):
    flags = next(line for line in open(f"/proc/{pid}/fdinfo/{name}") if line.startswith("flags:")).split()[1]
    table[name] = [os.readlink(f"/proc/{pid}/fd/{name}"), bool(int(flags, 8) & 0o2000000)]
json.dump(table, sys.stdout)
"""
# Exit status of the shell fixture when it cannot raise its soft NOFILE above 1025.
NOFILE_BLOCKED = 97


class ShellPipes:
    """One pipe per SHELL_PIPE_FDS slot; the test keeps the read ends.

    The write ends reach bash at fds >= 100 (pass_fds) and the shell moves
    each onto its slot with `exec N>&M M>&-`: a plain redirection, no CLOEXEC."""

    def __init__(self):
        import fcntl
        self.read, self.passed, self.inode = {}, {}, {}
        for slot in SHELL_PIPE_FDS:
            r, w = os.pipe()
            high = fcntl.fcntl(w, fcntl.F_DUPFD_CLOEXEC, 100)
            os.close(w)
            assert high not in SHELL_PIPE_FDS, ("pass-through fd collides with a slot", high)
            self.read[slot], self.passed[slot], self.inode[slot] = r, high, os.fstat(r).st_ino

    def prelude(self, record):
        moves = " ".join(f"{slot}>&{high} {high}>&-" for slot, high in self.passed.items())
        return (f"_b2_n=$(ulimit -Sn)\n"
                f"if [[ $_b2_n != unlimited ]] && (( _b2_n < 1026 )); then ulimit -Sn 1026 || exit {NOFILE_BLOCKED}; fi\n"
                f"exec {moves}\n"
                f"{shlex.quote(sys.executable)} -I -c {shlex.quote(RECORDER)} {FD_RECORDER} $$ > {shlex.quote(str(record))}\n"
                ).encode()

    def close_passed(self):
        for fd in self.passed.values():
            os.close(fd)
        self.passed = {}

    def close(self):
        self.close_passed()
        for fd in self.read.values():
            os.close(fd)
        self.read = {}

    def assert_held(self, initial):
        # 이것을 실패시키는 것: fixture가 파이프를 셸에 넘기지 않거나 CLOEXEC로 두어 공허하게 통과하는 것.
        for slot in SHELL_PIPE_FDS:
            entry = initial.get(slot)
            assert entry and entry.path == f"pipe:[{self.inode[slot]}]" and not entry.cloexec, (
                "the shell must hold this pipe write end without CLOEXEC", slot, entry)


def shell_initial(record):
    import json
    from fsbudget.attribute import FdEntry
    return {int(fd): FdEntry(int(fd), path, cloexec, "inherited")
            for fd, (path, cloexec) in json.loads(Path(record).read_text()).items()}


def shell_fd_capture(stage, tmp_path):
    """(trace from the recorder's spawn on, the shell table there, fixture, pipes)
    for one traced prompt of `stage` through a bash that holds SHELL_PIPE_FDS."""
    from fsbudget.strace_parse import Trace
    assert shutil.which("strace"), "this Linux gate must execute strace"
    require_release_helper(real_bin())
    fixture = HelperStageFixture(stage)
    pipes = ShellPipes()
    try:
        record, trace_path = fixture.base / "fd-record.json", tmp_path / f"{stage}.strace"
        print(f"\nfd capture: {trace_path}")
        fixture.prompt(trace_path, prelude=pipes.prelude(record), pass_fds=tuple(pipes.passed.values()))
        initial = shell_initial(record)
        trace = parse_trace(trace_path.read_text(errors="replace"))
        assert not trace.errors, trace.errors[:5]
        shell = trace.first_pid
        recorder, = {c.pid for c in trace if c.name == "execve" and c.ret == "0" and f'"{FD_RECORDER}"' in c.args}
        spawn, = [c for c in trace if c.pid == shell and c.name in SPAWNS and c.ret.split(" ")[0] == str(recorder)]
    except BaseException:
        wait_helpers(fixture.base)
        remove_fixture(fixture)
        raise
    finally:
        pipes.close()
    after = Trace()
    after.extend(c for c in trace if c.index > spawn.index)
    after.first_pid = shell
    return after, initial, fixture, pipes


def exec_pid(trace, path, verb):
    pids = {c.pid for c in trace if c.name == "execve" and c.ret == "0"
            and c.args.startswith(f'"{path}", ') and f'"{verb}"' in c.args}
    assert len(pids) == 1, ("one exec", path, verb, pids)
    return pids.pop()


def fd_summary(table):
    return {fd: (entry.path, entry.cloexec, entry.origin) for fd, entry in sorted(table.items())}


SPAWNED_DEV_NULL = ("/dev/null", False, "spawn-action")


def check_front_receives_shell_pipes(after, initial, pipes, exe):
    """Non-vacuity: the shell's pipes reach the front's exec, and the front marks each."""
    from fsbudget.attribute import fd_table_at_exec
    pipes.assert_held(initial)
    front = exec_pid(after, exe, "prompt")
    table = fd_table_at_exec(after, front, initial)
    for slot in SHELL_PIPE_FDS:
        assert table.get(slot) == initial[slot], ("the front must start with the shell's pipe", slot, table.get(slot))
    marked = {int(c.args.split("<")[0]) for c in after if c.pid == front and c.name == "fcntl"
              and c.args.endswith(", F_SETFD, FD_CLOEXEC") and c.ret == "0"}
    assert set(SHELL_PIPE_FDS) <= marked, ("the front's F_SETFD loop must mark every shell pipe", sorted(marked))


def helper_fd_table(after, exe, initial):
    """The helper's table at execve: fds 0-2 on the spawn's own /dev/null and
    fd 4 the read end of the front's environment pipe (pipe2 with O_NONBLOCK)."""
    from fsbudget.attribute import fd_table_at_exec
    front = exec_pid(after, exe, "prompt")
    env_pipes = [re.fullmatch(r'\[(\d+)<pipe:\[(\d+)\]>, (\d+)<pipe:\[\2\]>\], O_NONBLOCK\|O_CLOEXEC', c.args)
                 for c in after if c.pid == front and c.name == "pipe2" and c.ret == "0"
                 and c.args.endswith("O_NONBLOCK|O_CLOEXEC")]
    assert len(env_pipes) == 1 and env_pipes[0], ("one front environment pipe", env_pipes)
    inode = env_pipes[0][2]
    helper = fd_summary(fd_table_at_exec(after, exec_pid(after, exe, "__refresh-v1"), initial))
    assert helper == {**{fd: SPAWNED_DEV_NULL for fd in (0, 1, 2)},
                      4: (f"pipe:[{inode}]", False, "spawn-action")}, helper
    return helper


# 이것을 실패시키는 것: 앞단의 fcntl(F_SETFD) 루프를 건너뛰는 것(fd 3–9·1025가 도우미 exec에 남는다),
# fd 2의 addopen을 지우는 것(bash 훅의 2>/dev/null이 경로를 같게 만들어도 출처가 셸 상속이 된다),
# 환경 파이프의 adddup2를 지우는 것(fd 4가 없다), 도우미가 완전한 프레임 뒤에 EOF 읽기를 더 하는 것,
# 도우미가 fd 4를 NSS 뒤에 읽는 것(첫 open보다 늦다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_helper_fds_after_env(tmp_path):
    """GATE-FDS.1: at the helper's execve its table is exactly fds 0-2 on the
    spawn's own /dev/null and fd 4 the front's environment pipe, while the
    shell holds pipe write ends at 3-9 and 1025."""
    after, initial, fixture, pipes = shell_fd_capture("unchanged", tmp_path)
    try:
        exe = str(fixture.inst.exe)
        check_front_receives_shell_pipes(after, initial, pipes, exe)
        inode = helper_fd_table(after, exe, initial)[4][0]
        # the helper reads the whole frame in one read and closes fd 4,
        # before its own first open (the loader's and stack guard's come before
        # main; on the cold init path there is no fd 4).
        helper = exec_pid(after, exe, "__refresh-v1")
        calls = [c for c in after if c.pid == helper and c.index > next(
            e.index for e in after if e.pid == helper and e.name == "execve")]
        on_env = [c for c in calls if args_of(c) and args_of(c)[0] == f"4<{inode}>"]
        front_write, = [c for c in after if c.name == "write" and args_of(c)[0].endswith(f"<{inode}>")]
        assert [(c.name, c.ret) for c in on_env] == [("read", front_write.ret), ("close", "0")], on_env
        first_open = next(c.index for c in calls if c.name in OPENS and not SYSTEM_PATHS.fullmatch(call_paths(c)[0]))
        assert on_env[-1].index < first_open, ("fd 4 is read before the helper opens anything", on_env)
    finally:
        wait_helpers(fixture.base)
        remove_fixture(fixture)


# 이것을 실패시키는 것: 잠금의 adddup2 대상을 5에서 4로 바꾸는 것, collector 복사본을 F_DUPFD(CLOEXEC 없이)로
# 만들고 addclose 루프도 지우는 것(fd 7 이상이 남는다), 앞단 F_SETFD 루프를 건너뛰는 것(도우미 표에서 먼저 실패).
# 복사본 CLOEXEC와 addclose는 서로를 덮는 두 층이라 하나만 지우면 이 시험은 통과한다. addclose 하나는
# collector_process.rs의 spawn_closes_inherited_fds_outside_the_fixed_slots가 잡는다.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_live_collector_holds_only_fixed_fds(tmp_path):
    """GATE-FDS.2: at the collector's execve its table is exactly 0 and 2 on
    /dev/null, 1 the response pipe, 3 the request pipe and 5 the collection
    lock, all from the helper's spawn actions. On Linux there is no fd 6:
    the startup probe fd is macOS-only (collector.rs CollectorProbeFd)."""
    from fsbudget.attribute import fd_table_at_exec
    after, initial, fixture, pipes = shell_fd_capture("collect", tmp_path)
    try:
        exe = str(fixture.inst.exe)
        check_front_receives_shell_pipes(after, initial, pipes, exe)
        helper_fd_table(after, exe, initial)
        collector = fd_summary(fd_table_at_exec(after, exec_pid(after, fixture.collector, "__collect-v1"), initial))
        assert sorted(collector) == [0, 1, 2, 3, 5], collector
        assert collector[0] == collector[2] == SPAWNED_DEV_NULL, collector
        response, request, lock = collector[1], collector[3], collector[5]
        assert re.fullmatch(r"pipe:\[\d+\]", response[0]) and re.fullmatch(r"pipe:\[\d+\]", request[0]), collector
        assert response[0] != request[0], ("response and request are different pipes", collector)
        assert lock[0].endswith("/collection.lock"), collector
        assert response[1:] == request[1:] == lock[1:] == (False, "spawn-action"), collector
    finally:
        wait_helpers(fixture.base)
        remove_fixture(fixture)


def env_prompt(tmp_path, env):
    """One traced prompt of a published fixture with `env` added to the
    shell's environment: (trace, fixture, front pid, helper pid)."""
    require_release_helper(real_bin())
    assert shutil.which("strace"), "this Linux gate must execute strace"
    fixture = HelperStageFixture("unchanged")
    try:
        fixture.env.update(env)
        path = tmp_path / "env.strace"
        fixture.prompt(path)
        wait_helpers(fixture.base)
        trace = parse_trace(path.read_text(errors="replace"))
        assert not trace.errors, trace.errors[:5]
        exe = str(fixture.inst.exe)
        return trace, fixture, exec_pid(trace, exe, "prompt"), exec_pid(trace, exe, "__refresh-v1")
    except BaseException:
        wait_helpers(fixture.base)
        remove_fixture(fixture)
        raise


def env_pipe_of(trace, front):
    """The front's environment pipe: (inode, write calls on it)."""
    pipe, = [c for c in trace if c.pid == front and c.name == "pipe2" and c.args.endswith("O_NONBLOCK|O_CLOEXEC")]
    inode = re.fullmatch(r'\[\d+<(pipe:\[\d+\])>, \d+<\1>\], O_NONBLOCK\|O_CLOEXEC', pipe.args)[1]
    return inode, [c for c in trace if c.pid == front and c.name == "write" and args_of(c)[0].endswith(f"<{inode}>")]


def helper_env_reads(trace, helper, inode):
    return [c for c in trace if c.pid == helper and c.name == "read" and args_of(c)[0] == f"4<{inode}>"]


# 이것을 실패시키는 것: 환경을 도우미 envp로도 넘기는 것(도우미의 로더가 카나리를 올린다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux glibc loader")
def test_ld_preload_not_loaded_into_helper(tmp_path):
    """A shell LD_PRELOAD reaches the front's loader but never the helper's:
    the helper starts with an empty envp and gets the environment as bytes."""
    if require_release_helper(real_bin()) != "gnu":
        pytest.skip("static musl has no dynamic loader to preload into")
    canaries = tmp_path / "canaries"
    canaries.mkdir()
    library = tmp_path / "env-canary.so"
    subprocess.run(["cc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC", f'-DCANARY_DIR="{canaries}"',
                    str(ROOT / "tests/shell/fixtures/env_canary.c"), "-o", str(library)], check=True)
    trace, fixture, front, helper = env_prompt(tmp_path, {"LD_PRELOAD": str(library)})
    try:
        names = sorted(p.name.rsplit("-", 1)[0] for p in canaries.iterdir())
        # Non-vacuity: the shell's LD_PRELOAD reached the front's loader, and the helper ran.
        assert names == ["prompt"], names
        inode, _ = env_pipe_of(trace, front)
        reads = helper_env_reads(trace, helper, inode)
        assert len(reads) == 1 and "LD_PRELOAD=" in reads[0].args, ("the entry still reaches the helper as bytes", reads)
        # Positive control: the same library given to the helper through envp is loaded there.
        direct = subprocess.run([str(fixture.inst.exe), "__refresh-v1", "--ctx", "1", "--record", "B1"],
                                env={"LD_PRELOAD": str(library)}, capture_output=True, timeout=10)
        assert direct.returncode != 0
        assert sorted(p.name.rsplit("-", 1)[0] for p in canaries.iterdir()) == ["__refresh-v1", "prompt"]
    finally:
        remove_fixture(fixture)


# 이것을 실패시키는 것: 도우미가 환경의 XDG_RUNTIME_DIR로 위치를 정하는 것(그 폴더를 연다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_helper_ignores_xdg_runtime_dir_from_env(tmp_path):
    """The environment never decides a location: with XDG_RUNTIME_DIR pointing
    into a repository, the helper names no path under it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    trace, fixture, front, helper = env_prompt(tmp_path, {"XDG_RUNTIME_DIR": str(repo)})
    try:
        inode, writes = env_pipe_of(trace, front)
        reads = helper_env_reads(trace, helper, inode)
        # Non-vacuity: the value reached the helper, as frame bytes.
        assert len(reads) == 1 and f"XDG_RUNTIME_DIR={repo}" in reads[0].args, reads
        # Neither the front nor the helper names the folder outside the frame itself.
        named = [c for c in trace if str(repo) in c.args and c not in reads and c not in writes]
        assert named == [], named
    finally:
        remove_fixture(fixture)


# 이것을 실패시키는 것: 앞단 프레임의 상한 검사를 지우는 것(70 KB 프레임을 쓰고 일부만 들어간다).
# 설정 단위 실행 0은 감독(C2)이 생긴 뒤에 단언한다.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
def test_oversize_env_block_means_no_env(tmp_path):
    """A 70 KB environment: the front writes nothing and the helper reads end
    of file, which is no environment for the round."""
    trace, fixture, front, helper = env_prompt(tmp_path, {"BINGSU_BIG": "x" * (70 * 1024)})
    try:
        inode, writes = env_pipe_of(trace, front)
        assert writes == [], writes
        reads = helper_env_reads(trace, helper, inode)
        assert [c.ret for c in reads] == ["0"], reads
    finally:
        remove_fixture(fixture)


# How long after the shell exits its pipes must reach EOF. The helper lives
# 2 s (helper_limits LIFETIME); a helper holding a pipe keeps it open until then.
SHELL_EOF_WAIT_S = 0.5


# 이것을 실패시키는 것: 앞단의 fcntl(F_SETFD) 루프를 건너뛰는 것(막힌 도우미가 쓰지 않는 파이프를 쥐어
# EOF가 도우미 종료까지 오지 않는다).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux FUSE fixture")
def test_shell_pipe_reaches_eof_while_helper_is_alive(tmp_path):
    """GATE-HELPER-LIFETIME.2: the helper never holds the shell's descriptors.

    The config root sits on a FUSE mount whose daemon is stopped, so the
    prompt's helper waits there. The shell holds pipe write ends at 3-9 and
    1025 and exits right after the prompt: every read end, and the shell's
    stdout and stderr, must reach EOF while that helper is still alive."""
    import select
    import time
    from blocked_mount import blocked_mount
    from shell_support import Blocked
    base = tmp_path / "s"
    base.mkdir(mode=0o700)
    session = {}

    def prepare(mount):
        env = trusted_env(base)
        env["HOME"] = str(base / "home-t")
        os.mkdir(env["HOME"], 0o700)
        env["XDG_CONFIG_HOME"] = str(mount / "cfg")
        config = mount / "cfg" / "bingsu"
        config.mkdir(parents=True, mode=0o700)
        (config / "config.toml").write_text(TEMPLATES["plain"])
        (config / "config.toml").chmod(0o600)
        script = Install(base).init("bash", env)
        wait_helpers(base)
        session.update(env=env, script=script)

    try:
        with blocked_mount(tmp_path / "fuse", prepare=prepare):
            pipes = ShellPipes()
            shell = None
            try:
                record = base / "fd-record.json"
                f = base / "prompt.bash"
                f.write_bytes(bash_prompt_script(session["script"], base, 2, pipes.prelude(record)))
                shell = subprocess.Popen(SHELL_CMD["bash"] + [str(f)], env=session["env"], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         pass_fds=tuple(pipes.passed.values()))
                pipes.close_passed()
                status = shell.wait(timeout=10)
                exited = time.monotonic()
                if status == NOFILE_BLOCKED:
                    raise Blocked("the shell cannot raise its soft NOFILE above 1025")
                pending = {f"fd {slot}": fd for slot, fd in pipes.read.items()}
                pending.update(stdout=shell.stdout.fileno(), stderr=shell.stderr.fileno())
                output = {name: b"" for name in pending}
                while pending and (left := exited + SHELL_EOF_WAIT_S - time.monotonic()) > 0:
                    ready, _, _ = select.select(list(pending.values()), [], [], left)
                    for name, fd in list(pending.items()):
                        if fd in ready:
                            data = os.read(fd, 65536)
                            output[name] += data
                            if not data:
                                del pending[name]
                helpers = helper_processes(base)
                assert not pending, ("no EOF within the wait: something alive holds the shell's descriptors",
                                     sorted(pending), helpers)
                # 이것을 실패시키는 것: 도우미가 이미 끝난 뒤에 EOF를 보고 통과하는 것(막힌 도우미가 없으면 공허하다).
                assert helpers, "the prompt's helper is not alive on the blocked mount: the EOF proves nothing"
                assert status == 0, (status, output["stderr"])
                pipes.assert_held(shell_initial(record))
            finally:
                for pid in helper_processes(base):
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                wait_helpers(base)
                if shell is not None:
                    shell.stdout.close()
                    shell.stderr.close()
                pipes.close()
    except Blocked as error:
        pytest.fail(f"BLOCKED: {error.reason}", pytrace=False)


SESSION_SCRIPT = b": \"${_bingsu_session:=0123456789abcdef0123456789abcdef}\"\n"


def session_parent_name(runtime):
    root = os.stat(runtime)
    key = (root.st_dev.to_bytes(8, "little") + root.st_ino.to_bytes(8, "little") + b"\0"
           + b"0123456789abcdef0123456789abcdef")
    return f"bingsu-cmd-{hashlib.sha256(key).digest()[:16].hex()}"


# 위임된 cgroup에서는 이 세션의 정확한 부모만 원자 경로의 근거다. 이것을 실패시키는 것: 같은 uid의 다른
# bingsu-cmd-* 폴더를 받는 것, 부모가 없는 위임 셀을 best effort로 세는 것, 특권 셀에서 위임 없음을 받는 것,
# 쓸 수 없는 폴더나 읽기 전용 마운트를 위임으로 보는 것, 정확한 이름의 symlink를 부모로 받는 것.
@pytest.mark.parametrize("case", ["exact", "other", "missing", "priv-undelegated", "undelegated",
                                  "read-only", "symlink"])
def test_session_cgroup_parent_needs_this_sessions_parent(case, tmp_path, monkeypatch):
    own, runtime = tmp_path / "own", tmp_path / "runtime"
    own.mkdir()
    runtime.mkdir()
    monkeypatch.delenv("BINGSU_CGROUP_CELL", raising=False)
    if case == "exact":
        (own / session_parent_name(runtime)).mkdir()
        assert session_cgroup_parent(SESSION_SCRIPT, runtime, own) is True
        return
    if case == "other":
        (own / "bingsu-cmd-00112233445566778899aabbccddeeff").mkdir()
    if case == "symlink":
        (tmp_path / "elsewhere").mkdir()
        (own / session_parent_name(runtime)).symlink_to(tmp_path / "elsewhere")
    if case == "read-only":
        # Writable by permission bits, but on a read-only mount: not delegated.
        flags = type("S", (), {"f_flag": os.ST_RDONLY})()
        monkeypatch.setattr(os, "access", lambda *_: True)
        monkeypatch.setattr(os, "statvfs", lambda *_: flags)
        assert session_cgroup_parent(SESSION_SCRIPT, runtime, own) is False
        return
    if case in ("priv-undelegated", "undelegated"):
        monkeypatch.setattr(os, "access", lambda *_: False)
        if case == "undelegated":
            assert session_cgroup_parent(SESSION_SCRIPT, runtime, own) is False
            return
        monkeypatch.setenv("BINGSU_CGROUP_CELL", "priv")
    with pytest.raises(AssertionError):
        session_cgroup_parent(SESSION_SCRIPT, runtime, own)


# 이것을 실패시키는 것: 사용자 줄 뒤에 남은 바이트가 있을 때 seek를 0으로 보는 것, 줄이 버퍼 끝(1024·2048)이나 파일
# 끝일 때 1로 보는 것(줄 끝 < 파일 크기로만 판정), glibc에 musl 항을 주는 것.
def test_passwd_seeks_follow_musl_stdio():
    root = b"root:x:0:0:root:/root:/bin/bash\n"
    rest = b"".join(b"u%d:x:%d:%d::/h:/bin/sh\n" % (i, 1000 + i, 1000 + i) for i in range(60))
    data = root + rest
    assert passwd_seeks("musl", 0, data) == 1                    # root first: the rest is buffered
    last = 1000 + 59
    assert passwd_seeks("musl", last, data) == 0                 # the last line: nothing left
    # A line that ends exactly where a 1 KiB read ends leaves nothing in the
    # buffer even with data after it; one that ends inside the last, partial
    # buffer leaves the rest of it.
    for edge in (1024, 2048):
        line = b"u:x:5:5:" + b"y" * (edge - len(b"u:x:5:5:") - 2) + b":\n"
        assert len(line) == edge
        assert passwd_seeks("musl", 5, line + b"after:x:6:6::/h:/bin/sh\n") == 0, edge
    partial = root + b"p:x:7:7::/h:/bin/sh\n" + b"tail:x:8:8::/h:/bin/sh\n"
    assert len(partial) < 1024
    assert passwd_seeks("musl", 7, partial) == 1                 # ends inside the buffer, data after
    assert passwd_seeks("gnu", 0, data) == 0


# 이것을 실패시키는 것: 링크를 따라가지 않는 것(gnutrue 같은 대상의 hop을 0으로 셈), 다른 폴더·`.`·`..`·고리·끊어진
# 링크·폴더로 끝나는 링크·제품 상한을 넘는 hop을 받는 것.
def test_target_links_count_same_folder_hops(tmp_path):
    (tmp_path / "real").write_bytes(b"x")
    (tmp_path / "mid").symlink_to("real")
    (tmp_path / "name").symlink_to("mid")
    assert target_links(str(tmp_path / "real")) == 0
    assert target_links(str(tmp_path / "name")) == 2
    (tmp_path / "away").symlink_to(tmp_path / "real")
    (tmp_path / "self").symlink_to("self")
    (tmp_path / "a").symlink_to("b")
    (tmp_path / "b").symlink_to("a")
    (tmp_path / "dot").symlink_to(".")
    (tmp_path / "up").symlink_to("..")
    (tmp_path / "broken").symlink_to("missing")
    (tmp_path / "folder").mkdir()
    (tmp_path / "to-folder").symlink_to("folder")
    for shape in ("away", "self", "a", "dot", "up", "broken", "to-folder", "folder"):
        with pytest.raises(AssertionError):
            target_links(str(tmp_path / shape))
    previous = "real"
    for i in range(TARGET_LINKS_MAX + 1):
        (tmp_path / f"h{i}").symlink_to(previous)
        previous = f"h{i}"
    assert target_links(str(tmp_path / f"h{TARGET_LINKS_MAX - 1}")) == TARGET_LINKS_MAX
    with pytest.raises(AssertionError):
        target_links(str(tmp_path / f"h{TARGET_LINKS_MAX}"))


# GATE-FS-FRONT command response shapes (C4b):
# the prompt prefetches `command` with the collection responses before the
# filter and reads it after the filter only when the snapshot draws a command
# segment. A store without the file costs one ENOENT open; a file the snapshot
# does not draw costs its open and facts and one unread close, also when only
# a wider band than this prompt's width draws it (unread_narrow); a drawn one
# adds its header and body reads.
COMMAND_FRONT_SHAPES = ("no_response", "unread", "unread_narrow", "read")


def prompt_execs(lines):
    """The successful execs of a prompt process (argv[1] == "prompt") in a
    strace -f text, as (path, argv0). The parser joins an exec strace split
    into `<unfinished ...>` and `<... execve resumed>` when another process
    printed in between, so the result does not depend on that interleaving."""
    out = []
    for c in parse_trace("\n".join(lines)):
        if c.name == "execve" and c.ret == "0":
            m = re.match(r'"([^"]+)", \["([^"]+)", "prompt"', c.args)
            if m:
                out.append((m[1], m[2]))
    return out


def assert_dedicated_front(lines, inst):
    """The traced prompt is the shipped `bingsu-prompt` front, which init chose."""
    # 이것을 실패시키는 것: front 축 gate가 fallback(`bingsu prompt`) front를 재는 것.
    fronts = prompt_execs(lines)
    assert inst.dedicated and fronts and all(path == str(inst.prompt) for path, _ in fronts), fronts


# 이것을 실패시키는 것: 다른 프로세스의 출력에 갈라진 execve(unfinished … resumed)를 놓치는 것, 실패한 exec이나
# prompt가 아닌 exec을 front로 세는 것.
def test_prompt_execs_survive_a_split_exec_line():
    split = [
        '10 execve("/b/bingsu-prompt", ["/b/bingsu-prompt", "prompt", "--ctx", "1"], 0x1 /* 2 vars */ <unfinished ...>',
        '11 read(3, "x", 1) = 1',
        '10 <... execve resumed>) = 0',
        '12 execve("/b/bingsu-prompt", ["/b/bingsu-prompt", "prompt"], 0x1) = -1 ENOENT (No such file or directory)',
        '13 execve("/b/bingsu", ["/b/bingsu", "__refresh-v1"], 0x2 /* 0 vars */) = 0',
    ]
    assert prompt_execs(split) == [("/b/bingsu-prompt", "/b/bingsu-prompt")]
    whole = ['10 execve("/b/bingsu", ["/b/bingsu", "prompt"], 0x1) = 0']
    assert prompt_execs(whole) == [("/b/bingsu", "/b/bingsu")]


# 이것을 실패시키는 것: init이 형제를 고르지 않은 설치, prompt exec이 없는 trace, bingsu-prompt와 fallback(`bingsu
# prompt`) exec이 섞인 trace 중 하나를 받는 것.
def test_dedicated_front_check_refuses_each_other_shape():
    from types import SimpleNamespace
    dedicated = SimpleNamespace(dedicated=True, prompt=Path("/b/bingsu-prompt"))
    front = '10 execve("/b/bingsu-prompt", ["/b/bingsu-prompt", "prompt"], 0x1) = 0'
    fallback = '20 execve("/b/bingsu", ["/b/bingsu", "prompt"], 0x1) = 0'
    assert_dedicated_front([front], dedicated)
    for inst, lines in [
        (SimpleNamespace(dedicated=False, prompt=Path("/b/bingsu-prompt")), [front]),
        (dedicated, []),
        (dedicated, ['13 execve("/b/bingsu", ["/b/bingsu", "__refresh-v1"], 0x2) = 0']),
        (dedicated, [front, fallback]),
        (dedicated, [fallback]),
    ]:
        with pytest.raises(AssertionError):
            assert_dedicated_front(lines, inst)


def front_calls(lines, exe):
    """The prompt process's calls of a traced prompt and its filter boundary."""
    from fsbudget.strace_parse import Trace
    _, scoped = tree(lines, exe)
    root = int(next(line.split()[0] for line in scoped if is_root(line, exe)))
    parsed = parse_trace("\n".join(scoped))
    assert not parsed.errors, parsed.errors
    front = Trace()
    front.extend(c for c in parsed if c.pid == root and c.name != EXIT_EVENT)
    filters = [c.index for c in front if c.name == "prctl" and "PR_SET_SECCOMP" in c.args and c.ret == "0"]
    assert len(filters) == 1, filters
    return front, filters[0]


# 이것을 실패시키는 것: command 사본을 prefetch에서 빼는 것(no_response의 ENOENT 1이 없음), 그리지 않는 응답을
# 읽는 것(unread에 read가 생김), 넓은 구간에만 있는 command를 좁은 폭에서 읽는 것(unread_narrow에 read가 생김),
# 열어 둔 사본을 닫지 않는 것(unread의 close 1이 없음), 그리는 응답을 끝까지 읽지 않는 것(read의 머리·본문 읽기
# 수가 식과 다름).
@pytest.mark.skipif(sys.platform != "linux", reason="Linux strace runtime gate")
@pytest.mark.parametrize("shape", COMMAND_FRONT_SHAPES)
def test_live_front_command_response_shapes(shape, tmp_path):
    from fsbudget.formula import collection_front_expected
    assert shutil.which("strace"), "the front gate must execute strace"
    require_release_helper(real_bin())
    stage = {"no_response": "collect", "unread": "command_hit", "unread_narrow": "command_hit",
             "read": "command_hit"}[shape]
    fixture = HelperStageFixture(stage, entry="dedicated")
    try:
        if shape in ("unread", "unread_narrow"):
            # The unit stays declared and its response stays; the screen at
            # this width no longer draws it. Publish that snapshot first.
            fixture.put("command_not_run" if shape == "unread" else "command_wide")
            fixture.prompt()
            wait_helpers(fixture.base)
        trace = tmp_path / "trace.strace"
        fixture.prompt(trace)
        wait_helpers(fixture.base)
        lines = trace.read_text(errors="replace").splitlines()
        assert_dedicated_front(lines, fixture.inst)
        front, boundary = front_calls(lines, str(fixture.inst.front()))
        pinned = [os.path.realpath(Path(fixture.env[key]) / "bingsu")
                  for key in ("XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME")]
        cwd = os.fsencode(str(fixture.pwd))
        counts = assert_collection_trace(front, boundary, pinned, cwd, required=True)
        command_opens = [c for c in front if c.name == "openat" and call_paths(c)
                         and call_paths(c)[0].endswith("/store/command")]
        assert len(command_opens) == 1, command_opens
        opened = command_opens[0]
        fd = re.match(r"(\d+)", opened.ret)
        closes = [c for c in front if c.name == "close" and fd and args_of(c)[0].split("<")[0] == fd.group(1)
                  and c.index > opened.index]
        reads = [c for c in front if c.name == "read" and fd and args_of(c)[0].split("<")[0] == fd.group(1)
                 and c.index > opened.index]
        if shape == "no_response":
            assert opened.ret.startswith("-1 ENOENT"), opened
            return
        size = (fixture.response.stat().st_size if hasattr(fixture, "response") else
                next((fixture.store / "collections-v1").glob("*/store/command")).stat().st_size)
        assert fd and closes and closes[0].index > boundary, ("one close after the filter", closes)
        if shape in ("unread", "unread_narrow"):
            assert reads == [], reads
        else:
            assert len(reads) == 1 + -(-(size - 64) // 16_384), (size, reads)
        sizes = {}
        for name in ("response", "previous", "command"):
            files = list((fixture.store / "collections-v1").glob(f"*/store/{name}"))
            sizes[name] = files[0].stat().st_size if files else None
        body = (size - 64,) if shape == "read" else ()
        assert counts == collection_front_expected(3, (sizes["response"], sizes["previous"], sizes["command"]),
                                                   body), counts
    finally:
        wait_helpers(fixture.base)
        remove_fixture(fixture)
