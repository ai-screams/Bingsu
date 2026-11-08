"""Publication-only fixture ledger; admission and sweep have separate phases."""
import pytest
from fsbudget.formula import collection_expected


# 이것을 실패시키는 것: helper의 네 chain/lock 검증이나 same-fd staging 검증을 예산에서 빼는 것.
def test_publication_phase_coefficients():
    assert collection_expected(3, 100, False, False) == {
        "openat": 5, "fstat": 86, "statfs": 32, "read": 2,
        "write": 1, "renameat": 1, "unlinkat": 0, "flock": 0, "fsync": 0,
    }
    base = collection_expected(2, 100, False, False)
    longer = collection_expected(3, 100, False, False)
    assert longer["fstat"] - base["fstat"] == 16
    assert longer["statfs"] - base["statfs"] == 8


# 이것을 실패시키는 것: current 회전의 read/rename 또는 잔여 stage의 unlink를 빼는 것.
def test_rotation_and_recovery_are_helper_work():
    assert collection_expected(3, 262_080, True, True) == {
        "openat": 5, "fstat": 103, "statfs": 36, "read": 19,
        "write": 1, "renameat": 2, "unlinkat": 1, "flock": 0, "fsync": 0,
    }


# 이것을 실패시키는 것: body 상한에 64-byte header를 합산하지 않는 것.
def test_publication_axes_are_bounded():
    for components, body in [(-1, 0), (3301, 0), (3, -1), (3, 262_081)]:
        with pytest.raises(ValueError):
            collection_expected(components, body, False, False)
    for body in [0, 1, 16_384, 16_385, 262_080]:
        assert collection_expected(3, body, False, False)["read"] == 2


# 이것을 실패시키는 것: 앞단의 부재1/정상6(응답·이전·명령 응답)과 O_PATH ACL·16KiB 청크 계수를 바꾸는 것.
def test_front_prefetch_and_read_coefficients():
    from fsbudget.formula import collection_front_expected as front
    assert front(0, (), (), absent=True) == {
        "openat": 1, "fstat": 0, "fstatfs": 0, "fgetxattr": 0, "getxattr": 0, "read": 0}
    assert front(3, (100, 262144, None), (36, 262080)) == {
        "openat": 6, "fstat": 5, "fstatfs": 5, "fgetxattr": 5, "getxattr": 3, "read": 19}
    # A command response opened and read, and one opened and left unread.
    assert front(3, (None, None, 471_082), (471_018,))["read"] == 1 + 29
    assert front(3, (None, None, 1000), ()) == {
        "openat": 6, "fstat": 4, "fstatfs": 4, "fgetxattr": 4, "getxattr": 3, "read": 0}
    for depth in range(3):
        assert front(depth, (), ())["openat"] == depth + 1
    assert front(3, (None, 100, None), (36,))["fstat"] == 4
    for body, reads in [(0, 1), (1, 2), (16384, 2), (16385, 3), (262080, 17)]:
        assert front(3, (body + 64, None, None), (body,))["read"] == reads


# 이것을 실패시키는 것: 잘못된 선취 축이나 총 파일 상한을 허용하는 것.
def test_front_axes_fail_closed():
    from fsbudget.formula import collection_front_expected as front
    for directories, sizes, bodies in [(-1, (), ()), (4, (), ()), (2, (1,), ()),
                                      (3, (1, 2), ()), (3, (1, 2, 3, 4), ()), (3, (-1, 1, 1), ()),
                                      (3, (1, 1, 1), (-1,)), (3, (1, 1, 1), (471_019,)),
                                      (3, (1, 1, 1), (1, 1, 1, 1))]:
        with pytest.raises(ValueError):
            front(directories, sizes, bodies)
    with pytest.raises(ValueError):
        front(1, (), (), absent=True)


@pytest.fixture(scope="module")
def gc_test_binary():
    import json
    import pathlib
    import subprocess
    root = pathlib.Path(__file__).resolve().parents[3]
    build = subprocess.run(
        ["cargo", "test", "-j", "2", "-p", "bingsu", "--test", "collection_store",
         "--no-run", "--message-format=json"], cwd=root, text=True, capture_output=True, check=True)
    binaries = [row["executable"] for line in build.stdout.splitlines()
                if (row := json.loads(line)).get("reason") == "compiler-artifact"
                and row["target"]["name"] == "collection_store" and row.get("executable")]
    assert len(binaries) == 1
    return binaries[0]


# 이것을 실패시키는 것: 실제 catalog checkpoint 비용이 512 ops를 넘거나 큰 catalog 시험이 실행되지 않는 것.
def test_gc_checkpoint_measures_real_phase(gc_test_binary):
    import re
    import subprocess
    run = subprocess.run([gc_test_binary, "--exact", "gc_large_catalog_checkpoint_cost",
                          "--test-threads=1", "--nocapture"], text=True, capture_output=True, check=True)
    assert "1 passed; 0 failed" in run.stdout
    sample = re.search(r"GC_CHECKPOINT bytes=(\d+) ops=(\d+)", run.stderr)
    assert sample, run.stderr
    size, ops = map(int, sample.groups())
    assert 980_000 <= size <= 1_048_576 and 0 < ops <= 512


# 이것을 실패시키는 것: checkpoint에서 목록을 다시 읽거나 checkpoint 예약보다 많은 syscall을 실행하는 것.
def test_gc_checkpoint_linux_syscalls(gc_test_binary, tmp_path):
    import os
    import shutil
    import subprocess
    import sys
    from fsbudget.strace_parse import STRACE_FLAGS, parse
    if sys.platform != "linux" or not shutil.which("strace"):
        if os.environ.get("FSB_REQUIRE_STRACE") == "1":
            pytest.fail("GC checkpoint trace requires a Linux host with strace")
        pytest.skip("BLOCKED: Linux strace host required for actual checkpoint syscalls")
    trace_path = tmp_path / "gc-checkpoint.strace"
    run = subprocess.run(["strace", *STRACE_FLAGS, "-o", str(trace_path),
                          gc_test_binary, "--exact", "gc_large_catalog_checkpoint_cost",
                          "--test-threads=1", "--nocapture"], text=True, capture_output=True, check=True)
    assert "1 passed; 0 failed" in run.stdout
    trace = parse(trace_path.read_text())
    assert not trace.errors
    active_pid = None
    phase = []
    ended = False
    for call in trace:
        if call.name == "write" and 'GC_CHECKPOINT_BEGIN' in call.args:
            assert active_pid is None
            active_pid = call.pid
        elif call.name == "write" and 'GC_CHECKPOINT_END' in call.args:
            assert call.pid == active_pid
            ended = True
            break
        elif active_pid == call.pid:
            phase.append(call)
    names = [call.name for call in phase]
    assert ended and 0 < len(phase) <= 512
    assert "renameat" in names and "read" in names and "write" in names
    assert not ({"getdents", "getdents64", "fsync", "execve", "clone"} & set(names))


# GATE-CMD-FSBUDGET.1 계수: 감독은 시작에 exec·fd 표시 2를, 생성마다 시계 한 번·/dev/null·chdir을, 원자 경로에서는
# 단위 cgroup 만들기·열기 둘·kill 쓰기를, 최선 노력에서는 자기 프로세스 그룹을 센다. 생성 수는 1–12. N = 1 값은 live
# 캡처(test_live_helper_calls_match_stage_formula[command_miss])가 정확히 맞추는 값이다. 이것을 실패시키는 것: 시계를
# 회차에 한 번으로 세는 것(N > 1에서 줄어듦), cgroup 항을 최선 노력에도 세는 것, 생성 수 상한을 늘리거나 0을 받는 것.
def test_supervisor_coefficients():
    from fsbudget.formula import supervisor_expected
    clock = {"openat": 4, "fstat": 2, "statfs": 4, "read": 2, "readlink": 2}
    for n in (1, 2, 12):
        atomic = supervisor_expected(n, atomic=True)
        best = supervisor_expected(n, atomic=False)
        assert atomic == {"exec": 1, "fd_flags": 2, "fstat": clock["fstat"] * n, "statfs": clock["statfs"] * n,
                          "read": clock["read"] * n, "readlink": clock["readlink"] * n,
                          "openat": (clock["openat"] + 1 + 2) * n, "spawn": n, "cwd": n, "mkdir": n, "write": n}
        assert best == {"exec": 1, "fd_flags": 2, "fstat": clock["fstat"] * n, "statfs": clock["statfs"] * n,
                        "read": clock["read"] * n, "readlink": clock["readlink"] * n,
                        "openat": (clock["openat"] + 1) * n, "spawn": n, "cwd": n, "pgroup": n}
    for n in (0, 13):
        with pytest.raises(ValueError):
            supervisor_expected(n, atomic=True)
