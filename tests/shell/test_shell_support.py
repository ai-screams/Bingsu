"""The shared shell-test helpers."""
import os
import signal
import subprocess
import sys
import time

from shell_support import cargo_test_binaries, end_background, track_background


# 이것을 실패시키는 것: Cargo 1.99까지의 deps/나 1.100의 build/<package>/<hash>/out/ 한쪽을 보지 않는 것,
# 다른 package의 같은 이름을 받는 것, 실행할 수 없는 파일(dep-info, object)이나 폴더를 받는 것.
def test_cargo_test_binaries_reads_both_layouts(tmp_path):
    def put(rel, mode):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
        path.chmod(mode)
        return path

    old = put("deps/cli_prompt-1", 0o755)
    put("deps/cli_prompt-1.d", 0o644)
    new = put("build/bingsu/2/out/cli_prompt-2", 0o755)
    put("build/bingsu/2/out/cli_prompt-2.cli_prompt.rcgu.o", 0o644)
    put("build/other/3/out/cli_prompt-3", 0o755)
    (tmp_path / "build/bingsu/4/out/cli_prompt-4").mkdir(parents=True)
    got = cargo_test_binaries(tmp_path, "bingsu", "cli_prompt")
    assert sorted(got) == sorted([old, new]), got


# A stand-in for a bingsu that does not end (as a mutated build that ignores the end of its session):
# SIGTERM does not stop it.
STUCK = f"""#!{sys.executable}
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
signal.signal(signal.SIGHUP, signal.SIG_IGN)
print("up", flush=True)
while True:
    time.sleep(1)
"""


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


# A test that ran bingsu as a background job and failed leaves it running; the end of the test kills it.
# 이것을 실패시키는 것: 시험 끝에 남은 배경 bingsu를 죽이지 않는 것(셸과 시험이 끝난 뒤에도 남음).
def test_a_background_bingsu_left_running_is_killed(tmp_path, monkeypatch):
    stuck = (tmp_path / "bingsu").resolve()
    stuck.write_text(STUCK)
    stuck.chmod(0o755)
    monkeypatch.setenv("BINGSU_BIN", str(stuck))
    shell = subprocess.Popen(["/bin/sh", "-c", f'"{stuck}" & echo BPID=$!; wait $!'], stdout=subprocess.PIPE)
    try:
        log = shell.stdout.readline() + shell.stdout.readline()
        pid = int(log.split(b"BPID=")[1].split()[0])
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.3)
        assert alive(pid), "the stand-in must outlive SIGTERM"
        track_background(lambda: log)
        end_background()
        assert not alive(pid)
    finally:
        shell.kill()
        shell.wait()


# The number a log names can belong to another program by the end of the test: that one is left alone.
# 이것을 실패시키는 것: 명령 줄을 보지 않고 그 번호를 죽이는 것(다른 프로그램이 죽음).
def test_a_pid_that_names_another_program_is_left_alone(tmp_path, monkeypatch):
    monkeypatch.setenv("BINGSU_BIN", str((tmp_path / "bingsu").resolve()))
    other = subprocess.Popen(["sleep", "30"])
    try:
        track_background(lambda: f"BPID={other.pid}\n".encode())
        end_background()
        assert other.poll() is None, "another program was killed"
    finally:
        other.kill()
        other.wait()
