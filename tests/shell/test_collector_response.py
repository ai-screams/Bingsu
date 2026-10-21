"""Native C2 fixture -> confined front reader -> rendered B1 record."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, Install, real_bin, trusted_env, short_dir
from pty_session import Session, visible
from test_prompt_deadline import is_static
import test_prompt_env_paths as budget


@pytest.fixture(scope="module")
def reader_binary():
    # Minimum-shell images cannot execute the host's newer glibc test binary.
    # A prebuilt native fixture may be supplied explicitly in either environment.
    supplied = os.environ.get("BINGSU_COLLECTION_READER")
    if not supplied and sys.platform == "linux" and is_static(real_bin()):
        pytest.skip("native collection fixture runs on the GNU host")
    candidates = [Path(supplied)] if supplied else sorted(
        (ROOT / "target/debug/deps").glob("bingsu-*"),
        key=lambda p: p.stat().st_mtime_ns, reverse=True)
    for binary in candidates:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            continue
        result = subprocess.run([str(binary), "--list"], capture_output=True, timeout=15)
        if result.returncode == 0 and b"prompt_read::tests::collection_trace_child: test" in result.stdout:
            return str(binary)
    pytest.fail("build the bingsu test binary before pytest or set BINGSU_COLLECTION_READER")


def run_reader(reader_binary, tmp_path, mode="current", length=4, shell="bash", payload="CURRENT", trace=False):
    scratch = tmp_path / "reader"
    scratch.mkdir(mode=0o700)
    env = {**os.environ, "TMPDIR": str(scratch)}
    input_bytes = "\0".join([mode, str(length), shell, payload]).encode()
    command = [reader_binary, "--exact", "prompt_read::tests::collection_trace_child",
               "--ignored", "--nocapture", "--test-threads=1", "-q"]
    trace_path = tmp_path / "front.trace"
    if trace:
        strace = shutil.which("strace")
        assert strace, "Linux C3 gate must execute strace"
        command = [strace, "-f", "-q", "-yy", "-s", "65536", "-e", "trace=all", "-o", str(trace_path), *command]
    result = subprocess.run(command, env=env, input=input_bytes, capture_output=True, timeout=15)
    assert result.returncode == 0 and result.stderr == b"", (result.returncode, result.stdout, result.stderr)
    assert result.stdout.count(b"C3-BEGIN\n") == result.stdout.count(b"C3-PREPARED\n") == 1
    record = result.stdout.split(b"C3-PREPARED\n", 1)[1]
    assert record.startswith(b"B1\x1f") and record.endswith(b"\x1e")
    assert record.count(b"\x1f") == 9 and b"ok:none" in record
    return record, trace_path, scratch


# 이것을 실패시키는 것: 실제 발행 fixture·동일 fd·previous fallback 시험이 실행되지 않는 것.
@pytest.mark.parametrize("name", [
    "missing_collections_stops_after_one_enoent",
    "collection_prefetch_has_five_fixed_path_opens",
    "prefetch_uses_only_validated_context_and_cwd_address",
    "published_fixture_previous_and_unknown_reach_render",
    "new_completion_never_blocks_the_current_prompt",
])
def test_native_collection_contract(reader_binary, name):
    result = subprocess.run([reader_binary, "--exact", "prompt_read::tests::" + name,
                             "--test-threads=1", "--nocapture", "-q"], capture_output=True, timeout=30)
    assert result.returncode == 0 and result.stderr == b"", result
    assert b"test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout, result.stdout


# 이것을 실패시키는 것: response 부재·decode 실패에서 previous를 렌더하지 않는 것.
@pytest.mark.parametrize("mode,want", [("absent", b"?"), ("current", b"CURRENT"),
                                      ("previous", b"PREVIOUS"), ("corrupt", b"PREVIOUS")])
def test_store_to_render(reader_binary, tmp_path, mode, want):
    record, _, _ = run_reader(reader_binary, tmp_path, mode)
    assert want in record


# 이것을 실패시키는 것: 어느 셸에서든 수집 문자열이 제어문자나 명령으로 실행되는 것.
@pytest.mark.parametrize("shell", os.environ.get("BINGSU_TEST_SHELLS", "bash zsh fish").split())
def test_collected_text_is_sanitized_for_each_shell(reader_binary, tmp_path, shell):
    canary = short_dir() / "executed"
    payload = f"MARK $(touch {canary}) `touch {canary}` \x1b]0;TITLE\x07\nEND"
    record, _, _ = run_reader(reader_binary, tmp_path, shell=shell, payload=payload)
    assert b"MARK" in record and b"TITLE" in record and b"END" in record
    assert b"\x07" not in record and b"\x1b]" not in record
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    init = tmp_path / ("init." + shell)
    init.write_bytes(inst.init(shell, env))
    inst.use_fake(record)
    session = Session(shell, env, cols=400)
    session.run(f"source {init}")
    session.run("true")
    screen = visible(session.close())
    assert b"MARK" in screen and not canary.exists()


# 이것을 실패시키는 것: Linux 실행을 skip하거나 부재1·정상5/facts/청크 계약을 실제 trace에서 검사하지 않는 것.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp and strace runtime gate")
@pytest.mark.parametrize("length", [1, 3841, 65536])
@pytest.mark.parametrize("mode", ["absent", "current", "previous", "corrupt"])
def test_post_filter_has_no_new_path_or_metadata_effects(reader_binary, tmp_path, length, mode):
    record, path, scratch = run_reader(reader_binary, tmp_path, mode, length, trace=True)
    parsed = budget.parse_trace(path.read_text())
    assert not parsed.errors, parsed.errors
    begin, = [c for c in parsed if c.name == "write" and '"C3-BEGIN\\n"' in c.args]
    prepared, = [c for c in parsed if c.name == "write" and '"C3-PREPARED\\n"' in c.args]
    front = [c for c in parsed if c.pid == begin.pid and c.index > begin.index]
    filters = [c for c in front if c.name == "prctl" and "PR_SET_SECCOMP" in c.args]
    assert len(filters) == 1 and filters[0].ret == "0", "the native filter must actually install"
    boundary = filters[0].index
    assert begin.index < prepared.index < boundary
    base, = scratch.glob("bingsu-n4-read-*")
    pinned = [str(base), "/c", "/s"]
    cwd = b"/" if length == 1 else b"/" + b"a" * (length-2) + b"\xff"
    budget.prompt_root_io([c for c in front if c.name != budget.EXIT_EVENT],
                          boundary, reader_binary, pinned, begin.pid, cwd)
    counts = budget.assert_collection_trace(front, boundary, pinned, cwd, required=True)
    assert counts["openat"] == (1 if mode == "absent" else 5)
    assert sum(c.name == "write" for c in front if c.index > boundary) == 1
    table = {r[0] for r in budget._ROWS if r[0] != "-"}
    for call in front:
        if call.index > boundary and call.name != budget.EXIT_EVENT:
            assert call.name in table and not budget.call_paths(call), call
            assert call.name not in {"fstat", "newfstatat", "fstatfs", "fgetxattr", "getxattr", "wait4", "poll"}, call
    assert record and counts, "one complete native trace was checked"
