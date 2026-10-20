"""Compiler-free runtime audit of the prepared product and test worker.

The interposer is an observation canary, never a kernel sandbox. Descendant
sampling supplements it; it does not turn sampling into a hard guarantee.
"""
import ctypes
import fcntl
import json
import os
import select
import struct
import subprocess
import sys
import time

import pytest
from conftest import ROOT


def crc(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return struct.pack("<I", value ^ 0xffffffff)


def frame(kind, identity, payload):
    return b"BNGIPC02" + struct.pack("<HBBI", 2, kind, 0, len(payload)) + identity + bytes(32) + payload


def request(identity, mask):
    paths = b"".join(struct.pack("<I", len(p)) + p for p in (b"/c", b"/s", b"/r"))
    context = crc(b"bingsu-context-v3\0" + paths[:-6])
    body = bytes([1]) * 16 + bytes([2]) * 16 + struct.pack("<Q", 1) + bytes([3]) * 4 + context
    body += bytes([1]) + bytes(16) + struct.pack("<QII", 0, mask, 50) + paths + bytes(2)
    return (frame(2, identity, struct.pack("<IQ", len(body), 3))
            + frame(3, identity, bytes(4) + body) + frame(4, identity, crc(body)))


def children(pid):
    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    lib.proc_listchildpids.restype = ctypes.c_int
    values = (ctypes.c_int * 64)()
    count = lib.proc_listchildpids(pid, values, ctypes.sizeof(values))
    assert 0 <= count < len(values), "descendant census failed or overflowed"
    return list(values)[:count]


def run_worker(command, dylib, tmp_path, mutation=False):
    read, write = os.pipe()
    lock = os.open(tmp_path / "lock", os.O_CREAT | os.O_RDWR, 0o600)
    sources = [fcntl.fcntl(fd, fcntl.F_DUPFD, 10) for fd in (read, lock)]
    for fd in sources:
        os.set_inheritable(fd, True)
    def setup():
        os.dup2(sources[0], 3)
        os.dup2(sources[1], 5)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, cwd="/", close_fds=False, preexec_fn=setup,
                               env={"DYLD_INSERT_LIBRARIES": str(dylib)} if dylib else {})
    seen, output, sent = [], bytearray(), False
    deadline = time.monotonic() + 5
    try:
        for fd in sources:
            os.close(fd)
        while process.poll() is None or select.select([process.stdout], [], [], 0)[0]:
            seen.extend(children(process.pid) if process.poll() is None else [])
            assert time.monotonic() < deadline, "worker did not finish"
            if select.select([process.stdout], [], [], 0.002)[0]:
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    break
                output.extend(data)
            at = output.find(b"BNGIPC02")
            if not sent and at >= 0 and len(output) >= at + 104:
                mask, = struct.unpack_from("<I", output, at + 88)
                os.write(write, request(output[at + 16:at + 48], mask))
                sent = True
        code = process.wait(timeout=2)
        assert not seen, f"descendants: {seen}"
        if mutation:
            assert code == 86, (code, output)
        else:
            assert code == 0 and sent, (code, output)
            wire = output[output.index(b"BNGIPC02"):]
            kinds = []
            while wire:
                assert len(wire) >= 80
                kind, size = wire[10], struct.unpack_from("<I", wire, 12)[0]
                kinds.append(kind)
                wire = wire[80 + size:]
            assert kinds in ([1, 6], [1, 5, 6]), kinds
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for fd in (read, write, lock):
            os.close(fd)


def prepared():
    path = ROOT / "target/collector-audit/fixture.json"
    assert path.is_file(), "run scripts/prepare_collector_audit.py on the host first"
    return json.loads(path.read_text())


# 이것을 실패시키는 것: 자식의 한도 실패가 앞단의 exit0·B1·stderr0 계약을 바꾸는 것.
def test_worker_limits_fail_without_blocking_front():
    result = subprocess.run([prepared()["startup"], "--exact", "worker_limits_fail_without_blocking_front",
                             "--test-threads=1"], check=True, capture_output=True, timeout=15)
    assert b"test result: ok. 1 passed;" in result.stdout, result
    prompt = subprocess.run([prepared()["front"], "prompt", "--ctx", "1",
                             "--record", "B1", "--width", "80", "--runtime-root=1:2:/r"],
                            env={}, stdin=subprocess.DEVNULL, capture_output=True, timeout=2)
    assert prompt.returncode == 0 and prompt.stderr == b""
    assert prompt.stdout == b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fdegraded:runtime-root\x1e"


# 이것을 실패시키는 것: 제품·시험 공통 경로의 생성 호출 또는 canary 변이를 놓치는 것.
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS interpose audit; Linux uses B2 syscall tests")
def test_macos_no_spawn_harness_detects_creation(tmp_path):
    startup = prepared()["startup"]
    canary = prepared()["canary"]
    product = [prepared()["worker"], "__collect-v1"]
    fixture = [startup, "--exact", "fixture_worker_child", "--ignored", "--nocapture", "--test-threads=1"]
    product_output = run_worker(product, canary, tmp_path)
    fixture_output = run_worker(fixture, canary, tmp_path)
    assert b"fixture" in fixture_output
    at = fixture_output.index(b"BNGIPC02")
    assert product_output[16:48] != fixture_output[at + 16:at + 48]
    mutant = prepared()["mutant"]
    # A call from a separate executable is interposed. dyld deliberately does
    # not interpose calls originating inside the interposer image itself.
    run_worker([str(mutant)], canary, tmp_path, mutation=True)
    with pytest.raises(AssertionError):
        run_worker([str(mutant)], canary, tmp_path)


# 이것을 실패시키는 것: count를 bytes로 나누어 실제 fork의 자식을 놓치는 것.
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS descendant census")
def test_macos_descendant_census_catches_fork_without_canary(tmp_path):
    with pytest.raises(AssertionError, match="descendants:"):
        run_worker([prepared()["mutant"]], None, tmp_path)

