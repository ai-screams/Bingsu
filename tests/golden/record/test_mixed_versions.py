"""Version mixing (record change plan 12, security impact): the B1 readers of
M1 and M3 (counts 7 and 8, kept in legacy/ as fixtures) with a new record, and
the new reader with an old record, all fail and leave the field array empty. The new
binary refuses an old snapshot frame and its helper regenerates the file."""
import functools
import os
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
NEW = b"B1\x1f12\x1fL\x1f\x1f\x1f\x1f\x1f\x1fU\x1f\x1f\x1f\x1f\x1fok:none\x1e"
OLDER = b"B1\x1f7\x1fL\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"
OLD = b"B1\x1f8\x1fL\x1f\x1f\x1f\x1f\x1f\x1fU\x1fok:none\x1e"
SCRIPT = {
    "zsh": 'source "$1"; rec=$(cat -- "$2"; print -n .); rec=${rec%.}; '
           'if _bingsu_frame "$rec"; then r=accept; else r=reject; fi; print -r -- "$r ${#_bingsu_f}"',
    "bash": 'source "$1"; rec=$(cat -- "$2"; printf .); rec=${rec%.}; '
            'if _bingsu_frame "$rec"; then r=accept; else r=reject; fi; printf "%s %s\\n" "$r" "${#_bingsu_f[@]}"',
    "fish": 'source $argv[1]; set -l rec (cat -- $argv[2] | string collect -N); '
            'if _bingsu_frame "$rec"; set r accept; else; set r reject; end; printf "%s %s\\n" $r (count $_bingsu_f)',
}


def frame(shell, reader_src, record, tmp_path):
    reader = tmp_path / f"reader.{shell}"
    reader.write_text(reader_src.read_text().replace("@KNOWN_CODES@", ""))
    rec = tmp_path / "rec.bin"
    rec.write_bytes(record)
    args = [reader, rec] if shell == "fish" else [shell, reader, rec]
    r = subprocess.run(run.CMD[shell] + ["-c", SCRIPT[shell]] + [str(a) for a in args], capture_output=True)
    assert r.returncode == 0 and r.stderr == b"", r
    return r.stdout.decode().strip()


# 이것을 실패시키는 것: 새 reader가 옛 레코드(개수 7·8)를 받거나, 옛 reader가 새 레코드(개수 12)를 받는 것,
# 거부한 뒤 필드 배열을 비우지 않는 것.
@pytest.mark.parametrize("shell", SHELLS)
def test_mixed_versions_fail_closed(shell, tmp_path):
    for name, record, elements in [("count7", OLDER, 9), ("count8", OLD, 10)]:
        legacy = HERE / "legacy" / f"reader-b1-{name}.{shell}"
        assert frame(shell, legacy, record, tmp_path) == f"accept {elements}"
        assert frame(shell, legacy, NEW, tmp_path) == "reject 0"
        assert frame(shell, run.READER[shell], record, tmp_path) == "reject 0"
    assert frame(shell, run.READER[shell], NEW, tmp_path) == "accept 14"


# The old binary's side of the mix needs an old build, so CI cannot run it. It was
# checked once by hand: real 54ae132 and new binaries took turns on one store, and
# each refused the other's file and regenerated it. Here the new binary reads old bytes.
OLD_FIXTURE = HERE.parents[1] / "golden/snapshot/fixture-v2.bin"
TABLE = [functools.reduce(lambda c, _: (c >> 1) ^ (0x82f63b78 * (c & 1)), range(8), i) for i in range(256)]


def crc32c(*parts):
    crc = 0xffffffff
    for byte in b"".join(parts):
        crc = (crc >> 8) ^ TABLE[(crc ^ byte) & 0xff]
    return (crc ^ 0xffffffff).to_bytes(4, "little")


def sealed_session(tmp_path):
    from snapshot_support import SnapshotSession
    session = SnapshotSession(tmp_path)
    session.put("[style]\ntemplate='NEWFRAME {char}'\n")
    session.init()
    session.await_text("NEWFRAME")
    session.wait_quiet()
    return session, session.store()


def assert_refused_and_regenerated(session, store, wire):
    for name in ("snapshot", "last-good"):
        (store / name).write_bytes(wire)
    record = session.prompt()
    assert b"NEWFRAME" not in record and b"!" in record, record
    session.wait_quiet()
    assert b"NEWFRAME" in session.await_text("NEWFRAME")
    session.wait_quiet()
    for name in ("snapshot", "last-good"):
        assert (store / name).read_bytes()[:12] == b"BNGSNP03\x03\0\x40\0", name


def old_file_for(current):
    """Real version 2 bytes under this session's identity, so that a wrong boot
    or context is not what refuses them, with a valid version 2 checksum."""
    fixture = OLD_FIXTURE.read_bytes()
    body, metadata = (int.from_bytes(fixture[at:at + 4], "little") for at in (76, 80))
    end = 192 + body
    domain = b"bingsu-snapshot-v2\0"
    assert fixture[160:164] == crc32c(domain, fixture[:160], fixture[192:end])
    old = bytearray(fixture[:end + metadata])
    assert old[:12] == b"BNGSNP02\x02\0\x40\0" and old[192:200] == b"BNGCFG03"
    for start, stop in ((16, 28), (84, 124), (152, 160)):  # identity, clock, resume
        old[start:stop] = current[start:stop]
    old[160:164] = crc32c(domain, old[:160], old[192:end])
    return old


# 이것을 실패시키는 것: 도우미가 옛 형식을 last-good으로 복사해 오염시키는 것, 앞단이 진짜 옛 파일을 그리는 것.
def test_genuine_old_frame_is_refused_and_regenerated(tmp_path):
    session, store = sealed_session(tmp_path)
    assert_refused_and_regenerated(session, store, old_file_for((store / "snapshot").read_bytes()))


# A checksum, codec or identity refusal would hide a missing version check in a
# real old file, so each case differs from a valid new file by one old header
# field, resealed: that field is the only thing left to refuse it.
# 이것을 실패시키는 것: 그 필드의 비교를 전부 빼는 것(프레임 매직·버전은 header와 lengths 둘 다, 새 파일로 그린다).
@pytest.mark.parametrize("at, old", [(0, b"BNGSNP02"), (8, b"\x02\0"), (64, b"BNGCMP02"), (72, b"\x02\0")],
                         ids=["frame-magic", "frame-version", "prefix-magic", "prefix-version"])
def test_each_old_header_field_alone_is_refused(tmp_path, at, old):
    session, store = sealed_session(tmp_path)
    wire = bytearray((store / "snapshot").read_bytes())
    common, count = (int.from_bytes(wire[192 + n:196 + n], "little") for n in (12, 16))
    wire[at:at + len(old)] = old
    wire[160:164] = crc32c(b"bingsu-snapshot-v3\0", wire[:160], wire[192:192 + 20 + common + count * 16])
    assert_refused_and_regenerated(session, store, wire)
