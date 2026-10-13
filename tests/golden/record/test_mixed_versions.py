"""Version mixing (record change plan 12, security impact): the B1 reader of
M1 (count 7, kept in legacy/ as a fixture) with a new record, and the new
reader with an old record, both fail and leave the field array empty."""
import os
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run  # noqa: E402

SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
NEW = b"B1\x1f8\x1fL\x1f\x1f\x1f\x1f\x1f\x1fU\x1fok:none\x1e"
OLD = b"B1\x1f7\x1fL\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e"
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


# 이것을 실패시키는 것: 새 reader가 옛 레코드(개수 7)를 받거나, 옛 reader가 새 레코드(개수 8)를 받는 것,
# 거부한 뒤 필드 배열을 비우지 않는 것.
@pytest.mark.parametrize("shell", SHELLS)
def test_mixed_versions_fail_closed(shell, tmp_path):
    legacy = HERE / "legacy" / f"reader-b1-count7.{shell}"
    assert frame(shell, legacy, OLD, tmp_path) == "accept 9"
    assert frame(shell, legacy, NEW, tmp_path) == "reject 0"
    assert frame(shell, run.READER[shell], NEW, tmp_path) == "accept 10"
    assert frame(shell, run.READER[shell], OLD, tmp_path) == "reject 0"
