import importlib.util
import json
from pathlib import Path
import tarfile

import pytest

SPEC = importlib.util.spec_from_file_location("pack_evidence", Path(__file__).with_name("pack_collector_evidence.py"))
packer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packer)


@pytest.mark.parametrize("traces_only", [False, True])
def test_archive_preserves_evidence_without_following_links(tmp_path, traces_only):
    source = tmp_path / "native"
    case = source / "f3-real0"
    case.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "must-not-upload.trace").write_bytes(b"outside")
    (case / "absolute").symlink_to(outside, target_is_directory=True)
    (case / "cycle").symlink_to(source, target_is_directory=True)
    (case / "linked.trace").symlink_to(outside / "must-not-upload.trace")
    raw = b"full raw trace\n" * 10000
    (case / "failure.trace").write_bytes(raw)
    (case / "git-dirty.json").write_text('{"status": "BLOCKED"}')
    (case / "tracked-file").write_bytes(b"repository content")
    output = tmp_path / "evidence.tar.gz"
    packer.pack(source, output, traces_only=traces_only)
    with tarfile.open(output) as archive:
        assert archive.extractfile("f3-real0/failure.trace").read() == raw
        assert json.load(archive.extractfile("f3-real0/git-dirty.json"))["status"] == "BLOCKED"
        assert not any("must-not-upload" in n for n in archive.getnames())
        manifest = json.load(archive.extractfile("evidence-inventory.json"))
        assert {"path": "f3-real0/absolute", "link": str(outside)} in manifest["entries"]
        if traces_only:
            assert "f3-real0/tracked-file" not in archive.getnames()
            assert "f3-real0/linked.trace" not in archive.getnames()
        else:
            assert archive.getmember("f3-real0/absolute").issym()
            assert archive.getmember("f3-real0/linked.trace").issym()
    assert output.stat().st_size < len(raw)
