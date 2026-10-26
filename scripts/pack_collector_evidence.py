"""Compress evidence without following the hostile fixtures' symlinks.

M3b retains every raw trace and F3 observation, plus an inventory (including
symlink targets). F1/F2 retain their full trees, including links as links.
Never give upload-artifact a recursive glob over a live fixture tree: macOS
open-flags/root/absolute points to /.
"""
import argparse
import io
import json
import os
from pathlib import Path
import stat
import tarfile


def pack(source, destination, *, traces_only=False):
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    inventory = []
    total = 0
    with tarfile.open(destination, "w:gz", compresslevel=1, dereference=False) as archive:
        # os.walk does not follow directory links; lstat below also refuses
        # file links. There is no traversal or copying outside this root.
        for base, dirs, files in os.walk(source, followlinks=False):
            for name in sorted(dirs + files):
                path = Path(base) / name
                relative = path.relative_to(source)
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    inventory.append({"path": str(relative), "link": os.readlink(path)})
                    if not traces_only:
                        archive.add(path, arcname=str(relative), recursive=False)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                if traces_only and not (path.suffix == ".trace" or
                                        (path.suffix == ".json" and any(p.startswith("f3-real") for p in relative.parts))):
                    continue
                archive.add(path, arcname=str(relative), recursive=False)
                inventory.append({"path": str(relative), "bytes": metadata.st_size})
                total += metadata.st_size
        manifest = json.dumps({"source_exists": source.is_dir(), "raw_bytes": total,
                               "entries": inventory}, indent=2).encode()
        info = tarfile.TarInfo("evidence-inventory.json")
        info.size = len(manifest)
        archive.addfile(info, io.BytesIO(manifest))
    print(f"{destination.name}: {total} raw bytes, {destination.stat().st_size} compressed bytes, {len(inventory)} entries")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--traces-only", action="store_true")
    args = parser.parse_args()
    pack(args.source, args.destination, traces_only=args.traces_only)
