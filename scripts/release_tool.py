#!/usr/bin/env python3
"""Decisions of `.github/workflows/release.yml`, kept out of the workflow so
that pytest can break each one (`scripts/test_release_tool.py`).

Subcommands, in the order the workflow uses them:

  meta            tag and version agree; writes the job outputs
  gate            the tagged commit is on main and passed the required checks
  build-manifest  runs the fresh build once, records its identity line
  payload-pack    the three executables as one deterministic tar
  payload-unpack  safe extraction of that tar (no execution)
  stage           the folder an archive holds (executables plus documents)
  package         deterministic .tar.gz or .zip from a staged folder
  sums            SHA256SUMS of the archives
  verify-files    SHA256SUMS against the folder, names against the targets
  verify-archive  safe extraction, then `--version` and static-link checks
  static          readelf checks of one ELF file
  assets-check    the assets of a draft release against the folder
  notes           the release notes template

The tool reads and writes files and runs `gh` and `readelf`; it never
runs an archive's executable except in `verify-archive` and `build-manifest`,
which the workflow runs only in jobs without secrets.
It needs Python 3.9 or newer (the macOS runner's), so no `tomllib`.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

PRODUCTS = ("bingsu", "bingsu-prompt", "bingsu-collect")
DOCS = ("LICENSE-MIT", "LICENSE-APACHE", "README.md")
# target -> archive suffix
TARGETS = {
    "x86_64-unknown-linux-musl": "tar.gz",
    "aarch64-unknown-linux-musl": "tar.gz",
    "aarch64-apple-darwin": "zip",
}
SUMS = "SHA256SUMS"
MAX_MEMBER = 256 * 1024 * 1024
OK_CONCLUSIONS = ("success", "skipped", "neutral")
TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)$")
VERSION_LINE_RE = re.compile(
    r"^bingsu (?P<version>\S+) \((?P<identity>[0-9a-f]{64}), (?P<target>[A-Za-z0-9_.-]+), "
    r"rustc (?P<rustc>\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?) (?P<commit>[0-9a-f]{9})\)$"
)


class ReleaseError(Exception):
    """A release decision failed; the message says which one."""


def archive_name(version: str, target: str) -> str:
    return f"bingsu-{version}-{target}.{TARGETS[target]}"


def top_name(version: str, target: str) -> str:
    return f"bingsu-{version}-{target}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# --- version and tag --------------------------------------------------------


def toml_value(text: str, table: str, key: str):
    """The string value of `key = "..."` in `[table]`, `True` for
    `key.workspace = true`, `None` when absent. Only what Cargo.toml of this
    repository uses: plain tables and one value per line."""
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            current = line.strip("[]").strip()
            continue
        if current != table or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep:
            continue
        name, value = name.strip(), value.split("#")[0].strip()
        if name == key and value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        if name == key + ".workspace" and value == "true":
            return True
    return None


def read_version(root: Path) -> str:
    """The one version of the three product crates (their own, or the
    workspace's when they inherit it); a mismatch fails."""
    workspace = toml_value((root / "Cargo.toml").read_text(), "workspace.package", "version")
    found = {}
    for crate in PRODUCTS:
        value = toml_value((root / "crates" / crate / "Cargo.toml").read_text(), "package", "version")
        if value is True:
            value = workspace
        if not isinstance(value, str):
            raise ReleaseError(f"crates/{crate}/Cargo.toml has no version")
        found[crate] = value
    if len(set(found.values())) != 1:
        raise ReleaseError(f"product crates disagree on the version: {found}")
    return next(iter(found.values()))


def meta(event: str, ref: str, version: str) -> dict:
    if event in ("workflow_dispatch", "pull_request"):
        return {"version": version, "tag": "", "prerelease": "false", "dry_run": "true"}
    if event != "push":
        raise ReleaseError(f"unexpected event {event!r}")
    if not ref.startswith("refs/tags/"):
        raise ReleaseError(f"a push run needs a tag ref, got {ref!r}")
    tag = ref[len("refs/tags/"):]
    found = TAG_RE.match(tag)
    if not found:
        raise ReleaseError(f"tag {tag!r} is not v<major>.<minor>.<patch>[-<pre>]")
    if found.group(1) != version:
        raise ReleaseError(f"tag {tag!r} does not match the crates' version {version!r}")
    return {"version": version, "tag": tag, "prerelease": "true" if "-" in version else "false", "dry_run": "false"}


# --- the commit gate --------------------------------------------------------


def resolve_tag(tag: str, ref_json: dict, fetch_tag) -> str:
    """The commit a tag points at. One level of annotated tag is followed; a
    tag of a tag, or a tag of anything but a commit, fails."""
    if ref_json.get("ref") != f"refs/tags/{tag}":
        raise ReleaseError(f"remote answered for {ref_json.get('ref')!r}, not refs/tags/{tag}")
    obj = ref_json["object"]
    if obj["type"] == "commit":
        return obj["sha"]
    if obj["type"] == "tag":
        inner = fetch_tag(obj["sha"])["object"]
        if inner["type"] == "commit":
            return inner["sha"]
        raise ReleaseError(f"tag {tag!r} points at a {inner['type']} through an annotated tag")
    raise ReleaseError(f"tag {tag!r} points at a {obj['type']}, not a commit")


def required_contexts(rules: list) -> list:
    names = []
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            names += [c["context"] for c in rule["parameters"]["required_status_checks"]]
    if not names:
        raise ReleaseError("the branch rules list no required status checks")
    return sorted(set(names))


def check_failures(required: list, runs: list) -> list:
    latest: dict = {}
    for run in runs:
        if run["name"] not in latest or run["id"] > latest[run["name"]]["id"]:
            latest[run["name"]] = run
    problems = []
    for name in required:
        run = latest.get(name)
        if run is None:
            problems.append(f"{name}: no check run on this commit")
        elif run["status"] != "completed":
            problems.append(f"{name}: {run['status']}")
        elif run["conclusion"] not in OK_CONCLUSIONS:
            problems.append(f"{name}: {run['conclusion']}")
    return problems


def evaluate_gate(tag: str, sha: str, ref_json: dict, fetch_tag, compare_status: str, rules: list, runs: list) -> list:
    """Every reason the release must not go on; empty when it may."""
    try:
        tagged = resolve_tag(tag, ref_json, fetch_tag)
    except ReleaseError as error:
        return [str(error)]
    problems = []
    if tagged != sha:
        problems.append(f"the tag points at {tagged}, this run built {sha}")
    if compare_status not in ("identical", "behind"):
        problems.append(f"{sha} is not an ancestor of main (compare status {compare_status!r})")
    try:
        problems += check_failures(required_contexts(rules), runs)
    except ReleaseError as error:
        problems.append(str(error))
    return problems


def gh_api(path: str, *extra: str):
    out = subprocess.run(["gh", "api", *extra, path], check=True, capture_output=True, text=True).stdout
    return out


def run_gate(tag: str, sha: str, repo: str, branch: str = "main") -> list:
    base = f"repos/{repo}"
    ref_json = json.loads(gh_api(f"{base}/git/ref/tags/{tag}"))
    compare = gh_api(f"{base}/compare/{branch}...{sha}", "--jq", ".status").strip()
    rules = json.loads(gh_api(f"{base}/rules/branches/{branch}", "--paginate", "--slurp"))
    rules = [rule for page in rules for rule in (page if isinstance(page, list) else [page])]
    lines = gh_api(f"{base}/commits/{sha}/check-runs?per_page=100", "--paginate", "--jq",
                   ".check_runs[] | {id, name, status, conclusion}")
    runs = [json.loads(line) for line in lines.splitlines() if line.strip()]
    return evaluate_gate(
        tag, sha, ref_json, lambda tag_sha: json.loads(gh_api(f"{base}/git/tags/{tag_sha}")), compare, rules, runs
    )


# --- executables ------------------------------------------------------------


def check_version_output(text: str, version: str, target: str, rustc: str, first_line: str = None) -> list:
    """Problems of one `bingsu --version` output: three lines, the build line
    of this version, target and compiler (and of `first_line` when the build
    recorded one), and both siblings `same build`."""
    problems = []
    lines = text.split("\n")
    if lines[-1] != "":
        problems.append("output does not end with a newline")
    lines = lines[:-1] if lines[-1] == "" else lines
    if len(lines) != 3:
        problems.append(f"expected 3 lines, got {len(lines)}")
    found = VERSION_LINE_RE.match(lines[0]) if lines else None
    if not found:
        problems.append(f"first line is not a build line: {lines[:1]}")
    else:
        for field, want in (("version", version), ("target", target), ("rustc", rustc)):
            if found.group(field) != want:
                problems.append(f"{field} is {found.group(field)!r}, expected {want!r}")
        if first_line is not None and lines[0] != first_line:
            problems.append(f"build line differs from the build job's: {lines[0]!r} vs {first_line!r}")
    for index, sibling in ((1, "bingsu-prompt"), (2, "bingsu-collect")):
        want = f"{sibling}: same build"
        if len(lines) > index and lines[index] != want:
            problems.append(f"line {index + 1} is {lines[index]!r}, expected {want!r}")
    return problems


def static_problems(program_headers: str, dynamic: str, sections: str) -> list:
    problems = []
    if re.search(r"\bINTERP\b", program_headers):
        problems.append("has an INTERP program header (dynamic loader)")
    if re.search(r"\(NEEDED\)", dynamic):
        problems.append("has NEEDED entries (shared libraries)")
    if re.search(r"\s\.symtab\s", sections):
        problems.append("has a .symtab section (not stripped)")
    return problems


def readelf(path: Path, flag: str) -> str:
    out = subprocess.run(["readelf", flag, str(path)], capture_output=True, text=True)
    if out.returncode != 0:
        raise ReleaseError(f"readelf {flag} {path} failed: {out.stderr.strip()}")
    return out.stdout


def check_static(path: Path) -> list:
    return [
        f"{path.name}: {p}"
        for p in static_problems(readelf(path, "-lW"), readelf(path, "-dW"), readelf(path, "-SW"))
    ]


def run_version(folder: Path) -> str:
    out = subprocess.run([str(folder / "bingsu"), "--version"], capture_output=True, text=True, timeout=60, cwd=folder)
    if out.returncode != 0:
        raise ReleaseError(f"bingsu --version exited {out.returncode}: {out.stderr.strip()}")
    return out.stdout


# --- archives ---------------------------------------------------------------


def stage(payload: Path, docs_root: Path, out: Path, version: str, target: str) -> Path:
    """The folder an archive holds: the three executables from `payload` and
    the documents from the checkout. Nothing else is accepted in `payload`."""
    names = sorted(p.name for p in payload.iterdir())
    if names != sorted(PRODUCTS):
        raise ReleaseError(f"payload holds {names}, expected {sorted(PRODUCTS)}")
    folder = out / top_name(version, target)
    folder.mkdir(parents=True)
    for name in PRODUCTS:
        source = payload / name
        if source.is_symlink() or not source.is_file():
            raise ReleaseError(f"{name} in the payload is not a regular file")
        data = source.read_bytes()
        (folder / name).write_bytes(data)
        os.chmod(folder / name, 0o755)
    for name in DOCS:
        (folder / name).write_bytes((docs_root / name).read_bytes())
        os.chmod(folder / name, 0o644)
    return folder


def _file_mode(name: str) -> int:
    return 0o755 if name in PRODUCTS else 0o644


def _tar_bytes(files: list, top: str, mtime: int) -> bytes:
    """A tar of `files` (name, bytes) in sorted order with fixed owner and time."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        if top:
            info = tarfile.TarInfo(top)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, mtime
            tar.addfile(info)
        for name, data in sorted(files):
            info = tarfile.TarInfo(f"{top}/{name}" if top else name)
            info.size, info.mode, info.mtime = len(data), _file_mode(name), mtime
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def _folder_files(folder: Path, expected: tuple) -> list:
    names = sorted(p.name for p in folder.iterdir())
    if names != sorted(expected):
        raise ReleaseError(f"{folder} holds {names}, expected {sorted(expected)}")
    return [(name, (folder / name).read_bytes()) for name in expected]


def package_tar_gz(folder: Path, out: Path, version: str, target: str, mtime: int) -> None:
    files = _folder_files(folder, PRODUCTS + DOCS)
    data = _tar_bytes(files, top_name(version, target), mtime)
    with open(out, "wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0, compresslevel=9) as gz:
            gz.write(data)


def package_zip(folder: Path, out: Path, version: str, target: str, mtime: int) -> None:
    files = _folder_files(folder, PRODUCTS + DOCS)
    top = top_name(version, target)
    date = max(1980, 1970 + mtime // 31556952)  # a real date is not needed, a fixed one is
    stamp = (date, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        entry = zipfile.ZipInfo(top + "/", stamp)
        entry.external_attr = (stat.S_IFDIR | 0o755) << 16 | 0x10
        entry.create_system = 3
        archive.writestr(entry, b"")
        for name, data in sorted(files):
            entry = zipfile.ZipInfo(f"{top}/{name}", stamp)
            entry.external_attr = (stat.S_IFREG | _file_mode(name)) << 16
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)


def pack_payload(folder: Path, out: Path) -> None:
    out.write_bytes(_tar_bytes(_folder_files(folder, PRODUCTS), "", 0))


def _write_member(dest: Path, name: str, data: bytes) -> None:
    path = dest / name
    path.write_bytes(data)
    os.chmod(path, _file_mode(name.rsplit("/", 1)[-1]))


def unpack_payload(archive: Path, dest: Path) -> None:
    """The three executables of a payload tar; anything else, any link and any
    name outside the three fails. Nothing is run."""
    dest.mkdir(parents=True, exist_ok=True)
    seen = []
    with tarfile.open(archive, "r:") as tar:
        for member in tar.getmembers():
            if not member.isreg() or member.name not in PRODUCTS or member.size > MAX_MEMBER:
                raise ReleaseError(f"unexpected payload member {member.name!r} ({member.type!r})")
            seen.append(member.name)
            _write_member(dest, member.name, tar.extractfile(member).read())
    if sorted(seen) != sorted(PRODUCTS):
        raise ReleaseError(f"payload holds {sorted(seen)}")


def extract_archive(archive: Path, dest: Path, version: str, target: str) -> Path:
    """Unpack a release archive by reading members, never by `extractall`:
    the top folder, then exactly the six files, regular, bounded in size."""
    top = top_name(version, target)
    want = set(PRODUCTS + DOCS)
    dest.mkdir(parents=True, exist_ok=True)
    seen = []
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isdir() and member.name == top:
                    continue
                base = member.name[len(top) + 1:] if member.name.startswith(top + "/") else None
                if not member.isreg() or base not in want or member.size > MAX_MEMBER:
                    raise ReleaseError(f"unexpected archive member {member.name!r} ({member.type!r})")
                seen.append(base)
                (dest / top).mkdir(exist_ok=True)
                _write_member(dest / top, base, tar.extractfile(member).read())
    elif archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                kind = stat.S_IFMT(info.external_attr >> 16)
                if info.is_dir() and info.filename == top + "/":
                    continue
                base = info.filename[len(top) + 1:] if info.filename.startswith(top + "/") else None
                if kind not in (0, stat.S_IFREG) or base not in want or info.file_size > MAX_MEMBER:
                    raise ReleaseError(f"unexpected archive member {info.filename!r} (mode type {kind:o})")
                seen.append(base)
                (dest / top).mkdir(exist_ok=True)
                _write_member(dest / top, base, zf.read(info))
    else:
        raise ReleaseError(f"unknown archive type {archive.name!r}")
    if sorted(seen) != sorted(want):
        raise ReleaseError(f"archive holds {sorted(seen)}, expected {sorted(want)}")
    return dest / top


# --- SHA256SUMS -------------------------------------------------------------


def write_sums(folder: Path, names: list) -> str:
    return "".join(f"{sha256_file(folder / n)}  {n}\n" for n in sorted(names))


def check_release_files(folder: Path, version: str, targets: list) -> list:
    """The folder holds exactly the archives of `targets` and `SHA256SUMS`,
    and the list names every archive once with its digest."""
    expected = sorted(archive_name(version, t) for t in targets)
    problems = []
    present = sorted(p.name for p in folder.iterdir())
    if present != sorted(expected + [SUMS]):
        problems.append(f"folder holds {present}, expected {sorted(expected + [SUMS])}")
    sums_path = folder / SUMS
    if not sums_path.is_file():
        return problems + [f"{SUMS} is missing"]
    text = sums_path.read_text()
    entries = {}
    for number, line in enumerate(text.split("\n")[:-1] if text.endswith("\n") else text.split("\n"), 1):
        found = re.match(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$", line)
        if not found:
            problems.append(f"{SUMS} line {number} is malformed: {line!r}")
        elif found.group(2) in entries:
            problems.append(f"{SUMS} lists {found.group(2)} twice")
        else:
            entries[found.group(2)] = found.group(1)
    if not text.endswith("\n"):
        problems.append(f"{SUMS} does not end with a newline")
    if sorted(entries) != expected:
        problems.append(f"{SUMS} lists {sorted(entries)}, expected {expected}")
    for name in expected:
        path = folder / name
        if path.is_file() and name in entries and sha256_file(path) != entries[name]:
            problems.append(f"{name}: digest differs from {SUMS}")
    return problems


def check_assets(assets: list, folder: Path, version: str, targets: list) -> list:
    """The assets of a draft release are exactly the files in `folder`."""
    names = sorted(archive_name(version, t) for t in targets) + [SUMS]
    problems = []
    got = sorted(a["name"] for a in assets)
    if got != sorted(names):
        problems.append(f"draft holds {got}, expected {sorted(names)}")
    for asset in assets:
        path = folder / asset["name"]
        if not path.is_file():
            continue
        if asset.get("state") != "uploaded":
            problems.append(f"{asset['name']}: state {asset.get('state')!r}")
        if asset.get("size") != path.stat().st_size:
            problems.append(f"{asset['name']}: size {asset.get('size')} differs from the file")
        digest = asset.get("digest")
        if digest is not None and digest != "sha256:" + sha256_file(path):
            problems.append(f"{asset['name']}: digest differs from the file")
    return problems


def notes(tag: str, version: str, repo: str) -> str:
    return (
        f"Bingsu {version}\n\n"
        "Each archive holds `bingsu`, `bingsu-prompt` and `bingsu-collect`; keep the three in one folder.\n\n"
        "Check what you downloaded:\n\n"
        "```sh\n"
        "sha256sum -c SHA256SUMS --ignore-missing\n"
        f"gh attestation verify <archive> --repo {repo}\n"
        f"gh release verify {tag} --repo {repo}\n"
        "```\n\n"
        "See CHANGELOG.md for what changed.\n"
    )


# --- command line -----------------------------------------------------------


def output(pairs: dict) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    text = "".join(f"{k}={v}\n" for k, v in pairs.items())
    if path:
        with open(path, "a") as handle:
            handle.write(text)
    sys.stdout.write(text)


def summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as handle:
            handle.write(text + "\n")


def fail(problems: list, what: str) -> int:
    for problem in problems:
        print(f"error: {what}: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, *flags):
        cmd = sub.add_parser(name)
        for flag in flags:
            cmd.add_argument(flag, required=True)
        return cmd

    add("meta", "--root")
    add("gate", "--tag", "--sha", "--repo")
    add("build-manifest", "--dir", "--payload", "--out", "--target", "--version", "--rustc")
    add("payload-pack", "--dir", "--out")
    add("payload-unpack", "--payload", "--manifest", "--out")
    add("stage", "--payload", "--docs", "--out", "--version", "--target")
    add("package", "--folder", "--out", "--version", "--target", "--mtime")
    add("sums", "--dir", "--version", "--targets")
    add("verify-files", "--dir", "--version", "--targets").add_argument("--sums-sha256")
    add("verify-archive", "--dir", "--version", "--target", "--rustc", "--manifest", "--extract-to")
    add("static", "--dir")
    add("assets-check", "--json", "--dir", "--version", "--targets")
    add("notes", "--tag", "--version", "--repo")
    args = parser.parse_args(argv)

    try:
        return dispatch(args)
    except (ReleaseError, subprocess.CalledProcessError, OSError, KeyError, ValueError) as error:
        print(f"error: {args.cmd}: {error}", file=sys.stderr)
        return 1


def dispatch(args) -> int:
    targets = lambda: args.targets.split(",")  # noqa: E731
    if args.cmd == "meta":
        result = meta(os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"], read_version(Path(args.root)))
        output(result)
        summary(f"release run: version `{result['version']}`, dry run: {result['dry_run']}, prerelease: {result['prerelease']}")
        return 0
    if args.cmd == "gate":
        problems = run_gate(args.tag, args.sha, args.repo)
        if not problems:
            summary(f"commit gate: `{args.sha}` is on main and passed every required check")
        return fail(problems, "commit gate")
    if args.cmd == "build-manifest":
        folder = Path(args.dir)
        text = run_version(folder)
        problems = check_version_output(text, args.version, args.target, args.rustc)
        if problems:
            return fail(problems, "build identity")
        manifest = {
            "target": args.target,
            "payload_sha256": sha256_file(Path(args.payload)),
            "build_line": text.split("\n")[0],
        }
        Path(args.out).write_text(json.dumps(manifest, indent=1) + "\n")
        summary(f"`{args.target}` build line: `{manifest['build_line']}`")
        return 0
    if args.cmd == "payload-pack":
        pack_payload(Path(args.dir), Path(args.out))
        return 0
    if args.cmd == "payload-unpack":
        manifest = json.loads(Path(args.manifest).read_text())
        if sha256_file(Path(args.payload)) != manifest["payload_sha256"]:
            return fail(["payload digest differs from the build manifest"], "payload")
        unpack_payload(Path(args.payload), Path(args.out))
        return 0
    if args.cmd == "stage":
        stage(Path(args.payload), Path(args.docs), Path(args.out), args.version, args.target)
        return 0
    if args.cmd == "package":
        folder, out = Path(args.folder), Path(args.out)
        (package_zip if args.target.endswith("apple-darwin") else package_tar_gz)(
            folder, out, args.version, args.target, int(args.mtime)
        )
        return 0
    if args.cmd == "sums":
        folder = Path(args.dir)
        names = [archive_name(args.version, t) for t in targets()]
        (folder / SUMS).write_text(write_sums(folder, names))
        return 0
    if args.cmd == "verify-files":
        problems = check_release_files(Path(args.dir), args.version, targets())
        if args.sums_sha256 is not None and sha256_file(Path(args.dir) / SUMS) != args.sums_sha256:
            problems.append(f"{SUMS} is not the file package made (digest differs from the recorded one)")
        return fail(problems, "release files")
    if args.cmd == "verify-archive":
        archive = Path(args.dir) / archive_name(args.version, args.target)
        folder = extract_archive(archive, Path(args.extract_to), args.version, args.target)
        manifest = json.loads(Path(args.manifest).read_text())
        problems = []
        if manifest["target"] != args.target:
            problems.append(f"manifest is for {manifest['target']!r}")
        problems += check_version_output(
            run_version(folder), args.version, args.target, args.rustc, manifest["build_line"]
        )
        if args.target.endswith("linux-musl"):
            for name in PRODUCTS:
                problems += check_static(folder / name)
        if not problems:
            summary(f"`{archive.name}`: build line, siblings" + (", static link" if "linux" in args.target else ""))
            print(folder)
        return fail(problems, "archive")
    if args.cmd == "static":
        problems = []
        for name in PRODUCTS:
            problems += check_static(Path(args.dir) / name)
        return fail(problems, "static link")
    if args.cmd == "assets-check":
        assets = json.loads(Path(args.json).read_text())
        return fail(check_assets(assets, Path(args.dir), args.version, targets()), "draft assets")
    if args.cmd == "notes":
        sys.stdout.write(notes(args.tag, args.version, args.repo))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
