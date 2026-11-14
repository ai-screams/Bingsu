"""Tests of `release_tool.py` and of the shape of `.github/workflows/release.yml`.

Run: python3 -B -m pytest scripts/test_release_tool.py -q -p no:cacheprovider

Each check of the tool has a test that breaks it with one change of input
(one byte of an archive, one line of SHA256SUMS, a dynamic ELF, another
version string). The workflow tests read the YAML as text: the jobs, their
permissions and environments, the pins.
"""
import gzip
import hashlib
import io
import json
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import zipfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import release_tool as rt  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/release.yml"
VERSION = "0.1.0-rc.1"
RUSTC = "1.99.1"
IDENT = "a" * 64
LINUX = "x86_64-unknown-linux-musl"
MAC = "aarch64-apple-darwin"
ALL_TARGETS = list(rt.TARGETS)


def build_line(version=VERSION, target=LINUX, rustc=RUSTC, ident=IDENT):
    return f"bingsu {version} ({ident}, {target}, rustc {rustc} 012345678)"


def version_text(**kw):
    return build_line(**kw) + "\nbingsu-prompt: same build\nbingsu-collect: same build\n"


# --- tag and version --------------------------------------------------------


def write_crates(root, versions, workspace=None):
    ws = '[workspace]\nmembers = []\n'
    if workspace:
        ws += f'[workspace.package]\nversion = "{workspace}"\nedition = "2024"\n'
    (root / "Cargo.toml").write_text(ws)
    for crate, version in versions.items():
        folder = root / "crates" / crate
        folder.mkdir(parents=True)
        line = "version.workspace = true" if version is True else f'version = "{version}"'
        (folder / "Cargo.toml").write_text(f'[package]\nname = "{crate}"\n{line}  # comment\n[dependencies]\nversion = "9"\n')


def test_read_version_of_own_and_inherited_versions(tmp_path):
    write_crates(tmp_path, {c: VERSION for c in rt.PRODUCTS})
    assert rt.read_version(tmp_path) == VERSION
    other = tmp_path / "ws"
    other.mkdir()
    write_crates(other, {c: True for c in rt.PRODUCTS}, workspace="0.2.0")
    assert rt.read_version(other) == "0.2.0"


# 이것을 실패시키는 것: 세 제품 crate의 버전이 서로 다른데 통과시키는 것, [dependencies]의 version 줄을 읽는 것.
def test_read_version_rejects_disagreement(tmp_path):
    versions = {c: VERSION for c in rt.PRODUCTS}
    versions["bingsu-collect"] = "0.1.0"
    write_crates(tmp_path, versions)
    with pytest.raises(rt.ReleaseError, match="disagree"):
        rt.read_version(tmp_path)


def test_meta_tag_run():
    got = rt.meta("push", f"refs/tags/v{VERSION}", VERSION)
    assert got == {"version": VERSION, "tag": f"v{VERSION}", "prerelease": "true", "dry_run": "false"}
    assert rt.meta("push", "refs/tags/v0.1.0", "0.1.0")["prerelease"] == "false"


# 이것을 실패시키는 것: 태그와 crate 버전을 비교하지 않는 것, v 접두사를 빼고 비교하는 것, 태그가 아닌 ref의 push를 받는 것.
@pytest.mark.parametrize("ref", ["refs/tags/v0.1.1", "refs/tags/0.1.0", "refs/tags/v0.1", "refs/tags/v0.1.0+build",
                                 "refs/heads/v0.1.0", "refs/tags/v0.1.0-"])
def test_meta_rejects_tag_that_does_not_match(ref):
    with pytest.raises(rt.ReleaseError):
        rt.meta("push", ref, "0.1.0")


# 이것을 실패시키는 것: pull request 실행을 dry run으로 세지 않아 태그 run처럼 서명·게시 쪽으로 가는 것.
@pytest.mark.parametrize("event,ref", [("workflow_dispatch", "refs/heads/some-branch"), ("pull_request", "refs/pull/7/merge")])
def test_meta_dry_run_skips_the_tag(event, ref):
    got = rt.meta(event, ref, "0.1.0")
    assert got == {"version": "0.1.0", "tag": "", "prerelease": "false", "dry_run": "true"}
    with pytest.raises(rt.ReleaseError):
        rt.meta("schedule", ref, "0.1.0")


# --- commit gate ------------------------------------------------------------

SHA = "1" * 40
TAG_OBJ = "2" * 40


def ref(kind="commit", sha=SHA, tag="v0.1.0"):
    return {"ref": f"refs/tags/{tag}", "object": {"type": kind, "sha": sha}}


def rules(*contexts):
    """Each context is a name, or (name, integration id)."""
    checks = []
    for context in contexts:
        name, app = (context, None) if isinstance(context, str) else context
        checks.append({"context": name} if app is None else {"context": name, "integration_id": app})
    return [{"type": "pull_request", "parameters": {}},
            {"type": "required_status_checks", "parameters": {"required_status_checks": checks}}]


def runs(**by_name):
    out = []
    for i, (name, (status, conclusion)) in enumerate(by_name.items(), 1):
        out.append({"id": i, "name": name.replace("_", " "), "status": status, "conclusion": conclusion})
    return out


GOOD_RUNS = runs(Lint=("completed", "success"), Test=("completed", "success"), Gate=("completed", "skipped"))
GOOD_RULES = rules("Lint", "Test", "Gate")


def gate(ref_json=None, status="behind", rule=GOOD_RULES, run=GOOD_RUNS, sha=SHA, fetch=None):
    return rt.evaluate_gate("v0.1.0", sha, ref_json or ref(), fetch or (lambda s: None), status, rule, run)


def test_gate_passes_a_main_commit_with_every_check():
    assert gate() == []
    assert gate(status="identical") == []


# 이것을 실패시키는 것: main 조상 검사를 빼는 것, 'ahead'·'diverged'를 통과시키는 것.
@pytest.mark.parametrize("status", ["ahead", "diverged", ""])
def test_gate_rejects_a_commit_off_main(status):
    assert any("ancestor of main" in p for p in gate(status=status))


# 이것을 실패시키는 것: 필수 check 목록 대조를 빼는 것, 진행 중·실패·누락을 통과시키는 것, 같은 이름의 재실행 중 오래된 쪽을 보는 것.
def test_gate_rejects_missing_running_and_failed_checks():
    assert any("Test: no check run" in p for p in gate(run=runs(Lint=("completed", "success"), Gate=("completed", "success"))))
    assert any("Test: in_progress" in p for p in gate(run=runs(Lint=("completed", "success"), Test=("in_progress", None), Gate=("completed", "success"))))
    assert any("Test: failure" in p for p in gate(run=runs(Lint=("completed", "success"), Test=("completed", "failure"), Gate=("completed", "success"))))
    rerun = GOOD_RUNS + [{"id": 99, "name": "Test", "status": "completed", "conclusion": "failure"}]
    assert any("Test: failure" in p for p in gate(run=rerun))
    old_failure = [{"id": 0, "name": "Test", "status": "completed", "conclusion": "failure"}] + GOOD_RUNS
    assert gate(run=old_failure) == []


# 이것을 실패시키는 것: 필수 check의 출처 앱(integration_id)을 버리고 이름과 가장 큰 id로만 고르는 것
# (앱 A의 실패 뒤에 앱 B의 같은 이름 성공이 오면 통과), 규칙이 앱을 정하지 않을 때 다른 앱의 실패를 가리는 것.
def test_gate_pins_the_app_a_required_check_comes_from():
    def run(id, app, conclusion):
        return {"id": id, "name": "Test", "status": "completed", "conclusion": conclusion, "app_id": app}

    named = rules(("Test", 15368))
    both = [run(1, 15368, "failure"), run(2, 999, "success")]
    assert any("Test (app 15368): failure" in p for p in gate(rule=named, run=both))
    assert any("no check run" in p for p in gate(rule=named, run=[run(2, 999, "success")]))
    assert gate(rule=named, run=[run(1, 15368, "success"), run(2, 999, "failure")]) == []
    # no app named: every app's newest run of the name must be fine
    assert gate(rule=rules("Test"), run=[run(1, 15368, "success"), run(2, 999, "success")]) == []
    assert any("failure" in p for p in gate(rule=rules("Test"), run=both))
    assert any("failure" in p for p in gate(rule=rules("Test"), run=list(reversed(both))))
    later_failure = [run(1, 15368, "success"), run(2, 999, "failure")]
    assert any("failure" in p for p in gate(rule=rules("Test"), run=later_failure))
    # a rerun of the same app replaces its earlier run
    assert gate(rule=named, run=[run(1, 15368, "failure"), run(3, 15368, "success")]) == []


# 이것을 실패시키는 것: 규칙에 필수 check가 하나도 없는 것을 통과로 세는 것.
def test_gate_rejects_rules_without_required_checks():
    assert any("no required status checks" in p for p in gate(rule=[{"type": "pull_request"}]))


# 이것을 실패시키는 것: 태그가 가리키는 commit과 이 run의 sha를 대조하지 않는 것.
def test_gate_rejects_a_moved_tag():
    assert any("points at" in p for p in gate(ref_json=ref(sha="3" * 40)))


# 이것을 실패시키는 것: 주석 태그를 따라가지 않는 것, 태그의 태그와 tree를 가리키는 태그를 받는 것.
def test_gate_follows_one_annotated_tag_only():
    annotated = ref(kind="tag", sha=TAG_OBJ)
    assert gate(ref_json=annotated, fetch=lambda s: {"object": {"type": "commit", "sha": SHA}}) == []
    nested = gate(ref_json=annotated, fetch=lambda s: {"object": {"type": "tag", "sha": "4" * 40}})
    assert any("annotated tag" in p for p in nested)
    assert any("tree" in p for p in gate(ref_json=ref(kind="tree")))


def test_gate_rejects_an_answer_for_another_ref():
    assert any("remote answered" in p for p in gate(ref_json=ref(tag="v9.9.9")))


# --- build line and static link ---------------------------------------------


def test_version_output_passes():
    assert rt.check_version_output(version_text(), VERSION, LINUX, RUSTC) == []
    assert rt.check_version_output(version_text(), VERSION, LINUX, RUSTC, first_line=build_line()) == []


# 이것을 실패시키는 것: 버전, target, rustc, build 정체 중 하나를 대조하지 않는 것(변이마다 다른 문자열).
@pytest.mark.parametrize("change,needle", [
    ({"version": "0.1.0"}, "version is"),
    ({"target": MAC}, "target is"),
    ({"rustc": "1.98.1"}, "rustc is"),
])
def test_version_output_rejects_other_strings(change, needle):
    problems = rt.check_version_output(version_text(**change), VERSION, LINUX, RUSTC)
    assert any(needle in p for p in problems), problems


def test_version_output_rejects_other_identity():
    problems = rt.check_version_output(version_text(ident="b" * 64), VERSION, LINUX, RUSTC, first_line=build_line())
    assert any("differs from the build job" in p for p in problems)


# 이것을 실패시키는 것: 형제 줄 대조를 빼는 것, 줄 수를 세지 않는 것, 마지막 개행을 보지 않는 것, 앞 줄 모양 검사를 빼는 것.
@pytest.mark.parametrize("text", [
    build_line() + "\nbingsu-prompt: differs (build abcd)\nbingsu-collect: same build\n",
    build_line() + "\nbingsu-prompt: same build\nbingsu-collect: missing\n",
    build_line() + "\nbingsu-prompt: same build\nbingsu-collect: same build\nextra\n",
    build_line() + "\nbingsu-prompt: same build\n",
    build_line() + "\nbingsu-prompt: same build\nbingsu-collect: same build",
    "bingsu 0.1.0-rc.1\nbingsu-prompt: same build\nbingsu-collect: same build\n",
    build_line(ident="A" * 64) + "\nbingsu-prompt: same build\nbingsu-collect: same build\n",
])
def test_version_output_rejects_bad_shapes(text):
    assert rt.check_version_output(text, VERSION, LINUX, RUSTC) != []


STATIC_L = "Elf file type is DYN\nProgram Headers:\n  LOAD  0x0\n"
STATIC_D = "Dynamic section at offset 0x1 contains 3 entries:\n  0x0000000000000006 (SYMTAB)  0x1\n"
STATIC_S = "Section Headers:\n  [ 1] .text  PROGBITS\n  [ 2] .strtab STRTAB\n"


def test_static_passes_a_static_file():
    assert rt.static_problems(STATIC_L, STATIC_D, STATIC_S) == []
    assert rt.static_problems(STATIC_L, "There is no dynamic section in this file.\n", STATIC_S) == []


# 이것을 실패시키는 것: INTERP, NEEDED, .symtab 중 하나의 검사를 빼는 것.
def test_static_rejects_dynamic_and_unstripped():
    assert rt.static_problems(STATIC_L + "  INTERP 0x0\n", STATIC_D, STATIC_S)
    assert rt.static_problems(STATIC_L, STATIC_D + "  0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]\n", STATIC_S)
    assert rt.static_problems(STATIC_L, STATIC_D, STATIC_S + "  [ 3] .symtab SYMTAB\n")


@pytest.mark.skipif(sys.platform != "linux", reason="readelf and a C compiler")
def test_static_check_on_real_files(tmp_path):
    cc = subprocess.run(["sh", "-c", "command -v cc && command -v readelf"], capture_output=True, text=True)
    if cc.returncode != 0:
        pytest.skip("no cc or readelf")
    src = tmp_path / "x.c"
    src.write_text("int main(void){return 0;}\n")
    dynamic = tmp_path / "dyn"
    subprocess.run(["cc", "-o", str(dynamic), str(src)], check=True)
    assert rt.check_static(dynamic), "a dynamically linked executable must fail"
    static = tmp_path / "static"
    built = subprocess.run(["cc", "-static", "-s", "-o", str(static), str(src)], capture_output=True)
    if built.returncode == 0:
        assert rt.check_static(static) == []


# --- archives ---------------------------------------------------------------


def payload_folder(root):
    folder = root / "payload"
    folder.mkdir()
    for name in rt.PRODUCTS:
        (folder / name).write_bytes(b"\x7fELF" + name.encode())
    return folder


def make_archives(root, version=VERSION, targets=ALL_TARGETS, mtime=1_700_000_000):
    out = root / "files"
    out.mkdir()
    for target in targets:
        staged = rt.stage(payload_for(root, target), docs_folder_once(root), root / f"stage-{target}", version, target)
        target_out = out / rt.archive_name(version, target)
        (rt.package_zip if target.endswith("darwin") else rt.package_tar_gz)(staged, target_out, version, target, mtime)
    (out / rt.SUMS).write_text(rt.write_sums(out, [rt.archive_name(version, t) for t in targets]))
    return out


def payload_for(root, target):
    folder = root / f"payload-{target}"
    folder.mkdir(exist_ok=True)
    for name in rt.PRODUCTS:
        (folder / name).write_bytes(b"\x7fELF" + name.encode() + target.encode())
    return folder


def docs_folder_once(root):
    folder = root / "docs"
    if not folder.exists():
        folder.mkdir()
        for name in rt.DOCS:
            (folder / name).write_text(f"{name}\n")
    return folder


def test_release_files_pass(tmp_path):
    out = make_archives(tmp_path)
    assert rt.check_release_files(out, VERSION, ALL_TARGETS) == []


# 이것을 실패시키는 것: SHA256SUMS와 압축의 digest 대조를 빼는 것(압축 한 바이트를 바꿔 본다).
def test_release_files_reject_one_changed_byte(tmp_path):
    out = make_archives(tmp_path)
    target = out / rt.archive_name(VERSION, LINUX)
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 1
    target.write_bytes(bytes(data))
    assert any("digest differs" in p for p in rt.check_release_files(out, VERSION, ALL_TARGETS))


# 이것을 실패시키는 것: SHA256SUMS 한 줄의 digest 대조, 줄 모양 검사, 중복·누락 검사, 끝 개행 검사를 빼는 것.
@pytest.mark.parametrize("edit,needle", [
    (lambda lines: [lines[0].replace(lines[0][:1], "0" if lines[0][0] != "0" else "1", 1)] + lines[1:], "digest differs"),
    (lambda lines: lines[1:], "lists"),
    (lambda lines: lines + [lines[0]], "twice"),
    (lambda lines: [lines[0].replace("  ", " ")] + lines[1:], "malformed"),
    (lambda lines: lines + ["f" * 64 + "  extra.tar.gz"], "lists"),
])
def test_release_files_reject_one_changed_sums_line(tmp_path, edit, needle):
    out = make_archives(tmp_path)
    lines = (out / rt.SUMS).read_text().splitlines()
    (out / rt.SUMS).write_text("\n".join(edit(lines)) + "\n")
    problems = rt.check_release_files(out, VERSION, ALL_TARGETS)
    assert any(needle in p for p in problems), problems


def test_release_files_reject_missing_newline_extra_and_missing_files(tmp_path):
    out = make_archives(tmp_path)
    text = (out / rt.SUMS).read_text()
    (out / rt.SUMS).write_text(text.rstrip("\n"))
    assert any("newline" in p for p in rt.check_release_files(out, VERSION, ALL_TARGETS))
    (out / rt.SUMS).write_text(text)
    (out / "stray.txt").write_text("x")
    assert any("holds" in p for p in rt.check_release_files(out, VERSION, ALL_TARGETS))
    (out / "stray.txt").unlink()
    (out / rt.archive_name(VERSION, MAC)).unlink()
    assert any("holds" in p for p in rt.check_release_files(out, VERSION, ALL_TARGETS))


# 이것을 실패시키는 것: 압축 이름에 버전을 넣지 않아 다른 버전의 압축이 같은 이름으로 통과하는 것.
def test_release_files_reject_other_version(tmp_path):
    out = make_archives(tmp_path, version="0.1.0")
    assert rt.check_release_files(out, VERSION, ALL_TARGETS)


# 이것을 실패시키는 것: 압축에 mtime·소유자·gzip 이름을 넣어 같은 입력의 바이트가 달라지는 것, 파일 순서를 정렬하지 않는 것.
def test_archives_are_deterministic(tmp_path):
    a_root, b_root = tmp_path / "a", tmp_path / "b"
    a_root.mkdir()
    b_root.mkdir()
    a, b = make_archives(a_root), make_archives(b_root)
    for name in a.iterdir():
        assert name.read_bytes() == (b / name.name).read_bytes(), name.name


def test_archive_bytes_follow_the_commit_time_only(tmp_path):
    root1, root2 = tmp_path / "1", tmp_path / "2"
    root1.mkdir()
    root2.mkdir()
    one = make_archives(root1, mtime=1_700_000_000)
    two = make_archives(root2, mtime=1_700_000_001)
    name = rt.archive_name(VERSION, LINUX)
    assert (one / name).read_bytes() != (two / name).read_bytes()


# 이것을 실패시키는 것: 풀 때 owner·모드를 압축 안의 값 그대로 받는 것(실행 비트는 제품 파일에만).
def test_extract_gives_known_modes(tmp_path):
    out = make_archives(tmp_path)
    for target in ALL_TARGETS:
        folder = rt.extract_archive(out / rt.archive_name(VERSION, target), tmp_path / "x" / target, VERSION, target)
        for name in rt.PRODUCTS:
            assert (folder / name).stat().st_mode & 0o777 == 0o755
        for name in rt.DOCS:
            assert (folder / name).stat().st_mode & 0o777 == 0o644


def tar_gz(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)


def tar_info(name, kind=tarfile.REGTYPE, size=0, link=""):
    info = tarfile.TarInfo(name)
    info.type, info.size, info.linkname, info.mode = kind, size, link, 0o755
    return info


def good_members(top):
    members = [(tar_info(top, tarfile.DIRTYPE), None)]
    for name in rt.PRODUCTS + rt.DOCS:
        members.append((tar_info(f"{top}/{name}", size=1), b"x"))
    return members


TOP = rt.top_name(VERSION, LINUX)


# 이것을 실패시키는 것: 상위 폴더 밖 경로, 링크, 장치, 예상 밖 이름, 누락, 중복을 받아들이는 것(extractall로 바꾸는 것).
@pytest.mark.parametrize("mutate", [
    lambda m: m + [(tar_info("../evil", size=1), b"x")],
    lambda m: m + [(tar_info(f"{TOP}/../evil", size=1), b"x")],
    lambda m: m + [(tar_info("/etc/passwd", size=1), b"x")],
    lambda m: m + [(tar_info(f"{TOP}/extra", size=1), b"x")],
    lambda m: m + [(tar_info(f"{TOP}/link", tarfile.SYMTYPE, link="/etc/passwd"), None)],
    lambda m: m + [(tar_info(f"{TOP}/dev", tarfile.CHRTYPE), None)],
    lambda m: m[:-1],
    lambda m: m + [m[1]],
    lambda m: [(tar_info(f"{TOP}/bingsu", tarfile.SYMTYPE, link="bingsu-prompt"), None)] + m[2:],
])
def test_extract_rejects_unsafe_tar(tmp_path, mutate):
    archive = tmp_path / rt.archive_name(VERSION, LINUX)
    tar_gz(archive, mutate(good_members(TOP)))
    with pytest.raises(rt.ReleaseError):
        rt.extract_archive(archive, tmp_path / "out", VERSION, LINUX)
    assert not (tmp_path / "evil").exists() and not (tmp_path.parent / "evil").exists()


def zip_info(name, kind=stat.S_IFREG, mode=None):
    info = zipfile.ZipInfo(name)
    if mode is None:
        base = name.rsplit("/", 1)[-1]
        mode = 0o755 if base in rt.PRODUCTS else 0o644
    info.external_attr = (kind | mode) << 16
    return info


def build_zip(archive, top, extra=None, extra_kind=stat.S_IFREG, replace=None, top_kind=stat.S_IFDIR, mode_of=None):
    """The good archive, with one entry added (`extra`) or one replaced (`replace`: name -> (kind, mode))."""
    replace = replace or {}
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(zip_info(top + "/", top_kind, 0o755), b"")
        for name in rt.PRODUCTS + rt.DOCS:
            kind, mode = replace.get(name, (stat.S_IFREG, None))
            zf.writestr(zip_info(f"{top}/{name}", kind, mode), b"/etc/passwd" if kind != stat.S_IFREG else b"x")
        if extra:
            zf.writestr(zip_info(extra, extra_kind, 0o644), b"/etc/passwd")


def test_extract_rejects_unsafe_zip(tmp_path):
    top = rt.top_name(VERSION, MAC)
    archive = tmp_path / rt.archive_name(VERSION, MAC)
    build_zip(archive, top)
    assert rt.extract_archive(archive, tmp_path / "ok", VERSION, MAC).name == top
    for number, kwargs in enumerate((
        {"extra": "../evil"},
        {"extra": f"{top}/extra"},
        {"extra": f"{top}/link", "extra_kind": stat.S_IFLNK},
        # 이것을 실패시키는 것: 기대한 이름의 항목이 링크여도 받아들이는 것(모드 종류를 보지 않는 것).
        {"replace": {"bingsu": (stat.S_IFLNK, 0o755)}},
        # 이것을 실패시키는 것: 상위 폴더 항목을 이름 끝의 `/`만 보고 받아들이는 것(그 이름의 symlink가 통과).
        {"top_kind": stat.S_IFLNK},
        {"top_kind": stat.S_IFREG},
    )):
        build_zip(archive, top, **kwargs)
        with pytest.raises(rt.ReleaseError):
            rt.extract_archive(archive, tmp_path / f"bad{number}", VERSION, MAC)
        assert not (tmp_path / f"bad{number}").exists(), "nothing is written for a refused archive"


# 이것을 실패시키는 것: 풀기 전에 압축 안의 모드를 보지 않고 실행 파일에 0755를 덮어 쓰는 것(0644로 든 압축이 통과),
# setuid·group/other 쓰기·문서의 실행 비트를 받아들이는 것.
@pytest.mark.parametrize("name,mode", [("bingsu", 0o644), ("bingsu-prompt", 0o600), ("bingsu-collect", 0o655),
                                       ("bingsu", 0o4755), ("bingsu", 0o775), ("README.md", 0o755), ("LICENSE-MIT", 0o666)])
def test_extract_checks_the_modes_inside_the_archive(tmp_path, name, mode):
    top = rt.top_name(VERSION, MAC)
    zipped = tmp_path / rt.archive_name(VERSION, MAC)
    build_zip(zipped, top, replace={name: (stat.S_IFREG, mode)})
    with pytest.raises(rt.ReleaseError, match="mode|executable"):
        rt.extract_archive(zipped, tmp_path / "z", VERSION, MAC)
    tarred = tmp_path / rt.archive_name(VERSION, LINUX)
    members = good_members(rt.top_name(VERSION, LINUX))
    for info, _ in members:
        if info.name.endswith("/" + name):
            info.mode = mode
    tar_gz(tarred, members)
    with pytest.raises(rt.ReleaseError, match="mode|executable"):
        rt.extract_archive(tarred, tmp_path / "t", VERSION, LINUX)
    assert not (tmp_path / "t").exists() and not (tmp_path / "z").exists()


def test_payload_roundtrip_and_rejections(tmp_path):
    folder = payload_folder(tmp_path)
    archive = tmp_path / "payload.tar"
    rt.pack_payload(folder, archive)
    rt.unpack_payload(archive, tmp_path / "out")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(rt.PRODUCTS)
    assert (tmp_path / "out/bingsu").stat().st_mode & 0o777 == 0o755
    with tarfile.open(tmp_path / "bad.tar", "w") as tar:
        tar.addfile(tar_info("bingsu", tarfile.SYMTYPE, link="/etc/passwd"))
    with pytest.raises(rt.ReleaseError):
        rt.unpack_payload(tmp_path / "bad.tar", tmp_path / "out2")
    (folder / "extra").write_bytes(b"x")
    with pytest.raises(rt.ReleaseError):
        rt.pack_payload(folder, tmp_path / "again.tar")


# 이것을 실패시키는 것: payload tar 안의 모드를 보지 않는 것(0644로 든 실행 파일이 통과).
def test_payload_unpack_rejects_a_non_executable_member(tmp_path):
    with tarfile.open(tmp_path / "p.tar", "w") as tar:
        for name in rt.PRODUCTS:
            info = tar_info(name, size=1)
            info.mode = 0o644 if name == "bingsu" else 0o755
            tar.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(rt.ReleaseError, match="executable"):
        rt.unpack_payload(tmp_path / "p.tar", tmp_path / "out")
    assert not (tmp_path / "out").exists()


# 이것을 실패시키는 것: 서명 job이 payload의 digest를 build 기록과 대조하지 않는 것.
def test_payload_unpack_command_checks_the_manifest(tmp_path):
    folder = payload_folder(tmp_path)
    archive = tmp_path / "payload.tar"
    rt.pack_payload(folder, archive)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"target": LINUX, "payload_sha256": rt.sha256_file(archive), "build_line": build_line()}))
    args = ["payload-unpack", "--payload", str(archive), "--manifest", str(manifest), "--out"]
    assert rt.main(args + [str(tmp_path / "ok")]) == 0
    manifest.write_text(json.dumps({"target": LINUX, "payload_sha256": "0" * 64, "build_line": build_line()}))
    assert rt.main(args + [str(tmp_path / "bad")]) == 1
    assert not (tmp_path / "bad").exists()


def test_stage_needs_exactly_the_three_files(tmp_path):
    folder = payload_folder(tmp_path)
    (folder / "extra").write_bytes(b"x")
    with pytest.raises(rt.ReleaseError):
        rt.stage(folder, docs_folder_once(tmp_path), tmp_path / "o", VERSION, LINUX)


# --- draft assets -----------------------------------------------------------


def assets_of(out, **change):
    items = []
    for path in sorted(out.iterdir()):
        items.append({"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                      "digest": "sha256:" + rt.sha256_file(path)})
    items[0].update(change)
    return items


def test_assets_match(tmp_path):
    out = make_archives(tmp_path)
    assert rt.check_assets(assets_of(out), out, VERSION, ALL_TARGETS) == []


# 이것을 실패시키는 것: draft의 자산 이름 집합, 상태, 크기, digest 중 하나를 대조하지 않는 것.
def test_assets_reject_each_difference(tmp_path):
    out = make_archives(tmp_path)
    assert rt.check_assets(assets_of(out)[1:], out, VERSION, ALL_TARGETS)
    assert rt.check_assets(assets_of(out) + [{"name": "stray", "state": "uploaded", "size": 1}], out, VERSION, ALL_TARGETS)
    assert any("state" in p for p in rt.check_assets(assets_of(out, state="starter"), out, VERSION, ALL_TARGETS))
    assert any("size" in p for p in rt.check_assets(assets_of(out, size=1), out, VERSION, ALL_TARGETS))
    assert any("digest" in p for p in rt.check_assets(assets_of(out, digest="sha256:" + "0" * 64), out, VERSION, ALL_TARGETS))


def test_notes_name_the_tag_and_repo():
    text = rt.notes("v0.1.0", "0.1.0", "ai-screams/Bingsu")
    assert "gh release verify v0.1.0 --repo ai-screams/Bingsu" in text


# --- the workflow -----------------------------------------------------------


def workflow_text():
    return WORKFLOW.read_text().replace("\r\n", "\n")


def jobs():
    """job id -> its text, split on the two-space keys under `jobs:`."""
    text = workflow_text()
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][a-z0-9-]*):\n", body)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def test_workflow_jobs_exist():
    assert list(jobs()) == ["meta", "build", "sign-macos", "package", "verify", "publish"]


def test_workflow_triggers_and_defaults():
    text = workflow_text()
    head = text.split("\njobs:\n", 1)[0]
    assert re.search(r"(?m)^on:\n  push:\n    tags: \[\"v\*\"\]\n  workflow_dispatch:\n  pull_request:\n    paths:\n", head)
    assert "branches:" not in head and "pull_request_target" not in head
    paths = re.findall(r"(?m)^      - (\S+)$", head.split("pull_request:", 1)[1].split("\npermissions:", 1)[0])
    assert paths == [".github/workflows/release.yml", "scripts/release_tool.py", "scripts/test_release_tool.py"]
    assert re.search(r"(?m)^permissions:\n  contents: read\n", head)
    assert "cancel-in-progress: false" in head
    assert "group: release-${{ github.ref }}" in head
    assert re.search(r'(?m)^  RELEASE_RUST: "\d+\.\d+\.\d+"$', head)


# 이것을 실패시키는 것: environment를 다른 job에 두는 것, 쓰기 권한·id-token·attestations를 publish 밖에 두는 것.
def test_only_signing_and_publish_enter_the_environment_and_only_publish_writes():
    for name, body in jobs().items():
        has_env = re.search(r"(?m)^    environment: release$", body) is not None
        assert has_env == (name in ("sign-macos", "publish")), name
        writes = re.findall(r"(?m)^      (contents: write|id-token: write|attestations: write)$", body)
        assert bool(writes) == (name == "publish"), name
    assert set(re.findall(r"(?m)^      (\S+: write)$", jobs()["publish"])) == {"contents: write", "id-token: write", "attestations: write"}
    assert "secrets." not in "".join(b for n, b in jobs().items() if n not in ("sign-macos",)).replace("secrets.GITHUB_TOKEN", "")


# 이것을 실패시키는 것: dry-run이 서명·게시 job에 닿게 하는 if를 빼는 것.
def test_dry_run_skips_signing_and_publishing():
    cond = "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
    for name in ("sign-macos", "publish"):
        assert cond in jobs()[name], name
    assert "if: github.event_name" not in "".join(jobs()[n] for n in ("meta", "build", "package", "verify"))


def test_every_job_has_a_timeout_and_every_checkout_is_pinned_and_asserted():
    for name, body in jobs().items():
        assert re.search(r"(?m)^    timeout-minutes: \d+$", body), name
        for match in re.finditer(r"(?m)^( +)- uses: actions/checkout@", body):
            block = body[match.start():].split("\n      - ", 1)[0]
            assert "ref: ${{ github.sha }}" in block and "persist-credentials: false" in block, name
            assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in body[match.start():], name


# 이것을 실패시키는 것: action을 태그나 브랜치로 부르는 것, 버전 주석을 빼는 것, rust-cache를 쓰는 것.
def test_actions_are_pinned_and_no_cache_is_used():
    text = workflow_text()
    uses = re.findall(r"(?m)^\s*(?:- )?uses: (\S+)(.*)$", text)
    assert uses
    for target, rest in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", target), target
        assert re.match(r"\s+# \S+", rest), (target, rest)
    assert "rust-cache" not in text and "actions/cache" not in text


# 이것을 실패시키는 것: release의 컴파일러가 PR CI가 시험한 컴파일러와 어긋나는 것(RELEASE_RUST나 ci.yml의 고정 판 한쪽만 바꾸는 것).
def test_release_rust_is_the_toolchain_ci_tests_with():
    release = re.search(r'(?m)^  RELEASE_RUST: "(\d+\.\d+\.\d+)"$', workflow_text()).group(1)
    ci = (ROOT / ".github/workflows/ci.yml").read_text().replace("\r\n", "\n")
    body = ci.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][a-z0-9-]*):\n", body)
    pins = {}
    for i in range(1, len(parts), 2):
        if parts[i] in ("collector-msrv", "icount"):  # the MSRV job and the instruction-count job pin their own
            continue
        for value in re.findall(r"(?m)^\s+toolchain: (\S+)$", parts[i + 1]):
            pins.setdefault(value, []).append(parts[i])
    assert pins, "ci.yml pins no toolchain"
    assert set(pins) == {release}, (release, pins)


def test_pull_request_runs_never_reach_signing_or_publishing():
    head = workflow_text().split("\njobs:\n", 1)[0]
    assert "fork" in head
    for name in ("sign-macos", "publish"):
        body = jobs()[name]
        assert "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" in body, name
        assert "pull_request" not in body, name
    others = "".join(b for n, b in jobs().items() if n not in ("sign-macos", "publish"))
    assert "environment:" not in others and "secrets." not in others and ": write" not in others


def test_toolchain_is_the_pinned_release_and_rustup_is_asserted():
    text = workflow_text()
    lines = text.splitlines()
    uses = [i for i, line in enumerate(lines) if "uses: dtolnay/rust-toolchain@" in line]
    assert uses
    for i in uses:
        assert "toolchain: ${{ env.RELEASE_RUST }}" in "\n".join(lines[i:i + 4])
    assert text.count("command -v rustup") == len(uses)
    assert "CARGO_PROFILE_" in text, "the build job must refuse profile overrides"


def test_downloads_are_by_id_and_tools_are_checked():
    text = workflow_text()
    assert text.count("artifact-ids: ${{ needs.package.outputs.files_artifact_id }}") == 2, "verify and publish"
    assert "digest-mismatch: error" in text
    assert "curl" not in text or "sha256sum --check" in text
    assert "Acquire::Retries=5" in text
    assert text.count("apt-get") == text.count("apt-get -o Acquire::Retries=5")


# 이것을 실패시키는 것: gate를 서명·게시 job에서 빼는 것, 비밀 가져오기 뒤로 옮기는 것.
def test_commit_gate_runs_before_secrets_and_before_publishing():
    for name in ("meta", "sign-macos", "publish"):
        body = jobs()[name]
        assert "release_tool.py gate" in body, name
    sign = jobs()["sign-macos"]
    assert sign.index("release_tool.py gate") < sign.index("import-codesign-certs")
    publish = jobs()["publish"]
    assert publish.index("release_tool.py gate") < publish.index("attest-build-provenance")


# 이것을 실패시키는 것: 서명 job이 받은 실행 파일을 실행하는 것(--version, 직접 호출).
def test_signing_job_never_runs_the_payload():
    body = jobs()["sign-macos"]
    for word in ("verify-archive", "build-manifest", "run_version", "./bingsu", "/bingsu "):
        assert word not in body, word
    # `--version` is only ever the flag that names the release version.
    assert re.findall(r'--version(?! "\$VERSION")', body) == []
    assert not re.search(r'"\$RUNNER_TEMP/bin/\S+"\s', body.replace('--out "$RUNNER_TEMP/bin"', "").replace('--payload "$RUNNER_TEMP/bin"', "").replace('"$RUNNER_TEMP/bin/$name"', ""))


def test_attestation_binds_the_verified_bytes():
    body = jobs()["publish"]
    assert "needs.package.outputs.sums_sha256" in body and "needs.verify.outputs.verified_sums_sha256" in body
    assert 'test "$VERIFIED_SUMS_SHA256" = "$SUMS_SHA256"' in body
    assert "gh attestation verify" in body and "--bundle" in body
    for flag in ("--repo", "--signer-workflow", "--source-digest", "--source-ref"):
        assert flag in body, flag
    assert body.index("sums_sha256") < body.index("attest-build-provenance")
    assert "gh release create" in body and "--draft" in body and "--verify-tag" in body


# 이것을 실패시키는 것: 게시 전 SHA256SUMS를 package가 기록한 digest와 대조하지 않는 것.
def test_verify_files_checks_the_recorded_sums_digest(tmp_path):
    out = make_archives(tmp_path)
    good = rt.sha256_file(out / rt.SUMS)
    args = ["verify-files", "--dir", str(out), "--version", VERSION, "--targets", ",".join(ALL_TARGETS)]
    assert rt.main(args + ["--sums-sha256", good]) == 0
    assert rt.main(args + ["--sums-sha256", "0" * 64]) == 1


# 이것을 실패시키는 것: checkout 밖(`$RUNNER_TEMP/release`)에서 부르는 gh release·attestation에 --repo를 빼는 것
# ("not a git repository"로 늘 실패), gh api에서 repos/ 경로를 빼는 것.
def test_every_gh_call_names_its_repository():
    text = workflow_text().replace("\\\n", " ")
    calls = re.findall(r"(?m)\bgh (release|attestation|api|run|workflow|pr|issue)\b([^\n]*)", text)
    assert calls
    for kind, rest in calls:
        if kind == "api":
            assert "repos/" in rest, rest
        else:
            assert '--repo "$GITHUB_REPOSITORY"' in rest, (kind, rest)
    assert sum(1 for kind, _ in calls if kind == "release") == 2


# 이것을 실패시키는 것: 인증서를 가져온 뒤에 저장소 코드(release_tool.py)를 도는 것, stage를 가져오기 뒤로 옮기는 것.
def test_signing_job_runs_no_repository_code_after_the_certificate_import():
    body = jobs()["sign-macos"]
    cut = body.index("import-codesign-certs")
    before, after = body[:cut], body[cut:]
    assert "release_tool.py stage" in before and "release_tool.py payload-unpack" in before
    assert "release_tool.py" not in after and "python3 scripts" not in after
    for tool in ("codesign", "ditto", "notarytool"):
        assert tool in after


def test_verify_depends_on_package_and_publish_on_verify():
    assert re.search(r"needs: \[meta, package\]", jobs()["verify"])
    assert re.search(r"needs: \[meta, package, verify\]", jobs()["publish"])
