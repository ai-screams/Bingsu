"""Builtin language versions through the real helper, supervisor and relay
(plan D3a): a drawn language segment starts a round without config units,
its probe runs the real executable once and its version is published to the
command response; a version manager's fast path publishes without running.
The language command is `version-stub` (crates/bingsu-bench) copied under
the command's name: a probe never runs a `#!` script."""
import os
import subprocess
from pathlib import Path
import shutil

import pytest
from shell_support import real_bin, real_collector
from test_command_round import (
    CommandSession,
    _native_boot_required,  # noqa: F401 (fixture)
    command_response,
    forget_results,
    published_rounds,
    ready,
    rounds,
    runs,
)


def stub():
    path = Path(os.environ.get("BINGSU_VERSION_STUB", real_bin().with_name("version-stub")))
    assert path.is_file(), f"build it first: cargo build -p bingsu-bench --bin version-stub ({path})"
    return path


def install(folder, name):
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    shutil.copyfile(stub(), target)
    target.chmod(0o755)
    return target


def counted(target):
    return runs(Path(f"{target}.runs"))


def draws(*segments):
    words = ", ".join(f"'{s}'" for s in (*segments, "char"))
    return f"[layout.line2]\nleft=[{words}]\n"


class BuiltinSession(CommandSession):
    """A command session whose prompts also pass the pinned collector, so
    the collection runs and answers the drawn languages."""

    def prompt_args(self):
        return super().prompt_args() + [f"--collector-exe={real_collector()}"]


def session_with(tmp_path, *segments):
    session = BuiltinSession(tmp_path)
    session.env["HOME"] = str(session.base)
    # The shell's folder stands for the repository, and `PATH` folders inside
    # it are left out (C2 ruling J9): the tools live beside it.
    session.pwd = session.base / "work"
    session.pwd.mkdir()
    session.level = "info"
    session.put(draws(*segments))
    return session


def pyenv_fast(session):
    """pyenv's shim folder first on PATH and 3.12.1 installed and selected."""
    root = session.base / "pyenv"
    # As pyenv writes its shims: a script through env, which the executable
    # checks refuse; it must still be known as pyenv's (D3a review M3).
    shim = root / "shims" / "python3"
    shim.parent.mkdir(parents=True)
    shim.write_text("#!/usr/bin/env bash\nexec pyenv exec python3 \"$@\"\n")
    shim.chmod(0o755)
    # As CPython's own install lays it out: python3 is a link to python3.12.
    real = install(root / "versions" / "3.12.1" / "bin", "python3.12")
    (real.parent / "python3").symlink_to("python3.12")
    for folder in (root, root / "versions", root / "versions" / "3.12.1"):
        folder.chmod(0o755)
    (session.pwd / ".python-version").write_text("3.12.1\n")
    session.env["PYENV_ROOT"] = str(root)
    session.env["PATH"] = f"{shim.parent}:{session.env['PATH']}"
    return shim, real


# GATE-LANG-NODE.1: 설정 단위 없이 언어 segment만 그려도 감독이 뜨고, 프로브가 PATH의 실제 실행 파일을 한 번
# 실행해 버전을 명령 응답에 발행한다. 캐시 기간 안의 다음 회차는 다시 실행하지 않는다. 이것을 실패시키는 것:
# prepare에서 언어 segment가 있어도 NoUnits로 끝내는 것, grant에서 probe만 있는 회차를 버리는 것, probe 결과의
# 캐시 판정을 지우는 것.
def test_builtin_probe_runs_once_and_is_cached(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    Path(f"{node}.runs").unlink(missing_ok=True)
    published_rounds(session)
    assert b"18.20.4" in command_response(session)
    assert counted(node) == 1, counted(node)
    rounds(session, 3)
    assert counted(node) == 1, "a cached probe ran again"


# 프로브의 첫 줄에서 버전만 값으로 남긴다. 버전이 없는 줄은 값 없는 실패 항목이고 원본 줄도 남기지 않는다. 이것을
# 실패시키는 것: probe_entry의 버전 추출을 지우는 것(첫 줄이 그대로 값이 됨).
def test_builtin_probe_publishes_only_a_version(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    node = install(session.base / "bin", "node")
    Path(f"{node}.out").write_text("not-a-version-line\n")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    published_rounds(session)
    assert counted(node) >= 1
    response = command_response(session)
    assert b"node" in response, response
    assert b"not-a-version-line" not in response, response


# GATE-LANG-FAST.1: pyenv shim 뒤의 설치된 버전은 아무것도 실행하지 않고 발행하며, 같은 결정은 다시 쓰지 않는다.
# 이것을 실패시키는 것: 같은 빠른 값을 회차마다 다시 발행하는 것(응답 파일이 회차마다 새로 설치됨), 빠른 경로
# 대신 실행하는 것.
def test_builtin_fast_value_is_written_once(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "python")
    shim, real = pyenv_fast(session)
    ready(session)
    published_rounds(session)
    assert b"3.12.1" in command_response(session)
    store = Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu"
    first = [(p, p.stat().st_ino, p.stat().st_mtime_ns) for p in store.rglob("collections-v1/*/store/command")]
    assert first
    rounds(session, 3)
    again = [(p, p.stat().st_ino, p.stat().st_mtime_ns) for p in store.rglob("collections-v1/*/store/command")]
    assert again == first, "an unchanged fast value was published again"
    assert counted(shim) == 0 and counted(real) == 0, (counted(shim), counted(real))




# 중립 폴더가 검사를 통과하지 못하면 프로브는 돌지 않지만, 실행 없이 정한 값(빠른 경로)은 그대로 발행한다.
# 이것을 실패시키는 것: 중립 폴더 실패 때 내장 언어를 통째로 버리는 것(빠른 값이 사라짐), 그때도 프로브를 허가에
# 넣는 것(node가 실행됨).
def test_builtin_fast_value_survives_a_bad_neutral_folder(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "python", "node")
    pyenv_fast(session)
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    folder = session.neutral()
    folder.chmod(0o700)
    (folder / "left").write_text("x")
    folder.chmod(0o500)
    Path(f"{node}.runs").unlink(missing_ok=True)
    published_rounds(session)
    assert b"3.12.1" in command_response(session)
    assert counted(node) == 0, counted(node)
    assert b"neutral folder is not empty" in session.log(), session.log()


# 무효 표식 회차에도 내장 언어 버전은 실행·발행한다(설정 유래 단위만 막힘, 계획 Review Focus). 이것을 실패시키는
# 것: 무효 표식(허가 마감 0)이면 내장 언어를 버리는 것.
def test_builtin_versions_survive_invalid_marker(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    session.put("[broken")
    assert session.run("reload").returncode == 1
    Path(f"{node}.runs").unlink(missing_ok=True)
    forget_results(session)
    record = session.prompt()
    assert b"degraded:trust-invalid" in record, record
    session.wait_quiet(timeout=8)
    published_rounds(session)
    assert counted(node) >= 1, counted(node)
    assert b"18.20.4" in command_response(session)


# 레이아웃이 dir을 그리지 않아도 언어 회차는 수집된 저장소 뿌리를 경계로 쓴다. /repo/sub에서 PATH 앞의 /repo/bin/node는
# 저장소 안이라 실행하지 않고, 저장소 밖 node를 실행한다(D3a 리뷰 H1). 이것을 실패시키는 것: 언어 회차에 dir의
# 폴더 사실을 묻지 않는 것(셸 폴더가 저장소를 대신함), 폴더 사실 없이 내장 언어를 정하는 것.
def test_builtin_probe_never_runs_from_the_repository(tmp_path, _native_boot_required):
    session = BuiltinSession(tmp_path)
    session.env["HOME"] = str(session.base)
    session.level = "info"
    repo = session.base / "repo"
    (repo / "sub").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    session.pwd = repo / "sub"
    inside = install(repo / "bin", "node")
    outside = install(session.base / "tools", "node")
    session.env["PATH"] = f"{inside.parent}:{outside.parent}:{session.env['PATH']}"
    session.put("[layout.line1]\nleft=['git', 'node']\n[layout.line2]\nleft=['char']\n")
    ready(session)
    for f in (inside, outside):
        Path(f"{f}.runs").unlink(missing_ok=True)
    published_rounds(session)
    assert counted(inside) == 0, "an executable inside the repository ran"
    assert counted(outside) >= 1
    assert b"18.20.4" in command_response(session)


# 레이아웃에 언어 segment만 있어도(worker mask 0) 수집이 일어나 버전을 발행한다(D3a 리뷰 M2). 이것을 실패시키는 것:
# 언어 회차에 폴더 사실을 묻지 않는 것(답이 있어도 저장소 경계가 없어 정하지 않음).
def test_language_only_layout_is_collected(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    session.put("[layout.line1]\nleft=['node']\n[layout.line2]\nleft=['char']\n")
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    published_rounds(session)
    assert b"18.20.4" in command_response(session)
