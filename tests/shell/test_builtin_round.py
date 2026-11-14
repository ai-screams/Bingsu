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
    published,
    rounds_until,
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
    """A command session; its prompts pass the pinned collector (as every
    CommandSession's do), so the collection answers the drawn languages."""


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
    published(session, b"18.20.4")
    assert b"18.20.4" in command_response(session)
    assert counted(node) == 1, counted(node)
    rounds(session, 3)
    assert counted(node) == 1, "a cached probe ran again"


def explain(session):
    """`config check --explain` run from the session's shell folder."""
    env = dict(session.env, PWD=str(session.pwd))
    r = subprocess.run([str(session._launcher), "config", "check", "--explain"], cwd=session.pwd, env=env,
                       capture_output=True, timeout=20)
    return r.stdout.decode()


# E2 내장 절: config check --explain이 그리는 언어마다 회차가 지금 정할 것을 보인다. 저장된 폴더 사실이 없으면
# 정하지 않았다고 쓰고, 회차 뒤에는 pyenv 빠른 경로의 버전과 node probe의 실행 파일을 보이며, 아무것도 실행하지
# 않는다. 이것을 실패시키는 것: 내장 절을 붙이지 않는 것, 저장된 수집 응답을 읽지 않는 것(늘 정하지 않음),
# explain이 probe를 실행하는 것.
def test_explain_shows_what_a_round_would_decide(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "python", "node")
    pyenv_fast(session)
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    session.init()
    before = explain(session)
    assert "builtin languages (--explain;" in before, before
    assert "node  not decided: no folder facts" in before, before
    ready(session)
    published(session, b"3.12.1")
    Path(f"{node}.runs").unlink(missing_ok=True)
    after = explain(session)
    assert "python  shows 3.12.1 without running anything" in after, after
    runs = [line for line in after.splitlines() if line.startswith("node  runs ")]
    assert len(runs) == 1 and runs[0].endswith("/bin/node --version"), after
    assert counted(node) == 0, "explain ran the probe"
    # A valid response under a store folder others may read (0755) is not
    # read: the store's folder checks refuse it, as the helper's do.
    stores = list((Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu").rglob("collections-v1/*/store"))
    assert len(stores) == 1, stores
    stores[0].chmod(0o755)
    try:
        opened = explain(session)
    finally:
        stores[0].chmod(0o700)
    assert "node  not decided: no folder facts" in opened, opened
    assert "python  shows 3.12.1" in explain(session)


# D3b: 앞단이 이 셸의 내장 언어 버전을 프롬프트에 그린다. 같은 폴더라도 언어 변수가 다른 셸(여기서는 volta
# 폴더 변수)에는 그 값을 그리지 않는다(D3b Q1). 이것을 실패시키는 것: 앞단이 언어 segment의 응답 값을 채우지
# 않는 것, 앞단의 환경 요약값 비교를 빼는 것(다른 셸에도 보임).
def test_builtin_version_is_drawn_for_its_own_shell(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    published(session, b"18.20.4")
    assert b"18.20.4" in command_response(session)
    assert b"18.20.4" in session.prompt()
    session.wait_quiet(timeout=8)
    session.env["VOLTA_HOME"] = str(session.base / "volta")
    assert b"18.20.4" not in session.prompt()
    session.wait_quiet(timeout=8)


# TERM·TZ만 다른 두 셸(같은 폴더)은 같은 내장 버전을 둘 다 그린다(F1-b). 이것을 실패시키는 것: 내장 언어
# 요약값에 TERM이나 TZ를 다시 넣는 것.
def test_builtin_version_is_shared_across_terminals(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    session.env.update(TERM="xterm-256color", TZ="UTC")
    ready(session)
    published(session, b"18.20.4")
    assert b"18.20.4" in session.prompt()
    session.wait_quiet(timeout=8)
    for name, value in (("TERM", "tmux-256color"), ("TZ", "Asia/Seoul")):
        session.env[name] = value
        assert b"18.20.4" in session.prompt(), name
        session.wait_quiet(timeout=8)


# 프로브의 첫 줄에서 버전만 값으로 남긴다. 버전이 없는 줄은 값 없는 실패 항목이고 원본 줄도 남기지 않는다. 이것을
# 실패시키는 것: probe_entry의 버전 추출을 지우는 것(첫 줄이 그대로 값이 됨).
def test_builtin_probe_publishes_only_a_version(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "node")
    node = install(session.base / "bin", "node")
    Path(f"{node}.out").write_text("not-a-version-line\n")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ready(session)
    published(session, b"node")
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
    published(session, b"3.12.1")
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
    published(session, b"3.12.1")
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
    published(session, b"18.20.4")
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
    published(session, b"18.20.4")
    assert counted(inside) == 0, "an executable inside the repository ran"
    assert counted(outside) >= 1
    assert b"18.20.4" in command_response(session)


# 수집이 안쪽 저장소의 뿌리를 알려도, 그 위의 바깥 저장소 bin에 있는 node는 실행하지 않는다. 내장 언어도 설정 단위와
# 같은 저장소 목록(수집 뿌리와 셸 폴더 위의 `.git` 조상)을 쓰기 때문이다. 수집이 없는 회차는 언어를 그리면
# 생기지 않고(test_language_only_layout_is_collected), 뿌리를 확정하지 못한 회차는 정하지 않는다
# (test_unsettled_repository_decides_no_language). 이것을 실패시키는 것: 명령 회차의 저장소 목록에서 조상 검사를
# 빼는 것(수집 뿌리만 남아 바깥 저장소의 node가 실행됨).
def test_builtin_probe_skips_an_outer_repository_bin(tmp_path, _native_boot_required):
    session = BuiltinSession(tmp_path)
    session.env["HOME"] = str(session.base)
    session.level = "info"
    outer = session.base / "outer"
    inner = outer / "inner"
    (inner / "sub").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(outer)], check=True)
    subprocess.run(["git", "init", "-q", str(inner)], check=True)
    session.pwd = inner / "sub"
    above = install(outer / "bin", "node")
    outside = install(session.base / "tools", "node")
    session.env["PATH"] = f"{above.parent}:{outside.parent}:{session.env['PATH']}"
    session.put("[layout.line1]\nleft=['git', 'node']\n[layout.line2]\nleft=['char']\n")
    ready(session)
    for f in (above, outside):
        Path(f"{f}.runs").unlink(missing_ok=True)
    published(session, b"18.20.4")
    assert counted(above) == 0, "a node in an outer repository's bin ran"
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
    published(session, b"18.20.4")
    assert b"18.20.4" in command_response(session)


def git_repo(base):
    """A repository with one commit on main, a `sub` folder and a `bin`."""
    repo = base / "repo"
    (repo / "sub").mkdir(parents=True)
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@e"]
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(repo)], check=True)
    (repo / "f").write_text("x\n")
    subprocess.run([*git, "add", "f"], check=True)
    subprocess.run([*git, "commit", "-qm", "c"], check=True)
    return repo


RESOLVED = b"command round: shell folder resolved for rustup"


def unsettled(tmp_path, pwd_of, config_unit=False):
    """A round whose folder facts cannot settle the repository: the
    repository's own node is first on PATH, another node after it."""
    session = BuiltinSession(tmp_path)
    session.env["HOME"] = str(session.base)
    session.level = "debug"
    repo = git_repo(session.base)
    session.pwd = pwd_of(session.base, repo)
    inside = install(repo / "bin", "node")
    outside = install(session.base / "tools", "node")
    session.env["PATH"] = f"{inside.parent}:{outside.parent}:{session.env['PATH']}"
    unit = ""
    if config_unit:
        canary = session.base / "unit-ran"
        unit = f"[segment.\"custom/u\"]\nkind='command'\ncommand=['/usr/bin/touch','{canary}']\n"
    drawn = "'node', 'custom/u'" if config_unit else "'node'"
    session.put(f"{unit}[layout.line1]\nleft=[{drawn}]\n[layout.line2]\nleft=['char']\n")
    ready(session)
    for f in (inside, outside):
        Path(f"{f}.runs").unlink(missing_ok=True)
    seen = session.log().count(b"command round: PATH searched")
    resolved = session.log().count(RESOLVED)
    rounds(session, 3)
    searched = session.log().count(b"command round: PATH searched") - seen
    assert session.log().count(RESOLVED) == resolved, "a shell folder was resolved for no language"
    return session, inside, outside, searched


def alias(base, repo):
    link = base / "alias"
    link.symlink_to(repo / "sub")
    return link


def deep(base, repo):
    folder = repo / "sub"
    for i in range(34):
        folder = folder / f"d{i}"
    folder.mkdir(parents=True)
    return folder


# 폴더 사실이 저장소를 확정하지 못하면(별칭 경로, 탐색 깊이 제한) 내장 언어를 정하지 않는다. 저장소 안 node도, 밖
# node도 실행하지 않고 PATH도 걷지 않는다(D3a 재리뷰 H1, M3). 이것을 실패시키는 것: 미확정을 저장소 밖으로 보는
# 것(셸 폴더가 저장소를 대신해 /repo/bin/node가 실행됨), 할 일이 없는 회차에도 PATH를 걷는 것.
@pytest.mark.parametrize("where", ["alias", "deep"])
def test_unsettled_repository_decides_no_language(tmp_path, where, _native_boot_required):
    session, inside, outside, searched = unsettled(tmp_path, alias if where == "alias" else deep)
    assert counted(inside) == 0, "an executable inside the repository ran"
    assert counted(outside) == 0, "a language was decided without a settled repository"
    assert b"18.20.4" not in command_response(session)
    assert searched == 0, session.log()


# 양성 대조: 같은 회차에 설정 단위가 있으면 PATH를 걷고 그 단위는 실행된다(내장 언어는 여전히 정하지 않음).
# 이것을 실패시키는 것: 언어를 정할 수 없을 때 설정 단위까지 버리는 것.
def test_config_units_still_search_beside_an_unsettled_language(tmp_path, _native_boot_required):
    session, inside, outside, searched = unsettled(tmp_path, alias, config_unit=True)
    assert searched >= 1, session.log()
    assert (session.base / "unit-ran").exists(), "the config unit did not run"
    assert counted(inside) == 0 and counted(outside) == 0


# git과 언어 segment를 함께 그려도 git 값이 실제 프롬프트에 보인다. 도우미 요청의 mask와 앞단이 기대하는 binding이
# 같은 규칙에서 나오기 때문이다(D3a 재리뷰 M2). 이것을 실패시키는 것: 언어 회차의 dir 비트를 도우미 쪽에서만
# 더하는 것(수집 응답 전체가 거부되어 git 표시가 사라짐).
def test_git_shows_beside_a_language_segment(tmp_path, _native_boot_required):
    session = BuiltinSession(tmp_path)
    session.env["HOME"] = str(session.base)
    repo = git_repo(session.base)
    session.pwd = repo / "sub"
    node = install(session.base / "tools", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    session.put("[layout.line1]\nleft=['git', 'node']\n[layout.line2]\nleft=['char']\n")
    session.init()
    session.await_text("main", timeout=8)


# rustup 회차만 셸 폴더를 정규화한다(rustup의 폴더 override 비교). 설치된 1.80.0은 실행 없이 보이고, 그 회차의 debug
# 로그에 정규화 줄이 남는다. 미확정 저장소 회차에는 그 줄이 없다(위 시험). 이것을 실패시키는 것: 정규화 로그를
# 지우는 것, rustup 회차에 셸 폴더를 정규화하지 않는 것.
def test_rustup_round_resolves_the_shell_folder(tmp_path, _native_boot_required):
    session = session_with(tmp_path, "rust")
    session.level = "debug"
    cargo = session.base / "cargo"
    rustup = session.base / "rustup"
    proxy = install(cargo / "bin", "rustc")
    rustc = install(rustup / "toolchains" / "1.80.0-zz-host" / "bin", "rustc")
    (rustup / "settings.toml").write_text('version = "12"\ndefault_host_triple = "zz-host"\n')
    for folder in (rustup, rustup / "toolchains", rustup / "toolchains" / "1.80.0-zz-host"):
        folder.chmod(0o755)
    (rustup / "settings.toml").chmod(0o644)
    (session.pwd / "rust-toolchain").write_text("1.80.0\n")
    session.env["CARGO_HOME"] = str(cargo)
    session.env["RUSTUP_HOME"] = str(rustup)
    session.env["PATH"] = f"{proxy.parent}:{session.env['PATH']}"
    ready(session)
    seen = session.log().count(RESOLVED)
    published(session, b"1.80.0")
    assert b"1.80.0" in command_response(session)
    assert session.log().count(RESOLVED) > seen, session.log()
    assert counted(proxy) == 0 and counted(rustc) == 0


def deno(session, folder=None):
    """A `deno` that counts its runs and prints a version line, in `folder`
    (`bin` beside the shell's folder by default)."""
    counter = session.base / "deno.runs"
    path = (folder or session.base / "bin") / "deno"
    path.parent.mkdir(exist_ok=True)
    path.write_text(f"#!/bin/sh\necho x >> '{counter}'\necho 'deno 1.46.3 (stable, release)'\n")
    path.chmod(0o755)
    return path, counter


UNRESOLVED = b"command round: a unit's executable was not found or failed the checks"


def user_language(interpreter, extra=""):
    """A user language segment and a layout that draws nothing else that
    collects: no dir, no git, no builtin language."""
    return ("[segment.\"custom/deno\"]\nkind='language'\ndetect_files=['deno.json']\n"
            f"interpreter='{interpreter}'\nversion=['--version']\n{extra}"
            "[layout.line1]\nleft=['custom/deno']\n[layout.line2]\nleft=['char']\n")


def shown_after_a_round(session):
    """The next prompt's bytes after one more settled round."""
    session.prompt()
    session.wait_quiet(timeout=8)
    shown = session.prompt()
    session.wait_quiet(timeout=8)
    return shown


# GATE-LANG-USER.1: 사용자 language segment만 그리는 레이아웃에서도 수집이 일어나, 감지 파일이 있는 폴더에서 interpreter를
# 버전 인자로 실행하고 버전만 그린다. 감지 파일을 지우면 다음 회차부터 숨고, 더 실행하지 않으며, 숨긴 항목을 다시
# 쓰지 않는다(cache 없음). 이것을
# 실패시키는 것: worker mask에 사용자 language의 dir 비트를 더하지 않는 것(수집 요청이 없어 감지 안 됨), 감지 안 된
# 언어에 실패 항목을 쓰지 않는 것(지운 뒤에도 보임), 실행할 단위가 없는 회차에 그 항목을 발행하지 않는 것, 이미 숨긴
# 항목을 회차마다 다시 쓰는 것(응답 파일이 새로 설치됨), 응답 값을 버전으로 줄이지 않는 것.
def test_user_language_only_layout_draws_its_version_where_its_files_are(tmp_path, _native_boot_required):
    session = session_with(tmp_path)
    interpreter, counter = deno(session)
    (session.pwd / "deno.json").write_text("{}\n")
    session.put(user_language(interpreter))
    ready(session)
    published(session, b"1.46.3")
    assert runs(counter) >= 1
    shown = session.prompt()
    session.wait_quiet(timeout=8)
    assert b"1.46.3" in shown and b"stable" not in shown, shown
    (session.pwd / "deno.json").unlink()
    assert b"1.46.3" not in shown_after_a_round(session)
    before = runs(counter)
    store = Path(session.env["XDG_RUNTIME_DIR"]) / "bingsu"
    hidden = [(p, p.stat().st_ino, p.stat().st_mtime_ns) for p in store.rglob("collections-v1/*/store/command")]
    assert hidden
    rounds(session, 2)
    assert runs(counter) == before, "a language ran where its files are gone"
    again = [(p, p.stat().st_ino, p.stat().st_mtime_ns) for p in store.rglob("collections-v1/*/store/command")]
    assert again == hidden, "a hidden language was published again"


# GATE-LANG-USER.2: 감지 파일이 없는 폴더에서는 interpreter를 실행하지 않고 아무것도 그리지 않는다. 이것을 실패시키는
# 것: helper의 감지 확인(gate_languages)을 지우는 것(파일 없이도 실행).
def test_user_language_runs_nothing_where_its_files_are_not(tmp_path, _native_boot_required):
    session = session_with(tmp_path)
    interpreter, counter = deno(session)
    session.put(user_language(interpreter))
    ready(session)
    rounds(session, 3)
    assert runs(counter) == 0, "a language ran without its detect files"
    assert b"1.46.3" not in session.prompt()
    session.wait_quiet(timeout=8)


# GATE-LANG-USER.3: interpreter의 조회는 command의 첫 단어와 같다. 상대 경로(`./deno`)는 셸 폴더에 실행 파일이 있어도
# 실행하지 않는다. 공백이 든 bare 이름은 거부해, 그 이름 그대로의 실행 파일(`deno --version`)이 PATH에 있어도 실행하지
# 않는다(음성 대조). 공백이 든 절대 경로(`<base>/my tools/deno`)는 그 파일 하나를 가리키므로 실행한다. 이름만 쓴 `deno`는
# PATH에서 찾아 실행한다(양성 대조). 찾지
# 못한 결과는 10초 실패 항목이라 그 안의 회차는 다시 찾지 않는다. 이것을 실패시키는 것: 상대 경로를 이름으로 바꿔
# PATH에서 찾는 것, 이름의 공백 거부를 지우는 것(그 이름의 파일이 실행됨), 절대 경로에도 공백 거부를 거는 것(공백이 든
# 경로가 실행되지 않음), interpreter를 공백으로 나눠 인자로 만드는
# 것, 찾지 못한 항목을 감지 파일 없는 요약값으로 쓰는 것(적중하지 않아 회차마다 다시 찾음).
@pytest.mark.parametrize("interpreter, runs_it", [("./deno", False), ("deno --version", False),
                                                  ("{base}/my tools/deno", True), ("deno", True)],
                         ids=["relative", "space", "absolute-space", "name"])
def test_user_language_interpreter_is_looked_up_as_a_command(tmp_path, interpreter, runs_it,
                                                               _native_boot_required):
    session = session_with(tmp_path)
    found, counter = deno(session)
    deno(session, session.pwd)
    deno(session, session.base / "my tools")
    # The exact name a whitespace value would look up, as an executable.
    spaced = found.parent / "deno --version"
    spaced.write_text(found.read_text())
    spaced.chmod(0o755)
    session.env["PATH"] = f"{found.parent}:{session.env['PATH']}"
    (session.pwd / "deno.json").write_text("{}\n")
    interpreter = interpreter.format(base=session.base)
    session.put(user_language(interpreter))
    ready(session)
    published(session, b"custom/deno")
    assert (runs(counter) >= 1) == runs_it, (interpreter, runs(counter))
    assert (b"1.46.3" in session.prompt()) == runs_it
    session.wait_quiet(timeout=8)
    if not runs_it:
        # The failed lookup is a failure entry the next rounds hit for 10 s:
        # they look nothing up again.
        seen = session.log().count(UNRESOLVED)
        assert seen >= 1, session.log()
        rounds(session, 2)
        assert session.log().count(UNRESOLVED) == seen, "a failed lookup was tried again inside 10 s"


# GATE-LANG-USER.1-cache: cache를 둔 language는 그 기간 안의 회차에 다시 실행하지 않는다. 응답 항목은 감지 파일까지
# 묶은 요약값을 쓰므로, helper의 적중 판정도 같은 요약값이어야 맞는다. 이것을 실패시키는 것: 적중 판정에 감지 파일을
# 뺀 요약값을 쓰는 것(회차마다 다시 실행).
def test_user_language_cache_hit_runs_nothing(tmp_path, _native_boot_required):
    session = session_with(tmp_path)
    interpreter, counter = deno(session)
    (session.pwd / "deno.json").write_text("{}\n")
    session.put(user_language(interpreter, "cache='30s'\n"))
    ready(session)
    published(session, b"1.46.3")
    before = runs(counter)
    assert before >= 1
    rounds(session, 3)
    assert runs(counter) == before, "a language inside its cache time ran again"
    assert b"1.46.3" in session.prompt()
    session.wait_quiet(timeout=8)


# GATE-LANG-USER.1-git: git과 사용자 language segment를 함께 그려도 git 값이 실제 프롬프트에 보인다. 도우미 요청의
# mask와 앞단이 스냅샷에서 decode한 설정으로 얻는 기대 binding이 같은 규칙에서 나오기 때문이다. 이것을 실패시키는
# 것: 사용자 language의 dir 비트를 도우미 쪽에서만 더하는 것(수집 응답 전체가 거부되어 git 표시가 사라짐).
def test_git_shows_beside_a_user_language(tmp_path, _native_boot_required):
    session = BuiltinSession(tmp_path)
    session.env["HOME"] = str(session.base)
    repo = git_repo(session.base)
    session.pwd = repo / "sub"
    (session.pwd / "deno.json").write_text("{}\n")
    interpreter, counter = deno(session, session.base / "tools")
    session.put("[segment.\"custom/deno\"]\nkind='language'\ndetect_files=['deno.json']\n"
                f"interpreter='{interpreter}'\nversion=['--version']\n"
                "[layout.line1]\nleft=['git', 'custom/deno']\n[layout.line2]\nleft=['char']\n")
    session.init()
    session.await_text("main", timeout=8)


# 명령 응답에서 내장 언어와 설정 단위는 칸을 따로 쓴다. 설정 단위 32개를 모두 그리고 node를 함께 그려도, 32개의
# 값과 node 버전이 한 응답에 함께 남는다. 이것을 실패시키는 것: 응답 상한을 출처 구분 없이 32로 되돌리는 것(서로
# 밀어내 하나가 빠짐), merge가 넘친 출처 밖의 항목을 지우는 것.
def test_builtin_and_32_units_share_the_response(tmp_path, _native_boot_required):
    session = session_with(tmp_path)
    node = install(session.base / "bin", "node")
    session.env["PATH"] = f"{node.parent}:{session.env['PATH']}"
    ids = [f"custom/u{i:02}" for i in range(32)]
    units = "".join(f"[segment.\"{u}\"]\nkind='command'\ncommand=['/bin/echo', 'value-{u[-2:]}']\ncache='300s'\n"
                    for u in ids)
    drawn = ", ".join(f"'{u}'" for u in ids)
    session.put(units + f"[layout.line1]\nleft=['node', {drawn}]\n[layout.line2]\nleft=['char']\n")
    ready(session)
    # Eight config units run a round (round robin): four rounds reach all 32.
    rounds_until(session, lambda: all(f"value-{u[-2:]}".encode() in command_response(session) for u in ids)
                 and b"18.20.4" in command_response(session), limit=12)
    rounds(session, 2)
    response = command_response(session)
    assert b"18.20.4" in response
    missing = [u for u in ids if f"value-{u[-2:]}".encode() not in response]
    assert not missing, missing
