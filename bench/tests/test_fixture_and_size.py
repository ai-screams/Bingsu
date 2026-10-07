"""bench/fixtures/make-snapshot-present.sh and bench/size.sh. size.sh runs
with a stand-in cargo that writes a binary of a known size, so the loop,
the features and the output are checked without a release build."""
import json
import os
import pathlib
import platform
import subprocess
import sys

import pytest

from conftest import ROOT

FIXTURE = ROOT / "bench/fixtures/make-snapshot-present.sh"
SIZE = ROOT / "bench/size.sh"
OS = {"Darwin": "macos", "Linux": "linux"}[platform.system()]


def isolated_env(tmp, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(HOME=str(tmp), OLDPWD=str(tmp), GIT_CEILING_DIRECTORIES=str(tmp.parent), **extra)
    return env


def fixture(tmp, *args):
    return subprocess.run(["bash", str(FIXTURE), *args], env=isolated_env(tmp), cwd=tmp,
                          capture_output=True, text=True, timeout=30)


# 이것을 실패시키는 것: 세 파일의 크기(64 + 16,384, 128, 2,048)가 다르거나 폴더가 0700이 아닌 것.
def test_fixture_sizes(tmp_path):
    d = tmp_path / "run"
    r = fixture(tmp_path, str(d))
    assert r.returncode == 0 and r.stdout == f"{d}\n", r
    assert {p.name: p.stat().st_size for p in d.iterdir()} == {"snapshot": 16448, "marker": 128, "session": 2048}
    assert d.stat().st_mode & 0o777 == 0o700


# 이것을 실패시키는 것: 이미 있는 폴더에 쓰는 것(mkdir -p), 상대 경로를 받는 것, 인자 개수를 보지 않는 것.
@pytest.mark.parametrize("args", [["{tmp}/taken"], ["rel"], [], ["{tmp}/a", "{tmp}/b"]])
def test_fixture_refuses(tmp_path, args):
    (tmp_path / "taken").mkdir()
    (tmp_path / "taken/snapshot").write_text("keep")
    r = fixture(tmp_path, *[a.format(tmp=tmp_path) for a in args])
    assert r.returncode != 0, r
    assert (tmp_path / "taken/snapshot").read_text() == "keep"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["taken"]


CARGO = f"""#!{sys.executable}
import json, os, sys
a = sys.argv[1:]
open(os.environ["FAKE_CARGO_LOG"], "a").write(json.dumps(a) + "\\n")
tgt = a[a.index("--target-dir") + 1]
feats = a[a.index("--features") + 1] if "--features" in a else ""
os.makedirs(tgt + "/release", exist_ok=True)
open(tgt + "/release/bingsu-size-probe", "wb").write(b"x" * (1000 + 10 * len(feats)))
"""


def size(tmp, *args, **env):
    fake = tmp / "fakebin"
    fake.mkdir(exist_ok=True)
    (fake / "cargo").write_text(CARGO)
    (fake / "cargo").chmod(0o755)
    e = isolated_env(tmp, PATH=f"{fake}:{os.environ['PATH']}", FAKE_CARGO_LOG=str(tmp / "cargo.log"), **env)
    return subprocess.run(["bash", str(SIZE), *args], env=e, cwd=tmp, capture_output=True, text=True, timeout=30)


# 이것을 실패시키는 것: 세 조합의 기능을 바꿔 넘기거나, --release·--locked·probe의 manifest를 쓰지 않는 것,
# 바깥 CARGO_TARGET_DIR나 예전 빌드의 파일 크기를 읽는 것, 요약기가 읽는 os 이름을 쓰지 않는 것.
def test_size_rows(tmp_path):
    stale = tmp_path / "stale"
    (stale / "release").mkdir(parents=True)
    (stale / "release/bingsu-size-probe").write_bytes(b"s" * 5)
    out = tmp_path / "out"
    r = size(tmp_path, str(out), CARGO_TARGET_DIR=str(stale))
    assert r.returncode == 0, r.stderr
    rows = [json.loads(l) for l in (out / f"size-{OS}.jsonl").read_text().splitlines()]
    assert [(x["row"], x["features"], x["bytes"], x["os"]) for x in rows] == [
        ("base", "", 1000, OS), ("regex", "regex", 1050, OS), ("regex-yaml-json", "regex,yaml-json", 1150, OS)]
    calls = [json.loads(l) for l in (tmp_path / "cargo.log").read_text().splitlines()]
    manifest = str((ROOT / "bench/size-probe/Cargo.toml").resolve())
    assert all(c[:3] == ["build", "--quiet", "--release"] and "--locked" in c
               and c[c.index("--manifest-path") + 1] == manifest for c in calls), calls
    tgt = {c[c.index("--target-dir") + 1] for c in calls}
    assert len(tgt) == 1 and str(stale) not in tgt and not pathlib.Path(tgt.pop()).exists()


# 이것을 실패시키는 것: 상대 OUT_DIR(스크립트 폴더 기준으로 풀림)이나 이미 있는 결과 파일을 받아들이는 것.
@pytest.mark.parametrize("arg,code", [("rel", 2), ("{tmp}/taken", 1), (None, 2)])
def test_size_refuses(tmp_path, arg, code):
    (tmp_path / "taken").mkdir()
    (tmp_path / f"taken/size-{OS}.jsonl").write_text("keep")
    r = size(tmp_path, *([] if arg is None else [arg.format(tmp=tmp_path)]))
    assert r.returncode == code, r.stderr
    assert (tmp_path / f"taken/size-{OS}.jsonl").read_text() == "keep"
    assert not (tmp_path / "cargo.log").exists()


COSTS = pathlib.Path(os.environ.get("M1_FILE_COSTS", ROOT / "target/release/m1-file-costs"))


def costs(d):
    assert COSTS.is_file(), f"{COSTS} missing (cargo build --release -p bingsu-bench, or set M1_FILE_COSTS)"
    r = subprocess.run([str(COSTS), "--dir", str(d), "--snapshot-present", "--rounds", "5", "--warmup", "1"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    [row] = [json.loads(l) for l in r.stdout.splitlines()]
    assert row["row"] == "snapshot-present-read", row
    return row


# 이것을 실패시키는 것: m1-file-costs가 --snapshot-present 갈래로 가지 않는 것(일반 행을 냄), fixture 스크립트와
# 실행 파일의 크기가 어긋나는 것(na), 크기가 틀린 폴더를 잰 값으로 내는 것. 실행 파일이 없으면 실패한다.
def test_snapshot_present_row(tmp_path):
    fx = tmp_path / "run"
    assert fixture(tmp_path, str(fx)).returncode == 0
    row = costs(fx)
    assert row["n"] == 5 and row["median_ns"] > 0, row
    (fx / "session").write_bytes(b"\0" * 2047)
    assert costs(fx)["na"].startswith("fixture session: ")


# 이것을 실패시키는 것: 잰 연산이 세 파일을 다 읽지 않는 것(읽을 수 없는 파일이 있어도 잰 값이 나옴).
# root는 chmod 0으로도 읽으므로 root로 돌리면 실패한다(bench/tests를 돌리는 CI job은 root가 아님).
def test_snapshot_present_reads_every_file(tmp_path):
    assert os.geteuid() != 0, "run as a non-root user: chmod 0 does not stop root from reading"
    fx = tmp_path / "run"
    assert fixture(tmp_path, str(fx)).returncode == 0
    for name in ("snapshot", "marker", "session"):
        (fx / name).chmod(0)
        na = costs(fx)["na"]
        assert na.startswith(f"{name}: ") and na.endswith("(round 1)"), na
        (fx / name).chmod(0o600)
