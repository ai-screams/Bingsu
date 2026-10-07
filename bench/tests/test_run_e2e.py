"""bench/run-e2e.sh with a stand-in hyperfine: the stand-in runs every
command once (as `hyperfine -N` would: split on spaces, no shell, output
discarded) and fails when one exits non-zero, so the shape of the run is
checked without the timing tool. The output folder then goes through
summarize.py. Needs the bingsu binary (BINGSU_BIN, default
target/debug/bingsu), zsh and fish; a missing one fails, never skips."""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from conftest import ROOT

SCRIPT = ROOT / "bench/run-e2e.sh"
BIN = pathlib.Path(os.environ.get("BINGSU_BIN", ROOT / "target/debug/bingsu")).resolve()

FAKE = f"""#!{sys.executable}
import json, os, shlex, subprocess, sys, time
a = sys.argv[1:]
if a == ["--version"]:
    print("hyperfine 0.0.0-stand-in"); sys.exit(0)
log = open(os.environ["FAKE_HF_LOG"], "a")
log.write(json.dumps({{"argv": a}}) + "\\n")
out = a[a.index("--export-json") + 1]
cmds = [x for x in a[a.index("--export-json") + 2:]]
res = []
for c in cmds:
    t = time.monotonic()
    r = subprocess.run(shlex.split(c), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE)
    dt = time.monotonic() - t
    log.write(json.dumps({{"cmd": c, "rc": r.returncode, "home": os.environ.get("HOME"),
                           "stderr": r.stderr.decode(errors="replace")}}) + "\\n")
    if r.returncode != 0:
        sys.exit(f"stand-in hyperfine: {{c!r}} exited {{r.returncode}}")
    res.append({{"command": c, "times": [dt], "exit_codes": [0]}})
open(out, "w").write(json.dumps({{"results": res}}))
"""


def env_for(tmp):
    """Isolated: HOME, OLDPWD and cwd in tmp; no GIT_*; the stand-in first on PATH."""
    fake_dir = tmp / "fakebin"
    fake_dir.mkdir()
    (fake_dir / "hyperfine").write_text(FAKE)
    (fake_dir / "hyperfine").chmod(0o755)
    (tmp / "home").mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(PATH=f"{fake_dir}:{os.environ['PATH']}", HOME=str(tmp / "home"), OLDPWD=str(tmp),
               GIT_CEILING_DIRECTORIES=str(tmp.parent), FAKE_HF_LOG=str(tmp / "hf.log"),
               BINGSU_BIN=str(BIN))
    return env


def run(tmp, *args):
    return subprocess.run(["bash", str(SCRIPT), *args], env=env_for(tmp), cwd=tmp,
                          capture_output=True, timeout=120)


def log(tmp):
    return [json.loads(l) for l in (tmp / "hf.log").read_text().splitlines()]


def summarize_out(out):
    r = subprocess.run([sys.executable, "-B", str(ROOT / "bench/summarize.py"), str(out)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


# 이것을 실패시키는 것: 300회·warm-up 20을 넘기지 않는 것, 측정 명령이 0이 아닌 상태로 끝나는 것(가짜가 실패시킴),
# 측정 셸의 HOME을 사용자 것으로 두는 것, meta 줄(os·commit·sha256)을 쓰지 않는 것, 요약기가 셸 init 행을 짝짓지
# 못하는 이름으로 내보내는 것.
def test_warm_run_shape(tmp_path):
    assert BIN.is_file(), f"{BIN} missing (cargo build -p bingsu)"
    out = tmp_path / "out"
    r = run(tmp_path, str(out))
    assert r.returncode == 0, (r.stderr, (tmp_path / "hf.log").read_text())
    entries = log(tmp_path)
    calls = [e["argv"] for e in entries if "argv" in e]
    assert len(calls) in (5, 6) and all(c[:7] == ["-N", "--style", "basic", "--warmup", "20", "--runs", "300"]
                                        for c in calls), calls
    ran = [e for e in entries if "cmd" in e]
    # run-e2e gives the timed commands a HOME of its own, not the caller's
    homes = {e["home"] for e in ran}
    assert len(homes) == 1 and str(tmp_path / "home") not in homes and os.environ.get("HOME") not in homes, homes
    assert not pathlib.Path(homes.pop()).exists()  # removed on exit
    meta = json.loads((out / "e2e-meta.jsonl").read_text())["meta"]
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert meta["os"] in ("macos", "linux") and meta["commit"] == commit and len(meta["bingsu_sha256"]) == 64
    text = summarize_out(out)
    for shell in ("zsh", "fish"):
        assert f"{shell}): generator run median" in text, text
    line = [l for l in text.splitlines() if l.startswith(f"X-23 init added ({meta['os']}, zsh)")][0]
    assert "estimate not measured (header64+marker128)" in line, line
    assert "X-22 front path" in text and "startup (" in text
    if meta["bash_skipped"]:
        assert not (out / "init-bash.json").exists()
    else:
        assert "bash): generator run median" in text and (out / "init-bash.json").exists()


# 이것을 실패시키는 것: --cold-once가 1회·warm-up 0이 아니거나, 따뜻한 파일(prompt·redraw·init-gen)을 다시 쓰거나,
# 차가운 행에 -cold를 붙이지 않는 것(요약기가 따뜻한 추정에 섞음).
def test_cold_once_shape(tmp_path):
    out = tmp_path / "out"
    r = run(tmp_path, str(out), "--cold-once")
    assert r.returncode == 0, r.stderr
    calls = [e["argv"] for e in log(tmp_path) if "argv" in e]
    assert all(c[3:7] == ["--warmup", "0", "--runs", "1"] for c in calls), calls
    names = sorted(p.name for p in out.iterdir())
    assert "prompt.json" not in names and "init-zsh-cold.json" in names and "e2e-meta-cold.jsonl" in names
    assert all(n.endswith("-cold.json") or n == "e2e-meta-cold.jsonl" for n in names), names


# 이것을 실패시키는 것: 상대 OUT_DIR·모르는 둘째 인자·이미 있는 결과 파일을 받아들이는 것(덮어쓰거나 300회로 돌며 -cold를 붙임).
@pytest.mark.parametrize("args,code", [(["rel/out"], 2), (["{tmp}/o", "--cold"], 2), (["{tmp}/o", "--cold-once", "x"], 2),
                                       ([], 2), (["{tmp}/taken"], 1)])
def test_refuses(tmp_path, args, code):
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "prompt.json").write_text("keep")
    r = run(tmp_path, *[a.format(tmp=tmp_path) for a in args])
    assert r.returncode == code, r.stderr
    assert (taken / "prompt.json").read_text() == "keep"
    assert not (tmp_path / "hf.log").exists()
