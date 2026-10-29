"""bench/probes/login-transition.sh: the explicit probe the user runs by hand. It is only run here against a
temporary output file; it never logs out, reboots or uses sudo."""
import subprocess
import sys
import time

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "bench"))
import summarize  # noqa: E402

PROBE = ROOT / "bench/probes/login-transition.sh"
LABELS = ["before-logout", "after-login", "before-reboot", "after-reboot"]


def run(*args):
    return subprocess.run(["bash", str(PROBE), *args], capture_output=True, text=True, timeout=30)


# 이것을 실패시키는 것: label을 받지 않고 쓰는 것, 네 label 밖의 값(탭 포함)을 TSV 열에 쓰는 것, --out 없이 stdout에
# 쓰는 것, 인자 오류에도 파일을 만드는 것.
@pytest.mark.parametrize("args", [[], ["--label", "after-login"], ["--out", "X"], ["--label", "x", "--out", "X"],
                                  ["--label", "after-login\tx", "--out", "X"], ["--label"], ["--bogus"]])
def test_bad_arguments_write_nothing(args, tmp_path):
    out = tmp_path / "o.tsv"
    r = run(*[str(out) if a == "X" else a for a in args])
    assert r.returncode == 2 and "usage" in r.stderr and not out.exists(), r


# 이것을 실패시키는 것: 한 번 부를 때 한 줄이 아닌 것, 덮어쓰기(두 번째 호출이 첫 줄을 지움), 열 순서, 부팅 정체를
# x05 탐침과 다른 곳에서 읽는 것.
def test_each_call_appends_one_line_with_boot_identity(tmp_path):
    out = tmp_path / "o.tsv"
    for label in LABELS:
        assert run("--label", label, "--out", str(out)).returncode == 0
    lines = [l.split("\t") for l in out.read_text().splitlines()]
    assert [l[1] for l in lines] == LABELS and all(len(l) == 4 for l in lines)
    x05 = subprocess.run(["bash", str(ROOT / "bench/probes/x05-boot-id.sh"), "x"], capture_output=True, text=True)
    assert {l[2] for l in lines} == {x05.stdout.split("\t")[2]}


# 이것을 실패시키는 것: 한 label만 있는 쌍을 판정하는 것(로그아웃 전 줄만, 로그인 뒤 줄만), 같은 부팅의 두 줄을 부팅
# 전환으로 읽는 것. 실제 탐침 출력을 판정기에 넣는다.
def test_login_transition_requires_both_labels(tmp_path):
    out = tmp_path / "o.tsv"
    run("--label", "before-logout", "--out", str(out))
    got = summarize.judge_login_transition(out.read_text())
    assert got["logout"][0] == "BLOCKED" and got["reboot"][0] == "BLOCKED"
    time.sleep(1.1)  # the pair must be ordered by its second-resolution stamps
    run("--label", "after-login", "--out", str(out))
    got = summarize.judge_login_transition(out.read_text())
    assert got["logout"][0] == "same-boot" and got["reboot"][0] == "BLOCKED"
