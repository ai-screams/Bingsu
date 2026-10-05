"""The reader alone (as the golden runner sources it) takes inherited
exported names out of the environment. The hooks unexport the same names
again for bash and fish, so the init-level tests cannot see the reader's
own lines; this test sources the reader without the hooks."""
import importlib.util
import os
import subprocess

import pytest

from conftest import ROOT, SHELL_CMD

_spec = importlib.util.spec_from_file_location("golden_record_run", ROOT / "tests/golden/record/run.py")
golden = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(golden)

NAMES = ("_bingsu_f", "_bingsu_disp", "_bingsu_note", "_bingsu_key")
COUNT = {
    "zsh": "print -r -- \"EXPORTED=$(env | grep -c '^_bingsu_')\"\n",
    "bash": "echo \"EXPORTED=$(env | grep -c '^_bingsu_')\"\n",
    "fish": "echo \"EXPORTED=\"(env | grep -c '^_bingsu_')\n",
}


# 이것을 실패시키는 것: reader.zsh의 `typeset -g +x …`, reader.bash의 `export -n …`,
# reader.fish의 `set -gu …` 줄을 지우는 것(그 셸에서 EXPORTED가 0이 아님).
@pytest.mark.parametrize("shell", os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split())
def test_reader_unexports_inherited_globals(tmp_path, shell):
    reader = tmp_path / f"reader.{shell}"
    golden.render_reader(shell, reader)
    script = tmp_path / f"s.{shell}"
    script.write_text(f"source {reader}\n" + COUNT[shell])
    env = {"PATH": os.environ["PATH"], "LC_ALL": "C.UTF-8", **{n: "1" for n in NAMES}}
    r = subprocess.run(SHELL_CMD[shell] + [str(script)], env=env, capture_output=True, timeout=60)
    assert r.returncode == 0 and r.stderr == b"", r.stderr
    assert r.stdout == b"EXPORTED=0\n", r.stdout
