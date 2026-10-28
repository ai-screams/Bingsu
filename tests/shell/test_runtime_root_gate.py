"""C1 pinned runtime root; status-notice hook output belongs to M4/M5."""
import os
import shutil
import subprocess

from shell_support import ROOT, Install, real_bin, run_shell_script, trusted_env


# 이것을 실패시키는 것: 고정 dev·ino 비교 제거.
def test_deleted_and_recreated_runtime_root_degrades_every_prompt(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    script = inst.init("bash", env)
    baseline = run_shell_script("bash", script + b"\n_bingsu_save; _bingsu_install; printf '%s\\n' \"$_bingsu_rec\"\n", env, tmp_path)
    assert baseline.returncode == 0 and baseline.stdout.startswith(b"B1\x1f8\x1f"), baseline
    assert b"degraded:runtime-root" not in baseline.stdout, baseline.stdout
    root = tmp_path / "run-t/bingsu"
    before = root.stat()
    # Hold the removed inode open so immediate inode reuse cannot mask replacement.
    fd = os.open(root, os.O_RDONLY)
    try:
        shutil.rmtree(root)
        root.mkdir(mode=0o700)
        after = root.stat()
        # 이것을 실패시키는 것: 삭제만 하고 재생성하지 않거나 같은 inode를 재사용하는 fixture.
        assert (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        result = run_shell_script("bash", script + b"""
for attempt in 1 2 3; do
  _bingsu_save
  _bingsu_install
  printf '%s\\n' "$_bingsu_rec"
done
""", env, tmp_path)
        (tmp_path / "prompts.stdout").write_bytes(result.stdout)
        (tmp_path / "prompts.stderr").write_bytes(result.stderr)
        # 이것을 실패시키는 것: 셸 실행 실패를 정상 degraded 프롬프트로 세는 것.
        assert result.returncode == 0, result.stderr
        records = result.stdout.splitlines()
        # 이것을 실패시키는 것: 첫 프롬프트만 degraded이고 이후 교체된 뿌리를 받아들이는 것.
        assert len(records) == 3 and all(
            record.endswith(b"\x1fdegraded:runtime-root\x1e") for record in records
        ), records
    finally:
        os.close(fd)


RUNTIME_ROOT_EXAMPLES: tuple[tuple[str, bool], ...] = (
    ("/run/user/<uid>/bingsu", True),
    ("/private/var/folders/xx/yyy/T/bingsu", True),
    ("/tmp/<user-owned>/bingsu", True),
    ("/tmp/<root-or-other-owned>/bingsu", False),
    ("~/.cache/bingsu/run", True),
)


# 이것을 실패시키는 것: 두 번째 init이 함수의 runtime pin을 다시 정의하지 않는 것.
def test_init_again_recovers_runtime_root(tmp_path):
    inst = Install(tmp_path)
    env = trusted_env(tmp_path)
    old = inst.init("bash", env)
    call = b"\n_bingsu_save; _bingsu_install; printf '%s\\n' \"$_bingsu_rec\"\n"
    baseline = run_shell_script("bash", old + call, env, tmp_path)
    assert baseline.returncode == 0, baseline.stderr
    assert b"degraded:runtime-root" not in baseline.stdout
    root = tmp_path / "run-t/bingsu"
    fd = os.open(root, os.O_RDONLY)
    try:
        shutil.rmtree(root)
        root.mkdir(mode=0o700)
        new = inst.init("bash", env)
        call = b"\n_bingsu_save; _bingsu_install; printf '%s\\n' \"$_bingsu_rec\"\n"
        result = run_shell_script("bash", old + call + new + call, env, tmp_path)
        assert result.returncode == 0, result.stderr
        records = result.stdout.splitlines()
        assert len(records) == 2, records
        assert records[0].endswith(b"\x1fdegraded:runtime-root\x1e"), records
        assert records[1].startswith(b"B1\x1f8\x1f"), records
        assert records[1] == baseline.stdout.rstrip(b"\n"), records
    finally:
        os.close(fd)


# 이것을 실패시키는 것: 실제 제품 walk_verdict의 sticky 의무·소유권·로컬 규칙 제거.
def test_runtime_root_path_examples():
    # Prebuilt by the workflow, same profile/target as the shipped front.
    candidates = list((real_bin().parent / "deps").glob("cli_prompt-*"))
    binaries = [p for p in candidates if p.is_file() and os.access(p, os.X_OK) and not p.suffix]
    assert binaries, "build cargo test -p bingsu --test cli_prompt --no-run first"
    binary = max(binaries, key=lambda p: p.stat().st_mtime_ns)
    result = subprocess.run([str(binary), "runtime_root_path_examples", "--exact", "--nocapture"],
                            capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout, result.stdout
    for path, accepted in RUNTIME_ROOT_EXAMPLES:
        assert f"{path}: {str(accepted).lower()}" in result.stdout, result.stdout
