"""The shared shell-test helpers that do not start a shell."""
from shell_support import cargo_test_binaries


# 이것을 실패시키는 것: Cargo 1.99까지의 deps/나 1.100의 build/<package>/<hash>/out/ 한쪽을 보지 않는 것,
# 다른 package의 같은 이름을 받는 것, 실행할 수 없는 파일(dep-info, object)이나 폴더를 받는 것.
def test_cargo_test_binaries_reads_both_layouts(tmp_path):
    def put(rel, mode):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
        path.chmod(mode)
        return path

    old = put("deps/cli_prompt-1", 0o755)
    put("deps/cli_prompt-1.d", 0o644)
    new = put("build/bingsu/2/out/cli_prompt-2", 0o755)
    put("build/bingsu/2/out/cli_prompt-2.cli_prompt.rcgu.o", 0o644)
    put("build/other/3/out/cli_prompt-3", 0o755)
    (tmp_path / "build/bingsu/4/out/cli_prompt-4").mkdir(parents=True)
    got = cargo_test_binaries(tmp_path, "bingsu", "cli_prompt")
    assert sorted(got) == sorted([old, new]), got
