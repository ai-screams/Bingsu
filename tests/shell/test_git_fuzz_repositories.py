"""F2 file-backed seed repositories under the protected collector.

The in-memory parser fuzz (fuzz/collector, crates/bingsu-collect/tests/
fuzz_seeds.rs) never opens a path. Classes that need real files run here, in a
separate subprocess: the F1 worker (shipped protection sequence, product
collector) on repositories written byte by byte, without any Git command.
Oracles per seed: exit 0 (no panic), the 10 s harness deadline, no spawn or
outside access in the Linux strace / macOS interposer trace, no file change
(snapshot), and no outside sentinel byte in the published values.
"""
import hashlib
import os
from pathlib import Path
import zlib

import pytest

from test_git_collection_security import CorpusCase, corpus, execute  # noqa: F401  (fixture)

SENTINEL = b"F2-OUTSIDE-SENTINEL"


def write(path, data, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    if mode is not None:
        path.chmod(mode)


def loose(git, kind, body):
    raw = f"{kind} {len(body)}\0".encode() + body
    oid = hashlib.sha1(raw).hexdigest()
    write(git / "objects" / oid[:2] / oid[2:], zlib.compress(raw))
    return oid


def index_v2(entries):
    out = b"DIRC" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    for path, oid, size in entries:
        start = len(out)
        out += bytes(24) + (0o100644).to_bytes(4, "big") + bytes(8) + size.to_bytes(4, "big")
        out += bytes.fromhex(oid) + len(path).to_bytes(2, "big") + path + b"\0"
        while (len(out) - start) % 8:
            out += b"\0"
    return out + hashlib.sha1(out).digest()


def repository(root):
    """A minimal clean repository: one tracked file, one commit, an index."""
    git = root / ".git"
    write(root / "tracked", "base\n")
    blob = loose(git, "blob", b"base\n")
    tree = loose(git, "tree", b"100644 tracked\0" + bytes.fromhex(blob))
    commit = loose(git, "commit", f"tree {tree}\nauthor A <a@example.invalid> 0 +0000\n"
                   f"committer A <a@example.invalid> 0 +0000\n\nbase\n".encode())
    write(git / "HEAD", "ref: refs/heads/main\n")
    write(git / "refs/heads/main", commit + "\n")
    write(git / "config", "[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
    write(git / "index", index_v2([(b"tracked", blob, 5)]))
    return git, commit


def seed_config_cap(git, outside):
    write(git / "config", b"# " + b"x" * 65_535)


def seed_packed_refs_cap(git, outside):
    write(git / "packed-refs", b"# " + b"x" * 262_143)


def seed_index_damaged(git, outside):
    write(git / "index", b"DIRC\0\0\0\2\xff\xff\xff\xff" + bytes(20))


def seed_index_oversize(git, outside):
    write(git / "index", b"DIRC" + bytes(4_194_301))


def seed_pack_damaged(git, outside):
    for path in (git / "objects").glob("??/*"):
        path.unlink()
    name = "pack-" + "1" * 40
    write(git / "objects/pack" / (name + ".pack"), b"PACK\0\0\0\2\0\0\0\1" + bytes(40))
    write(git / "objects/pack" / (name + ".idx"), b"\xfftOc\0\0\0\2" + bytes(64))
    write(git / "objects/pack/multi-pack-index", b"MIDX\1\1\4\0" + b"\xff" * 64)


def seed_commit_graph(git, outside):
    # The collector never uses commit-graph: damaged and oversized files in
    # both layouts must see zero opens, reads and maps (NO_OPEN below).
    write(git / "objects/info/commit-graph", b"CGPH\1\1\x7f\0" + b"\xff" * 9_000_000)
    write(git / "objects/info/commit-graphs/commit-graph-chain", "f" * 40 + "\n")
    write(git / "objects/info/commit-graphs" / ("graph-" + "f" * 40 + ".graph"), b"CGPH" + bytes(64))


def seed_symref_cycle(git, outside):
    write(git / "HEAD", "ref: refs/heads/a\n")
    write(git / "refs/heads/a", "ref: refs/heads/b\n")
    write(git / "refs/heads/b", "ref: refs/heads/a\n")


def seed_symref_depth(git, outside):
    write(git / "HEAD", "ref: refs/heads/l0\n")
    for n in range(41):
        write(git / f"refs/heads/l{n}", f"ref: refs/heads/l{n + 1}\n")
    write(git / "refs/heads/l41", (git / "refs/heads/main").read_text())


def seed_config_fifo(git, outside):
    (git / "config").unlink()
    os.mkfifo(git / "config", 0o600)


def seed_config_symlink(git, outside):
    (git / "config").unlink()
    (git / "config").symlink_to(outside / "sentinel")


def seed_head_symlink(git, outside):
    (git / "HEAD").unlink()
    (git / "HEAD").symlink_to(outside / "sentinel")


def seed_objects_symlink(git, outside):
    (git / "objects").rename(outside / "objects")
    (git / "objects").symlink_to(outside / "objects")


def gitfile(pointer):
    def seed(git, outside):
        # Replace the in-place gitdir with a pointer file in the worktree.
        git.rename(git.parent / ".git-moved")
        write(git.parent / ".git", pointer(outside))
    return seed


def empty_target(path):
    path.mkdir(parents=True)
    return f"gitdir: {path}\n"


def foreign_worktree(git, outside):
    """A worktrees-shaped pointer into another repository whose backlink names
    a different worktree: acquired (its exact directory only), then refused."""
    target = git.parent.parent / "elsewhere/.git/worktrees/w"
    write(target / "HEAD", (git / "HEAD").read_text())
    write(target / "commondir", "../..\n")
    write(target / "gitdir", str(git.parent.parent / "elsewhere-worktree/.git") + "\n")
    git.rename(git.parent / ".git-moved")
    write(git.parent / ".git", f"gitdir: {target}\n")


def linked(commondir):
    def seed(git, outside):
        worktrees = git / "worktrees/w"
        write(worktrees / "HEAD", (git / "HEAD").read_text())
        write(worktrees / "commondir", commondir(git, outside))
        write(worktrees / "gitdir", str(git.parent.parent / "linked/.git") + "\n")
        write(git.parent.parent / "linked/.git", f"gitdir: {worktrees}\n")
        write(git.parent.parent / "linked/tracked", "base\n")
    return seed


SEEDS = {
    # safe-read caps at cap+1 (in-memory parsers see only capped bytes)
    "config-cap-plus-one": seed_config_cap,
    "packed-refs-cap-plus-one": seed_packed_refs_cap,
    "index-damaged-huge-count": seed_index_damaged,
    "index-cap-plus-one": seed_index_oversize,
    "pack-idx-midx-damaged": seed_pack_damaged,
    "commit-graph-unused": seed_commit_graph,
    # file-backed cycles and depth
    "symref-cycle": seed_symref_cycle,
    "symref-depth-41": seed_symref_depth,
    # special files and links to the outside
    "config-fifo": seed_config_fifo,
    "config-symlink-outside": seed_config_symlink,
    "head-symlink-outside": seed_head_symlink,
    "objects-symlink-outside": seed_objects_symlink,
    # gitdir pointers: outside, parent escape, foreign or empty worktree metadata, self
    "gitdir-outside": gitfile(lambda outside: f"gitdir: {outside}\n"),
    "gitdir-parent-escape": gitfile(lambda outside: "gitdir: ../../../../../../../../tmp\n"),
    "gitdir-empty-worktrees-target": gitfile(lambda outside: empty_target(outside.parent / "empty/.git/worktrees/w")),
    "gitdir-foreign-worktree-backlink": foreign_worktree,
    "gitdir-outside-modules-shape": gitfile(lambda outside: f"gitdir: {outside}/.git/modules/m\n"),
    "gitdir-self": gitfile(lambda outside: "gitdir: .\n"),
    # commondir of a linked worktree: outside, chain, self
    "commondir-outside": linked(lambda git, outside: f"{outside}\n"),
    "commondir-parent-escape": linked(lambda git, outside: "../../../../../../../../tmp\n"),
    "commondir-self": linked(lambda git, outside: ".\n"),
}

# Pinned outcome per seed: (collection Ok, last published stage, partial).
# A refused pointer publishes nothing; a refused capped/special/linked file
# keeps stage A with B-D Pending; a damaged index or pack stays Partial.
REFUSED, A_ONLY = (False, None, None), (False, "A", True)
EXPECT = {
    "config-cap-plus-one": A_ONLY, "packed-refs-cap-plus-one": A_ONLY,
    "index-damaged-huge-count": (True, "D", True), "index-cap-plus-one": (True, "D", True),
    "pack-idx-midx-damaged": (True, "D", True), "commit-graph-unused": (True, "D", False),
    "symref-cycle": A_ONLY, "symref-depth-41": A_ONLY, "config-fifo": A_ONLY,
    "config-symlink-outside": A_ONLY, "head-symlink-outside": REFUSED, "objects-symlink-outside": A_ONLY,
    "gitdir-outside": REFUSED, "gitdir-parent-escape": REFUSED, "gitdir-empty-worktrees-target": REFUSED,
    "gitdir-foreign-worktree-backlink": REFUSED, "gitdir-outside-modules-shape": REFUSED,
    "gitdir-self": REFUSED, "commondir-outside": REFUSED, "commondir-parent-escape": REFUSED,
    "commondir-self": REFUSED,
}

# Seeds whose collection opens a second, verified metadata root.
LINKED = {name for name in SEEDS if name.startswith("commondir-")}
# commit-graph is not an input: any open of these paths fails the trace.
NO_OPEN = {"commit-graph-unused": [".git/objects/info/commit-graph", ".git/objects/info/commit-graphs"]}
# Worktrees-shaped pointers: discovery may acquire exactly that directory
# (and stat its ancestors) to check the reciprocal backlink, nothing else.
POINTED = {"gitdir-empty-worktrees-target": "empty/.git/worktrees/w",
           "gitdir-foreign-worktree-backlink": "elsewhere/.git/worktrees/w"}


def build(tmp_path, name):
    case = tmp_path / name
    outside = case / "outside"
    write(outside / "sentinel", SENTINEL + b"-" + name.encode() + b"\n")
    repo = case / "repo"
    git, _ = repository(repo)
    SEEDS[name](git, outside)
    worktree = case / "linked" if name in LINKED else repo
    roots = [str(worktree), str(git / "worktrees/w"), str(git)] if name in LINKED else [str(repo), str(git)]
    if name in POINTED:
        roots = [str(repo), str(case / POINTED[name])]
    data = {"case": "f2-" + name, "policy": "exact", "canary": "-", "repo": str(worktree),
            "roots": roots, "outside": str(outside),
            "no_open": [str(repo / path) for path in NO_OPEN.get(name, [])]}
    if EXPECT[name] == REFUSED:
        data["axes"] = {}  # no read layer is installed; asserted after the run
    return CorpusCase(data)


def assert_no_outside_bytes(name, result):
    published = repr(result["updates"]) + repr(result["display"])
    assert SENTINEL.decode() not in published, (name, "outside bytes published")


# 이것을 실패시키는 것: 파일 기반 seed 하나에서 외부 접근·spawn·쓰기·panic·
# 시간 초과 중 하나를 허용하는 것(execute의 trace·snapshot·종료 코드 검사).
def test_every_seed_has_a_pinned_outcome():
    assert set(EXPECT) == set(SEEDS)


@pytest.mark.parametrize("name", sorted(SEEDS))
def test_hostile_seed_repositories_have_zero_effects(corpus, tmp_path, name):  # noqa: F811
    case = build(tmp_path / "repos", name)
    result = execute(corpus, case, tmp_path / "run", require_update=False)
    assert_no_outside_bytes(name, result)
    value = result["value"] or {}
    got = (result["result"] == "Ok(())", value.get("stage"), value.get("partial"))
    assert got == EXPECT[name], (name, result["result"], value)
    # A refused pointer or HEAD never reaches the repository read layer.
    assert ("read-layer" in result["phases"]) is (EXPECT[name] != REFUSED), (name, sorted(result["phases"]))


# 이것을 실패시키는 것: 발행된 값에 외부 sentinel이 섞여도 통과시키는 것.
def test_outside_bytes_in_published_values_are_refused():
    assert_no_outside_bytes("clean", {"updates": [{"branch": "main"}], "display": "main"})
    for leaked in ({"updates": [{"branch": SENTINEL.decode()}], "display": ""},
                   {"updates": [], "display": SENTINEL.decode() + "-x"}):
        with pytest.raises(AssertionError, match="outside bytes"):
            assert_no_outside_bytes("leak", leaked)


# 이것을 실패시키는 것: seed 저장소에서 외부 read·쓰기·spawn 시도를 놓치는 것
# (trace·snapshot·interposer 중 하나를 끄거나 seed의 forbidden root를 비우는 것).
@pytest.mark.parametrize("name", sorted(SEEDS))
def test_each_seed_rejects_read_spawn_and_write_mutations(corpus, tmp_path, name):  # noqa: F811
    case = build(tmp_path / "repos", name)
    for mutation, message in (("read", "outside|forbidden"), ("write", "write|mutation"),
                              ("spawn", "spawn|process|forbidden repository effect")):
        with pytest.raises(AssertionError, match=message):
            execute(corpus, case, tmp_path / mutation, mutant=mutation, require_update=False)


# 이것을 실패시키는 것: 갱신 없는 출력을 F1의 기본 decode가 받아들이는 것, 또는
# F2의 거부 seed 경로가 결과 줄 없는 출력까지 받아들이는 것.
def test_decode_requires_an_update_unless_refused():
    from test_git_collection_security import decode
    refused = b"F1_PHASE end\nF1_RESULT Err(Read(Escape)) 10\n"
    with pytest.raises(AssertionError):
        decode(refused)
    assert decode(refused, require_update=False)["value"] is None
    with pytest.raises(AssertionError):
        decode(b"F1_PHASE end\n", require_update=False)
