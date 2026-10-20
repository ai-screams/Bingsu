#!/usr/bin/env python3
"""Runs check_core_no_std.judge on synthetic cargo metadata, one case per
rule. The real graph is clean, so the gate alone never shows that a rule
still fires; these cases do. Run by check-core-purity.sh.
Usage: python3 -B scripts/test_check_core_no_std.py
"""
import copy
import pathlib
import sys
import unittest

import check_core_no_std as gate

ROOT = pathlib.Path("/w")
EDGES = {
    "bingsu-core": ["libm", "unicode-segmentation", "toml"],
    "toml": ["toml_parser", "toml_datetime", "serde_spanned", "winnow"],
    "toml_parser": ["winnow"],
    "bingsu": ["bingsu-core", "bingsu-collect", "libc"],
    "bingsu-collect": ["bingsu-core", "libc"],
}


def package(key, features, kinds):
    name, version, source = key
    workspace = source.endswith("Cargo.toml")
    targets = [{"name": name, "kind": [k], "crate_types": [k], "required-features": [],
                "src_path": str(ROOT / pathlib.Path(source).parent / "src/main.rs")
                if k == "bin" else "/x/lib.rs"} for k in kinds]
    targets.append({"name": "t", "kind": ["test"], "crate_types": ["bin"],
                    "src_path": "/x/t.rs", "required-features": []})
    pkg = {"id": name, "name": name, "version": version, "targets": targets,
           "source": None if workspace else source, "links": None,
           "manifest_path": str(ROOT / source) if workspace else "/reg/Cargo.toml"}
    node = {"id": name, "features": list(features),
            "deps": [{"pkg": d, "dep_kinds": [{"kind": None}]} for d in EDGES.get(name, [])]}
    return pkg, node


def clean():
    """Metadata that matches the pins exactly."""
    meta = {"packages": [], "resolve": {"nodes": []}}
    for key, (features, kinds) in gate.BINGSU_GRAPH.items():
        pkg, node = package(key, features, kinds)
        meta["packages"].append(pkg)
        meta["resolve"]["nodes"].append(node)
    return meta


def pkg(meta, name):
    return next(p for p in meta["packages"] if p["name"] == name)


def node(meta, name):
    return next(n for n in meta["resolve"]["nodes"] if n["id"] == name)


def add_dep(meta, parent, name, kinds, edge=None, links=None):
    p, n = package((name, "1.0.0", gate.CRATES_IO), (), kinds)
    p["links"] = links
    meta["packages"].append(p)
    meta["resolve"]["nodes"].append(n)
    node(meta, parent)["deps"].append({"pkg": name, "dep_kinds": [{"kind": edge}]})


class Judge(unittest.TestCase):
    def judged(self, meta, manifest=None):
        return gate.judge(meta, manifest or {}, ROOT)

    def fails_with(self, meta, reason, manifest=None):
        bad = self.judged(meta, manifest)
        self.assertTrue(any(reason in b for b in bad), f"{reason!r} not in {bad}")

    # 이것을 실패시키는 것: 깨끗한 그래프에서 무엇이든 잡는 것(아래 경우들이 엉뚱한 이유로 통과하지 않음을 보증).
    def test_clean_graph_passes(self):
        self.assertEqual(self.judged(clean()), [])

    # 이것을 실패시키는 것: 버전을 키에서 빼는 것.
    def test_version(self):
        m = clean()
        pkg(m, "libm")["version"] = "0.2.17"
        self.fails_with(m, "('libm', '0.2.17', ")

    # 이것을 실패시키는 것: source를 키에서 빼는 것(git·다른 registry로 바꿔치기).
    def test_source(self):
        m = clean()
        pkg(m, "libm")["source"] = "git+https://example.invalid/libm"
        self.fails_with(m, "git+https://example.invalid/libm")

    # 이것을 실패시키는 것: path package를 manifest 위치 없이 이름만으로 보는 것.
    def test_path_replacement(self):
        m = clean()
        p = pkg(m, "libm")
        p["source"] = None
        p["manifest_path"] = str(ROOT / "crates/fake-libm/Cargo.toml")
        self.fails_with(m, "crates/fake-libm/Cargo.toml")

    # 이것을 실패시키는 것: 해석된 feature 집합을 비교하지 않는 것.
    def test_features(self):
        m = clean()
        node(m, "libm")["features"] = ["arch"]
        self.fails_with(m, "('libm', '0.2.16', ")

    # 이것을 실패시키는 것: target 종류를 비교하지 않는 것.
    def test_target_kinds(self):
        m = clean()
        pkg(m, "unicode-segmentation")["targets"].append(
            {"name": "u", "kind": ["cdylib"], "crate_types": ["cdylib"],
             "src_path": "/x/lib.rs", "required-features": []})
        self.fails_with(m, "('cdylib', 'lib')")

    # 이것을 실패시키는 것: links 검사를 지우는 것.
    def test_links(self):
        m = clean()
        pkg(m, "libm")["links"] = "m"
        self.fails_with(m, "libm links native library 'm'")

    # 이것을 실패시키는 것: proc-macro 검사를 지우는 것.
    def test_proc_macro(self):
        m = clean()
        add_dep(m, "bingsu-core", "derive", ["proc-macro"])
        self.fails_with(m, "derive is a proc-macro")

    # 이것을 실패시키는 것: 검토 안 한 build script 검사를 지우는 것, 검토 목록을 이름만으로 보는 것.
    def test_unreviewed_build_script(self):
        m = clean()
        add_dep(m, "bingsu-core", "sys", ["custom-build", "lib"])
        self.fails_with(m, "build script of sys 1.0.0 is not reviewed")
        m = clean()
        pkg(m, "libm")["version"] = "0.2.17"
        self.fails_with(m, "build script of libm 0.2.17 is not reviewed")

    # 이것을 실패시키는 것: 고정 목록에 없는 새 package를 놓치는 것, build 간선을 따라가지 않는 것, dev 간선을 따라가는 것.
    def test_new_package_and_edges(self):
        m = clean()
        add_dep(m, "bingsu-core", "extra", ["lib"])
        self.fails_with(m, "('extra', '1.0.0', ")
        m = clean()
        add_dep(m, "bingsu-core", "builder", ["lib"], edge="build")
        self.fails_with(m, "('builder', '1.0.0', ")
        m = clean()
        add_dep(m, "bingsu-core", "devonly", ["lib"], edge="dev")
        self.assertEqual(self.judged(m), [])

    # 이것을 실패시키는 것: 간선을 package id가 아니라 이름으로 따라가는 것(같은 이름의 다른 package, 예를 들어
    # 꺼진 선택 의존이나 다른 버전이 그래프에 섞임). 이름이 같은 proc-macro가 resolve에는 있지만 간선이 없다.
    def test_edges_follow_package_ids(self):
        m = clean()
        twin, twin_node = package(("libm", "9.9.9", gate.CRATES_IO), (), ("proc-macro",))
        twin["id"] = twin_node["id"] = "libm-twin"
        m["packages"].append(twin)
        m["resolve"]["nodes"].append(twin_node)
        self.assertEqual(self.judged(m), [])

    def optional_dep(self, m, owner, dep, kinds, table, enabled, rename=None, lib=None):
        """`owner` gets an optional dependency on `dep` (of target `kinds`),
        listed in the resolve as cargo metadata does when another member
        pulls `dep` in. `lib` is the edge's lib name (default: the key)."""
        add_dep(m, owner, dep, kinds)
        p = pkg(m, owner)
        p["features"] = table
        p.setdefault("dependencies", []).append(
            {"name": dep, "rename": rename, "optional": True, "kind": None})
        node(m, owner)["deps"][-1]["name"] = lib or (rename or dep).replace("-", "_")
        node(m, owner)["features"] = list(enabled)

    # 이것을 실패시키는 것: weak feature(`x?/f`)만 가리키는 선택 의존을 간선으로 따라가는 것
    # (cargo metadata는 다른 member가 그 package를 넣으면 간선을 적지만 빌드는 넣지 않는다).
    def test_weak_feature_edge_is_not_followed(self):
        # A dependency key may also name an unrelated enabled feature.
        for rename in (None, "sc", "alloc"):
            m = clean()
            key = rename or "serde_core"
            self.optional_dep(m, "serde_spanned", "serde_core", ["proc-macro"],
                              {"alloc": [f"{key}?/alloc"], "serde": [f"dep:{key}"]}, ["alloc"], rename)
            self.assertEqual(self.judged(m), [], rename)

    # 이것을 실패시키는 것: 켜진 선택 의존을 건너뛰는 것(`dep:x`, weak 아닌 `x/f`, 암시적 feature,
    # 이름을 바꾼 의존과 하이픈 이름 각각).
    def test_enabled_optional_edge_is_followed(self):
        cases = [
            ({"alloc": [], "serde": ["dep:serde_core"]}, ["alloc", "serde"], None, "serde_core"),
            ({"alloc": [], "std": ["serde_core/std"]}, ["alloc", "std"], None, "serde_core"),
            ({"alloc": []}, ["alloc", "serde_core"], None, "serde_core"),
            ({"alloc": [], "w": ["dep:uw"]}, ["alloc", "w"], "uw", "unicode-width"),
            ({"alloc": []}, ["alloc", "uw"], "uw", "unicode-width"),
            ({"alloc": [], "w": ["unicode-width/std"]}, ["alloc", "w"], None, "unicode-width"),
        ]
        for table, enabled, rename, dep in cases:
            with self.subTest(table=table, rename=rename):
                m = clean()
                self.optional_dep(m, "serde_spanned", dep, ["proc-macro"], table, enabled, rename)
                self.fails_with(m, f"{dep} is a proc-macro")

    # 이것을 실패시키는 것: 간선을 lib 이름으로 선언에 맞추는 것. 필수 의존(proc-macro, build script)의
    # lib 이름이 꺼진 선택 의존과 같으면 그 필수 간선이 "꺼진 선택 의존"으로 보여 빠졌다.
    def test_required_dep_named_like_an_off_optional_one(self):
        for kinds, reason in ((["proc-macro"], "evil is a proc-macro"),
                              (["custom-build", "lib"], "build script of evil 1.0.0 is not reviewed")):
            with self.subTest(kinds=kinds):
                m = clean()
                self.optional_dep(m, "bingsu-core", "foo", ["lib"], {"alloc": ["foo?/x"]}, [])
                add_dep(m, "bingsu-core", "evil", kinds)
                node(m, "bingsu-core")["deps"][-1]["name"] = "foo"  # `[lib] name = "foo"`
                pkg(m, "bingsu-core")["dependencies"].append(
                    {"name": "evil", "rename": None, "optional": False, "kind": None})
                self.fails_with(m, reason)

    # 이것을 실패시키는 것: 같은 이름이 한 번은 필수로, 한 번은 선택으로 선언됐을 때 선택으로만 보는 것.
    def test_a_required_declaration_keeps_the_edge(self):
        m = clean()
        self.optional_dep(m, "serde_spanned", "serde_core", ["proc-macro"], {"alloc": ["serde_core?/alloc"]}, ["alloc"])
        pkg(m, "serde_spanned")["dependencies"].append(
            {"name": "serde_core", "rename": None, "optional": False, "kind": None})
        self.fails_with(m, "serde_core is a proc-macro")

    # 이것을 실패시키는 것: resolve 간선의 종류와 다른 선언까지 보고 선택 의존을 필수로 판정하는 것.
    def test_declarations_match_the_edge_kind(self):
        m = clean()
        self.optional_dep(m, "serde_spanned", "serde_core", ["proc-macro"],
                          {"alloc": ["serde_core?/alloc"]}, ["alloc"])
        pkg(m, "serde_spanned")["dependencies"].append(
            {"name": "serde_core", "rename": None, "optional": False, "kind": "build"})
        self.assertEqual(self.judged(m), [])
        node(m, "serde_spanned")["deps"][-1]["dep_kinds"] = [{"kind": "build"}]
        self.fails_with(m, "serde_core is a proc-macro")

    # 이것을 실패시키는 것: [patch]·[replace] 검사를 지우는 것(둘 각각).
    def test_patch_and_replace(self):
        for table in ("patch", "replace"):
            self.fails_with(clean(), "[patch] and [replace] are not allowed", {table: {}})

    # 이것을 실패시키는 것: bingsu의 bin target 고정을 지우는 것.
    def test_bingsu_targets(self):
        m = clean()
        pkg(m, "bingsu")["targets"][0]["src_path"] = str(ROOT / "crates/bingsu/alt.rs")
        self.fails_with(m, "bingsu targets")

    # 이것을 실패시키는 것: 같은 이름의 workspace package가 둘일 때 하나만 보는 것.
    def test_one_workspace_root(self):
        m = clean()
        twin = copy.deepcopy(pkg(m, "bingsu-core"))
        twin["id"] = "bingsu-core-twin"
        m["packages"].append(twin)
        self.fails_with(m, "bingsu-core: expected one workspace package, got 2")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
