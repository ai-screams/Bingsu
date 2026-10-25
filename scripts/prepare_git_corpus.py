#!/usr/bin/env python3
"""Host-only F1 builder. The compiler-free tests never execute this preparation.

The fixed test catalog calls the shipped collector and protection sequence.
Only visibility and observation hooks change in the generated copy; there is
no product switch. Semantic cases use injected stage deadlines; --timed uses
the unchanged product deadlines. All children are waited for synchronously.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/git-corpus/manifest.tsv"
OUT = ROOT / "target/git-corpus"


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True,
                          timeout=300, **kwargs).stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    paths = [ROOT / "Cargo.lock", MANIFEST, Path(__file__).resolve()]
    for crate in ("bingsu-collect", "bingsu-core", "bingsu-identity"):
        paths += sorted((ROOT / "crates" / crate).rglob("*.rs"))
        paths += sorted((ROOT / "crates" / crate).glob("*.tsv"))
        paths.append(ROOT / "crates" / crate / "Cargo.toml")
    return {str(p.relative_to(ROOT)): digest(p) for p in paths}


def replace_once(source, old, new):
    assert source.count(old) == 1, ("stale host seam", old)
    return source.replace(old, new)


def git(path, *args):
    # This function is used ONLY before arming a canary, or on an explicitly
    # normalized oracle. No ambient global/system config, hooks or credentials.
    env = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "Corpus", "GIT_AUTHOR_EMAIL": "corpus@example.invalid",
           "GIT_COMMITTER_NAME": "Corpus", "GIT_COMMITTER_EMAIL": "corpus@example.invalid",
           "GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00Z"}
    # Auto gc/maintenance may run detached and add or drop lock files while the
    # oracle copy is taken; the corpus must be a quiescent snapshot.
    return run(["git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false", "-c", "gc.auto=0",
                "-c", "maintenance.auto=false", "-C", path, *args], env=env)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def base_repo(path):
    path.mkdir(parents=True)
    git(path, "init", "-q", "--initial-branch=main")
    write(path / "tracked", "base\n")
    write(path / "kept/file", "kept\n")
    write(path / "other/file", "other\n")
    git(path, "add", ".")
    git(path, "commit", "-qm", "base")
    git(path, "branch", "upstream")
    git(path, "branch", "--set-upstream-to=upstream")


def prepare_case(row):
    name = row["case"]
    directory = OUT / "cases" / name
    repo = directory / "repo"
    base_repo(repo)
    outside = directory / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    write(sentinel, "F1-OUTSIDE-SENTINEL-" + name + "\n")
    command = outside / "canary"
    write(command, f"#!/bin/sh\nprintf executed > '{outside / 'executed'}'\ncat '{sentinel}'\n")
    command.chmod(0o700)
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    blob = git(repo, "hash-object", "-w", "tracked").decode().strip()
    config = ""
    safe_config = ""
    if name == "ancestor-bound":
        for n in range(300):
            write(directory / f"hidden-{n:03}", "raw ancestor slot")
    if name == "dirty":
        write(repo / "tracked", "changed\n")
        write(repo / "staged", "new\n")
        git(repo, "add", "staged")
    elif name == "untracked":
        write(repo / "new/a", "a")
        write(repo / "new/b", "b")
    elif name in {"untracked-under-cap", "untracked-at-cap", "untracked-over-cap", "untracked-large"}:
        # U7's per-directory cap is 256 files. Below it counts remain exact;
        # reaching it leaves EOF unproven, even when Git counts exactly 256.
        # The manifest's untracked-cap-boundary policy requires 256+ partial.
        count = {"untracked-under-cap": 255, "untracked-at-cap": 256,
                 "untracked-over-cap": 257, "untracked-large": 1024}[name]
        for n in range(count):
            write(repo / "new" / f"file-{n:04}", "untracked\n")
        # Hitting the untracked cap must preserve independently known counts.
        write(repo / "tracked", "changed\n")
        write(repo / "staged", "staged\n")
        git(repo, "add", "staged")
    elif name == "untracked-empty":
        (repo / "empty/nested").mkdir(parents=True)
    elif name == "untracked-embedded":
        base_repo(repo / "embedded")
    elif name == "ignore":
        write(repo / ".gitignore", "*.tmp\n!keep.tmp\nignored/\n")
        git(repo, "add", ".gitignore")
        git(repo, "commit", "-qm", "ignore")
        for p in ("drop.tmp", "keep.tmp", "ignored/a", "visible"):
            write(repo / p, "x")
    elif name == "split-index":
        git(repo, "update-index", "--split-index")
        write(repo / "tracked", "changed\n")
    elif name == "sparse-index":
        git(repo, "sparse-checkout", "init", "--cone", "--sparse-index")
        git(repo, "sparse-checkout", "set", "kept")
        write(repo / "kept/file", "changed\n")
    elif name == "gitlink-staged":
        git(repo, "update-index", "--add", "--cacheinfo", "160000", oid, "sub")
        git(repo, "commit", "-qm", "gitlink")
        other = git(repo, "rev-parse", "HEAD").decode().strip()
        git(repo, "update-index", "--cacheinfo", "160000", other, "sub")
        write(repo / "sub/.git", f"gitdir: {outside}\n")
        write(repo / "sub/sentinel", "submodule must not open")
    elif name.startswith("skip-"):
        if name == "skip-staged":
            git(repo, "update-index", "--cacheinfo", "100644", blob, "kept/file")
        git(repo, "update-index", "--skip-worktree", "kept/file")
        if name == "skip-deleted":
            (repo / "kept/file").unlink()
        else:
            write(repo / "kept/file", "changed skip\n")
    elif name == "linked-worktree":
        linked = directory / "linked"
        git(repo, "worktree", "add", "-q", "-b", "linked", linked)
        repo = linked
    elif row["policy"].startswith("filtered"):
        attr = "filter=canary" if name.startswith("filter-") else "text" if name.startswith("text") else "text eol=crlf"
        write(repo / ".gitattributes", f"tracked {attr}\n")
        git(repo, "add", ".gitattributes")
        git(repo, "commit", "-qm", "attributes")
        # Size and mtime differ; the oracle sees the same modified count even
        # after conversion is removed. The approximation flag is asserted too.
        if row["policy"] == "filtered-zero":
            stamp = (repo / "tracked").stat().st_mtime_ns
            write(repo / "tracked", "evil\n")  # same size/mtime, different raw blob
            os.utime(repo / "tracked", ns=(stamp, stamp))
        else:
            write(repo / "tracked", "different length\n")
        if name.startswith("filter-"):
            driver = "clean" if name == "filter-preserved" else name[7:]
            config = f'[filter "canary"]\n\t{driver} = {command}\n\trequired = true\n'
    elif name in {"textconv", "external-diff"}:
        write(repo / ".gitattributes", "tracked diff=canary\n")
        git(repo, "add", ".gitattributes")
        git(repo, "commit", "-qm", "diff attribute")
        config = f'[diff "canary"]\n\ttextconv = {command}\n' if name == "textconv" else f'[diff]\n\texternal = {command}\n'
        write(repo / "tracked", "changed\n")
    elif name in {"fsmonitor", "hooks-path", "askpass", "editor", "pager", "ssh-command"}:
        key = {"fsmonitor": "fsmonitor", "hooks-path": "hooksPath", "askpass": "askPass",
               "editor": "editor", "pager": "pager", "ssh-command": "sshCommand"}[name]
        target = outside if name == "hooks-path" else command
        config = f'[core]\n\t{key} = {target}\n'
        if name == "hooks-path":
            for hook in ("post-index-change", "post-checkout", "pre-commit"):
                shutil.copy2(command, outside / hook)
    elif name == "credential":
        config = f'[credential]\n\thelper = !{command}\n'
    elif name in {"include", "include-if"}:
        section = "include" if name == "include" else f'includeIf "gitdir:{repo}/"'
        write(sentinel, f'[core]\nfsmonitor = {command}\n[branch "main"]\nmerge = refs/heads/evil\n')
        config = f'[{section}]\n\tpath = {sentinel}\n'
    elif name in {"attributes-file", "excludes-file"}:
        key = "attributesFile" if name == "attributes-file" else "excludesFile"
        write(sentinel, "* filter=canary\n" if name == "attributes-file" else "*\n")
        config = f'[core]\n\t{key} = {sentinel}\n'
        write(repo / "visible", "visible")
    elif name in {"alternates", "http-alternates"}:
        write(repo / ".git/objects/info" / name, str(outside) + "\n")
    elif name == "replace-loose":
        write(repo / ".git/refs/replace" / oid, oid + "\n")
    elif name == "replace-packed":
        write(repo / ".git/packed-refs", f"# pack-refs with: peeled fully-peeled sorted\n{oid} refs/replace/{oid}\n")
    elif name == "core-worktree":
        config = "[core]\n\tworktree = /\n"
    elif name == "global-unknown":
        write(repo / "maybe-ignored", "unknown global rules")
    elif name == "embedded-symlink":
        embedded = outside / "embedded"
        base_repo(embedded)
        (repo / "embedded").mkdir()
        os.symlink(embedded / ".git", repo / "embedded/.git")
    elif name.startswith("precompose-"):
        value = "true" if name.endswith("on") else "false"
        git(repo, "config", "core.precomposeUnicode", value)
        write(repo / "caf\u00e9", "base\n")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "unicode")
        os.rename(repo / "caf\u00e9", repo / "cafe\u0301")
        safe_config = f"[core]\nprecomposeUnicode = {value}\n"
    elif name == "case-collision":
        git(repo, "update-index", "--add", "--cacheinfo", "100644", blob, "TRACKED")
        config = "[core]\nignoreCase = true\n"
        safe_config = config
    elif name == "checkstat-minimal":
        config = "[core]\ncheckStat = minimal\n"
        safe_config = config
        write(repo / "tracked", "changed\n")
    elif name == "trustctime-false":
        config = "[core]\ntrustctime = false\n"
        safe_config = config
        write(repo / "tracked", "changed\n")
    elif name == "racy-stat":
        write(repo / "tracked", "racy\n")
        stamp = (repo / ".git/index").stat().st_mtime_ns
        os.utime(repo / "tracked", ns=(stamp, stamp))
    elif name.startswith("stat-"):
        _, checkstat, ctime, change = name.split("-")
        safe_config = f'[core]\ncheckStat = {checkstat}\ntrustctime = {str(ctime == "ctime").lower()}\n'
        config = safe_config
        if change == "racy":
            write(repo / "tracked", "racy\n")
            stamp = (repo / ".git/index").stat().st_mtime_ns
            os.utime(repo / "tracked", ns=(stamp, stamp))

    # Copy before arming unsafe config. Never invoke Git on the armed original.
    oracle = directory / "oracle"
    if name == "linked-worktree":
        shutil.copytree(repo, oracle, symlinks=True)
        (oracle / ".git").unlink()
        shutil.copytree(directory / "repo/.git", oracle / ".git", symlinks=True)
        for entry in ("worktrees",):
            shutil.rmtree(oracle / ".git" / entry)
        write(oracle / ".git/HEAD", "ref: refs/heads/linked\n")
    else:
        shutil.copytree(repo, oracle, symlinks=True)
    for relative in ("objects/info/alternates", "objects/info/http-alternates", "packed-refs"):
        (oracle / ".git" / relative).unlink(missing_ok=True)
    shutil.rmtree(oracle / ".git/refs/replace", ignore_errors=True)
    if name == "embedded-symlink":
        (oracle / "embedded/.git").unlink()
        shutil.copytree(outside / "embedded/.git", oracle / "embedded/.git")
    if name == "gitlink-staged":
        shutil.rmtree(oracle / "sub")
        (oracle / "sub").mkdir()
    # Preserve only reviewed semantic knobs. No include/filter/command source.
    original_config = (repo / ".git/config").read_text() if (repo / ".git").is_dir() else (directory / "repo/.git/config").read_text()
    # The base was built in an isolated environment; sparse extensions are
    # kept in the oracle, then reviewed safe knobs are appended.
    write(oracle / ".git/config", original_config + safe_config)
    if row["policy"].startswith("filtered"):
        write(oracle / ".gitattributes", "")
        # Keep .gitattributes' tracked content unchanged; CLI overrides disable
        # conversion through a highest-precedence info/attributes file.
        shutil.copy2(repo / ".gitattributes", oracle / ".gitattributes")
        write(oracle / ".git/info/attributes", "* -text -ident -filter -eol -working-tree-encoding\n")
    oracle_bytes = git(oracle, "-c", "diff.renames=false", "-c", "status.renames=false",
                       "status", "--porcelain=v2", "--untracked-files=all", "--ignore-submodules=all")
    write(directory / "porcelain", oracle_bytes)
    if config:
        target = repo / ".git/config"
        assert target.is_file()
        target.write_text(target.read_text() + config)
    roots = [str(repo), str(repo / ".git")]
    if name == "linked-worktree":
        roots = [str(repo), str(directory / "repo/.git/worktrees/linked"), str(directory / "repo/.git")]
    return {**row, "repo": str(repo), "oracle": str(oracle), "outside": str(outside),
            "porcelain": str(directory / "porcelain"), "roots": roots,
            "forbidden": [str(outside)] + ([str(repo / "sub")] if name == "gitlink-staged" else []),
            "safe_config": safe_config}


RUST = r'''
#![allow(dead_code, unused_imports)]
@MODULES@
use bingsu_identity::build_id;
use bingsu_core::{collection::{self, path_facts::PathQuery, wire::{self, Binding, Request, Update, Progress}}, field::{self, FieldValue, ValueState}, snapshot};
use std::{io::{self, Write}, os::unix::ffi::OsStrExt, time::{Duration, Instant}, sync::OnceLock};
static START: OnceLock<Instant> = OnceLock::new();
fn line(s: &str) { io::stdout().write_all(s.as_bytes()).unwrap(); }
fn phase(s: &str) {
    line(&format!("F1_PHASE {s}\n"));
    if let Some(start) = START.get() { line(&format!("F1_TIME {s} {}\n", start.elapsed().as_nanos())); }
}
fn hex(b: &[u8]) -> String { b.iter().map(|v|format!("{v:02x}")).collect() }
struct Sink;
impl update_sink::UpdateSink for Sink {
    fn update(&mut self, u: Update) -> io::Result<()> {
        if let Some(v)=u.value {
            line("F1_UPDATE\n");
            for (decl,f) in field::BUILTIN[u.segment as usize].fields.iter().zip(&v.fields) {
                let value=if f.state==ValueState::Pending { "pending".into() } else { match &f.value {
                    FieldValue::Count{n,saturated}=>format!("count:{n}:{saturated}"),
                    FieldValue::Text(v)=>format!("text:{}",hex(v.as_str().as_bytes())),
                    FieldValue::Bool(v)=>format!("bool:{v}"),
                    FieldValue::Absent=>"absent".into(), _=>panic!("unexpected field") }};
                line(&format!("F1_FIELD {} {value}\n",decl.name));
            }
            line("F1_END_UPDATE\n");
            let display=bingsu_core::shell_values::format_git(&v,bingsu_core::icons::IconSet::Ascii,bingsu_core::width::WidthProfile::DEFAULT);
            line(&format!("F1_DISPLAY {}\n",hex(display.text().as_bytes())));
        }
        if let Some(f)=u.facts {
            for s in f.siblings { line(&format!("F1_SIBLING {} {} {}\n",s.component,s.complete,s.names.len())); }
        }
        Ok(())
    }
    fn progress(&mut self, p: Progress)->io::Result<()> { line(&format!("F1_PROGRESS {}\n",p.stage_a_complete)); Ok(()) }
}
fn main() {
    // fd 2 remains /dev/null as in the product. Preserve test-only startup
    // diagnostics on the observation pipe instead of losing a rare failure.
    std::panic::set_hook(Box::new(|error| line(&format!("F1_PANIC {error}\n"))));
    let args:Vec<_>=std::env::args_os().collect();
    let cwd=args[1].as_bytes().to_vec();
    let home=args[2].as_bytes();
    #[allow(unused_mut)]
    let mut timed=args[3]=="timed" || args[3]=="slow";
    let slow=args[3]=="slow";
    let known=args[4]!="unknown";
    let unique=args[5]=="unique";
    let catalog=collection::selection::Catalog{segments:&field::BUILTIN,workers:(1<<3)|(1<<1)};
    let binding=Binding{build_id:build_id(),snapshot:snapshot::Identity{boot:[1;16],epoch:[2;16],generation:1,source:[3;4],context:snapshot::context_crc(b"/c",b"/s").unwrap()},clock_kind:1,domain:[0;16],resume:0,config:b"/c".to_vec(),state:b"/s".to_vec(),path_query:PathQuery::for_path(&cwd,Some(home),unique),cwd,mask:catalog.workers};
    let mut request=collection::request(&catalog,binding,wire::M3B_REQUEST_ID,50).unwrap().unwrap();
    request.global_excludes_known=known;
    sys::orphan_guard().unwrap();
    let mut fds=sys::validate_worker_fds().unwrap();
    sys::hygiene().unwrap();
    worker::protected().unwrap();
    #[cfg(target_os="macos")] let access=worker::probe_before_ready(&mut fds).unwrap();
    #[cfg(target_os="linux")] let access=worker::probe_before_ready().unwrap();
    line(&format!("F1_READY {:?}\n",access.scope()));
    fds.read_exact(&mut [0u8;1]).unwrap();
    let start=Instant::now();
    START.set(start).unwrap();
    phase("acquisition");
    @MUTATION@
    let mut meter=meter::Meter::new(start+Duration::from_millis(if timed {50}else{30_000}));
    meter.hook=Some(Box::new(move |e| { match e {
        "stage_a_head" | "path_facts" | "before_read_layer" | "preflight_start" | "stage_c" | "stage_d" => phase(e), _=>{}
    }
        if slow && e=="preflight_start" {
            // Adversarial real elapsed time after A, with product deadlines.
            // Busy wait avoids adding a syscall to the protected pipeline.
            while start.elapsed() < Duration::from_millis(55) { std::hint::spin_loop(); }
        }
    }));
    let deadlines=if timed {git::StageDeadlines::PRODUCT}else{git::StageDeadlines{a_ms:30_000,b_ms:30_000,c_ms:30_000,d_ms:30_000,path_ms:30_000}};
    let result=git::collect_with_deadlines(&request,&mut Sink,meter,access,deadlines);
    phase("end");
    line(&format!("F1_RESULT {:?} {}\n",result,start.elapsed().as_nanos()));
}
'''


def build_workers():
    result = run(["cargo", "build", "--release", "-j", "2", "-p", "bingsu-collect", "--message-format=json"], cwd=ROOT)
    artifacts = [json.loads(line) for line in result.splitlines()]
    deps = {a["target"]["name"]: p for a in artifacts if a.get("reason") == "compiler-artifact"
            for p in a.get("filenames", []) if p.endswith(".rlib")}
    src = OUT / "src"
    shutil.copytree(ROOT / "crates/bingsu-collect/src", src)
    shutil.copy2(ROOT / "crates/bingsu-collect/collector-syscalls.tsv", OUT)
    worker = (src / "worker.rs").read_text()
    worker = replace_once(worker, "fn protected()", "pub(crate) fn protected()")
    # One definition per OS: two exact signatures, both stay cfg guarded.
    worker = replace_once(worker, "fn probe_before_ready()", "pub(crate) fn probe_before_ready()")
    worker = replace_once(worker, "fn probe_before_ready(fds:", "pub(crate) fn probe_before_ready(fds:")
    (src / "worker.rs").write_text(worker)
    # Observation only: distinguish the held-ancestor operation from readonly
    # metadata, and count processed raw slots (a kernel batch may contain >256).
    source = src / "safe_read/mod.rs"
    source.write_text(replace_once(source.read_text(),
        "        entries_bounded(&self.root, 256, Some(bytes), meter)",
        '        crate::phase("ancestor_names");\n        entries_bounded(&self.root, 256, Some(bytes), meter)'))
    for backend in ("linux", "macos"):
        source = src / "safe_read" / f"{backend}.rs"
        source.write_text(replace_once(source.read_text(), "            raw += 1;",
            '            raw += 1;\n            if bytes.is_some() { crate::line(&format!("F1_RAW {raw}\\n")); }'))
    import re
    modules = "\n".join(re.findall(r"(?m)(?:(?:#\[[^\n]+\]|//[^\n]*)\n)*mod \w+;$", (src / "main.rs").read_text()))
    assert "mod git;" in modules and "mod worker;" in modules
    text = RUST.replace("@MODULES@", modules)
    command = ["rustc", "--edition=2024", "--cfg", "test", "-O", "-C", "lto=fat", "-C", "embed-bitcode=yes",
               "-L", f"dependency={ROOT / 'target/release/deps'}"]
    for name in ("bingsu_core", "bingsu_identity", "libc", "gix_config", "gix_ref", "gix_index", "gix_object", "gix_pack", "gix_error", "gix_zlib", "gix_ignore", "gix_attributes", "gix_utils", "gix_revwalk"):
        command += ["--extern", f"{name}={deps[name]}"]
    paths = {}
    effect_mutation = r'''
    if args[6]=="deadline" { timed=false; } else {
    let target=std::ffi::CString::new(args[7].as_bytes()).unwrap();
    unsafe {
        let flags=if args[6]=="write" {libc::O_WRONLY|libc::O_TRUNC}else{libc::O_RDONLY};
        let fd=libc::open(target.as_ptr(),flags);
        if fd>=0 { let mut b=[0u8;1]; libc::read(fd,b.as_mut_ptr().cast(),1); libc::close(fd); }
    }
    }
    '''
    for name, mutation in [("worker", ""), ("effect-mutant", effect_mutation),
                           ("spawn-mutant", "unsafe { let p=libc::fork(); if p==0 {libc::_exit(0);} if p>0 {libc::waitpid(p,std::ptr::null_mut(),0);} }")]:
        (src / "main.rs").write_text(text.replace("@MUTATION@", mutation))
        binary = OUT / name
        run([*command, src / "main.rs", "-o", binary], cwd=ROOT)
        paths[name] = str(binary)
    return paths


def prepare_probe():
    runtime = OUT / "runtime"
    root = runtime / "collector-probes-v1/open-flags/root"
    for p in (runtime, root.parent.parent, root.parent, root, root / "dir", root.parent / "outside"):
        p.mkdir(parents=True, exist_ok=True)
        p.chmod(0o700)
    for name, value in (("value", "inside"), ("dir/file", "inside"), ("hard", "linked")):
        write(root / name, value)
        (root / name).chmod(0o600)
    os.link(root / "hard", root / "hard2")
    for target, name in [("../value", "dir/inner"), ("../../outside", "dir/up"), ("dir", "linkdir"), ("/", "absolute"), ("../outside", "escape")]:
        os.symlink(target, root / name)
    return str(root)


INTERPOSER = r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/attr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
static int active;
static int output_closed;
static void hx(const char *s, char *out) {
    const char *digits = "0123456789abcdef";
    size_t n = strlen(s);
    if (n > 1023) _exit(87);
    for (size_t i = 0; i < n; ++i) {
        unsigned char b = (unsigned char)s[i];
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 15];
    }
    out[n * 2] = 0;
}
static void event(const char *name, int fd, const char *path, long flags) {
    if (!active) return;
    if (output_closed) _exit(87);
    int saved = errno;
    char base[1024] = "/";
    if (fd != AT_FDCWD && fcntl(fd, F_GETPATH, base) != 0) {
        if (path == NULL) return; /* pipe/control descriptor, not file IO */
        strcpy(base, "?");
    }
    char a[2048], b[2048], out[4300];
    hx(base, a);
    hx(path == NULL ? "" : path, b);
    int n = snprintf(out, sizeof(out), "F1_IO %s %s %s %ld %d\n", name, a, b[0] ? b : "-", flags, fd);
    if (n < 0 || (size_t)n >= sizeof(out) || write(1, out, (size_t)n) != n) _exit(87);
    errno = saved;
}
static int opened(int fd) {
    if (active && fd >= 0) {
        int saved = errno;
        char path[1024], encoded[2048], out[2100];
        if (fcntl(fd, F_GETPATH, path) != 0) _exit(87);
        hx(path, encoded);
        int n = snprintf(out, sizeof(out), "F1_BIND %d %s\n", fd, encoded);
        if (n < 0 || (size_t)n >= sizeof(out) || write(1, out, (size_t)n) != n) _exit(87);
        errno = saved;
    }
    return fd;
}
static int audit_close(int fd) {
    if (fd == 1) output_closed = 1;
    int result = close(fd);
    /* WorkerFds closes its pipe before its remaining control descriptors.
       Other IO after that point still fails closed in event(). */
    if (active && !output_closed && result == 0) {
        int saved = errno;
        char out[64];
        int n = snprintf(out, sizeof(out), "F1_CLOSE %d\n", fd);
        if (n < 0 || (size_t)n >= sizeof(out) || write(1, out, (size_t)n) != n) _exit(87);
        errno = saved;
    }
    return result;
}
static ssize_t audit_write(int fd, const void *p, size_t n) {
    if (fd == 1 && n >= 9 && !memcmp(p, "F1_PHASE ", 9)) active = 1;
    if (fd != 1 && active) _exit(88);
    return write(fd, p, n);
}
static int audit_openat(int fd, const char *p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    event("openat", fd, p, flags);
    if (active && (flags & (O_ACCMODE | O_APPEND | O_CREAT | O_TRUNC))) _exit(88);
    return opened(openat(fd, p, flags, mode));
}
static int audit_open(const char *p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    event("open", AT_FDCWD, p, flags);
    if (active && (flags & (O_ACCMODE | O_APPEND | O_CREAT | O_TRUNC))) _exit(88);
    return opened(open(p, flags, mode));
}
static int audit_fstatat(int fd, const char *p, struct stat *s, int flags) {
    event("fstatat", fd, p, flags);
    return fstatat(fd, p, s, flags);
}
static int audit_stat(const char *p, struct stat *s) {
    event("stat", AT_FDCWD, p, 0);
    return stat(p, s);
}
static int audit_lstat(const char *p, struct stat *s) {
    event("lstat", AT_FDCWD, p, 0);
    return lstat(p, s);
}
static int audit_fstat(int fd, struct stat *s) {
    event("fstat", fd, NULL, 0);
    return fstat(fd, s);
}
static int audit_fstatfs(int fd, struct statfs *s) {
    event("fstatfs", fd, NULL, 0);
    return fstatfs(fd, s);
}
static ssize_t audit_read(int fd, void *p, size_t n) {
    event("read", fd, NULL, (long)n);
    return read(fd, p, n);
}
static ssize_t audit_pread(int fd, void *p, size_t n, off_t at) {
    event("pread", fd, NULL, (long)n);
    return pread(fd, p, n, at);
}
static ssize_t audit_readlinkat(int fd, const char *p, char *b, size_t n) {
    event("readlinkat", fd, p, (long)n);
    return readlinkat(fd, p, b, n);
}
static ssize_t audit_readlink(const char *p, char *b, size_t n) {
    event("readlink", AT_FDCWD, p, (long)n);
    return readlink(p, b, n);
}
static int audit_faccessat(int fd, const char *p, int mode, int flags) {
    event("faccessat", fd, p, flags);
    return faccessat(fd, p, mode, flags);
}
extern ssize_t __getdirentries64(int, void *, size_t, off_t *);
static ssize_t audit_dirs(int fd, void *p, size_t n, off_t *at) {
    event("getdents", fd, NULL, (long)n);
    return __getdirentries64(fd, p, n, at);
}
static int audit_bulk(int fd, struct attrlist *a, void *p, size_t n, uint64_t options) {
    event("bulk", fd, NULL, (long)n);
    return getattrlistbulk(fd, a, p, n, options);
}
static void *audit_mmap(void *p, size_t n, int prot, int flags, int fd, off_t at) {
    if (!(flags & MAP_ANON)) event("mmap", fd, NULL, prot);
    return mmap(p, n, prot, flags, fd, at);
}
static void refused(void) { _exit(86); }
#define PAIR(replacement, original, id) \
__attribute__((used,section("__DATA,__interpose"))) static const \
struct { const void *r; const void *o; } id = { (const void *)replacement, (const void *)original };
PAIR(audit_write, write, w)
PAIR(audit_close, close, cl)
PAIR(audit_openat, openat, oa)
PAIR(audit_open, open, o)
PAIR(audit_fstatat, fstatat, sa)
PAIR(audit_fstat, fstat, sf)
PAIR(audit_stat, stat, s)
PAIR(audit_lstat, lstat, ls)
PAIR(audit_fstatfs, fstatfs, fs)
PAIR(audit_read, read, r)
PAIR(audit_pread, pread, pr)
PAIR(audit_readlinkat, readlinkat, rl)
PAIR(audit_readlink, readlink, rlp)
PAIR(audit_faccessat, faccessat, ac)
PAIR(audit_dirs, __getdirentries64, dirs)
PAIR(audit_bulk, getattrlistbulk, bulk)
PAIR(audit_mmap, mmap, mm)
@FORBIDDEN@
__attribute__((constructor)) static void clean(void) { unsetenv("DYLD_INSERT_LIBRARIES"); }
'''


def build_interposer():
    forbidden = ("posix_spawn", "posix_spawnp", "execve", "execv", "execvp", "execvP", "execl", "execlp", "execle",
                 "fork", "vfork", "system", "popen", "socket", "socketpair", "connect", "bind", "listen", "accept",
                 "sendto", "sendmsg", "recvfrom", "recvmsg", "shutdown", "getsockname", "getpeername", "setsockopt", "getsockopt",
                 "rename", "renameat", "renameatx_np", "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir",
                 "truncate", "ftruncate", "link", "linkat", "symlink", "symlinkat", "pwrite", "pwritev", "writev",
                 "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "utimes", "futimes", "utimensat",
                 "setxattr", "fsetxattr", "removexattr", "fremovexattr")
    code = INTERPOSER.replace("@FORBIDDEN@", "\n".join(f"PAIR(refused, {name}, forbidden{i})" for i, name in enumerate(forbidden)))
    source = OUT / "audit.c"
    source.write_text(code)
    dylib = OUT / "audit.dylib"
    run(["cc", "-dynamiclib", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", source, "-o", dylib])
    return dylib


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    workers = build_workers()
    rows = list(csv.DictReader(MANIFEST.open(), delimiter="\t"))
    cases = [prepare_case(row) for row in rows]
    manifest = {"workers": workers, "cases": cases, "probe": prepare_probe(), "source_hashes": source_hashes()}
    if sys.platform == "darwin":
        manifest["interposer"] = str(build_interposer())
    manifest["binary_hashes"] = {p: digest(p) for p in [*workers.values(), *([manifest["interposer"]] if "interposer" in manifest else [])]}
    (OUT / "prepared.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"F1 prepared {len(cases)} cases: {OUT / 'prepared.json'}")


if __name__ == "__main__":
    main()
