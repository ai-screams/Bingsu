#!/usr/bin/env python3
"""M3c real collection observations; never formal M3d B5--B7 certification.

Prepare release siblings explicitly with --prepare. Runtime measurement never
builds, retries a failed round, widens a deadline, or substitutes a degraded
prompt. Test-only helper clock injection is labelled separately from the normal
product prompt. Product scratch stays under target; raw measurement output lives outside the checkout.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(tempfile.gettempdir()) / "bingsu-measurements"
CASES = ("no-git", "git-clean", "git-dirty", "tracked-19000", "budget-bound")
# Whole-prompt time with the command environment and command values (M6 C4b-3).
# These run only the normal product prompt, not the helper fixture. The gate
# records them only (size_gate.py --record-only): a base that reads no command
# response makes the ratio the whole added cost, and the worst increment is
# bounded by +0.5 ms (U-23), not by the ratio.
# - prompt-env64k: about 60 KiB of shell environment, so the prompt writes a near-full frame.
# - prompt-env64k-commands: the same environment and 32 cached command segments
#   that each allow another variable (32 environment digests, none shared),
#   all drawn (2,400 columns).
# - prompt-commands-hit: three cached command segments, values of a few bytes.
# - prompt-commands-max: 32 cached command segments, each value 4 KB of mixed text, all drawn (2,400 columns).
# - prompt-commands-max-empty: the max config with no command response: the
#   prompts pass no session, so no unit runs and nothing is published. Its
#   difference from max is the cost of drawing command values (U-23).
# - prompt-commands-redraw: the max config, redrawn (`--redraw`: no helper).
# - prompt-commands-max-empty-redraw: the empty max config, redrawn. Neither
#   redraw starts a helper, so its difference from the redraw case is the
#   prompt's own cost of drawing command values (m6-P1).
# - prompt-text-max: the max layout and width with 32 text segments of the
#   same values instead of commands; its difference from max is what the
#   command feature itself adds (reading, decoding, deciding), apart from
#   drawing 32 wide segments (U-23).
# - prompt-env-segments: 32 env segments (C5) over the near-full frame of
#   prompt-env64k, each variable about 1 KB of mixed text, all drawn (2,400
#   columns). No command, no session, no response. A base without env
#   segments draws none; a part is refused.
SESSION = "0123456789abcdef0123456789abcdef"
COMMAND_CASES = ("prompt-env64k", "prompt-env64k-commands", "prompt-commands-hit", "prompt-commands-max",
                 "prompt-commands-max-empty", "prompt-commands-redraw", "prompt-commands-max-empty-redraw",
                 "prompt-text-max", "prompt-env-segments")
EMPTY_CASES = ("prompt-commands-max-empty", "prompt-commands-max-empty-redraw")
REDRAW_CASES = ("prompt-commands-redraw", "prompt-commands-max-empty-redraw")
# Cases without any command response for the whole run.
NO_RESPONSE_CASES = EMPTY_CASES + ("prompt-text-max", "prompt-env-segments")
ALL_CASES = CASES + COMMAND_CASES
STAGES = ("A", "PathFacts", "B", "C", "D")

# commands::run names crate::relay on Linux and macOS; the relay itself is not part of this build.
RELAY_STUB = '#[cfg(any(target_os = "linux", target_os = "macos"))] mod relay {pub(crate) fn run(_: &[std::ffi::OsString]) -> std::process::ExitCode {unreachable!("the relay runs only in the bingsu binary")}}'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

M3B = module("f3_m3b", ROOT / "bench/collector-product.py")


def manifest_path(binary):
    return Path(binary).resolve().with_name("git-product.json")


def stage_harness(source):
    """The stage fixture's Rust text belongs to the tree it is compiled
    against: the base tip builds with its own copy, the candidate with its
    own, so a field one side lacks never breaks the other."""
    return Path(source) / "scripts/prepare_git_corpus.py"


def sources(source):
    return {**M3B.preparation_sources(source), "f3_harness": M3B.digest(__file__), "stage_harness": M3B.digest(stage_harness(source))}


def prepared(binary):
    binary = Path(binary).resolve()
    value = json.loads(manifest_path(binary).read_text())
    for name, path in (("front", Path(value["front"])), ("cli", binary), ("collector", binary.with_name("bingsu-collect")),
                       ("fixture", Path(value["fixture"])), ("diagnostic", Path(value["diagnostic"]))):
        if M3B.digest(path) != value["hashes"][name]:
            raise ValueError("stale prepared " + name)
    if value["source_hashes"] != sources(Path(value["source"])):
        raise ValueError("stale prepared sources")
    if value["profile"] != "release" or value["product_mask"] != 10:
        raise ValueError("release product mask 10 required")
    return value


HELPER = r'''
#![allow(dead_code, unused_imports)]
@MODULES@
pub use bingsu_identity::build_id;
use bingsu_core::{collection::{self, wire}, snapshot::{self,Clock,ClockSource}, envelope::Envelope};
use commands::{collector_process as process, collection_store::{CollectionStore,Admission}};
use std::{fs,ffi::OsStr,os::unix::{ffi::OsStrExt,fs::{MetadataExt,PermissionsExt}},path::Path,time::Instant};
struct Fixed(Clock);
impl ClockSource for Fixed {fn observe(&mut self)->Result<Clock,snapshot::ClockError>{Ok(self.0)}}
fn opt(n:Option<u64>)->String {n.map_or("null".into(),|n|n.to_string())}
fn hex(b:&[u8])->String {b.iter().map(|b|format!("{b:02x}")).collect()}
fn main() {
 let args:Vec<_>=std::env::args_os().collect();
 if args[1]=="--read" {prompt_read::tests::f3_read_measure(Path::new(&args[2]),Path::new(&args[3]));return;}
 let base=Path::new(&args[1]);let repo=Path::new(&args[2]);
 let _guard=commands::sys::test_inherited_fd_lock();
 for name in ["runtime","config","state","home"] {let p=base.join(name);fs::create_dir_all(&p).unwrap();fs::set_permissions(p,fs::Permissions::from_mode(0o700)).unwrap();}
 let config=base.join("config/config.toml");
 if !config.exists(){fs::write(config,"icons='ascii'\n").unwrap();}
 let now=commands::collector_supervisor::fixture_clock().unwrap();
 let md=fs::metadata(base.join("runtime")).unwrap();
 let request=commands::refresh::RefreshRequest {
 runtime:commands::runtime_root::Pinned{path:base.join("runtime"),dev:md.dev(),ino:md.ino()},
 config_written:base.join("config"),config_canonical:base.join("config"),config_root_shape_only:false,
 state_root:base.join("state"),home:repo.to_owned(),me:commands::sys::current_uid(),
 user:commands::sys::passwd_entry(commands::sys::current_uid()).unwrap().name,version:[0,0,0],build:Some([1;40]),process_started:now};
 let primed=commands::refresh::refresh(request.clone(),&mut Fixed(now));
 assert!(matches!(primed,commands::refresh::RefreshResult::Published{..}|commands::refresh::RefreshResult::Revalidated{..}),"snapshot prime: {primed:?}");
 let envelope=Envelope {config_root:Some(request.config_canonical.as_os_str().as_bytes().to_vec()),state_root:Some(request.state_root.as_os_str().as_bytes().to_vec()),pwd:Some(repo.as_os_str().as_bytes().to_vec()),home:Some(repo.as_os_str().as_bytes().to_vec()),width:80,..Envelope::default()};
 let mut groups=commands::group_policy::SystemGroups::new(&request.user);
 let watchdog=commands::helper_limits::start(Instant::now()).unwrap();
 let mut verification=commands::helper::Verification::start();
 let mut handle=None;let mut admission_ns=0;let mut product_mask=None;let mut deferred=None;
 let value=std::sync::Arc::new(std::sync::Mutex::new(None));let output=value.clone();
 let broker=commands::refresh::refresh_broker(request,&mut Fixed(now),&mut |context,display,clock@MARKER@| {
 verification.verified();
 let mut selected=commands::helper::selected_request(&collection::selection::PRODUCT,&envelope,display,clock)?.unwrap();
 assert_eq!(selected.binding.mask,10);
 product_mask=Some(selected.binding.mask);
 // An isolated HOME/XDG with no global files is a known empty input, exactly
 // the normal helper's result for the measurement environment.
 selected.global_excludes_known=true;
 let pin=commands::collector::PinnedCollector::verify(OsStr::new(@COLLECTOR@),commands::sys::current_uid(),&mut groups)?;
 let at=process::now_ns()?;
 // Only the explicit regression mode injects an expired admission clock.
 // Ordinary observations retain the shipped GC time and operation budgets.
 let admission=if args.get(3).is_some_and(|arg|arg=="--expire-admission") {
 CollectionStore::fixture_admit(context,&selected.binding,clock,bingsu_core::field::BUILTIN,
 commands::collection_gc::GcBudget{max_ops:4096,max_ns:0},Some(||0))?
 } else {CollectionStore::admit(context,&selected.binding,clock)?};
 let mut store=match admission {
 Admission::Admitted(store)=>store,Admission::Deferred(reason)=>{deferred=Some(reason);return Err(commands::snapshot_store::StoreError::Busy)}};
 admission_ns=process::now_ns()?.saturating_sub(at);
 let lock=store.worker_lock()?;
 let job=verification.attach(commands::collector::spawn(&pin,selected,lock,&watchdog,context)?,&store);
 let output=output.clone();
 handle=Some(job.start(Box::new(move |v| {let r=store.publish(&v);if r.is_ok(){*output.lock().unwrap()=Some(v);}r}))?);
 let pidfd=handle.as_ref().and_then(|h|h.child_pidfd());
 commands::helper_limits::install(&watchdog)?;commands::helper_filter::install(pidfd)?;
 handle.as_ref().unwrap().confirm_confinement()?;Ok(())
 });
 let Some(handle)=handle else {
 println!("F3_RESULT {{\"status\":\"BLOCKED\",\"product_mask\":{},\"blocked_at\":\"admission\",\"deferred\":\"{deferred:?}\",\"broker\":\"{broker:?}\"}}",product_mask.map_or("null".into(),|n|n.to_string()));
 return;
 };
 let report=handle.finish();
 let value=value.lock().unwrap();
 let partial=value.as_ref().map(|v|v.reason!=wire::EndReason::Complete || v.updates.iter().any(|u|u.value.as_ref().is_some_and(|v|v.fields.get(10).is_some_and(|f|matches!(f.value,bingsu_core::field::FieldValue::Bool(true))))));
 let t=report.lifecycle;
 let events=[("verify_start",t.verify_start),("verify_end",t.verify_end),("spawn_enter",t.spawn_enter),("spawn_return",t.spawn_return),("ready",t.ready),("request_sent",t.request_sent),("completed",t.completed),("response_renamed",t.response_renamed),("lock_acquired",t.lock_acquired),("lock_closed",t.lock_closed),("request_deadline",t.request_deadline),("as_baseline",t.as_baseline)];
 let events=events.iter().map(|(k,v)|format!("\"{k}\":{}",opt(*v))).collect::<Vec<_>>().join(",");
 let frames=report.f3_frames.iter().map(|(n,b)|format!("[{},\"{}\"]",n,hex(b))).collect::<Vec<_>>().join(",");
 println!("F3_RESULT {{\"product_mask\":{},\"events\":{{{events}}},\"frames\":[{frames}],\"reason\":\"{:?}\",\"published\":{},\"reaped\":{},\"stage_a\":{},\"partial\":{},\"admission_gc_ns\":{admission_ns},\"completed_at_ns\":{}}}",product_mask.unwrap(),report.reason,report.published,report.reaped,report.progress.stage_a_complete,partial.map_or("null".into(),|v|v.to_string()),opt(value.as_ref().map(|v|v.completed_at_ns)));
}
'''


def prepared_directory(binary, source):
    # Keyed by the source tree too: a base and a candidate whose front binaries are
    # byte-identical (a change that does not reach the product) must not share, and
    # so overwrite, one fixture.
    return OUT / "prepared" / (M3B.digest(binary)[:16] + "-" + hashlib.sha256(str(Path(source).resolve()).encode()).hexdigest()[:8])


def prepare(binary):
    binary = Path(binary).resolve()
    source = M3B.build_context(binary)
    if binary.parent.name != "release":
        raise ValueError("release sibling pair required")
    directory = prepared_directory(binary, source)
    directory.mkdir(parents=True, exist_ok=True)
    dedicated = M3B.dedicated_prompt(binary)
    command = ["cargo", "build", "--locked", "-j", "2", "--release", "-p", "bingsu", "-p", "bingsu-collect",
               *(["-p", "bingsu-prompt"] if dedicated else []), "--message-format=json"]
    triple = binary.parent.parent.name
    cross = triple.endswith(("-linux-musl", "-linux-gnu"))
    if cross:
        command += ["--target", triple]
    artifacts = [json.loads(line) for line in M3B.run(command, cwd=source, timeout=900).stdout.splitlines()]
    deps = {a["target"]["name"]: p for a in artifacts if a.get("reason") == "compiler-artifact"
            for p in a.get("filenames", []) if p.endswith(".rlib")}
    copied = directory / "commands"
    shutil.copytree(source / "crates/bingsu/src/commands", copied, dirs_exist_ok=True)
    shutil.copytree(source / "crates/bingsu/src/shell", directory / "shell", dirs_exist_ok=True)
    mod = copied / "mod.rs"
    mod.write_text(mod.read_text().replace("mod collector;", "pub(crate) mod collector;").replace("mod group_policy;", "pub(crate) mod group_policy;"))
    supervisor = copied / "collector_supervisor.rs"
    text = supervisor.read_text()
    for old, new in [
        ("    pub frames: u16,", "    pub frames: u16,\n    pub f3_frames: Vec<(u64,Vec<u8>)>,"),
        ("            frames: 0,", "            frames: 0,\n            f3_frames: Vec::new(),"),
        ("                        complete = frame.kind == Kind::Complete;", "                        report.f3_frames.push((now_ns().unwrap(),buffer[..have].to_vec()));\n                        complete = frame.kind == Kind::Complete;"),
        ("            fixture_clock: false,", "            fixture_clock: true,"),
    ]:
        if old == "            frames: 0,":
            assert text.count(old) == 2
            text = text.replace(old, new)
        else:
            text = M3B.replace_required(text, old, new)
    supervisor.write_text(text)
    process = copied / "collector_process.rs"
    # The gate prepares the base and the candidate with this one script, so the
    # child attach is matched in either visibility (it became pub(crate) for
    # the command supervisor); the printed pid is the same either way.
    text = process.read_text()
    attach = next(line for line in ("    pub(crate) fn attach(pid: libc::pid_t, expires_ns: u64) -> io::Result<Self> {",
                                    "    fn attach(pid: libc::pid_t, expires_ns: u64) -> io::Result<Self> {")
                  if line in text)
    process.write_text(M3B.replace_required(text, attach, attach + '\n        println!("F3_PID {pid}");'))
    modules = [f'#[path={json.dumps(str(mod))}] mod commands;', RELAY_STUB]
    for name in ("prompt", "prompt_io", "prompt_read", "prompt_spawn"):
        path = source / "crates/bingsu/src" / (name + ".rs")
        if name == "prompt_read":
            reader = path.read_text()
            measurement = M3B.read_measurement(source)
            measurement = measurement.replace("product_read_measure(base: &std::path::Path)", "f3_read_measure(base: &std::path::Path, repo: &std::path::Path)")
            measurement = measurement.replace('        config_value.bands.clear();config_value.band_order.clear();config_value.collect_mask=TEST_MASK;\n', '')
            measurement = measurement.replace('        config_value.variants=vec![bingsu_core::template::compile::compile("{fixture}",&crate::SEGMENTS).unwrap()];\n', '')
            measurement = measurement.replace('"/repo".to_owned(),', 'repo.to_string_lossy().into_owned(),format!("--home={}",repo.display()),')
            measurement = measurement.replace('bingsu_core::collection::wire::BuildId(bingsu_core::collection::cwd_hash::sha256(&[crate::build_id().0.as_slice(),b"test-worker"].concat()))', 'crate::build_id()')
            measurement = measurement.replace('Catalog{segments:&crate::SEGMENTS,workers:TEST_MASK}', 'bingsu_core::collection::selection::PRODUCT')
            path = directory / "reader.rs"
            at = reader.rfind("}")
            path.write_text(reader[:at] + measurement + reader[at:])
        modules.append(f'#[path={json.dumps(str(path))}] mod {name};')
    modules.append(f'#[path={json.dumps(str(source / "crates/bingsu/src/sandbox.rs"))}] mod sandbox;' if platform.system() == "Linux" else
                   'mod sandbox {pub fn enter()->bingsu_core::front::Sandbox{bingsu_core::front::Sandbox::Absent}}')
    rust = directory / "main.rs"
    rust.write_text(HELPER.replace("@MODULES@", "\n".join(modules)).replace("@COLLECTOR@", json.dumps(str(binary.with_name("bingsu-collect"))))
                    .replace("@MARKER@", M3B.broker_marker(source)))
    fixture = directory / "git-product"
    command = ["rustc", "--edition=2024", "--cfg", "test", "-O", "-C", "lto=fat", "-C", "embed-bitcode=yes", str(rust), "-o", str(fixture), "-L", f"dependency={binary.parent / 'deps'}"]
    for name in ("bingsu_core", "bingsu_identity", "libc", *M3B.cli_libraries(source)):
        command += ["--extern", f"{name}={deps[name]}"]
    if cross:
        command += ["--target", triple]
        linker = os.environ.get("CARGO_TARGET_" + triple.upper().replace("-", "_") + "_LINKER")
        if linker:
            command += ["-C", "linker=" + linker]
    M3B.run(command, env={**os.environ, "CARGO_MANIFEST_DIR": str(source / "crates/bingsu"), "CARGO_PKG_VERSION": M3B.workspace_version(source)}, timeout=300)
    audit = module("f3_symbols", ROOT / "scripts/check_collector_symbols.py")
    identity = audit.build_id(binary, 2)
    if identity != audit.build_id(binary.with_name("bingsu-collect"), 1):
        raise ValueError("sibling build mismatch")
    # The front is the binary the hook runs for the prompt: bingsu-prompt when
    # the tree has it (missing, it fails here rather than measure the fallback).
    front = binary.with_name("bingsu-prompt") if dedicated else binary
    if dedicated and identity != audit.build_id(front, 3):
        raise ValueError("prompt sibling build mismatch")
    sizes = stripped_sizes(binary, front, directory, dedicated)
    diagnostic = prepare_diagnostic(source, directory, binary, deps, cross, triple)
    value = {"diagnostic": str(diagnostic), "source": str(source), "profile": "release", "product_mask": 10, "fixture": str(fixture),
             "front": str(front),
             "hashes": {"front": M3B.digest(front), "cli": M3B.digest(binary), "collector": M3B.digest(binary.with_name("bingsu-collect")), "fixture": M3B.digest(fixture), "diagnostic": M3B.digest(diagnostic)},
             "source_hashes": sources(source), "sibling_build_id": identity.hex(), "stripped_bytes": sizes,
             "compiler": M3B.run(["rustc", "-vV"]).stdout.decode(),
             "probe_sources": {"stage_fixture": M3B.digest(stage_harness(source)), "reader_fixture": M3B.digest(ROOT / "bench/collector-product.py")}}
    manifest_path(binary).write_text(json.dumps(value, indent=2) + "\n")
    return value


def stripped_sizes(binary, front, directory, dedicated):
    """Stripped bytes of the front, the collector and the CLI beside `binary`,
    each stripped into `directory`, and the two sums: combined (the prompt image
    and the collector, the size cap) and installed (every file of the install,
    recorded only). Without bingsu-prompt the front is the CLI itself."""
    sizes = {}
    for name, path in (("front", front), ("collector", Path(binary).with_name("bingsu-collect")), ("cli", binary)):
        stripped = Path(directory) / (name + "-stripped")
        M3B.run(["strip", "-o", str(stripped), str(path)])
        sizes[name] = stripped.stat().st_size
    sizes["combined"] = sizes["front"] + sizes["collector"]
    sizes["installed"] = sizes["combined"] + (sizes["cli"] if dedicated else 0)
    return sizes


def prepare_diagnostic(source, directory, binary, deps, cross, triple):
    """Separate stage-local observations; never substituted for shipped samples."""
    corpus = module("f3_stage_source", stage_harness(source))
    copied = directory / "collector"
    shutil.copytree(source / "crates/bingsu-collect/src", copied, dirs_exist_ok=True)
    shutil.copy2(source / "crates/bingsu-collect/collector-syscalls.tsv", directory)
    worker = copied / "worker.rs"
    text = worker.read_text()
    for old in ("fn protected()", "fn probe_before_ready()", "fn probe_before_ready(fds:"):
        text = M3B.replace_required(text, old, "pub(crate) " + old)
    worker.write_text(text)
    git_source = copied / "git/mod.rs"
    text = git_source.read_text()
    text = M3B.replace_required(text, '    sink.stage_deadline(std::time::Instant::now() + std::time::Duration::from_millis(millis));',
        '    let f3_start=std::time::Instant::now();\n    sink.stage_deadline(std::time::Instant::now() + std::time::Duration::from_millis(millis));')
    text = M3B.replace_required(text, '    meter.replace(owner);\n    result',
        '    meter.replace(owner);\n    crate::line(&format!("F3_STAGE {} {} {:?}\\n", millis, f3_start.elapsed().as_nanos(), result.as_ref().map(|_| ())));\n    result')
    git_source.write_text(text)
    declarations = "\n".join(re.findall(r"(?m)(?:(?:#\[[^\n]+\]|//[^\n]*)\n)*mod \w+;$", (copied / "main.rs").read_text()))
    rust = copied / "main.rs"
    rust.write_text(corpus.RUST.replace("@MODULES@", declarations).replace("@MUTATION@", ""))
    diagnostic = directory / "git-stages"
    command = ["rustc", "--edition=2024", "--cfg", "test", "-O", "-C", "lto=fat", "-C", "embed-bitcode=yes",
               str(rust), "-o", str(diagnostic), "-L", f"dependency={binary.parent / 'deps'}"]
    for name in ("bingsu_core", "bingsu_identity", "libc", "gix_config", "gix_ref", "gix_index", "gix_object", "gix_pack", "gix_error", "gix_zlib", "gix_ignore", "gix_attributes", "gix_utils", "gix_revwalk"):
        command += ["--extern", f"{name}={deps[name]}"]
    if cross:
        command += ["--target", triple]
        linker = os.environ.get("CARGO_TARGET_" + triple.upper().replace("-", "_") + "_LINKER")
        if linker:
            command += ["-C", "linker=" + linker]
    M3B.run(command, timeout=300)
    return diagnostic


def observe_stages(preparation, directory, repo):
    read_fd, write_fd = os.pipe()
    lock = os.open(directory / "diagnostic.lock", os.O_CREAT | os.O_RDONLY, 0o600)
    originals = [read_fd, lock]
    if platform.system() == "Darwin":
        probe = directory / "runtime/collector-probes-v1/open-flags/root"
        originals.append(os.open(probe, os.O_RDONLY))
    copies = [fcntl.fcntl(fd, fcntl.F_DUPFD, 20) for fd in originals]
    for fd in copies:
        os.set_inheritable(fd, True)
    def setup():
        for fd, target in zip(copies, (3, 5, 6)):
            os.dup2(fd, target)
    output = bytearray()
    try:
        with subprocess.Popen([str(preparation["diagnostic"]), str(repo), str(repo), "timed", "known", "plain", "false", "/unused"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env={}, cwd="/", close_fds=False, preexec_fn=setup) as child:
            for fd in copies:
                os.close(fd)
            copies.clear()
            sent = False
            deadline = time.monotonic() + 3
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    child.kill()
                    break
                if select.select([child.stdout], [], [], .002)[0]:
                    output.extend(os.read(child.stdout.fileno(), 65536))
                if not sent and b"F1_READY " in output and b"\n" in output:
                    os.write(write_fd, b"x")
                    sent = True
            output.extend(child.communicate()[0])
        text = output.decode(errors="replace")
        # A round that asks for languages gives C two of its milliseconds (U-19).
        stages = [{"stage": {5: "A", 3: "PathFacts", 28: "B", 8: "C", 6: "C", 4: "D", 2: "Languages"}[int(ms)],
                   "budget_ns": int(ms) * 1_000_000, "elapsed_ns": int(ns), "result": result}
                  for ms, ns, result in re.findall(r"(?m)^F3_STAGE (\d+) (\d+) (.*)$", text)]
        status = "OBSERVED" if child.returncode == 0 and "F1_RESULT " in text and "AllStages(" in text else "BLOCKED"
        return {"status": status, "exit": child.returncode, "stages": stages, "raw": text,
                "basis": "separate protected release fixture, unchanged product deadlines; not shipped timing"}
    finally:
        for fd in [*copies, *originals, write_fd]:
            os.close(fd)


def repositories(directory):
    return {name: repository(directory, name) for name in CASES}


def repository(directory, name):
    corpus = module("f3_corpus", ROOT / "scripts/prepare_git_corpus.py")
    path = directory / name
    if name == "no-git":
        # A .git file pointing nowhere would test a malformed repo. Instead
        # use a private directory with its own filesystem ceiling marker.
        path.mkdir()
        # Discovery stops at HOME; the helper's path query uses this cwd.
    else:
        corpus.base_repo(path)
        if name == "git-dirty":
            (path / "tracked").write_text("dirty\n")
            (path / "staged").write_text("staged\n")
            corpus.git(path, "add", "staged")
            (path / "untracked").write_text("new\n")
        if name == "tracked-19000":
            # 190 directories, 100 files each; includes the initial 3 paths.
            for n in range(18_997):
                p = path / f"d{n // 100:03}" / f"f{n:05}"
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(b"x\n")
            corpus.git(path, "add", ".")
            corpus.git(path, "commit", "-qm", "19000 tracked files")
            corpus.git(path, "branch", "-f", "upstream", "HEAD")
        if name == "budget-bound":
            # A real count cap: 257 untracked leaves in one directory.
            for n in range(257):
                p = path / "new" / str(n)
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(b"x")
    return path


def command_setup(case, directory):
    """The config, extra environment and expected values of a command case.

    Values are by unit id; each starts with its own mark `uNN-`, so a record
    shows which units it drew."""
    directory.mkdir(parents=True, exist_ok=True)
    # 60 entries of 1,000 bytes: under the 64 KiB frame with PATH and LC_ALL.
    pad = {f"BINGSU_PAD_{i:02}": "x" * 986 for i in range(60)}
    if case == "prompt-env64k":
        # The built-in layout draws dir and git, so every prompt would start a
        # collector in the background; the command cases draw neither. One
        # `char`, as they draw besides their units, keeps the helper's round
        # the same light kind and the timing on the frame.
        return "icons = 'ascii'\n[layout.line1]\nleft = ['char']\n", pad, {}
    if case == "prompt-env-segments":
        # The first 32 pad variables become the shown values: each starts
        # with its mark and keeps the pad's size, so the frame stays near full.
        values = {}
        for i in range(32):
            data = (f"u{i:02}-" + "kube-\uD55C\uAE00-ctx/" * 80).encode()[:986]
            while True:
                try:
                    data.decode()
                    break
                except UnicodeDecodeError:
                    data = data[:-1]
            pad[f"BINGSU_PAD_{i:02}"] = data.decode()
            values[f"custom/e{i:02}"] = data
        lines = "".join(f"[segment.\"custom/e{i:02}\"]\nkind = 'env'\nenv = 'BINGSU_PAD_{i:02}'\n" for i in range(32))
        ids = ", ".join(f"'custom/e{i:02}'" for i in range(32))
        return "icons = 'ascii'\n" + lines + f"[layout.line1]\nleft = [{ids}, 'char']\n", pad, values
    allow = [[]] * 32
    env = {}
    if case == "prompt-commands-hit":
        values = [b"u00-prod-cluster", b"u01-default", b"u02-v1.29"]
        argv = [["/bin/echo", v.decode()] for v in values]
    elif case == "prompt-env64k-commands":
        # The near-full frame and 32 units that each allow another variable:
        # 32 environment digests over it, nothing shared between units.
        values = [f"u{i:02}-env".encode() for i in range(32)]
        argv = [["/bin/echo", v.decode()] for v in values]
        allow = [[f"BINGSU_PAD_{i:02}"] for i in range(32)]
        env = pad
    else:
        # One line of 4,096 bytes of mixed text (ASCII, Hangul, a separator)
        # per unit, no newline, cut on a character boundary.
        values, argv = [], []
        for i in range(32):
            data = (f"u{i:02}-" + "kube-\uD55C\uAE00-ctx/" * 400).encode()[:4096]
            while True:
                try:
                    data.decode()
                    break
                except UnicodeDecodeError:
                    data = data[:-1]
            path = directory / f"value{i:02}.txt"
            path.write_bytes(data)
            values.append(data)
            argv.append(["/usr/bin/head", "-c", "4096", str(path)])
    lines = []
    if case == "prompt-text-max":
        for i, value in enumerate(values):
            lines.append(f"[segment.\"custom/k{i:02}\"]\nkind = 'text'\ntext = {json.dumps(value.decode())}\n")
        argv = []
    for i, words in enumerate(argv):
        quoted = ", ".join(json.dumps(w) for w in words)
        allowed = f"env_allow = [{', '.join(json.dumps(n) for n in allow[i])}]\n" if allow[i] else ""
        lines.append(f"[segment.\"custom/k{i:02}\"]\nkind = 'command'\ncommand = [{quoted}]\ncache = '3600s'\n{allowed}")
    ids = ", ".join(f"'custom/k{i:02}'" for i in range(len(values)))
    config = "icons = 'ascii'\n" + "".join(lines) + f"[layout.line1]\nleft = [{ids}, 'char']\n"
    return config, env, {f"custom/k{i:02}": v for i, v in enumerate(values)}


def response_units(directory):
    """The entries of the published command response under `directory`, by
    unit id: (status, value). BNGCMD01: a 64-byte head, the binding, a
    one-byte count, then per entry its id, origin, three digests, two times,
    status, value and raw line. Empty when there is no complete file."""
    for path in directory.rglob("store/command"):
        data = path.read_bytes()
        at = 64 + 32 + 16 + 16 + 4 + 1 + 16 + 8
        try:
            for _ in range(3):
                at += 4 + int.from_bytes(data[at:at + 4], "little")
            count, at = data[at], at + 1
            units = {}
            for _ in range(count):
                n = int.from_bytes(data[at:at + 2], "little")
                name, at = data[at + 2:at + 2 + n].decode(), at + 2 + n
                at += 1 + 32 * 3 + 16
                status, at = data[at], at + 1
                n = int.from_bytes(data[at:at + 4], "little")
                value, at = data[at + 4:at + 4 + n], at + 4 + n
                at += 4 + int.from_bytes(data[at:at + 4], "little")
                units[name] = (status, value)
            return units
        except (IndexError, UnicodeDecodeError):
            return {}
    return {}


def shown_value(value):
    """The value the helper publishes for a first line `value`: the prefix
    the prompt reads to cut a user segment (`Clean::read_prefix`, 64 cells:
    272 bytes, back to a character boundary)."""
    end = min(len(value), 64 * 4 + 16)
    while end < len(value) and end > 0 and value[end] & 0xC0 == 0x80:
        end -= 1
    return value[:end]


def response_ready(units, values):
    """Whether the published units are exactly `values`, each a success
    holding the whole value or its read prefix (`shown_value`)."""
    return set(units) == set(values) and all(
        units[name] in ((0, value), (0, shown_value(value))) for name, value in values.items())


def drawn_units(values, record):
    """How many units of `values` the record shows, by their marks."""
    return sum(v[:4] in record for v in values.values())


def command_context(binary, directory, case):
    """A warm prompt for a command case: the product snapshot is current and,
    for a command config, the helper has published every unit's value. The
    context keeps how many units the warm record draws: all of them, or none
    for a base without command values; a part is refused."""
    config, extra_env, values = command_setup(case, directory)
    command, env = M3B.prompt_context(binary, directory, config_text=config, extra_env=extra_env)
    # The shell hooks pass a session value on every prompt; command units run
    # only with one. The empty case passes none: the helper still starts every
    # prompt, but runs no unit and publishes no command response.
    empty = case in EMPTY_CASES or case == "prompt-env-segments"
    if not empty:
        command = [*command, "--session", SESSION]
    if len(values) == 32:
        # 32 values, separators included, fit only a wide line: at 80
        # columns the layout drops them and nothing is drawn.
        command[command.index("--width") + 1] = "2400"
    if not values:
        return command, env, values, None
    if case == "prompt-env-segments":
        result = M3B.run(command, env=env)
        drawn = drawn_units(values, result.stdout)
        if not M3B.normal_record(result) or any(directory.rglob("store/command")) or drawn not in (0, len(values)):
            raise ValueError(f"{case}: a command response exists or the prompt draws {drawn} units")
        return command, env, values, drawn
    if case == "prompt-text-max":
        result = M3B.run(command, env=env)
        drawn = drawn_units(values, result.stdout)
        if not M3B.normal_record(result) or any(directory.rglob("store/command")) or drawn != len(values):
            raise ValueError(f"{case}: a command response exists or the prompt draws {drawn} units")
        return command, env, values, drawn
    if empty:
        if case in REDRAW_CASES:
            command = [*command, "--redraw"]
        result = M3B.run(command, env=env)
        drawn = drawn_units(values, result.stdout)
        if not M3B.normal_record(result) or any(directory.rglob("store/command")) or drawn:
            raise ValueError(f"{case}: a command response exists or the prompt draws {drawn} units")
        return command, env, values, 0
    # Each prompt starts a refresh helper, which runs at most eight units a
    # round and caches the results: wait until every unit succeeded with its
    # value. A build that publishes only the part the prompt reads stores the
    # read prefix; an older one (the base of a comparison) stores the whole
    # value. Either is ready.
    for _ in range(400):
        result = M3B.run(command, env=env)
        if M3B.normal_record(result) and response_ready(response_units(directory), values):
            break
        time.sleep(0.05)
    else:
        raise ValueError(f"{case}: the command response never held every unit's value")
    if case in REDRAW_CASES:
        command = [*command, "--redraw"]
    drawn = drawn_units(values, M3B.run(command, env=env).stdout)
    if drawn not in (0, len(values)):
        raise ValueError(f"{case}: the warm prompt draws {drawn} of {len(values)} units")
    return command, env, values, drawn


def observe_command(binary, contexts, directory, case):
    """One normal product prompt of a command case, timed. A prompt that
    draws another number of units than the warm one is not a sample."""
    key = str(directory)
    if key not in contexts:
        try:
            contexts[key] = command_context(binary, directory, case)
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            contexts[key] = str(error)
    if isinstance(contexts[key], str):
        return {"status": "BLOCKED", "reason": contexts[key]}
    command, env, values, drawn = contexts[key]
    start = time.monotonic_ns()
    try:
        result = M3B.run(command, env=env)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        return {"status": "BLOCKED", "reason": str(error)}
    elapsed = time.monotonic_ns() - start
    if not M3B.normal_record(result):
        return {"status": "BLOCKED", "reason": "normal B1 record unavailable"}
    now = None if drawn is None else drawn_units(values, result.stdout)
    if now != drawn:
        return {"status": "BLOCKED", "reason": f"drew {now} of {len(values)} units, the warm prompt {drawn}"}
    # The empty case stays without a response for the whole run.
    if case in NO_RESPONSE_CASES and any(directory.rglob("store/command")):
        return {"status": "BLOCKED", "reason": "a command response was published"}
    return {"status": "OBSERVED", "prompt_ns": elapsed, "units": len(values), "drawn": now}


def summarize_prompt(samples, rounds):
    """The prompt time of a command case, and how many units it drew."""
    observed = [s for s in samples if s.get("status") == "OBSERVED"]
    values = [s["prompt_ns"] for s in observed]
    return {"attempted": len(samples), "observed": len(observed),
            "units": sorted({s.get("units") for s in observed}, key=str),
            "drawn": sorted({s.get("drawn") for s in observed}, key=str),
            "metrics": {"prompt_ns": {"status": "OBSERVED" if len(values) == rounds else "BLOCKED",
                                      **(M3B.summary(values) if values else {"n": 0})}}}


def memory_sample(pid):
    at = time.monotonic_ns()
    if platform.system() == "Linux":
        try:
            lines = Path(f"/proc/{pid}/status").read_text().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            return None
        values = {l.split(":")[0]: int(l.split()[1]) * 1024 for l in lines if l.startswith(("VmPeak:", "VmHWM:", "VmRSS:"))}
        if not values:
            return None
        return {"at_ns": at, "as_peak_bytes": values.get("VmPeak"), "rss_peak_bytes": values.get("VmHWM"), "resident_bytes": values.get("VmRSS")}
    if platform.system() == "Darwin":
        # rusage_info_v2: uuid[16], then the published u64 fields. The final
        # fields are child and disk accounting; resident/footprint are u64 slots 8/9 after the UUID.
        data = (ctypes.c_uint64 * 20)()
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        if lib.proc_pid_rusage(pid, 2, ctypes.byref(data)) != 0:
            return None
        return {"at_ns": at, "resident_bytes": data[8], "footprint_bytes": data[9]}
    return None


def observe(binary, preparation, directory, repo):
    directory.mkdir(parents=True, exist_ok=True)
    load = list(os.getloadavg())
    output = bytearray()
    memory = []
    pid = None
    with subprocess.Popen([str(preparation["fixture"]), str(directory), str(repo)], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env={**os.environ, "TMPDIR": str(directory)}) as child:
        deadline = time.monotonic() + 5
        while child.poll() is None:
            if time.monotonic() >= deadline:
                child.kill()
                break
            if select.select([child.stdout], [], [], .002)[0]:
                output.extend(os.read(child.stdout.fileno(), 65536))
                for line in output.splitlines():
                    if line.startswith(b"F3_PID "):
                        pid = int(line.split()[1])
            if pid is not None:
                sample = memory_sample(pid)
                if sample:
                    memory.append(sample)
        rest, stderr = child.communicate()
        output.extend(rest)
    lines = [line[10:] for line in output.splitlines() if line.startswith(b"F3_RESULT ")]
    if child.returncode or len(lines) != 1 or any(not line.startswith(b"lifecycle: ") for line in stderr.splitlines()):
        return {"status": "BLOCKED", "error": "helper observation failed", "exit": child.returncode,
                "stdout": output.decode(errors="replace"), "stderr": stderr.decode(errors="replace"), "memory_samples": memory, "load": load}
    sample = json.loads(lines[0])
    sample.setdefault("status", "OBSERVED")
    sample.update(memory_samples=memory, load=load, cwd=str(repo), clock="fixture helper identity; unchanged monotonic deadlines",
                  exit=child.returncode, stdout=output.decode(errors="replace"), stderr=stderr.decode(errors="replace"))
    if sample["status"] == "BLOCKED":
        return sample
    sample["completion_status"] = "OBSERVED" if sample.get("reason") == "Complete" else "BLOCKED"
    try:
        reader = M3B.run([str(preparation["fixture"]), "--read", str(directory), str(repo)])
        sample["previous_read"] = json.loads(reader.stdout)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sample["previous_read"] = {"status": "BLOCKED", "reason": str(error)}
    # The normal prompt is independent evidence. A failure stays missing.
    try:
        contexts = preparation.setdefault("prompt_contexts", {})
        key = str(directory)
        if key not in contexts:
            try:
                contexts[key] = M3B.prompt_context(binary, directory)
            except ValueError as error:
                contexts[key] = str(error)
        if isinstance(contexts[key], str):
            raise ValueError(contexts[key])
        command, env = contexts[key]
        # prompt_context accepts a Path executable; normalize before inspecting
        # argv, just as M3B.run does at the subprocess boundary. Keep the cached
        # context unchanged when retargeting this observation's repository.
        command = [str(word) for word in command]
        command = ["--home=" + str(repo) if word.startswith("--home=") else word for word in command]
        command[command.index("--pwd") + 1] = str(repo)
        start = time.monotonic_ns()
        prompt = M3B.run(command, env=env)
        elapsed = time.monotonic_ns() - start
        if not M3B.normal_record(prompt):
            raise ValueError("normal B1 record unavailable")
        sample["prompt_ns"] = elapsed
        sample["record_hex"] = prompt.stdout.hex()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sample["prompt_blocked"] = str(error)
    try:
        sample["stage_diagnostic"] = observe_stages(preparation, directory, repo)
    except (OSError, ValueError) as error:
        sample["stage_diagnostic"] = {"status": "BLOCKED", "reason": str(error), "stages": []}
    return sample


def rate(n, denominator):
    return {"count": n, "denominator": denominator, "rate": n / denominator if denominator else None}


def summarize(samples, rounds):
    if any(s.get("kind") == "process-model-trace" for s in samples):
        raise ValueError("a strace process-model trace is not a latency sample")
    observed = [s for s in samples if s.get("status") == "OBSERVED"]
    published = [s for s in observed if s["published"]]
    reasons = {}
    overwrites = 0
    opportunities = 0
    previous = None
    for s in observed:
        if s["published"] and s["partial"]:
            reasons[s["reason"]] = reasons.get(s["reason"], 0) + 1
        if s["published"]:
            if previous is not None and not previous["partial"] and previous["cwd"] == s["cwd"]:
                opportunities += 1
                if s["partial"] and s["completed_at_ns"] > previous["completed_at_ns"]:
                    overwrites += 1
            previous = s
    metrics = {}
    for name, (start, end) in M3B.INTERVALS.items():
        values = [s["events"][end] - s["events"][start] for s in observed
                  if s["events"].get(start) is not None and s["events"].get(end) is not None]
        metrics[name] = {"status": "OBSERVED" if len(values) == rounds else "INCOMPLETE", **(M3B.summary(values) if values else {"n": 0})}
    for name in ("prompt_ns", "admission_gc_ns"):
        values = [s[name] for s in observed if name in s]
        metrics[name] = {"status": "OBSERVED" if len(values) == rounds else "BLOCKED", **(M3B.summary(values) if values else {"n": 0})}
    for name in ("front_read_ns", "front_prefetch_ns"):
        values = [s["previous_read"][name] for s in observed if name in s.get("previous_read", {})]
        metrics[name] = {"status": "OBSERVED" if len(values) == rounds else "BLOCKED", **(M3B.summary(values) if values else {"n": 0})}
    stage_metrics = {}
    for stage in STAGES:
        rows = [r for s in samples for r in s.get("stage_diagnostic", {}).get("stages", []) if r["stage"] == stage]
        values = [r["elapsed_ns"] for r in rows]
        stage_metrics[stage] = {"status": "OBSERVED" if len(rows) == rounds else "INCOMPLETE",
                                **(M3B.summary(values) if values else {"n": 0}),
                                "deadline": rate(sum("Deadline" in r["result"] or "TimedOut" in r["result"] for r in rows), len(rows)),
                                "elapsed_over_budget": rate(sum(r["elapsed_ns"] > r["budget_ns"] for r in rows), len(rows))}
    intervals = [b["at_ns"] - a["at_ns"] for s in samples for a, b in zip(s["memory_samples"], s["memory_samples"][1:])]
    overshoot = [max(0, m.get("footprint_bytes", m.get("as_peak_bytes", 0)) - s["events"]["as_baseline"] - 33_554_432)
                 for s in observed if s["events"].get("as_baseline") is not None
                 for m in s["memory_samples"] if m.get("footprint_bytes", m.get("as_peak_bytes")) is not None]
    saturated = [s for s in observed if re.search(r"F1_FIELD \w+ count:\d+:true", s.get("stage_diagnostic", {}).get("raw", ""))]
    return {"stage_diagnostic": stage_metrics, "attempted": len(samples), "observed": len(observed), "metrics": metrics,
            "stage_a_reach": rate(sum(s["stage_a"] for s in observed), len(samples)),
            "partial": rate(sum(bool(s["partial"]) for s in published), len(published)),
            "partial_reasons": reasons, "deadline": rate(sum(s["reason"] == "Deadline" for s in observed), len(samples)),
            "complete_to_partial": rate(overwrites, opportunities), "complete_to_partial_per_round": rate(overwrites, len(samples)),
            "memory": {"samples": sum(len(s["memory_samples"]) for s in samples),
                       "sample_interval_ns": M3B.summary(intervals) if intervals else {"n": 0, "status": "BLOCKED"},
                       "sampled_overshoot_bytes": M3B.summary(overshoot) if overshoot else {"n": 0, "status": "BLOCKED"},
                       "kill_latency": {"status": "BLOCKED", "reason": "external samples do not observe watchdog signal time; see dedicated resource contract"},
                       "peaks": {key: max((m[key] for s in samples for m in s["memory_samples"] if m.get(key) is not None), default=None)
                                 for key in ("as_peak_bytes", "rss_peak_bytes", "resident_bytes", "footprint_bytes")}},
            "budget_overrun": {"deadline": rate(sum(s["reason"] == "Deadline" for s in observed), len(samples)),
                               "saturated_diagnostic": rate(len(saturated), len(samples)),
                               "counter_limits": {"status": "BLOCKED", "reason": "shipped wire does not expose the failing budget axis; Partial alone is not a counter overrun"}}}


class ProcessModelSample(TypedDict):
    spawns: dict[str, int]
    write_calls: dict[str, int]
    syscall_time_us: dict[str, int]


TRACE_LINE = re.compile(r"^(\d+)\s+(.*)$")
WRITES = ("write(", "writev(", "pwrite64(", "pwritev(", "pwritev2(")


def trace_role(path, argv):
    if Path(path).name == "bingsu-collect":
        return "collector"
    second = argv[1] if len(argv) > 1 else None
    return {"prompt": "front", "__refresh-v1": "helper"}.get(second, "other")


def parse_process_trace(text):
    """Roles from `strace -f -yy`: a process takes the role of its last exec;
    before that, of its parent. Spawns count execs per role, writes count
    write-family calls per role at the moment of the call."""
    roles, pending, parents, spawns, writes = {}, {}, {}, {}, {}
    for line in text.splitlines():
        match = TRACE_LINE.match(line)
        if not match:
            continue
        pid, call = int(match[1]), match[2]
        if call.startswith("execve("):
            exec_match = re.match(r'execve\("([^"]*)", \[((?:"[^"]*"(?:, )?)*)', call)
            if not exec_match:
                raise ValueError("unparsed execve: " + line)
            pending[pid] = trace_role(exec_match[1], re.findall(r'"([^"]*)"', exec_match[2]))
        if call.startswith("execve(") or call.startswith("<... execve resumed>"):
            if "<unfinished ...>" not in call:
                if re.search(r"\)\s+= 0$", call):
                    roles[pid] = pending.pop(pid)
                    spawns[roles[pid]] = spawns.get(roles[pid], 0) + 1
                else:
                    pending.pop(pid, None)
            continue
        child = re.search(r"^(?:clone3?|vfork|fork)\(.*\)\s+= (\d+)$|^<\.\.\. (?:clone3?|vfork|fork) resumed>.*\)\s+= (\d+)$", call)
        if child:
            parents[int(child[1] or child[2])] = pid
        if call.startswith(WRITES):
            role = roles.get(pid)
            ancestor = pid
            while role is None and ancestor in parents:
                ancestor = parents[ancestor]
                role = roles.get(ancestor)
            role = role or "unknown"
            writes[role] = writes.get(role, 0) + 1
    return spawns, writes


def parse_syscall_time(text):
    """`strace -f -c` summary: microseconds per system call, all processes."""
    times = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not re.fullmatch(r"\d+\.\d+", parts[0]) or parts[-1] == "total":
            continue
        times[parts[-1]] = round(float(parts[1]) * 1_000_000)
    if not times:
        raise ValueError("no strace -c summary")
    return times


def observe_process_model(binary: str, case: str) -> ProcessModelSample:
    """Linux only, trace runs only: the normal product prompt for `case` under
    `strace -f -yy` (process roles, spawns, writes) and then, separately,
    `strace -f -c` (system call time). Timing under strace is never a latency."""
    strace = shutil.which("strace")
    if platform.system() != "Linux" or strace is None:
        raise ValueError("process model trace needs Linux strace")
    (ROOT / "target").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="x03-trace-", dir=ROOT / "target") as scratch:
        scratch = Path(scratch)
        repo = repository(scratch, case)
        directory = scratch / "context"
        directory.mkdir(mode=0o700)
        command, env = M3B.prompt_context(str(Path(binary).resolve()), directory)
        command = [str(word) for word in command]
        command = ["--home=" + str(repo) if word.startswith("--home=") else word for word in command]
        command[command.index("--pwd") + 1] = str(repo)
        traces = {}
        for name, flags in (("yy", ["-f", "-yy", "-s", "64"]), ("count", ["-f", "-c"])):
            path = scratch / (name + ".trace")
            result = subprocess.run([strace, *flags, "-o", str(path), "--", *command], env=env,
                                    capture_output=True, timeout=60)
            if result.returncode != 0:
                raise ValueError(f"strace {name} run failed: {result.stderr.decode(errors='replace')[:2000]}")
            traces[name] = path.read_text(errors="replace")
    spawns, writes = parse_process_trace(traces["yy"])
    return ProcessModelSample(spawns=spawns, write_calls=writes, syscall_time_us=parse_syscall_time(traces["count"]))


def trace_run(binary, cases):
    value = {"schema": 1, "milestone": "M3d", "kind": "process-model-trace", "status": "OBSERVED",
             "evidence_use": "process model only; never a latency sample", "binary": str(binary), "cases": {}}
    if platform.system() != "Linux":
        return {**value, "status": "BLOCKED", "reason": "process model trace needs Linux strace"}
    for case in cases:
        try:
            value["cases"][case] = {"status": "OBSERVED", **observe_process_model(binary, case)}
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            value["cases"][case] = {"status": "BLOCKED", "reason": str(error)}
            value["status"] = "BLOCKED"
    return value


def measure_pair(base: str, candidate: str, rounds: int, *, cases=None, condition=None) -> dict:
    if rounds < 200:
        raise ValueError("M3c requires at least 200 warm rounds")
    cases = list(CASES if cases is None else cases)
    if not cases or len(set(cases)) != len(cases) or set(cases) - set(ALL_CASES):
        raise ValueError("unknown or duplicate cases")
    binaries = {"base": str(Path(base).resolve()), "candidate": str(Path(candidate).resolve())}
    preparations = {name: prepared(binary) for name, binary in binaries.items()}
    OUT.mkdir(parents=True, exist_ok=True)
    (ROOT / "target").mkdir(exist_ok=True)
    result = {"schema": 1, "milestone": "M3c", "formal_B5_B7": False, "status": "OBSERVED", "rounds": rounds,
              "host": M3B.host(), "cold_definition": "first process; filesystem caches not flushed", "cases": {},
              "variants": {name: {key: p[key] for key in ("front", "hashes", "source_hashes", "sibling_build_id", "stripped_bytes", "compiler", "product_mask")} for name, p in preparations.items()},
              "common": {"I": {"status": "BLOCKED", "reason": "import dedicated Callgrind positive Ir and call-count artifacts; never inferred from latency"},
                         "S": {"status": "BLOCKED", "reason": "import per-role Linux strace -f -yy evidence; formula-only rows remain formula-only"},
                         "L": {"stage_durations": {"basis": "separate protected release diagnostic; see per-case raw stage_diagnostic, no substitution for shipped collection"},
                               "front_previous_read": {"basis": "shared confined prompt reader; fixture clock identity; separate from normal prompt wall time"}}},
              "pending": ["M3d formal B5-B7", "whole-prompt peak RSS (separate --prompt-memory run; BLOCKED while D5 proof obligations are open)",
                          "reboot-cold", "minimum supported hosts", "memory hypothesis certification"]}
    with tempfile.TemporaryDirectory(prefix="observations-", dir=ROOT / "target") as scratch:
        scratch = Path(scratch)
        repos = repositories(scratch)
        case_seed = M3B.protocol.random.SystemRandom().randrange(2**63)
        M3B.protocol.random.Random(case_seed).shuffle(cases)
        result['case_seed'], result['case_order'] = case_seed, cases
        for case in cases:
            if case in COMMAND_CASES:
                contexts = {}
                paired = M3B.protocol.paired(binaries['base'], binaries['candidate'], rounds, condition,
                    lambda name, binary: observe_command(binary, contexts, scratch / name / case, case),
                    required_metrics=("prompt_ns",))
            else:
                repo = repos[case]
                paired = M3B.protocol.paired(binaries['base'], binaries['candidate'], rounds, condition,
                    lambda name, binary: observe(binary, preparations[name], scratch / name / case, repo),
                    required_metrics=("prompt_ns", "admission_gc_ns"))
            cold = paired.get('cold_first_process', {})
            samples = {n: paired['variants'][n]['samples'] for n in binaries}
            order = paired['order']
            if paired['status'] == 'BLOCKED':
                result['status'] = 'BLOCKED'
            row = {**paired, "cold_first_process": cold, "order": order, "variants": {}}
            for name in binaries:
                stats = (summarize_prompt if case in COMMAND_CASES else summarize)(samples[name], rounds)
                row["variants"][name] = {**paired["variants"][name], "samples": samples[name], **stats}
                if stats["observed"] != rounds or stats["metrics"]["prompt_ns"]["n"] != rounds:
                    result["status"] = "BLOCKED"
            result["cases"][case] = row
            # Crash recovery never discards already completed cases.
            M3B.protocol.write_output(OUT / "latest-partial.json", result)
    return result


def memory_run(binary: str, cases, rounds: int, shell: str, condition: dict) -> dict:
    """D5 rows: traced prompts only, never inside latency rounds. The session
    lock keeps every other measurement harness off the host meanwhile."""
    memory = module("d5_prompt_memory", ROOT / "bench/prompt_memory.py")
    value = {"schema": 1, "milestone": "M3d", "kind": "prompt-memory", "status": "OBSERVED", "metric": "rss",
             "evidence_use": "RSS rows; a row certifies only with every proof obligation proven", "binary": str(binary),
             "shell": shell, "host": M3B.host(), "condition": condition, "host_condition": M3B.protocol.observe_host(), "cases": {}}
    with open(Path(tempfile.gettempdir()) / "bingsu-measurement.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for case in cases:
            row = memory.measure_row(binary, case, rounds, shell=shell)
            value["cases"][case] = row
            if row["status"] != "OBSERVED":
                value["status"] = "BLOCKED"
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare")
    parser.add_argument("--x03-trace", metavar="BINARY", help="Linux strace process-model runs; separate from latency")
    parser.add_argument("--prompt-memory", metavar="BINARY", help="D5 whole-prompt peak RSS rows (Linux ptrace); separate from latency")
    parser.add_argument("--shell", choices=("bash", "zsh", "fish"), default="bash")
    parser.add_argument("--base")
    parser.add_argument("--candidate")
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--mode", choices=("gate", "experiment"), default="gate")
    parser.add_argument("--condition", type=json.loads)
    parser.add_argument("--admission", choices=("default", "ci-r2"), default="default",
                        help="gate admission rule; ci-r2 (U3 rule R2: in-block reference stability) only on a GitHub Actions runner without a power device")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    global OUT
    OUT = args.out.resolve().parent
    try:
        M3B.protocol.validate_output(OUT)
        # One request path, and only where it is judged: never dropped silently.
        if isinstance(args.condition, dict) and "admission" in args.condition:
            raise ValueError("admission is chosen with --admission, not --condition")
        if args.admission != "default" and (args.x03_trace or args.prompt_memory or args.prepare):
            raise ValueError("--admission applies only to a paired --base/--candidate measurement")
        if args.x03_trace:
            cases = args.cases.split(",")
            if not cases or set(cases) - set(CASES):
                raise ValueError("unknown cases")
            value = trace_run(args.x03_trace, cases)
        elif args.prompt_memory:
            cases = args.cases.split(",")
            if not cases or len(set(cases)) != len(cases) or set(cases) - set(CASES):
                raise ValueError("unknown or duplicate cases")
            value = memory_run(args.prompt_memory, cases, args.rounds, args.shell,
                               {**M3B.protocol.DEFAULT, **(args.condition or {}), "mode": args.mode})
        else:
            value = prepare(args.prepare) if args.prepare else measure_pair(args.base, args.candidate, args.rounds, cases=args.cases.split(","),
            condition={**M3B.protocol.DEFAULT, **(args.condition or {}), "mode": args.mode, "admission": args.admission})
        code = 2 if value.get("status") == "BLOCKED" else 0
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        value = {"milestone": "M3c", "formal_B5_B7": False, "status": "BLOCKED", "reason": str(error)}
        code = 2
    M3B.protocol.write_output(args.out, value)
    if code:
        # The JSON keeps the whole reason; the job log shows why without opening it.
        print(f"BLOCKED: {str(value.get('reason', value.get('status')))[:4000]}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
