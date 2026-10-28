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
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(tempfile.gettempdir()) / "bingsu-measurements"
CASES = ("no-git", "git-clean", "git-dirty", "tracked-19000", "budget-bound")
STAGES = ("A", "PathFacts", "B", "C", "D")

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

M3B = module("f3_m3b", ROOT / "bench/collector-product.py")


def manifest_path(binary):
    return Path(binary).resolve().with_name("git-product.json")


def sources(source):
    return {**M3B.preparation_sources(source), "f3_harness": M3B.digest(__file__), "stage_harness": M3B.digest(ROOT / "scripts/prepare_git_corpus.py")}


def prepared(binary):
    binary = Path(binary).resolve()
    value = json.loads(manifest_path(binary).read_text())
    for name, path in (("front", binary), ("collector", binary.with_name("bingsu-collect")),
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
 let broker=commands::refresh::refresh_broker(request,&mut Fixed(now),&mut |context,display,clock| {
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


def prepare(binary):
    binary = Path(binary).resolve()
    source = M3B.build_context(binary)
    if binary.parent.name != "release":
        raise ValueError("release sibling pair required")
    directory = OUT / "prepared" / M3B.digest(binary)[:16]
    directory.mkdir(parents=True, exist_ok=True)
    command = ["cargo", "build", "--locked", "-j", "2", "--release", "-p", "bingsu", "-p", "bingsu-collect", "--message-format=json"]
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
    process.write_text(M3B.replace_required(process.read_text(), "    fn attach(pid: libc::pid_t, expires_ns: u64) -> io::Result<Self> {",
        '    fn attach(pid: libc::pid_t, expires_ns: u64) -> io::Result<Self> {\n        println!("F3_PID {pid}");'))
    modules = [f'#[path={json.dumps(str(mod))}] mod commands;']
    for name in ("prompt", "prompt_io", "prompt_read", "prompt_spawn"):
        path = source / "crates/bingsu/src" / (name + ".rs")
        if name == "prompt_read":
            reader = path.read_text()
            measurement = M3B.READ_MEASUREMENT
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
    rust.write_text(HELPER.replace("@MODULES@", "\n".join(modules)).replace("@COLLECTOR@", json.dumps(str(binary.with_name("bingsu-collect")))))
    fixture = directory / "git-product"
    command = ["rustc", "--edition=2024", "--cfg", "test", "-O", "-C", "lto=fat", "-C", "embed-bitcode=yes", str(rust), "-o", str(fixture), "-L", f"dependency={binary.parent / 'deps'}"]
    for name in ("bingsu_core", "bingsu_identity", "libc"):
        command += ["--extern", f"{name}={deps[name]}"]
    if cross:
        command += ["--target", triple]
        linker = os.environ.get("CARGO_TARGET_" + triple.upper().replace("-", "_") + "_LINKER")
        if linker:
            command += ["-C", "linker=" + linker]
    M3B.run(command, env={**os.environ, "CARGO_MANIFEST_DIR": str(source / "crates/bingsu"), "CARGO_PKG_VERSION": "0.0.0"}, timeout=300)
    audit = module("f3_symbols", ROOT / "scripts/check_collector_symbols.py")
    identity = audit.build_id(binary, 2)
    if identity != audit.build_id(binary.with_name("bingsu-collect"), 1):
        raise ValueError("sibling build mismatch")
    sizes = {}
    for name, path in (("front", binary), ("collector", binary.with_name("bingsu-collect"))):
        stripped = directory / (name + "-stripped")
        M3B.run(["strip", "-o", str(stripped), str(path)])
        sizes[name] = stripped.stat().st_size
    sizes["combined"] = sum(sizes.values())
    diagnostic = prepare_diagnostic(source, directory, binary, deps, cross, triple)
    value = {"diagnostic": str(diagnostic), "source": str(source), "profile": "release", "product_mask": 10, "fixture": str(fixture),
             "hashes": {"front": M3B.digest(binary), "collector": M3B.digest(binary.with_name("bingsu-collect")), "fixture": M3B.digest(fixture), "diagnostic": M3B.digest(diagnostic)},
             "source_hashes": sources(source), "sibling_build_id": identity.hex(), "stripped_bytes": sizes,
             "compiler": M3B.run(["rustc", "-vV"]).stdout.decode(),
             "probe_sources": {"stage_fixture": M3B.digest(ROOT / "scripts/prepare_git_corpus.py"), "reader_fixture": M3B.digest(ROOT / "bench/collector-product.py")}}
    manifest_path(binary).write_text(json.dumps(value, indent=2) + "\n")
    return value


def prepare_diagnostic(source, directory, binary, deps, cross, triple):
    """Separate stage-local observations; never substituted for shipped samples."""
    corpus = module("f3_stage_source", ROOT / "scripts/prepare_git_corpus.py")
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
        stages = [{"stage": {5: "A", 3: "PathFacts", 28: "B", 8: "C", 4: "D"}[int(ms)],
                   "budget_ns": int(ms) * 1_000_000, "elapsed_ns": int(ns), "result": result}
                  for ms, ns, result in re.findall(r"(?m)^F3_STAGE (\d+) (\d+) (.*)$", text)]
        status = "OBSERVED" if child.returncode == 0 and "F1_RESULT " in text and "AllStages(" in text else "BLOCKED"
        return {"status": status, "exit": child.returncode, "stages": stages, "raw": text,
                "basis": "separate protected release fixture, unchanged product deadlines; not shipped timing"}
    finally:
        for fd in [*copies, *originals, write_fd]:
            os.close(fd)


def repositories(directory):
    corpus = module("f3_corpus", ROOT / "scripts/prepare_git_corpus.py")
    result = {}
    for name in CASES:
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
        result[name] = path
    return result


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


def measure_pair(base: str, candidate: str, rounds: int, *, cases=None, condition=None) -> dict:
    if rounds < 200:
        raise ValueError("M3c requires at least 200 warm rounds")
    cases = list(CASES if cases is None else cases)
    if not cases or len(set(cases)) != len(cases) or set(cases) - set(CASES):
        raise ValueError("unknown or duplicate cases")
    binaries = {"base": str(Path(base).resolve()), "candidate": str(Path(candidate).resolve())}
    preparations = {name: prepared(binary) for name, binary in binaries.items()}
    OUT.mkdir(parents=True, exist_ok=True)
    (ROOT / "target").mkdir(exist_ok=True)
    result = {"schema": 1, "milestone": "M3c", "formal_B5_B7": False, "status": "OBSERVED", "rounds": rounds,
              "host": M3B.host(), "cold_definition": "first process; filesystem caches not flushed", "cases": {},
              "variants": {name: {key: p[key] for key in ("hashes", "source_hashes", "sibling_build_id", "stripped_bytes", "compiler", "product_mask")} for name, p in preparations.items()},
              "common": {"I": {"status": "BLOCKED", "reason": "import dedicated Callgrind positive Ir and call-count artifacts; never inferred from latency"},
                         "S": {"status": "BLOCKED", "reason": "import per-role Linux strace -f -yy evidence; formula-only rows remain formula-only"},
                         "L": {"stage_durations": {"basis": "separate protected release diagnostic; see per-case raw stage_diagnostic, no substitution for shipped collection"},
                               "front_previous_read": {"basis": "shared confined prompt reader; fixture clock identity; separate from normal prompt wall time"}}},
              "pending": ["M3d formal B5-B7", "whole-prompt peak RSS", "reboot-cold", "minimum supported hosts", "memory hypothesis certification"]}
    with tempfile.TemporaryDirectory(prefix="observations-", dir=ROOT / "target") as scratch:
        scratch = Path(scratch)
        repos = repositories(scratch)
        case_seed = M3B.protocol.random.SystemRandom().randrange(2**63)
        M3B.protocol.random.Random(case_seed).shuffle(cases)
        result['case_seed'], result['case_order'] = case_seed, cases
        for case in cases:
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
                stats = summarize(samples[name], rounds)
                row["variants"][name] = {**paired["variants"][name], "samples": samples[name], **stats}
                if stats["observed"] != rounds or stats["metrics"]["prompt_ns"]["n"] != rounds:
                    result["status"] = "BLOCKED"
            result["cases"][case] = row
            # Crash recovery never discards already completed cases.
            M3B.protocol.write_output(OUT / "latest-partial.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare")
    parser.add_argument("--base")
    parser.add_argument("--candidate")
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--mode", choices=("gate", "experiment"), default="gate")
    parser.add_argument("--condition", type=json.loads)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    global OUT
    OUT = args.out.resolve().parent
    try:
        M3B.protocol.validate_output(OUT)
        value = prepare(args.prepare) if args.prepare else measure_pair(args.base, args.candidate, args.rounds, cases=args.cases.split(","),
            condition={**M3B.protocol.DEFAULT, **(args.condition or {}), "mode": args.mode})
        code = 2 if value.get("status") == "BLOCKED" else 0
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        value = {"milestone": "M3c", "formal_B5_B7": False, "status": "BLOCKED", "reason": str(error)}
        code = 2
    M3B.protocol.write_output(args.out, value)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
