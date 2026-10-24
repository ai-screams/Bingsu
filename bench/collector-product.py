#!/usr/bin/env python3
"""M3b observations, not M3d B5--B7 certification.

--prepare builds test-only main-thread fixtures on the host. Measurement and
shell tests never build. Each sibling pair has a hash-bound preparation manifest.
Absent evidence is BLOCKED (exit 2), never a passing skip. Cold here means the
first process in this run, not a claim that OS caches were flushed.

Run from the source checkout, keeping CARGO_TARGET_DIR unchanged if configured:
  cargo build -j 2 -p bingsu -p bingsu-collect
  python3 bench/collector-product.py --prepare <target-dir>/debug/bingsu
  BINGSU_BIN=<target-dir>/debug/bingsu python3 -m pytest tests/shell/test_collector_security.py
The default target-dir is target. The executable path must pass the existing
trusted-ancestor checks; a world-writable /tmp ancestor is not an install root.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ("verify_start", "verify_end", "spawn_enter", "spawn_return", "ready",
          "request_sent", "completed", "response_renamed", "lock_acquired", "lock_closed")
INTERVALS = {
    "verification_to_spawn_ns": ("verify_start", "spawn_enter"),
    "verified_to_spawn_ns": ("verify_end", "spawn_enter"),
    "spawn_call_ns": ("spawn_enter", "spawn_return"),
    "spawn_to_ready_ns": ("spawn_enter", "ready"),
    "collection_ns": ("request_sent", "completed"),
    "publication_ns": ("completed", "response_renamed"),
    "lock_hold_ns": ("lock_acquired", "lock_closed"),
}
REQUIRED = tuple(INTERVALS) + ("front_read_ns", "front_prefetch_ns", "filter_install_ns",
                               "collector_peak_rss_bytes", "collector_as_bytes", "prompt_ns",
                               "m1_stub_exit_ns", "m1_stub_limits_ns", "m1_stub_sandbox_ns",
                               "product_mask0_verify_ns")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, **kwargs):
    result = subprocess.run([str(x) for x in command], capture_output=True, timeout=kwargs.pop("timeout", 30), **kwargs)
    if result.returncode != 0:
        raise ValueError(f"{Path(command[0]).name}: exit {result.returncode}: {(result.stderr + result.stdout).decode(errors='replace')[:8000]}")
    return result


def manifest_path(binary):
    return Path(binary).resolve().with_name("collector-product.json")


def preparation_sources(source):
    # Bind the copied command modules, reader, native contracts, worker and M1
    # stub as well as the generator and build inputs. Membership is checked too.
    files = [source / name for name in ("Cargo.toml", "Cargo.lock", "bench/collector-product.py")]
    for crate in ("bingsu", "bingsu-core", "bingsu-collect", "bingsu-bench", "bingsu-identity"):
        directory = source / "crates" / crate
        files.append(directory / "Cargo.toml")
        files.extend(directory.rglob("*.rs"))
    return {str(p.relative_to(source)): digest(p) for p in sorted(files)}


def prepared(binary):
    binary = Path(binary).resolve()
    path = manifest_path(binary)
    if not path.is_file():
        raise ValueError("host preparation manifest missing; run --prepare for this sibling pair")
    result = json.loads(path.read_text())
    for key, file in (("front", binary), ("collector", binary.with_name("bingsu-collect")),
                      ("fixture", Path(result["fixture"])), ("stub", Path(result["stub"]))):
        if not file.is_file() or result["hashes"][key] != digest(file):
            raise ValueError(f"stale or missing prepared {key}")
    source = next((p for p in binary.parents if (p / "Cargo.toml").is_file()), ROOT)
    if not result.get("source_hashes") or result["source_hashes"] != preparation_sources(source):
        raise ValueError("stale prepared source_hashes; run --prepare after the last source change")
    return result


def summary(values):
    if not values or any(not isinstance(n, (int, float)) or not math.isfinite(n) or n < 0 for n in values):
        raise ValueError("missing/non-finite/negative observations")
    ordered = sorted(values)
    return {"n": len(values), "p50": statistics.median(ordered),
            "p95": ordered[math.ceil(len(ordered) * .95) - 1],
            "variance": statistics.pvariance(values), "min": ordered[0], "max": ordered[-1]}


def validate_sample(sample, *, require_prompt=True):
    stamps = sample["events"]
    for name in EVENTS:
        if not isinstance(stamps.get(name), int) or stamps[name] <= 0:
            raise ValueError(f"missing lifecycle event: {name}")
    chain = ("verify_start", "verify_end", "spawn_enter", "spawn_return", "ready", "request_sent", "completed", "response_renamed", "lock_closed")
    if any(stamps[a] > stamps[b] for a, b in zip(chain, chain[1:])):
        raise ValueError("helper lifecycle event ordering")
    if not stamps["verify_end"] <= stamps["lock_acquired"] <= stamps["spawn_enter"]:
        raise ValueError("collection lock ordering")
    if not stamps["request_sent"] < sample["request_deadline"] or not stamps["completed"] < sample["request_deadline"]:
        raise ValueError("collection exceeded its absolute deadline")
    if sample.get("reason") != "Complete" or not sample.get("published") or not sample.get("reaped"):
        raise ValueError("fixture did not complete, publish and reap")
    for name, (start, end) in INTERVALS.items():
        sample[name] = stamps[end] - stamps[start]
    for name in REQUIRED:
        if name == "prompt_ns" and not require_prompt:
            continue
        if name not in sample:
            raise ValueError(f"missing metric: {name}")
        summary([sample[name]])
    if sample["collector_as_bytes"] <= 0 or sample["collector_peak_rss_bytes"] <= 0:
        raise ValueError("missing actual resource observations")
    return sample


def normal_record(result):
    return (result.returncode == 0 and result.stderr == b"" and result.stdout.startswith(b"B1\x1f")
            and result.stdout.endswith(b"ok:none\x1e") and result.stdout.count(b"\x1f") == 9)


def prompt_context(binary, directory):
    """Prime a real mask0 product snapshot outside the measured interval."""
    env = {"PATH": os.environ["PATH"], "LC_ALL": "C.UTF-8"}
    for key, name in (("XDG_CONFIG_HOME", "product-config"), ("XDG_STATE_HOME", "product-state"),
                      ("XDG_RUNTIME_DIR", "product-runtime"), ("XDG_CACHE_HOME", "product-cache")):
        path = Path(directory) / name
        path.mkdir(mode=0o700, exist_ok=True)
        env[key] = str(path)
    config = Path(env["XDG_CONFIG_HOME"]) / "bingsu"
    config.mkdir(mode=0o700, exist_ok=True)
    (config / "config.toml").write_text("icons = 'ascii'\n")
    init = run([binary, "init", "bash"], env=env)
    cold_notice = (b"bingsu: reading your settings did not finish in time; the prompt starts with "
                   b"the built-in look and takes your settings when they are ready\n")
    if init.stderr.replace(cold_notice, b""):
        raise ValueError("normal product init refused its pinned roots: " + init.stderr.decode(errors="replace"))
    roots = []
    for line in init.stdout.decode().splitlines():
        if "--runtime-root=" in line and "--config-root=" in line:
            roots = [word for word in shlex.split(line)
                     if word.startswith(("--runtime-root=", "--runtime-groups=", "--config-root=", "--config-root-written=",
                                         "--state-root=", "--log-root=", "--home=", "--collector-exe="))
                     or word == "--config-root-shape-only"]
            break
    if not roots:
        raise ValueError("normal product init did not pin roots")
    command = [binary, "prompt", "--ctx", "1", "--record", "B1", "--shell", "bash", "--width", "80",
               "--pwd", str(directory), "--log-level=off", *roots]
    for _ in range(16):
        result = run(command, env=env)
        if normal_record(result):
            return command, env
    raise ValueError("normal mask0 product snapshot unavailable (clock/trust/host prerequisite)")


def observe(binary, preparation, directory):
    # The helper fixture uses the common runtime/context/display verification,
    # supervisor, worker protection/exchange, and atomic store implementation.
    # The separate reader uses C3's actual confined read continuation on main.
    fixture = preparation["fixture"]
    sample = json.loads(run([fixture, "--helper", directory], env={**os.environ, "TMPDIR": str(directory)}).stdout)
    reader = json.loads(run([fixture, "--read", directory], env={**os.environ, "TMPDIR": str(directory)}).stdout)
    sample.update(reader)
    if "prompt_context" not in preparation and "prompt_context_error" not in preparation:
        try:
            preparation["prompt_context"] = prompt_context(binary, directory)
        except ValueError as error:
            preparation["prompt_context_error"] = str(error)
    if "prompt_context" in preparation:
        command, env = preparation["prompt_context"]
        start = time.monotonic_ns()
        prompt = run(command, env=env)
        sample["prompt_ns"] = time.monotonic_ns() - start
        if not normal_record(prompt):
            sample.pop("prompt_ns")
            sample["blocked"] = {"prompt_ns": "normal mask0 prompt did not emit a silent complete B1 record"}
    else:
        sample["blocked"] = {"prompt_ns": preparation["prompt_context_error"]}
    zero = json.loads(run([fixture, "--helper-product", directory], env={**os.environ, "TMPDIR": str(directory)}).stdout)
    if zero["spawn_count"] != 0 or zero["events"]["spawn_enter"] is not None:
        raise ValueError("product mask0 spawned a collector")
    sample["product_mask0_verify_ns"] = zero["events"]["verify_end"] - zero["events"]["verify_start"]
    sample["product_zero"] = zero
    sample["m1_stub_sandbox_ns"] = 0
    for mode in (("exit", "limits", "sandbox") if platform.system() == "Linux" else ("exit", "limits")):
        at = time.monotonic_ns()
        stub = run([preparation["stub"], "--mode", mode], env={})
        sample[f"m1_stub_{mode}_ns"] = time.monotonic_ns() - at
        if stub.stdout != (b"" if mode == "exit" else b"R") or stub.stderr:
            raise ValueError("M1 stub readiness evidence missing")
    return validate_sample(sample, require_prompt="prompt_ns" in sample)


def parse_watchdog_evidence(stdout):
    if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in stdout:
        raise ValueError("macOS watchdog contract did not actually run")
    evidence = {}
    for label in ("spawn-to-termination us", "footprint overshoot bytes", "completed sample interval us", "sample-to-kill-request us"):
        match = re.search(re.escape(label) + r": count=(\d+) p50=(\d+) p95=(\d+) max=(\d+)", stdout)
        if not match or int(match[1]) < 200:
            raise ValueError("missing/insufficient macOS watchdog observations: " + label)
        evidence[label] = dict(zip(("n", "p50", "p95", "max"), map(int, match.groups())))
    return evidence


def watchdog_evidence(preparation):
    if platform.system() != "Darwin":
        return {"status": "not applicable", "basis": "Linux uses enforced RLIMIT_AS"}
    binary = preparation["contracts"]["collector_lifecycle"]
    if digest(binary) != preparation["contract_hashes"]["collector_lifecycle"]:
        raise ValueError("stale watchdog contract binary")
    result = run([binary, "--exact", "macos_first_completed_overlimit_sample_terminates", "--nocapture", "--test-threads=1"], timeout=90)
    stdout = result.stdout.decode()
    return {"status": "PASS", "metrics": parse_watchdog_evidence(stdout), "stdout": stdout}


def host():
    # A caller may supply a public revision label; binary/source hashes remain
    # authoritative. Never read or mutate repository metadata here.
    power = run(["pmset", "-g", "batt"]).stdout.decode().splitlines()[0] if platform.system() == "Darwin" else "not observed"
    return {"os": platform.system(), "kernel": platform.release(), "arch": platform.machine(),
            "host": platform.node(), "libc": " ".join(platform.libc_ver()) or "libSystem",
            "load": list(os.getloadavg()), "power": power,
            "revision": os.environ.get("BINGSU_MEASUREMENT_REVISION", "unrecorded"),
            "observed_at": datetime.now(timezone.utc).isoformat(), "cpu_count": os.cpu_count()}


def measure_pair(base: str, candidate: str, rounds: int) -> dict:
    if rounds < 200:
        raise ValueError("M3b requires at least 200 warm observations per binary")
    binaries = {"base": str(Path(base).resolve()), "candidate": str(Path(candidate).resolve())}
    preparations = {name: prepared(binary) for name, binary in binaries.items()}
    samples = {name: [] for name in binaries}
    cold, order = {}, []
    with tempfile.TemporaryDirectory(prefix="collector-product-", dir=ROOT / "target") as temp:
        for name, binary in binaries.items():
            directory = Path(temp) / name
            directory.mkdir(mode=0o700)
            cold[name] = observe(binary, preparations[name], directory)
        for i in range(rounds):
            for name in (("base", "candidate") if i % 2 == 0 else ("candidate", "base")):
                order.append(name)
                samples[name].append(observe(binaries[name], preparations[name], Path(temp) / name))
    result = {"comparison": "same-binary-control" if preparations["base"]["hashes"] == preparations["candidate"]["hashes"] else "base-candidate",
              "schema": 1, "milestone": "M3b", "formal_B5_B7": False, "status": "PASS",
              "cold_definition": "first process only; OS caches not flushed; reboot-cold pending",
              "host": host(), "rounds": rounds, "order": order, "cold_first_process": cold,
              "variants": {}, "missing": [], "pending": ["M3c/M3d git 19000-file RSS", "M3d formal B5-B7", "reboot-cold", "whole-prompt peak RSS"]}
    for name in binaries:
        result["variants"][name] = {"hashes": preparations[name]["hashes"],
                                    "policy": preparations[name]["policy"],
                                    "source_hashes": preparations[name].get("source_hashes", {}),
                                    "revision": os.environ.get("BINGSU_" + name.upper() + "_REVISION", "uncommitted-worktree"),
                                    "sibling_build_id": preparations[name].get("sibling_build_id"),
                                    "compiler": preparations[name].get("compiler", "unrecorded"),
                                    "samples": samples[name],
                                    "metrics": {},
                                    "stripped_bytes": preparations[name]["stripped_bytes"]}
        for metric in REQUIRED:
            values = [s[metric] for s in samples[name] if metric in s]
            if len(values) != rounds:
                result["missing"].append(name + "." + metric)
                result["status"] = "BLOCKED"
                result["variants"][name]["metrics"][metric] = {"n": len(values), "status": "BLOCKED",
                    "reason": next((s.get("blocked", {}).get(metric) for s in samples[name] if metric not in s), "missing observation")}
            else:
                result["variants"][name]["metrics"][metric] = summary(values)
        try:
            result["variants"][name]["memory_watchdog"] = watchdog_evidence(preparations[name])
        except ValueError as error:
            result["variants"][name]["memory_watchdog"] = {"status": "BLOCKED", "reason": str(error)}
            result["missing"].append(name + ".memory_watchdog")
            result["status"] = "BLOCKED"
    limit = 1_000_000 if platform.system() == "Linux" else 2_000_000
    result["hypotheses"] = {name: {"ready_p50_within_hypothesis": v["metrics"]["spawn_to_ready_ns"]["p50"] <= limit,
                                   "prompt_p50_within_10ms": (v["metrics"]["prompt_ns"]["p50"] <= 10_000_000) if v["metrics"]["prompt_ns"]["n"] == rounds else None,
                                   "prompt_p95_within_15ms": (v["metrics"]["prompt_ns"]["p95"] <= 15_000_000) if v["metrics"]["prompt_ns"]["n"] == rounds else None}
                            for name, v in result["variants"].items()}
    return result


# Generated into the build directory only. All traced roles enter on main;
# the product never acquires a fixture switch. The shared worker uses write(2).
HARNESS = r'''
#![allow(dead_code, unused_imports)]
@MODULES@
pub use bingsu_identity::build_id;
const PRODUCT_COLLECTOR:&str=@COLLECTOR@;
use bingsu_core::{collection::{self, wire::{BuildId,EndReason}}, snapshot::{self,Clock,ClockSource}, envelope::Envelope};
use commands::{collector_process as process, collector_supervisor::CollectorJob, collection_store::CollectionStore};
use std::{fs::{self,File},ffi::OsStr,os::unix::{ffi::OsStrExt,fs::{PermissionsExt,MetadataExt}},path::{Path,PathBuf},time::Instant};
const SEGMENTS: [bingsu_core::field::SegmentDecl;32] = {
 let mut segments=[const{bingsu_core::field::SegmentDecl{id:"fixture",role:"fg",fields:&[]}};32];
 const NAMES:[&str;31]=["a00","a01","a02","a03","a04","a05","a06","a07","a08","a09","a10","a11","a12","a13","a14","a15","a16","a17","a18","a19","a20","a21","a22","a23","a24","a25","a26","a27","a28","a29","a30"];
 let mut i=0;while i<31{segments[i].id=NAMES[i];i+=1;}segments
};
struct Fixed(Clock);
impl ClockSource for Fixed { fn observe(&mut self)->Result<Clock,snapshot::ClockError>{Ok(self.0)} }
fn stamp()->u64 {process::now_ns().unwrap()}
fn print_sample(report: commands::collector_supervisor::SupervisionReport, filter:u64, rss:u64, address:u64) {
    let t=report.lifecycle;
    println!("{{\"events\":{{\"verify_start\":{},\"verify_end\":{},\"spawn_enter\":{},\"spawn_return\":{},\"ready\":{},\"request_sent\":{},\"completed\":{},\"response_renamed\":{},\"lock_acquired\":{},\"lock_closed\":{}}},\"request_deadline\":{},\"landlock_abi\":{},\"as_baseline\":{},\"reason\":\"{:?}\",\"published\":{},\"reaped\":{},\"filter_install_ns\":{},\"collector_peak_rss_bytes\":{},\"collector_as_bytes\":{}}}",
      t.verify_start.unwrap(),t.verify_end.unwrap(),t.spawn_enter.unwrap(),t.spawn_return.unwrap(),t.ready.unwrap(),t.request_sent.unwrap(),t.completed.unwrap(),t.response_renamed.unwrap(),t.lock_acquired.unwrap(),t.lock_closed.unwrap(),t.request_deadline.unwrap(),t.landlock_abi.unwrap(),t.as_baseline.unwrap(),report.reason,report.published,report.reaped,filter,rss,address);
}
fn helper(base:&Path,mode:&str) {
    let _guard=commands::sys::test_inherited_fd_lock();
    for name in ["runtime","config","state","home"] {let p=base.join(name);fs::create_dir_all(&p).unwrap();fs::set_permissions(p,fs::Permissions::from_mode(0o700)).unwrap();}
    fs::write(base.join("config/config.toml"),"icons = 'ascii'\n").unwrap();
    let now=commands::collector_supervisor::fixture_clock().unwrap();
    let meta=fs::metadata(base.join("runtime")).unwrap();
    let request=commands::refresh::RefreshRequest {
      runtime:commands::runtime_root::Pinned{path:base.join("runtime"),dev:meta.dev(),ino:meta.ino()},
      config_written:base.join("config"),config_canonical:base.join("config"),config_root_shape_only:false,
      state_root:base.join("state"),home:base.join("home"),me:commands::sys::current_uid(),user:commands::sys::passwd_entry(commands::sys::current_uid()).unwrap().name,version:[0,0,0],build:Some([1;40]),process_started:now,
    };
    // Prime once; this is setup, outside the measured validation interval.
    assert!(matches!(commands::refresh::refresh(request.clone(),&mut Fixed(now)),commands::refresh::RefreshResult::Published{..}|commands::refresh::RefreshResult::Revalidated{..}));
    let envelope=Envelope {config_root:Some(request.config_canonical.as_os_str().as_bytes().to_vec()),state_root:Some(request.state_root.as_os_str().as_bytes().to_vec()),pwd:Some(b"/repo".to_vec()),width:80,..Envelope::default()};
    let mut groups=commands::group_policy::SystemGroups::new(&request.user);
    let probe=std::sync::Arc::new(std::sync::Mutex::new(String::new())); let observed_probe=probe.clone();
    let metrics=std::sync::Arc::new(std::sync::Mutex::new(None)); let observed=metrics.clone();
    let watchdog=commands::helper_limits::start(Instant::now()).unwrap();
    let mut verification=commands::helper::Verification::start();
    let start=verification.start.unwrap(); let mut verified=None; let mut handle=None;
    let result=commands::refresh::refresh_broker(request,&mut Fixed(now),&mut |context,display,clock| {
       verification.verified();let end=verification.end.unwrap();verified=Some(end);
       if mode=="--product-zero" {
          assert!(commands::helper::selected_request(&collection::selection::PRODUCT,&envelope,display,clock)?.is_none());
          commands::helper_limits::install(&watchdog)?;commands::helper_filter::install(None)?;return Ok(());
       }
       let (config,id)=display.unwrap(); let mut config=config.clone();
       config.bands.clear(); config.band_order.clear(); config.variants=vec![bingsu_core::template::compile::compile("{fixture}",&SEGMENTS).unwrap()];config.collect_mask=1<<31;
       let catalog=collection::selection::Catalog {segments:&SEGMENTS,workers:1<<31};
       let mut selected=commands::helper::selected_request(&catalog,&envelope,Some((&config,id)),clock)?.unwrap();
       selected.binding.build_id=BuildId(collection::cwd_hash::sha256(&[build_id().0.as_slice(),b"test-worker"].concat()));
       // Include the actual sibling pin and pre-spawn revalidation in the
       // measured interval; only the executable/catalog used for collection is
       // test-only. Product mask0 correctly skips this entire branch.
       let pin=commands::collector::PinnedCollector::verify(OsStr::new(PRODUCT_COLLECTOR),commands::sys::current_uid(),&mut groups)?;
       let shipped=mode=="--shipped-worker";
       if shipped {selected.binding.build_id=build_id();selected.binding.mask=0;}
       let segments=if shipped {collection::selection::PRODUCT.segments}else{&SEGMENTS};
       let mut store=CollectionStore::fixture(context,&selected.binding,clock,segments,None)?;
       let lock=store.worker_lock()?;
       let _=pin.executable()?;
       let executable=if shipped {std::path::PathBuf::from(PRODUCT_COLLECTOR)}else{std::env::current_exe()?};
       let verb=if shipped {"__collect-v1"}else{mode};
       let job=verification.attach(CollectorJob::fixture(executable.as_os_str(),OsStr::new(verb),selected,lock,&watchdog,segments)?,&store);
       let observed=observed.clone();
       let observed_probe=observed_probe.clone();
       let trace_publication=mode=="--security-worker";
       let failure_case=mode!="--worker";
       handle=Some(job.start(Box::new(move |value| {
          if shipped {return store.publish(&value);}
          let text=value.updates[0].value.as_ref().unwrap().text();
          if trace_publication {
             let begin=b"D2-PUBLICATION-BEGIN\n";
             unsafe{libc::write(1,begin.as_ptr().cast(),begin.len());}
             let result=store.publish(&value);
             let end=b"D2-PUBLICATION-END\n";
             unsafe{libc::write(1,end.as_ptr().cast(),end.len());}
             return result;
          }
          if failure_case {
             *observed_probe.lock().unwrap()=text.to_owned();
             return store.publish(&value);
          }
          let v:Vec<u64>=text.split(',').map(|v|v.parse().unwrap()).collect();
          *observed.lock().unwrap()=Some((v[0],v[1],v[2]));
          store.publish(&value)
       }))?);
       commands::helper_limits::install(&watchdog)?;
       commands::helper_filter::install(handle.as_ref().unwrap().child_pidfd())?;
       handle.as_ref().unwrap().confirm_confinement()?;
       Ok(())
    });
    assert!(matches!(result,commands::refresh::RefreshResult::Published{..}|commands::refresh::RefreshResult::Revalidated{..}));
    if mode=="--product-zero" {
       assert!(handle.is_none());
       println!("{{\"spawn_count\":0,\"events\":{{\"verify_start\":{},\"verify_end\":{},\"spawn_enter\":null}}}}",start,verified.unwrap());
       return;
    }
    let report=handle.unwrap().finish();
    if mode!="--worker" {
       let probe=probe.lock().unwrap();
       println!("{{\"reason\":\"{:?}\",\"published\":{},\"reaped\":{},\"partial_values\":{},\"probe\":\"{}\"}}",report.reason,report.published,report.reaped,usize::from(!probe.is_empty()),*probe);
       return;
    }
    let metrics=metrics.lock().unwrap().take().unwrap();
    print_sample(report,metrics.0,metrics.1,metrics.2);
}
static WORKER_FILTER_NS:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
fn worker_metrics()->String {
    #[cfg(target_os="linux")]
    let (rss,as_bytes)={
       let status=fs::read_to_string("/proc/self/status").unwrap();
       let value=|key:&str|status.lines().find(|l|l.starts_with(key)).unwrap().split_whitespace().nth(1).unwrap().parse::<u64>().unwrap()*1024;
       (value("VmHWM:"),value("VmPeak:"))
    };
    #[cfg(target_os="macos")]
    let (rss,as_bytes)={
       let mut usage:libc::rusage=unsafe{std::mem::zeroed()};
       assert_eq!(unsafe{libc::getrusage(libc::RUSAGE_SELF,&mut usage)},0);
       // mach task virtual size is diagnostic only; no AS enforcement claim.
       let mut info:libc::mach_task_basic_info=unsafe{std::mem::zeroed()};
       let mut count=libc::MACH_TASK_BASIC_INFO_COUNT;
       assert_eq!(unsafe{libc::task_info(libc::mach_task_self(),libc::MACH_TASK_BASIC_INFO,(&mut info as *mut libc::mach_task_basic_info).cast(),&mut count)},libc::KERN_SUCCESS);
       (usage.ru_maxrss as u64,info.virtual_size)
    };
    format!("{},{},{}",WORKER_FILTER_NS.load(std::sync::atomic::Ordering::Relaxed),rss,as_bytes)
}
static FAILURE:std::sync::atomic::AtomicU8=std::sync::atomic::AtomicU8::new(0);
fn fail_after_update(fds:&mut sys::WorkerFds,buffer:&mut [u8;collection::wire::FRAME_MAX],build_id:BuildId)->std::io::Result<()> {
    use collection::wire::{self,Frame,Kind,M3B_REQUEST_ID};
    let mode=FAILURE.load(std::sync::atomic::Ordering::Relaxed);
    if mode==0{return Ok(());}
    if mode==5 {fds.write_all(b"malformed frame after valid Update")?;return Err(std::io::Error::other("malformed"));}
    probe_limit(mode);
    // A validated second Update is emitted only after the mode's probe passes.
    let text=match mode{1=>"probe-cpu-pass",2=>"probe-as-pass",3=>"probe-nofile-pass",4=>"probe-exec-pass",_=>unreachable!()};
    let mut payload=vec![31,0,1];payload.extend((text.len() as u32).to_le_bytes());payload.extend(text.as_bytes());payload.extend(0u16.to_le_bytes());payload.push(0);
    let n=wire::encode_frame(Frame{kind:Kind::Update,build_id,request_id:M3B_REQUEST_ID,payload:&payload},buffer).unwrap();
    fds.write_all(&buffer[..n])?;
    if mode==1 {loop {std::hint::black_box(17u64.wrapping_mul(11));}}
    Err(std::io::Error::other("controlled collector failure after verified probe"))
}
fn probe_limit(mode:u8) {
    unsafe {
       let mut limit:libc::rlimit=std::mem::zeroed();
       let resource=if mode==1{libc::RLIMIT_CPU}else{libc::RLIMIT_NOFILE};
       assert_eq!(libc::getrlimit(resource,&mut limit),0);
       assert_eq!(limit.rlim_cur,if mode==1{1}else{64});
       assert_eq!(limit.rlim_max,if mode==1{1}else{64});

       #[cfg(target_os="linux")]
       if mode==2 {
          let memory=libc::mmap(std::ptr::null_mut(),(limits::MEMORY_ALLOWANCE*2) as usize,libc::PROT_READ|libc::PROT_WRITE,libc::MAP_PRIVATE|libc::MAP_ANONYMOUS,-1,0);
          assert_eq!(memory,libc::MAP_FAILED);assert_eq!(std::io::Error::last_os_error().raw_os_error(),Some(libc::ENOMEM));
       }
       if mode==3 {
          let mut opened=0;loop{let fd=libc::open(c"/dev/null".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC);if fd<0{assert_eq!(std::io::Error::last_os_error().raw_os_error(),Some(libc::EMFILE));break;}assert!(fd<64);opened+=1;}assert!(opened>0);
       }
       #[cfg(target_os="linux")]
       if mode==4 {
          assert_eq!(libc::execve(c"/never-executed".as_ptr(),[c"/never-executed".as_ptr(),std::ptr::null()].as_ptr(),[std::ptr::null()].as_ptr()),-1);
          assert_eq!(std::io::Error::last_os_error().raw_os_error(),Some(libc::EPERM));
       }
    }
}
fn limit(mode:u8) {
    worker::protected().unwrap();
    probe_limit(mode);
    if mode==1 {let marker=b"CPU1\n";unsafe{libc::write(1,marker.as_ptr().cast(),marker.len());}loop{std::hint::black_box(19u64.wrapping_mul(13));}}
    let marker=b"RESOURCE PASS\n";
    unsafe{assert_eq!(libc::write(1,marker.as_ptr().cast(),marker.len()),marker.len() as isize);libc::_exit(0);}
}
fn main(){
 let args:Vec<_>=std::env::args_os().collect();
 match args.get(1).and_then(|s|s.to_str()) {
  Some("--policy")=>{
    #[cfg(target_os="linux")]
    {
      sys::no_new_privs().unwrap();
      let state=landlock::install_read_only().unwrap();
      let mode=if state.covers_openat2_writes(){filter::Openat2Policy::WriteSetCovered}else{filter::Openat2Policy::Deny};
      println!("{{\"initial_bpf_instructions\":{},\"final_bpf_instructions\":{},\"openat2_policy\":\"{:?}\"}}",filter::bootstrap_program(filter::AuditArch::native(), mode).len(),filter::program(filter::AuditArch::native(), mode).len(),mode);
    }
    #[cfg(not(target_os="linux"))]
    println!("{{\"initial_bpf_instructions\":0,\"final_bpf_instructions\":0}}");
  },
  Some("--worker")=>worker::fixture_entry().unwrap(),
  Some("--security-worker")=>security_worker::fixture_entry().unwrap(),
  Some("--trace")=>{
    let out=std::process::Command::new(std::env::current_exe().unwrap()).arg("--trace-helper").arg(&args[2]).arg(args.get(3).map_or(OsStr::new("--security-worker"),|s|s.as_os_str())).env_clear().output().unwrap();
    assert!(out.status.success(),"{:?}",out);print!("{}",String::from_utf8(out.stdout).unwrap());
  },
  Some("--trace-helper")=>helper(Path::new(&args[2]),args[3].to_str().unwrap()),
  Some("--helper-product")=>helper(Path::new(&args[2]),"--product-zero"),
  Some("--helper")=>helper(Path::new(&args[2]),"--worker"),
  Some("--helper-case")=>helper(Path::new(&args[2]),args[3].to_str().unwrap()),
  Some("--cpu-worker")=>{FAILURE.store(1,std::sync::atomic::Ordering::Relaxed);security_worker::fixture_entry().unwrap();},
  Some("--as-worker")=>{FAILURE.store(2,std::sync::atomic::Ordering::Relaxed);security_worker::fixture_entry().unwrap();},
  Some("--nofile-worker")=>{FAILURE.store(3,std::sync::atomic::Ordering::Relaxed);security_worker::fixture_entry().unwrap();},
  Some("--exec-worker")=>{FAILURE.store(4,std::sync::atomic::Ordering::Relaxed);security_worker::fixture_entry().unwrap();},
  Some("--ready-failure-worker")=>{},
  Some("--malformed-worker")=>{FAILURE.store(5,std::sync::atomic::Ordering::Relaxed);security_worker::fixture_entry().unwrap();},
  Some("--limit-cpu")=>limit(1),Some("--limit-as")=>limit(2),Some("--limit-nofile")=>limit(3),Some("--limit-exec")=>limit(4),
  Some("--read")=>prompt_read::tests::product_read_measure(Path::new(&args[2])),
  _=>panic!("fixture mode"),
 }
}
'''

# Only visibility and measurement code are added to the test reader module in
# the generated translation unit. The shipped TCB files remain byte-identical.
READ_MEASUREMENT = r'''
    fn product_reader_clock(deadline:Option<Deadline>)->ClockPins {
        let mut pins=fixed_clock(deadline);
        pins.identity=Some(crate::commands::collector_supervisor::fixture_clock().unwrap());
        pins
    }
    pub(crate) fn product_read_measure(base: &std::path::Path) {
        let _guard=crate::commands::sys::test_inherited_fd_lock();
        use std::os::unix::ffi::OsStrExt;
        let root=base.join("runtime");let config=base.join("config");let state=base.join("state");
        let meta=fs::metadata(&root).unwrap();
        let store=snapshot::context_components(config.as_os_str().as_bytes(),state.as_os_str().as_bytes()).unwrap().into_iter().fold(root.clone(),|p,n|p.join(n));
        let mut config_value=Snapshot::decode(&fs::read(store.join("snapshot")).unwrap()).unwrap().config;
        config_value.bands.clear();config_value.band_order.clear();config_value.collect_mask=TEST_MASK;
        config_value.variants=vec![bingsu_core::template::compile::compile("{fixture}",&crate::SEGMENTS).unwrap()];
        let args=vec!["--ctx".to_owned(),"1".to_owned(),"--record".to_owned(),"B1".to_owned(),"--width".to_owned(),"80".to_owned(),"--shell".to_owned(),"bash".to_owned(),"--pwd".to_owned(),"/repo".to_owned(),format!("--runtime-root={}:{}:{}",meta.dev(),meta.ino(),root.display()),format!("--config-root={}",config.display()),format!("--state-root={}",state.display())];
        let entry=crate::commands::collector_supervisor::fixture_clock().unwrap();
        let before=crate::prompt_io::monotonic_ns().unwrap();
        let mut p=prepare_with_clock(&args.iter().map(|s|s.as_bytes()).collect::<Vec<_>>(),product_reader_clock,None);
        let build=bingsu_core::collection::wire::BuildId(bingsu_core::collection::cwd_hash::sha256(&[crate::build_id().0.as_slice(),b"test-worker"].concat()));
        p.plan=p.plan.with_build_id(build).with_entry(entry).with_catalog(Catalog{segments:&crate::SEGMENTS,workers:TEST_MASK},config_value);
        let prefetched=crate::prompt_io::monotonic_ns().unwrap();
        let installed=crate::sandbox::enter();
        assert!(bingsu_core::front::runs_core(installed));
        let mut start=None; let mut elapsed=None;
        let record=loop {
          match std::mem::replace(&mut p.step,Step::Done(staged::Observed::default())) {
            Step::Done(observed)=>break staged::finish(p.plan,observed).record,
            Step::Read(effect)=> {
              if matches!(effect.operation(),Operation::OpenCollection(_)) && start.is_none(){start=Some(crate::prompt_io::monotonic_ns().unwrap());}
              if matches!(effect.operation(),Operation::Clock){elapsed=start.map(|at|crate::prompt_io::monotonic_ns().unwrap()-at);}
              let observation=p.after(&effect);p.step=staged::next(&mut p.plan,Some(observation));
            }
          }
        };
        let hex:String=record.iter().map(|b|format!("{b:02x}")).collect();
        let out=format!("{{\"front_read_ns\":{},\"front_prefetch_ns\":{},\"record_hex\":\"{}\"}}\n",elapsed.unwrap(),prefetched-before,hex);
        unsafe { libc::write(1,out.as_ptr().cast(),out.len());libc::_exit(0); }
    }
'''


def build_context(binary):
    binary = Path(binary).resolve()
    source = next((p for p in binary.parents if (p / "Cargo.toml").is_file()), ROOT)
    metadata = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=source).stdout)
    source = Path(metadata["workspace_root"])
    target = Path(metadata["target_directory"])
    profile = binary.parent.name
    triple = binary.parent.parent.name
    expected = target / triple if triple.endswith(("-linux-musl", "-linux-gnu")) else target
    expected = (expected / profile / "bingsu").resolve()
    if profile not in {"debug", "release"} or binary != expected:
        raise ValueError(f"expected build-tree binary {expected}; build, prepare that exact sibling pair, then set BINGSU_BIN={expected} for pytest")
    return source


def replace_required(text, old, new):
    assert text.count(old) == 1, f"worker.rs substitution expected exactly once: {old!r}"
    changed = text.replace(old, new)
    assert changed != text, f"worker.rs substitution did not change text: {old!r}"
    return changed


def collector_modules(source, worker_path):
    # main.rs uses external modules with one-line outer attributes. Preserve
    # those attributes (especially cfg), and let Rust resolve child modules at
    # their original paths, including directory modules such as safe_read/.
    root = source / "crates/bingsu-collect/src"
    declarations = re.findall(r"(?m)((?:(?:#\[[^\n]+\]|//[^\n]*)\n)*)mod (\w+);$",
                              (root / "main.rs").read_text())
    assert sum(name == "worker" for _, name in declarations) == 1, "expected one collector worker module"
    modules = []
    for attributes, name in declarations:
        path = worker_path if name == "worker" else root / f"{name}.rs"
        if name != "worker" and not path.is_file():
            path = root / name / "mod.rs"
        assert path.is_file(), f"collector module source missing: {path}"
        modules.append(f'{attributes}#[path={json.dumps(str(path))}] mod {name};')
    return modules


def prepare(binary):
    binary = Path(binary).resolve()
    source = build_context(binary)
    # This operation is host-only and explicit, never called by measure_pair.
    profile = "release" if binary.parent.name == "release" else "debug"
    build = ["cargo", "build", "-j", "2", "-p", "bingsu", "-p", "bingsu-collect", "--message-format=json"]
    if profile == "release":
        build.append("--release")
    triple = binary.parent.parent.name
    if triple.endswith(("-linux-musl", "-linux-gnu")):
        build += ["--target", triple]
    artifacts = [json.loads(line) for line in run(build, cwd=source, timeout=120).stdout.splitlines()]
    collector_artifact, = [a for a in artifacts if a.get("reason") == "compiler-artifact"
                          and a["target"]["name"] == "bingsu-collect" and a.get("executable")]
    deps = {}
    for a in artifacts:
        if a.get("reason") == "compiler-artifact":
            for filename in a.get("filenames", []):
                if filename.endswith(".rlib"):
                    deps[a["target"]["name"]] = filename
    spec = importlib.util.spec_from_file_location("sibling_audit", ROOT / "scripts/check_collector_symbols.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    sibling_id = audit.build_id(binary, 2)
    if sibling_id != audit.build_id(binary.with_name("bingsu-collect"), 1):
        raise ValueError("sibling build identity mismatch")
    directory = binary.parent / "collector-product-fixture"
    directory.mkdir(exist_ok=True)
    modules = []
    for name, rel in {"commands": "crates/bingsu/src/commands/mod.rs", "prompt": "crates/bingsu/src/prompt.rs",
                      "prompt_io": "crates/bingsu/src/prompt_io.rs", "prompt_spawn": "crates/bingsu/src/prompt_spawn.rs"}.items():
        module_path = source / rel
        if name == "commands":
            # Preserve Rust's child-module paths while exposing the sibling
            # pin only in this generated test translation unit. Copies retain
            # the original implementations; the shipped source is unchanged.
            copied = directory / "commands"
            shutil.copytree(module_path.parent, copied, dirs_exist_ok=True)
            shutil.copytree(source / "crates/bingsu/src/shell", directory / "shell", dirs_exist_ok=True)
            commands = module_path.read_text()
            commands = commands.replace("mod collector;", "pub(crate) mod collector;")
            commands = commands.replace("mod group_policy;", "pub(crate) mod group_policy;")
            module_path = copied / "mod.rs"
            module_path.write_text(commands)
        modules.append(f'#[path={json.dumps(str(module_path))}] mod {name};')
    if platform.system() == "Linux":
        modules.append(f'#[path={json.dumps(str(source / "crates/bingsu/src/sandbox.rs"))}] mod sandbox;')
    else:
        modules.append('mod sandbox {pub fn enter()->bingsu_core::front::Sandbox{bingsu_core::front::Sandbox::Absent}}')
    worker = (source / "crates/bingsu-collect/src/worker.rs").read_text()
    # main.rs supplies the shared update_sink module, including for both
    # generated worker copies; do not duplicate a worker-local module list.
    # Collection has written the fixture Update through the sink. Release its
    # borrows before the existing raw failure/probe frames, and never Complete
    # a failure transcript. Mode zero retains the normal sink completion path.
    worker = replace_required(worker, '                collect(&request, &mut sink)?;',
                              '                collect(&request, &mut sink)?;\n'
                              '                if crate::FAILURE.load(std::sync::atomic::Ordering::Relaxed) != 0 {\n'
                              '                    drop(sink);\n'
                              '                    return crate::fail_after_update(fds, buffer, build_id);\n'
                              '                }')
    security = worker
    worker = replace_required(worker, "    let landlock = initial()?;", "    let initial_start = crate::stamp();\n    let landlock = initial()?;\n    let initial_ns = crate::stamp() - initial_start;")
    worker = replace_required(worker, "    final_filter()?;", "    let final_start = crate::stamp();\n    final_filter()?;\n    crate::WORKER_FILTER_NS.store(if cfg!(target_os=\"linux\"){initial_ns + crate::stamp() - final_start}else{0}, std::sync::atomic::Ordering::Relaxed);")
    worker = replace_required(worker, '            payload.extend(7u32.to_le_bytes());\n            payload.extend(b"fixture");', '            let metrics=crate::worker_metrics();\n            payload.extend((metrics.len() as u32).to_le_bytes());\n            payload.extend(metrics.as_bytes());')
    worker = replace_required(worker, "fn protected()", "pub(crate) fn protected()")
    security_path = directory / "security_worker.rs"
    security_path.write_text(security)
    modules.append(f'#[path={json.dumps(str(security_path))}] mod security_worker;')
    worker_path = directory / "worker.rs"
    worker_path.write_text(worker)
    modules.extend(collector_modules(source, worker_path))
    reader = (source / "crates/bingsu/src/prompt_read.rs").read_text()
    at = reader.rfind("}")
    reader = reader[:at] + READ_MEASUREMENT + reader[at:]
    reader_path = directory / "reader.rs"
    reader_path.write_text(reader)
    modules.append(f'#[path={json.dumps(str(reader_path))}] mod prompt_read;')
    rust = directory / "main.rs"
    rust.write_text(HARNESS.replace("@MODULES@", "\n".join(modules)).replace("@COLLECTOR@", json.dumps(str(binary.with_name("bingsu-collect")))))
    fixture = directory / "collector-product"
    command = ["rustc", "--edition=2024", "--cfg", "test", "-O", str(rust), "-o", str(fixture),
               "-L", f"dependency={binary.parent / 'deps'}"]
    if profile == "release":
        command += ["-C", "lto=fat", "-C", "embed-bitcode=yes"]
    if triple.endswith(("-linux-musl", "-linux-gnu")):
        command += ["--target", triple]
        linker = os.environ.get("CARGO_TARGET_" + triple.upper().replace("-", "_") + "_LINKER")
        if linker:
            command += ["-C", "linker=" + linker]
    # 이것을 실패시키는 것: collector git 모듈의 bytes-parser extern을 누락하는 것 (--prepare).
    for name in ("bingsu_core", "bingsu_identity", "libc", "gix_config", "gix_ref", "gix_index",
                 "gix_object", "gix_pack", "gix_error", "gix_zlib", "gix_ignore",
                 "gix_attributes", "gix_utils"):
        command += ["--extern", f"{name}={deps[name]}"]
    env = {**os.environ, "CARGO_MANIFEST_DIR": str(source / "crates/bingsu"), "CARGO_PKG_VERSION": "0.0.0"}
    run(command, env=env, cwd=source, timeout=120)
    table = source / "crates/bingsu-collect/collector-syscalls.tsv"
    sizes = {}
    for name, original in (("front", binary), ("collector", binary.with_name("bingsu-collect"))):
        stripped = directory / (name + "-stripped")
        run(["strip", "-o", stripped, original])
        sizes[name] = stripped.stat().st_size
    sizes["combined"] = sum(sizes.values())
    stub_build = ["cargo", "build", "-j", "2", "-p", "bingsu-bench", "--bin", "m1-collect-stub"]
    if profile == "release":
        stub_build.append("--release")
    if triple.endswith(("-linux-musl", "-linux-gnu")):
        stub_build += ["--target", triple]
    run(stub_build, cwd=source, timeout=120)
    policy = json.loads(run([fixture, "--policy"]).stdout)
    result = {"fixture": str(fixture), "stub": str(binary.with_name("m1-collect-stub")),
              "collector_debug_assertions": collector_artifact["profile"]["debug_assertions"],
              "hashes": {"front": digest(binary), "collector": digest(binary.with_name("bingsu-collect")), "fixture": digest(fixture), "stub": digest(binary.with_name("m1-collect-stub"))},
              "sibling_build_id": sibling_id.hex(), "compiler": run(["rustc", "-vV"]).stdout.decode(), "stripped_bytes": sizes, "policy": {"table_sha256": digest(table), "product_mask": 0,
               "fixture_mask": 1 << 31, "formal": False, "product_target": triple if triple.endswith(("-linux-musl", "-linux-gnu")) else next(line.split(": ",1)[1] for line in run(["rustc", "-vV"]).stdout.decode().splitlines() if line.startswith("host: ")), **policy,
               "filter_kind": "seccomp-bootstrap+final+Landlock" if platform.system() == "Linux" else "absent",
               "as_baseline_kind": "virtual address space" if platform.system() == "Linux" else "sampled footprint",
               "diagnostic_only_worker_reads": ["/proc/self/status"] if platform.system() == "Linux" else ["getrusage", "task_info"]}}
    result["source_hashes"] = preparation_sources(source)
    result["contracts"] = prepare_contracts(source, directory, command, env)
    result["contract_hashes"] = {name: digest(path) for name, path in result["contracts"].items()}
    manifest_path(binary).write_text(json.dumps(result, indent=2) + "\n")
    return result


def prepare_contracts(source, directory, command, env):
    contracts = {}
    for name in ("collector_lifecycle", "collection_store"):
        original = source / "crates/bingsu/tests" / (name + ".rs")
        content = original.read_text()
        begin = content.index("fn peer()")
        # The C peer is prebuilt once, then copied into each test process's
        # private scratch directory. No compiler, Cargo or toolchain in pytest.
        if name == "collector_lifecycle":
            c_code = content.split('const PEER: &str = r#"', 1)[1].split('"#;', 1)[0]
            end = content.index("fn lock(", begin)
            signature = "fn peer() -> &'static PathBuf"
            returned = "PATH.get_or_init(|| {"
            finish = "})"
        else:
            c_code = content[begin:].split('r#"', 1)[1].split('"#', 1)[0]
            end = content.index("// 이것을 실패시키는 것:", begin)
            signature = "fn peer() -> PathBuf"
            returned = "PATH.get_or_init(|| {"
            finish = "}).clone()"
        c_path = directory / (name + ".c")
        peer = directory / (name + "-peer")
        c_path.write_text(c_code)
        run([os.environ.get("CC", "cc"), "-O2", "-Wall", "-Werror", c_path, "-o", peer])
        factory = signature + " {\n static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();\n " + returned
        factory += 'let dir=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target").join(format!("prepared-' + name + '-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));std::fs::create_dir_all(&dir).unwrap();let path=dir.join("peer");std::fs::copy(' + json.dumps(str(peer)) + ',&path).unwrap();std::fs::canonicalize(path).unwrap()' + finish + "\n}\n"
        content = content[:begin] + factory + content[end:]
        content = re.sub(r'#\[path = "([^"]+)"\]', lambda m: '#[path = ' + json.dumps(str((original.parent / m[1]).resolve())) + ']', content)
        rust = directory / (name + ".rs")
        rust.write_text(content)
        executable = directory / name
        args = command.copy()
        args[args.index("-o") + 1] = str(executable)
        args[args.index("-O") + 1] = str(rust)
        args += ["--test"]
        run(args, env=env, cwd=source, timeout=120)
        contracts[name] = str(executable)
    return contracts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", type=Path)
    parser.add_argument("--base")
    parser.add_argument("--candidate")
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.prepare:
            result = prepare(args.prepare)
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps({"status": "PREPARED", **result}, indent=2) + "\n")
            return 0
        if not args.base or not args.candidate or not args.out:
            parser.error("measurement needs --base, --candidate and --out")
        result = measure_pair(args.base, args.candidate, args.rounds)
        code = 0 if result["status"] == "PASS" else 2
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        result = {"milestone": "M3b", "formal_B5_B7": False, "status": "BLOCKED", "reason": str(error)}
        code = 2
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n")
    else:
        print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
