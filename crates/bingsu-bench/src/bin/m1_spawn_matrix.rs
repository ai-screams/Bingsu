//! Collector cost matrix (spec section 9 M1 row). Prints one JSON line per
//! row: measured rows carry `median_ns`/`p95_ns`, rows that cannot be
//! measured carry `na` and the reason. Rows take turns within each round
//! (no order effect). Single-threaded on purpose: `spawn` and
//! `spawn_in_cgroup` both require it of their caller.
#![deny(unsafe_code)] // FFI lives in bingsu_bench::sys only

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("m1-spawn-matrix runs on Linux and macOS only");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    imp::main();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use bingsu_bench::report::{json_line, json_na};
    use bingsu_bench::stats::summarize;
    use bingsu_bench::sys::spawn::{SpawnSpec, read_byte, reap, spawn};
    use std::ffi::{CStr, CString};
    use std::time::Instant;

    const USAGE: &str = "usage: m1-spawn-matrix --dedicated PATH --same PATH [--rounds N] [--warmup N] [--cgroup-dir DIR]";
    /// The stub's filter is partial (bingsu-collect `sys::sandbox`), so rows
    /// that install it measure a lower bound for the spec's filter.
    const LOWER_BOUND: (&str, &str) = ("sandbox_filter", r#""lower-bound""#);

    struct Args {
        dedicated: String,
        same: String,
        rounds: usize,
        warmup: usize,
        cgroup_dir: Option<String>,
    }

    /// Fails closed: an unknown or repeated option, a missing value, a
    /// non-number or zero rounds is an error, never a default.
    fn parse(args: &[String]) -> Result<Args, String> {
        let mut seen: Vec<&str> = Vec::new();
        let (mut ded, mut same, mut rounds, mut warmup, mut cg) = (None, None, None, None, None);
        let mut it = args.iter();
        while let Some(k) = it.next() {
            let slot = match k.as_str() {
                "--dedicated" => &mut ded,
                "--same" => &mut same,
                "--rounds" => &mut rounds,
                "--warmup" => &mut warmup,
                "--cgroup-dir" => &mut cg,
                _ => return Err(format!("unknown argument {k:?}")),
            };
            if seen.contains(&k.as_str()) {
                return Err(format!("{k} given twice"));
            }
            seen.push(k);
            *slot = Some(it.next().ok_or(format!("{k} needs a value"))?.clone());
        }
        let num = |v: Option<String>, name: &str, default: usize| {
            v.map_or(Ok(default), |s| {
                s.parse::<usize>().map_err(|e| format!("{name} {s:?}: {e}"))
            })
        };
        let rounds = num(rounds, "--rounds", 300)?;
        if rounds == 0 {
            return Err("--rounds must be at least 1".into());
        }
        Ok(Args {
            dedicated: ded.ok_or("--dedicated PATH is required")?,
            same: same.ok_or("--same PATH is required")?,
            rounds,
            warmup: num(warmup, "--warmup", 20)?,
            cgroup_dir: cg,
        })
    }

    fn cs(s: &str) -> CString {
        CString::new(s).expect("argument without NUL")
    }

    enum Kind {
        /// posix_spawn; `wait_ready` stops the clock at the ready byte,
        /// otherwise at the spawn call's return.
        Spawn {
            env: Option<Vec<CString>>,
            new_session: bool,
            wait_ready: bool,
        },
        /// clone3 into the fixed cgroup, or into a unique one made per spawn.
        #[cfg(target_os = "linux")]
        Cgroup { unique: bool },
    }

    struct Row {
        name: &'static str,
        program: CString,
        argv: Vec<CString>,
        kind: Kind,
        extra: Vec<(&'static str, String)>,
        samples: Vec<u64>,
        failure: Option<String>,
    }

    fn sanitized_env() -> Vec<CString> {
        vec![cs("PATH=/usr/bin:/bin"), cs("LANG=C.UTF-8")]
    }

    fn row(name: &'static str, bin: &str, same: bool, mode: &str, kind: Kind) -> Row {
        let mut argv = vec![cs(bin)];
        if same {
            argv.push(cs("__collect-stub"));
        }
        argv.extend([cs("--mode"), cs(mode)]);
        let bytes = std::fs::metadata(bin)
            .unwrap_or_else(|e| panic!("{bin}: {e}"))
            .len();
        let mut extra = vec![("binary_bytes", bytes.to_string())];
        if mode == "sandbox" {
            extra.push((LOWER_BOUND.0, LOWER_BOUND.1.into()));
        }
        Row {
            name,
            program: cs(bin),
            argv,
            kind,
            extra,
            samples: Vec::new(),
            failure: None,
        }
    }

    /// Panics on any failure: these rows run everywhere, so a failure is a
    /// broken harness, not a missing platform feature.
    fn spawn_once(r: &Row, env: Option<&[CString]>, new_session: bool, wait_ready: bool) -> u64 {
        let argv: Vec<&CStr> = r.argv.iter().map(CString::as_c_str).collect();
        let env: Option<Vec<&CStr>> = env.map(|e| e.iter().map(CString::as_c_str).collect());
        let spec = SpawnSpec {
            program: &r.program,
            argv: &argv,
            env: env.as_deref(),
            new_session,
            capture_stdout: wait_ready,
        };
        let t0 = Instant::now();
        let child = spawn(&spec).unwrap();
        if let Some(fd) = &child.stdout {
            assert_eq!(read_byte(fd).unwrap(), b'R', "{}: no ready byte", r.name);
        }
        let ns = t0.elapsed().as_nanos() as u64;
        let status = reap(child.pid).unwrap();
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "{}: child exit status {status:#x}",
            r.name
        );
        ns
    }

    pub fn main() {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let a = match parse(&argv) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("m1-spawn-matrix: {e}\n{USAGE}");
                std::process::exit(2);
            }
        };
        let (ded, same) = (a.dedicated.as_str(), a.same.as_str());
        let posix = |env: bool, new_session: bool, wait_ready: bool| Kind::Spawn {
            env: env.then(sanitized_env),
            new_session,
            wait_ready,
        };
        let mut rows = vec![
            row(
                "bare/dedicated",
                ded,
                false,
                "bare",
                posix(false, false, true),
            ),
            row("bare/same", same, true, "bare", posix(false, false, true)),
            row(
                "env-limits/dedicated",
                ded,
                false,
                "limits",
                posix(true, true, true),
            ),
            row(
                "env-limits/same",
                same,
                true,
                "limits",
                posix(true, true, true),
            ),
        ];
        #[cfg(target_os = "linux")]
        rows.extend([
            row(
                "sandbox-ready/dedicated",
                ded,
                false,
                "sandbox",
                posix(true, true, true),
            ),
            row(
                "sandbox-ready/same",
                same,
                true,
                "sandbox",
                posix(true, true, true),
            ),
        ]);
        #[cfg(target_os = "linux")]
        let mut area = linux::Area::open(a.cgroup_dir.as_deref());
        #[cfg(target_os = "linux")]
        for (name, bin, is_same, unique) in [
            ("cgroup-clone3/dedicated", ded, false, false),
            ("cgroup-clone3/same", same, true, false),
            ("cgroup-mkdir-clone3/dedicated", ded, false, true),
            ("cgroup-mkdir-clone3/same", same, true, true),
        ] {
            let mut r = row(name, bin, is_same, "sandbox", Kind::Cgroup { unique });
            r.failure = area.as_ref().err().cloned();
            rows.push(r);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = &a.cgroup_dir;
        rows.push(row(
            "min-child-spawn-call",
            ded,
            false,
            "exit",
            posix(true, true, false),
        ));

        for round in 0..a.warmup + a.rounds {
            for r in rows.iter_mut().filter(|r| r.failure.is_none()) {
                let ns = match &r.kind {
                    Kind::Spawn {
                        env,
                        new_session,
                        wait_ready,
                    } => Ok(spawn_once(r, env.as_deref(), *new_session, *wait_ready)),
                    #[cfg(target_os = "linux")]
                    Kind::Cgroup { unique } => match &mut area {
                        Ok(area) => area.once(r, *unique),
                        Err(e) => Err(e.clone()),
                    },
                };
                match ns {
                    Ok(ns) if round >= a.warmup => r.samples.push(ns),
                    Ok(_) => {}
                    Err(e) => r.failure = Some(e),
                }
            }
        }
        #[cfg(target_os = "linux")]
        let cleanup = area.map_or(Ok(()), linux::Area::close);
        for r in &mut rows {
            match &r.failure {
                Some(why) => println!("{}", json_na("spawn", r.name, why)),
                None => println!(
                    "{}",
                    json_line("spawn", r.name, &summarize(&mut r.samples), &r.extra)
                ),
            }
        }
        #[cfg(target_os = "linux")]
        if let Err(e) = cleanup {
            eprintln!("m1-spawn-matrix: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::Row;
        use bingsu_bench::sys::cgroup::spawn_in_cgroup;
        use bingsu_bench::sys::spawn::{pipe_cloexec, read_byte, reap};
        use std::ffi::{CString, c_char};
        use std::fs::File;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::path::PathBuf;
        use std::time::Instant;

        /// The delegated cgroup v2 area: a fixed child cgroup for the
        /// clone3 rows, a counter for the unique ones, and /dev/null.
        pub struct Area {
            dir: PathBuf,
            fixed_path: PathBuf,
            fixed: OwnedFd,
            devnull: File,
            envp: Vec<CString>,
            seq: u64,
        }

        impl Area {
            /// Err is the `na` reason for every cgroup row.
            pub fn open(dir: Option<&str>) -> Result<Area, String> {
                let dir =
                    PathBuf::from(dir.ok_or("no --cgroup-dir (no delegated cgroup v2 area)")?);
                let fixed_path = dir.join(format!("bingsu-m1-fixed-{}", std::process::id()));
                std::fs::create_dir(&fixed_path).map_err(|e| format!("fixed cgroup mkdir: {e}"))?;
                let fixed = match File::open(&fixed_path) {
                    Ok(f) => f.into(),
                    Err(e) => {
                        let _ = std::fs::remove_dir(&fixed_path);
                        return Err(format!("fixed cgroup open: {e}"));
                    }
                };
                let devnull = File::open("/dev/null").map_err(|e| format!("/dev/null: {e}"))?;
                Ok(Area {
                    dir,
                    fixed_path,
                    fixed,
                    devnull,
                    envp: super::sanitized_env(),
                    seq: 0,
                })
            }

            /// Removes the fixed cgroup; Err if it cannot (left behind).
            pub fn close(self) -> Result<(), String> {
                drop(self.fixed);
                std::fs::remove_dir(&self.fixed_path)
                    .map_err(|e| format!("rmdir {}: {e}", self.fixed_path.display()))
            }

            /// One spawn: pipe, optional unique mkdir + open, clone3 into the
            /// cgroup, the ready byte (clock stops), reap, rmdir. Any failure,
            /// a non-zero exit or a failed rmdir is returned, never a panic.
            pub fn once(&mut self, r: &Row, unique: bool) -> Result<u64, String> {
                let argv: Vec<*const c_char> = r
                    .argv
                    .iter()
                    .map(|s| s.as_ptr())
                    .chain([std::ptr::null()])
                    .collect();
                let envp: Vec<*const c_char> = self
                    .envp
                    .iter()
                    .map(|s| s.as_ptr())
                    .chain([std::ptr::null()])
                    .collect();
                let path = unique.then(|| {
                    self.seq += 1;
                    self.dir
                        .join(format!("bingsu-m1-{}-{}", std::process::id(), self.seq))
                });
                let t0 = Instant::now();
                let (rd, w) = pipe_cloexec().map_err(|e| format!("pipe: {e}"))?;
                if let Some(p) = &path {
                    std::fs::create_dir(p).map_err(|e| format!("mkdir: {e}"))?;
                }
                let run = || -> Result<u64, String> {
                    let opened: OwnedFd;
                    let cg = match &path {
                        Some(p) => {
                            opened = File::open(p).map_err(|e| format!("open: {e}"))?.into();
                            &opened
                        }
                        None => &self.fixed,
                    };
                    let (pid, _pidfd) = spawn_in_cgroup(
                        cg,
                        &r.program,
                        &argv,
                        &envp,
                        w.as_raw_fd(),
                        self.devnull.as_raw_fd(),
                    )
                    .map_err(|e| format!("clone3: {e}"))?;
                    drop(w);
                    let ready = read_byte(&rd);
                    let ns = t0.elapsed().as_nanos() as u64;
                    let status = reap(pid).map_err(|e| format!("waitpid: {e}"))?;
                    match ready {
                        Ok(b'R') if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => {
                            Ok(ns)
                        }
                        Ok(b'R') => Err(format!("child exit status {status:#x}")),
                        _ => Err(format!("no ready byte (child exit status {status:#x})")),
                    }
                };
                let result = run();
                match path {
                    Some(p) => {
                        let removed = std::fs::remove_dir(&p).map_err(|e| format!("rmdir: {e}"));
                        result.and_then(|ns| removed.map(|()| ns))
                    }
                    None => result,
                }
            }
        }
    }
}
