//! Collector cost matrix (spec section 9 M1 row). Prints one JSON line per
//! row: measured rows carry `median_ns`/`p95_ns`, rows that cannot be
//! measured carry `na` and the reason. Rows take turns within each round,
//! in alternating direction (see `drive`). Single-threaded on purpose:
//! `spawn` requires it on macOS (its pipe becomes close-on-exec in two
//! steps); the `spawn_in_cgroup` child makes only async-signal-safe calls.
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
        // posix_spawn rows vs clone3 rows: clone3 here runs without CLONE_VM
        // (a fork-style copy of this process), while glibc's posix_spawn
        // shares the memory (clone3 with CLONE_VM | CLONE_VFORK, seen with
        // strace on glibc 2.41). A difference in definition, not noise.
        let method = match &kind {
            Kind::Spawn { .. } => r#""posix_spawn""#,
            #[cfg(target_os = "linux")]
            Kind::Cgroup { .. } => r#""clone3-no-vm""#,
        };
        let mut extra = vec![
            ("binary_bytes", bytes.to_string()),
            ("spawn_method", method.into()),
        ];
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
            rows.push(row(name, bin, is_same, "sandbox", Kind::Cgroup { unique }));
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

        drive(rows.len(), a.warmup + a.rounds, |round, i| {
            let r = &mut rows[i];
            if r.failure.is_some() {
                return;
            }
            let ns: Result<u64, String> = match &r.kind {
                Kind::Spawn {
                    env,
                    new_session,
                    wait_ready,
                } => Ok(spawn_once(r, env.as_deref(), *new_session, *wait_ready)),
                // A setup failure surfaces here, at the row's first attempt.
                #[cfg(target_os = "linux")]
                Kind::Cgroup { unique } => match &mut area {
                    Ok(area) => area.once(r, *unique),
                    Err(e) => Err(e.clone()),
                },
            };
            match ns {
                Ok(ns) if round >= a.warmup => r.samples.push(ns),
                Ok(_) => {}
                Err(e) => r.failure = Some(format!("{e} (round {})", round + 1)),
            }
        });
        // The fixed cgroup is removed before printing: if that fails, the
        // rows that used it become na instead of clean-looking numbers.
        #[cfg(target_os = "linux")]
        if let Err(e) = area.map_or(Ok(()), linux::Area::close) {
            eprintln!("m1-spawn-matrix: {e}");
            for r in rows.iter_mut().filter(|r| r.failure.is_none()) {
                if let Kind::Cgroup { unique: false } = r.kind {
                    r.failure = Some(format!("{e} (cleanup)"));
                }
            }
        }
        for r in &mut rows {
            match &r.failure {
                Some(why) => println!("{}", json_na("spawn", r.name, why)),
                None => println!(
                    "{}",
                    json_line("spawn", r.name, &summarize(&mut r.samples), &r.extra)
                ),
            }
        }
    }

    /// Calls `step(round, row)` for every row in every round. Even rounds go
    /// forward and odd rounds backward, so each pair of rounds puts a row at
    /// mirrored positions and the position bias cancels out in pairs (the
    /// middle row of an odd count stays in place; the reference harness
    /// alternates the same way).
    fn drive(rows: usize, rounds: usize, mut step: impl FnMut(usize, usize)) {
        for round in 0..rounds {
            if round % 2 == 0 {
                (0..rows).for_each(|i| step(round, i));
            } else {
                (0..rows).rev().for_each(|i| step(round, i));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        // 이것을 실패시키는 것: 홀수 회차의 역순을 빼는 것, 회차나 행을 빠뜨리는 것.
        #[test]
        fn rounds_alternate_direction_and_cover_every_row() {
            let mut calls = Vec::new();
            super::drive(3, 4, |round, i| calls.push((round, i)));
            assert_eq!(
                calls,
                [
                    (0, 0),
                    (0, 1),
                    (0, 2),
                    (1, 2),
                    (1, 1),
                    (1, 0),
                    (2, 0),
                    (2, 1),
                    (2, 2),
                    (3, 2),
                    (3, 1),
                    (3, 0)
                ]
            );
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::Row;
        use bingsu_bench::sys::cgroup::spawn_in_cgroup;
        use bingsu_bench::sys::spawn::{pipe_cloexec, read_byte, reap};
        use std::ffi::{CStr, CString};
        use std::fs::File;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::path::PathBuf;
        use std::time::Instant;

        /// The delegated cgroup v2 area: a fixed child cgroup for the
        /// clone3 rows, a counter for the unique ones, and /dev/null.
        pub struct Area {
            dir: PathBuf,
            // Declared before `fixed_dir`, so the fd closes before the rmdir.
            fixed: OwnedFd,
            fixed_dir: FixedDir,
            devnull: File,
            envp: Vec<CString>,
            seq: u64,
        }

        /// The fixed cgroup folder from its mkdir on. Dropping it removes the
        /// folder (best effort), so an early return in `Area::open` or a panic
        /// in another row unwinding through `Area` leaves nothing behind;
        /// `Area::close` takes the path and reports the rmdir result instead.
        struct FixedDir(Option<PathBuf>);

        impl Drop for FixedDir {
            fn drop(&mut self) {
                if let Some(p) = self.0.take() {
                    let _ = std::fs::remove_dir(p);
                }
            }
        }

        impl Area {
            /// Err is the `na` reason for every cgroup row.
            pub fn open(dir: Option<&str>) -> Result<Area, String> {
                let dir =
                    PathBuf::from(dir.ok_or("no --cgroup-dir (no delegated cgroup v2 area)")?);
                let devnull = File::open("/dev/null").map_err(|e| format!("/dev/null: {e}"))?;
                let fixed_path = dir.join(format!("bingsu-m1-fixed-{}", std::process::id()));
                std::fs::create_dir(&fixed_path).map_err(|e| format!("fixed cgroup mkdir: {e}"))?;
                let fixed_dir = FixedDir(Some(fixed_path));
                let fixed = File::open(fixed_dir.0.as_ref().expect("just made"))
                    .map_err(|e| format!("fixed cgroup open: {e}"))?
                    .into();
                Ok(Area {
                    dir,
                    fixed,
                    fixed_dir,
                    devnull,
                    envp: super::sanitized_env(),
                    seq: 0,
                })
            }

            /// Removes the fixed cgroup; Err if it cannot (left behind).
            pub fn close(mut self) -> Result<(), String> {
                let p = self.fixed_dir.0.take().expect("closed once");
                drop(self);
                std::fs::remove_dir(&p).map_err(|e| format!("rmdir {}: {e}", p.display()))
            }

            /// One spawn: pipe, optional unique mkdir + open, clone3 into the
            /// cgroup, the ready byte (clock stops), reap, rmdir. Any failure,
            /// a non-zero exit or a failed rmdir is returned, never a panic.
            pub fn once(&mut self, r: &Row, unique: bool) -> Result<u64, String> {
                let argv: Vec<&CStr> = r.argv.iter().map(CString::as_c_str).collect();
                let envp: Vec<&CStr> = self.envp.iter().map(CString::as_c_str).collect();
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
