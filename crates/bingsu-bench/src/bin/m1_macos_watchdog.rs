//! macOS memory watchdog costs (spec section 4, X-25):
//! 1. cost of one proc_pid_rusage call,
//! 2. parent CPU per sampling interval (1, 2, 4 ms),
//! 3. footprint vs resident while a child maps and touches a file
//!    (gix pack mmap stand-in) and then grows anonymous memory,
//! 4. overshoot past a limit at the first 2 ms sample that sees it.
//!
//! Every process it samples is its own child. A row it cannot measure is
//! `na` with the reason; a failed sample is never written as 0.
#![deny(unsafe_code)]

#[cfg(not(target_os = "macos"))]
fn main() {
    println!(r#"{{"matrix":"watchdog","na":"macOS only"}}"#);
}

#[cfg(target_os = "macos")]
fn main() {
    imp::main();
}

#[cfg(target_os = "macos")]
mod imp {
    use bingsu_bench::report::{json_line, json_na};
    use bingsu_bench::stats::{summarize, timer_tick_ns};
    use bingsu_bench::sys::macos::{RusageSample, rusage_v4, self_rusage, touch_mapped_file};
    use std::io::{BufRead, BufReader, Lines, Write};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};

    const MATRIX: &str = "watchdog";
    const MIB: u64 = 1024 * 1024;
    const USAGE: &str = "usage: m1-macos-watchdog PACK [--batches N] [--interval-secs N] [--trials N] [--over-mib N]";
    /// Calls per timed batch of row 1.
    const BATCH: u32 = 1000;
    /// A grow trial that has not crossed its limit by then is a miss.
    const TRIAL_DEADLINE: Duration = Duration::from_secs(2);
    const PHASES: [&str; 3] = ["start", "file-touched", "anon-64mib"];

    struct Args {
        pack: String,
        batches: usize,
        interval_secs: u64,
        trials: usize,
        /// Row 4's limit above the child's base footprint (spec: 64 MiB).
        over_mib: u64,
    }

    /// Fails closed: an unknown or repeated option, a missing value, a
    /// non-number or a zero count is an error, never a default.
    fn parse(args: &[String]) -> Result<Args, String> {
        let mut it = args.iter();
        let pack = it.next().ok_or("PACK is required")?.clone();
        let mut seen: Vec<&str> = Vec::new();
        let (mut batches, mut secs, mut trials, mut over) = (None, None, None, None);
        while let Some(k) = it.next() {
            let slot = match k.as_str() {
                "--batches" => &mut batches,
                "--interval-secs" => &mut secs,
                "--trials" => &mut trials,
                "--over-mib" => &mut over,
                _ => return Err(format!("unknown argument {k:?}")),
            };
            if seen.contains(&k.as_str()) {
                return Err(format!("{k} given twice"));
            }
            seen.push(k);
            let v = it.next().ok_or(format!("{k} needs a value"))?;
            let n = v.parse::<u64>().map_err(|e| format!("{k} {v:?}: {e}"))?;
            if n == 0 {
                return Err(format!("{k} must be at least 1"));
            }
            *slot = Some(n);
        }
        Ok(Args {
            pack,
            batches: batches.unwrap_or(300) as usize,
            interval_secs: secs.unwrap_or(2),
            trials: trials.unwrap_or(50) as usize,
            over_mib: over.unwrap_or(64),
        })
    }

    /// A child killed and reaped on drop (also on a panic), so no sleeper
    /// or grower outlives the run.
    struct Guard(Child);

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl Guard {
        fn pid(&self) -> libc::pid_t {
            self.0.id() as libc::pid_t
        }

        /// Reaps the child and says how it ended; Err unless it exited 0.
        fn finish(mut self) -> Result<(), String> {
            let st = self.0.wait().map_err(|e| format!("wait: {e}"))?;
            if st.success() {
                Ok(())
            } else {
                Err(format!("child {st}"))
            }
        }
    }

    /// Spawns this binary in a child mode with piped stdin/stdout.
    fn spawn_self(
        mode: &[&str],
    ) -> Result<(Guard, ChildStdin, Lines<BufReader<ChildStdout>>), String> {
        let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let mut c = Command::new(me)
            .args(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;
        let (Some(i), Some(o)) = (c.stdin.take(), c.stdout.take()) else {
            let _g = Guard(c);
            return Err("child pipes missing".into());
        };
        Ok((Guard(c), i, BufReader::new(o).lines()))
    }

    /// Prints `what` and blocks until the parent writes a line (or closes
    /// stdin): the parent samples while this child is parked.
    fn barrier(what: &str, stdin: &mut Lines<std::io::StdinLock<'static>>) {
        println!("{what}");
        if std::io::stdout().flush().is_err() {
            std::process::exit(5);
        }
        let _ = stdin.next();
    }

    /// `--child-phases FILE`: park at start; map and touch FILE, park; grow
    /// 64 MiB anonymous, park; exit 0. Exit 3 if FILE cannot be mapped.
    fn child_phases(file: &str) -> i32 {
        let mut stdin = std::io::stdin().lines();
        barrier("phase start", &mut stdin);
        match touch_mapped_file(std::path::Path::new(file)) {
            Ok(sum) => {
                std::hint::black_box(sum);
            }
            Err(e) => {
                eprintln!("{file}: {e}");
                return 3;
            }
        }
        barrier("phase file-touched", &mut stdin);
        let keep: Vec<Vec<u8>> = (0..16).map(|_| vec![1u8; (4 * MIB) as usize]).collect();
        barrier("phase anon-64mib", &mut stdin);
        std::hint::black_box(keep);
        0
    }

    /// `--child-grow`: park until "go", then grow 4 MiB per millisecond up
    /// to 256 MiB, then wait for the parent to kill it (or close stdin).
    fn child_grow() -> i32 {
        let mut stdin = std::io::stdin().lines();
        barrier("ready", &mut stdin);
        let mut keep: Vec<Vec<u8>> = Vec::new();
        for _ in 0..64 {
            keep.push(vec![1u8; (4 * MIB) as usize]);
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = stdin.next();
        std::hint::black_box(keep);
        0
    }

    fn sample_line(row: &str, s: RusageSample) -> String {
        format!(
            r#"{{"matrix":"{MATRIX}","row":"{row}","os":"macos","arch":"{}","footprint":{},"resident":{}}}"#,
            std::env::consts::ARCH,
            s.phys_footprint,
            s.resident_size
        )
    }

    /// Row 1. ns per call from batches of `BATCH` calls on a sleeping child.
    fn per_call(pid: libc::pid_t, batches: usize) -> String {
        let row = "proc_pid_rusage/call";
        let tick = timer_tick_ns();
        let mut ns = Vec::with_capacity(batches);
        for b in 0..batches {
            let t = Instant::now();
            for _ in 0..BATCH {
                if let Err(e) = rusage_v4(pid) {
                    return json_na(MATRIX, row, &format!("{e} (batch {})", b + 1));
                }
            }
            ns.push(t.elapsed().as_nanos() as u64 / u64::from(BATCH));
        }
        json_line(
            MATRIX,
            row,
            &summarize(&mut ns),
            &[
                ("calls_per_batch", BATCH.to_string()),
                ("timer_tick_ns", tick.to_string()),
            ],
        )
    }

    /// Row 2. This process's CPU while it sleeps `ms` and samples, for `secs`.
    fn interval(pid: libc::pid_t, ms: u64, secs: u64) -> String {
        let row = format!("interval/{ms}ms");
        let run = || -> Result<String, String> {
            let (u0, s0) = self_rusage().map_err(|e| format!("getrusage: {e}"))?;
            let t = Instant::now();
            let mut samples = 0u64;
            while t.elapsed() < Duration::from_secs(secs) {
                std::thread::sleep(Duration::from_millis(ms));
                rusage_v4(pid).map_err(|e| format!("{e} (sample {})", samples + 1))?;
                samples += 1;
            }
            let wall = t.elapsed().as_nanos();
            let (u1, s1) = self_rusage().map_err(|e| format!("getrusage: {e}"))?;
            Ok(format!(
                r#"{{"matrix":"{MATRIX}","row":"{row}","os":"macos","arch":"{}","samples":{samples},"wall_ns":{wall},"cpu_ns":{}}}"#,
                std::env::consts::ARCH,
                (u1 - u0) + (s1 - s0)
            ))
        };
        run().unwrap_or_else(|e| json_na(MATRIX, &row, &e))
    }

    /// Row 3. One line per phase; a phase the child never reached, or a
    /// child that did not exit 0, is `na`.
    fn phases(pack: &str) -> Vec<String> {
        let mut out = Vec::new();
        let (child, mut go, lines) = match spawn_self(&["--child-phases", pack]) {
            Ok(c) => c,
            Err(e) => {
                return PHASES
                    .iter()
                    .map(|p| json_na(MATRIX, &format!("phase/{p}"), &e))
                    .collect();
            }
        };
        let mut seen = Vec::new();
        for l in lines {
            let Ok(l) = l else { break };
            let Some(phase) = l.strip_prefix("phase ") else {
                continue;
            };
            let row = format!("phase/{phase}");
            out.push(match rusage_v4(child.pid()) {
                Ok(s) => sample_line(&row, s),
                Err(e) => json_na(MATRIX, &row, &e.to_string()),
            });
            seen.push(phase.to_string());
            if writeln!(go, "go").is_err() {
                break;
            }
        }
        drop(go);
        let end = child.finish();
        for p in PHASES.iter().filter(|p| !seen.iter().any(|s| s == *p)) {
            let why = end
                .clone()
                .err()
                .unwrap_or_else(|| "child did not report it".into());
            out.push(json_na(MATRIX, &format!("phase/{p}"), &why));
        }
        if let Err(e) = end {
            if seen.len() == PHASES.len() {
                out.push(json_na(MATRIX, "phase/exit", &e));
            }
        }
        out
    }

    /// Row 4. Bytes past base + `over_mib` at the first 2 ms sample above it.
    /// A trial whose child has not crossed it within `TRIAL_DEADLINE` (or
    /// cannot be sampled) is counted as missed, not as an overshoot.
    fn overshoot(trials: usize, over_mib: u64) -> String {
        let row = "overshoot/2ms";
        let mut over = Vec::new();
        let mut missed = 0usize;
        for t in 0..trials {
            let fail = |e: String| json_na(MATRIX, row, &format!("{e} (trial {})", t + 1));
            let (child, mut go, mut lines) = match spawn_self(&["--child-grow"]) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            if !matches!(lines.next(), Some(Ok(ref l)) if l == "ready") {
                return fail("child did not report ready".into());
            }
            let base = match rusage_v4(child.pid()) {
                Ok(s) => s.phys_footprint,
                Err(e) => return fail(e.to_string()),
            };
            let limit = base + over_mib * MIB;
            if writeln!(go, "go").is_err() {
                return fail("child closed stdin".into());
            }
            let start = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(2));
                match rusage_v4(child.pid()) {
                    Ok(s) if s.phys_footprint > limit => {
                        over.push(s.phys_footprint - limit);
                        break;
                    }
                    Ok(_) if start.elapsed() < TRIAL_DEADLINE => {}
                    _ => {
                        missed += 1;
                        break;
                    }
                }
            }
            drop(child);
        }
        if over.is_empty() {
            return json_na(
                MATRIX,
                row,
                &format!("no trial crossed the limit ({missed} missed)"),
            );
        }
        let o = summarize(&mut over); // values are bytes, not nanoseconds
        format!(
            r#"{{"matrix":"{MATRIX}","row":"{row}","os":"macos","arch":"{}","n":{},"missed":{missed},"limit_above_base_bytes":{},"median_bytes":{},"p95_bytes":{},"min_bytes":{},"max_bytes":{}}}"#,
            std::env::consts::ARCH,
            o.n,
            over_mib * MIB,
            o.median_ns,
            o.p95_ns,
            o.min_ns,
            o.max_ns
        )
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match args.as_slice() {
            [m, file] if m == "--child-phases" => std::process::exit(child_phases(file)),
            [m] if m == "--child-grow" => std::process::exit(child_grow()),
            _ => {}
        }
        let a = parse(&args).unwrap_or_else(|e| {
            eprintln!("{e}\n{USAGE}");
            std::process::exit(2);
        });
        if !std::path::Path::new(&a.pack).is_file() {
            eprintln!(
                "{}: not a file (bench/probes/make-pack-fixture.sh makes one)",
                a.pack
            );
            std::process::exit(2);
        }

        // Rows 1 and 2 sample a sleeping child.
        match Command::new("/bin/sleep")
            .arg("600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
        {
            Ok(c) => {
                let sleeper = Guard(c);
                println!("{}", per_call(sleeper.pid(), a.batches));
                for ms in [1u64, 2, 4] {
                    println!("{}", interval(sleeper.pid(), ms, a.interval_secs));
                }
            }
            Err(e) => {
                let why = format!("spawn /bin/sleep: {e}");
                println!("{}", json_na(MATRIX, "proc_pid_rusage/call", &why));
                for ms in [1u64, 2, 4] {
                    println!("{}", json_na(MATRIX, &format!("interval/{ms}ms"), &why));
                }
            }
        }
        for l in phases(&a.pack) {
            println!("{l}");
        }
        println!("{}", overshoot(a.trials, a.over_mib));
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn p(a: &[&str]) -> Result<Args, String> {
            parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        }

        // 이것을 실패시키는 것: PACK 없이 기본값으로 돌거나, 모르는·반복된 옵션, 0이나 숫자가 아닌 값을 받는 것.
        #[test]
        fn parse_fails_closed() {
            let a = p(&["f"]).unwrap();
            assert_eq!(
                (
                    a.pack.as_str(),
                    a.batches,
                    a.interval_secs,
                    a.trials,
                    a.over_mib
                ),
                ("f", 300, 2, 50, 64)
            );
            let a = p(&[
                "f",
                "--trials",
                "3",
                "--batches",
                "2",
                "--interval-secs",
                "1",
            ])
            .unwrap();
            assert_eq!((a.batches, a.interval_secs, a.trials), (2, 1, 3));
            for bad in [
                &[][..],
                &["--trials", "3"],
                &["f", "--trials"],
                &["f", "--trials", "0"],
                &["f", "--trials", "x"],
                &["f", "--trials", "1", "--trials", "2"],
                &["f", "--rounds", "1"],
            ] {
                assert!(p(bad).is_err(), "{bad:?}");
            }
        }
    }
}
