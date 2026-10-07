//! Write-only child spawn and fd cleanup order (spec section 4 side-effect
//! rules). The default mode times both orders in one process, taking turns
//! within each round in alternating direction; `--demo ORDER` shows the
//! effect on a shell's $(...); `--probe-child PATH` spawns PATH through the
//! same path with a leaked fd in place and prints what the child saw.
//! Single-threaded on purpose: fds 1 and 2 move while it runs.
#![deny(unsafe_code)] // FFI lives in bingsu_bench::sys only

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("m1-writer-child runs on Linux and macOS only");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    imp::main();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use bingsu_bench::report::{json_line, json_na};
    use bingsu_bench::rounds::drive;
    use bingsu_bench::stats::summarize;
    use bingsu_bench::sys::spawn::{SpawnSpec, dup_onto_stdout, pipe_cloexec, reap};
    use bingsu_bench::sys::stdio::{
        Saved, dup_inheritable_at, open_fds_and_sid, redirect_stdout_stderr_to_null,
        restore_stdout_stderr, save_stdout_stderr, spawn_writer_child,
    };
    use std::ffi::{CStr, CString};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::time::Instant;

    const USAGE: &str = "usage: m1-writer-child [--rounds N] [--warmup N] [--child PATH]\n       m1-writer-child --demo release-first|spawn-first\n       m1-writer-child --probe-child PATH";
    const ORDERS: [&str; 2] = ["release-first", "spawn-first"];

    #[derive(Debug, PartialEq)]
    enum Mode {
        Cost {
            rounds: usize,
            warmup: usize,
            child: String,
        },
        Demo(&'static str),
        Probe(String),
    }

    /// Fails closed: an unknown or repeated option, a missing value, a
    /// non-number, zero rounds, an unknown order or options of two modes
    /// together is an error, never a default.
    fn parse(args: &[String]) -> Result<Mode, String> {
        let mut seen: Vec<&str> = Vec::new();
        let (mut rounds, mut warmup, mut child, mut demo, mut probe) =
            (None, None, None, None, None);
        let mut it = args.iter();
        while let Some(k) = it.next() {
            let slot = match k.as_str() {
                "--rounds" => &mut rounds,
                "--warmup" => &mut warmup,
                "--child" => &mut child,
                "--demo" => &mut demo,
                "--probe-child" => &mut probe,
                _ => return Err(format!("unknown argument {k:?}")),
            };
            if seen.contains(&k.as_str()) {
                return Err(format!("{k} given twice"));
            }
            seen.push(k);
            *slot = Some(it.next().ok_or(format!("{k} needs a value"))?.clone());
        }
        let cost_options = rounds.is_some() || warmup.is_some() || child.is_some();
        match (demo, probe) {
            (Some(_), Some(_)) => Err("--demo and --probe-child are separate modes".into()),
            (Some(_), None) | (None, Some(_)) if cost_options => {
                Err("--rounds, --warmup and --child belong to the timing mode".into())
            }
            (Some(d), None) => ORDERS
                .into_iter()
                .find(|o| *o == d)
                .map(Mode::Demo)
                .ok_or(format!(
                    "--demo {d:?}: expected release-first or spawn-first"
                )),
            (None, Some(p)) => Ok(Mode::Probe(p)),
            (None, None) => {
                let num = |v: Option<String>, name: &str, default: usize| {
                    v.map_or(Ok(default), |s| {
                        s.parse::<usize>().map_err(|e| format!("{name} {s:?}: {e}"))
                    })
                };
                let rounds = num(rounds, "--rounds", 300)?;
                if rounds == 0 {
                    return Err("--rounds must be at least 1".into());
                }
                Ok(Mode::Cost {
                    rounds,
                    warmup: num(warmup, "--warmup", 20)?,
                    child: child.unwrap_or_else(|| "/usr/bin/true".into()),
                })
            }
        }
    }

    fn cs(s: &str) -> CString {
        CString::new(s).expect("argument without NUL")
    }

    fn spec<'a>(prog: &'a CStr, argv: &'a [&'a CStr]) -> SpawnSpec<'a> {
        SpawnSpec {
            program: prog,
            argv,
            env: None,
            new_session: true,
            capture_stdout: false,
        }
    }

    /// Reaps `pid` and turns anything but exit status 0 into an error.
    fn reap_ok(pid: libc::pid_t) -> Result<(), String> {
        let status = reap(pid).map_err(|e| format!("waitpid: {e}"))?;
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(())
        } else {
            Err(format!("child exit status {status:#x}"))
        }
    }

    /// Puts fds 1/2 back. If that fails, nothing printed later would reach
    /// the caller, so the run stops here with the reason on the saved
    /// stderr copy.
    fn restore_or_exit(saved: &Saved) {
        if let Err(e) = restore_stdout_stderr(saved) {
            if let Ok(fd) = saved.stderr().try_clone_to_owned() {
                let _ = writeln!(
                    std::fs::File::from(fd),
                    "m1-writer-child: restore fds 1/2: {e}"
                );
            }
            std::process::exit(1);
        }
    }

    /// One timed hand-off: both orders do the same two steps (release fds
    /// 1/2 to /dev/null, spawn the child); only their order differs, so the
    /// clock covers the same work in both rows. fds 1/2 are put back and the
    /// child is reaped outside the clock.
    fn once(saved: &Saved, release_first: bool, prog: &CStr) -> Result<u64, String> {
        let argv = [prog];
        let release =
            || redirect_stdout_stderr_to_null(saved).map_err(|e| format!("release fds 1/2: {e}"));
        let spawn = || spawn_writer_child(&spec(prog, &argv)).map_err(|e| format!("spawn: {e}"));
        let t = Instant::now();
        let pid = if release_first {
            // A failed release leaves fds 1/2 as they were and spawns nothing.
            release().and_then(|()| spawn())
        } else {
            spawn().and_then(|pid| {
                release()
                    .map(|()| pid)
                    .or_else(|e| reap_ok(pid).and(Err(e)))
            })
        };
        let ns = t.elapsed().as_nanos() as u64;
        restore_or_exit(saved);
        reap_ok(pid?)?;
        Ok(ns)
    }

    fn cost(rounds: usize, warmup: usize, child: &str) {
        let prog = cs(child);
        // Without posix_spawn closefrom (musl, glibc < 2.34) nothing can be
        // measured: both rows are `na` with the reason.
        let argv = [prog.as_c_str()];
        match spawn_writer_child(&spec(&prog, &argv)).map_err(|e| (e.kind(), e.to_string())) {
            Ok(pid) => {
                if let Err(e) = reap_ok(pid) {
                    for row in ORDERS {
                        println!("{}", json_na("writer", row, &format!("{e} (probe)")));
                    }
                    return;
                }
            }
            Err((_, e)) => {
                for row in ORDERS {
                    println!("{}", json_na("writer", row, &format!("spawn: {e} (probe)")));
                }
                return;
            }
        }
        let saved = match save_stdout_stderr() {
            Ok(s) => s,
            Err(e) => {
                for row in ORDERS {
                    println!("{}", json_na("writer", row, &format!("save fds 1/2: {e}")));
                }
                return;
            }
        };
        let mut samples: [Vec<u64>; 2] = [Vec::with_capacity(rounds), Vec::with_capacity(rounds)];
        let mut failure: [Option<String>; 2] = [None, None];
        drive(ORDERS.len(), warmup + rounds, |round, i| {
            if failure[i].is_some() {
                return;
            }
            match once(&saved, i == 0, &prog) {
                Ok(ns) if round >= warmup => samples[i].push(ns),
                Ok(_) => {}
                Err(e) => failure[i] = Some(format!("{e} (round {})", round + 1)),
            }
        });
        drop(saved);
        for (i, row) in ORDERS.into_iter().enumerate() {
            match &failure[i] {
                Some(why) => println!("{}", json_na("writer", row, why)),
                None => println!(
                    "{}",
                    json_line("writer", row, &summarize(&mut samples[i]), &[])
                ),
            }
        }
    }

    /// The front printed its record; now it hands off to a child that sleeps
    /// 1 s and exits without waiting for it. Any failure exits non-zero.
    fn demo(order: &str) {
        print!("record");
        // Must reach the shell pipe before fd 1 is replaced.
        std::io::stdout().flush().expect("flush the record");
        let (sleep, one) = (c"/bin/sleep", c"1");
        let argv = [sleep, one];
        let saved = save_stdout_stderr().expect("save fds 1/2");
        if order == "release-first" {
            redirect_stdout_stderr_to_null(&saved).expect("release fds 1/2");
            spawn_writer_child(&spec(sleep, &argv)).expect("spawn the writer child");
        } else {
            // The child inherits the shell pipe.
            spawn_writer_child(&spec(sleep, &argv)).expect("spawn the writer child");
            redirect_stdout_stderr_to_null(&saved).expect("release fds 1/2");
        }
    }

    /// Same spawn path as the timed loop, with a leaked non-CLOEXEC fd at
    /// fd >= 100 and fd 1 pointed at a pipe we read. A control child started
    /// without the child-side close (std `Command`) must see the leak (proves
    /// the report looks that high) and must not see the saved copies of fds
    /// 1/2 (they are close-on-exec); the writer child sees neither. Lines the
    /// writer child printed come back prefixed with `CHILD `.
    fn probe(path: &str) {
        let devnull: OwnedFd = std::fs::File::open("/dev/null")
            .expect("open /dev/null")
            .into();
        let leak = dup_inheritable_at(&devnull, 100).expect("plant the leaked fd");
        let saved = save_stdout_stderr().expect("save fds 1/2");
        let control = std::process::Command::new(path)
            .output()
            .expect("control child");
        assert!(
            control.status.success(),
            "control child: {:?}",
            control.status
        );
        let (r, w) = pipe_cloexec().expect("pipe");
        dup_onto_stdout(&w).expect("point fd 1 at the pipe");
        drop(w);
        let prog = cs(path);
        let argv = [prog.as_c_str()];
        let spawned = spawn_writer_child(&spec(&prog, &argv));
        // fd 1 goes back before anything can fail loudly; the pipe's write
        // end then lives only in the child, so the read below ends with it.
        restore_or_exit(&saved);
        let pid = spawned.expect("spawn the writer child");
        let mut out = String::new();
        std::fs::File::from(r)
            .read_to_string(&mut out)
            .expect("read the child's output");
        let status = match reap_ok(pid) {
            Ok(()) => "0".to_string(),
            Err(e) => e,
        };
        let (_, parent_sid) = open_fds_and_sid().expect("parent session");
        let control = String::from_utf8_lossy(&control.stdout);
        let control_fds = control
            .lines()
            .find_map(|l| l.strip_prefix("FDS "))
            .unwrap_or("");
        let [s1, s2] = saved.raw();
        for line in out.lines() {
            println!("CHILD {line}");
        }
        println!(
            "CHILD_STATUS {status}\nPARENT_SID {parent_sid}\nLEAK {}\nSAVED {s1},{s2}\nCONTROL_FDS {control_fds}",
            leak.as_raw_fd()
        );
    }

    pub fn main() {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        match parse(&argv) {
            Ok(Mode::Cost {
                rounds,
                warmup,
                child,
            }) => cost(rounds, warmup, &child),
            Ok(Mode::Demo(order)) => demo(order),
            Ok(Mode::Probe(path)) => probe(&path),
            Err(e) => {
                eprintln!("m1-writer-child: {e}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Mode, parse};

        fn p(args: &[&str]) -> Result<Mode, String> {
            parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        }

        // 이것을 실패시키는 것: 모르는 인자·중복·값 없음·숫자 아님·0 rounds·모르는 순서·두 모드 섞기를 기본값으로 넘기는 것.
        #[test]
        fn parse_fails_closed() {
            assert_eq!(
                p(&[]).unwrap(),
                Mode::Cost {
                    rounds: 300,
                    warmup: 20,
                    child: "/usr/bin/true".into()
                }
            );
            assert_eq!(
                p(&["--demo", "spawn-first"]).unwrap(),
                Mode::Demo("spawn-first")
            );
            assert_eq!(
                p(&["--probe-child", "/x"]).unwrap(),
                Mode::Probe("/x".into())
            );
            for bad in [
                &["--order", "spawn-first"][..],
                &["--rounds", "3", "--rounds", "4"],
                &["--rounds"],
                &["--rounds", "x"],
                &["--rounds", "0"],
                &["--demo", "later"],
                &["--demo", "release-first", "--rounds", "3"],
                &["--probe-child", "/x", "--child", "/y"],
                &["--demo", "release-first", "--probe-child", "/x"],
            ] {
                assert!(p(bad).is_err(), "{bad:?} accepted");
            }
        }
    }
}
