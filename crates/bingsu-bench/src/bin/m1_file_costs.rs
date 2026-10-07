//! File cost rows (spec section 9 M1 row (7), "lock and generation check"
//! and the `statfs` of `init`). Prints one JSON line per row; a row that
//! fails carries `na` with the reason and the round. Rows take turns within
//! each round, in alternating direction (`bingsu_bench::rounds::drive`).
//! `--once` makes one pass of the reads inside the fsb marker window for the
//! strace read-count test and touches nothing else.
#![deny(unsafe_code)] // FFI lives in bingsu_bench::sys only

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("m1-file-costs runs on Linux and macOS only");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    imp::main();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use bingsu_bench::BUF;
    use bingsu_bench::report::{json_line, json_na};
    use bingsu_bench::rounds::drive;
    use bingsu_bench::stats::{summarize, timer_tick_ns};
    use bingsu_bench::sys::meta::{
        acl_probe_path, lock_and_read_generation, lstat_path, open_dir, open_fstat_read_close,
        stat_path, statfs_path,
    };
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    const USAGE: &str = "usage: m1-file-costs --dir RUNTIME_DIR [--rounds N] [--warmup N]\n       m1-file-costs --dir DIR --once";
    const HEADER: usize = 64;
    const MARKER: usize = 128;
    const SWEEP: [usize; 4] = [64, 256, 1024, 4096];
    const GENERATION: u64 = 7;

    #[derive(Debug, PartialEq)]
    struct Args {
        dir: PathBuf,
        rounds: usize,
        warmup: usize,
        once: bool,
    }

    /// Fails closed: an unknown or repeated option, a missing value, a
    /// non-number, zero rounds or timing options with `--once` is an error,
    /// never a default.
    fn parse(args: &[String]) -> Result<Args, String> {
        let mut seen: Vec<&str> = Vec::new();
        let (mut dir, mut rounds, mut warmup, mut once) = (None, None, None, false);
        let mut it = args.iter();
        while let Some(k) = it.next() {
            if seen.contains(&k.as_str()) {
                return Err(format!("{k} given twice"));
            }
            let slot = match k.as_str() {
                "--once" => {
                    once = true;
                    seen.push(k);
                    continue;
                }
                "--dir" => &mut dir,
                "--rounds" => &mut rounds,
                "--warmup" => &mut warmup,
                _ => return Err(format!("unknown argument {k:?}")),
            };
            seen.push(k);
            *slot = Some(it.next().ok_or(format!("{k} needs a value"))?.clone());
        }
        if once && (rounds.is_some() || warmup.is_some()) {
            return Err("--once makes one untimed pass; --rounds and --warmup do not apply".into());
        }
        let num = |v: Option<String>, name: &str, default: usize| {
            v.map_or(Ok(default), |s| {
                s.parse::<usize>().map_err(|e| format!("{name} {s:?}: {e}"))
            })
        };
        let rounds = num(rounds, "--rounds", 1000)?;
        if rounds == 0 {
            return Err("--rounds must be at least 1".into());
        }
        Ok(Args {
            dir: PathBuf::from(dir.ok_or("--dir RUNTIME_DIR is required")?),
            rounds,
            warmup: num(warmup, "--warmup", 100)?,
            once,
        })
    }

    /// The fixture folder inside the runtime folder; removed on drop, so a
    /// panic or an early return leaves nothing behind.
    struct Fixture(PathBuf);

    impl Fixture {
        /// A new folder named by pid, time and attempt; `create_dir` refuses
        /// one that already exists, so nothing planted in advance is used.
        fn create(parent: &Path) -> Result<Fixture, String> {
            let fx = Fixture(new_dir(parent, "bingsu-m1-file")?);
            let write = |name: &str, bytes: &[u8]| {
                std::fs::write(fx.0.join(name), bytes).map_err(|e| format!("write {name}: {e}"))
            };
            write("header", &[0u8; HEADER])?;
            write("marker", &[0u8; MARKER])?;
            for n in SWEEP {
                write(&format!("sweep-{n}"), &vec![0u8; n])?;
            }
            // Dummy bytes of the right size; only the generation at 8..16 is read.
            let mut h = [0u8; HEADER];
            h[8..16].copy_from_slice(&GENERATION.to_le_bytes());
            write("snapshot-header", &h)?;
            write("lock", b"")?;
            Ok(fx)
        }
    }

    fn new_dir(parent: &Path, tag: &str) -> Result<PathBuf, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        for attempt in 0..100 {
            let dir = parent.join(format!("{tag}-{}-{nanos}-{attempt}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("mkdir {}: {e}", dir.display())),
            }
        }
        Err(format!("no free folder name under {}", parent.display()))
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// One read of `name` relative to the folder fd (ceil(size / BUF) read
    /// calls; the strace test counts them), or an error naming the file.
    fn read_file(
        dir: BorrowedFd<'_>,
        name: &CStr,
        size: usize,
        buf: &mut [u8],
    ) -> Result<(), String> {
        open_fstat_read_close(dir, name, size, buf)
            .map(drop)
            .map_err(|e| format!("{}: {e}", name.to_string_lossy()))
    }

    fn sweep_name(n: usize) -> CString {
        CString::new(format!("sweep-{n}")).expect("no NUL")
    }

    #[cfg(target_os = "linux")]
    fn marker(name: &CStr) {
        bingsu_bench::sys::fs::marker(name).expect("fsb marker");
    }

    #[cfg(not(target_os = "linux"))]
    fn marker(_: &CStr) {}

    fn fail(e: impl std::fmt::Display) -> ! {
        eprintln!("m1-file-costs: {e}");
        std::process::exit(1);
    }

    /// Inside the fsb window: the folder open, then header, marker and the
    /// sweep files, which the caller made in `dir`. Nothing touches the
    /// filesystem outside the window (closed-window rule, Task B1), so the
    /// folder open is counted too; a failure exits non-zero.
    fn once(dir: &Path) {
        let mut buf = vec![0u8; BUF];
        let mut files = vec![
            (c"header".to_owned(), HEADER),
            (c"marker".to_owned(), MARKER),
        ];
        files.extend(SWEEP.map(|n| (sweep_name(n), n)));
        marker(c"fsb:begin");
        let fd = open_dir(dir).unwrap_or_else(|e| fail(format!("open {}: {e}", dir.display())));
        for (name, size) in &files {
            if let Err(e) = read_file(fd.as_fd(), name, *size, &mut buf) {
                fail(e);
            }
        }
        drop(fd);
        marker(c"fsb:end");
    }

    type Op<'a> = Box<dyn FnMut(&mut [u8]) -> Result<(), String> + 'a>;

    struct Row<'a> {
        name: String,
        extra: Vec<(&'static str, String)>,
        op: Op<'a>,
        samples: Vec<u64>,
        failure: Option<String>,
    }

    fn row<'a>(name: String, extra: Vec<(&'static str, String)>, op: Op<'a>) -> Row<'a> {
        Row {
            name,
            extra,
            op,
            samples: Vec::new(),
            failure: None,
        }
    }

    /// The `lock+generation` operation: only a free lock on our own file with
    /// the expected generation counts as a measured success.
    fn lock_row(dir: BorrowedFd<'_>) -> Result<(), String> {
        match lock_and_read_generation(dir, c"lock", c"snapshot-header", GENERATION) {
            Ok(true) => Ok(()),
            Ok(false) => Err("not ours, locked or another generation".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// macOS reports "no ACL" for a missing file too (`acl_probe_path`), so
    /// once the rounds are done the probed file must still be there; checked
    /// outside the timed calls.
    fn acl_probe_still_there(probe: &Path) -> Result<(), String> {
        lstat_path(probe)
            .map_err(|e| format!("ACL probe {}: {e} (after the rounds)", probe.display()))
    }

    /// Rows over the fixture folder `fx` (its fd is `fd`) and the runtime
    /// root `root` (the `statfs` row: `init` asks it of the runtime root).
    fn rows<'a>(fx: &Path, fd: BorrowedFd<'a>, root: &'a Path) -> Vec<Row<'a>> {
        let buf_extra = || ("buf", BUF.to_string());
        let mut rows = vec![row(
            "header64+marker128".into(),
            vec![buf_extra()],
            Box::new(move |buf| {
                read_file(fd, c"header", HEADER, buf)?;
                read_file(fd, c"marker", MARKER, buf)
            }),
        )];
        for n in SWEEP {
            let name = sweep_name(n);
            rows.push(row(
                format!("sweep/{n}"),
                vec![buf_extra(), ("reads", n.div_ceil(BUF).to_string())],
                Box::new(move |buf| read_file(fd, &name, n, buf)),
            ));
        }
        let probe = fx.join("header");
        for (name, f) in [
            ("meta/stat", stat_path as fn(&Path) -> std::io::Result<()>),
            ("meta/lstat", lstat_path),
        ] {
            let p = probe.clone();
            rows.push(row(
                name.into(),
                vec![],
                Box::new(move |_| f(&p).map_err(|e| e.to_string())),
            ));
        }
        rows.push(row(
            "meta/statfs".into(),
            vec![("target", r#""runtime-root""#.into())],
            Box::new(move |_| statfs_path(root).map_err(|e| e.to_string())),
        ));
        // The common case is a file without an ACL; one with an ACL (say,
        // inherited from the folder) takes another path, so it fails the row.
        rows.push(row(
            "meta/acl".into(),
            vec![("acl", r#""absent""#.into())],
            Box::new(move |_| match acl_probe_path(&probe) {
                Ok(false) => Ok(()),
                Ok(true) => Err("the fixture has an ACL".into()),
                Err(e) => Err(e.to_string()),
            }),
        ));
        rows.push(row(
            "lock+generation".into(),
            vec![],
            Box::new(move |_| lock_row(fd)),
        ));
        rows
    }

    pub fn main() {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let a = match parse(&argv) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("m1-file-costs: {e}\n{USAGE}");
                std::process::exit(2);
            }
        };
        if a.once {
            return once(&a.dir);
        }
        let fx = Fixture::create(&a.dir).unwrap_or_else(|e| fail(format!("fixture: {e}")));
        let fd = open_dir(&fx.0).unwrap_or_else(|e| fail(format!("open the fixture folder: {e}")));
        // Measured before the rounds, outside every clock; recorded on each row.
        let tick = timer_tick_ns();
        let mut rows = rows(&fx.0, fd.as_fd(), &a.dir);
        let mut buf = vec![0u8; BUF];
        drive(rows.len(), a.warmup + a.rounds, |round, i| {
            let r = &mut rows[i];
            if r.failure.is_some() {
                return;
            }
            let t = Instant::now();
            let result = (r.op)(&mut buf);
            let ns = t.elapsed().as_nanos() as u64;
            match result {
                Ok(()) if round >= a.warmup => r.samples.push(ns),
                Ok(()) => {}
                Err(e) => r.failure = Some(format!("{e} (round {})", round + 1)),
            }
        });
        if let Some(r) = rows.iter_mut().find(|r| r.name == "meta/acl") {
            if let (None, Err(e)) = (&r.failure, acl_probe_still_there(&fx.0.join("header"))) {
                r.failure = Some(e);
            }
        }
        for r in &mut rows {
            r.extra.push(("timer_tick_ns", tick.to_string()));
            match &r.failure {
                Some(why) => println!("{}", json_na("file", &r.name, why)),
                None => println!(
                    "{}",
                    json_line("file", &r.name, &summarize(&mut r.samples), &r.extra)
                ),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            Args, Fixture, GENERATION, acl_probe_still_there, lock_row, new_dir, open_dir, parse,
        };
        use std::os::fd::AsFd;

        // 이것을 실패시키는 것: 잠금이 다른 곳에 잡혀 있거나 세대가 다른데 lock+generation을 잰 값으로 세는 것.
        #[test]
        fn held_lock_or_other_generation_is_a_failure() {
            let fx = Fixture(new_dir(&std::env::temp_dir(), "bingsu-lockrow").unwrap());
            let fd = open_dir(&fx.0).unwrap();
            let (lock, header) = (fx.0.join("lock"), fx.0.join("snapshot-header"));
            std::fs::write(&lock, b"").unwrap();
            let mut h = [0u8; 16];
            h[8..].copy_from_slice(&GENERATION.to_le_bytes());
            std::fs::write(&header, h).unwrap();
            assert_eq!(lock_row(fd.as_fd()), Ok(()));
            // flock locks belong to the open file description: a second open
            // in this process conflicts like another process would.
            let holder = std::fs::File::open(&lock).unwrap();
            holder.lock().unwrap();
            let no = Err("not ours, locked or another generation".to_string());
            assert_eq!(lock_row(fd.as_fd()), no);
            drop(holder);
            h[8..].copy_from_slice(&(GENERATION + 1).to_le_bytes());
            std::fs::write(&header, h).unwrap();
            assert_eq!(lock_row(fd.as_fd()), no);
        }

        // 이것을 실패시키는 것: 라운드 뒤 ACL 조회 파일이 없어도 meta/acl을 잰 값으로 두는 것(macOS는 없는 파일도 "ACL 없음").
        #[test]
        fn missing_acl_probe_is_a_failure() {
            let fx = Fixture(new_dir(&std::env::temp_dir(), "bingsu-aclprobe").unwrap());
            let probe = fx.0.join("header");
            std::fs::write(&probe, b"x").unwrap();
            assert_eq!(acl_probe_still_there(&probe), Ok(()));
            std::fs::remove_file(&probe).unwrap();
            let e = acl_probe_still_there(&probe).unwrap_err();
            assert!(e.contains("(after the rounds)"), "{e}");
        }

        // 이것을 실패시키는 것: 이미 있는 폴더 이름을 그대로 쓰는 것(create_dir_all처럼).
        #[test]
        fn new_dir_never_reuses_a_folder() {
            let parent = Fixture(new_dir(&std::env::temp_dir(), "bingsu-newdir").unwrap());
            let a = new_dir(&parent.0, "x").unwrap();
            let b = new_dir(&parent.0, "x").unwrap();
            assert_ne!(a, b);
            assert!(std::fs::read_dir(&a).unwrap().next().is_none());
        }

        fn p(args: &[&str]) -> Result<Args, String> {
            parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        }

        // 이것을 실패시키는 것: 모르는 인자·중복(--once 포함)·값 없음·숫자 아님·0 rounds·--dir 없음·
        // --once와 시간 인자 섞기를 기본값으로 넘기는 것.
        #[test]
        fn parse_fails_closed() {
            let a = p(&["--dir", "/d"]).unwrap();
            assert_eq!((a.rounds, a.warmup, a.once), (1000, 100, false));
            assert!(p(&["--dir", "/d", "--once"]).unwrap().once);
            for bad in [
                &["--dir", "/d", "--bogus"][..],
                &["--dir", "/d", "--dir", "/e"],
                &["--dir", "/d", "--once", "--once"],
                &["--dir"],
                &["--dir", "/d", "--rounds", "x"],
                &["--dir", "/d", "--rounds", "0"],
                &["--rounds", "3"],
                &["--dir", "/d", "--once", "--rounds", "3"],
            ] {
                assert!(p(bad).is_err(), "{bad:?} accepted");
            }
        }
    }
}
