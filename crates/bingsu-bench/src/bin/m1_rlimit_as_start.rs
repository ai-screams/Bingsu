//! Linux: VmSize of the collector stub right after its limits, for the
//! "start address space + allowance" RLIMIT_AS rule (spec section 4). Runs
//! the stub with `--mode limits --report-vm` and reads its `VM <KiB>` line.
//! Elsewhere the stub prints `VM unsupported`, so the rows are `na`: a value
//! that is not a number is never counted as 0.
#![deny(unsafe_code)]

use bingsu_bench::report::{escape, json_na};
use bingsu_bench::rounds::drive;
use bingsu_bench::stats::summarize;
use std::process::{Command, Stdio};

const USAGE: &str = "usage: m1-rlimit-as-start --dedicated PATH --same PATH [--runs N]";
const MATRIX: &str = "rlimit_as";

struct Args {
    dedicated: String,
    same: String,
    runs: usize,
}

/// Fails closed: an unknown or repeated option, a missing value, a
/// non-number or zero runs is an error, never a default.
fn parse(args: &[String]) -> Result<Args, String> {
    let mut seen: Vec<&str> = Vec::new();
    let (mut ded, mut same, mut runs) = (None, None, None);
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let slot = match k.as_str() {
            "--dedicated" => &mut ded,
            "--same" => &mut same,
            "--runs" => &mut runs,
            _ => return Err(format!("unknown argument {k:?}")),
        };
        if seen.contains(&k.as_str()) {
            return Err(format!("{k} given twice"));
        }
        seen.push(k);
        *slot = Some(it.next().ok_or(format!("{k} needs a value"))?.clone());
    }
    let runs = match runs {
        None => 50,
        Some(s) => s
            .parse::<usize>()
            .map_err(|e| format!("--runs {s:?}: {e}"))?,
    };
    if runs == 0 {
        return Err("--runs must be at least 1".into());
    }
    Ok(Args {
        dedicated: ded.ok_or("--dedicated PATH is required")?,
        same: same.ok_or("--same PATH is required")?,
        runs,
    })
}

/// The KiB of the stub's first line, `VM <u64>`. Anything else (`VM
/// unknown`, `VM unsupported`, no line) is the reason this run has no value.
fn vm_kib(stdout: &str) -> Result<u64, String> {
    let first = stdout.split('\n').next().unwrap_or("");
    first
        .strip_prefix("VM ")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| format!("stub printed {first:?}, not \"VM <KiB>\""))
}

/// One stub run: its VmSize in KiB, or why there is none (a stub that
/// failed its limits exits 3; its line would not be the start size).
fn run_once(prog: &str, pre: &[&str]) -> Result<u64, String> {
    let out = Command::new(prog)
        .args(pre)
        .args(["--mode", "limits", "--report-vm"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    if !out.status.success() {
        return Err(format!("stub {}", out.status));
    }
    vm_kib(&String::from_utf8_lossy(&out.stdout))
}

struct Row {
    name: &'static str,
    prog: String,
    pre: &'static [&'static str],
    kib: Vec<u64>,
    failure: Option<String>,
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = parse(&argv).unwrap_or_else(|e| {
        eprintln!("{e}\n{USAGE}");
        std::process::exit(2);
    });
    let mut rows = [
        Row {
            name: "dedicated",
            prog: a.dedicated,
            pre: &[],
            kib: Vec::new(),
            failure: None,
        },
        Row {
            name: "same",
            prog: a.same,
            pre: &["__collect-stub"],
            kib: Vec::new(),
            failure: None,
        },
    ];
    drive(rows.len(), a.runs, |round, i| {
        let r = &mut rows[i];
        if r.failure.is_some() {
            return;
        }
        match run_once(&r.prog, r.pre) {
            Ok(k) => r.kib.push(k),
            Err(e) => r.failure = Some(format!("{e} (round {})", round + 1)),
        }
    });
    for r in &mut rows {
        match &r.failure {
            Some(why) => println!("{}", json_na(MATRIX, r.name, why)),
            None => {
                let s = summarize(&mut r.kib);
                println!(
                    r#"{{"matrix":"{MATRIX}","row":"{}","os":"{}","arch":"{}","n":{},"vmsize_kib_median":{},"vmsize_kib_p95":{},"vmsize_kib_min":{},"vmsize_kib_max":{},"stub":"{}"}}"#,
                    r.name,
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    s.n,
                    s.median_ns,
                    s.p95_ns,
                    s.min_ns,
                    s.max_ns,
                    escape(&r.prog)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Args, String> {
        parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    // 이것을 실패시키는 것: 모르는·반복된 옵션, 값 없는 옵션, 0이나 숫자가 아닌 --runs를 받아들이는 것.
    #[test]
    fn parse_fails_closed() {
        let ok = p(&["--dedicated", "a", "--same", "b"]).unwrap();
        assert_eq!(
            (ok.dedicated.as_str(), ok.same.as_str(), ok.runs),
            ("a", "b", 50)
        );
        assert_eq!(
            p(&["--dedicated", "a", "--same", "b", "--runs", "3"])
                .unwrap()
                .runs,
            3
        );
        for bad in [
            &["--dedicated", "a"][..],
            &["--same", "b"],
            &["--dedicated", "a", "--same", "b", "--x", "1"],
            &["--dedicated", "a", "--dedicated", "a", "--same", "b"],
            &["--dedicated", "a", "--same"],
            &["--dedicated", "a", "--same", "b", "--runs", "0"],
            &["--dedicated", "a", "--same", "b", "--runs", "-1"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    // 이것을 실패시키는 것: 숫자가 아닌 VM 값(unknown·unsupported)이나 VM 줄이 없는 출력을 0으로 세는 것.
    #[test]
    fn vm_line() {
        assert_eq!(vm_kib("VM 2048\nR"), Ok(2048));
        assert!(vm_kib("VM unknown\nR").is_err());
        assert!(vm_kib("VM unsupported\nR").is_err());
        assert!(vm_kib("VM \nR").is_err());
        assert!(vm_kib("R").is_err());
        assert!(vm_kib("").is_err());
    }
}
