//! X-29: what does macOS do with setrlimit(RLIMIT_AS, smaller than now)?
//! The parent measures its own virtual size first, then runs each trial in a
//! separate child: the child reports the setrlimit result, then allocates
//! and touches 512 MiB; the parent classifies the child's exit or signal.
#![deny(unsafe_code)]

#[cfg(not(target_os = "macos"))]
fn main() {
    println!(r#"{{"x":"X-29","na":"macOS only"}}"#);
}

#[cfg(target_os = "macos")]
fn main() {
    imp::main();
}

/// What a trial child's exit and stdout mean. Only the exit status and the
/// child's own lines decide (the allocation failure mode, abort or panic,
/// is not assumed).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn classify(success: bool, out: &str) -> &'static str {
    let rc = out.lines().find_map(|l| {
        l.strip_prefix("setrlimit rc=")?
            .split_whitespace()
            .next()?
            .parse::<i32>()
            .ok()
    });
    let Some(rc) = rc else {
        return "error"; // the child died before it could try
    };
    if !(success && out.lines().any(|l| l.starts_with("alloc-done "))) {
        "limited"
    } else if rc != 0 {
        // A refused setrlimit also lets the allocation succeed.
        "refused"
    } else {
        "not-limited"
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::classify;
    use bingsu_bench::report::escape;
    use bingsu_bench::sys::macos::{get_rlimit_as, set_rlimit_as, virtual_size};
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;

    const USAGE: &str = "usage: m1-macos-rlimit-as";

    fn json_opt(v: Option<i32>) -> String {
        v.map_or_else(|| "null".into(), |n| n.to_string())
    }

    /// `--trial BYTES`: set the soft limit to BYTES, report, then allocate.
    fn trial(bytes: &str) -> i32 {
        let Ok(cur) = bytes.parse::<u64>() else {
            eprintln!("--trial {bytes:?}: not a number");
            return 2;
        };
        let Ok((_, max)) = get_rlimit_as() else {
            eprintln!("getrlimit failed");
            return 5;
        };
        let (rc, errno) = set_rlimit_as(cur, max);
        let after = get_rlimit_as().map_or_else(|e| format!("<{e}>"), |(c, _)| c.to_string());
        println!("setrlimit rc={rc} errno={errno} after_cur={after}");
        if std::io::stdout().flush().is_err() {
            return 5;
        }
        let v = std::hint::black_box(vec![1u8; 512 << 20]);
        let sum: u64 = v.iter().step_by(4096).map(|&b| u64::from(b)).sum();
        println!("alloc-done {}", std::hint::black_box(sum));
        0
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match args.as_slice() {
            [] => {}
            [flag, bytes] if flag == "--trial" => std::process::exit(trial(bytes)),
            _ => {
                eprintln!("{USAGE}");
                std::process::exit(2);
            }
        }
        let me = std::env::current_exe().unwrap_or_else(|e| {
            eprintln!("current_exe: {e}");
            std::process::exit(5);
        });
        let vsize = virtual_size(std::process::id() as libc::pid_t);
        let limits = get_rlimit_as();
        // A value this probe could not read is a quoted "na: reason", never 0.
        let na = |e: &std::io::Error| format!(r#""na: {}""#, escape(&e.to_string()));
        let (cur, max) = match &limits {
            Ok((c, m)) => (c.to_string(), m.to_string()),
            Err(e) => (na(e), na(e)),
        };
        println!(
            r#"{{"x":"X-29","vsize_before":{},"rlimit_cur":{cur},"rlimit_max":{max}}}"#,
            vsize.as_ref().map_or_else(na, u64::to_string),
        );
        let half = vsize.as_ref().ok().map(|v| v / 2);
        for (label, bytes) in [
            ("half-vsize", half),
            ("256MiB", Some(256u64 << 20)),
            ("1GiB", Some(1u64 << 30)),
        ] {
            let Some(bytes) = bytes else {
                println!(r#"{{"x":"X-29","try":"{label}","verdict":"na","na":"no virtual size"}}"#);
                continue;
            };
            let out = match std::process::Command::new(&me)
                .args(["--trial", &bytes.to_string()])
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    println!(
                        r#"{{"x":"X-29","try":"{label}","bytes":{bytes},"verdict":"na","na":"{}"}}"#,
                        escape(&format!("spawn: {e}"))
                    );
                    continue;
                }
            };
            let text = String::from_utf8_lossy(&out.stdout);
            let st = out.status;
            println!(
                r#"{{"x":"X-29","try":"{label}","bytes":{bytes},"child":"{}","exit":{},"signal":{},"verdict":"{}"}}"#,
                escape(text.trim()),
                json_opt(st.code()),
                json_opt(st.signal()),
                classify(st.success(), &text)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::classify;

    // 이것을 실패시키는 것: refused와 not-limited 갈래의 순서를 바꾸는 것(거부된 경우가 not-limited가 됨),
    // rc를 문자열 포함으로 읽어 rc=-10 같은 값이나 setrlimit 줄이 없는 자식을 잘못 분류하는 것.
    #[test]
    fn verdicts() {
        let refused = "setrlimit rc=-1 errno=22 after_cur=9\nalloc-done 524288\n";
        let accepted = "setrlimit rc=0 errno=0 after_cur=268435456\nalloc-done 524288\n";
        assert_eq!(classify(true, refused), "refused");
        assert_eq!(classify(true, accepted), "not-limited");
        assert_eq!(
            classify(false, "setrlimit rc=0 errno=0 after_cur=1\n"),
            "limited"
        );
        assert_eq!(classify(false, accepted), "limited");
        assert_eq!(
            classify(true, "setrlimit rc=0 errno=0 after_cur=1\n"),
            "limited"
        );
        assert_eq!(classify(false, ""), "error");
        assert_eq!(classify(true, "setrlimit rc=x\nalloc-done 1\n"), "error");
        assert_eq!(classify(true, "note rc=-1\nalloc-done 1\n"), "error");
    }
}
