#![cfg(unix)]
#[path = "support/process.rs"]
mod process;

use std::{
    io::{self, Write},
    process::Command,
    time::{Duration, Instant},
};

fn command(case: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BINGSU_PROCESS_FIXTURE", case);
    command
}

#[test]
#[ignore = "isolated deadline/pipe fixture"]
fn fixture() {
    println!("\nFIXTURE pid={}", std::process::id());
    match std::env::var("BINGSU_PROCESS_FIXTURE").unwrap().as_str() {
        "sleep" => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        "flood" => {
            let bytes = [b'x'; 8192];
            loop {
                io::stdout().write_all(&bytes).unwrap();
                io::stderr().write_all(&bytes).unwrap();
            }
        }
        "both-pipes" => {
            // More than either pipe's capacity, with distinct terminal markers.
            let bytes = [b'x'; 8192];
            for _ in 0..32 {
                io::stdout().write_all(&bytes).unwrap();
                io::stderr().write_all(&bytes).unwrap();
            }
            println!("\nSTDOUT PASS");
            eprintln!("\nSTDERR PASS");
        }
        case => panic!("unknown fixture {case}"),
    }
}

#[test]
fn both_pipes_are_drained_and_status_preserved() {
    let out = process::output(
        &mut command("both-pipes"),
        "both-pipes",
        process::PROBE_TIMEOUT,
    )
    .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|s| s == "STDOUT PASS")
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .any(|s| s == "STDERR PASS")
    );
}

#[test]
fn sleeping_and_flooding_children_time_out_and_are_reaped() {
    for case in ["sleep", "flood"] {
        let start = Instant::now();
        let error = process::output(&mut command(case), case, Duration::from_secs(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < process::PROBE_TIMEOUT);
        let message = error.to_string();
        assert!(
            message.starts_with(&format!("{case}: timed out")),
            "{message}"
        );
        assert!(
            message.contains("FIXTURE pid="),
            "child never entered its fixture"
        );
        let pid: libc::pid_t = message
            .split("pid=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut status = 0;
        assert_eq!(
            // SAFETY: query only the known child PID with writable status storage.
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        // SAFETY: signal zero only checks existence of the child we just killed.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
