//! Prints the fds >= 3 this process holds and its session id (the child
//! side of the writer-child probe). `--cgroup` (Linux) adds the first line
//! of /proc/self/cgroup, read after the fds are listed so its own open file
//! is not among them (the child side of the cgroup spawn test).
#![deny(unsafe_code)] // FFI lives in bingsu_bench::sys only

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("m1-fd-report runs on Linux and macOS only");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cgroup = match args.as_slice() {
        [] => false,
        [a] if a == "--cgroup" && cfg!(target_os = "linux") => true,
        _ => {
            eprintln!("usage: m1-fd-report [--cgroup]   (--cgroup on Linux only)");
            std::process::exit(2);
        }
    };
    let (open, sid) = match bingsu_bench::sys::stdio::open_fds_and_sid() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("m1-fd-report: list open fds: {e}");
            std::process::exit(1);
        }
    };
    let list: Vec<String> = open.iter().map(i32::to_string).collect();
    let fds = if list.is_empty() {
        "-".to_string()
    } else {
        list.join(",")
    };
    println!("FDS {fds}\nSID {sid}");
    if cgroup {
        match std::fs::read_to_string("/proc/self/cgroup") {
            Ok(text) => println!("CGROUP {}", text.lines().next().unwrap_or("")),
            Err(e) => {
                eprintln!("m1-fd-report: read /proc/self/cgroup: {e}");
                std::process::exit(1);
            }
        }
    }
}
