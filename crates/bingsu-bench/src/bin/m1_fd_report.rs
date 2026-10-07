//! Prints the fds >= 3 this process holds and its session id (the child
//! side of the writer-child probe).
#![deny(unsafe_code)] // FFI lives in bingsu_bench::sys only

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("m1-fd-report runs on Linux and macOS only");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
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
}
