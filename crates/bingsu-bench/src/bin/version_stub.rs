//! A stand-in language command for the builtin probe tests (plan D3a): a
//! real executable (probes never run a `#!` script) that prints a version
//! line by the name it was copied under, or the contents of `<self>.out`
//! when that file exists, and appends one line to `<self>.runs` per run.
use std::io::Write;

fn main() {
    let Ok(exe) = std::env::current_exe() else {
        std::process::exit(2);
    };
    let with = |suffix: &str| {
        let mut name = exe.clone().into_os_string();
        name.push(suffix);
        std::path::PathBuf::from(name)
    };
    if let Ok(mut runs) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(with(".runs"))
    {
        let _ = runs.write_all(b"x\n");
    }
    let line = match std::fs::read(with(".out")) {
        Ok(text) => text,
        Err(_) => match exe.file_name().and_then(|n| n.to_str()) {
            Some("node") => b"v18.20.4\n".to_vec(),
            Some("python3") => b"Python 3.12.1\n".to_vec(),
            Some("rustc") => b"rustc 1.80.0 (stub 2024-07-21)\n".to_vec(),
            Some("go") => b"go version go1.22.5 stub\n".to_vec(),
            _ => b"stub\n".to_vec(),
        },
    };
    let _ = std::io::stdout().write_all(&line);
}
