fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(bingsu_bench::collector_stub::stub_main(&args));
}
