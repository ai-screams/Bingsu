//! Collector-process stub for the M1 cost matrix. Reproduces only the
//! startup order of spec section 4 ("execution ban" row): limits, then
//! no_new_privs + seccomp (Linux), then the ready byte. Collects nothing.
#![deny(unsafe_code)]
use std::ffi::OsString;

#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;

fn value<'a>(args: &'a [OsString], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.to_str())
}

pub fn stub_main(args: &[OsString]) -> i32 {
    #[cfg(not(unix))]
    {
        let _ = (args, value(args, "--mode"));
        2
    }
    #[cfg(unix)]
    {
        let has = |n: &str| args.iter().any(|a| a == n);
        match value(args, "--mode").unwrap_or("bare") {
            "exit" => return 0,
            "bare" => {}
            "limits" => {
                if sys::set_limits().is_err() {
                    return 3;
                }
            }
            "sandbox" => {
                if sys::set_limits().is_err() || sys::sandbox().is_err() {
                    return 4;
                }
            }
            _ => return 2,
        }
        if has("--probe-exec") {
            sys::probe_exec();
        }
        if has("--probe-clone3") {
            sys::probe_clone3();
        }
        if has("--report-vm") {
            sys::report_vm();
        }
        sys::ready();
        0
    }
}
