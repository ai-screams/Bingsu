//! Collector-process stub for the M1 cost matrix. Reproduces only the
//! startup order of spec section 4 ("execution ban" row): limits, then
//! no_new_privs + seccomp (Linux), then the ready byte. Collects nothing.
//! The filter content is partial (see `sys::sandbox`), so its install cost
//! is a lower bound for the spec's filter.
#![deny(unsafe_code)]
use std::ffi::OsString;

#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;

#[derive(Debug, Default, PartialEq, Eq)]
struct Opts<'a> {
    mode: Option<&'a str>,
    probe_exec: bool,
    probe_clone3: bool,
    probe_fork: bool,
    probe_x32: bool,
    report_vm: bool,
}

/// Fails closed: a missing or non-UTF-8 `--mode` value, a repeated option
/// or an unknown argument is an error, never the bare default.
fn parse(args: &[OsString]) -> Option<Opts<'_>> {
    let mut o = Opts::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let flag = match a.to_str()? {
            "--mode" => {
                if o.mode.replace(it.next()?.to_str()?).is_some() {
                    return None;
                }
                continue;
            }
            "--probe-exec" => &mut o.probe_exec,
            "--probe-clone3" => &mut o.probe_clone3,
            "--probe-fork" => &mut o.probe_fork,
            "--probe-x32" => &mut o.probe_x32,
            "--report-vm" => &mut o.report_vm,
            _ => return None,
        };
        if std::mem::replace(flag, true) {
            return None;
        }
    }
    Some(o)
}

/// Probes that only mean something on some platforms are refused elsewhere
/// rather than run as a no-op, so a harness that asks for one there sees
/// exit 2 instead of a plain `R`: clone3 on Linux; the legacy fork/vfork
/// and x32 calls on x86_64 Linux.
fn probes_supported(o: &Opts<'_>) -> bool {
    let linux = cfg!(target_os = "linux");
    let x86_64_linux = cfg!(all(target_os = "linux", target_arch = "x86_64"));
    (!o.probe_clone3 || linux) && (!(o.probe_fork || o.probe_x32) || x86_64_linux)
}

/// Exit codes: 0 ready, 2 bad arguments, 3 limits failed, 4 sandbox failed
/// or unsupported, 5 writing to stdout failed. `--probe-fork` is accepted in
/// sandbox mode only: unfiltered, its raw `vfork` would share this stack.
pub fn stub_main(args: &[OsString]) -> i32 {
    let Some(o) = parse(args) else { return 2 };
    if !probes_supported(&o) || (o.probe_fork && o.mode != Some("sandbox")) {
        return 2;
    }
    #[cfg(not(unix))]
    {
        let _ = o;
        2
    }
    #[cfg(unix)]
    {
        match o.mode.unwrap_or("bare") {
            "exit" => return 0,
            "bare" => {}
            "limits" => {
                if sys::set_limits().is_err() {
                    return 3;
                }
            }
            "sandbox" => {
                if sys::set_limits().is_err() {
                    return 3;
                }
                if sys::sandbox().is_err() {
                    return 4;
                }
            }
            _ => return 2,
        }
        let mut out = Ok(());
        for (on, probe) in [
            (o.probe_exec, sys::probe_exec as fn() -> std::io::Result<()>),
            (o.probe_clone3, sys::probe_clone3),
            (o.probe_fork, sys::probe_fork),
            (o.probe_x32, sys::probe_x32),
            (o.report_vm, sys::report_vm),
        ] {
            if on {
                out = out.and_then(|()| probe());
            }
        }
        match out.and_then(|()| sys::ready()) {
            Ok(()) => 0,
            Err(_) => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Option<Opts<'static>> {
        let v: Vec<OsString> = args.iter().map(OsString::from).collect();
        // Leaked so the borrowed result can outlive this helper in a test.
        parse(Vec::leak(v))
    }

    // 이것을 실패시키는 것: 값 없는 --mode·반복된 옵션·모르는 인자를 받아들이는 것(fail-open).
    #[test]
    fn parse_fails_closed() {
        assert_eq!(p(&[]), Some(Opts::default()));
        let all = Opts {
            mode: Some("sandbox"),
            probe_exec: true,
            probe_clone3: true,
            probe_fork: true,
            probe_x32: true,
            report_vm: true,
        };
        let full = [
            "--probe-fork",
            "--mode",
            "sandbox",
            "--report-vm",
            "--probe-exec",
            "--probe-clone3",
            "--probe-x32",
        ];
        assert_eq!(p(&full), Some(all));
        assert_eq!(p(&["--mode"]), None);
        assert_eq!(p(&["--mode", "bare", "--mode", "bare"]), None);
        assert_eq!(p(&["--report-vm", "--report-vm"]), None);
        assert_eq!(p(&["--nope"]), None);
    }

    // 이것을 실패시키는 것: non-UTF-8 값을 건너뛰고 기본 모드로 가는 것.
    #[cfg(unix)]
    #[test]
    fn parse_rejects_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0xff]);
        assert_eq!(parse(&[OsString::from("--mode"), bad.clone()]), None);
        assert_eq!(parse(&[bad]), None);
    }
}
