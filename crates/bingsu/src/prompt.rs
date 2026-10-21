//! `bingsu prompt`: the OS adapter, and the trusted computing base (TCB) of
//! the prompt path. It decides nothing: the arguments become bytes,
//! `bingsu_core::front` (pure, `no_std`) parses them and says what to read
//! (`prepare`), the pinned pre-filter reader retains approved descriptors and
//! completed collection slots remain distinct from snapshot slots;
//! `finish` gives the record, which this module writes before it exits. An
//! unwind panic in the core becomes `bingsu_core::front::after_panic`'s
//! record. `main` calls `dispatch` first; every other command gets the
//! arguments back and runs in `crate::commands`, which this module cannot
//! name.
//!
//! The system calls of the prompt are the rows of
//! crates/bingsu/prompt-syscalls.tsv: core-cfg-check --adapter requires the
//! libc names used here to equal its `libc` column, on Linux the seccomp
//! filter allows only its `syscall` column, and the strace test checks the
//! calls the prompt makes.
// Prompt path: the clippy.toml rules (environment reads among them, spec 4
// rule 7, F-01) are forbidden here. Unlike the crate-wide deny, forbid cannot
// be switched off with #[expect] or #[allow]. scripts/check_cli_prompt_forbid.py
// checks this line.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use bingsu_core::front;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

/// The arguments of a command other than `prompt`, for `crate::commands`.
pub struct NonPromptArgs {
    pub argv0: OsString,
    pub args: Vec<OsString>,
}

/// A completed record is the only output attempt. An unwind after even one
/// byte must not append after_panic's second B1 record.
fn write_until(record: &[u8], deadline: front::output::Deadline) -> ! {
    write_guarded(
        record,
        deadline,
        crate::prompt_io::deadline_now,
        write_stdout,
    )
}

fn write_guarded(
    record: &[u8],
    deadline: front::output::Deadline,
    observe: impl FnMut(front::output::Deadline) -> Option<u64>,
    write: impl FnMut(&[u8]) -> front::output::IoResult,
) -> ! {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_loop(record, deadline, observe, write);
    }));
    exit(0)
}

fn write_stdout(buf: &[u8]) -> front::output::IoResult {
    // SAFETY: initialized slice, valid for buf.len() bytes, fixed stdout fd.
    let n = unsafe { libc::write(1, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            front::output::IoResult::Interrupted
        } else {
            front::output::IoResult::Failed
        }
    } else {
        match usize::try_from(n) {
            Ok(n) => front::output::IoResult::Written(n),
            Err(_) => front::output::IoResult::Failed,
        }
    }
}

fn write_loop(
    mut buf: &[u8],
    deadline: front::output::Deadline,
    mut observe: impl FnMut(front::output::Deadline) -> Option<u64>,
    mut write: impl FnMut(&[u8]) -> front::output::IoResult,
) {
    while !buf.is_empty() {
        if observe(deadline).is_none() {
            return;
        }
        let result = write(buf);
        let Some(now) = observe(deadline) else {
            return;
        };
        match front::output::write_decision(buf.len(), result, false, now, deadline.end()) {
            front::output::WriteStep::Continue(n) => buf = &buf[n..],
            front::output::WriteStep::Retry => {}
            front::output::WriteStep::Stop => return,
        }
    }
}

fn exit(code: i32) -> ! {
    // SAFETY: _exit never returns and takes no pointers.
    unsafe { libc::_exit(code) }
}

/// The prompt process. After fail-closed deadline setup, the silent panic hook
/// and unwind guard protect BPF construction, filter installation and the
/// record for a refused filter. The default hook writes to
/// stderr before unwinding (spec section 6 rule 1); this one does nothing.
/// After an unwind panic the record is `front::after_panic`'s; a second
/// panic inside that aborts with rc 101, and the shell draws its own
/// minimal prompt (spec section 6 rule 2). Whether the core runs is
/// `front::runs_core`; after pre-filter preparation, a refused filter
/// (decision P18) supplies only `without_sandbox`: the record-version pair
/// rule and the minimal record, no snapshot decoding or render.
fn run_prompt(
    deadline: Option<front::output::Deadline>,
    args: &[OsString],
    exe: &OsString,
    enter_sandbox: impl FnOnce() -> front::Sandbox,
    respond: impl FnOnce(Vec<u8>) -> Vec<u8>,
    refused: impl FnOnce(&[&[u8]]) -> Vec<u8>,
) -> ! {
    let Some(deadline) = deadline else { exit(0) };
    std::panic::set_hook(Box::new(|_| {}));
    let raw: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    if !crate::prompt_io::arm_deadline(deadline) {
        exit(0)
    }
    let rec = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::prompt_spawn::bootstrap(exe, &raw, Some(deadline));
        let staged = crate::prompt_read::prepare(&raw, deadline);
        if front::runs_core(enter_sandbox()) {
            respond(staged())
        } else {
            refused(&raw)
        }
    }))
    .unwrap_or_else(|_| front::after_panic(&raw));
    write_until(&rec, deadline)
}

/// The first thing `main` does: owns the process arguments, and for
/// `bingsu prompt` never returns. Any other command gets them back.
/// `enter_sandbox` (Linux: the seccomp filter of crates/bingsu/src/sandbox.rs,
/// elsewhere nothing) runs as soon as the command is known to be `prompt`,
/// after the core-directed descriptor preparation and before content reads.
pub fn dispatch(enter_sandbox: fn() -> front::Sandbox) -> NonPromptArgs {
    let deadline = crate::prompt_io::entry_deadline();
    let mut all = std::env::args_os();
    let argv0 = all.next().unwrap_or_default();
    let args: Vec<OsString> = all.collect();
    if args.first().map(|a| a.as_bytes()) == Some(b"prompt".as_slice()) {
        run_prompt(
            deadline,
            &args[1..],
            &argv0,
            enter_sandbox,
            |record| record,
            front::without_sandbox,
        )
    }
    NonPromptArgs { argv0, args }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERNAL: &[u8] = b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1ferror:internal\x1e";
    const SANDBOX: &[u8] = b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fdegraded:sandbox\x1e";

    fn args() -> Vec<OsString> {
        [
            "--ctx", "1", "--record", "B1", "--width", "80", "--shell", "zsh",
        ]
        .iter()
        .map(OsString::from)
        .collect()
    }

    fn panics(_: &[&[u8]]) -> Vec<u8> {
        panic!("injected")
    }

    fn panic_record(_: Vec<u8>) -> Vec<u8> {
        panic!("injected")
    }

    // Children of the tests below: each runs the whole prompt path in its
    // own process, so the parent sees the real stdout, stderr and exit
    // status. Test builds only: the shipped binary has no way to make the
    // core or the filter panic on purpose.
    #[test]
    #[ignore = "child of the prompt path tests"]
    fn core_panics_child() {
        // The unwind runs under the prompt's seccomp filter, as in the shell.
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &args(),
            &OsString::new(),
            crate::sandbox::enter,
            panic_record,
            front::without_sandbox,
        )
    }

    #[test]
    #[ignore = "child of the prompt path tests"]
    fn filter_panics_child() {
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &args(),
            &OsString::new(),
            || panic!("in the filter"),
            |record| record,
            front::without_sandbox,
        )
    }

    #[test]
    #[ignore = "child of the prompt path tests"]
    fn refused_child() {
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &args(),
            &OsString::new(),
            || front::Sandbox::Blocked,
            panic_record,
            front::without_sandbox,
        )
    }

    #[test]
    #[ignore = "child of the prompt path tests"]
    fn refused_record_panics_child() {
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &args(),
            &OsString::new(),
            || front::Sandbox::Blocked,
            |record| record,
            panics,
        )
    }

    #[test]
    #[ignore = "child of the prompt path tests"]
    fn absent_child() {
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &args(),
            &OsString::new(),
            || front::Sandbox::Absent,
            |_| b"<rendered>".to_vec(),
            panics,
        )
    }

    fn helper_args(home: &std::path::Path) -> Vec<OsString> {
        let mut a = args();
        a.extend(
            [
                "--runtime-root=1:2:/r",
                "--config-root=/c",
                "--config-root-written=/c",
                "--state-root=/s",
                "--log-level=info",
            ]
            .map(OsString::from),
        );
        a.push(OsString::from(format!("--home={}", home.display())));
        a
    }
    // 이것을 실패시키는 것: spawn 실패를 sandbox 실패로 바꾸거나 record 출력을 막는 것.
    #[test]
    #[ignore = "isolated prompt entry"]
    fn spawn_failure_child() {
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &helper_args(std::path::Path::new("/h")),
            &OsString::from("/missing-bingsu"),
            || front::Sandbox::Absent,
            |_| b"<rendered>".to_vec(),
            panics,
        )
    }
    // 이것을 실패시키는 것: bootstrap을 필터 뒤로 옮기거나 Blocked일 때 미리 생성하지 않는 것.
    #[test]
    #[ignore = "isolated prompt entry"]
    fn spawn_before_blocked_child() {
        let (base, exe) = crate::commands::n3_test::probe("blocked");
        run_prompt(
            crate::prompt_io::entry_deadline(),
            &helper_args(&base),
            &exe.into_os_string(),
            || {
                // SAFETY: initialized writable storage for a read-only query.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                // SAFETY: valid signal and writable action; does not change disposition.
                let rc = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) };
                assert_eq!(rc, 0);
                assert_eq!(action.sa_sigaction, libc::SIG_IGN);
                front::Sandbox::Blocked
            },
            panic_record,
            front::without_sandbox,
        )
    }
    // 이것을 실패시키는 것: spawn 실패·Blocked의 record 계약 또는 셸 파이프 EOF를 깨는 것.
    #[test]
    fn bootstrap_failure_and_blocked_do_not_delay_the_record() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("spawn_failure_child", b"<rendered>");
        let start = std::time::Instant::now();
        child("spawn_before_blocked_child", SANDBOX);
        assert!(start.elapsed() < std::time::Duration::from_millis(1500));
    }

    fn child(name: &str, want: &[u8]) {
        let me = std::env::current_exe().expect("test binary");
        let out = std::process::Command::new(me)
            .args([
                "--ignored",
                "--exact",
                &format!("prompt::tests::{name}"),
                "--test-threads=1",
                "--nocapture",
                "-q",
            ])
            .output()
            .expect("child");
        assert_eq!(out.status.code(), Some(0), "{name}");
        assert!(
            out.stderr.is_empty(),
            "{name}: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        // --nocapture: a panic message would reach the real stderr. libtest
        // prints its header before the child runs; the record is the last
        // thing written before _exit.
        assert!(
            out.stdout.ends_with(want),
            "{name}: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    // 이것을 실패시키는 것: 조용한 panic hook을 지우는 것(기본 hook이 stderr에 씀), 패닉 뒤 0이 아닌 종료,
    // 폴백 레코드를 쓰지 않거나 다른 상태로 쓰는 것.
    #[test]
    fn panic_fallback_is_silent() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("core_panics_child", INTERNAL);
    }

    // 이것을 실패시키는 것: 필터 설치(BPF 생성 포함)를 panic 보호 밖에서 하는 것.
    #[test]
    fn a_panic_in_the_filter_is_guarded() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("filter_panics_child", INTERNAL);
    }

    // 이것을 실패시키는 것: 거부된 필터에서 core를 부르는 것, degraded:sandbox가 아닌 레코드, 0이 아닌 종료.
    #[test]
    fn no_sandbox_skips_the_core() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("refused_child", SANDBOX);
    }

    // 이것을 실패시키는 것: 거부된 필터의 레코드를 panic 보호 밖에서 만드는 것.
    #[test]
    fn a_panic_in_the_refused_record_is_guarded() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("refused_record_panics_child", INTERNAL);
    }

    // 이것을 실패시키는 것: 커널에 seccomp가 없을 때 core를 건너뛰는 것(WSL1·오래된 커널에서 렌더 안 됨).
    #[test]
    fn no_seccomp_in_the_kernel_renders() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("absent_child", b"<rendered>");
    }
    // 이것을 실패시키는 것: 부분 쓰기·EINTR 뒤 접두부 재출력, 오류·0-byte 재시도.
    #[test]
    fn writer_progress_and_interrupts_use_exact_suffixes() {
        use front::output::IoResult::{Failed, Interrupted, Written};
        let deadline = front::output::Deadline::from_entry(10, 20).unwrap();
        for end in [Failed, Written(0), Written(100)] {
            let mut steps = [Written(2), Interrupted, Written(1), end].into_iter();
            let mut seen = Vec::new();
            write_loop(
                b"abcdef",
                deadline,
                |_| Some(11),
                |buf| {
                    seen.push(buf.to_vec());
                    steps.next().expect("must stop")
                },
            );
            assert_eq!(
                seen,
                [
                    b"abcdef".to_vec(),
                    b"cdef".to_vec(),
                    b"cdef".to_vec(),
                    b"def".to_vec()
                ]
            );
        }
    }

    // 이것을 실패시키는 것: 첫 쓰기·재시도 전 새 시각 검사 누락, 신호 폭주로 마감 연장.
    #[test]
    fn writer_checks_before_every_attempt_and_after_every_result() {
        use front::output::IoResult::{Interrupted, Written};
        let deadline = front::output::Deadline::from_entry(10, 20).unwrap();
        for result in [Written(1), Interrupted] {
            for allowed_observations in 0..=8 {
                let mut samples = 0;
                let mut writes = 0;
                write_loop(
                    b"abcdefghijklmnop",
                    deadline,
                    |_| {
                        samples += 1;
                        (samples <= allowed_observations).then_some(11)
                    },
                    |_| {
                        writes += 1;
                        result
                    },
                );
                assert_eq!(writes, (allowed_observations + 1) / 2);
                assert_eq!(samples, allowed_observations + 1);
            }
        }
    }

    #[test]
    #[ignore = "child: exits after a partial write and injected unwind"]
    fn partial_panic_child() {
        std::panic::set_hook(Box::new(|_| {}));
        let deadline = front::output::Deadline::from_entry(10, 20).unwrap();
        let mut writes = 0;
        write_guarded(
            INTERNAL,
            deadline,
            |_| Some(11),
            |buf| {
                writes += 1;
                if writes == 1 {
                    write_stdout(&buf[..3])
                } else {
                    panic!("after prefix")
                }
            },
        );
    }

    // 이것을 실패시키는 것: 출력 시작 뒤 panic에서 after_panic 레코드를 추가하거나 stderr 출력.
    #[test]
    fn partial_panic_never_appends_another_record() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        child("partial_panic_child", b"B1\x1f");
    }
}
