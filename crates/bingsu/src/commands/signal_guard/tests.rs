//! Signal handling is per process, so the case runs in a child process (this
//! test binary again, `--exact <case> --ignored`), never in the multithreaded
//! test process. The case plays bingsu: SIGINT keeps the default handling,
//! as in the product, and SIGQUIT gets a handler of the case's own, so a
//! restore must put back exactly what was there. It then runs the probe,
//! which plays the editor, through `run_ignoring_interrupts`.
use super::*;
use std::process::Stdio;
use std::sync::atomic::{AtomicI32, Ordering};

static GOT_QUIT: AtomicI32 = AtomicI32::new(0);

extern "C" fn note_quit(sig: libc::c_int) {
    GOT_QUIT.store(sig, Ordering::SeqCst);
}

fn handler_of(sig: libc::c_int) -> usize {
    // SAFETY: all-zero storage for the action sigaction writes.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: no new action; `current` is writable.
    let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &mut current) };
    assert_eq!(rc, 0);
    current.sa_sigaction
}

fn this_test(name: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        &format!("commands::signal_guard::tests::{name}"),
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .stdin(Stdio::null());
    cmd
}

// What fails this:
// - the ignore before the start: the probe inherits SIG_IGN for Ctrl-C;
// - no ignore while waiting: the probe's SIGINT ends the case;
// - SIGQUIT left out: the probe's SIGQUIT reaches the case's handler;
// - no restore afterwards: SIGINT stays SIG_IGN;
// - a restore to the default instead of the saved action: SIGQUIT loses the
//   case's handler.
#[test]
fn editor_gets_the_signals_and_bingsu_waits_them_out() {
    let _fds = crate::commands::sys::test_inherited_fd_lock();
    let out = this_test("bingsu_case").output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && text.contains("1 passed; 0 failed;"),
        "{:?}\n{text}",
        out.status
    );
}

#[test]
#[ignore = "child of editor_gets_the_signals_and_bingsu_waits_them_out"]
fn bingsu_case() {
    // Set, not assumed: a shell without job control starts `cmd &` with
    // SIGINT and SIGQUIT ignored, and the test binary would inherit that.
    // SAFETY: all-zero storage is SIG_DFL with no flags and an empty mask.
    let default: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: valid action; no old action is requested.
    let rc = unsafe { libc::sigaction(libc::SIGINT, &default, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let quit = note_quit as *const () as usize;
    let mut action = default;
    action.sa_sigaction = quit;
    // SAFETY: valid action; `note_quit` only stores to an atomic.
    let rc = unsafe { libc::sigaction(libc::SIGQUIT, &action, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    // The probe's own test summary would read like this case's.
    let mut probe = this_test("editor_probe");
    let status = run_ignoring_interrupts(probe.stdout(Stdio::null())).unwrap();
    assert!(status.success(), "the probe failed: {status:?}");
    assert_eq!(GOT_QUIT.load(Ordering::SeqCst), 0, "SIGQUIT reached bingsu");
    assert_eq!(handler_of(libc::SIGINT), libc::SIG_DFL);
    assert_eq!(handler_of(libc::SIGQUIT), quit);
}

#[test]
#[ignore = "child of bingsu_case"]
fn editor_probe() {
    // The editor starts with the default handling: the case's caught
    // SIGQUIT handler resets at exec, an inherited SIG_IGN would not.
    assert_eq!(handler_of(libc::SIGINT), libc::SIG_DFL);
    assert_eq!(handler_of(libc::SIGQUIT), libc::SIG_DFL);
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    // A fixed list, not IGNORED: a signal dropped from that list must
    // still be sent here.
    for sig in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: the parent waits for this process, so its pid is live.
        assert_eq!(unsafe { libc::kill(parent, sig) }, 0);
    }
}
