//! Signal handling is per process, so each case runs in a child process
//! (this test binary again, `--exact <case> --ignored`), never in the
//! multithreaded test process. A case plays bingsu. It first unblocks SIGINT
//! and SIGQUIT and sets the handling it needs itself, because a test runner
//! may start it with either blocked or ignored (a shell without job control
//! starts `cmd &` with both ignored).
use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Stdio;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// The write end of the probe's ready pipe, while a case waits for it.
static READY: Mutex<Option<File>> = Mutex::new(None);

/// Called by `run_ignoring_interrupts` right after the ignore: tells the
/// probe it may send its signals now, so the test never races the short gap
/// between the start and the ignore. It checks that the ignore is in place,
/// so a call moved before it fails at once. Test builds only.
pub(super) fn ignored() {
    if let Some(mut ready) = READY.lock().unwrap().take() {
        assert_eq!(action_of(libc::SIGINT).0, libc::SIG_IGN);
        assert_eq!(action_of(libc::SIGQUIT).0, libc::SIG_IGN);
        assert_eq!(ready.write(b"r").unwrap(), 1);
    }
}

static GOT_QUIT: AtomicI32 = AtomicI32::new(0);

extern "C" fn note_quit(sig: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    GOT_QUIT.store(sig, Ordering::SeqCst);
}

/// What sigaction holds for `sig`: handler, flags and the mask's members.
fn action_of(sig: libc::c_int) -> (usize, libc::c_int, Vec<libc::c_int>) {
    // SAFETY: all-zero storage for the action sigaction writes.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: no new action; `current` is writable.
    let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &mut current) };
    assert_eq!(rc, 0);
    let members = (1..32)
        // SAFETY: `sa_mask` is an initialized set and 1..32 are valid signals.
        .filter(|&s| unsafe { libc::sigismember(&current.sa_mask, s) } == 1)
        .collect();
    (current.sa_sigaction, current.sa_flags, members)
}

/// Unblocks SIGINT and SIGQUIT in this (the test) thread and puts SIGINT at
/// its default, as in the product.
fn case_start() {
    // SAFETY: all-zero storage, emptied below.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable.
    unsafe { libc::sigemptyset(&mut set) };
    for sig in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: `set` is initialized and `sig` is a valid signal.
        unsafe { libc::sigaddset(&mut set, sig) };
    }
    // SAFETY: `set` is initialized; only this thread's mask changes.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    // SAFETY: all-zero storage is SIG_DFL with no flags and an empty mask.
    let default: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: valid action; no old action is requested.
    let rc = unsafe { libc::sigaction(libc::SIGINT, &default, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
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

fn run_case(name: &str) {
    let _fds = crate::commands::sys::test_inherited_fd_lock();
    let out = this_test(name).output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && text.contains("1 passed; 0 failed;"),
        "{:?}\n{text}",
        out.status
    );
}

// What fails this:
// - the ignore before the start: the probe inherits SIG_IGN for Ctrl-C;
// - no ignore while waiting, or a restore before the wait: the probe's
//   SIGINT ends the case;
// - SIGQUIT left out: the probe's SIGQUIT reaches the case's handler;
// - no restore afterwards: SIGINT stays SIG_IGN;
// - a restore of the handler alone: SIGQUIT loses its flags and mask;
// - no ready byte after the ignore: the probe gives up waiting; the ready
//   byte before the ignore: the check in `ignored` fails;
// - no unblock at the case start, when the runner blocks both signals: the
//   probe's signals stay pending and a missing ignore goes unseen.
#[test]
fn editor_gets_the_signals_and_bingsu_waits_them_out() {
    run_case("bingsu_case");
}

#[test]
#[ignore = "child of editor_gets_the_signals_and_bingsu_waits_them_out"]
fn bingsu_case() {
    case_start();
    // SAFETY: all-zero storage; handler, flags and mask are set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = note_quit as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
    for sig in [libc::SIGUSR1, libc::SIGTERM] {
        // SAFETY: `sa_mask` is a writable set inside `action`.
        unsafe { libc::sigaddset(&mut action.sa_mask, sig) };
    }
    // SAFETY: valid action; `note_quit` takes the SA_SIGINFO arguments and
    // only stores to an atomic.
    let rc = unsafe { libc::sigaction(libc::SIGQUIT, &action, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let before = [action_of(libc::SIGINT), action_of(libc::SIGQUIT)];
    let (read, write) = crate::commands::collector_process::pipe().unwrap();
    *READY.lock().unwrap() = Some(write);
    let log = std::env::temp_dir().join(format!("bingsu-signal-probe-{}", std::process::id()));
    let mut probe = this_test("editor_probe");
    probe
        .stdin(OwnedFd::from(read))
        .stdout(File::create(&log).unwrap());
    let status = run_ignoring_interrupts(&mut probe).unwrap();
    let printed = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(&log).unwrap();
    assert!(status.success(), "the probe failed: {status:?}\n{printed}");
    // A renamed probe would run no test and still end with success.
    assert!(printed.contains("1 passed; 0 failed;"), "{printed}");
    assert_eq!(GOT_QUIT.load(Ordering::SeqCst), 0, "SIGQUIT reached bingsu");
    assert_eq!([action_of(libc::SIGINT), action_of(libc::SIGQUIT)], before);
}

#[test]
#[ignore = "child of bingsu_case"]
fn editor_probe() {
    // The editor starts with the default handling: the case's caught
    // SIGQUIT handler resets at exec, an inherited SIG_IGN would not.
    assert_eq!(action_of(libc::SIGINT).0, libc::SIG_DFL);
    assert_eq!(action_of(libc::SIGQUIT).0, libc::SIG_DFL);
    let mut p = libc::pollfd {
        fd: std::io::stdin().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for this call.
    let rc = unsafe { libc::poll(&mut p, 1, 10_000) };
    assert_eq!(rc, 1, "no ready byte from the parent");
    let mut byte = [0u8; 1];
    assert_eq!(
        std::io::stdin().read(&mut byte).unwrap(),
        1,
        "no ready byte"
    );
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    // A fixed list, not IGNORED: a signal dropped from that list must
    // still be sent here.
    for sig in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: the parent waits for this process, so its pid is live.
        assert_eq!(unsafe { libc::kill(parent, sig) }, 0);
    }
}

// What fails this: no lock around the call. The second call then starts
// while the first waits, saves its SIG_IGN as the handling before, and puts
// SIG_IGN back after the first has restored the default.
#[test]
fn overlapping_calls_restore_the_handling_before_both() {
    run_case("overlap_case");
}

#[test]
#[ignore = "child of overlapping_calls_restore_the_handling_before_both"]
fn overlap_case() {
    case_start();
    let before = action_of(libc::SIGINT);
    let sleep = |seconds: &str| {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg(seconds).stdin(Stdio::null());
        cmd
    };
    let first = std::thread::spawn(move || run_ignoring_interrupts(&mut sleep("0.3")).unwrap());
    std::thread::sleep(Duration::from_millis(100));
    let second = run_ignoring_interrupts(&mut sleep("0.6")).unwrap();
    assert!(first.join().unwrap().success() && second.success());
    assert_eq!(action_of(libc::SIGINT), before);
}
