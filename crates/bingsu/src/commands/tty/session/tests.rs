use super::*;
use crate::commands::tty::tests::pty::{
    Pty, SESSION_SIGNALS, disposition, masked, mode, say, start_test, take_terminal, wait_queued,
};
use crate::commands::tty::{CANCEL, test_terminal};
use std::os::unix::process::ExitStatusExt;

const ENTER_ALL: &[u8] =
    b"\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l";
const LEAVE_ALL: &[u8] = b"\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l";
const LEAVE_SYNCED: &[u8] = b"\x1b[?2026l\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l";
const WAIT: Duration = Duration::from_secs(5);

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn shown(bytes: &[u8]) -> String {
    bytes.escape_ascii().to_string()
}

/// The child test `name` of this module on a new pseudo-terminal, started
/// with the session's signals blocked (`masked`): the child lets them
/// through on its own thread (`take_signals`), so libtest's other threads
/// never take them, as in a bingsu with one thread.
fn start(name: &str, env: &[(&str, &str)]) -> Pty {
    start_test(
        &format!("commands::tty::session::tests::{name}"),
        80,
        24,
        env,
        true,
    )
}

/// In a child started masked: the session's signals came blocked to this
/// thread, and are let through on it.
/// 이것을 실패시키는 것: 자식을 masked 없이 띄우는 것(다른 스레드가 신호를 받아 순서가 흔들림; 이 assert).
fn take_signals() {
    // SAFETY: an all-zero `sigset_t` is valid storage for the call to fill.
    let mut now: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: a null new set only reads this thread's mask into `now`.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut now) };
    assert_eq!(rc, 0);
    // SAFETY: an all-zero `sigset_t` is valid storage for sigemptyset.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a valid set.
    unsafe { libc::sigemptyset(&mut set) };
    for sig in SESSION_SIGNALS {
        // SAFETY: `now` was filled by pthread_sigmask.
        let blocked = unsafe { libc::sigismember(&now, sig) };
        assert_eq!(blocked, 1, "signal {sig} was not blocked");
        // SAFETY: `set` is a valid set.
        unsafe { libc::sigaddset(&mut set, sig) };
    }
    // SAFETY: `set` is valid; this thread's mask only.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

/// A parameter the parent test gave the child.
#[allow(
    clippy::disallowed_methods,
    reason = "test parameter from the parent test, never production input"
)]
fn param(name: &str) -> String {
    std::env::var(name).unwrap()
}

/// A parameter the parent test may have given the child.
#[allow(
    clippy::disallowed_methods,
    reason = "test parameter from the parent test, never production input"
)]
fn param_if_given(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn signal_named(name: &str) -> libc::c_int {
    match name {
        "INT" => libc::SIGINT,
        "TERM" => libc::SIGTERM,
        "HUP" => libc::SIGHUP,
        "TSTP" => libc::SIGTSTP,
        _ => panic!("{name}"),
    }
}

/// Writes one frame through `write_some`, waiting for room.
fn draw(s: &mut Session<'_>, text: &[u8]) {
    let frame = cat(&[b"\x1b[H\x1b[2J", text]);
    let mut rest = &frame[..];
    let until = Instant::now() + WAIT;
    while !rest.is_empty() {
        let n = s.write_some(rest).unwrap();
        rest = &rest[n..];
        if !rest.is_empty() {
            match s.wait(true, Some(until)) {
                Event::Writable => {}
                e => panic!("{e:?}"),
            }
        }
    }
}

// 이것을 실패시키는 것: 켠 모드 하나라도 되돌리지 않는 것, 되돌리는 차례를 바꾸는 것(SGR reset이 2004l 뒤,
// 1049l이 25h 앞), 켜지 않은 2026을 끄는 것, 켜지 않았는데 SGR reset을 보내는 것.
#[test]
fn leaving_puts_back_only_what_is_on_in_order() {
    let order: [(u8, &[u8]); 5] = [
        (SYNC, b"\x1b[?2026l"),
        (0, b"\x1b[0m"),
        (PASTE, b"\x1b[?2004l"),
        (HIDDEN, b"\x1b[?25h"),
        (ALT, b"\x1b[?1049l"),
    ];
    for modes in 0..16u8 {
        let want: Vec<u8> = order
            .iter()
            .filter(|(bit, _)| {
                if *bit == 0 {
                    modes != 0
                } else {
                    modes & bit != 0
                }
            })
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        assert_eq!(shown(&leave_bytes(modes)), shown(&want), "{modes:#06b}");
    }
    assert_eq!(leave_bytes(ALT | HIDDEN | PASTE), LEAVE_ALL);
}

#[test]
fn descriptors_that_fit_select() {
    let size = RawFd::try_from(libc::FD_SETSIZE).unwrap();
    assert!(fits_select(0));
    assert!(fits_select(size - 1));
    assert!(!fits_select(size));
    assert!(!fits_select(-1));
}

fn fd_flag(fd: RawFd, get: libc::c_int) -> libc::c_int {
    // SAFETY: `fd` is open; F_GETFD and F_GETFL only read flags.
    unsafe { libc::fcntl(fd, get) }
}

// 이것을 실패시키는 것: pipe 끝 하나라도 O_NONBLOCK이 아닌 것(처리기의 write가 꽉 찬 pipe에서 막힘), 하나라도
// FD_CLOEXEC가 아닌 것(편집기 같은 자식이 깨우기 pipe를 물려받음), 부를 때마다 새 pipe를 만드는 것.
#[test]
fn the_wake_pipe_is_non_blocking_closed_on_exec_and_made_once() {
    let _one = WAKE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let read = wake_pipe().unwrap();
    let ends = PIPE.lock().unwrap().unwrap();
    assert_eq!(ends.0, read);
    assert_eq!(WAKE.load(Ordering::SeqCst), ends.1);
    for fd in [ends.0, ends.1] {
        assert_ne!(fd_flag(fd, libc::F_GETFL) & libc::O_NONBLOCK, 0, "{fd}");
        assert_ne!(fd_flag(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0, "{fd}");
    }
    assert_eq!(wake_pipe().unwrap(), read);
    assert_eq!(PIPE.lock().unwrap().unwrap(), ends);
}

/// The tests here that set `WAKE` in this process, one at a time.
static WAKE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The bytes a pipe holds.
fn queued(fd: RawFd) -> usize {
    let mut n: libc::c_int = 0;
    // SAFETY: `fd` is open; `n` is a writable int.
    assert_eq!(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) }, 0);
    usize::try_from(n).unwrap()
}

// A handler's write fails with EAGAIN on a full pipe; errno must be what the
// interrupted code left. 이것을 실패시키는 것: wake가 errno를 되돌리지 않는 것, 자리가 있는데 바이트를 쓰지 않는 것.
#[test]
fn waking_writes_one_byte_and_keeps_errno() {
    let (r, w) = super::super::sys::nonblocking_pipe().unwrap();
    let (read, write) = (r.as_raw_fd(), w.as_raw_fd());
    let errno = super::super::sys::errno_location();
    // This process makes no session (they run in children) and installs no
    // handler, so nothing else writes there meanwhile.
    let _one = WAKE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let was = WAKE.swap(write, Ordering::SeqCst);
    super::super::wake();
    assert_eq!(queued(read), 1);
    let chunk = [0u8; 4096];
    // SAFETY: `write` is the open pipe end; `chunk` is readable.
    while unsafe { libc::write(write, chunk.as_ptr().cast(), chunk.len()) } > 0 {}
    // SAFETY: errno is this thread's slot.
    unsafe { *errno = libc::EDOM };
    let full = queued(read);
    super::super::wake();
    // SAFETY: as above.
    let after = unsafe { *errno };
    WAKE.store(was, Ordering::SeqCst);
    assert_eq!(queued(read), full, "the pipe was full");
    assert_eq!(after, libc::EDOM);
}

// 이것을 실패시키는 것: 모드를 켜고 그리고 되돌리는 열이 하나라도 다르거나 차례가 바뀌는 것, 끝난 뒤 termios나
// O_NONBLOCK을 되돌리지 않는 것.
#[test]
fn entering_and_leaving_put_every_mode_back_in_order() {
    let t = start("enter_leave_child", &[]);
    let restored = t.mode_restored_after();
    let (lines, all) = restored;
    assert_eq!(
        lines,
        [
            "size 80x24",
            "restored true",
            "flags restored true",
            "handlers back true"
        ]
    );
    assert_eq!(
        shown(&all),
        shown(&cat(&[ENTER_ALL, b"\x1b[H\x1b[2JHELLO", LEAVE_ALL]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn enter_leave_child() {
    take_signals();
    let tty = take_terminal();
    let before = mode();
    let flags = fd_flag(tty.file.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK;
    let handlers = || JOB_SIGNALS.map(disposition);
    let handlers_before = handlers();
    {
        let mut s = tty.full_screen().unwrap();
        say(&format!("size {}x{}", s.size().cols, s.size().rows));
        draw(&mut s, b"HELLO");
    }
    say(&format!("restored {}", mode() == before));
    say(&format!(
        "flags restored {}",
        fd_flag(tty.file.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK == flags
    ));
    say(&format!("handlers back {}", handlers() == handlers_before));
}

impl Pty {
    /// `finish`, and whether the terminal's mode is the one from before.
    fn mode_restored_after(mut self) -> (Vec<String>, Vec<u8>) {
        let (lines, status, out, err) = self.end();
        assert!(status.success(), "{lines:?} {out}\n{err}");
        assert!(self.mode_restored(), "the mode is back");
        (lines, std::mem::take(&mut self.all))
    }
}

/// A signal at one stage (`BINGSU_TEST_STAGE`): `entering` (after the
/// alternate screen went on), `idle` (between the flag check and the
/// select), `writing` (a frame cut after 3 bytes).
#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn stage_child() {
    take_signals();
    let sig = signal_named(&param("BINGSU_TEST_SIGNAL"));
    let tty = take_terminal();
    match param("BINGSU_TEST_STAGE").as_str() {
        "entering" => {
            test_session::AFTER_STEP.set(Some((0, sig)));
            // SIGINT, SIGTERM, SIGHUP: the failed entry's drop raises the
            // signal again, so no line. SIGTSTP: the entry goes on, and the
            // first wait stops.
            if let Ok(mut s) = tty.full_screen() {
                say(&format!("{:?}", s.wait(false, Some(Instant::now() + WAIT))));
            }
        }
        "idle" => {
            let mut s = tty.full_screen().unwrap();
            test_session::BEFORE_SELECT.set(Some(sig));
            say(&format!("{:?}", s.wait(false, None)));
        }
        "writing" => {
            let mut s = tty.full_screen().unwrap();
            s.mark_synced(true);
            let mut frame = b"\x1b[?2026h".to_vec();
            frame.resize(64 << 10, b'x');
            frame.extend_from_slice(b"END\x1b[?2026l");
            // The terminal takes 3 bytes and then nothing, as the writer
            // tries again.
            test_terminal::ROOM.set(Some((3, test_terminal::Then::Stall)));
            let took = s.write_some(&frame).unwrap();
            let again = s.write_some(&frame[took..]).unwrap();
            say(&format!("took {took} then {again}"));
            test_terminal::ROOM.set(None);
            test_session::BEFORE_SELECT.set(Some(sig));
            say(&format!("{:?}", s.wait(true, None)));
        }
        "untaken" => {
            let mut s = tty.full_screen().unwrap();
            s.mark_synced(true);
            // The terminal takes nothing of the frame.
            test_terminal::ROOM.set(Some((0, test_terminal::Then::Stall)));
            say(&format!("took {}", s.write_some(b"\x1b[?2026hX").unwrap()));
            test_terminal::ROOM.set(None);
            test_session::BEFORE_SELECT.set(Some(sig));
            say(&format!("{:?}", s.wait(true, None)));
        }
        stage => panic!("{stage}"),
    }
}

// 신호가 어느 단계에 와도: 들어가는 중(1049h 뒤)이면 켠 것(1049)만, 기다리는 중이면 모두, 프레임을 쓰다 만 중이면
// escape를 끊고(CANCEL) 2026까지 되돌리고, termios를 되돌린 뒤 그 신호로 끝난다.
// 이것을 실패시키는 것: 들어가는 동안 온 신호를 보지 않는 것(25l·2004h가 나감), 켜지 않은 모드를 되돌리는 것,
// 깃발을 본 뒤 select 사이에 온 신호를 놓치는 것(깨우기 바이트가 없으면 마감 없는 select에서 멈춤), 끊긴 프레임에
// CANCEL을 보내지 않는 것, 2026을 끄지 않는 것, termios를 되돌리지 않는 것, 신호를 다시 올리지 않는 것.
#[test]
fn a_signal_at_any_stage_puts_the_terminal_back() {
    for stage in ["entering", "idle", "writing"] {
        for name in ["INT", "TERM", "HUP"] {
            let sig = signal_named(name);
            let mut t = start(
                "stage_child",
                &[("BINGSU_TEST_STAGE", stage), ("BINGSU_TEST_SIGNAL", name)],
            );
            let want = match stage {
                "entering" => cat(&[b"\x1b[?1049h", b"\x1b[0m\x1b[?1049l"]),
                "idle" => cat(&[ENTER_ALL, LEAVE_ALL]),
                _ => {
                    t.expect(&cat(&[ENTER_ALL, b"\x1b[?"]));
                    t.send(&[test_terminal::READ]);
                    cat(&[ENTER_ALL, b"\x1b[?", CANCEL, LEAVE_SYNCED])
                }
            };
            let (lines, status, out, err) = t.end();
            assert_eq!(status.signal(), Some(sig), "{stage} {name}: {out}\n{err}");
            assert!(t.mode_restored(), "{stage} {name}");
            assert_eq!(shown(&t.all), shown(&want), "{stage} {name}");
            let said = match stage {
                "entering" => vec![],
                "idle" => vec![format!("Signal({sig})")],
                _ => vec!["took 3 then 0".to_owned(), format!("Signal({sig})")],
            };
            assert_eq!(lines, said, "{stage} {name}");
        }
    }
}

// A frame the terminal took nothing of is not cut: no CANCEL before the way
// out (synchronized output still goes off). 이것을 실패시키는 것: 받지 않은 쓰기를 끊긴 프레임으로 치는 것.
#[test]
fn a_frame_the_terminal_took_nothing_of_is_not_cancelled() {
    let t = start(
        "stage_child",
        &[
            ("BINGSU_TEST_STAGE", "untaken"),
            ("BINGSU_TEST_SIGNAL", "TERM"),
        ],
    );
    let mut t = t;
    let (lines, status, out, err) = t.end();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{out}\n{err}");
    assert_eq!(
        lines,
        ["took 0".to_owned(), format!("Signal({})", libc::SIGTERM)]
    );
    assert_eq!(shown(&t.all), shown(&cat(&[ENTER_ALL, LEAVE_SYNCED])));
}

// The terminal takes the first 3 bytes of the alternate screen's switch and
// then nothing: the entry fails, and what went out is ended and put back.
// 이것을 실패시키는 것: 모드를 쓴 뒤에야 켬으로 기록하는 것(반쯤 나간 1049h를 되돌리지 않음), 반쯤 나간 쓰기를
// 끊지 않는 것(CANCEL이 빠짐), 들어가기에 실패하고도 termios를 되돌리지 않는 것.
#[test]
fn an_entry_the_terminal_stopped_taking_is_put_back() {
    let mut t = start("partial_entry_child", &[]);
    t.expect(b"\x1b[?");
    t.send(&[test_terminal::READ]);
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["entry Some(TimedOut)", "restored true"]);
    assert_eq!(
        shown(&all),
        shown(&cat(&[b"\x1b[?", CANCEL, b"\x1b[0m\x1b[?1049l"]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn partial_entry_child() {
    take_signals();
    let tty = take_terminal();
    let before = mode();
    test_terminal::ROOM.set(Some((3, test_terminal::Then::Stall)));
    say(&format!(
        "entry {:?}",
        tty.full_screen().err().map(|e| e.kind())
    ));
    say(&format!("restored {}", mode() == before));
}

// A terminal that is slow, not stuck: a frame waits for room and goes on.
// 이것을 실패시키는 것: write를 청해도 tty를 쓰기 집합에 넣지 않는 것(Writable이 오지 않고 마감에 Timeout).
#[test]
fn a_frame_waits_for_room_and_goes_on() {
    let mut t = start("slow_terminal_child", &[]);
    assert!(!t.wait_unread(Duration::from_millis(300)));
    t.expect(b"FRAME");
    let (lines, _) = t.mode_restored_after();
    assert_eq!(lines, ["took 0", "Writable", "took 5"]);
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn slow_terminal_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    crate::commands::tty::tests::pty::fill_output();
    say(&format!("took {}", s.write_some(b"FRAME").unwrap()));
    say(&format!("{:?}", s.wait(true, Some(Instant::now() + WAIT))));
    say(&format!("took {}", s.write_some(b"FRAME").unwrap()));
}

// SIGSTOP (no handler can run before it), seen stopped, then SIGCONT: the
// terminal is put back first and then taken again, and the caller is told
// to draw again. 이것을 실패시키는 것: 제 정지가 아닌 재개에서 먼저 되돌리지 않는 것(모드를 두 번 켬), 다시 잡지
// 않는 것.
#[test]
fn a_continue_after_a_sigstop_takes_the_terminal_again() {
    let mut t = start("continued_child", &[]);
    t.expect(b"READY");
    // SAFETY: stops the child this test started.
    assert_eq!(unsafe { libc::kill(t.pid(), libc::SIGSTOP) }, 0);
    let (_, status) = wait_for(t.pid(), libc::WUNTRACED);
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP,
        "the child did not stop (status {status:#x}): {}",
        shown(&t.all)
    );
    // SAFETY: as above, continues it.
    assert_eq!(unsafe { libc::kill(t.pid(), libc::SIGCONT) }, 0);
    continued(t);
}

// A SIGCONT with no stop at all is taken the same way: the session cannot
// tell it from the end of a stop it did not see.
// 이것을 실패시키는 것: 제 정지가 아닌 재개에서 먼저 되돌리지 않는 것, 다시 잡지 않는 것.
#[test]
fn a_lone_continue_takes_the_terminal_again() {
    let mut t = start("continued_child", &[]);
    t.expect(b"READY");
    // SAFETY: continues the child this test started, which runs.
    assert_eq!(unsafe { libc::kill(t.pid(), libc::SIGCONT) }, 0);
    continued(t);
}

/// The rest of the two tests above.
fn continued(mut t: Pty) {
    t.expect(b"AGAIN");
    t.send(b"q");
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["Resumed(Size { cols: 80, rows: 24 })"]);
    assert_eq!(
        shown(&all),
        shown(&cat(&[
            ENTER_ALL,
            b"\x1b[H\x1b[2JREADY",
            LEAVE_ALL,
            ENTER_ALL,
            b"\x1b[H\x1b[2JAGAIN",
            LEAVE_ALL
        ]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn continued_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    draw(&mut s, b"READY");
    loop {
        match s.wait(false, Some(Instant::now() + WAIT)) {
            e @ Event::Resumed(_) => {
                say(&format!("{e:?}"));
                draw(&mut s, b"AGAIN");
            }
            Event::Input(b"q") => break,
            e => panic!("{e:?}"),
        }
    }
}

// A stop in an orphaned process group (this child is a session leader whose
// parent is in another session): the kernel drops SIGTSTP, the call returns
// at once, and the session comes back; at the entry too (the job handlers are
// in before the modes). 이것을 실패시키는 것: 멈추기 전에 터미널을 되돌리지 않는 것, 멈춘 뒤
// 신호(SIGCONT)를 기다리는 것(여기서는 오지 않아 멈춤), 돌아와서 모드를 다시 켜지 않는 것, Resumed를 알리지 않는 것,
// 끊긴 프레임을 끊지 않는 것, 들어가는 중에 온 SIGTSTP를 보지 않는 것.
#[test]
fn a_stop_the_kernel_drops_comes_back_at_once() {
    for stage in ["entering", "idle", "writing"] {
        let mut t = start(
            "stage_child",
            &[("BINGSU_TEST_STAGE", stage), ("BINGSU_TEST_SIGNAL", "TSTP")],
        );
        let want = if stage != "writing" {
            cat(&[ENTER_ALL, LEAVE_ALL, ENTER_ALL, LEAVE_ALL])
        } else {
            t.expect(&cat(&[ENTER_ALL, b"\x1b[?"]));
            t.send(&[test_terminal::READ]);
            cat(&[
                ENTER_ALL,
                b"\x1b[?",
                CANCEL,
                LEAVE_SYNCED,
                ENTER_ALL,
                LEAVE_ALL,
            ])
        };
        let (lines, all) = t.mode_restored_after();
        assert_eq!(shown(&all), shown(&want), "{stage}");
        assert_eq!(
            lines.last().map(String::as_str),
            Some("Resumed(Size { cols: 80, rows: 24 })"),
            "{stage}"
        );
    }
}

// Taking the terminal again after a stop (here one the kernel drops, in
// this orphaned process group) fails: the terminal takes 3 bytes of the
// alternate screen's switch and then nothing (`partial`), nothing at all
// (`timeout`), or the write fails (`eio`). What went out is ended and put
// back and the session ends with `Hangup`, or with the SIGTERM that came
// as it put things back (`failsignal`). A SIGTERM while taking it again
// (`signal`) ends it with that signal, with no `Resumed`.
// 이것을 실패시키는 것: 실패해도 Resumed를 알리는 것, 반쯤 켠 모드를 되돌리지 않는 것, 끝내지 않는 것, 받은 종료 신호보다
// Hangup을 먼저 알리는 것, 들어가는 중 온 종료 신호에도 Resumed를 알리는 것, 쓰기 오류에도 자리를 기다리는 것(eio의 waits).
#[test]
fn a_failed_reentry_ends_the_session() {
    let again = cat(&[ENTER_ALL, LEAVE_ALL]);
    let back = b"\x1b[0m\x1b[?1049l".as_slice();
    for case in ["partial", "timeout", "eio", "signal", "failsignal"] {
        let mut t = start("reentry_child", &[("BINGSU_TEST_REENTRY", case)]);
        let want = match case {
            "partial" => {
                t.expect(&cat(&[&again, b"\x1b[?"]));
                t.send(&[test_terminal::READ]);
                cat(&[&again, b"\x1b[?", CANCEL, back])
            }
            "signal" => cat(&[&again, b"\x1b[?1049h", back]),
            _ => cat(&[&again, back]),
        };
        let (lines, status, out, err) = t.end();
        assert!(t.mode_restored(), "{case}");
        assert_eq!(shown(&t.all), shown(&want), "{case}");
        let event = lines.first().cloned().unwrap_or_default();
        if case == "signal" || case == "failsignal" {
            assert_eq!(status.signal(), Some(libc::SIGTERM), "{case}: {out}\n{err}");
            assert_eq!(event, format!("Signal({})", libc::SIGTERM), "{case}");
        } else {
            assert!(status.success(), "{case}: {out}\n{err}");
            assert_eq!(event, "Hangup", "{case}");
        }
        // The timeout waits for room (to the write limit); the failed write
        // ends without a wait. (`end` bounds the whole run.)
        let waits: usize = lines[1].strip_prefix("waits ").unwrap().parse().unwrap();
        match case {
            "timeout" => assert!(waits >= 1, "{waits}"),
            "eio" => assert_eq!(waits, 0),
            _ => {}
        }
    }
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn reentry_child() {
    take_signals();
    use test_terminal::Then;
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    match param("BINGSU_TEST_REENTRY").as_str() {
        "partial" => test_session::REENTRY_ROOM.set(Some((3, Then::Stall))),
        "timeout" => test_session::REENTRY_ROOM.set(Some((0, Then::Stall))),
        "eio" => test_session::REENTRY_ROOM.set(Some((0, Then::Fail))),
        "signal" => test_session::REENTRY_STEP.set(Some((0, libc::SIGTERM))),
        "failsignal" => {
            test_session::REENTRY_ROOM.set(Some((0, Then::Stall)));
            test_session::REENTRY_LEAVE.set([libc::SIGTERM, 0]);
        }
        case => panic!("{case}"),
    }
    test_session::BEFORE_SELECT.set(Some(libc::SIGTSTP));
    test_session::ROOM_WAITS.set(0);
    let event = format!("{:?}", s.wait(false, Some(Instant::now() + WAIT)));
    say(&event);
    say(&format!("waits {}", test_session::ROOM_WAITS.get()));
}

// Ctrl-Z as the key (0x1a, ISIG is off): `suspend` stops the process group;
// in this orphaned group the stop is dropped and the session comes back.
// 이것을 실패시키는 것: suspend가 터미널을 되돌리지 않거나 다시 잡지 않는 것.
#[test]
fn ctrl_z_puts_the_terminal_back_and_takes_it_again() {
    let mut t = start("ctrl_z_child", &[]);
    t.expect(ENTER_ALL);
    t.send(b"\x1a");
    t.expect(b"AGAIN");
    t.send(b"q");
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["resumed", "typed q"]);
    assert_eq!(
        shown(&all),
        shown(&cat(&[
            ENTER_ALL,
            LEAVE_ALL,
            ENTER_ALL,
            b"\x1b[H\x1b[2JAGAIN",
            LEAVE_ALL
        ]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn ctrl_z_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    loop {
        match s.wait(false, Some(Instant::now() + WAIT)) {
            Event::Input(b"\x1a") => s.suspend(),
            Event::Resumed(_) => {
                say("resumed");
                draw(&mut s, b"AGAIN");
            }
            Event::Input(b"q") => {
                say("typed q");
                break;
            }
            e => panic!("{e:?}"),
        }
    }
}

// SIGTSTP ignored when the session began (a parent that does not want its
// child stopped): it stays ignored, and Ctrl-Z does nothing.
// 이것을 실패시키는 것: 무시하던 SIGTSTP에 처리기를 거는 것, suspend가 그래도 터미널을 되돌리고 멈추는 것, 끝난
// 뒤 SIG_IGN을 되돌리지 않는 것.
#[test]
fn an_ignored_stop_stays_ignored() {
    let t = start("ignored_stop_child", &[]);
    let (lines, all) = t.mode_restored_after();
    assert_eq!(
        lines,
        ["ignored during true", "Timeout", "ignored after true"]
    );
    assert_eq!(shown(&all), shown(&cat(&[ENTER_ALL, LEAVE_ALL])));
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn ignored_stop_child() {
    take_signals();
    // SAFETY: sets this process's SIGTSTP disposition to ignore.
    unsafe { libc::signal(libc::SIGTSTP, libc::SIG_IGN) };
    let tty = take_terminal();
    {
        let mut s = tty.full_screen().unwrap();
        say(&format!(
            "ignored during {}",
            disposition(libc::SIGTSTP) == libc::SIG_IGN
        ));
        s.suspend();
        // SAFETY: raises SIGTSTP in this process, which ignores it.
        unsafe { libc::raise(libc::SIGTSTP) };
        say(&format!(
            "{:?}",
            s.wait(false, Some(Instant::now() + Duration::from_millis(100)))
        ));
    }
    say(&format!(
        "ignored after {}",
        disposition(libc::SIGTSTP) == libc::SIG_IGN
    ));
}

// SIGTSTP blocked in the thread's mask when the session began: taken as
// ignored, so Ctrl-Z does nothing and no handler is put on it.
// 이것을 실패시키는 것: 막아 둔 SIGTSTP에 처리기를 거는 것(suspend가 되돌리고 바로 다시 잡음).
#[test]
fn a_blocked_stop_counts_as_ignored() {
    let t = start("blocked_stop_child", &[]);
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["default during true", "Timeout"]);
    assert_eq!(shown(&all), shown(&cat(&[ENTER_ALL, LEAVE_ALL])));
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn blocked_stop_child() {
    take_signals();
    // SAFETY: an all-zero `sigset_t` is valid storage for sigemptyset.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a valid set.
    unsafe { libc::sigemptyset(&mut set) };
    // SAFETY: as above.
    unsafe { libc::sigaddset(&mut set, libc::SIGTSTP) };
    // SAFETY: `set` is valid; this thread's mask only. It stays blocked: in
    // this orphaned process group a stop let through would be dropped.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    say(&format!(
        "default during {}",
        disposition(libc::SIGTSTP) == libc::SIG_DFL
    ));
    s.suspend();
    let short = Instant::now() + Duration::from_millis(100);
    say(&format!("{:?}", s.wait(false, Some(short))));
}

// The window changes while the alternate screen is on: the new columns and
// rows come as one event, and the screen stays alternate.
// 이것을 실패시키는 것: SIGWINCH에 처리기를 걸지 않는 것(wait가 깨지 않음), 줄 수를 읽지 않는 것, 크기 변경에
// 대체 화면을 나가는 것, 크기가 그대로인 SIGWINCH를 알리는 것(자식의 assert).
#[test]
fn a_resize_under_the_alternate_screen_is_reported_with_rows() {
    let mut t = start("resize_child", &[]);
    t.expect(b"READY");
    t.resize(100, 30);
    t.expect(b"SIZE 100x30");
    t.send(b"q");
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["Resized(Size { cols: 100, rows: 30 })"]);
    assert_eq!(
        shown(&all),
        shown(&cat(&[
            ENTER_ALL,
            b"\x1b[H\x1b[2JREADY",
            b"\x1b[H\x1b[2JSIZE 100x30",
            LEAVE_ALL
        ]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn resize_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    // A window change signal with no change is no event.
    test_session::BEFORE_SELECT.set(Some(libc::SIGWINCH));
    let short = Instant::now() + Duration::from_millis(100);
    assert_eq!(s.wait(false, Some(short)), Event::Timeout);
    draw(&mut s, b"READY");
    loop {
        match s.wait(false, Some(Instant::now() + WAIT)) {
            Event::Resized(size) => {
                say(&format!("{:?}", Event::Resized(size)));
                draw(
                    &mut s,
                    format!("SIZE {}x{}", size.cols, size.rows).as_bytes(),
                );
            }
            Event::Input(b"q") => break,
            e => panic!("{e:?}"),
        }
    }
}

// A SIGTERM from outside while the session waits with no time limit. In
// this test process it often lands on another thread than the waiting one,
// whose select then sees only the wake byte. The signal is sent once the
// child drew after `full_screen` returned: from then on a SIGTERM reaches
// `wait` as `Signal`, whenever it comes. (A SIGTERM during the entry is the
// entering cells of a_signal_at_any_stage_puts_the_terminal_back.)
// 이것을 실패시키는 것: 처리기가 깨우기 pipe에 쓰지 않는 것(다른 스레드가 신호를 받으면 select가 깨지 않아 자식이
// 끝나지 않음).
#[test]
fn a_signal_from_outside_wakes_a_wait_with_no_time_limit() {
    // Not masked: this test is about a handler that runs on another thread.
    let mut t = start_test(
        "commands::tty::session::tests::wait_forever_child",
        80,
        24,
        &[],
        false,
    );
    t.expect(b"WAITING");
    // Most likely in the select by now; a signal before it is the same case.
    t.idle(Duration::from_millis(50));
    // SAFETY: sends SIGTERM to the child this test started.
    assert_eq!(unsafe { libc::kill(t.pid(), libc::SIGTERM) }, 0);
    let (lines, status, out, err) = t.end();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{out}\n{err}");
    assert_eq!(lines, [format!("Signal({})", libc::SIGTERM)]);
    assert!(t.mode_restored());
    assert_eq!(
        shown(&t.all),
        shown(&cat(&[ENTER_ALL, b"\x1b[H\x1b[2JWAITING", LEAVE_ALL]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn wait_forever_child() {
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    draw(&mut s, b"WAITING");
    say(&format!("{:?}", s.wait(false, None)));
}

// The terminal goes away while the session waits. SIGHUP caught: the
// process ends with it at once. SIGHUP ignored (nohup): the read gives the
// end, and the session reports `Hangup`. 이것을 실패시키는 것: 0바이트 읽기나 EIO를 끝으로 보지 않는 것
// (마감까지 되풀이), 끊긴 터미널의 복구가 마감을 기다리는 것, SIGHUP을 다시 올리지 않는 것.
#[test]
fn a_hang_up_ends_the_session() {
    for ignored in ["no", "yes"] {
        let mut t = start("hang_up_child", &[("BINGSU_TEST_IGNORE_HUP", ignored)]);
        t.expect(ENTER_ALL);
        let started = Instant::now();
        t.hang_up();
        let (lines, status, out, err) = t.end();
        assert!(started.elapsed() < Duration::from_secs(2), "{ignored}");
        if ignored == "yes" {
            assert!(status.success(), "{out}\n{err}");
            assert_eq!(lines, ["Hangup"]);
        } else {
            // The read can see the end before SIGHUP arrives; the process
            // ends with SIGHUP all the same, once it is raised again or
            // reaches the handler put back.
            assert_eq!(
                status.signal(),
                Some(libc::SIGHUP),
                "{lines:?} {out}\n{err}"
            );
            let hup = format!("Signal({})", libc::SIGHUP);
            assert!(lines == [hup.as_str()] || lines == ["Hangup"], "{lines:?}");
        }
    }
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn hang_up_child() {
    take_signals();
    if param("BINGSU_TEST_IGNORE_HUP") == "yes" {
        // SAFETY: sets this process's SIGHUP disposition to ignore.
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    }
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    say(&format!("{:?}", s.wait(false, None)));
}

// 이것을 실패시키는 것: 깨우기 pipe의 끝 하나가 FD_SETSIZE에 있어도 쓰는 것(select의 집합 밖에 씀).
#[test]
fn a_wake_pipe_above_fd_setsize_is_refused() {
    let t = start("high_pipe_child", &[]);
    let (lines, _) = t.mode_restored_after();
    assert_eq!(lines, ["refused true"]);
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn high_pipe_child() {
    take_signals();
    let size = RawFd::try_from(libc::FD_SETSIZE).unwrap();
    // SAFETY: an all-zero rlimit is valid storage for getrlimit to fill.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: `limit` is writable.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    assert_eq!(rc, 0);
    let want = libc::rlim_t::try_from(size + 64).unwrap();
    limit.rlim_cur = limit.rlim_max.min(want);
    // SAFETY: `limit` is a valid rlimit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    // Every number below FD_SETSIZE taken but the last, so the pipe's read
    // end fits select and its write end does not.
    let mut held = Vec::new();
    loop {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        held.push(file);
        if fd >= size - 1 {
            break;
        }
    }
    let last = held.pop().unwrap();
    assert_eq!(last.as_raw_fd(), size - 1);
    drop(last);
    say(&format!("refused {}", wake_pipe().is_err()));
}

/// A shell's way of giving the terminal to `group`: from the background
/// too, so SIGTTOU is blocked for the call.
fn give_terminal(group: libc::pid_t) {
    // SAFETY: an all-zero `sigset_t` is valid storage for sigemptyset.
    let mut block: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `block` is a valid set.
    unsafe { libc::sigemptyset(&mut block) };
    // SAFETY: as above.
    unsafe { libc::sigaddset(&mut block, libc::SIGTTOU) };
    // SAFETY: as above, storage for the mask in force.
    let mut was: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: both sets are valid; this thread's mask only.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut was) };
    // SAFETY: fd 0 is this session's terminal; `group` is a group in it.
    assert_eq!(unsafe { libc::tcsetpgrp(0, group) }, 0);
    // SAFETY: `was` is the mask pthread_sigmask returned above.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &was, std::ptr::null_mut()) };
}

/// `waitpid` of `pid` with `flags`: (the pid it returned, the status).
fn wait_for(pid: libc::pid_t, flags: libc::c_int) -> (libc::pid_t, libc::c_int) {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a writable int; `pid` is this process's child.
        let got = unsafe { libc::waitpid(pid, &mut status, flags) };
        if got >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return (got, status);
        }
    }
}

/// Sets or clears local mode flags of the terminal on fd 0.
fn set_local(flag: libc::tcflag_t, on: bool) {
    // SAFETY: all-zero storage for tcgetattr to fill.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 is the terminal; `t` is writable.
    assert_eq!(unsafe { libc::tcgetattr(0, &mut t) }, 0);
    if on {
        t.c_lflag |= flag;
    } else {
        t.c_lflag &= !flag;
    }
    // SAFETY: as above; `t` came from tcgetattr.
    assert_eq!(unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) }, 0);
}

/// Writes `text` to the terminal on fd 0, as a shell prints.
fn print(text: &[u8]) {
    // SAFETY: fd 0 is the terminal; `text` is a valid slice.
    let n = unsafe { libc::write(0, text.as_ptr().cast(), text.len()) };
    assert_eq!(usize::try_from(n).ok(), Some(text.len()));
}

// Under a shell with job control (job_shell_child plays it: the session is
// its job, in a process group of its own in the same session, so a stop is
// real). `tostop` is on: a background job that writes to the terminal is
// stopped too, as one that reads it or sets its mode.

/// The parent's side of job_shell_child's scenario: what it types and when.
fn job_shell(scenario: &str) -> (Vec<String>, Vec<u8>) {
    let report = std::env::temp_dir().join(format!(
        "bingsu-session-test-{}-{scenario}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&report);
    let mut t = start(
        "job_shell_child",
        &[
            ("BINGSU_TEST_SCENARIO", scenario),
            ("BINGSU_TEST_REPORT", report.to_str().unwrap()),
        ],
    );
    if scenario == "entrystopfg" || scenario == "entrytaken" {
        // The terminal took 3 bytes of the alternate screen's switch.
        t.expect(b"\x1b[?");
        t.send(&[test_terminal::READ]);
    }
    if scenario != "enterlost" && scenario != "entrytaken" {
        t.expect(b"REDRAW 1");
    }
    match scenario {
        "entrystopfg" => t.send(b"q"),
        "reenterlost" => {
            t.send(b"\x1a");
            t.expect(b"REDRAW 2");
            t.send(b"q");
        }
        "writestop" | "writestopfg" => {
            t.expect(b"REDRAW 2");
            t.send(b"q");
        }
        "readtaken" => {
            t.expect(b"SHELL took");
            t.send(b"x");
        }
        "rawstop" => {
            t.expect(b"REDRAW 2");
            t.send(b"q");
        }
        "leaveterm" | "stopterm" => t.send(b"\x1a"),
        "leavecont" => {
            t.send(b"\x1a");
            t.expect(b"REDRAW 2");
            t.send(b"q");
        }
        "stop" => {
            t.send(b"\x1a");
            t.expect(b"SHELL bg");
            t.send(b"zz");
            t.expect(b"REDRAW 2");
            t.send(b"q");
        }
        "winch" => {
            t.send(b"\x1a");
            t.expect(b"REDRAW 2");
            t.send(b"q");
        }
        "hangup" => {
            t.send(b"\x1a");
            t.expect(b"SHELL bg");
        }
        _ => {}
    }
    let (mut lines, status, out, err) = t.end();
    assert!(status.success(), "{scenario}: {lines:?} {out}\n{err}");
    // The job's own report, when the shell did not outlive it.
    if let Ok(text) = std::fs::read_to_string(&report) {
        lines.extend(text.lines().map(str::to_owned));
        let _ = std::fs::remove_file(&report);
    }
    (lines, std::mem::take(&mut t.all))
}

fn has(lines: &[String], want: &str) -> bool {
    lines.iter().any(|l| l == want)
}

// Ctrl-Z, `bg` (keys typed meanwhile), `fg`. 이것을 실패시키는 것: Ctrl-Z가 작업의 다른 프로세스를 멈추지 않는 것,
// 멈추기 전에 터미널을 되돌리지 않는 것, bg로
// 이어 가서 터미널을 다시 잡는 것(SIGCONT 뒤 전경 확인을 빼면 배경에서 tcsetattr로 다시 멈춤), 배경에서 터미널을
// select하고 읽는 것(SIGTTIN으로 멈춤), fg 때 다시 들어가지 않는 것, 멈춘 사이 친 글자를 버리지 않는 것, 다시
// 들어갈 때 터미널의 모드를 새로 읽지 않는 것(멈춘 사이 바뀐 모드 대신 처음 모드로 되돌림).
#[test]
fn stop_bg_and_fg_under_a_job_control_shell() {
    let (lines, all) = job_shell("stop");
    for want in [
        "stopped by TSTP true",
        "restored at the stop true",
        "the job's other process stopped too true",
        "job: back from the stop, wrote 0",
        "background quiet true",
        "job: resumed 1",
        "job: typed q",
        "job ended true",
        "restored to the mode at fg true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    // The job put the terminal back, wrote nothing while in the background,
    // and took the terminal again after `fg`.
    let stop = cat(&[b"REDRAW 1", LEAVE_ALL, b"SHELL bg\r\n", ENTER_ALL]);
    assert!(
        all.windows(stop.len()).any(|w| w == stop),
        "{}",
        shown(&all)
    );
    assert!(all.ends_with(LEAVE_ALL), "{}", shown(&all));
}

// The shell takes the terminal back without stopping the job, then ends it.
// 이것을 실패시키는 것: 전경이 아닌데 나가며 터미널을 건드리는 것(복구 열이나 tcsetattr: tostop과 SIGTTOU로 멈춤).
#[test]
fn a_session_that_lost_the_terminal_does_not_touch_it() {
    let (lines, all) = job_shell("taken");
    assert!(
        has(&lines, "ended by TERM without a stop true"),
        "{lines:?}"
    );
    assert!(all.ends_with(b"REDRAW 1"), "{}", shown(&all));
}

// After `bg` the shell gives the terminal back without SIGCONT; the window
// change sent to the new foreground group brings the session back (the
// once-a-second look is turned off here). 이것을 실패시키는 것: 배경에서 SIGWINCH 뒤 전경인지 보지 않는 것.
#[test]
fn a_window_change_in_the_background_looks_for_the_terminal() {
    let (lines, _) = job_shell("winch");
    for want in ["job: resumed 1", "job ended true"] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
}

// The shell ends (as one that does not hang up its jobs) while the session
// waits in the background: the terminal is no longer this job's, no signal
// comes to a background job, and the once-a-second look finds it.
// 이것을 실패시키는 것: 배경에서 마감 없이 pipe만 기다리는 것(끝나지 않음; 자식의 alarm이 10초 뒤 끝냄), 터미널의
// 그룹을 읽지 못한 것을 끝으로 보지 않는 것.
#[test]
fn a_background_session_ends_when_its_terminal_goes_away() {
    let (lines, _) = job_shell("hangup");
    assert!(has(&lines, "job: Hangup"), "{lines:?}");
}

// A SIGTSTP right after the raw switch, before the modes go on: it is the
// session's to handle (the job control handlers are in before the switch),
// so the terminal is put back before the job stops, and `fg` takes it
// again. 이것을 실패시키는 것: 처리기를 raw 전환 뒤에 거는 것(기본 동작으로 raw인 채 멈춤: 멈춘 때의 모드가 다름).
#[test]
fn a_stop_right_after_the_raw_switch_puts_the_terminal_back() {
    let (lines, all) = job_shell("rawstop");
    for want in [
        "stopped by TSTP true",
        "restored at the stop true",
        "job: resumed 1",
        "job ended true",
        "restored at the end true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    let want = cat(&[
        ENTER_ALL,
        b"\x1b[H\x1b[2JREDRAW 1",
        LEAVE_ALL,
        ENTER_ALL,
        b"\x1b[H\x1b[2JREDRAW 2",
        LEAVE_ALL,
    ]);
    assert_eq!(shown(&all), shown(&want));
}

// Ctrl-Z, and a SIGTERM while the terminal is put back: the exit goes first,
// nothing of the process group stops, and nothing is written to the
// terminal given back. 이것을 실패시키는 것: 되돌리는 동안 온 종료 요청을 보지 않고 멈추는 것(셸이 정지를 봄),
// 되돌린 터미널에 쓰는 것(AFTER).
#[test]
fn a_terminate_during_the_way_out_ends_without_a_stop() {
    let (lines, all) = job_shell("leaveterm");
    for want in [
        "job: back from the stop, wrote 0",
        "ended by TERM without a stop true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    let want = cat(&[ENTER_ALL, b"\x1b[H\x1b[2JREDRAW 1", LEAVE_ALL]);
    assert_eq!(shown(&all), shown(&want));
}

// Ctrl-Z, and SIGTSTP then SIGCONT while the terminal is put back: the
// continue drops the stop (and the SIGTSTP before it), as the kernel drops
// a pending stop on SIGCONT. 이것을 실패시키는 것: 되돌리는 동안 온 재개를 보지 않고 멈추는 것, SIGCONT가 그 앞의
// SIGTSTP를 지우지 않는 것(다시 잡은 뒤 한 번 더 멈춤).
#[test]
fn a_continue_during_the_way_out_cancels_the_stop() {
    let (lines, all) = job_shell("leavecont");
    for want in [
        "job: back from the stop, wrote 5",
        "job: resumed 1",
        "ended without a stop true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    let want = cat(&[
        ENTER_ALL,
        b"\x1b[H\x1b[2JREDRAW 1",
        LEAVE_ALL,
        ENTER_ALL,
        b"AFTER\x1b[H\x1b[2JREDRAW 2",
        LEAVE_ALL,
    ]);
    assert_eq!(shown(&all), shown(&want));
}

// A SIGTERM sent while the job is stopped comes with the SIGCONT of `fg`:
// the session ends with it and does not take the terminal again.
// 이것을 실패시키는 것: 재개 뒤 종료 요청을 보지 않고 다시 들어가는 것(두 번째 진입 열).
#[test]
fn a_terminate_while_stopped_ends_without_taking_the_terminal() {
    let (lines, all) = job_shell("stopterm");
    for want in [
        "stopped by TSTP true",
        "restored at the stop true",
        "job: back from the stop, wrote 0",
        "ended by TERM after the stop true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    let want = cat(&[ENTER_ALL, b"\x1b[H\x1b[2JREDRAW 1", LEAVE_ALL]);
    assert_eq!(shown(&all), shown(&want));
}

// `Writable`, then SIGSTOP and `bg` before the write: the write waits for
// the next `wait` (nothing reaches the terminal from the background), and
// `fg` takes the terminal again. 이것을 실패시키는 것: 쓰기 전에 소유를 보지 않는 것(배경에서 써서 tostop과
// SIGTTOU로 멈춤).
#[test]
fn a_write_after_a_stop_and_bg_writes_nothing() {
    let (lines, all) = job_shell("writestop");
    for want in [
        "stopped by STOP true",
        "job: wrote 0",
        "background quiet true",
        "job: resumed 1",
        "job ended true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    assert!(!all.windows(5).any(|w| w == b"FRAME"), "{}", shown(&all));
}

// `Writable`, then SIGSTOP and `fg`: still the foreground job, but the
// continue is not handled yet (the shell may have drawn on the screen), so
// the write waits for `Resumed`. 이것을 실패시키는 것: 처리하지 않은 재개를 보지 않고 쓰는 것(FRAME이 나감).
#[test]
fn a_write_after_a_stop_and_fg_waits_for_the_resume() {
    let (lines, all) = job_shell("writestopfg");
    for want in [
        "stopped by STOP true",
        "job: wrote 0",
        "job: resumed 1",
        "job ended true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    assert!(!all.windows(5).any(|w| w == b"FRAME"), "{}", shown(&all));
}

// The shell takes the terminal back without stopping the job, which then
// writes. 이것을 실패시키는 것: 쓰기 전에 전경인지 보지 않는 것(배경에서 써서 SIGTTOU로 멈춤).
#[test]
fn a_write_after_the_terminal_was_taken_writes_nothing() {
    let (lines, all) = job_shell("writetaken");
    for want in [
        "job: wrote 0",
        "background quiet true",
        "ended by TERM without a stop true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    assert!(!all.windows(5).any(|w| w == b"FRAME"), "{}", shown(&all));
}

// The shell takes the terminal back without stopping the job, and a key
// comes: the job, which sees it readable, does not read it.
// 이것을 실패시키는 것: 읽기 전에 소유를 보지 않는 것(배경에서 읽어 SIGTTIN으로 멈춤).
#[test]
fn a_session_that_lost_the_terminal_reads_nothing() {
    let (lines, _) = job_shell("readtaken");
    for want in ["background quiet true", "ended by TERM without a stop true"] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
}

// SIGSTOP after the first mode went on, and `bg`: the entry writes no more
// from the background and fails. 이것을 실패시키는 것: 들어가는 쓰기마다 전경인지 보지 않는 것(배경에서 25l을 써서
// SIGTTOU로 멈춤).
#[test]
fn an_entry_whose_terminal_was_taken_writes_no_more() {
    let (lines, all) = job_shell("enterlost");
    for want in ["stopped by STOP true", "job: entry Other", "job ended true"] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    assert_eq!(shown(&all), shown(b"\x1b[?1049h"));
}

// Ctrl-Z and `fg`; while the terminal is taken again, SIGSTOP and `bg`: the
// session waits in the background (writing nothing) and the next `fg` puts
// back the half-entered modes and takes the terminal again.
// 이것을 실패시키는 것: 다시 들어가다 터미널을 잃은 세션을 배경으로 두지 않는 것(배경에서 다시 그려 SIGTTOU로 멈춤).
#[test]
fn a_reentry_whose_terminal_was_taken_waits_for_the_next_continue() {
    let (lines, all) = job_shell("reenterlost");
    for want in [
        "stopped by STOP true",
        "background quiet true",
        "job: resumed 1",
        "job ended true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    // The cursor's mode was recorded as on before its write found the
    // terminal taken: its reset comes too (harmless for a mode never set).
    let again = cat(&[
        b"\x1b[?1049h",
        b"\x1b[0m\x1b[?25h\x1b[?1049l",
        ENTER_ALL,
        b"\x1b[H\x1b[2JREDRAW 2",
    ]);
    assert!(
        all.windows(again.len()).any(|w| w == again),
        "{}",
        shown(&all)
    );
}

// The shell takes the terminal back without a stop, and the session is
// then told to suspend: it stops alone, and the other process of its job
// does not. 이것을 실패시키는 것: 터미널을 잃은 세션이 그룹 전체에 SIGTSTP를 보내는 것.
#[test]
fn a_suspend_without_the_terminal_stops_only_the_session() {
    let (lines, _) = job_shell("suspendtaken");
    for want in [
        "stopped by TSTP true",
        "the job's other process stopped too false",
        "job: back from the suspend",
        "ended by TERM true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
}

// SIGSTOP while the alternate screen's switch waits for room (the terminal
// took 3 bytes), then `fg`: the rest is not written before the continue is
// handled; the first wait ends the cut sequence, puts back what went out
// and takes the terminal again. 이것을 실패시키는 것: 진입 쓰기 루프에서 처리하지 않은 재개를 보지 않는 것(나머지를
// 그대로 씀).
#[test]
fn an_entry_cut_by_sigstop_and_fg_starts_again() {
    let (lines, all) = job_shell("entrystopfg");
    for want in [
        "stopped by STOP true",
        "job: first Resumed(Size { cols: 80, rows: 24 })",
        "job ended true",
    ] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    let want = cat(&[
        b"\x1b[?",
        CANCEL,
        b"\x1b[0m\x1b[?1049l",
        ENTER_ALL,
        b"\x1b[H\x1b[2JREDRAW 1",
        LEAVE_ALL,
    ]);
    assert_eq!(shown(&all), shown(&want));
}

// The shell takes the terminal while the alternate screen's switch waits for
// room, without a stop: the rest is not written from the background, and
// the entry fails. 이것을 실패시키는 것: 진입 쓰기 루프에서 기다린 뒤 전경인지 보지 않는 것(배경에서 나머지를 써서
// SIGTTOU로 멈춤).
#[test]
fn an_entry_cut_when_the_shell_takes_the_terminal_writes_no_more() {
    let (lines, all) = job_shell("entrytaken");
    for want in ["job: paused", "job: entry Other", "job ended true"] {
        assert!(has(&lines, want), "{want}: {lines:?}");
    }
    assert_eq!(shown(&all), shown(b"\x1b[?"));
}

// The raw switch fails once the job control handlers are in: they go back.
// 이것을 실패시키는 것: 실패한 진입에서 처리기를 되돌리지 않는 것.
#[test]
fn a_failed_raw_switch_puts_the_handlers_back() {
    let t = start("failed_raw_child", &[]);
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["refused true", "handlers back true"]);
    assert_eq!(shown(&all), "");
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn failed_raw_child() {
    take_signals();
    let tty = take_terminal();
    let handlers = || JOB_SIGNALS.map(disposition);
    let before = handlers();
    test_session::FAIL_RAW.set(true);
    say(&format!("refused {}", tty.full_screen().is_err()));
    say(&format!("handlers back {}", handlers() == before));
}

/// Kills the job's process group when dropped (`None`: the job is meant to
/// outlive the shell).
struct KillJob(Option<libc::pid_t>);

impl Drop for KillJob {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: sends SIGKILL to the job's process group; one that
            // ended already is not there (ESRCH).
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
}

/// The scenario's shell (`BINGSU_TEST_SCENARIO`); see the parent tests. The job's lines come through a pipe,
/// which also tells the shell when the job is ready or back from a stop.
#[test]
#[ignore = "child: a job control shell on a pseudo-terminal"]
fn job_shell_child() {
    use std::io::BufRead;
    use std::os::unix::process::CommandExt;
    let scenario = param("BINGSU_TEST_SCENARIO");
    let _tty = take_terminal();
    set_local(libc::TOSTOP, true);
    let before = mode();
    // SAFETY: getpgrp takes no arguments and cannot fail.
    let own = unsafe { libc::getpgrp() };
    #[allow(
        clippy::zombie_processes,
        reason = "reaped by waitpid below, which also reports a stop"
    )]
    let mut job = masked(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::tty::session::tests::job_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .process_group(0)
            .stdout(std::process::Stdio::piped()),
    )
    .spawn()
    .unwrap();
    let pid = libc::pid_t::try_from(job.id()).unwrap();
    // A job a broken build leaves stopped or waiting is killed: when this
    // shell fails, and in any case after 20 s.
    let mut killer = KillJob(Some(pid));
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));
        // SAFETY: sends SIGKILL to the job's process group.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    });
    let (tell, told) = std::sync::mpsc::channel();
    let out = job.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(out).lines() {
            let line = line.unwrap();
            println!("{line}");
            let _ = tell.send(line);
        }
    });
    let wait_line = |want: &str| loop {
        let line = told.recv_timeout(WAIT).expect(want);
        if line.contains(want) {
            return;
        }
    };
    give_terminal(pid);
    let sibling = (scenario == "stop" || scenario == "suspendtaken").then(|| {
        loop {
            let line = told.recv_timeout(WAIT).expect("the sibling");
            if let Some(n) = line.split("job: sibling ").nth(1) {
                break n.to_owned();
            }
        }
    });
    if scenario == "entrystopfg" {
        // Stopped (SIGSTOP) while the alternate screen's switch waited for
        // room; `fg`.
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "stopped by STOP {}",
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP
        ));
        // SAFETY: continues the job's process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        wait_line("job: ready");
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "job ended {}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        ));
        return;
    }
    if scenario == "entrytaken" {
        // The shell takes the terminal while the alternate screen's switch
        // waits for room, without a stop.
        wait_line("job: paused");
        give_terminal(own);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "job ended {}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        ));
        return;
    }
    if scenario == "enterlost" {
        // Stopped (SIGSTOP) after the first mode went on; `bg`.
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        give_terminal(own);
        say(&format!(
            "stopped by STOP {}",
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP
        ));
        // SAFETY: continues the job's process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "job ended {}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        ));
        return;
    }
    wait_line("job: ready");
    if scenario == "writestop" || scenario == "writestopfg" {
        // The job stops itself (SIGSTOP) between `Writable` and its write.
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "stopped by STOP {}",
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP
        ));
        if scenario == "writestop" {
            // `bg`: the write must wait; the job must touch nothing.
            give_terminal(own);
            // SAFETY: continues the job's process group.
            assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
            wait_line("job: wrote");
            std::thread::sleep(Duration::from_millis(300));
            let (got, _) = wait_for(pid, libc::WNOHANG | libc::WUNTRACED);
            say(&format!("background quiet {}", got == 0));
            give_terminal(pid);
        }
        // `fg` (for `writestopfg`, the terminal never left the job).
        // SAFETY: as above.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        give_terminal(own);
        say(&format!(
            "job ended {}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        ));
        return;
    }
    if scenario == "suspendtaken" {
        // The shell takes the terminal back without a stop; the job then
        // suspends itself.
        give_terminal(own);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "stopped by TSTP {}",
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTSTP
        ));
        let sibling = sibling.as_deref().unwrap();
        let stopped = || {
            let state = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", sibling])
                .output()
                .unwrap();
            String::from_utf8_lossy(&state.stdout)
                .trim()
                .starts_with('T')
        };
        // A group stop would reach the sibling within this window.
        let until = Instant::now() + Duration::from_millis(300);
        let mut seen = false;
        while Instant::now() < until && !seen {
            seen = stopped();
            std::thread::sleep(Duration::from_millis(10));
        }
        say(&format!("the job's other process stopped too {seen}"));
        // `bg`, then the end.
        // SAFETY: continues the job's process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        wait_line("job: back from the suspend");
        // SAFETY: sends SIGTERM to the job.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "ended by TERM {}",
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM
        ));
        return;
    }
    if scenario == "writetaken" || scenario == "readtaken" {
        // The shell takes the terminal back without stopping the job; the
        // job then writes (`writetaken`) or keys come (`readtaken`).
        give_terminal(own);
        if scenario == "writetaken" {
            wait_line("job: wrote");
        } else {
            print(b"SHELL took\n");
            wait_queued(1);
        }
        std::thread::sleep(Duration::from_millis(300));
        let (got, _) = wait_for(pid, libc::WNOHANG | libc::WUNTRACED);
        say(&format!("background quiet {}", got == 0));
        // SAFETY: sends SIGTERM to the job.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "ended by TERM without a stop {}",
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM
        ));
        return;
    }
    if scenario == "leaveterm" {
        // Ctrl-Z, and a SIGTERM while the terminal is put back.
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "ended by TERM without a stop {}",
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM
        ));
        return;
    }
    if scenario == "leavecont" {
        // Ctrl-Z, and SIGTSTP then SIGCONT while the terminal is put back.
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        let stopped = libc::WIFSTOPPED(status);
        if stopped {
            // A broken build stopped: `fg`, so the test can end.
            give_terminal(pid);
            // SAFETY: continues the job's process group.
            unsafe { libc::kill(-pid, libc::SIGCONT) };
            wait_for(pid, libc::WUNTRACED);
        }
        give_terminal(own);
        say(&format!("ended without a stop {}", !stopped));
        return;
    }
    if scenario == "taken" {
        give_terminal(own);
        // SAFETY: sends SIGTERM to the job.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        say(&format!(
            "ended by TERM without a stop {}",
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM
        ));
        return;
    }
    // Ctrl-Z stops it (or, in `rawstop`, the SIGTSTP that came right after
    // the raw switch).
    let (_, status) = wait_for(pid, libc::WUNTRACED);
    give_terminal(own);
    say(&format!(
        "stopped by TSTP {}",
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTSTP
    ));
    say(&format!("restored at the stop {}", mode() == before));
    if scenario == "reenterlost" {
        // `fg`; the job stops again (SIGSTOP) after the first mode went on
        // again; `bg`, then `fg`.
        give_terminal(pid);
        // SAFETY: continues the job's process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        give_terminal(own);
        say(&format!(
            "stopped by STOP {}",
            libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP
        ));
        // SAFETY: as above.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        std::thread::sleep(Duration::from_millis(300));
        let (got, _) = wait_for(pid, libc::WNOHANG | libc::WUNTRACED);
        say(&format!("background quiet {}", got == 0));
        give_terminal(pid);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        give_terminal(own);
        say(&format!(
            "job ended {}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        ));
        return;
    }
    if scenario == "stopterm" {
        // `fg`, with a SIGTERM sent while the job is stopped.
        give_terminal(pid);
        // SAFETY: sends SIGTERM to the stopped job; it comes with SIGCONT.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        // SAFETY: continues the job's process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        give_terminal(own);
        say(&format!(
            "ended by TERM after the stop {}",
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM
        ));
        return;
    }
    if scenario == "rawstop" {
        // `fg`.
        give_terminal(pid);
        // SAFETY: continues the job's process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        let (_, status) = wait_for(pid, libc::WUNTRACED);
        give_terminal(own);
        say(&format!(
            "job ended {}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        ));
        say(&format!("restored at the end {}", mode() == before));
        return;
    }
    if let Some(sibling) = &sibling {
        // The group's stop reaches the sibling on its own time.
        let stopped = || {
            let state = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", sibling])
                .output()
                .unwrap();
            String::from_utf8_lossy(&state.stdout)
                .trim()
                .starts_with('T')
        };
        let until = Instant::now() + Duration::from_secs(1);
        while !stopped() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        say(&format!(
            "the job's other process stopped too {}",
            stopped()
        ));
    }
    // The mode changes meanwhile (and with no line editing and no echo,
    // typed-ahead keys can be counted): the job keeps the new one.
    set_local(libc::ECHOCTL | libc::ECHO | libc::ICANON, false);
    let changed = mode();
    // `bg`.
    // SAFETY: continues the job's process group.
    assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
    wait_line("job: back from the stop");
    match scenario.as_str() {
        "winch" => {
            // The terminal back without SIGCONT; the kernel would send
            // SIGWINCH to the foreground group on a resize.
            give_terminal(pid);
            // SAFETY: as above, a window change signal.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGWINCH) }, 0);
        }
        "hangup" => {
            // The shell ends; the job reports through its file.
            killer.0 = None;
            print(b"SHELL bg\n");
            return;
        }
        _ => {
            // A window change meant for it, and keys typed: it must touch
            // nothing.
            // SAFETY: as above, a window change signal.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGWINCH) }, 0);
            print(b"SHELL bg\n");
            wait_queued(2);
            std::thread::sleep(Duration::from_millis(300));
            let (got, _) = wait_for(pid, libc::WNOHANG | libc::WUNTRACED);
            say(&format!("background quiet {}", got == 0));
            // `fg`.
            give_terminal(pid);
            // SAFETY: as above.
            assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
        }
    }
    let (_, status) = wait_for(pid, libc::WUNTRACED);
    give_terminal(own);
    say(&format!(
        "job ended {}",
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    ));
    say(&format!("restored to the mode at fg {}", mode() == changed));
}

#[test]
#[ignore = "child: a job of job_shell_child"]
fn job_child() {
    take_signals();
    let scenario = param("BINGSU_TEST_SCENARIO");
    // Only a signal brings the session back here, not the once-a-second look.
    if matches!(
        scenario.as_str(),
        "stop"
            | "winch"
            | "rawstop"
            | "writestop"
            | "writetaken"
            | "readtaken"
            | "reenterlost"
            | "suspendtaken"
    ) {
        test_session::BACKGROUND_CHECK.set(Some(Duration::from_secs(60)));
    }
    if scenario == "hangup" {
        // Ends a job that never notices, so the test fails instead of
        // waiting for it.
        // SAFETY: alarm takes an integer; SIGALRM's default action ends the
        // process.
        unsafe { libc::alarm(10) };
    }
    // The shell gives the terminal right after the start.
    let until = Instant::now() + WAIT;
    // SAFETY: getpgrp takes no arguments and cannot fail.
    let own = unsafe { libc::getpgrp() };
    // SAFETY: fd 0 is the terminal; the call reads its group.
    while unsafe { libc::tcgetpgrp(0) } != own {
        assert!(Instant::now() < until, "never the foreground job");
        std::thread::sleep(Duration::from_millis(2));
    }
    // Another process of the job (as a shell pipeline has): Ctrl-Z stops it
    // too. Its descriptors are not the test's pipes.
    let mut sibling = (scenario == "stop" || scenario == "suspendtaken").then(|| {
        std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    });
    if let Some(sibling) = &sibling {
        say(&format!("job: sibling {}", sibling.id()));
    }
    match scenario.as_str() {
        "rawstop" => test_session::AFTER_RAW.set(Some(libc::SIGTSTP)),
        "leaveterm" => test_session::DURING_LEAVE.set([libc::SIGTERM, 0]),
        "leavecont" => test_session::DURING_LEAVE.set([libc::SIGTSTP, libc::SIGCONT]),
        "enterlost" => test_session::AFTER_STEP.set(Some((0, libc::SIGSTOP))),
        "entrystopfg" | "entrytaken" => {
            test_terminal::ROOM.set(Some((3, test_terminal::Then::Stall)));
            test_session::PAUSE.set(Some(if scenario == "entrytaken" {
                test_session::Pause::Taken
            } else {
                test_session::Pause::Stop
            }));
        }
        "reenterlost" => test_session::REENTRY_STEP.set(Some((0, libc::SIGSTOP))),
        _ => {}
    }
    let tty = Tty::open().unwrap();
    let mut s = match tty.full_screen() {
        Ok(s) => s,
        Err(e) => {
            say(&format!("job: entry {:?}", e.kind()));
            return;
        }
    };
    if scenario == "entrystopfg" {
        // The entry stopped short for the continue; the first wait takes the
        // terminal again from the start.
        let event = format!("{:?}", s.wait(false, Some(Instant::now() + WAIT)));
        say(&format!("job: first {event}"));
    }
    draw(&mut s, b"REDRAW 1");
    say("job: ready");
    match scenario.as_str() {
        "writestop" | "writestopfg" => {
            assert_eq!(s.wait(true, Some(Instant::now() + WAIT)), Event::Writable);
            // SAFETY: stops this process, as a SIGSTOP from outside would.
            unsafe { libc::raise(libc::SIGSTOP) };
            let wrote = s.write_some(b"FRAME").unwrap_or(0);
            say(&format!("job: wrote {wrote}"));
        }
        "suspendtaken" => {
            // SAFETY: getpgrp takes no arguments and cannot fail.
            let own = unsafe { libc::getpgrp() };
            let until = Instant::now() + WAIT;
            // SAFETY: fd 0 is the terminal; the call reads its group.
            while unsafe { libc::tcgetpgrp(0) } == own {
                assert!(Instant::now() < until, "the shell never took the terminal");
                std::thread::sleep(Duration::from_millis(2));
            }
            s.suspend();
            say("job: back from the suspend");
        }
        "writetaken" => {
            // SAFETY: getpgrp takes no arguments and cannot fail.
            let own = unsafe { libc::getpgrp() };
            let until = Instant::now() + WAIT;
            // SAFETY: fd 0 is the terminal; the call reads its group.
            while unsafe { libc::tcgetpgrp(0) } == own {
                assert!(Instant::now() < until, "the shell never took the terminal");
                std::thread::sleep(Duration::from_millis(2));
            }
            let wrote = s.write_some(b"FRAME").unwrap_or(0);
            say(&format!("job: wrote {wrote}"));
        }
        _ => {}
    }
    let mut resumed = 0;
    let mut typed = Vec::new();
    loop {
        match s.wait(false, None) {
            Event::Input(b"\x1a") => {
                s.suspend();
                let wrote = s.write_some(b"AFTER").unwrap_or(0);
                say(&format!("job: back from the stop, wrote {wrote}"));
            }
            Event::Input(b) => {
                typed.extend_from_slice(b);
                if typed.contains(&b'q') {
                    break;
                }
            }
            Event::Resumed(_) => {
                resumed += 1;
                draw(&mut s, format!("REDRAW {}", resumed + 1).as_bytes());
            }
            Event::Hangup => {
                // The shell is gone, with the pipe it read: a file.
                std::fs::write(param("BINGSU_TEST_REPORT"), "job: Hangup\n").unwrap();
                return;
            }
            // Dropping the session raises it again.
            Event::Signal(_) => return,
            e => panic!("{e:?}"),
        }
    }
    say(&format!("job: resumed {resumed}"));
    say(&format!("job: typed {}", shown(&typed)));
    drop(s);
    if let Some(sibling) = &mut sibling {
        let _ = sibling.kill();
        let _ = sibling.wait();
    }
}

// The session waits in the background (another process group has the
// terminal) and its wait on the pipe fails: it ends with `Hangup` instead
// of waiting again. 이것을 실패시키는 것: 실패한 기다림 뒤에도 다시 기다리는 것(끝나지 않음).
#[test]
fn a_failed_wait_in_the_background_ends_the_session() {
    let t = start("background_failure_child", &[]);
    let (lines, _) = t.mode_restored_after();
    assert_eq!(lines, ["Hangup"]);
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn background_failure_child() {
    use std::os::unix::process::CommandExt;
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    let mut other = std::process::Command::new("sleep")
        .arg("30")
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let group = libc::pid_t::try_from(other.id()).unwrap();
    give_terminal(group);
    // SAFETY: raises SIGCONT on this thread; the session's handler takes it.
    unsafe { libc::raise(libc::SIGCONT) };
    test_session::FAIL_SELECT.set(true);
    say(&format!("{:?}", s.wait(false, Some(Instant::now() + WAIT))));
    // SAFETY: getpgrp takes no arguments and cannot fail.
    give_terminal(unsafe { libc::getpgrp() });
    drop(s);
    other.kill().unwrap();
    other.wait().unwrap();
}

// A time limit years away (macOS select refuses more than 1e8 s): the wait
// still waits, and a key ends it. 이것을 실패시키는 것: select에 남은 시간을 그대로 넘기는 것(macOS에서 EINVAL로
// Hangup; Linux에서는 살아남음).
#[test]
fn a_wait_with_a_far_time_limit_goes_on() {
    let mut t = start("far_limit_child", &[]);
    t.expect(b"READY");
    t.send(b"k");
    let (lines, _) = t.mode_restored_after();
    assert_eq!(lines, ["Input([107])"]);
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn far_limit_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    draw(&mut s, b"READY");
    let years = Instant::now() + Duration::from_secs(4 * 365 * 24 * 60 * 60);
    say(&format!("{:?}", s.wait(false, Some(years))));
}

// Another reader of the foreground group takes the keys between the select
// and the read, which then gives 0: no hang-up, and the next key comes. The
// child says so from the branch itself (on its standard error) before the
// next key is sent, so the key cannot be what that read got.
// 이것을 실패시키는 것: 0바이트 읽기를 끝난 터미널로 보는 것(Hangup; READ NOTHING이 오지 않음).
#[test]
fn a_read_of_nothing_is_no_hang_up() {
    let mut t = start("stolen_input_child", &[]);
    t.expect(b"READY");
    t.send(b"x");
    t.expect_stderr("READ NOTHING");
    t.send(b"q");
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["Input([113])"]);
    assert_eq!(
        shown(&all),
        shown(&cat(&[ENTER_ALL, b"\x1b[H\x1b[2JREADY", LEAVE_ALL]))
    );
}

// The write of no bytes after a read of nothing is interrupted, or would
// wait (on Linux another writer of the group can hold the terminal's write
// lock): that tells nothing of a hang-up, and the next key comes.
// 이것을 실패시키는 것: 일시적인 오류를 끊김으로 보는 것(Hangup; READ NOTHING이 오지 않음), 둘 중 하나만 일시적으로
// 보는 것(그 칸).
#[test]
fn a_probe_that_would_wait_is_no_hang_up() {
    for errno in [libc::EAGAIN, libc::EINTR] {
        let errno = errno.to_string();
        let mut t = start("stolen_input_child", &[("BINGSU_TEST_PROBE", &errno)]);
        t.expect(b"READY");
        t.send(b"x");
        t.expect_stderr("READ NOTHING");
        t.send(b"q");
        let (lines, _) = t.mode_restored_after();
        assert_eq!(lines, ["Input([113])"], "errno {errno}");
    }
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn stolen_input_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    draw(&mut s, b"READY");
    test_session::STEAL.set(true);
    if let Some(errno) = param_if_given("BINGSU_TEST_PROBE") {
        test_session::PROBE.set(Some(errno.parse().unwrap()));
    }
    say(&format!("{:?}", s.wait(false, Some(Instant::now() + WAIT))));
}

// The terminal takes the first 3 bytes of the way out and then nothing: the
// sequence it is in is ended, and the mode goes back all the same.
// 이것을 실패시키는 것: 반쯤 나간 복구 열을 끊지 않는 것, 그때 termios를 되돌리지 않는 것.
#[test]
fn a_way_out_the_terminal_stopped_taking_is_ended() {
    let mut t = start("partial_leave_child", &[]);
    t.expect(&cat(&[ENTER_ALL, b"\x1b[0"]));
    t.send(&[test_terminal::READ]);
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["restored true"]);
    assert_eq!(shown(&all), shown(&cat(&[ENTER_ALL, b"\x1b[0", CANCEL])));
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn partial_leave_child() {
    take_signals();
    let tty = take_terminal();
    let before = mode();
    let s = tty.full_screen().unwrap();
    test_terminal::ROOM.set(Some((3, test_terminal::Then::Stall)));
    drop(s);
    say(&format!("restored {}", mode() == before));
}

// A SIGTSTP that came as the first session ended, never handled: the next
// session does not stop for it. 이것을 실패시키는 것: 새 세션이 앞 세션의 깃발을 지우지 않는 것.
#[test]
fn a_new_session_starts_with_no_signal_seen() {
    let t = start("two_sessions_child", &[]);
    let (lines, all) = t.mode_restored_after();
    assert_eq!(lines, ["Timeout"]);
    assert_eq!(
        shown(&all),
        shown(&cat(&[ENTER_ALL, LEAVE_ALL, ENTER_ALL, LEAVE_ALL]))
    );
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn two_sessions_child() {
    take_signals();
    let tty = take_terminal();
    let s = tty.full_screen().unwrap();
    // SAFETY: raises SIGTSTP in this thread; the session's handler takes it.
    unsafe { libc::raise(libc::SIGTSTP) };
    drop(s);
    let mut s = tty.full_screen().unwrap();
    let short = Instant::now() + Duration::from_millis(100);
    say(&format!("{:?}", s.wait(false, Some(short))));
}

// A signal that interrupts the select itself (here SIGWINCH with no size
// change, sent to the waiting thread): the wait goes on to its time limit.
// 이것을 실패시키는 것: select의 EINTR을 끝난 터미널로 보는 것(Hangup).
#[test]
fn an_interrupted_wait_goes_on() {
    let t = start("interrupted_child", &[]);
    let (lines, _) = t.mode_restored_after();
    assert_eq!(lines, ["Timeout"]);
}

#[test]
#[ignore = "child: a session on a pseudo-terminal"]
fn interrupted_child() {
    take_signals();
    let tty = take_terminal();
    let mut s = tty.full_screen().unwrap();
    // SAFETY: pthread_self takes no arguments and cannot fail.
    let me = unsafe { libc::pthread_self() } as usize;
    let poke = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: `me` is the waiting thread, alive until the join below.
        unsafe { libc::pthread_kill(me as libc::pthread_t, libc::SIGWINCH) };
    });
    let until = Instant::now() + Duration::from_millis(400);
    say(&format!("{:?}", s.wait(false, Some(until))));
    poke.join().unwrap();
}

/// Run by a real shell (tests/shell/test_tty_session.py): draws
/// `SCREEN n COLSxROWS` on entering and after each `Resumed` or `Resized`,
/// stops on Ctrl-Z and ends on `q`. Its lines go to its standard output.
#[test]
#[ignore = "child: run by tests/shell/test_tty_session.py"]
fn screen_child() {
    take_signals();
    let tty = Tty::open().unwrap();
    let mut s = tty.full_screen().unwrap();
    let mut n = 1;
    let show = |s: &mut Session<'_>, n: usize| {
        let size = s.size();
        draw(
            s,
            format!("SCREEN {n} {}x{}", size.cols, size.rows).as_bytes(),
        );
    };
    show(&mut s, n);
    loop {
        match s.wait(false, None) {
            Event::Input(b"\x1a") => s.suspend(),
            Event::Input(b"q") => break,
            Event::Input(_) => {}
            e @ (Event::Resumed(_) | Event::Resized(_)) => {
                say(&format!("{e:?}"));
                n += 1;
                show(&mut s, n);
            }
            e => {
                say(&format!("{e:?}"));
                break;
            }
        }
    }
    say("done");
}
