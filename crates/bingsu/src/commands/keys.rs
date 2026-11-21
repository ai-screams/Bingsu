//! The editor's keys (`bingsu setup`): the key reader of
//! `bingsu_core::keys` on this process's monotonic clock. Not on any
//! prompt path.
//!
//! The full-screen session's wait gives what one read of the terminal
//! brought; [`KeyInput::feed`] turns it into keys at once (keys from one
//! read come together, which is how a confirmation tells a later read from
//! the same one). The session's wait takes [`KeyInput::deadline`] as its
//! time limit (with the frame writer's and the animation's), and on a
//! timeout [`KeyInput::tick`] gives the Esc key or ends a bound. After a
//! stop and a resume, [`KeyInput::reset`]: input typed meanwhile was
//! dropped, so a sequence in progress has no rest to come.
//!
//! End of input is the session's: a read that gives 0 bytes or fails with
//! EIO after the terminal was ready is a hang-up, and the editor ends
//! without saving. A 0x04 byte is Ctrl-D, a key.
use bingsu_core::keys::{KeyReader, Keys};
use std::time::{Duration, Instant};

pub struct KeyInput {
    reader: KeyReader,
    /// The time the reader's offsets count from.
    origin: Instant,
}

impl KeyInput {
    pub fn new(origin: Instant) -> Self {
        Self {
            reader: KeyReader::new(),
            origin,
        }
    }

    /// The keys of one read, `bytes`, which came at `now`.
    pub fn feed(&mut self, bytes: &[u8], now: Instant) -> Keys {
        self.reader.feed(bytes, self.since(now))
    }

    /// The keys time alone makes by `now` (the Esc key, or none).
    pub fn tick(&mut self, now: Instant) -> Keys {
        self.reader.tick(self.since(now))
    }

    /// When `tick` is due; `None` while nothing waits on time.
    pub fn deadline(&self) -> Option<Instant> {
        // 이것을 실패시키는 것: 기한을 기준 시각으로 되돌리지 않는 것(홀로 된 Esc가 30 ms 뒤가 아니라 바로 또는 영영
        // 끝남).
        self.reader
            .deadline()
            .and_then(|d| self.origin.checked_add(d))
    }

    /// Forgets a sequence in progress.
    pub fn reset(&mut self) {
        self.reader.reset();
    }

    fn since(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::keys::{ESC_WAIT, Key};

    // 이것을 실패시키는 것: 기준 시각에서 잰 시각을 넘기지 않는 것, 기한을 이 프로세스의 시각으로 되돌리지 않는 것.
    #[test]
    fn times_count_from_the_origin() {
        let origin = Instant::now();
        let mut input = KeyInput::new(origin);
        let at = origin + Duration::from_secs(5);
        assert!(input.feed(b"\x1b", at).is_empty());
        assert_eq!(input.deadline(), Some(at + ESC_WAIT));
        assert!(
            input
                .tick(at + ESC_WAIT - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(input.tick(at + ESC_WAIT).as_slice(), [Key::Esc]);
        assert_eq!(input.deadline(), None);
        // A time before the origin counts as the origin.
        assert_eq!(
            input
                .feed(b"q", origin - Duration::from_millis(1))
                .as_slice(),
            [Key::Char(b'q')]
        );
        input.feed(b"\x1b[", at);
        input.reset();
        assert_eq!(input.deadline(), None);
    }
}

/// Keys read from a real pseudo-terminal in raw mode (`Tty::raw`, the mode
/// the editor uses): split sequences, late rests, pastes, an 8-bit string,
/// Enter under `ICRNL`, Ctrl-D, bursts and a hang-up. The child test runs in
/// a process of its own with the pseudo-terminal as its controlling
/// terminal. Each step is synchronized, so no result depends on the
/// scheduler: the parent types into the terminal, then tells the child on
/// a control pipe how many bytes to read as one read and at which logical
/// time, and waits for the child's answer on its standard output. What this
/// shows is the real terminal's bytes (raw mode, `ICRNL`, no echo, 8-bit
/// bytes kept) going through the reader; the time bounds themselves are
/// the pure tests' business.
#[cfg(test)]
#[allow(unsafe_code)]
mod pty {
    use super::KeyInput;
    use crate::commands::tty::Tty;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::CommandExt as _;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{Receiver, channel};
    use std::time::{Duration, Instant};

    /// The longest any step may take.
    const WAIT: Duration = Duration::from_secs(10);

    /// The control pipe's descriptor in the child.
    const CONTROL: RawFd = 3;

    struct Pty {
        _spawns: std::sync::MutexGuard<'static, ()>,
        master: Option<File>,
        control: File,
        answers: Receiver<String>,
        child: Child,
    }

    #[allow(
        clippy::unnecessary_mut_passed,
        reason = "openpty takes the window size as *mut on macOS and *const on Linux"
    )]
    fn start(name: &str) -> Pty {
        let spawns = crate::commands::sys::test_inherited_fd_lock();
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: an all-zero `winsize` is valid; the size is set below.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        size.ws_col = 80;
        size.ws_row = 24;
        assert_eq!(
            // SAFETY: two writable descriptor outputs; default termios.
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut size,
                )
            },
            0
        );
        let mut ends = [-1; 2];
        // SAFETY: `ends` has room for the two descriptors.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // Without close-on-exec the child would hold the master too, and
        // closing it here would not hang up; the control pipe's read end
        // reaches the child only as fd 3.
        for fd in [master, slave, ends[0], ends[1]] {
            // SAFETY: descriptors just made.
            let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            assert_eq!(rc, 0);
        }
        // SAFETY: new descriptors, each owned once from here on.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: as above.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        // SAFETY: as above.
        let read_end = unsafe { OwnedFd::from_raw_fd(ends[0]) };
        // SAFETY: as above.
        let control = unsafe { File::from_raw_fd(ends[1]) };
        let from = read_end.as_raw_fd();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            &format!("commands::keys::pty::{name}"),
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let hook = move || {
            // SAFETY: `from` is open in the child until exec.
            let rc = unsafe { libc::dup2(from, CONTROL) };
            // SAFETY: fd 3 is open now; the call clears close-on-exec, also
            // when dup2 had nothing to do (`from` was 3).
            if rc < 0 || unsafe { libc::fcntl(CONTROL, libc::F_SETFD, 0) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: between fork and exec the hook calls only dup2 and fcntl,
        // which are async-signal-safe.
        unsafe { cmd.pre_exec(hook) };
        let mut child = cmd.spawn().unwrap();
        drop(read_end);
        let (tx, answers) = channel();
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                // libtest's "test ... " has no newline before the output.
                if let Some((_, answer)) = line.split_once("ANSWER ") {
                    if tx.send(answer.to_owned()).is_err() {
                        break;
                    }
                }
            }
        });
        Pty {
            _spawns: spawns,
            master: Some(master),
            control,
            answers,
            child,
        }
    }

    /// Writes all of `bytes` to `fd`.
    fn put(fd: RawFd, bytes: &[u8]) {
        let done = crate::commands::sys::write_fd(fd, bytes);
        assert!(matches!(done, crate::commands::sys::WriteOutcome::Done));
    }

    impl Pty {
        /// The child's next answer. On a timeout the child is ended and
        /// its error output shown.
        fn answer(&mut self) -> String {
            if let Ok(answer) = self.answers.recv_timeout(WAIT) {
                return answer;
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            let mut err = String::new();
            if let Some(mut e) = self.child.stderr.take() {
                let _ = e.read_to_string(&mut err);
            }
            panic!("no answer from the child:\n{err}");
        }

        fn tell(&mut self, line: &str) {
            put(self.control.as_raw_fd(), format!("{line}\n").as_bytes());
        }

        /// Types `bytes` as the terminal's user would; the child reads them
        /// as one read at `at` ms. Its answer: the keys and the bytes read,
        /// in hex.
        fn read(&mut self, bytes: &[u8], at: u64) -> String {
            put(self.master.as_ref().unwrap().as_raw_fd(), bytes);
            self.tell(&format!("R {at} {}", bytes.len()));
            self.answer()
        }

        /// The child ticks at `at` ms. Its answer: the keys and `-`.
        fn tick(&mut self, at: u64) -> String {
            self.tell(&format!("T {at}"));
            self.answer()
        }

        /// Closes the master (the terminal goes away), lets the child read
        /// once more and waits for it, which must pass or end with SIGHUP.
        /// Its last answer.
        fn hang_up(mut self) -> String {
            self.master = None;
            self.tell("E");
            let answer = self.answer();
            let until = Instant::now() + WAIT;
            let status = loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < until, "the child did not end");
                std::thread::sleep(Duration::from_millis(5));
            };
            // The hang-up also sends SIGHUP to the child, a session leader:
            // the guard takes it and raises it again once the terminal is
            // put back, after the answer.
            use std::os::unix::process::ExitStatusExt as _;
            assert!(
                status.success() || status.signal() == Some(libc::SIGHUP),
                "{status:?}"
            );
            answer
        }
    }

    // 이것을 실패시키는 것: 실제 raw 터미널의 바이트로 나뉜 화살표를 하나로 읽지 않는 것, Esc 판정 뒤 늦은 창 안의
    // 나머지를 키로 내는 것과 창 밖의 키를 버리는 것, 끝 표지가 나뉜 붙여 넣기나 8비트 문자열의 내용을 키로 내는 것,
    // 묶음의 키를 내는 것과 그 안의 Ctrl-C를 버리는 것, ICRNL로 LF가 되어 오는 Enter를 Enter로 읽지 않는 것(또는
    // raw 모드가 ICRNL을 끄는 것), Ctrl-D를 입력의 끝으로 보는 것, 끊긴 터미널을 입력의 끝으로 알리지 않는 것.
    #[test]
    fn keys_on_a_pseudo_terminal() {
        let mut t = start("keys_child");
        assert_eq!(t.answer(), "READY");

        // An arrow key in two reads 5 ms apart: Up.
        assert_eq!(t.read(b"\x1b", 0), "[] 1b");
        assert_eq!(t.read(b"[A", 5), "[Up] 5b41");
        // The rest 50 ms after the Esc key: late, dropped.
        assert_eq!(t.read(b"\x1b", 100), "[] 1b");
        assert_eq!(t.tick(130), "[Esc] -");
        assert_eq!(t.read(b"OA", 180), "[] 4f41");
        assert_eq!(t.read(b"x", 300), "[Char(120)] 78");
        // Past the late window: two keys.
        assert_eq!(t.read(b"\x1b", 400), "[] 1b");
        assert_eq!(t.tick(430), "[Esc] -");
        assert_eq!(t.read(b"OA", 600), "[Char(79), Char(65)] 4f41");

        // Enter: raw mode keeps ICRNL, so CR comes as LF; CR LF in one read
        // is two Enter keys of one read. Ctrl-D is a key.
        assert_eq!(t.read(b"\r", 700), "[Enter] 0a");
        assert_eq!(t.read(b"\n", 701), "[Enter] 0a");
        assert_eq!(t.read(b"\r\n", 702), "[Enter, Enter] 0a0a");
        assert_eq!(t.read(b"\x04", 703), "[Ctrl(100)] 04");

        // A bracketed paste, its end mark split, fewer than four keys per
        // read (so the marks drop it, not the burst guess); the drain after
        // it ends 100 ms after its last byte.
        assert_eq!(t.read(b"\x1b[200~q\r", 800), "[] 1b5b3230307e710a");
        assert_eq!(t.read(b"s\x1b[20", 801), "[] 731b5b3230");
        assert_eq!(t.read(b"1~", 802), "[] 317e");
        assert_eq!(t.tick(902), "[] -");
        assert_eq!(t.read(b"x", 903), "[Char(120)] 78");

        // An 8-bit APC (0x9f ... 0x9c) holding two CRs in two reads.
        assert_eq!(t.read(b"\x9f\r", 1000), "[] 9f0a");
        assert_eq!(t.read(b"\r\x9c", 1001), "[] 0a9c");
        assert_eq!(t.tick(1101), "[] -");

        // Four keys in one read: none, but for a Ctrl-C among them; three
        // keys are typed keys.
        assert_eq!(t.read(b"qqqq", 1200), "[] 71717171");
        assert_eq!(t.read(b"qq\x03q", 1201), "[Ctrl(99)] 71710371");
        assert_eq!(
            t.read(b"jjj", 1202),
            "[Char(106), Char(106), Char(106)] 6a6a6a"
        );

        assert_eq!(t.hang_up(), "end of input");
    }

    /// Waits until `fd` can be read or `until` passes.
    #[allow(
        clippy::unnecessary_fallible_conversions,
        reason = "`tv_usec` is 32 bits on macOS and 64 on Linux; one spelling for both"
    )]
    fn readable(fd: RawFd, until: Instant) -> bool {
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let mut tv = libc::timeval {
                tv_sec: left.as_secs().try_into().unwrap_or(0),
                tv_usec: left.subsec_micros().try_into().unwrap_or(0),
            };
            let mut set = std::mem::MaybeUninit::<libc::fd_set>::uninit();
            // SAFETY: `set` is writable memory; FD_ZERO initialises all of it.
            unsafe { libc::FD_ZERO(set.as_mut_ptr()) };
            // SAFETY: FD_ZERO above initialised `set`.
            let mut set = unsafe { set.assume_init() };
            // SAFETY: fd 0 fits the set, which is initialised.
            unsafe { libc::FD_SET(fd, &mut set) };
            // SAFETY: `set` and `tv` are valid for the call.
            let n = unsafe {
                libc::select(
                    fd + 1,
                    &mut set,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if n > 0 {
                return true;
            }
            if n == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return false;
            }
        }
    }

    /// In the child: makes stdin (the slave) the controlling terminal.
    #[allow(
        clippy::useless_conversion,
        reason = "TIOCSCTTY is c_uint on macOS and the ioctl request type elsewhere"
    )]
    fn take_terminal() -> Tty {
        // SAFETY: setsid takes no arguments; a test process is no group leader.
        assert!(unsafe { libc::setsid() } >= 0);
        // SAFETY: fd 0 is the slave this process holds.
        assert_eq!(unsafe { libc::ioctl(0, libc::TIOCSCTTY.into(), 0) }, 0);
        Tty::open().expect("the pseudo-terminal is the controlling terminal")
    }

    fn say(answer: &str) {
        println!("ANSWER {answer}");
        let _ = std::io::stdout().flush();
    }

    /// The child: the terminal in raw mode, and the parent's steps from the
    /// control pipe: `R <ms> <n>` reads `n` bytes of the terminal and feeds
    /// them as one read at `<ms>`, `T <ms>` ticks, `E` reads until the
    /// terminal is gone. Each step answers `<keys> <bytes in hex>`.
    #[test]
    #[ignore = "child: reads keys on a pseudo-terminal"]
    fn keys_child() {
        let tty = take_terminal();
        let _raw = tty.raw().unwrap();
        // SAFETY: the parent passed the control pipe's read end as fd 3,
        // owned here alone.
        let control = BufReader::new(unsafe { File::from_raw_fd(CONTROL) });
        let origin = Instant::now();
        let at = |ms: &str| origin + Duration::from_millis(ms.parse().unwrap());
        let mut input = KeyInput::new(origin);
        let mut buf = [0u8; 1024];
        // Reads what the terminal has, once it has some: `None` when it is
        // gone (a read of 0 bytes, or EIO).
        let read = |buf: &mut [u8]| {
            assert!(readable(0, Instant::now() + WAIT), "nothing to read");
            // SAFETY: fd 0 is the terminal; `buf` is writable.
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            usize::try_from(n).ok().filter(|&n| n > 0)
        };
        say("READY");
        for line in control.lines() {
            let line = line.unwrap();
            let words: Vec<&str> = line.split(' ').collect();
            match words[..] {
                ["R", ms, n] => {
                    let n: usize = n.parse().unwrap();
                    let mut got = Vec::new();
                    while got.len() < n {
                        let k = read(&mut buf).expect("the terminal is there");
                        got.extend_from_slice(&buf[..k]);
                    }
                    let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
                    say(&format!("{:?} {hex}", input.feed(&got, at(ms)).as_slice()));
                }
                ["T", ms] => say(&format!("{:?} -", input.tick(at(ms)).as_slice())),
                ["E"] => {
                    while read(&mut buf).is_some() {}
                    say("end of input");
                    return;
                }
                _ => panic!("unknown step {line:?}"),
            }
        }
        panic!("the control pipe closed");
    }
}
