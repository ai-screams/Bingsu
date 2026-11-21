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

/// Keys read from a real pseudo-terminal in raw mode: split sequences,
/// pastes, Enter under `ICRNL`, Ctrl-D, and a hang-up. The child test runs
/// in a process of its own with the pseudo-terminal as its controlling
/// terminal; the parent types into it and reads what it reports.
#[cfg(test)]
#[allow(unsafe_code)]
mod pty {
    use super::KeyInput;
    use crate::commands::tty::{Terminal, Tty};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// The longest any step may take.
    const WAIT: Duration = Duration::from_secs(10);

    struct Pty {
        _spawns: std::sync::MutexGuard<'static, ()>,
        master: Option<File>,
        child: Child,
        unread: Vec<u8>,
        all: Vec<u8>,
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
        // Without close-on-exec the child would hold the master too, and
        // closing it here would not hang up.
        for fd in [master, slave] {
            // SAFETY: the descriptors openpty just made.
            let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            assert_eq!(rc, 0);
        }
        // SAFETY: a new descriptor, owned once from here on.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: as above.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        assert_eq!(
            // SAFETY: the test owns the master's description.
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("commands::keys::pty::{name}"),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(Stdio::from(slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Pty {
            _spawns: spawns,
            master: Some(master),
            child,
            unread: Vec::new(),
            all: Vec::new(),
        }
    }

    impl Pty {
        /// Reads what the child wrote for up to `d`; `true` once `stop`
        /// says so of what is unread.
        fn pump(&mut self, d: Duration, stop: impl Fn(&[u8]) -> bool) -> bool {
            let until = Instant::now() + d;
            let mut buf = [0u8; 256];
            loop {
                if stop(&self.unread) {
                    return true;
                }
                let Some(mut m) = self.master.as_ref() else {
                    return false;
                };
                if let Ok(n @ 1..) = m.read(&mut buf) {
                    self.unread.extend_from_slice(&buf[..n]);
                    self.all.extend_from_slice(&buf[..n]);
                    continue;
                }
                if Instant::now() >= until {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        fn expect(&mut self, want: &[u8]) {
            let found = |b: &[u8]| b.windows(want.len()).any(|w| w == want);
            assert!(
                self.pump(WAIT, found),
                "no {:?} in {:?}",
                want.escape_ascii().to_string(),
                self.all.escape_ascii().to_string()
            );
            let at = self
                .unread
                .windows(want.len())
                .position(|w| w == want)
                .unwrap();
            self.unread.drain(..at + want.len());
        }

        /// The next report of the child: `keys bytes` (bytes `-` for a
        /// tick).
        fn next_report(&mut self) -> String {
            let line = |b: &[u8]| b.windows(2).any(|w| w == b"\r\n");
            assert!(
                self.pump(WAIT, line),
                "no report in {:?}",
                self.all.escape_ascii().to_string()
            );
            let at = self.unread.windows(2).position(|w| w == b"\r\n").unwrap();
            let text = String::from_utf8_lossy(&self.unread[..at]).into_owned();
            self.unread.drain(..at + 2);
            text.strip_prefix("K ")
                .unwrap_or_else(|| panic!("not a report: {text:?}"))
                .to_owned()
        }

        /// The keys of the next report.
        fn next_keys(&mut self) -> String {
            let report = self.next_report();
            report
                .rsplit_once(' ')
                .map_or(report.clone(), |(k, _)| k.to_owned())
        }

        /// Types as the terminal's user would, in one write.
        fn send(&mut self, bytes: &[u8]) {
            let fd = self.master.as_ref().unwrap().as_raw_fd();
            // SAFETY: the master is open and `bytes` is a valid slice.
            let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            assert_eq!(usize::try_from(n).ok(), Some(bytes.len()));
        }

        /// Reads for `d` without typing.
        fn idle(&mut self, d: Duration) {
            self.pump(d, |_| false);
        }

        /// Types `x` once the reader is surely back in Ground (past any
        /// drain) and checks that it is the next report: nothing came out
        /// of what was typed before.
        fn nothing_more(&mut self) {
            self.idle(Duration::from_millis(250));
            self.send(b"x");
            assert_eq!(self.next_keys(), "[Char(120)]");
        }

        /// Closes the master (the terminal goes away) and waits for the
        /// child, which must pass or end with SIGHUP. Its `ANSWER` lines.
        fn hang_up(mut self) -> Vec<String> {
            self.master = None;
            let until = Instant::now() + WAIT;
            let status = loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= until {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!("the child did not end");
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut out = String::new();
            let mut err = String::new();
            self.child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut out)
                .unwrap();
            self.child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            // The terminal's hang-up also sends SIGHUP to the child, a
            // session leader: the guard takes it and raises it again once
            // the terminal is put back, after the report.
            use std::os::unix::process::ExitStatusExt as _;
            assert!(
                status.success() || status.signal() == Some(libc::SIGHUP),
                "{status:?}\n{out}\n{err}"
            );
            out.lines()
                .filter_map(|l| l.split_once("ANSWER "))
                .map(|(_, a)| a.to_owned())
                .collect()
        }
    }

    // 이것을 실패시키는 것: 실제 raw 터미널에서 나뉜 화살표의 `[`·`A`나 늦은 나머지가 키가 되는 것, 표지 있는 붙여
    // 넣기나 표지 없는 묶음의 키가 나오는 것, Enter가 ICRNL로 LF가 되어 오는데 Enter로 읽지 않는 것, Ctrl-D를 입력의
    // 끝으로 보는 것, 끊긴 터미널을 입력의 끝으로 알리지 않는 것.
    #[test]
    fn keys_on_a_pseudo_terminal() {
        let mut t = start("keys_child");
        t.expect(b"READY\r\n");

        // An arrow key split 5 ms apart: Up. A busy machine may read the
        // ESC alone for 30 ms (then the Esc key, and the rest is late);
        // either way no `[` or `A`.
        t.send(b"\x1b");
        std::thread::sleep(Duration::from_millis(5));
        t.send(b"[A");
        let split = t.next_keys();
        assert!(split == "[Up]" || split == "[Esc]", "{split}");
        t.nothing_more();

        // Split 50 ms apart: the Esc key, and the late rest is dropped (a
        // machine too busy to read the ESC alone reads Up).
        t.send(b"\x1b");
        std::thread::sleep(Duration::from_millis(50));
        t.send(b"OA");
        let late = t.next_keys();
        assert!(late == "[Esc]" || late == "[Up]", "{late}");
        println!("split 5 ms: {split}; split 50 ms: {late}");
        t.nothing_more();

        // Enter: raw mode keeps ICRNL, so CR comes as LF.
        t.send(b"\r");
        assert_eq!(t.next_report(), "[Enter] 0a");
        t.send(b"\n");
        assert_eq!(t.next_report(), "[Enter] 0a");
        // Ctrl-D is a key; the reader goes on.
        t.send(b"\x04");
        assert_eq!(t.next_keys(), "[Ctrl(100)]");

        // A bracketed paste, its end mark split: nothing. Fewer than four
        // keys per read, so it is the marks that drop it, not a burst.
        t.send(b"\x1b[200~q\r");
        std::thread::sleep(Duration::from_millis(5));
        t.send(b"s\x1b[20");
        std::thread::sleep(Duration::from_millis(5));
        t.send(b"1~");
        t.nothing_more();

        // Four keys in one read without the marks: nothing.
        t.send(b"qqqq");
        t.nothing_more();

        // Three keys in one read are typed keys, reported together.
        t.send(b"jjj");
        assert_eq!(t.next_keys(), "[Char(106), Char(106), Char(106)]");

        assert_eq!(t.hang_up(), ["end of input"]);
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

    /// The child: the terminal in raw mode (`Tty::raw`, the mode the editor
    /// uses), each read of fd 0 (the same terminal) fed to the key reader
    /// as it comes, and each tick at the reader's deadline. Keys are
    /// reported on the terminal as `K <keys> <bytes of the read in hex>`.
    #[test]
    #[ignore = "child: reads keys on a pseudo-terminal"]
    fn keys_child() {
        let tty = take_terminal();
        let mut g = tty.raw().unwrap();
        let mut input = KeyInput::new(Instant::now());
        // Output keeps ONLCR: `\n` comes out as `\r\n`.
        g.write(b"READY\n").unwrap();
        let end = Instant::now() + 3 * WAIT;
        let mut buf = [0u8; 1024];
        while Instant::now() < end {
            let until = input
                .deadline()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
            let (keys, bytes) = if readable(0, until) {
                // SAFETY: fd 0 is the terminal; `buf` is writable.
                let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
                // Readable but nothing (or EIO): the terminal went away.
                let Ok(n @ 1..) = usize::try_from(n) else {
                    println!("ANSWER end of input");
                    return;
                };
                let hex: String = buf[..n].iter().map(|b| format!("{b:02x}")).collect();
                (input.feed(&buf[..n], Instant::now()), hex)
            } else {
                (input.tick(Instant::now()), "-".to_owned())
            };
            if !keys.is_empty() {
                let line = format!("K {:?} {bytes}\n", keys.as_slice());
                g.write(line.as_bytes()).unwrap();
            }
        }
        panic!("no hang-up");
    }
}
