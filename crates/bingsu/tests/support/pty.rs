//! Running a test command with standard output on a pseudo-terminal.
/// What `cmd` writes with standard output on a new pseudo-terminal of `cols`
/// columns, `\r\n` read back as `\n`, and how it exited. Standard error goes
/// to /dev/null.
#[allow(
    clippy::unnecessary_mut_passed,
    reason = "openpty takes the window size as *mut on macOS and *const on Linux"
)]
pub fn on_a_terminal(mut cmd: std::process::Command, cols: u16) -> (Option<i32>, String) {
    use std::io::Read as _;
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: an all-zero `winsize` is valid; the size is set below.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    size.ws_col = cols;
    size.ws_row = 24;
    // SAFETY: two writable descriptor outputs; default termios.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: the descriptor openpty just made, owned from here on.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // SAFETY: as above.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    for fd in [&master, &slave] {
        use std::os::fd::AsRawFd as _;
        // SAFETY: an open descriptor; other tests' children must not keep it.
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        assert_eq!(rc, 0);
    }
    // Read while the child writes: once the slave closes, Linux may drop what
    // is still queued.
    let mut master = std::fs::File::from(master);
    let reader = std::thread::spawn(move || {
        let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
        loop {
            match master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                // EIO: the last slave descriptor closed.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("{e}"),
            }
        }
        out
    });
    let status = cmd
        .stdout(std::process::Stdio::from(slave))
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    // The command holds the slave: drop it before reading to the end.
    drop(cmd);
    let out = reader.join().unwrap();
    (
        status.code(),
        String::from_utf8_lossy(&out).replace("\r\n", "\n"),
    )
}
