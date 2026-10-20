//! Parent-side deadlines: never block on a probe's pipes before checking time.
use std::{
    io::{self, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const CAPTURE_LIMIT: usize = 1024 * 1024;

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        // Also stop compiler subprocesses or an unexpected fork holding a pipe.
        // SAFETY: spawn put this child in its own process group.
        unsafe { libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL) };
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: read the flags of a live, owned pipe.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: only change this parent's pipe to nonblocking mode.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_available(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> io::Result<bool> {
    // One bounded read per iteration: continuous output cannot starve the timer
    // or the other pipe. Output beyond the diagnostic cap is still drained.
    let mut buf = [0; 8192];
    match pipe.read(&mut buf) {
        Ok(0) => Ok(true),
        Ok(n) => {
            let keep = n.min(CAPTURE_LIMIT.saturating_sub(bytes.len()));
            bytes.extend_from_slice(&buf[..keep]);
            Ok(false)
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

pub fn output(command: &mut Command, label: &str, timeout: Duration) -> io::Result<Output> {
    let mut child = Guard(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?,
    );
    let deadline = Instant::now() + timeout;
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    loop {
        if !out_eof {
            out_eof = read_available(&mut stdout, &mut out)?;
        }
        if !err_eof {
            err_eof = read_available(&mut stderr, &mut err)?;
        }
        if let Some(status) = child.0.try_wait()? {
            if out_eof && err_eof {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        if Instant::now() >= deadline {
            // Guard kills the group and reaps the direct child before returning
            // this error. Never call wait_with_output or join pipe readers here.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{label}: timed out after {timeout:?}; pid={}; stdout={:?}; stderr={:?}",
                    child.0.id(),
                    String::from_utf8_lossy(&out),
                    String::from_utf8_lossy(&err),
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
