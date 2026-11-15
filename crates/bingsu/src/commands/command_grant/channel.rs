//! Sending the grant to the supervisor and waiting for it.
use super::*;

/// Writes all of `bytes` to the non-blocking `fd` by `until_ns`, waiting in
/// `poll` when the channel is full: the supervisor reads the grant while it
/// arrives, and a channel can be smaller than the frame (a Linux pipe past
/// pipe-user-pages-soft, m6-C1a). The wait relies on `POLLOUT` being exact,
/// which is why macOS gets a socket (`command_process::channel`).
pub(super) fn send(fd: i32, bytes: &[u8], until_ns: u64) -> bool {
    send_with(
        bytes,
        until_ns,
        &mut || now_ns().ok(),
        &mut |b: &[u8]| {
            // SAFETY: `b` is readable for its length.
            let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
            usize::try_from(n)
                .map_err(|_| std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        },
        &mut |wait_ms| {
            let mut fds = [libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            }];
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(fds.as_mut_ptr(), 1, wait_ms) };
        },
    )
}

/// `send` with its clock, write and wait passed in (tests replace them).
pub(super) fn send_with(
    mut bytes: &[u8],
    until_ns: u64,
    now: &mut dyn FnMut() -> Option<u64>,
    write: &mut dyn FnMut(&[u8]) -> Result<usize, i32>,
    wait: &mut dyn FnMut(i32),
) -> bool {
    while !bytes.is_empty() {
        // Before the first write and every retry: a late grant is no grant.
        if now().is_none_or(|at| at >= until_ns) {
            return false;
        }
        match write(bytes) {
            Ok(n) => {
                bytes = &bytes[n..];
                continue;
            }
            Err(libc::EAGAIN | libc::EINTR) => {}
            Err(_) => return false,
        }
        // The clock again right before the wait: the write itself took time.
        let Some(at) = now().filter(|&at| at < until_ns) else {
            return false;
        };
        wait(i32::try_from((until_ns - at).div_ceil(1_000_000)).unwrap_or(i32::MAX));
    }
    true
}

/// Waits for the supervisor to exit (it ends its children first) until the
/// helper's deadline; the drop then kills and reaps whatever is left.
/// Whether it exited.
pub(super) fn wait(child: &mut OwnedChild, deadline: u64) -> bool {
    loop {
        match child.reap() {
            Ok(true) => return true,
            Ok(false) if now_ns().is_ok_and(|now| now < deadline) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            _ => return false,
        }
    }
}
