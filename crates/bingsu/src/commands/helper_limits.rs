//! Helper-only limits and an independent watchdog, ready before NSS or roots.
use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const LIFETIME: Duration = Duration::from_secs(2);
const MEMORY: u64 = 128 * 1024 * 1024;

pub struct Watchdog {
    #[cfg(target_os = "linux")]
    initial_vm: u64,
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
pub fn start(started: Instant) -> io::Result<Watchdog> {
    start_for(started, LIFETIME)
}
fn start_for(started: Instant, lifetime: Duration) -> io::Result<Watchdog> {
    let deadline = started
        .checked_add(lifetime)
        .ok_or_else(|| io::Error::other("deadline"))?;
    let baseline = memory_usage()?;
    let (stop, stopped) = mpsc::channel();
    let (ready, prepared) = mpsc::sync_channel(0);
    let thread = std::thread::Builder::new()
        .name("refresh-watchdog".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            if ready.send(()).is_err() {
                return;
            }
            loop {
                if Instant::now() >= deadline || memory_exceeded(baseline) {
                    kill_self();
                }
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(2));
                match stopped.recv_timeout(remaining) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        })?;
    prepared
        .recv()
        .map_err(|_| io::Error::other("watchdog readiness"))?;
    Ok(Watchdog {
        #[cfg(target_os = "linux")]
        initial_vm: baseline,
        stop,
        thread: Some(thread),
    })
}
fn kill_self() -> ! {
    // SAFETY: getpid has no arguments or preconditions.
    let pid = unsafe { libc::getpid() };
    // SAFETY: own process, uncatchable signal. This also terminates blocked worker threads.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc == 0 {
        loop {
            // SAFETY: wait for the uncatchable signal; never race it with _exit.
            unsafe { libc::pause() };
        }
    }
    // SAFETY: fallback if an outer sandbox refused kill; never resume publication.
    unsafe { libc::_exit(1) }
}
#[cfg(target_os = "macos")]
fn memory_usage() -> io::Result<u64> {
    // SAFETY: integer-only storage, filled by proc_pid_rusage.
    let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: no arguments.
    let pid = unsafe { libc::getpid() };
    // SAFETY: V2 storage has the documented layout and sufficient capacity.
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            (&mut usage as *mut libc::rusage_info_v2).cast(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usage.ri_phys_footprint)
}
#[cfg(target_os = "linux")]
fn memory_usage() -> io::Result<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let pages: u64 = statm
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("statm"))?
        .parse()
        .map_err(io::Error::other)?;
    // SAFETY: read-only constant query.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    pages
        .checked_mul(u64::try_from(page).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::other("VM overflow"))
}
#[cfg(target_os = "macos")]
fn memory_exceeded(baseline: u64) -> bool {
    memory_usage().map_or(true, |now| now > baseline.saturating_add(MEMORY))
}
#[cfg(not(target_os = "macos"))]
fn memory_exceeded(_: u64) -> bool {
    false
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(any(target_os = "macos", target_env = "musl"))]
type Resource = libc::c_int;
fn get(resource: Resource) -> io::Result<libc::rlimit> {
    // SAFETY: writable integer-only storage.
    let mut value = unsafe { std::mem::zeroed() };
    // SAFETY: valid resource and output pointer.
    if unsafe { libc::getrlimit(resource, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
fn set(resource: Resource, soft: libc::rlim_t, hard: libc::rlim_t) -> io::Result<()> {
    let value = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: valid resource and initialized rlimit.
    if unsafe { libc::setrlimit(resource, &value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let got = get(resource)?;
    if got.rlim_cur != soft || got.rlim_max != hard {
        return Err(io::Error::other("rlimit readback"));
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn kernel_nofile() -> io::Result<libc::rlim_t> {
    let mut cap: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&cap);
    // SAFETY: fixed read-only name, correctly sized c_int storage.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut cap as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size != std::mem::size_of_val(&cap) || cap <= 0 {
        return Err(io::Error::other("maxfilesperproc"));
    }
    Ok(cap as libc::rlim_t)
}
#[cfg(target_os = "linux")]
fn kernel_nofile() -> io::Result<libc::rlim_t> {
    Ok(libc::RLIM_INFINITY)
}

pub fn install(watchdog: &Watchdog) -> io::Result<()> {
    let _ = watchdog;
    let fd = get(libc::RLIMIT_NOFILE)?;
    set(
        libc::RLIMIT_NOFILE,
        4608.min(fd.rlim_max).min(kernel_nofile()?),
        fd.rlim_max,
    )?;
    let cpu = get(libc::RLIMIT_CPU)?;
    set(libc::RLIMIT_CPU, 1.min(cpu.rlim_max), 2.min(cpu.rlim_max))?;
    let file = get(libc::RLIMIT_FSIZE)?;
    set(
        libc::RLIMIT_FSIZE,
        (32 * 1024 * 1024).min(file.rlim_max),
        file.rlim_max,
    )?;
    #[cfg(target_os = "linux")]
    {
        let old = get(libc::RLIMIT_AS)?;
        let cap = watchdog
            .initial_vm
            .checked_add(MEMORY)
            .ok_or_else(|| io::Error::other("VM cap"))?;
        set(
            libc::RLIMIT_AS,
            cap.min(old.rlim_cur).min(old.rlim_max),
            old.rlim_max,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    // 이것을 실패시키는 것: 자식만 NOFILE을 올리지 않거나 CPU·FSIZE readback을 생략하는 것.
    #[test]
    #[ignore = "isolated rlimit child"]
    fn limits_child() {
        // SAFETY: isolated test process only.
        unsafe { libc::umask(0o777) };
        super::super::helper::detach().unwrap();
        // SAFETY: readback with the same helper mask, isolated process.
        let mask = unsafe { libc::umask(0o077) };
        assert_eq!(mask, 0o077);
        // SAFETY: read-only process queries, own process.
        let sid = unsafe { libc::getsid(0) };
        // SAFETY: no arguments.
        assert_eq!(sid, unsafe { libc::getpid() });
        let old = get(libc::RLIMIT_NOFILE).unwrap();
        set(libc::RLIMIT_NOFILE, 256.min(old.rlim_max), old.rlim_max).unwrap();
        let started = Instant::now();
        let _watchdog = start(started).unwrap();
        install(&_watchdog).unwrap();
        let fd = get(libc::RLIMIT_NOFILE).unwrap();
        assert_eq!(
            fd.rlim_cur,
            4608.min(old.rlim_max).min(kernel_nofile().unwrap())
        );
        assert_eq!(fd.rlim_max, old.rlim_max);
        assert_eq!(get(libc::RLIMIT_CPU).unwrap().rlim_cur, 1);
        assert!(get(libc::RLIMIT_CPU).unwrap().rlim_max <= 2);
        assert_eq!(get(libc::RLIMIT_FSIZE).unwrap().rlim_cur, 32 * 1024 * 1024);
        let lower = get(libc::RLIMIT_NOFILE).unwrap();
        set(libc::RLIMIT_NOFILE, 256, 1024.min(lower.rlim_max)).unwrap();
        install(&_watchdog).unwrap();
        assert_eq!(
            get(libc::RLIMIT_NOFILE).unwrap().rlim_cur,
            1024.min(kernel_nofile().unwrap())
        );
    }
    // 이것을 실패시키는 것: watchdog가 worker 협조를 기다리거나 2초 수명을 강제하지 않는 것.
    #[test]
    #[ignore = "watchdog intentionally kills this child"]
    fn watchdog_child() {
        let _watchdog = start(Instant::now()).unwrap();
        std::thread::sleep(Duration::from_secs(10));
        panic!("watchdog did not kill");
    }
    // 이것을 실패시키는 것: macOS footprint 감시 또는 Linux VM 상한을 제거하는 것.
    #[test]
    #[ignore = "memory limit isolated child"]
    fn memory_child() {
        let _watchdog = start(Instant::now()).unwrap();
        install(&_watchdog).unwrap();
        let mut memory = Vec::<u8>::new();
        #[cfg(target_os = "linux")]
        {
            assert!(memory.try_reserve_exact(160 * 1024 * 1024).is_err());
        }
        #[cfg(target_os = "macos")]
        {
            memory.resize(160 * 1024 * 1024, 0x7f);
            std::hint::black_box(&mut memory);
            std::thread::sleep(Duration::from_secs(1));
            panic!("footprint not enforced");
        }
    }
    // 이것을 실패시키는 것: 메모리 한도를 적용하지 않아 큰 할당이 계속되는 것.
    #[test]
    fn memory_is_enforced() {
        let out = child("commands::helper_limits::tests::memory_child");
        #[cfg(target_os = "macos")]
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGKILL),
            "{:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        #[cfg(target_os = "linux")]
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    fn child(name: &str) -> std::process::Output {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap()
    }
    // 이것을 실패시키는 것: rlimit을 부모에 적용하거나 watchdog 시작 barrier·SIGKILL을 제거하는 것.
    #[test]
    fn limits_and_independent_lifetime() {
        let before = get(libc::RLIMIT_NOFILE).unwrap();
        let out = child("commands::helper_limits::tests::limits_child");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let after = get(libc::RLIMIT_NOFILE).unwrap();
        assert_eq!(
            (before.rlim_cur, before.rlim_max),
            (after.rlim_cur, after.rlim_max)
        );
        let start = Instant::now();
        let out = child("commands::helper_limits::tests::watchdog_child");
        assert_eq!(out.status.signal(), Some(libc::SIGKILL));
        assert!(start.elapsed() >= Duration::from_millis(1800));
        assert!(start.elapsed() < Duration::from_secs(4));
    }
}
