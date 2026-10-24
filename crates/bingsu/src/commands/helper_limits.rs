//! Process-local limits and an independent watchdog, ready before NSS or roots.
use super::collector_process::{OwnedChild, SignalChild, now_ns};
use std::io;
use std::sync::mpsc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

pub const LIFETIME: Duration = Duration::from_secs(2);
const MEMORY: u64 = 128 * 1024 * 1024;
#[cfg(target_os = "macos")]
fn sample_over_limit(baseline: u64, sample: &io::Result<Option<u64>>) -> bool {
    sample.as_ref().map_or(true, |value| {
        value.is_some_and(|bytes| bytes > baseline.saturating_add(32 * 1024 * 1024))
    })
}
#[cfg(target_os = "macos")]
fn sample_wait(remaining: Duration) -> Duration {
    remaining.min(Duration::from_millis(2))
}

pub struct Watchdog {
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
    collector: Arc<Mutex<Option<WatchedCollector>>>,
    expires_ns: u64,
    #[cfg(all(test, target_os = "macos"))]
    #[allow(dead_code, reason = "native integration measurements")]
    pub(crate) observations: Arc<Mutex<Vec<(u64, u64, u64)>>>,
}
struct WatchedCollector {
    child: SignalChild,
    expires_ns: Arc<AtomicU64>,
    reason: Arc<AtomicU8>,
    #[cfg(target_os = "macos")]
    baseline: u64,
}
pub(crate) struct CollectorRegistration {
    collector: Arc<Mutex<Option<WatchedCollector>>>,
    expires_ns: Arc<AtomicU64>,
    reason: Arc<AtomicU8>,
    wake: mpsc::Sender<()>,
    request_started: bool,
}
impl CollectorRegistration {
    pub fn reason(&self) -> Option<bingsu_core::collection::wire::EndReason> {
        use bingsu_core::collection::wire::EndReason;
        match self.reason.load(Ordering::Acquire) {
            1 => Some(EndReason::Deadline),
            2 => Some(EndReason::Resource),
            _ => None,
        }
    }
    /// The sole Ready -> request transition. Updates/Progress cannot rearm it.
    pub fn begin_request(&mut self, deadline: u64) -> io::Result<()> {
        if self.request_started {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.request_started = true;
        self.expires_ns.store(deadline, Ordering::Release);
        let _ = self.wake.send(());
        Ok(())
    }
}
impl Drop for CollectorRegistration {
    fn drop(&mut self) {
        // The watchdog holds this same mutex through signal/sample completion.
        self.collector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let _ = self.wake.send(());
    }
}
impl Watchdog {
    pub fn expires_ns(&self) -> u64 {
        self.expires_ns
    }
    pub fn register_collector(
        &self,
        child: &OwnedChild,
        expires_ns: u64,
    ) -> io::Result<CollectorRegistration> {
        let mut slot = self.collector.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Err(io::Error::other("collector already registered"));
        }
        let child = child.signal_copy()?;
        #[cfg(target_os = "macos")]
        let baseline = child
            .footprint()?
            .ok_or_else(|| io::Error::other("collector exited"))?;
        let expires_ns = Arc::new(AtomicU64::new(expires_ns.min(self.expires_ns)));
        let reason = Arc::new(AtomicU8::new(0));
        *slot = Some(WatchedCollector {
            child,
            expires_ns: expires_ns.clone(),
            reason: reason.clone(),
            #[cfg(target_os = "macos")]
            baseline,
        });
        let registration = CollectorRegistration {
            collector: self.collector.clone(),
            expires_ns,
            reason,
            wake: self.stop.clone(),
            request_started: false,
        };
        let _ = self.stop.send(());
        Ok(registration)
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        // A wake-up is not a stop: registration and shortened deadlines wake
        // the same channel. Disconnect it only after active ownership ends.
        let (replacement, _) = mpsc::channel();
        self.stop = replacement;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
pub fn start(started: Instant) -> io::Result<Watchdog> {
    start_for(started, LIFETIME)
}
fn start_for(started: Instant, lifetime: Duration) -> io::Result<Watchdog> {
    let expires_ns = now_ns()?
        .checked_add(
            u64::try_from(lifetime.saturating_sub(started.elapsed()).as_nanos())
                .map_err(io::Error::other)?,
        )
        .ok_or_else(|| io::Error::other("deadline"))?;
    let collector: Arc<Mutex<Option<WatchedCollector>>> = Arc::default();
    let watched = collector.clone();
    #[cfg(all(test, target_os = "macos"))]
    let observations = Arc::new(Mutex::new(Vec::new()));
    #[cfg(all(test, target_os = "macos"))]
    let samples = observations.clone();
    #[cfg(target_os = "macos")]
    let baseline = memory_usage()?;
    let (stop, stopped) = mpsc::channel();
    let (ready, prepared) = mpsc::sync_channel(0);
    let thread = std::thread::Builder::new()
        .name("refresh-watchdog".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            // Warm up malloc's per-thread arena before readiness, including
            // space for the channel's parker. Linux measures VM in install().
            let allocation = vec![0u8; 4096];
            std::hint::black_box(&allocation);
            if ready.send(()).is_err() {
                return;
            }
            loop {
                let now = now_ns().unwrap_or(u64::MAX);
                let mut next = expires_ns;
                #[cfg(target_os = "macos")]
                let helper_over = memory_exceeded(baseline);
                #[cfg(not(target_os = "macos"))]
                let helper_over = false;
                {
                    let slot = watched.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(worker) = slot.as_ref() {
                        let deadline = worker.expires_ns.load(Ordering::Acquire);
                        let terminate = now >= deadline || now >= expires_ns;
                        #[cfg(target_os = "macos")]
                        let footprint = worker.child.footprint();
                        #[cfg(all(test, target_os = "macos"))]
                        let sampled_at = now_ns().unwrap();
                        #[cfg(target_os = "macos")]
                        let resource =
                            helper_over || sample_over_limit(worker.baseline, &footprint);
                        #[cfg(not(target_os = "macos"))]
                        let resource = helper_over;
                        if terminate || resource {
                            // Collector first, before logging, file I/O, or helper death.
                            let _ = worker.reason.compare_exchange(
                                0,
                                if resource { 2 } else { 1 },
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                            let _ = worker.child.signal(libc::SIGKILL);
                        } else if !worker.child.reaped() {
                            next = next.min(deadline);
                        }
                        #[cfg(all(test, target_os = "macos"))]
                        if let Ok(Some(bytes)) = footprint {
                            let overshoot = bytes
                                .saturating_sub(worker.baseline.saturating_add(32 * 1024 * 1024));
                            let signalled_at = if overshoot > 0 && worker.child.kill_requested() {
                                now_ns().unwrap()
                            } else {
                                0
                            };
                            samples
                                .lock()
                                .unwrap()
                                .push((sampled_at, overshoot, signalled_at));
                        }
                    }
                }
                if now >= expires_ns || helper_over {
                    kill_self();
                }
                let remaining = Duration::from_nanos(next.saturating_sub(now));
                #[cfg(target_os = "macos")]
                let remaining = sample_wait(remaining);
                match stopped.recv_timeout(remaining) {
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        })?;
    prepared
        .recv()
        .map_err(|_| io::Error::other("watchdog readiness"))?;
    Ok(Watchdog {
        stop,
        thread: Some(thread),
        collector,
        expires_ns,
        #[cfg(all(test, target_os = "macos"))]
        observations,
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
    // The argument proves start()'s allocation/readiness barrier completed.
    let _ = watchdog;
    let fd = get(libc::RLIMIT_NOFILE)?;
    let cap = 4608.min(fd.rlim_max).min(kernel_nofile()?);
    set(libc::RLIMIT_NOFILE, cap, cap)?;
    let cpu = get(libc::RLIMIT_CPU)?;
    set(libc::RLIMIT_CPU, 1.min(cpu.rlim_max), 2.min(cpu.rlim_max))?;
    let file = get(libc::RLIMIT_FSIZE)?;
    let cap = (32 * 1024 * 1024).min(file.rlim_cur).min(file.rlim_max);
    set(libc::RLIMIT_FSIZE, cap, cap)?;
    #[cfg(target_os = "linux")]
    {
        let old = get(libc::RLIMIT_AS)?;
        let cap = memory_usage()?
            .checked_add(MEMORY)
            .ok_or_else(|| io::Error::other("VM cap"))?;
        let cap = cap.min(old.rlim_cur).min(old.rlim_max);
        set(libc::RLIMIT_AS, cap, cap)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    // 이것을 실패시키는 것: Update마다 request 마감을 다시 설정하도록 허용.
    #[test]
    fn request_deadline_can_only_be_armed_once() {
        let (wake, _receiver) = mpsc::channel();
        let mut registration = CollectorRegistration {
            collector: Arc::default(),
            expires_ns: Arc::new(AtomicU64::new(100)),
            reason: Arc::new(AtomicU8::new(0)),
            wake,
            request_started: false,
        };
        registration.begin_request(50).unwrap();
        assert_eq!(
            registration.begin_request(500).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(registration.expires_ns.load(Ordering::Acquire), 50);
    }
    // 이것을 실패시키는 것: 표본 오류를 무시하거나 초과 경계/2ms 대기 상한을 바꾸는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn first_completed_sample_and_wait_bound() {
        let cap = 100 + 32 * 1024 * 1024;
        assert!(!sample_over_limit(100, &Ok(Some(cap))));
        assert!(sample_over_limit(100, &Ok(Some(cap + 1))));
        assert!(sample_over_limit(
            100,
            &Err(io::Error::other("sample error"))
        ));
        assert!(!sample_over_limit(100, &Ok(None)));
        assert_eq!(
            sample_wait(Duration::from_secs(1)),
            Duration::from_millis(2)
        );
        assert_eq!(
            sample_wait(Duration::from_micros(500)),
            Duration::from_micros(500)
        );
    }
    // 이것을 실패시키는 것: parent bootstrap이 부모의 NOFILE soft를 바꾸는 것.
    #[test]
    fn n7_parent_nofile_unchanged() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::helper_limits::tests::n7_parent_limit_child",
                "--ignored",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
    }
    #[test]
    #[ignore = "isolated parent rlimit fixture"]
    fn n7_parent_limit_child() {
        let old = get(libc::RLIMIT_NOFILE).unwrap();
        set(libc::RLIMIT_NOFILE, 256.min(old.rlim_max), old.rlim_max).unwrap();
        let before = get(libc::RLIMIT_NOFILE).unwrap();
        crate::prompt_spawn::bootstrap(std::ffi::OsStr::new("/n7-does-not-exist"), &[], None);
        let after = get(libc::RLIMIT_NOFILE).unwrap();
        assert_eq!(
            (before.rlim_cur, before.rlim_max),
            (after.rlim_cur, after.rlim_max)
        );
    }
    // 이것을 실패시키는 것: 자식만 NOFILE을 올리지 않거나 CPU·FSIZE readback을 생략하는 것.
    #[test]
    #[ignore = "isolated rlimit child"]
    fn limits_child() {
        set(
            libc::RLIMIT_CORE,
            4096.min(get(libc::RLIMIT_CORE).unwrap().rlim_max),
            get(libc::RLIMIT_CORE).unwrap().rlim_max,
        )
        .unwrap();
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
        assert_detached();
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
        assert_eq!(fd.rlim_max, fd.rlim_cur);
        assert_eq!(get(libc::RLIMIT_CPU).unwrap().rlim_cur, 1);
        assert!(get(libc::RLIMIT_CPU).unwrap().rlim_max <= 2);
        assert_eq!(get(libc::RLIMIT_FSIZE).unwrap().rlim_cur, 32 * 1024 * 1024);
        assert_irreversible();
        let lower = get(libc::RLIMIT_NOFILE).unwrap();
        set(libc::RLIMIT_NOFILE, 256, 1024.min(lower.rlim_max)).unwrap();
        install(&_watchdog).unwrap();
        assert_eq!(
            get(libc::RLIMIT_NOFILE).unwrap().rlim_cur,
            1024.min(kernel_nofile().unwrap())
        );
    }
    fn assert_detached() {
        // 이것을 실패시키는 것: helper/collector가 cwd를 붙들거나 core의 soft/hard 중 하나를 남기는 것.
        assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/"));
        let core = get(libc::RLIMIT_CORE).unwrap();
        assert_eq!((core.rlim_cur, core.rlim_max), (0, 0));
    }
    fn assert_irreversible() {
        // 이것을 실패시키는 것: CPU·FSIZE·AS·NOFILE hard를 남겨 프로세스가 예산을 다시 올릴 수 있는 것.
        for resource in [
            libc::RLIMIT_CPU,
            libc::RLIMIT_FSIZE,
            libc::RLIMIT_NOFILE,
            #[cfg(target_os = "linux")]
            libc::RLIMIT_AS,
        ] {
            let limit = get(resource).unwrap();
            assert_ne!(limit.rlim_max, libc::RLIM_INFINITY);
            if resource != libc::RLIMIT_CPU {
                assert_eq!(limit.rlim_cur, limit.rlim_max);
            }
            assert!(set(resource, limit.rlim_max + 1, limit.rlim_max + 1).is_err());
        }
    }
    // 이것을 실패시키는 것: watchdog의 malloc arena 준비 전에 VM 기준을 재서 128 MiB 여유가 줄어드는 것.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated address-space limit"]
    fn headroom_child() {
        let watchdog = start(Instant::now()).unwrap();
        install(&watchdog).unwrap();
        let available = get(libc::RLIMIT_AS).unwrap().rlim_cur - memory_usage().unwrap();
        assert!(
            available >= MEMORY,
            "available VM: {available}, planned: {MEMORY}"
        );
        // Allocate the complete budget, not merely inspect the limit value.
        // SAFETY: anonymous private mapping, no borrowed memory or file.
        let region = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MEMORY as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(region, libc::MAP_FAILED);
        // SAFETY: exactly the mapping just returned.
        assert_eq!(unsafe { libc::munmap(region, MEMORY as usize) }, 0);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn watchdog_leaves_full_vm_headroom() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let out = child("commands::helper_limits::tests::headroom_child");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // 이것을 실패시키는 것: Linux watchdog이 마감까지 한 번 기다리지 않고 2 ms마다 깨는 것.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolates watchdog scheduling observations"]
    fn watchdog_wait_child() {
        let _watchdog = start(Instant::now()).unwrap();
        let task = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                std::fs::read_to_string(path.join("comm"))
                    .unwrap()
                    .starts_with("refresh-watchdo")
            })
            .unwrap();
        let switches = || {
            std::fs::read_to_string(task.join("status"))
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap()
        };
        let before = switches();
        std::thread::sleep(Duration::from_millis(60));
        assert!(switches() - before <= 2, "watchdog is polling");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn watchdog_waits_until_deadline() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let out = child("commands::helper_limits::tests::watchdog_wait_child");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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
