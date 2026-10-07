//! Synthetic program with known filesystem calls for the budget scaffold
//! (spec section 9 M1 row, change (6)). Inside its fsb window each role makes
//! exactly the calls of its formula with every coefficient = 1. Apart from
//! the start-up prologue (the dynamic loader and std before main), every
//! filesystem call this program makes itself is inside the window: names
//! come from FSB_NAMES, the runtime-root fd is inherited as fd 10, axes go
//! to stdout (a pipe).
//! FSB_ACL=1 makes the helper probe the POSIX ACL of every walked component
//! and every source file (the c12·(F + P) term).
#![deny(unsafe_code)] // FFI lives in bingsu_bench::sys only

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("fsb-synthetic runs on Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    imp::main();
}

#[cfg(target_os = "linux")]
mod imp {
    use bingsu_bench::sys::fs::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use bingsu_bench::BUF;
    const RT_FD: i32 = 10;
    const RO: libc::c_int = libc::O_RDONLY | libc::O_NOFOLLOW;
    const DIR: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    const NEW: libc::c_int = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW;
    const SNAPSHOT_BYTES: usize = 6000;

    fn c(s: &[u8]) -> CString {
        CString::new(s).unwrap()
    }

    fn arg(name: &str) -> Option<String> {
        let a: Vec<String> = std::env::args().collect();
        a.iter()
            .position(|x| x == name)
            .and_then(|i| a.get(i + 1).cloned())
    }

    fn mutate(what: &str) -> bool {
        std::env::var("FSB_MUTATE").is_ok_and(|v| v == what)
    }

    fn begin() {
        marker(c"fsb:begin").expect("fsb:begin");
    }

    fn end() {
        marker(c"fsb:end").expect("fsb:end");
    }

    /// openat + fstat (+ an ACL probe when `acl`) for "/" and every
    /// component: the P (helper) or C (front) axis. Returns the last fd and
    /// the number of components.
    fn walk(path: &Path, acl: bool) -> (OwnedFd, usize) {
        let mut fd = openat(libc::AT_FDCWD, c"/", DIR).unwrap();
        fstat(&fd).unwrap();
        if acl {
            acl_probe(&fd);
        }
        let mut n = 1;
        for comp in path.components().skip(1) {
            let next = openat(fd.as_raw_fd(), &c(comp.as_os_str().as_bytes()), DIR).unwrap();
            fstat(&next).unwrap();
            if acl {
                acl_probe(&next);
            }
            fd = next;
            n += 1;
        }
        (fd, n)
    }

    /// The runtime-root fd the front placed at RT_FD.
    #[allow(unsafe_code)]
    fn runtime_root() -> OwnedFd {
        // SAFETY: the front dup'ed the runtime-root fd onto RT_FD before
        // spawning this role; nothing else in this process opens or owns
        // that number, and each role calls this once.
        unsafe { inherited(RT_FD) }
    }

    /// Hands the runtime-root fd to the roles the front spawns.
    #[allow(unsafe_code)]
    fn reserve_runtime_root(rt: &OwnedFd) {
        // SAFETY: nothing in this process owns RT_FD: std opens no fd before
        // main and the walk holds at most two fds at a time, all below 10.
        unsafe { dup_to_reserved(rt, RT_FD) }.unwrap();
    }

    /// linux_dirent64 records in a getdents64 result (d_reclen at offset 16).
    fn entries(buf: &[u8]) -> usize {
        let (mut at, mut n) = (0, 0);
        while at + 18 <= buf.len() {
            let reclen = usize::from(u16::from_ne_bytes([buf[at + 16], buf[at + 17]]));
            assert!(reclen > 0, "linux_dirent64 with d_reclen 0");
            at += reclen;
            n += 1;
        }
        n
    }

    /// openat + fstat + ceil(size / BUF) reads, no end-check read. Returns
    /// the size from fstat.
    fn open_read_exact(dir: &OwnedFd, name: &[u8], buf: &mut [u8]) -> usize {
        let fd = openat(dir.as_raw_fd(), &c(name), RO).unwrap();
        let size = fstat(&fd).unwrap().st_size as usize;
        let mut left = size;
        while left > 0 {
            left -= read(&fd, &mut buf[..BUF.min(left)]).unwrap().max(1);
        }
        size
    }

    /// Reads until a 0 return (ceil + 1 reads for in-place files).
    fn read_to_eof(fd: &OwnedFd, buf: &mut [u8]) -> usize {
        let mut total = 0;
        loop {
            match read(fd, buf).unwrap() {
                0 => return total,
                n => total += n,
            }
        }
    }

    fn spawn(role: &str, fx: &Path) -> std::process::Child {
        // Mutation: the helper runs under a name no rule matches.
        let role = if role == "helper" && mutate("misattr") {
            "helper-renamed"
        } else {
            role
        };
        std::process::Command::new("/proc/self/exe")
            .args(["--role", role, "--fixture"])
            .arg(fx)
            .spawn()
            .unwrap()
    }

    fn front(fx: &Path) {
        let mut buf = vec![0u8; BUF];
        begin();
        let (rt, comps) = walk(&fx.join("run"), false);
        // Snapshot: fstat gives the size; one 64-byte header read, then the section.
        let snap = openat(rt.as_raw_fd(), c"snapshot", RO).unwrap();
        let total = fstat(&snap).unwrap().st_size as usize;
        read(&snap, &mut buf[..64]).unwrap();
        let section = total - 64;
        let mut left = section;
        while left > 0 {
            left -= read(&snap, &mut buf[..BUF.min(left)]).unwrap().max(1);
        }
        open_read_exact(&rt, b"marker", &mut buf);
        let session = open_read_exact(&rt, b"session", &mut buf);
        reserve_runtime_root(&rt);
        let mut kids = vec![
            spawn("helper", fx),
            spawn("writer", fx),
            spawn("worker", fx),
        ];
        kids.push(std::process::Command::new("/bin/true").spawn().unwrap());
        end();
        for k in &mut kids {
            let _ = k.wait();
        }
        println!(r#"AXES front {{"C":{comps},"section":{section},"session":{session}}}"#);
    }

    fn helper(fx: &Path, changed: bool, acl: bool) {
        let mut buf = vec![0u8; BUF];
        let names: Vec<Vec<u8>> = std::env::var("FSB_NAMES")
            .expect("FSB_NAMES")
            .split(',')
            .map(|n| n.as_bytes().to_vec())
            .collect();
        let rt = runtime_root();
        begin();
        let (cfg_fd, p) = walk(&fx.join("cfg"), acl); // P (+ P ACL probes)
        let files: Vec<OwnedFd> = names
            .iter()
            .map(|n| {
                let fd = openat(cfg_fd.as_raw_fd(), &c(n), RO).unwrap(); // R
                fstat(&fd).unwrap();
                if acl {
                    acl_probe(&fd); // F ACL probes
                }
                fd
            })
            .collect();
        let confd = openat(cfg_fd.as_raw_fd(), c"conf.d", DIR).unwrap(); // D
        let (mut eb, mut en) = (0, 0);
        loop {
            match getdents64(&confd, &mut buf).unwrap() {
                0 => break,
                n => {
                    eb += n;
                    en += entries(&buf[..n]);
                }
            }
        }
        let mut lbuf = [0u8; 256];
        readlinkat(cfg_fd.as_raw_fd(), c"link.toml", &mut lbuf).unwrap(); // L
        fstatfs(&cfg_fd).unwrap(); // M
        let mut sizes = Vec::new();
        if changed {
            for n in &names {
                let fd = openat(cfg_fd.as_raw_fd(), &c(n), RO).unwrap(); // F (content)
                sizes.push(read_to_eof(&fd, &mut buf)); // B
            }
        }
        for f in &files {
            fstat(f).unwrap(); // final recheck, F
        }
        if mutate("extra-fstat") {
            fstat(&cfg_fd).unwrap();
        }
        let lock = openat(
            rt.as_raw_fd(),
            c"lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW,
        )
        .unwrap();
        fstat(&lock).unwrap();
        flock_ex_nb(&lock).unwrap();
        open_read_exact(&rt, b"snapshot-header", &mut buf);
        open_read_exact(&rt, b"marker", &mut buf);
        let tmp = openat(rt.as_raw_fd(), c"marker.tmp", NEW).unwrap();
        write(&tmp, &[0u8; 128]).unwrap();
        renameat(rt.as_raw_fd(), c"marker.tmp", c"marker").unwrap();
        if changed {
            let s = openat(rt.as_raw_fd(), c"snapshot.tmp", NEW).unwrap();
            for chunk in vec![0u8; SNAPSHOT_BYTES].chunks(BUF) {
                write(&s, chunk).unwrap();
            }
            renameat(rt.as_raw_fd(), c"snapshot.tmp", c"snapshot-header").unwrap();
        }
        end();
        let f = names.len();
        println!(
            r#"AXES helper {{"F":{f},"P":{p},"L":1,"R":{f},"D":1,"E_n":[{en}],"E_b":[{eb}],"M":1,"B":{sizes:?},"acl":{acl},"lock_fd_inherited":false,"snapshot_bytes":{SNAPSHOT_BYTES}}}"#
        );
    }

    fn writer() {
        let rt = runtime_root();
        begin();
        // Per-session writer lock, separate from the helper's per-user
        // snapshot lock (spec section 4), so the two never race.
        let lock = openat(
            rt.as_raw_fd(),
            c"session.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW,
        )
        .unwrap();
        fstat(&lock).unwrap();
        flock_ex_nb(&lock).unwrap();
        let tmp = openat(rt.as_raw_fd(), c"session.tmp", NEW).unwrap();
        write(&tmp, b"state").unwrap();
        renameat(rt.as_raw_fd(), c"session.tmp", c"session").unwrap();
        end();
    }

    fn worker() {
        let mut buf = vec![0u8; BUF];
        let rt = runtime_root();
        begin();
        open_read_exact(&rt, b"worker-input", &mut buf);
        end();
    }

    pub fn main() {
        let fx = PathBuf::from(arg("--fixture").expect("--fixture"));
        // Children inherit the environment, so the test sets FSB_CHANGED for the helper.
        let changed =
            std::env::args().any(|a| a == "--changed") || std::env::var_os("FSB_CHANGED").is_some();
        // FSB_ACL makes the helper probe ACLs (children inherit it too).
        let acl = std::env::var_os("FSB_ACL").is_some();
        match arg("--role").as_deref() {
            Some("front") => front(&fx),
            Some("helper" | "helper-renamed") => helper(&fx, changed, acl),
            Some("writer") => writer(),
            Some("worker") => worker(),
            _ => std::process::exit(2),
        }
    }
}
