//! X-04 cgroup capability probe. Run with a label, once over SSH and once
//! in a desktop terminal, on a 5.10 machine and a 6.x machine. It really
//! moves a process: creates a child cgroup, writes a sleeping child's pid to
//! its cgroup.procs, reads it back, and (if the child cgroup has cgroup.kill)
//! kills through it. Prints one line with the keys of
//! `bench/probes/x04-schema.tsv`; what it cannot do is `false`.
#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    println!(r#"{{"x":"X-04","na":"not linux"}}"#);
}

#[cfg(target_os = "linux")]
fn main() {
    let label = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "unlabeled".into());
    println!("{}", imp::probe(label).line());
}

#[cfg(target_os = "linux")]
mod imp {
    use bingsu_bench::cgroup_rule::X04;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// The child cgroup this probe made; removed on drop (also on a panic)
    /// unless `remove` already did. Declared before the sleeper, so the
    /// sleeper (dropped first) has left it by then.
    struct CgDir {
        path: PathBuf,
        removed: bool,
    }

    impl CgDir {
        /// rmdir. Called after the sleeper is reaped: a cgroup with no
        /// live or zombie member can be removed at once.
        fn remove(&mut self) -> bool {
            self.removed = std::fs::remove_dir(&self.path).is_ok();
            self.removed
        }
    }

    impl Drop for CgDir {
        fn drop(&mut self) {
            if !self.removed {
                self.remove();
            }
        }
    }

    /// The sleeping child; killed and reaped on drop (also on a panic).
    struct Sleeper(Child);

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p)
            .map(|s| s.trim().replace('\n', " "))
            .unwrap_or_else(|e| format!("<{e}>"))
    }

    pub fn probe(label: String) -> X04 {
        let mut x = X04 {
            label,
            release: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|e| format!("<{e}>")),
            ..X04::default()
        };
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let Some(path) = own.lines().find_map(|l| l.strip_prefix("0::")) else {
            x.cgroup = "<no cgroup v2 entry>".into();
            return x;
        };
        x.cgroup = path.to_string();
        let dir = PathBuf::from(format!("/sys/fs/cgroup{path}"));
        x.controllers = read(&dir.join("cgroup.controllers"));
        x.subtree_control = read(&dir.join("cgroup.subtree_control"));
        // A v1 or hybrid mount has no cgroup v2 files at this path; a mkdir
        // there would make a plain folder, not a cgroup.
        if !dir.join("cgroup.procs").is_file() {
            return x;
        }
        let path = dir.join(format!("bingsu-x04-{}", std::process::id()));
        // create_dir refuses an existing folder, so one planted in advance
        // is never used (or removed) as ours.
        if std::fs::create_dir(&path).is_err() {
            return x;
        }
        x.mkdir_child = true;
        let mut cg = CgDir {
            path,
            removed: false,
        };
        x.child_has_kill = cg.path.join("cgroup.kill").exists();
        if let Ok(child) = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let mut sleeper = Sleeper(child);
            let pid = sleeper.0.id().to_string();
            x.move_ok = std::fs::write(cg.path.join("cgroup.procs"), &pid).is_ok();
            x.readback_ok = x.move_ok
                && read(&cg.path.join("cgroup.procs"))
                    .split_whitespace()
                    .any(|p| p == pid);
            // Test seam (probe_shapes `x04_delegated`): panic while the
            // sleeper sits in the child cgroup, so the test sees what the
            // guards clean up on unwind.
            if x.move_ok && std::env::var_os("BINGSU_X04_PANIC_AFTER_MOVE").is_some() {
                panic!("BINGSU_X04_PANIC_AFTER_MOVE");
            }
            if x.readback_ok
                && x.child_has_kill
                && std::fs::write(cg.path.join("cgroup.kill"), "1").is_ok()
            {
                let t = Instant::now();
                while t.elapsed() < Duration::from_secs(2) {
                    if let Ok(Some(st)) = sleeper.0.try_wait() {
                        x.kill_ok = st.signal() == Some(libc::SIGKILL);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            drop(sleeper);
        }
        x.rmdir_ok = cg.remove();
        x
    }
}
