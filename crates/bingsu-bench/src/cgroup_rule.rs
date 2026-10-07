//! When the atomic cgroup.kill path may be used (spec section 4 deadline
//! order 4; platform table: CLONE_INTO_CGROUP 5.7, cgroup.kill 5.14), and
//! the X-04 probe line built from what the probe observed. Pure: the probe
//! binary does the I/O, this module only decides and formats.
use crate::report::escape;

pub fn atomic_kill_available(kernel: (u32, u32), has_cgroup_kill: bool, delegated: bool) -> bool {
    kernel >= (5, 14) && has_cgroup_kill && delegated
}

/// Delegation as X-04 means it: this user really moved a process into a
/// child cgroup and read it back there (spec section 9, "쓰기 권한").
pub fn delegated(move_ok: bool, readback_ok: bool) -> bool {
    move_ok && readback_ok
}

/// (major, minor) from `/proc/sys/kernel/osrelease` ("6.8.0-45-generic").
/// Fails closed: anything that does not start with `N.N` is None, and the
/// probe then reports the atomic path as off.
pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let mut it = release.trim().splitn(3, '.');
    let major = it.next()?.parse().ok()?;
    let minor_part = it.next()?;
    let end = minor_part
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(minor_part.len());
    let minor = minor_part[..end].parse().ok()?;
    Some((major, minor))
}

/// Whether `pid` is one of the lines of a `cgroup.procs` read (one pid per
/// line): `12` is not in `123`.
pub fn procs_has(procs: &str, pid: &str) -> bool {
    procs.lines().any(|l| l == pid)
}

/// The cgroup v2 path of the `0::` line of `/proc/self/cgroup`. Refuses a
/// path that is not absolute or has a `.` or `..` component (inside a
/// cgroup namespace the line can read `/../..`): joined under
/// /sys/fs/cgroup it would name a folder outside this process's cgroup.
pub fn cgroup_v2_path(proc_self_cgroup: &str) -> Result<&str, String> {
    let path = proc_self_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or("no cgroup v2 entry")?;
    if !path.starts_with('/') || path.split('/').any(|c| c == ".." || c == ".") {
        return Err(format!("refused cgroup path {path:?}"));
    }
    Ok(path)
}

/// What the X-04 probe saw. Strings are the raw file contents (or an error
/// text); `line` escapes them.
#[derive(Clone, Debug, Default)]
pub struct X04 {
    pub label: String,
    pub release: String,
    pub cgroup: String,
    pub controllers: String,
    pub subtree_control: String,
    pub mkdir_child: bool,
    pub child_has_kill: bool,
    pub move_ok: bool,
    pub readback_ok: bool,
    pub kill_ok: bool,
    pub rmdir_ok: bool,
}

impl X04 {
    /// One JSON line with exactly the keys of `bench/probes/x04-schema.tsv`.
    pub fn line(&self) -> String {
        let delegated = delegated(self.move_ok, self.readback_ok);
        let atomic = parse_kernel(&self.release)
            .is_some_and(|k| atomic_kill_available(k, self.child_has_kill, delegated));
        format!(
            r#"{{"x":"X-04","label":"{}","kernel":"{}","cgroup":"{}","controllers":"{}","subtree_control":"{}","mkdir_child":{},"child_has_kill":{},"move_ok":{},"readback_ok":{},"kill_ok":{},"rmdir_ok":{},"delegated":{delegated},"atomic":{atomic}}}"#,
            escape(&self.label),
            escape(self.release.trim()),
            escape(&self.cgroup),
            escape(&self.controllers),
            escape(&self.subtree_control),
            self.mkdir_child,
            self.child_has_kill,
            self.move_ok,
            self.readback_ok,
            self.kill_ok,
            self.rmdir_ok,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 5.7(CLONE_INTO_CGROUP)을 바닥으로 쓰는 것, 위임 없이 켜는 것.
    #[test]
    fn rule_table() {
        assert!(!atomic_kill_available((5, 10), true, true));
        assert!(!atomic_kill_available((5, 13), true, true));
        assert!(atomic_kill_available((5, 14), true, true));
        assert!(atomic_kill_available((6, 8), true, true));
        assert!(!atomic_kill_available((6, 8), false, true));
        assert!(!atomic_kill_available((6, 8), true, false));
    }

    // 이것을 실패시키는 것: 옮기기와 다시 읽기 중 하나만으로 위임이라 하는 것(`&&`를 `||`로).
    #[test]
    fn delegation_needs_move_and_readback() {
        assert!(delegated(true, true));
        assert!(!delegated(true, false));
        assert!(!delegated(false, true));
        assert!(!delegated(false, false));
    }

    // 이것을 실패시키는 것: 부 버전의 꼬리(-45, rc1)를 숫자로 읽지 못하는 것, 형식이 아닌 값에 (0, 0) 같은 기본값을 주는 것.
    #[test]
    fn kernel_release() {
        assert_eq!(parse_kernel("6.8.0-45-generic\n"), Some((6, 8)));
        assert_eq!(parse_kernel("5.10.0-28-amd64"), Some((5, 10)));
        assert_eq!(parse_kernel("5.14"), Some((5, 14)));
        assert_eq!(parse_kernel("6.12rc1"), Some((6, 12)));
        assert_eq!(parse_kernel("6"), None);
        assert_eq!(parse_kernel("6."), None);
        assert_eq!(parse_kernel(""), None);
        assert_eq!(parse_kernel("x.y"), None);
    }

    // 이것을 실패시키는 것: cgroupns의 `..`·`.` 구성요소나 상대 경로를 받아 /sys/fs/cgroup 밖을 가리키는 것,
    // 0:: 줄이 없을 때 빈 경로(= 루트)로 넘어가는 것.
    #[test]
    fn cgroup_path() {
        assert_eq!(
            cgroup_v2_path("0::/user.slice/a.scope\n"),
            Ok("/user.slice/a.scope")
        );
        assert_eq!(cgroup_v2_path("1:name=systemd:/x\n0::/\n"), Ok("/"));
        assert_eq!(cgroup_v2_path("0::/a..b/c\n"), Ok("/a..b/c"));
        for bad in [
            "0::/../..\n",
            "0::/a/../b\n",
            "0::/a/./b\n",
            "0::a/b\n",
            "0::\n",
            "1:cpu:/x\n",
            "",
        ] {
            assert!(cgroup_v2_path(bad).is_err(), "{bad:?}");
        }
    }

    // 이것을 실패시키는 것: 줄 단위가 아니라 부분 문자열로 찾는 것(`contains`이면 12가 123에 맞는다).
    #[test]
    fn procs_lines() {
        assert!(procs_has("12\n", "12"));
        assert!(procs_has("1\n12\n", "12"));
        assert!(!procs_has("123\n", "12"));
        assert!(!procs_has("412\n", "12"));
        assert!(!procs_has("", "12"));
    }

    fn full() -> X04 {
        X04 {
            label: "ssh".into(),
            release: "6.8.0-45-generic\n".into(),
            cgroup: "/user.slice/x.scope".into(),
            controllers: "cpu memory pids".into(),
            subtree_control: String::new(),
            mkdir_child: true,
            child_has_kill: true,
            move_ok: true,
            readback_ok: true,
            kill_ok: true,
            rmdir_ok: true,
        }
    }

    // 이것을 실패시키는 것: 줄의 delegated·atomic을 관찰값이 아닌 것으로 계산하는 것
    // (부모 폴더의 cgroup.kill을 쓰거나, 다시 읽기를 빼거나, 커널 판정을 빼는 것).
    #[test]
    fn line_derives_delegated_and_atomic() {
        assert!(
            full()
                .line()
                .ends_with(r#""delegated":true,"atomic":true}"#),
            "{}",
            full().line()
        );
        let no_readback = X04 {
            readback_ok: false,
            ..full()
        };
        assert!(
            no_readback
                .line()
                .ends_with(r#""delegated":false,"atomic":false}"#)
        );
        let no_kill = X04 {
            child_has_kill: false,
            ..full()
        };
        assert!(
            no_kill
                .line()
                .ends_with(r#""delegated":true,"atomic":false}"#)
        );
        let old = X04 {
            release: "5.10.0-28-amd64".into(),
            ..full()
        };
        assert!(old.line().ends_with(r#""delegated":true,"atomic":false}"#));
        let unknown = X04 {
            release: "<No such file>".into(),
            ..full()
        };
        assert!(
            unknown
                .line()
                .ends_with(r#""delegated":true,"atomic":false}"#)
        );
    }

    // 이것을 실패시키는 것: label·cgroup 경로 같은 바깥 문자열을 escape 없이 넣는 것.
    #[test]
    fn line_escapes_strings() {
        let l = X04 {
            label: "a\"b".into(),
            cgroup: "/x\\y\n".into(),
            ..full()
        }
        .line();
        assert!(l.contains(r#""label":"a\"b","#), "{l}");
        assert!(l.contains(r#""cgroup":"/x\\y\n","#), "{l}");
    }
}
