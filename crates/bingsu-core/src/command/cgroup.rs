//! The cgroup layer's pure parts (spec section 4, stop order step 4; U-14
//! F0, U-15 Q1): whether a kernel release has `cgroup.kill`, the process's
//! own cgroup v2 path from `/proc/self/cgroup`, and the names of the session
//! parent folder and of each unit's cgroup. Nothing here touches a file.
use crate::collection::cwd_hash::sha256;
use alloc::{format, string::String};

/// One reclaim visits at most this many folders: the entries right under
/// the session parent and every folder of their subtrees (U-9d).
pub const RECLAIM_VISITS: usize = 64;
/// Deepest subtree level a reclaim enters below a unit folder (U-9d); a
/// folder deeper than this is never visited, so its unit folder stays.
pub const RECLAIM_DEPTH: usize = 4;
/// Work time of one reclaim (U-9d).
pub const RECLAIM_NS: u64 = 20_000_000;
/// Reads of `cgroup.events` after a kill before an entry counts as still
/// populated (the plan's `r`).
pub const POPULATED_RETRIES: usize = 3;
/// Longest `/proc/self/cgroup` content the parser accepts.
pub const PROC_CGROUP_MAX: usize = 4096;
/// Longest `cgroup.procs` the capability check reads; a larger one is no
/// atomic path (the shell's own cgroup holds that many processes).
pub const PROCS_MAX: usize = 65_536;

/// `cgroup.kill` exists from Linux 5.14; below that the atomic path is off
/// and the best-effort path runs (U-14 F0). `release` is `uname -r`: the
/// leading `major.minor` numbers decide, the rest is ignored. Anything that
/// does not start with two numbers is not atomic.
pub fn kernel_has_kill(release: &[u8]) -> bool {
    let mut parts = release.split(|&b| b == b'.');
    let mut number = || -> Option<u32> {
        let p = parts.next()?;
        let digits = p.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || digits > 6 {
            return None;
        }
        p[..digits].iter().try_fold(0u32, |n, d| {
            n.checked_mul(10)?.checked_add(u32::from(d - b'0'))
        })
    };
    match (number(), number()) {
        (Some(major), Some(minor)) => (major, minor) >= (5, 14),
        _ => false,
    }
}

/// The cgroup v2 path of the `0::` line, as the kernel wrote it: absolute,
/// no empty, `.` or `..` component, no NUL, not a removed cgroup. `None`
/// means no usable unified hierarchy (cgroup v1 only, or an odd line), and
/// the best-effort path runs.
pub fn own_path(proc_self_cgroup: &[u8]) -> Option<&[u8]> {
    if proc_self_cgroup.len() > PROC_CGROUP_MAX {
        return None;
    }
    let line = proc_self_cgroup
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"0::"))?;
    if line.first() != Some(&b'/') || line.contains(&0) || line.ends_with(b" (deleted)") {
        return None;
    }
    if line == b"/" {
        return Some(line);
    }
    let clean = line[1..]
        .split(|&b| b == b'/')
        .all(|c| !c.is_empty() && c != b"." && c != b"..");
    clean.then_some(line)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The session's fixed-length name part: the first 16 bytes of
/// `sha256(session)` in lowercase hex. The session lock and the session's
/// cgroup parent share it; the raw session value never names a file.
pub fn session_digest(session: &[u8]) -> String {
    hex(&sha256(session)[..16])
}

/// `bingsu-cmd-<digest>`: the one cgroup parent folder of a shell session,
/// under the cgroup the supervisor inherited from the shell. The digest
/// covers the session and the runtime root's `(dev, ino)`, the root the
/// session lock lives in: helpers that share a parent always share the
/// lock, so a reclaim under the lock never meets a live supervisor's unit.
pub fn parent_name(session: &[u8], runtime: (u64, u64)) -> String {
    format!("bingsu-cmd-{}", parent_digest(session, runtime))
}

/// The digest part of [`parent_name`]: 32 lowercase hex digits. The
/// session lock is named by it too (`command-<digest>.lock`), so a helper
/// that holds a lock owns the parent of the same digest: the GC's parent
/// sweep takes the lock of each parent it lists (m6-C4a7).
pub fn parent_digest(session: &[u8], runtime: (u64, u64)) -> String {
    let mut input = alloc::vec::Vec::with_capacity(session.len() + 17);
    input.extend_from_slice(&runtime.0.to_le_bytes());
    input.extend_from_slice(&runtime.1.to_le_bytes());
    input.push(0);
    input.extend_from_slice(session);
    hex(&sha256(&input)[..16])
}

/// A unit cgroup's name: `u` and 16 lowercase hex digits of `seq`.
pub fn unit_name(seq: u64) -> String {
    format!("u{seq:016x}")
}

/// Whether a folder under the session parent is a unit cgroup this layer
/// made; a reclaim touches nothing else.
pub fn is_unit_name(name: &[u8]) -> bool {
    name.len() == 17
        && name[0] == b'u'
        && name[1..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// The next unit's sequence value: the boot clock now, but always past the
/// previous one. One supervisor per session runs at a time (U-15 Q1) and the
/// boot clock never goes back, so no name repeats within a boot; a reboot
/// removes every cgroup. No record file is kept.
pub fn next_seq(previous: Option<u64>, now: u64) -> u64 {
    match previous {
        Some(p) => now.max(p.saturating_add(1)),
        None => now,
    }
}

/// Whether `cgroup.procs` (one pid per line) lists `pid`.
pub fn procs_contains(procs: &[u8], pid: u32) -> bool {
    let want = format!("{pid}");
    procs.split(|&b| b == b'\n').any(|l| l == want.as_bytes())
}

/// `populated 0` or `populated 1` in `cgroup.events`; `None` when the line
/// is missing or holds anything else (counted as populated by callers).
pub fn populated(events: &[u8]) -> Option<bool> {
    let value = events
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"populated "))?;
    match value {
        b"0" => Some(false),
        b"1" => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 5.13에는 cgroup.kill이 없으므로 최선 노력 경로. 이것을 실패시키는 것: 비교를 (5, 7)로 낮추거나
    // 커널 조건을 지워 늘 true를 내는 것(5.13 입력이 원자 경로가 됨).
    #[test]
    fn test_capability_requires_514() {
        assert!(!kernel_has_kill(b"5.13.19-generic"));
        assert!(!kernel_has_kill(b"5.10.0-28-amd64"));
        assert!(!kernel_has_kill(b"4.19.0"));
        assert!(kernel_has_kill(b"5.14.0"));
        assert!(kernel_has_kill(b"5.15.0-91-generic"));
        assert!(kernel_has_kill(b"6.8.0-117-generic"));
        assert!(kernel_has_kill(b"10.0"));
    }

    // 숫자 둘로 시작하지 않으면 원자 경로가 아니다. 이것을 실패시키는 것: match의 `_ => false`를
    // `_ => true`로 바꾸는 것.
    #[test]
    fn odd_releases_are_not_atomic() {
        for r in [&b""[..], b"6", b"x.20", b"6.", b".14", b"9999999.1"] {
            assert!(!kernel_has_kill(r), "{r:?}");
        }
    }

    // 이것을 실패시키는 것: `..`·빈 성분 검사를 지우는 것(아래 거부 입력이 Some이 됨).
    #[test]
    fn own_path_takes_only_a_clean_unified_line() {
        let v2 = b"0::/user.slice/user-1000.slice/session-3.scope\n";
        assert_eq!(
            own_path(v2),
            Some(&b"/user.slice/user-1000.slice/session-3.scope"[..])
        );
        assert_eq!(own_path(b"0::/\n"), Some(&b"/"[..]));
        let hybrid = b"12:pids:/user.slice\n1:name=systemd:/user.slice\n0::/user.slice/x\n";
        assert_eq!(own_path(hybrid), Some(&b"/user.slice/x"[..]));
        for bad in [
            &b"12:pids:/user.slice\n"[..],
            b"0::relative\n",
            b"0::/a/../b\n",
            b"0::/a//b\n",
            b"0::/a/./b\n",
            b"0::/a/\n",
            b"0::/gone (deleted)\n",
            b"0::/a\0b\n",
            b"",
        ] {
            assert_eq!(own_path(bad), None, "{bad:?}");
        }
        let mut long = b"0::/".to_vec();
        long.resize(PROC_CGROUP_MAX + 1, b'a');
        assert_eq!(own_path(&long), None);
    }

    // 세션 부모 이름은 고정 길이 요약값이고, 세션과 런타임 뿌리(잠금이 사는 곳)의 정체를 함께 묶는다. 이것을
    // 실패시키는 것: 세션 값을 그대로 쓰는 것, 런타임 뿌리의 dev나 ino를 요약에서 빼는 것(뿌리가 다른 두
    // helper가 잠금은 따로, 부모는 같이 씀).
    #[test]
    fn parent_name_is_a_fixed_length_digest() {
        let s = b"0123456789abcdef0123456789abcdef";
        let a = parent_name(s, (1, 2));
        assert_eq!(a.len(), "bingsu-cmd-".len() + 32);
        assert!(!a.contains("0123456789abcdef0123"));
        assert_ne!(a, parent_name(b"fedcba9876543210fedcba9876543210", (1, 2)));
        assert_ne!(a, parent_name(s, (3, 2)));
        assert_ne!(a, parent_name(s, (1, 4)));
        assert_eq!(a, parent_name(s, (1, 2)));
        assert_eq!(session_digest(b"s").len(), 32);
    }

    // 회수는 이 문법의 이름만 건드린다. 이것을 실패시키는 것: 길이 검사나 16진 검사를 지우는 것.
    #[test]
    fn unit_names_round_trip_the_grammar() {
        for seq in [0, 1, 0xdead_beef, u64::MAX] {
            assert!(is_unit_name(unit_name(seq).as_bytes()));
        }
        for bad in [
            &b"u0123"[..],
            b"u0123456789abcdefg",
            b"u0123456789ABCDEF",
            b"x0123456789abcdef",
            b"u0123456789abcdeg",
            b"cgroup.kill",
            b"..",
        ] {
            assert!(!is_unit_name(bad), "{bad:?}");
        }
    }

    // 같은 시각이나 뒤로 간 시각에도 이전보다 큰 값. 이것을 실패시키는 것: next_seq가 now만 돌려주는 것.
    #[test]
    fn next_seq_always_moves_forward() {
        assert_eq!(next_seq(None, 5), 5);
        assert_eq!(next_seq(Some(5), 5), 6);
        assert_eq!(next_seq(Some(9), 5), 10);
        assert_eq!(next_seq(Some(5), 9), 9);
    }

    // 같은 줄 전체가 그 pid일 때만. 이것을 실패시키는 것: 줄 비교를 접두사·포함 비교로 바꾸는 것(12가 123을
    // 담은 목록에서 참).
    #[test]
    fn procs_contains_matches_whole_lines() {
        assert!(procs_contains(b"1\n12\n300\n", 12));
        assert!(!procs_contains(b"1\n123\n300\n", 12));
        assert!(!procs_contains(b"312\n", 12));
        assert!(!procs_contains(b"", 12));
    }

    // 이것을 실패시키는 것: "1" 외 값을 비어 있음으로 보는 것(알 수 없는 값은 None, 호출 쪽이 남김).
    #[test]
    fn populated_reads_only_zero_or_one() {
        assert_eq!(populated(b"populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(populated(b"populated 1\nfrozen 0\n"), Some(true));
        assert_eq!(populated(b"frozen 0\n"), None);
        assert_eq!(populated(b"populated 2\n"), None);
        assert_eq!(populated(b"populated 0x\n"), None);
    }
}
