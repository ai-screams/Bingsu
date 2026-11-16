use super::*;
use std::collections::BTreeMap;

/// A cgroup tree in memory: each folder has children in listing order,
/// a populated value that a kill clears unless the folder is stuck, and
/// a log of every call. Every call advances the clock by `tick`.
#[derive(Default)]
pub(crate) struct Fake {
    pub folders: BTreeMap<Vec<u8>, Folder>,
    pub log: Vec<String>,
    pub clock: u64,
    pub tick: u64,
    /// The clock when each call started.
    pub starts: Vec<u64>,
    /// The longest wait a populated read asked for.
    pub waited: i32,
}
#[derive(Default, Clone)]
pub(crate) struct Folder {
    pub children: Vec<Vec<u8>>,
    pub populated: bool,
    /// `cgroup.kill` does not empty it (a descendant held in the kernel).
    pub stuck: bool,
    /// Reads before a kill takes effect.
    pub dying: usize,
}

impl Fake {
    pub(crate) fn add(&mut self, path: &str) {
        let mut parent = String::new();
        for part in path.split('/') {
            let me = if parent.is_empty() {
                part.to_owned()
            } else {
                format!("{parent}/{part}")
            };
            if !self.folders.contains_key(me.as_bytes()) {
                self.folders
                    .insert(me.clone().into_bytes(), Folder::default());
                if let Some(p) = self.folders.get_mut(parent.as_bytes()) {
                    p.children.push(part.as_bytes().to_vec());
                }
            }
            parent = me;
        }
    }
    pub(crate) fn get(&mut self, path: &str) -> &mut Folder {
        self.folders.get_mut(path.as_bytes()).unwrap()
    }
    fn step(&mut self) {
        self.starts.push(self.clock);
        self.clock += self.tick;
    }
    /// Unit folders still under `parent`.
    pub(crate) fn left(&self, parent: &str) -> Vec<String> {
        self.folders[parent.as_bytes()]
            .children
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect()
    }
    fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
        [dir, b"/", name].concat()
    }
}

impl Tree for Fake {
    type Dir = Vec<u8>;
    fn subdirs(&mut self, dir: &mut Vec<u8>, max: usize) -> io::Result<Vec<Vec<u8>>> {
        self.step();
        let kids = &self.folders[dir.as_slice()].children;
        Ok(kids.iter().take(max).cloned().collect())
    }
    fn open(&mut self, dir: &Vec<u8>, name: &[u8]) -> io::Result<Vec<u8>> {
        self.step();
        let path = Self::join(dir, name);
        self.log
            .push(format!("open {}", String::from_utf8_lossy(&path)));
        self.folders
            .contains_key(&path)
            .then_some(path)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }
    fn kill(&mut self, dir: &Vec<u8>) -> io::Result<()> {
        self.step();
        self.log
            .push(format!("kill {}", String::from_utf8_lossy(dir)));
        // A kill reaches the whole subtree.
        let prefix = [dir.as_slice(), b"/"].concat();
        for (path, f) in self.folders.iter_mut() {
            if (path == dir || path.starts_with(&prefix)) && !f.stuck {
                f.dying = f.dying.max(usize::from(f.populated));
            }
        }
        Ok(())
    }
    fn populated(&mut self, dir: &mut Vec<u8>, wait_ms: i32) -> io::Result<Option<bool>> {
        self.step();
        self.waited = self.waited.max(wait_ms);
        self.clock += u64::try_from(wait_ms).unwrap_or(0) * 1_000_000;
        let prefix = [dir.as_slice(), b"/"].concat();
        let mut any = false;
        for (path, f) in self.folders.iter_mut() {
            if path == dir || path.starts_with(&prefix) {
                if f.populated && !f.stuck && f.dying > 0 {
                    f.dying -= 1;
                    if f.dying == 0 {
                        f.populated = false;
                    }
                }
                any |= f.populated;
            }
        }
        self.log.push(format!(
            "populated {} {}",
            String::from_utf8_lossy(dir),
            u8::from(any)
        ));
        Ok(Some(any))
    }
    fn rmdir(&mut self, dir: &Vec<u8>, name: &[u8]) -> io::Result<()> {
        self.step();
        let path = Self::join(dir, name);
        self.log
            .push(format!("rmdir {}", String::from_utf8_lossy(&path)));
        let f = &self.folders[&path];
        if !f.children.is_empty() || f.populated {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.folders.remove(&path);
        self.folders
            .get_mut(dir.as_slice())
            .unwrap()
            .children
            .retain(|c| c != name);
        Ok(())
    }
    fn now(&mut self) -> u64 {
        self.clock
    }
}

fn unit(i: u64) -> String {
    cgroup::unit_name(i)
}

/// The deep unit (a chain six levels down) first, a unit exactly four
/// levels deep, 30 empty units, then one unit holding 40 cgroups three
/// levels deep: 81 visits in all,
/// more than one reclaim may make.
fn caps_fixture(tick: u64) -> Fake {
    let mut f = Fake {
        tick,
        ..Fake::default()
    };
    f.add(&format!("p/{}/a/b/c/d/e/f", unit(0)));
    // Exactly four levels: still removed.
    f.add(&format!("p/{}/a/b/c/d", unit(50)));
    for i in 1..=30 {
        f.add(&format!("p/{}", unit(i)));
    }
    let wide = unit(99);
    for a in 0..4 {
        for b in 0..3 {
            for c in 0..2 {
                f.add(&format!("p/{wide}/a{a}/b{b}/c{c}"));
            }
        }
    }
    f
}

// 상한: 한 회수의 방문 ≤ 64, 작업 시간 ≤ 20 ms, 두 회수 안에 깊이 3 트리는 모두 제거, 깊이 6 트리의 단위
// 폴더는 남고 진단 1줄. 이것을 실패시키는 것: 방문 상한(`r.visits >= RECLAIM_VISITS`) 두 곳을 지우는 것
// (첫 회수가 64곳을 넘게 방문), 시간 상한(`t.now() >= end`)을 지우는 것(느린 시계에서 20 ms를 넘김), 깊이 상한을
// 지우는 것(깊이 6 단위가 제거되고 진단이 없음), 빈 폴더의 조기 true를 지우는 것(깊이 정확히 4인 단위가 남음),
// `!cleared` 분기를 지우는 것(남은 하위 트리 위 폴더에 rmdir을 시도해 failed가 생김).
#[test]
fn test_reclaim_depth_and_count_caps() {
    let mut f = caps_fixture(1_000);
    let mut parent = b"p".to_vec();
    let first = reclaim(&mut f, &mut parent);
    assert!(first.visits <= RECLAIM_VISITS, "{first:?}");
    assert!(first.capped, "{first:?}");
    let second = reclaim(&mut f, &mut parent);
    assert!(second.visits <= RECLAIM_VISITS, "{second:?}");
    assert_eq!(f.left("p"), [unit(0)]);
    assert!(
        f.folders
            .contains_key(format!("p/{}/a/b/c/d", unit(0)).as_bytes())
    );
    assert_eq!(second.deep, 1, "{second:?}");
    // No rmdir is tried on a folder whose subtree stayed.
    assert_eq!(first.failed + second.failed, 0, "{first:?} {second:?}");
    assert_eq!(
        second.messages(),
        ["command reclaim: a unit cgroup deeper than 4 levels stays"]
    );
    // A slow tree: every call takes 1 ms, so the clock, not the window,
    // ends it: while killing units, and inside one wide subtree.
    let mut slow = caps_fixture(1_000_000);
    let r = reclaim(&mut slow, &mut parent);
    assert!(r.capped, "{r:?}");
    assert!(r.elapsed_ns <= RECLAIM_NS + 2 * slow.tick, "{r:?}");
    let mut wide = Fake {
        tick: 1_000_000,
        ..Fake::default()
    };
    for a in 0..40 {
        wide.add(&format!("p/{}/a{a}", unit(7)));
    }
    let r = reclaim(&mut wide, &mut parent);
    assert!(r.capped, "{r:?}");
    assert!(r.elapsed_ns <= RECLAIM_NS + 2 * wide.tick, "{r:?}");
    // More units than the kill pass may take: it stops at 64.
    let mut many = Fake::default();
    for i in 0..70 {
        many.add(&format!("p/{}", unit(i)));
    }
    let r = reclaim(&mut many, &mut parent);
    assert_eq!((r.kills, r.removed), (KILL_MAX, KILL_MAX), "{r:?}");
    assert!(r.capped);
}

// 남는 항목은 건너뛰고 빈 항목은 그 회수에 모두 제거. 이것을 실패시키는 것: populated 뒤의
// `if !empty { stuck; continue }`를 지우는 것(남는 항목 셋에 rmdir을 시도해 stuck 0, failed 3).
#[test]
fn test_reclaim_skips_stuck_entries() {
    let mut f = Fake::default();
    for i in 0..8 {
        f.add(&format!("p/{}", unit(i)));
    }
    for i in [0, 3, 6] {
        let u = f.get(&format!("p/{}", unit(i)));
        u.populated = true;
        u.stuck = true;
    }
    let mut parent = b"p".to_vec();
    let r = reclaim(&mut f, &mut parent);
    assert_eq!((r.removed, r.stuck, r.failed), (5, 3, 0), "{r:?}");
    assert_eq!(f.left("p"), [unit(0), unit(3), unit(6)]);
}

// rmdir은 그 단위의 populated=0 관측 뒤에만. 이것을 실패시키는 것: populated 확인을 건너뛰는 것
// (`let mut empty = true`), kill 직후 첫 rmdir이 populated 기록보다 앞선다.
#[test]
fn test_populated_checked_before_rmdir() {
    let mut f = Fake::default();
    f.add(&format!("p/{}/x", unit(1)));
    let u = f.get(&format!("p/{}", unit(1)));
    // The kill takes two reads to empty it.
    u.populated = true;
    u.dying = 2;
    let x = f.get(&format!("p/{}/x", unit(1)));
    x.populated = true;
    x.dying = 2;
    let mut parent = b"p".to_vec();
    let r = reclaim(&mut f, &mut parent);
    assert_eq!(r.removed, 1, "{r:?} {:?}", f.log);
    let zero = f
        .log
        .iter()
        .position(|l| l == &format!("populated p/{} 0", unit(1)))
        .expect("populated 0 observed");
    let first_rmdir = f.log.iter().position(|l| l.starts_with("rmdir")).unwrap();
    assert!(zero < first_rmdir, "{:?}", f.log);
}

// 문법 밖 이름은 열지도 죽이지도 않는다. 이것을 실패시키는 것: is_unit_name 거르기를 지우는 것.
#[test]
fn reclaim_touches_only_unit_names() {
    let mut f = Fake::default();
    f.add("p/other");
    f.add(&format!("p/{}", unit(2)));
    let mut parent = b"p".to_vec();
    let r = reclaim(&mut f, &mut parent);
    assert_eq!(r.removed, 1);
    assert_eq!(f.left("p"), ["other"]);
    assert!(!f.log.iter().any(|l| l.contains("other")), "{:?}", f.log);
}

fn chunks(data: &'static [u8], size: usize) -> impl FnMut(&mut [u8], u64) -> io::Result<usize> {
    move |buf, at| {
        let at = usize::try_from(at).unwrap().min(data.len());
        let n = data[at..].len().min(size).min(buf.len());
        buf[..n].copy_from_slice(&data[at..at + n]);
        Ok(n)
    }
}

// cgroup.procs는 EOF까지 여러 번 읽는다(첫 청크 뒤의 pid도 찾음). 누적이 상한을 넘으면 None. 이것을
// 실패시키는 것: 첫 읽기 하나로 끝내는 것(둘째 청크의 4242를 놓침), 상한 검사를 지우는 것(상한을 넘는 목록을
// 그대로 돌려줌).
#[test]
fn read_bounded_reads_every_chunk_up_to_its_cap() {
    let list = b"1\n2\n3\n4242\n";
    let got = read_bounded(&mut chunks(list, 4), 64).unwrap();
    assert!(cgroup::procs_contains(&got, 4242), "{got:?}");
    assert_eq!(read_bounded(&mut chunks(list, 4), 8), None);
    assert_eq!(read_bounded(&mut chunks(b"", 4), 8), Some(Vec::new()));
}

// kill 단계와 정리 단계의 예산이 따로라, 하위 폴더 하나씩 가진 빈 단위 64개도 한 회수에 일부가 제거된다.
// 이것을 실패시키는 것: kill 단계가 정리 단계의 방문 창을 쓰는 것(kill마다 visits를 늘림: 64개를 kill하면
// 하위 폴더를 볼 방문이 없어 제거 0), 정리 단계의 단위마다 하는 창 검사를 지우는 것(방문이 64를 넘음).
#[test]
fn test_reclaim_leaves_room_for_subtrees() {
    let mut f = Fake::default();
    for i in 0..64 {
        f.add(&format!("p/{}/x", unit(i)));
    }
    let mut parent = b"p".to_vec();
    let r = reclaim(&mut f, &mut parent);
    assert!(r.removed > 0, "{r:?}");
    assert!(r.visits <= RECLAIM_VISITS, "{r:?}");
}

// 문법 밖 이름은 방문을 쓰지 않으므로 그 뒤의 단위도 회수된다. 한 회수가 읽는 이름 수를 넘으면 잘림 진단을
// 남긴다. 이것을 실패시키는 것: 목록 상한을 RECLAIM_VISITS + 1로 되돌리는 것(문법 밖 65개 뒤 단위가
// 보이지 않음), 잘림 표시를 지우는 것(진단 없음).
#[test]
fn test_reclaim_reads_past_foreign_names() {
    let mut f = Fake::default();
    for i in 0..65 {
        f.add(&format!("p/other{i:03}"));
    }
    f.add(&format!("p/{}", unit(1)));
    let mut parent = b"p".to_vec();
    let r = reclaim(&mut f, &mut parent);
    assert_eq!(r.removed, 1, "{r:?}");
    assert!(!r.truncated);
    let mut f = Fake::default();
    for i in 0..LIST_MAX {
        f.add(&format!("p/other{i:04}"));
    }
    f.add(&format!("p/{}", unit(1)));
    let r = reclaim(&mut f, &mut parent);
    assert_eq!(r.removed, 0, "{r:?}");
    assert!(r.truncated, "{r:?}");
    assert!(r.messages().contains(
        &"command reclaim: the session's cgroup folder holds more names than one reclaim reads"
    ));
}

// 마감이 지나면 목록 읽기·rmdir·대기를 새로 시작하지 않는다: 깊이 4 체인의 재귀가 돌아오는 중에 예산이
// 끝나는 경우와, 남는 항목의 재시도 대기가 남은 예산보다 길어지는 경우. 이것을 실패시키는 것: clear의 rmdir
// 앞 마감 확인을 지우는 것, 목록 읽기 앞 확인을 지우는 것, 부모 rmdir 앞 확인을 지우는 것, 재시도 대기를
// 남은 예산으로 자르지 않는 것.
#[test]
fn test_reclaim_stops_at_its_deadline() {
    let mut parent = b"p".to_vec();
    for tick in (1_000_000..4_000_000).step_by(100_000) {
        let mut f = Fake {
            tick,
            ..Fake::default()
        };
        f.add(&format!("p/{}/a/b/c/d", unit(1)));
        let r = reclaim(&mut f, &mut parent);
        let late: Vec<u64> = f
            .starts
            .iter()
            .copied()
            .filter(|&at| at >= RECLAIM_NS)
            .collect();
        assert!(
            late.is_empty(),
            "tick {tick}: calls after the deadline {late:?} {r:?}"
        );
    }
    // A stuck unit whose first read leaves less than 1 ms: no further wait.
    let mut f = Fake {
        tick: 4_875_000,
        ..Fake::default()
    };
    f.add(&format!("p/{}", unit(2)));
    let u = f.get(&format!("p/{}", unit(2)));
    u.populated = true;
    u.stuck = true;
    let r = reclaim(&mut f, &mut parent);
    let left = RECLAIM_NS - f.starts[3] - f.tick;
    assert!(left > 0 && left < 1_000_000, "first read leaves {left} ns");
    assert_eq!(f.waited, 0, "{r:?}");
    assert!(f.starts.iter().all(|&at| at < RECLAIM_NS), "{:?}", f.starts);
    // The open ends at the deadline: no kill follows it.
    let mut f = Fake {
        tick: 10_000_000,
        ..Fake::default()
    };
    f.add(&format!("p/{}", unit(3)));
    let r = reclaim(&mut f, &mut parent);
    assert!(
        !f.log.iter().any(|l| l.starts_with("kill")),
        "{:?} {r:?}",
        f.log
    );
}

// 제거할 수 없는 단위(깊이 제한으로 남는 트리 32개)가 앞에 있어도 뒤의 단위는 kill을 받는다: 실행 중인 고아가
// 끝난다. 이것을 실패시키는 것: KILL_MAX를 방문 창의 절반(32)으로 되돌리는 것(뒤의 단위가 kill되지 않음).
#[test]
fn test_reclaim_kills_past_units_that_stay() {
    let mut f = Fake::default();
    for i in 0..32 {
        f.add(&format!("p/{}/a/b/c/d/e/f", unit(i)));
    }
    let orphan = format!("p/{}", unit(40));
    f.add(&orphan);
    f.get(&orphan).populated = true;
    let mut parent = b"p".to_vec();
    let r = reclaim(&mut f, &mut parent);
    assert!(f.log.contains(&format!("kill {orphan}")), "{r:?}");
    assert!(
        !f.folders[orphan.as_bytes()].populated || f.folders[orphan.as_bytes()].dying > 0,
        "{r:?}"
    );
}
