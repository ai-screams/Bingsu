use super::*;
use bingsu_core::{fs_trust::RefuseGroupWrite, snapshot::ClockError};
use std::io;
use std::{
    cell::Cell,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    rc::Rc,
};

const COMMAND: &str = "[segment.\"custom/probe\"]\nkind = \"command\"\ncommand = [\"printf\", \"NEVER_EXECUTE\"]\n[layout.line1]\nleft = [\"custom/probe\", \"char\"]\n";
fn clock() -> Clock {
    Clock {
        kind: 1,
        domain: [3; 16],
        resume: 0,
        boot: [4; 16],
        now: 10_000_000_000,
    }
}
struct Fixed(Clock);
impl ClockSource for Fixed {
    fn observe(&mut self) -> Result<Clock, ClockError> {
        Ok(self.0)
    }
}
struct Fx {
    base: PathBuf,
    request: RefreshRequest,
}
impl Fx {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("bingsu-n2-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();
        mode(&base, 0o700);
        let base = fs::canonicalize(base).unwrap();
        for n in ["runtime", "config", "state"] {
            fs::create_dir(base.join(n)).unwrap();
            mode(&base.join(n), 0o700);
        }
        let runtime = base.join("runtime");
        let m = fs::metadata(&runtime).unwrap();
        let request = RefreshRequest {
            runtime: Pinned {
                path: runtime,
                dev: m.dev(),
                ino: m.ino(),
            },
            config_written: base.join("config"),
            config_canonical: base.join("config"),
            config_root_shape_only: false,
            state_root: base.join("state"),
            home: base.clone(),
            me: sys::current_uid(),
            user: sys::passwd_entry(sys::current_uid()).unwrap().name,
            version: [0, 3, 0],
            build: Some([1; 40]),
            process_started: clock(),
        };
        Self { base, request }
    }
    fn put(&self, text: &str) {
        put(
            &self.request.config_canonical.join("config.toml"),
            text.as_bytes(),
        );
    }
    fn run(&self) -> RefreshResult {
        refresh(self.request.clone(), &mut Fixed(clock()))
    }
    fn hook(&self, hook: &mut dyn FnMut(Checkpoint)) -> RefreshResult {
        refresh_with(self.request.clone(), &mut Fixed(clock()), hook)
    }
    fn dir(&self) -> PathBuf {
        snapshot::context_components(
            self.request.config_canonical.as_os_str().as_bytes(),
            self.request.state_root.as_os_str().as_bytes(),
        )
        .unwrap()
        .iter()
        .fold(self.request.runtime.path.clone(), |p, n| p.join(n))
    }
    fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir().join(name)).unwrap()
    }
    fn marker(&self) -> Marker {
        Marker::decode(&self.bytes("marker")).unwrap()
    }
    fn snap(&self) -> Snapshot {
        Snapshot::decode(&self.bytes("snapshot")).unwrap()
    }
    fn state(&self) -> Vec<Vec<u8>> {
        ["snapshot", "last-good", "marker"]
            .iter()
            .map(|n| self.bytes(n))
            .collect()
    }
    fn open(&self) -> CheckedContextFd {
        CheckedContextFd::open(
            &self.request.runtime,
            self.request.config_canonical.as_os_str().as_bytes(),
            self.request.state_root.as_os_str().as_bytes(),
            self.request.me,
            &mut RefuseGroupWrite,
            true,
        )
        .unwrap()
    }
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn put(p: &Path, b: &[u8]) {
    fs::write(p, b).unwrap();
    mode(p, 0o600);
}
fn mode(p: &Path, m: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
}
fn published(r: RefreshResult) -> u64 {
    match r {
        RefreshResult::Published { generation, .. } => generation,
        x => panic!("expected publish: {x:?}"),
    }
}

// 이것을 실패시키는 것: 없는 상태 뿌리를 만들지 않거나 설정 뿌리까지 만드는 것.
#[test]
fn fresh_state_root_publishes_on_first_refresh_without_creating_config() {
    let mut f = Fx::new("fresh-state");
    fs::remove_dir(&f.request.state_root).unwrap();
    fs::remove_dir(&f.request.config_canonical).unwrap();
    f.request.state_root = f.base.join("st/deep/bingsu");
    assert_eq!(published(f.run()), 1);
    for name in ["st", "st/deep", "st/deep/bingsu"] {
        assert_eq!(
            fs::metadata(f.base.join(name)).unwrap().mode() & 0o7777,
            0o700
        );
    }
    assert!(!f.request.config_canonical.exists());
    assert_eq!(f.snap().id.generation, 1);
    assert_eq!(f.run(), RefreshResult::Revalidated { generation: 1 });
}

// 이것을 실패시키는 것: 생성 전 조상 판정과 최종 사슬 판정을 생략하는 것.
#[test]
fn fresh_state_root_under_unsafe_ancestor_stays_incomplete() {
    let mut f = Fx::new("unsafe-state");
    let parent = f.base.join("unsafe");
    fs::create_dir(&parent).unwrap();
    // Other write is unsafe regardless of the machine's group membership.
    mode(&parent, 0o757);
    f.request.state_root = parent.join("st/bingsu");
    assert_eq!(f.run(), RefreshResult::Incomplete);
    assert!(!parent.join("st").exists());
    assert!(!f.dir().join("snapshot").exists());
    assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o757);
}

// 이것을 실패시키는 것: init 뒤 심어진 상태 뿌리 링크를 정규화하거나 따라가는 것.
#[test]
fn planted_state_root_symlink_stays_incomplete_and_target_untouched() {
    let mut f = Fx::new("linked-state");
    let target = f.request.state_root.clone();
    put(&target.join("canary"), b"unchanged");
    f.request.state_root = f.base.join("planted");
    symlink(&target, &f.request.state_root).unwrap();
    assert_eq!(f.run(), RefreshResult::Incomplete);
    assert!(
        fs::symlink_metadata(&f.request.state_root)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(target.join("canary")).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
    assert!(!f.dir().join("snapshot").exists());
}

// 이것을 실패시키는 것: 같은 증거에서 G 또는 snapshot inode를 바꾸거나 marker의 V를 갱신하지 않는 것.
#[test]
fn unchanged_reuses_snapshot_and_both_palettes() {
    let f = Fx::new("unchanged");
    f.put(COMMAND);
    assert_eq!(published(f.run()), 1);
    let before = f.state();
    let ino = fs::metadata(f.dir().join("snapshot")).unwrap().ino();
    let c = f.snap().config;
    assert!(c.exec_units.iter().any(|u| u.not_run.is_none()));
    assert_ne!(c.palette, c.light_palette);
    assert_eq!(f.run(), RefreshResult::Revalidated { generation: 1 });
    assert_eq!(f.bytes("snapshot"), before[0]);
    assert_eq!(f.bytes("last-good"), before[1]);
    assert_eq!(fs::metadata(f.dir().join("snapshot")).unwrap().ino(), ino);
    assert_eq!(f.marker().seq, 2);
    assert_eq!(f.marker().verified_at, clock().now);
    assert_ne!(
        fs::metadata(f.dir().join("snapshot")).unwrap().ino(),
        fs::metadata(f.dir().join("last-good")).unwrap().ino()
    );
}
// 이것을 실패시키는 것: 정상 exe -> link -> binary 설치의 마지막 링크를 거부해 매번 재컴파일하는 것.
#[test]
fn symlinked_build_identity_reuses_snapshot() {
    let mut f = Fx::new("linked-build");
    f.put(COMMAND);
    fs::create_dir(f.base.join("bin")).unwrap();
    put(&f.base.join("binary"), b"installed executable");
    symlink(f.base.join("binary"), f.base.join("link")).unwrap();
    let exe = f.base.join("bin/exe");
    symlink("../link", &exe).unwrap();
    let first = super::super::build_identity::read(&exe).unwrap();
    f.request.build = Some(first);
    assert_eq!(published(f.run()), 1);
    let before = f.state();
    let ino = fs::metadata(f.dir().join("snapshot")).unwrap().ino();
    f.request.build = super::super::build_identity::read(&exe);
    assert_eq!(f.request.build, Some(first));
    assert_eq!(f.run(), RefreshResult::Revalidated { generation: 1 });
    assert_eq!(f.bytes("snapshot"), before[0]);
    assert_eq!(f.bytes("last-good"), before[1]);
    assert_eq!(fs::metadata(f.dir().join("snapshot")).unwrap().ino(), ino);
}

// 이것을 실패시키는 것: 비교 증거에서 build identity를 빼고 같은 semver의 snapshot을 재사용하는 것.
#[test]
fn same_version_different_build_recompiles() {
    // Each fact alone must invalidate the compilation, including mtime ns.
    for offset in [0, 8, 16, 24, 32] {
        let mut f = Fx::new(&format!("changed-build-{offset}"));
        f.put(COMMAND);
        assert_eq!(published(f.run()), 1);
        let old = f.bytes("snapshot");
        assert_eq!(f.run(), RefreshResult::Revalidated { generation: 1 });
        f.request.build.as_mut().unwrap()[offset] ^= 1;
        assert_eq!(published(f.run()), 2);
        assert_eq!(f.bytes("last-good"), old);
        assert_eq!(f.run(), RefreshResult::Revalidated { generation: 2 });
    }
}

// 이것을 실패시키는 것: snapshot의 fact schema 불일치를 허용해 기존 field index를 재사용하는 것.
#[test]
fn fact_schema_mismatch_recompiles_with_unchanged_source_and_build() {
    let f = Fx::new("fact-schema");
    f.put("[style]\ntemplate='{git.operation}{git.staged}{git.stash}{char}'\n");
    assert_eq!(published(f.run()), 1);
    let expected = f.snap().config;
    for (version, generation) in [(1u16, 2), (3, 3)] {
        let mut bytes = f.bytes("snapshot");
        let end = bytes.len() - f.snap().metadata.len();
        assert_eq!(&bytes[192..204], b"BNGCFG03\x03\0\x02\0");
        bytes[202..204].copy_from_slice(&version.to_le_bytes());
        let crc = snapshot::crc32c(&[b"bingsu-snapshot-v2\0", &bytes[..160], &bytes[192..end]]);
        bytes[160..164].copy_from_slice(&crc);
        put(&f.dir().join("snapshot"), &bytes);
        assert_eq!(published(f.run()), generation);
        assert_eq!(f.snap().config, expected);
        assert_eq!(f.bytes("last-good"), f.bytes("snapshot"));
        assert_eq!(
            Snapshot::decode_front(&bytes[..end], bytes.len(), 80),
            Err(bingsu_core::snapshot_codec::Error::Tag)
        );
        assert_eq!(f.run(), RefreshResult::Revalidated { generation });
    }
}

// 이것을 실패시키는 것: 빌드 식별값을 읽지 못한 두 요청을 같다고 보고 재사용하는 것.
#[test]
fn unavailable_build_identity_always_recompiles() {
    let mut f = Fx::new("unavailable-build");
    f.put(COMMAND);
    assert_eq!(published(f.run()), 1);
    f.request.build = None;
    for generation in 2..=3 {
        let old = f.bytes("snapshot");
        assert_eq!(published(f.run()), generation);
        assert_eq!(f.bytes("last-good"), old);
    }
}

// 이것을 실패시키는 것: ENOENT·끊긴 링크·FIFO의 미완료 관찰을 발행/Invalid로 확정하는 것.
#[test]
fn unresolved_sources_preserve_all_published_bytes() {
    for kind in ["missing", "dangling", "fifo"] {
        let f = Fx::new(&format!("unresolved-{kind}"));
        f.put(COMMAND);
        published(f.run());
        let before = f.state();
        let sequence = f.bytes("sequence");
        match kind {
            "missing" => f.put("extends = ['missing.toml']\n"),
            _ => {
                // A shared conf.d target cannot establish execution trust for
                // a child that the descriptor walk could not resolve.
                let shared = f.base.join("shared");
                fs::create_dir(&shared).unwrap();
                mode(&shared, 0o777);
                symlink(&shared, f.request.config_canonical.join("conf.d")).unwrap();
                if kind == "dangling" {
                    symlink("missing.toml", shared.join("bad.toml")).unwrap();
                } else {
                    sys::make_test_fifo(&shared.join("bad.toml")).unwrap();
                }
            }
        }
        assert_eq!(f.run(), RefreshResult::Incomplete, "{kind}");
        assert_eq!(f.state(), before, "{kind}");
        assert_eq!(f.bytes("sequence"), sequence, "{kind}");
    }
}

// 이것을 실패시키는 것: 같은 내용의 새 inode나 mtime/ctime 변경을 CRC 일치만으로 재검증 처리하는 것.
#[test]
fn identical_bytes_replacement_and_edit_back_advance_generation() {
    let f = Fx::new("same-bytes");
    f.put(COMMAND);
    published(f.run());
    let id = f.snap().id;
    put(&f.base.join("replacement"), COMMAND.as_bytes());
    fs::rename(
        f.base.join("replacement"),
        f.request.config_canonical.join("config.toml"),
    )
    .unwrap();
    assert_eq!(published(f.run()), 2);
    assert_ne!(f.snap().id.source, id.source);
    f.put("icons = \"ascii\"\n");
    f.put(COMMAND);
    assert_eq!(published(f.run()), 3);
}
// 이것을 실패시키는 것: 깨끗해진 root에서 Envelope의 shape-only 표시를 누락하거나 작성 경로 없는 hook을 복원하는 것.
#[test]
fn envelope_shape_only_ceiling_survives_clean_reopen() {
    let f = Fx::new("shape-ceiling");
    f.put(COMMAND);
    let bytes = |p: &Path| p.as_os_str().as_bytes().to_vec();
    let mut e = Envelope {
        runtime_root: Some(bingsu_core::envelope::OwnedRuntimeRoot {
            dev: f.request.runtime.dev,
            ino: f.request.runtime.ino,
            path: bytes(&f.request.runtime.path),
        }),
        config_root: Some(bytes(&f.request.config_canonical)),
        config_root_written: Some(bytes(&f.request.config_written)),
        config_root_shape_only: true,
        state_root: Some(bytes(&f.request.state_root)),
        home: Some(bytes(&f.base)),
        ..Default::default()
    };
    let user = sys::Passwd {
        name: f.request.user.clone(),
        home: f.base.clone(),
        gid: 0,
    };
    let exe = f.base.join("pinned-exe");
    put(&exe, b"init-pinned executable");
    let r = RefreshRequest::from_envelope(&exe, &e, &user, clock(), [0, 3, 0]).unwrap();
    let identity = super::super::build_identity::read(&exe).unwrap();
    assert_eq!(r.build, Some(identity));
    assert!(r.config_root_shape_only);
    published(refresh(r, &mut Fixed(clock())));
    assert!(
        f.snap()
            .config
            .exec_units
            .iter()
            .all(|u| u.not_run.is_some())
    );
    e.config_root_written = None;
    assert!(RefreshRequest::from_envelope(&exe, &e, &user, clock(), [0, 3, 0]).is_none());
}
// 이것을 실패시키는 것: shape-only 파일 오류를 전체 Invalid로 바꾸거나 left_out 집합을 누락하는 것.
#[test]
fn left_out_publishes_remaining_execution_set() {
    let f = Fx::new("left-out");
    let shape = f.base.join("shape.toml");
    put(&shape, b"icons = 7\n");
    f.put(&format!("extends = [\"{}\"]\n{COMMAND}", shape.display()));
    match f.run() {
        RefreshResult::Published { left_out, .. } => {
            assert_eq!(left_out.as_slice(), std::slice::from_ref(&shape))
        }
        x => panic!("{x:?}"),
    }
    assert!(
        f.snap()
            .config
            .exec_units
            .iter()
            .any(|u| u.not_run.is_none())
    );
    put(&shape, b"icons = \"ascii\"\n");
    match f.run() {
        RefreshResult::Published {
            generation: 2,
            left_out,
        } => assert!(left_out.is_empty()),
        x => panic!("{x:?}"),
    }
}
// 이것을 실패시키는 것: 확인한 컴파일 실패가 화면을 덮거나 Invalid를 쓰지 않는 것.
#[test]
fn invalid_preserves_display_and_advances_only_verification() {
    let f = Fx::new("invalid");
    f.put(COMMAND);
    published(f.run());
    let before = f.state();
    f.put("[broken\n");
    assert_eq!(f.run(), RefreshResult::Invalid);
    assert_eq!(f.bytes("snapshot"), before[0]);
    assert_eq!(f.bytes("last-good"), before[1]);
    assert!(f.marker().invalid);
    assert_eq!((f.marker().id.generation, f.marker().seq), (1, 2));
    let seq = Sequence::decode(&f.bytes("sequence")).unwrap();
    assert_eq!((seq.generation, seq.verified), (1, 2));
}
// 이것을 실패시키는 것: Invalid 분기에서 재확인을 생략하거나 관찰 변경에도 표식을 바꾸는 것.
#[test]
fn changed_during_invalid_read_is_incomplete() {
    let f = Fx::new("invalid-race");
    f.put(COMMAND);
    published(f.run());
    let before = f.state();
    f.put("[broken\n");
    let got = f.hook(&mut |p| {
        if p == Checkpoint::Read {
            f.put(COMMAND);
        }
    });
    assert_eq!(got, RefreshResult::Incomplete);
    assert_eq!(f.state(), before);
}
// 이것을 실패시키는 것: 마지막 원본 fd·이름·부모·모양 파일·목록·부재 확인 중 하나를 생략하는 것.
#[test]
fn mutations_after_staging_never_get_a_new_marker() {
    for kind in 0..8 {
        let f = Fx::new(&format!("source-race-{kind}"));
        f.put(COMMAND);
        published(f.run());
        f.put(&format!("icons = \"ascii\"\n{COMMAND}"));
        let shape = f.base.join("shape.toml");
        put(&shape, b"icons = \"ascii\"\n");
        if kind == 4 {
            f.put(&format!("extends = [\"{}\"]\n{COMMAND}", shape.display()));
        }
        if kind == 5 {
            fs::create_dir(f.request.config_canonical.join("conf.d")).unwrap();
        }
        if kind == 6 {
            fs::create_dir(f.base.join("conf-target")).unwrap();
            symlink(
                f.base.join("conf-target"),
                f.request.config_canonical.join("conf.d"),
            )
            .unwrap();
        }
        let marker = f.bytes("marker");
        let snapshot = f.bytes("snapshot");
        let got = f.hook(&mut |p| {
            if p == Checkpoint::Staged {
                match kind {
                    0 => f.put(COMMAND),
                    1 => {
                        let path = f.request.config_canonical.join("config.toml");
                        fs::rename(&path, f.base.join("old")).unwrap();
                        put(&path, COMMAND.as_bytes());
                    }
                    2 => mode(&f.request.config_canonical, 0o777),
                    3 => put(
                        &f.request.config_canonical.join("config.local.toml"),
                        b"icons='ascii'",
                    ),
                    4 => put(&shape, b"icons='unicode'"),
                    5 => put(
                        &f.request.config_canonical.join("conf.d/new.toml"),
                        b"icons='ascii'",
                    ),
                    6 => {
                        fs::remove_file(f.request.config_canonical.join("conf.d")).unwrap();
                        symlink(
                            f.base.join("conf-target"),
                            f.request.config_canonical.join("conf.d"),
                        )
                        .unwrap();
                    }
                    7 => {
                        fs::create_dir(f.request.config_canonical.join("conf.d")).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        });
        assert_eq!(got, RefreshResult::Incomplete, "case {kind}");
        assert_eq!(f.bytes("marker"), marker, "case {kind}");
        assert_eq!(f.bytes("snapshot"), snapshot, "case {kind}");
    }
}
// 이것을 실패시키는 것: 파일 시스템 관찰 오류를 확인한 부재/Invalid로 낮추는 것.
#[test]
fn observation_errors_preserve_all_published_bytes() {
    let f = Fx::new("observe-error");
    f.put(COMMAND);
    published(f.run());
    let before = f.state();
    let seq = f.bytes("sequence");
    put(
        &f.request.config_canonical.join("conf.d"),
        b"not a directory",
    );
    assert_eq!(f.run(), RefreshResult::Incomplete);
    assert_eq!(f.state(), before);
    assert_eq!(f.bytes("sequence"), seq);
}
// 이것을 실패시키는 것: 현재 snapshot 교체를 마지막 확인에서 발견하지 못하는 것.
#[test]
fn snapshot_changed_under_lock_is_not_published() {
    let f = Fx::new("snapshot-race");
    f.put(COMMAND);
    published(f.run());
    let marker = f.bytes("marker");
    f.put("icons='ascii'\n");
    assert_eq!(
        f.hook(&mut |p| if p == Checkpoint::Staged {
            put(&f.dir().join("snapshot"), b"replaced");
        }),
        RefreshResult::Incomplete
    );
    assert_eq!(f.bytes("marker"), marker);
}
// 이것을 실패시키는 것: 검증한 staging fd 대신 나중에 바뀐 이름의 파일을 발행하는 것.
#[test]
fn replaced_stage_is_rejected() {
    let f = Fx::new("stage-race");
    f.put(COMMAND);
    published(f.run());
    let marker = f.bytes("marker");
    f.put("icons='ascii'\n");
    assert_eq!(
        f.hook(&mut |p| if p == Checkpoint::Validated {
            let p = f.dir().join(".snapshot.stage");
            fs::remove_file(&p).unwrap();
            put(&p, b"replacement");
        }),
        RefreshResult::Incomplete
    );
    assert_eq!(f.bytes("marker"), marker);
}
// 이것을 실패시키는 것: 손상된 snapshot을 last-good으로 복사하거나 손상 sequence의 epoch를 재사용하는 것.
#[test]
fn corruption_recovers_with_new_epoch_and_good_copy() {
    let f = Fx::new("corrupt");
    f.put(COMMAND);
    published(f.run());
    let old = f.snap().id;
    put(&f.dir().join("snapshot"), b"broken");
    put(&f.dir().join("sequence"), b"broken");
    assert_eq!(published(f.run()), 1);
    assert_ne!(f.snap().id.epoch, old.epoch);
    assert_eq!(f.bytes("snapshot"), f.bytes("last-good"));
    assert!(!f.marker().invalid);
}
// 이것을 실패시키는 것: 다른 부팅의 화면을 last-good으로 보존하거나 이전 부팅의 번호를 계속 쓰는 것.
#[test]
fn reboot_does_not_retain_foreign_display() {
    let mut f = Fx::new("reboot");
    f.put(COMMAND);
    published(f.run());
    f.request.process_started.boot = [9; 16];
    f.put("icons='ascii'\n");
    let c = f.request.process_started;
    assert_eq!(published(refresh(f.request.clone(), &mut Fixed(c))), 1);
    assert_eq!(f.bytes("snapshot"), f.bytes("last-good"));
    assert_eq!(f.snap().id.boot, [9; 16]);
}
// 이것을 실패시키는 것: 500ms/수명 마감·시각 역행·domain/boot/resume 변경 뒤 Valid를 발행하는 것.
#[test]
fn clock_boundaries_preserve_marker_and_use_start_time() {
    struct Changing {
        value: Rc<Cell<Clock>>,
    }
    impl ClockSource for Changing {
        fn observe(&mut self) -> Result<Clock, ClockError> {
            Ok(self.value.get())
        }
    }
    for kind in 0..8 {
        let f = Fx::new(&format!("clock-{kind}"));
        f.put(COMMAND);
        published(f.run());
        let marker = f.bytes("marker");
        f.put("icons='ascii'\n");
        let value = Rc::new(Cell::new(clock()));
        let mut c = Changing {
            value: value.clone(),
        };
        let mut r = f.request.clone();
        if kind == 6 {
            r.process_started.now = clock().now - LIFE_NS + 1;
        }
        let got = refresh_with(r, &mut c, &mut |p| {
            if kind == 7 && p == Checkpoint::Staged {
                let mut c = clock();
                c.now += 100;
                value.set(c);
            }
            if p == Checkpoint::Before(Slot::Marker) {
                let mut now = clock();
                match kind {
                    0 => now.now += WORK_NS,
                    1 => now.now -= 1,
                    2 => now.domain = [8; 16],
                    3 => now.boot = [8; 16],
                    4 => now.resume = 1,
                    5 => now.now += WORK_NS - 1,
                    6 => now.now += 1,
                    7 => now.now += 90,
                    _ => unreachable!(),
                };
                value.set(now);
            }
        });
        if kind == 5 {
            assert!(matches!(got, RefreshResult::Published { .. }));
            assert_eq!(f.marker().verified_at, clock().now);
        } else {
            assert_eq!(got, RefreshResult::Incomplete, "case {kind}");
            assert_eq!(f.bytes("marker"), marker, "case {kind}");
        }
    }
}
// 이것을 실패시키는 것: 마감 시작 전에 root를 열거나 시계 실패를 0으로 대체하는 것.
#[test]
fn missing_clock_has_no_filesystem_effect() {
    struct Failed;
    impl ClockSource for Failed {
        fn observe(&mut self) -> Result<Clock, ClockError> {
            Err(ClockError::Time)
        }
    }
    let f = Fx::new("no-clock");
    assert_eq!(
        refresh(f.request.clone(), &mut Failed),
        RefreshResult::Incomplete
    );
    assert!(
        fs::read_dir(&f.request.runtime.path)
            .unwrap()
            .next()
            .is_none()
    );
}
// 이것을 실패시키는 것: state root를 문맥 키에서 빼거나 같은 설정 문맥의 잠금을 공유하지 않는 것.
#[test]
fn context_locks_are_shared_only_for_identical_root_pairs() {
    let f = Fx::new("contexts");
    f.put(COMMAND);
    published(f.run());
    let root = f.open();
    let _lock = root.try_lock().unwrap();
    let before = f.state();
    assert_eq!(f.run(), RefreshResult::Busy);
    assert_eq!(f.state(), before);
    let mut other = f.request.clone();
    other.state_root = f.base.join("other-state");
    fs::create_dir(&other.state_root).unwrap();
    mode(&other.state_root, 0o700);
    assert_eq!(published(refresh(other, &mut Fixed(clock()))), 1);
}
// 이것을 실패시키는 것: 잠금 아래 예약된 G/V의 빈 번호를 실패 뒤 재사용하는 것.
#[test]
fn reserved_numbers_are_not_reused_after_failure() {
    let f = Fx::new("reservation");
    f.put(COMMAND);
    published(f.run());
    f.put("icons='ascii'\n");
    assert_eq!(
        f.hook(&mut |p| if p == Checkpoint::Staged {
            f.put("icons='unicode'\n");
        }),
        RefreshResult::Incomplete
    );
    let seq = Sequence::decode(&f.bytes("sequence")).unwrap();
    assert_eq!((seq.generation, seq.verified), (2, 2));
    assert_eq!(published(f.run()), 3);
    assert_eq!(f.marker().seq, 3);
}
// 이것을 실패시키는 것: CLOEXEC fd를 상속한 exec 전 자식이 종료할 때까지 정상 반환 뒤 잠금을 유지하는 것.
#[test]
fn inherited_descriptors_do_not_extend_a_refresh_lock() {
    let _inherited_fds = sys::test_inherited_fd_lock();
    struct Expiring(Rc<Cell<bool>>);
    impl ClockSource for Expiring {
        fn observe(&mut self) -> Result<Clock, ClockError> {
            let mut now = clock();
            if self.0.get() {
                now.now += WORK_NS;
            }
            Ok(now)
        }
    }
    // Staged holds the snapshot lock; Validated holds both locks. Exercise
    // successful publication and an Incomplete return with the child alive.
    for point in [Checkpoint::Staged, Checkpoint::Validated] {
        for incomplete in [false, true] {
            let f = Fx::new(&format!("inherited-{point:?}-{incomplete}"));
            f.put(COMMAND);
            published(f.run());
            let marker = f.bytes("marker");
            f.put("icons='ascii'\n");
            let mut child = None;
            let expired = Rc::new(Cell::new(false));
            let got = refresh_with(
                f.request.clone(),
                &mut Expiring(expired.clone()),
                &mut |p| {
                    if p == point {
                        child = Some(sys::PausedFork::new());
                        expired.set(incomplete);
                    }
                },
            );
            assert!(child.is_some());
            if incomplete {
                assert_eq!(got, RefreshResult::Incomplete);
                assert_eq!(f.bytes("marker"), marker);
            } else {
                published(got);
            }
            // A fresh open-file description must acquire each lock while the
            // child still owns inherited references to the previous ones.
            drop(
                SelectionLock::try_lock(&f.request.state_root, f.request.me, &mut RefuseGroupWrite)
                    .unwrap(),
            );
            f.put(COMMAND);
            published(f.run());
            drop(child);
        }
    }
}
// 이것을 실패시키는 것: 회수 중 symlink·hardlink·mode·FIFO·초과 크기를 지우거나 현재 파일까지 지우는 것.
#[test]
fn staging_recovery_checks_safety_before_unlink() {
    let _inherited_fds = sys::test_inherited_fd_lock();
    for kind in 0..6 {
        let f = Fx::new(&format!("recover-{kind}"));
        f.put(COMMAND);
        let mut child = None;
        published(f.hook(&mut |point| {
            if point == Checkpoint::Validated {
                child = Some(sys::PausedFork::new());
            }
        }));
        // 이것을 실패시키는 것: 상속 fd가 살아 있을 때 scope 종료의 명시적 unlock을 생략하는 것.
        assert!(child.is_some());
        let before = f.state();
        let p = f.dir().join(".snapshot.stage");
        match kind {
            0 => put(&p, b"partial"),
            1 => symlink("snapshot", &p).unwrap(),
            2 => fs::hard_link(f.dir().join("snapshot"), &p).unwrap(),
            3 => {
                put(&p, b"partial");
                mode(&p, 0o644);
            }
            4 => sys::make_test_fifo(&p).unwrap(),
            5 => {
                put(&p, b"");
                fs::OpenOptions::new()
                    .write(true)
                    .open(&p)
                    .unwrap()
                    .set_len(32 * 1024 * 1024 + 1)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let got = f.run();
        if kind == 0 {
            assert_eq!(got, RefreshResult::Revalidated { generation: 1 });
            assert!(!p.exists());
        } else {
            assert_eq!(got, RefreshResult::Incomplete, "case {kind}");
            assert!(fs::symlink_metadata(&p).is_ok());
            assert_eq!(f.state(), before);
        }
    }
}
// 이것을 실패시키는 것: 영속 잠금 파일을 rename/unlink하거나 잘못된 파일을 lock으로 허용하는 것.
#[test]
fn lock_safety_and_identity_are_enforced() {
    let f = Fx::new("lock-safety");
    let root = f.open();
    let p = f.dir().join("snapshot.lock");
    put(&p, b"not empty");
    assert!(root.try_lock().is_err());
    put(&p, b"");
    mode(&p, 0o644);
    assert!(root.try_lock().is_err());
    mode(&p, 0o600);
    let lock = root.try_lock().unwrap();
    let ino = fs::metadata(&p).unwrap().ino();
    fs::rename(&p, f.dir().join("old-lock")).unwrap();
    put(&p, b"");
    assert!(lock.verify_lock().is_err());
    drop(lock);
    assert_eq!(fs::metadata(f.dir().join("old-lock")).unwrap().ino(), ino);
    assert!(p.exists());
}
// 이것을 실패시키는 것: 발행 전에 renew를 쓰거나 새 canonical 선택을 자동 renew로 덮어쓰는 것.
#[test]
fn selection_renewal_is_serialized_and_follows_publication() {
    use super::super::trust_record::{self, Record};
    let f = Fx::new("renew");
    let selected = f.base.join("selected.toml");
    put(&selected, COMMAND.as_bytes());
    let md = fs::metadata(&selected).unwrap();
    let old = Record {
        path: selected.clone(),
        dev: md.dev(),
        ino: md.ino(),
    };
    trust_record::write(
        &f.request.state_root,
        f.request.me,
        &mut RefuseGroupWrite,
        &old,
    )
    .unwrap();
    published(f.run());
    put(&f.base.join("next"), COMMAND.as_bytes());
    fs::rename(f.base.join("next"), &selected).unwrap();
    let mut observed = false;
    published(f.hook(&mut |p| {
        if p == Checkpoint::Published {
            observed = true;
            assert_eq!(
                trust_record::read(&f.request.state_root, f.request.me, &mut RefuseGroupWrite)
                    .unwrap(),
                old
            );
            assert_eq!(
                trust_record::write(
                    &f.request.state_root,
                    f.request.me,
                    &mut RefuseGroupWrite,
                    &old
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }));
    assert!(observed);
    let renewed =
        trust_record::read(&f.request.state_root, f.request.me, &mut RefuseGroupWrite).unwrap();
    assert_ne!(renewed.ino, old.ino);
    let lock = SelectionLock::try_lock(&f.request.state_root, f.request.me, &mut RefuseGroupWrite)
        .unwrap();
    let evidence = lock.read(&mut RefuseGroupWrite).unwrap().unwrap();
    assert!(
        lock.renew(
            &evidence,
            &Record {
                path: f.base.join("different"),
                ..renewed
            },
            &mut RefuseGroupWrite
        )
        .is_err()
    );
}
// 이것을 실패시키는 것: 기록 부재를 최종 확인하지 않거나 보유 RecordEvidence 없이 선택을 신뢰하는 것.
#[test]
fn approval_appearance_or_replacement_aborts_publication() {
    for present in [false, true] {
        let f = Fx::new(if present {
            "record-replace"
        } else {
            "record-appear"
        });
        f.put(COMMAND);
        published(f.run());
        let marker = f.bytes("marker");
        if present {
            super::super::trust_record::write(
                &f.request.state_root,
                f.request.me,
                &mut RefuseGroupWrite,
                &super::super::trust_record::Record {
                    path: f.request.config_canonical.join("config.toml"),
                    dev: 1,
                    ino: 1,
                },
            )
            .unwrap();
        }
        f.put("icons='ascii'\n");
        assert_eq!(
            f.hook(&mut |p| if p == Checkpoint::Staged {
                put(&f.request.state_root.join("config-use"), b"changed");
            }),
            RefreshResult::Incomplete
        );
        assert_eq!(f.bytes("marker"), marker);
    }
}

fn child_request(base: PathBuf) -> RefreshRequest {
    let runtime = base.join("runtime");
    let m = fs::metadata(&runtime).unwrap();
    RefreshRequest {
        runtime: Pinned {
            path: runtime,
            dev: m.dev(),
            ino: m.ino(),
        },
        config_written: base.join("config"),
        config_canonical: base.join("config"),
        config_root_shape_only: false,
        state_root: base.join("state"),
        home: base,
        me: sys::current_uid(),
        user: sys::passwd_entry(sys::current_uid()).unwrap().name,
        version: [0, 3, 0],
        build: Some([1; 40]),
        process_started: clock(),
    }
}
fn spawn_child(f: &Fx, point: &str) -> std::process::Child {
    let exe = std::env::current_exe().unwrap();
    let mut command = if point == "umask" {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "umask 0277; exec \"$@\"", "bingsu-umask-test"])
            .arg(exe);
        command
    } else {
        std::process::Command::new(exe)
    };
    command
        .args([
            "--exact",
            "commands::refresh::tests::process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("BINGSU_N2_TEST_BASE", &f.base)
        .env("BINGSU_N2_TEST_POINT", point)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap()
}
fn await_ready(f: &Fx, child: &mut std::process::Child) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !f.base.join("ready").exists() {
        if let Some(status) = child.try_wait().unwrap() {
            // The child can write ready and exit between exists and try_wait.
            // Parents still check its exit status and exact checkpoint bytes.
            assert!(
                f.base.join("ready").exists(),
                "child exited before checkpoint: {status}"
            );
            break;
        }
        if std::time::Instant::now() >= until {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("checkpoint timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
// 이것을 실패시키는 것: 새 open-file description의 두 프로세스 lock을 동시에 허용하거나 Busy에서 파일을 바꾸는 것.
#[test]
fn two_processes_observe_nonblocking_snapshot_and_selection_locks() {
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    let f = Fx::new("process-lock");
    f.put(COMMAND);
    published(f.run());
    let before = f.state();
    let root = f.open();
    let lock = root.try_lock().unwrap();
    let mut child = spawn_child(&f, "contend");
    await_ready(&f, &mut child);
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read(f.base.join("ready")).unwrap(), b"Busy");
    assert_eq!(f.state(), before);
    drop(lock);
    fs::remove_file(f.base.join("ready")).unwrap();
    let _selection =
        SelectionLock::try_lock(&f.request.state_root, f.request.me, &mut RefuseGroupWrite)
            .unwrap();
    let mut child = spawn_child(&f, "selection");
    await_ready(&f, &mut child);
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read(f.base.join("ready")).unwrap(), b"Busy");
}
// 이것을 실패시키는 것: 어느 rename 중단점에서든 잘못 짝지은 Valid를 허용하거나 SIGKILL 잔여를 회수하지 않는 것.
#[test]
fn sigkill_before_and_after_every_rename_recovers_fixed_slots() {
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    for slot in Slot::ALL {
        for before in [true, false] {
            let f = Fx::new(&format!("kill-{slot:?}-{before}"));
            f.put(COMMAND);
            published(f.run());
            let old = f.snap().id;
            let old_marker = f.bytes("marker");
            let lock_ino = fs::metadata(f.dir().join("snapshot.lock")).unwrap().ino();
            f.put("icons='ascii'\n");
            let point = if before {
                Checkpoint::Before(slot)
            } else {
                Checkpoint::After(slot)
            };
            let mut child = spawn_child(&f, &format!("{point:?}"));
            await_ready(&f, &mut child);
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert!(!status.success());
            if point != Checkpoint::After(Slot::Marker) {
                assert_eq!(f.bytes("marker"), old_marker);
            }
            // 이것을 실패시키는 것: last-good rename 뒤 현재의 옛 정상 세대를 잃는 것.
            if matches!(
                point,
                Checkpoint::After(Slot::LastGood)
                    | Checkpoint::Before(Slot::Snapshot)
                    | Checkpoint::After(Slot::Snapshot)
                    | Checkpoint::Before(Slot::Marker)
            ) {
                assert_eq!(Snapshot::decode(&f.bytes("last-good")).unwrap().id, old);
            }
            if matches!(
                point,
                Checkpoint::After(Slot::Snapshot) | Checkpoint::Before(Slot::Marker)
            ) {
                assert_ne!(f.snap().id, old);
                assert!(
                    snapshot::eligible(f.snap().id, Some(f.marker()), clock(), f.snap().id.context)
                        .is_err()
                );
            }
            assert!(matches!(
                f.run(),
                RefreshResult::Published { .. } | RefreshResult::Revalidated { .. }
            ));
            assert!(
                snapshot::eligible(f.snap().id, Some(f.marker()), clock(), f.snap().id.context)
                    .is_ok()
            );
            assert_eq!(
                fs::metadata(f.dir().join("snapshot.lock")).unwrap().ino(),
                lock_ino
            );
            let names: Vec<_> = fs::read_dir(f.dir())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names.len(), 5, "staging accumulation: {names:?}");
            assert!(Snapshot::decode(&f.bytes("last-good")).is_ok());
        }
    }
}
// A second generation with its own command, so units tell the generations apart.
const NEW_COMMAND: &str = "icons = \"ascii\"\n[segment.\"custom/probe\"]\nkind = \"command\"\ncommand = [\"printf\", \"NEVER_EXECUTE_NEW\"]\n[layout.line1]\nleft = [\"char\", \"custom/probe\"]\n";
/// What the front decides from the published files: the whole record (status,
/// warning and layout included), the status, and the execution it approves.
#[derive(Debug, PartialEq)]
struct FrontView {
    record: Vec<u8>,
    status: bingsu_core::status::Status,
    units: Vec<bingsu_core::config::compile::ExecUnit>,
    permit: Option<bingsu_core::handoff::Permit>,
}
fn read_front(f: &Fx) -> FrontView {
    read_front_at(f, clock())
}
/// The front's view when its own clock (start and end samples) reads `at`.
fn read_front_at(f: &Fx, at: Clock) -> FrontView {
    let r = crate::prompt_read::tests::published_response(
        &f.request.runtime.path,
        f.request.config_canonical.as_os_str().as_bytes(),
        f.request.state_root.as_os_str().as_bytes(),
        at,
    );
    FrontView {
        record: r.record,
        status: r.status,
        units: r.execution.units().to_vec(),
        permit: r.execution.permit(),
    }
}
fn argv(front: &FrontView) -> Vec<Vec<String>> {
    front
        .units
        .iter()
        .map(|u| match &u.policy {
            bingsu_core::config::compile::ExecPolicy::Command { argv, .. } => argv.clone(),
            _ => Vec::new(),
        })
        .collect()
}
fn command(word: &str) -> Vec<Vec<String>> {
    vec![vec!["printf".to_owned(), word.to_owned()]]
}
fn kill_at(f: &Fx, point: Checkpoint) {
    let mut child = spawn_child(f, &format!("{point:?}"));
    await_ready(f, &mut child);
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
}
// 세대 일치(GATE-GENERATION.1·2): 어느 중단점에서 죽여도 앞단은 표의 snapshot·marker 조합 하나를
// 고르고, 그 조합을 죽이지 않고 써 둔 대조와 레코드·상태·실행 단위·permit이 모두 같다.
// 이것을 실패시키는 것: Marker를 Snapshot보다 먼저 rename하는 것, 앞단의 짝 비교(eligible의 id 비교와
// staged의 Pair 분기)를 없애는 것, 다음 도우미가 짝을 맞추지 않고 끝내는 것.
#[test]
fn front_matches_checkpoint_control_at_every_kill_point() {
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    // Same tag, so every fixture below has the same paths, context and units.
    let tag = "kill-front";
    let (old, mixed, new) = {
        let f = Fx::new(tag);
        f.put(COMMAND);
        published(f.run());
        let (snapshot, marker) = (f.bytes("snapshot"), f.bytes("marker"));
        f.put(NEW_COMMAND);
        published(f.run());
        let write = |s: &[u8], m: &[u8]| {
            put(&f.dir().join("snapshot"), s);
            put(&f.dir().join("marker"), m);
            read_front(&f)
        };
        let (new_snapshot, new_marker) = (f.bytes("snapshot"), f.bytes("marker"));
        (
            write(&snapshot, &marker),
            write(&new_snapshot, &marker),
            write(&new_snapshot, &new_marker),
        )
    };
    use bingsu_core::status::Status;
    // 이것을 실패시키는 것: 앞단에 게시자 시계가 닿지 않아 모든 행이 거부되는 것(대조 자체가 빈 것).
    assert_eq!(
        (old.status, argv(&old)),
        (Status::OK_NONE, command("NEVER_EXECUTE"))
    );
    assert!(old.permit.is_some());
    assert_eq!(
        (new.status, argv(&new)),
        (Status::OK_NONE, command("NEVER_EXECUTE_NEW"))
    );
    assert!(new.permit.is_some());
    // The mixed control selects the new snapshot (its layout) and approves nothing.
    assert_eq!(mixed.status, Status::DEGRADED_TRUST_MISMATCH);
    assert!(mixed.units.is_empty());
    assert_eq!(mixed.permit, None);
    assert_ne!(mixed.record, old.record);
    assert_ne!(mixed.record, new.record);
    // The new layout draws ASCII glyphs; the old one draws '❯'.
    assert!(mixed.record.windows(3).all(|w| w != "❯".as_bytes()));
    assert!(old.record.windows(3).any(|w| w == "❯".as_bytes()));
    // Every checkpoint variant, so a new one cannot be left out silently.
    let points = [
        Checkpoint::Locked,
        Checkpoint::Read,
        Checkpoint::Staged,
        Checkpoint::Validated,
        Checkpoint::Published,
    ]
    .into_iter()
    .chain(
        Slot::ALL
            .into_iter()
            .flat_map(|s| [Checkpoint::Before(s), Checkpoint::After(s)]),
    );
    for point in points {
        // Exhaustive: a new variant fails to compile until it is listed above.
        match point {
            Checkpoint::Locked
            | Checkpoint::Read
            | Checkpoint::Staged
            | Checkpoint::Validated
            | Checkpoint::Published
            | Checkpoint::Before(_)
            | Checkpoint::After(_) => {}
        }
        let f = Fx::new(tag);
        f.put(COMMAND);
        published(f.run());
        let before = f.state();
        let first = f.snap().id;
        f.put(NEW_COMMAND);
        kill_at(&f, point);
        let (new_snapshot, new_marker) = match point {
            Checkpoint::After(Slot::Snapshot) | Checkpoint::Before(Slot::Marker) => (true, false),
            Checkpoint::After(Slot::Marker) | Checkpoint::Published => (true, true),
            _ => (false, false),
        };
        // Files: exactly the table's combination; last-good is always the old copy.
        assert_eq!(f.bytes("last-good"), before[1], "{point:?}");
        assert_eq!(f.bytes("snapshot") == before[0], !new_snapshot, "{point:?}");
        assert_eq!(f.bytes("marker") == before[2], !new_marker, "{point:?}");
        let selected = f.snap().id;
        assert_eq!(
            (selected.epoch, selected.generation),
            (first.epoch, if new_snapshot { 2 } else { 1 }),
            "{point:?}"
        );
        if new_marker {
            assert_eq!(f.marker().id, selected, "{point:?}");
        }
        let expected = match (new_snapshot, new_marker) {
            (false, false) => &old,
            (true, false) => &mixed,
            _ => &new,
        };
        let got = read_front(&f);
        assert_eq!(&got, expected, "{point:?}");
        if new_snapshot && !new_marker {
            assert_eq!(got.status, Status::DEGRADED_TRUST_MISMATCH, "{point:?}");
            assert!(got.units.is_empty(), "{point:?}");
            assert_eq!(got.permit, None, "{point:?}");
        }
        // The next helper finishes publication with a matching pair.
        let next = f.run();
        assert!(
            matches!(
                next,
                RefreshResult::Published { .. } | RefreshResult::Revalidated { .. }
            ),
            "{point:?}: {next:?}"
        );
        assert_eq!(f.marker().id, f.snap().id, "{point:?}");
        assert_eq!(read_front(&f), new, "{point:?}");
    }
}
// 표식 짝(GATE-MARKER-UPDATE.2): 세대만 또는 원본 요약만 다른 표식에도 앞단은 실행 단위를 하나도 승인하지 않는다.
// 이것을 실패시키는 것: 앞단 짝 비교(eligible과 staged 두 곳)를 세대만 비교하도록 줄이거나 없애는 것.
#[test]
fn marker_disagreeing_in_generation_or_summary_launches_no_unit() {
    use bingsu_core::status::Status;
    let f = Fx::new("pair-fields");
    f.put(COMMAND);
    published(f.run());
    let good = f.bytes("marker");
    let allowed = read_front(&f);
    assert_eq!(
        (allowed.status, argv(&allowed)),
        (Status::OK_NONE, command("NEVER_EXECUTE"))
    );
    assert!(allowed.permit.is_some());
    for (what, change) in [
        (
            "generation",
            (|m: &mut Marker| m.id.generation += 1) as fn(&mut Marker),
        ),
        ("summary", |m| m.id.source[0] ^= 1),
    ] {
        let mut marker = Marker::decode(&good).unwrap();
        change(&mut marker);
        put(&f.dir().join("marker"), &marker.encode());
        let got = read_front(&f);
        assert_eq!(got.status, Status::DEGRADED_TRUST_MISMATCH, "{what}");
        assert!(got.units.is_empty(), "{what}");
        assert_eq!(got.permit, None, "{what}");
    }
}
/// P-R4 (user ruling 2026-10-15): a file that fails its safety check or whose
/// ACL cannot be decided is left out; the rest is verified and marked. Two
/// approved units, then `damage` takes trust from the conf.d one only.
fn assert_drops_only_that_files_units(damage: &str) {
    use bingsu_core::status::Status;
    let f = Fx::new(&format!("left-out-{damage}"));
    f.put("[segment.\"custom/keep\"]\nkind = \"command\"\ncommand = [\"printf\", \"KEEP\"]\n[layout.line1]\nleft = [\"custom/keep\", \"custom/drop\", \"char\"]\n");
    let conf_d = f.request.config_canonical.join("conf.d");
    fs::create_dir(&conf_d).unwrap();
    mode(&conf_d, 0o700);
    let dropped = conf_d.join("drop.toml");
    put(
        &dropped,
        b"[segment.\"custom/drop\"]\nkind = \"command\"\ncommand = [\"printf\", \"DROP\"]\n",
    );
    published(f.run());
    let both = read_front(&f);
    let mut approved = argv(&both);
    approved.sort();
    assert_eq!(
        approved,
        [command("DROP"), command("KEEP")].concat(),
        "{damage}"
    );
    let old_marker = f.bytes("marker");
    match damage {
        "mode-0646" => mode(&dropped, 0o646),
        "acl-allows-write" => {
            let out = std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(&dropped)
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        "acl-undecided" => set_posix_acl(&dropped),
        _ => unreachable!(),
    }
    assert_eq!(
        f.run(),
        RefreshResult::Published {
            generation: 2,
            left_out: vec![dropped.clone()],
        },
        "{damage}"
    );
    // A fresh valid marker replaces the one that approved the dropped unit.
    assert_ne!(f.bytes("marker"), old_marker, "{damage}");
    assert!(!f.marker().invalid, "{damage}");
    assert_eq!(f.marker().id, f.snap().id, "{damage}");
    // The very next front read, at the same clock (no wait for T): only the rest.
    let got = read_front(&f);
    assert_eq!(
        (got.status, argv(&got)),
        (Status::OK_NONE, command("KEEP")),
        "{damage}"
    );
    assert!(got.permit.is_some(), "{damage}");
}
/// Linux POSIX access ACL with a named entry, then group write: the mode's
/// group bits become the mask, which `fs_trust` cannot decide (L-R7).
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_posix_acl(path: &Path) {
    // Version 2, then (tag, perm, id): USER_OBJ rw, USER nobody r, GROUP_OBJ none, MASK rw, OTHER none.
    let mut blob = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 65534),
        (4, 0, u32::MAX),
        (0x10, 6, u32::MAX),
        (0x20, 0, u32::MAX),
    ] {
        blob.extend(tag.to_le_bytes());
        blob.extend(perm.to_le_bytes());
        blob.extend(id.to_le_bytes());
    }
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: NUL-terminated path and attribute name, initialized value bytes.
    let rc = unsafe {
        libc::setxattr(
            name.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            blob.as_ptr().cast(),
            blob.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    mode(path, 0o660);
}
#[cfg(not(target_os = "linux"))]
fn set_posix_acl(_: &Path) {
    unreachable!("Linux POSIX ACL fixture")
}
// 표식 갱신 조건(GATE-MARKER-UPDATE.1): 마감 초과·일부 훑음·conf.d 목록 실패에서는 Incomplete이고
// snapshot·last-good·marker·sequence가 한 바이트도 바뀌지 않는다. ACL 오류(판정 불가)는 P-R4대로 그 파일만
// 빠지고 그 단위는 바로 다음 앞단에서 승인되지 않는다(Linux POSIX ACL; macOS의 ACL 조회 오류는 주입할 수 없다, M1 L243).
// 이것을 실패시키는 것: Verified::Incomplete를 Invalid 표식으로 바꾸는 것(N-057 모양), 마감 확인을 빼는 것,
// 훑지 못한 원본이나 conf.d 목록 오류를 확인한 부재로 낮추는 것, 판정 불가 ACL 파일을 실행 가능으로 두는 것.
#[test]
fn marker_unchanged_after_deadline_partial_scan_acl_error_or_conf_d_failure() {
    struct Late(Rc<Cell<bool>>);
    impl ClockSource for Late {
        fn observe(&mut self) -> Result<Clock, ClockError> {
            let mut now = clock();
            if self.0.get() {
                now.now += WORK_NS;
            }
            Ok(now)
        }
    }
    for case in ["deadline", "partial-scan", "conf-d-listing"] {
        let f = Fx::new(&format!("unchanged-{case}"));
        f.put(COMMAND);
        published(f.run());
        let before = (f.state(), f.bytes("sequence"));
        let late = Rc::new(Cell::new(false));
        match case {
            "deadline" => f.put(&format!("icons = \"ascii\"\n{COMMAND}")),
            // An extends source that cannot be walked leaves the set unscanned.
            "partial-scan" => f.put(&format!("extends = [\"parts/none.toml\"]\n{COMMAND}")),
            "conf-d-listing" => put(
                &f.request.config_canonical.join("conf.d"),
                b"not a directory",
            ),
            _ => unreachable!(),
        }
        let got = refresh_with(f.request.clone(), &mut Late(late.clone()), &mut |p| {
            if case == "deadline" && p == Checkpoint::Read {
                late.set(true);
            }
        });
        assert_eq!(got, RefreshResult::Incomplete, "{case}");
        assert_eq!((f.state(), f.bytes("sequence")), before, "{case}");
    }
    #[cfg(target_os = "linux")]
    assert_drops_only_that_files_units("acl-undecided");
}
// 확인한 실패(GATE-MARKER-UPDATE.3): 컴파일 실패를 확인하면 무효 표식이 써지고, 바로 다음 앞단 읽기가
// degraded:trust-invalid이며 실행 단위를 승인하지 않는다. 옛 화면은 남는다. 확인한 신뢰 실패(남 쓰기 0646,
// macOS ACL 쓰기 허용)는 P-R4대로 그 파일만 빠지고, 바로 다음 앞단에서 그 단위만 승인되지 않는다(T를 기다리지 않음).
// 이것을 실패시키는 것: 확인한 실패를 Incomplete로 낮춰 옛 표식이 T까지 승인되게 하는 것, 앞단이 invalid 표식을 무시하는 것,
// 신뢰를 잃은 파일의 단위를 새 표식에 남기는 것(안전 거부 무시, 앞단 not_run 거름 제거).
#[test]
fn confirmed_trust_or_compile_failure_writes_invalid_marker_and_next_prompt_degrades() {
    use bingsu_core::status::Status;
    let f = Fx::new("confirmed-invalid");
    f.put(COMMAND);
    published(f.run());
    let shown = read_front(&f);
    assert_eq!(
        (shown.status, argv(&shown)),
        (Status::OK_NONE, command("NEVER_EXECUTE"))
    );
    f.put("[broken\n");
    assert_eq!(f.run(), RefreshResult::Invalid);
    assert!(f.marker().invalid);
    assert_eq!(f.marker().id, f.snap().id);
    let got = read_front(&f);
    assert_eq!(got.status, Status::DEGRADED_TRUST_INVALID);
    assert!(got.units.is_empty());
    assert_eq!(got.permit, None);
    // The display stays: the same layout as before, now with the warning.
    assert!(got.record.windows(3).any(|w| w == "❯".as_bytes()));
    assert_ne!(got.record, shown.record);
    assert_drops_only_that_files_units("mode-0646");
    #[cfg(target_os = "macos")]
    assert_drops_only_that_files_units("acl-allows-write");
}
// 이것을 실패시키는 것: 부모가 요청한 실제 Rust 발행 중단점이나 두 프로세스 Busy 검사를 실행하지 않는 것.
#[test]
#[ignore = "child of the bounded lock and SIGKILL parent tests"]
#[expect(
    clippy::disallowed_methods,
    reason = "test child fixture and checkpoint, never production inputs"
)]
fn process_child() {
    let base = PathBuf::from(std::env::var_os("BINGSU_N2_TEST_BASE").unwrap());
    let point = std::env::var("BINGSU_N2_TEST_POINT").unwrap();
    let r = child_request(base.clone());
    if point == "umask" {
        assert_eq!(published(refresh(r.clone(), &mut Fixed(clock()))), 1);
        assert_eq!(
            refresh(r, &mut Fixed(clock())),
            RefreshResult::Revalidated { generation: 1 }
        );
        put(&base.join("ready"), b"Published and revalidated");
        return;
    }
    if point == "contend" {
        let got = refresh(r, &mut Fixed(clock()));
        assert_eq!(got, RefreshResult::Busy);
        put(&base.join("ready"), b"Busy");
        return;
    }
    if point == "selection" {
        assert_eq!(
            SelectionLock::try_lock(&r.state_root, r.me, &mut RefuseGroupWrite)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        put(&base.join("ready"), b"Busy");
        return;
    }
    let got = refresh_with(r, &mut Fixed(clock()), &mut |p| {
        if format!("{p:?}") == point {
            put(&base.join("ready"), b"checkpoint");
            loop {
                std::thread::park();
            }
        }
    });
    panic!("missed checkpoint {point}: {got:?}");
}
// 이것을 실패시키는 것: 증거 payload 상한을 빼거나 내용 비교를 CRC만으로 대체하는 것.
#[test]
fn canonical_evidence_is_bounded_and_compares_all_bytes() {
    use super::super::evidence::{Encoder, EvidenceExport};
    let mut e = Encoder::new();
    e.raw(&vec![0; snapshot::META_MAX]);
    assert!(e.finish().is_err());
    let f = Fx::new("evidence");
    f.put(COMMAND);
    published(f.run());
    let metadata = f.snap().metadata;
    let mut export = EvidenceExport {
        comparison: EvidenceExport::comparison_in(&metadata).unwrap().to_vec(),
        ..Default::default()
    };
    assert!(export.matches(&metadata));
    export.comparison[0] ^= 1;
    assert!(!export.matches(&metadata));
    assert!(!export.matches(b"bad"));
    export.comparison[0] ^= 1;
    let mut wrong_tag = snapshot::decode_metadata(&metadata).unwrap().to_vec();
    wrong_tag[0] ^= 1;
    assert!(!export.matches(&snapshot::encode_metadata(&wrong_tag).unwrap()));
    for payload in [
        b"wrongtag".to_vec(),
        b"BNGEVD02".to_vec(),
        [b"BNGEVD02".as_slice(), &u64::MAX.to_le_bytes()].concat(),
        [b"BNGEVD02".as_slice(), &9u64.to_le_bytes()].concat(),
    ] {
        let malformed = snapshot::encode_metadata(&payload).unwrap();
        assert!(!export.matches(&malformed));
        assert!(EvidenceExport::comparison_in(&malformed).is_none());
    }
}

// 이것을 실패시키는 것: Unsafe 원본의 실행 키를 살아 있는 실행 단위로 발행하거나 제외 알림을 버리는 것.
#[test]
fn unsafe_sources_keep_shape_but_never_execution() {
    let f = Fx::new("unsafe-source");
    f.put(&format!("icons='ascii'\n{COMMAND}"));
    mode(&f.request.config_canonical.join("config.toml"), 0o666);
    match f.run() {
        RefreshResult::Published { left_out, .. } => {
            assert_eq!(left_out, [f.request.config_canonical.join("config.toml")])
        }
        x => panic!("{x:?}"),
    }
    let c = f.snap().config;
    assert_eq!(c.icons, bingsu_core::icons::IconSet::Ascii);
    assert!(!c.exec_units.is_empty());
    assert!(c.exec_units.iter().all(|u| u.not_run.is_some()));
}
// 이것을 실패시키는 것: 늦은 시작·시계 종류/좌표 불일치·overflow에서도 작업 마감을 생성하는 것.
#[test]
fn budget_rejects_invalid_initial_coordinates() {
    let c = clock();
    assert!(Budget::new(c, c).is_some());
    for kind in 0..5 {
        let mut start = c;
        let mut process = c;
        match kind {
            0 => {
                start.kind = 9;
                process.kind = 9;
            }
            1 => process.domain = [0; 16],
            2 => start.now += LIFE_NS,
            3 => process.now += 1,
            4 => start.now = u64::MAX,
            _ => unreachable!(),
        }
        assert!(Budget::new(start, process).is_none(), "case {kind}");
    }
}
// 이것을 실패시키는 것: 정상 실패 후 staging을 남기거나 같은 문맥 디렉터리 교체를 감지하지 못하는 것.
#[test]
fn context_replacement_and_normal_failure_cleanup() {
    let f = Fx::new("context-replace");
    f.put(COMMAND);
    published(f.run());
    let marker = f.bytes("marker");
    f.put("icons='ascii'\n");
    let old = f.dir().with_file_name("old-store");
    assert_eq!(
        f.hook(&mut |p| if p == Checkpoint::Staged {
            fs::rename(f.dir(), &old).unwrap();
            fs::create_dir(f.dir()).unwrap();
            mode(&f.dir(), 0o700);
        }),
        RefreshResult::Incomplete
    );
    assert_eq!(fs::read(old.join("marker")).unwrap(), marker);
    assert!(
        fs::read_dir(old)
            .unwrap()
            .all(|e| !e.unwrap().file_name().as_bytes().ends_with(b".stage"))
    );
}
// 이것을 실패시키는 것: 자동 renew 실패를 발행 실패로 돌리거나 변경된 승인 기록을 덮는 것.
#[test]
fn renewal_failure_keeps_published_result_and_new_selection() {
    use super::super::trust_record::{self, Record};
    let f = Fx::new("renew-failure");
    let selected = f.base.join("selected");
    put(&selected, COMMAND.as_bytes());
    let m = fs::metadata(&selected).unwrap();
    trust_record::write(
        &f.request.state_root,
        f.request.me,
        &mut RefuseGroupWrite,
        &Record {
            path: selected.clone(),
            dev: m.dev(),
            ino: m.ino(),
        },
    )
    .unwrap();
    published(f.run());
    put(&f.base.join("next"), COMMAND.as_bytes());
    fs::rename(f.base.join("next"), &selected).unwrap();
    published(f.hook(&mut |p| {
        if p == Checkpoint::Published {
            put(
                &f.request.state_root.join("config-use"),
                b"concurrently changed selection",
            );
        }
    }));
    assert_eq!(
        fs::read(f.request.state_root.join("config-use")).unwrap(),
        b"concurrently changed selection"
    );
    assert!(
        snapshot::eligible(f.snap().id, Some(f.marker()), clock(), f.snap().id.context).is_ok()
    );
}
// 이것을 실패시키는 것: staging의 형식·크기 검사를 빼거나 staging 이름의 새 inode 교체를 허용하는 것.
#[test]
fn store_refuses_invalid_staged_wire_and_changed_fds() {
    let f = Fx::new("bad-stage");
    let root = f.open();
    let store = root.try_lock().unwrap();
    for slot in Slot::ALL {
        assert!(store.stage(slot, b"invalid").is_err());
    }
    assert!(
        store
            .stage(Slot::Marker, &vec![0; snapshot::MARKER + 1])
            .is_err()
    );
    let seq = Sequence {
        boot: clock().boot,
        epoch: [2; 16],
        generation: 1,
        verified: 1,
    };
    store.stage(Slot::Sequence, &seq.encode()).unwrap();
    put(
        &f.dir().join("replacement"),
        &Sequence {
            generation: 2,
            ..seq
        }
        .encode(),
    );
    fs::rename(f.dir().join("replacement"), f.dir().join(".sequence.stage")).unwrap();
    assert!(store.install(Slot::Sequence).is_err());
}
// 이것을 실패시키는 것: 새 stage/lock fd의 fchmod를 빼서 umask가 0600에서 소유자 쓰기 비트를 지우게 하는 것.
#[test]
fn restrictive_umask_still_publishes_private_files() {
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    let f = Fx::new("umask");
    f.put(COMMAND);
    // Provision the private directory walk before changing the child's umask;
    // this regression concerns file creation, not mkdir's separate mode policy.
    drop(f.open());
    let mut child = spawn_child(&f, "umask");
    await_ready(&f, &mut child);
    assert!(child.wait().unwrap().success());
    for name in [
        "snapshot.lock",
        "sequence",
        "snapshot",
        "last-good",
        "marker",
    ] {
        assert_eq!(
            fs::metadata(f.dir().join(name)).unwrap().mode() & 0o7777,
            0o600,
            "{name}"
        );
    }
    assert_eq!(
        fs::metadata(f.request.state_root.join("selection.lock"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
}
// 이것을 실패시키는 것: 기존 lock을 열 때도 0600으로 고쳐 안전하지 않은 mode를 숨기는 것.
#[test]
fn existing_lock_permissions_are_never_repaired() {
    let f = Fx::new("existing-lock-mode");
    f.put(COMMAND);
    published(f.run());
    let lock = f.dir().join("snapshot.lock");
    mode(&lock, 0o640);
    assert_eq!(f.run(), RefreshResult::Incomplete);
    assert_eq!(fs::metadata(lock).unwrap().mode() & 0o7777, 0o640);
}
// 이것을 실패시키는 것: 매번 전체 컴파일하거나 증거 변경을 무시해 재검증 경로로 보내는 것.
#[test]
#[ignore = "explicit release cost measurement, run with --ignored --nocapture"]
fn measure_changed_and_unchanged_refresh() {
    let f = Fx::new("measure");
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    for i in 0..25 {
        f.put(&format!(
            "icons='{}'\n{COMMAND}",
            if i % 2 == 0 { "ascii" } else { "unicode" }
        ));
        let t = std::time::Instant::now();
        assert_eq!(published(f.run()), i + 1);
        changed.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = std::time::Instant::now();
        assert_eq!(f.run(), RefreshResult::Revalidated { generation: i + 1 });
        unchanged.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    for (name, mut values) in [("changed", changed), ("unchanged", unchanged)] {
        values.sort_by(f64::total_cmp);
        eprintln!(
            "N2 {name} n=25 median_ms={:.3} p95_ms={:.3}",
            values[12], values[23]
        );
    }
}

// 이것을 실패시키는 것: 승인 기록이 없어도 state root의 정체 변경을 비교 증거에서 누락하는 것.
#[test]
fn state_identity_changes_generation_even_without_selection() {
    let f = Fx::new("state-identity");
    f.put(COMMAND);
    published(f.run());
    fs::rename(&f.request.state_root, f.base.join("old-state")).unwrap();
    fs::create_dir(&f.request.state_root).unwrap();
    mode(&f.request.state_root, 0o700);
    assert_eq!(published(f.run()), 2);
}
// 이것을 실패시키는 것: 증거 직렬화에서 파일 시각·size·uid/gid/mode·ACL·소유권을 누락하거나 잘못된 nsec를 받는 것.
#[test]
fn evidence_fields_are_explicit_and_directory_times_are_not_sources() {
    use super::super::evidence::Encoder;
    use bingsu_core::fs_trust::{AclFacts, Facts};
    let f = Facts {
        dev: 1,
        ino: 2,
        uid: 3,
        gid: 4,
        mode: 0o100600,
        acl: AclFacts::None,
        ownership: Some(true),
    };
    let encode = |f| {
        let mut e = Encoder::new();
        e.facts(f);
        e.finish().unwrap()
    };
    for changed in [
        Facts { dev: 9, ..f },
        Facts { ino: 9, ..f },
        Facts { uid: 9, ..f },
        Facts { gid: 9, ..f },
        Facts {
            mode: 0o100644,
            ..f
        },
        Facts {
            acl: AclFacts::Unknown,
            ..f
        },
        Facts {
            ownership: None,
            ..f
        },
    ] {
        assert_ne!(encode(f), encode(changed));
    }
    let s = sys::Stamp {
        dev: 1,
        ino: 2,
        uid: 3,
        gid: 4,
        mode: 0o100600,
        size: 5,
        mtime: (6, 7),
        ctime: (8, 9),
    };
    let encode = |s: &sys::Stamp| {
        let mut e = Encoder::new();
        e.stamp(s);
        e.finish()
    };
    for changed in [
        sys::Stamp {
            size: 9,
            ..s.clone()
        },
        sys::Stamp {
            mtime: (6, 8),
            ..s.clone()
        },
        sys::Stamp {
            ctime: (8, 10),
            ..s.clone()
        },
    ] {
        assert_ne!(encode(&s).unwrap(), encode(&changed).unwrap());
    }
    assert!(
        encode(&sys::Stamp {
            mtime: (0, -1),
            ..s.clone()
        })
        .is_err()
    );
    let dir = sys::Stamp { mode: 0o40700, ..s };
    let changed = sys::Stamp {
        size: 900,
        mtime: (900, 900),
        ctime: (900, 900),
        ..dir.clone()
    };
    assert_eq!(encode(&dir).unwrap(), encode(&changed).unwrap());
}

// 이것을 실패시키는 것: init이 없다고 본 root가 읽기 도중 나타나도 확인한 부재를 보존하는 것.
#[test]
fn missing_config_root_is_part_of_final_absence_check() {
    let f = Fx::new("missing-root");
    fs::remove_dir(&f.request.config_canonical).unwrap();
    published(f.run());
    let marker = f.bytes("marker");
    assert_eq!(
        f.hook(&mut |p| if p == Checkpoint::Staged {
            fs::create_dir(&f.request.config_canonical).unwrap();
        }),
        RefreshResult::Incomplete
    );
    assert_eq!(f.bytes("marker"), marker);
}

// 이것을 실패시키는 것: selection.lock을 전체 컴파일 동안 잡아 서로 다른 문맥을 Busy로 막는 것.
#[test]
fn different_configs_with_one_state_can_compile_concurrently() {
    let f = Fx::new("shared-state");
    f.put(COMMAND);
    let config = f.base.join("other-config");
    fs::create_dir(&config).unwrap();
    mode(&config, 0o700);
    let mut other = f.request.clone();
    other.config_written = config.clone();
    other.config_canonical = config;
    published(f.hook(&mut |p| {
        if p == Checkpoint::Read {
            assert_eq!(published(refresh(other.clone(), &mut Fixed(clock()))), 1);
        }
    }));
}
// 이것을 실패시키는 것: 읽기 이후 config use의 성공한 선택 변경을 놓치거나 발행 직전 state Busy를 새 Valid로 바꾸는 것.
#[test]
fn selection_changes_and_late_contention_preserve_marker() {
    use super::super::trust_record::{self, Record};
    for kind in 0..3 {
        let f = Fx::new(&format!("late-selection-{kind}"));
        f.put(COMMAND);
        published(f.run());
        let marker = f.bytes("marker");
        f.put("icons='ascii'\n");
        let selected = f.base.join("selected.toml");
        put(&selected, COMMAND.as_bytes());
        let m = fs::metadata(&selected).unwrap();
        let mut lock = None;
        assert_eq!(
            f.hook(&mut |p| if p == Checkpoint::Staged {
                if kind == 0 {
                    trust_record::write(
                        &f.request.state_root,
                        f.request.me,
                        &mut RefuseGroupWrite,
                        &Record {
                            path: selected.clone(),
                            dev: m.dev(),
                            ino: m.ino(),
                        },
                    )
                    .unwrap();
                } else if kind == 2 {
                    fs::rename(&f.request.state_root, f.base.join("old-state")).unwrap();
                    fs::create_dir(&f.request.state_root).unwrap();
                    mode(&f.request.state_root, 0o700);
                } else {
                    lock = Some(
                        SelectionLock::try_lock(
                            &f.request.state_root,
                            f.request.me,
                            &mut RefuseGroupWrite,
                        )
                        .unwrap(),
                    );
                }
            }),
            RefreshResult::Incomplete
        );
        assert_eq!(f.bytes("marker"), marker);
    }
}

// 이것을 실패시키는 것: cold 화면 수집·검증 전 broker 호출·필터 실패 후 발행·broker 뒤 최종 재검증 생략.
#[test]
fn broker_runs_after_validation_before_final_revalidation() {
    let fx = Fx::new("broker");
    fx.put(COMMAND);
    let mut calls = 0;
    let result = refresh_broker(
        fx.request.clone(),
        &mut Fixed(clock()),
        &mut |_, display, now| {
            calls += 1;
            assert!(
                display.is_none(),
                "cold screen is published before collection"
            );
            assert_eq!(now.boot, clock().boot);
            Err(StoreError::Unsafe)
        },
    );
    assert_eq!(calls, 1);
    assert_eq!(result, RefreshResult::Incomplete);
    assert!(!fx.dir().join("marker").exists());
    let result = refresh_broker(fx.request.clone(), &mut Fixed(clock()), &mut |_, _, _| {
        fx.put("broken = [");
        Ok(())
    });
    assert_eq!(result, RefreshResult::Incomplete);
    assert!(!fx.dir().join("marker").exists());
    fx.put(COMMAND);
    published(fx.run());
    let id = fx.snap().id;
    fx.put("broken = [");
    let result = refresh_broker(
        fx.request.clone(),
        &mut Fixed(clock()),
        &mut |_, display, _| {
            assert_eq!(display.unwrap().1, id);
            Ok(())
        },
    );
    assert_eq!(result, RefreshResult::Invalid);
}

// 이것을 실패시키는 것: staging 용량 초과를 확인한 설정 Invalid로 바꾸거나 표식을 갱신하는 것.
#[test]
fn n7_capacity_is_incomplete() {
    let f = Fx::new("n7-capacity");
    f.put(COMMAND);
    published(f.run());
    let before = f.state();
    f.put(&format!("icons='ascii'\n{COMMAND}"));
    let result = f.hook(&mut |point| {
        if point == Checkpoint::Staged {
            fs::OpenOptions::new()
                .write(true)
                .open(f.dir().join(".snapshot.stage"))
                .unwrap()
                .set_len(
                    (snapshot::HEADER
                        + snapshot::PREFIX
                        + snapshot::COMPILED_MAX
                        + snapshot::META_MAX
                        + 1) as u64,
                )
                .unwrap();
        }
    });
    assert_eq!(result, RefreshResult::Incomplete);
    assert_eq!(f.state(), before);
}

// 이것을 실패시키는 것: marker 원자 rename을 기존 inode의 overwrite로 바꾸는 것.
#[test]
fn n7_marker_replacement_changes_inode() {
    let f = Fx::new("n7-marker-inode");
    f.put(COMMAND);
    published(f.run());
    // Keep the old inode open, so inode-number recycling cannot mimic overwrite.
    let old = fs::File::open(f.dir().join("marker")).unwrap();
    let old_bytes = f.bytes("marker");
    assert!(matches!(f.run(), RefreshResult::Revalidated { .. }));
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(f.dir().join("marker")).unwrap().ino()
    );
    use std::os::unix::fs::FileExt;
    let mut held = vec![0; old_bytes.len()];
    old.read_exact_at(&mut held, 0).unwrap();
    assert_eq!(held, old_bytes);
}

// 이것을 실패시키는 것: changed/unchanged 분류를 바꾸거나 경계 설정을 발행하지 못하는 것.
#[test]
#[ignore = "N7 release measurements: 20 warmups, 240 alternating pairs; --nocapture"]
fn n7_measure_publish() {
    struct Advancing;
    impl ClockSource for Advancing {
        fn observe(&mut self) -> Result<Clock, ClockError> {
            Ok(Clock {
                now: crate::prompt_io::monotonic_ns(crate::prompt_io::ClockUse::Deadline)?,
                ..clock()
            })
        }
    }
    for (name, body) in [
        ("normal", COMMAND.to_owned()),
        (
            "4096-band",
            (0..4095)
                .map(|i| format!("[layout.when.b{i}]\nmin_cols={}\nmax_cols=10000\n", i + 60))
                .collect::<String>(),
        ),
    ] {
        let f = Fx::new(&format!("n7-measure-{name}"));
        let mut request = f.request.clone();
        // Sample held descriptors at publication boundaries in a separate pass;
        // enumeration itself must not inflate any timed sample.
        f.put(&body);
        request.process_started = Advancing.observe().unwrap();
        let mut peak = 0;
        let probe = refresh_with(request.clone(), &mut Advancing, &mut |_| {
            let directory = if cfg!(target_os = "linux") {
                "/proc/self/fd"
            } else {
                "/dev/fd"
            };
            let count = fs::read_dir(directory).unwrap().count().saturating_sub(1);
            peak = peak.max(count);
        });
        println!("N7_FD\t{name}\tcheckpoint_peak={peak}\tresult={probe:?}");
        let mut run = || {
            request.process_started = Advancing.observe().unwrap();
            let start = std::time::Instant::now();
            let result = refresh(request.clone(), &mut Advancing);
            (result, start.elapsed().as_nanos())
        };
        for i in 0..260 {
            f.put(&format!(
                "icons='{}'\n{body}",
                if i % 2 == 0 { "ascii" } else { "unicode" }
            ));
            let (changed, changed_ns) = run();
            if !matches!(changed, RefreshResult::Published { .. }) {
                eprintln!(
                    "N7_STOP\t{name}\titeration={i}\tresult={changed:?}\telapsed_ns={changed_ns}"
                );
                break; // report; do not raise a budget or reinterpret Incomplete
            }
            let (unchanged, unchanged_ns) = run();
            assert!(matches!(unchanged, RefreshResult::Revalidated { .. }));
            if i >= 20 {
                println!(
                    "N7_PUBLISH\t{name}\t{}\t{changed_ns}\t{unchanged_ns}\t{}",
                    i - 20,
                    f.bytes("snapshot").len()
                );
            }
        }
    }
}

// 이것을 실패시키는 것: runtime staging/rename 경로에 fsync를 추가하는 것.
#[test]
#[cfg(not(target_env = "musl"))]
fn n7_runtime_publication_has_no_fsync() {
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    use std::process::Command;
    let f = Fx::new("n7-fsync-parent");
    let library = f.base.join("no-fsync.dylib");
    let mut compiler = Command::new("cc");
    #[cfg(target_os = "macos")]
    compiler.arg("-dynamiclib");
    #[cfg(target_os = "linux")]
    compiler.args(["-shared", "-fPIC"]);
    let compiled = compiler
        .args(["-Wall", "-Werror", "-o"])
        .arg(&library)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/n7_no_fsync.c"))
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let key = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::refresh::tests::n7_runtime_fsync_child",
            "--ignored",
        ])
        .env(key, &library)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "runtime fsync probe: {:?}\n{}\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "isolated preload fixture; persistent selection renewal is deliberately absent"]
fn n7_runtime_fsync_child() {
    let f = Fx::new("n7-fsync-child");
    f.put(COMMAND);
    published(f.run());
    assert!(matches!(f.run(), RefreshResult::Revalidated { .. }));
}

// ---- C3: trust revocation past verified_at + T and scan-time changes ----
// 신뢰 철회(GATE-TRUST-REVOKE.1): 설정 파일에 chmod g+w를 한 뒤 다시 확인할 도우미가 끝나지 못하면
// (다른 도우미가 문맥 잠금을 쥐고 막혀 Busy) 옛 표식이 그대로 남고, 앞단 시계가 verified_at + T에
// 닿은 프롬프트부터 그 파일의 실행 단위는 승인되지 않는다. 마감 1ns 전은 아직 승인한다(양성 대조,
// 스펙이 받아들인 T 창). 도우미가 다시 확인을 끝내는 경로(P-R4, 그 파일만 빠짐)는 C2의
// confirmed_trust_or_compile_failure_writes_invalid_marker_and_next_prompt_degrades가 맡는다.
// 이것을 실패시키는 것: snapshot::eligible의 T 비교를 `>=`에서 `>`로 바꾸는 것.
#[test]
fn chmod_g_w_after_verified_at_plus_t_approves_no_unit() {
    use bingsu_core::status::Status;
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    let f = Fx::new("revoke-after-t");
    f.put(COMMAND);
    published(f.run());
    let verified = f.marker().verified_at;
    let before = f.state();
    mode(&f.request.config_canonical.join("config.toml"), 0o620);
    {
        // A helper blocked while holding the context lock (GATE-HELPER-LIFETIME.3).
        let root = f.open();
        let _held = root.try_lock().unwrap();
        assert_eq!(f.run(), RefreshResult::Busy);
    }
    assert_eq!(f.state(), before);
    let at = |now| Clock { now, ..clock() };
    let inside = read_front_at(&f, at(verified + snapshot::T_NS - 1));
    assert_eq!(
        (inside.status, argv(&inside)),
        (Status::OK_NONE, command("NEVER_EXECUTE"))
    );
    assert_eq!(
        inside.permit.map(|p| p.deadline),
        Some(verified + snapshot::T_NS)
    );
    for now in [verified + snapshot::T_NS, verified + 2 * snapshot::T_NS] {
        let past = read_front_at(&f, at(now));
        assert_eq!(past.status, Status::DEGRADED_TRUST_EXPIRED, "{now}");
        assert!(past.units.is_empty(), "{now}");
        assert_eq!(past.permit, None, "{now}");
    }
}
// 훑기 중 변경(GATE-EXEC-DEADLINE.2): 원본을 다 읽은 직후(Checkpoint::Read, 최종 재확인 전) 설정 파일에
// chmod g+w를 하거나 같은 내용의 새 파일로 교체하면 최종 재확인이 실패해 Incomplete이고, snapshot·
// last-good·marker·sequence가 바이트 단위로 그대로다. 아무것도 바꾸지 않은 대조는 Revalidated이고
// 표식이 바뀐다(표식이 바뀔 수 있는 실행이었음을 보임). Staged 시점 주입은 GATE-EXEC-DEADLINE.2-m3a 행.
// 이것을 실패시키는 것: 최종 재확인(Loader::revalidate_with)을 통째로 생략하는 것. 원본 관찰 비교만 끄면
// 보유한 실행 가능 파일의 재확인이 같은 변화를 잡는다(동등 변이, 보고서 참조).
#[test]
fn scan_time_chmod_or_replace_keeps_marker() {
    let mut seen = Vec::new();
    for case in ["control", "chmod-g+w", "replace"] {
        let f = Fx::new(&format!("scan-time-{case}"));
        f.put(COMMAND);
        published(f.run());
        let before = (f.state(), f.bytes("sequence"));
        let path = f.request.config_canonical.join("config.toml");
        let got = f.hook(&mut |p| {
            if p == Checkpoint::Read {
                match case {
                    "chmod-g+w" => mode(&path, 0o620),
                    "replace" => {
                        let staged = f.request.config_canonical.join("config.toml.new");
                        put(&staged, COMMAND.as_bytes());
                        fs::rename(&staged, &path).unwrap();
                    }
                    _ => {}
                }
            }
        });
        // Every case is reported together, so one mutation shows each case's outcome.
        seen.push((case, got, (f.state(), f.bytes("sequence")) == before));
    }
    assert_eq!(
        seen,
        [
            (
                "control",
                RefreshResult::Revalidated { generation: 1 },
                false
            ),
            ("chmod-g+w", RefreshResult::Incomplete, true),
            ("replace", RefreshResult::Incomplete, true),
        ]
    );
}

mod axes {
    //! Helper I/O axes over whole refresh rounds (spec 1435, user decision U2).
    use super::*;
    use crate::commands::io_meter::{
        self, AXIS_CAPS, AxisCaps, AxisExceeded, HelperAxis, TestCaps,
    };

    const UNLIMITED: AxisCaps = AxisCaps {
        f: u64::MAX,
        p: u64::MAX,
        l: u64::MAX,
        r: u64::MAX,
        d: u64::MAX,
        e_n: u64::MAX,
        e_b: u64::MAX,
        m: u64::MAX,
        b: u64::MAX,
    };

    /// One refresh, and what its session charged.
    fn metered(f: &Fx, caps: AxisCaps) -> (RefreshResult, AxisUse, Option<AxisExceeded>) {
        let _caps = TestCaps::set(caps);
        let r = f.run();
        let (used, exceeded) = io_meter::last_session().expect("one session");
        (r, used, exceeded)
    }

    fn at(used: &AxisUse, axis: HelperAxis) -> u64 {
        used[axis as usize]
    }

    fn with_cap(axis: HelperAxis, cap: u64) -> AxisCaps {
        let mut c = UNLIMITED;
        *match axis {
            HelperAxis::F => &mut c.f,
            HelperAxis::P => &mut c.p,
            HelperAxis::L => &mut c.l,
            HelperAxis::R => &mut c.r,
            HelperAxis::D => &mut c.d,
            HelperAxis::En => &mut c.e_n,
            HelperAxis::Eb => &mut c.e_b,
            HelperAxis::M => &mut c.m,
            HelperAxis::B => &mut c.b,
        } = cap;
        c
    }

    /// Normal names below "/" of an absolute path.
    fn depth(p: &Path) -> u64 {
        p.components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .count() as u64
    }

    /// The `d_reclen` sum of one listing, counted with libc directly.
    #[allow(unsafe_code)]
    fn reclen_sum(dir: &Path) -> u64 {
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: c is NUL-terminated; the stream is closed below.
        let stream = unsafe { libc::opendir(c.as_ptr()) };
        assert!(!stream.is_null());
        let mut sum = 0;
        loop {
            // SAFETY: stream is live until closedir.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: entry is readdir's live record.
            sum += u64::from(unsafe { (*entry).d_reclen });
        }
        // SAFETY: closes the stream opened above once.
        unsafe { libc::closedir(stream) };
        sum
    }

    /// A shape-only theme outside the config root that does not parse: core
    /// drops it and the config still publishes.
    const BAD: &[u8] = b"[style\nthis is not toml\n";

    type Setup = Box<dyn Fn(&Fx)>;
    type Delta = Box<dyn Fn(&Fx) -> Option<u64>>;

    struct Case {
        axis: HelperAxis,
        /// The fixture without, then with, the refused or non-config work.
        base: Setup,
        extra: Setup,
        /// What the extra work must add on this axis (None: platform facts).
        delta: Delta,
    }

    fn themes(f: &Fx) -> PathBuf {
        let d = f.base.join("themes");
        if !d.exists() {
            fs::create_dir(&d).unwrap();
            mode(&d, 0o700);
        }
        d
    }

    fn conf_d(f: &Fx, names: &[&str]) -> PathBuf {
        let d = f.request.config_canonical.join("conf.d");
        fs::create_dir(&d).unwrap();
        mode(&d, 0o700);
        for n in names {
            if n.ends_with('/') {
                fs::create_dir(d.join(n.trim_end_matches('/'))).unwrap();
            } else {
                put(&d.join(n), b"");
            }
        }
        d
    }

    fn extends(f: &Fx, refs: &[String]) {
        let list: Vec<String> = refs.iter().map(|r| format!("{r:?}")).collect();
        f.put(&format!(
            "extends = [{}]\nicons = \"ascii\"\n",
            list.join(", ")
        ));
    }

    fn cases() -> Vec<Case> {
        let bad_theme = |f: &Fx| {
            let p = themes(f).join("bad.toml");
            put(&p, BAD);
            p
        };
        vec![
            // F: a dropped shape-only theme is still a distinct file opened.
            Case {
                axis: HelperAxis::F,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(move |f| {
                    let p = bad_theme(f);
                    extends(f, &[p.display().to_string()]);
                }),
                delta: Box::new(|_| Some(1)),
            },
            // P: every name of the dropped theme's path, in the first walk and
            // in each of the three revalidations.
            Case {
                axis: HelperAxis::P,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(move |f| {
                    let p = bad_theme(f);
                    extends(f, &[p.display().to_string()]);
                }),
                delta: Box::new(|f| Some(4 * depth(&f.base.join("themes/bad.toml")))),
            },
            // L: a link to the dropped theme, read in each of the four walks.
            Case {
                axis: HelperAxis::L,
                base: Box::new(move |f| {
                    let p = bad_theme(f);
                    extends(f, &[p.display().to_string()]);
                }),
                extra: Box::new(move |f| {
                    bad_theme(f);
                    let link = themes(f).join("link.toml");
                    symlink("bad.toml", &link).unwrap();
                    extends(f, &[link.display().to_string()]);
                }),
                delta: Box::new(|_| Some(4)),
            },
            // R: entries refused before any lookup still count, one each.
            Case {
                axis: HelperAxis::R,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(|f| {
                    extends(
                        f,
                        &[
                            "$THEME".into(),
                            "https://x/y.toml".into(),
                            "~other/z.toml".into(),
                        ],
                    )
                }),
                delta: Box::new(|_| Some(3)),
            },
            // D: the one conf.d, listed four times in a round, is one folder.
            Case {
                axis: HelperAxis::D,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(|f| {
                    f.put("icons = \"ascii\"\n");
                    conf_d(f, &["a.toml"]);
                }),
                delta: Box::new(|_| Some(1)),
            },
            // E_n: entries that are not config (hidden, other suffix, folder)
            // count in each of the four listings.
            Case {
                axis: HelperAxis::En,
                base: Box::new(|f| {
                    f.put("icons = \"ascii\"\n");
                    conf_d(f, &["a.toml"]);
                }),
                extra: Box::new(|f| {
                    f.put("icons = \"ascii\"\n");
                    conf_d(f, &["a.toml", ".hidden.toml", "notes.txt", "sub/"]);
                }),
                delta: Box::new(|_| Some(4 * 3)),
            },
            // E_b: the same entries' record bytes, four listings.
            Case {
                axis: HelperAxis::Eb,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(|f| {
                    f.put("icons = \"ascii\"\n");
                    conf_d(f, &["a.toml", ".hidden.toml", "notes.txt", "sub/"]);
                }),
                delta: Box::new(|f| {
                    Some(4 * reclen_sum(&f.request.config_canonical.join("conf.d")))
                }),
            },
            // M: the mounts of every walked folder (macOS reads fstatfs; Linux none).
            Case {
                axis: HelperAxis::M,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(|f| f.put("icons = \"ascii\"\n")),
                delta: Box::new(|_| None),
            },
            // B: the dropped theme's bytes are read once.
            Case {
                axis: HelperAxis::B,
                base: Box::new(|f| f.put("icons = \"ascii\"\n")),
                extra: Box::new(move |f| {
                    let p = bad_theme(f);
                    extends(f, &[p.display().to_string()]);
                }),
                delta: Box::new(|f| {
                    let config = fs::metadata(f.request.config_canonical.join("config.toml"));
                    Some(
                        BAD.len() as u64 + config.unwrap().len()
                            - "icons = \"ascii\"\n".len() as u64,
                    )
                }),
            },
        ]
    }

    /// Distinct `st_dev` of "/" and every folder down to `p`.
    fn mounts_down_to(p: &Path) -> u64 {
        let mut devs: Vec<u64> = p
            .ancestors()
            .map(|a| fs::metadata(a).unwrap().dev())
            .collect();
        devs.sort_unstable();
        devs.dedup();
        devs.len() as u64
    }

    // 축 아홉 각각: 버린·거부한 참조와 설정이 아닌 항목의 일이 그 축에 들어가고(base 대비 delta), 그 회차의
    // 사용량 U에서 cap = U는 통과, cap = U − 1은 Incomplete이며 snapshot·last-good·marker·sequence가 그대로다.
    // 이것을 실패시키는 것: 걸러낸 뒤에만 E_n을 세는 것, 거부된 참조를 R에서 빼는 것, D를 목록마다 세는 것,
    // 재검증의 걷기·목록을 세지 않는 것, 버린 원본의 바이트를 B에서 빼는 것, 두 축 칸을 합치는 것, cap 비교의
    // 하나 차이, B 읽기를 남은 여유 + 1바이트로 묶지 않는 것.
    #[test]
    fn test_each_axis_counts_rejected_and_non_config_work() {
        let mut seen = Vec::new();
        for case in cases() {
            let tag = format!("{:?}", case.axis).to_lowercase();
            let base = Fx::new(&format!("axis-{tag}-base"));
            (case.base)(&base);
            let (r, base_used, _) = metered(&base, UNLIMITED);
            published(r);
            let f = Fx::new(&format!("axis-{tag}"));
            (case.extra)(&f);
            published(metered(&f, UNLIMITED).0);
            let (r, used, exceeded) = metered(&f, UNLIMITED);
            assert_eq!(r, RefreshResult::Revalidated { generation: 1 }, "{tag}");
            assert_eq!(exceeded, None);
            let u = at(&used, case.axis);
            let delta = u - at(&base_used, case.axis);
            let expected = (case.delta)(&f).unwrap_or_else(|| {
                if cfg!(target_os = "macos") {
                    mounts_down_to(&f.request.config_canonical)
                } else {
                    0
                }
            });
            if case.axis == HelperAxis::M {
                seen.push((case.axis, u, expected));
            } else {
                seen.push((case.axis, delta, expected));
            }
            // Cap = U passes; on Linux M is 0 and cannot be crossed on disk.
            let (r, _, exceeded) = metered(&f, with_cap(case.axis, u));
            assert_eq!(
                (r, exceeded),
                (RefreshResult::Revalidated { generation: 1 }, None),
                "{tag} at cap"
            );
            if u == 0 {
                continue;
            }
            let before = (f.state(), f.bytes("sequence"));
            let (r, _, exceeded) = metered(&f, with_cap(case.axis, u - 1));
            assert_eq!(r, RefreshResult::Incomplete, "{tag} over cap");
            assert_eq!(exceeded.map(|e| e.axis), Some(case.axis), "{tag}");
            assert_eq!((f.state(), f.bytes("sequence")), before, "{tag}");
            if case.axis == HelperAxis::B {
                // A read never asks for more than one byte past the room left.
                let (r, _, exceeded) = metered(&f, with_cap(HelperAxis::B, u - 10));
                assert_eq!(r, RefreshResult::Incomplete);
                assert_eq!(exceeded.map(|e| e.used), Some(u - 9));
            }
        }
        let want: Vec<_> = seen.iter().map(|(a, _, e)| (*a, *e)).collect();
        let got: Vec<_> = seen.iter().map(|(a, d, _)| (*a, *d)).collect();
        assert_eq!(got, want);
    }

    /// `n` bytes that do not parse: core drops the file alone.
    fn unparsable(n: usize) -> Vec<u8> {
        let mut b = b"[style\n".to_vec();
        b.resize(n, b'x');
        b
    }

    /// `n` bytes of valid TOML (comment lines).
    fn comments(n: usize) -> Vec<u8> {
        let mut b = Vec::with_capacity(n);
        while b.len() < n {
            let line = n - b.len();
            b.push(b'#');
            b.extend(std::iter::repeat_n(b'c', line.min(64).saturating_sub(2)));
            if b.len() < n {
                b.push(b'\n');
            }
        }
        b.truncate(n);
        b
    }

    fn snapshot_and_sequence(f: &Fx) -> (Vec<Vec<u8>>, Vec<u8>) {
        (f.state(), f.bytes("sequence"))
    }

    const KIB256: usize = 256 * 1024;

    /// The config writing `refs` as its extends, `body` after it.
    fn extends_with(f: &Fx, refs: &[String], body: &str) {
        let list: Vec<String> = refs.iter().map(|r| format!("{r:?}")).collect();
        f.put(&format!("extends = [{}]\n{body}", list.join(", ")));
    }

    // 실제 U2 값에서: 신뢰 파일의 extends로 R을 넘기면 Invalid가 아니라 Incomplete이고, conf.d 항목이 마지막
    // 재검증에서야 넘는 경우에도 sequence를 옮기기 전에 끝나며, 버린 원본까지 센 B가 2 MiB를 넘으면 끝난다. 모두
    // snapshot·last-good·marker·sequence가 그대로다. 각 경우 cap에 딱 맞는 설정은 발행된다.
    // 이것을 실패시키는 것: 상한 초과를 확인한 실패(Invalid)로 내는 것, sequence staging 전 재검증 비용 확인을
    // 빼는 것(마지막 목록에서 넘어 sequence가 바뀜), B의 읽기 한도를 빼는 것 또는 버린 원본을 세지 않는 것,
    // cap 비교의 하나 차이, R을 extends마다 세지 않는 것.
    #[test]
    fn exceeded_axis_keeps_marker_unchanged() {
        let mut seen = Vec::new();
        // R: 2 root candidates (config.toml, absent config.local.toml) + n entries.
        for n in [254usize, 255] {
            let f = Fx::new(&format!("cap-r-{n}"));
            f.put(COMMAND);
            published(f.run());
            let before = snapshot_and_sequence(&f);
            let refs: Vec<String> = (0..n).map(|i| format!("$THEME_{i}")).collect();
            extends_with(&f, &refs, COMMAND);
            let r = f.run();
            seen.push(("R", n, r, snapshot_and_sequence(&f) == before));
        }
        // E_n: a.toml, k other entries, `.` and `..`, listed four times a round.
        // At k = 254 the first three listings fit (771) and the fourth would not.
        for k in [253usize, 254] {
            let f = Fx::new(&format!("cap-en-{k}"));
            f.put(COMMAND);
            published(f.run());
            let before = snapshot_and_sequence(&f);
            let names: Vec<String> = std::iter::once("a.toml".to_string())
                .chain((0..k).map(|i| format!("n{i:03}.txt")))
                .collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            conf_d(&f, &names);
            let r = f.run();
            seen.push(("E_n", k, r, snapshot_and_sequence(&f) == before));
        }
        // B: the config, seven dropped 256 KiB themes and one sized to reach 2 MiB.
        for extra in [0usize, 1] {
            let f = Fx::new(&format!("cap-b-{extra}"));
            f.put(COMMAND);
            published(f.run());
            let before = snapshot_and_sequence(&f);
            let dir = themes(&f);
            let refs: Vec<String> = (0..8)
                .map(|i| dir.join(format!("t{i}.toml")).display().to_string())
                .collect();
            extends_with(&f, &refs, COMMAND);
            let config = fs::metadata(f.request.config_canonical.join("config.toml"))
                .unwrap()
                .len() as usize;
            for (i, r) in refs.iter().enumerate() {
                let n = if i < 7 {
                    KIB256
                } else {
                    KIB256 - config + extra
                };
                put(Path::new(r), &unparsable(n));
            }
            let r = f.run();
            seen.push(("B", extra, r, snapshot_and_sequence(&f) == before));
        }
        let published_at_cap = |r: &RefreshResult| matches!(r, RefreshResult::Published { .. });
        let got: Vec<_> = seen
            .iter()
            .map(|(axis, n, r, same)| {
                (
                    *axis,
                    *n,
                    published_at_cap(r),
                    *r == RefreshResult::Incomplete,
                    *same,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("R", 254, true, false, false),
                ("R", 255, false, true, true),
                ("E_n", 253, true, false, false),
                ("E_n", 254, false, true, true),
                ("B", 0, true, false, false),
                ("B", 1, false, true, true),
            ]
        );
    }

    // 오늘 발행되는 설정 모양은 U2 값에서도 발행된다: 내장 설정만, 뿌리 순서(config.toml·conf.d·local), conf.d
    // 하드 링크 40개, 링크 20개 사슬의 config.toml, 링크로 고정한 설정 뿌리, 4,097개 참조를 가진 버려지는 shape-only 테마, conf.d의
    // 설정이 아닌 항목 200개, 깊이 8의 큰 shape-only 사슬, 해석 실패 256 KiB 넷 뒤 256 KiB 하나.
    // 이것을 실패시키는 것: 의미 상한 숫자를 I/O 상한에 대입하는 것(F 32는 하드 링크 40개, B 1 MiB는 1.25 MiB
    // 묶음에서 실패), D를 목록마다 세는 것, 축을 의도보다 넓게 세는 것, 보유한 증거(실행 원본, 설정 뿌리)의
    // 재확인에서 링크 읽기를 세지 않는 것.
    #[test]
    fn test_configs_published_today_still_publish() {
        let seen = std::cell::RefCell::new(Vec::new());
        let run = |tag: &str, setup: &dyn Fn(&Fx)| {
            let f = Fx::new(&format!("compat-{tag}"));
            setup(&f);
            let r = f.run();
            let (used, exceeded) = io_meter::last_session().unwrap();
            seen.borrow_mut().push((
                tag.to_string(),
                matches!(r, RefreshResult::Published { .. }),
                exceeded,
            ));
            used
        };
        run("builtin-only", &|_| {});
        run("roots-in-order", &|f| {
            f.put(COMMAND);
            conf_d(f, &["10.toml", "20.toml"]);
            put(
                &f.request.config_canonical.join("config.local.toml"),
                b"icons = \"ascii\"\n",
            );
        });
        let aliases = run("conf-d-hard-links", &|f| {
            f.put(COMMAND);
            let d = conf_d(f, &["000.toml"]);
            for i in 1..40 {
                fs::hard_link(d.join("000.toml"), d.join(format!("{i:03}.toml"))).unwrap();
            }
        });
        let links = run("link-chain", &|f| {
            let dots = f.base.join("dotfiles");
            fs::create_dir(&dots).unwrap();
            mode(&dots, 0o700);
            put(&dots.join("real.toml"), COMMAND.as_bytes());
            let mut target = dots.join("real.toml");
            for i in 0..19 {
                let link = dots.join(format!("l{i}.toml"));
                symlink(&target, &link).unwrap();
                target = link;
            }
            symlink(&target, f.request.config_canonical.join("config.toml")).unwrap();
        });
        // A stow-style config root: init pinned the link's spelling.
        let rooted = {
            let f = Fx::new("compat-root-link");
            let link = f.base.join("config-link");
            symlink(&f.request.config_canonical, &link).unwrap();
            let mut request = f.request.clone();
            request.config_written = link;
            f.put(COMMAND);
            let r = refresh(request, &mut Fixed(clock()));
            let (used, exceeded) = io_meter::last_session().unwrap();
            seen.borrow_mut().push((
                "root-link".into(),
                matches!(r, RefreshResult::Published { .. }),
                exceeded,
            ));
            used
        };
        run("discarded-theme-fanout", &|f| {
            let refs: Vec<String> = (0..4097)
                .map(|i| {
                    let name = format!("theme-{i}.toml");
                    put(&f.base.join(&name), b"");
                    format!("{name:?}")
                })
                .collect();
            put(
                &f.base.join("theme.toml"),
                format!("extends = [{}]\n", refs.join(",")).as_bytes(),
            );
            f.put("extends = [\"~/theme.toml\"]\n");
            put(
                &f.request.config_canonical.join("config.local.toml"),
                COMMAND.as_bytes(),
            );
        });
        run("conf-d-non-config-200", &|f| {
            f.put(COMMAND);
            let names: Vec<String> = std::iter::once("a.toml".to_string())
                .chain((0..199).map(|i| format!(".n{i:03}")))
                .collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            conf_d(f, &names);
        });
        let chain = run("shape-only-chain-8", &|f| {
            let dir = themes(f);
            for i in 0..7 {
                let mut b = format!("extends = [\"c{}.toml\"]\n", i + 1).into_bytes();
                b.extend(comments(120 * 1024));
                put(&dir.join(format!("c{i}.toml")), &b);
            }
            put(&dir.join("c7.toml"), &comments(120 * 1024));
            f.put(&format!(
                "extends = [{:?}]\n{COMMAND}",
                dir.join("c0.toml").display().to_string()
            ));
        });
        let bytes = run("dropped-four-then-one", &|f| {
            let dir = themes(f);
            let refs: Vec<String> = (0..5)
                .map(|i| dir.join(format!("t{i}.toml")).display().to_string())
                .collect();
            for (i, r) in refs.iter().enumerate() {
                put(
                    Path::new(r),
                    &if i < 4 {
                        unparsable(KIB256)
                    } else {
                        comments(KIB256)
                    },
                );
            }
            extends_with(f, &refs, COMMAND);
        });
        let seen = seen.into_inner();
        assert!(
            seen.iter()
                .all(|(_, published, exceeded)| *published && exceeded.is_none()),
            "{seen:?}"
        );
        // The shapes that bind on the semantic numbers this meter must not reuse.
        assert!(at(&aliases, HelperAxis::F) > 32, "{aliases:?}");
        assert!(at(&bytes, HelperAxis::B) > 1024 * 1024, "{bytes:?}");
        // Twenty links behind config.toml, each read in five walks (probe, open
        // before reading, three revalidations) and four checks of the retained
        // evidence (after reading, three revalidations).
        assert_eq!(at(&links, HelperAxis::L), 20 * 9);
        // The root's own link: read by the reopen walk and its recheck, then in
        // each of the three revalidations.
        assert_eq!(at(&rooted, HelperAxis::L), 5);
        assert!(at(&chain, HelperAxis::B) > 7 * 120 * 1024);
        for (used, what) in [
            (aliases, "aliases"),
            (links, "links"),
            (rooted, "root link"),
            (chain, "chain"),
            (bytes, "bytes"),
        ] {
            for axis in HelperAxis::ALL {
                assert!(
                    at(&used, axis) <= AXIS_CAPS.cap(axis),
                    "{what} {axis:?} {used:?}"
                );
            }
        }
    }

    // 사용자 결정 자료의 "오늘 받아들여지는 설정을 거부하는 경우" 표에서 만들기 싼 행: 기준 revision 1d900e4에서는
    // 모두 발행됐고(신뢰 conf.d 300개는 Invalid), 이제는 Incomplete이며 snapshot·last-good·marker·sequence가
    // 그대로다. 넘는 축도 고정한다.
    // 이것을 실패시키는 것: 상한을 넘은 회차를 발행하거나 Invalid로 확인하는 것, 버린 테마 그래프의 시도를 R에서
    // 빼는 것, 재검증 목록을 세지 않는 것, 버린 원본 바이트를 B에서 빼는 것.
    #[test]
    fn todays_rejected_shapes_are_incomplete_with_marker_unchanged() {
        type Shape = fn(&Fx);
        let shapes: [(&str, bool, Shape, HelperAxis); 5] = [
            (
                "shape-only root, conf.d of 300 configs",
                true,
                |f| {
                    let names: Vec<String> = (0..300).map(|i| format!("{i:03}.toml")).collect();
                    let names: Vec<&str> = names.iter().map(String::as_str).collect();
                    conf_d(f, &names);
                },
                HelperAxis::R,
            ),
            (
                "trusted conf.d of 300 configs",
                false,
                |f| {
                    let names: Vec<String> = (0..300).map(|i| format!("{i:03}.toml")).collect();
                    let names: Vec<&str> = names.iter().map(String::as_str).collect();
                    conf_d(f, &names);
                },
                HelperAxis::R,
            ),
            (
                "conf.d with 600 hidden entries",
                false,
                |f| {
                    let names: Vec<String> = std::iter::once("a.toml".to_string())
                        .chain((0..600).map(|i| format!(".n{i:03}")))
                        .collect();
                    let names: Vec<&str> = names.iter().map(String::as_str).collect();
                    conf_d(f, &names);
                },
                HelperAxis::En,
            ),
            (
                "nine theme graphs of 30 tries that fail",
                false,
                |f| {
                    let dir = themes(f);
                    let refs: Vec<String> = (0..9)
                        .map(|i| {
                            let kids: Vec<String> = (0..29)
                                .map(|k| {
                                    let c = dir.join(format!("g{i}-{k}.toml"));
                                    put(&c, if k == 28 { b"[broken\n" } else { b"" });
                                    format!("{:?}", c.display().to_string())
                                })
                                .collect();
                            let p = dir.join(format!("g{i}.toml"));
                            put(&p, format!("extends = [{}]\n", kids.join(",")).as_bytes());
                            p.display().to_string()
                        })
                        .collect();
                    extends_with(f, &refs, COMMAND);
                },
                HelperAxis::R,
            ),
            (
                "eight 256 KiB themes that do not parse",
                false,
                |f| {
                    let dir = themes(f);
                    let refs: Vec<String> = (0..8)
                        .map(|i| dir.join(format!("t{i}.toml")).display().to_string())
                        .collect();
                    for r in &refs {
                        put(Path::new(r), &unparsable(KIB256));
                    }
                    extends_with(f, &refs, COMMAND);
                },
                HelperAxis::B,
            ),
        ];
        let mut seen = Vec::new();
        for (i, (what, shape_root, shape, _)) in shapes.iter().enumerate() {
            let mut f = Fx::new(&format!("rejected-{i}"));
            f.request.config_root_shape_only = *shape_root;
            f.put(if *shape_root {
                "icons = \"ascii\"\n"
            } else {
                COMMAND
            });
            published(f.run());
            let before = snapshot_and_sequence(&f);
            shape(&f);
            let r = f.run();
            let (_, exceeded) = io_meter::last_session().unwrap();
            seen.push((
                *what,
                r,
                exceeded.map(|e| e.axis),
                snapshot_and_sequence(&f) == before,
            ));
        }
        let want: Vec<_> = shapes
            .iter()
            .map(|(what, _, _, axis)| (*what, RefreshResult::Incomplete, Some(*axis), true))
            .collect();
        assert_eq!(seen, want);
    }

    // 사전 점검을 지난 뒤 설정 트리가 바뀌어 마지막 재검증에서야 상한을 넘는 회차는, 그 시점에 변경을 감지한
    // 회차와 같은 기존 경로로 끝난다: Incomplete, snapshot·last-good·marker는 그대로, sequence는 이미 설치한 예약
    // 그대로 남는다(원래 동작). 같은 변경을 상한 없이 하면 다시 확인되므로, 거기서 끝낸 것은 상한이다.
    // 이것을 실패시키는 것: 마지막 재검증의 실패를 무시하고 표식을 쓰는 것, 마지막 재검증을 세지 않는 것,
    // 상한 초과에 새 결과 상태를 만드는 것.
    #[test]
    fn a_cap_crossed_only_at_the_last_revalidation_ends_like_a_late_change() {
        let mut seen = Vec::new();
        for (case, caps) in [
            ("crossing", AXIS_CAPS),
            ("unlimited", UNLIMITED),
            ("late-change", UNLIMITED),
        ] {
            let f = Fx::new(&format!("late-{case}"));
            f.put(COMMAND);
            // a.toml, 253 others, `.` and `..`: four listings are exactly 1,024.
            let names: Vec<String> = std::iter::once("a.toml".to_string())
                .chain((0..253).map(|i| format!("n{i:03}.txt")))
                .collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let d = conf_d(&f, &names);
            published(f.run());
            let (state, sequence) = snapshot_and_sequence(&f);
            let _caps = TestCaps::set(caps);
            let r = f.hook(&mut |p| {
                if p == Checkpoint::Staged {
                    if case == "late-change" {
                        put(&d.join("b.toml"), b"");
                    } else {
                        // Hidden entries: the config names stay the same.
                        for i in 0..10 {
                            put(&d.join(format!(".late{i}")), b"");
                        }
                    }
                }
            });
            let (_, exceeded) = io_meter::last_session().unwrap();
            let (state_now, sequence_now) = snapshot_and_sequence(&f);
            seen.push((
                case,
                r,
                exceeded.map(|e| e.axis),
                state_now == state,
                sequence_now == sequence,
            ));
        }
        assert_eq!(
            seen,
            [
                (
                    "crossing",
                    RefreshResult::Incomplete,
                    Some(HelperAxis::En),
                    true,
                    false
                ),
                (
                    "unlimited",
                    RefreshResult::Revalidated { generation: 1 },
                    None,
                    false,
                    false
                ),
                ("late-change", RefreshResult::Incomplete, None, true, false),
            ]
        );
    }

    // 설정 뿌리 다시 열기(없는 접미 이름마다 걷기를 한 번 더 함)도 회차 계수기가 센다. 링크를 거쳐 쓴 뿌리
    // 아래에 없는 이름이 여섯 개면 다시 열기가 일곱 번 걷고, P 상한을 그 합 − 1로 낮추면 다시 열기만으로 넘는다.
    // 그때 링크 읽기(L)는 다시 열기의 걷기 일곱 번만큼이고(Loader는 정규 경로만 걸어 링크를 읽지 않음), R은 0,
    // store는 그대로다.
    // 이것을 실패시키는 것: 다시 열기를 계수기 밖에서 하는 것, 접미 이름마다 하는 재걷기나 끝의 재확인을 세지
    // 않는 것, 다시 열기의 계수기를 Loader가 이어받지 않는 것.
    #[test]
    fn the_config_root_reopen_alone_can_cross_p() {
        let mut f = Fx::new("reopen-p");
        let link = f.base.join("config-link");
        symlink(f.base.join("config"), &link).unwrap();
        let tail = |p: PathBuf| (1..=6).fold(p, |p, i| p.join(format!("m{i}")));
        f.request.config_written = tail(link);
        f.request.config_canonical = tail(f.base.join("config"));
        let (r, used, exceeded) = metered(&f, UNLIMITED);
        published(r);
        assert_eq!(exceeded, None);
        let before = snapshot_and_sequence(&f);
        // Each walk descends to the link's folder, reads the link and walks its
        // absolute target from "/" again. Reopen walks seven times (six
        // missing suffixes, then the root) and rechecks once.
        let one_walk = depth(&f.base) + depth(&f.base.join("config"));
        let reopen = 7 * one_walk;
        assert!(at(&used, HelperAxis::P) > reopen, "{used:?}");
        let (r, used, exceeded) = metered(&f, with_cap(HelperAxis::P, reopen - 1));
        assert_eq!(r, RefreshResult::Incomplete);
        assert_eq!(exceeded.map(|e| e.axis), Some(HelperAxis::P));
        assert_eq!(
            [HelperAxis::L, HelperAxis::R].map(|a| at(&used, a)),
            [7, 0],
            "{used:?}"
        );
        assert_eq!(snapshot_and_sequence(&f), before);
        // The recheck after the seventh walk reads the link an eighth time.
        let (r, used, exceeded) = metered(&f, with_cap(HelperAxis::L, 7));
        assert_eq!(r, RefreshResult::Incomplete);
        assert_eq!(exceeded.map(|e| e.axis), Some(HelperAxis::L));
        assert_eq!(at(&used, HelperAxis::R), 0, "{used:?}");
        assert_eq!(snapshot_and_sequence(&f), before);
    }
}
