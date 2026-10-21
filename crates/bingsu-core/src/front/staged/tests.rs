#[cfg(test)]
mod cases {
    use super::super::*;
    use crate::snapshot::{HEADER, Identity, PREFIX, Snapshot, T_NS};
    use alloc::format;
    use alloc::string::String;

    fn args() -> Vec<&'static [u8]> {
        vec![
            b"--ctx",
            b"1",
            b"--record",
            b"B1",
            b"--width",
            b"80",
            b"--shell",
            b"zsh",
            b"--runtime-root=1:9:/r",
            b"--config-root=/c",
            b"--state-root=/s",
            b"--pwd",
            b"/x/project",
        ]
    }
    fn clock() -> Clock {
        Clock {
            boot: [1; 16],
            kind: 1,
            resume: 0,
            domain: [2; 16],
            now: 101,
        }
    }

    // 이것을 실패시키는 것: collections-v1 open 실패로 순회를 멈춰도 cwd 해시를 계산하는 것.
    #[test]
    fn collection_address_is_computed_only_after_advancing_past_the_root() {
        let hashes = core::cell::Cell::new(0);
        let address = || {
            hashes.set(hashes.get() + 1);
            String::from("cwd-address")
        };
        {
            let mut components = collection_components_with_address(address);
            assert_eq!(hashes.get(), 0);
            assert_eq!(components.next().as_deref(), Some("collections-v1"));
            assert_eq!(hashes.get(), 0);
            // The adapter returns here on ENOENT, dropping the iterator.
        }
        assert_eq!(hashes.get(), 0);
        let mut components = collection_components_with_address(address);
        assert_eq!(components.next().as_deref(), Some("collections-v1"));
        assert_eq!(components.next().as_deref(), Some("cwd-address"));
        assert_eq!(hashes.get(), 1);
        assert_eq!(components.next().as_deref(), Some("store"));
        assert_eq!(components.next(), None);
        assert_eq!(hashes.get(), 1);
    }

    // 이것을 실패시키는 것: finish의 정상·오류·빈 출력에서 진입 마감을 잃거나 다시 잡는 것.
    #[test]
    fn response_preserves_entry_deadline_on_every_record_path() {
        let deadline = Deadline::from_entry(100, 50).unwrap();
        for argv in [
            args(),
            vec![b"--ctx".as_slice(), b"2", b"--record", b"B1"],
            Vec::new(),
        ] {
            let ordinary = finish(prepare(&argv), Observed::default());
            let timed = finish(prepare(&argv).with_deadline(deadline), Observed::default());
            assert_eq!(timed.deadline, Some(deadline));
            assert_eq!(timed.record, ordinary.record);
            assert_eq!(timed.status, ordinary.status);
            assert_eq!(timed.execution.permit(), ordinary.execution.permit());
        }
    }
    fn snapshot(text: &str) -> Snapshot {
        Snapshot {
            id: Identity {
                boot: clock().boot,
                context: snapshot::context_crc(b"/c", b"/s").unwrap(),
                epoch: [3; 16],
                generation: 7,
                source: [4; 4],
            },
            config: crate::config::report::tests::read(text, &[])
                .snapshot
                .unwrap(),
            metadata: snapshot::encode_metadata(b"metadata must never be read").unwrap(),
        }
    }
    fn marker(s: &Snapshot) -> Marker {
        Marker {
            id: s.id,
            seq: 9,
            verified_at: 100,
            kind: 1,
            domain: clock().domain,
            resume: 0,
            invalid: false,
        }
    }
    fn facts(dir: bool, root: bool, size: usize) -> FdFacts {
        FdFacts {
            entry: Facts {
                dev: 1,
                ino: 9,
                uid: if root { 0 } else { 501 },
                gid: 20,
                mode: if root {
                    0o040755
                } else if dir {
                    0o040700
                } else {
                    0o100600
                },
                acl: fs_trust::AclFacts::None,
                ownership: Some(true),
            },
            local: Some(true),
            nlink: 1,
            size: size as u64,
        }
    }
    struct Harness {
        current: Option<Vec<u8>>,
        last: Option<Vec<u8>>,
        marker: Option<Vec<u8>>,
        clock: Option<Clock>,
        final_clock: Option<Clock>,
        current_name: &'static [u8],
        offset: usize,
        dirs: [Option<Vec<u8>>; 2],
        live_file: bool,
        calls: Vec<Operation>,
        reads: Vec<(&'static [u8], usize, usize)>,
        directory_change: Option<(Vec<u8>, FdFacts)>,
        file_change: Option<(&'static [u8], FdFacts)>,
        clocks: usize,
        short: usize,
        fail_at: Option<usize>,
    }
    impl Harness {
        fn new() -> Self {
            let s = snapshot("");
            Self {
                current: Some(s.encode(1, 0).unwrap()),
                last: None,
                marker: Some(marker(&s).encode().to_vec()),
                clock: Some(clock()),
                final_clock: Some(clock()),
                current_name: b"",
                offset: 0,
                dirs: [None, None],
                live_file: false,
                calls: Vec::new(),
                reads: Vec::new(),
                directory_change: None,
                file_change: None,
                clocks: 0,
                short: usize::MAX,
                fail_at: None,
            }
        }
        fn bytes(&self) -> Option<&[u8]> {
            match self.current_name {
                b"snapshot" => self.current.as_deref(),
                b"last-good" => self.last.as_deref(),
                b"marker" => self.marker.as_deref(),
                _ => None,
            }
        }
        fn observe(&mut self, effect: Effect) -> Observation {
            let fail = self.fail_at == Some(self.calls.len());
            if fail && !matches!(effect.operation(), Operation::Close(_)) {
                self.calls.push(effect.operation);
                return Observation::Failed;
            }
            let result = match effect.operation() {
                Operation::Uid => Observation::Uid(501),
                Operation::Clock => {
                    self.clocks += 1;
                    Observation::Clock(if self.clocks == 1 {
                        self.clock
                    } else {
                        self.final_clock
                    })
                }
                Operation::OpenDirectory { parent, name, into } => {
                    if let Some(parent) = parent {
                        assert!(self.dirs[parent.index()].is_some());
                    }
                    assert!(self.dirs[into.index()].is_none());
                    assert!(name == b"/" || !name.contains(&b'/'));
                    self.dirs[into.index()] = Some(name.clone());
                    Observation::Opened
                }
                Operation::Inspect(Slot::File) => {
                    assert!(self.live_file);
                    Observation::Facts(
                        self.file_change
                            .filter(|(name, _)| *name == self.current_name)
                            .map_or_else(
                                || facts(false, false, self.bytes().unwrap().len()),
                                |(_, f)| f,
                            ),
                    )
                }
                Operation::Inspect(slot) => {
                    let name = self.dirs[slot.index()].as_ref().unwrap();
                    Observation::Facts(
                        self.directory_change
                            .as_ref()
                            .filter(|(n, _)| n == name)
                            .map_or_else(|| facts(true, name == b"/", 0), |(_, f)| *f),
                    )
                }
                Operation::OpenCollection(_) => Observation::Failed,
                Operation::OpenFile { parent, name, into } => {
                    assert_eq!(*into, Slot::File);
                    assert_eq!(
                        self.dirs[parent.index()].as_deref(),
                        Some(b"store".as_slice())
                    );
                    assert!(!self.live_file);
                    self.current_name = name;
                    self.offset = 0;
                    if self.bytes().is_some() {
                        self.live_file = true;
                        Observation::Opened
                    } else {
                        Observation::Failed
                    }
                }
                Operation::Read { slot, len } => {
                    assert_eq!(*slot, Slot::File);
                    assert!(self.live_file);
                    let b = self.bytes().unwrap();
                    let end = self
                        .offset
                        .saturating_add((*len).min(self.short))
                        .min(b.len());
                    let bytes = b[self.offset..end].to_vec();
                    self.reads.push((self.current_name, self.offset, *len));
                    self.offset = end;
                    Observation::Bytes(bytes)
                }
                Operation::Close(slot) => {
                    if *slot == Slot::File {
                        assert!(self.live_file);
                        self.live_file = false;
                    } else {
                        assert!(self.dirs[slot.index()].take().is_some());
                    }
                    Observation::Closed
                }
            };
            self.calls.push(effect.operation);
            if fail { Observation::Failed } else { result }
        }
        fn run(&mut self, args: &[&[u8]], mode: Mode) -> Response {
            self.run_catalog(args, mode, None)
        }
        fn run_catalog(
            &mut self,
            args: &[&[u8]],
            mode: Mode,
            fixture: Option<&crate::collection::selection::Catalog<'_>>,
        ) -> Response {
            let mut args = args.to_vec();
            args.extend([
                b"--colorfgbg".as_slice(),
                if mode == Mode::Light {
                    b"0;15"
                } else {
                    b"15;0"
                },
            ]);
            let mut plan = prepare(&args);
            let mut previous = None;
            for _ in 0..100_000 {
                match next(&mut plan, previous.take()) {
                    Step::Read(e) => previous = Some(self.observe(e)),
                    Step::Done(mut o) => {
                        assert!(self.dirs.iter().all(Option::is_none) && !self.live_file);
                        if let Some(catalog) = fixture {
                            if let Some(s) = o.selected.as_mut() {
                                // Catalog injection follows the same verified read plan.
                                s.config.bands.clear();
                                s.config.band_order.clear();
                                s.config.collect_mask = 1 << 31;
                                s.config.variants = vec![
                                    crate::template::compile::compile(
                                        "{fixture}",
                                        catalog.segments,
                                    )
                                    .unwrap(),
                                ];
                            }
                            return finish_with_catalog(plan, o, catalog);
                        }
                        return finish(plan, o);
                    }
                }
            }
            panic!("continuation failed to terminate")
        }
    }
    fn record(r: &Response) -> String {
        String::from_utf8(r.record.clone()).unwrap()
    }

    // 이것을 실패시키는 것: 앞 구획 길이 승인 전 본문 읽기, metadata 읽기, 다른 문맥/원본 열기, fd 누수.
    #[test]
    fn stages_only_read_the_selected_front_and_marker() {
        for short in [usize::MAX, 1, 17] {
            let mut h = Harness::new();
            h.short = short;
            let r = h.run(&args(), Mode::Dark);
            assert_eq!(r.status, Status::OK_NONE);
            assert!(r.execution.permit().is_some());
            assert!(!record(&r).contains('!'));
            let (c, _) = snapshot::lengths(h.current.as_ref().unwrap()).unwrap();
            assert!(h.reads.iter().all(|(name, off, len)| match *name {
                b"snapshot" => *off + *len <= HEADER + PREFIX + c,
                b"marker" => *off + *len <= snapshot::MARKER,
                _ => false,
            }));
            assert_eq!(h.reads[0], (b"snapshot".as_slice(), 0, HEADER));
            if short == usize::MAX {
                assert_eq!(h.reads[1], (b"snapshot".as_slice(), HEADER, PREFIX));
            }
        }
    }
    // 이것을 실패시키는 것: 머리·접두부의 길이·ABI 또는 fd 크기 불일치 뒤 본문 읽기를 허용하는 것.
    #[test]
    fn malformed_headers_and_sizes_stop_before_body() {
        for at in [0, 8, 12, 28, 60, 64, 72, 76, 80, 84, 124, 164] {
            let mut h = Harness::new();
            h.current.as_mut().unwrap()[at] ^= 0x80;
            let r = h.run(&args(), Mode::Dark);
            assert_eq!(r.status, Status::ERROR_CONFIG_DEFAULT, "{at}");
            assert!(
                h.reads
                    .iter()
                    .filter(|(name, _, _)| *name == b"snapshot")
                    .all(|(_, off, len)| *off + *len
                        <= if at < HEADER && at != 60 {
                            HEADER
                        } else {
                            HEADER + PREFIX
                        }),
                "{at}"
            );
        }
        for size in [
            0,
            191,
            usize::MAX,
            Harness::new().current.unwrap().len() + 1,
        ] {
            let mut h = Harness::new();
            h.file_change = Some((b"snapshot", facts(false, false, size)));
            assert_eq!(
                h.run(&args(), Mode::Dark).status,
                Status::ERROR_CONFIG_DEFAULT
            );
            assert!(
                h.reads
                    .iter()
                    .filter(|(name, _, _)| *name == b"snapshot")
                    .all(|(_, off, len)| *off + *len <= HEADER + PREFIX)
            );
        }
    }
    // 이것을 실패시키는 것: fallback이면 무조건 실행 거부, 현재 머리의 자격 재사용, Invalid의 세대 무관 철회.
    #[test]
    fn last_good_uses_its_own_pair_and_keeps_notice() {
        let mut h = Harness::new();
        let mut old = snapshot("icons='ascii'");
        old.id.generation = 6;
        h.last = Some(old.encode(1, 0).unwrap());
        h.current.as_mut().unwrap()[192] ^= 1;
        h.marker = Some(marker(&old).encode().to_vec());
        let r = h.run(&args(), Mode::Dark);
        assert_eq!(r.status, Status::ERROR_CONFIG_LAST_GOOD);
        assert!(r.execution.permit().is_some());
        assert!(record(&r).contains('!'));
        h.marker = Some(marker(&snapshot("")).encode().to_vec());
        assert!(h.run(&args(), Mode::Dark).execution.permit().is_none());
        let mut m = marker(&old);
        m.invalid = true;
        m.id.generation = 123;
        h.marker = Some(m.encode().to_vec());
        assert!(h.run(&args(), Mode::Dark).execution.permit().is_none());
        old.id.boot = [9; 16];
        h.last = Some(old.encode(1, 0).unwrap());
        assert_eq!(
            h.run(&args(), Mode::Dark).status,
            Status::ERROR_CONFIG_DEFAULT
        );
    }
    // 이것을 실패시키는 것: 표식 오류/각 정체/시각 오류를 fresh로 렌더하거나 상태 우선순위를 바꾸는 것.
    #[test]
    fn status_priority_and_trust_rejections() {
        for case in 0..15 {
            let mut h = Harness::new();
            let s = snapshot("");
            let mut m = marker(&s);
            let want = match case {
                0 => {
                    h.marker = None;
                    Status::DEGRADED_TRUST_UNVERIFIED
                }
                1 => {
                    h.marker.as_mut().unwrap()[0] ^= 1;
                    Status::DEGRADED_TRUST_UNVERIFIED
                }
                2 => {
                    m.invalid = true;
                    m.id.generation = 0;
                    h.marker = Some(m.encode().to_vec());
                    Status::DEGRADED_TRUST_INVALID
                }
                3 => {
                    m.id.generation += 1;
                    h.marker = Some(m.encode().to_vec());
                    Status::DEGRADED_TRUST_MISMATCH
                }
                4 => {
                    m.domain = [9; 16];
                    h.marker = Some(m.encode().to_vec());
                    Status::DEGRADED_TRUST_CLOCK
                }
                5 => {
                    m.resume = 1;
                    h.marker = Some(m.encode().to_vec());
                    Status::DEGRADED_TRUST_CLOCK
                }
                6 => {
                    m.verified_at = 102;
                    h.marker = Some(m.encode().to_vec());
                    Status::DEGRADED_TRUST_CLOCK
                }
                7 => {
                    h.final_clock.as_mut().unwrap().now = 100 + T_NS;
                    Status::DEGRADED_TRUST_EXPIRED
                }
                8 => {
                    h.final_clock = None;
                    Status::DEGRADED_TRUST_CLOCK
                }
                9 => {
                    h.final_clock.as_mut().unwrap().now = 100;
                    Status::DEGRADED_TRUST_CLOCK
                }
                10 => {
                    h.current = Some(s.encode(2, 0).unwrap());
                    Status::DEGRADED_TRUST_CLOCK
                }
                11 => {
                    h.current = Some(s.encode(1, 1).unwrap());
                    Status::DEGRADED_TRUST_CLOCK
                }
                12 => {
                    h.clock.as_mut().unwrap().domain = [9; 16];
                    Status::DEGRADED_TRUST_CLOCK
                }
                13 => {
                    h.clock.as_mut().unwrap().resume = 1;
                    Status::DEGRADED_TRUST_CLOCK
                }
                _ => {
                    h.clock.as_mut().unwrap().kind = 2;
                    Status::DEGRADED_TRUST_CLOCK
                }
            };
            let r = h.run(&args(), Mode::Dark);
            assert_eq!(r.status, want, "case {case}");
            assert!(r.execution.permit().is_none(), "case {case}");
            assert!(record(&r).contains('!'));
            // Product collection remains empty independently of execution eligibility.
            assert_eq!(r.worker_mask, 0);
        }
    }
    // 이것을 실패시키는 것: 부팅/현재 셸 문맥을 선택에서 빼거나 외부 문맥의 일치하는 짝을 허용하는 것.
    #[test]
    fn boot_and_context_are_required_even_for_a_matching_pair() {
        for case in 0..5 {
            let mut h = Harness::new();
            let mut s = snapshot("");
            match case {
                0 => h.clock = None,
                1 => s.id.boot = [7; 16],
                2 => s.id.context = snapshot::context_crc(b"/c", b"/other-state").unwrap(),
                3 => s.id.context = snapshot::context_crc(b"/other-config", b"/s").unwrap(),
                _ => h.final_clock.as_mut().unwrap().boot = [9; 16],
            }
            h.current = Some(s.encode(1, 0).unwrap());
            h.last = h.current.clone();
            h.marker = Some(marker(&s).encode().to_vec());
            let r = h.run(&args(), Mode::Dark);
            assert_eq!(r.status, Status::ERROR_CONFIG_DEFAULT);
            assert!(r.execution.permit().is_none());
            assert!(record(&r).contains('!'));
        }
    }
    // 이것을 실패시키는 것: 열린 fd의 owner/mode/regular/nlink/ACL/local/ownership 검사를 생략하고 read하는 것.
    #[test]
    fn file_facts_gate_every_read() {
        for name in [b"snapshot".as_slice(), b"marker"] {
            for case in 0..9 {
                let mut h = Harness::new();
                let mut f = facts(
                    false,
                    false,
                    if name == b"snapshot" {
                        h.current.as_ref().unwrap().len()
                    } else {
                        snapshot::MARKER
                    },
                );
                match case {
                    0 => f.entry.uid = 0,
                    1 => f.entry.mode = 0o100644,
                    2 => f.entry.mode = 0o010600,
                    3 => f.nlink = 2,
                    4 => f.entry.acl = fs_trust::AclFacts::Unknown,
                    5 => f.entry.acl = fs_trust::AclFacts::AllowsWrite,
                    6 => f.entry.ownership = None,
                    7 => f.local = None,
                    _ => f.entry.ownership = Some(false),
                }
                h.file_change = Some((name, f));
                assert!(h.run(&args(), Mode::Dark).execution.permit().is_none());
                assert!(
                    h.reads.iter().all(|(n, _, _)| *n != name),
                    "{name:?} case {case}"
                );
            }
        }
    }
    // 이것을 실패시키는 것: 마지막 0700 검사를 /에 적용, runtime pin/조상 거부 후 하위 open, sticky 의무 유실.
    #[test]
    fn directory_checks_stop_the_walk_and_preserve_sticky_owner() {
        for (name, mut f) in [
            (b"/".to_vec(), facts(true, true, 0)),
            (b"r".to_vec(), facts(true, false, 0)),
            (b"contexts-v2".to_vec(), facts(true, false, 0)),
        ] {
            f.entry.mode |= 2;
            let mut h = Harness::new();
            h.directory_change = Some((name.clone(), f));
            let r = h.run(&args(), Mode::Dark);
            assert_eq!(r.status, Status::DEGRADED_RUNTIME_ROOT);
            assert!(
                !h.calls
                    .iter()
                    .any(|o| matches!(o, Operation::OpenFile { .. }))
            );
            assert_eq!(
                h.calls
                    .iter()
                    .filter_map(|o| match o {
                        Operation::OpenDirectory { name, .. } => Some(name),
                        _ => None,
                    })
                    .next_back(),
                Some(&name)
            );
        }
        let mut h = Harness::new();
        let mut f = facts(true, false, 0);
        f.entry.ino = 10;
        h.directory_change = Some((b"r".to_vec(), f));
        assert_eq!(
            h.run(&args(), Mode::Dark).status,
            Status::DEGRADED_RUNTIME_ROOT
        );
        let mut h = Harness::new();
        let mut f = facts(true, true, 0);
        f.entry.mode = 0o041777;
        h.directory_change = Some((b"/".to_vec(), f));
        assert_eq!(h.run(&args(), Mode::Dark).status, Status::OK_NONE);
        // Pure staged R oracle checks retain Mine across an observation boundary.
        let next = fs_trust::ancestor_verdict(
            &f.entry,
            501,
            0,
            NextOwner::Any,
            &mut PinnedGroupWrite(&[]),
        )
        .unwrap();
        // 이것을 실패시키는 것: sticky 조상의 NextOwner::Mine을 Any로 초기화하는 것.
        assert_eq!(next, NextOwner::Mine { parent: 0 });
        let mut child = facts(true, false, 0);
        child.entry.uid = 0;
        assert!(
            fs_trust::final_verdict(
                &child.entry,
                501,
                1,
                next,
                Last::PrivateFolder,
                Some(true),
                &mut PinnedGroupWrite(&[])
            )
            .is_err()
        );
    }
    // 이것을 실패시키는 것: bad-args나 구 hook에 읽기 요청, 미완료 상태를 성공으로 finish, 무한 재시도.
    #[test]
    fn bad_envelopes_and_incomplete_continuations_fail_closed() {
        for a in [vec![b"--ctx".as_slice(), b"2", b"--record", b"B1"], vec![]] {
            let mut h = Harness::new();
            let r = h.run(&a, Mode::Dark);
            assert!(h.calls.is_empty());
            assert!(r.execution.permit().is_none());
        }
        let r = finish(prepare(&args()), Observed::default());
        assert_eq!(r.status, Status::DEGRADED_RUNTIME_ROOT);
        let mut p = prepare(&args());
        assert!(matches!(next(&mut p, None), Step::Read(_)));
        assert!(matches!(next(&mut p, None), Step::Done(_)));
    }
    // Explicit config modes win over either COLORFGBG observation; auto uses it.
    // 이것을 실패시키는 것: 봉투 모드를 Dark로 고정하거나 명시 모드를 auto처럼 컴파일하는 것.
    #[test]
    fn colorfgbg_selects_auto_and_config_mode_wins() {
        let mut records = Vec::new();
        for configured in ["auto", "dark", "light"] {
            let s = snapshot(&format!("[colors]\nmode='{configured}'\n"));
            let mut h = Harness::new();
            h.current = Some(s.encode(1, 0).unwrap());
            h.marker = Some(marker(&s).encode().to_vec());
            let dark = h.run(&args(), Mode::Dark);
            let light = h.run(&args(), Mode::Light);
            assert_eq!(dark.status, Status::OK_NONE);
            assert_eq!(light.status, Status::OK_NONE);
            records.push((dark.record, light.record));
        }
        assert_ne!(records[0].0, records[0].1);
        assert_eq!(records[1].0, records[1].1);
        assert_eq!(records[2].0, records[2].1);
        assert_eq!(records[0].0, records[1].0);
        assert_eq!(records[0].1, records[2].0);
    }

    // 이것을 실패시키는 것: snapshot의 not_run/승인 정책 대신 임의 unit 허용, compiled render 옵션·팔레트 무시.
    #[test]
    fn compiled_screen_and_only_allowed_units_survive() {
        let s = snapshot(
            "icons='ascii'\n[colors]\nmode='auto'\n[segment.duration]\nmin='1ms'\n[segment.\"custom/yes\"]\nkind='command'\ncommand=['echo','yes']\n[segment.\"custom/no\"]\nkind='command'\ncommand=['echo','no']\nenabled=false\n[layout.line2]\nleft=['custom/yes','custom/no','duration','char']",
        );
        let mut h = Harness::new();
        h.current = Some(s.encode(1, 0).unwrap());
        h.marker = Some(marker(&s).encode().to_vec());
        let mut a = args();
        a.extend([
            b"--duration-ms".as_slice(),
            b"1",
            b"--colorterm",
            b"truecolor",
        ]);
        let dark = h.run(&a, Mode::Dark);
        let light = h.run(&a, Mode::Light);
        assert_eq!(dark.status, Status::OK_NONE);
        assert_eq!(
            dark.execution
                .units()
                .iter()
                .map(|u| u.id.as_str())
                .collect::<Vec<_>>(),
            ["custom/yes"]
        );
        assert!(record(&dark).contains("1ms"));
        assert_ne!(dark.record, light.record);
        assert!(!record(&dark).contains('\u{276f}'));
    }
    // 이것을 실패시키는 것: Invalid·만료 표식이 안전한 화면의 fixture 수집까지 0으로 만드는 것.
    #[test]
    fn n7_builtin_collection_survives_invalid_marker() {
        let mut h = Harness::new();
        let ordinary = h.run(&args(), Mode::Dark);
        assert_eq!(ordinary.worker_mask, 0);
        let mut m = marker(&snapshot(""));
        m.invalid = true;
        h.marker = Some(m.encode().to_vec());
        let invalid = h.run(&args(), Mode::Dark);
        assert_eq!(invalid.worker_mask, ordinary.worker_mask);
        assert!(invalid.execution.permit().is_none());
        let ids = [
            "a00", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10", "a11",
            "a12", "a13", "a14", "a15", "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23",
            "a24", "a25", "a26", "a27", "a28", "a29", "a30", "fixture",
        ];
        let segments = ids.map(|id| crate::field::SegmentDecl {
            id,
            role: "fg",
            fields: &[],
        });
        let catalog = crate::collection::selection::Catalog {
            segments: &segments,
            workers: 1 << 31,
        };
        for invalid in [false, true] {
            let mut h = Harness::new();
            let mut m = marker(&snapshot(""));
            m.invalid = invalid;
            if !invalid {
                m.verified_at = 0;
                h.final_clock.as_mut().unwrap().now = T_NS + 1;
            }
            h.marker = Some(m.encode().to_vec());
            let r = h.run_catalog(&args(), Mode::Dark, Some(&catalog));
            assert_eq!(r.worker_mask, 1 << 31);
            assert!(r.execution.permit().is_none());
        }
    }

    // 이것을 실패시키는 것: 문맥 부재에서 구 전역 저장소 이름으로 읽기를 계속하는 것.
    #[test]
    fn n7_missing_context_never_reads_global_store() {
        let mut h = Harness::new();
        // Uid, Clock, open '/', inspect '/', open 'r', inspect 'r', close '/',
        // then the first missing context component. Derive its position from a normal walk.
        h.run(&args(), Mode::Dark);
        let missing = h
            .calls
            .iter()
            .position(|op| {
                matches!(op,
            Operation::OpenDirectory { name, .. } if name == b"contexts-v2")
            })
            .unwrap();
        let mut h = Harness::new();
        h.fail_at = Some(missing);
        let response = h.run(&args(), Mode::Dark);
        assert!(response.execution.permit().is_none());
        assert!(
            !h.calls
                .iter()
                .any(|op| matches!(op, Operation::OpenFile { .. }))
        );
    }

    // 이것을 실패시키는 것: 관찰 오류를 성공으로 간주하거나 닫기 실패를 무한 재시도하는 것.
    #[test]
    fn every_failed_effect_terminates_with_no_authorization() {
        let mut normal = Harness::new();
        normal.run(&args(), Mode::Dark);
        for i in 0..normal.calls.len() {
            let mut h = Harness::new();
            h.fail_at = Some(i);
            let r = h.run(&args(), Mode::Dark);
            assert!(r.execution.permit().is_none(), "effect {i}");
            assert_ne!(r.status, Status::OK_NONE, "effect {i}");
        }
    }
    // 이것을 실패시키는 것: group pin을 무시하거나 정체/gid/mode가 바뀐 그룹 쓰기 조상을 허용하는 것.
    #[test]
    fn staged_groups_use_only_the_exact_init_pin() {
        let mut f = facts(true, false, 0);
        f.entry.mode = 0o040775;
        let group = alloc::format!(
            "--runtime-groups={}",
            crate::helper::encode_groups(&[fs_trust::GroupPin::of(&f.entry)])
        );
        let mut a = args();
        a[8] = b"--runtime-root=1:9:/g/r";
        a.push(group.as_bytes());
        for case in 0..5 {
            let mut h = Harness::new();
            let mut changed = f;
            match case {
                1 => changed.entry.dev += 1,
                2 => changed.entry.ino += 1,
                3 => changed.entry.gid += 1,
                4 => changed.entry.mode = 0o040770,
                _ => {}
            }
            h.directory_change = Some((b"g".to_vec(), changed));
            assert_eq!(
                h.run(&a, Mode::Dark).status,
                if case == 0 {
                    Status::OK_NONE
                } else {
                    Status::DEGRADED_RUNTIME_ROOT
                }
            );
        }
    }
    // 이것을 실패시키는 것: 승인된 조상 이전 prefetch 발급, 다른 parent/name/slot 허용.
    #[test]
    fn prefetch_is_bound_to_the_approved_first_file() {
        let mut h = Harness::new();
        let mut p = prepare(&args());
        let mut previous = None;
        loop {
            let Step::Read(effect) = next(&mut p, previous.take()) else {
                panic!("no first file")
            };
            if matches!(effect.operation(), Operation::OpenFile { .. }) {
                let sources = p.prefetch(&effect).expect("approved boundary");
                assert_eq!(
                    sources.names(),
                    [b"snapshot".as_slice(), b"last-good", b"marker"]
                );
                assert_eq!(sources.index(&effect), Some(0));
                for (i, name) in sources.names().into_iter().enumerate() {
                    let op = |parent, into, name| Effect {
                        operation: Operation::OpenFile { parent, into, name },
                    };
                    assert_eq!(
                        sources.index(&op(sources.parent(), Slot::File, name)),
                        Some(i)
                    );
                    assert_eq!(
                        sources.index(&op(sources.parent().other(), Slot::File, name)),
                        None
                    );
                    assert_eq!(
                        sources.index(&op(sources.parent(), Slot::Directory0, name)),
                        None
                    );
                }
                assert_eq!(
                    sources.index(&Effect {
                        operation: Operation::OpenFile {
                            parent: sources.parent(),
                            name: b"other",
                            into: Slot::File
                        }
                    }),
                    None
                );
                p.observed.runtime_ok = false;
                assert!(p.prefetch(&effect).is_none());
                break;
            }
            assert!(p.prefetch(&effect).is_none());
            previous = Some(h.observe(effect));
        }
    }
    // 이것을 실패시키는 것: 아직 선택하지 않은 last-good/marker 사실·크기를 필터 전에 승인하지 않는 것.
    #[test]
    fn prefetch_checks_every_saved_file_before_filter() {
        let sources = Prefetch {
            parent: Slot::Directory0,
            uid: 501,
            cwd: None,
        };
        let h = Harness::new();
        for (index, size) in [
            (0, h.current.as_ref().unwrap().len()),
            (1, h.current.as_ref().unwrap().len()),
            (2, snapshot::MARKER),
        ] {
            let f = facts(false, false, size);
            assert!(sources.accepts(index, f));
            for case in 0..9 {
                let mut bad = f;
                match case {
                    0 => bad.entry.uid = 0,
                    1 => bad.entry.mode = 0o100644,
                    2 => bad.nlink = 2,
                    3 => bad.entry.ownership = None,
                    4 => bad.local = Some(false),
                    5 => bad.entry.acl = fs_trust::AclFacts::Unknown,
                    6 => bad.entry.acl = fs_trust::AclFacts::AllowsWrite,
                    7 => bad.size = 1,
                    _ => bad.size = u64::MAX,
                }
                assert!(!sources.accepts(index, bad), "source {index} case {case}");
            }
            assert!(!sources.accepts(3, f));
        }
    }
}
