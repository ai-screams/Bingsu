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
            assert_eq!(timed.execution.units(), ordinary.execution.units());
        }
    }
    /// One command the snapshot draws, so "units" tells whether execution was granted.
    const UNIT: &str = "[segment.\"custom/yes\"]\nkind='command'\ncommand=['echo','yes']\n[layout.line2]\nleft=['custom/yes','char']";
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
        /// The command response file, the environment frame and the entry
        /// clock the prompt would hand the plan (C4b); `None` by default.
        commands: Option<Vec<u8>>,
        environment: Option<Vec<u8>>,
        entry: Option<Clock>,
        /// The build identity comes with `entry`; these leave it out with
        /// an entry, or hand it without one.
        no_build_id: bool,
        build_without_entry: bool,
    }
    impl Harness {
        fn new() -> Self {
            let s = snapshot(UNIT);
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
                commands: None,
                environment: None,
                entry: None,
                no_build_id: false,
                build_without_entry: false,
            }
        }
        fn bytes(&self) -> Option<&[u8]> {
            match self.current_name {
                b"snapshot" => self.current.as_deref(),
                b"last-good" => self.last.as_deref(),
                b"marker" => self.marker.as_deref(),
                b"command" => self.commands.as_deref(),
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
                Operation::OpenCollection(CollectionCopy::Command) if self.commands.is_some() => {
                    assert!(!self.live_file);
                    self.current_name = b"command";
                    self.offset = 0;
                    self.live_file = true;
                    Observation::Opened
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
            let mut plan = prepare(&args).with_environment(self.environment.clone());
            if let Some(entry) = self.entry {
                plan = plan.with_entry(entry);
            }
            if (self.entry.is_some() || self.build_without_entry) && !self.no_build_id {
                plan = plan.with_build_id(BuildId([8; 32]));
            }
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
                                s.config.band = None;
                                s.config.lines = crate::template::compile::compile(
                                    "{fixture}",
                                    catalog.segments,
                                )
                                .unwrap();
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
            assert!(!r.execution.units().is_empty());
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
        let mut old = snapshot(&format!("icons='ascii'\n{UNIT}"));
        old.id.generation = 6;
        h.last = Some(old.encode(1, 0).unwrap());
        h.current.as_mut().unwrap()[192] ^= 1;
        h.marker = Some(marker(&old).encode().to_vec());
        let r = h.run(&args(), Mode::Dark);
        assert_eq!(r.status, Status::ERROR_CONFIG_LAST_GOOD);
        assert!(!r.execution.units().is_empty());
        assert!(record(&r).contains('!'));
        h.marker = Some(marker(&snapshot("")).encode().to_vec());
        assert!(h.run(&args(), Mode::Dark).execution.units().is_empty());
        let mut m = marker(&old);
        m.invalid = true;
        m.id.generation = 123;
        h.marker = Some(m.encode().to_vec());
        assert!(h.run(&args(), Mode::Dark).execution.units().is_empty());
        old.id.boot = [9; 16];
        h.last = Some(old.encode(1, 0).unwrap());
        assert_eq!(
            h.run(&args(), Mode::Dark).status,
            Status::ERROR_CONFIG_DEFAULT
        );
    }
    /// The first byte of the variant selected at `width`.
    fn variant_at(wire: &[u8], width: u16) -> usize {
        let (c, _) = snapshot::lengths(wire).unwrap();
        let compiled = &wire[HEADER + PREFIX..HEADER + PREFIX + c];
        let front = crate::snapshot_codec::front_len(compiled, c).unwrap();
        let plan = crate::snapshot_codec::plan_front(&compiled[..front], c, width).unwrap();
        HEADER + PREFIX + plan.offset
    }
    // 이것을 실패시키는 것: last-good만 다른 폭으로 읽는 것, 앞단이 envelope의 폭 대신 고정 폭으로 고르는 것.
    #[test]
    fn both_copies_take_the_same_selected_read() {
        let s = snapshot(
            "[layout.when.narrow]\nmax_cols=100\n[layout.when.narrow.style]\ntemplate='NARROW {char}'\n",
        );
        let wire = s.encode(1, 0).unwrap();
        assert_ne!(variant_at(&wire, 80), variant_at(&wire, 120));
        let mut unselected = wire.clone();
        unselected[variant_at(&wire, 120)] ^= 1;
        let mut selected = wire.clone();
        selected[variant_at(&wire, 80)] ^= 1;
        let mut h = Harness::new();
        h.marker = Some(marker(&s).encode().to_vec());
        h.current = Some(unselected.clone());
        h.last = Some(selected.clone());
        let r = h.run(&args(), Mode::Dark);
        assert_eq!(r.status, Status::OK_NONE);
        assert!(record(&r).contains("NARROW"));
        h.current = Some(selected.clone());
        h.last = Some(unselected);
        let r = h.run(&args(), Mode::Dark);
        assert_eq!(r.status, Status::ERROR_CONFIG_LAST_GOOD);
        assert!(record(&r).contains("NARROW"));
        h.last = Some(selected);
        assert_eq!(
            h.run(&args(), Mode::Dark).status,
            Status::ERROR_CONFIG_DEFAULT
        );
    }
    /// 64 bands of 4 columns, keyed in width order or against it.
    fn banded_text(rising: bool) -> String {
        let mut text = String::new();
        for i in 0..64 {
            let min = if rising { i + 1 } else { 64 - i } * 4;
            let x = "x".repeat(600);
            text += &format!(
                "[layout.when.b{i:02}]\nmin_cols={min}\nmax_cols={}\n[layout.when.b{i:02}.style]\ntemplate='{x} {{char}}'\n",
                min + 3
            );
        }
        text
    }
    /// What the read plan asks for when each read returns at most `short`
    /// bytes. `front` and `end` are file offsets: the end of INDEX and of the
    /// variant selected at width 80; `body` the end of the compiled section.
    fn read_plan(short: usize, front: usize, end: usize, body: usize) -> Vec<usize> {
        let (mut plan, mut at) = (Vec::new(), 0);
        for limit in [HEADER, HEADER + PREFIX] {
            while at < limit {
                plan.push(limit - at);
                at += (limit - at).min(short);
            }
        }
        while at < if at < front { body } else { end } {
            let limit = if at < front { body } else { end };
            let ask = (limit - at).min(snapshot::READ_CHUNK);
            plan.push(ask);
            at += ask.min(short);
        }
        plan
    }
    // 이것을 실패시키는 것: 받은 바이트가 아닌 요청량으로 위치를 세는 것, 색인을 끝낸 다음 읽기가 옛 한도를 쓰는 것,
    // 짧은 읽기 뒤 한도를 잃는 것, 한도를 `c_len` 너머로 두는 것.
    #[test]
    fn short_reads_keep_the_read_limit() {
        for rising in [true, false] {
            let s = snapshot(&banded_text(rising));
            let wire = s.encode(1, 0).unwrap();
            let (c, _) = snapshot::lengths(&wire).unwrap();
            let compiled = &wire[HEADER + PREFIX..HEADER + PREFIX + c];
            let front = crate::snapshot_codec::front_len(compiled, c).unwrap();
            let plan = crate::snapshot_codec::plan_front(&compiled[..front], c, 80).unwrap();
            let (front, end) = (
                HEADER + PREFIX + front,
                HEADER + PREFIX + plan.offset + plan.len,
            );
            let body = HEADER + PREFIX + c;
            assert!(front < end && end < body);
            // The one-sized first body read that ends exactly at INDEX's end
            // makes the next read the first under the variant's limit.
            for short in [usize::MAX, 1 << 13, 4097, 251, front - HEADER - PREFIX] {
                let mut h = Harness::new();
                h.marker = Some(marker(&s).encode().to_vec());
                h.current = Some(wire.clone());
                h.short = short;
                assert_eq!(
                    h.run(&args(), Mode::Dark).status,
                    Status::OK_NONE,
                    "{short}"
                );
                let asked: Vec<usize> = h
                    .reads
                    .iter()
                    .filter(|(name, ..)| *name == b"snapshot")
                    .map(|(_, _, len)| *len)
                    .collect();
                assert_eq!(asked, read_plan(short, front, end, body), "{short}");
                let last = h.reads.iter().rfind(|(name, ..)| *name == b"snapshot");
                let &(_, offset, len) = last.unwrap();
                assert!(offset + len.min(short) <= body, "{short}");
            }
        }
    }
    const TRUST_CASES: u8 = 15;
    fn trust_case(case: u8) -> (Harness, Status) {
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
        (h, want)
    }
    // 이것을 실패시키는 것: 표식 오류/각 정체/시각 오류를 fresh로 렌더하거나 상태 우선순위를 바꾸는 것.
    #[test]
    fn status_priority_and_trust_rejections() {
        for case in 0..TRUST_CASES {
            let (mut h, want) = trust_case(case);
            let r = h.run(&args(), Mode::Dark);
            assert_eq!(r.status, want, "case {case}");
            assert!(r.execution.units().is_empty(), "case {case}");
            assert!(record(&r).contains('!'));
            // A safe compiled screen collects independently of command eligibility.
            assert_eq!(r.worker_mask, 10);
        }
    }
    // 이것을 실패시키는 것: redraw에서 표식·시각 판정을 건너뛰어 fresh로 그리거나 다른 상태를 내는 것.
    #[test]
    fn test_redraw_uses_same_eligibility_as_prompt() {
        let mut redraw = args();
        redraw.push(b"--redraw");
        for case in 0..TRUST_CASES {
            let (mut h, want) = trust_case(case);
            let r = h.run(&redraw, Mode::Dark);
            assert_eq!(r.status, want, "case {case}");
            assert!(r.execution.units().is_empty(), "case {case}");
            assert_eq!(r.worker_mask, 0, "case {case}");
            let (mut plain, _) = trust_case(case);
            assert_eq!(
                r.record,
                plain.run(&args(), Mode::Dark).record,
                "case {case}"
            );
        }
        let fresh = Harness::new().run(&redraw, Mode::Dark);
        assert_eq!(fresh.status, Status::OK_NONE);
        assert_eq!(fresh.record, Harness::new().run(&args(), Mode::Dark).record);
    }
    // 이것을 실패시키는 것: redraw 분기에서만 표시 자격(단위 목록)을 비우거나 바꾸는 것.
    #[test]
    fn test_redraw_display_matches_normal() {
        let mut redraw = args();
        redraw.push(b"--redraw");
        let normal = Harness::new().run(&args(), Mode::Dark);
        let redrawn = Harness::new().run(&redraw, Mode::Dark);
        assert!(!normal.execution.units().is_empty());
        assert_eq!(redrawn.execution.units(), normal.execution.units());
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
            assert!(r.execution.units().is_empty());
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
                assert!(h.run(&args(), Mode::Dark).execution.units().is_empty());
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
            assert!(r.execution.units().is_empty());
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
        assert_eq!(ordinary.worker_mask, 10);
        let mut m = marker(&snapshot(""));
        m.invalid = true;
        h.marker = Some(m.encode().to_vec());
        let invalid = h.run(&args(), Mode::Dark);
        assert_eq!(invalid.worker_mask, ordinary.worker_mask);
        assert!(invalid.execution.units().is_empty());
        // 이것을 실패시키는 것: 무효 표식에서 실행 단위를 허용하는 것.
        assert!(invalid.execution.units().is_empty());
        let s = snapshot(
            "[segment.\"custom/run\"]\nkind='command'\ncommand=['echo','yes']\n[layout.line2]\nleft=['custom/run','char']",
        );
        let mut h = Harness::new();
        h.current = Some(s.encode(1, 0).unwrap());
        let mut m = marker(&s);
        h.marker = Some(m.encode().to_vec());
        // 이것을 실패시키는 것: 실행 단위가 없는 fixture로 무효 표식 시험을 공허하게 만드는 것.
        assert_eq!(h.run(&args(), Mode::Dark).execution.units().len(), 1);
        m.invalid = true;
        h.marker = Some(m.encode().to_vec());
        // 이것을 실패시키는 것: 무효 표식에서 설정의 실행 단위를 허용하는 것.
        assert!(h.run(&args(), Mode::Dark).execution.units().is_empty());

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
            assert!(r.execution.units().is_empty());
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
        assert!(response.execution.units().is_empty());
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
            assert!(r.execution.units().is_empty(), "effect {i}");
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

    // C3 (GATE-EXEC-DEADLINE.1, GATE-CLOCK-READS.1): the approval clock samples and the deadline.
    fn command_harness() -> Harness {
        let s = snapshot(UNIT);
        let mut h = Harness::new();
        h.current = Some(s.encode(1, 0).unwrap());
        h.marker = Some(marker(&s).encode().to_vec());
        h
    }
    // 판정 직후 시계가 마감을 넘긴 fixture: 마감 1ns 전 관찰은 그 단위를 승인하고(양성 대조),
    // 마감 이상이면 단위가 없다.
    // 이것을 실패시키는 것: snapshot::eligible의 T 비교를 `>=`에서 `>`로 바꾸는 것, 끝 시계 대신 시작 시계로
    // 판정하는 것, FinalClock 단계를 생략하는 것.
    #[test]
    fn finish_refuses_units_when_final_clock_reaches_deadline() {
        let end = 100 + T_NS;
        for (now, approved) in [(end - 1, true), (end, false), (end + 1, false)] {
            let mut h = command_harness();
            h.final_clock.as_mut().unwrap().now = now;
            let r = h.run(&args(), Mode::Dark);
            if approved {
                assert_eq!(r.status, Status::OK_NONE, "{now}");
                assert_eq!(
                    r.execution
                        .units()
                        .iter()
                        .map(|u| u.id.as_str())
                        .collect::<Vec<_>>(),
                    ["custom/yes"]
                );
            } else {
                assert_eq!(r.status, Status::DEGRADED_TRUST_EXPIRED, "{now}");
                assert!(r.execution.units().is_empty(), "{now}");
            }
            assert_eq!(h.clocks, 2);
        }
    }
    // 경로마다 계획이 내는 시계 단계 수가 고정이다: 시작 시계는 UID 바로 뒤 하나, 끝 시계는 모든
    // 파일을 닫은 뒤 하나이고, runtime root가 거부되거나 boot 정체가 없으면 끝 시계가 없다.
    // 이것을 실패시키는 것: FinalClock 단계를 생략하는 것(next_file이 Cleanup으로 감), 시계 단계를 더 내는 것,
    // 끝 시계를 파일을 닫기 전에 내는 것.
    #[test]
    fn staged_plan_emits_fixed_clock_operations_per_path() {
        let mut bad_runtime = args();
        bad_runtime[8] = b"--runtime-root=1:8:/r";
        for (case, argv, want) in [
            ("normal", args(), 2),
            ("last-good", args(), 2),
            ("marker-invalid", args(), 2),
            ("marker-missing", args(), 2),
            ("runtime-root", bad_runtime, 1),
            ("no-start-clock", args(), 1),
            (
                "bad-args",
                vec![b"--ctx".as_slice(), b"2", b"--record", b"B1"],
                0,
            ),
        ] {
            let mut h = command_harness();
            match case {
                "last-good" => {
                    h.last = h.current.clone();
                    h.current.as_mut().unwrap()[192] ^= 1;
                }
                "marker-invalid" => {
                    let mut m = Marker::decode(h.marker.as_ref().unwrap()).unwrap();
                    m.invalid = true;
                    h.marker = Some(m.encode().to_vec());
                }
                "marker-missing" => h.marker = None,
                "no-start-clock" => h.clock = None,
                _ => {}
            }
            let r = h.run(&argv, Mode::Dark);
            let clocks: Vec<_> = h
                .calls
                .iter()
                .enumerate()
                .filter(|(_, c)| matches!(c, Operation::Clock))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(clocks.len(), want, "{case}");
            assert_eq!(h.clocks, want, "{case}");
            if want > 0 {
                assert!(matches!(h.calls[0], Operation::Uid), "{case}");
                assert_eq!(clocks[0], 1, "{case}: start clock right after the uid");
            }
            if want == 2 {
                // The end clock follows every file effect; after it only directory cleanup runs,
                // and the harness checks that no file is left open at Done.
                let last_file = h
                    .calls
                    .iter()
                    .rposition(|c| matches!(c, Operation::Read { .. } | Operation::OpenFile { .. }))
                    .unwrap();
                assert!(clocks[1] > last_file, "{case}");
                assert!(
                    h.calls[clocks[1] + 1..].iter().all(|c| matches!(
                        c,
                        Operation::Close(Slot::Directory0 | Slot::Directory1)
                    )),
                    "{case}"
                );
            }
            let expected = match case {
                "normal" => Status::OK_NONE,
                "last-good" => Status::ERROR_CONFIG_LAST_GOOD,
                "marker-invalid" => Status::DEGRADED_TRUST_INVALID,
                "marker-missing" => Status::DEGRADED_TRUST_UNVERIFIED,
                "runtime-root" => Status::DEGRADED_RUNTIME_ROOT,
                "no-start-clock" => Status::ERROR_CONFIG_DEFAULT,
                _ => Status::ERROR_BAD_ARGS,
            };
            assert_eq!(r.status, expected, "{case}");
            assert_eq!(
                !r.execution.units().is_empty(),
                case == "normal" || case == "last-good",
                "{case}"
            );
        }
    }

    /// A command response for `UNIT` as the helper publishes it for this
    /// prompt (context /c /s, cwd /x/project, build [8; 32]), run in `frame`.
    fn command_response(value: &str, frame: &[u8], cwd: &[u8]) -> Vec<u8> {
        use crate::command::{plan, response as cr, wire::policy_digest};
        let s = snapshot(UNIT);
        let unit = &s.config.exec_units[0];
        let r = plan::runnable(unit).unwrap();
        let vars = plan::Environ::parse(crate::command::env_frame::body(frame).unwrap());
        cr::Response {
            binding: cr::Binding {
                build_id: BuildId([8; 32]),
                boot: s.id.boot,
                epoch: s.id.epoch,
                context: s.id.context,
                clock_kind: clock().kind,
                domain: clock().domain,
                resume: clock().resume,
                config: b"/c".to_vec(),
                state: b"/s".to_vec(),
                cwd: cwd.to_vec(),
            },
            entries: vec![cr::Entry {
                origin: crate::handoff::Origin::Config,
                id: unit.id.clone(),
                policy: policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow),
                environment: plan::env_digest(&vars, &r.env_allow),
                pattern: [0; 32],
                attempted_at: 40,
                completed_at: 50,
                status: cr::Status::Ok,
                value: value.into(),
                raw: value.into(),
            }],
        }
        .encode()
        .unwrap()
    }
    fn frame() -> Vec<u8> {
        crate::command::env_frame::encode([b"PATH=/usr/bin\0".as_slice(), b"LANG=C\0"]).unwrap()
    }
    fn commanded(value: &str) -> Harness {
        let mut h = Harness::new();
        h.environment = Some(frame());
        h.entry = Some(clock());
        h.commands = Some(command_response(value, &frame(), b"/x/project"));
        h
    }
    fn reads_commands(h: &Harness) -> bool {
        h.calls
            .iter()
            .any(|op| matches!(op, Operation::OpenCollection(CollectionCopy::Command)))
    }

    const ENV_SEG: &str = "[segment.\"custom/aws\"]\nkind='env'\nenv='AWS_PROFILE'\n[layout.line2]\nleft=['custom/aws','char']";
    fn with_env(text: &str, entries: &[&[u8]]) -> Harness {
        let mut h = Harness::new();
        let s = snapshot(text);
        h.current = Some(s.encode(1, 0).unwrap());
        h.marker = Some(marker(&s).encode().to_vec());
        h.environment = Some(crate::command::env_frame::encode(entries.iter().copied()).unwrap());
        h
    }

    // C5: env segment는 이 프롬프트의 환경 frame에서 선언한 이름의 값을 그린다. 진입 시계·build id·명령 응답 없이도
    // 그린다. 이것을 실패시키는 것: env 값 읽기를 빼는 것, 명령 응답이 있을 때만 env 값을 채우는 것, 이름 대신 다른
    // 변수를 읽는 것.
    #[test]
    fn test_env_segment_shows_value_when_set() {
        let mut h = with_env(ENV_SEG, &[b"AWS_PROFILE=dev-acct\0", b"OTHER=zzother\0"]);
        let r = h.run(&args(), Mode::Dark);
        assert_eq!(r.status, Status::OK_NONE);
        assert!(record(&r).contains("dev-acct"), "{}", record(&r));
        assert!(!record(&r).contains("zzother"));
        assert!(!reads_commands(&h));
    }

    // 선언하지 않은 이름은 읽지 않는다: 템플릿이 선언 없는 `custom/secret`을 참조해도(W408로 빠짐) 그 이름의 값은
    // 그려지지 않는다. 빈 값, 없는 이름, 두 번 나온 이름, frame 없음(64 KiB 초과)도 그리지 않는다. 이것을 실패시키는
    // 것: 선언 필터를 지우고 참조 id로 환경을 찾는 것, 빈 값을 그리는 것.
    #[test]
    fn test_undeclared_name_never_read() {
        let text = "[segment.\"custom/aws\"]\nkind='env'\nenv='AWS_PROFILE'\n[style]\ntemplate='{custom/aws}{custom/secret}{char}'";
        let mut h = with_env(
            text,
            &[
                b"SECRET=zzsecret\0",
                b"secret=zzlower\0",
                b"AWS_PROFILE=dev-acct\0",
            ],
        );
        let out = record(&h.run(&args(), Mode::Dark));
        assert!(
            out.contains("dev-acct") && !out.contains("zzsecret") && !out.contains("zzlower"),
            "{out}"
        );
        for entries in [
            &[b"AWS_PROFILE=\0".as_slice()][..],
            &[b"OTHER=1\0".as_slice()][..],
            &[
                b"AWS_PROFILE=zzone\0".as_slice(),
                b"AWS_PROFILE=zztwo\0".as_slice(),
            ][..],
        ] {
            let mut h = with_env(ENV_SEG, entries);
            let out = record(&h.run(&args(), Mode::Dark));
            assert!(!out.contains("custom") && !out.contains("zz"), "{out}");
        }
        let mut h = with_env(ENV_SEG, &[b"AWS_PROFILE=dev-acct\0"]);
        h.environment = None;
        assert!(!record(&h.run(&args(), Mode::Dark)).contains("dev-acct"));
    }

    // env 값은 text와 같은 칸 수로 잘리고 정제된다. 잘못된 UTF-8은 대체 문자로 바뀌고 제어 문자는 빠진다. 이것을
    // 실패시키는 것: env 값을 자르지 않는 것, 정제 없이 그리는 것.
    #[test]
    fn an_env_value_is_cut_and_sanitized() {
        let long = alloc::format!("AWS_PROFILE={}\0", "Q".repeat(5000));
        let mut h = with_env(ENV_SEG, &[long.as_bytes()]);
        let counts: Vec<usize> = record(&h.run(&args(), Mode::Dark))
            .split('\x1f')
            .map(|f| f.matches('Q').count())
            .collect();
        assert!(counts.iter().any(|&n| n > 0), "{counts:?}");
        assert!(
            counts
                .iter()
                .all(|&n| n <= usize::from(crate::field::CUSTOM_TEXT_CELLS)),
            "{counts:?}"
        );
        let mut h = with_env(ENV_SEG, &[b"AWS_PROFILE=a\x1b[31mb\xffc\0"]);
        let out = record(&h.run(&args(), Mode::Dark));
        assert!(
            out.contains("a[31mb\u{FFFD}c") && !out.contains("\x1b[31mb"),
            "{out:?}"
        );
    }

    // env 값은 정제 뒤에 자른다: 지워지는 글자로 시작하는 긴 값도 그 뒤의 글이 보인다. 빈 값은 구분자와 함께
    // 빠져, 그 segment가 레이아웃에 없는 것과 같은 레코드다. 이것을 실패시키는 것: 원문을 정제 전에 바이트 상한에서
    // 자르는 것(read_prefix를 원문에 쓰는 것), 빈 값을 빈 text로 그려 구분자를 남기는 것.
    #[test]
    fn env_values_are_sanitized_before_the_cut_and_empty_drops_the_separators() {
        let esc = [
            b"AWS_PROFILE=".to_vec(),
            b"\x1b".repeat(272),
            b"VISIBLE\0".to_vec(),
        ]
        .concat();
        let rlo = [
            b"AWS_PROFILE=".to_vec(),
            "\u{202E}".repeat(91).into_bytes(),
            b"dev\0".to_vec(),
        ]
        .concat();
        for entry in [esc, rlo] {
            let mut h = with_env(ENV_SEG, &[entry.as_slice()]);
            let out = record(&h.run(&args(), Mode::Dark));
            assert!(out.contains("VISIBLE") || out.contains("dev"), "{out:?}");
        }
        let two = "[segment.\"custom/aws\"]\nkind='env'\nenv='AWS_PROFILE'\n[segment.\"custom/t\"]\nkind='text'\ntext='TT'\n";
        let with_seg = alloc::format!("{two}[layout.line2]\nleft=['custom/t','custom/aws','char']");
        let without = alloc::format!("{two}[layout.line2]\nleft=['custom/t','char']");
        let mut empty = with_env(&with_seg, &[b"AWS_PROFILE=\0"]);
        let mut absent = with_env(&without, &[b"AWS_PROFILE=\0"]);
        assert_eq!(
            record(&empty.run(&args(), Mode::Dark)),
            record(&absent.run(&args(), Mode::Dark))
        );
    }

    // 양성 대조: 스냅샷이 그리는 command 세그먼트는 이 프롬프트의 응답 값을 그린다. 이것을 실패시키는 것: 명령 응답
    // 읽기를 빼는 것, finish가 값을 render에 넘기지 않는 것.
    #[test]
    fn a_drawn_command_segment_shows_its_value() {
        let mut h = commanded("prod-cluster");
        let r = h.run(&args(), Mode::Dark);
        assert_eq!(r.status, Status::OK_NONE);
        assert!(reads_commands(&h));
        assert!(record(&r).contains("prod-cluster"), "{}", record(&r));
    }

    // 원본 줄에 제어 문자가 든 응답도 앞단은 값만 그린다(원본 줄은 그리지 않으므로 그 글자를 검사하지 않는다).
    // helper가 읽는 decode는 같은 파일을 거부한다. 이것을 실패시키는 것: 앞단이 helper의 decode로 읽는 것(값을
    // 잃음).
    #[test]
    fn a_raw_line_the_prompt_does_not_draw_does_not_hide_the_value() {
        let mut bytes = command_response("prod-cluster", &frame(), b"/x/project");
        let raw = bytes
            .windows(12)
            .rposition(|w| w == b"prod-cluster")
            .unwrap();
        bytes[raw] = 0x1b;
        let crc = crate::snapshot::crc32c(&[&bytes[command::HEADER..]]);
        bytes[16..20].copy_from_slice(&crc);
        assert!(command::Response::decode(&bytes).is_err());
        let mut h = commanded("prod-cluster");
        h.commands = Some(bytes);
        let r = h.run(&args(), Mode::Dark);
        assert!(record(&r).contains("prod-cluster"), "{}", record(&r));
        assert!(!record(&r).contains("\u{1b}rod-cluster"));
    }

    // 값을 낼 수 없으면 응답을 읽지 않는다: 환경 프레임이 없을 때, 그리는 command 세그먼트가 없을 때. 이것을
    // 실패시키는 것: draws_commands의 환경 조건이나 세그먼트 조건을 지우는 것(읽기가 생김).
    #[test]
    fn the_response_is_read_only_when_a_value_can_show() {
        let mut h = commanded("prod-cluster");
        h.environment = None;
        let r = h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
        assert!(!record(&r).contains("prod-cluster"));
        let mut h = commanded("prod-cluster");
        // A drawn text segment only: user segments, none of them a command.
        let s = snapshot(
            "[segment.\"custom/t\"]\nkind='text'\ntext='T'\n[layout.line2]\nleft=['custom/t','char']",
        );
        h.current = Some(s.encode(1, 0).unwrap());
        h.marker = Some(marker(&s).encode().to_vec());
        h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
    }

    // 다른 조건은 모두 갖춘 채 진입 시계만, build id만 빠지거나 환경 frame의 checksum이 틀리면 응답을 읽지 않는다.
    // 이것을 실패시키는 것: draws_commands에서 진입 시계 조건, build id 조건을 지우는 것, with_environment가 frame의
    // checksum을 보지 않는 것.
    #[test]
    fn a_missing_entry_build_id_or_a_damaged_frame_alone_stops_the_read() {
        let mut h = commanded("prod-cluster");
        h.run(&args(), Mode::Dark);
        assert!(reads_commands(&h));
        let mut h = commanded("prod-cluster");
        h.entry = None;
        h.build_without_entry = true;
        h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
        let mut h = commanded("prod-cluster");
        h.no_build_id = true;
        h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
        let mut h = commanded("prod-cluster");
        let mut damaged = frame();
        let last = damaged.len() - 2;
        damaged[last] ^= 1;
        h.environment = Some(damaged);
        let r = h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
        assert!(!record(&r).contains("prod-cluster"));
    }

    /// `UNIT` drawn only in a band from 120 columns.
    const WIDE: &str = "[segment.\"custom/yes\"]\nkind='command'\ncommand=['echo','yes']\n\
        [layout.when.wide]\nmin_cols=120\n[layout.when.wide.line2]\nleft=['custom/yes','char']";

    // 응답은 이 폭이 고른 줄이 command 세그먼트를 그릴 때만 읽는다. 넓은 구간에만 있는 command는 좁은 폭에서 읽지
    // 않고, redraw에서도 그 폭의 줄을 따른다. 이것을 실패시키는 것: draws_commands가 폭과 무관한 사용자 세그먼트
    // 목록만 보는 것(80열에서 읽음), 그 폭의 줄 검사를 지우는 것.
    #[test]
    fn a_command_only_in_a_wider_band_is_read_only_at_that_width() {
        let s = snapshot(WIDE);
        for redraw in [false, true] {
            for (width, read) in [(b"80".as_slice(), false), (b"130".as_slice(), true)] {
                let mut h = commanded("prod-cluster");
                h.current = Some(s.encode(1, 0).unwrap());
                h.marker = Some(marker(&s).encode().to_vec());
                let mut a = args();
                let at = a.iter().position(|w| *w == b"--width").unwrap() + 1;
                a[at] = width;
                if redraw {
                    a.push(b"--redraw");
                }
                let r = h.run(&a, Mode::Dark);
                assert_eq!(reads_commands(&h), read, "{width:?} redraw={redraw}");
                assert_eq!(record(&r).contains("prod-cluster"), read, "{}", record(&r));
            }
        }
    }

    // 템플릿이 command를 필드로만 참조해도(`{custom/yes.value}`) 응답을 읽고 그린다. 일반 프롬프트와 redraw 모두.
    // 이것을 실패시키는 것: 그리는 줄 검사가 세그먼트 노드만 보고 필드 노드를 놓치는 것.
    #[test]
    fn a_command_drawn_only_by_its_field_is_read() {
        let s = snapshot(
            "[segment.\"custom/yes\"]\nkind='command'\ncommand=['echo','yes']\n\
             [style]\ntemplate='{custom/yes.value} {char}'",
        );
        for redraw in [false, true] {
            let mut h = commanded("prod-cluster");
            h.current = Some(s.encode(1, 0).unwrap());
            h.marker = Some(marker(&s).encode().to_vec());
            let mut a = args();
            if redraw {
                a.push(b"--redraw");
            }
            let r = h.run(&a, Mode::Dark);
            assert!(reads_commands(&h), "redraw={redraw}");
            assert!(record(&r).contains("prod-cluster"), "{}", record(&r));
        }
    }

    // 다른 cwd의 응답, 무효 표식, 프롬프트 중 바뀐 시계에서는 그리지 않는다. 이것을 실패시키는 것: 기대 binding의
    // cwd를 응답에서 가져오는 것, 표시 자격 대신 true를 넘기는 것, 마지막 시계가 어긋날 때 응답을 남기는 것.
    #[test]
    fn another_cwd_an_invalid_marker_or_a_moved_clock_shows_nothing() {
        let mut h = commanded("prod-cluster");
        h.commands = Some(command_response("prod-cluster", &frame(), b"/x/other"));
        assert!(!record(&h.run(&args(), Mode::Dark)).contains("prod-cluster"));
        let mut h = commanded("prod-cluster");
        let s = snapshot(UNIT);
        let mut m = marker(&s);
        m.invalid = true;
        h.marker = Some(m.encode().to_vec());
        assert!(!record(&h.run(&args(), Mode::Dark)).contains("prod-cluster"));
        let mut h = commanded("prod-cluster");
        let mut moved = clock();
        moved.boot = [9; 16];
        h.final_clock = Some(moved);
        assert!(!record(&h.run(&args(), Mode::Dark)).contains("prod-cluster"));
    }

    // 값은 text 세그먼트와 같은 칸 수로 잘린다(C4b 판정 Q3). 이것을 실패시키는 것: command 값을 자르지 않고
    // 그리는 것.
    #[test]
    fn a_long_value_is_cut_to_the_segment_cells() {
        let long = "Q".repeat(usize::from(crate::field::CUSTOM_TEXT_CELLS) + 40);
        let mut h = commanded(&long);
        let r = h.run(&args(), Mode::Dark);
        // The record carries the line in more than one field (the prompt and
        // its vi variants); each draws the value cut to the cells.
        let counts: Vec<usize> = record(&r)
            .split('\x1f')
            .map(|f| f.matches('Q').count())
            .collect();
        assert!(counts.iter().any(|&n| n > 0), "{counts:?}");
        assert!(
            counts
                .iter()
                .all(|&n| n <= usize::from(crate::field::CUSTOM_TEXT_CELLS)),
            "{counts:?}"
        );
    }

    // command 사본은 수집 응답보다 큰 명령 응답 상한까지 받고, 수집 사본은 그대로다. 이것을 실패시키는 것: command
    // 사본에 수집 응답 크기 범위를 쓰는 것(300 KB 응답을 버림), 상한을 넘는 응답을 받는 것.
    #[test]
    fn the_command_copy_takes_the_command_response_sizes() {
        let p = Prefetch {
            parent: Slot::Directory0,
            uid: 501,
            cwd: None,
        };
        let at = |n: usize| facts(false, false, n);
        assert!(p.accepts_collection(
            CollectionCopy::Command,
            at(crate::command::response::RESPONSE_MAX)
        ));
        assert!(p.accepts_collection(CollectionCopy::Command, at(STREAM_MAX + 1)));
        assert!(!p.accepts_collection(
            CollectionCopy::Command,
            at(crate::command::response::RESPONSE_MAX + 1)
        ));
        assert!(!p.accepts_collection(
            CollectionCopy::Command,
            at(crate::command::response::HEADER - 1)
        ));
        assert!(!p.accepts_collection(CollectionCopy::Current, at(STREAM_MAX + 1)));
    }

    /// A layout that draws the node segment.
    const NODE: &str = "[layout.line2]\nleft=['node','char']";
    /// A command response with node's version as the helper publishes it
    /// for this prompt, decided in `frame`.
    fn language_response(value: &str, frame: &[u8]) -> Vec<u8> {
        use crate::command::{builtin, plan, response as cr};
        let s = snapshot(NODE);
        let vars = plan::Environ::parse(crate::command::env_frame::body(frame).unwrap());
        cr::Response {
            binding: cr::Binding {
                build_id: BuildId([8; 32]),
                boot: s.id.boot,
                epoch: s.id.epoch,
                context: s.id.context,
                clock_kind: clock().kind,
                domain: clock().domain,
                resume: clock().resume,
                config: b"/c".to_vec(),
                state: b"/s".to_vec(),
                cwd: b"/x/project".to_vec(),
            },
            entries: vec![cr::Entry {
                origin: crate::handoff::Origin::Builtin,
                id: "node".into(),
                policy: [4; 32],
                environment: builtin::language(b"node").unwrap().env_digest(&vars),
                pattern: [0; 32],
                attempted_at: 40,
                completed_at: 50,
                status: cr::Status::Ok,
                value: value.into(),
                raw: value.into(),
            }],
        }
        .encode()
        .unwrap()
    }
    fn languaged(value: &str) -> Harness {
        let s = snapshot(NODE);
        let mut h = Harness::new();
        h.current = Some(s.encode(1, 0).unwrap());
        h.marker = Some(marker(&s).encode().to_vec());
        h.environment = Some(frame());
        h.entry = Some(clock());
        h.commands = Some(language_response(value, &frame()));
        h
    }

    // D3b: 그리는 내장 언어 segment는 응답의 버전을 그린다. 표식이 없어도(내장 값에는 표식 조건이 없음) 그리고,
    // redraw에서도 그린다. 이것을 실패시키는 것: draws_commands가 언어 segment를 보지 않는 것(응답을 읽지 않음),
    // finish가 언어 값을 render에 넘기지 않는 것, 언어 값에 표식 조건을 거는 것.
    #[test]
    fn a_drawn_language_segment_shows_its_version() {
        for (case, redraw, marker) in [
            ("plain", false, true),
            ("redraw", true, true),
            ("no marker", false, false),
        ] {
            let mut h = languaged("22.11.0");
            if !marker {
                h.marker = None;
            }
            let mut a = args();
            if redraw {
                a.push(b"--redraw");
            }
            let r = h.run(&a, Mode::Dark);
            assert!(reads_commands(&h), "{case}");
            assert!(record(&r).contains("22.11.0"), "{case}: {}", record(&r));
        }
    }

    // 다른 셸의 언어 값은 그리지 않는다: 응답 항목의 환경 요약값을 만든 frame과 이 프롬프트의 frame이 언어 변수에서
    // 다르면 숨긴다(D3b Q1). frame이 없으면 응답을 읽지 않고 숨긴다. 언어 segment를 그리지 않는 설정은 응답을
    // 읽지 않는다. 이것을 실패시키는 것: 앞단에서 환경 요약값 비교를 지우는 것, draws_commands의 frame 조건을
    // 지우는 것, 언어 segment를 그리지 않을 때도 읽는 것.
    #[test]
    fn a_language_version_needs_this_shells_frame() {
        let mut h = languaged("22.11.0");
        let other = crate::command::env_frame::encode([
            b"PATH=/usr/bin\0".as_slice(),
            b"LANG=C\0",
            b"VOLTA_HOME=/v\0",
        ])
        .unwrap();
        h.environment = Some(other);
        let r = h.run(&args(), Mode::Dark);
        assert!(reads_commands(&h));
        assert!(!record(&r).contains("22.11.0"), "{}", record(&r));
        let mut h = languaged("22.11.0");
        h.environment = None;
        let r = h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
        assert!(!record(&r).contains("22.11.0"));
        let mut h = languaged("22.11.0");
        let s = snapshot("[layout.line2]\nleft=['dir','char']");
        h.current = Some(s.encode(1, 0).unwrap());
        h.marker = Some(marker(&s).encode().to_vec());
        h.run(&args(), Mode::Dark);
        assert!(!reads_commands(&h));
    }
}
