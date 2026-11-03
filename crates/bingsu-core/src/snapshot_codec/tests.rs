// The purity checker scans every source file independently.
#[cfg(test)]
mod cases {
    use super::super::*;
    use alloc::{format, vec};

    fn bytes<T: Wire>(v: &T) -> Vec<u8> {
        let mut w = Writer {
            bytes: Some(Vec::new()),
            len: 0,
            error: None,
            segs: usize::MAX,
        };
        v.put(&mut w);
        assert_eq!(w.error, None);
        w.bytes.unwrap()
    }
    fn read<T: Wire>(b: &[u8]) -> Result<T, Error> {
        T::get(&mut Reader {
            rest: b,
            budget: MAX_ALLOC,
            segs: crate::field::BUILTIN.len(),
        })
    }
    fn round<T: Wire + PartialEq + core::fmt::Debug>(v: T) {
        assert_eq!(read::<T>(&bytes(&v)).unwrap(), v);
    }
    fn config() -> CompiledConfig {
        crate::config::report::tests::read("", &[])
            .snapshot
            .unwrap()
    }

    // 이것을 실패시키는 것: 필드·enum payload를 생략하거나 태그를 잘못 쓰고 알 수 없는 태그를 받아들이는 것.
    #[test]
    fn all_wire_types_and_tags() {
        round(u64::MAX);
        round(i64::MIN);
        round(i32::MIN);
        round(u32::MAX);
        round(u16::MAX);
        round(255u8);
        round(Some(55u64));
        round(None::<u64>);
        round(true);
        round(false);
        round(String::from("한글\0bytes"));
        for x in [Trust::Executable, Trust::ShapeOnly, Trust::Unsafe] {
            round(x);
        }
        for x in [Side::Left, Side::Right] {
            round(x);
        }
        for x in [
            IconSet::Nerd,
            IconSet::Light,
            IconSet::Unicode,
            IconSet::Ascii,
        ] {
            round(x);
        }
        for x in [When::Needed, When::Always] {
            round(x);
        }
        for x in [Keep::Start, Keep::End] {
            round(x);
        }
        for x in [Shape::Triangle, Shape::Round, Shape::Slant, Shape::Flat] {
            round(x);
        }
        for x in [FillKind::Space, FillKind::Dot, FillKind::Line] {
            round(x);
        }
        for x in [Mode::Plain, Mode::Block] {
            round(x);
        }
        for x in [AnsiSlot::Default, AnsiSlot::Slot(0), AnsiSlot::Slot(15)] {
            round(x);
        }
        for x in [
            Method::None,
            Method::Depth(2),
            Method::Abbrev(3),
            Method::Unique,
            Method::Repo,
            Method::Truncate {
                max: 9,
                keep: Keep::Start,
            },
            Method::Truncate {
                max: 8,
                keep: Keep::End,
            },
        ] {
            round(x);
        }
        for x in [
            NotRun::Disabled,
            NotRun::NotInTrustedLayout,
            NotRun::UnsafeFile {
                key: "command".into(),
            },
        ] {
            round(x);
        }
        round(ExecPolicy::Command {
            argv: vec!["printf".into(), "%s".into()],
            cwd: Some("/a b".into()),
            env_allow: vec!["PATH".into()],
            shell: Some("/bin/sh".into()),
            unsafe_shell: true,
        });
        round(ExecPolicy::Language {
            interpreter: Some("python".into()),
            version_argv: vec!["--version".into()],
            detect_files: vec!["pyproject.toml".into()],
        });
        for x in [
            PaletteWarning::TextContrast { token: 1, milli: 2 },
            PaletteWarning::BlockContrast { token: 3, milli: 4 },
            PaletteWarning::Clipped { token: 5 },
            PaletteWarning::MarkContrast { token: 6, milli: 7 },
            PaletteWarning::BackgroundClipped,
        ] {
            round(x);
        }
        for x in [
            Node::Text("ice".into()),
            Node::Segment {
                seg: 1,
                mode: Mode::Block,
            },
            Node::Field { seg: 2, field: 3 },
            Node::Sep(Shape::Round),
            Node::Head(Shape::Slant),
            Node::Tail(Shape::Flat),
            Node::Fill(FillKind::Dot),
            Node::Icon(4),
            Node::Style(StyleSpec {
                fg: Some(1),
                bg: Some(2),
                attrs: 3,
            }),
            Node::StyleEnd,
            Node::Group { len: 4 },
            Node::GroupEnd,
        ] {
            round(x);
        }
        assert_eq!(read::<bool>(&[2]), Err(Error::Tag));
        assert_eq!(read::<Option<u8>>(&[2]), Err(Error::Tag));
        assert!(read::<Trust>(&[255]).is_err());
        assert!(read::<Side>(&[255]).is_err());
        assert!(read::<IconSet>(&[255]).is_err());
        assert!(read::<When>(&[255]).is_err());
        assert!(read::<Keep>(&[255]).is_err());
        assert!(read::<Shape>(&[255]).is_err());
        assert!(read::<FillKind>(&[255]).is_err());
        assert!(read::<Mode>(&[255]).is_err());
        assert!(read::<AnsiSlot>(&[255]).is_err());
        assert!(read::<AnsiSlot>(&[1, 16]).is_err());
        assert!(read::<Method>(&[255]).is_err());
        assert!(read::<NotRun>(&[255]).is_err());
        assert!(read::<ExecPolicy>(&[255]).is_err());
        assert!(read::<PaletteWarning>(&[255]).is_err());
        assert!(read::<Node>(&[255]).is_err());
        assert!(read::<WidthProfile>(&[0, 2]).is_err());
    }

    // 이것을 실패시키는 것: 할당 예산·길이 검사·UTF-8·u32 변환·인코딩 사전 용량 검사를 빼는 것.
    #[test]
    fn bounds_before_allocation() {
        assert_eq!(read::<Vec<u64>>(&[2, 0, 0, 0, 1]), Err(Error::Limit));
        assert_eq!(read::<String>(&[1, 0, 0, 0, 255]), Err(Error::Utf8));
        assert_eq!(read::<String>(&[2, 0, 0, 0, b'a']), Err(Error::Short));
        assert_eq!(read::<Vec<u64>>(&u32::MAX.to_le_bytes()), Err(Error::Limit));
        let b = bytes(&vec![1u64]);
        assert_eq!(
            Vec::<u64>::get(&mut Reader {
                rest: &b,
                budget: 7,
                segs: 0,
            }),
            Err(Error::Limit)
        );
        let b = bytes(&String::from("abc"));
        assert_eq!(
            String::get(&mut Reader {
                rest: &b,
                budget: 2,
                segs: 0,
            }),
            Err(Error::Limit)
        );
        let mut w = Writer {
            bytes: None,
            len: MAX_BYTES,
            error: None,
            segs: usize::MAX,
        };
        1u8.put(&mut w);
        assert_eq!(w.error, Some(Error::Limit));
        let mut w = Writer {
            bytes: None,
            len: 0,
            error: None,
            segs: usize::MAX,
        };
        // On wasm32 every usize fits the wire; native also verifies failed conversion.
        if let Some(too_large) = (u32::MAX as usize).checked_add(1) {
            too_large.put(&mut w);
            assert_eq!(w.error, Some(Error::Limit));
        }
        let mut c = config();
        c.exec_units.push(ExecUnit {
            id: "custom/large".into(),
            policy: ExecPolicy::Language {
                interpreter: Some("a".repeat(MAX_BYTES)),
                version_argv: vec![],
                detect_files: vec![],
            },
            timeout_ms: None,
            cache_ms: None,
            origins: vec![],
            approved_by: vec![],
            shown_at: vec![],
            not_run: Some(NotRun::Disabled),
        });
        assert_eq!(encode_compiled(&c), Err(Error::Limit));
        assert_eq!(decode_compiled(&vec![0; MAX_BYTES + 1]), Err(Error::Limit));
    }

    // 이것을 실패시키는 것: 구획 안의 남는 바이트를 허용하는 것.
    #[test]
    fn codec_reject_trailing_bytes() {
        let mut b = encode_compiled(&config()).unwrap();
        b.push(0);
        assert_eq!(decode_compiled(&b), Err(Error::Shape));
        let spare = [0; 5];
        assert_eq!(
            section::<u32>(&spare, section_sum(&spare), MAX_ALLOC, 0).map(drop),
            Err(Error::Trailing)
        );
    }

    // 이것을 실패시키는 것: 색인이 없는 구획을 머리에서 거부하지 않는 것, plan_front가 정확한 앞부분이 아닌
    // 조각을 받는 것.
    #[test]
    fn head_refuses_no_variants_and_plan_takes_the_exact_front() {
        let mut b = encode_compiled(&config()).unwrap();
        let front = front_len(&b, b.len()).unwrap();
        assert!(plan_front(&b[..front], b.len(), 80).is_ok());
        assert_eq!(
            plan_front(&b[..front - 1], b.len(), 80).err(),
            Some(Error::Shape)
        );
        assert_eq!(
            plan_front(&b[..front + 1], b.len(), 80).err(),
            Some(Error::Shape)
        );
        b[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(front_len(&b, b.len()), Err(Error::Limit));
    }

    // 이것을 실패시키는 것: variant 표의 charge를 빼는 것(남은 예산이 표보다 작아도 도우미가 받는다), 표 charge를
    // 공통부에서 넘겨받은 예산이 아닌 새 예산에서 빼는 것.
    #[test]
    fn the_variant_table_is_charged_to_the_one_budget() {
        let mut c = config();
        c.widths.clear();
        let b = encode_compiled(&c).unwrap();
        let s = parse_sections(&b[..front_len(&b, b.len()).unwrap()], b.len()).unwrap();
        let mut left = s.budget;
        for i in 0..s.variants() {
            let e = s.entry(i);
            left = section::<Vec<CompiledLine>>(
                &b[e.offset..e.offset + e.len],
                e.crc,
                left,
                crate::field::BUILTIN.len() + s.common.custom.len(),
            )
            .unwrap()
            .1;
        }
        left = section::<Vec<String>>(&b[s.names..], s.common.names_crc, left, 0)
            .unwrap()
            .1;
        let run = size_of::<WidthRun>();
        let table = s.variants() * size_of::<Vec<CompiledLine>>();
        assert!(run < table, "{run} {table}");
        let runs = |n| {
            vec![
                WidthRun {
                    from: 0,
                    to: 0,
                    band: None,
                };
                n
            ]
        };
        // These runs leave less than the table needs, though all else fits.
        c.widths = runs(left / run);
        assert_eq!(
            decode_compiled(&encode_compiled(&c).unwrap()),
            Err(Error::Limit)
        );
        c.widths = runs((left - table) / run);
        assert!(decode_compiled(&encode_compiled(&c).unwrap()).is_ok());
    }

    // 이것을 실패시키는 것: Writer의 길이 덧셈 overflow를 wrapping으로 바꾸는 것.
    #[test]
    fn codec_reject_arithmetic_overflow() {
        let mut w = Writer {
            bytes: None,
            len: usize::MAX,
            error: None,
            segs: usize::MAX,
        };
        w.extend_from_slice(&[0]);
        assert_eq!(w.error, Some(Error::Limit));
        assert_eq!(w.len, usize::MAX);
    }

    fn raw_config(c: &CompiledConfig) -> Vec<u8> {
        write_compiled(c, compiled_size(c).unwrap()).unwrap()
    }

    fn rejected(c: &CompiledConfig) {
        assert_eq!(encode_compiled(c), Err(Error::Shape));
        // Bypass encode's validation so decode must enforce the same rule.
        assert_eq!(decode_compiled(&raw_config(c)), Err(Error::Shape));
    }

    // 이것을 실패시키는 것: 한 줄을 거부하거나 왕복 중 레이아웃·렌더 바이트를 바꾸는 것.
    #[test]
    fn one_line_configs_roundtrip_and_render_equally() {
        use crate::color::{palette::Mode, sgr::ColorDepth};
        use crate::field::{BUILTIN, Value};
        use crate::layout::{Inputs, Options};
        use crate::recorder::NoopRecorder;
        use crate::render::{Target, render_prompt};
        use crate::shell_word::Shell;

        for root in [
            "[style]\ntemplate = '{dir}{char}'\n",
            "[layout.line1]\nenabled = false\n",
            "[layout.line2]\nenabled = false\n",
        ] {
            // The S3b load -> merge -> check -> compile pipeline, not a
            // hand-edited CompiledConfig. The built-in narrow template
            // remains two lines, so the same config exercises both sizes.
            let c = crate::config::report::tests::read(root, &[])
                .snapshot
                .expect("one-line config compiles");
            assert_eq!(c.variants[0].len(), 1, "{root}");
            assert_eq!(c.variants[1].len(), 2, "{root}");
            let d = decode_compiled(&encode_compiled(&c).unwrap()).unwrap();
            assert_eq!(d, c);
            let values = vec![Some(Value::new(b"fixture", vec![])); BUILTIN.len()];
            let facts = vec![None; BUILTIN.len()];
            for mode in [Mode::Dark, Mode::Light] {
                for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
                    for width in [49, 60, 120] {
                        let render = |compiled: &CompiledConfig| {
                            render_prompt(
                                &compiled.theme_for(mode),
                                &Inputs {
                                    catalog: BUILTIN,
                                    values: &values,
                                    facts: &facts,
                                    setup: &compiled.setup(),
                                },
                                &Target {
                                    shell,
                                    depth: ColorDepth::TrueColor,
                                    options: Options {
                                        width,
                                        profile: compiled.profile,
                                        icons: compiled.icons,
                                        use_last_column: compiled.use_last_column,
                                    },
                                },
                                &mut NoopRecorder,
                            )
                        };
                        let want = render(&c);
                        assert_eq!(render(&d), want, "{root} {mode:?} {shell:?} {width}");
                        if width >= 60 {
                            assert!(want.upper.is_empty());
                            assert!(!want.left.is_empty());
                        }
                    }
                }
            }
        }
    }

    // 이것을 실패시키는 것: 빈 variant 또는 MAX_LINES를 넘는 variant를 허용하는 것.
    #[test]
    fn variant_line_count_bounds() {
        for count in [0, MAX_LINES + 1] {
            let mut c = config();
            c.variants[0] = vec![c.variants[0][0].clone(); count];
            rejected(&c);
        }
    }

    const COMMAND: &str = "[segment.\"custom/hello\"]\nkind='command'\ncommand=['echo','ok']\n";
    const DRAW_COMMAND: &str = "[layout.line2]\nleft=['custom/hello','char']\n";

    fn runnable_config() -> CompiledConfig {
        let c = crate::config::report::tests::read(&format!("{COMMAND}{DRAW_COMMAND}"), &[])
            .snapshot
            .unwrap();
        assert_eq!(c.exec_units.len(), 1);
        assert_eq!(c.exec_units[0].not_run, None);
        c
    }

    // 이것을 실패시키는 것: Unsafe 실행 키 출처가 있는 유닛을 실행 가능하게 받는 것.
    #[test]
    fn runnable_unit_rejects_unsafe_origin() {
        let mut c = runnable_config();
        c.exec_units[0].origins[0].1.trust = Trust::Unsafe;
        rejected(&c);
    }

    // 이것을 실패시키는 것: 신뢰된 레이아웃의 승인 없이 실행 가능하게 받는 것.
    #[test]
    fn runnable_unit_requires_approval() {
        let mut c = runnable_config();
        c.exec_units[0].approved_by.clear();
        rejected(&c);
    }

    // 이것을 실패시키는 것: 현재 레이아웃에서 보이지 않는 유닛을 실행 가능하게 받는 것.
    #[test]
    fn runnable_unit_requires_shown_location() {
        let mut c = runnable_config();
        c.exec_units[0].shown_at.clear();
        rejected(&c);
    }

    // 이것을 실패시키는 것: id 중복 검사를 지우는 것(같은 id가 둘이면 id 조회가 모호해진다).
    #[test]
    fn test_validate_rejects_duplicate_exec_id() {
        let mut c = runnable_config();
        let twin = c.exec_units[0].clone();
        c.exec_units.push(twin);
        rejected(&c);
    }

    // 이것을 실패시키는 것: namespace 검사를 지우는 것(내장·플러그인 id를 실행 단위로 받는다).
    #[test]
    fn test_validate_rejects_non_custom_namespace() {
        for id in ["git", "dir", "vendor/name"] {
            let mut c = runnable_config();
            c.exec_units[0].id = id.into();
            rejected(&c);
        }
    }

    // 이것을 실패시키는 것: origins 검사를 지우는 것(컴파일러는 `kind` 키 출처를 항상 남긴다).
    #[test]
    fn test_validate_rejects_empty_origins() {
        for not_run in [None, Some(NotRun::Disabled)] {
            let mut c = runnable_config();
            c.exec_units[0].origins.clear();
            c.exec_units[0].not_run = not_run;
            rejected(&c);
        }
    }

    // 이것을 실패시키는 것: `>= bands.len()` 검사를 지우거나 `>`로 바꾸는 것(없는 구간 참조를 실행 가능으로 받는다),
    // UnknownBand 단위까지 거부해 컴파일러가 만든 스냅샷이 되읽히지 않는 것.
    #[test]
    fn unknown_band_reference_is_kept_only_on_a_unit_that_never_runs() {
        let mut c = runnable_config();
        let n = c.bands.len() as u16;
        assert!(n > 0);
        for r in c.exec_units[0].shown_at.iter_mut() {
            r.band = Some(n);
        }
        rejected(&c);
        c.exec_units[0].not_run = Some(NotRun::UnknownBand);
        assert_eq!(decode_compiled(&encode_compiled(&c).unwrap()).unwrap(), c);
        for r in c.exec_units[0].shown_at.iter_mut() {
            r.band = Some(n - 1);
        }
        c.exec_units[0].not_run = None;
        assert_eq!(decode_compiled(&encode_compiled(&c).unwrap()).unwrap(), c);
    }

    // 이것을 실패시키는 것: 거부 사유가 출처에 없는 실행 키를 가리켜도 받는 것.
    #[test]
    fn unsafe_file_reason_requires_origin_key() {
        let mut c = runnable_config();
        c.exec_units[0].not_run = Some(NotRun::UnsafeFile {
            key: "absent".into(),
        });
        rejected(&c);
    }

    // 이것을 실패시키는 것: 실행 여부와 무관하게 소스가 거부하는 ID 문법을 받는 것.
    #[test]
    fn exec_ids_follow_source_grammar() {
        for id in [
            "../../x\x1b]",
            "",
            "custom/Hello",
            "custom/hello-",
            "custom/a/b",
            "file/hello",
            &format!("custom/{}", "a".repeat(33)),
        ] {
            for not_run in [None, Some(NotRun::Disabled)] {
                let mut c = runnable_config();
                c.exec_units[0].id = id.into();
                c.exec_units[0].not_run = not_run;
                rejected(&c);
            }
        }
    }

    // 이것을 실패시키는 것: 리뷰의 조작된 실행 유닛을 encode 또는 raw decode가 허용하는 것.
    #[test]
    fn reviewers_crafted_runnable_unit_is_rejected() {
        let mut c = runnable_config();
        let u = &mut c.exec_units[0];
        u.id = "../../x\x1b]".into();
        for (_, o) in &mut u.origins {
            o.trust = Trust::Unsafe;
        }
        u.approved_by.clear();
        assert_eq!(u.not_run, None);
        rejected(&c);
    }

    // 이것을 실패시키는 것: 소스가 만든 실행 가능·차단 유닛을 거부하거나 허가 정보를 바꾸는 것.
    #[test]
    fn source_exec_permissions_roundtrip() {
        use crate::color::palette::Mode;
        use crate::config::report::{report, tests::builtin};
        use crate::config::source::tests::{files, opened};

        for (root, trust, expected) in [
            (format!("{COMMAND}{DRAW_COMMAND}"), Trust::Executable, None),
            (
                format!("{COMMAND}enabled=false\n{DRAW_COMMAND}"),
                Trust::Executable,
                Some(NotRun::Disabled),
            ),
            (
                COMMAND.into(),
                Trust::Executable,
                Some(NotRun::NotInTrustedLayout),
            ),
            (
                format!("{COMMAND}{DRAW_COMMAND}"),
                Trust::Unsafe,
                Some(NotRun::UnsafeFile { key: "kind".into() }),
            ),
        ] {
            let mut source = opened("root", &root, 1);
            source.trust = trust;
            let c = report(
                vec![builtin(), source],
                &mut files(&[]),
                [0, 3, 0],
                Mode::Dark,
            )
            .snapshot
            .expect("source compiles");
            assert_eq!(c.exec_units[0].not_run, expected);
            assert_eq!(decode_compiled(&encode_compiled(&c).unwrap()).unwrap(), c);
        }
    }

    // 이것을 실패시키는 것: band 이름에 segment ID 문법을 잘못 적용하거나 중복 이름을 받는 것.
    #[test]
    fn band_names_follow_source_table_keys() {
        for (quoted, name) in [
            ("\"\"", ""),
            ("\"Wide band\"", "Wide band"),
            ("\"넓음\"", "넓음"),
            ("\"a/b\"", "a/b"),
            ("\"../x\"", "../x"),
            ("\"\\u001b]\"", "\x1b]"),
        ] {
            let root = format!("[layout.when.{quoted}]\nmin_cols=100\n");
            let mut c = crate::config::report::tests::read(&root, &[])
                .snapshot
                .expect("quoted band name compiles");
            assert!(c.band_names.iter().any(|n| n == name));
            assert_eq!(decode_compiled(&encode_compiled(&c).unwrap()).unwrap(), c);
            c.band_names[1] = c.band_names[0].clone();
            c.widths.clear();
            rejected(&c);
        }
    }

    // 이것을 실패시키는 것: CRC가 맞는 본문의 크기 관계·순서·mask·팔레트·출처 검사를 빼는 것.
    #[test]
    fn compiled_invariants() {
        let base = config();
        let mut bad = Vec::new();
        let mut c = base.clone();
        c.variants.pop();
        bad.push(c);
        let mut c = base.clone();
        c.band_names.clear();
        c.widths.clear();
        bad.push(c);
        let mut c = base.clone();
        c.setup.pop();
        bad.push(c);
        let mut c = base.clone();
        c.palette.tokens.pop();
        bad.push(c);
        let mut c = base.clone();
        c.light_palette.tokens.pop();
        bad.push(c);
        let mut c = base.clone();
        c.band_order.clear();
        bad.push(c);
        let mut c = base.clone();
        c.band_order[0] = u32::MAX as usize;
        bad.push(c);
        let mut c = base.clone();
        c.bands[0].min_cols = Some(100);
        bad.push(c);
        let mut c = base.clone();
        c.collect_mask = u32::MAX;
        bad.push(c);
        let mut c = base.clone();
        c.palette
            .warnings
            .push(PaletteWarning::Clipped { token: 999 });
        bad.push(c);
        let mut c = base.clone();
        c.light_palette.tokens[0].ansi = AnsiSlot::Slot(16);
        bad.push(c);
        let mut c = base.clone();
        c.widths[0].from = 100;
        c.widths[0].to = 0;
        bad.push(c);
        let mut c = base.clone();
        c.widths[0].band = Some("absent".into());
        bad.push(c);
        let mut c = base.clone();
        c.bands = vec![
            Band {
                min_cols: None,
                max_cols: Some(99),
                order: None,
            },
            Band {
                min_cols: None,
                max_cols: Some(49),
                order: None,
            },
        ];
        c.band_order = vec![0, 1];
        c.band_names = vec!["a".into(), "b".into()];
        c.widths.clear();
        c.variants.push(c.variants[0].clone());
        bad.push(c.clone());
        c.band_order = vec![0, 0];
        bad.push(c);
        let mut disjoint = base.clone();
        disjoint.bands = vec![
            Band {
                min_cols: None,
                max_cols: Some(49),
                order: None,
            },
            Band {
                min_cols: Some(100),
                max_cols: Some(149),
                order: None,
            },
        ];
        disjoint.band_names = vec!["a".into(), "b".into()];
        disjoint.widths.clear();
        disjoint.variants.push(disjoint.variants[0].clone());
        disjoint.band_order = vec![0, 0];
        bad.push(disjoint);
        let mut large = base.clone();
        large.bands = vec![base.bands[0]; crate::bands::MAX_BANDS + 1];
        assert_eq!(validate(&large), Err(Error::Shape));
        let mut ordered = base.clone();
        ordered.bands = vec![
            Band {
                min_cols: None,
                max_cols: Some(99),
                order: Some(2),
            },
            Band {
                min_cols: None,
                max_cols: Some(49),
                order: Some(1),
            },
        ];
        ordered.band_names = vec!["a".into(), "b".into()];
        ordered.widths.clear();
        ordered.variants.push(ordered.variants[0].clone());
        ordered.band_order = vec![0, 1];
        bad.push(ordered.clone());
        ordered.band_order = vec![1, 0];
        assert!(validate(&ordered).is_ok());
        let mut crossing = ordered.clone();
        crossing.bands = vec![
            Band {
                min_cols: None,
                max_cols: Some(99),
                order: None,
            },
            Band {
                min_cols: Some(49),
                max_cols: Some(199),
                order: None,
            },
        ];
        bad.push(crossing);
        let origin = Origin {
            source: SourceId(9),
            key_span: crate::config::tree::Span { start: 2, end: 1 },
            span: crate::config::tree::Span { start: 0, end: 1 },
            trust: Trust::ShapeOnly,
        };
        let unit = ExecUnit {
            id: "custom/a".into(),
            policy: ExecPolicy::Language {
                interpreter: None,
                version_argv: vec![],
                detect_files: vec![],
            },
            timeout_ms: Some(9),
            cache_ms: None,
            origins: vec![("key".into(), origin)],
            approved_by: vec![],
            shown_at: vec![],
            not_run: Some(NotRun::Disabled),
        };
        let mut c = base.clone();
        c.exec_units.push(unit);
        bad.push(c.clone());
        c.exec_units[0].origins[0].1.key_span.end = 2;
        c.exec_units[0].origins[0].1.span.start = 3;
        bad.push(c.clone());
        c.exec_units[0].origins.clear();
        c.exec_units[0].shown_at.push(LayoutRef {
            band: None,
            line: 3,
            side: Side::Left,
            origin: None,
        });
        bad.push(c.clone());
        c.exec_units[0].shown_at[0].line = 1;
        c.exec_units[0].shown_at[0].band = Some(c.bands.len() as u16);
        bad.push(c);
        for (i, c) in bad.iter().enumerate() {
            assert!(encode_compiled(c).is_err(), "encode {i}");
            assert!(decode_compiled(&raw_config(c)).is_err(), "decode {i}");
        }
        let mut b = encode_compiled(&base).unwrap();
        b.push(0);
        assert_eq!(decode_compiled(&b), Err(Error::Shape));
        for at in [0, 7, 8, 9] {
            let mut b = encode_compiled(&base).unwrap();
            b[at] ^= 1;
            assert!(decode_compiled(&b).is_err());
        }
    }

    fn with_custom(list: &[(&str, &str)]) -> CompiledConfig {
        let mut c = config();
        c.custom = list
            .iter()
            .map(|(id, text)| CustomText {
                id: (*id).into(),
                text: (*text).into(),
            })
            .collect();
        c
    }

    // 이것을 실패시키는 것: custom 목록 검사 삭제. 정렬 아닌 목록, 중복, custom이 아닌 id, 제어 문자가
    // 든 글, 칸 상한의 4배 바이트를 넘는 글, 개수 상한 초과를 인코드와 디코드 둘 다 거부해야 한다.
    #[test]
    fn custom_list_is_checked_on_both_sides() {
        let ok = with_custom(&[("custom/a", "x"), ("custom/b", "")]);
        assert_eq!(decode_compiled(&encode_compiled(&ok).unwrap()).unwrap(), ok);
        let long = "a".repeat(usize::from(crate::field::CUSTOM_TEXT_CELLS) * 4 + 1);
        for bad in [
            with_custom(&[("custom/b", "x"), ("custom/a", "x")]),
            with_custom(&[("custom/a", "x"), ("custom/a", "y")]),
            with_custom(&[("git", "x")]),
            with_custom(&[("acme/a", "x")]),
            with_custom(&[("custom/a", "e\u{1b}")]),
            with_custom(&[("custom/a", &long)]),
        ] {
            rejected(&bad);
        }
        let many: Vec<(String, &str)> = (0..=crate::config::compile::MAX_CUSTOM_TEXT)
            .map(|i| (alloc::format!("custom/t{i:04}"), "x"))
            .collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), *b)).collect();
        rejected(&with_custom(&refs));
    }

    // 이것을 실패시키는 것: 노드 번호 상한을 `BUILTIN.len()`에 고정하는 것(선언된 custom 번호 거부) 또는
    // 상한 검사를 빼는 것(선언 밖 번호와 custom의 둘째 필드 통과).
    #[test]
    fn node_numbers_follow_the_declared_custom_count() {
        let n = crate::field::BUILTIN.len();
        let line = |seg: usize, field: Option<u16>, segs: usize| {
            let node = match field {
                None => Node::Segment {
                    seg: seg as u16,
                    mode: Mode::Plain,
                },
                Some(field) => Node::Field {
                    seg: seg as u16,
                    field,
                },
            };
            CompiledLine::from_snapshot(vec![node], vec![Span { start: 0, end: 0 }], None, segs)
                .is_some()
        };
        assert!(!line(n, None, n));
        assert!(line(n, None, n + 1));
        assert!(!line(n + 1, None, n + 1));
        assert!(line(n, Some(0), n + 1));
        assert!(!line(n, Some(1), n + 1));
        assert!(!line(n + 1, Some(0), n + 1));
    }

    // 이것을 실패시키는 것: encode가 세그먼트 노드나 필드 노드의 번호를 보지 않는 것(목록에 없는 custom 번호를
    // 쓰는 설정이 인코드되고 디코드에서야 거부된다). 두 노드 종류를 따로 본다.
    #[test]
    fn encode_rejects_node_numbers_past_the_list() {
        for src in ["{custom/a}", "{custom/a.value}"] {
            let mut c = config();
            c.custom = vec![CustomText {
                id: "custom/a".into(),
                text: "x".into(),
            }];
            c.variants[0] =
                crate::template::compile::compile_with(src, crate::field::BUILTIN, &["custom/a"])
                    .unwrap();
            assert!(encode_compiled(&c).is_ok(), "{src}");
            c.custom.clear();
            assert_eq!(encode_compiled(&c), Err(Error::Shape), "{src}");
        }
    }

    // 이것을 실패시키는 것: encode가 transient·vi에도 custom 번호를 허용하는 것(디코드는 COMMON을 내장 번호로만
    // 읽으므로 인코드는 되고 디코드에서 거부되는 비대칭).
    #[test]
    fn transient_and_vi_may_not_name_custom_segments() {
        let custom = |c: &mut CompiledConfig| {
            c.custom = vec![CustomText {
                id: "custom/a".into(),
                text: "x".into(),
            }];
            crate::template::compile::compile_with(
                "{custom/a}",
                crate::field::BUILTIN,
                &["custom/a"],
            )
            .unwrap()
            .remove(0)
        };
        let mut c = config();
        c.transient = custom(&mut c);
        assert_eq!(encode_compiled(&c), Err(Error::Shape));
        let mut c = config();
        c.vi = custom(&mut c);
        assert_eq!(encode_compiled(&c), Err(Error::Shape));
    }

    fn line_bytes(nodes: Vec<Node>, origin: Vec<Span>, fill: Option<usize>) -> Vec<u8> {
        let mut b = bytes(&nodes);
        b.extend(bytes(&origin));
        b.extend(bytes(&fill));
        b
    }
    // 이것을 실패시키는 것: 템플릿 private 복원에서 문자·필드·아이콘·style·중첩·fill 불변식을 생략하는 것.
    #[test]
    fn checked_line_invariants() {
        let seg = Node::Segment {
            seg: 0,
            mode: Mode::Plain,
        };
        let style = Node::Style(StyleSpec {
            fg: Some(0),
            bg: Some(1),
            attrs: 1,
        });
        let mut cases = vec![
            vec![Node::Text("a".repeat(4097))],
            vec![seg.clone(); 4097],
            vec![Node::Style(StyleSpec::default()), Node::StyleEnd],
            vec![Node::Text("bad\x1b".into())],
            vec![Node::Segment {
                seg: u16::MAX,
                mode: Mode::Plain,
            }],
            vec![Node::Field {
                seg: u16::MAX,
                field: 0,
            }],
            vec![Node::Field {
                seg: 0,
                field: u16::MAX,
            }],
            vec![Node::Icon(u16::MAX)],
            vec![
                Node::Style(StyleSpec {
                    attrs: 128,
                    ..Default::default()
                }),
                Node::StyleEnd,
            ],
            vec![
                Node::Style(StyleSpec {
                    fg: Some(u16::MAX),
                    ..Default::default()
                }),
                Node::StyleEnd,
            ],
            vec![Node::StyleEnd],
            vec![style.clone()],
            vec![Node::GroupEnd],
            vec![Node::Group { len: u32::MAX }, seg.clone(), Node::GroupEnd],
            vec![Node::Group { len: 1 }, Node::GroupEnd],
            vec![Node::Group { len: 0 }],
            vec![Node::Group { len: 2 }, seg.clone(), Node::StyleEnd],
            vec![style.clone(), seg.clone(), Node::GroupEnd],
            vec![style.clone(), Node::Fill(FillKind::Space), Node::StyleEnd],
            vec![Node::Fill(FillKind::Space), Node::Fill(FillKind::Dot)],
        ];
        // Shared end target makes a style end incorrectly popping a group
        // independent of the final GroupEnd check.
        cases.push(vec![
            Node::Group { len: 4 },
            Node::Group { len: 3 },
            seg.clone(),
            Node::StyleEnd,
            Node::GroupEnd,
        ]);
        let nested_fill = vec![style.clone(), Node::Fill(FillKind::Space), Node::StyleEnd];
        assert!(
            read::<CompiledLine>(&line_bytes(
                nested_fill,
                vec![Span { start: 0, end: 1 }; 3],
                Some(1)
            ))
            .is_err()
        );
        let two_fills = vec![Node::Fill(FillKind::Space), Node::Fill(FillKind::Dot)];
        assert!(
            read::<CompiledLine>(&line_bytes(
                two_fills,
                vec![Span { start: 0, end: 1 }; 2],
                Some(1)
            ))
            .is_err()
        );
        let mut deep = vec![style; 9];
        deep.push(seg.clone());
        deep.extend(vec![Node::StyleEnd; 9]);
        cases.push(deep);
        // Crossing groups: both targets are GroupEnd, but stack order is wrong.
        cases.push(vec![
            Node::Group { len: 3 },
            Node::Group { len: 3 },
            seg.clone(),
            Node::GroupEnd,
            Node::GroupEnd,
        ]);
        for (i, n) in cases.into_iter().enumerate() {
            let origin = vec![Span { start: 0, end: 1 }; n.len()];
            assert!(
                read::<CompiledLine>(&line_bytes(n, origin, None)).is_err(),
                "{i}"
            );
        }
        assert!(read::<CompiledLine>(&line_bytes(vec![seg.clone()], vec![], None)).is_err());
        assert!(
            read::<CompiledLine>(&line_bytes(
                vec![seg.clone()],
                vec![Span { start: 2, end: 1 }],
                None
            ))
            .is_err()
        );
        assert!(
            read::<CompiledLine>(&line_bytes(
                vec![seg],
                vec![Span { start: 0, end: 1 }],
                Some(0)
            ))
            .is_err()
        );
        assert!(
            read::<CompiledLine>(&line_bytes(
                vec![Node::Fill(FillKind::Space)],
                vec![Span { start: 0, end: 1 }],
                None
            ))
            .is_err()
        );
        assert!(
            read::<CompiledLine>(&line_bytes(
                vec![Node::Icon(0)],
                vec![Span {
                    start: 0,
                    end: 4097
                }],
                None
            ))
            .is_err()
        );
        let src = format!(
            "{}{{@group}}{{char}}{{@end}}{}",
            "{@style:bold}".repeat(7),
            "{@end}".repeat(7)
        );
        round(
            crate::template::compile::compile(&src, crate::field::BUILTIN)
                .unwrap()
                .remove(0),
        );
    }

    // 이것을 실패시키는 것: 절단된 고정 폭/본문을 받아들이거나 입력을 인덱스로 바로 써 패닉을 일으키는 것.
    #[test]
    fn every_truncation_and_bounded_arbitrary_corpus() {
        let b = encode_compiled(&config()).unwrap();
        for end in 0..b.len() {
            assert!(decode_compiled(&b[..end]).is_err(), "{end}");
        }
        let mut seed = 0x12345678u32;
        for n in 0..2048 {
            let mut b = vec![0; n % 513];
            for x in &mut b {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *x = seed as u8;
            }
            let _ = decode_compiled(&b);
        }
        // Valid prefix/mostly valid shape reaches much deeper than random magic bytes.
        for i in 10..b.len() {
            let mut changed = b.clone();
            changed[i] ^= 255;
            let _ = decode_compiled(&changed);
        }
    }
}

#[cfg(test)]
mod band_boundary {
    use super::super::*;
    // 이것을 실패시키는 것: 4096 상한·포함 숲의 자식 우선순위·분리된 부모 pop을 잘못 검사하는 것.
    #[test]
    fn maximum_band_forest() {
        let mut c = crate::config::report::tests::read("", &[])
            .snapshot
            .unwrap();
        let n = crate::bands::MAX_BANDS;
        c.bands = (0..n)
            .map(|i| Band {
                min_cols: Some(i as u16),
                max_cols: Some(10000),
                order: None,
            })
            .collect();
        c.band_names = (0..n).map(|i| alloc::format!("b{i}")).collect();
        c.band_order = (0..n).rev().collect();
        c.variants = alloc::vec![c.variants[0].clone();n+1];
        c.widths.clear();
        let b = encode_compiled(&c).unwrap();
        assert_eq!(decode_compiled(&b).unwrap(), c);
        c.band_order.swap(0, 1);
        assert!(validate(&c).is_err());
        c.band_order.swap(0, 1);
        c.bands.push(c.bands[0]);
        c.band_names.push("too-many".into());
        c.band_order.push(n);
        c.variants.push(c.variants[0].clone());
        assert_eq!(validate(&c), Err(Error::Shape));
        c.bands = (0..n)
            .map(|i| Band {
                min_cols: Some(i as u16),
                max_cols: Some(i as u16),
                order: None,
            })
            .collect();
        c.band_names.pop();
        c.band_order = (0..n).collect();
        c.variants.pop();
        assert!(validate(&c).is_ok());
    }
}
