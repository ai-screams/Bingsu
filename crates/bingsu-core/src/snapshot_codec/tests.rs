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
        };
        v.put(&mut w);
        assert_eq!(w.error, None);
        w.bytes.unwrap()
    }
    fn read<T: Wire>(b: &[u8]) -> Result<T, Error> {
        T::get(&mut Reader {
            rest: b,
            budget: MAX_ALLOC,
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
                budget: 7
            }),
            Err(Error::Limit)
        );
        let b = bytes(&String::from("abc"));
        assert_eq!(
            String::get(&mut Reader {
                rest: &b,
                budget: 2
            }),
            Err(Error::Limit)
        );
        let mut w = Writer {
            bytes: None,
            len: MAX_BYTES,
            error: None,
        };
        1u8.put(&mut w);
        assert_eq!(w.error, Some(Error::Limit));
        let mut w = Writer {
            bytes: None,
            len: 0,
            error: None,
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

    fn raw_config(c: &CompiledConfig) -> Vec<u8> {
        let mut b = b"BNGCFG02\x02\0".to_vec();
        b.extend(bytes(c));
        b
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
        c.variants[0].pop();
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
            not_run: None,
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
        c.exec_units[0].shown_at[0].band = Some("absent".into());
        bad.push(c);
        for (i, c) in bad.iter().enumerate() {
            assert!(encode_compiled(c).is_err(), "encode {i}");
            assert!(decode_compiled(&raw_config(c)).is_err(), "decode {i}");
        }
        let mut b = encode_compiled(&base).unwrap();
        b.push(0);
        assert_eq!(decode_compiled(&b), Err(Error::Trailing));
        for at in [0, 7, 8, 9] {
            let mut b = encode_compiled(&base).unwrap();
            b[at] ^= 1;
            assert!(decode_compiled(&b).is_err());
        }
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
