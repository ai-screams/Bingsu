//! Git display, hostile fields and collected directory facts use the real renderer.
use bingsu_core::{
    collection::{
        self,
        path_facts::{PathFactInput, PathQuery, SiblingSet},
        response::Completed,
        wire::{Binding, BuildId, EndReason, M3B_REQUEST_ID, ProtocolError, Update},
    },
    envelope::Envelope,
    field::{self, Field, FieldValue, Value, ValueState},
    icons::IconSet,
    layout::{self, Inputs, Options, SegmentSetup, When},
    recorder::NoopRecorder,
    shell_values::{self, Collected, format_git},
    shorten::{Anchor, Method, PathFacts, ShortenRequest, Source, run_builtin},
    snapshot::{self, Identity},
    template::compile::compile,
    width::{WidthProfile, str_width},
};

pub const COUNTS: [&str; 7] = [
    "staged",
    "modified",
    "untracked",
    "conflicted",
    "ahead",
    "behind",
    "stash",
];
pub const CASES: [&str; 19] = [
    "no-repo",
    "unborn",
    "unborn-pending",
    "detached",
    "rebase",
    "merge",
    "cherry-pick",
    "revert",
    "bisect",
    "counts",
    "pending",
    "saturated",
    "filtered",
    "clean",
    "partial",
    "filtered-pending",
    "filtered-zero",
    "filtered-unknown-count",
    "filtered-unknown-zero",
];
pub fn set(v: &mut Value, name: &str, f: Field) {
    v.fields[field::BUILTIN[3].field_index(name).unwrap()] = f;
}
fn count(n: u32, saturated: bool) -> Field {
    Field::known(FieldValue::Count { n, saturated })
}
pub fn git_value(case: &str) -> Value {
    let mut v = Value::new(
        b"WORKER DISPLAY MUST NOT APPEAR",
        vec![Field::ABSENT; field::BUILTIN[3].fields.len()],
    );
    set(
        &mut v,
        "branch",
        Field::text(b"main", 256, WidthProfile::DEFAULT),
    );
    for name in ["detached", "filtered", "no_repo", "partial"] {
        set(&mut v, name, Field::known(FieldValue::Bool(false)));
    }
    set(&mut v, "stage", Field::text(b"D", 1, WidthProfile::DEFAULT));
    for name in COUNTS {
        set(&mut v, name, count(0, false));
    }
    match case {
        "no-repo" => return collection::git::no_repo(),
        "unborn" | "unborn-pending" => {
            // Owned stage A proves the missing ref: both head fields are Absent.
            set(&mut v, "branch", Field::ABSENT);
            if case == "unborn-pending" {
                for name in COUNTS {
                    set(&mut v, name, Field::PENDING);
                }
                set(&mut v, "stage", Field::text(b"A", 1, WidthProfile::DEFAULT));
                set(&mut v, "partial", Field::known(FieldValue::Bool(true)));
            }
        }
        "detached" => {
            set(&mut v, "branch", Field::ABSENT);
            set(&mut v, "detached", Field::known(FieldValue::Bool(true)));
            set(
                &mut v,
                "commit",
                Field::text(b"012345abcdef", 16, WidthProfile::DEFAULT),
            );
        }
        "rebase" | "merge" | "cherry-pick" | "revert" | "bisect" => set(
            &mut v,
            "operation",
            Field::text(case.as_bytes(), 16, WidthProfile::DEFAULT),
        ),
        "counts" | "saturated" => {
            for (i, name) in COUNTS.into_iter().enumerate() {
                set(&mut v, name, count(i as u32 + 1, case == "saturated"));
            }
        }
        "pending" => {
            for name in COUNTS {
                set(&mut v, name, Field::PENDING);
            }
            set(&mut v, "stage", Field::text(b"A", 1, WidthProfile::DEFAULT));
            set(&mut v, "partial", Field::known(FieldValue::Bool(true)));
        }
        "partial" => {
            set(&mut v, "ahead", Field::PENDING);
            set(&mut v, "behind", Field::PENDING);
            set(&mut v, "partial", Field::known(FieldValue::Bool(true)));
        }
        "filtered" | "filtered-pending" | "filtered-zero" => {
            set(
                &mut v,
                "modified",
                match case {
                    "filtered" => count(2, false),
                    "filtered-zero" => count(0, false),
                    _ => Field::PENDING,
                },
            );
            set(&mut v, "filtered", Field::known(FieldValue::Bool(true)));
            set(&mut v, "partial", Field::known(FieldValue::Bool(true)));
        }
        "filtered-unknown-count" | "filtered-unknown-zero" => {
            set(&mut v, "filtered", Field::PENDING);
            set(&mut v, "partial", Field::known(FieldValue::Bool(true)));
            if case == "filtered-unknown-count" {
                set(&mut v, "modified", count(2, false));
                set(&mut v, "untracked", count(5, true));
            }
        }
        "clean" => (),
        _ => panic!("unknown fixture"),
    }
    v
}
pub fn binding() -> Binding {
    Binding {
        build_id: BuildId([7; 32]),
        snapshot: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 3,
            source: [4; 4],
            context: snapshot::context_crc(b"/c", b"/s").unwrap(),
        },
        clock_kind: 1,
        domain: [5; 16],
        resume: 0,
        config: b"/c".to_vec(),
        state: b"/s".to_vec(),
        cwd: b"/home/u/alphabet/leaf".to_vec(),
        mask: 10,
        path_query: PathQuery {
            home_component: Some(1),
            unique: true,
        },
    }
}
pub fn facts() -> PathFactInput {
    PathFactInput {
        repo_component: Some(2),
        in_repo: Some(true),
        readonly: Some(true),
        siblings: vec![SiblingSet {
            component: 2,
            complete: true,
            names: vec![b"alpine".to_vec()],
        }],
        partial: false,
    }
}
pub fn response(v: Value) -> Completed {
    Completed {
        binding: binding(),
        request_id: M3B_REQUEST_ID,
        completed_at_ns: 99,
        reason: EndReason::Complete,
        progress: Default::default(),
        updates: vec![
            Update {
                segment: 3,
                value: Some(v),
                facts: None,
            },
            Update {
                segment: 1,
                value: None,
                facts: Some(facts()),
            },
        ],
    }
}
pub fn envelope() -> Envelope {
    Envelope {
        pwd: Some(binding().cwd),
        home: Some(b"/home/u".to_vec()),
        width: 80,
        ..Default::default()
    }
}
pub fn merged(v: Value, icons: IconSet, profile: WidthProfile) -> Collected {
    let mut c = shell_values::collect(&envelope());
    let r = response(v);
    collection::merge(
        &mut c,
        Some(&r),
        &binding(),
        &binding().cwd,
        Some(b"/home/u"),
    )
    .unwrap();
    if let Some(v) = &mut c.values[3] {
        *v = format_git(v, icons, profile);
    }
    c
}
pub fn hostile_cases() -> Vec<(&'static str, Vec<u8>)> {
    include_str!("../../../tests/hostile/classes.tsv")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let mut c = line.split('\t');
            let name = c.next().unwrap();
            let spec = c.next().unwrap();
            let bytes = if let Some(rest) = spec.strip_prefix("repeat:") {
                let (byte, n) = rest.split_once(':').unwrap();
                vec![u8::from_str_radix(byte, 16).unwrap(); n.parse().unwrap()]
            } else {
                (0..spec.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&spec[i..i + 2], 16).unwrap())
                    .collect()
            };
            (name, bytes)
        })
        .collect()
}
fn draw(
    c: &Collected,
    template: &str,
    width: u16,
    icons: IconSet,
    profile: WidthProfile,
    methods: &[Method],
) -> layout::LaidLine {
    draw_when(c, template, width, icons, profile, methods, When::Always)
}
fn draw_when(
    c: &Collected,
    template: &str,
    width: u16,
    icons: IconSet,
    profile: WidthProfile,
    methods: &[Method],
    when: When,
) -> layout::LaidLine {
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        field::BUILTIN.len()
    ];
    setup[1] = SegmentSetup {
        priority: 900,
        required: true,
        methods,
        when,
    };
    let line = compile(template, field::BUILTIN).unwrap().remove(0);
    layout::layout_line(
        0,
        &line,
        false,
        &Inputs {
            catalog: field::BUILTIN,
            values: &c.values,
            facts: &c.facts,
            setup: &setup,
        },
        &Options {
            width,
            profile,
            icons,
            use_last_column: false,
        },
        &mut NoopRecorder,
    )
}
fn plain(line: &layout::LaidLine) -> String {
    line.left.iter().map(|r| r.text.as_str()).collect()
}

// Killed by reversing count order, rendering exact zero/Absent, or trusting worker text.
#[test]
fn default_git_order_and_zero_hiding() {
    for (icons, prefix, up, down) in [
        (IconSet::Ascii, "", "^", "v"),
        (IconSet::Unicode, "", "⇡", "⇣"),
        (IconSet::Light, "", "⇡", "⇣"),
        (IconSet::Nerd, "\u{e0a0} ", "⇡", "⇣"),
    ] {
        for amb in [1, 2] {
            let p = WidthProfile::new(amb, 2).unwrap();
            assert_eq!(
                bingsu_core::icons::readonly_marker(icons, p),
                if icons == IconSet::Nerd {
                    "\u{f023}"
                } else {
                    "[ro]"
                }
            );
            assert_eq!(
                format_git(&git_value("counts"), icons, p).text(),
                format!("{prefix}main +1 !2 ?3 =4 {up}5 {down}6 $7")
            );
            assert_eq!(
                format_git(&git_value("clean"), icons, p).text(),
                format!("{prefix}main")
            );
            assert_eq!(
                format_git(&git_value("detached"), icons, p).text(),
                format!("{prefix}012345abcdef")
            );
            assert_eq!(format_git(&git_value("unborn"), icons, p).text(), "");
            assert_eq!(format_git(&git_value("no-repo"), icons, p).text(), "");
            for op in ["rebase", "merge", "cherry-pick", "revert", "bisect"] {
                assert_eq!(
                    format_git(&git_value(op), icons, p).text(),
                    format!("{prefix}main {op}")
                );
            }
            let mut v = git_value("clean");
            for name in COUNTS {
                set(&mut v, name, Field::ABSENT);
            }
            assert_eq!(format_git(&v, icons, p).text(), format!("{prefix}main"));
            assert_eq!(merged(git_value("no-repo"), icons, p).values[3], None);
        }
    }
}

// Killed by preserving worker display text in the merged value before formatting.
#[test]
fn merged_git_discards_worker_display_before_formatting() {
    let mut c = shell_values::collect(&envelope());
    let r = response(git_value("counts"));
    collection::merge(
        &mut c,
        Some(&r),
        &binding(),
        &binding().cwd,
        Some(b"/home/u"),
    )
    .unwrap();
    let git = c.values[3].as_ref().unwrap();
    assert_eq!(git.text(), "");
    assert_eq!(git.fields, r.updates[0].value.as_ref().unwrap().fields);
    assert_eq!(
        format_git(git, IconSet::Ascii, WidthProfile::DEFAULT).text(),
        "main +1 !2 ?3 =4 ^5 v6 $7"
    );
}

// Killed by ignoring Pending state, hiding saturated zero, or dropping the approximation mark.
#[test]
fn git_pending_saturation_and_filter_markers() {
    let text = |v: &Value| {
        format_git(v, IconSet::Ascii, WidthProfile::DEFAULT)
            .text()
            .to_owned()
    };
    assert_eq!(text(&git_value("pending")), "main +? !? ?? =? ^? v? $?");
    assert_eq!(text(&git_value("unborn-pending")), "+? !? ?? =? ^? v? $?");
    assert_eq!(
        text(&git_value("saturated")),
        "main +1+ !2+ ?3+ =4+ ^5+ v6+ $7+"
    );
    assert_eq!(text(&git_value("filtered")), "main !2~");
    assert_eq!(text(&git_value("filtered-pending")), "main !?~");
    assert_eq!(text(&git_value("filtered-zero")), "main !0~");
    assert_eq!(text(&git_value("filtered-unknown-count")), "main !2~ ?5+");
    assert_eq!(text(&git_value("filtered-unknown-zero")), "main !0~");
    let mut v = git_value("clean");
    set(
        &mut v,
        "modified",
        Field {
            value: FieldValue::Count {
                n: 999,
                saturated: false,
            },
            state: ValueState::Pending,
        },
    );
    set(&mut v, "staged", count(0, true));
    set(&mut v, "filtered", Field::PENDING);
    assert_eq!(text(&v), "main +0+ !?~");
    set(&mut v, "modified", count(0, false));
    set(&mut v, "filtered", Field::known(FieldValue::Bool(true)));
    assert_eq!(text(&v), "main +0+ !0~");
    set(&mut v, "operation", Field::PENDING);
    assert_eq!(text(&v), "main ? +0+ !0~");
    // Every non-false filter state is conservative, but Absent counts stay hidden.
    for filtered in [
        Field::known(FieldValue::Bool(true)),
        Field::PENDING,
        Field::ABSENT,
        Field {
            value: FieldValue::Bool(false),
            state: ValueState::Pending,
        },
    ] {
        let mut v = git_value("clean");
        set(&mut v, "filtered", filtered);
        for (modified, expected) in [
            (Field::ABSENT, "main"),
            (count(0, false), "main !0~"),
            (count(0, true), "main !0+~"),
            (count(2, false), "main !2~"),
            (count(2, true), "main !2+~"),
            (Field::PENDING, "main !?~"),
        ] {
            set(&mut v, "modified", modified);
            assert_eq!(text(&v), expected);
        }
    }
}

// Killed by hiding direct zero, emitting Bool text, or making any public field unreachable.
#[test]
fn all_git_fields_are_template_addressable() {
    let p = WidthProfile::DEFAULT;
    let mut c = merged(git_value("clean"), IconSet::Ascii, p);
    assert_eq!(field::BUILTIN[3].fields.len(), 15);
    for (i, d) in field::BUILTIN[3].fields.iter().enumerate() {
        let expected = match d.ty {
            field::FieldType::Text { max_cells } => {
                c.values[3].as_mut().unwrap().fields[i] = Field::text(b"x", max_cells, p);
                "x"
            }
            field::FieldType::Count => {
                c.values[3].as_mut().unwrap().fields[i] = count(0, false);
                "0"
            }
            field::FieldType::Bool => {
                c.values[3].as_mut().unwrap().fields[i] = Field::known(FieldValue::Bool(true));
                ""
            }
            _ => unreachable!(),
        };
        assert_eq!(
            plain(&draw(
                &c,
                &format!("{{git.{}}}", d.name),
                80,
                IconSet::Ascii,
                p,
                &[]
            )),
            expected,
            "{}",
            d.name
        );
    }
    let c = merged(git_value("clean"), IconSet::Ascii, p);
    assert_eq!(
        plain(&draw(
            &c,
            "{git.staged}{@group}+{git.staged}{@end}",
            80,
            IconSet::Ascii,
            p,
            &[]
        )),
        "0"
    );
    let c = merged(git_value("pending"), IconSet::Ascii, p);
    assert_eq!(
        plain(&draw(
            &c,
            "{@group}partial{git.partial}{@end}{@group}+{git.staged}{@end}",
            80,
            IconSet::Ascii,
            p,
            &[]
        )),
        "partial+?"
    );
}

// Killed by using raw display text, counting before sanitizing, or ignoring the selected profile.
#[test]
fn hostile_branches_are_sanitized_before_cell_counting() {
    for (name, bytes) in hostile_cases() {
        for amb in [1, 2] {
            let p = WidthProfile::new(amb, 2).unwrap();
            let mut v = git_value("clean");
            set(
                &mut v,
                "branch",
                Field::text(&bytes, 256, WidthProfile::DEFAULT),
            );
            let f = format_git(&v, IconSet::Ascii, p);
            let oracle = Field::text(
                bingsu_core::sanitize::sanitize(&bytes).as_bytes(),
                256,
                WidthProfile::DEFAULT,
            );
            let FieldValue::Text(oracle) = oracle.value else {
                unreachable!()
            };
            let oracle = Field::text(oracle.as_str().as_bytes(), 256, p);
            let mut expected = String::new();
            oracle.write_to(&mut expected);
            assert_eq!(f.text(), expected, "{name}/{amb}");
            assert!(str_width(f.text(), p) <= 256);
            assert!(!f.text().chars().any(bingsu_core::sanitize::is_removed));
        }
    }
    let mut v = git_value("clean");
    set(
        &mut v,
        "branch",
        Field::text("·".repeat(256).as_bytes(), 256, WidthProfile::DEFAULT),
    );
    let p = WidthProfile::new(2, 2).unwrap();
    assert_eq!(str_width(format_git(&v, IconSet::Nerd, p).text(), p), 258);
}

// Killed by using incomplete sibling sets, relabeling hook paths, hiding unknown access,
// or losing the marker in any shortening/overflow path. Oracle is the existing shortener.
#[test]
fn readonly_and_collected_shortening_match_full_input_oracle() {
    for icons in [IconSet::Ascii, IconSet::Unicode, IconSet::Nerd] {
        for amb in [1, 2] {
            let p = WidthProfile::new(amb, 2).unwrap();
            for ro in [None, Some(false), Some(true)] {
                for complete in [false, true] {
                    let mut r = response(git_value("clean"));
                    let f = r.updates[1].facts.as_mut().unwrap();
                    f.readonly = ro;
                    f.siblings[0].complete = complete;
                    let mut c = shell_values::collect(&envelope());
                    collection::merge(
                        &mut c,
                        Some(&r),
                        &binding(),
                        &binding().cwd,
                        Some(b"/home/u"),
                    )
                    .unwrap();
                    let names: &[&[u8]] = &[b"alpine"];
                    let siblings = if complete {
                        vec![Some(names), None]
                    } else {
                        vec![]
                    };
                    let oracle =
                        PathFacts::new(Anchor::Home, &[b"alphabet", b"leaf"], Some(0), &siblings);
                    let prefix = if ro == Some(true) {
                        format!("{} ", bingsu_core::icons::readonly_marker(icons, p))
                    } else {
                        String::new()
                    };
                    assert_eq!(
                        plain(&draw(&c, "{dir}", 80, icons, p, &[])),
                        format!("{prefix}~/alphabet/leaf")
                    );
                    for method in [
                        Method::Repo,
                        Method::Unique,
                        Method::Abbrev(1),
                        Method::Depth(1),
                    ] {
                        let expected = run_builtin(&ShortenRequest {
                            source: Source::Path(&oracle),
                            method,
                            budget: u32::MAX,
                            profile: p,
                        })
                        .unwrap()
                        .text();
                        let prefix = if ro == Some(true) {
                            format!("{} ", bingsu_core::icons::readonly_marker(icons, p))
                        } else {
                            String::new()
                        };
                        assert_eq!(
                            plain(&draw(&c, "{dir}", 80, icons, p, &[method])),
                            format!("{prefix}{expected}")
                        );
                        for width in 0..65 {
                            let line = draw(&c, "{dir}", width, icons, p, &[method]);
                            let text = plain(&line);
                            assert!(
                                str_width(&text, p) <= u32::from(width.max(1)),
                                "{width}: {text}"
                            );
                            if width > 1 && ro == Some(true) && !text.is_empty() && !line.minimal {
                                assert!(text.starts_with(&prefix), "{width}: {text:?}");
                            }
                        }
                    }
                    // No configured shortening method reaches layout's generic
                    // truncation directly; the marker still stays whole.
                    for width in 2..30 {
                        let line = draw(&c, "{dir}", width, icons, p, &[]);
                        let text = plain(&line);
                        assert!(str_width(&text, p) < u32::from(width));
                        if ro == Some(true) && !line.minimal && !text.is_empty() {
                            assert!(
                                text.starts_with(bingsu_core::icons::readonly_marker(icons, p))
                            );
                        }
                    }
                    let readonly = &c.values[1].as_ref().unwrap().fields[2];
                    assert_eq!(
                        readonly,
                        &ro.map_or(Field::PENDING, |b| Field::known(FieldValue::Bool(b)))
                    );
                }
            }
        }
    }
}

// Killed by allowing any envelope builtin, accepting invalid fields, or applying a
// valid update before rejecting a later hostile one. Errors are specific and atomic.
#[test]
fn malicious_updates_cannot_replace_envelope_values() {
    let mut e = envelope();
    e.status = Some(1);
    e.duration_ms = Some(4000);
    e.jobs = Some(2);
    e.host = Some(b"host".to_vec());
    e.venv = Some(b"venv".to_vec());
    for segment in [0, 2, 4, 5, 6, 7, 8] {
        let mut c = shell_values::collect(&e);
        let original = c.values.clone();
        let mut r = response(git_value("counts"));
        r.binding.mask |= 1 << segment;
        r.updates.push(Update {
            segment,
            value: Some(Value::new(
                b"OVERRIDE",
                vec![Field::ABSENT; field::BUILTIN[usize::from(segment)].fields.len()],
            )),
            facts: None,
        });
        assert_eq!(
            collection::merge(
                &mut c,
                Some(&r),
                &r.binding,
                &r.binding.cwd,
                Some(b"/home/u")
            ),
            Err(ProtocolError::Schema)
        );
        assert_eq!(c.values, original);
        assert_eq!(c.facts[1].as_ref().unwrap().readonly(), None);
    }
    let mut c = shell_values::collect(&e);
    let original = c.values[1].clone();
    let mut r = response(git_value("counts"));
    r.updates[1].value = Some(Value::new(
        b"OVERRIDE",
        vec![
            Field::known(FieldValue::Bool(false)),
            Field::text(b"/FORGED", 4096, WidthProfile::DEFAULT),
            Field::known(FieldValue::Bool(false)),
        ],
    ));
    collection::merge(
        &mut c,
        Some(&r),
        &r.binding,
        &r.binding.cwd,
        Some(b"/home/u"),
    )
    .unwrap();
    assert_eq!(
        c.values[1].as_ref().unwrap().fields[1],
        original.unwrap().fields[1]
    );
    assert_eq!(c.facts[1].as_ref().unwrap().display(), "~/alphabet/leaf");
    assert_eq!(c.facts[1].as_ref().unwrap().readonly(), Some(true));
}

// Killed by retaining an earlier readonly observation after the response disappears.
#[test]
fn missing_observations_clear_the_readonly_marker() {
    let mut c = merged(git_value("clean"), IconSet::Ascii, WidthProfile::DEFAULT);
    collection::merge(&mut c, None, &binding(), &binding().cwd, Some(b"/home/u")).unwrap();
    assert_eq!(c.values[1].as_ref().unwrap().fields[2], Field::PENDING);
    assert_eq!(c.facts[1].as_ref().unwrap().readonly(), None);
    assert!(
        !plain(&draw(
            &c,
            "{dir}",
            80,
            IconSet::Ascii,
            WidthProfile::DEFAULT,
            &[]
        ))
        .contains("[ro]")
    );
}

// Killed by weakening the exact merge binding, per-update schema, facts attachment,
// or duplicate checks. A rejected response cannot leave earlier updates applied.
#[test]
fn invalid_merge_is_atomic_and_missing_observations_are_pending() {
    for case in 0..10 {
        let mut c = shell_values::collect(&envelope());
        let original = c.values.clone();
        let mut r = response(git_value("counts"));
        let expected = binding();
        let mut pwd = expected.cwd.clone();
        let mut home: &[u8] = b"/home/u";
        let error = match case {
            0 => {
                r.binding.path_query.unique = false;
                ProtocolError::Schema
            }
            1 => {
                pwd.push(b'x');
                ProtocolError::Schema
            }
            2 => {
                home = b"/home";
                ProtocolError::Schema
            }
            3 => {
                r.updates.push(r.updates[0].clone());
                ProtocolError::Duplicate
            }
            4 => {
                r.updates[0].facts = Some(facts());
                ProtocolError::Schema
            }
            5 => {
                r.updates[1].facts.as_mut().unwrap().siblings[0].component = 99;
                ProtocolError::Schema
            }
            6 => {
                r.updates[0].value.as_mut().unwrap().fields.pop();
                ProtocolError::Schema
            }
            7 => {
                set(
                    r.updates[0].value.as_mut().unwrap(),
                    "commit",
                    Field::text(b"012345abcdef", 16, WidthProfile::DEFAULT),
                );
                ProtocolError::Schema
            }
            8 => {
                r.updates[0].segment = 32;
                ProtocolError::Schema
            }
            _ => {
                r.updates[1].facts.as_mut().unwrap().siblings[0].names = vec![b"x".to_vec(); 257];
                ProtocolError::Budget
            }
        };
        assert_eq!(
            collection::merge(&mut c, Some(&r), &expected, &pwd, Some(home)),
            Err(error),
            "case {case}"
        );
        assert_eq!(c.values, original, "case {case}");
        assert_eq!(c.facts[1].as_ref().unwrap().readonly(), None);
    }
    let mut c = shell_values::collect(&envelope());
    collection::merge(&mut c, None, &binding(), &binding().cwd, Some(b"/home/u")).unwrap();
    assert_eq!(c.values[3], None);
    assert_eq!(c.values[1].as_ref().unwrap().fields[0], Field::PENDING);
    assert_eq!(c.values[1].as_ref().unwrap().fields[2], Field::PENDING);
    // A value-only dir update has the same tri-state access semantics as facts.
    let mut r = response(git_value("clean"));
    r.updates[1].facts = None;
    r.updates[1].value = Some(Value::new(
        b"FORGED",
        vec![
            Field::known(FieldValue::Bool(true)),
            Field::ABSENT,
            Field::known(FieldValue::Bool(true)),
        ],
    ));
    collection::merge(
        &mut c,
        Some(&r),
        &binding(),
        &binding().cwd,
        Some(b"/home/u"),
    )
    .unwrap();
    assert_eq!(c.facts[1].as_ref().unwrap().readonly(), Some(true));
}

// Killed by dropping readonly or treating Some(false)/None as readonly above the cap.
#[test]
fn oversized_readonly_path_keeps_the_marker_without_reading_its_display() {
    let mut c = shell_values::collect(&envelope());
    let name = vec![0xff; 1024];
    let facts = PathFacts::new(Anchor::Root, &vec![name.as_slice(); 64], None, &[]);
    assert!(facts.display_len() > layout::PATH_BYTES_MAX);
    for readonly in [Some(true), Some(false), None] {
        c.facts[1] = Some(facts.clone().with_readonly(readonly));
        for icons in [IconSet::Ascii, IconSet::Unicode, IconSet::Nerd] {
            for amb in [1, 2] {
                let p = WidthProfile::new(amb, 2).unwrap();
                let ellipsis = bingsu_core::width::ellipsis(p, 1);
                let expected = if readonly == Some(true) {
                    format!(
                        "{} {ellipsis}",
                        bingsu_core::icons::readonly_marker(icons, p)
                    )
                } else {
                    ellipsis.to_owned()
                };
                assert_eq!(
                    plain(&draw(&c, "{dir}", 80, icons, p, &[Method::Unique])),
                    expected
                );
                for width in 0..12 {
                    let line = draw(&c, "{dir}", width, icons, p, &[]);
                    if !line.minimal {
                        assert_eq!(plain(&line), expected);
                    }
                }
            }
        }
    }
}

// Killed by replacing value-only directory observations with Pending.
#[test]
fn value_only_dir_fields_preserve_observations_and_envelope_path() {
    let p = WidthProfile::DEFAULT;
    for observed in [
        Field::known(FieldValue::Bool(true)),
        Field::known(FieldValue::Bool(false)),
        Field::PENDING,
        Field::ABSENT,
    ] {
        let mut c = merged(git_value("clean"), IconSet::Ascii, p);
        let path = c.values[1].as_ref().unwrap().fields[1].clone();
        let mut r = response(git_value("clean"));
        r.updates[1].facts = None;
        r.updates[1].value = Some(Value::new(
            b"FORGED DISPLAY",
            vec![
                observed.clone(),
                Field::text(b"/forged", 4096, p),
                observed.clone(),
            ],
        ));
        collection::merge(
            &mut c,
            Some(&r),
            &binding(),
            &binding().cwd,
            Some(b"/home/u"),
        )
        .unwrap();
        let dir = c.values[1].as_ref().unwrap();
        assert_eq!(dir.fields, vec![observed.clone(), path, observed.clone()]);
        let readonly = match observed {
            Field {
                value: FieldValue::Bool(b),
                state: ValueState::Known,
            } => Some(b),
            _ => None,
        };
        assert_eq!(c.facts[1].as_ref().unwrap().readonly(), readonly);
        assert_eq!(
            plain(&draw(&c, "{dir}", 80, IconSet::Ascii, p, &[])),
            if readonly == Some(true) {
                "[ro] ~/alphabet/leaf"
            } else {
                "~/alphabet/leaf"
            }
        );
    }
}

// Killed by counting empty segment references as group content or drawing block padding.
#[test]
fn empty_git_display_hides_its_block_and_group_but_keeps_direct_zero() {
    let p = WidthProfile::DEFAULT;
    let c = merged(git_value("unborn"), IconSet::Ascii, p);
    for template in [
        "{git:block}",
        "{@group} {git}{@end}",
        "{@head:triangle}{git:block}{@tail:triangle}",
    ] {
        assert_eq!(plain(&draw(&c, template, 80, IconSet::Ascii, p, &[])), "");
    }
    assert_eq!(
        plain(&draw(&c, "{git.staged}", 80, IconSet::Ascii, p, &[])),
        "0"
    );
}

// Killed by suppressing non-empty segments together with empty git displays.
#[test]
fn non_git_non_empty_display_keeps_its_block_and_group() {
    let p = WidthProfile::DEFAULT;
    let c = shell_values::collect(&envelope());
    for (template, expected) in [
        ("{dir}", "~/alphabet/leaf"),
        ("{dir:block}", " ~/alphabet/leaf "),
        (
            "{@group}before {dir} after{@end}",
            "before ~/alphabet/leaf after",
        ),
        (
            "{@group}before {dir:block} after{@end}",
            "before  ~/alphabet/leaf  after",
        ),
    ] {
        assert_eq!(
            plain(&draw(&c, template, 80, IconSet::Ascii, p, &[])),
            expected
        );
    }
}

// Killed by failing to reserve marker cells before picking a shortening method.
#[test]
fn readonly_marker_cells_participate_in_method_selection() {
    let p = WidthProfile::DEFAULT;
    let c = merged(git_value("clean"), IconSet::Ascii, p);
    // Repo alone fits 16 cells, but its five-cell marker does not. Unique does.
    assert_eq!(
        plain(&draw_when(
            &c,
            "{dir}",
            17,
            IconSet::Ascii,
            p,
            &[Method::Repo, Method::Unique],
            When::Needed
        )),
        "[ro] ~/alph/leaf"
    );
}
