//! `preview::lines` (the setup editor's preview) against the prompt front:
//! the same config, width and values give the bytes the prompt writes for
//! fish, line by line.
use bingsu_core::collection::path_facts::{PathFactInput, PathQuery};
use bingsu_core::collection::response::Completed;
use bingsu_core::collection::selection::worker_mask;
use bingsu_core::collection::wire::{Binding, BuildId, EndReason, M3B_REQUEST_ID, Update};
use bingsu_core::color::palette::{Mode, ResolvedPalette};
use bingsu_core::color::sgr::{ColorDepth, RESET, paint};
use bingsu_core::config::compile::CompiledConfig;
use bingsu_core::emit::emit;
use bingsu_core::envelope;
use bingsu_core::field::{self, Field, FieldValue, Value};
use bingsu_core::front;
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{self, Options, Run, target};
use bingsu_core::layout_view::LayoutView;
use bingsu_core::preview::{PreviewLine, PreviewSide, Request, Sample, lines};
use bingsu_core::shell_word::Shell;
use bingsu_core::snapshot::{self, Identity};
use bingsu_core::status::Status;
use bingsu_core::style::PRESETS;
use bingsu_core::width::WidthProfile;
use bingsu_core_tests::snapshot_fixture::compile;

const HOME: &[u8] = b"/home/u";
const HOST: &[u8] = b"ice-box";
/// A folder with a bidi override and an ESC, a long one that overflows, and
/// one with `..`, which collected folder facts do not anchor at home.
const FOLDERS: [&[u8]; 3] = [
    b"/home/u/src/\xE2\x80\xAEevil\x1b[31m",
    b"/home/u/Works/AiScream/themes/crates/bingsu-core/src/preview",
    b"/home/u/src/../themes",
];
const ICONS: [(IconSet, &str); 4] = [
    (IconSet::Nerd, "nerd"),
    (IconSet::Light, "light"),
    (IconSet::Unicode, "unicode"),
    (IconSet::Ascii, "ascii"),
];
const WIDTHS: [u16; 15] = [0, 1, 2, 3, 5, 8, 12, 20, 40, 59, 60, 61, 80, 120, 200];

/// The fish fields `upper`, `left` and `right` the prompt front writes.
#[derive(Debug, PartialEq, Eq)]
struct Fields {
    upper: Vec<u8>,
    left: Vec<u8>,
    right: Vec<u8>,
}

/// The sample repository, written here from the design (branch `main`, one
/// modified and one untracked file), not taken from the preview.
fn git_value() -> Value {
    let d = &field::BUILTIN[3];
    let mut v = Value::new(b"", vec![Field::ABSENT; d.fields.len()]);
    let mut set = |name, f| v.fields[d.field_index(name).unwrap()] = f;
    set("branch", Field::text(b"main", 256, WidthProfile::DEFAULT));
    set("stage", Field::text(b"D", 1, WidthProfile::DEFAULT));
    for name in ["detached", "filtered", "no_repo", "partial"] {
        set(name, Field::known(FieldValue::Bool(false)));
    }
    for name in [
        "staged",
        "modified",
        "untracked",
        "conflicted",
        "ahead",
        "behind",
        "stash",
    ] {
        let n = u32::from(matches!(name, "modified" | "untracked"));
        set(
            name,
            Field::known(FieldValue::Count {
                n,
                saturated: false,
            }),
        );
    }
    v
}

/// The collection round the preview's samples stand for, for the segments
/// the config's mask asks the workers about.
fn response(mask: u32, pwd: &[u8]) -> Completed {
    let mut updates = Vec::new();
    if mask & (1 << 1) != 0 {
        updates.push(Update {
            segment: 1,
            value: None,
            facts: Some(PathFactInput {
                in_repo: Some(true),
                readonly: Some(false),
                ..PathFactInput::default()
            }),
        });
    }
    if mask & (1 << 3) != 0 {
        updates.push(Update {
            segment: 3,
            value: Some(git_value()),
            facts: None,
        });
    }
    Completed {
        language_queries: Vec::new(),
        languages: Vec::new(),
        binding: Binding {
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
            cwd: pwd.to_vec(),
            mask,
            path_query: PathQuery::for_path(pwd, Some(HOME), false),
        },
        request_id: M3B_REQUEST_ID,
        completed_at_ns: 99,
        reason: EndReason::Complete,
        progress: Default::default(),
        updates,
    }
}

fn front_fields(
    c: &CompiledConfig,
    mode: Mode,
    width: u16,
    depth: ColorDepth,
    pwd: &[u8],
) -> Fields {
    let w = width.to_string();
    let mut args: Vec<&[u8]> = [
        "--ctx",
        "1",
        "--record",
        "B1",
        "--width",
        &w,
        "--runtime-root=1:2:/r",
        "--home=/home/u",
        "--shell",
        "fish",
        "--status",
        "0",
        "--duration-ms",
        "2100",
        "--jobs",
        "1",
    ]
    .iter()
    .map(|s| s.as_bytes())
    .collect();
    args.extend([&b"--pwd"[..], pwd, b"--host", HOST]);
    if depth == ColorDepth::TrueColor {
        args.extend([&b"--colorterm"[..], b"truecolor"]);
    }
    let e = envelope::parse(&args).unwrap();
    let r = response(worker_mask(c, width, false), pwd);
    let mut out = Vec::new();
    front::render_selected_with_values(
        &e,
        Shell::Fish,
        Status::OK_NONE,
        Some(c),
        mode,
        Some(&r),
        &[],
        &mut out,
    );
    assert_eq!(out.pop(), Some(0x1e));
    let el: Vec<&[u8]> = out.split(|&b| b == 0x1f).collect();
    // `B1`, `12`, then left, right, transient left and right, vi insert and
    // command, upper (record::Fields::in_order).
    assert_eq!(&el[..2], [b"B1", b"12"]);
    Fields {
        upper: el[8].to_vec(),
        left: el[2].to_vec(),
        right: el[3].to_vec(),
    }
}

fn palette(c: &CompiledConfig, mode: Mode) -> &ResolvedPalette {
    match mode {
        Mode::Dark => &c.palette,
        Mode::Light => &c.light_palette,
    }
}

/// A side written back through the prompt's `emit` for fish.
fn fish(side: &PreviewSide, p: &ResolvedPalette, depth: ColorDepth) -> Vec<u8> {
    let runs: Vec<Run> = side
        .runs()
        .map(|r| Run {
            text: r.text.into(),
            style: r.style,
        })
        .collect();
    let mut v = Vec::new();
    emit(Shell::Fish, &runs, p, depth, &mut v);
    v
}

fn preview_fields(
    c: &CompiledConfig,
    mode: Mode,
    icons: IconSet,
    width: u16,
    depth: ColorDepth,
    pwd: &[u8],
) -> (Vec<PreviewLine>, Fields) {
    let req = Request {
        mode,
        icons,
        depth,
        width,
        sample: Sample {
            pwd,
            home: Some(HOME),
            host: Some(HOST),
        },
    };
    let l = lines(c, &req);
    let p = palette(c, mode);
    let f = match l.as_slice() {
        [input] => Fields {
            upper: Vec::new(),
            left: fish(&input.left, p, depth),
            right: fish(&input.right, p, depth),
        },
        [upper, input] => Fields {
            upper: fish(&upper.left, p, depth),
            left: fish(&input.left, p, depth),
            right: fish(&input.right, p, depth),
        },
        other => panic!("{} lines", other.len()),
    };
    (l, f)
}

fn preset_config(preset: &str, icons: &str) -> CompiledConfig {
    compile(&format!(
        "icons = \"{icons}\"\n[style]\npreset = \"{preset}\"\n"
    ))
}

/// Checks every line of `c` at every width against the front, and that each
/// run's paint is its style resolved with the mode's palette.
fn same_as_the_prompt(c: &CompiledConfig, what: &str) {
    for mode in [Mode::Dark, Mode::Light] {
        for depth in [ColorDepth::TrueColor, ColorDepth::Ansi256] {
            for w in WIDTHS {
                for pwd in FOLDERS {
                    let (l, got) = preview_fields(c, mode, c.icons, w, depth, pwd);
                    let want = front_fields(c, mode, w, depth, pwd);
                    assert_eq!(got, want, "{what} {mode:?} {depth:?} {w}");
                    // An empty upper field is no line: the shells print none.
                    let n = 1 + usize::from(!want.upper.is_empty());
                    assert_eq!(l.len(), n, "{what} {mode:?} {depth:?} {w}");
                    for line in &l {
                        for r in line.left.runs().chain(line.right.runs()) {
                            assert_eq!(r.paint, paint(r.style, palette(c, mode), depth));
                        }
                    }
                }
            }
        }
    }
}

// 이것을 실패시키는 것: 미리보기가 프롬프트와 다른 변형·팔레트·setup·옵션을 고르는 것(폭으로 band를
// 고르지 않는 것, `MIN_WIDTH`로 넓히는 것, 기본 폭 profile이나 `use_last_column = false`를 박는 것),
// 표본 값을 프롬프트의 값 코드와 다르게 만드는 것(git을 `format_git`에 넣지 않는 것, 폴더 사실을 거두기
// 결과와 다르게 두는 것), 위 줄을 프롬프트가 버리는 폭에서 남기는 것, paint를 모드의 팔레트로 풀지 않는 것.
// 여덟 프리셋 × 네 아이콘 묶음 × 두 모드 × 두 깊이 × 15 폭 × 두 폴더를 fish 바이트로 맞춘다.
#[test]
fn runs_are_the_prompt() {
    for p in PRESETS {
        for (_, icons) in ICONS {
            same_as_the_prompt(
                &preset_config(p.name, icons),
                &format!("{} {icons}", p.name),
            );
        }
    }
}

// 이것을 실패시키는 것: 사용자 text 세그먼트를 그리지 않는 것(프롬프트 front처럼 목록을 늘리지 않는 것),
// 명령 세그먼트에 값을 만드는 것, 설정의 `duration.min`을 무시하는 것, 폭 profile·`use_last_column`을
// 설정에서 읽지 않는 것.
#[test]
fn config_keys_reach_the_preview() {
    // 40 ellipses are 80 cells with `ambiguous = 2`, so the text is cut to its
    // 64 cells (`field::CUSTOM_TEXT_CELLS`) as in the prompt.
    let text = format!(
        "icons = \"nerd\"\n[width]\nambiguous = 2\n[layout]\nuse_last_column = true\n\
        [segment.\"custom/tag\"]\nkind = \"text\"\ntext = \"prod{}\"\n\
        [segment.\"custom/kube\"]\nkind = \"command\"\ncommand = [\"kubectl\"]\n\
        [layout.line1]\nleft = [\"dir\", \"custom/tag\", \"custom/kube\", \"git\"]\nright = [\"duration\"]\n",
        "\u{2026}".repeat(40)
    );
    let c = compile(&text);
    same_as_the_prompt(&c, "keys");
    let (l, _) = preview_fields(
        &c,
        Mode::Dark,
        c.icons,
        200,
        ColorDepth::TrueColor,
        FOLDERS[0],
    );
    let upper = l[0].left.text();
    assert!(upper.contains("prod\u{2026}"), "{upper:?}");
    assert!(upper.matches('\u{2026}').count() < 40, "{upper:?}");
    assert!(upper.contains("2.1s"));
    // The segment's field, drawn alone, is cut the same way.
    let field = compile(&format!(
        "{text}[style]\ntemplate = \"{{custom/tag.value}}{{@nl}}{{char}}\"\n"
    ));
    same_as_the_prompt(&field, "field");
    let (l, _) = preview_fields(
        &field,
        Mode::Dark,
        c.icons,
        200,
        ColorDepth::TrueColor,
        FOLDERS[0],
    );
    assert!(
        l[0].left.text().starts_with("prod\u{2026}"),
        "{:?}",
        l[0].left.text()
    );
    let slow = compile(&format!("{text}[segment.duration]\nmin = \"5s\"\n"));
    same_as_the_prompt(&slow, "min");
    let (l, _) = preview_fields(
        &slow,
        Mode::Dark,
        c.icons,
        80,
        ColorDepth::TrueColor,
        FOLDERS[0],
    );
    assert!(!l[0].left.text().contains("2.1s"));
}

/// The cells a line may use at `w` for `c`.
fn line_target(c: &CompiledConfig, w: u16) -> u32 {
    let s = c.shared();
    target(&Options {
        width: w,
        profile: s.profile,
        icons: s.icons,
        use_last_column: s.use_last_column,
    })
}

// 이것을 실패시키는 것: 거두기 한 번이 알리는 폴더 사실(저장소 안, 읽기 전용 아님)을 표본에 넣지 않는 것. 묶음이
// `dir.in_repo`를 읽는 template에서만 보이고, 읽기 전용 표시는 `dir`에 자물쇠를 붙인다.
#[test]
fn folder_facts_reach_the_preview() {
    let c = compile(
        "icons = \"ascii\"\n[style]\ntemplate = \"{@group}REPO {dir.in_repo}{@end}{dir}{@nl}{char}\"\n",
    );
    same_as_the_prompt(&c, "facts");
    let (l, _) = preview_fields(
        &c,
        Mode::Dark,
        IconSet::Ascii,
        80,
        ColorDepth::TrueColor,
        FOLDERS[1],
    );
    assert!(
        l[0].left.text().starts_with("REPO ~/Works/"),
        "{:?}",
        l[0].left.text()
    );
}

// 이것을 실패시키는 것: 오른쪽 시작 칸을 줄의 목표 폭(`layout::target`, 마지막 칸을 비움)이 아닌 터미널 폭에서
// 빼는 것, 칸 수를 run마다 따로 세는 것, 왼쪽이 오른쪽에 겹치는 것, 채움이 있는 위 줄(60칸부터)이 목표 폭을
// 다 채우지 않는 것.
#[test]
fn the_right_side_ends_on_the_last_cell() {
    for (last, text) in [(false, ""), (true, "[layout]\nuse_last_column = true\n")] {
        for p in PRESETS {
            let c = compile(&format!(
                "icons = \"nerd\"\n[style]\npreset = \"{}\"\n{text}",
                p.name
            ));
            for w in [2u16, 12, 40, 60, 80, 200] {
                let (l, _) = preview_fields(
                    &c,
                    Mode::Dark,
                    IconSet::Nerd,
                    w,
                    ColorDepth::TrueColor,
                    FOLDERS[1],
                );
                let end = line_target(&c, w);
                assert_eq!(end, u32::from(w) - u32::from(!last));
                let (input, upper) = l.split_last().unwrap();
                assert_eq!(input.right_at + input.right.width(), end, "{} {w}", p.name);
                assert!(input.left.width() <= input.right_at, "{} {w}", p.name);
                for side in [&input.left, &input.right] {
                    let cells: u32 = side.cells().map(|c| u32::from(c.width)).sum();
                    assert_eq!(cells, side.width());
                }
                // A line with a fill spans the target; the narrow band's upper
                // line has none.
                if let Some(u) = upper.first() {
                    assert!(u.left.width() <= end, "{} {w}", p.name);
                    if w >= 60 {
                        assert_eq!(u.left.width(), end, "{} {w}", p.name);
                    }
                    assert!(u.right.is_empty());
                }
            }
        }
    }
}

// 이것을 실패시키는 것: 오른쪽 쪽의 keycap(`#` + VS16)과 ZWJ 이모지를 설정의 emoji 폭(1, 2)이 아닌 폭으로 세는 것
// (오른쪽이 layout이 잰 폭과 달라 줄의 마지막 칸에서 끝나지 않는다), 칸 위치가 쪽의 폭에서 끝나지 않는 것, 프롬프트와
// 다른 바이트를 내는 것.
#[test]
fn emoji_on_the_right_side_ends_on_the_last_cell() {
    for emoji in [1u8, 2] {
        let c = compile(&format!(
            "icons = \"unicode\"\n[width]\nemoji = {emoji}\n\
             [segment.\"custom/key\"]\nkind = \"text\"\ntext = \"#\u{FE0F}\"\n\
             [segment.\"custom/fam\"]\nkind = \"text\"\ntext = \"\u{1F469}\u{200D}\u{1F469}\"\n\
             [layout.line2]\nleft = [\"char\"]\nright = [\"custom/key\", \"custom/fam\"]\n"
        ));
        same_as_the_prompt(&c, &format!("emoji {emoji}"));
        for w in [60u16, 80, 120] {
            let (l, _) = preview_fields(
                &c,
                Mode::Dark,
                IconSet::Unicode,
                w,
                ColorDepth::TrueColor,
                FOLDERS[1],
            );
            let input = l.last().unwrap();
            let right = &input.right;
            assert!(
                right.text().contains("#\u{FE0F}")
                    && right.text().contains("\u{1F469}\u{200D}\u{1F469}"),
                "{emoji} {w}: {:?}",
                right.text()
            );
            let runs: Vec<Run> = right
                .runs()
                .map(|r| Run {
                    text: r.text.into(),
                    style: r.style,
                })
                .collect();
            assert_eq!(
                right.width(),
                layout::runs_width(&runs, c.profile),
                "{emoji} {w}"
            );
            let last = right.cells().last().unwrap();
            assert_eq!(
                last.at + u32::from(last.width),
                right.width(),
                "{emoji} {w}"
            );
            assert_eq!(
                input.right_at + right.width(),
                line_target(&c, w),
                "{emoji} {w}"
            );
            assert!(input.left.width() <= input.right_at, "{emoji} {w}");
            let wide: Vec<u8> = right
                .cells()
                .filter(|x| x.text.contains('\u{FE0F}') || x.text.contains('\u{200D}'))
                .map(|x| x.width)
                .collect();
            assert_eq!(wide, [emoji, emoji], "{emoji} {w}");
        }
    }
}

// 이것을 실패시키는 것: 표본 값이 설계와 다른 것(host, git `main`과 수정·새 파일 1, 2.1 s, 작업 1, 시간 없음),
// 폴더 이름의 제어 글자·bidi가 run 글자에 남는 것, 절대 경로가 아닌 폴더를 그리는 것, 아이콘 인자를 무시하는 것,
// 줄 끝 SGR reset이 빠지는 것.
#[test]
fn samples_follow_the_design() {
    let c = preset_config("lean", "ascii");
    let (l, f) = preview_fields(
        &c,
        Mode::Dark,
        IconSet::Ascii,
        120,
        ColorDepth::TrueColor,
        FOLDERS[0],
    );
    let hostile = l[0].left.text();
    let upper = hostile;
    for want in ["ice-box", "~/src/", "main", "2.1s"] {
        assert!(upper.contains(want), "{want}: {upper:?}");
    }
    assert!(!upper.contains("12:34"), "{upper:?}");
    assert!(
        !upper.contains('\u{202E}') && !upper.contains('\x1b'),
        "{upper:?}"
    );
    assert!(f.upper.ends_with(RESET), "{:?}", f.upper);
    // The ascii git line of the design, and one job at the end.
    let (l, _) = preview_fields(
        &c,
        Mode::Dark,
        IconSet::Ascii,
        120,
        ColorDepth::TrueColor,
        FOLDERS[1],
    );
    let upper = l[0].left.text();
    assert!(upper.contains(" main !1 ?1 "), "{upper:?}");
    assert!(upper.ends_with(" 2.1s 1"), "{upper:?}");
    let nerd = lines(
        &c,
        &Request {
            icons: IconSet::Nerd,
            ..request(120, FOLDERS[0])
        },
    );
    assert_ne!(nerd[0].left.text(), hostile);
    let relative = lines(&c, &request(120, b"home/u/src"));
    assert!(
        !relative[0].left.text().contains("src"),
        "{:?}",
        relative[0].left.text()
    );
}

fn request(width: u16, pwd: &[u8]) -> Request<'_> {
    Request {
        mode: Mode::Dark,
        icons: IconSet::Ascii,
        depth: ColorDepth::TrueColor,
        width,
        sample: Sample {
            pwd,
            home: Some(HOME),
            host: Some(HOST),
        },
    }
}

// 이것을 실패시키는 것: dark와 light에서 같은 paint를 내는 것(편집판의 칸 비교가 모드 전환을 놓친다), 모드에
// 따라 token 스타일이나 글자가 바뀌는 것(같은 배치에서 색만 달라야 한다), 모드를 박은 설정(`colors.mode`)이 두
// 모드에 다른 팔레트를 갖는 것.
#[test]
fn a_mode_switch_changes_paint_only() {
    let c = preset_config("capsule", "nerd");
    let at = |mode| {
        lines(
            &c,
            &Request {
                mode,
                icons: IconSet::Nerd,
                ..request(80, FOLDERS[0])
            },
        )
    };
    let (dark, light) = (at(Mode::Dark), at(Mode::Light));
    assert_eq!(dark.len(), light.len());
    let mut changed = 0;
    for (d, l) in dark.iter().zip(&light) {
        for (a, b) in d.left.runs().zip(l.left.runs()) {
            assert_eq!((a.text, a.cells, a.style), (b.text, b.cells, b.style));
            changed += usize::from(a.paint != b.paint);
        }
    }
    assert!(changed > 0);
    // An explicit mode compiles one palette for both (`Request::mode`).
    let light =
        compile("icons = \"nerd\"\n[style]\npreset = \"capsule\"\n[colors]\nmode = \"light\"\n");
    let at = |mode| {
        lines(
            &light,
            &Request {
                mode,
                icons: IconSet::Nerd,
                ..request(80, FOLDERS[0])
            },
        )
    };
    assert_eq!(at(Mode::Dark), at(Mode::Light));
}

// 이것을 실패시키는 것: 프롬프트 envelope의 `--pwd`·`--host` 규칙(절대 경로, `PATH_BYTES_MAX` 이하, 빈 host는 없음)을
// 미리보기 표본에 쓰지 않는 것. 너무 긴 host는 프롬프트에서 값이 없으므로 64칸으로 잘려 나오면 안 된다.
#[test]
fn machine_values_follow_the_envelope_rules() {
    let c = preset_config("lean", "ascii");
    let upper = |pwd: &[u8], host: Option<&[u8]>| {
        let r = Request {
            sample: Sample {
                pwd,
                home: Some(HOME),
                host,
            },
            ..request(200, pwd)
        };
        lines(&c, &r)[0].left.text().to_string()
    };
    let plain = upper(FOLDERS[1], Some(HOST));
    assert!(plain.starts_with("ice-box ~/Works/"), "{plain:?}");
    let no_host = upper(FOLDERS[1], None);
    assert!(no_host.starts_with("~/Works/"), "{no_host:?}");
    assert_eq!(upper(FOLDERS[1], Some(b"")), no_host);
    let long_host = vec![b'h'; layout::PATH_BYTES_MAX + 1];
    assert_eq!(upper(FOLDERS[1], Some(&long_host)), no_host);
    assert!(upper(b"home/u/src", Some(HOST)).starts_with("ice-box main"));
    let mut long = b"/home/u/".to_vec();
    long.resize(layout::PATH_BYTES_MAX + 1, b'a');
    assert!(upper(&long, Some(HOST)).starts_with("ice-box main"));
}
