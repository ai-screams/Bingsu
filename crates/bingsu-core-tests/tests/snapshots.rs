//! Layer 2 render snapshots (spec section 7): fixed inputs (presets, color
//! depths, a width band) drawn for each shell and compared byte for byte with tests/golden/render/snapshots/
//! (BINGSU_UPDATE_GOLDEN=1 rewrites them; review the diff), and the visible
//! text equal across the three shells, the vi fields included.
use bingsu_core::bands::{Band, order_bands};
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{RenderedPrompt, Target, Theme, render_prompt};
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, Method, PathFacts};
use bingsu_core::style::{LineLayout, StyleOptions, generate, preset};
use bingsu_core::template::compile::compile;
use bingsu_core::width::WidthProfile;
use bingsu_core_tests::{parse_field, parse_readline};

/// One snapshot input: a preset at a color depth, optionally with a band
/// (at most 50 columns) that switches to a one-line lean layout.
#[derive(Clone, Copy, Debug)]
struct Case {
    name: &'static str,
    preset: &'static str,
    depth: ColorDepth,
    banded: bool,
}

const CASES: [Case; 5] = [
    Case {
        name: "lean",
        preset: "lean",
        depth: ColorDepth::TrueColor,
        banded: false,
    },
    Case {
        name: "triangle",
        preset: "triangle",
        depth: ColorDepth::TrueColor,
        banded: false,
    },
    Case {
        name: "triangle_256",
        preset: "triangle",
        depth: ColorDepth::Ansi256,
        banded: false,
    },
    Case {
        name: "lean_16",
        preset: "lean",
        depth: ColorDepth::Ansi16,
        banded: false,
    },
    Case {
        name: "banded",
        preset: "triangle",
        depth: ColorDepth::TrueColor,
        banded: true,
    },
];

/// The band of the banded case and the width each case is snapshotted at
/// (40 is inside the band, 60 outside).
const BAND: Band = Band {
    min_cols: None,
    max_cols: Some(50),
    order: None,
};

fn snapshot_width(c: &Case) -> u16 {
    if c.banded { 40 } else { 60 }
}

const SHELLS: [Shell; 3] = [Shell::Zsh, Shell::Bash, Shell::Fish];

fn render(shell: Shell, c: &Case, width: u16) -> RenderedPrompt {
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    let v = |id: &str, text: &[u8], set: &[(&str, FieldValue)]| {
        let d = segment(id).unwrap();
        let mut f = vec![Field::ABSENT; d.fields.len()];
        for (n, x) in set {
            f[d.field_index(n).unwrap()] = Field::known(x.clone());
        }
        Some(Value::new(text, f))
    };
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
    values[i("char")] = v("char", b"", &[("failed", FieldValue::Bool(true))]);
    values[i("dir")] = v("dir", b"", &[]);
    let steps: [&[u8]; 4] = [b"Works", b"AiScream", b"themes", b"50% done"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, Some(2), &[]));
    values[i("git")] = v("git", b"main", &[]);
    values[i("status")] = v("status", b"1", &[]);
    values[i("time")] = v("time", b"12:34", &[]);
    setup[i("char")].required = true;
    setup[i("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods: &[Method::Repo, Method::Depth(1)],
        when: When::Needed,
    };
    setup[i("time")].priority = 1;
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let style = |name: &str, lines: &[LineLayout<'_>]| {
        let t = generate(preset(name).unwrap(), &StyleOptions::default(), lines).unwrap();
        compile(&t, BUILTIN).unwrap()
    };
    // The input line has a right side too (`status`, also on the line
    // above), so the right field is not empty.
    let mut variants = vec![style(
        c.preset,
        &[
            LineLayout {
                left: &["dir", "git"],
                right: &["status", "time"],
            },
            LineLayout {
                left: &["char"],
                right: &["status"],
            },
        ],
    )];
    let bands: &[Band] = if c.banded {
        variants.push(style(
            "lean",
            &[LineLayout {
                left: &["dir", "char"],
                right: &["time"],
            }],
        ));
        &[BAND]
    } else {
        &[]
    };
    let band_order = order_bands(bands).unwrap();
    let tr = compile("{char}{@fill}{status}", BUILTIN).unwrap().remove(0);
    let vi = compile("{char}", BUILTIN).unwrap().remove(0);
    let pal = resolve_palette(&PaletteInput {
        mode: Mode::Dark,
        knobs: Knobs::default(),
        overrides: &[],
        roles: &[],
    })
    .unwrap();
    let theme = Theme {
        variants: &variants,
        bands,
        band_order: &band_order,
        transient: &tr,
        vi: &vi,
        palette: &pal,
    };
    let o = Options {
        width,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    };
    render_prompt(
        &theme,
        &inputs,
        &Target {
            shell,
            depth: c.depth,
            options: o,
        },
        &mut NoopRecorder,
    )
}

/// Compares `bytes` with the committed golden file `name`, or rewrites it
/// when BINGSU_UPDATE_GOLDEN=1. A missing file fails: no silent skip.
fn check_golden(name: &str, bytes: &[u8]) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/render/snapshots")
        .join(name);
    if std::env::var_os("BINGSU_UPDATE_GOLDEN").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("golden dir");
        std::fs::write(&path, bytes).expect("write golden");
        return;
    }
    let want = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (BINGSU_UPDATE_GOLDEN=1 creates it)",
            path.display()
        )
    });
    assert!(want == bytes, "{name} differs from {}", path.display());
}

fn all(r: &RenderedPrompt) -> [(&'static str, &[u8]); 7] {
    [
        ("upper", &r.upper),
        ("left", &r.left),
        ("right", &r.right),
        ("transient_left", &r.transient_left),
        ("transient_right", &r.transient_right),
        ("vi_insert", &r.vi_insert),
        ("vi_command", &r.vi_command),
    ]
}

/// What the terminal shows, read with the shell's field grammar; bash vi
/// fields are readline strings and are decoded first.
fn visible(shell: Shell, name: &str, b: &[u8]) -> String {
    let field = if shell == Shell::Bash && name.starts_with("vi_") {
        parse_readline(b).unwrap_or_else(|e| panic!("{name}: {e}"))
    } else {
        b.to_vec()
    };
    parse_field(shell, &field).unwrap_or_else(|e| panic!("{shell:?} {name}: {e}"))
}

// 이것을 실패시키는 것: 셸별 출력 바이트가 바뀌는 것(리뷰가 스냅샷 차이를 본다), golden 파일이 없는 것.
#[test]
fn shell_outputs() {
    for shell in SHELLS {
        for c in &CASES {
            let r = render(shell, c, snapshot_width(c));
            let mut bytes = Vec::new();
            for (n, b) in all(&r) {
                bytes.extend_from_slice(n.as_bytes());
                bytes.extend_from_slice(b": ");
                bytes.extend_from_slice(b);
                bytes.push(b'\n');
            }
            check_golden(&format!("{}_{}.bin", shell.as_str(), c.name), &bytes);
        }
    }
}

// 이것을 실패시키는 것: 셸 출력에 Target의 색 깊이를 넘기지 않는 것(필드 하나라도, bash vi의 readline
// 문자열 포함), 필드를 비우는 것(구간 사례의 윗줄만 빈다). 256색은 `38;5;`만, 16색은 둘 다 없이 쓴다.
#[test]
fn color_depth_reaches_every_field() {
    for shell in SHELLS {
        for c in &CASES {
            let r = render(shell, c, snapshot_width(c));
            // The banded case draws no upper line at 40 columns.
            for (name, b) in all(&r)
                .into_iter()
                .filter(|(n, _)| !(c.banded && *n == "upper"))
            {
                // bash vi fields are readline strings (ESC written `\\e`).
                let b = if shell == Shell::Bash && name.starts_with("vi_") {
                    parse_readline(b).unwrap()
                } else {
                    b.to_vec()
                };
                let has = |pat: &[u8]| b.windows(pat.len()).any(|w| w == pat);
                let (rgb, x256) = (has(b"38;2;"), has(b"38;5;"));
                let ok = match c.depth {
                    ColorDepth::TrueColor => rgb && !x256,
                    ColorDepth::Ansi256 => x256 && !rgb,
                    ColorDepth::Ansi16 => !rgb && !x256 && has(b"\x1b[0;"),
                };
                assert!(
                    ok,
                    "{shell:?} {} {name}: {:?}",
                    c.name,
                    String::from_utf8_lossy(&b)
                );
            }
        }
    }
}

// 이것을 실패시키는 것: 렌더가 폭 구간을 layout에 넘기지 않는 것(구간 안의 폭에서도 두 줄 기본 레이아웃을
// 그림). 구간(50칸 이하) 안에서는 한 줄 lean 변형, 밖에서는 두 줄 기본 레이아웃이다.
#[test]
fn band_picks_the_variant() {
    let banded = &CASES[4];
    assert!(banded.banded);
    for shell in SHELLS {
        let inside = render(shell, banded, 40);
        assert!(inside.upper.is_empty(), "{shell:?}");
        let left = visible(shell, "left", &inside.left);
        assert!(left.contains("50% done"), "{shell:?}: {left:?}");
        let outside = render(shell, banded, 60);
        let plain = render(shell, &CASES[1], 60);
        assert!(!outside.upper.is_empty(), "{shell:?}");
        assert_eq!(outside, plain, "{shell:?}");
    }
}

// 이것을 실패시키는 것: 셸마다 보이는 글자가 달라지는 것(같은 설정 → 같은 칸 내용, 스펙 목표 1), vi 두 필드
// 포함(bash는 readline 문자열을 되돌려 비교), vi 입력·명령 기호가 같아지는 것.
#[test]
fn same_visible_text_in_every_shell() {
    for c in &CASES {
        for w in [20u16, 40, 60, 80, 120] {
            let rs = SHELLS.map(|s| (s, render(s, c, w)));
            let fish = &rs[2].1;
            assert_ne!(
                visible(Shell::Fish, "vi_insert", &fish.vi_insert),
                visible(Shell::Fish, "vi_command", &fish.vi_command),
                "{} {w}",
                c.name
            );
            for (shell, r) in &rs[..2] {
                for ((name, b), (_, fb)) in all(r).into_iter().zip(all(fish)) {
                    assert_eq!(
                        visible(*shell, name, b),
                        visible(Shell::Fish, name, fb),
                        "{} {w} {shell:?} {name}",
                        c.name
                    );
                }
            }
        }
    }
}

// 이것을 실패시키는 것: 기본 테마(M3a의 첫 보이는 프롬프트)의 바이트가 바뀌는 것(프리셋·레이아웃·narrow 구간·우선순위·색),
// golden 파일이 없는 것. 100칸은 두 줄 기본, 50칸은 narrow 구간이다.
#[test]
fn default_theme_outputs() {
    default_theme_goldens(true, "");
}

// 이것을 실패시키는 것: duration 없는 기본 테마에 공백·구분자가 남는 것.
#[test]
fn default_theme_without_duration_outputs() {
    default_theme_goldens(false, "_no_duration");
}

fn default_theme_goldens(duration: bool, suffix: &str) {
    use bingsu_core::default_theme::DefaultTheme;
    let d = DefaultTheme::new(Mode::Dark).unwrap();
    let i = |id| BUILTIN.iter().position(|x| x.id == id).unwrap();
    let v = |id: &str, text: &[u8], set: &[(&str, FieldValue)]| {
        let s = segment(id).unwrap();
        let mut f = vec![Field::ABSENT; s.fields.len()];
        for (n, x) in set {
            f[s.field_index(n).unwrap()] = Field::known(x.clone());
        }
        Some(Value::new(text, f))
    };
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    values[i("char")] = v("char", b"", &[("failed", FieldValue::Bool(true))]);
    values[i("dir")] = v("dir", b"", &[]);
    let steps: [&[u8]; 3] = [b"Works", b"AiScream", b"50% done"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, None, &[]));
    values[i("status")] = v("status", b"1", &[("code", FieldValue::Int(1))]);
    if duration {
        values[i("duration")] = v(
            "duration",
            b"3.2s",
            &[("ms", FieldValue::Duration { ms: 3200 })],
        );
    }
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: d.setup(),
    };
    for shell in SHELLS {
        for width in [100u16, 50] {
            let t = Target {
                shell,
                depth: ColorDepth::Ansi256,
                options: Options {
                    width,
                    profile: WidthProfile::DEFAULT,
                    icons: bingsu_core::default_theme::ICONS,
                    use_last_column: false,
                },
            };
            let r = render_prompt(&d.theme(), &inputs, &t, &mut NoopRecorder);
            let mut bytes = Vec::new();
            for (n, b) in all(&r) {
                bytes.extend_from_slice(n.as_bytes());
                bytes.extend_from_slice(b": ");
                bytes.extend_from_slice(b);
                bytes.push(b'\n');
            }
            check_golden(
                &format!("{}_default_{width}{suffix}.bin", shell.as_str()),
                &bytes,
            );
        }
    }
}
