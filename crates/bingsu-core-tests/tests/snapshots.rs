//! Layer 2 render snapshots (spec section 7): a fixed input drawn for each
//! shell and compared byte for byte with tests/golden/render/snapshots/
//! (BINGSU_UPDATE_GOLDEN=1 rewrites them; review the diff), and the visible
//! text equal across the three shells, the vi fields included.
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

fn render(shell: Shell, preset_name: &str, width: u16) -> RenderedPrompt {
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
    let t = generate(
        preset(preset_name).unwrap(),
        &StyleOptions::default(),
        &[
            LineLayout {
                left: &["dir", "git"],
                right: &["status", "time"],
            },
            LineLayout {
                left: &["char"],
                right: &[],
            },
        ],
    )
    .unwrap();
    let lines = compile(&t, BUILTIN).unwrap();
    let tr = compile("{char}", BUILTIN).unwrap().remove(0);
    let pal = resolve_palette(&PaletteInput {
        mode: Mode::Dark,
        knobs: Knobs::default(),
        overrides: &[],
        roles: &[],
    })
    .unwrap();
    let theme = Theme {
        variants: &[lines],
        bands: &[],
        band_order: &[],
        transient: &tr,
        vi: &tr,
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
            depth: ColorDepth::TrueColor,
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
    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
        for p in ["lean", "triangle"] {
            let r = render(shell, p, 60);
            let mut bytes = Vec::new();
            for (n, b) in all(&r) {
                bytes.extend_from_slice(n.as_bytes());
                bytes.extend_from_slice(b": ");
                bytes.extend_from_slice(b);
                bytes.push(b'\n');
            }
            check_golden(&format!("{}_{p}.bin", shell.as_str()), &bytes);
        }
    }
}

// 이것을 실패시키는 것: 셸마다 보이는 글자가 달라지는 것(같은 설정 → 같은 칸 내용, 스펙 목표 1), vi 두 필드
// 포함(bash는 readline 문자열을 되돌려 비교), vi 입력·명령 기호가 같아지는 것.
#[test]
fn same_visible_text_in_every_shell() {
    for p in ["lean", "triangle"] {
        for w in [20u16, 40, 60, 80, 120] {
            let rs = [Shell::Zsh, Shell::Bash, Shell::Fish].map(|s| (s, render(s, p, w)));
            let fish = &rs[2].1;
            assert_ne!(
                visible(Shell::Fish, "vi_insert", &fish.vi_insert),
                visible(Shell::Fish, "vi_command", &fish.vi_command),
                "{p} {w}"
            );
            for (shell, r) in &rs[..2] {
                for ((name, b), (_, fb)) in all(r).into_iter().zip(all(fish)) {
                    assert_eq!(
                        visible(*shell, name, b),
                        visible(Shell::Fish, name, fb),
                        "{p} {w} {shell:?} {name}"
                    );
                }
            }
        }
    }
}
