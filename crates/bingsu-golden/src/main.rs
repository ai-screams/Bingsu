//! Determinism probe (spec section 7 layer 7, F-06). Prints one line per
//! case: `case<TAB>value`. CI runs it natively on Linux, macOS and Windows
//! and under wasmtime as wasm32-wasip1, and compares each output with
//! tests/golden/render/render.tsv byte for byte. The cases cover every
//! float path (OKLCH conversion, gamut limiting, contrast, 256-color
//! search) and the full renderer.
//!
//! `BINGSU_UPDATE_GOLDEN=1` is not read here: regenerate the file with
//! `cargo run -q -p bingsu-golden --release > tests/golden/render/render.tsv`
//! and review the diff.
use bingsu_core::color::math::{
    Oklch, contrast_milli, nearest_256, oklab_q, oklch_to_srgb8, xterm,
};
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{Target, Theme, render_prompt};
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, Keep, Method, PathFacts};
use bingsu_core::style::{LineLayout, StyleOptions, generate, preset};
use bingsu_core::template::compile::compile;
use bingsu_core::width::WidthProfile;
use std::fmt::Write as _;
use std::io::Write as _;

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn color_cases(out: &mut String) {
    for l in (0..=20).map(|i| f64::from(i) / 20.0) {
        for c in [0.0, 0.05, 0.12, 0.2, 0.37] {
            for h in (0..12).map(|i| f64::from(i) * 30.0 + 7.5) {
                let (s, clipped) = oklch_to_srgb8(Oklch { l, c, h });
                let q = oklab_q(s);
                let _ = writeln!(
                    out,
                    "oklch {l} {c} {h}\t{:02x}{:02x}{:02x} {clipped} {} {} {} {}",
                    s.r,
                    s.g,
                    s.b,
                    q.l,
                    q.a,
                    q.b,
                    nearest_256(s)
                );
            }
        }
    }
    for i in 16..=255u8 {
        let _ = writeln!(out, "contrast {i}\t{}", contrast_milli(xterm(i), xterm(16)));
    }
    let tuned = Knobs {
        hue: Some(30.0),
        accent_l: Some(0.84),
        accent_c: Some(0.2),
    };
    for mode in [Mode::Dark, Mode::Light] {
        for knobs in [Knobs::default(), tuned] {
            let p = resolve_palette(&PaletteInput {
                mode,
                knobs,
                overrides: &[],
                roles: &[],
            })
            .expect("built-in palette");
            for (i, t) in p.tokens.iter().enumerate() {
                let _ = writeln!(out, "token {mode:?} {knobs:?} {i}\t{t:?}");
            }
            let _ = writeln!(
                out,
                "palette {mode:?} {knobs:?}\t{:?} {:?}",
                p.background, p.warnings
            );
        }
    }
}

fn render_cases(out: &mut String) {
    let i = |id| BUILTIN.iter().position(|d| d.id == id).expect("built-in");
    let v = |id: &str, text: &[u8], set: &[(&str, FieldValue)]| {
        let d = segment(id).expect("built-in");
        let mut f = vec![Field::ABSENT; d.fields.len()];
        for (n, x) in set {
            f[d.field_index(n).expect("field")] = Field::known(x.clone());
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
    values[i("char")] = v("char", b"", &[]);
    values[i("dir")] = v("dir", b"", &[]);
    let steps: [&[u8]; 4] = [
        b"Works",
        "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}".as_bytes(),
        b"themes",
        b"src",
    ];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, Some(2), &[]));
    values[i("git")] = v(
        "git",
        "feature/\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}-long-branch".as_bytes(),
        &[(
            "ahead",
            FieldValue::Count {
                n: 3,
                saturated: true,
            },
        )],
    );
    values[i("duration")] = v(
        "duration",
        b"2.3s",
        &[("ms", FieldValue::Duration { ms: 2300 })],
    );
    values[i("time")] = v("time", b"12:34", &[]);
    setup[i("char")].required = true;
    setup[i("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods: &[Method::Repo, Method::Abbrev(1), Method::Depth(1)],
        when: When::Needed,
    };
    setup[i("git")].methods = &[Method::Truncate {
        max: 16,
        keep: Keep::Start,
    }];
    setup[i("time")].priority = 1;
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let tr = compile("{char}", BUILTIN).expect("transient").remove(0);
    for preset_name in ["lean", "triangle"] {
        let t = generate(
            preset(preset_name).expect("preset"),
            &StyleOptions::default(),
            &[
                LineLayout {
                    left: &["dir", "git"],
                    right: &["duration", "time"],
                },
                LineLayout {
                    left: &["char"],
                    right: &[],
                },
            ],
        )
        .expect("template");
        let lines = compile(&t, BUILTIN).expect("template");
        for mode in [Mode::Dark, Mode::Light] {
            let pal = resolve_palette(&PaletteInput {
                mode,
                knobs: Knobs::default(),
                overrides: &[],
                roles: &[],
            })
            .expect("palette");
            let theme = Theme {
                variants: std::slice::from_ref(&lines),
                bands: &[],
                band_order: &[],
                transient: &tr,
                vi: &tr,
                palette: &pal,
            };
            for amb in [1, 2] {
                for depth in [
                    ColorDepth::TrueColor,
                    ColorDepth::Ansi256,
                    ColorDepth::Ansi16,
                ] {
                    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
                        for width in [0u16, 1, 2, 3, 10, 20, 40, 60, 80, 120, 200] {
                            let o = Options {
                                width,
                                profile: WidthProfile::new(amb, 2).expect("profile"),
                                icons: IconSet::Nerd,
                                use_last_column: false,
                            };
                            let r = render_prompt(
                                &theme,
                                &inputs,
                                &Target {
                                    shell,
                                    depth,
                                    options: o,
                                },
                                &mut NoopRecorder,
                            );
                            let _ = write!(
                                out,
                                "render {preset_name} {mode:?} {amb} {depth:?} {} {width}\t",
                                shell.as_str()
                            );
                            for f in [
                                &r.upper,
                                &r.left,
                                &r.right,
                                &r.transient_left,
                                &r.transient_right,
                                &r.vi_insert,
                                &r.vi_command,
                            ] {
                                out.push_str(&hex(f));
                                out.push(' ');
                            }
                            out.push('\n');
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    let mut out = String::new();
    color_cases(&mut out);
    render_cases(&mut out);
    // A closed stdout (a pipe that went away) is not an error worth a panic.
    let _ = std::io::stdout().write_all(out.as_bytes());
}
