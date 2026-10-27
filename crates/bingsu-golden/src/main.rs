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
    Oklch, OklchQ, Srgb8, contrast_milli, nearest_256, oklab_q, oklch_to_srgb8, xterm,
};
use bingsu_core::color::palette::{
    AnsiSlot, Knobs, Mode, PaletteInput, PaletteWarning, ResolvedToken, resolve_palette,
};
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

#[allow(
    dead_code,
    unused_imports,
    reason = "shared git display fixtures; integration assertions run in core"
)]
#[path = "../../bingsu-core/tests/git_render.rs"]
mod git_fixture;

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

// The committed file must not depend on `Debug` output, which Rust does not
// keep stable across toolchains: every value below has a fixed format.
fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Dark => "dark",
        Mode::Light => "light",
    }
}

fn depth_name(d: ColorDepth) -> &'static str {
    match d {
        ColorDepth::TrueColor => "truecolor",
        ColorDepth::Ansi256 => "ansi256",
        ColorDepth::Ansi16 => "ansi16",
    }
}

fn opt(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_owned(), |x| x.to_string())
}

fn knobs_text(k: &Knobs) -> String {
    format!("{} {} {}", opt(k.hue), opt(k.accent_l), opt(k.accent_c))
}

fn rgb(s: Srgb8) -> String {
    format!("{:02x}{:02x}{:02x}", s.r, s.g, s.b)
}

fn lch(q: OklchQ) -> String {
    format!("{}/{}/{}", q.l, q.c, q.h)
}

fn slot(a: AnsiSlot) -> String {
    match a {
        AnsiSlot::Default => "default".to_owned(),
        AnsiSlot::Slot(n) => format!("slot{n}"),
    }
}

fn token_text(t: &ResolvedToken) -> String {
    format!(
        "fg={} bg={} fg_lch={} bg_lch={} fg256={} bg256={} ansi={} on_block={} on_block256={} on_block_ansi={} clipped={}",
        rgb(t.fg),
        rgb(t.bg),
        lch(t.fg_oklch),
        lch(t.bg_oklch),
        t.fg256,
        t.bg256,
        slot(t.ansi),
        rgb(t.on_block),
        t.on_block256,
        slot(t.on_block_ansi),
        t.clipped
    )
}

fn warning_text(w: &PaletteWarning) -> String {
    match *w {
        PaletteWarning::TextContrast { token, milli } => format!("text:{token}:{milli}"),
        PaletteWarning::BlockContrast { token, milli } => format!("block:{token}:{milli}"),
        PaletteWarning::Clipped { token } => format!("clipped:{token}"),
        PaletteWarning::MarkContrast { token, milli } => format!("mark:{token}:{milli}"),
        PaletteWarning::BackgroundClipped => "background".to_owned(),
    }
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
                let _ = writeln!(
                    out,
                    "token {} {} {i}\t{}",
                    mode_name(mode),
                    knobs_text(&knobs),
                    token_text(t)
                );
            }
            let warnings: Vec<String> = p.warnings.iter().map(warning_text).collect();
            let _ = writeln!(
                out,
                "palette {} {}\t{} [{}]",
                mode_name(mode),
                knobs_text(&knobs),
                rgb(p.background),
                warnings.join(" ")
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
                                "render {preset_name} {} {amb} {} {} {width}\t",
                                mode_name(mode),
                                depth_name(depth),
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
    git_cases(&mut out);
    // A closed stdout (a pipe that went away) is not an error worth a panic.
    let _ = std::io::stdout().write_all(out.as_bytes());
}

fn git_cases(out: &mut String) {
    let mut cases: Vec<_> = git_fixture::CASES
        .into_iter()
        .map(|name| (name, git_fixture::git_value(name)))
        .collect();
    for (name, raw) in git_fixture::hostile_cases() {
        let mut value = git_fixture::git_value("clean");
        git_fixture::set(
            &mut value,
            "branch",
            Field::text(&raw, 256, WidthProfile::DEFAULT),
        );
        cases.push((name, value));
    }
    for name in ["readonly-unknown", "readonly-false", "readonly-true"] {
        cases.push((name, git_fixture::git_value("clean")));
    }
    let theme = bingsu_core::default_theme::DefaultTheme::new(Mode::Dark).unwrap();
    for (name, value) in cases {
        for (set, icons) in [
            ("ascii", IconSet::Ascii),
            ("unicode", IconSet::Unicode),
            ("nerd", IconSet::Nerd),
        ] {
            for amb in [1, 2] {
                let profile = WidthProfile::new(amb, 2).unwrap();
                let mut r = git_fixture::response(value.clone());
                if name.starts_with("readonly-") {
                    r.updates[1].facts.as_mut().unwrap().readonly = match name {
                        "readonly-true" => Some(true),
                        "readonly-false" => Some(false),
                        _ => None,
                    };
                }
                let mut collected = bingsu_core::shell_values::collect(&git_fixture::envelope());
                bingsu_core::collection::merge(
                    &mut collected,
                    Some(&r),
                    &r.binding,
                    &r.binding.cwd,
                    Some(b"/home/u"),
                )
                .unwrap();
                if let Some(v) = &mut collected.values[3] {
                    *v = bingsu_core::shell_values::format_git(v, icons, profile);
                }
                let inputs = Inputs {
                    catalog: BUILTIN,
                    values: &collected.values,
                    facts: &collected.facts,
                    setup: theme.setup(),
                };
                for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
                    for width in [0, 1, 2, 3, 59, 60, 120] {
                        let rendered = render_prompt(
                            &theme.theme(),
                            &inputs,
                            &Target {
                                shell,
                                depth: ColorDepth::TrueColor,
                                options: Options {
                                    width,
                                    profile,
                                    icons,
                                    use_last_column: false,
                                },
                            },
                            &mut NoopRecorder,
                        );
                        let _ = write!(out, "git {name} {set} {amb} {} {width}\t", shell.as_str());
                        for bytes in [
                            &rendered.upper,
                            &rendered.left,
                            &rendered.right,
                            &rendered.transient_left,
                            &rendered.transient_right,
                            &rendered.vi_insert,
                            &rendered.vi_command,
                        ] {
                            out.push_str(&hex(bytes));
                            out.push(' ');
                        }
                        out.push('\n');
                    }
                }
            }
        }
    }
}

// Filesystem oracle: the complete listing and its reverse must yield the same
// unique result. No test depends on readdir/getdents order.
#[test]
fn filesystem_sibling_order_matches_the_full_shortener() {
    use bingsu_core::{
        collection, shell_values,
        shorten::{Method, ShortenRequest, Source, run_builtin},
    };
    use git_fixture::{binding, envelope, facts, git_value, response};
    // The pid can be reused after a run that never dropped; the clock keeps the name fresh.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "bingsu-e2-siblings-{}-{nonce:x}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            // No panic in Drop: a failed cleanup must not mask the test result.
            if let Err(e) = std::fs::remove_dir_all(&self.0) {
                eprintln!("cleanup of {} failed: {e}", self.0.display());
            }
        }
    }
    let _cleanup = Cleanup(root.clone());
    for name in ["alphabet", "alpine", "beta"] {
        std::fs::create_dir(root.join(name)).unwrap();
    }
    let mut names: Vec<Vec<u8>> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            assert!(e.file_type().unwrap().is_dir());
            e.file_name().into_string().unwrap().into_bytes()
        })
        .collect();
    assert_eq!(names.len(), 3);
    let expected = "~/alph/leaf";
    for _ in 0..2 {
        let mut f = facts();
        f.siblings[0].names = names.clone();
        let mut r = response(git_value("clean"));
        r.updates[1].facts = Some(f);
        let mut c = shell_values::collect(&envelope());
        collection::merge(
            &mut c,
            Some(&r),
            &binding(),
            &binding().cwd,
            Some(b"/home/u"),
        )
        .unwrap();
        let shown = run_builtin(&ShortenRequest {
            source: Source::Path(c.facts[1].as_ref().unwrap()),
            method: Method::Unique,
            budget: u32::MAX,
            profile: WidthProfile::DEFAULT,
        })
        .unwrap()
        .text();
        assert_eq!(shown, expected);
        names.reverse();
    }
}
