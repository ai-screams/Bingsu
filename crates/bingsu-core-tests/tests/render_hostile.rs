//! Producer layer for rendered prompts (spec section 3 "시험은 두 층이다",
//! F-19): every hostile class from tests/hostile/classes.tsv through layout
//! and shell output, once per input path (segment text, `{git.branch}`
//! field, folder name, theme text) so that each path is checked on its own.
//! Every field is read back with the shell's field grammar
//! (`bingsu_core_tests::parse_field`), which also checks that each field
//! closes what it opens.
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When, target};
use bingsu_core::record::{Encoded, encode_b1};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{RenderedPrompt, Target, Theme, render_prompt, to_b1_fields};
use bingsu_core::sanitize::sanitize;
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, PathFacts};
use bingsu_core::status::Status;
use bingsu_core::template::compile::compile;
use bingsu_core::width::{WidthProfile, str_width};
use bingsu_core_tests::{parse_field, parse_readline};

const SHELLS: [Shell; 3] = [Shell::Zsh, Shell::Bash, Shell::Fish];

fn payload(spec: &str) -> Vec<u8> {
    if let Some(rest) = spec.strip_prefix("repeat:") {
        let (byte, n) = rest.split_once(':').unwrap();
        return vec![u8::from_str_radix(byte, 16).unwrap(); n.parse().unwrap()];
    }
    let raw: Vec<u8> = (0..spec.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&spec[i..i + 2], 16).unwrap())
        .collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i..].starts_with(b"CANARY") {
            out.extend_from_slice(b"/tmp/x");
            i += 6;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

/// (class, payload, render column) of every matrix row.
fn rows() -> Vec<(String, Vec<u8>, String)> {
    let text = include_str!("../../../tests/hostile/classes.tsv");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            assert_eq!(c.len(), 8, "{l}");
            (c[0].to_owned(), payload(c[1]), c[6].to_owned())
        })
        .collect()
}

fn pal() -> ResolvedPalette {
    resolve_palette(&PaletteInput {
        mode: Mode::Dark,
        knobs: Knobs::default(),
        overrides: &[],
        roles: &[],
    })
    .unwrap()
}

fn idx(id: &str) -> usize {
    BUILTIN.iter().position(|d| d.id == id).unwrap()
}

fn absent(id: &str) -> Vec<Field> {
    vec![Field::ABSENT; segment(id).unwrap().fields.len()]
}

/// Where the hostile value goes in; the other inputs stay plain.
#[derive(Clone, Copy, Debug)]
enum Path {
    /// The git segment's display text.
    Segment,
    /// The `git.branch` field (`Field::text`, the `Clean` newtype).
    BranchField,
    /// A folder name in the path facts.
    Folder,
}

fn opts() -> Options {
    Options {
        width: u16::MAX,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    }
}

fn render_with(
    shell: Shell,
    branch: &[u8],
    branch_field: &[u8],
    folder: &[u8],
    template: &str,
    transient: &str,
    width: u16,
) -> RenderedPrompt {
    let pal = pal();
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    let git = segment("git").unwrap();
    let mut gf = absent("git");
    gf[git.field_index("branch").unwrap()] = Field::text(branch_field, 256, WidthProfile::DEFAULT);
    values[idx("git")] = Some(Value::new(branch, gf));
    values[idx("dir")] = Some(Value::new(b"", absent("dir")));
    facts[idx("dir")] = Some(PathFacts::new(Anchor::Root, &[folder], None, &[]));
    values[idx("char")] = Some(Value::new(b"", absent("char")));
    let setup = vec![
        SegmentSetup {
            priority: 1,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let lines = compile(template, BUILTIN).unwrap();
    let tr = compile(transient, BUILTIN).unwrap().remove(0);
    let vi = compile("{char}", BUILTIN).unwrap().remove(0);
    let theme = Theme {
        variants: &[lines],
        bands: &[],
        band_order: &[],
        transient: &tr,
        vi: &vi,
        palette: &pal,
    };
    let o = Options { width, ..opts() };
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

fn render(shell: Shell, path: Path, p: &[u8], width: u16) -> RenderedPrompt {
    // The value is in the upper line and on both sides of the input line;
    // the transient line carries it on both sides too.
    let (b, f, d, seg) = match path {
        Path::Segment => (p, &b"main"[..], &b"w"[..], "{git}"),
        Path::BranchField => (&b"g"[..], p, &b"w"[..], "{git.branch}"),
        Path::Folder => (&b"main"[..], &b"main"[..], p, "{dir}"),
    };
    let tr = format!("{seg} {{char}}{{@fill}}{seg}");
    let t = format!("{seg}{{@nl}}{tr}");
    render_with(shell, b, f, d, &t, &tr, width)
}

fn named(r: &RenderedPrompt) -> [(&'static str, &[u8]); 7] {
    [
        ("left", &r.left),
        ("right", &r.right),
        ("transient_left", &r.transient_left),
        ("transient_right", &r.transient_right),
        ("vi_insert", &r.vi_insert),
        ("vi_command", &r.vi_command),
        ("upper", &r.upper),
    ]
}

/// The text a field shows, read with its shell's grammar. bash vi fields
/// are readline strings: decoded first, then read as a bash field.
fn shown(shell: Shell, name: &str, b: &[u8]) -> Result<String, String> {
    if shell == Shell::Bash && name.starts_with("vi_") {
        parse_field(shell, &parse_readline(b)?)
    } else {
        parse_field(shell, b)
    }
}

/// Widths every hostile value is drawn at: narrow ones that hide, shorten
/// and cut (step 7 drops the upper line at 4), a common one and the
/// widest, where every value is shown whole.
const WIDTHS: [u16; 5] = [4, 12, 30, 80, u16::MAX];

fn cells(shell: Shell, name: &str, b: &[u8]) -> u32 {
    str_width(&shown(shell, name, b).unwrap(), WidthProfile::DEFAULT)
}

// 이것을 실패시키는 것: 정제·셸 출력이 classes.tsv render 열과 다르게 바꾸는 것, 어느 한 입력 경로(세그먼트
// 글자, `{git.branch}` 필드, 폴더 이름)가 정제를 건너뛰는 것, 셸 필드 문법을 어기는 필드(열린 `%{`·SOH,
// 짝 없는 `%`, zsh·fish의 SOH·STX, 제어 바이트) — 윗줄·오른쪽·transient 오른쪽 필드 포함, 오른쪽 필드를
// 다른 셸 문법으로 쓰는 것, 오른쪽 필드를 비우는 것, 레코드가 받지 않는 필드. 좁은 폭(4·12·30)에서만
// 갈리는 것: grapheme 경계가 아닌 곳에서 자르는 것(layout이 panic), layout에 폭을 넘기지 않아 폭보다 넓게
// 그리는 것. truncate는 출력으로 판정한다: 말줄임표가 보이고 필드가 값의 1/16보다 짧아야 한다(값을 10바이트로
// 줄이면 갈린다).
#[test]
fn hostile_values_render_safely() {
    for (class, p, want) in rows() {
        let clean = sanitize(&p);
        let holds = match want.as_str() {
            "same" => clean.as_bytes() == p.as_slice() && !clean.contains('%'),
            "strip" => clean.len() < p.len() && !clean.contains('\u{FFFD}'),
            "fffd" => clean.contains('\u{FFFD}'),
            "zsh-escape" => clean.as_bytes() == p.as_slice() && clean.contains('%'),
            // Decided from the rendered fields below.
            "truncate" => true,
            other => panic!("{class}: unknown render outcome {other}"),
        };
        assert!(holds, "{class}: render column {want} does not hold");
        for path in [Path::Segment, Path::BranchField, Path::Folder] {
            for shell in SHELLS {
                for width in WIDTHS {
                    let at = format!("{class} {path:?} {shell:?} {width}");
                    let r = render(shell, path, &p, width);
                    for (name, f) in named(&r) {
                        shown(shell, name, f).unwrap_or_else(|e| panic!("{at} {name}: {e}: {f:?}"));
                    }
                    let target = target(&Options { width, ..opts() });
                    let line = cells(shell, "left", &r.left) + cells(shell, "right", &r.right);
                    let tr = cells(shell, "transient_left", &r.transient_left)
                        + cells(shell, "transient_right", &r.transient_right);
                    let up = cells(shell, "upper", &r.upper);
                    assert!(
                        line <= target && tr <= target && up <= target,
                        "{at}: {up} {line} {tr} cells, target {target}"
                    );
                    let mut out = Vec::new();
                    let enc = encode_b1(&to_b1_fields(&r), Status::OK_NONE, &mut out)
                        .unwrap_or_else(|e| panic!("{at}: {e:?}"));
                    assert_eq!(enc, Encoded::Full, "{at}");
                    if width != u16::MAX {
                        continue;
                    }
                    // The widest: every value is whole, or cut by its byte cap.
                    assert!(!r.upper.is_empty(), "{at}: no upper line");
                    for (name, f) in named(&r) {
                        if name.starts_with("vi_") {
                            continue;
                        }
                        let text = shown(shell, name, f).unwrap();
                        if want == "truncate" {
                            assert!(
                                text.contains('\u{2026}') && f.len() < p.len() / 16,
                                "{at} {name}: not truncated ({} bytes): {:?}",
                                f.len(),
                                text.get(..64)
                            );
                        } else {
                            assert!(
                                text.contains(clean.as_str()),
                                "{at} {name}: {text:?} lacks {clean:?}"
                            );
                        }
                    }
                    if shell == Shell::Zsh && want == "zsh-escape" {
                        let doubled = clean.replace('%', "%%");
                        let left = String::from_utf8_lossy(&r.left);
                        assert!(left.contains(&doubled), "{at}: {left:?}");
                    }
                }
            }
        }
    }
}

// 이것을 실패시키는 것: 테마 글자의 정제 대상 글자를 받는 템플릿, 테마 글자의 `%`를 zsh에서 이스케이프하지 않는 것.
// compile은 정제 대상 글자(제어·형식 문자)를 모두 거부한다(`syntax.rs`의 ControlChar). 그래서 strip 행은
// 모두 거부되고, 받는 행은 글자 그대로 보인다.
#[test]
fn theme_text_is_checked_and_escaped() {
    let mut accepted = 0;
    for (class, p, want) in rows() {
        let Ok(text) = std::str::from_utf8(&p) else {
            assert_eq!(want, "fffd", "{class}");
            continue;
        };
        let escaped = text.replace('{', "{{").replace('}', "}}");
        let t = format!("{escaped}{{char}}");
        match compile(&t, BUILTIN) {
            Err(_) => assert!(
                matches!(want.as_str(), "strip" | "truncate"),
                "{class}: rejected but render={want}"
            ),
            Ok(_) => {
                assert!(
                    matches!(want.as_str(), "same" | "zsh-escape"),
                    "{class}: accepted but render={want}"
                );
                accepted += 1;
                for shell in SHELLS {
                    let r = render_with(shell, b"main", b"main", b"w", &t, "{char}", u16::MAX);
                    let left = parse_field(shell, &r.left).unwrap();
                    assert!(left.contains(text), "{class} {shell:?}: {left:?}");
                    if shell == Shell::Zsh {
                        let raw = String::from_utf8_lossy(&r.left);
                        assert!(raw.contains(&text.replace('%', "%%")), "{class}: {raw:?}");
                    }
                }
            }
        }
    }
    assert!(accepted > 0);
}

// 이것을 실패시키는 것: 필드 합이 64KiB를 넘는 렌더를 레코드가 최소 레코드로 바꾸지 않는 것.
// 한 줄의 글자는 LINE_BYTES_MAX(16KiB)로 묶이므로 한 필드만으로는 넘지 못한다. 색이 번갈아 바뀌는 세그먼트
// 400개(줄마다 SGR 400개)를 윗줄·입력 줄·transient에 두어 셋을 합쳐 넘긴다. 세 셸 모두: fish는 표지
// 바이트가 없어 필드가 가장 짧으므로 합이 64KiB를 넘는지를 셸마다 먼저 확인한다.
#[test]
fn oversize_render_becomes_minimal_record() {
    let wide = "한".repeat(13);
    let line = "{dir}{git}".repeat(200);
    let t = format!("{line}{{@nl}}{line}");
    for shell in SHELLS {
        let r = render_with(
            shell,
            wide.as_bytes(),
            b"main",
            wide.as_bytes(),
            &t,
            &line,
            u16::MAX,
        );
        for (name, f) in [
            ("upper", &r.upper),
            ("left", &r.left),
            ("transient_left", &r.transient_left),
        ] {
            assert!(
                f.len() < 64 * 1024 && f.len() > 22 * 1024,
                "{shell:?} {name}: {}",
                f.len()
            );
        }
        let total: usize = named(&r).iter().map(|(_, f)| f.len()).sum();
        assert!(total > 65_536, "{shell:?}: {total}");
        let mut out = Vec::new();
        assert_eq!(
            encode_b1(&to_b1_fields(&r), Status::OK_NONE, &mut out),
            Ok(Encoded::ReplacedBySizeLimit),
            "{shell:?}"
        );
    }
}

// 이것을 실패시키는 것: 바이트 상한 없이 칸 수로만 자르는 것. 결합 문자 4만 개가 붙은 글자 하나는
// 1칸이지만 80 KB다. 값의 바이트 상한이 그 글자를 말줄임표로 바꿔야 줄이 그려진다. 상한이 없으면 줄이
// LINE_BYTES_MAX를 넘어 최소 프롬프트로 떨어진다(그래서 크기만 보는 검사로는 갈리지 않는다). 세 셸 모두.
#[test]
fn combining_flood_stays_under_the_byte_cap() {
    let flood = [&b"a"[..], &"\u{301}".repeat(40_000).into_bytes()].concat();
    for shell in SHELLS {
        for path in [Path::Segment, Path::BranchField, Path::Folder] {
            let r = render(shell, path, &flood, u16::MAX);
            assert!(
                r.left.len() < 20_000,
                "{shell:?} {path:?}: {}",
                r.left.len()
            );
            let shown = parse_field(shell, &r.left).unwrap();
            assert!(shown.contains('\u{2026}'), "{shell:?} {path:?}: {shown:?}");
            let mut out = Vec::new();
            assert_eq!(
                encode_b1(&to_b1_fields(&r), Status::OK_NONE, &mut out),
                Ok(Encoded::Full),
                "{shell:?} {path:?}"
            );
        }
    }
}
