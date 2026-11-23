//! `setup_editor` against the real loader, merge and compile: what the
//! editor writes draws what it shows, the three layers follow `extends` and
//! `conf.d`, and the screen fits every size with nothing from outside left
//! unsanitized.
use bingsu_core::color::palette::Mode;
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::config::compile::{BUILTIN_TOML, CompiledConfig};
use bingsu_core::config::report::{ConfigReport, report};
use bingsu_core::config::source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust};
use bingsu_core::config::starter::{Icons as StarterIcons, Mode as StarterMode};
use bingsu_core::config::tree::Format;
use bingsu_core::diag::{Severity, SourceId};
use bingsu_core::field::BUILTIN;
use bingsu_core::keys::Key;
use bingsu_core::preview::{PreviewLine, Request, Sample, lines};
use bingsu_core::setup_editor::layers::Layers;
use bingsu_core::setup_editor::model::{Effect, Given, Input, Model, Note, Screen, Target};
use bingsu_core::setup_editor::rows::{self, ENDS, GAPS, ICONS, JOINTS, Row, STYLES};
use bingsu_core::setup_editor::screen::{Grid, View, draw, frame};
use bingsu_core::setup_editor::write::{changes, new_file_text, written_keys};
use bingsu_core::style::{PRESETS, generate, preset};
use bingsu_core::template::compile::{CompiledLine, compile};

const TARGET: &str = "config.toml";

/// Named files: `(name, text)`.
type Files<'a> = &'a [(&'a str, &'a str)];

fn opened(name: &str, text: &str, ino: u64) -> Opened {
    Opened {
        key: FileKey { dev: 1, ino },
        bytes: text.as_bytes().to_vec(),
        trust: Trust::Executable,
        display: name.as_bytes().to_vec(),
    }
}

/// `extends` entries answered by name.
struct Parts<'a>(&'a [(&'a str, &'a str)]);
impl Resolver for Parts<'_> {
    fn open(&mut self, _: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let i = self
            .0
            .iter()
            .position(|(n, _)| *n == r.text)
            .ok_or(OpenError {
                reason: "no such part".into(),
                trust: Trust::Executable,
            })?;
        Ok(opened(self.0[i].0, self.0[i].1, 100 + i as u64))
    }
}

/// The built-in theme, the target, then `later` roots (as `conf.d` files
/// come after the target).
fn load(target: &str, later: &[(&str, &str)], parts: &[(&str, &str)]) -> ConfigReport {
    let mut roots = vec![
        opened("(built-in)", BUILTIN_TOML, 0),
        opened(TARGET, target, 1),
    ];
    for (i, (name, text)) in later.iter().enumerate() {
        roots.push(opened(name, text, 10 + i as u64));
    }
    report(roots, &mut Parts(parts), [0, 3, 0], Mode::Dark)
}

fn target_of(r: &ConfigReport) -> SourceId {
    r.files
        .iter()
        .find(|f| f.opened.display == TARGET.as_bytes())
        .map(|f| f.id)
        .unwrap()
}

fn layers(r: &ConfigReport) -> Layers {
    Layers::from_sources(&r.files, &r.order, target_of(r))
}

/// The compiled settings, with no error or warning (notes such as N501 are
/// what a written part key gives under the built-in `narrow` band).
fn compiled(r: ConfigReport) -> CompiledConfig {
    let bad: Vec<_> = r
        .diagnostics
        .iter()
        .filter(|d| d.severity() != Severity::Note)
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
    r.snapshot.expect("compiles")
}

/// The lines a state draws, made straight from the style generator.
fn template_of(s: [u8; 5]) -> Vec<CompiledLine> {
    let o = rows::options(s[0], s[1], s[2], s[3], s[4]);
    let p = preset(STYLES[usize::from(s[0])]).unwrap();
    compile(
        &generate(p, &o, &bingsu_core::default_theme::LINES).unwrap(),
        BUILTIN,
    )
    .unwrap()
}

const SHAPE: [Row; 5] = [Row::Style, Row::Outer, Row::Joint, Row::Inner, Row::Gap];

fn states() -> impl Iterator<Item = [u8; 5]> {
    (0..8u8).flat_map(|s| {
        (0..5u8).flat_map(move |o| {
            (0..6u8).flat_map(move |j| {
                (0..5u8).flat_map(move |i| (0..2u8).map(move |g| [s, o, j, i, g]))
            })
        })
    })
}

fn set(m: &mut Model, s: [u8; 5]) {
    for (row, v) in SHAPE.iter().zip(s) {
        m.pick(*row, v);
    }
}

// 이것을 실패시키는 것: 고른 값이 물려받은 값과 같을 때도 쓰거나(괜찮다) 다를 때 쓰지 않는 것(그 값이 사라진다),
// 프리셋을 늘 쓰지 않는 것, 부분 키의 물려받은 값을 최종 프리셋이 아닌 것에서 가져오는 것, 새 파일 글이 TOML로
// 읽히지 않거나 표 머리 뒤에 뿌리 키를 두는 것, 키 이름·값 목록이 config와 어긋나는 것. 프리셋 8 × 바깥 끝 5 ×
// 이음 6 × 안쪽 끝 5 × 빈칸 2 = 2,400 상태마다, 쓴 파일을 compile한 줄이 그 상태를 생성기로 만든 줄과 같아야 한다.
// 그 아래에 내장만 있을 때, 부분 키 넷을 프리셋과 다른 값으로 쓰는 `extends`가 있을 때(같으면 안 씀이 시험된다),
// 뒤 `conf.d`가 바깥 끝을 덮을 때(최종 값이 그것을 따름) 세 번.
#[test]
fn every_shape_state_writes_a_file_that_draws_it() {
    let base =
        "[style]\nouter_end = \"slant\"\nseparator = \"round\"\ninner_end = \"flat\"\ngap = true\n";
    let parts = [("base", base)];
    let cover = [("conf.d/a.toml", "[style]\nouter_end = \"round\"\n")];
    let cases: [(&str, Files, Files); 3] = [
        ("", &[], &[]),
        ("extends = [\"base\"]\n", &[], &parts),
        ("", &cover, &[]),
    ];
    let mut checked = 0;
    for (head, later, parts) in cases {
        let l = layers(&load(head, later, parts));
        for s in states() {
            let mut m = Model::new(l.clone(), Target::New, Given::default());
            set(&mut m, s);
            let mut want = s;
            if !later.is_empty() {
                want[1] = ENDS.iter().position(|e| *e == "round").unwrap() as u8;
            }
            for (row, v) in SHAPE.iter().zip(want) {
                assert_eq!(m.effective(*row), v, "{s:?} {row:?} {head:?}");
            }
            let text = format!("{head}{}", new_file_text(&m).unwrap());
            let c = compiled(load(&text, later, parts));
            assert_eq!(c.variants[0], template_of(want), "{s:?}\n{text}");
            checked += 1;
        }
    }
    assert_eq!(checked, 3 * 2400);
}

// 이것을 실패시키는 것: `extends`의 값을 물려받은 값으로 읽지 않는 것, 대상의 값을 쓴 값으로 읽지 않는 것, 뒤
// 출처(`conf.d`)를 덮는 값과 그 이름으로 남기지 않는 것, 템플릿을 둔 출처를 잊는 것, 줄의 목록에 없는 값을 읽는
// 것(compile처럼 없는 것으로 쳐야 한다), Backspace가 대상의 값을 지우지 않는 것.
#[test]
fn the_three_layers_follow_extends_and_conf_d() {
    let target =
        "extends = [\"base\"]\nicons = \"ascii\"\n[style]\nseparator = \"rounds\"\ngap = true\n";
    let base = "[style]\npreset = \"pill\"\nouter_end = \"round\"\n[colors]\nmode = \"light\"\n";
    let later = [
        ("conf.d/a.toml", "[style]\ninner_end = \"slant\"\n"),
        (
            "config.local.toml",
            "[style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        ),
    ];
    let r = load(target, &later, &[("base", base)]);
    let l = layers(&r);
    let pos = |list: &[&str], v: &str| list.iter().position(|x| *x == v).unwrap() as u8;
    assert_eq!(
        l.rows[Row::Style.index()].earlier,
        Some(pos(&STYLES, "pill"))
    );
    assert_eq!(
        l.rows[Row::Outer.index()].earlier,
        Some(pos(&ENDS, "round"))
    );
    assert_eq!(l.rows[Row::Colors.index()].earlier, Some(2));
    assert_eq!(
        l.rows[Row::Icons.index()].written,
        Some(pos(&ICONS, "ascii"))
    );
    assert_eq!(l.rows[Row::Gap.index()].written, Some(1));
    // A value the row does not know is no opinion, but its text is kept.
    assert_eq!(l.rows[Row::Joint.index()].written, None);
    assert_eq!(
        l.rows[Row::Joint.index()].written_raw[0].as_deref(),
        Some("\"rounds\"")
    );
    let (v, n) = l.rows[Row::Inner.index()].later.unwrap();
    assert_eq!(v, pos(&ENDS, "slant"));
    assert_eq!(l.names[n], b"conf.d/a.toml");
    assert_eq!(l.names[l.template.unwrap()], b"config.local.toml");
    // The model over these layers.
    let mut m = Model::new(l, Target::Existing(Format::Toml), Given::default());
    assert_eq!(m.inherited(Row::Style), pos(&STYLES, "pill"));
    // pill's own joint is caps; the target's "rounds" is ignored.
    assert_eq!(m.effective(Row::Joint), pos(&JOINTS, "caps"));
    assert_eq!(m.effective(Row::Inner), pos(&ENDS, "slant"));
    assert_eq!(m.chosen(Row::Inner), pos(&ENDS, "round"));
    assert_eq!(m.covered_by(Row::Inner), Some(n));
    assert!(!m.changed());
    m.remove_override(Row::Gap);
    assert_eq!((m.written(Row::Gap), m.effective(Row::Gap)), (None, 0));
    assert!(m.changed() && m.marked(Row::Gap));
}

fn key(m: &mut Model, k: Key, read: u64) -> Effect {
    m.handle(Input { key: k, read })
}

fn fresh() -> Model {
    Model::new(layers(&load("", &[], &[])), Target::New, Given::default())
}

// 이것을 실패시키는 것: 새 파일의 시작 값(nerd 아이콘, triangle, 자동 색, 2줄)이 다른 것, 쓴 키 목록과 파일이
// 갈라지는 것, 인자로 준 값을 쓸 줄로 두지 않는 것, 아이콘이 고르는 프리셋(light → triangle, ascii → lean)이
// 어긋나는 것.
#[test]
fn a_new_file_starts_from_nerd_and_follows_the_icons() {
    let m = fresh();
    assert_eq!(m.chosen(Row::Icons), 0);
    assert_eq!(m.chosen(Row::Style), 1);
    assert_eq!(m.chosen(Row::Colors), 0);
    assert_eq!(m.chosen(Row::Lines), 0);
    let keys: Vec<_> = written_keys(&m).into_iter().map(|k| k.key).collect();
    assert_eq!(keys, ["style.preset", "icons"]);
    let text = new_file_text(&m).unwrap();
    for k in &keys {
        let name = k.rsplit('.').next().unwrap();
        assert!(text.contains(&format!("\n{name} = ")), "{k}: {text}");
    }
    assert!(text.is_ascii() && text.starts_with("#:schema https://"));
    let l = layers(&load("", &[], &[]));
    for (icons, preset) in [
        (StarterIcons::Light, "triangle"),
        (StarterIcons::Ascii, "lean"),
        (StarterIcons::Unicode, "lean"),
    ] {
        let given = Given {
            icons: Some(icons),
            mode: Some(StarterMode::Auto),
        };
        let m = Model::new(l.clone(), Target::New, given);
        assert_eq!(
            STYLES[usize::from(m.chosen(Row::Style))],
            preset,
            "{icons:?}"
        );
        assert_eq!(ICONS[usize::from(m.chosen(Row::Icons))], icons.word());
        assert!(m.marked(Row::Icons) && m.marked(Row::Colors), "{icons:?}");
        assert!(!m.changed());
    }
    let dark = Model::new(
        l.clone(),
        Target::New,
        Given {
            icons: None,
            mode: Some(StarterMode::Dark),
        },
    );
    assert_eq!(dark.chosen(Row::Colors), 1);
    // The four sets of the editor are the icon sets of the config.
    for (i, name) in ICONS.iter().enumerate() {
        assert_eq!(
            bingsu_core::icons::IconSet::parse(name).map(|s| s as usize),
            Some(i)
        );
    }
    assert_eq!(PRESETS.iter().map(|p| p.name).collect::<Vec<_>>(), STYLES);
}

// 이것을 실패시키는 것: 아이콘을 바꾸면 손대지 않은 새 파일의 프리셋이 따라가지 않는 것, 모양 줄을 하나라도
// 바꾼 뒤에도 따라가는 것(프리셋이 바뀌어 사용자가 고른 끝이 지워진다), 프리셋을 바꿀 때 부분 키를 남기는 것과 그것을
// 알리지 않는 것, `u` 한 번이 둘을 함께 되돌리지 않거나 `u` 두 번이 원래대로가 아닌 것, `r`을 되돌릴 수 없는 것.
#[test]
fn presets_reset_parts_and_one_undo_brings_them_back() {
    let mut m = fresh();
    assert_eq!(key(&mut m, Key::Char(b'i'), 1), Effect::Draw);
    assert_eq!(m.chosen(Row::Icons), 1);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "triangle");
    key(&mut m, Key::Char(b'i'), 2);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "lean");
    // A shape row touched: icons no longer pick the preset.
    key(&mut m, Key::Char(b's'), 3);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "triangle");
    key(&mut m, Key::Char(b'o'), 4);
    let outer = m.written(Row::Outer);
    assert!(outer.is_some());
    key(&mut m, Key::Char(b'I'), 5);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "triangle");
    assert_eq!(m.written(Row::Outer), outer);
    // A preset change takes the part keys, in one step undone.
    key(&mut m, Key::Char(b's'), 6);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "pill");
    assert_eq!(m.written(Row::Outer), None);
    assert_eq!(m.note(), Some(Note::PartsReset));
    key(&mut m, Key::Char(b'u'), 7);
    assert_eq!(m.written(Row::Outer), outer);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "triangle");
    key(&mut m, Key::Char(b'u'), 8);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "pill");
    assert_eq!(m.written(Row::Outer), None);
    key(&mut m, Key::Char(b'u'), 9);
    assert_eq!(m.written(Row::Outer), outer);
    // r, then u.
    key(&mut m, Key::Char(b'r'), 10);
    assert!(!m.changed());
    key(&mut m, Key::Char(b'u'), 11);
    assert_eq!(m.written(Row::Outer), outer);
}

// 이것을 실패시키는 것: 바꾼 것이 있을 때 `q` 한 번에 나가는 것, 같은 읽기의 두 번째 `q`(`qq` 붙여 넣기)를 확인으로
// 치는 것, 다른 키 뒤에도 기다리던 `q`가 남는 것, 저장 화면을 연 Enter와 같은 읽기의 Enter(`\r\n`)로 쓰는 것,
// Ctrl-C를 바로 취소로 하지 않는 것, 화면이 작을 때 값 키를 받는 것.
#[test]
fn confirmations_need_a_later_read() {
    let mut m = fresh();
    assert_eq!(key(&mut m, Key::Char(b'q'), 1), Effect::Quit);
    key(&mut m, Key::Char(b'g'), 1);
    assert!(m.changed());
    assert_eq!(key(&mut m, Key::Char(b'q'), 2), Effect::Draw);
    assert_eq!(m.note(), Some(Note::QuitAgain));
    assert_eq!(key(&mut m, Key::Char(b'q'), 2), Effect::Draw);
    assert_eq!(key(&mut m, Key::Char(b'q'), 3), Effect::Quit);
    let mut m = fresh();
    key(&mut m, Key::Char(b'g'), 1);
    key(&mut m, Key::Char(b'q'), 2);
    key(&mut m, Key::Down, 3);
    assert_eq!(key(&mut m, Key::Char(b'q'), 4), Effect::Draw);
    // Save: the Enter that opened the screen's read does not confirm.
    assert_eq!(key(&mut m, Key::Enter, 5), Effect::Draw);
    assert!(matches!(m.screen(), Screen::Save { opened: 5 }));
    assert_eq!(key(&mut m, Key::Enter, 5), Effect::None);
    assert_eq!(key(&mut m, Key::Enter, 6), Effect::Write);
    assert_eq!(key(&mut m, Key::Ctrl(b'c'), 6), Effect::Cancel);
    let mut e = Model::new(
        layers(&load("icons = \"nerd\"\n", &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    key(&mut e, Key::Enter, 1);
    assert_eq!(key(&mut e, Key::Char(b'y'), 2), Effect::Report);
    let mut m = fresh();
    m.set_too_small(true);
    let before = m.chosen(Row::Style);
    assert_eq!(key(&mut m, Key::Char(b's'), 1), Effect::None);
    assert_eq!(m.chosen(Row::Style), before);
    assert_eq!(key(&mut m, Key::Char(b'q'), 2), Effect::Quit);
}

// 이것을 실패시키는 것: 행 키·화살표·숫자·Space·대문자가 설계의 키 표와 다르게 움직이는 것, 줄 이동이 값을
// 바꾸는 것, 줄 이동이 되돌리기 기록을 바꾸는 것, 목록 밖 숫자를 받는 것, `?`·Esc가 겹창을 열고 닫지 않는 것.
#[test]
fn the_key_table() {
    let mut m = fresh();
    key(&mut m, Key::Char(b'j'), 1);
    assert_eq!(m.row(), Row::Joint);
    key(&mut m, Key::Down, 2);
    assert_eq!(m.row(), Row::Inner);
    key(&mut m, Key::BackTab, 3);
    key(&mut m, Key::BackTab, 4);
    assert_eq!(m.row(), Row::Outer);
    key(&mut m, Key::Tab, 5);
    assert_eq!(m.row(), Row::Joint);
    key(&mut m, Key::Char(b'5'), 6);
    assert_eq!(JOINTS[usize::from(m.chosen(Row::Joint))], "none");
    assert_eq!(key(&mut m, Key::Char(b'9'), 7), Effect::None);
    assert_eq!(JOINTS[usize::from(m.chosen(Row::Joint))], "none");
    key(&mut m, Key::Right, 8);
    assert_eq!(JOINTS[usize::from(m.chosen(Row::Joint))], "caps");
    key(&mut m, Key::Char(b' '), 9);
    assert_eq!(JOINTS[usize::from(m.chosen(Row::Joint))], "triangle");
    key(&mut m, Key::Left, 10);
    key(&mut m, Key::Char(b'J'), 11);
    assert_eq!(JOINTS[usize::from(m.chosen(Row::Joint))], "none");
    key(&mut m, Key::Up, 12);
    key(&mut m, Key::Char(b'u'), 13);
    assert_eq!(JOINTS[usize::from(m.chosen(Row::Joint))], "caps");
    key(&mut m, Key::Char(b'?'), 14);
    assert_eq!(m.screen(), Screen::Keys);
    key(&mut m, Key::Char(b's'), 15);
    assert_eq!(m.screen(), Screen::Keys);
    key(&mut m, Key::Esc, 16);
    assert_eq!(m.screen(), Screen::Main);
    assert_eq!(key(&mut m, Key::Esc, 17), Effect::None);
    assert_eq!(key(&mut m, Key::Ctrl(b'd'), 18), Effect::None);
    assert_eq!(GAPS.len(), 2);
}

// 이것을 실패시키는 것: 있는 파일의 바꿀 줄이 바뀐 줄만이 아닌 것, TOML에 표 이름 없이 또는 JSON에 TOML 줄로
// 알리는 것, 지울 키를 "지움"으로 알리지 않는 것, 파일의 지금 값(목록에 없는 값 포함)을 정제해 보이지 않는 것, 뒤
// 출처가 덮는 키에 그 이름을 붙이지 않는 것, 있는 파일에 쓸 글을 만드는 것.
#[test]
fn an_existing_file_gets_the_lines_to_change() {
    let target = "icons = \"nerd\"\n[style]\nseparator = \"r\\u001b[2Jx\"\ngap = true\n";
    let later = [("conf.d/a.toml", "[style]\nouter_end = \"round\"\n")];
    let l = layers(&load(target, &later, &[]));
    let mut m = Model::new(l.clone(), Target::Existing(Format::Toml), Given::default());
    assert!(changes(&m).is_empty() && new_file_text(&m).is_none());
    m.remove_override(Row::Gap);
    m.pick(Row::Joint, 4);
    m.pick(Row::Outer, 2);
    m.pick(Row::Icons, 3);
    let c = changes(&m);
    let lines: Vec<String> = c
        .iter()
        .map(|c| format!("{}|{}|{}|{}", c.key, c.now, c.chosen, c.line))
        .collect();
    assert_eq!(
        lines,
        [
            "style.outer_end|not set|\"round\"|under [style]: outer_end = \"round\"",
            "style.separator|\"r[2Jx\"|\"none\"|under [style]: separator = \"none\"",
            "style.gap|true|not set|delete gap under [style]",
            "icons|\"nerd\"|\"ascii\"|icons = \"ascii\"",
        ]
    );
    assert!(c[0].covered_by.is_some() && c[1].covered_by.is_none());
    let mut j = Model::new(l, Target::Existing(Format::Json), Given::default());
    j.remove_override(Row::Gap);
    j.pick(Row::Lines, 1);
    let lines: Vec<String> = changes(&j).iter().map(|c| c.line.clone()).collect();
    assert_eq!(
        lines,
        [
            "delete style.gap",
            "layout.line1.left: [\"host\", \"dir\", \"git\", \"char\"]",
            "layout.line2.enabled: false",
        ]
    );
}

// 이것을 실패시키는 것: 긴 머신 이름(CI 러너의 61자)을 미리보기 줄에 다 넣으려고 줄 폭을 넘기는 것, 자를 때 줄임표 없이
// 자르는 것, 이름의 앞부분을 남기지 않는 것. 편집판 시험(`test_the_preview_follows_each_key`)은 이 모양으로 머신 이름을 찾는다.
#[test]
fn a_long_host_name_is_cut_with_an_ellipsis() {
    let host = "sjc22-bt144-881efc80-108a-428d-bc68-0d60264e3be6-92F81018D27A";
    let c = compiled(load("", &[], &[]));
    let left = |cols: u16| {
        let l = lines(
            &c,
            &Request {
                mode: Mode::Dark,
                icons: c.icons,
                depth: ColorDepth::TrueColor,
                width: cols,
                sample: Sample {
                    pwd: b"/home/u/src",
                    home: Some(b"/home/u"),
                    host: Some(host.as_bytes()),
                },
            },
        );
        l[0].left.text().to_string()
    };
    // At 80 columns it does not fit: a prefix, then the ellipsis.
    let cut = left(80);
    assert!(!cut.contains(host), "{cut:?}");
    let kept = (1..host.len())
        .rev()
        .find(|k| cut.contains(&format!("{}\u{2026}", &host[..*k])))
        .unwrap_or(0);
    assert!(kept >= 8, "{cut:?}");
    // At 120 it fits whole.
    assert!(left(120).contains(&format!(" {host} ")), "{:?}", left(120));
}

fn view_lines(c: &CompiledConfig, cols: u16) -> Vec<PreviewLine> {
    lines(
        c,
        &Request {
            mode: Mode::Dark,
            icons: c.icons,
            depth: ColorDepth::TrueColor,
            width: cols,
            sample: Sample {
                pwd: b"/home/u/src",
                home: Some(b"/home/u"),
                host: Some(b"ice-box"),
            },
        },
    )
}

fn screen(m: &Model, path: &[u8], cols: u16, rows: u16) -> Grid {
    let c = compiled(load(&new_file_text(m).unwrap_or_default(), &[], &[]));
    let lines = view_lines(&c, cols);
    draw(
        m,
        &View {
            cols,
            rows,
            path,
            lines: &lines,
            palette: &c.palette,
            mode: Mode::Dark,
            depth: ColorDepth::TrueColor,
            mode_note: "auto: dark (no COLORFGBG)",
            terminal: None,
            narrow: cols < 60,
            mono: false,
        },
    )
}

fn text(g: &Grid) -> Vec<String> {
    text_of(g)
}

fn text_of(g: &Grid) -> Vec<String> {
    (0..g.rows()).map(|y| g.row_text(y)).collect()
}

const PATH: &[u8] = b"/home/u/.config/bingsu/config.toml";

// 이것을 실패시키는 것: 크기별 배치가 설계와 다른 것(80칸 이상은 값 전부, 60–79는 하나만, 24줄과 60칸 미만은 그릇
// 자리 없음, 40×16 미만은 "too small", 12×3 미만은 빈 화면), 어느 줄이든 칸 폭을 넘거나 마지막 칸을 쓰는 것, 지금 줄
// `>`·쓸 줄 `*`·이유 글이 색 없이도 보이지 않는 것, 키 안내가 좁은 폭에서 줄지 않는 것.
#[test]
fn every_size_lays_out_inside_its_width() {
    let mut m = fresh();
    m.pick(Row::Style, 0);
    for (cols, rows) in [
        (80, 24),
        (79, 24),
        (60, 20),
        (59, 24),
        (40, 16),
        (39, 16),
        (12, 3),
        (1, 1),
        (200, 50),
    ] {
        let g = screen(&m, PATH, cols, rows);
        assert_eq!((g.cols(), g.rows()), (cols, rows));
        for y in 0..rows {
            let row = g.row_text(y);
            let w = bingsu_core::width::str_width(&row, bingsu_core::width::WidthProfile::DEFAULT);
            assert_eq!(w, u32::from(cols), "{cols}x{rows} row {y}: {row:?}");
            assert_eq!(
                g.cell(cols - 1, y).text,
                " ",
                "{cols}x{rows} row {y}: {row:?}"
            );
        }
    }
    let t = text(&screen(&m, PATH, 80, 24));
    assert!(
        t[0].starts_with(" bingsu setup") && t[0].trim_end().ends_with("config.toml  new file"),
        "{:?}",
        t[0]
    );
    assert!(t[8].starts_with(" preview  80 columns, auto: dark (no COLORFGBG), sample values"));
    assert!(
        t[12].starts_with(">* s style     lean  triangle  pill"),
        "{:?}",
        t[12]
    );
    assert!(
        t[13].starts_with("   o outer    [none] triangle"),
        "{:?}",
        t[13]
    );
    assert!(
        t[13].contains("no ends without a background"),
        "{:?}",
        t[13]
    );
    assert!(
        t[17].starts_with(" * i icons     nerd  light  unicode  ascii"),
        "{:?}",
        t[17]
    );
    assert!(
        t[21].starts_with(" writes 2 keys: style.preset, icons"),
        "{:?}",
        t[21]
    );
    assert!(
        t[23].starts_with(
            " s o j n g i c l change  arrows move  ? keys  u undo  enter save  q quit"
        )
    );
    let t = text(&screen(&m, PATH, 79, 24));
    assert!(
        t[12].starts_with(">* s style     < lean >  1/8"),
        "{:?}",
        t[12]
    );
    let t = text(&screen(&m, PATH, 60, 20));
    assert!(
        t[1].trim().is_empty() && t[2].starts_with(" preview  60 columns"),
        "{t:#?}"
    );
    let t = text(&screen(&m, PATH, 40, 16));
    assert!(
        t.iter().any(|l| l.starts_with(">* s style     < lean >")),
        "{t:#?}"
    );
    assert!(t[15].starts_with(" ? keys  enter save  q quit"), "{t:#?}");
    assert!(
        t.iter()
            .any(|l| l.contains("narrow layout under 60 columns")),
        "{t:#?}"
    );
    let t = text(&screen(&m, PATH, 39, 16));
    assert!(
        t[1].starts_with(" Too small: 40x16 or more needed."),
        "{t:#?}"
    );
    let t = text(&screen(&m, PATH, 12, 3));
    assert_eq!(t[0], " bingsu set ");
    let t = text(&screen(&m, PATH, 11, 3));
    assert!(t.iter().all(|l| l.trim().is_empty()), "{t:#?}");
}

// 이것을 실패시키는 것: 경로·다른 설정 파일 이름의 제어 글자(OSC 52, CSI 2J)나 bidi(U+202E)를 정제하지 않고 칸에
// 두는 것, 긴 경로를 가운데에서 `...`로 줄이지 않는 것.
#[test]
fn text_from_outside_is_sanitized_and_cut() {
    let hostile = "\u{1b}]52;c;cHduZWQ=\u{7}\u{1b}[2J\u{202e}evil";
    let later_name = format!("conf.d/{hostile}.toml");
    let later = [(later_name.as_str(), "[style]\nouter_end = \"round\"\n")];
    let l = layers(&load("", &later, &[]));
    let mut m = Model::new(l, Target::New, Given::default());
    m.pick(Row::Outer, 1);
    let path = format!("/home/u/{hostile}/{}/config.toml", "deep".repeat(30));
    for (cols, rows) in [(80, 24), (60, 16), (40, 16)] {
        let mut grids = vec![screen(&m, path.as_bytes(), cols, rows)];
        key(&mut m, Key::Enter, 1);
        grids.push(screen(&m, path.as_bytes(), cols, rows));
        key(&mut m, Key::Esc, 2);
        for g in grids {
            let all: String = text(&g).concat();
            assert!(
                !all.chars().any(bingsu_core::sanitize::is_removed),
                "{cols}x{rows}: {all:?}"
            );
        }
    }
    let t = text(&screen(&m, path.as_bytes(), 80, 24));
    assert!(
        t[0].contains("...") && t[0].contains("/config.toml  new file"),
        "{:?}",
        t[0]
    );
    assert!(t[13].contains("overridden by conf.d/]52;"), "{:?}", t[13]);
    assert!(
        t[21].starts_with(" style.outer_end covered by conf.d/]52;"),
        "{:?}",
        t[21]
    );
}

// 이것을 실패시키는 것: 대상이 적용 순서에 없을 때 다른 출처를 앞 출처로 치지 않는 것, 내장 기본과 같아도
// `extends`가 주는 값을 이겨야 하는 값을 쓰지 않는 것, 있는 파일에서 아이콘이 프리셋을 고르는 것, 고칠 것 없는
// Backspace가 무언가 바꾸는 것, Backspace로 스타일 줄을 지운 뒤에도 아이콘이 프리셋을 고르는 것.
#[test]
fn defaults_overrides_and_who_picks_the_preset() {
    let r = load("icons = \"nerd\"\n", &[], &[]);
    let gone = Layers::from_sources(&r.files, &r.order, SourceId(999));
    assert_eq!(gone.rows[Row::Icons.index()].written, None);
    assert_eq!(gone.rows[Row::Icons.index()].earlier, Some(0));
    assert_eq!(gone.rows[Row::Style.index()].earlier, Some(1));
    // `extends` gives the inherited value; picking the preset's own value
    // over it is written.
    let base = [("base", "[style]\nouter_end = \"slant\"\n")];
    let l = layers(&load("extends = [\"base\"]\n", &[], &base));
    let mut m = Model::new(l, Target::New, Given::default());
    let slant = ENDS.iter().position(|e| *e == "slant").unwrap() as u8;
    assert_eq!((m.chosen(Row::Outer), m.written(Row::Outer)), (slant, None));
    m.pick(Row::Outer, 0);
    assert_eq!((m.chosen(Row::Outer), m.written(Row::Outer)), (0, Some(0)));
    assert_eq!(m.remove_override(Row::Joint), Effect::None);
    // An existing file keeps its preset whatever the icons.
    let mut e = Model::new(
        layers(&load("[style]\npreset = \"pill\"\n", &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    e.pick(Row::Icons, 3);
    assert_eq!(STYLES[usize::from(e.chosen(Row::Style))], "pill");
    // Backspace on the style row is a shape change.
    let mut m = fresh();
    m.pick(Row::Icons, 2);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "lean");
    m.remove_override(Row::Style);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "triangle");
    m.pick(Row::Icons, 3);
    assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "triangle");
}

// 이것을 실패시키는 것: Ctrl-Z·Ctrl-L이 정지·다시 그리기가 아니거나 기다리던 `q`를 지우는 것, 알림만 바뀐 키에
// 그리지 않는 것(알림이 남는다).
#[test]
fn control_keys_keep_a_pending_quit() {
    let mut m = fresh();
    m.pick(Row::Gap, 1);
    key(&mut m, Key::Char(b'q'), 1);
    assert_eq!(key(&mut m, Key::Ctrl(b'z'), 2), Effect::Suspend);
    assert_eq!(key(&mut m, Key::Ctrl(b'l'), 3), Effect::Redraw);
    assert_eq!(key(&mut m, Key::Char(b'q'), 4), Effect::Quit);
    key(&mut m, Key::Char(b'q'), 5);
    assert_eq!(key(&mut m, Key::Esc, 6), Effect::Draw);
    assert_eq!(m.note(), None);
    assert_eq!(key(&mut m, Key::Esc, 7), Effect::None);
}

// 이것을 실패시키는 것: 2줄을 물려받은 1줄 위에 쓰지 않는 것(위 줄을 내장 값으로, 아래 줄을 켜서), 그 주석이 내장
// 줄 주석과 같은 것.
#[test]
fn two_lines_over_an_inherited_single_line() {
    let base = [(
        "base",
        "[layout.line1]\nleft = [\"dir\", \"char\"]\n[layout.line2]\nenabled = false\n",
    )];
    let head = "extends = [\"base\"]\n";
    let mut m = Model::new(
        layers(&load(head, &[], &base)),
        Target::New,
        Given::default(),
    );
    assert_eq!(m.chosen(Row::Lines), 1);
    m.pick(Row::Lines, 0);
    let text = new_file_text(&m).unwrap();
    assert!(
        text.contains("left = [\"host\", \"dir\", \"git\"]\n\n[layout.line2]\nenabled = true\n"),
        "{text}"
    );
    assert!(
        text.contains("follow the lines your other files set"),
        "{text}"
    );
    let c = compiled(load(&format!("{head}{text}"), &[], &base));
    assert_eq!(c.variants[0].len(), 2);
    // The save screen shows the pair as the lines' change.
    key(&mut m, Key::Enter, 1);
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let t = text_of(&draw(&m, &view(&m, &c, &lines, 80, 24))).concat();
    assert!(
        t.contains("layout.line1.left = [\"host\", \"dir\", \"git\"]"),
        "{t}"
    );
    assert!(t.contains("layout.line2.enabled = true"), "{t}");
    // A later file that keeps one line covers the pair.
    let later = [("conf.d/one.toml", "[layout.line2]\nenabled = false\n")];
    let mut covered = Model::new(
        layers(&load("", &later, &[])),
        Target::New,
        Given::default(),
    );
    covered.pick(Row::Lines, 0);
    assert_eq!(covered.written(Row::Lines), None);
    assert_eq!(
        (covered.chosen(Row::Lines), covered.effective(Row::Lines)),
        (0, 1)
    );
    let t = text_of(&draw(&covered, &view(&covered, &c, &lines, 80, 24)));
    assert!(
        t[19].contains("overridden by conf.d/one.toml"),
        "{:?}",
        t[19]
    );
    covered.pick(Row::Lines, 1);
    covered.pick(Row::Lines, 0);
    assert_eq!(covered.written(Row::Lines), None);
    let mut one = fresh();
    one.pick(Row::Lines, 1);
    let text = new_file_text(&one).unwrap();
    assert!(text.contains("follow the built-in lines"), "{text}");
    assert_eq!(compiled(load(&text, &[], &[])).variants[0].len(), 1);
}

fn view<'a>(
    m: &Model,
    c: &'a CompiledConfig,
    lines: &'a [PreviewLine],
    cols: u16,
    rows: u16,
) -> View<'a> {
    let _ = m;
    View {
        cols,
        rows,
        path: PATH,
        lines,
        palette: &c.palette,
        mode: Mode::Dark,
        depth: ColorDepth::TrueColor,
        mode_note: "dark",
        terminal: None,
        narrow: cols < 60,
        mono: false,
    }
}

// 이것을 실패시키는 것: NO_COLOR에서 편집판 글에 색을 쓰는 것, 고른 값을 반전·굵게로 표시하지 않는 것(색만 신호가
// 됨), 효과 없는 고른 값을 고른 값과 같게 그리는 것, 미리보기의 색까지 지우는 것, 반전을 SGR 7로 쓰지 않는 것.
#[test]
fn without_color_the_pick_is_reversed_and_only_the_preview_keeps_color() {
    use bingsu_core::color::sgr::{BOLD, Ink, Paint, REVERSE, write_paint};
    let mut m = fresh();
    m.pick(Row::Style, 0);
    let c = compiled(load(&new_file_text(&m).unwrap(), &[], &[]));
    let lines = view_lines(&c, 80);
    let colored = draw(&m, &view(&m, &c, &lines, 80, 24));
    let base = c.palette.background;
    let base = Ink::Rgb(base.r, base.g, base.b);
    let preview: Vec<u16> = (0..24)
        .filter(|&y| colored.cell(78, y).paint.bg == base)
        .collect();
    assert!(!preview.is_empty());
    let mut v = view(&m, &c, &lines, 80, 24);
    v.mono = true;
    let g = draw(&m, &v);
    let pick = g.cell(15, 12).paint;
    assert_eq!(
        pick,
        Paint {
            fg: Ink::Default,
            bg: Ink::Default,
            attrs: BOLD | REVERSE,
        }
    );
    // A pick that changes nothing: brackets, no reverse, no color.
    let idle = g.cell(15, 13).paint;
    assert_eq!(idle, Paint::default());
    assert!(g.row_text(13).starts_with("   o outer    [none] "));
    let mut painted = Vec::new();
    for y in 0..24 {
        for x in 0..80 {
            let p = g.cell(x, y).paint;
            if (p.fg != Ink::Default || p.bg != Ink::Default) && !painted.contains(&y) {
                painted.push(y);
            }
        }
    }
    assert!(!painted.is_empty(), "the preview keeps its colors");
    assert!(
        painted.iter().all(|y| preview.contains(y)),
        "{painted:?} {preview:?}"
    );
    // Too small: no preview, and nothing of bingsu's own has a color.
    v.cols = 30;
    v.rows = 10;
    let g = draw(&m, &v);
    for y in 0..10 {
        for x in 0..30 {
            let p = g.cell(x, y).paint;
            assert_eq!((p.fg, p.bg), (Ink::Default, Ink::Default), "{x},{y}");
        }
    }
    let mut out = Vec::new();
    write_paint(pick, &mut out);
    assert!(out.starts_with(b"\x1b[0;1;7"), "{out:?}");
}

// 이것을 실패시키는 것: 줄 끝 알림의 차례(템플릿 > 덮음 > 효과 없음 > 같은 모양 > 터미널 색)나 문구가 다른 것,
// 효과 없는 고른 값을 괄호 없이, 또는 상자(바탕색)나 보조 글색이 아닌 색으로 그리는 것, 미리보기 빈 바탕을 모드의 `neutral.base`로
// 칠하지 않는 것, 다른 폭의 미리보기를 받으면 넘치는 것, 아이콘 안내가 nerd·light 밖에서나 아이콘을 바꾼 뒤에도
// 보이는 것, 좁은 폭 안내의 긴 꼴과 짧은 꼴, 키 안내의 긴 꼴(79칸)과 짧은 꼴(70칸), 제목의 상태 글.
#[test]
fn row_notes_paints_and_hints() {
    let mut m = fresh();
    m.pick(Row::Style, 0);
    let c = compiled(load(&new_file_text(&m).unwrap(), &[], &[]));
    let lines = view_lines(&c, 80);
    let g = draw(&m, &view(&m, &c, &lines, 80, 24));
    let t = text(&g);
    assert!(t[14].contains("one blank cell"), "{:?}", t[14]);
    assert!(t[16].contains("only with none or caps"), "{:?}", t[16]);
    // The picked `none` of outer changes nothing: `[none]` in the subtext
    // color on the screen's background, weaker than `lean`'s accent box.
    let idle = g.cell(15, 13).paint;
    let pick = g.cell(15, 12).paint;
    assert_ne!(idle.bg, pick.bg);
    let at = |name: &str| {
        let c = bingsu_core::color::palette::named_color(name, Mode::Dark, true).unwrap();
        bingsu_core::color::sgr::Ink::Rgb(c.r, c.g, c.b)
    };
    assert_eq!(idle.fg, at("neutral.subtext"));
    assert_eq!(idle.bg, g.cell(79, 13).paint.bg);
    assert_eq!(g.cell(14, 13).text, "[");
    assert_eq!(g.cell(19, 13).text, "]");
    assert_eq!(g.cell(14, 13).paint, idle);
    // Under 80 columns the one value shown keeps its brackets.
    let narrow = view_lines(&c, 70);
    let t70 = text(&draw(&m, &view(&m, &c, &narrow, 70, 24)));
    assert!(t70[13].contains("<[none]>"), "{:?}", t70[13]);
    assert!(t70[12].contains("< lean >"), "{:?}", t70[12]);
    let base = c.palette.background;
    assert_eq!(
        g.cell(78, 9).paint.bg,
        bingsu_core::color::sgr::Ink::Rgb(base.r, base.g, base.b)
    );
    // Lines laid out for another width (a resize) stay inside the grid.
    let wide = view_lines(&c, 120);
    let g = draw(&m, &view(&m, &c, &wide, 80, 24));
    assert_eq!(g.cell(79, 9).text, " ");
    // Look-alike shapes, with a block preset and unicode icons.
    let mut u = fresh();
    u.pick(Row::Icons, 2);
    u.pick(Row::Style, 1);
    let t = text(&draw(&u, &view(&u, &c, &lines, 80, 24)));
    assert!(t[13].contains("3 shapes look alike here"), "{:?}", t[13]);
    assert!(t[11].trim().is_empty(), "{:?}", t[11]);
    // The terminal's own answer, when colors follow it.
    let mut v = view(&u, &c, &lines, 80, 24);
    v.terminal = Some(Mode::Light);
    let t = text(&draw(&u, &v));
    assert!(
        t[18].contains("the terminal looks light; pick light"),
        "{:?}",
        t[18]
    );
    u.pick(Row::Colors, 1);
    let t = text(&draw(&u, &v));
    assert!(!t[18].contains("terminal looks"), "{:?}", t[18]);
    // The icons hint goes once the icons row changed, also back to nerd.
    let mut h = fresh();
    assert!(text(&draw(&h, &view(&h, &c, &lines, 80, 24)))[11].contains("Boxes or blanks"));
    h.pick(Row::Icons, 1);
    assert!(
        text(&draw(&h, &view(&h, &c, &lines, 80, 24)))[11]
            .trim()
            .is_empty()
    );
    let given = Model::new(
        layers(&load("", &[], &[])),
        Target::New,
        Given {
            icons: Some(StarterIcons::Unicode),
            mode: None,
        },
    );
    assert!(
        text(&draw(&given, &view(&given, &c, &lines, 80, 24)))[11]
            .trim()
            .is_empty()
    );
    // A template replaces the shape rows.
    let later = [(
        "config.local.toml",
        "[style]\ntemplate = \"{dir}{@nl}{char}\"\n",
    )];
    let tm = Model::new(
        layers(&load("", &later, &[])),
        Target::New,
        Given::default(),
    );
    let t = text(&draw(&tm, &view(&tm, &c, &lines, 80, 24)));
    assert!(
        t[16].contains("a template in config.local.toml replaces these"),
        "{:?}",
        t[15]
    );
    assert!(!t[17].contains("template"), "{:?}", t[17]);
    // Narrow notes and key lines by width.
    let n50 = text(&draw(&m, &view(&m, &c, &view_lines(&c, 50), 50, 18)));
    assert!(
        n50.iter()
            .any(|l| l.contains("narrow layout under 60 columns; widen to compare"))
    );
    let k79 = text(&draw(&m, &view(&m, &c, &view_lines(&c, 79), 79, 24)));
    assert!(
        k79[23].starts_with(" s o j n g i c l change"),
        "{:?}",
        k79[23]
    );
    let k70 = text(&draw(&m, &view(&m, &c, &view_lines(&c, 70), 70, 24)));
    assert!(
        k70[23].starts_with(" ? keys  enter save  q quit"),
        "{:?}",
        k70[23]
    );
    let k59 = text(&draw(&m, &view(&m, &c, &view_lines(&c, 59), 59, 24)));
    assert!(k59[2].starts_with(" preview  59 columns"), "{k59:#?}");
    let mut rom = m.clone();
    rom.set_read_only(true);
    assert!(
        text(&draw(&rom, &view(&rom, &c, &lines, 80, 24)))[0]
            .trim_end()
            .ends_with("read only")
    );
    let ex = Model::new(
        layers(&load("", &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    assert!(
        text(&draw(&ex, &view(&ex, &c, &lines, 80, 24)))[0]
            .trim_end()
            .ends_with("exists: not changed")
    );
    let blank = draw(&m, &view(&m, &c, &lines, 12, 2));
    assert!(text(&blank).iter().all(|l| l.trim().is_empty()));
}

// 이것을 실패시키는 것: 한 줄 프롬프트가 줄어든 화면에서 미리보기 두 줄 자리를 차지하는 것, 상태 줄이 바꿀 것 없음·
// 한 키·여러 키를 다르게 말하지 않는 것, 저장 화면이 N501·한 줄 안내를 쓸 때만 쓰지 않는 것, 읽기 전용에서 쓰기를
// 권하는 것, 있는 파일 저장 화면의 제목·"이미 그 값" 문구, 넘치는 줄을 `...`로 줄이지 않는 것.
#[test]
fn status_and_save_screens() {
    let mut one = fresh();
    one.pick(Row::Lines, 1);
    let c1 = compiled(load(&new_file_text(&one).unwrap(), &[], &[]));
    let l1 = view_lines(&c1, 60);
    assert_eq!(l1.len(), 1);
    let t = text(&draw(&one, &view(&one, &c1, &l1, 60, 16)));
    assert!(
        t[2].starts_with(" ") && t[3].contains("Boxes or blanks"),
        "{t:#?}"
    );
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let mut e = Model::new(
        layers(&load(
            "[style]\ngap = true\nouter_end = \"round\"\n",
            &[],
            &[],
        )),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    let status = |m: &Model| text(&draw(m, &view(m, &c, &lines, 80, 24)))[21].clone();
    assert!(status(&e).starts_with(" no changes"), "{}", status(&e));
    e.remove_override(Row::Gap);
    assert!(
        status(&e).starts_with(" changes 1 key: style.gap"),
        "{}",
        status(&e)
    );
    e.remove_override(Row::Outer);
    assert!(
        status(&e).starts_with(" changes 2 keys: style.outer_end, style.gap"),
        "{}",
        status(&e)
    );
    key(&mut e, Key::Enter, 1);
    let t = text(&draw(&e, &view(&e, &c, &lines, 80, 24)));
    assert!(
        t[0].starts_with(" config.toml is already there; bingsu does not change it."),
        "{t:#?}"
    );
    assert!(
        t.iter().any(|l| l.contains("delete gap under [style]")),
        "{t:#?}"
    );
    assert!(
        t[23].starts_with(" enter print and quit  esc back"),
        "{t:#?}"
    );
    let mut same = Model::new(
        layers(&load("", &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    key(&mut same, Key::Enter, 1);
    let t = text(&draw(&same, &view(&same, &c, &lines, 80, 24)));
    assert!(
        t.iter()
            .any(|l| l.contains("It already has the choices you made.")),
        "{t:#?}"
    );
    // New file: the notes only when they hold.
    let mut m = fresh();
    key(&mut m, Key::Enter, 1);
    let plain = text(&draw(&m, &view(&m, &c, &lines, 80, 24))).concat();
    assert!(
        !plain.contains("Under 60 columns") && !plain.contains("1 line:"),
        "{plain}"
    );
    assert!(plain.contains("enter write  esc back  q quit"));
    key(&mut m, Key::Esc, 2);
    m.pick(Row::Outer, 2);
    m.pick(Row::Lines, 1);
    key(&mut m, Key::Enter, 3);
    let both = text(&draw(&m, &view(&m, &c, &lines, 80, 24))).concat();
    assert!(
        both.contains("Under 60 columns the built-in narrow layout draws instead"),
        "{both}"
    );
    assert!(both.contains("1 line: under 60 columns"), "{both}");
    // Read only: the save screen says so, and confirming writes nothing.
    m.set_read_only(true);
    assert!(
        text(&draw(&m, &view(&m, &c, &lines, 80, 24)))
            .concat()
            .contains("The folder cannot be written.")
    );
    assert_eq!(key(&mut m, Key::Enter, 4), Effect::None);
    m.set_read_only(false);
    assert_eq!(key(&mut m, Key::Enter, 5), Effect::Write);
    // More lines than rows: the last that fits says there is more.
    let mut many = Model::new(
        layers(&load(
            "icons = \"nerd\"\n[style]\npreset = \"pill\"\nouter_end = \"round\"\nseparator = \"round\"\ninner_end = \"round\"\ngap = true\n[colors]\nmode = \"dark\"\n",
            &[],
            &[],
        )),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    for r in Row::ALL {
        many.remove_override(r);
    }
    many.pick(Row::Lines, 1);
    key(&mut many, Key::Enter, 1);
    let t = text(&draw(&many, &view(&many, &c, &lines, 40, 16)));
    assert!(t[14].starts_with(" ..."), "{t:#?}");
}

// 이것을 실패시키는 것: 끝 자르기가 `...`를 붙이지 않거나 칸을 넘는 것, 가운데 자르기가 앞과 끝을 남기지 않는 것.
#[test]
fn cutting_by_cells() {
    use bingsu_core::setup_editor::screen::{cut_end, cut_middle};
    assert_eq!(cut_end("abcdef", 6), "abcdef");
    assert_eq!(cut_end("abcdef", 5), "ab...");
    assert_eq!(cut_end("abcdef", 2), "..");
    assert_eq!(cut_end("\u{6f22}\u{5b57}x", 4), "...");
    assert_eq!(cut_middle("abcdefghij", 7), "ab...ij");
    assert_eq!(cut_middle("abcdefghij", 4), "a...");
}

// 이것을 실패시키는 것: 터미널 드라이버가 주는 창 크기(0–65535)를 그대로 칸 격자 크기로 쓰는 것(65535×65535면
// 칸 43억 개를 만든다), 0×0에서 넘치거나 멈추는 것.
#[test]
fn the_window_size_is_bounded_before_the_grid() {
    use bingsu_core::setup_editor::screen::{MAX_COLS, MAX_ROWS};
    let m = fresh();
    let c = compiled(load(&new_file_text(&m).unwrap(), &[], &[]));
    let lines = view_lines(&c, MAX_COLS);
    let g = draw(&m, &view(&m, &c, &lines, u16::MAX, u16::MAX));
    assert_eq!((g.cols(), g.rows()), (MAX_COLS, MAX_ROWS));
    assert!(g.row_text(0).starts_with(" bingsu setup"));
    let g = draw(&m, &view(&m, &c, &[], 0, 0));
    assert_eq!((g.cols(), g.rows()), (0, 0));
    let g = draw(&m, &view(&m, &c, &[], u16::MAX, 0));
    assert_eq!((g.cols(), g.rows()), (MAX_COLS, 0));
}

// 이것을 실패시키는 것: 모양 다섯 줄(style, outer, joint, inner, gap) 가운데 style 줄만 아이콘 따라가기를 멈추는 것
// (끝·이음을 바꾼 뒤 아이콘을 바꾸면 프리셋이 바뀌어 그 값이 지워진다), 아이콘 줄이나 색 줄이 멈추게 하는 것.
#[test]
fn any_shape_row_stops_the_icons_from_picking_the_preset() {
    for row in [Row::Style, Row::Outer, Row::Joint, Row::Inner, Row::Gap] {
        let mut m = fresh();
        key(&mut m, Key::Char(row.key()), 1);
        let (style, own) = (m.chosen(Row::Style), m.written(row));
        key(&mut m, Key::Char(b'i'), 2);
        key(&mut m, Key::Char(b'i'), 3);
        assert_eq!(m.chosen(Row::Icons), 2, "{row:?}");
        assert_eq!(m.chosen(Row::Style), style, "{row:?}");
        assert_eq!(m.written(row), own, "{row:?}");
    }
    for row in [Row::Colors, Row::Lines] {
        let mut m = fresh();
        key(&mut m, Key::Char(row.key()), 1);
        key(&mut m, Key::Char(b'i'), 2);
        key(&mut m, Key::Char(b'i'), 3);
        assert_eq!(STYLES[usize::from(m.chosen(Row::Style))], "lean", "{row:?}");
    }
}

// 이것을 실패시키는 것: 부분 키를 지우지 않은 프리셋 바꿈에도 "reset" 알림을 내는 것, 바꿀 것 없는 `r`·`u`가 무언가
// 하는 것, 알림만 남은 화면에서 아무 키나 알림을 지우지 않는 것, `?`가 키 목록을 닫지 않는 것, 저장 화면에서 Esc가
// 돌아가지 않는 것, Backspace 키가 이 파일의 값을 지우지 않는 것, 상태 줄이 마지막 키의 알림을 먼저 보이지 않는 것.
#[test]
fn messages_and_the_other_keys() {
    let mut m = fresh();
    assert_eq!(key(&mut m, Key::Char(b'r'), 1), Effect::None);
    assert_eq!(key(&mut m, Key::Char(b'u'), 2), Effect::None);
    key(&mut m, Key::Char(b's'), 3);
    assert_eq!(m.note(), None);
    key(&mut m, Key::Char(b'u'), 4);
    assert_eq!(m.note(), Some(Note::Undone));
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let t = text(&draw(&m, &view(&m, &c, &lines, 80, 24)));
    assert!(
        t[21].starts_with(" undone; u again brings it back"),
        "{:?}",
        t[21]
    );
    assert_eq!(key(&mut m, Key::Esc, 5), Effect::Draw);
    assert_eq!(m.note(), None);
    key(&mut m, Key::Char(b'?'), 6);
    key(&mut m, Key::Char(b'?'), 7);
    assert_eq!(m.screen(), Screen::Main);
    key(&mut m, Key::Enter, 8);
    key(&mut m, Key::Esc, 9);
    assert_eq!(m.screen(), Screen::Main);
    key(&mut m, Key::Char(b'g'), 10);
    assert_eq!(m.written(Row::Gap), Some(1));
    key(&mut m, Key::Backspace, 11);
    assert_eq!(m.written(Row::Gap), None);
}

// 이것을 실패시키는 것: 배경 없는 프리셋의 이음 `none`·`caps`에도 "one blank cell"을 붙이는 것, 블록 프리셋의 빈칸
// 이유를 "only with caps"가 아니게 쓰는 것, Nerd 글리프에 "3 shapes look alike"를 붙이는 것, 줄 끝 알림의 차례(템플릿
// > 덮음 > 효과 없음), 맨 앞이 결합 표지뿐인 미리보기 쪽이 폭 0 칸을 만드는 것.
#[test]
fn note_order_and_edge_cells() {
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let at = |m: &Model, y: usize| text(&draw(m, &view(m, &c, &lines, 80, 24)))[y].clone();
    let mut lean = fresh();
    lean.pick(Row::Style, 0);
    lean.pick(Row::Joint, 4);
    assert!(
        !at(&lean, 14).contains("one blank cell"),
        "{}",
        at(&lean, 14)
    );
    assert!(!at(&lean, 16).contains("only with"), "{}", at(&lean, 16));
    let tri = fresh();
    assert!(at(&tri, 16).contains("only with caps"), "{}", at(&tri, 16));
    assert!(!at(&tri, 13).contains("look alike"), "{}", at(&tri, 13));
    // Covered beats changes nothing; a template beats covered.
    let later = [("conf.d/a.toml", "[style]\nouter_end = \"round\"\n")];
    let mut lc = Model::new(
        layers(&load("", &later, &[])),
        Target::New,
        Given::default(),
    );
    lc.pick(Row::Style, 0);
    assert!(
        at(&lc, 13).contains("overridden by conf.d/a.toml"),
        "{}",
        at(&lc, 13)
    );
    let both = [
        ("conf.d/a.toml", "[style]\ngap = true\n"),
        (
            "config.local.toml",
            "[style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        ),
    ];
    let tc = Model::new(layers(&load("", &both, &[])), Target::New, Given::default());
    assert!(
        at(&tc, 16).contains("a template in config.local.toml"),
        "{}",
        at(&tc, 16)
    );
    // A right side that is only a combining mark.
    let text_seg = "[segment.\"custom/m\"]\nkind = \"text\"\ntext = \"\\u0301\"\n[layout.line2]\nleft = [\"char\"]\nright = [\"custom/m\"]\n";
    let cm = compiled(load(text_seg, &[], &[]));
    let ml = view_lines(&cm, 80);
    let g = draw(&tri, &view(&tri, &cm, &ml, 80, 24));
    for y in 0..24 {
        let w = bingsu_core::width::str_width(
            &g.row_text(y),
            bingsu_core::width::WidthProfile::DEFAULT,
        );
        assert_eq!(w, 80, "row {y}: {:?}", g.row_text(y));
    }
}

// 이것을 실패시키는 것: 있는 파일에 쓸 키 목록을 내는 것, 줄 수를 물려받은 2줄로 되돌릴 때 두 키를 지우라고 하지
// 않는 것, 위 줄 키의 지금 값을 파일의 목록이 아닌 것(아래 줄 키의 글, 1줄이 쓰는 목록)으로 보이는 것, TOML 뿌리
// 키를 지울 때 표 이름을 붙이는 것.
#[test]
fn existing_lines_and_root_deletes() {
    let target = "icons = \"nerd\"\n[layout.line1]\nleft = [\"dir\", \"char\"]\n[layout.line2]\nenabled = false\n";
    let mut m = Model::new(
        layers(&load(target, &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    assert!(written_keys(&m).is_empty());
    m.pick(Row::Lines, 0);
    m.remove_override(Row::Icons);
    let c: Vec<String> = changes(&m)
        .iter()
        .map(|c| format!("{}|{}|{}", c.key, c.now, c.line))
        .collect();
    assert_eq!(
        c,
        [
            "icons|\"nerd\"|delete icons",
            "layout.line1.left|[\"dir\", \"char\"]|delete left under [layout.line1]",
            "layout.line2.enabled|false|delete enabled under [layout.line2]",
        ]
    );
}

// 이것을 실패시키는 것: 새 파일에서 쓴 값이 없어도 늘 쓰는 `style.preset` 줄에 `*`를 붙이지 않는 것, 블록 프리셋의
// 이음 `none`(붙은 블록)에서 빈칸이 무언가 바꾼다고 하는 것(`style::gap_applies`), 다른 폭으로 만든 미리보기의 2칸
// 글자가 격자 오른쪽 끝을 넘어 다음 줄 칸에 쓰이는 것.
#[test]
fn preset_mark_gap_rule_and_the_right_edge() {
    let m = fresh();
    assert_eq!(m.written(Row::Style), None);
    assert!(m.marked(Row::Style));
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let t = text(&draw(&m, &view(&m, &c, &lines, 80, 24)));
    assert!(t[12].starts_with(">* s style"), "{:?}", t[12]);
    let mut touching = fresh();
    touching.pick(Row::Joint, 4);
    let t = text(&draw(&touching, &view(&touching, &c, &lines, 80, 24)));
    assert!(t[16].contains("only with caps"), "{:?}", t[16]);
    let mut caps = fresh();
    caps.pick(Row::Joint, 5);
    let t = text(&draw(&caps, &view(&caps, &c, &lines, 80, 24)));
    assert!(!t[16].contains("only with"), "{:?}", t[16]);
    // Lines of 2-cell glyphs laid out wider than the grid.
    let wide = compiled(load(
        "[segment.\"custom/w\"]\nkind = \"text\"\ntext = \"\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\u{6f22}\"\n[layout.line1]\nleft = [\"custom/w\", \"custom/w\"]\nright = []\n",
        &[],
        &[],
    ));
    let wl = view_lines(&wide, 200);
    for cols in [80u16, 81] {
        let g = draw(&m, &view(&m, &wide, &wl, cols, 24));
        for y in 0..24 {
            let w = bingsu_core::width::str_width(
                &g.row_text(y),
                bingsu_core::width::WidthProfile::DEFAULT,
            );
            assert_eq!(w, u32::from(cols), "{cols} row {y}: {:?}", g.row_text(y));
        }
        let first: String = g.row_text(10).chars().take(3).collect();
        assert!(!first.contains('\u{6f22}'), "{cols}: {:?}", g.row_text(10));
    }
}

// 이것을 실패시키는 것: 덮는 출처가 고칠 수 있는 파일인지 모르면서(패키지 테마를 `extends`로 읽은 `conf.d` 등)
// 저장 화면에서 그 파일을 고치라고 권하는 것. 덮는다는 사실만 말해야 한다.
#[test]
fn an_override_is_stated_not_handed_over() {
    let parts = [(
        "/usr/share/bingsu/theme.toml",
        "[style]\nouter_end = \"round\"\n",
    )];
    let later = [(
        "conf.d/a.toml",
        "extends = [\"/usr/share/bingsu/theme.toml\"]\n",
    )];
    let mut m = Model::new(
        layers(&load("[style]\nouter_end = \"slant\"\n", &later, &parts)),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    m.pick(Row::Outer, 4);
    key(&mut m, Key::Enter, 1);
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let t = text(&draw(&m, &view(&m, &c, &lines, 80, 24))).concat();
    assert!(
        t.contains("/usr/share/bingsu/theme.toml sets this too, and wins."),
        "{t}"
    );
    assert!(!t.contains("change it there"), "{t}");
}

// 이것을 실패시키는 것: 크기 변경 전의 더 넓은 폭으로 만든 미리보기가 마지막 칸(비워 두는 칸)을 채우는 것. ASCII와 2칸
// 글자 둘 다.
#[test]
fn a_stale_wide_preview_leaves_the_last_column() {
    let m = fresh();
    for (glyph, n) in [("x", 60), ("\u{6f22}", 30)] {
        let text = glyph.repeat(n);
        let c = compiled(load(
            &format!(
                "[style]\npreset = \"lean\"\n[segment.\"custom/w\"]\nkind = \"text\"\ntext = \"{text}\"\n[layout.line1]\nleft = [\"custom/w\", \"custom/w\"]\nright = []\n"
            ),
            &[],
            &[],
        ));
        let lines = view_lines(&c, 120);
        for cols in [80u16, 81] {
            // The stale line reaches past the grid, so its edge is tried.
            assert!(lines[0].left.width() > u32::from(cols), "{glyph}");
            let g = draw(&m, &view(&m, &c, &lines, cols, 24));
            assert_eq!(
                g.cell(cols - 1, 9).text,
                " ",
                "{glyph} {cols}: {:?}",
                g.row_text(9)
            );
            assert!(
                g.cell(cols - 3, 9).text != " ",
                "{glyph} {cols}: {:?}",
                g.row_text(9)
            );
        }
    }
}

// 이것을 실패시키는 것: 공개 구조체(`Layers`)로 들어온 줄 목록 밖 값을 걸러 내지 않아 새 파일 글·화면에서 범위 밖
// 색인으로 멈추는 것, 공개 필드 `PreviewLine::right_at`이 `u32` 끝일 때 좌표 덧셈이 넘치는 것(release에서는 돌아
// 격자 안 칸으로 쓰인다), `Layers`로 들어온 파일 값의 글을 화면에 그대로 내는 것.
#[test]
fn public_inputs_out_of_range_are_dropped() {
    let mut l = layers(&load("", &[], &[]));
    l.rows[Row::Outer.index()].earlier = Some(200);
    l.rows[Row::Joint.index()].written = Some(255);
    l.rows[Row::Gap.index()].later = Some((9, 0));
    l.rows[Row::Gap.index()].later_keys[0] = Some(0);
    let m = Model::new(l.clone(), Target::New, Given::default());
    assert_eq!(m.inherited(Row::Outer), 0);
    assert_eq!(m.written(Row::Joint), None);
    // Covered, by a value that is dropped: the default shows.
    assert_eq!(m.covered_by(Row::Gap), Some(0));
    assert_eq!(m.effective(Row::Gap), 0);
    let text = new_file_text(&m).unwrap();
    assert!(!text.contains("outer_end"), "{text}");
    let c = compiled(load("[layout.line2]\nright = [\"duration\"]\n", &[], &[]));
    let mut lines = view_lines(&c, 80);
    assert!(!lines[1].right.is_empty());
    assert!(text_of(&draw(&m, &view(&m, &c, &lines, 80, 24)))[10].contains("2.1s"));
    lines[1].right_at = u32::MAX;
    let g = draw(&m, &view(&m, &c, &lines, 80, 24));
    assert!(!g.row_text(10).contains("2.1s"), "{:?}", g.row_text(10));
    // A file's own text from a hand-made `Layers` is cleaned when shown.
    let mut l = layers(&load("[style]\nouter_end = \"round\"\n", &[], &[]));
    l.rows[Row::Outer.index()].written_raw[0] = Some("\"\u{1b}[2J\u{202e}x\"".into());
    let mut e = Model::new(l, Target::Existing(Format::Toml), Given::default());
    e.remove_override(Row::Outer);
    key(&mut e, Key::Enter, 1);
    let all = text_of(&draw(&e, &view(&e, &c, &lines, 80, 24))).concat();
    assert!(
        !all.chars().any(bingsu_core::sanitize::is_removed),
        "{all:?}"
    );
    assert!(all.contains("style.outer_end: \"[2Jx\" now"), "{all}");
}

// 이것을 실패시키는 것: 프리셋 바꿈 규칙이 이 파일의 프리셋 선택이 아니라 최종 프리셋을 보는 것(뒤 `config.local`이
// 프리셋을 덮으면 이 파일의 프리셋을 바꿔도 이 파일의 끝 키가 남는다), 지움과 프리셋 바꿈이 한 번의 `u`로 돌아오지
// 않는 것.
#[test]
fn the_preset_reset_follows_this_files_choice() {
    let later = [("config.local.toml", "[style]\npreset = \"pill\"\n")];
    let target = "[style]\npreset = \"triangle\"\nouter_end = \"flat\"\n";
    let mut m = Model::new(
        layers(&load(target, &later, &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    let flat = ENDS.iter().position(|e| *e == "flat").unwrap() as u8;
    assert_eq!(m.written(Row::Outer), Some(flat));
    assert_eq!(STYLES[usize::from(m.effective(Row::Style))], "pill");
    let capsule = STYLES.iter().position(|s| *s == "capsule").unwrap() as u8;
    m.pick(Row::Style, capsule);
    assert_eq!(STYLES[usize::from(m.effective(Row::Style))], "pill");
    assert_eq!(m.written(Row::Outer), None);
    assert_eq!(m.note(), Some(Note::PartsReset));
    m.undo();
    assert_eq!(
        (
            m.written(Row::Outer),
            STYLES[usize::from(m.chosen(Row::Style))]
        ),
        (Some(flat), "triangle")
    );
}

// 이것을 실패시키는 것: 템플릿이 줄 수(`layout` 줄)도 대신 그리는데 lines 줄에 그 알림을 붙이지 않는 것, 저장 화면이
// 템플릿을 둔 출처와 그 키들이 그려지지 않는다는 것을 말하지 않는 것, 쓰는 키가 없을 때도 그 줄을 내는 것.
#[test]
fn a_template_replaces_the_lines_too() {
    let later = [(
        "config.local.toml",
        "[style]\ntemplate = \"{dir}{@nl}{char}\"\n",
    )];
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let mut m = Model::new(
        layers(&load("", &later, &[])),
        Target::New,
        Given::default(),
    );
    m.pick(Row::Lines, 1);
    let t = text(&draw(&m, &view(&m, &c, &lines, 80, 24)));
    assert!(
        t[19].contains("a template in config.local.toml replaces these"),
        "{:?}",
        t[19]
    );
    assert!(!t[17].contains("template"), "{:?}", t[17]);
    key(&mut m, Key::Enter, 1);
    let save = text(&draw(&m, &view(&m, &c, &lines, 80, 24))).concat();
    assert!(
        save.contains("A template in config.local.toml draws in place of the style and line keys."),
        "{save}"
    );
    // An existing file that changes nothing under the template: no line.
    let mut e = Model::new(
        layers(&load("icons = \"nerd\"\n", &later, &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    e.pick(Row::Icons, 3);
    key(&mut e, Key::Enter, 1);
    let save = text(&draw(&e, &view(&e, &c, &lines, 80, 24))).concat();
    assert!(!save.contains("A template in"), "{save}");
}

// 이것을 실패시키는 것: lines 줄의 두 키 가운데 `layout.line2.enabled`만 보고 뒤 출처가 `layout.line1.left`만 덮는 것을
// 놓치는 것(저장한 배열이 말없이 바뀌어 입력 표시가 사라진다), 저장 화면·상태 줄의 덮음 안내를 줄 단위로 만들어 덮지
// 않은 키까지 덮는다고 하는 것, 뒤 출처의 목록 밖 값이 이 파일의 키를 덮는다는 것을 놓치는 것, 앞 출처의 목록 밖 값을
// 건너뛰고 그 앞의 값을 물려받는 것.
#[test]
fn a_later_file_covers_key_by_key() {
    let later = [("conf.d/a.toml", "[layout.line1]\nleft = [\"dir\"]\n")];
    let c = compiled(load("", &[], &[]));
    let lines = view_lines(&c, 80);
    let mut m = Model::new(
        layers(&load("", &later, &[])),
        Target::New,
        Given::default(),
    );
    assert_eq!(m.covered_by(Row::Lines), Some(2));
    assert_eq!(
        (m.covered_key(Row::Lines, 0), m.covered_key(Row::Lines, 1)),
        (Some(2), None)
    );
    m.pick(Row::Lines, 1);
    let t = text(&draw(&m, &view(&m, &c, &lines, 80, 24)));
    assert!(t[19].contains("overridden by conf.d/a.toml"), "{:?}", t[19]);
    assert!(
        t[21].starts_with(" layout.line1.left covered by conf.d/a.toml;"),
        "{:?}",
        t[21]
    );
    key(&mut m, Key::Enter, 1);
    let save = text(&draw(&m, &view(&m, &c, &lines, 80, 24))).concat();
    assert!(
        save.contains("conf.d/a.toml sets layout.line1.left too, and wins."),
        "{save}"
    );
    assert!(!save.contains("sets layout.line2.enabled"), "{save}");
    // A later value outside the list still covers this file's key (`config
    // check` refuses that value; the key is no longer this file's).
    let bad = [("conf.d/a.toml", "[style]\nouter_end = \"rounds\"\n")];
    let mut b = Model::new(layers(&load("", &bad, &[])), Target::New, Given::default());
    b.pick(Row::Outer, 2);
    assert_eq!(b.chosen(Row::Outer), 2);
    assert_eq!(b.effective(Row::Outer), 0);
    assert!(b.covered_by(Row::Outer).is_some());
    // An earlier unknown value hides the one before it.
    let parts = [
        ("a", "[style]\nouter_end = \"round\"\n"),
        ("b", "[style]\nouter_end = \"rounds\"\n"),
    ];
    let e = Model::new(
        layers(&load("extends = [\"a\", \"b\"]\n", &[], &parts)),
        Target::New,
        Given::default(),
    );
    assert_eq!(e.inherited(Row::Outer), 0);
}

// 이것을 실패시키는 것: 파일에 있는 키와 그 줄의 값을 가르지 않아, 줄 값으로 읽히지 않는 키(`layout.line1.left`만,
// 목록 밖 `outer_end = "rounds"`)를 Backspace로 지울 수 없는 것, 파일에 없는 키까지 지우라고 하는 것, 그대로 둔 키를
// 바뀐 것으로 치는 것, 프리셋을 바꿀 때 목록 밖 부분 키를 남기는 것.
#[test]
fn keys_the_file_has_can_be_removed() {
    let target = "[layout.line1]\nleft = [\"dir\"]\n[style]\nouter_end = \"rounds\"\n";
    let mut m = Model::new(
        layers(&load(target, &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    assert!(m.kept(Row::Lines) && m.kept(Row::Outer));
    assert!(!m.changed() && changes(&m).is_empty());
    assert_eq!(m.chosen(Row::Lines), 0);
    assert_eq!(m.chosen(Row::Outer), 0);
    m.remove_override(Row::Lines);
    assert!(m.changed() && m.marked(Row::Lines));
    let c: Vec<String> = changes(&m)
        .iter()
        .map(|c| format!("{}|{}|{}", c.key, c.now, c.line))
        .collect();
    assert_eq!(
        c,
        ["layout.line1.left|[\"dir\"]|delete left under [layout.line1]"]
    );
    m.remove_override(Row::Outer);
    let c: Vec<String> = changes(&m).iter().map(|c| c.line.clone()).collect();
    assert_eq!(
        c,
        [
            "delete outer_end under [style]",
            "delete left under [layout.line1]"
        ]
    );
    m.restart();
    assert!(m.kept(Row::Outer) && m.kept(Row::Lines) && !m.changed());
    // A pick replaces the kept text.
    m.pick(Row::Outer, 2);
    let c: Vec<String> = changes(&m)
        .iter()
        .map(|c| format!("{}|{}", c.now, c.line))
        .collect();
    assert_eq!(c, ["\"rounds\"|under [style]: outer_end = \"round\""]);
    // One line written over the kept array sets both keys; the input line
    // key is not in the file, so a change back deletes only the array.
    let mut l = Model::new(
        layers(&load(target, &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    l.pick(Row::Lines, 1);
    assert_eq!(changes(&l).len(), 2);
    // A preset change takes a kept part key too.
    let mut p = Model::new(
        layers(&load(target, &[], &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    p.pick(Row::Style, 2);
    assert!(!p.kept(Row::Outer));
    assert_eq!(p.note(), Some(Note::PartsReset));
    assert!(
        changes(&p)
            .iter()
            .any(|c| c.line == "delete outer_end under [style]")
    );
}

// 이것을 실패시키는 것: 남겨 둔 키(목록 밖 값)가 있는 줄에서 물려받은 값을 고르면 파일의 그 키를 지우라고 하지 않는
// 것, 남겨 둔 값 키가 보이는 값을 기본값이 아닌 물려받은 값으로 두는 것(그 파일 값이 앞 출처를 덮는다), 있는 파일의
// 바꿀 줄에서 덮는 출처를 키가 아니라 줄 단위로 붙이는 것.
#[test]
fn kept_keys_and_covers_per_key() {
    let parts = [("base", "[style]\nouter_end = \"round\"\n")];
    let target = "extends = [\"base\"]\n[style]\nouter_end = \"rounds\"\n";
    let mut m = Model::new(
        layers(&load(target, &[], &parts)),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    let round = ENDS.iter().position(|e| *e == "round").unwrap() as u8;
    assert!(m.kept(Row::Outer));
    assert_eq!((m.inherited(Row::Outer), m.chosen(Row::Outer)), (round, 0));
    m.pick(Row::Outer, round);
    assert_eq!(m.written(Row::Outer), None);
    let c: Vec<String> = changes(&m).iter().map(|c| c.line.clone()).collect();
    assert_eq!(c, ["delete outer_end under [style]"]);
    // Per key: a later file sets the array, not the input line key.
    let later = [("conf.d/a.toml", "[layout.line1]\nleft = [\"dir\"]\n")];
    let file = "[layout.line1]\nleft = [\"host\", \"dir\", \"git\", \"char\"]\n[layout.line2]\nenabled = false\n";
    let mut l = Model::new(
        layers(&load(file, &later, &[])),
        Target::Existing(Format::Toml),
        Given::default(),
    );
    l.remove_override(Row::Lines);
    let c: Vec<(String, bool)> = changes(&l)
        .iter()
        .map(|c| (c.key.to_string(), c.covered_by.is_some()))
        .collect();
    assert_eq!(
        c,
        [
            ("layout.line1.left".to_string(), true),
            ("layout.line2.enabled".to_string(), false)
        ]
    );
}

// 이것을 실패시키는 것: 내장 narrow 구간을 폭으로 고르지 않는 것(경계 59·60칸), 다른 구간을 narrow로 보는 것, 사용자가
// narrow 구간의 template을 쓴 때나 구간을 끈 때나 경계를 옮긴 때에도 내장 narrow라고 하는 것, 나중 출처가 아닌 처음
// 출처의 template을 보는 것.
#[test]
fn the_built_in_narrow_band_is_told_from_its_width_and_source() {
    use bingsu_core::setup_editor::layers::builtin_narrow;
    let at = |r: &ConfigReport, w: u16| {
        let c = r.snapshot.as_ref().expect("compiles");
        builtin_narrow(&r.files, &r.order, &c.widths, w)
    };
    let plain = load("", &[], &[]);
    assert!(at(&plain, 59) && at(&plain, 1));
    assert!(!at(&plain, 60) && !at(&plain, 80));
    let own = load(
        "",
        &[(
            "conf.d/10.toml",
            "[layout.when.narrow.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        )],
        &[],
    );
    assert!(!at(&own, 59), "a template a source wrote");
    let back = load(
        "",
        &[
            (
                "conf.d/10.toml",
                "[layout.when.narrow.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
            ),
            (
                "conf.d/20.toml",
                &format!(
                    "[layout.when.narrow.style]\ntemplate = \"{}\"\n",
                    bingsu_core::default_theme::NARROW_TEMPLATE
                ),
            ),
        ],
        &[],
    );
    assert!(at(&back, 59), "the last source decides");
    let off = load(
        "",
        &[("conf.d/10.toml", "[layout.when.narrow]\nenabled = false\n")],
        &[],
    );
    assert!(!at(&off, 59));
    let moved = load(
        "",
        &[("conf.d/10.toml", "[layout.when.narrow]\nmax_cols = 49\n")],
        &[],
    );
    assert!(at(&moved, 49) && !at(&moved, 50));
}

/// One cell as a terminal holds it: its text and the SGR it was drawn or
/// erased with.
type Shown = (String, Vec<u8>);

/// Plays `bytes` onto `screen` as a terminal places them, with `g` telling
/// each cell's width. Only cursor moves, SGR, a whole clear, an erase to
/// the line's end and cell texts may come. Returns the cursor moves and the
/// last column a glyph went to.
fn play(bytes: &[u8], screen: &mut [Vec<Shown>], g: &Grid) -> (usize, u16) {
    let (mut i, mut x, mut y, mut moves, mut far) = (0, 0u16, 0u16, 0, 0);
    let mut sgr: Vec<u8> = Vec::new();
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            assert_eq!(bytes.get(i + 1), Some(&b'['), "only CSI at {i}");
            let end = i
                + 2
                + bytes[i + 2..]
                    .iter()
                    .position(|b| (0x40..=0x7e).contains(b))
                    .unwrap();
            let params = std::str::from_utf8(&bytes[i + 2..end]).unwrap();
            match bytes[end] {
                b'H' => {
                    let (r, c) = params.split_once(';').unwrap();
                    y = r.parse::<u16>().unwrap() - 1;
                    x = c.parse::<u16>().unwrap() - 1;
                    moves += 1;
                }
                b'm' => sgr = bytes[i..=end].to_vec(),
                b'J' => {
                    assert_eq!(params, "2");
                    for row in screen.iter_mut() {
                        row.fill((String::from(" "), sgr.clone()));
                    }
                }
                b'K' => {
                    assert_eq!(params, "");
                    for cell in &mut screen[usize::from(y)][usize::from(x)..] {
                        *cell = (String::from(" "), sgr.clone());
                    }
                }
                f => panic!("final byte {f}"),
            }
            i = end + 1;
            continue;
        }
        let want = &g.cell(x, y).text;
        assert!(!want.is_empty(), "a covered cell at {x},{y}");
        assert!(
            bytes[i..].starts_with(want.as_bytes()),
            "{x},{y}: {want:?} vs {:?}",
            String::from_utf8_lossy(&bytes[i..(i + 8).min(bytes.len())])
        );
        let w = if x + 1 < g.cols() && g.cell(x + 1, y).text.is_empty() {
            2
        } else {
            1
        };
        screen[usize::from(y)][usize::from(x)] = (want.clone(), sgr.clone());
        if w == 2 {
            screen[usize::from(y)][usize::from(x) + 1] = (String::new(), sgr.clone());
        }
        far = far.max(x + w - 1);
        x += w;
        i += want.len();
    }
    (moves, far)
}

/// The screen shows `g`: every cell's text and paint, the last column's
/// paint too.
fn shows(screen: &[Vec<Shown>], g: &Grid) -> bool {
    (0..g.rows()).all(|y| {
        (0..g.cols()).all(|x| {
            let cell = g.cell(x, y);
            let mut sgr = Vec::new();
            bingsu_core::color::sgr::write_paint(cell.paint, &mut sgr);
            let (text, got) = &screen[usize::from(y)][usize::from(x)];
            *text == cell.text && *got == sgr
        })
    })
}

fn unknown(cols: usize, rows: usize) -> Vec<Vec<Shown>> {
    vec![vec![(String::from("?"), Vec::new()); cols]; rows]
}

// 이것을 실패시키는 것: 마지막 칸에 글자를 쓰는 것, 처음 프레임에서 화면을 지우지 않는 것, 칸을 엉뚱한 자리나 다른
// 색으로 쓰는 것, 줄마다 마지막 칸의 바탕을 그 칸의 색으로 지우지 않는 것(미리보기 줄의 끝이 다른 색으로 남음), 두 칸
// 글자 뒤 커서를 한 칸만 옮긴 것으로 보는 것(줄마다 이동이 더 늘어남), 바뀐 칸만이 아니라 다 쓰는 것, 크기가
// 바뀌었는데 차이만 쓰는 것, 0칸 격자에서 넘치는 것, CSI 밖의 escape(문자열)를 쓰는 것.
#[test]
fn frames_draw_the_grid_and_then_only_what_changed() {
    let mut m = fresh();
    let c = compiled(load(&new_file_text(&m).unwrap(), &[], &[]));
    let wide = lines(
        &c,
        &Request {
            mode: Mode::Dark,
            icons: c.icons,
            depth: ColorDepth::TrueColor,
            width: 80,
            sample: Sample {
                pwd: "/home/u/\u{65e5}\u{672c}\u{8a9e}".as_bytes(),
                home: Some(b"/home/u"),
                host: Some(b"ice-box"),
            },
        },
    );
    let g1 = draw(&m, &view(&m, &c, &wide, 80, 24));
    assert!(
        (0..24).any(|y| (0..79).any(|x| g1.cell(x, y).text.is_empty())),
        "the grid has a 2-cell cluster"
    );
    assert!(
        (0..24).any(|y| g1.cell(79, y).paint != g1.cell(79, 0).paint),
        "the last column has more than one paint"
    );
    let mut full = Vec::new();
    frame(None, &g1, &mut full);
    assert!(full.starts_with(b"\x1b[0") && full.windows(4).any(|w| w == b"\x1b[2J"));
    let mut screen = unknown(80, 24);
    let (moves, far) = play(&full, &mut screen, &g1);
    assert!(shows(&screen, &g1));
    assert!(far < 79, "no glyph in the last column");
    assert_eq!(
        moves, 48,
        "two moves a row (its cells, its last column): a 2-cell cluster moves the cursor by 2"
    );
    // An SGR where the paint changes from the cell drawn before, the last
    // column of each row included.
    let mut want = 0;
    let mut last = None;
    for y in 0..24 {
        for x in 0..80 {
            let cell = g1.cell(x, y);
            if (x == 79 || !cell.text.is_empty()) && last != Some(cell.paint) {
                last = Some(cell.paint);
                want += 1;
            }
        }
    }
    let escapes = full.iter().filter(|&&b| b == 0x1b).count();
    assert_eq!(
        escapes - moves - 1 - 24,
        want + 1,
        "the clear's paint, then each change"
    );
    // One key: only what changed.
    m.pick(Row::Style, 0);
    let g2 = draw(&m, &view(&m, &c, &wide, 80, 24));
    let mut diff = Vec::new();
    frame(Some(&g1), &g2, &mut diff);
    assert!(!diff.windows(4).any(|w| w == b"\x1b[2J"));
    assert!(
        diff.len() * 4 < full.len(),
        "{} vs {}",
        diff.len(),
        full.len()
    );
    play(&diff, &mut screen, &g2);
    assert!(shows(&screen, &g2));
    let mut same = Vec::new();
    frame(Some(&g2), &g2, &mut same);
    assert!(same.is_empty());
    // Another size: the whole screen.
    for (cols, rows) in [(79, 24), (81, 24), (80, 25)] {
        let g3 = draw(&m, &view(&m, &c, &wide, cols, rows));
        let mut again = Vec::new();
        frame(Some(&g2), &g3, &mut again);
        assert!(again.windows(4).any(|w| w == b"\x1b[2J"), "{cols}x{rows}");
    }
    // Every paint changes (the light palette): every cell and every last
    // column again.
    let mut v = view(&m, &c, &wide, 80, 24);
    v.mode = Mode::Light;
    v.palette = &c.light_palette;
    let g4 = draw(&m, &v);
    let mut light = Vec::new();
    frame(Some(&g2), &g4, &mut light);
    play(&light, &mut screen, &g4);
    assert!(shows(&screen, &g4));
    // No cells, no bytes.
    let none = draw(&m, &view(&m, &c, &wide, 0, 0));
    let mut empty = Vec::new();
    frame(None, &none, &mut empty);
    assert!(empty.is_empty());
}

// 이것을 실패시키는 것: 편집판의 글(제목, 줄 이름, 값, 고른 값, 효과 없는 값, 안내, 키 안내, 저장 화면)을 바탕과
// 4.5:1 아래로 칠하는 것, 고른 값의 상자(표시)를 화면 바탕과 3:1 아래로 칠하는 것, 효과 없는 고른 값에 상자를
// 두는 것(두 모드, 24비트와 256색), 팔레트에 없는 이름에 색을 주는 것.
// 미리보기 줄은 사용자 테마의 색이고, 그릇 줄(1-7)은 장식이라 이 기준 밖이다.
#[test]
fn every_editor_text_cell_meets_4_5_to_1() {
    use bingsu_core::color::math::{Srgb8, contrast_milli, xterm};
    use bingsu_core::color::sgr::Ink;
    let rgb = |i: Ink| match i {
        Ink::Rgb(r, g, b) => Some(Srgb8 { r, g, b }),
        Ink::Indexed(n) => Some(xterm(n)),
        _ => None,
    };
    // Lean picked: outer's none then changes nothing (the idle box).
    let mut m = fresh();
    m.pick(Row::Style, 0);
    let c = compiled(load(&new_file_text(&m).unwrap(), &[], &[]));
    let lines = view_lines(&c, 80);
    let (mut checked, mut picks, mut idles) = (0, 0, 0);
    for mode in [Mode::Dark, Mode::Light] {
        for depth in [ColorDepth::TrueColor, ColorDepth::Ansi256] {
            for screen in ["main", "keys", "save"] {
                let mut s = m.clone();
                let key = match screen {
                    "keys" => Some(Key::Char(b'?')),
                    "save" => Some(Key::Enter),
                    _ => None,
                };
                if let Some(key) = key {
                    s.handle(Input { key, read: 1 });
                }
                let mut v = view(&s, &c, &lines, 80, 24);
                v.mode = mode;
                v.depth = depth;
                v.palette = match mode {
                    Mode::Dark => &c.palette,
                    Mode::Light => &c.light_palette,
                };
                let g = draw(&s, &v);
                let label = (0..24).find(|&y| g.row_text(y).starts_with(" preview"));
                let exempt = |y: u16| {
                    (screen == "main" && (1..=7).contains(&y))
                        || label.is_some_and(|l| y == l + 1 || y == l + 2)
                };
                let base = rgb(g.cell(79, 0).paint.bg).unwrap();
                let shown = |name: &str| {
                    let c = bingsu_core::color::palette::named_color(name, mode, false).unwrap();
                    match depth {
                        ColorDepth::Ansi256 => xterm(bingsu_core::color::math::nearest_256(c)),
                        _ => c,
                    }
                };
                let accent = shown("accent.blue");
                for y in (0..24).filter(|&y| !exempt(y)) {
                    for x in 0..79 {
                        let cell = g.cell(x, y);
                        // The box of an effective pick (the accent) marks
                        // it: 3:1 on the screen's background. A pick that
                        // changes nothing has no box: its brackets and
                        // text are text cells, 4.5:1 below.
                        if let Some(bg) = rgb(cell.paint.bg).filter(|&b| b == accent) {
                            assert!(
                                contrast_milli(bg, base) >= 3000,
                                "{mode:?} {depth:?} {x},{y}: box {}",
                                contrast_milli(bg, base)
                            );
                            picks += 1;
                        } else if cell.paint.bg != g.cell(79, 0).paint.bg {
                            panic!("{mode:?} {depth:?} {x},{y}: a box of another color");
                        }
                        if cell.text == "[" {
                            idles += 1;
                        }
                        if cell.text.trim().is_empty() {
                            continue;
                        }
                        let (Some(fg), Some(bg)) = (rgb(cell.paint.fg), rgb(cell.paint.bg)) else {
                            panic!("{mode:?} {depth:?} {screen} {x},{y}: {:?}", cell.paint);
                        };
                        let ratio = contrast_milli(fg, bg);
                        assert!(
                            ratio >= 4500,
                            "{mode:?} {depth:?} {screen} {x},{y} {:?}: {ratio}",
                            cell.text
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert!(checked > 1000, "{checked}");
    assert!(
        picks > 0 && idles > 0,
        "a box and a bracketed pick were checked"
    );
    assert_eq!(
        bingsu_core::color::palette::named_color("neutral.nope", Mode::Dark, true),
        None
    );
}
