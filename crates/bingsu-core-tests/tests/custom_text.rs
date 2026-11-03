//! User `kind = "text"` segments (M6 A2): config text to B1 record through
//! the real front, in every shell, plus the numbering and snapshot rules
//! that keep them off the collection mask.
use bingsu_core::{
    collection::selection,
    color::palette::Mode,
    config::compile::{CompiledConfig, MAX_CUSTOM_TEXT},
    diag_codes as codes, envelope,
    field::BUILTIN,
    front,
    layout_view::{FrontConfig, LayoutView},
    shell_word::Shell,
    snapshot::{Identity, Snapshot, encode_metadata},
    snapshot_codec::{decode_compiled, encode_compiled},
    status::Status,
    template::compile::compile_with,
};
use bingsu_core_tests::{parse_field, snapshot_fixture as fixture};

const SHELLS: [(Shell, &str); 3] = [
    (Shell::Zsh, "zsh"),
    (Shell::Bash, "bash"),
    (Shell::Fish, "fish"),
];
/// Record element index of the left prompt, as the shells read it.
const LEFT: usize = 2;

/// A TOML basic string for any text: every non-ASCII-printable char is a
/// `\U` escape, so hostile classes survive the config text.
fn toml_str(t: &str) -> String {
    let mut o = String::from("\"");
    for c in t.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            ' '..='~' => o.push(c),
            _ => o.push_str(&format!("\\U{:08X}", c as u32)),
        }
    }
    o.push('"');
    o
}

fn config(text: &str) -> String {
    format!(
        "[segment.\"custom/a\"]\nkind = \"text\"\ntext = {}\n[layout.line2]\nleft = [\"custom/a\", \"char\"]\n",
        toml_str(text)
    )
}

fn left<L: LayoutView>(c: &L, shell: (Shell, &str), width: u16) -> String {
    let args: Vec<Vec<u8>> = [
        "--ctx",
        "1",
        "--record",
        "B1",
        "--width",
        &width.to_string(),
        "--runtime-root=1:2:/r",
        "--home=/home/u",
        "--shell",
        shell.1,
        "--pwd",
        "/home/u/p",
        "--status",
        "0",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let argv: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let e = envelope::parse(&argv).unwrap();
    let mut out = Vec::new();
    front::render_selected(
        &e,
        shell.0,
        Status::OK_NONE,
        Some(c),
        Mode::Dark,
        None,
        &mut out,
    );
    assert_eq!(out.pop(), Some(0x1e));
    let elements: Vec<&[u8]> = out.split(|&b| b == 0x1f).collect();
    parse_field(shell.0, elements[LEFT]).unwrap()
}

// 이것을 실패시키는 것: 컴파일이 text 선언을 만들지 않는 것(참조가 잘려 `X`가 사라진다), 앞단이 값을
// 붙이지 않는 것, 값이 셸 필드 문법을 어기는 것.
#[test]
fn text_segment_is_drawn_in_every_shell() {
    let c = fixture::compile(&config("X"));
    assert_eq!(c.custom.len(), 1);
    for sh in SHELLS {
        let text = left(&c, sh, 80);
        assert!(text.contains('X'), "{sh:?}: {text:?}");
    }
}

// 이것을 실패시키는 것: 빈 text에서 선언을 건너뛰어 번호가 어긋나는 것, 빈 값이 칸을 차지하는 것.
#[test]
fn empty_text_draws_nothing() {
    let c = fixture::compile(&config(""));
    assert_eq!(c.custom.len(), 1);
    for sh in SHELLS {
        let with = left(&c, sh, 80);
        let without = left(
            &fixture::compile("[layout.line2]\nleft = [\"char\"]\n"),
            sh,
            80,
        );
        assert_eq!(with, without, "{sh:?}");
    }
}

// 이것을 실패시키는 것: custom 값이 기존 정제·이스케이프 경로를 건너뛰는 것. zsh 필드에서 `%`가
// `%%`로, 읽은 뒤 원문 그대로여야 한다. 원시 레코드의 `%%F{red}!!`는 아래 raw 단언이 잡는다.
#[test]
fn zsh_percent_and_bang_are_escaped_as_for_any_segment() {
    let c = fixture::compile(&config("%F{red}!"));
    let args: Vec<Vec<u8>> = [
        "--ctx",
        "1",
        "--record",
        "B1",
        "--width",
        "80",
        "--runtime-root=1:2:/r",
        "--shell",
        "zsh",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let argv: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let e = envelope::parse(&argv).unwrap();
    let mut out = Vec::new();
    front::render_selected(
        &e,
        Shell::Zsh,
        Status::OK_NONE,
        Some(&c),
        Mode::Dark,
        None,
        &mut out,
    );
    let raw = String::from_utf8_lossy(&out);
    assert!(raw.contains("%%F{red}!"), "{raw:?}");
    assert!(
        !raw.contains("%F{red}!") || raw.contains("%%F{red}!"),
        "{raw:?}"
    );
    for sh in SHELLS {
        assert!(left(&c, sh, 80).contains("%F{red}!"), "{sh:?}");
    }
}

// 이것을 실패시키는 것: 제어 문자 검사 삭제(ESC가 든 text가 오류 없이 통과한다). 렌더 정제가 ESC를
// 조용히 지우므로 출력이 아니라 `config check` 진단 코드를 단언한다.
#[test]
fn text_control_char_rejected() {
    let r = fixture::report(&config("a\u{1b}[31mb"));
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::CONTROL_IN_TEXT),
        "{:?}",
        r.diagnostics
    );
    assert!(r.snapshot.is_none());
}

// classes.tsv의 모든 값이 text 경로를 지난다: 정제가 지우는 행은 `config check`가 거부하고, 나머지는
// 같은 글자로 모든 셸에서 읽힌다(zsh는 `%` 이스케이프 뒤 원문).
#[test]
fn hostile_classes_through_text() {
    let table = include_str!("../../../tests/hostile/classes.tsv");
    let mut ran = 0;
    for l in table
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let col: Vec<&str> = l.split('\t').collect();
        if col[1].starts_with("repeat:") {
            continue;
        }
        let raw: Vec<u8> = (0..col[1].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&col[1][i..i + 2], 16).unwrap())
            .collect();
        let Ok(raw) = String::from_utf8(raw) else {
            continue;
        };
        let raw = raw.replace("CANARY", "/tmp/x");
        if raw.contains('\0') {
            continue;
        }
        let report = fixture::report(&config(&raw));
        ran += 1;
        match col[6] {
            "strip" => {
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .any(|d| d.code == codes::CONTROL_IN_TEXT),
                    "{}",
                    col[0]
                );
            }
            "same" | "zsh-escape" => {
                let c = report.snapshot.unwrap_or_else(|| panic!("{}", col[0]));
                for sh in SHELLS {
                    let shown = left(&c, sh, 200);
                    assert!(shown.contains(&raw), "{} {sh:?}: {shown:?}", col[0]);
                }
            }
            other => panic!("{}: {other}", col[0]),
        }
    }
    assert!(ran >= 15, "{ran}");
}

// 이것을 실패시키는 것: custom 번호가 수집 mask 비트를 쓰는 것(9번 이후 비트가 켜진다), 번호가
// 32 이상일 때 시프트가 넘치는 것.
#[test]
fn text_segments_never_take_a_collection_bit() {
    let mut cfg = String::new();
    let mut ids = Vec::new();
    for i in 0..40 {
        let id = format!("custom/t{i:02}");
        cfg += &format!("[segment.\"{id}\"]\nkind = \"text\"\ntext = \"{i}\"\n");
        ids.push(format!("\"{id}\""));
    }
    cfg += &format!("[layout.line1]\nleft = [{}, \"char\"]\n", ids.join(", "));
    let c = fixture::compile(&cfg);
    assert_eq!(c.custom.len(), 40);
    assert!(c.custom.windows(2).all(|w| w[0].id < w[1].id));
    assert_eq!(c.collect_mask >> BUILTIN.len(), 0);
    assert_eq!(selection::builtin_mask(&c, 80) >> BUILTIN.len(), 0);
    assert_eq!(selection::worker_mask(&c, 80, false) >> BUILTIN.len(), 0);
}

// 이것을 실패시키는 것: 선언 없이 참조만 있는 id, 그리기 않는 선언, `enabled = false`를 목록에 싣는 것.
#[test]
fn only_drawn_enabled_text_is_declared() {
    let cfg = "[segment.\"custom/a\"]\nkind = \"text\"\ntext = \"A\"\n\
               [segment.\"custom/off\"]\nkind = \"text\"\ntext = \"O\"\nenabled = false\n\
               [segment.\"custom/idle\"]\nkind = \"text\"\ntext = \"I\"\n\
               [layout.line1]\nleft = [\"custom/off\", \"custom/a\", \"char\"]\n";
    let c = fixture::compile(cfg);
    let ids: Vec<_> = c.custom.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, ["custom/a"]);
}

// 이것을 실패시키는 것: command·language를 text와 함께 그리기 시작하는 것(M6 뒤 단계가 열리기 전).
#[test]
fn command_segment_stays_hidden() {
    let cfg = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n\
               [segment.\"custom/a\"]\nkind = \"text\"\ntext = \"A\"\n\
               [layout.line1]\nleft = [\"custom/k\", \"custom/a\", \"char\"]\n";
    let r = fixture::report(cfg);
    let c = r.snapshot.unwrap();
    assert_eq!(c.custom.len(), 1);
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::CUSTOM_DRAWN_LATER)
    );
}

fn wire(c: &CompiledConfig) -> Vec<u8> {
    Snapshot {
        id: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            context: [3; 4],
            generation: 7,
            source: [4; 4],
        },
        config: c.clone(),
        metadata: encode_metadata(b"m").unwrap(),
    }
    .encode(1, 0)
    .unwrap()
}

// 이것을 실패시키는 것: 스냅샷이 custom 목록을 나르지 않는 것(앞단 디코드에서 번호가 범위 밖이 된다),
// 앞단이 helper 전체 디코드와 다른 목록을 얻는 것.
#[test]
fn custom_list_survives_the_snapshot_and_the_front_decode() {
    let c = fixture::compile(&config("X"));
    assert_eq!(decode_compiled(&encode_compiled(&c).unwrap()).unwrap(), c);
    let b = wire(&c);
    let end = b.len() - encode_metadata(b"m").unwrap().len();
    let f: FrontConfig = Snapshot::decode_front(&b[..end], b.len(), 80)
        .unwrap()
        .config;
    for sh in SHELLS {
        assert_eq!(left(&f, sh, 80), left(&c, sh, 80));
    }
}

// 이것을 실패시키는 것: 노드 번호 검사를 `BUILTIN.len()`에 고정하는 것(custom 번호가 거부된다), 또는
// 검사를 빼는 것(목록 밖 번호가 통과한다).
#[test]
fn segment_numbers_are_checked_against_the_declared_list() {
    let n = BUILTIN.len();
    let ok = compile_with("{custom/a}", BUILTIN, &["custom/a"]).unwrap();
    assert!(matches!(
        ok[0].nodes()[0],
        bingsu_core::template::compile::Node::Segment { seg, .. } if usize::from(seg) == n
    ));
    assert!(compile_with("{custom/b}", BUILTIN, &["custom/a"]).is_err());
    assert!(compile_with("{custom/a.value}", BUILTIN, &["custom/a"]).is_ok());
    assert!(compile_with("{custom/a.nope}", BUILTIN, &["custom/a"]).is_err());
}

// 이것을 실패시키는 것: 개수 상한 검사 삭제. 한 템플릿은 4096바이트에 걸려 상한에 닿기 전에 거부되므로
// 구간마다 9개씩 나눠 그린다. 25구간(225개)은 통과하고 30구간(270개)은 오류다.
#[test]
fn too_many_text_segments_is_an_error() {
    let build = |bands: usize| {
        let mut cfg = String::new();
        for i in 0..bands * 9 {
            cfg += &format!("[segment.\"custom/t{i:03}\"]\nkind = \"text\"\ntext = \"x\"\n");
        }
        for band in 0..bands {
            let refs: String = (0..9)
                .map(|k| format!("{{custom/t{:03}}}", band * 9 + k))
                .collect();
            cfg += &format!(
                "[layout.when.b{band}]\nmin_cols = {}\nmax_cols = {}\n[layout.when.b{band}.style]\ntemplate = \"{refs}{{char}}\"\n",
                100 + band * 10,
                109 + band * 10
            );
        }
        fixture::report(&cfg)
    };
    assert_eq!(build(25).snapshot.expect("225 drawn").custom.len(), 225);
    let r = build(30);
    assert!(r.snapshot.is_none());
    assert!(r.diagnostics.iter().any(|d| d.code == codes::BAD_VALUE));
    assert_eq!(MAX_CUSTOM_TEXT, 256);
}
