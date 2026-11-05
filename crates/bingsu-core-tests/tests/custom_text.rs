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
    left_with(c, shell, width, &[])
}

/// `left` with the values of the config's command segments.
fn left_with<L: LayoutView>(
    c: &L,
    shell: (Shell, &str),
    width: u16,
    commands: &[Option<&str>],
) -> String {
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
    front::render_selected_with_values(
        &e,
        shell.0,
        Status::OK_NONE,
        Some(c),
        Mode::Dark,
        None,
        commands,
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

// 값이 없는 command 세그먼트는 칸도 구분자도 남기지 않는다: text 사이에 끼워도, 앞뒤에 두어도, 그것만 있는
// 그룹이어도 그 세그먼트를 뺀 배치와 같다. 이것을 실패시키는 것: 값이 없는 command 칸에 자리표시 글자를 그리는
// 것, command 세그먼트를 그리는 목록에서 빼는 것(번호가 밀려 text가 엉뚱한 칸에 감). 빈 값은 빈 text처럼 이미
// 숨으므로 None과 Some("")는 같은 결과다. command id(`custom/k`)가 text id(`custom/m`, `custom/n`)보다
// 앞에 정렬되므로, 앞단이 command 값 자리를 비우면 안 된다: command 분기의 `values.push(None)`을 지우면
// text 값이 한 칸씩 밀린다.
#[test]
fn a_command_segment_without_a_value_leaves_nothing() {
    let decl = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n\
                [segment.\"custom/m\"]\nkind = \"text\"\ntext = \"A\"\n\
                [segment.\"custom/n\"]\nkind = \"text\"\ntext = \"B\"\n";
    for (with, without) in [
        (
            "['custom/m', 'custom/k', 'custom/n', 'char']",
            "['custom/m', 'custom/n', 'char']",
        ),
        ("['custom/k', 'custom/m', 'char']", "['custom/m', 'char']"),
        ("['custom/m', 'custom/k']", "['custom/m']"),
    ] {
        let c = fixture::compile(&format!("{decl}[layout.line2]\nleft = {with}\n"));
        let base = fixture::compile(&format!("{decl}[layout.line2]\nleft = {without}\n"));
        assert_eq!(c.custom.len(), base.custom.len() + 1, "{with}");
        for sh in SHELLS {
            assert_eq!(left(&c, sh, 80), left(&base, sh, 80), "{sh:?} {with}");
        }
    }
    let tpl = |t: &str| format!("{decl}[style]\ntemplate = \"{t}\"\n");
    let c = fixture::compile(&tpl("{custom/m}{@group}[{custom/k}]{@end} {char}"));
    let base = fixture::compile(&tpl("{custom/m} {char}"));
    for sh in SHELLS {
        assert_eq!(
            left(&c, sh, 80),
            left(&base, sh, 80),
            "{sh:?} template group"
        );
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

// classes.tsv의 모든 값을 명령 stdout으로 보낸다: helper가 첫 줄을 정제해 응답에 싣고(응답 형식은 정제가 지우는
// 글자를 거부한다), 앞단이 command 세그먼트로 그린다. 정제가 지우는 행은 그 글자 없이, 나머지는 같은 글자로 모든
// 셸에서 읽힌다(zsh는 `%` 이스케이프 뒤 원문). 이것을 실패시키는 것: helper가 첫 줄을 정제하지 않고 싣는 것(응답
// 인코딩이 거부), 첫 줄 뒤를 함께 싣는 것(newline 행), 앞단이 command 값을 세그먼트 칸(64)으로 자르지 않는 것
// (one_mib 행).
#[test]
fn hostile_classes_through_command_output() {
    use bingsu_core::{
        collection::wire::BuildId,
        command::response::{self, Binding, Entry, Response},
        handoff::Origin,
        snapshot::context_crc,
    };
    let c = fixture::compile(
        "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n\
         [layout.line2]\nleft = [\"custom/k\", \"char\"]\n",
    );
    let (config, state) = (b"/c".to_vec(), b"/s".to_vec());
    let binding = Binding {
        build_id: BuildId([7; 32]),
        boot: [1; 16],
        epoch: [2; 16],
        context: context_crc(&config, &state).unwrap(),
        clock_kind: 1,
        domain: [3; 16],
        resume: 4,
        config,
        state,
        cwd: b"/w".to_vec(),
    };
    // What no shell field may show: C0, DEL, C1, and the bidi and invisible format characters.
    let hidden = |ch: char| {
        ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
    };
    let table = include_str!("../../../tests/hostile/classes.tsv");
    let mut ran = 0;
    for l in table
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let col: Vec<&str> = l.split('\t').collect();
        let stdout: Vec<u8> = match col[1].strip_prefix("repeat:") {
            Some(r) => {
                let (b, n) = r.split_once(':').unwrap();
                vec![u8::from_str_radix(b, 16).unwrap(); n.parse().unwrap()]
            }
            None => (0..col[1].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&col[1][i..i + 2], 16).unwrap())
                .collect(),
        };
        // CANARY is ASCII: replace it in the bytes, so `bad_utf8` stays invalid.
        let stdout = match stdout.windows(6).position(|w| w == b"CANARY") {
            Some(i) => [&stdout[..i], b"/tmp/x".as_slice(), &stdout[i + 6..]].concat(),
            None => stdout,
        };
        let value = response::first_line(&stdout);
        let published = Response {
            binding: binding.clone(),
            entries: vec![Entry {
                origin: Origin::Config,
                id: "custom/k".into(),
                policy: [0; 32],
                environment: [0; 32],
                pattern: [0; 32],
                attempted_at: 1,
                completed_at: 2,
                status: response::Status::Ok,
                value: value.clone(),
                raw: value,
            }],
        };
        let read = Response::decode(
            &published
                .encode()
                .unwrap_or_else(|e| panic!("{}: {e:?}", col[0])),
        )
        .unwrap();
        let value = read.entries[0].value.as_str();
        ran += 1;
        for sh in SHELLS {
            let shown = left_with(&c, sh, 200, &[Some(value)]);
            assert!(!shown.chars().any(hidden), "{} {sh:?}: {shown:?}", col[0]);
            let raw = String::from_utf8_lossy(&stdout).into_owned();
            match col[6] {
                "same" | "zsh-escape" => {
                    assert!(shown.contains(&raw), "{} {sh:?}: {shown:?}", col[0])
                }
                // The first line only: `a`, never the `b` after the newline.
                "strip" if col[0] == "newline" => {
                    assert!(
                        shown.contains('a') && !shown.contains('b'),
                        "{sh:?}: {shown:?}"
                    )
                }
                // Gone with what sanitizing removes; `hidden` above checks that.
                "strip" => {}
                "fffd" => assert!(shown.contains('\u{fffd}'), "{sh:?}: {shown:?}"),
                "truncate" => {
                    let a = shown.chars().filter(|&ch| ch == 'a').count();
                    assert!((1..=64).contains(&a), "{sh:?}: {a}")
                }
                other => panic!("{}: {other}", col[0]),
            }
        }
    }
    assert_eq!(ran, 21);
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

// command 세그먼트는 text와 같은 번호 규칙으로 그려지는 목록에 들고 N502를 내지 않는다. env는 아직(C5) 그리지
// 않고 N502를 낸다. 이것을 실패시키는 것: command를 그리는 종류에서 빼는 것(목록에 없음, N502), env를 그리기
// 시작하는 것.
#[test]
fn command_segment_is_drawn_env_stays_hidden() {
    use bingsu_core::config::compile::CustomKind;
    let cfg = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n\
               [segment.\"custom/a\"]\nkind = \"text\"\ntext = \"A\"\n\
               [segment.\"custom/e\"]\nkind = \"env\"\nvar = \"E\"\n\
               [layout.line1]\nleft = [\"custom/k\", \"custom/a\", \"custom/e\", \"char\"]\n";
    let r = fixture::report(cfg);
    let drawn_later: Vec<_> = r
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::CUSTOM_DRAWN_LATER)
        .collect();
    let c = r.snapshot.unwrap();
    let kinds: Vec<_> = c.custom.iter().map(|t| (t.id.as_str(), &t.kind)).collect();
    assert_eq!(
        kinds,
        [
            ("custom/a", &CustomKind::Text("A".into())),
            ("custom/k", &CustomKind::Command)
        ]
    );
    assert_eq!(drawn_later.len(), 1, "{drawn_later:?}");
}

// 꺼진 text·command 세그먼트는 "아직 그리지 않는 종류"가 아니므로 N502를 내지 않는다. 그리지 않는 종류(env)만
// 낸다. 이것을 실패시키는 것: N502 조건에서 그리는 종류 검사를 지우는 것(꺼진 둘에도 N502).
#[test]
fn a_turned_off_text_or_command_segment_is_not_drawn_later() {
    let cfg = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\nenabled = false\n\
               [segment.\"custom/a\"]\nkind = \"text\"\ntext = \"A\"\nenabled = false\n\
               [segment.\"custom/e\"]\nkind = \"env\"\nvar = \"E\"\n\
               [layout.line1]\nleft = [\"custom/k\", \"custom/a\", \"custom/e\", \"char\"]\n";
    let r = fixture::report(cfg);
    let drawn_later: Vec<_> = r
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::CUSTOM_DRAWN_LATER)
        .collect();
    assert_eq!(drawn_later.len(), 1, "{drawn_later:?}");
    assert!(r.snapshot.unwrap().custom.is_empty());
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

// 이것을 실패시키는 것: 컴파일이 원문을 그대로 저장하는 것(257자 이상이 `config check`를 통과하고 발행에서
// 코덱 바이트 상한에 걸린다), 칸 대신 바이트로 자르는 것, 설정의 폭 프로필을 쓰지 않는 것.
// 64칸은 그대로, 65칸은 말줄임으로 잘리고, 어느 경우든 encode와 decode가 성공한다.
#[test]
fn long_text_is_cut_to_the_cells_and_always_encodes() {
    let ambiguous = "\u{b7}".repeat(40);
    let cases: [(&str, String, u32); 6] = [
        ("", "a".repeat(64), 1),
        ("", "a".repeat(65), 1),
        ("", "a".repeat(300), 1),
        ("", "\u{d55c}".repeat(100), 1),
        ("", format!("{}\u{d55c}", "a".repeat(63)), 1),
        ("[width]\nambiguous = 2\n", ambiguous, 2),
    ];
    for (head, text, amb) in cases {
        let r = fixture::report(&format!("{head}{}", config(&text)));
        assert!(
            r.diagnostics.iter().all(|d| d.code != codes::BAD_VALUE),
            "{text:.8}"
        );
        let c = r
            .snapshot
            .unwrap_or_else(|| panic!("{text:.8}: {:?}", r.diagnostics));
        let bingsu_core::config::compile::CustomKind::Text(kept) = &c.custom[0].kind else {
            panic!("{text:.8}: a text segment");
        };
        let p = bingsu_core::width::WidthProfile::new(amb as u8, 2).unwrap();
        let cells = bingsu_core::width::str_width(kept, p);
        assert!(
            cells <= 64 && kept.len() <= 256,
            "{text:.8}: {cells} cells {} bytes",
            kept.len()
        );
        if text.chars().count() <= 64 && cells_of(&text, p) <= 64 {
            assert_eq!(kept, &text);
        } else {
            assert!(kept.ends_with('\u{2026}'), "{text:.8}: {kept}");
        }
        let b = encode_compiled(&c).unwrap_or_else(|e| panic!("{text:.8}: {e:?}"));
        assert_eq!(decode_compiled(&b).unwrap(), c);
    }
}

fn cells_of(t: &str, p: bingsu_core::width::WidthProfile) -> u32 {
    bingsu_core::width::str_width(t, p)
}

// 이것을 실패시키는 것: custom 번호에서 `+ i`를 빼는 것(둘째 선언이 첫째 값으로 나온다), 선언 순서로
// 번호를 매기는 것(id 순서와 어긋난다). b를 먼저 선언하고 세그먼트와 `.value`를 번갈아 부른다.
#[test]
fn each_text_segment_shows_its_own_value() {
    let cfg = "[segment.\"custom/b\"]\nkind = \"text\"\ntext = \"BBB\"\n\
               [segment.\"custom/a\"]\nkind = \"text\"\ntext = \"AAA\"\n\
               [style]\ntemplate = \"{custom/b}-{custom/a.value}-{custom/a}-{custom/b.value}{char}\"\n";
    let c = fixture::compile(cfg);
    for sh in SHELLS {
        let text = left(&c, sh, 80);
        assert!(text.contains("BBB-AAA-AAA-BBB"), "{sh:?}: {text:?}");
    }
}
