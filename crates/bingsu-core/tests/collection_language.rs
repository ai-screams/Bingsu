//! D1: the version string grammar, the per-format extraction, the request
//! and response encodings of language detection and the receiver's checks.
use bingsu_core::{
    collection::{
        language::{
            self, BUILTIN, Candidate, Format, LanguageQuery, LanguageResult, Version, extract,
            user_queries, version_ok,
        },
        response::Completed,
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, M3B_REQUEST_ID, ProtocolError as E,
            Request, RequestDecoder, Transcript,
        },
    },
    field::{FieldDecl, FieldType, SegmentDecl},
    snapshot::{self, Clock, Identity},
};

const FIELDS: [FieldDecl; 1] = [FieldDecl {
    name: "text",
    ty: FieldType::Text { max_cells: 64 },
}];
const CATALOG: [SegmentDecl; 2] = [const {
    SegmentDecl {
        id: "fixture",
        role: "fg",
        fields: &FIELDS,
    }
}; 2];

fn request(languages: Vec<LanguageQuery>) -> Request {
    Request {
        languages,
        request_id: M3B_REQUEST_ID,
        binding: Binding {
            path_query: Default::default(),
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
            resume: 6,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            cwd: b"/w".to_vec(),
            mask: 1 << 1,
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
    }
}

fn frame<'a>(r: &Request, kind: Kind, payload: &'a [u8]) -> Frame<'a> {
    Frame {
        kind,
        build_id: r.binding.build_id,
        request_id: r.request_id,
        payload,
    }
}

fn ready(mask: u32) -> Vec<u8> {
    let mut b = 3u64.to_le_bytes().to_vec();
    b.extend(mask.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    b
}

fn transcript(r: &Request) -> Transcript {
    let mut t = Transcript::with_catalog(r, &CATALOG).unwrap();
    t.accept(frame(r, Kind::Ready, &ready(r.binding.mask)))
        .unwrap();
    t.request_sent().unwrap();
    t
}

fn clock(r: &Request) -> Clock {
    Clock {
        kind: r.binding.clock_kind,
        boot: r.binding.snapshot.boot,
        domain: r.binding.domain,
        resume: r.binding.resume,
        now: 99,
    }
}

/// The fixture segment 1 with one known text field: a round's one update.
fn update() -> Vec<u8> {
    let mut p = 1u16.to_le_bytes().to_vec();
    p.push(1);
    p.extend(0u32.to_le_bytes());
    p.extend(1u16.to_le_bytes());
    p.extend(0u16.to_le_bytes());
    p.extend([0, 0]);
    p.extend(1u32.to_le_bytes());
    p.push(b'x');
    p.push(0);
    p
}

fn found(index: u8, value: &[u8]) -> LanguageResult {
    LanguageResult {
        index,
        marker: Some((0, 1)),
        version: Version::Found {
            file: 0,
            level: 2,
            digest: [9; 16],
            value: value.to_vec(),
        },
    }
}

// 스펙 935행의 문법과 보안 리뷰 M1(D1, C2 판정 Q3의 "첫 글자 `-` 금지"를 대체): 첫 글자는 [0-9A-Za-z]다.
// 이것을 실패시키는 것: 허용 글자에 `/`를 더하는 것, `..` 금지를 지우는 것, 첫 글자 검사를 `-`만 막는 쪽으로
// 되돌리는 것(`.`, `.hidden`, `+nightly`, `_x`가 통과), 길이 상한(32)이나 하한(1)을 지우는 것, 제어 문자를 허용
// 글자에 넣는 것.
#[test]
fn version_grammar_table() {
    for ok in [
        &b"3.12.1"[..],
        b"lts",
        b"1.75.0+nightly",
        b"go1.22_rc-2",
        &[b'a'; 32],
    ] {
        assert!(version_ok(ok), "{:?}", String::from_utf8_lossy(ok));
    }
    for bad in [
        &b""[..],
        b"x/y",
        b"../x",
        b"1..2",
        b"-v",
        b".",
        b".hidden",
        b"+nightly",
        b"_x",
        b"3.12\n",
        b"3 12",
        b"\x1b[31m",
        &[b'a'; 33],
    ] {
        assert!(!version_ok(bad), "{:?}", String::from_utf8_lossy(bad));
    }
}

// 형식별 추출. 이것을 실패시키는 것: Line이 주석·빈 줄을 건너뛰지 않는 것, rust-toolchain.toml이 [toolchain] 밖의
// channel을 읽거나 escape를 받는 것, `path` 키를 보지 않는 것(channel과 함께여도 Path, D2 판정 Q4), `path.x`를
// 받는 것, go.mod가 toolchain보다 go 지시어를 먼저 쓰는 것(C2 판정 Q5, D1).
#[test]
fn formats_extract_one_candidate() {
    let cases: [(Format, &[u8], Candidate<'_>); 14] = [
        (
            Format::Line,
            b"\n# c\n  3.12 \r\n4\n",
            Candidate::Value(b"3.12"),
        ),
        (Format::Line, b"\n# only\n", Candidate::Absent),
        (
            Format::RustToolchainToml,
            b"[toolchain]\npath = \"/opt/rust\"\n",
            Candidate::Path,
        ),
        (
            Format::RustToolchainToml,
            b"[toolchain]\nchannel = \"1.80.0\"\npath = \"/opt/rust\"\n",
            Candidate::Path,
        ),
        (
            Format::RustToolchainToml,
            b"[toolchain]\npath.x = \"/opt/rust\"\n",
            Candidate::Malformed,
        ),
        (
            Format::RustToolchainToml,
            b"[toolchain]\nchannel = \"1.80.0\"\n",
            Candidate::Value(b"1.80.0"),
        ),
        (
            Format::RustToolchainToml,
            b"channel = \"x\"\n[toolchain]\n",
            Candidate::Absent,
        ),
        (
            Format::RustToolchainToml,
            b"[toolchain]\nchannel = \"a\\\"b\"\n",
            Candidate::Malformed,
        ),
        (
            Format::RustToolchainToml,
            b"[toolchain]\nchannel = nightly\n",
            Candidate::Malformed,
        ),
        (
            Format::RustToolchainToml,
            b"[other]\nchannel = \"x\"\n",
            Candidate::Absent,
        ),
        (
            Format::GoMod,
            b"module m\ngo 1.21\ntoolchain go1.22.1\n",
            Candidate::Value(b"1.22.1"),
        ),
        (
            Format::GoMod,
            b"module m\ngo 1.21 // c\n",
            Candidate::Value(b"1.21"),
        ),
        (Format::GoMod, b"toolchain local x\n", Candidate::Malformed),
        (Format::GoMod, b"module m\n", Candidate::Absent),
    ];
    for (format, bytes, want) in cases {
        assert_eq!(
            extract(&format, bytes),
            want,
            "{format:?} {:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

// 응답에는 문법을 통과한 값만 Found로 남는다. 이것을 실패시키는 것: version()이 문법 검사 없이 Found를 만드는 것.
#[test]
fn version_found_only_after_the_grammar() {
    assert!(matches!(
        language::version(&Format::Line, b"x/y\n", 0, 0),
        Version::Refused { .. }
    ));
    assert!(matches!(
        language::version(&Format::Line, b"3.12\n", 0, 0),
        Version::Found { .. }
    ));
}

// 요청 왕복과 이름 규칙. 이것을 실패시키는 것: 질의 이름에 `/`·`..`·NUL을 받는 것, 개수 상한(16)을 지우는 것,
// 요청 본문에 언어 절을 싣지 않는 것(decode 뒤 질의가 비어 있음).
#[test]
fn requests_carry_valid_queries_only() {
    let r = request(BUILTIN.iter().map(|b| b.query()).collect());
    let body = r.encode_body().unwrap();
    let back = Request::decode_body(r.binding.build_id, r.request_id, &body).unwrap();
    assert_eq!(back.languages, r.languages);
    for bad in [&b"a/b"[..], b"..", b".", b"a\0", b""] {
        let q = LanguageQuery {
            id: b"x".to_vec(),
            markers: vec![bad.to_vec()],
            version_files: vec![],
        };
        assert_eq!(request(vec![q]).encode_body(), Err(E::Schema), "{bad:?}");
    }
    let many = vec![BUILTIN[0].query(); language::LANGUAGES_MAX + 1];
    assert_eq!(request(many).encode_body(), Err(E::Budget));
}

// 받는 쪽 검사: 결과는 질의에 맞아야 한다. 이것을 실패시키는 것: Transcript의 result.check 호출을 지우는 것,
// 같은 언어의 두 번째 결과를 받는 것, check가 레벨 상한·파일 index·문법 가운데 하나를 보지 않는 것.
#[test]
fn language_results_must_fit_the_query() {
    let r = request(vec![BUILTIN[1].query()]);
    let ok = found(0, b"3.12");
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Language, &ok.encode())).unwrap();
    assert_eq!(
        t.accept(frame(&r, Kind::Language, &ok.encode())),
        Err(E::Duplicate)
    );
    let mut level = found(0, b"3.12");
    level.marker = Some((0, 33));
    let mut file = found(0, b"3.12");
    if let Version::Found { file: f, .. } = &mut file.version {
        *f = 9;
    }
    for bad in [found(1, b"3.12"), found(0, b"x/y"), level, file] {
        let mut t = transcript(&r);
        assert_eq!(
            t.accept(frame(&r, Kind::Language, &bad.encode())),
            Err(E::Schema),
            "{bad:?}"
        );
    }
}

// 저장 응답 왕복과 봉투 버전. 이것을 실패시키는 것: Completed가 언어 절을 쓰지 않는 것, decode가 검사를 건너뛰는
// 것(질의 밖 결과를 받는 것), 옛 BNGRES04를 받는 것.
#[test]
fn stored_responses_keep_the_language_section() {
    let r = request(vec![BUILTIN[1].query(), BUILTIN[3].query()]);
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &update())).unwrap();
    t.accept(frame(&r, Kind::Language, &found(1, b"1.22").encode()))
        .unwrap();
    t.accept(frame(&r, Kind::Language, &found(0, b"3.12").encode()))
        .unwrap();
    let c = t.finish(EndReason::Deadline, clock(&r)).unwrap().unwrap();
    assert_eq!(
        c.languages.iter().map(|l| l.index).collect::<Vec<_>>(),
        [0, 1]
    );
    let bytes = c.encode_with_catalog(&CATALOG).unwrap();
    assert_eq!(&bytes[..10], b"BNGRES05\x05\0");
    let back = Completed::decode_with_catalog(&bytes, &CATALOG).unwrap();
    assert_eq!(back, c);
    let mut old = bytes.clone();
    old[..8].copy_from_slice(b"BNGRES04");
    assert_eq!(
        Completed::decode_with_catalog(&old, &CATALOG),
        Err(E::Magic)
    );
    let mut old = bytes.clone();
    old[8] = 4;
    assert_eq!(
        Completed::decode_with_catalog(&old, &CATALOG),
        Err(E::Version)
    );
    let mut outside = c.clone();
    outside.languages[1].index = 5;
    assert_eq!(outside.encode_with_catalog(&CATALOG), Err(E::Schema));
}

// 옛 IPC 봉투(BNGIPC06)는 거부한다. 이것을 실패시키는 것: frame_len이 옛 magic이나 version 6을 받는 것.
#[test]
fn old_ipc_frames_are_refused() {
    let r = request(vec![]);
    let mut out = [0; wire::FRAME_MAX];
    let n = wire::encode_frame(frame(&r, Kind::Complete, &[]), &mut out).unwrap();
    assert_eq!(&out[..10], b"BNGIPC07\x07\0");
    let mut old = out[..n].to_vec();
    old[..8].copy_from_slice(b"BNGIPC06");
    assert_eq!(wire::decode_frame(&old), Err(E::Magic));
    let mut old = out[..n].to_vec();
    old[8] = 6;
    assert_eq!(wire::decode_frame(&old), Err(E::Version));
}

// 요청 디코더도 언어 질의를 지나 돌려준다. 이것을 실패시키는 것: decode_body가 언어 절을 읽지 않는 것(남은
// 바이트로 Schema).
#[test]
fn decoder_returns_the_queries() {
    let r = request(vec![BUILTIN[0].query()]);
    let body = r.encode_body().unwrap();
    let mut d = RequestDecoder::new();
    d.accept(frame(&r, Kind::Ready, &ready(r.binding.mask)))
        .unwrap();
    let mut begin = (body.len() as u32).to_le_bytes().to_vec();
    begin.extend(3u64.to_le_bytes());
    d.accept(frame(&r, Kind::RequestBegin, &begin)).unwrap();
    let mut chunk = 0u32.to_le_bytes().to_vec();
    chunk.extend(&body);
    d.accept(frame(&r, Kind::RequestChunk, &chunk)).unwrap();
    let got = d
        .accept(frame(&r, Kind::RequestEnd, &snapshot::crc32c(&[&body])))
        .unwrap()
        .unwrap();
    assert_eq!(got.languages, r.languages);
}

// C2 판정 Q1(D1): 사용자 정의 language 단위의 detect_files만 질의가 된다. not_run 단위와 경로 성분이 아닌 이름은
// 뺀다. 이것을 실패시키는 것: not_run 거름을 지우는 것, user_queries의 validate 거름을 지우는 것.
#[test]
fn user_queries_leave_out_bad_names() {
    use bingsu_core::config::compile::{ExecPolicy, ExecUnit, NotRun};
    let unit = |id: &str, files: &[&str], not_run| ExecUnit {
        id: id.into(),
        policy: ExecPolicy::Language {
            interpreter: None,
            version_argv: vec![],
            detect_files: files.iter().map(|f| f.to_string()).collect(),
            cwd: None,
            env_allow: Vec::new(),
        },
        timeout_ms: None,
        cache_ms: None,
        origins: vec![],
        approved_by: vec![],
        shown_at: vec![],
        not_run,
        pattern: None,
    };
    let units = [
        unit("custom/deno", &["deno.json"], None),
        unit("custom/off", &["x"], Some(NotRun::Disabled)),
        unit("custom/bad", &["../x"], None),
        unit("custom/none", &[], None),
    ];
    let queries = user_queries(&units);
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].id, b"custom/deno");
    assert_eq!(queries[0].markers, [b"deno.json".to_vec()]);
    assert!(queries[0].version_files.is_empty());
}

// 저장 응답의 decode도 같은 검사를 한다: 질의 밖 결과(index 1)는 거부한다. 이것을 실패시키는 것: decode의
// languages_len 호출을 지우는 것. 순서와 중복은 stored_languages_are_ascending_and_unique가 본다.
#[test]
fn stored_languages_are_checked_on_decode() {
    let r = request(vec![BUILTIN[1].query()]);
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &update())).unwrap();
    t.accept(frame(&r, Kind::Language, &found(0, b"3.12").encode()))
        .unwrap();
    let c = t.finish(EndReason::Deadline, clock(&r)).unwrap().unwrap();
    let bytes = c.encode_with_catalog(&CATALOG).unwrap();
    // The last result's index byte: result = index, 3 marker, tag, file,
    // level, 16 digest, 4 length, 4 value bytes.
    let at = bytes.len() - (1 + 3 + 1 + 2 + 16 + 4 + 4);
    assert_eq!(bytes[at], 0);
    let mut bad = bytes.clone();
    bad[at] = 1;
    let crc = snapshot::crc32c(&[&bad[64..]]);
    bad[16..20].copy_from_slice(&crc);
    assert_eq!(
        Completed::decode_with_catalog(&bad, &CATALOG),
        Err(E::Schema)
    );
}

fn reseal(bytes: &mut [u8]) {
    let crc = snapshot::crc32c(&[&bytes[64..]]);
    bytes[16..20].copy_from_slice(&crc);
}

// 보안 리뷰 M2: 저장 응답의 언어 결과는 index 오름차순이고 겹치지 않는다. [1,0]과 [0,0]은 encode도 decode도
// 거부한다. 이것을 실패시키는 것: languages_len의 순서 검사를 `>`로 바꾸는 것([0,0]이 통과), 검사를 지우는 것.
#[test]
fn stored_languages_are_ascending_and_unique() {
    let r = request(vec![BUILTIN[1].query(), BUILTIN[3].query()]);
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &update())).unwrap();
    t.accept(frame(&r, Kind::Language, &found(0, b"3.12").encode()))
        .unwrap();
    t.accept(frame(&r, Kind::Language, &found(1, b"1.22").encode()))
        .unwrap();
    let c = t.finish(EndReason::Deadline, clock(&r)).unwrap().unwrap();
    let bytes = c.encode_with_catalog(&CATALOG).unwrap();
    // Two results of 1 index + 3 marker + 1 tag + 2 file and level + 16
    // digest + 4 length + 4 value bytes end the file.
    let second = bytes.len() - 31;
    let first = second - 31;
    assert_eq!((bytes[first], bytes[second]), (0, 1));
    for order in [[1, 0], [0, 0]] {
        let mut stored = c.clone();
        stored.languages[0].index = order[0];
        stored.languages[1].index = order[1];
        assert_eq!(
            stored.encode_with_catalog(&CATALOG),
            Err(E::Schema),
            "{order:?}"
        );
        let mut bad = bytes.clone();
        bad[first] = order[0];
        bad[second] = order[1];
        reseal(&mut bad);
        assert_eq!(
            Completed::decode_with_catalog(&bad, &CATALOG),
            Err(E::Schema),
            "{order:?}"
        );
    }
}

// 보안 리뷰 M2와 Codex L6: 받는 쪽 검사의 나머지 칸. Found의 레벨 33, 표시 파일 index 9, Refused의 파일 index 9,
// 표시 파일이 없다는 바이트(0) 뒤의 0이 아닌 index나 level은 거부한다. 이것을 실패시키는 것: check의 file_ok에서
// 레벨 검사를 지우는 것, 표시 파일 index 검사를 지우는 것, Refused를 검사 없이 받는 것, read의 `m == 0`이나
// `level == 0` 조건을 지우는 것, Path의 파일 index를 보지 않는 것(D2).
#[test]
fn receiver_checks_every_index_and_level() {
    let r = request(vec![BUILTIN[1].query()]);
    let mut level = found(0, b"3.12");
    if let Version::Found { level: l, .. } = &mut level.version {
        *l = 33;
    }
    let mut marker = found(0, b"3.12");
    marker.marker = Some((9, 0));
    let refused = LanguageResult {
        index: 0,
        marker: None,
        version: Version::Refused {
            file: 9,
            level: 0,
            digest: [0; 16],
        },
    };
    let absent = LanguageResult {
        index: 0,
        marker: None,
        version: Version::None,
    }
    .encode();
    assert_eq!(&absent[1..4], [0, 0, 0]);
    let (mut index, mut level_byte) = (absent.clone(), absent);
    index[2] = 1;
    level_byte[3] = 1;
    // BUILTIN[1] (python) has one version file: index 1 is out.
    let path = LanguageResult {
        index: 0,
        marker: None,
        version: Version::Path { file: 1, level: 0 },
    };
    let cases = [
        level.encode(),
        marker.encode(),
        refused.encode(),
        index,
        level_byte,
        path.encode(),
    ];
    for payload in cases {
        let mut t = transcript(&r);
        assert_eq!(
            t.accept(frame(&r, Kind::Language, &payload)),
            Err(E::Schema),
            "{payload:?}"
        );
    }
    // Positive control: the same shapes with valid indices are accepted.
    let ok = LanguageResult {
        index: 0,
        marker: Some((3, 32)),
        version: Version::Refused {
            file: 0,
            level: 32,
            digest: [0; 16],
        },
    };
    transcript(&r)
        .accept(frame(&r, Kind::Language, &ok.encode()))
        .unwrap();
    let path_ok = LanguageResult {
        version: Version::Path { file: 0, level: 32 },
        ..ok
    };
    transcript(&r)
        .accept(frame(&r, Kind::Language, &path_ok.encode()))
        .unwrap();
}

// Codex M3: rust-toolchain.toml은 주석과 문자열 문맥을 안다. 표 머리 뒤 주석을 받고, 여러 줄 문자열과 여러 줄
// 값 안의 가짜 표·키는 읽지 않는다. channel을 정할 수 있는데 지원하지 않는 구문은 값 없음(Malformed)이다.
// 이것을 실패시키는 것: 표 머리 뒤 주석을 거부하는 것, 여러 줄 문자열 상태를 지우는 것(가짜 channel을 읽음),
// 여러 줄 기본 문자열 안의 `\` 건너뛰기를 지우는 것, 괄호 깊이를 지우는 것(배열 안의 `[`를 표 머리로 읽음),
// 따옴표 키·최상위 toolchain·점 키·따옴표 표 이름·머리 뒤 잔여·열린 문자열 거부를 지우는 것. 재리뷰 M2·M3·L5:
// channel을 찾은 뒤에도 파일 끝까지 검증하는 것을 지우는 것(뒤의 따옴표 키·열린 문자열·두 번째 channel을 놓침),
// 괄호를 종류 없이 세는 것(`[}`가 닫힘), 32단 중첩 상한을 지우는 것, `channel.` 거부를 지우는 것, channel 값
// 뒤 잔여 검사(comment_or_end)를 지우는 것. 확인 리뷰 M: `toolchain` 표를 다시 여는 것(두 번째 `[toolchain]`,
// `[[toolchain]]`, `[toolchain.<x>]`)을 받는 것(각 조건을 지우면 뒤 channel이나 재정의를 놓침).
#[test]
fn rust_toolchain_toml_knows_comments_and_strings() {
    let deep = |n: usize| {
        let mut b = b"x = ".to_vec();
        b.extend(vec![b'['; n]);
        b.extend(vec![b']'; n]);
        b.extend(b"\n[toolchain]\nchannel = \"1.80\"\n");
        b
    };
    assert_eq!(
        extract(&Format::RustToolchainToml, &deep(32)),
        Candidate::Value(b"1.80")
    );
    assert_eq!(
        extract(&Format::RustToolchainToml, &deep(33)),
        Candidate::Malformed
    );
    let cases: [(&[u8], Candidate<'_>); 27] = [
        (
            br#"[toolchain]
channel = "1.80"
"channel" = "nightly"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80"
x = "open
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80"
channel = "1.81"
"#,
            Candidate::Malformed,
        ),
        (
            br#"note = [}
[toolchain]
channel = "1.80"
"#,
            Candidate::Malformed,
        ),
        (
            br#"note = {]
[toolchain]
channel = "1.80"
"#,
            Candidate::Malformed,
        ),
        (
            br#"note = { a = [1] }
[toolchain]
channel = "1.80"
"#,
            Candidate::Value(b"1.80"),
        ),
        (
            br#"[toolchain]
channel.x = "y"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80" garbage
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain] # pinned
channel = "1.80.0" # x
"#,
            Candidate::Value(b"1.80.0"),
        ),
        (
            br#"note = """
[toolchain]
channel = "fake"
"""
[toolchain]
channel = "1.79"
"#,
            Candidate::Value(b"1.79"),
        ),
        (
            br#"[toolchain]
profile = '''
channel = "fake"
'''
"#,
            Candidate::Absent,
        ),
        (
            br#"[toolchain]
x = """a\"""
channel = "fake"
"""
"#,
            Candidate::Absent,
        ),
        (
            br#"targets = [
  ["a"],
]
[toolchain]
channel = "1.80"
"#,
            Candidate::Value(b"1.80"),
        ),
        (
            br#"[toolchain]
components = [
"x",
]
channel = "1.81"
"#,
            Candidate::Value(b"1.81"),
        ),
        (
            br#"[toolchain]
"channel" = "x"
"#,
            Candidate::Malformed,
        ),
        (
            br#"toolchain = { channel = "x" }
"#,
            Candidate::Malformed,
        ),
        (
            br#"toolchain.channel = "x"
"#,
            Candidate::Malformed,
        ),
        (
            br#"["toolchain"]
channel = "x"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain] x
channel = "x"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
profile = "min
channel = "x"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
profile = """
"#,
            Candidate::Malformed,
        ),
        (
            br#"[[toolchain]]
channel = "x"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80"
[[toolchain]]
channel = "1.81"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80"
[toolchain.channel]
x = "y"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80"
[other]
[toolchain]
profile = "minimal"
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain.x]
y = 1
"#,
            Candidate::Malformed,
        ),
        (
            br#"[toolchain]
channel = "1.80"
[other.toolchain]
x = 1
"#,
            Candidate::Value(b"1.80"),
        ),
    ];
    for (bytes, want) in cases {
        assert_eq!(
            extract(&Format::RustToolchainToml, bytes),
            want,
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

// D3a 판정 Q-B: 갱신 없이 언어 결과만 있는 회차도 결과(Completed)를 낸다. helper가 이번 회차의 내장 조사에 넘기기
// 때문이다. 기록은 저장소가 갱신 있을 때만 만든다(보안 리뷰 L4의 계약, collection_store 시험이 고정). 둘 다 없으면
// 결과도 없다. 이것을 실패시키는 것: finish가 언어 결과만 있는 회차를 None으로 보내는 것, 빈 회차에 결과를 내는 것.
#[test]
fn language_results_alone_reach_the_round() {
    let r = request(vec![BUILTIN[1].query()]);
    let t = transcript(&r);
    assert_eq!(t.finish(EndReason::Deadline, clock(&r)), Ok(None));
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Language, &found(0, b"3.12").encode()))
        .unwrap();
    let c = t.finish(EndReason::Deadline, clock(&r)).unwrap().unwrap();
    assert_eq!((c.updates.len(), c.languages.len()), (0, 1));
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &update())).unwrap();
    t.accept(frame(&r, Kind::Language, &found(0, b"3.12").encode()))
        .unwrap();
    let c = t.finish(EndReason::Deadline, clock(&r)).unwrap().unwrap();
    assert_eq!((c.updates.len(), c.languages.len()), (1, 1));
}

// D2 판정 Q9·Q11: 내장 파일 순서는 관리자가 읽는 순서다. rustup은 한 폴더에 둘이 있으면 `rust-toolchain`을 읽는다
// (rustup 1.29.2 실측). `.tool-versions`는 읽지 않는다. 형식 태그 1(옛 `.tool-versions`)은 거부한다. 이것을 실패시키는
// 것: rust 파일 순서를 toml 먼저로 되돌리는 것, format_from이 태그 1을 받는 것.
#[test]
fn formats_follow_the_managers_order() {
    let rust = BUILTIN[2].query();
    assert_eq!(rust.version_files[0].name, b"rust-toolchain");
    assert_eq!(rust.version_files[1].name, b"rust-toolchain.toml");
    assert!(
        BUILTIN
            .iter()
            .flat_map(|b| b.query().version_files)
            .all(|f| f.name != b".tool-versions")
    );
    let mut r = request(vec![LanguageQuery {
        id: b"x".to_vec(),
        markers: vec![],
        version_files: vec![language::VersionFile {
            name: b"f".to_vec(),
            format: Format::Line,
        }],
    }]);
    let mut body = r.encode_body().unwrap();
    // The last byte is the only file's format tag.
    *body.last_mut().unwrap() = 1;
    assert!(Request::decode_body(r.binding.build_id, r.request_id, &body).is_err());
    *body.last_mut().unwrap() = 0;
    r.languages[0].version_files[0].format = Format::Line;
    assert_eq!(
        Request::decode_body(r.binding.build_id, r.request_id, &body)
            .unwrap()
            .languages,
        r.languages
    );
}

// D2 판정 Q4: path 툴체인은 값도 거부도 아닌 자기 답(Path)이고, 받는 쪽과 저장 응답을 지난다. 이것을 실패시키는
// 것: version()이 Candidate::Path를 Refused로 보내는 것, Path의 wire 태그를 읽지 않는 것.
#[test]
fn path_toolchain_is_its_own_answer() {
    let path = language::version(
        &Format::RustToolchainToml,
        b"[toolchain]\npath = \"/opt/rust\"\n",
        1,
        2,
    );
    assert_eq!(path, Version::Path { file: 1, level: 2 });
    let r = request(vec![BUILTIN[2].query()]);
    let result = LanguageResult {
        index: 0,
        marker: Some((0, 2)),
        version: path,
    };
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &update())).unwrap();
    t.accept(frame(&r, Kind::Language, &result.encode()))
        .unwrap();
    let c = t.finish(EndReason::Deadline, clock(&r)).unwrap().unwrap();
    let bytes = c.encode_with_catalog(&CATALOG).unwrap();
    assert_eq!(
        Completed::decode_with_catalog(&bytes, &CATALOG)
            .unwrap()
            .languages,
        [result]
    );
}

// 그려진 내장 언어 segment만 각각 묻고(D3 판정 Q6), worker mask가 0이어도 언어가 있으면 요청을 만든다. 이것을
// 실패시키는 것: builtin_languages에서 그려진 비트 검사를 지우는 것(그리지 않은 언어까지 물음), mask가 0이면
// 언어가 있어도 요청을 만들지 않는 것.
#[test]
fn requests_follow_language_segments() {
    use bingsu_core::collection::{builtin_languages, request_with_languages, selection::PRODUCT};
    let bit = |id: &str| {
        let i = bingsu_core::field::BUILTIN
            .binary_search_by(|d| d.id.cmp(id))
            .unwrap();
        1u32 << i
    };
    let ids =
        |drawn| -> Vec<Vec<u8>> { builtin_languages(drawn).into_iter().map(|q| q.id).collect() };
    assert_eq!(ids(0), Vec::<Vec<u8>>::new());
    assert_eq!(ids(bit("node")), vec![b"node".to_vec()]);
    assert_eq!(
        ids(bit("rust") | bit("python") | bit("git")),
        vec![b"python".to_vec(), b"rust".to_vec()]
    );
    let mut binding = request(vec![]).binding;
    binding.mask = 0;
    let made = |languages| {
        request_with_languages(&PRODUCT, binding.clone(), M3B_REQUEST_ID, 50, languages).unwrap()
    };
    assert!(made(vec![]).is_none());
    let go = made(builtin_languages(bit("go"))).unwrap();
    assert_eq!(go.languages.len(), 1);
    assert_eq!(
        bingsu_core::field::BUILTIN[usize::from(bingsu_core::collection::DIR_SEGMENT)].id,
        "dir"
    );
}
