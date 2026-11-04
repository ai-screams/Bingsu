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

// 스펙 935행의 문법과 C2 판정 Q3(D1). 이것을 실패시키는 것: 허용 글자에 `/`를 더하는 것, `..` 금지를 지우는 것,
// 첫 글자 `-` 금지를 지우는 것, 길이 상한(32)이나 하한(1)을 지우는 것, 제어 문자를 허용 글자에 넣는 것.
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
        b"3.12\n",
        b"3 12",
        b"\x1b[31m",
        &[b'a'; 33],
    ] {
        assert!(!version_ok(bad), "{:?}", String::from_utf8_lossy(bad));
    }
}

// 형식별 추출. 이것을 실패시키는 것: Line이 주석·빈 줄을 건너뛰지 않는 것, .tool-versions가 다른 도구의
// 줄을 읽는 것, rust-toolchain.toml이 [toolchain] 밖의 channel을 읽거나 escape를 받는 것, go.mod가 toolchain보다
// go 지시어를 먼저 쓰는 것(C2 판정 Q5, D1).
#[test]
fn formats_extract_one_candidate() {
    let tool = |t: &[u8]| Format::ToolVersions(t.to_vec());
    let cases: [(Format, &[u8], Candidate<'_>); 14] = [
        (
            Format::Line,
            b"\n# c\n  3.12 \r\n4\n",
            Candidate::Value(b"3.12"),
        ),
        (Format::Line, b"\n# only\n", Candidate::Absent),
        (
            tool(b"python"),
            b"nodejs 20\npython 3.11 3.10 # x\n",
            Candidate::Value(b"3.11"),
        ),
        (tool(b"python"), b"python\n", Candidate::Malformed),
        (tool(b"python"), b"# python 3\n", Candidate::Absent),
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
// 것(질의 밖 결과를 받는 것), 옛 BNGRES03를 받는 것.
#[test]
fn stored_responses_keep_the_language_section() {
    let r = request(vec![BUILTIN[1].query(), BUILTIN[3].query()]);
    let mut t = transcript(&r);
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
    assert_eq!(&bytes[..10], b"BNGRES04\x04\0");
    let back = Completed::decode_with_catalog(&bytes, &CATALOG).unwrap();
    assert_eq!(back, c);
    let mut old = bytes.clone();
    old[..8].copy_from_slice(b"BNGRES03");
    assert_eq!(
        Completed::decode_with_catalog(&old, &CATALOG),
        Err(E::Magic)
    );
    let mut old = bytes.clone();
    old[8] = 3;
    assert_eq!(
        Completed::decode_with_catalog(&old, &CATALOG),
        Err(E::Version)
    );
    let mut outside = c.clone();
    outside.languages[1].index = 5;
    assert_eq!(outside.encode_with_catalog(&CATALOG), Err(E::Schema));
}

// 옛 IPC 봉투(BNGIPC05)는 거부한다. 이것을 실패시키는 것: frame_len이 옛 magic이나 version 5를 받는 것.
#[test]
fn old_ipc_frames_are_refused() {
    let r = request(vec![]);
    let mut out = [0; wire::FRAME_MAX];
    let n = wire::encode_frame(frame(&r, Kind::Complete, &[]), &mut out).unwrap();
    assert_eq!(&out[..10], b"BNGIPC06\x06\0");
    let mut old = out[..n].to_vec();
    old[..8].copy_from_slice(b"BNGIPC05");
    assert_eq!(wire::decode_frame(&old), Err(E::Magic));
    let mut old = out[..n].to_vec();
    old[8] = 5;
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
        },
        timeout_ms: None,
        cache_ms: None,
        origins: vec![],
        approved_by: vec![],
        shown_at: vec![],
        not_run,
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

// 저장 응답의 decode도 같은 검사를 한다: 질의 밖 결과, 순서가 틀린 결과는 거부한다. 이것을 실패시키는 것:
// decode의 languages_len 검사를 지우는 것.
#[test]
fn stored_languages_are_checked_on_decode() {
    let r = request(vec![BUILTIN[1].query()]);
    let mut t = transcript(&r);
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
