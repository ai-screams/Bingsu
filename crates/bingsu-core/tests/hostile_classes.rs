//! Producer layer of the hostile-value matrix (tests/hostile/classes.tsv).
use bingsu_core::record::{Encoded, Fields, encode_b1};
use bingsu_core::status::Status;

fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn payload(spec: &str) -> Vec<u8> {
    if let Some(rest) = spec.strip_prefix("repeat:") {
        let (byte, n) = rest.split_once(':').unwrap();
        return vec![u8::from_str_radix(byte, 16).unwrap(); n.parse().unwrap()];
    }
    let raw: Vec<u8> = (0..spec.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&spec[i..i + 2], 16).unwrap())
        .collect();
    replace(&raw, b"CANARY", b"/tmp/x")
}

// 이것을 실패시키는 것: 행렬의 producer 열과 다르게 받거나 거부하거나 대체하는 인코더,
// class 이름이 비었거나 형식이 틀리거나 겹치는 행, 윗줄(일곱째 필드)을 검사하지 않는 인코더.
#[test]
fn producer_column_matches() {
    let text = include_str!("../../../tests/hostile/classes.tsv");
    let declared: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("# rows\t"))
        .expect("'# rows<TAB>N' line")
        .parse()
        .unwrap();
    let mut rows = 0;
    let mut seen: Vec<&str> = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let c: Vec<&str> = line.split('\t').collect();
        let (class, want) = (c[0], c[3]);
        // Same rule as tests/hostile/matrix.py: [a-z][a-z0-9_]*, each once.
        let mut chars = class.bytes();
        assert!(
            chars.next().is_some_and(|b| b.is_ascii_lowercase())
                && chars.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "class {class:?} does not match [a-z][a-z0-9_]*"
        );
        assert!(!seen.contains(&class), "class {class:?} repeats");
        seen.push(class);
        let p = payload(c[1]);
        // Every display field, the upper line (record change plan 12) included.
        for field in 0..7 {
            let mut parts: [&[u8]; 7] = [b""; 7];
            parts[field] = &p;
            let f = Fields {
                left: parts[0],
                right: parts[1],
                transient_left: parts[2],
                transient_right: parts[3],
                vi_insert: parts[4],
                vi_command: parts[5],
                upper: parts[6],
            };
            let mut out = Vec::new();
            let got = match encode_b1(&f, Status::OK_NONE, &mut out) {
                Ok(Encoded::Full) => "accept",
                Ok(Encoded::ReplacedBySizeLimit) => "replaced",
                Err(_) => "reject",
            };
            assert_eq!(got, want, "{class} field {field}");
        }
        rows += 1;
    }
    assert_eq!(rows, declared, "classes.tsv declares {declared} rows");
}

// All hostile classes, including NUL/invalid UTF-8 and 1 MiB, are display data.
// 이것을 실패시키는 것: COLORFGBG 원문을 그리거나 잘못된 값으로 다른 모드를 고르는 것.
#[test]
fn colorfgbg_hostile_classes_are_discarded() {
    let base: &[&[u8]] = &[
        b"--ctx",
        b"1",
        b"--record",
        b"B1",
        b"--width",
        b"80",
        b"--shell",
        b"bash",
    ];
    let expected = bingsu_core::front::respond(base);
    for row in include_str!("../../../tests/hostile/classes.tsv")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let cells: Vec<_> = row.split('\t').collect();
        let bytes = payload(cells[1]);
        let mut args = base.to_vec();
        args.extend([b"--colorfgbg".as_slice(), &bytes]);
        assert_eq!(
            bingsu_core::envelope::parse(&args).unwrap().colorfgbg,
            None,
            "{}",
            cells[0]
        );
        assert_eq!(bingsu_core::front::respond(&args), expected, "{}", cells[0]);
    }
}
